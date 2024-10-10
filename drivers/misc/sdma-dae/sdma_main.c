// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/debugfs.h>
#include <linux/iommu.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include <linux/device.h>

#include "sdma_hal.h"
#include "sdma_irq.h"
#include "sdma_umem.h"
#include "sdma_auth.h"

#define BASE_DIR		"sdma" /* Subdir in /sys/kernel/debug/  */
#define UPPER_SHIFT		32
#define MAX_INPUT_LENGTH	128

u32 share_chns = 16;
module_param(share_chns, uint, RW_R_R);
MODULE_PARM_DESC(share_chns, "num of share channels, 16 by default");

static bool safe_mode = true; /* fast mode by default */
module_param(safe_mode, bool, RW_R_R);
MODULE_PARM_DESC(safe_mode, "| 0 - fast_mode| 1 - safe_mode(default)|");

struct ida fd_ida;
struct hisi_sdma_core_device hisi_sdma_core_device = {0};
static struct class *sdma_class;
static struct dentry *sdma_dbgfs_dir;

static bool sdma_channel_alloc_sq_cq(struct hisi_sdma_channel *pchan, u32 idx)
{
	int sync_size = sizeof(struct hisi_sdma_queue_info);
	struct page *page_list;

	if (idx >= HISI_SDMA_MAX_NODES) {
		pr_err("SDMA device id overflow, probe sdma%u failed!\n", idx);
		return false;
	}
	page_list = alloc_pages_node(idx, GFP_KERNEL | __GFP_ZERO, get_order(HISI_SDMA_SQ_SIZE));
	if (!page_list) {
		pr_err("sdma channel%u: alloc sq page_list failed\n", pchan->idx);
		return false;
	}
	pchan->sq_base = (struct hisi_sdma_sq_entry *)page_to_virt(page_list);

	page_list = alloc_pages_node(idx, GFP_KERNEL | __GFP_ZERO, get_order(HISI_SDMA_CQ_SIZE));
	if (!page_list) {
		pr_err("sdma channel%u: alloc cq page_list failed\n", pchan->idx);
		return false;
	}
	pchan->cq_base = (struct hisi_sdma_cq_entry *)page_to_virt(page_list);

	page_list = alloc_pages_node(idx, GFP_KERNEL | __GFP_ZERO, get_order(sync_size));
	if (!page_list) {
		pr_err("sdma channel%u: alloc sync_info page_list failed\n", pchan->idx);
		return false;
	}
	pchan->sync_info_base = (struct hisi_sdma_queue_info *)page_to_virt(page_list);
	pchan->sync_info_base->cq_vld = 1;

	return true;
}

static void sdma_channel_init(struct hisi_sdma_channel *pchan)
{
	void __iomem *io_base = pchan->io_base;
	u64 sq_addr = virt_to_phys(pchan->sq_base);
	u64 cq_addr = virt_to_phys(pchan->cq_base);

	writel(sq_addr & 0xFFFFFFFF, io_base + HISI_SDMA_CH_SQBASER_L_REG);
	writel(sq_addr >> UPPER_SHIFT, io_base + HISI_SDMA_CH_SQBASER_H_REG);
	writel(cq_addr & 0xFFFFFFFF, io_base + HISI_SDMA_CH_CQBASER_L_REG);
	writel(cq_addr >> UPPER_SHIFT, io_base + HISI_SDMA_CH_CQBASER_H_REG);

	sdma_channel_set_sq_size(pchan, HISI_SDMA_SQ_LENGTH - 1);
	sdma_channel_set_cq_size(pchan, HISI_SDMA_CQ_LENGTH - 1);
	sdma_channel_set_sq_tail(pchan, 0);
	sdma_channel_set_cq_head(pchan, 0);
	sdma_channel_clr_normal_sqe_cnt(pchan);
	sdma_channel_clr_err_sqe_cnt(pchan);

	sdma_channel_enable(pchan);
}

static void sdma_channel_reset_sq_cq(struct hisi_sdma_channel *pchan)
{
	u32 sq_head, sq_tail, cq_head, cq_tail;

	sq_head = sdma_channel_get_sq_head(pchan);
	sq_tail = sdma_channel_get_sq_tail(pchan);
	cq_head = sdma_channel_get_cq_head(pchan);
	cq_tail = sdma_channel_get_cq_tail(pchan);

	if (sq_head != sq_tail)
		sdma_channel_set_sq_tail(pchan, sq_head);

	if (cq_head != cq_tail)
		sdma_channel_set_cq_head(pchan, cq_tail);
}

static void sdma_channel_reset(struct hisi_sdma_channel *pchan)
{
	int i = 0;

	sdma_channel_reset_sq_cq(pchan);
	sdma_channel_set_pause(pchan);
	while (!sdma_channel_is_paused(pchan)) {
		msleep(HISI_SDMA_FSM_INTERVAL);
		if (++i > HISI_SDMA_FSM_TIMEOUT) {
			pr_warn("chn%u cannot get paused\n", pchan->idx);
			return;
		}
	}
	i = 0;
	while (!sdma_channel_is_quiescent(pchan)) {
		msleep(HISI_SDMA_FSM_INTERVAL);
		if (++i > HISI_SDMA_FSM_TIMEOUT) {
			pr_warn("chn%u cannot get quiescent\n", pchan->idx);
			return;
		}
	}
	i = 0;
	sdma_channel_write_reset(pchan);
	while (!sdma_channel_is_idle(pchan)) {
		msleep(HISI_SDMA_FSM_INTERVAL);
		if (++i > HISI_SDMA_FSM_TIMEOUT) {
			pr_warn("chn%u cannot get idle\n", pchan->idx);
			return;
		}
	}
}

static void sdma_free_all_sq_cq(struct hisi_sdma_device *psdma_dev)
{
	struct hisi_sdma_channel *pchan;
	int sync_size;
	int i;

	sync_size = sizeof(struct hisi_sdma_queue_info);

	for (i = psdma_dev->nr_channel - 1; i >= 0; i--) {
		pchan = psdma_dev->channels + i;
		if (pchan->io_base)
			sdma_channel_reset(pchan);
		if (pchan->sq_base)
			free_pages((uintptr_t)(void *)pchan->sq_base, get_order(HISI_SDMA_SQ_SIZE));
		if (pchan->cq_base)
			free_pages((uintptr_t)(void *)pchan->cq_base, get_order(HISI_SDMA_CQ_SIZE));
		if (pchan->sync_info_base)
			free_pages((uintptr_t)(void *)pchan->sync_info_base, get_order(sync_size));
	}
}

static void sdma_destroy_channels(struct hisi_sdma_device *psdma_dev)
{
	if (!psdma_dev || !psdma_dev->channels)
		return;

	sdma_free_all_sq_cq(psdma_dev);
	kfree(psdma_dev->channels);
	psdma_dev->channels = NULL;
}

static int sdma_init_channels(struct hisi_sdma_device *psdma_dev)
{
	u32 chn_num = psdma_dev->nr_channel;
	struct hisi_sdma_channel *pchan;
	u32 i;

	psdma_dev->channels = kcalloc_node(chn_num, sizeof(struct hisi_sdma_channel), GFP_KERNEL,
					   psdma_dev->node_idx);
	if (!psdma_dev->channels)
		return -ENOMEM;

	for (i = 0; i < chn_num; i++) {
		pchan = psdma_dev->channels + i;
		pchan->idx = i;
		pchan->pdev = psdma_dev;
		pchan->ida = 0;
		spin_lock_init(&pchan->owner_chn_lock);

		if (sdma_channel_alloc_sq_cq(pchan, psdma_dev->node_idx) == false)
			goto err_out;

		pchan->io_base = psdma_dev->io_base + i * HISI_SDMA_CHANNEL_IOMEM_SIZE;

		sdma_channel_disable(pchan);
		sdma_channel_init(pchan);
	}

	if (share_chns > chn_num) {
		dev_warn(&psdma_dev->pdev->dev, "share_chns max val = %u!\n", chn_num);
		share_chns = chn_num;
	}
	bitmap_set(psdma_dev->channel_map, 0, chn_num - share_chns);

	return 0;

err_out:
	sdma_destroy_channels(psdma_dev);
	return -ENOMEM;
}

static int sdma_device_add(struct hisi_sdma_device *psdma_dev)
{
	u32 idx = psdma_dev->idx;
	struct cdev *cdev = NULL;
	u32 sdma_minor;
	int devno;
	int ret;

	if (idx >= HISI_SDMA_MAX_DEVS) {
		dev_err(&psdma_dev->pdev->dev, "Exceeded the maximum number of devices\n");
		return -ENODEV;
	}

	spin_lock(&hisi_sdma_core_device.device_lock);
	sdma_minor = idx;
	hisi_sdma_core_device.sdma_devices[idx] = psdma_dev;
	cdev = &hisi_sdma_core_device.sdma_devices[idx]->cdev;
	devno = MKDEV(hisi_sdma_core_device.sdma_major, sdma_minor);

	sdma_cdev_init(cdev);
	ret = cdev_add(cdev, devno, 1);
	if (ret) {
		spin_unlock(&hisi_sdma_core_device.device_lock);
		dev_err(&psdma_dev->pdev->dev, "Error %d adding sdma\n", ret);
		return -ENODEV;
	}

	if (IS_ERR(device_create(sdma_class, NULL, devno, NULL, "sdma%u", idx))) {
		spin_unlock(&hisi_sdma_core_device.device_lock);
		dev_err(&psdma_dev->pdev->dev, "device_create failed\n");
		cdev_del(cdev);
		return -ENODEV;
	}

	hisi_sdma_core_device.sdma_device_num++;
	spin_unlock(&hisi_sdma_core_device.device_lock);

	return 0;
}

static void sdma_device_delete(struct hisi_sdma_device *psdma_dev)
{
	if (hisi_sdma_core_device.sdma_device_num == 0)
		return;

	spin_lock(&hisi_sdma_core_device.device_lock);
	device_destroy(sdma_class, MKDEV(hisi_sdma_core_device.sdma_major, psdma_dev->idx));
	cdev_del(&psdma_dev->cdev);
	hisi_sdma_core_device.sdma_device_num--;
	hisi_sdma_core_device.sdma_devices[psdma_dev->idx] = NULL;
	spin_unlock(&hisi_sdma_core_device.device_lock);
}

static int of_sdma_collect_info(struct platform_device *pdev, struct hisi_sdma_device *psdma_dev)
{
	struct resource *res;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		dev_err(&pdev->dev, "get io_base info from dtb failed\n");
		return -ENOMEM;
	}
	psdma_dev->base_addr = res->start;
	psdma_dev->base_addr_size = resource_size(res);
	if (psdma_dev->base_addr_size < psdma_dev->nr_channel * HISI_SDMA_CHANNEL_IOMEM_SIZE ||
	    psdma_dev->base_addr_size > HISI_SDMA_MAX_BASE_ADDR_SIZE) {
		dev_err(&pdev->dev, "io reg size wrong!\n");
		return -EFAULT;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (res == NULL) {
		dev_err(&pdev->dev, "get common reg info from dtb failed\n");
		return -ENOMEM;
	}
	psdma_dev->common_base_addr = res->start;
	psdma_dev->common_base_addr_size = resource_size(res);
	if (psdma_dev->common_base_addr_size != HISI_SDMA_MAX_COMMEN_BASE_ADDR_SIZE) {
		dev_err(&pdev->dev, "global io reg size wrong!\n");
		return -EFAULT;
	}

	psdma_dev->irq_cnt = platform_irq_count(pdev);
	if (psdma_dev->irq_cnt < 0 || psdma_dev->irq_cnt > SDMA_IRQ_NUM_MAX) {
		dev_err(&pdev->dev, "Get irq_cnt failed!\n");
		return -EINVAL;
	}
	dev_dbg(&pdev->dev, "get irq_cnt:%d\n", psdma_dev->irq_cnt);

	return 0;
}

static int parse_sdma(struct hisi_sdma_device *psdma_dev, struct platform_device *pdev)
{
	u32 nr_channel;

	if (device_property_read_u32(&pdev->dev, "sdma-chn-num", &nr_channel)) {
		pr_err("ACPI sdma-chn-num get failed!\n");
		return -EINVAL;
	} else {
		if (nr_channel <= HISI_STARS_CHN_NUM || nr_channel >
		    HISI_SDMA_DEFAULT_CHANNEL_NUM + HISI_STARS_CHN_NUM) {
			pr_err("ACPI sdma-chn-num = %u not as required\n", nr_channel);
			return -EINVAL;
		}
		psdma_dev->nr_channel = (u16)(nr_channel - HISI_STARS_CHN_NUM);
	}

	return 0;
}

static int sdma_init_device_info(struct hisi_sdma_device *psdma_dev)
{
	int ret;

	psdma_dev->io_orig_base = ioremap(psdma_dev->base_addr, psdma_dev->base_addr_size);
	if (!psdma_dev->io_orig_base) {
		dev_err(&psdma_dev->pdev->dev, "remap io reg failed!\n");
		return -EFAULT;
	}

	psdma_dev->common_base = ioremap(psdma_dev->common_base_addr,
					 psdma_dev->common_base_addr_size);
	if (!psdma_dev->common_base) {
		iounmap(psdma_dev->io_orig_base);
		dev_err(&psdma_dev->pdev->dev, "remap io common base failed!\n");
		return -EFAULT;
	}
	psdma_dev->io_base = psdma_dev->io_orig_base + HISI_SDMA_CH_OFFSET;
	ret = sdma_init_channels(psdma_dev);
	if (ret < 0) {
		iounmap(psdma_dev->common_base);
		iounmap(psdma_dev->io_orig_base);
		return ret;
	}

	ret = sdma_irq_init(psdma_dev);
	if (ret < 0) {
		sdma_destroy_channels(psdma_dev);
		iounmap(psdma_dev->common_base);
		iounmap(psdma_dev->io_orig_base);
		return ret;
	}

	return 0;
}

static void sdma_deinit_device_info(struct hisi_sdma_device *psdma_dev)
{
	sdma_irq_deinit(psdma_dev);
	sdma_destroy_channels(psdma_dev);
	iounmap(psdma_dev->common_base);
	iounmap(psdma_dev->io_orig_base);
}

static int sdma_smmu_enable(struct device *dev)
{
	int ret;

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_IOPF);
	if (ret) {
		dev_err(dev, "failed to enable IOPF feature! ret = %d\n", ret);
		return ret;
	}

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		dev_err(dev, "failed to enable SVA feature! ret = %d\n", ret);
		iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_IOPF);
		return ret;
	}

	return 0;
}

static int sdma_device_probe(struct platform_device *pdev)
{
	struct hisi_sdma_device *psdma_dev;
	u32 device_num;
	int node_id;
	int ret;

	device_num = hisi_sdma_core_device.sdma_device_num;
	if (!node_online(pdev->dev.numa_node)) {
		pr_info("numa_node %d not online, register sdma%u failed\n", pdev->dev.numa_node,
			device_num);
		node_id = 0;
	} else
		node_id = pdev->dev.numa_node;

	psdma_dev = kzalloc_node(sizeof(*psdma_dev), GFP_KERNEL, node_id);
	if (!psdma_dev)
		return -ENOMEM;

	psdma_dev->idx = device_num;
	psdma_dev->node_idx = node_id;
	ret = parse_sdma(psdma_dev, pdev);
	if (ret < 0)
		goto free_dev;

	psdma_dev->pdev = pdev;
	dev_set_drvdata(&pdev->dev, psdma_dev);

	ret = of_sdma_collect_info(pdev, psdma_dev);
	if (ret < 0) {
		dev_err(&psdma_dev->pdev->dev, "collect device info failed, %d\n", ret);
		goto free_dev;
	}

	ret = sdma_init_device_info(psdma_dev);
	if (ret < 0)
		goto free_dev;

	ret = sdma_smmu_enable(&pdev->dev);
	if (ret)
		goto deinit_device;

	psdma_dev->streamid = pdev->dev.iommu->fwspec->ids[0];
	spin_lock_init(&psdma_dev->channel_lock);
	hash_init(psdma_dev->sdma_pid_ref_ht);
	spin_lock_init(&psdma_dev->pid_lock);

	ret = sdma_device_add(psdma_dev);
	if (ret)
		goto sva_device_shutdown;

	dev_info(&pdev->dev, "sdma%u registered\n", psdma_dev->idx);

	return 0;

sva_device_shutdown:
	sdma_clear_pid_ref(psdma_dev);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
deinit_device:
	sdma_deinit_device_info(psdma_dev);
free_dev:
	kfree(psdma_dev);

	return ret;
}

static int sdma_device_remove(struct platform_device *pdev)
{
	struct hisi_sdma_device *psdma_dev = dev_get_drvdata(&pdev->dev);

	sdma_device_delete(psdma_dev);
	sdma_clear_pid_ref(psdma_dev);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
	sdma_deinit_device_info(psdma_dev);
	dev_info(&pdev->dev, "sdma%u removed\n", psdma_dev->idx);

	kfree(psdma_dev);

	return 0;
}

static const struct acpi_device_id sdma_acpi_match[] = {
	{ "HISI0431", 0 },
	{}
};
MODULE_DEVICE_TABLE(acpi, sdma_acpi_match);

static struct platform_driver sdma_driver = {
	.probe    = sdma_device_probe,
	.remove   = sdma_device_remove,
	.driver   = {
		.name             = HISI_SDMA_DEVICE_NAME,
		.acpi_match_table = sdma_acpi_match,
	},
};

static long sdma_create_debugfs(void)
{
	long ret;

	/* Create dbgfs dir */
	sdma_dbgfs_dir = debugfs_create_dir(BASE_DIR, NULL);
	if (IS_ERR(sdma_dbgfs_dir)) {
		pr_err("Couldn't create debugfs dir /sys/kernel/debug/%s\n", BASE_DIR);
		return PTR_ERR(sdma_dbgfs_dir);
	}
	/* Create dbgfs nodes */
	ret = sdma_create_dbg_node(sdma_dbgfs_dir);
	if (ret < 0) {
		pr_err("Couldn't create sdma debug node file, ret = %ld\n", ret);
		debugfs_remove_recursive(sdma_dbgfs_dir);
		return ret;
	}

	return 0;
}

static int __init sdma_driver_init(void)
{
	dev_t sdma_dev;
	long ret;

	ida_init(&fd_ida);
	sdma_info_sync_cdev(&hisi_sdma_core_device, &share_chns, &fd_ida, &safe_mode);
	sdma_info_sync_dbg(&hisi_sdma_core_device, &share_chns);

	sdma_class = class_create(THIS_MODULE, "sdma");
	if (IS_ERR(sdma_class)) {
		pr_err("class_create() failed for sdma_class: %ld\n", PTR_ERR(sdma_class));
		goto destroy_ida;
	}
	ret = alloc_chrdev_region(&sdma_dev, 0, HISI_SDMA_MAX_DEVS, "sdma");
	if (ret < 0) {
		pr_err("alloc_chrdev_region() failed for sdma\n");
		goto destroy_class;
	}
	spin_lock_init(&hisi_sdma_core_device.device_lock);
	hisi_sdma_core_device.sdma_major = MAJOR(sdma_dev);
	ret = sdma_create_debugfs();
	if (ret != 0)
		goto unregister_chrdev;

	ret = platform_driver_register(&sdma_driver);
	if (ret) {
		pr_err("sdma platform_driver_register failed!\n");
		goto remove_debugfs;
	}

	if (sdma_hash_init()) {
		pr_err("sdma_hash alloc failed!\n");
		goto unregister_driver;
	}

	if (sdma_authority_hash_init()) {
		pr_err("sdma_authority_hash alloc failed!\n");
		goto umem_hash_free;
	}

	return 0;

umem_hash_free:
	sdma_hash_free();
unregister_driver:
	platform_driver_unregister(&sdma_driver);
remove_debugfs:
	debugfs_remove_recursive(sdma_dbgfs_dir);
unregister_chrdev:
	unregister_chrdev_region(sdma_dev, HISI_SDMA_MAX_DEVS);
destroy_class:
	class_destroy(sdma_class);
destroy_ida:
	ida_destroy(&fd_ida);

	return -ENODEV;
}

static void __exit sdma_driver_exit(void)
{
	sdma_authority_ht_free();
	sdma_hash_free();
	platform_driver_unregister(&sdma_driver);
	debugfs_remove_recursive(sdma_dbgfs_dir);

	unregister_chrdev_region(MKDEV(hisi_sdma_core_device.sdma_major, 0), HISI_SDMA_MAX_DEVS);
	class_destroy(sdma_class);
	ida_destroy(&fd_ida);
}

module_init(sdma_driver_init);
module_exit(sdma_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("SDMA data accelerator engine for Userland applications");
