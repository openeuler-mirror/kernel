// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/dma-iommu.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include <linux/device.h>

#include "sdma_hal.h"

struct ida fd_ida;
struct hisi_sdma_core_device hisi_sdma_core_device = {0};
static struct class *sdma_class;

static int sdma_device_add(struct hisi_sdma_device *psdma_dev)
{
	u32 idx = psdma_dev->idx;
	struct cdev *cdev = NULL;
	u32 sdma_minor;
	int devno;
	int ret;

	if (idx >= HISI_SDMA_MAX_DEVS) {
		pr_err("Exceeded the maximum number of devices\n");
		goto out_err;
	}

	sdma_minor = idx;
	hisi_sdma_core_device.sdma_devices[idx] = psdma_dev;
	cdev = &hisi_sdma_core_device.sdma_devices[idx]->cdev;
	devno = MKDEV(hisi_sdma_core_device.sdma_major, sdma_minor);

	sdma_cdev_init(cdev);
	ret = cdev_add(cdev, devno, 1);
	if (ret) {
		pr_err("Error %d adding sdma", ret);
		goto out_err;
	}

	if (IS_ERR(device_create(sdma_class, NULL, devno, NULL, "sdma%u", idx))) {
		pr_err("device_create failed\n");
		cdev_del(cdev);
		goto out_err;
	}

	hisi_sdma_core_device.sdma_device_num++;

	return 0;

out_err:
	return -ENODEV;
}

static void sdma_device_delete(struct hisi_sdma_device *psdma_dev)
{
	if (hisi_sdma_core_device.sdma_device_num == 0)
		return;

	hisi_sdma_core_device.sdma_device_num--;
	hisi_sdma_core_device.sdma_devices[psdma_dev->idx] = NULL;
}

static int of_sdma_collect_info(struct platform_device *pdev, struct hisi_sdma_device *psdma_dev)
{
	struct resource *res;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		pr_err("get io_base info from dtb failed\n");
		return -ENOMEM;
	}
	psdma_dev->base_addr = res->start;
	psdma_dev->base_addr_size = resource_size(res);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (res == NULL) {
		pr_err("get common reg info from dtb failed\n");
		return -ENOMEM;
	}
	psdma_dev->common_base_addr = res->start;
	psdma_dev->common_base_addr_size = resource_size(res);

	return 0;
}

static int parse_sdma(struct hisi_sdma_device *psdma_dev, struct platform_device *pdev)
{
	u32 nr_channel;

	if (device_property_read_u32(&pdev->dev, "sdma-chn-num", &nr_channel)) {
		pr_err("ACPI sdma-chn-num get failed!\n");
		psdma_dev->nr_channel = HISI_SDMA_DEFAULT_CHANNEL_NUM;
	} else {
		if (nr_channel <= HISI_STARS_CHN_NUM) {
			pr_err("ACPI sdma-chn-num = %u is insufficient\n", nr_channel);
			return -1;
		}
		psdma_dev->nr_channel = (u16)(nr_channel - HISI_STARS_CHN_NUM);
	}

	return 0;
}

static int sdma_init_device_info(struct hisi_sdma_device *psdma_dev)
{
	int ret;

	psdma_dev->io_orig_base = ioremap(psdma_dev->base_addr, psdma_dev->base_addr_size);
	if (!psdma_dev->io_orig_base)
		return -ENOMEM;

	psdma_dev->common_base = ioremap(psdma_dev->common_base_addr,
					 psdma_dev->common_base_addr_size);
	if (!psdma_dev->common_base) {
		iounmap(psdma_dev->io_orig_base);
		return -ENOMEM;
	}
	psdma_dev->io_base = psdma_dev->io_orig_base + HISI_SDMA_CH_OFFSET;

	return 0;
}

static int sdma_smmu_enable(struct device *dev)
{
	int ret;

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_IOPF);
	if (ret) {
		pr_err("failed to enable IOPF feature! ret = %p\n", ERR_PTR(ret));
		return ret;
	}

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		pr_err("failed to enable SVA feature! ret = %p\n", ERR_PTR(ret));
		iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_IOPF);
		return ret;
	}

	return 0;
}

static int sdma_device_probe(struct platform_device *pdev)
{
	struct hisi_sdma_device *psdma_dev;
	u32 device_num;
	int ret;

	device_num = hisi_sdma_core_device.sdma_device_num;
	psdma_dev = kzalloc_node(sizeof(*psdma_dev), GFP_KERNEL, pdev->dev.numa_node);
	if (!psdma_dev)
		return -ENOMEM;

	psdma_dev->idx = device_num;
	psdma_dev->node_idx = pdev->dev.numa_node;
	ret = parse_sdma(psdma_dev, pdev);
	if (ret < 0)
		goto free_dev;

	psdma_dev->pdev = pdev;
	dev_set_drvdata(&pdev->dev, psdma_dev);

	ret = of_sdma_collect_info(pdev, psdma_dev);
	if (ret < 0) {
		pr_err("collect device info failed, %d\n", ret);
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

	ret = sdma_device_add(psdma_dev);
	if (ret)
		goto sva_device_shutdown;

	dev_info(&pdev->dev, "sdma%d registered\n", psdma_dev->idx);

	return 0;

sva_device_shutdown:
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
deinit_device:
	iounmap(psdma_dev->common_base);
	iounmap(psdma_dev->io_orig_base);
free_dev:
	kfree(psdma_dev);

	return ret;
}

static int sdma_device_remove(struct platform_device *pdev)
{
	struct hisi_sdma_device *psdma_dev = dev_get_drvdata(&pdev->dev);

	sdma_device_delete(psdma_dev);
	device_destroy(sdma_class, MKDEV(hisi_sdma_core_device.sdma_major, psdma_dev->idx));
	cdev_del(&psdma_dev->cdev);

	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
	iounmap(psdma_dev->io_orig_base);
	iounmap(psdma_dev->common_base);

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

static void global_var_init(struct hisi_sdma_global_info *g_info)
{
	ida_init(&fd_ida);

	g_info->core_dev = &hisi_sdma_core_device;
	g_info->fd_ida = &fd_ida;
}

static int __init sdma_driver_init(void)
{
	struct hisi_sdma_global_info *g_info = NULL;
	dev_t sdma_dev;
	int ret;

	g_info = kcalloc(1, sizeof(struct hisi_sdma_global_info), GFP_KERNEL);
	if (!g_info)
		return -ENOMEM;

	global_var_init(g_info);
	sdma_info_sync_cdev(g_info);

	sdma_class = class_create(THIS_MODULE, "sdma");
	if (IS_ERR(sdma_class)) {
		pr_err("class_create() failed for sdma_class: %d\n", PTR_ERR(sdma_class));
		goto destroy_ida;
	}
	ret = alloc_chrdev_region(&sdma_dev, 0, HISI_SDMA_MAX_DEVS, "sdma");
	if (ret < 0) {
		pr_err("alloc_chrdev_region() failed for sdma\n");
		goto destroy_class;
	}
	hisi_sdma_core_device.sdma_major = MAJOR(sdma_dev);
	ret = platform_driver_register(&sdma_driver);
	if (ret)
		goto unregister_chrdev;

	kfree(g_info);

	return 0;

unregister_chrdev:
	unregister_chrdev_region(sdma_dev, HISI_SDMA_MAX_DEVS);
destroy_class:
	class_destroy(sdma_class);
destroy_ida:
	ida_destroy(&fd_ida);
	kfree(g_info);

	return -ENODEV;
}

static void __exit sdma_driver_exit(void)
{
	dev_t devno;

	platform_driver_unregister(&sdma_driver);

	devno = MKDEV(hisi_sdma_core_device.sdma_major, 0);
	unregister_chrdev_region(devno, HISI_SDMA_MAX_DEVS);
	class_destroy(sdma_class);
	ida_destroy(&fd_ida);
}

module_init(sdma_driver_init);
module_exit(sdma_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("SDMA data accelerator engine for Userland applications");
