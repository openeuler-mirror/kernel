/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_non_ptp.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include "ossl_knl.h"
#include "hinic5_lld.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_chip_info.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_nictool.h"
#include "hinic5_non_ptp.h"

#if !defined(__UEFI__) && !defined(__VMWARE__) && !defined(__WIN__)
/* all chip's non ptp info saved buffer, PAGE_SIZE aligned */
#define NON_PTP_INFO_SIZE (CARD_MAX_SIZE * sizeof(struct hinic5_non_ptp_info))
#define NON_PTP_BUF_SIZE ((NON_PTP_INFO_SIZE / PAGE_SIZE + 1) * PAGE_SIZE)
#define NON_PTP_BUF_PAGE_ORDER (get_order(NON_PTP_BUF_SIZE))
#define HINIC5_NON_PTP_CDEV "hinic5_non_ptp_cdev"
#define HINIC5_NON_PTP_CLASS "hinic5_non_ptp_class"
/* for calculate time diff of kernel and chip, influenced by EMU/FPGA/ASIC/EDA,
 * default at ASIC condition is 1, can be modified with dfx tools
 */
unsigned int g_freq_reduce_ratio = 1;
/* for multiple hosts, cdev is created on different hosts */
/* for multiple chips, cdev is reffered by different chips */
atomic_t g_non_ptp_cdev_ref_cnt = ATOMIC_INIT(0);
/* create one global cdev for all chip on current host/vm */
static struct hinic5_non_ptp_cdev *g_non_ptp_cdev;
/* all chip's non ptp info saved page base addr, index is chip_id, on current host/vm */
static struct hinic5_non_ptp_info *g_non_ptp_info;

static int hinic5_non_ptp_mmap(struct file *filp, struct vm_area_struct *vma)
{
	ulong pfn;
	ulong offset = vma->vm_pgoff << PAGE_SHIFT;
	ulong size = vma->vm_end - vma->vm_start;

	if (offset + size > NON_PTP_BUF_SIZE)
		return -EINVAL;

	if (!g_non_ptp_info)
		return -EFAULT;
	/* Map the base address of no_ptp_info, offset 0 corresponds to chip_id 0 */
	pfn = virt_to_phys(g_non_ptp_info) >> PAGE_SHIFT;

	// Force read-only
	vm_flags_clear(vma, VM_WRITE);

	// Set nocache
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static const struct file_operations fops = {
	.mmap = hinic5_non_ptp_mmap,
};

static int hinic5_non_ptp_mem_alloc(struct hinic5_hwdev *hwdev)
{
	/* On first load, initialize cdev memory and ptp info memory */
	if (atomic_read(&g_non_ptp_cdev_ref_cnt) > 0)
		return 0;

	g_non_ptp_cdev =
		kzalloc(sizeof(struct hinic5_non_ptp_cdev), GFP_KERNEL);
	if (!g_non_ptp_cdev) {
		sdk_err(hwdev->dev_hdl, "non_ptp_cdev mem alloc fail.\n");
		return -ENOMEM;
	}

	g_non_ptp_info =
		(struct hinic5_non_ptp_info *)
		(uintptr_t)__get_free_pages(GFP_KERNEL, NON_PTP_BUF_PAGE_ORDER);
	if (!g_non_ptp_info) {
		sdk_err(hwdev->dev_hdl, "non_ptp_info mem alloc fail.\n");
		kfree(g_non_ptp_cdev);
		g_non_ptp_cdev = NULL;
		return -ENOMEM;
	}
	return 0;
}

static void hinic5_non_ptp_mem_free(void)
{
	if (atomic_read(&g_non_ptp_cdev_ref_cnt) > 0)
		return;

	/* When no references, free non ptp info page and cdev memory */
	if (g_non_ptp_info) {
		free_pages((ulong)(uintptr_t)g_non_ptp_info, NON_PTP_BUF_PAGE_ORDER);
		g_non_ptp_info = NULL;
	}

	if (g_non_ptp_cdev) {
		kfree(g_non_ptp_cdev);
		g_non_ptp_cdev = NULL;
	}
}

static int hinic5_non_ptp_info_init(struct hinic5_hwdev *hwdev, u32 chip_id)
{
	struct card_node *chip_node = (struct card_node *)hwdev->chip_node;

	/* Initialize non_ptp_info for current chip */
	if (!chip_node->non_ptp_info) {
		chip_node->non_ptp_info = g_non_ptp_info + chip_id;
		memcpy(chip_node->non_ptp_info->name,
		       chip_node->chip_name, IFNAMSIZ);
		atomic_set(&chip_node->non_ptp_info->ref_cnt, 0);
	}

	atomic_inc(&chip_node->non_ptp_info->ref_cnt);

	return 0;
}

static void hinic5_non_ptp_info_deinit(struct card_node *chip_node)
{
	/* Initialize non_ptp_info for current chip */
	if (!chip_node->non_ptp_info)
		return;

	if (atomic_read(&chip_node->non_ptp_info->ref_cnt) == 0)
		return;

	/* After ref_cnt decrements by 1, if not 0, interface returns false, early return */
	if (!atomic_sub_and_test(1, &chip_node->non_ptp_info->ref_cnt))
		return;

	memset(chip_node->non_ptp_info, 0, sizeof(struct hinic5_non_ptp_info));
	chip_node->non_ptp_info = NULL;
}

static int hinic5_non_ptp_para_check(struct hinic5_hwdev *hwdev, u32 *chip_id)
{
	struct card_node *chip_node = NULL;
	int err;
	if ((!hwdev) || (!HINIC5_IS_PPF(hwdev)))
		return -EINVAL;

	chip_node = (struct card_node *)hwdev->chip_node;
	if (!chip_node)
		return -EINVAL;

	/* Get chip number for indexing non ptp information */
	err = sscanf(chip_node->chip_name, HINIC5_CHIP_NAME "%u", chip_id);
	if (err != 1) {
		sdk_err(hwdev->dev_hdl, "Failed to get card id err %d.\n", err);
		return -EINVAL;
	}

	if (*chip_id >= MAX_CARD_NUM) {
		sdk_err(hwdev->dev_hdl, "Invalid card id %d.\n", *chip_id);
		return -EINVAL;
	}

	return 0;
}

static int hinic5_non_ptp_ctrl_init(struct hinic5_hwdev *hwdev)
{
	int err;

	/* first chip create cdev, region, class */
	err = alloc_chrdev_region(&g_non_ptp_cdev->devid, 0,
				  HINIC5_NON_PTP_CDEV_MAX_DEVICES,
				  HINIC5_NON_PTP_CDEV);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Alloc non ptp cdev region failed %d.\n",
			err);
		return err;
	}

	/* Create equipment */
	g_non_ptp_cdev->cdev_class = class_create(THIS_MODULE, HINIC5_NON_PTP_CLASS);
	if (IS_ERR(g_non_ptp_cdev->cdev_class)) {
		sdk_err(hwdev->dev_hdl, "Create non ptp class fail %ld.\n",
			PTR_ERR(g_non_ptp_cdev->cdev_class));
		err = -EFAULT;
		goto class_create_err;
	}

	// Initialize cdev structure
	cdev_init(&g_non_ptp_cdev->dev, &fops);
	g_non_ptp_cdev->dev.owner = THIS_MODULE;

	// Add cdev to system
	err = cdev_add(&g_non_ptp_cdev->dev, g_non_ptp_cdev->devid,
		       HINIC5_NON_PTP_CDEV_MAX_DEVICES);
	if (err < 0) {
		sdk_err(hwdev->dev_hdl,
			"Add non ptp cdev to operating system fail %d\n", err);
		goto cdev_add_err;
	}

	g_non_ptp_cdev->cdev_device = device_create(g_non_ptp_cdev->cdev_class, NULL,
						    g_non_ptp_cdev->devid, NULL,
						    HINIC5_NON_PTP_CDEV);
	if (IS_ERR(g_non_ptp_cdev->cdev_device)) {
		sdk_err(hwdev->dev_hdl,
			"Export non ptp cdev information to user space fail\n");
		err = -EFAULT;
		goto device_create_err;
	}

	return 0;

device_create_err:
	cdev_del(&g_non_ptp_cdev->dev);
cdev_add_err:
	class_destroy(g_non_ptp_cdev->cdev_class);
class_create_err:
	unregister_chrdev_region(g_non_ptp_cdev->devid,
				 HINIC5_NON_PTP_CDEV_MAX_DEVICES);
	return err;
}

static void hinic5_non_ptp_ctrl_deinit(void)
{
	if (atomic_read(&g_non_ptp_cdev_ref_cnt) > 0)
		return;

	if (!g_non_ptp_cdev)
		return;
	device_destroy(g_non_ptp_cdev->cdev_class, g_non_ptp_cdev->devid);
	cdev_del(&g_non_ptp_cdev->dev);
	class_destroy(g_non_ptp_cdev->cdev_class);
	unregister_chrdev_region(g_non_ptp_cdev->devid,
				 HINIC5_NON_PTP_CDEV_MAX_DEVICES);
}

/* non ptp function initialization main function */
int hinic5_non_ptp_cdev_init(struct hinic5_hwdev *hwdev)
{
	int err;
	u32 chip_id;
	struct card_node *chip_node = (struct card_node *)hwdev->chip_node;

	sdk_info(hwdev->dev_hdl, "init non ptp start %d.\n", atomic_read(&g_non_ptp_cdev_ref_cnt));

	err = hinic5_non_ptp_para_check(hwdev, &chip_id);
	if (err != 0)
		return err;

	err = hinic5_non_ptp_mem_alloc(hwdev);
	if (err != 0)
		return err;

	err = hinic5_non_ptp_info_init(hwdev, chip_id);
	if (err != 0)
		goto info_init_err;

	if (atomic_read(&g_non_ptp_cdev_ref_cnt) > 0) {
		atomic_inc(&g_non_ptp_cdev_ref_cnt);
		sdk_info(hwdev->dev_hdl,
			 "non ptp cdev exist,  cdev refcnt %d, chip refcnt %d.\n",
			 atomic_read(&g_non_ptp_cdev_ref_cnt),
			 atomic_read(&chip_node->non_ptp_info->ref_cnt));
		return 0;
	}

	/* The following process only involves first initialization */
	atomic_inc(&g_non_ptp_cdev_ref_cnt);

	/* Initialize non ptp cdev class region and device */
	err = hinic5_non_ptp_ctrl_init(hwdev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Create non ptp sys device fail.\n");
		goto ctrl_init_err;
	}

	sdk_info(hwdev->dev_hdl,
		 "Init non ptp end cdev refcnt %d, chip refcnt %d.\n",
		 atomic_read(&g_non_ptp_cdev_ref_cnt),
		 atomic_read(&chip_node->non_ptp_info->ref_cnt));
	return 0;

ctrl_init_err:
	atomic_set(&g_non_ptp_cdev_ref_cnt, 0);
	hinic5_non_ptp_info_deinit(chip_node);

info_init_err:
	hinic5_non_ptp_mem_free();
	return err;
}

/* non ptp function deinitialization main function */
void hinic5_non_ptp_cdev_deinit(struct hinic5_hwdev *hwdev)
{
	struct card_node *chip_node = NULL;

	if (!hwdev || !HINIC5_IS_PPF(hwdev))
		return;

	chip_node = (struct card_node *)hwdev->chip_node;
	if (!chip_node || !chip_node->non_ptp_info) {
		sdk_info(hwdev->dev_hdl,
			 "Exit non ptp deinit, refcnt %d.\n", atomic_read(&g_non_ptp_cdev_ref_cnt));
		return;
	}
	/* Destroy non ptp info managed by current function's chip */
	hinic5_non_ptp_info_deinit(chip_node);

	/* After ref_cnt decrements by 1, if not 0, interface returns false, early return */
	if (!atomic_sub_and_test(1, &g_non_ptp_cdev_ref_cnt)) {
		sdk_info(hwdev->dev_hdl,
			 "Quick deinit non ptp end %d.\n", atomic_read(&g_non_ptp_cdev_ref_cnt));
		return;
	}

	/* Try to destroy non ptp system device, class, region, etc */
	hinic5_non_ptp_ctrl_deinit();

	hinic5_non_ptp_mem_free();
	sdk_info(hwdev->dev_hdl, "Deinit non ptp end %d.\n", atomic_read(&g_non_ptp_cdev_ref_cnt));
}

int hinic5_get_non_ptp_chip_time(void *dev, u64 *chip_time)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)dev;
	int err;

	if (!hwdev || !chip_time)
		return -EINVAL;

	err = hinic5_n_ptp_ts_up_en(hwdev, BIT(1));
	if (err != 0) {
		sdk_warn(hwdev->dev_hdl, "Failed to get n_ptp time, err: %d\n", err);
		return err;
	}

	err = hinic5_read_n_ptp_ts_data(hwdev, chip_time);
	if (err != 0) {
		sdk_warn(hwdev->dev_hdl, "Failed to read n_ptp time, err: %d\n", err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_get_non_ptp_chip_time);

int hinic5_sync_kernel_time(struct hinic5_hwdev *hwdev)
{
	int err;
	u64 kernel_time, chip_time;
	struct card_node *chip_node = (struct card_node *)(hwdev->chip_node);

	if (!chip_node || !chip_node->non_ptp_info)
		return 0;

	if (g_freq_reduce_ratio == 0) {
		sdk_warn(hwdev->dev_hdl, "The frequency scaling ratio must be greater than zero.\n");
		return -EPERM;
	}

	err = hinic5_get_non_ptp_chip_time(hwdev, &chip_time);
	if (err != 0) {
		sdk_warn(hwdev->dev_hdl, "Failed to read n_ptp time, err: %d\n", err);
		return err;
	}

	kernel_time = ktime_get_ns() / g_freq_reduce_ratio;
	chip_node->non_ptp_info->non_ptp_time_diff = (kernel_time > chip_time ?
		(kernel_time - chip_time) : -(chip_time - kernel_time));
	return err;
}

/* valid dev can get the chip time diff */
int hinic5_get_non_ptp_time_diff(void *dev, s64 *time_diff)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)dev;
	struct card_node *chip_node = NULL;

	if (!hwdev || !time_diff)
		return -EINVAL;

	chip_node = (struct card_node *)(hwdev->chip_node);
	if (!chip_node || !chip_node->non_ptp_info) {
		sdk_warn(hwdev->dev_hdl, "chip_node is NULL\n");
		return -EINVAL;
	}

	if (chip_node->non_ptp_info->non_ptp_time_diff_enable != 0) {
		*time_diff = chip_node->non_ptp_info->non_ptp_time_diff;
		return 0;
	}
	sdk_warn(hwdev->dev_hdl, "non ptp time diff is disable\n");
	return -EINVAL;
}
EXPORT_SYMBOL(hinic5_get_non_ptp_time_diff);

/* only support ppf dev to set the ratio */
int hinic5_set_freq_reduce_ratio(void *dev, u32 ratio)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)dev;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_func_type(hwdev) != TYPE_PPF)
		return -EPERM;

	if (ratio == 0)
		return -EINVAL;

	g_freq_reduce_ratio = ratio;
	sdk_info(hwdev->dev_hdl, "set freq reduce ratio %d\n", ratio);
	return 0;
}
EXPORT_SYMBOL(hinic5_set_freq_reduce_ratio);

/* only support ppf dev to turn on/off the switch */
int hinic5_set_non_ptp_time_diff_en(void *dev, bool enable)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)dev;
	struct card_node *chip_node = NULL;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_func_type(hwdev) != TYPE_PPF)
		return -EPERM;

	chip_node = (struct card_node *)(hwdev->chip_node);
	if (!chip_node || !chip_node->non_ptp_info)
		return -EINVAL;

	if (enable == chip_node->non_ptp_info->non_ptp_time_diff_enable)
		return 0;

	chip_node->non_ptp_info->non_ptp_time_diff_enable = enable;
	if (enable) {
		/* When switching from disable to enable, need to queue work */
		queue_delayed_work(hwdev->workq, &hwdev->sync_kernel_time_task,
				   msecs_to_jiffies(HINIC5_NON_PTP_SYNC_FW_TIME_PERIOD));
		sdk_info(hwdev->dev_hdl, "enable non ptp time diff\n");
	} else {
		chip_node->non_ptp_info->non_ptp_time_diff = 0;
		sdk_info(hwdev->dev_hdl, "disable non ptp time diff\n");
	}
	return 0;
}
EXPORT_SYMBOL(hinic5_set_non_ptp_time_diff_en);

#endif
