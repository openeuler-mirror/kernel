/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_sriov.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/interrupt.h>

#include "ossl_knl.h"
#include "hinic5_hwdev.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#ifndef __WIN__
#include "hinic5_lld.h"
#include "hinic5_dev_mgmt.h"
#endif
#include "hinic5_sriov.h"

int hinic5_init_vf_hw(void *hwdev, u16 start_vf_id, u16 end_vf_id)
{
	u16 i, func_idx;
	int err;

	/* mbox msg channel resources will be freed during remove process */
	err = hinic5_init_func_mbox_msg_channel(hwdev,
						hinic5_func_max_vf(hwdev));
	if (err != 0)
		return err;

	/* vf use 256K as default wq page size, and can't change it */
	for (i = start_vf_id; i <= end_vf_id; i++) {
		func_idx = hinic5_glb_pf_vf_offset(hwdev) + i;
		err = hinic5_set_wq_page_size(hwdev, func_idx,
					      HINIC5_DEFAULT_WQ_PAGE_SIZE,
					      HINIC5_CHANNEL_COMM);
		if (err != 0)
			return err;
	}

	return 0;
}

#if !(defined(HAVE_SRIOV_CONFIGURE) || defined(HAVE_RHEL6_SRIOV_CONFIGURE)) && !defined(__WIN__)
ssize_t hinic5_sriov_totalvfs_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sprintf_s(buf, PAGE_SIZE, "%d\n", pci_sriov_get_totalvfs(pdev));
}

ssize_t hinic5_sriov_numvfs_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sprintf_s(buf, PAGE_SIZE, "%d\n", pci_num_vf(pdev));
}

ssize_t hinic5_sriov_numvfs_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int ret;
	u16 num_vfs;
	int cur_vfs, total_vfs;

	ret = kstrtou16(buf, 0, &num_vfs);
	if (ret < 0)
		return ret;

	cur_vfs = pci_num_vf(pdev);
	total_vfs = pci_sriov_get_totalvfs(pdev);
	if (num_vfs > total_vfs)
		return -ERANGE;

	if (num_vfs == cur_vfs)
		return count;    /* no change */

	if (num_vfs == 0) {
		/* disable VFs */
		ret = hinic5_pci_sriov_configure(pdev, 0);
		if (ret < 0)
			return ret;
		return count;
	}

	/* enable VFs */
	if (cur_vfs) {
		nic_warn(&pdev->dev, "%d VFs already enabled. Disable before enabling %d VFs\n",
			 cur_vfs, num_vfs);
		return -EBUSY;
	}

	ret = hinic5_pci_sriov_configure(pdev, num_vfs);
	if (ret < 0)
		return ret;

	if (ret != num_vfs)
		nic_warn(&pdev->dev, "%d VFs requested; only %d enabled\n",
			 num_vfs, ret);

	return count;
}
#endif /* !(HAVE_SRIOV_CONFIGURE || HAVE_RHEL6_SRIOV_CONFIGURE) */

#ifndef __WIN__
static void migration_uninit_vf(struct pci_dev *pdev)
{
#if (defined CONFIG_ARM) || (defined CONFIG_ARM64)
	void (*uninit_vfs)(struct pci_dev *) = __symbol_get("migration_dev_uninit_vfs");

	if (uninit_vfs) {
		uninit_vfs(pdev);
		__symbol_put("migration_dev_uninit_vfs");
	}
#endif
}

int hinic5_pci_sriov_disable(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	struct hinic5_sriov_info *sriov_info = NULL;
	struct hinic5_event_info event = {0};
	void *hwdev = NULL;

	sriov_info = hinic5_get_sriov_info_by_pcidev(dev);
	hwdev = hinic5_get_hwdev_by_pcidev(dev);
	if (!hwdev) {
		sdk_err(&dev->dev, "SR-IOV disable is not permitted, please wait...\n");
		return -EPERM;
	}

	/* if SR-IOV is already disabled then there is nothing to do */
	if (!sriov_info->sriov_enabled)
		return 0;

	if (test_and_set_bit(HINIC5_SRIOV_DISABLE, &sriov_info->state)) {
		sdk_err(&dev->dev, "SR-IOV disable in process, please wait");
		return -EPERM;
	}

	/* If our VFs are assigned we cannot shut down SR-IOV
	 * without causing issues, so just leave the hardware
	 * available but disabled
	 */
	if (pci_vfs_assigned(dev) != 0) {
		clear_bit(HINIC5_SRIOV_DISABLE, &sriov_info->state);
		sdk_warn(&dev->dev, "Unloading driver while VFs are assigned - VFs will not be deallocated\n");
		return -EPERM;
	}

	event.service = EVENT_SRV_COMM;
	event.type = EVENT_COMM_SRIOV_STATE_CHANGE;
	((struct hinic5_sriov_state_info *)(void *)event.event_data)->enable = 0;
	((struct hinic5_sriov_state_info *)(void *)event.event_data)->num_vfs = 0;
	hinic5_event_callback(hwdev, &event);

	sriov_info->sriov_enabled = false;

	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(dev);

	sriov_info->num_vfs = 0;

	clear_bit(HINIC5_SRIOV_DISABLE, &sriov_info->state);

	migration_uninit_vf(dev);
#endif

	return 0;
}

#ifdef CONFIG_PCI_IOV
#if (defined CONFIG_ARM) || (defined CONFIG_ARM64)
static int migration_init_vf(struct pci_dev *dev, int num_vfs, struct hinic5_sriov_info *sriov_info)
{
	int err = 0;
	int (*migration_dev_init_vfs)(struct pci_dev *dev, uint32_t num_vfs);

	migration_dev_init_vfs = __symbol_get("migration_dev_init_vfs");
	if (migration_dev_init_vfs) {
		sdk_warn(&dev->dev, "migration_dev_init_vfs is not NULL\n");
		err = migration_dev_init_vfs(dev, num_vfs);
		__symbol_put("migration_dev_init_vfs");
		if (err < 0) {
			pci_disable_sriov(dev);
			clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
			return err;
		}
	}
	return err;
}
#endif

static void hinic5_event_callback_dev(struct hinic5_sriov_info *sriov_info,
				      void *hwdev, int num_vfs)
{
	struct hinic5_event_info event = {0};
	sriov_info->sriov_enabled = true;

	sriov_info->num_vfs = (u32)num_vfs;

	event.service = EVENT_SRV_COMM;
	event.type = EVENT_COMM_SRIOV_STATE_CHANGE;
	((struct hinic5_sriov_state_info *)(void *)event.event_data)->enable = 1;
	((struct hinic5_sriov_state_info *)(void *)event.event_data)->num_vfs = (u16)num_vfs;
	hinic5_event_callback(hwdev, &event);

	clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
}
#endif

int hinic5_pci_sriov_enable(struct pci_dev *dev, int num_vfs)
{
#ifdef CONFIG_PCI_IOV
	int err, pre_existing_vfs;

	struct hinic5_sriov_info *sriov_info = hinic5_get_sriov_info_by_pcidev(dev);
	void *hwdev = hinic5_get_hwdev_by_pcidev(dev);

	if (!hwdev) {
		sdk_err(&dev->dev, "hwdev is null\n");
		return -EPERM;
	}

	if (test_and_set_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state)) {
		sdk_err(&dev->dev, "SR-IOV enable in process, please wait, num_vfs %d\n", num_vfs);
		return -EPERM;
	}

	pre_existing_vfs = pci_num_vf(dev);

	if (num_vfs > pci_sriov_get_totalvfs(dev)) {
		clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
		return -ERANGE;
	}
	if (pre_existing_vfs != 0 && pre_existing_vfs != num_vfs) {
		err = hinic5_pci_sriov_disable(dev);
		if (err != 0) {
			clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
			return err;
		}
	} else if (pre_existing_vfs == num_vfs) {
		clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
		return num_vfs;
	}

	err = hinic5_init_vf_hw(hwdev, 1, (u16)num_vfs);
	if (err != 0) {
		sdk_err(&dev->dev,
			"Failed to init vf in hardware before enable sriov, error %d\n", err);
		clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
		return err;
	}

	err = pci_enable_sriov(dev, num_vfs);
	if (err != 0) {
		sdk_err(&dev->dev, "Failed to enable SR-IOV, error %d\n", err);
		clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
		return err;
	}

#if (defined CONFIG_ARM) || (defined CONFIG_ARM64)
	err = migration_init_vf(dev, num_vfs, sriov_info);
	if (err < 0)
		return err;
#endif
	hinic5_event_callback_dev(sriov_info, hwdev, num_vfs);
	return num_vfs;
#else

	return 0;
#endif
}

void hinic5_pci_sriov_enable_ops(struct hinic5_adev *adev, int num_vfs)
{
	struct pci_dev *pdev = to_pci_dev(adev->dev);

	(void)hinic5_pci_sriov_enable(pdev, num_vfs);
}

int hinic5_pci_sriov_configure(struct pci_dev *dev, int num_vfs)
{
	struct hinic5_sriov_info *sriov_info = NULL;

	sriov_info = hinic5_get_sriov_info_by_pcidev(dev);
	if (!sriov_info)
		return -EFAULT;

	if (!test_bit(HINIC5_FUNC_PERSENT, &sriov_info->state))
		return -EFAULT;

	if (num_vfs == 0)
		return hinic5_pci_sriov_disable(dev);
	else
		return hinic5_pci_sriov_enable(dev, num_vfs);
}
#endif
