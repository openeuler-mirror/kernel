// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/pci.h>
#include <linux/interrupt.h>

#include "sphw_common.h"
#include "sphw_crm.h"
#include "sphw_hw.h"
#include "spnic_lld.h"
#include "spnic_sriov.h"
#include "spnic_dev_mgmt.h"

int spnic_init_vf_hw(void *hwdev, u16 start_vf_id, u16 end_vf_id)
{
	u16 i, func_idx;
	int err;

	/* mbox msg channel resources will be freed during remove process */
	err = sphw_init_func_mbox_msg_channel(hwdev, sphw_func_max_vf(hwdev));
	if (err)
		return err;

	/* vf use 256K as default wq page size, and can't change it */
	for (i = start_vf_id; i <= end_vf_id; i++) {
		func_idx = sphw_glb_pf_vf_offset(hwdev) + i;
		err = sphw_set_wq_page_size(hwdev, func_idx, SPHW_DEFAULT_WQ_PAGE_SIZE,
					    SPHW_CHANNEL_COMM);
		if (err)
			return err;
	}

	return 0;
}

int spnic_deinit_vf_hw(void *hwdev, u16 start_vf_id, u16 end_vf_id)
{
	u16 func_idx, idx;

	for (idx = start_vf_id; idx <= end_vf_id; idx++) {
		func_idx = sphw_glb_pf_vf_offset(hwdev) + idx;
		sphw_set_wq_page_size(hwdev, func_idx, SPHW_HW_WQ_PAGE_SIZE, SPHW_CHANNEL_COMM);
	}

	return 0;
}

int spnic_pci_sriov_disable(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	struct spnic_sriov_info *sriov_info = NULL;
	struct sphw_event_info event = {0};
	void *hwdev = NULL;
	u16 tmp_vfs;

	sriov_info = spnic_get_sriov_info_by_pcidev(dev);
	hwdev = spnic_get_hwdev_by_pcidev(dev);
	if (!hwdev) {
		sdk_err(&dev->dev, "SR-IOV disable is not permitted, please wait...\n");
		return -EPERM;
	}

	/* if SR-IOV is already disabled then there is nothing to do */
	if (!sriov_info->sriov_enabled)
		return 0;

	if (test_and_set_bit(SPNIC_SRIOV_DISABLE, &sriov_info->state)) {
		sdk_err(&dev->dev, "SR-IOV disable in process, please wait");
		return -EPERM;
	}

	/* If our VFs are assigned we cannot shut down SR-IOV
	 * without causing issues, so just leave the hardware
	 * available but disabled
	 */
	if (pci_vfs_assigned(dev)) {
		clear_bit(SPNIC_SRIOV_DISABLE, &sriov_info->state);
		sdk_warn(&dev->dev, "Unloading driver while VFs are assigned - VFs will not be deallocated\n");
		return -EPERM;
	}

	event.type = SPHW_EVENT_SRIOV_STATE_CHANGE;
	event.sriov_state.enable = 0;
	sphw_event_callback(hwdev, &event);

	sriov_info->sriov_enabled = false;

	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(dev);

	tmp_vfs = (u16)sriov_info->num_vfs;
	sriov_info->num_vfs = 0;
	spnic_deinit_vf_hw(hwdev, 1, tmp_vfs);

	clear_bit(SPNIC_SRIOV_DISABLE, &sriov_info->state);

#endif

	return 0;
}

int spnic_pci_sriov_enable(struct pci_dev *dev, int num_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct spnic_sriov_info *sriov_info = NULL;
	struct sphw_event_info event = {0};
	void *hwdev = NULL;
	int pre_existing_vfs = 0;
	int err = 0;

	sriov_info = spnic_get_sriov_info_by_pcidev(dev);
	hwdev = spnic_get_hwdev_by_pcidev(dev);
	if (!hwdev) {
		sdk_err(&dev->dev, "SR-IOV enable is not permitted, please wait...\n");
		return -EPERM;
	}

	if (test_and_set_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state)) {
		sdk_err(&dev->dev, "SR-IOV enable in process, please wait, num_vfs %d\n",
			num_vfs);
		return -EPERM;
	}

	pre_existing_vfs = pci_num_vf(dev);

	if (num_vfs > pci_sriov_get_totalvfs(dev)) {
		clear_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state);
		return -ERANGE;
	}
	if (pre_existing_vfs && pre_existing_vfs != num_vfs) {
		err = spnic_pci_sriov_disable(dev);
		if (err) {
			clear_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state);
			return err;
		}
	} else if (pre_existing_vfs == num_vfs) {
		clear_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state);
		return num_vfs;
	}

	err = spnic_init_vf_hw(hwdev, 1, (u16)num_vfs);
	if (err) {
		sdk_err(&dev->dev, "Failed to init vf in hardware before enable sriov, error %d\n",
			err);
		clear_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state);
		return err;
	}

	err = pci_enable_sriov(dev, num_vfs);
	if (err) {
		sdk_err(&dev->dev, "Failed to enable SR-IOV, error %d\n", err);
		clear_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state);
		return err;
	}

	sriov_info->sriov_enabled = true;
	sriov_info->num_vfs = num_vfs;

	event.type = SPHW_EVENT_SRIOV_STATE_CHANGE;
	event.sriov_state.enable = 1;
	event.sriov_state.num_vfs = (u16)num_vfs;
	sphw_event_callback(hwdev, &event);

	clear_bit(SPNIC_SRIOV_ENABLE, &sriov_info->state);

	return num_vfs;
#else

	return 0;
#endif
}

static bool spnic_is_support_sriov_configure(struct pci_dev *pdev)
{
	/* TODO: get cap from firmware */

	return true;
}

int spnic_pci_sriov_configure(struct pci_dev *dev, int num_vfs)
{
	struct spnic_sriov_info *sriov_info = NULL;

	if (!spnic_is_support_sriov_configure(dev))
		return -EFAULT;

	sriov_info = spnic_get_sriov_info_by_pcidev(dev);
	if (!sriov_info)
		return -EFAULT;

	if (!test_bit(SPNIC_FUNC_PERSENT, &sriov_info->state))
		return -EFAULT;

	if (!num_vfs)
		return spnic_pci_sriov_disable(dev);
	else
		return spnic_pci_sriov_enable(dev, num_vfs);
}
