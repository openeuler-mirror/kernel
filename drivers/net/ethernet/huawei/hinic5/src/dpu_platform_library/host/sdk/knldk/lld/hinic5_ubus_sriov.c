/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ubus_sriov.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifdef __UBUS_DRIVER__
#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/interrupt.h>

#include "ossl_knl.h"
#include "hinic5_hwdev.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#ifndef __WIN__
#include "hinic5_lld.h"
#include "hinic5_dev_mgmt.h"
#endif
#include "hinic5_ubus_sriov.h"
#include "hinic5_ubus.h"

static int ub_get_totalvds(hinic_ub_dev *udev)
{
#ifdef UB_SUPPORT_ENTITY
	if (!udev->is_mue)
		return 0;

	return udev->total_ues;
#else
	if (!udev->is_pd)
		return 0;

	return udev->total_vds;
#endif
}

static int ub_num_vdevice(hinic_ub_dev *udev)
{
#ifdef UB_SUPPORT_ENTITY
	if (!udev->is_mue)
		return 0;

	return udev->num_ues;
#else
	if (!udev->is_pd)
		return 0;

	return udev->num_vds;
#endif
}

static void hinic5_ubus_event_callback_dev(struct hinic5_sriov_info *sriov_info, void *hwdev, int num_vfs)
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

int hinic5_ubus_init_func_mbox_channel(void *hwdev)
{
	/* mbox msg channel resources will be freed during remove process */
	return hinic5_init_func_mbox_msg_channel(hwdev,
						hinic5_func_max_vf(hwdev));
}

int hinic5_ubus_init_vf_hw(void *hwdev, u16 start_vf_id, u16 end_vf_id)
{
	u16 i, func_idx;
	int err;

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

int hinic5_ubus_sriov_enable(hinic_ub_dev *ubus_dev, int ue_idx)
{
	int err, pre_existing_vfs;
	struct hinic5_adev *adev = dev_get_drvdata(&ubus_dev->dev);
	void *hwdev = adev->hwdev;
	struct hinic5_sriov_info *sriov_info = &adev->sriov_info;
	u32 tmp_vf_id = ue_idx - sriov_info->first_ue_idx;

	if (!hwdev) {
		sdk_err(&ubus_dev->dev, "hwdev is null\n");
		return -EPERM;
	}

	if (test_and_set_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state)) {
		sdk_err(&ubus_dev->dev,
			"SR-IOV enable in process, please wait, ue_idx %d\n", ue_idx);
		return -EPERM;
	}

	pre_existing_vfs = ub_num_vdevice(ubus_dev);
	if ((pre_existing_vfs + 1) > ub_get_totalvds(ubus_dev)) {
		clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
		return -ERANGE;
	}

	/* If not first enable, do not reinitialize FUNC MAILBOX channel */
	if (!sriov_info->sriov_enabled) {
		err = hinic5_ubus_init_func_mbox_channel(hwdev);
		sriov_info->first_ue_idx = ue_idx;
		if (err != 0) {
			clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
			return err;
		}
	}

	err = hinic5_ubus_init_vf_hw(hwdev, tmp_vf_id, tmp_vf_id);
	if (err != 0) {
		sdk_err(&ubus_dev->dev,
			"Failed to init vf in hardware before enable sriov, error %d\n", err);
		clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
		return err;
	}

	err = HINIC_UB_ENABLE_VDEV(ubus_dev, ue_idx);
	if (err != 0) {
		sdk_err(&ubus_dev->dev, "Failed to enable SR-IOV, error %d\n", err);
		clear_bit(HINIC5_SRIOV_ENABLE, &sriov_info->state);
		return err;
	}

	hinic5_ubus_event_callback_dev(sriov_info, hwdev, (pre_existing_vfs + 1));
	return 0;
}

int hinic5_ubus_sriov_disable(hinic_ub_dev *ubus_dev, int ue_idx)
{
	struct hinic5_adev *adev = dev_get_drvdata(&ubus_dev->dev);
	struct hinic5_sriov_info *sriov_info = &adev->sriov_info;
	struct hinic5_event_info event = {0};
	void *hwdev = adev->hwdev;
	u32 tmp_vf_id = ue_idx - sriov_info->first_ue_idx;
	int err, pre_existing_vfs;

	if (!hwdev) {
		sdk_err(&ubus_dev->dev, "SR-IOV disable is not permitted, please wait...\n");
		return -EPERM;
	}

	/* if SR-IOV is already disabled then there is nothing to do */
	if (!sriov_info->sriov_enabled)
		return 0;

	if (test_and_set_bit(HINIC5_SRIOV_DISABLE, &sriov_info->state)) {
		sdk_err(&ubus_dev->dev, "SR-IOV disable in process, please wait");
		return -EPERM;
	}

	/* If our VFs are assigned we cannot shut down SR-IOV
	 * without causing issues, so just leave the hardware
	 * available but disabled
	 */
	// todo, VFs in VM，cannot disable directly

	pre_existing_vfs = ub_num_vdevice(ubus_dev);
	event.service = EVENT_SRV_COMM;
	event.type = EVENT_COMM_SRIOV_STATE_CHANGE;
	((struct hinic5_sriov_state_info *)(void *)event.event_data)->enable = 0;
	((struct hinic5_sriov_state_info *)(void *)event.event_data)->vf_id = tmp_vf_id;
	((struct hinic5_sriov_state_info *)(void *)event.event_data)->num_vfs =
									(u16)(pre_existing_vfs - 1);
	hinic5_event_callback(hwdev, &event);

	/* disable iov and allow time for transactions to clear */
	err = HINIC_UB_DISABLE_VDEV(ubus_dev, ue_idx);
	if (err != 0) {
		sdk_err(&ubus_dev->dev, "Failed to disable SR-IOV, error %d\n", err);
		clear_bit(HINIC5_SRIOV_DISABLE, &sriov_info->state);
		return err;
	}

	sriov_info->num_vfs = pre_existing_vfs - 1;

	if (sriov_info->num_vfs == 0)
		sriov_info->sriov_enabled = 0;
	clear_bit(HINIC5_SRIOV_DISABLE, &sriov_info->state);
	return 0;
}

/*
	UBUS sriov implementation differs from PCIE, UBUS supports dynamic vf number modification
	1) pcie needs echo 2 --> echo 0 --> echo 3, ubus does not,
		ub_dev maintains vdevice list with start_vf_idx and end_vf_idx
	2) pcie echo only calls driver interface once per echo,
		decides how many vfs to enable based on vf_num parameter;
		ubus echo calls driver interface multiple times based on vf_num
 */
int hinic5_ubus_virt_configure(hinic_ub_dev *ubus_dev, int ue_idx, bool is_en)
{
	struct hinic5_sriov_info *sriov_info = NULL;
	struct hinic5_adev *adev = dev_get_drvdata(&ubus_dev->dev);

	if (!adev)
		return -EFAULT;

	sriov_info = &adev->sriov_info;

	if (!sriov_info)
		return -EFAULT;

	if (!test_bit(HINIC5_FUNC_PERSENT, &sriov_info->state))
		return -EFAULT;

	/* The ubus framework have ensure that only primary entity can come
	 * here, so we not need to check is this a primary entity again.
	 */
	dev_info(&ubus_dev->dev, "ubase virt configure set idx = %d en = %d.\n",
		 ue_idx, is_en);

	if (!is_en)
		return hinic5_ubus_sriov_disable(ubus_dev, ue_idx);
	else
		return hinic5_ubus_sriov_enable(ubus_dev, ue_idx);
}
#endif
