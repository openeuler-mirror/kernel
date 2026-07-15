/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_fast_msg.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>

#include "comm_defs.h"
#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_cqm_fast_msg.h"

s32 hinic5_cqm_fast_msg_create_q(void *ex_handle, u32 queue_num, u32 sq_depth, u32 rq_depth)
{
	return 0;
}
EXPORT_SYMBOL(hinic5_cqm_fast_msg_create_q);

s32 hinic5_cqm_fast_msg_connect(void *ex_handle, struct dest_info *des_info, resp_func *rsp, recv_func *recv)
{
	return 0;
}
EXPORT_SYMBOL(hinic5_cqm_fast_msg_connect);

s32 hinic5_cqm_fast_msg_close(void *ex_handle, u64 msg_id)
{
	return 0;
}
EXPORT_SYMBOL(hinic5_cqm_fast_msg_close);

s32 hinic5_cqm_fast_msg_listen(void *ex_handle, u32 credit, resp_func *rsp, recv_func *recv)
{
	return 0;
}
EXPORT_SYMBOL(hinic5_cqm_fast_msg_listen);

s32 hinic5_cqm_fast_msg_send(void *ex_handle, u64 msg_id, struct dest_info *des_info, u8 *buf_res)
{
	return 0;
}
EXPORT_SYMBOL(hinic5_cqm_fast_msg_send);

static int hinic5_cqm_fast_msg_pf_handler(void *pri_handle, u16 vf_id, u16 cmd, void *buf_in, u16 in_size, void *buf_out,
	u16 *out_size)
{
#define SPU_HOST_ID 4

	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)pri_handle;
	void *ppf_hw_dev = NULL;
	int ret;

	if (!hwdev)
		return -EINVAL;

	ppf_hw_dev = hinic5_get_ppf_hw_dev_unsafe(pri_handle);
	if (!ppf_hw_dev) {
		pr_err("hinic5_cqm_fast_msg_pf_handler ppf is null.\n");
		return -EINVAL;
	}

	sdk_info(hwdev->dev_hdl, "hinic5_cqm_fast_msg_pf_handler recv vf 0x%x mbox, cmd: 0x%x\n",
		 vf_id, cmd);

	ret = hinic5_mbox_ppf_to_host(ppf_hw_dev, HINIC5_MOD_FAKE_FMSG, 0,
				      SPU_HOST_ID, buf_in, in_size, buf_out,
				      out_size, 0, HINIC5_CHANNEL_UB);
	if (ret != 0) {
		pr_err("hinic5_cqm_fast_msg_pf_handler failed send msg to host %u ret:%d\n",
		       SPU_HOST_ID, ret);
		return ret;
	}
	return 0;
}

static struct hinic5_hwdev *get_pf_dev_by_ppf(struct hinic5_hwdev *ppf_hwdev, bool hold, u16 pf_id)
{
	struct hinic5_adev *adev = NULL;
	struct card_node *chip_node = NULL;
	struct hinic5_adev *dev = NULL;

	if (!ppf_hwdev)
		return NULL;

	adev = ppf_hwdev->adapter_hdl;
	if (!adev)
		return NULL;

	hinic5_lld_hold();
	chip_node = adev->chip_node;
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (dev->hwdev && hinic5_global_func_id(dev->hwdev) == pf_id) {
			if (hold)
				hinic5_lld_dev_hold(&dev->lld_dev);
			hinic5_lld_put();
			return dev->hwdev;
		}
	}
	hinic5_lld_put();

	return NULL;
}

static int hinic5_cqm_fast_msg_ppf_handler(void *pri_handle, u16 pf_idx, u16 vf_id, u16 cmd, void *buf_in, u16 in_size, void *buf_out,
					   u16 *out_size)
{
#define SDI_PPF_ID 16
#define HOST_PF_ID 2
#define SPU_HOST_VFID 64U

	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)pri_handle;
	struct hinic5_hwdev *pf_hwdev = NULL;
	fast_msg_t *msg = (fast_msg_t *)buf_in;
	u16 ppf_id;
	int ret = 0;

	if (!hwdev)
		return -EINVAL;

	ppf_id = hinic5_global_func_id(hwdev);
	if (ppf_id == SDI_PPF_ID) {
		pr_err("hinic5_cqm_fast_msg_ppf_handler channel error, src: 0x%x cmd: 0x%x.\n",
		       pf_idx, cmd);
	} else {
		pf_hwdev = get_pf_dev_by_ppf(hwdev, false, HOST_PF_ID);
		if (!pf_hwdev) {
			pr_err("hinic5_cqm_fast_msg_ppf_handler pf hwdev is null\n");
			return -EFAULT;
		}
		ret = hinic5_mbox_to_vf(pf_hwdev, msg->dst_fe_idx - SPU_HOST_VFID + 1u,
					HINIC5_MOD_FAKE_FMSG, 0, buf_in,
					in_size, buf_out, out_size, 0, HINIC5_CHANNEL_UB);
	}
	return ret;
}

s32 hinic5_cqm_init_fast_msg(void *hwdev)
{
	struct hinic5_hwdev *hw_dev = (struct hinic5_hwdev *)hwdev;

	if (HINIC5_IS_PPF(hw_dev))
		hinic5_register_ppf_mbox_cb(hwdev, HINIC5_MOD_FAKE_FMSG, hwdev,
					    hinic5_cqm_fast_msg_ppf_handler);
	if (HINIC5_IS_PF(hw_dev))
		hinic5_register_pf_mbox_cb(hwdev, HINIC5_MOD_FAKE_FMSG, hwdev,
					   hinic5_cqm_fast_msg_pf_handler);
	return 0;
}

void hinic5_cqm_deinit_fast_msg(void *hwdev)
{
	struct hinic5_hwdev *hw_dev = (struct hinic5_hwdev *)hwdev;

	if (HINIC5_IS_PPF(hw_dev))
		hinic5_unregister_ppf_mbox_cb(hwdev, HINIC5_MOD_FAKE_FMSG);

	if (HINIC5_IS_PF(hw_dev))
		hinic5_unregister_pf_mbox_cb(hwdev, HINIC5_MOD_FAKE_FMSG);
}
