/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_sdk_attack.c
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
#include "hinic5_fast_msg.h"
#include "hinic5_comm_cmd.h"
#include "hinic5_cmdq.h"
#include "fast_msg_common_define.h"
#include "hinic5_sdk_attack.h"

/* Current macro & structure & enum definition needs to be consistent with tools, see sdk_attack.h */
#define SDK_ATTACK_DW_CNT 512
typedef struct sdk_attack_info {
	u32 type;
	u32 dw_cnt;
	union {
		u32 data[SDK_ATTACK_DW_CNT];                   // Default max support attack 2K Bytes
		hisdk5_fast_msg_header attack_fastmsg_header;  // fast_msg header type 16Bytes
	};
} sdk_attack_info_t;

typedef enum sdk_attack_opcode {
	SDK_ATTACK_FASTMSG = 0,
	SDK_ATTACK_INVALID_OPCODE = 0xFF
} sdk_attack_opcode_e;

/* Attack interface, fastmsg en interception removed */
int hinic5_attack_fast_msg(void *hwdev, struct hinic5_cmd_buf *cmd_buf, u64 *out_param)
{
	struct hinic5_hwdev *dev = hwdev;
	int err;
	u32 fast_msg_qid = HINIC5_CMDQ_FAST_MSG;

	if (!hwdev || !cmd_buf || !out_param) {
		err = -EINVAL;
		goto fail;
	}

	if (dev->glb_attr.cmdq_num < fast_msg_qid) {
		err = -EPERM;
		goto fail;
	}

	/* When cmdq number equals 2, fast_msg uses async queue */
	if (dev->glb_attr.cmdq_num == fast_msg_qid) {
		fast_msg_qid = HINIC5_CMDQ_ASYNC;
	}

	err = hinic5_cos_id_detail_resp(hwdev,
					HINIC5_MOD_COMM, COMM_CMD_UCODE_FAST_MSG_CMD,
					HINIC5_CMDQ_FAST_MSG, cmd_buf, cmd_buf,
					out_param, 0, HINIC5_CHANNEL_COMM);
	if (!hinic5_is_chip_present(dev)) {
		err = -ETIMEDOUT;
		goto fail;
	}

	if (err != 0) {
		goto fail;
	}

	return 0;

fail:
	sdk_err(dev->dev_hdl, "Failed to send fast msg, ret = 0x%x\n", err);
	return err;
}

int hinic5_sdk_attack_handler(struct hinic5_lld_dev *lld_dev, const void *buf_in,
			      u32 in_size, void *buf_out, u32 *out_size)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)lld_dev->hwdev;
	struct hinic5_cmd_buf *cmd_buf = NULL;
	sdk_attack_info_t *attack_info = (sdk_attack_info_t *)buf_in;
	u32 attack_len = attack_info->dw_cnt * sizeof(u32);
	u32 i = 0;
	int ret = 0;

	switch (attack_info->type) {
	case SDK_ATTACK_FASTMSG:
		cmd_buf = hinic5_alloc_cmd_buf(lld_dev->hwdev);
		if (!cmd_buf) {
			sdk_err(hwdev->dev_hdl, "Failed to allocate cmd buf\n");
			return -ENOMEM;
		}
		memset(cmd_buf->buf, 0, cmd_buf->size);
		memcpy(cmd_buf->buf, &attack_info->attack_fastmsg_header,
		       attack_len);
		sdk_info(hwdev->dev_hdl, "attack dw cnt %d\n", attack_info->dw_cnt);
		for (; i < attack_info->dw_cnt; i++)
			sdk_info(hwdev->dev_hdl,
				 "fastmsg[dw%d]:0x%08x\n", i, ((u32 *)cmd_buf->buf)[i]);
		cmd_buf->size = sizeof(hisdk5_fast_msg_header) +
					attack_info->attack_fastmsg_header.data_len;
		hinic5_cpu_to_be32(cmd_buf->buf, cmd_buf->size);
		ret = hinic5_attack_fast_msg(lld_dev->hwdev, cmd_buf, buf_out);
		if (ret != 0)
			sdk_info(hwdev->dev_hdl, "fastmsg err ret %d\n", ret);
		hinic5_free_cmd_buf(lld_dev->hwdev, cmd_buf);
		break;
	default:
		break;
	}
	return ret;
}
