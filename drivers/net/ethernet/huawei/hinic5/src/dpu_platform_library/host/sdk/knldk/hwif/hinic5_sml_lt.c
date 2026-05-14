/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_sml_lt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "ossl_knl.h"
#include "hinic5_common.h"
#include "hinic5_sm_lt.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_api_cmd.h"
#include "hinic5_mgmt.h"

#define ACK 1
#define NOACK 0

#define LT_LOAD16_API_SIZE (16 + 4)
#define LT_STORE16_API_SIZE (32 + 4)

#ifndef HTONL
#define HTONL(x) \
	((((x) & 0x000000ff) << 24) \
	| (((x) & 0x0000ff00) << 8) \
	| (((x) & 0x00ff0000) >> 8) \
	| (((x) & 0xff000000) >> 24))
#endif

static inline void sm_lt_build_head(union sml_lt_req_head *head,
				    u8 instance_id,
				    u8 op_id, u8 ack)
{
	head->value = 0;
	head->bs.instance = instance_id;
	head->bs.op_id = op_id;
	head->bs.ack = ack;
	head->bs.num = 0;
	head->bs.abuf_flg = 0;
	head->bs.bc = 1;
	head->bs.offset = 0;
	head->value = HTONL((head->value));
}

static inline void sm_lt_load_build_req(struct sml_lt_load_req *req,
					u8 instance_id,
					u8 op_id, u8 ack,
					u32 lt_index)
{
	sm_lt_build_head(&req->head, instance_id, op_id, ack);
	req->extra = 0;
	req->index = lt_index;
	req->index = HTONL(req->index);
	req->pad0 = 0;
	req->pad1 = 0;
}

static void sml_lt_store_data(u32 *dst, const u32 *src, u8 num)
{
	u32 sm_lt_idx;

	if (num > SM_LT_NUM_2)
		return;
	for (sm_lt_idx = 0; sm_lt_idx <= num; sm_lt_idx++) {
		// 16Byte each
		u32 offset = sm_lt_idx * SM_LT_OFFSET_4;
		*(dst + SM_LT_OFFSET_3 + offset) = *(src + SM_LT_OFFSET_3 + offset);
		*(dst + SM_LT_OFFSET_2 + offset) = *(src + SM_LT_OFFSET_2 + offset);
		*(dst + SM_LT_OFFSET_1 + offset) = *(src + SM_LT_OFFSET_1 + offset);
		*(dst + offset) = *(src + offset);
	}
}

static inline void sm_lt_store_build_req(struct sml_lt_store_req *req,
					 u8 instance_id,
					 u8 op_id, u8 ack,
					 u32 lt_index,
					 u16 byte_enb1,
					 u8 *data)
{
	sm_lt_build_head(&req->head, instance_id, op_id, ack);
	req->index     = lt_index;
	req->index     = HTONL(req->index);
	req->extra = 0;
	req->byte_enb[0] = 0;
	req->byte_enb[0] = HTONL(req->byte_enb[0]);
	req->byte_enb[1] = HTONL(byte_enb1);
	sml_lt_store_data((u32 *)req->write_data, (u32 *)(void *)data, 0);
}

int hinic5_dbg_lt_rd_16byte(void *hwdev, u8 dest, u8 instance,
			    u32 lt_index, u8 *data)
{
	struct sml_lt_load_req req;
	int ret;

	if (!hwdev)
		return -EFAULT;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	sm_lt_load_build_req(&req, instance, SM_LT_LOAD, ACK, lt_index);

	ret = hinic5_api_cmd_read_ack(hwdev, dest, (u8 *)(&req),
				      LT_LOAD16_API_SIZE, (void *)data, 0x10);
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Read linear table 16byte fail, err: %d\n", ret);
		return -EFAULT;
	}

	return 0;
}

int hinic5_dbg_lt_wr_16byte_mask(void *hwdev, u8 dest, u8 instance,
				 u32 lt_index, u8 *data, u16 mask)
{
	struct sml_lt_store_req req;
	int ret;

	if (!hwdev || !data)
		return -EINVAL;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	sm_lt_store_build_req(&req, instance, SM_LT_STORE, NOACK, lt_index,
			      mask, data);

	ret = hinic5_api_cmd_write_nack(hwdev, dest, &req, LT_STORE16_API_SIZE);
	if (ret != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Write linear table 16byte fail, err: %d\n", ret);
		return -EFAULT;
	}

	return 0;
}

