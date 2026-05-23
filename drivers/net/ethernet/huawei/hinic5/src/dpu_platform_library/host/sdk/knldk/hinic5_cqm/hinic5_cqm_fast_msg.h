/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_fast_msg.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_FAST_MSG_H
#define HINIC5_CQM_FAST_MSG_H

#include <linux/types.h>
#include <linux/module.h>

#include "ossl_knl.h"

struct dest_info {
	u32 func_id;
	u32 queue_id;
};

struct src_info {
	u32 func_id;
	u32 queue_id;
	u64 msg_id;
};

typedef struct fast_msg {
	u16 dst_fe_idx;
} fast_msg_t;

typedef s32 (resp_func)(u64 msg_id, u8 *buf_res, s32 result);
typedef s32 (recv_func)(struct src_info *src, u8 *buf_res);
s32 hinic5_cqm_fast_msg_create_q(void *ex_handle, u32 queue_num, u32 sq_depth, u32 rq_depth);
s32 hinic5_cqm_fast_msg_connect(void *ex_handle, struct dest_info *des_info, resp_func *rsp, recv_func *recv);
s32 hinic5_cqm_fast_msg_close(void *ex_handle, u64 msg_id);
s32 hinic5_cqm_fast_msg_listen(void *ex_handle, u32 credit, resp_func *rsp, recv_func *recv);
s32 hinic5_cqm_fast_msg_send(void *ex_handle, u64 msg_id, struct dest_info *des_info, u8 *buf_res);
s32 hinic5_cqm_init_fast_msg(void *hwdev);
void hinic5_cqm_deinit_fast_msg(void *hwdev);


#endif
