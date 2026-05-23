/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_CMD_H
#define HINIC5_CQM_CMD_H

#include <linux/types.h>

#include "hinic5_cqm_object.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#ifndef HI1825V100
#define HINIC5_CQM_CMD_TIMEOUT 10000 /* ms */
#else
#define HINIC5_CQM_CMD_TIMEOUT 1000000 /* ms */
#endif

struct tag_hinic5_cqm_cmd_buf *hinic5_cqm_cmd_alloc(void *ex_handle);
void hinic5_cqm_cmd_free(void *ex_handle, struct tag_hinic5_cqm_cmd_buf *cmd_buf);
s32 hinic5_cqm_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, struct tag_hinic5_cqm_cmd_buf *buf_in,
		     struct tag_hinic5_cqm_cmd_buf *buf_out, u64 *out_param, u32 timeout,
		     u16 channel);
s32 hinic5_cqm_lb_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, u8 cos_id,
			struct tag_hinic5_cqm_cmd_buf *buf_in, struct tag_hinic5_cqm_cmd_buf *buf_out,
			u64 *out_param, u32 timeout, u16 channel);
s32 hinic5_cqm_send_cmd_imm(void *ex_handle, u8 mod, u8 cmd, struct tag_hinic5_cqm_cmd_buf *buf_in,
		     u64 *out_param, u32 timeout, u16 channel);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* HINIC5_CQM_CMD_H */
