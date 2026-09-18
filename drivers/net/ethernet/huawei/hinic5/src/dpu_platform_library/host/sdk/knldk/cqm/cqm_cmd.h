/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM command header
 */

#ifndef CQM_CMD_H
#define CQM_CMD_H

#include <linux/types.h>

#include "cqm_object.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#ifndef HI1825V100
#define CQM_CMD_TIMEOUT 10000 /* ms */
#else
#define CQM_CMD_TIMEOUT 1000000 /* ms */
#endif

struct tag_cqm_cmd_buf *cqm5_cmd_alloc(void *ex_handle);
void cqm5_cmd_free(void *ex_handle, struct tag_cqm_cmd_buf *cmd_buf);
s32 cqm5_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, struct tag_cqm_cmd_buf *buf_in,
		     struct tag_cqm_cmd_buf *buf_out, u64 *out_param, u32 timeout,
		     u16 channel);
s32 cqm5_lb_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, u8 cos_id,
			struct tag_cqm_cmd_buf *buf_in, struct tag_cqm_cmd_buf *buf_out,
			u64 *out_param, u32 timeout, u16 channel);
s32 cqm5_send_cmd_imm(void *ex_handle, u8 mod, u8 cmd, struct tag_cqm_cmd_buf *buf_in,
		     u64 *out_param, u32 timeout, u16 channel);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* CQM_CMD_H */
