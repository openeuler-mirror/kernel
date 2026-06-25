/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_cmdq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_CMDQ_H
#define HINIC5_CQM_CMDQ_H

#include "ossl_knl.h"
#include "hinic5_cqm_npu_cmd_defs.h"
#include "hinic5_cqm_main.h"

struct hinic5_cqm_cmdq_ops {
	s32 (*prepare_cmd_buf_bat_update)(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					  struct tag_hinic5_cqm_cmd_buf *buf_in,
					  struct tag_hinic5_cqm_bat_update_param *param,
					  u8 *cmd);
	void (*prepare_cmd_buf_cla_update)(hinic5_cqm_cla_update_cmd_s *cmd_info,
					 struct tag_hinic5_cqm_cmd_buf *buf_in, u8 *cmd);
	void (*prepare_cmd_cache_invalidate)(hinic5_cqm_cla_cache_invalid_cmd_s *cmd_info,
					   struct tag_hinic5_cqm_cmd_buf *buf_in, u8 *cmd);
};

struct hinic5_cqm_cmdq_ops *hinic5_cqm_cmdq_get_182x_ops(void);
struct hinic5_cqm_cmdq_ops *hinic5_cqm_cmdq_get_187x_ops(void);

void hinic5_cqm_cmdq_adapt_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);
#endif
