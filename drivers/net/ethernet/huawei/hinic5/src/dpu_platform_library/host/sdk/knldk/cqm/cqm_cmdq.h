/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_cmdq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM CMDQ header
 */

#ifndef CQM_CMDQ_H
#define CQM_CMDQ_H

#include "ossl_knl.h"
#include "cqm_npu_cmd_defs.h"
#include "cqm_main.h"

struct cqm_cmdq_ops {
	s32 (*prepare_cmd_buf_bat_update)(struct tag_cqm_handle *cqm_handle,
					  struct tag_cqm_cmd_buf *buf_in,
					  struct tag_cqm_bat_update_param *param,
					  u8 *cmd);
	void (*prepare_cmd_buf_cla_update)(cqm_cla_update_cmd_s *cmd_info,
					 struct tag_cqm_cmd_buf *buf_in, u8 *cmd);
	void (*prepare_cmd_cache_invalidate)(cqm_cla_cache_invalid_cmd_s *cmd_info,
					   struct tag_cqm_cmd_buf *buf_in, u8 *cmd);
};

struct cqm_cmdq_ops *cqm_cmdq_get_182x_ops(void);
struct cqm_cmdq_ops *cqm_cmdq_get_187x_ops(void);

void cqm_cmdq_adapt_init(struct tag_cqm_handle *cqm_handle);
#endif
