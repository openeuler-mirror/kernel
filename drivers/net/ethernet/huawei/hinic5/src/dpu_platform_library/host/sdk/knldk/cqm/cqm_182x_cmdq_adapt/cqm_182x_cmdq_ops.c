/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_182x_cmdq_ops.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM 182x CMDQ operations implementation
 */

#include "ossl_knl.h"
#include "hinic5_cqm.h"
#include "cqm_npu_cmd.h"
#include "cqm_cmdq.h"
#include "cqm_main.h"
#include "cqm_npu_cmd_defs.h"
#include "cqm_182x_cmdq_ops.h"

static s32 prepare_cmd_buf_bat_update(struct tag_cqm_handle *cqm_handle,
				      struct tag_cqm_cmd_buf *buf_in,
				      struct tag_cqm_bat_update_param *param,
				      u8 *cmd)
{
	struct tag_cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_182x_bat_update_cmd *cmd_data = buf_in->buf;
	u8 *bat = NULL;

	cmd_data->offset = param->bat_offset / CQM_BAT_ENTRY_SIZE;
	cmd_data->byte_len = param->update_size;
	cmd_data->smf_id = param->smf_id;
	cmd_data->func_id = param->func_id;

	bat = bat_table->bat + param->bat_offset;
	memcpy(cmd_data->data, bat, param->update_size);

	cqm_swab32((u8 *)cmd_data,
		   sizeof(struct cqm_182x_bat_update_cmd) >> CQM_DW_SHIFT);
	*cmd = (u8)CQM_CMD_T_BAT_UPDATE;

	return CQM_SUCCESS;
}

static void prepare_cmd_buf_cla_update(cqm_cla_update_cmd_s *cmd_info,
				       struct tag_cqm_cmd_buf *buf_in,
				       u8 *cmd)
{
	struct cqm_182x_cla_update_cmd *cmd_data = buf_in->buf;

	cmd_data->gpa_h = cmd_info->gpa_h;
	cmd_data->gpa_l = cmd_info->gpa_l;
	cmd_data->value_h = cmd_info->value_h;
	cmd_data->value_l = cmd_info->value_l;
	cmd_data->smf_id = cmd_info->smf_id;
	cmd_data->func_id = cmd_info->func_id;

	cqm_swab32((u8 *)cmd_data,
		   (sizeof(struct cqm_182x_cla_update_cmd) >> CQM_DW_SHIFT));
	*cmd = (u8) CQM_CMD_T_CLA_UPDATE;
}

static void prepare_cmd_cache_invalidate(cqm_cla_cache_invalid_cmd_s *cmd_info,
					 struct tag_cqm_cmd_buf *buf_in,
					 u8 *cmd)
{
	struct cqm_182x_cla_cache_invalid_cmd *cmd_data = buf_in->buf;

	cmd_data->gpa_h = cmd_info->gpa_h;
	cmd_data->gpa_l = cmd_info->gpa_l;
	cmd_data->cache_size = cmd_info->cache_size;
	cmd_data->smf_id = cmd_info->smf_id;
	cmd_data->func_id = cmd_info->func_id;

	cqm_swab32((u8 *)cmd_data,
		   /* shift 2 bits by right to get length of dw(4B) */
		   (sizeof(struct cqm_182x_cla_cache_invalid_cmd) >> CQM_DW_SHIFT));
	*cmd = (u8)CQM_CMD_T_CLA_CACHE_INVALID;
}

struct cqm_cmdq_ops *cqm_cmdq_get_182x_ops(void)
{
	static struct cqm_cmdq_ops cmdq_182x_ops = {
		.prepare_cmd_buf_bat_update = prepare_cmd_buf_bat_update,
		.prepare_cmd_buf_cla_update = prepare_cmd_buf_cla_update,
		.prepare_cmd_cache_invalidate = prepare_cmd_cache_invalidate,
	};

	return &cmdq_182x_ops;
};
