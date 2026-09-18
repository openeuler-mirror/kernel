/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_cmdq_adapt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM CMDQ adaptation implementation
 */

#include "cqm_cmdq.h"
#include "hinic5_hwdev.h"

void cqm_cmdq_adapt_init(struct tag_cqm_handle *cqm_handle)
{
	if (!COMM_SUPPORT_HTN_CMD(cqm_handle->ex_handle)) {
		cqm_handle->cmdq_ops = cqm_cmdq_get_182x_ops();
	} else {
		cqm_handle->cmdq_ops = cqm_cmdq_get_187x_ops();
	}
}
