/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_cmdq_adapt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include "hinic5_cqm_cmdq.h"
#include "hinic5_hwdev.h"

void hinic5_cqm_cmdq_adapt_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	if (!COMM_SUPPORT_HTN_CMD(hinic5_cqm_handle->ex_handle)) {
		hinic5_cqm_handle->cmdq_ops = hinic5_cqm_cmdq_get_182x_ops();
	} else {
		hinic5_cqm_handle->cmdq_ops = hinic5_cqm_cmdq_get_187x_ops();
	}
}
