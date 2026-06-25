/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cmdq_adapt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include "hinic5_nic_cmdq.h"

void hinic5_nic_cmdq_adapt_init(struct hinic5_nic_io *nic_io)
{
	if (!HINIC5_SUPPORT_FEATURE(nic_io->hwdev, HTN_CMDQ))
		nic_io->cmdq_ops = hinic5_nic_cmdq_get_182x_ops();
	else
		nic_io->cmdq_ops = hinic5_nic_cmdq_get_187x_ops();
}
