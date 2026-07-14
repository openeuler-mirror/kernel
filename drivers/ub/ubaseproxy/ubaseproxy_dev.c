// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_cmd.h>

#include "ubaseproxy_dev.h"

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "enable ubaseproxy debug log: 0:disable, others:enable, default:0");

int ubaseproxy_dbg_log(void)
{
	return debug;
}
