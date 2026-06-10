// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubmgr entry implementation file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#include "../ubcore_log.h"
#include "ubmgr_ping.h"

#include "ubmgr.h"

int ubmgr_init(void)
{
	int ret;

	ret = ubmgr_ping_init();
	if (ret != 0) {
		ubcore_log_err("Failed to init ping, ret=%d\n", ret);
		return ret;
	}

	return ret;
}
