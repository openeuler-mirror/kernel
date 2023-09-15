// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: kmod ub data path API
 * Author: sunfang
 * Create: 2023-05-09
 * Note:
 * History: 2023-05-09
 */
#include <stddef.h>
#include "ubcore_log.h"
#include <urma/ubcore_api.h>
#include <urma/ubcore_opcode.h>
#include <urma/ubcore_types.h>

int ubcore_rearm_jfc(struct ubcore_jfc *jfc, bool solicited_only)
{
	struct ubcore_ops *dev_ops;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
	    jfc->ub_dev->ops->rearm_jfc == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jfc->ub_dev->ops;
	return dev_ops->rearm_jfc(jfc, solicited_only);
}
EXPORT_SYMBOL(ubcore_rearm_jfc);
