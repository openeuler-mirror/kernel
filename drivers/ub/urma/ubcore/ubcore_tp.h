/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: ubcore tp header
 * Author: Yan Fangfang
 * Create: 2022-09-08
 * Note:
 * History: 2022-09-208: Create file
 */

#ifndef UBCORE_TP_H
#define UBCORE_TP_H

#include <urma/ubcore_types.h>
#include "ubcore_netlink.h"

static inline bool ubcore_have_tp_ops(const struct ubcore_device *dev)
{
	return (dev != NULL && dev->ops->create_tp != NULL && dev->ops->modify_tp != NULL &&
		dev->ops->destroy_tp != NULL);
}
#endif
