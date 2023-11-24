/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _KBOX_INCLUDE_H_
#define _KBOX_INCLUDE_H_

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netdevice.h>

#ifdef DRV_VERSION
#define KBOX_VERSION MICRO_TO_STR(DRV_VERSION)
#else
#define KBOX_VERSION "0.3.6"
#endif

#define UNUSED(x) (x = x)
#define KBOX_FALSE (-1)
#define KBOX_TRUE 0

#ifdef KBOX_DEBUG
#define KBOX_MSG(fmt, args...) \
	netdev_notice(0, "kbox: %s(), %d, " fmt, __func__, __LINE__, ## args)
#else
#define KBOX_MSG(fmt, args...)
#endif

#endif
