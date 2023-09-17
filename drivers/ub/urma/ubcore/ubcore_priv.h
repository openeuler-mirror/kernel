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
 * Description: ubcore's private data structure and function declarations
 * Author: Qian Guoxin
 * Create: 2022-7-22
 * Note:
 * History: 2022-7-22: Create file
 */

#ifndef UBCORE_PRIV_H
#define UBCORE_PRIV_H

#include <linux/jhash.h>
#include <urma/ubcore_types.h>

static inline struct ubcore_ucontext *ubcore_get_uctx(struct ubcore_udata *udata)
{
	return udata == NULL ? NULL : udata->uctx;
}

static inline bool ubcore_check_dev_name_invalid(struct ubcore_device *dev, char *dev_name)
{
	return (strcmp(dev->dev_name, dev_name) != 0);
}

/* Caller must put device */
struct ubcore_device *ubcore_find_device(union ubcore_eid *eid, enum ubcore_transport_type type);
void ubcore_get_device(struct ubcore_device *dev);
void ubcore_put_device(struct ubcore_device *dev);

/* Must call ubcore_put_devices to put and release the returned devices */
struct ubcore_device **ubcore_get_devices_from_netdev(struct net_device *netdev, uint32_t *cnt);
void ubcore_put_devices(struct ubcore_device **devices, uint32_t cnt);
void ubcore_set_default_eid(struct ubcore_device *dev);

static inline uint32_t ubcore_get_jetty_hash(const struct ubcore_jetty_id *jetty_id)
{
	return jhash(jetty_id, sizeof(struct ubcore_jetty_id), 0);
}

#endif
