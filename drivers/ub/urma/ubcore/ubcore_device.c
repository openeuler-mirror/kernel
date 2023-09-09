// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Description: ubcore device add and remove ops file
 * Author: Qian Guoxin
 * Create: 2021-08-03
 * Note:
 * History: 2021-08-03: create file
 */

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/dma-mapping.h>
#include <linux/uaccess.h>

#include <urma/ubcore_uapi.h>
#include "ubcore_log.h"
#include "ubcore_priv.h"

static LIST_HEAD(g_client_list);
static LIST_HEAD(g_device_list);

/*
 * g_device_mutex and g_lists_rwsem protect both g_device_list and g_client_list.
 * g_device_mutex protects writer access by device and client
 * g_lists_rwsem protects reader access to these lists.
 * Iterators of these lists must lock it for read, while updates
 * to the lists must be done with a write lock.
 */
static DEFINE_MUTEX(g_device_mutex);
static DECLARE_RWSEM(g_lists_rwsem);

struct ubcore_device *ubcore_find_device(union ubcore_eid *eid, enum ubcore_transport_type type)
{
	struct ubcore_device *dev, *target = NULL;

	mutex_lock(&g_device_mutex);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (memcmp(&dev->attr.eid, eid, sizeof(union ubcore_eid)) == 0 &&
		    dev->transport_type == type) {
			target = dev;
			ubcore_get_device(target);
			break;
		}
	}
	mutex_unlock(&g_device_mutex);
	return target;
}

struct ubcore_device **ubcore_get_devices_from_netdev(struct net_device *netdev, uint32_t *cnt)
{
	struct ubcore_device **devices;
	struct ubcore_device *dev;
	uint32_t i = 0;

	mutex_lock(&g_device_mutex);
	list_for_each_entry(dev, &g_device_list, list_node) {
		/* Assume netdev is related to the first and only port */
		if (dev->netdev == netdev)
			i++;
	}

	if (i == 0) {
		*cnt = 0;
		mutex_unlock(&g_device_mutex);
		return NULL;
	}

	devices = kzalloc(i * sizeof(struct ubcore_device *), GFP_ATOMIC);
	if (devices == NULL) {
		*cnt = 0;
		mutex_unlock(&g_device_mutex);
		return NULL;
	}

	*cnt = i;
	i = 0;
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->netdev == netdev) {
			ubcore_get_device(dev);
			devices[i] = dev;
			i++;
		}
	}
	mutex_unlock(&g_device_mutex);
	return devices;
}

void ubcore_put_devices(struct ubcore_device **devices, uint32_t cnt)
{
	uint32_t i;

	if (devices == NULL)
		return;

	for (i = 0; i < cnt; i++)
		ubcore_put_device(devices[i]);

	kfree(devices);
}

void ubcore_get_device(struct ubcore_device *dev)
{
	if (IS_ERR_OR_NULL(dev)) {
		ubcore_log_err("Invalid parameter");
		return;
	}

	atomic_inc(&dev->use_cnt);
}

void ubcore_put_device(struct ubcore_device *dev)
{
	if (IS_ERR_OR_NULL(dev)) {
		ubcore_log_err("Invalid parameter");
		return;
	}

	if (atomic_dec_and_test(&dev->use_cnt))
		complete(&dev->comp);
}

int ubcore_set_eid(struct ubcore_device *dev, union ubcore_eid *eid)
{
	int ret;

	if (dev == NULL || eid == NULL || dev->ops == NULL || dev->ops->set_eid == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->set_eid(dev, *eid);
	if (ret != 0) {
		ubcore_log_err("failed to set eid, ret: %d.\n", ret);
		return -EPERM;
	}
	dev->attr.eid = *eid;
	return 0;
}
EXPORT_SYMBOL(ubcore_set_eid);
