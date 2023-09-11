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

#include "ubcore_log.h"
#include <urma/ubcore_uapi.h>
#include <urma/ubcore_api.h>
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

void ubcore_set_client_ctx_data(struct ubcore_device *dev, const struct ubcore_client *client,
				void *data)
{
	struct ubcore_client_ctx *ctx;
	unsigned long flags;

	spin_lock_irqsave(&dev->client_ctx_lock, flags);
	list_for_each_entry(ctx, &dev->client_ctx_list, list_node) {
		if (ctx->client == client) {
			ctx->data = data;
			goto out;
		}
	}
	ubcore_log_err("no client ctx found, device_name: %s, client_name: %s.\n", dev->dev_name,
		       client->client_name);

out:
	spin_unlock_irqrestore(&dev->client_ctx_lock, flags);
}
EXPORT_SYMBOL(ubcore_set_client_ctx_data);

void *ubcore_get_client_ctx_data(struct ubcore_device *dev, const struct ubcore_client *client)
{
	struct ubcore_client_ctx *found_ctx = NULL;
	struct ubcore_client_ctx *ctx, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&dev->client_ctx_lock, flags);
	list_for_each_entry_safe(ctx, tmp, &dev->client_ctx_list, list_node) {
		if (ctx->client == client) {
			found_ctx = ctx;
			break;
		}
	}

	if (found_ctx == NULL) {
		spin_unlock_irqrestore(&dev->client_ctx_lock, flags);
		ubcore_log_warn("no client ctx found, dev_name: %s, client_name: %s.\n",
				dev->dev_name, client->client_name);
		return NULL;
	}
	spin_unlock_irqrestore(&dev->client_ctx_lock, flags);

	return found_ctx->data;
}
EXPORT_SYMBOL(ubcore_get_client_ctx_data);

static struct ubcore_client_ctx *create_client_ctx(struct ubcore_device *dev,
						   struct ubcore_client *client)
{
	struct ubcore_client_ctx *ctx;
	unsigned long flags;

	ctx = kmalloc(sizeof(struct ubcore_client_ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->data = NULL;
	ctx->client = client;

	down_write(&g_lists_rwsem);
	spin_lock_irqsave(&dev->client_ctx_lock, flags);
	list_add(&ctx->list_node, &dev->client_ctx_list);
	spin_unlock_irqrestore(&dev->client_ctx_lock, flags);
	up_write(&g_lists_rwsem);

	return ctx;
}

static void destroy_client_ctx(struct ubcore_device *dev, struct ubcore_client_ctx *ctx)
{
	unsigned long flags;

	if (dev == NULL || ctx == NULL)
		return;

	down_write(&g_lists_rwsem);
	spin_lock_irqsave(&dev->client_ctx_lock, flags);
	list_del(&ctx->list_node);
	spin_unlock_irqrestore(&dev->client_ctx_lock, flags);
	up_write(&g_lists_rwsem);
	kfree(ctx);
}

int ubcore_register_client(struct ubcore_client *new_client)
{
	struct ubcore_device *dev;
	struct ubcore_client_ctx *ctx = NULL;

	mutex_lock(&g_device_mutex);

	list_for_each_entry(dev, &g_device_list, list_node) {
		ctx = create_client_ctx(dev, new_client);
		if (ctx == NULL)
			continue;

		if (new_client->add && new_client->add(dev) != 0) {
			destroy_client_ctx(dev, ctx);
			ubcore_log_err("ubcore client: %s register dev:%s failed.\n",
				       new_client->client_name, dev->dev_name);
		}
	}
	down_write(&g_lists_rwsem);
	list_add_tail(&new_client->list_node, &g_client_list);
	up_write(&g_lists_rwsem);

	mutex_unlock(&g_device_mutex);

	ubcore_log_info("ubcore client: %s register success.\n", new_client->client_name);
	return 0;
}
EXPORT_SYMBOL(ubcore_register_client);

void ubcore_unregister_client(struct ubcore_client *rm_client)
{
	struct ubcore_client_ctx *ctx, *tmp;
	struct ubcore_device *dev;
	unsigned long flags;

	mutex_lock(&g_device_mutex);

	down_write(&g_lists_rwsem);
	list_del(&rm_client->list_node);
	up_write(&g_lists_rwsem);

	list_for_each_entry(dev, &g_device_list, list_node) {
		struct ubcore_client_ctx *found_ctx = NULL;

		down_write(&g_lists_rwsem);
		spin_lock_irqsave(&dev->client_ctx_lock, flags);
		list_for_each_entry_safe(ctx, tmp, &dev->client_ctx_list, list_node) {
			if (ctx->client == rm_client) {
				found_ctx = ctx;
				break;
			}
		}
		spin_unlock_irqrestore(&dev->client_ctx_lock, flags);
		up_write(&g_lists_rwsem);

		if (found_ctx == NULL) {
			ubcore_log_warn("no client ctx found, dev_name: %s, client_name: %s.\n",
					dev->dev_name, rm_client->client_name);
			continue;
		}
		if (rm_client->remove)
			rm_client->remove(dev, found_ctx->data);

		destroy_client_ctx(dev, found_ctx);
		ubcore_log_info("dev remove client, dev_name: %s, client_name: %s.\n",
				dev->dev_name, rm_client->client_name);
	}

	mutex_unlock(&g_device_mutex);
	ubcore_log_info("ubcore client: %s unregister success.\n", rm_client->client_name);
}
EXPORT_SYMBOL(ubcore_unregister_client);

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

/* Find only, without get_device */
static struct ubcore_device *ubcore_find_device_with_name(const char *dev_name)
{
	struct ubcore_device *dev, *target = NULL;

	mutex_lock(&g_device_mutex);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (strcmp(dev->dev_name, dev_name) == 0) {
			target = dev;
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

static void ubcore_device_release(struct device *device)
{
}

static int init_ubcore_device(struct ubcore_device *dev)
{
	if (dev->ops->query_device_attr != NULL &&
	    dev->ops->query_device_attr(dev, &dev->attr) != 0) {
		ubcore_log_err("Failed to query device attributes");
		return -1;
	}

	device_initialize(&dev->dev);
	dev_set_drvdata(&dev->dev, dev);
	dev_set_name(&dev->dev, "%s", dev->dev_name);
	dev->dev.release = ubcore_device_release;

	INIT_LIST_HEAD(&dev->list_node);
	spin_lock_init(&dev->client_ctx_lock);
	INIT_LIST_HEAD(&dev->client_ctx_list);
	INIT_LIST_HEAD(&dev->port_list);
	spin_lock_init(&dev->event_handler_lock);
	INIT_LIST_HEAD(&dev->event_handler_list);

	init_completion(&dev->comp);
	atomic_set(&dev->use_cnt, 1);

	ubcore_set_default_eid(dev);
	return 0;
}

static void uninit_ubcore_device(struct ubcore_device *dev)
{
	put_device(&dev->dev);
}

int ubcore_register_device(struct ubcore_device *dev)
{
	struct ubcore_client *client = NULL;
	struct ubcore_client_ctx *ctx = NULL;

	if (dev == NULL || dev->ops == NULL || strlen(dev->dev_name) == 0) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (ubcore_find_device_with_name(dev->dev_name) != NULL) {
		ubcore_log_err("Duplicate device name %s.\n", dev->dev_name);
		return -EEXIST;
	}

	if (init_ubcore_device(dev) != 0) {
		ubcore_log_err("failed to init ubcore device.\n");
		return -EINVAL;
	}

	mutex_lock(&g_device_mutex);

	list_for_each_entry(client, &g_client_list, list_node) {
		ctx = create_client_ctx(dev, client);
		if (ctx == NULL)
			continue;
		if (client->add && client->add(dev) != 0) {
			destroy_client_ctx(dev, ctx);
			ubcore_log_err("ubcore device: %s register client:%s failed.\n",
				       dev->dev_name, client->client_name);
		}
	}

	down_write(&g_lists_rwsem);
	list_add_tail(&dev->list_node, &g_device_list);
	up_write(&g_lists_rwsem);

	mutex_unlock(&g_device_mutex);

	ubcore_log_info("ubcore device: %s register success.\n", dev->dev_name);
	return 0;
}
EXPORT_SYMBOL(ubcore_register_device);

void ubcore_unregister_device(struct ubcore_device *dev)
{
	struct ubcore_client_ctx *ctx, *tmp;

	mutex_lock(&g_device_mutex);

	/* Remove device from g_device_list */
	down_write(&g_lists_rwsem);
	list_del(&dev->list_node);

	/* Destroy uburma device, may be scheduled.
	 * This should not be done within a spin_lock_irqsave
	 */
	list_for_each_entry_safe(ctx, tmp, &dev->client_ctx_list, list_node) {
		if (ctx->client != NULL && ctx->client->remove != NULL)
			ctx->client->remove(dev, ctx->data);
	}
	up_write(&g_lists_rwsem);

	uninit_ubcore_device(dev);

	mutex_unlock(&g_device_mutex);

	/* Finally, free client ctx */
	list_for_each_entry_safe(ctx, tmp, &dev->client_ctx_list, list_node)
		destroy_client_ctx(dev, ctx);

	/* Pair with set use_cnt = 1 when init device */
	ubcore_put_device(dev);
	/* Wait for use cnt == 0 */
	wait_for_completion(&dev->comp);

	ubcore_log_info("ubcore device: %s unregister success.\n", dev->dev_name);
}
EXPORT_SYMBOL(ubcore_unregister_device);

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

int ubcore_query_device_attr(struct ubcore_device *dev, struct ubcore_device_attr *attr)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->query_device_attr == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->query_device_attr(dev, attr);
	if (ret != 0) {
		ubcore_log_err("failed to query device attr, ret: %d.\n", ret);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_query_device_attr);

int ubcore_query_stats(const struct ubcore_device *dev, struct ubcore_stats_key *key,
		       struct ubcore_stats_val *val)
{
	int ret;

	if (dev == NULL || key == NULL || val == NULL || dev->ops == NULL ||
	    dev->ops->query_stats == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->query_stats(dev, key, val);
	if (ret != 0) {
		ubcore_log_err("Failed to query stats, ret: %d.\n", ret);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_query_stats);
