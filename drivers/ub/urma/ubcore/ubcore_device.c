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

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/dma-mapping.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/if_vlan.h>

#include "urma/ubcore_types.h"
#include "ubcore_log.h"
#include <urma/ubcore_uapi.h>
#include <urma/ubcore_api.h>
#include "ubcore_priv.h"
#include "ubcore_hash_table.h"
#include "ubcore_tp.h"
#include "ubcore_tp_table.h"
#include "urma/ubcore_jetty.h"
#include "ubcore_msg.h"
#include "ubcore_netdev.h"
#include "ubcore_utp.h"
#include "ubcore_vtp.h"
#include "ubcore_tpg.h"
#include "ubcore_ctp.h"
#include "ubcore_netlink.h"
#include "ubcore_workqueue.h"
#include "ubcore_cdev_file.h"
#include "ubcore_uvs_cmd.h"
#include "ubcore_cmd.h"
#include "ubcore_main.h"
#include "ubcore_device.h"

#define UBCORE_DEVICE_NAME "ubcore"

struct ubcore_ctx {
	dev_t ubcore_devno;
	struct cdev ubcore_cdev;
	struct device *ubcore_dev;
};

static LIST_HEAD(g_client_list);
static LIST_HEAD(g_device_list);

/*
 * g_device_rwsem protects writer access by device
 */
static DECLARE_RWSEM(g_device_rwsem);

/*
 * g_clients_rwsem protect g_client_list.
 */
static DECLARE_RWSEM(g_clients_rwsem);
static DEFINE_MUTEX(g_upi_lock);
static LIST_HEAD(g_upi_list);

static unsigned int g_ubcore_net_id;
static LIST_HEAD(g_ubcore_net_list);
static DEFINE_SPINLOCK(g_ubcore_net_lock);
static DECLARE_RWSEM(g_ubcore_net_rwsem);

static bool g_shared_ns = true;

static struct ubcore_ctx g_ubcore_ctx = {0};

static const void *ubcore_net_namespace(struct device *dev)
{
	struct ubcore_logic_device *ldev = dev_get_drvdata(dev);
	struct ubcore_device *ubc_dev;

	if (ldev == NULL || ldev->ub_dev == NULL) {
		ubcore_log_info("init net %pK", ldev);
		return &init_net;
	}

	ubc_dev = ldev->ub_dev;
	if (ubc_dev->transport_type == UBCORE_TRANSPORT_UB) {
		return read_pnet(&ldev->net);
	} else if (ubc_dev->transport_type == UBCORE_TRANSPORT_IP) {
		if (ubc_dev->netdev)
			return dev_net(ubc_dev->netdev);
		else
			return &init_net;
	} else { /* URMA IB device not support namespace yet */
		return &init_net;
	}
}

static struct class g_ubcore_class = {
	.name    = "ubcore",
	.ns_type = &net_ns_type_operations,
	.namespace = ubcore_net_namespace
};

struct ubcore_net {
	possible_net_t net;
	struct list_head node;
};

struct ubcore_upi_entry {
	struct ubcore_device *dev;
	uint32_t upi;
	struct list_head node;
};

struct ubcore_event_work {
	struct work_struct work;
	struct ubcore_event event;
};

void ubcore_set_client_ctx_data(struct ubcore_device *dev, struct ubcore_client *client,
				void *data)
{
	struct ubcore_client_ctx *ctx;

	if (dev == NULL || client == NULL || client->client_name == NULL ||
		strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME ||
		strnlen(client->client_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("dev or client is null");
		return;
	}

	down_read(&dev->client_ctx_rwsem);
	list_for_each_entry(ctx, &dev->client_ctx_list, list_node) {
		if (ctx->client == client) {
			ctx->data = data;
			goto out;
		}
	}
	ubcore_log_err("no client ctx found, device_name: %s, client_name: %s.\n", dev->dev_name,
		       client->client_name);

out:
	up_read(&dev->client_ctx_rwsem);
}
EXPORT_SYMBOL(ubcore_set_client_ctx_data);

static struct ubcore_client_ctx *ubcore_lookup_client_context(struct ubcore_device *dev,
	struct ubcore_client *client)
{
	struct ubcore_client_ctx *found_ctx = NULL;
	struct ubcore_client_ctx *ctx, *tmp;

	if (dev == NULL || client == NULL) {
		ubcore_log_err("dev is null");
		return NULL;
	}

	down_read(&dev->client_ctx_rwsem);
	list_for_each_entry_safe(ctx, tmp, &dev->client_ctx_list, list_node) {
		if (ctx->client == client) {
			found_ctx = ctx;
			break;
		}
	}
	up_read(&dev->client_ctx_rwsem);
	return found_ctx;
}

void *ubcore_get_client_ctx_data(struct ubcore_device *dev, struct ubcore_client *client)
{
	struct ubcore_client_ctx *found_ctx = NULL;

	if (dev == NULL || client == NULL || client->client_name == NULL ||
		strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME ||
		strnlen(client->client_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("dev or client is null");
		return NULL;
	}

	found_ctx = ubcore_lookup_client_context(dev, client);
	if (found_ctx == NULL) {
		ubcore_log_warn("no client ctx found, dev_name: %s, client_name: %s.\n",
				dev->dev_name, client->client_name);
		return NULL;
	} else {
		return found_ctx->data;
	}
}
EXPORT_SYMBOL(ubcore_get_client_ctx_data);

static int create_client_ctx(struct ubcore_device *dev, struct ubcore_client *client)
{
	struct ubcore_client_ctx *ctx;

	ctx = kmalloc(sizeof(struct ubcore_client_ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->data = NULL;
	ctx->client = client;

	down_write(&dev->client_ctx_rwsem);
	list_add(&ctx->list_node, &dev->client_ctx_list);
	downgrade_write(&dev->client_ctx_rwsem);
	if (client->add && client->add(dev) != 0) {
		list_del(&ctx->list_node);
		kfree(ctx);
		up_read(&dev->client_ctx_rwsem);
		return -EPERM;
	}
	up_read(&dev->client_ctx_rwsem);
	return 0;
}

static void destroy_client_ctx(struct ubcore_device *dev, struct ubcore_client_ctx *ctx)
{
	if (dev == NULL || ctx == NULL)
		return;

	down_write(&dev->client_ctx_rwsem);
	list_del(&ctx->list_node);
	kfree(ctx);
	up_write(&dev->client_ctx_rwsem);
}

int ubcore_register_client(struct ubcore_client *new_client)
{
	struct ubcore_device *dev;

	if (new_client == NULL || new_client->client_name == NULL ||
		new_client->add == NULL || new_client->remove == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -1;
	}

	if (strnlen(new_client->client_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("Invalid parameter, client name.\n");
		return -1;
	}

	down_write(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (create_client_ctx(dev, new_client) != 0)
			ubcore_log_warn("ubcore device: %s add client:%s context failed.\n",
				dev->dev_name, new_client->client_name);
	}
	down_write(&g_clients_rwsem);
	list_add_tail(&new_client->list_node, &g_client_list);
	up_write(&g_clients_rwsem);

	up_write(&g_device_rwsem);

	ubcore_log_info("ubcore client: %s register success.\n", new_client->client_name);
	return 0;
}
EXPORT_SYMBOL(ubcore_register_client);

void ubcore_unregister_client(struct ubcore_client *rm_client)
{
	struct ubcore_client_ctx *found_ctx = NULL;
	struct ubcore_device *dev;

	if (rm_client == NULL || rm_client->client_name == NULL ||
		rm_client->add == NULL || rm_client->remove == NULL) {
		ubcore_log_err("Invalid parameter");
		return;
	}
	if (strnlen(rm_client->client_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("Invalid parameter, client name.\n");
		return;
	}

	down_write(&g_device_rwsem);

	down_write(&g_clients_rwsem);
	list_del(&rm_client->list_node);
	up_write(&g_clients_rwsem);

	downgrade_write(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		found_ctx = ubcore_lookup_client_context(dev, rm_client);
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

	up_read(&g_device_rwsem);
	ubcore_log_info("ubcore client: %s unregister success.\n", rm_client->client_name);
}
EXPORT_SYMBOL(ubcore_unregister_client);

struct ubcore_device *ubcore_find_device(union ubcore_eid *eid, enum ubcore_transport_type type)
{
	struct ubcore_device *dev, *target = NULL;
	uint32_t idx;

	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (IS_ERR_OR_NULL(dev->eid_table.eid_entries))
			continue;
		for (idx = 0; idx < dev->attr.dev_cap.max_eid_cnt; idx++) {
			if (memcmp(&dev->eid_table.eid_entries[idx].eid, eid,
				sizeof(union ubcore_eid)) == 0 && dev->transport_type == type) {
				target = dev;
				ubcore_get_device(target);
				break;
			}
		}
		if (target != NULL)
			break;
	}
	up_read(&g_device_rwsem);
	return target;
}

struct ubcore_device *ubcore_find_device_with_name(const char *dev_name)
{
	struct ubcore_device *dev, *target = NULL;

	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (strcmp(dev->dev_name, dev_name) == 0) {
			target = dev;
			ubcore_get_device(target);
			break;
		}
	}
	up_read(&g_device_rwsem);
	return target;
}

bool ubcore_check_dev_is_exist(const char *dev_name)
{
	struct ubcore_device *dev = NULL;

	dev = ubcore_find_device_with_name(dev_name);
	if (dev != NULL)
		ubcore_put_device(dev);

	return dev != NULL ? true : false;
}

struct ubcore_device *ubcore_find_upi_with_dev_name(const char *dev_name, uint32_t *upi)
{
	struct ubcore_upi_entry *entry = NULL;
	struct ubcore_device *dev = NULL;

	mutex_lock(&g_upi_lock);
	list_for_each_entry(entry, &g_upi_list, node) {
		if (entry != NULL && strcmp(entry->dev->dev_name, dev_name) == 0) {
			*upi = entry->upi;
			dev = entry->dev;
			break;
		}
	}
	mutex_unlock(&g_upi_lock);
	return dev;
}

int ubcore_add_upi_list(struct ubcore_device *dev, uint32_t upi)
{
	struct ubcore_upi_entry *entry = NULL, *new_entry = NULL;

	mutex_lock(&g_upi_lock);
	list_for_each_entry(entry, &g_upi_list, node) {
		if (entry != NULL && entry->dev == dev) {
			entry->upi = upi;
			mutex_unlock(&g_upi_lock);
			return 0;
		}
	}
	mutex_unlock(&g_upi_lock);

	new_entry = kzalloc(sizeof(struct ubcore_upi_entry), GFP_ATOMIC);
	if (new_entry == NULL)
		return -ENOMEM;

	new_entry->dev = dev;
	new_entry->upi = upi;

	mutex_lock(&g_upi_lock);
	list_add_tail(&new_entry->node, &g_upi_list);
	mutex_unlock(&g_upi_lock);
	ubcore_log_info("add dev_name: %s, upi: 0x%x to upi list\n", dev->dev_name, upi);
	return 0;
}

void ubcore_destroy_upi_list(struct ubcore_device *dev)
{
	struct ubcore_upi_entry *entry = NULL, *next;

	mutex_lock(&g_upi_lock);
	list_for_each_entry_safe(entry, next, &g_upi_list, node) {
		if (entry != NULL && entry->dev == dev) {
			list_del(&entry->node);
			kfree(entry);
			break;
		}
	}
	mutex_unlock(&g_upi_lock);
}

static bool ubcore_netdev_in_ubdev(struct ubcore_device *dev, struct net_device *netdev)
{
	struct net_device *real_netdev = NULL;

	if (dev->transport_type == UBCORE_TRANSPORT_UB && is_vlan_dev(netdev))
		real_netdev = vlan_dev_real_dev(netdev);
	else
		real_netdev = netdev;

	return (dev->netdev == real_netdev);
}

struct ubcore_device **ubcore_get_devices_from_netdev(struct net_device *netdev,
	uint32_t *cnt)
{
	struct ubcore_device **devices;
	struct ubcore_device *dev;
	uint32_t i = 0;

	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		/* Assume netdev is related to the first and only port */
		if (ubcore_netdev_in_ubdev(dev, netdev))
			i++;
	}
	up_read(&g_device_rwsem);

	if (i == 0) {
		*cnt = 0;
		return NULL;
	}

	devices = kzalloc(i * sizeof(struct ubcore_device *), GFP_ATOMIC);
	if (devices == NULL) {
		*cnt = 0;
		return NULL;
	}

	*cnt = i;
	i = 0;
	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (ubcore_netdev_in_ubdev(dev, netdev)) {
			ubcore_get_device(dev);
			devices[i] = dev;
			i++;
		}
	}
	up_read(&g_device_rwsem);

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
		ubcore_log_err("Invalid parameter\n");
		return;
	}

	atomic_inc(&dev->use_cnt);
}

void ubcore_put_device(struct ubcore_device *dev)
{
	if (IS_ERR_OR_NULL(dev)) {
		ubcore_log_err("Invalid parameter\n");
		return;
	}

	if (atomic_dec_and_test(&dev->use_cnt))
		complete(&dev->comp);
}

struct ubcore_device *ubcore_find_tpf_device_by_name(char *dev_name)
{
	struct ubcore_device *dev;

	dev = ubcore_find_device_with_name(dev_name);
	if (dev == NULL) {
		ubcore_log_err("can not find dev by name:%s", dev_name);
		return NULL;
	}

	if (dev->attr.tp_maintainer)
		return dev;

	ubcore_log_err("dev:%s is not tpf", dev_name);
	ubcore_put_device(dev);
	return NULL;
}

static uint32_t ubcore_get_all_tpf_device_cnt(enum ubcore_transport_type type)
{
	struct ubcore_device *dev;
	uint32_t cnt = 0;

	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->attr.tp_maintainer && dev->transport_type == type)
			++cnt;
	}
	up_read(&g_device_rwsem);
	return cnt;
}

struct ubcore_device **ubcore_get_all_tpf_device(enum ubcore_transport_type type, uint32_t *dev_cnt)
{
	struct ubcore_device **dev_list;
	struct ubcore_device *dev;
	int i = 0;

	*dev_cnt = ubcore_get_all_tpf_device_cnt(type);
	if (*dev_cnt == 0)
		return NULL;

	dev_list = kcalloc(1, (*dev_cnt) * (uint32_t)sizeof(struct ubcore_device *), GFP_KERNEL);
	if (dev_list == NULL)
		return NULL;

	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->attr.tp_maintainer && dev->transport_type == type) {
			dev_list[i++] = dev;
			ubcore_get_device(dev);
		}
	}
	up_read(&g_device_rwsem);
	return dev_list;
}

struct ubcore_device *ubcore_find_tpf_device(union ubcore_net_addr_union *netaddr,
	enum ubcore_transport_type type)
{
	if (netaddr == NULL)
		return NULL;

	return ubcore_lookup_tpf_by_sip_addr(netaddr);
}

int ubcore_tpf_device_set_global_cfg(struct ubcore_set_global_cfg *cfg)
{
	struct ubcore_device_cfg dev_cfg = {0};
	struct ubcore_device *dev = NULL;
	int ret;

	if (cfg == NULL) {
		ubcore_log_err("Invalid paramete");
		return -EINVAL;
	}

	if (cfg->mask.bs.suspend_period == 1) {
		dev_cfg.mask.bs.suspend_period = 1;
		dev_cfg.suspend_period = cfg->suspend_period;
	}

	if (cfg->mask.bs.suspend_cnt == 1) {
		dev_cfg.mask.bs.suspend_cnt = 1;
		dev_cfg.suspend_cnt = cfg->suspend_cnt;
	}

	/* Query all existing TPF devices and configure */
	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->attr.tp_maintainer == false)
			continue;

		dev_cfg.fe_idx = dev->attr.fe_idx;
		ret = ubcore_config_device(dev, &dev_cfg);
		if (ret != 0)
			ubcore_log_err("dev: %s set failed, ret: %d", dev->dev_name, ret);
	}
	up_read(&g_device_rwsem);
	return 0;
}

static void ubcore_free_driver_obj(void *obj)
{
	// obj alloced by driver, should not free by ubcore
	ubcore_log_err("obj was not free correctly!");
}

static struct ubcore_ht_param g_ht_params[] = {
	[UBCORE_HT_JFS] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jfs, hnode),
		offsetof(struct ubcore_jfs, jfs_id) + offsetof(struct ubcore_jetty_id, id),
		sizeof(uint32_t), NULL, ubcore_free_driver_obj, ubcore_jfs_get},

	[UBCORE_HT_JFR] = { UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jfr, hnode),
		offsetof(struct ubcore_jfr, jfr_id) + offsetof(struct ubcore_jetty_id, id),
		sizeof(uint32_t), NULL, ubcore_free_driver_obj, ubcore_jfr_get},
	[UBCORE_HT_JFC] = { UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jfc, hnode),
		offsetof(struct ubcore_jfc, id), sizeof(uint32_t), NULL,
		ubcore_free_driver_obj, NULL},

	[UBCORE_HT_JETTY] = { UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jetty, hnode),
		offsetof(struct ubcore_jetty, jetty_id) + offsetof(struct ubcore_jetty_id, id),
		sizeof(uint32_t), NULL, ubcore_free_driver_obj, ubcore_jetty_get},

	[UBCORE_HT_TP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_tp, hnode),
		offsetof(struct ubcore_tp, tpn), sizeof(uint32_t),
		NULL, ubcore_free_driver_obj, ubcore_tp_get},

	[UBCORE_HT_TPG] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_tpg, hnode),
		offsetof(struct ubcore_tpg, tpgn), sizeof(uint32_t),
		NULL, ubcore_free_driver_obj, ubcore_tpg_get},

	/* key: seid + deid */
	[UBCORE_HT_RM_VTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtp, hnode),
		offsetof(struct ubcore_vtp, cfg) + offsetof(struct ubcore_vtp_cfg, local_eid),
		sizeof(union ubcore_eid) * 2, NULL, ubcore_free_driver_obj, ubcore_vtp_get},

	/* key: deid + djetty */
	[UBCORE_HT_RC_VTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtp, hnode),
		offsetof(struct ubcore_vtp, cfg) + offsetof(struct ubcore_vtp_cfg, peer_eid),
		sizeof(union ubcore_eid) + sizeof(uint32_t), NULL, ubcore_free_driver_obj,
		ubcore_vtp_get},

	/* key: seid + deid */
	[UBCORE_HT_UM_VTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtp, hnode),
		offsetof(struct ubcore_vtp, cfg) + offsetof(struct ubcore_vtp_cfg, local_eid),
		sizeof(union ubcore_eid) * 2, NULL, ubcore_free_driver_obj, ubcore_vtp_get},

	/* key: src_eid + des_eid */
	[UBCORE_HT_RM_VTPN] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtpn, hnode),
		offsetof(struct ubcore_vtpn, local_eid), 2 * sizeof(union ubcore_eid),
		NULL, ubcore_free_driver_obj, ubcore_vtpn_get},

	/* key: src_eid + des_eid + src_jetty + des_jetty */
	[UBCORE_HT_RC_VTPN] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtpn, hnode),
		offsetof(struct ubcore_vtpn, local_eid),
		2 * sizeof(union ubcore_eid) + 2 * sizeof(uint32_t),
		NULL, ubcore_free_driver_obj, ubcore_vtpn_get},

	/* key: src_eid + des_eid */
	[UBCORE_HT_UM_VTPN] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtpn, hnode),
		offsetof(struct ubcore_vtpn, local_eid), 2 * sizeof(union ubcore_eid),
		NULL, ubcore_free_driver_obj, ubcore_vtpn_get},

	/* key: utp idx */
	[UBCORE_HT_UTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_utp, hnode),
		offsetof(struct ubcore_utp, utpn), sizeof(uint32_t), NULL,
		ubcore_free_driver_obj, ubcore_utp_get},

	/* key: ctp idx */
	[UBCORE_HT_CTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_ctp, hnode),
		offsetof(struct ubcore_ctp, ctpn), sizeof(uint32_t), NULL,
		ubcore_free_driver_obj, ubcore_ctp_get},
};

static inline void ubcore_set_vtp_hash_table_size(uint32_t vtp_size)
{
	if (vtp_size == 0 || vtp_size > UBCORE_HASH_TABLE_SIZE)
		return;
	g_ht_params[UBCORE_HT_RM_VTP].size = vtp_size;
	g_ht_params[UBCORE_HT_RC_VTP].size = vtp_size;
	g_ht_params[UBCORE_HT_UM_VTP].size = vtp_size;
}

static inline void ubcore_set_vtpn_hash_table_size(uint32_t vtpn_size)
{
	if (vtpn_size == 0 || vtpn_size > UBCORE_HASH_TABLE_SIZE)
		return;
	g_ht_params[UBCORE_HT_RM_VTPN].size = vtpn_size;
	g_ht_params[UBCORE_HT_RC_VTPN].size = vtpn_size;
	g_ht_params[UBCORE_HT_UM_VTPN].size = vtpn_size;
}

static void ubcore_update_hash_tables_size(const struct ubcore_device_cap *cap)
{
	if (cap->max_jfs != 0 && cap->max_jfs < g_ht_params[UBCORE_HT_JFS].size)
		g_ht_params[UBCORE_HT_JFS].size = cap->max_jfs;
	if (cap->max_jfr != 0 && cap->max_jfr < g_ht_params[UBCORE_HT_JFR].size)
		g_ht_params[UBCORE_HT_JFR].size = cap->max_jfr;
	if (cap->max_jfc != 0 && cap->max_jfc < g_ht_params[UBCORE_HT_JFC].size)
		g_ht_params[UBCORE_HT_JFC].size = cap->max_jfc;
	if (cap->max_jetty != 0 && cap->max_jetty < g_ht_params[UBCORE_HT_JETTY].size)
		g_ht_params[UBCORE_HT_JETTY].size = cap->max_jetty;
	if (cap->max_tp_cnt != 0 && cap->max_tp_cnt < g_ht_params[UBCORE_HT_TP].size)
		g_ht_params[UBCORE_HT_TP].size = cap->max_tp_cnt;
	if (cap->max_tpg_cnt != 0 && cap->max_tpg_cnt < g_ht_params[UBCORE_HT_TPG].size)
		g_ht_params[UBCORE_HT_TPG].size = cap->max_tpg_cnt;
	if (cap->max_vtp_cnt_per_fe < UBCORE_HASH_TABLE_SIZE &&
		cap->max_fe_cnt < UBCORE_HASH_TABLE_SIZE)
		ubcore_set_vtp_hash_table_size((cap->max_vtp_cnt_per_fe * cap->max_fe_cnt));
	ubcore_set_vtpn_hash_table_size(cap->max_vtp_cnt_per_fe);

	if (cap->max_utp_cnt != 0 && cap->max_utp_cnt < g_ht_params[UBCORE_HT_UTP].size)
		g_ht_params[UBCORE_HT_UTP].size = cap->max_utp_cnt;
	/* ctp size use max_tp_cnt */
	if (cap->max_tp_cnt != 0 && cap->max_tp_cnt < g_ht_params[UBCORE_HT_CTP].size)
		g_ht_params[UBCORE_HT_CTP].size = cap->max_tp_cnt;
}


static int ubcore_alloc_hash_tables(struct ubcore_device *dev)
{
	uint32_t i, j;
	int ret;

	ubcore_update_hash_tables_size(&dev->attr.dev_cap);
	for (i = 0; i < ARRAY_SIZE(g_ht_params); i++) {
		ret = ubcore_hash_table_alloc(&dev->ht[i], &g_ht_params[i]);
		if (ret != 0) {
			ubcore_log_err("alloc hash tables failed.\n");
			goto free_tables;
		}
	}

	return 0;

free_tables:
	for (j = 0; j < i; j++)
		ubcore_hash_table_free(&dev->ht[j]);
	return -1;
}

static void ubcore_free_hash_tables(struct ubcore_device *dev)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(g_ht_params); i++)
		ubcore_hash_table_free(&dev->ht[i]);
}

static void ubcore_device_release(struct device *device)
{
}

static int ubcore_create_eidtable(struct ubcore_device *dev)
{
	struct ubcore_eid_entry *entry_list;

	if (dev->attr.dev_cap.max_eid_cnt > UBCORE_MAX_EID_CNT) {
		ubcore_log_err("Max eid cnt:%u exceeds ubcore_max_eid_cnt!\n",
		dev->attr.dev_cap.max_eid_cnt);
		return -EINVAL;
	}

	entry_list = kcalloc(1,
		dev->attr.dev_cap.max_eid_cnt * sizeof(struct ubcore_eid_entry), GFP_ATOMIC);
	if (entry_list == NULL)
		return -ENOMEM;

	dev->eid_table.eid_entries = entry_list;
	spin_lock_init(&dev->eid_table.lock);
	dev->eid_table.eid_cnt = dev->attr.dev_cap.max_eid_cnt;
	dev->dynamic_eid = 1;
	return 0;
}

static void ubcore_destroy_eidtable(struct ubcore_device *dev)
{
	struct ubcore_eid_entry *e = NULL;

	spin_lock(&dev->eid_table.lock);
	e = dev->eid_table.eid_entries;
	dev->eid_table.eid_entries = NULL;
	spin_unlock(&dev->eid_table.lock);
	if (e != NULL)
		kfree(e);
}

static int ubcore_send_remove_tpf_dev_info(struct ubcore_device *dev)
{
	struct ubcore_update_tpf_dev_info_req *data;
	struct ubcore_nlmsg *req_msg;
	int ret;

	req_msg = kcalloc(1, sizeof(struct ubcore_nlmsg) +
		sizeof(struct ubcore_update_tpf_dev_info_req), GFP_KERNEL);
	if (req_msg == NULL)
		return -ENOMEM;

	req_msg->msg_type = UBCORE_CMD_UPDATE_TPF_DEV_INFO_REQ;
	req_msg->transport_type = dev->transport_type;
	req_msg->payload_len = sizeof(struct ubcore_update_tpf_dev_info_req);

	/* fill msg payload */
	data = (struct ubcore_update_tpf_dev_info_req *)req_msg->payload;
	data->dev_fea = dev->attr.dev_cap.feature;
	data->cc_entry_cnt = 0;
	data->opcode = UBCORE_UPDATE_TPF_DEL;
	(void)strncpy(data->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME - 1);

	ret = ubcore_nl_send_nowait_without_cb(req_msg);
	if (ret)
		ubcore_log_err("Failed to send rmv tpf dev info request ret:%d", ret);
	else
		ubcore_log_info("Success to send rmv tpf dev:%s info request", dev->dev_name);

	kfree(req_msg);
	return ret;
}

static struct ubcore_cc_entry *ubcore_get_cc_entry(struct ubcore_device *dev,
	uint32_t *cc_entry_cnt)
{
	struct ubcore_cc_entry *cc_entry = NULL;
	*cc_entry_cnt = 0;

	if (dev->ops == NULL || dev->ops->query_cc == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		return NULL;
	}

	cc_entry = dev->ops->query_cc(dev, cc_entry_cnt);
	if (cc_entry == NULL) {
		ubcore_log_err("Failed to query cc entry\n");
		return NULL;
	}

	if (*cc_entry_cnt > UBCORE_CC_IDX_TABLE_SIZE || *cc_entry_cnt == 0) {
		kfree(cc_entry);
		ubcore_log_err("cc_entry_cnt invalid, %u.\n", *cc_entry_cnt);
		return NULL;
	}

	return cc_entry;
}

struct ubcore_nlmsg *ubcore_new_tpf_dev_msg(struct ubcore_device *dev)
{
	struct ubcore_update_tpf_dev_info_req *data;
	struct ubcore_cc_entry *cc_entry;
	struct ubcore_cc_entry *array;
	struct ubcore_nlmsg *req_msg;
	uint32_t cc_entry_cnt;
	uint32_t cc_len;

	// If not support cc, cc_entry may be NULL, cc_entry_cnt is 0
	cc_entry = ubcore_get_cc_entry(dev, &cc_entry_cnt);

	cc_len = (uint32_t)sizeof(struct ubcore_update_tpf_dev_info_req) +
		cc_entry_cnt * (uint32_t)sizeof(struct ubcore_cc_entry);
	req_msg = kcalloc(1, sizeof(struct ubcore_nlmsg) + cc_len, GFP_KERNEL);
	if (req_msg == NULL)
		goto out;

	/* fill msg head */
	req_msg->msg_type = UBCORE_CMD_UPDATE_TPF_DEV_INFO_REQ;
	req_msg->transport_type = dev->transport_type;
	req_msg->payload_len = cc_len;

	/* fill msg payload */
	data = (struct ubcore_update_tpf_dev_info_req *)req_msg->payload;
	data->dev_fea = dev->attr.dev_cap.feature;
	data->cc_entry_cnt = cc_entry_cnt;
	(void)strncpy(data->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME - 1);
	data->opcode = UBCORE_UPDATE_TPF_ADD;

	if (dev->netdev != NULL &&
		strnlen(dev->netdev->name, UBCORE_MAX_DEV_NAME) < UBCORE_MAX_DEV_NAME)
		(void)strncpy(data->netdev_name, dev->netdev->name, UBCORE_MAX_DEV_NAME - 1);

	if (cc_entry != NULL) {
		array = (struct ubcore_cc_entry *)data->data;
		(void)memcpy(array, cc_entry, sizeof(struct ubcore_cc_entry) * cc_entry_cnt);
	}

out:
	if (cc_entry != NULL)
		kfree(cc_entry);
	return req_msg;
}

static int ubcore_query_send_tpf_dev_info(struct ubcore_device *dev)
{
	struct ubcore_nlmsg *req_msg;
	int ret;

	req_msg = ubcore_new_tpf_dev_msg(dev);
	if (req_msg == NULL)
		return -1;

	ret = ubcore_nl_send_nowait_without_cb(req_msg);
	if (ret)
		ubcore_log_err("Failed to nowait send query tpf dev info request");
	else
		ubcore_log_info("Success to nowait send query tpf dev info request");

	kfree(req_msg);
	return ret;
}

static int ubcore_create_main_device(struct ubcore_device *dev)
{
	struct ubcore_logic_device *ldev = &dev->ldev;
	struct net *net = &init_net;
	int ret;

	if (dev->transport_type == UBCORE_TRANSPORT_IP && dev->netdev != NULL)
		net = dev_net(dev->netdev);

	/* create /sys/class/ubcore/<dev->dev_name> */
	write_pnet(&ldev->net, net);
	ldev->ub_dev = dev;
	ldev->dev = &dev->dev;

	device_initialize(&dev->dev);
	dev->dev.class = &g_ubcore_class;
	dev->dev.release = ubcore_device_release;
	/* dev_set_name will alloc mem use put_device to free */
	(void)dev_set_name(&dev->dev, "%s", dev->dev_name);
	dev_set_drvdata(&dev->dev, ldev);
	ret = device_add(&dev->dev);
	if (ret) {
		put_device(&dev->dev); // to free res used by kobj
		return ret;
	}

	if (ubcore_fill_logic_device_attr(ldev, dev) != 0) {
		device_del(&dev->dev);
		put_device(&dev->dev);
		ldev->dev = NULL;
		ubcore_log_err("failed to fill attributes, device:%s.\n", dev->dev_name);
		return -EPERM;
	}

	return 0;
}

static void ubcore_destroy_main_device(struct ubcore_device *dev)
{
	struct ubcore_logic_device *ldev = &dev->ldev;

	ubcore_unfill_logic_device_attr(ldev, dev);
	device_del(ldev->dev);
	put_device(ldev->dev);
	ldev->dev = NULL;
}

static int init_ubcore_device(struct ubcore_device *dev)
{
	if (dev->ops->query_device_attr != NULL &&
	    dev->ops->query_device_attr(dev, &dev->attr) != 0) {
		ubcore_log_err("Failed to query device attributes");
		return -1;
	}

	if (ubcore_is_ub_device(dev) && dev->attr.tp_maintainer) {
		if (ubcore_sip_table_init(&dev->sip_table,
			dev->attr.dev_cap.max_netaddr_cnt) != 0) {
			ubcore_log_err("Failed init sip table.\n");
			return -1;
		}
	}

	INIT_LIST_HEAD(&dev->list_node);
	init_rwsem(&dev->client_ctx_rwsem);
	INIT_LIST_HEAD(&dev->client_ctx_list);
	INIT_LIST_HEAD(&dev->port_list);
	init_rwsem(&dev->event_handler_rwsem);
	INIT_LIST_HEAD(&dev->event_handler_list);

	if (!dev->attr.virtualization)
		(void)ubcore_add_upi_list(dev, UCBORE_INVALID_UPI);

	init_completion(&dev->comp);
	atomic_set(&dev->use_cnt, 1);

	/* save tpf device to the list g_tpf_list */
	if (dev->transport_type == UBCORE_TRANSPORT_UB && dev->attr.tp_maintainer) {
		if (ubcore_get_netlink_valid() && ubcore_query_send_tpf_dev_info(dev) != 0)
			ubcore_log_warn(
				"failed to query cc info in ubcore with dev name %s",
				dev->dev_name);
	}

	if (ubcore_create_eidtable(dev) != 0) {
		ubcore_log_err("create eidtable failed.\n");
		return -1;
	}

	if (ubcore_alloc_hash_tables(dev) != 0) {
		ubcore_destroy_eidtable(dev);
		ubcore_log_err("alloc hash tables failed.\n");
		return -1;
	}
	ubcore_update_netdev_addr(dev, dev->netdev, UBCORE_ADD_NET_ADDR, false);

	mutex_init(&dev->ldev_mutex);
	INIT_LIST_HEAD(&dev->ldev_list);
	return 0;
}

static void ubcore_remove_uvs_sip_info(struct ubcore_device *dev)
{
	struct ubcore_sip_info *sip_info;
	uint32_t i;

	mutex_lock(&dev->sip_table.lock);
	for (i = 0; i < dev->sip_table.max_sip_cnt; i++) {
		sip_info = &dev->sip_table.entry[i];
		if (!sip_info->is_active)
			continue;
		if (ubcore_get_netlink_valid() == true)
			(void)ubcore_notify_uvs_del_sip(dev, sip_info, i);
	}
	mutex_unlock(&dev->sip_table.lock);
}

static void uninit_ubcore_device(struct ubcore_device *dev)
{
	mutex_destroy(&dev->ldev_mutex);

	ubcore_put_port_netdev(dev);
	ubcore_update_netdev_addr(dev, dev->netdev, UBCORE_DEL_NET_ADDR, false);
	ubcore_free_hash_tables(dev);
	ubcore_destroy_eidtable(dev);

	if (!dev->attr.virtualization)
		ubcore_destroy_upi_list(dev);

	if (dev->transport_type == UBCORE_TRANSPORT_UB && dev->attr.tp_maintainer) {
		ubcore_remove_uvs_sip_info(dev);
		ubcore_sip_table_uninit(&dev->sip_table);
		if (ubcore_get_netlink_valid() && ubcore_send_remove_tpf_dev_info(dev) != 0)
			ubcore_log_warn("failed to remove tpf dev info %s", dev->dev_name);
	}

	if (dev->transport_type == UBCORE_TRANSPORT_HNS_UB && dev->attr.tp_maintainer)
		ubcore_sip_table_uninit(&dev->sip_table);
}

static int ubcore_nego_ver_rsp_msg_cb(struct ubcore_device *dev,
	struct ubcore_resp *resp, void *msg_ctx)
{
	struct ubcore_msg_nego_ver_resp *data;

	if (resp == NULL || resp->len != sizeof(struct ubcore_msg_nego_ver_resp) ||
		resp->opcode != UBCORE_MSG_NEGO_VER) {
		ubcore_log_err("Invalid version negotiation response.\n");
		return -EINVAL;
	}

	data = (struct ubcore_msg_nego_ver_resp *)resp->data;
	if (data->ret == UBCORE_MSG_RESP_FAIL) {
		ubcore_log_err("Fail to negotiate version with backend ubcore.\n");
		return -1;
	}

	ubcore_set_version(data->version);
	ubcore_set_cap(data->cap);
	return 0;
}

static int ubcore_initiate_negotiation(struct ubcore_device *dev)
{
	struct ubcore_msg_nego_ver_req *data;
	struct ubcore_req *req_msg;
	struct ubcore_resp_cb cb = {
		.callback = ubcore_nego_ver_rsp_msg_cb,
		.user_arg = NULL
	};
	uint32_t data_length;
	int ret;

	if (dev->transport_type != UBCORE_TRANSPORT_UB)
		return 0;

	if (ubcore_negotiated())
		return 0;

	if (!dev->attr.virtualization) {
		ubcore_set_version(UBCORE_VERSION);
		ubcore_set_cap(UBCORE_CAP);
		return 0;
	}

	data_length = sizeof(struct ubcore_msg_nego_ver_req) +
		UBCORE_SUPPORT_VERION_NUM * sizeof(uint32_t);
	req_msg = kcalloc(1, sizeof(struct ubcore_req) + data_length, GFP_KERNEL);
	if (req_msg == NULL)
		return -ENOMEM;

	req_msg->opcode = UBCORE_MSG_NEGO_VER;
	req_msg->len = data_length;

	data = (struct ubcore_msg_nego_ver_req *)req_msg->data;
	data->cap = UBCORE_CAP;
	data->version_num = UBCORE_SUPPORT_VERION_NUM;
	(void)memcpy(data->versions, ubcore_get_support_versions(),
		UBCORE_SUPPORT_VERION_NUM * sizeof(uint32_t));

	ret = ubcore_send_fe2tpf_msg(dev, req_msg, &cb);
	/* Frontend request is freed after above blocking function. */
	kfree(req_msg);
	if (ret != 0) {
		ubcore_log_err("Fail to send fe2tpf version negitiation message.\n");
		return -1;
	}
	return ret;
}

static int ubcore_config_device_rsp_msg_cb(struct ubcore_device *dev,
	struct ubcore_resp *resp, void *msg_ctx)
{
	struct ubcore_msg_config_device_resp *data;
	struct ubcore_device_cfg cfg = {0};

	if (dev == NULL || dev->ops == NULL || dev->ops->config_device == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (resp == NULL || resp->len != sizeof(struct ubcore_msg_config_device_resp) ||
		resp->opcode != UBCORE_MSG_CONFIG_DEVICE) {
		ubcore_log_err("Failed to query data from the UVS. Use the default value.\n");
		return -EINVAL;
	}

	data = (struct ubcore_msg_config_device_resp *)resp->data;
	cfg.fe_idx = dev->attr.fe_idx;
	cfg.mask.bs.rc_cnt = 1;
	cfg.mask.bs.rc_depth = 1;
	cfg.rc_cfg.rc_cnt = data->rc_cnt;
	cfg.rc_cfg.depth = data->rc_depth;

	cfg.mask.bs.reserved_jetty_id_min = 1;
	cfg.mask.bs.reserved_jetty_id_max = 1;
	cfg.reserved_jetty_id_min = UBCORE_RESERVED_JETTY_ID_MIN;
	cfg.reserved_jetty_id_max = UBCORE_RESERVED_JETTY_ID_MAX;

	cfg.mask.bs.slice = data->set_slice;
	cfg.slice = data->slice;

	/* For a new TPF device, the suspend config needs to be set. */
	if (data->is_tpf_dev) {
		cfg.mask.bs.suspend_period = 1;
		cfg.suspend_period = data->suspend_period;
		cfg.mask.bs.suspend_cnt = 1;
		cfg.suspend_cnt = data->suspend_cnt;
	}

	return dev->ops->config_device(dev, &cfg);
}

static int ubcore_config_device_default(struct ubcore_device *dev)
{
	struct ubcore_device_cfg cfg = {0};

	if (dev == NULL || dev->ops == NULL || dev->ops->config_device == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	cfg.fe_idx = dev->attr.fe_idx;

	cfg.mask.bs.rc_cnt = 1;
	cfg.mask.bs.rc_depth = 1;
	cfg.rc_cfg.rc_cnt = dev->attr.dev_cap.max_rc;
	cfg.rc_cfg.depth = dev->attr.dev_cap.max_rc_depth;

	cfg.mask.bs.reserved_jetty_id_min = 1;
	cfg.mask.bs.reserved_jetty_id_max = 1;
	cfg.reserved_jetty_id_min = UBCORE_RESERVED_JETTY_ID_MIN;
	cfg.reserved_jetty_id_max = UBCORE_RESERVED_JETTY_ID_MAX;

	/* slice and mask.slice are set to 0 by default */

	/* If suspend_period and cnt cannot be read, do not need to configure it */
	return dev->ops->config_device(dev, &cfg);
}

static int ubcore_config_device_in_register(struct ubcore_device *dev)
{
	struct ubcore_msg_config_device_req *data;
	struct ubcore_req *req_msg;
	struct ubcore_resp_cb cb = {
		.callback = ubcore_config_device_rsp_msg_cb,
		.user_arg = NULL
	};
	int ret;

	if (dev->transport_type != UBCORE_TRANSPORT_UB)
		return 0;

	if (ubcore_get_netlink_valid() == false && !dev->attr.virtualization) {
		ubcore_log_info("UVS is not connected, and use default config. dev: %s.\n",
			dev->dev_name);
		return ubcore_config_device_default(dev);
	}

	req_msg = kcalloc(1, sizeof(struct ubcore_req) +
		sizeof(struct ubcore_msg_config_device_req), GFP_KERNEL);
	if (req_msg == NULL)
		return -ENOMEM;

	/* Should not send UBCORE_MSG_CONFIG_DEVICE after register dev
	 * It will clear fe resource in uvs
	 */
	req_msg->opcode = UBCORE_MSG_CONFIG_DEVICE;
	req_msg->len = (uint32_t)sizeof(struct ubcore_msg_config_device_req);

	data = (struct ubcore_msg_config_device_req *)req_msg->data;
	(void)memcpy(data->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	data->max_rc_cnt = dev->attr.dev_cap.max_rc;
	data->max_rc_depth = dev->attr.dev_cap.max_rc_depth;
	data->min_slice = dev->attr.dev_cap.min_slice;
	data->max_slice = dev->attr.dev_cap.max_slice;
	data->virtualization = dev->attr.virtualization;

	/* New TPF devices need to be query suspend info. */
	data->is_tpf_dev = dev->attr.tp_maintainer;

	ret = ubcore_send_fe2tpf_msg(dev, req_msg, &cb);
	kfree(req_msg);
	if (ret != 0) {
		ubcore_log_err("send fe2tpf failed.\n");
		return ubcore_config_device_default(dev);
	}
	return ret;
}

static void ubcore_clients_add(struct ubcore_device *dev)
{
	struct ubcore_client *client = NULL;

	down_read(&g_clients_rwsem);
	list_for_each_entry(client, &g_client_list, list_node) {
		if (create_client_ctx(dev, client) != 0)
			ubcore_log_warn("ubcore device: %s add client:%s context failed.\n",
				dev->dev_name, client->client_name);
	}
	up_read(&g_clients_rwsem);
}

static void ubcore_clients_remove(struct ubcore_device *dev)
{
	struct ubcore_client_ctx *ctx, *tmp;

	down_read(&dev->client_ctx_rwsem);
	list_for_each_entry_safe(ctx, tmp, &dev->client_ctx_list, list_node) {
		if (ctx->client && ctx->client->remove)
			ctx->client->remove(dev, ctx->data);
	}
	up_read(&dev->client_ctx_rwsem);

	down_write(&dev->client_ctx_rwsem);
	list_for_each_entry_safe(ctx, tmp, &dev->client_ctx_list, list_node) {
		list_del(&ctx->list_node);
		kfree(ctx);
	}
	up_write(&dev->client_ctx_rwsem);
}

static int ubcore_create_logic_device(struct ubcore_logic_device *ldev,
	struct ubcore_device *dev, struct net *net)
{
	/* create /sys/class/ubcore/<dev->dev_name> */
	write_pnet(&ldev->net, net);
	ldev->ub_dev = dev;

	ldev->dev = device_create(&g_ubcore_class, dev->dev.parent,
		MKDEV(0, 0), ldev, "%s", dev->dev_name);
	if (IS_ERR(ldev->dev)) {
		ubcore_log_err("device create failed, device:%s.\n", dev->dev_name);
		return -ENOMEM;
	}

	if (ubcore_fill_logic_device_attr(ldev, dev) != 0) {
		device_unregister(ldev->dev);
		ldev->dev = NULL;
		ubcore_log_err("failed to fill attributes, device:%s.\n", dev->dev_name);
		return -EPERM;
	}

	return 0;
}

static void ubcore_destroy_logic_device(struct ubcore_logic_device *ldev, struct ubcore_device *dev)
{
	ubcore_unfill_logic_device_attr(ldev, dev);
	device_unregister(ldev->dev);
	ldev->dev = NULL;
}

static void ubcore_remove_one_logic_device(struct ubcore_device *dev, struct net *net)
{
	struct ubcore_logic_device *ldev, *tmp;

	mutex_lock(&dev->ldev_mutex);
	list_for_each_entry_safe(ldev, tmp, &dev->ldev_list, node) {
		if (net_eq(read_pnet(&ldev->net), net)) {
			ubcore_destroy_logic_device(ldev, dev);
			list_del(&ldev->node);
			kfree(ldev);
			break;
		}
	}
	mutex_unlock(&dev->ldev_mutex);
}

static void ubcore_remove_logic_devices(struct ubcore_device *dev)
{
	struct ubcore_logic_device *ldev, *tmp;

	if (dev->transport_type != UBCORE_TRANSPORT_UB)
		return;

	mutex_lock(&dev->ldev_mutex);
	list_for_each_entry_safe(ldev, tmp, &dev->ldev_list, node) {
		ubcore_destroy_logic_device(ldev, dev);
		list_del(&ldev->node);
		kfree(ldev);
	}
	mutex_unlock(&dev->ldev_mutex);
}

static int ubcore_add_one_logic_device(struct ubcore_device *dev, struct net *net)
{
	struct ubcore_logic_device *ldev;
	int ret;

	mutex_lock(&dev->ldev_mutex);
	list_for_each_entry(ldev, &dev->ldev_list, node) {
		if (net_eq(read_pnet(&ldev->net), net)) {
			mutex_unlock(&dev->ldev_mutex);
			return 0;
		}
	}

	ldev = kzalloc(sizeof(struct ubcore_logic_device), GFP_KERNEL);
	if (ldev == NULL) {
		mutex_unlock(&dev->ldev_mutex);
		return -ENOMEM;
	}

	ret = ubcore_create_logic_device(ldev, dev, net);
	if (ret) {
		kfree(ldev);
		mutex_unlock(&dev->ldev_mutex);
		ubcore_log_err("add device failed %s in net %u", dev->dev_name, net->ns.inum);
		return ret;
	}

	list_add_tail(&ldev->node, &dev->ldev_list);
	mutex_unlock(&dev->ldev_mutex);
	ubcore_log_info("add device %s in net %u", dev->dev_name, net->ns.inum);
	return 0;
}

static int ubcore_copy_logic_devices(struct ubcore_device *dev)
{
	struct ubcore_net *unet;
	int ret = 0;

	if (dev->transport_type != UBCORE_TRANSPORT_UB)
		return 0;

	down_read(&g_ubcore_net_rwsem);
	list_for_each_entry(unet, &g_ubcore_net_list, node) {
		if (net_eq(read_pnet(&unet->net), read_pnet(&dev->ldev.net)))
			continue;
		ret = ubcore_add_one_logic_device(dev, read_pnet(&unet->net));
		if (ret != 0)
			break;
	}
	up_read(&g_ubcore_net_rwsem);

	if (ret)
		ubcore_remove_logic_devices(dev);

	return ret;
}

static int ubcore_open(struct inode *i_node, struct file *filp)
{
	return 0;
}

static long ubcore_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ubcore_cmd_hdr hdr;
	int ret;

	if (cmd == UBCORE_UVS_CMD) {
		ret = ubcore_copy_from_user(&hdr, (void *)arg, sizeof(struct ubcore_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBCORE_MAX_CMD_SIZE)) {
			ubcore_log_err("length of ioctl input parameter is out of range.\n");
			return -EINVAL;
		}
		return ubcore_uvs_cmd_parse(&hdr);
	}

	ubcore_log_err("bad ioctl command.\n");
	return -ENOIOCTLCMD;
}

static int ubcore_close(struct inode *i_node, struct file *filp)
{
	return 0;
}

static const struct file_operations g_ubcore_ops = {
	.owner = THIS_MODULE,
	.open = ubcore_open,
	.release = ubcore_close,
	.unlocked_ioctl = ubcore_ioctl,
	.compat_ioctl = ubcore_ioctl,
};

static int ubcore_register_sysfs(void)
{
	int ret;

	// If sysfs is created, return Success
	// Need to add mutex
	if (!IS_ERR_OR_NULL(g_ubcore_ctx.ubcore_dev))
		return 0;

	ret = alloc_chrdev_region(&g_ubcore_ctx.ubcore_devno, 0, 1, UBCORE_DEVICE_NAME);
	if (ret != 0) {
		ubcore_log_err("alloc chrdev region failed, ret:%d.\n", ret);
		return ret;
	}

	cdev_init(&g_ubcore_ctx.ubcore_cdev, &g_ubcore_ops);
	ret = cdev_add(&g_ubcore_ctx.ubcore_cdev, g_ubcore_ctx.ubcore_devno, 1);
	if (ret != 0) {
		ubcore_log_err("chrdev add failed, ret:%d.\n", ret);
		goto unreg_cdev_region;
	}

	/* /dev/ubcore */
	g_ubcore_ctx.ubcore_dev =
		device_create(&g_ubcore_class, NULL, g_ubcore_ctx.ubcore_devno, NULL,
			      UBCORE_DEVICE_NAME);
	if (IS_ERR(g_ubcore_ctx.ubcore_dev)) {
		ret = (int)PTR_ERR(g_ubcore_ctx.ubcore_dev);
		ubcore_log_err("couldn't create device %s, ret:%d.\n", UBCORE_DEVICE_NAME, ret);
		g_ubcore_ctx.ubcore_dev = NULL;
		goto del_cdev;
	}
	ubcore_log_info("ubcore device created success.\n");
	return 0;

del_cdev:
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
unreg_cdev_region:
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
	return ret;
}

int ubcore_unregister_sysfs(void)
{
	// If sysfs is not created, return Success
	// Need to add mutex
	if (IS_ERR_OR_NULL(g_ubcore_ctx.ubcore_dev))
		return 0;

	device_destroy(&g_ubcore_class, g_ubcore_ctx.ubcore_cdev.dev);
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
	ubcore_log_info("ubcore sysfs device destroyed success.\n");
	return 0;
}

typedef int (*ubcore_device_handler)(void);

static int ubcore_device_cdev_proc_withoutlock(ubcore_device_handler cb)
{
	struct ubcore_device *dev;
	uint32_t cnt = 0;
	int ret = 0;

	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->attr.tp_maintainer)
			++cnt;
	}
	if (cnt == 0)
		ret = cb();

	return ret;
}

static int ubcore_device_cdev_proc(ubcore_device_handler cb)
{
	int ret = 0;

	down_read(&g_device_rwsem);
	ret = ubcore_device_cdev_proc_withoutlock(cb);
	up_read(&g_device_rwsem);
	return ret;
}

int ubcore_register_device(struct ubcore_device *dev)
{
	struct ubcore_device *find_dev = NULL;
	int ret;

	if (dev == NULL || dev->ops == NULL || strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) == 0 ||
		strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	find_dev = ubcore_find_device_with_name(dev->dev_name);
	if (find_dev != NULL) {
		ubcore_log_err("Duplicate device name %s.\n", dev->dev_name);
		ubcore_put_device(find_dev);
		return -EEXIST;
	}

	if (init_ubcore_device(dev) != 0) {
		ubcore_log_err("failed to init ubcore device.\n");
		return -EINVAL;
	}

	// dev->attr is invalid before init_ubcore_device
	if (dev->attr.tp_maintainer) {
		ret = ubcore_device_cdev_proc(ubcore_register_sysfs);
		if (ret) {
			uninit_ubcore_device(dev);
			ubcore_log_err("failed to create ubcore char device.\n");
			return -EINVAL;
		}
	}

	ret = ubcore_create_main_device(dev);
	if (ret) {
		if (dev->attr.tp_maintainer)
			(void)ubcore_device_cdev_proc(ubcore_unregister_sysfs);
		uninit_ubcore_device(dev);
		ubcore_log_err("create main device failed.\n");
		return ret;
	}

	if (ubcore_initiate_negotiation(dev) != 0) {
		ubcore_log_err("Fail to negotiate version.\n");
		ret = -1;
		goto destroy_mdev;
	}

	if (ubcore_config_device_in_register(dev) != 0) {
		ubcore_log_err("failed to config ubcore device.\n");
		ret = -EPERM;
		goto destroy_mdev;
	}
	ubcore_cgroup_reg_dev(dev);

	down_write(&g_device_rwsem);
	ubcore_clients_add(dev);
	ret = ubcore_copy_logic_devices(dev);
	if (ret) {
		ubcore_clients_remove(dev);
		up_write(&g_device_rwsem);

		ubcore_log_err("copy logic device failed, device:%s.\n", dev->dev_name);
		goto err;
	}

	list_add_tail(&dev->list_node, &g_device_list);
	up_write(&g_device_rwsem);

	ubcore_log_info("ubcore device: %s register success.\n", dev->dev_name);
	return 0;

err:
	ubcore_cgroup_unreg_dev(dev);
destroy_mdev:
	ubcore_destroy_main_device(dev);
	uninit_ubcore_device(dev);
	if (dev->attr.tp_maintainer)
		(void)ubcore_device_cdev_proc(ubcore_unregister_sysfs);
	return ret;
}
EXPORT_SYMBOL(ubcore_register_device);

void ubcore_unregister_device(struct ubcore_device *dev)
{
	if (dev == NULL || strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_warn("Invalid input dev is null ptr.\n");
		return;
	}
	down_write(&g_device_rwsem);

	/* Remove device from g_device_list */
	list_del(&dev->list_node);

	/* Destroy uburma device, may be scheduled.
	 * This should not be done within a spin_lock_irqsave
	 */
	downgrade_write(&g_device_rwsem);
	ubcore_clients_remove(dev);

	ubcore_flush_workqueue((int)UBCORE_DISPATCH_EVENT_WQ);
	ubcore_flush_workqueue((int)UBCORE_SIP_NOTIFY_WQ);

	ubcore_cgroup_unreg_dev(dev);

	ubcore_remove_logic_devices(dev);
	ubcore_destroy_main_device(dev);
	up_read(&g_device_rwsem);

	/* Pair with set use_cnt = 1 when init device */
	ubcore_put_device(dev);
	/* Wait for use cnt == 0 */
	wait_for_completion(&dev->comp);
	uninit_ubcore_device(dev); /* Protect eid table access security based on ref cnt */

	ubcore_log_info("ubcore device: %s unregister success.\n", dev->dev_name);
}
EXPORT_SYMBOL(ubcore_unregister_device);

void ubcore_register_event_handler(struct ubcore_device *dev, struct ubcore_event_handler *handler)
{
	if (dev == NULL || handler == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}

	down_write(&dev->event_handler_rwsem);
	list_add_tail(&handler->node, &dev->event_handler_list);
	up_write(&dev->event_handler_rwsem);
}
EXPORT_SYMBOL(ubcore_register_event_handler);

static void ubcore_dispatch_event_clients(struct ubcore_event *event)
{
	struct ubcore_event_handler *handler;
	struct ubcore_device *dev = event->ub_dev;

	down_read(&dev->event_handler_rwsem);
	list_for_each_entry(handler, &dev->event_handler_list, node)
		handler->event_callback(event, handler);
	up_read(&dev->event_handler_rwsem);
}

static void ubcore_dispatch_event_task(struct work_struct *work)
{
	struct ubcore_event_work *l_ubcore_event =
		container_of(work, struct ubcore_event_work, work);

	ubcore_dispatch_event_clients(&l_ubcore_event->event);
	kfree(l_ubcore_event);
}

int ubcore_dispatch_event(struct ubcore_event *event)
{
	struct ubcore_event_work *l_ubcore_event;

	l_ubcore_event = kzalloc(sizeof(*l_ubcore_event), GFP_ATOMIC);
	if (!l_ubcore_event)
		return -ENOMEM;

	INIT_WORK(&l_ubcore_event->work, ubcore_dispatch_event_task);
	l_ubcore_event->event = *event;

	if (ubcore_queue_work((int)UBCORE_DISPATCH_EVENT_WQ, &l_ubcore_event->work) != 0) {
		kfree(l_ubcore_event);
		ubcore_log_err("Queue work failed");
	}

	return 0;
}

void ubcore_unregister_event_handler(struct ubcore_device *dev,
				     struct ubcore_event_handler *handler)
{
	if (dev == NULL || handler == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}

	down_write(&dev->event_handler_rwsem);
	list_del(&handler->node);
	up_write(&dev->event_handler_rwsem);
}
EXPORT_SYMBOL(ubcore_unregister_event_handler);

static bool ubcore_preprocess_event(struct ubcore_event *event)
{
	if (event->event_type == UBCORE_EVENT_TP_ERR && event->element.tp != NULL) {
		ubcore_log_info("ubcore detect tp error event with tpn %u", event->element.tp->tpn);
		if (event->ub_dev->transport_type == UBCORE_TRANSPORT_HNS_UB) {
			ubcore_restore_tp(event->ub_dev, event->element.tp);
		} else if (event->ub_dev->transport_type == UBCORE_TRANSPORT_UB) {
			if (event->element.tp->state == UBCORE_TP_STATE_ERR ||
				event->element.tp->state == UBCORE_TP_STATE_RESET) {
				ubcore_log_warn("Tp %u already in state %d, ignore err event",
					event->element.tp->tpn, (int32_t)event->element.tp->state);
				return true;
			}

			if (ubcore_change_tp_to_err(event->ub_dev, event->element.tp) != 0)
				ubcore_log_info("ubcore change tp %u to error failed",
					event->element.tp->tpn);
		}
		return true;
	} else if (event->event_type == UBCORE_EVENT_TP_SUSPEND && event->element.tp != NULL) {
		ubcore_log_info("ubcore detect tp %u suspend event", event->element.tp->tpn);
		ubcore_report_tp_suspend(event->ub_dev, event->element.tp);
		return true;
	} else if (event->event_type == UBCORE_EVENT_MIGRATE_VTP_SWITCH &&
		event->element.vtp != NULL) {
		ubcore_log_info("ubcore detect migrate vtp %u switch event",
			event->element.vtp->cfg.vtpn);
		ubcore_report_migrate_vtp(event->ub_dev, event->element.vtp,
			UBCORE_EVENT_MIGRATE_VTP_SWITCH);
		return true;
	} else if (event->event_type == UBCORE_EVENT_MIGRATE_VTP_ROLLBACK &&
		event->element.vtp != NULL) {
		ubcore_log_info("ubcore detect migrate vtp %u rollback event",
			event->element.vtp->cfg.vtpn);
		ubcore_report_migrate_vtp(event->ub_dev, event->element.vtp,
			UBCORE_EVENT_MIGRATE_VTP_ROLLBACK);
		return true;
	} else if (event->event_type == UBCORE_EVENT_TP_FLUSH_DONE &&
		event->element.tp != NULL) {
		ubcore_log_info("ubcore detect tp %u flush done event", event->element.tp->tpn);
		if (event->element.tp->state == UBCORE_TP_STATE_RESET) {
			ubcore_log_warn("Tp %u already in state %d, ignore flush done event",
				event->element.tp->tpn, (int32_t)event->element.tp->state);
			return true;
		}
		/* flush done means tp already in error,
		 * and all pkt have been send need uvs to restore
		 */
		if (event->ub_dev->transport_type == UBCORE_TRANSPORT_UB)
			ubcore_report_tp_error(event->ub_dev, event->element.tp);
		return true;
	}
	return false;
}

void ubcore_dispatch_async_event(struct ubcore_event *event)
{
	if (event == NULL || event->ub_dev == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}

	if (ubcore_preprocess_event(event))
		return;

	if (ubcore_dispatch_event(event) != 0)
		ubcore_log_err("ubcore_dispatch_event failed");
}
EXPORT_SYMBOL(ubcore_dispatch_async_event);

bool ubcore_eid_accessible(struct ubcore_device *dev, uint32_t eid_index)
{
	struct net *net;

	if (eid_index >= dev->eid_table.eid_cnt) {
		ubcore_log_err("eid_indx: %u is over the up limit: %u",
			eid_index, dev->eid_table.eid_cnt);
		return false;
	}

	spin_lock(&dev->eid_table.lock);
	if (IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
		spin_unlock(&dev->eid_table.lock);
		return false;
	}

	if (!dev->eid_table.eid_entries[eid_index].valid) {
		spin_unlock(&dev->eid_table.lock);
		return false;
	}
	net = dev->eid_table.eid_entries[eid_index].net;
	spin_unlock(&dev->eid_table.lock);
	return net_eq(net, current->nsproxy->net_ns);
}

bool ubcore_dev_accessible(struct ubcore_device *dev, struct net *net)
{
	return (g_shared_ns || net_eq(net, read_pnet(&dev->ldev.net)));
}

struct ubcore_ucontext *ubcore_alloc_ucontext(struct ubcore_device *dev, uint32_t eid_index,
	struct ubcore_udrv_priv *udrv_data)
{
	struct ubcore_ucontext *ucontext;
	struct ubcore_cg_object cg_obj;
	int ret;

	if (dev == NULL || strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME ||
		dev->ops == NULL || dev->ops->alloc_ucontext == NULL ||
			eid_index >= UBCORE_MAX_EID_CNT) {
		ubcore_log_err("Invalid argument.\n");
		return ERR_PTR(-EINVAL);
	}

	if (!ubcore_dev_accessible(dev, current->nsproxy->net_ns) ||
		!ubcore_eid_accessible(dev, eid_index)) {
		ubcore_log_err("eid is not accessible by current ns.\n");
		return ERR_PTR(-EPERM);
	}

	ret = ubcore_cgroup_try_charge(&cg_obj, dev, UBCORE_RESOURCE_HCA_HANDLE);
	if (ret != 0) {
		ubcore_log_err("cgroup charge fail:%d ,dev_name :%s\n", ret, dev->dev_name);
		return ERR_PTR(ret);
	}

	ucontext = dev->ops->alloc_ucontext(dev, eid_index, udrv_data);
	if (IS_ERR_OR_NULL(ucontext)) {
		ubcore_log_err("failed to alloc ucontext.\n");
		ubcore_cgroup_uncharge(&cg_obj, dev, UBCORE_RESOURCE_HCA_HANDLE);
		return UBCORE_CHECK_RETURN_ERR_PTR(ucontext, ENOEXEC);
	}

	ucontext->eid_index = eid_index;
	ucontext->ub_dev = dev;
	ucontext->cg_obj = cg_obj;

	return ucontext;
}
EXPORT_SYMBOL(ubcore_alloc_ucontext);

void ubcore_free_ucontext(struct ubcore_device *dev, struct ubcore_ucontext *ucontext)
{
	int ret;
	struct ubcore_cg_object cg_obj;

	if (dev == NULL || ucontext == NULL || dev->ops == NULL ||
		dev->ops->free_ucontext == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}
	cg_obj = ucontext->cg_obj;

	ret = dev->ops->free_ucontext(ucontext);
	if (ret != 0)
		ubcore_log_err("failed to free_adu, ret: %d.\n", ret);

	ubcore_cgroup_uncharge(&cg_obj, dev, UBCORE_RESOURCE_HCA_HANDLE);
}
EXPORT_SYMBOL(ubcore_free_ucontext);

int ubcore_add_ueid(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg)
{
	int ret;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || fe_idx >= UBCORE_MAX_FE_CNT) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	if (dev->ops->add_ueid == NULL)
		return 0;

	ret = dev->ops->add_ueid(dev, fe_idx, cfg);
	if (ret != 0)
		ubcore_log_err("failed to add ueid, ret:%d\n", ret);

	return ret;
}
EXPORT_SYMBOL(ubcore_add_ueid);

int ubcore_delete_ueid(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg)
{
	int ret;

	if (dev == NULL || cfg == NULL || dev->ops == NULL ||
		fe_idx >= UBCORE_MAX_FE_CNT) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	if (dev->ops->delete_ueid == NULL)
		return 0;

	ret = dev->ops->delete_ueid(dev, fe_idx, cfg);
	if (ret != 0)
		ubcore_log_err("failed to add ueid, ret:%d\n", ret);

	return ret;
}
EXPORT_SYMBOL(ubcore_delete_ueid);

int ubcore_query_device_attr(struct ubcore_device *dev, struct ubcore_device_attr *attr)
{
	int ret;

	if (dev == NULL || attr == NULL || dev->ops == NULL ||
		dev->ops->query_device_attr == NULL) {
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

int ubcore_query_device_status(struct ubcore_device *dev, struct ubcore_device_status *status)
{
	int ret;

	if (dev == NULL || status == NULL || dev->ops == NULL ||
		dev->ops->query_device_status == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->query_device_status(dev, status);
	if (ret != 0) {
		ubcore_log_err("failed to query device status, ret: %d.\n", ret);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_query_device_status);

int ubcore_query_resource(struct ubcore_device *dev, struct ubcore_res_key *key,
			  struct ubcore_res_val *val)
{
	int ret;

	if (dev == NULL || key == NULL || val == NULL || dev->ops == NULL ||
		dev->ops->query_res == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}
	ret = dev->ops->query_res(dev, key, val);
	if (ret != 0) {
		ubcore_log_err("failed to query res, ret: %d.\n", ret);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_query_resource);

int ubcore_config_device(struct ubcore_device *dev, struct ubcore_device_cfg *cfg)
{
	int ret;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->config_device == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->config_device(dev, cfg);
	if (ret != 0) {
		ubcore_log_err("failed to config device, ret: %d.\n", ret);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_config_device);

int ubcore_user_control(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl)
{
	int ret;

	if (k_user_ctl == NULL) {
		ubcore_log_err("invalid parameter with input nullptr.\n");
		return -1;
	}

	if (dev == NULL || dev->ops == NULL || dev->ops->user_ctl == NULL) {
		ubcore_log_err("invalid parameter with dev nullptr.\n");
		return -1;
	}

	ret = dev->ops->user_ctl(dev, k_user_ctl);
	if (ret != 0) {
		ubcore_log_err("failed to exec kdrv_user_ctl in %s.\n", __func__);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL(ubcore_user_control);

int ubcore_query_stats(struct ubcore_device *dev, struct ubcore_stats_key *key,
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

static int ubcore_add_device_sip(struct ubcore_sip_info *sip, uint32_t *sip_idx)
{
	struct ubcore_device *dev;
	uint32_t index;
	int ret = 0;

	if (sip == NULL) {
		ubcore_log_err("There is an illegal parameter.\n");
		return -1;
	}

	dev = ubcore_find_tpf_device_by_name(sip->dev_name);
	if (!dev || dev->transport_type != UBCORE_TRANSPORT_UB) {
		ubcore_log_err("update sip, dev:%s no tpf, or not UB\n", sip->dev_name);
		return -1;
	}

	if (ubcore_lookup_sip_idx(&dev->sip_table, sip, &index) == 0) {
		ubcore_log_warn("sip already exists, sip_idx %u\n", index);
		ret = -EEXIST;
	} else {
		index = ubcore_sip_idx_alloc(&dev->sip_table);

		if (dev->ops->add_net_addr != NULL &&
			dev->ops->add_net_addr(dev, &sip->addr, index) != 0) {
			ubcore_log_err("Failed to set net addr");
			goto free_sip_index;
		}
		/* add net_addr entry, record idx -> netaddr mapping */
		if (ubcore_add_sip_entry(&dev->sip_table, sip, index) != 0)
			goto del_net_addr;
	}

	/* nodify uvs add sip info */
	if (ubcore_get_netlink_valid() == true)
		(void)ubcore_notify_uvs_add_sip(dev, sip, index);

	*sip_idx = index;
	ubcore_put_device(dev);
	return ret;

del_net_addr:
	if (dev->ops->delete_net_addr != NULL)
		dev->ops->delete_net_addr(dev, index);
free_sip_index:
	(void)ubcore_sip_idx_free(&dev->sip_table, index);
	ubcore_put_device(dev);
	return -1;
}

static int ubcore_del_device_sip(struct ubcore_sip_info *sip)
{
	struct ubcore_device *dev;
	uint32_t index;

	if (sip == NULL) {
		ubcore_log_err("There is an illegal parameter.\n");
		return -1;
	}

	dev = ubcore_find_tpf_device_by_name(sip->dev_name);
	if (!dev || dev->transport_type != UBCORE_TRANSPORT_UB) {
		ubcore_log_err("del sip, dev:%s no tpf, or dev not UB\n", sip->dev_name);
		return -1;
	}

	if (ubcore_lookup_sip_idx(&dev->sip_table, sip, &index) != 0) {
		ubcore_log_err("sip not exists\n");
		ubcore_put_device(dev);
		return -1;
	}

	(void)ubcore_del_sip_entry(&dev->sip_table, index);

	if (dev->ops->delete_net_addr != NULL && dev->ops->delete_net_addr(dev, index) != 0) {
		ubcore_log_err("Failed to delete net addr");
		goto add_sip_entry;
	}
	/* nodify uvs add sip info */
	if (ubcore_get_netlink_valid() == true && ubcore_notify_uvs_del_sip(dev, sip, index) != 0)
		goto add_net_addr;

	(void)ubcore_sip_idx_free(&dev->sip_table, index);
	ubcore_put_device(dev);
	return 0;

add_net_addr:
	if (dev->ops->add_net_addr != NULL)
		dev->ops->add_net_addr(dev, &sip->addr, index);
add_sip_entry:
	(void)ubcore_add_sip_entry(&dev->sip_table, sip, index);
	ubcore_put_device(dev);
	return -1;
}

int ubcore_add_sip(struct ubcore_sip_info *sip, uint32_t *sip_idx)
{
	if (sip == NULL || sip_idx == NULL ||
		strnlen(sip->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME ||
		strnlen(sip->netdev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}
	return ubcore_add_device_sip(sip, sip_idx);
}
EXPORT_SYMBOL(ubcore_add_sip);

int ubcore_delete_sip(struct ubcore_sip_info *sip)
{
	if (sip == NULL || strnlen(sip->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("invalid parameter.\n");
		return -EINVAL;
	}

	return ubcore_del_device_sip(sip);
}
EXPORT_SYMBOL(ubcore_delete_sip);

struct ubcore_eid_info *ubcore_get_eid_list(struct ubcore_device *dev, uint32_t *cnt)
{
	struct ubcore_eid_info *eid_list;
	struct ubcore_eid_info *tmp;
	uint32_t count;
	uint32_t i;

	if (dev == NULL || dev->attr.dev_cap.max_eid_cnt == 0 ||
		dev->attr.dev_cap.max_eid_cnt > UBCORE_MAX_EID_CNT || cnt == NULL ||
		IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
		ubcore_log_err("invalid input parameter.\n");
		return NULL;
	}

	tmp = vmalloc(dev->attr.dev_cap.max_eid_cnt * sizeof(struct ubcore_eid_info));
	if (tmp == NULL)
		return NULL;

	spin_lock(&dev->eid_table.lock);
	for (i = 0, count = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == true) {
			tmp[count].eid = dev->eid_table.eid_entries[i].eid;
			tmp[count].eid_index = i;
			count++;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	if (count == 0) {
		vfree(tmp);
		return NULL;
	}
	*cnt = count;

	eid_list = vmalloc(count * sizeof(struct ubcore_eid_info));
	if (eid_list == NULL) {
		vfree(tmp);
		return NULL;
	}
	for (i = 0; i < count; i++)
		eid_list[i] = tmp[i];

	vfree(tmp);
	return eid_list;
}
EXPORT_SYMBOL(ubcore_get_eid_list);

void ubcore_free_eid_list(struct ubcore_eid_info *eid_list)
{
	if (eid_list != NULL)
		vfree(eid_list);
}
EXPORT_SYMBOL(ubcore_free_eid_list);

static int ubcore_lookup_sip_by_addr(struct ubcore_device *dev,
	const union ubcore_net_addr_union *addr)
{
	struct ubcore_sip_table *sip_table = NULL;
	uint32_t i;

	sip_table = &dev->sip_table;
	mutex_lock(&sip_table->lock);
	for (i = 0; i < sip_table->max_sip_cnt; i++) {
		if (sip_table->entry[i].is_active &&
			memcmp(addr, &sip_table->entry[i].addr.net_addr,
				sizeof(union ubcore_net_addr_union)) == 0) {
			mutex_unlock(&sip_table->lock);
			return 0;
		}
	}
	mutex_unlock(&sip_table->lock);

	return -1;
}

struct ubcore_device *ubcore_lookup_tpf_by_sip_addr(union ubcore_net_addr_union *addr)
{
	struct ubcore_device *dev = NULL, *target = NULL;

	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev != NULL && dev->attr.tp_maintainer == true) {
			if (ubcore_lookup_sip_by_addr(dev, addr) == 0) {
				target = dev;
				ubcore_get_device(dev);
				break;
			}
		}
	}
	up_read(&g_device_rwsem);

	return target;
}

static void ubcore_modify_eid_ns(struct ubcore_device *dev, struct net *net)
{
	struct ubcore_eid_entry *e;
	uint32_t i;

	if (dev->eid_table.eid_entries == NULL)
		return;

	spin_lock(&dev->eid_table.lock);
	for (i = 0; i < dev->eid_table.eid_cnt; i++) {
		e = &dev->eid_table.eid_entries[i];
		if (e->valid && !net_eq(e->net, net))
			e->net = net;
	}
	spin_unlock(&dev->eid_table.lock);
}

static void ubcore_invalidate_eid_ns(struct ubcore_device *dev, struct net *net)
{
	struct ubcore_eid_entry *e;
	uint32_t i;

	if (dev->eid_table.eid_entries == NULL)
		return;

	spin_lock(&dev->eid_table.lock);
	for (i = 0; i < dev->eid_table.eid_cnt; i++) {
		e = &dev->eid_table.eid_entries[i];
		if (e->valid && net_eq(e->net, net)) {
			e->net = &init_net;
			e->valid = false;
		}
	}
	spin_unlock(&dev->eid_table.lock);
}

static int ubcore_modify_dev_ns(struct ubcore_device *dev, struct net *net, bool exit)
{
	struct net *cur;
	int ret;

	cur = read_pnet(&dev->ldev.net);
	if (net_eq(net, cur))
		return 0;

	kobject_uevent(&dev->ldev.dev->kobj, KOBJ_REMOVE);
	ubcore_clients_remove(dev);
	write_pnet(&dev->ldev.net, net);
	ret = device_rename(dev->ldev.dev, dev_name(dev->ldev.dev));
	if (ret) {
		write_pnet(&dev->ldev.net, cur);
		ubcore_log_err("Failed to rename device in the new ns.\n");
		goto out;
	}

	if (exit)
		ubcore_invalidate_eid_ns(dev, cur);
	else
		ubcore_modify_eid_ns(dev, net);

out:
	ubcore_clients_add(dev);
	kobject_uevent(&dev->ldev.dev->kobj, KOBJ_ADD);
	return ret;
}

int ubcore_set_dev_ns(char *device_name, uint32_t ns_fd)
{
	struct ubcore_device *dev = NULL, *tmp;
	struct net *net;
	int ret = 0;

	if (!ns_capable(current->nsproxy->net_ns->user_ns, CAP_NET_ADMIN)) {
		ubcore_log_err("current user does not have net admin capability");
		return -EPERM;
	}

	if (g_shared_ns) {
		ubcore_log_err("Can not set device to ns under shared ns mode.\n");
		return -EPERM;
	}

	net = get_net_ns_by_fd(ns_fd);
	if (IS_ERR(net)) {
		ubcore_log_err("Failed to get ns by fd.\n");
		return PTR_ERR(net);
	}

	/* Find device by name */
	/* device_name len checked by genl */
	down_read(&g_device_rwsem);
	list_for_each_entry(tmp, &g_device_list, list_node) {
		if (strcmp(dev_name(tmp->ldev.dev), device_name) == 0) {
			dev = tmp;
			break;
		}
	}
	if (dev == NULL || dev->transport_type != UBCORE_TRANSPORT_UB) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find device.\n");
		goto out;
	}

	/* Put device in the new ns */
	ret = ubcore_modify_dev_ns(dev, net, false);

out:
	up_read(&g_device_rwsem);
	put_net(net);
	return ret;
}

int ubcore_set_ns_mode(bool shared)
{
	unsigned long flags;

	if (!ns_capable(current->nsproxy->net_ns->user_ns, CAP_NET_ADMIN)) {
		ubcore_log_err("current user does not have net admin capability");
		return -EPERM;
	}

	down_write(&g_ubcore_net_rwsem);
	if (g_shared_ns == shared) {
		up_write(&g_ubcore_net_rwsem);
		return 0;
	}
	spin_lock_irqsave(&g_ubcore_net_lock, flags);
	if (!list_empty(&g_ubcore_net_list)) {
		spin_unlock_irqrestore(&g_ubcore_net_lock, flags);
		up_write(&g_ubcore_net_rwsem);
		ubcore_log_err("Failed to modify ns mode with existing ns");
		return -EPERM;
	}
	g_shared_ns = shared;
	spin_unlock_irqrestore(&g_ubcore_net_lock, flags);
	up_write(&g_ubcore_net_rwsem);
	return 0;
}

void ubcore_net_exit(struct net *net)
{
	struct ubcore_net *unet = net_generic(net, g_ubcore_net_id);
	struct ubcore_device *dev;
	unsigned long flags;

	if (unet == NULL)
		return;

	ubcore_log_info("net exit %u, net:0x%p", net->ns.inum, net);
	down_write(&g_ubcore_net_rwsem);
	spin_lock_irqsave(&g_ubcore_net_lock, flags);
	if (list_empty(&unet->node)) {
		spin_unlock_irqrestore(&g_ubcore_net_lock, flags);
		up_write(&g_ubcore_net_rwsem);
		return;
	}
	list_del_init(&unet->node);
	spin_unlock_irqrestore(&g_ubcore_net_lock, flags);
	up_write(&g_ubcore_net_rwsem);

	if (!g_shared_ns) {
		down_read(&g_device_rwsem);
		list_for_each_entry(dev, &g_device_list, list_node) {
			if (dev->transport_type != UBCORE_TRANSPORT_UB ||
				!net_eq(read_pnet(&dev->ldev.net), net))
				continue;
			(void)ubcore_modify_dev_ns(dev, &init_net, true);
		}
		up_read(&g_device_rwsem);
	} else {
		down_write(&g_device_rwsem);
		list_for_each_entry(dev, &g_device_list, list_node) {
			if (dev->transport_type != UBCORE_TRANSPORT_UB)
				continue;
			ubcore_remove_one_logic_device(dev, net);
			ubcore_invalidate_eid_ns(dev, net);
		}
		up_write(&g_device_rwsem);
	}
}

static int ubcore_net_init(struct net *net)
{
	struct ubcore_net *unet = net_generic(net, g_ubcore_net_id);
	struct ubcore_device *dev;
	unsigned long flags;
	int ret = 0;

	if (unet == NULL)
		return 0;

	ubcore_log_info("net init %u, net:0x%p", net->ns.inum, net);
	write_pnet(&unet->net, net);
	if (net_eq(net, &init_net)) {
		INIT_LIST_HEAD(&unet->node);
		return 0;
	}

	spin_lock_irqsave(&g_ubcore_net_lock, flags);
	list_add_tail(&unet->node, &g_ubcore_net_list);
	spin_unlock_irqrestore(&g_ubcore_net_lock, flags);

	if (!g_shared_ns)
		return 0;

	down_read(&g_device_rwsem);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->transport_type != UBCORE_TRANSPORT_UB)
			continue;

		down_read(&g_ubcore_net_rwsem);
		ret = ubcore_add_one_logic_device(dev, net);
		up_read(&g_ubcore_net_rwsem);
		if (ret)
			break;
	}
	up_read(&g_device_rwsem);
	if (ret)
		ubcore_net_exit(net);

	/* return ret will cause error starting a container */
	return 0;
}

int ubcore_get_max_mtu(struct ubcore_device *dev, enum ubcore_mtu *mtu)
{
	enum ubcore_mtu mtu_min = UBCORE_MTU_8192;
	enum ubcore_mtu mtu_tmp;
	bool found = false;
	uint32_t i;

	if (dev == NULL ||  mtu == NULL) {
		ubcore_log_info("invalid parameter");
		return -1;
	}

	for (i = 0; i < UBCORE_MAX_PORT_CNT; i++) {
		mtu_tmp = dev->attr.port_attr[i].max_mtu;
		if ((uint32_t)mtu_tmp != 0 && mtu_tmp <= mtu_min) {
			mtu_min = mtu_tmp;
			found = true;
		}
	}

	if (!found) {
		ubcore_log_err("Failed to find valid max_mtu");
		return -1;
	}

	*mtu = mtu_min;
	return 0;
}

static struct pernet_operations g_ubcore_net_ops = {
	.init = ubcore_net_init,
	.exit = ubcore_net_exit,
	.id = &g_ubcore_net_id,
	.size = sizeof(struct ubcore_net)
};

int ubcore_register_pnet_ops(void)
{
	return register_pernet_device(&g_ubcore_net_ops);
}
void ubcore_unregister_pnet_ops(void)
{
	unregister_pernet_device(&g_ubcore_net_ops);
}

int ubcore_class_register(void)
{
	int ret;

	ret = class_register(&g_ubcore_class);
	if (ret)
		ubcore_log_err("couldn't create class\n");
	return ret;
}

void ubcore_class_unregister(void)
{
	class_unregister(&g_ubcore_class);
}
