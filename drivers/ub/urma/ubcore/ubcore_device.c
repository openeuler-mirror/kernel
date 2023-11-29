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
#include <linux/netdevice.h>

#include "ubcore_log.h"
#include <urma/ubcore_uapi.h>
#include <urma/ubcore_api.h>
#include "ubcore_priv.h"
#include "ubcore_hash_table.h"
#include "ubcore_tp.h"
#include "ubcore_tp_table.h"
#include "ubcore_msg.h"
#include "ubcore_netdev.h"
#include "ubcore_vtp.h"
#include "ubcore_netlink.h"

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
static struct ubcore_device *g_tpf;
static DEFINE_MUTEX(g_upi_lock);
static LIST_HEAD(g_upi_list);

struct ubcore_upi_entry {
	struct ubcore_device *dev;
	uint32_t upi;
	struct list_head node;
};

void ubcore_set_client_ctx_data(struct ubcore_device *dev, struct ubcore_client *client,
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

void *ubcore_get_client_ctx_data(struct ubcore_device *dev, struct ubcore_client *client)
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
	uint32_t idx;

	mutex_lock(&g_device_mutex);
	list_for_each_entry(dev, &g_device_list, list_node) {
		for (idx = 0; idx < dev->attr.max_eid_cnt; idx++) {
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
	mutex_unlock(&g_device_mutex);
	return target;
}

struct ubcore_device *ubcore_find_device_with_name(const char *dev_name)
{
	struct ubcore_device *dev, *target = NULL;

	mutex_lock(&g_device_mutex);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (strcmp(dev->dev_name, dev_name) == 0) {
			target = dev;
			ubcore_get_device(target);
			break;
		}
	}
	mutex_unlock(&g_device_mutex);
	return target;
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
	struct ubcore_upi_entry *entry, *new_entry;

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

void ubcore_destroy_upi_list(void)
{
	struct ubcore_upi_entry *entry = NULL, *next;

	mutex_lock(&g_upi_lock);
	list_for_each_entry_safe(entry, next, &g_upi_list, node) {
		if (entry != NULL) {
			list_del(&entry->node);
			kfree(entry);
		}
	}
	mutex_unlock(&g_upi_lock);
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

struct ubcore_device *ubcore_find_tpf_device(struct ubcore_net_addr *netaddr,
	enum ubcore_transport_type type)
{
	if (g_tpf == NULL)
		ubcore_log_err("tpf is not registered yet");

	ubcore_get_device(g_tpf);
	return g_tpf;
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
	mutex_lock(&g_device_mutex);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->attr.tp_maintainer == false)
			continue;

		dev_cfg.fe_idx = dev->attr.fe_idx;
		ret = ubcore_config_device(dev, &dev_cfg);
		if (ret != 0)
			ubcore_log_err("dev: %s set failed, ret: %d", dev->dev_name, ret);
	}
	mutex_unlock(&g_device_mutex);
	return 0;
}

static struct ubcore_ht_param g_ht_params[] = {
	[UBCORE_HT_JFS] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jfs, hnode),
		offsetof(struct ubcore_jfs, id), sizeof(uint32_t), NULL, NULL},

	[UBCORE_HT_JFR] = { UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jfr, hnode),
			    offsetof(struct ubcore_jfr, id), sizeof(uint32_t), NULL, NULL },

	[UBCORE_HT_JFC] = { UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jfc, hnode),
			    offsetof(struct ubcore_jfc, id), sizeof(uint32_t), NULL, NULL },

	[UBCORE_HT_JETTY] = { UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_jetty, hnode),
			      offsetof(struct ubcore_jetty, id), sizeof(uint32_t), NULL, NULL },

	[UBCORE_HT_TP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_tp_node, hnode),
		offsetof(struct ubcore_tp_node, key), sizeof(struct ubcore_tp_key), NULL, NULL},

	[UBCORE_HT_TPG] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_tpg, hnode),
		offsetof(struct ubcore_tpg, tpgn), sizeof(uint32_t), NULL, NULL},

	/* key: seid + deid */
	[UBCORE_HT_RM_VTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtp, hnode),
		offsetof(struct ubcore_vtp, cfg) + offsetof(struct ubcore_vtp_cfg, local_eid),
		sizeof(union ubcore_eid) * 2, NULL, NULL},

	/* key: deid + djetty */
	[UBCORE_HT_RC_VTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtp, hnode),
		offsetof(struct ubcore_vtp, cfg) + offsetof(struct ubcore_vtp_cfg, peer_eid),
		sizeof(union ubcore_eid) + sizeof(uint32_t), NULL, NULL},

	/* key: seid + deid */
	[UBCORE_HT_UM_VTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtp, hnode),
		offsetof(struct ubcore_vtp, cfg) + offsetof(struct ubcore_vtp_cfg, local_eid),
		sizeof(union ubcore_eid) * 2, NULL, NULL},

	/* key: src_eid + des_eid */
	[UBCORE_HT_VTPN] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_vtpn, hnode),
		offsetof(struct ubcore_vtpn, local_eid), sizeof(union ubcore_eid) * 2, NULL, NULL},

	/* key: utp idx */
	[UBCORE_HT_UTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_utp, hnode),
		offsetof(struct ubcore_utp, utpn), sizeof(uint32_t), NULL, NULL},

	/* key: ctp idx */
	[UBCORE_HT_CTP] = {UBCORE_HASH_TABLE_SIZE, offsetof(struct ubcore_ctp, hnode),
		offsetof(struct ubcore_ctp, ctpn), sizeof(uint32_t), NULL, NULL},
};

static int ubcore_alloc_hash_tables(struct ubcore_device *dev)
{
	uint32_t i, j;
	int ret;

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

	entry_list = kcalloc(1,
		dev->attr.max_eid_cnt * sizeof(struct ubcore_eid_entry), GFP_ATOMIC);
	if (entry_list == NULL)
		return -ENOMEM;

	dev->eid_table.eid_entries = entry_list;
	spin_lock_init(&dev->eid_table.lock);
	dev->eid_table.eid_cnt = dev->attr.max_eid_cnt;
	dev->dynamic_eid = 1;
	return 0;
}

static void ubcore_destroy_eidtable(struct ubcore_device *dev)
{
	if (dev->eid_table.eid_entries != NULL) {
		kfree(dev->eid_table.eid_entries);
		dev->eid_table.eid_entries = NULL;
	}
}

static int ubcore_query_send_tpf_dev_info(struct ubcore_device *dev)
{
	struct ubcore_nlmsg *resp_msg, *req_msg;
	struct ubcore_update_tpf_dev_info_resp *resp;
	struct ubcore_update_tpf_dev_info_req *data;
	struct ubcore_cc_entry *cc_entry;
	struct ubcore_cc_entry *array;
	uint32_t cc_entry_cnt;
	uint32_t cc_len;
	int ret;

	if (dev->ops == NULL || dev->ops->query_cc == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		return -EINVAL;
	}

	cc_entry = dev->ops->query_cc(dev, &cc_entry_cnt);
	if (cc_entry == NULL) {
		ubcore_log_err("Failed to query cc entry\n");
		return -EPERM;
	}

	if (cc_entry_cnt > UBCORE_CC_IDX_TABLE_SIZE || cc_entry_cnt == 0) {
		kfree(cc_entry);
		ubcore_log_err("cc_entry_cnt invalid, %u.\n", cc_entry_cnt);
		return -EINVAL;
	}

	cc_len = sizeof(struct ubcore_update_tpf_dev_info_req) +
		cc_entry_cnt * sizeof(struct ubcore_cc_entry);

	req_msg = kcalloc(1, sizeof(struct ubcore_nlmsg) + cc_len, GFP_KERNEL);
	if (req_msg == NULL) {
		kfree(cc_entry);
		ubcore_log_err("Failed to alloc update tpf dev req msg.\n");
		return -ENOMEM;
	}

	/* fill msg head */
	req_msg->msg_type = UBCORE_NL_UPDATE_TPF_DEV_INFO_REQ;
	req_msg->transport_type = dev->transport_type;
	req_msg->payload_len = cc_len;

	/* fill msg payload */
	data = (struct ubcore_update_tpf_dev_info_req *)req_msg->payload;
	data->dev_fea = dev->attr.dev_cap.feature;
	data->cc_entry_cnt = cc_entry_cnt;
	(void)strcpy(data->dev_name, dev->dev_name);
	array = (struct ubcore_cc_entry *)data->data;
	(void)memcpy(array, cc_entry, sizeof(struct ubcore_cc_entry) * cc_entry_cnt);

	resp_msg = ubcore_nl_send_wait(req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to wait query response");
		kfree(cc_entry);
		kfree(req_msg);
		return -1;
	}

	resp = (struct ubcore_update_tpf_dev_info_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != UBCORE_NL_UPDATE_TPF_DEV_INFO_RESP || resp == NULL ||
		resp->ret != UBCORE_NL_RESP_SUCCESS) {
		ubcore_log_err("update tpf dev info request is rejected with type %d ret %d",
			resp_msg->msg_type, (resp == NULL ? 1 : resp->ret));
		ret = -1;
	} else {
		ret = 0;
	}

	kfree(cc_entry);
	kfree(resp_msg);
	kfree(req_msg);
	return ret;
}

int ubcore_query_all_device_tpf_dev_info(void)
{
	struct ubcore_device *dev;
	int ret = 0;

	mutex_lock(&g_device_mutex);
	list_for_each_entry(dev, &g_device_list, list_node) {
		if (dev->transport_type == UBCORE_TRANSPORT_UB && dev->attr.tp_maintainer) {
			if (ubcore_query_send_tpf_dev_info(dev) != 0) {
				ubcore_log_warn("failed to update tpf dev info in ubcore with dev name %s",
					dev->dev_name);
				ret = -1;
			}
		}
	}
	mutex_unlock(&g_device_mutex);
	return ret;
}

static int init_ubcore_device(struct ubcore_device *dev)
{
	if (dev->ops->query_device_attr != NULL &&
	    dev->ops->query_device_attr(dev, &dev->attr) != 0) {
		ubcore_log_err("Failed to query device attributes");
		return -1;
	}

	/* set tpf device */
	if (dev->transport_type == UBCORE_TRANSPORT_UB && g_tpf == NULL && dev->attr.tp_maintainer)
		g_tpf = dev;

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
	ubcore_update_default_eid(dev, true);
	return 0;
}

static void uninit_ubcore_device(struct ubcore_device *dev)
{
	ubcore_update_default_eid(dev, false);
	ubcore_free_hash_tables(dev);
	ubcore_destroy_eidtable(dev);

	if (!dev->attr.virtualization)
		ubcore_destroy_upi_list();
	if (g_tpf == dev && dev->attr.tp_maintainer)
		g_tpf = NULL;

	put_device(&dev->dev);
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

	cfg.mask.bs.slice = 1;
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

	cfg.mask.bs.slice = 1;
	cfg.slice = dev->attr.dev_cap.max_slice;

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

	if (ubcore_get_netlink_valid() == false) {
		ubcore_log_info("UVS is not connected, and use default config. dev: %s.\n",
			dev->dev_name);
		return ubcore_config_device_default(dev);
	}

	req_msg = kcalloc(1, sizeof(struct ubcore_req) +
		sizeof(struct ubcore_msg_config_device_req), GFP_KERNEL);
	if (req_msg == NULL)
		return -ENOMEM;

	req_msg->opcode = UBCORE_MSG_CONFIG_DEVICE;
	req_msg->len = (uint32_t)sizeof(struct ubcore_msg_config_device_req);

	data = (struct ubcore_msg_config_device_req *)req_msg->data;
	(void)memcpy(data->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	data->max_rc_cnt = dev->attr.dev_cap.max_rc;
	data->max_rc_depth = dev->attr.dev_cap.max_rc_depth;
	data->min_slice = dev->attr.dev_cap.min_slice;
	data->max_slice = dev->attr.dev_cap.max_slice;

	/* New TPF devices need to be query suspend info. */
	data->is_tpf_dev = dev->attr.tp_maintainer;

	ret = ubcore_send_fe2tpf_msg(dev, req_msg, true, &cb);
	if (ret != 0) {
		ubcore_log_err("send fe2tpf failed.\n");
		return ubcore_config_device_default(dev);
	}
	return ret;
}

int ubcore_register_device(struct ubcore_device *dev)
{
	struct ubcore_client *client = NULL;
	struct ubcore_client_ctx *ctx = NULL;
	struct ubcore_device *find_dev = NULL;

	if (dev == NULL || dev->ops == NULL || strlen(dev->dev_name) == 0) {
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

	if (ubcore_config_device_in_register(dev) != 0) {
		ubcore_log_err("failed to config ubcore device.\n");
		return -EPERM;
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

void ubcore_register_event_handler(struct ubcore_device *dev, struct ubcore_event_handler *handler)
{
	unsigned long flags;

	if (dev == NULL || handler == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}

	spin_lock_irqsave(&dev->event_handler_lock, flags);
	list_add_tail(&handler->node, &dev->event_handler_list);
	spin_unlock_irqrestore(&dev->event_handler_lock, flags);
}
EXPORT_SYMBOL(ubcore_register_event_handler);

void ubcore_unregister_event_handler(struct ubcore_device *dev,
				     struct ubcore_event_handler *handler)
{
	unsigned long flags;

	if (dev == NULL || handler == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}

	spin_lock_irqsave(&dev->event_handler_lock, flags);
	list_del(&handler->node);
	spin_unlock_irqrestore(&dev->event_handler_lock, flags);
}
EXPORT_SYMBOL(ubcore_unregister_event_handler);

void ubcore_dispatch_async_event(struct ubcore_event *event)
{
	struct ubcore_event_handler *handler;
	struct ubcore_device *dev;
	unsigned long flags;

	if (event == NULL || event->ub_dev == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}

	if (event->event_type == UBCORE_EVENT_TP_ERR && event->element.tp != NULL) {
		ubcore_log_info("ubcore detect tp error event");
		if (event->ub_dev->transport_type == UBCORE_TRANSPORT_IB) {
			ubcore_restore_tp(event->ub_dev, event->element.tp);
		} else if (event->ub_dev->transport_type == UBCORE_TRANSPORT_UB) {
			if (event->element.tp->state == UBCORE_TP_STATE_ERR ||
				event->element.tp->state == UBCORE_TP_STATE_RESET) {
				ubcore_log_warn("Tp already in state %d, ignore err event",
					(int32_t)event->element.tp->state);
				return;
			}

			if (ubcore_change_tp_to_err(event->ub_dev, event->element.tp) != 0)
				ubcore_log_info("ubcore change tp to error failed");
		}
		return;
	} else if (event->event_type == UBCORE_EVENT_TP_SUSPEND && event->element.tp != NULL) {
		ubcore_log_info("ubcore detect tp suspend event");
		ubcore_report_tp_suspend(event->ub_dev, event->element.tp);
		return;
	} else if (event->event_type == UBCORE_EVENT_MIGRATE_VTP_SWITCH &&
		event->element.vtp != NULL) {
		ubcore_log_info("ubcore detect migrate vtp switch event");
		ubcore_report_migrate_vtp(event->ub_dev, event->element.vtp,
			UBCORE_EVENT_MIGRATE_VTP_SWITCH);
		return;
	} else if (event->event_type == UBCORE_EVENT_MIGRATE_VTP_ROLLBACK &&
		event->element.vtp != NULL) {
		ubcore_log_info("ubcore detect migrate vtp rollback event");
		ubcore_report_migrate_vtp(event->ub_dev, event->element.vtp,
			UBCORE_EVENT_MIGRATE_VTP_ROLLBACK);
		return;
	} else if (event->event_type == UBCORE_EVENT_TP_FLUSH_DONE) {
		ubcore_log_info("ubcore detect tp flush done event");
		if (event->element.tp->state == UBCORE_TP_STATE_RESET) {
			ubcore_log_warn("Tp already in state %d, ignore flush done event",
				(int32_t)event->element.tp->state);
			return;
		}
		/* flush done means tp already in error,
		 * and all pkt have been send need uvs to restore
		 */
		if (event->ub_dev->transport_type == UBCORE_TRANSPORT_UB)
			ubcore_report_tp_error(event->ub_dev, event->element.tp);
		return;
	}

	dev = event->ub_dev;
	spin_lock_irqsave(&dev->event_handler_lock, flags);
	list_for_each_entry(handler, &dev->event_handler_list, node)
		handler->event_callback(event, handler);
	spin_unlock_irqrestore(&dev->event_handler_lock, flags);
}
EXPORT_SYMBOL(ubcore_dispatch_async_event);

struct ubcore_ucontext *ubcore_alloc_ucontext(struct ubcore_device *dev, uint32_t eid_index,
	struct ubcore_udrv_priv *udrv_data)
{
	struct ubcore_ucontext *ucontext;

	if (dev == NULL || dev->ops == NULL || dev->ops->alloc_ucontext == NULL) {
		ubcore_log_err("alloc_ucontext not registered.\n");
		return NULL;
	}
	ucontext = dev->ops->alloc_ucontext(dev, eid_index, udrv_data);
	if (ucontext == NULL) {
		ubcore_log_err("failed to alloc ucontext.\n");
		return NULL;
	}

	ucontext->eid_index = eid_index;
	ucontext->ub_dev = dev;
	return ucontext;
}
EXPORT_SYMBOL(ubcore_alloc_ucontext);

void ubcore_free_ucontext(struct ubcore_device *dev, struct ubcore_ucontext *ucontext)
{
	int ret;

	if (dev == NULL || ucontext == NULL || dev->ops == NULL ||
	    dev->ops->free_ucontext == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return;
	}

	ret = dev->ops->free_ucontext(ucontext);
	if (ret != 0)
		ubcore_log_err("failed to free_adu, ret: %d.\n", ret);
}
EXPORT_SYMBOL(ubcore_free_ucontext);

int ubcore_set_upi(struct ubcore_device *dev, uint16_t fe_idx, uint16_t idx, uint32_t upi)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->set_upi == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->set_upi(dev, fe_idx, idx, upi);
	if (ret != 0) {
		ubcore_log_err("failed to set fe%hu upi%hu, ret: %d.\n", fe_idx, idx, ret);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_set_upi);

int ubcore_add_ueid(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg)
{
	int ret;

	if (dev == NULL || cfg == NULL || dev->ops == NULL || dev->ops->add_ueid == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->add_ueid(dev, fe_idx, cfg);
	if (ret != 0) {
		ubcore_log_err("failed to add ueid, ret: %d.\n", ret);
		return -EPERM;
	}
	return ret;
}
EXPORT_SYMBOL(ubcore_add_ueid);

int ubcore_delete_ueid(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->delete_ueid == NULL) {
		ubcore_log_err("Invalid argument.\n");
		return -EINVAL;
	}

	ret = dev->ops->delete_ueid(dev, fe_idx, cfg);
	if (ret != 0) {
		ubcore_log_err("failed to delete eid, ret: %d.\n", ret);
		return -EPERM;
	}
	return ret;
}
EXPORT_SYMBOL(ubcore_delete_ueid);

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

int ubcore_query_device_status(struct ubcore_device *dev, struct ubcore_device_status *status)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->query_device_status == NULL) {
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

static int ubcore_add_device_sip(struct ubcore_device *dev, struct ubcore_sip_info *sip)
{
	uint32_t index;
	int ret;

	ret = ubcore_lookup_sip_idx(sip, &index);
	if (ret == 0) {
		ubcore_log_err("sip already exists\n");
		return -1;
	}
	index = ubcore_sip_idx_alloc(0);

	if (dev->ops->add_net_addr != NULL && dev->ops->add_net_addr(dev, &sip->addr, index) != 0) {
		ubcore_log_err("Failed to set net addr");
		ret = -1;
		goto free_sip_index;
	}
	/* add net_addr entry, record idx -> netaddr mapping */
	if (ubcore_add_sip_entry(sip, index) != 0) {
		ret = -1;
		goto del_net_addr;
	}
	/* nodify uvs add sip info */
	if (ubcore_get_netlink_valid() == true)
		(void)ubcore_notify_uvs_add_sip(dev, sip, index);
	return 0;

del_net_addr:
	if (dev->ops->delete_net_addr != NULL)
		dev->ops->delete_net_addr(dev, index);
free_sip_index:
	(void)ubcore_sip_idx_free(index);
	return ret;
}

static int ubcore_del_device_sip(struct ubcore_device *dev, struct ubcore_sip_info *sip)
{
	uint32_t index;

	if (ubcore_lookup_sip_idx(sip, &index) != 0)
		return -1;

	(void)ubcore_del_sip_entry(index);

	if (dev->ops->delete_net_addr != NULL && dev->ops->delete_net_addr(dev, index) != 0) {
		ubcore_log_err("Failed to delete net addr");
		(void)ubcore_add_sip_entry(sip, index);
		return -1;
	}
	/* nodify uvs add sip info */
	if (ubcore_get_netlink_valid() == true)
		(void)ubcore_notify_uvs_del_sip(dev, sip, index);

	(void)ubcore_sip_idx_free(index);
	return 0;
}

static int ubcore_update_sip(struct ubcore_sip_info *sip, bool is_add)
{
	struct ubcore_device *tpf_dev;

	if (sip == NULL) {
		ubcore_log_err("There is an illegal parameter.\n");
		return -1;
	}
	tpf_dev = ubcore_find_tpf_device(&sip->addr, UBCORE_TRANSPORT_UB);
	if (is_add) {
		if (tpf_dev && ubcore_add_device_sip(tpf_dev, sip) != 0) {
			ubcore_put_device(tpf_dev);
			return -1;
		}
	} else {
		if (tpf_dev && ubcore_del_device_sip(tpf_dev, sip) != 0) {
			ubcore_put_device(tpf_dev);
			return -1;
		}
	}
	ubcore_put_device(tpf_dev);
	return 0;
}

int ubcore_add_sip(struct ubcore_sip_info *sip)
{
	return ubcore_update_sip(sip, true);
}
EXPORT_SYMBOL(ubcore_add_sip);

int ubcore_delete_sip(struct ubcore_sip_info *sip)
{
	return ubcore_update_sip(sip, false);
}
EXPORT_SYMBOL(ubcore_delete_sip);

void ubcore_sync_sip_table(void)
{
	struct ubcore_sip_info *sip;
	struct ubcore_device *tpf_dev;
	uint32_t max_cnt;
	uint32_t i;

	max_cnt = ubcore_get_sip_max_cnt();

	for (i = 0; i < max_cnt; i++) {
		sip = ubcore_lookup_sip_info(i);
		if (sip == NULL)
			continue;

		tpf_dev = ubcore_find_tpf_device(&sip->addr, UBCORE_TRANSPORT_UB);
		if (tpf_dev) {
			(void)ubcore_notify_uvs_add_sip(tpf_dev, sip, i);
			ubcore_put_device(tpf_dev);
		}
	}
}

struct ubcore_eid_info *ubcore_get_eid_list(struct ubcore_device *dev, uint32_t *cnt)
{
	struct ubcore_eid_info *tmp;
	struct ubcore_eid_info *eid_list;
	uint32_t count;
	uint32_t i;

	tmp = vmalloc(dev->attr.max_eid_cnt * sizeof(struct ubcore_eid_info));
	if (tmp == NULL)
		return NULL;

	spin_lock(&dev->eid_table.lock);
	for (i = 0, count = 0; i < dev->attr.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == true) {
			tmp[count].eid = dev->eid_table.eid_entries[i].eid;
			tmp[count].eid_index = i;
			count++;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	*cnt = count;

	eid_list = vmalloc(count * sizeof(struct ubcore_eid_info));
	if (eid_list == NULL) {
		vfree(tmp);
		ubcore_log_err("failed to apply for memory.\n");
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
