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
 * Description: ubcore netdev module
 * Author: Chen Wen
 * Create: 2023-08-27
 * Note:
 * History: 2023-08-27: create file
 */
#include <linux/device.h>
#include <linux/netdevice.h>

#include <urma/ubcore_types.h>
#include "ubcore_log.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_netlink.h"
#include "ubcore_priv.h"

static DECLARE_RWSEM(g_port_list_lock);

struct ubcore_ndev_port {
	struct net_device *ndev;
	uint8_t port_list[UBCORE_MAX_PORT_CNT];
	bool valid_list[UBCORE_MAX_PORT_CNT];
	uint8_t port_cnt;
	struct list_head node;
	char dev_name[UBCORE_MAX_DEV_NAME];
};

uint32_t ubcore_get_sip_max_cnt(struct ubcore_sip_table *sip_table)
{
	int i;

	for (i = (int)UBCORE_SIP_TABLE_SIZE - 1; i >= 0; i--) {
		if (sip_table->entry[i] != NULL)
			break;
	}

	return (uint32_t)(i + 1);
}

struct ubcore_sip_info *ubcore_lookup_sip_info(struct ubcore_sip_table *sip_table, uint32_t idx)
{
	struct ubcore_sip_info *sip = NULL;

	if (idx >= UBCORE_SIP_TABLE_SIZE || sip_table->entry[idx] == NULL) {
		ubcore_log_err("sip node does not exist");
		return NULL;
	}
	sip = sip_table->entry[idx];
	return sip;
}

static struct ubcore_nlmsg *ubcore_alloc_sip_req(enum ubcore_nlmsg_type msg_type,
	enum ubcore_transport_type transport_type, uint32_t payload_len,
	struct ubcore_sip_info *sip_info)
{
	struct ubcore_nlmsg *req_msg;

	req_msg = kzalloc(sizeof(struct ubcore_nlmsg) + payload_len, GFP_KERNEL);
	if (req_msg == NULL)
		return NULL;

	req_msg->msg_type = msg_type;
	req_msg->transport_type = transport_type;
	(void)memcpy(req_msg->dst_eid.raw, sip_info->addr.net_addr.raw,
		UBCORE_EID_SIZE);
	(void)memcpy(req_msg->src_eid.raw, sip_info->addr.net_addr.raw,
		UBCORE_EID_SIZE);
	req_msg->payload_len = payload_len;

	return req_msg;
}

int ubcore_notify_uvs_del_sip(struct ubcore_device *dev,
	struct ubcore_sip_info *sip_info, uint32_t index)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;
	struct ubcore_del_sip_req *sip_req;
	struct ubcore_del_sip_resp *resp;

	req_msg = ubcore_alloc_sip_req(UBCORE_NL_DEL_SIP_REQ, dev->transport_type,
		sizeof(struct ubcore_del_sip_req), sip_info);
	if (req_msg == NULL)
		return -ENOMEM;

	sip_req = (struct ubcore_del_sip_req *)(void *)req_msg->payload;
	sip_req->index = index;
	(void)memcpy(sip_req->dev_name, dev->dev_name,
		UBCORE_MAX_DEV_NAME);

	resp_msg = ubcore_nl_send_wait(dev, req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to wait query response");
		kfree(req_msg);
		return -1;
	}
	resp = (struct ubcore_del_sip_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != UBCORE_NL_DEL_SIP_RESP ||
		resp_msg->payload_len != sizeof(struct ubcore_del_sip_resp) ||
		resp->ret != UBCORE_NL_RESP_SUCCESS) {
		ubcore_log_err("del sip request is rejected with type %d ret %d",
			resp_msg->msg_type, (resp == NULL ? 1 : resp->ret));
		kfree(resp_msg);
		kfree(req_msg);
		return -1;
	}
	kfree(resp_msg);
	kfree(req_msg);
	return 0;
}

int ubcore_notify_uvs_add_sip(struct ubcore_device *dev,
	struct ubcore_sip_info *sip_info, uint32_t index)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;
	struct ubcore_add_sip_req *sip_req;
	struct ubcore_add_sip_resp *resp;

	req_msg = ubcore_alloc_sip_req(UBCORE_NL_ADD_SIP_REQ, dev->transport_type,
		sizeof(struct ubcore_add_sip_req), sip_info);
	if (req_msg == NULL)
		return -ENOMEM;

	sip_req = (struct ubcore_add_sip_req *)(void *)req_msg->payload;
	(void)memcpy(sip_req->dev_name, sip_info->dev_name,
		UBCORE_MAX_DEV_NAME);
	(void)memcpy(&sip_req->netaddr, &sip_info->addr,
		sizeof(struct ubcore_net_addr));
	sip_req->index = index;
	sip_req->port_cnt = sip_info->port_cnt;
	(void)memcpy(sip_req->port_id, sip_info->port_id,
		UBCORE_MAX_PORT_CNT);
	sip_req->prefix_len = sip_info->prefix_len;
	sip_req->mtu = sip_info->mtu;

	if (strnlen(sip_info->netdev_name, UBCORE_MAX_DEV_NAME) == UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("sip_info->netdev_name len is invalid");
		kfree(req_msg);
		return -1;
	}

	(void)memcpy(sip_req->netdev_name, sip_info->netdev_name, UBCORE_MAX_DEV_NAME);

	resp_msg = ubcore_nl_send_wait(dev, req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to wait query response");
		kfree(req_msg);
		return -1;
	}

	resp = (struct ubcore_add_sip_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != UBCORE_NL_ADD_SIP_RESP ||
		resp_msg->payload_len != sizeof(struct ubcore_add_sip_resp) ||
		resp->ret != UBCORE_NL_RESP_SUCCESS) {
		ubcore_log_err("add sip request is rejected with type %d ret %d",
			resp_msg->msg_type, (resp == NULL ? 1 : resp->ret));
		kfree(resp_msg);
		kfree(req_msg);
		return -1;
	}
	kfree(resp_msg);
	kfree(req_msg);
	return 0;
}

int ubcore_check_port_state(struct ubcore_device *dev, uint8_t port_idx)
{
	struct ubcore_device_status status;

	if (dev == NULL || port_idx >= UBCORE_MAX_PORT_CNT) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for state failed with dev name %s\n",
			dev->dev_name);
		return -EPERM;
	}

	if (status.port_status[port_idx].state != UBCORE_PORT_ACTIVE) {
		ubcore_log_err("port state is not active with dev name: %s and port_idx: %hhu\n",
			dev->dev_name, port_idx);
		return -EPERM;
	}
	ubcore_log_info("Success to query dev %s port state and it's active.\n", dev->dev_name);
	return 0;
}

void ubcore_find_port_netdev(struct ubcore_device *dev,
	struct net_device *ndev, uint8_t **port_list, uint8_t *port_cnt)
{
	struct ubcore_ndev_port *port_info;

	down_write(&g_port_list_lock);
	list_for_each_entry(port_info, &dev->port_list, node) {
		if (port_info->ndev == ndev) {
			*port_list = port_info->port_list;
			*port_cnt = port_info->port_cnt;
			up_write(&g_port_list_lock);
			ubcore_log_info("Success to fill in port_list with port cnt: %hhu",
				*port_cnt);
			return;
		}
	}
	up_write(&g_port_list_lock);
	ubcore_log_warn("ndev:%s no available port found.\n", netdev_name(ndev));
	/* Currently assigned port0 by default; So, here we don't need to change */
}

static int ubcore_add_new_port(struct ubcore_ndev_port *port_info,
	uint8_t port_id, struct ubcore_device *dev, struct net_device *ndev)
{
	uint8_t i;

	if (port_info->port_cnt >= UBCORE_MAX_PORT_CNT) {
		ubcore_log_err("Failed to add port because it's over the max length");
		return -1;
	}
	for (i = 0; i < UBCORE_MAX_PORT_CNT; i++) {
		if (!port_info->valid_list[i]) {
			port_info->port_list[i] = (uint8_t)port_id;
			port_info->valid_list[i] = true;
			port_info->port_cnt++;
			ubcore_log_info("ndev:%s dev_name: %s bound port%hhu: %hhu\n",
				netdev_name(ndev), dev->dev_name, i, port_id);
			break;
		}
	}
	return 0;
}

static int ubcore_port_duplicate_check(struct ubcore_ndev_port *port_info,
	uint8_t port_id, struct ubcore_device *dev, struct net_device *ndev)
{
	uint8_t i;

	for (i = 0; i < UBCORE_MAX_PORT_CNT; i++) {
		if (port_info->valid_list[i] && port_info->port_list[i] == port_id) {
			ubcore_log_err("ndev:%s dev_name: %s bound port%hhu: %hhu is already in the list\n",
				netdev_name(ndev), dev->dev_name, i, port_id);
			return -1;
		}
	}
	return 0;
}

static void ubcore_sync_sip_port_list(struct ubcore_device *dev,
	uint8_t *port_list, uint8_t port_cnt)
{
	struct ubcore_sip_info *new_sip;
	struct ubcore_sip_info old_sip;
	struct ubcore_device *tpf_dev;
	uint32_t max_cnt;
	uint32_t i;

	tpf_dev = ubcore_find_tpf_device(NULL, UBCORE_TRANSPORT_UB);
	if (tpf_dev == NULL)
		return;

	mutex_lock(&tpf_dev->sip_table.lock);
	max_cnt = ubcore_get_sip_max_cnt(&tpf_dev->sip_table);
	for (i = 0; i < max_cnt; i++) {
		new_sip = ubcore_lookup_sip_info(&tpf_dev->sip_table, i);
		if (new_sip == NULL)
			continue;
		old_sip = *new_sip;
		(void)memcpy(new_sip->port_id, port_list,
			UBCORE_MAX_PORT_CNT);
		new_sip->port_cnt = port_cnt;

		if (ubcore_get_netlink_valid() == true) {
			(void)ubcore_notify_uvs_del_sip(tpf_dev, &old_sip, i);
			(void)ubcore_notify_uvs_add_sip(tpf_dev, new_sip, i);
		}
		ubcore_log_info("dev_name: %s, old port_cnt: %hhu, new port_cnt: %hhu\n",
			dev->dev_name, old_sip.port_cnt, new_sip->port_cnt);
	}
	mutex_unlock(&tpf_dev->sip_table.lock);
	ubcore_put_device(tpf_dev);
}

int ubcore_set_port_netdev(struct ubcore_device *dev, struct net_device *ndev,
	unsigned int port_id)
{
	struct ubcore_ndev_port *port_info, *new_node;

	if (dev == NULL || ndev == NULL) {
		ubcore_log_err("invalid input parameter.\n");
		return -1;
	}
	down_write(&g_port_list_lock);
	list_for_each_entry(port_info, &dev->port_list, node) {
		if (port_info->ndev == ndev) {
			if (ubcore_port_duplicate_check(port_info,
				(uint8_t)port_id, dev, ndev) != 0) {
				up_write(&g_port_list_lock);
				ubcore_log_err("Failed to do ubcore_port_duplicate_check");
				return -1;
			}
			if (ubcore_add_new_port(port_info, (uint8_t)port_id, dev, ndev) != 0) {
				up_write(&g_port_list_lock);
				ubcore_log_err("Failed to ubcore_add_new_port");
				return -1;
			}
			/* sync to sip table */
			ubcore_sync_sip_port_list(dev, port_info->port_list, port_info->port_cnt);
			up_write(&g_port_list_lock);
			return 0;
		}
	}
	up_write(&g_port_list_lock);

	/* ndev port dones't exist, add new entry */
	new_node = kzalloc(sizeof(struct ubcore_ndev_port), GFP_ATOMIC);
	if (new_node == NULL)
		return -ENOMEM;

	new_node->ndev = ndev;
	new_node->port_list[0] = (uint8_t)port_id;
	new_node->valid_list[0] = true;
	new_node->port_cnt = 1;
	(void)memcpy(new_node->dev_name, dev->dev_name, sizeof(char) * UBCORE_MAX_DEV_NAME);
	down_write(&g_port_list_lock);
	list_add_tail(&new_node->node, &dev->port_list);
	up_write(&g_port_list_lock);
	ubcore_log_info("ndev:%s bound port[0]: %hhu\n", netdev_name(ndev), new_node->port_list[0]);
	ubcore_sync_sip_port_list(dev, new_node->port_list, new_node->port_cnt);
	return 0;
}
EXPORT_SYMBOL(ubcore_set_port_netdev);

/* del corresponding port id, if the port list cnt is 0, it will del the entry */
static int ubcore_del_port(struct ubcore_ndev_port *port_info,
	uint8_t port_id, struct ubcore_device *dev, struct net_device *ndev)
{
	bool del = false;
	uint8_t i;

	for (i = 0; i < UBCORE_MAX_PORT_CNT; i++) {
		if (port_info->valid_list[i] && port_info->port_list[i] == port_id) {
			port_info->port_list[i] = 0;
			port_info->valid_list[i] = false;
			port_info->port_cnt--;
			del = true;
			ubcore_log_info("ndev:%s dev_name: %s bound port%hhu: %hhu has been deleted\n",
				netdev_name(ndev), dev->dev_name, i, port_id);
			break;
		}
	}
	if (!del) {
		ubcore_log_info("ndev:%s dev_name: %s bound port: %hhu cannot be found\n",
			netdev_name(ndev), dev->dev_name, port_id);
		return -1;
	}
	ubcore_sync_sip_port_list(dev, port_info->port_list, port_info->port_cnt);

	if (port_info->port_cnt == 0) {
		list_del(&port_info->node);
		kfree(port_info);
		ubcore_log_info("ndev:%s bound port_list has been remove entirely\n",
			netdev_name(ndev));
	}
	return 0;
}

int ubcore_unset_port_netdev(struct ubcore_device *dev, struct net_device *ndev,
	unsigned int port_id)
{
	struct ubcore_ndev_port *port_info;

	if (dev == NULL || ndev == NULL) {
		ubcore_log_err("invalid input parameter.\n");
		return -1;
	}
	down_write(&g_port_list_lock);
	list_for_each_entry(port_info, &dev->port_list, node) {
		if (port_info->ndev == ndev) {
			if (ubcore_del_port(port_info, (uint8_t)port_id, dev, ndev) != 0) {
				up_write(&g_port_list_lock);
				ubcore_log_err("Failed to do ubcore_del_port");
				return -1;
			}
			up_write(&g_port_list_lock);
			return 0;
		}
	}
	up_write(&g_port_list_lock);

	ubcore_log_err("Failed to find and remove ndev:%s dev_name: %s bound port: %u\n",
		netdev_name(ndev), dev->dev_name, port_id);
	return -1;
}
EXPORT_SYMBOL(ubcore_unset_port_netdev);

void ubcore_put_port_netdev(struct ubcore_device *dev)
{
	struct ubcore_ndev_port *port_info, *next;

	if (dev == NULL) {
		ubcore_log_warn("invalid input dev is null_ptr.\n");
		return;
	}

	down_write(&g_port_list_lock);
	list_for_each_entry_safe(port_info, next, &dev->port_list, node) {
		if (port_info != NULL) {
			if (port_info->port_cnt != 0) {
				port_info->port_cnt = 0;
				(void)memset(port_info->port_list,
					0, sizeof(uint8_t) * UBCORE_MAX_PORT_CNT);
				ubcore_sync_sip_port_list(
					dev, port_info->port_list, port_info->port_cnt);
			}
			list_del(&port_info->node);
			kfree(port_info);
		}
	}
	up_write(&g_port_list_lock);
}
EXPORT_SYMBOL(ubcore_put_port_netdev);

void ubcore_sip_table_init(struct ubcore_sip_table *sip_table)
{
	uint32_t i;

	bitmap_zero(sip_table->index_bitmap, UBCORE_MAX_SIP);
	for (i = 0; i < UBCORE_SIP_TABLE_SIZE; i++)
		sip_table->entry[i] = NULL;
	mutex_init(&sip_table->lock);
}

void ubcore_sip_table_uninit(struct ubcore_sip_table *sip_table)
{
	uint32_t max_cnt;
	uint32_t i;

	mutex_lock(&sip_table->lock);
	max_cnt = ubcore_get_sip_max_cnt(sip_table);
	for (i = 0; i < max_cnt; i++) {
		if (sip_table->entry[i] != NULL) {
			kfree(sip_table->entry[i]);
			sip_table->entry[i] = NULL;
		}
	}
	mutex_unlock(&sip_table->lock);
	mutex_destroy(&sip_table->lock);
}

int ubcore_sip_idx_alloc(struct ubcore_sip_table *sip_table)
{
	uint32_t ret_idx;

	mutex_lock(&sip_table->lock);
	ret_idx = (uint32_t)find_first_zero_bit(sip_table->index_bitmap, UBCORE_MAX_SIP);
	if (ret_idx >= UBCORE_MAX_SIP) {
		ubcore_log_err("idx allocation failed.\n");
		mutex_unlock(&sip_table->lock);
		return -1;
	}
	set_bit(ret_idx, sip_table->index_bitmap);
	mutex_unlock(&sip_table->lock);
	return (int)ret_idx;
}

int ubcore_sip_idx_free(struct ubcore_sip_table *sip_table, uint32_t idx)
{
	mutex_lock(&sip_table->lock);
	if (test_bit(idx, sip_table->index_bitmap) == false) {
		mutex_unlock(&sip_table->lock);
		ubcore_log_err("idx:%u is not used.\n", idx);
		return -EINVAL;
	}
	clear_bit(idx, sip_table->index_bitmap);
	mutex_unlock(&sip_table->lock);
	return 0;
}

int ubcore_add_sip_entry(struct ubcore_sip_table *sip_table, const struct ubcore_sip_info *sip,
	uint32_t idx)
{
	struct ubcore_sip_info *new_sip;

	if (idx >= UBCORE_SIP_TABLE_SIZE || sip_table->entry[idx] != NULL) {
		ubcore_log_err("Parameters are illegal.\n");
		return -EINVAL;
	}
	new_sip = kzalloc(sizeof(struct ubcore_sip_info), GFP_ATOMIC);
	if (new_sip == NULL)
		return -ENOMEM;

	mutex_lock(&sip_table->lock);
	(void)memcpy(new_sip, sip, sizeof(struct ubcore_sip_info));
	sip_table->entry[idx] = new_sip;
	mutex_unlock(&sip_table->lock);
	ubcore_log_info("tpf_dev_name: %s sip table add entry idx: %d.\n",
		sip->dev_name, idx);
	return 0;
}

int ubcore_del_sip_entry(struct ubcore_sip_table *sip_table, uint32_t idx)
{
	if (idx >= UBCORE_SIP_TABLE_SIZE || sip_table->entry[idx] == NULL) {
		ubcore_log_err("Parameters are illegal.\n");
		return -EINVAL;
	}

	ubcore_log_info("tpf_name: %s del sip entry idx: %d.\n",
		sip_table->entry[idx]->dev_name, idx);
	mutex_lock(&sip_table->lock);
	kfree(sip_table->entry[idx]);
	sip_table->entry[idx] = NULL;
	mutex_unlock(&sip_table->lock);

	return 0;
}

int ubcore_lookup_sip_idx(struct ubcore_sip_table *sip_table, struct ubcore_sip_info *sip,
	uint32_t *idx)
{
	uint32_t i;

	mutex_lock(&sip_table->lock);
	for (i = 0; i < UBCORE_SIP_TABLE_SIZE; i++) {
		if (sip_table->entry[i] != NULL &&
			memcmp(sip_table->entry[i], sip,
			sizeof(struct ubcore_sip_info)) == 0) {
			*idx = i;
			break;
		}
	}
	if (i == UBCORE_SIP_TABLE_SIZE) {
		mutex_unlock(&sip_table->lock);
		ubcore_log_warn("no available idx found.\n");
		return -EINVAL;
	}
	mutex_unlock(&sip_table->lock);
	return 0;
}
