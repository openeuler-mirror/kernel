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
#include <linux/if_vlan.h>

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

struct ubcore_sip_info *ubcore_lookup_sip_info_without_lock(
	struct ubcore_sip_table *sip_table, uint32_t idx)
{
	struct ubcore_sip_info *sip = NULL;

	if (idx >= sip_table->max_sip_cnt || !sip_table->entry[idx].is_active) {
		ubcore_log_err("sip node does not exist");
		return NULL;
	}
	sip = &sip_table->entry[idx];
	return sip;
}

static struct ubcore_nlmsg *ubcore_alloc_sip_req(enum ubcore_cmd msg_type,
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

	req_msg = ubcore_alloc_sip_req(UBCORE_CMD_DEL_SIP_REQ, dev->transport_type,
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
	if (resp_msg->msg_type != UBCORE_CMD_DEL_SIP_RESP ||
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

struct ubcore_nlmsg *ubcore_new_sip_req_msg(struct ubcore_device *dev,
	struct ubcore_sip_info *sip_info, uint32_t index)
{
	struct ubcore_add_sip_req *sip_req;
	struct ubcore_nlmsg *req_msg;

	req_msg = ubcore_alloc_sip_req(UBCORE_CMD_ADD_SIP_REQ, dev->transport_type,
		sizeof(struct ubcore_add_sip_req), sip_info);
	if (req_msg == NULL)
		return NULL;

	sip_req = (struct ubcore_add_sip_req *)(void *)req_msg->payload;
	(void)memcpy(sip_req->dev_name, sip_info->dev_name,
		UBCORE_MAX_DEV_NAME);
	(void)memcpy(&sip_req->netaddr, &sip_info->addr,
		sizeof(struct ubcore_net_addr));
	sip_req->index = index;
	sip_req->port_cnt = sip_info->port_cnt;
	(void)memcpy(sip_req->port_id, sip_info->port_id,
		UBCORE_MAX_PORT_CNT);
	sip_req->mtu = sip_info->mtu;

	if (strnlen(sip_info->netdev_name, UBCORE_MAX_DEV_NAME) == UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("sip_info->netdev_name len is invalid");
		kfree(req_msg);
		return NULL;
	}

	(void)memcpy(sip_req->netdev_name, sip_info->netdev_name, UBCORE_MAX_DEV_NAME);
	return req_msg;
}

int ubcore_notify_uvs_add_sip(struct ubcore_device *dev,
	struct ubcore_sip_info *sip_info, uint32_t index)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;
	struct ubcore_add_sip_resp *resp;

	req_msg = ubcore_new_sip_req_msg(dev, sip_info, index);
	if (req_msg == NULL)
		return -ENOMEM;

	resp_msg = ubcore_nl_send_wait(dev, req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to wait query response");
		kfree(req_msg);
		return -1;
	}

	resp = (struct ubcore_add_sip_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != UBCORE_CMD_ADD_SIP_RESP ||
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

int ubcore_check_port_state(struct ubcore_device *dev)
{
	struct ubcore_device_status status = {0};
	uint32_t i;

	if (dev == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (ubcore_query_device_status(dev, &status) != 0) {
		ubcore_log_err("query device status for state failed with dev name %s\n",
			dev->dev_name);
		return -EPERM;
	}

	for (i = 0; i < UBCORE_MAX_PORT_CNT; i++) {
		if (status.port_status[i].state == UBCORE_PORT_ACTIVE) {
			ubcore_log_debug("Success to query dev %s - port %u state and it's active.\n",
				dev->dev_name, i);
			return 0;
		}
	}
	ubcore_log_err("port state is not active with dev name: %s\n", dev->dev_name);
	return -EPERM;
}

void ubcore_fill_port_netdev(struct ubcore_device *dev,
	struct net_device *ndev, uint8_t *port_list, uint8_t *port_cnt)
{
	struct net_device *real_netdev = NULL;
	struct ubcore_ndev_port *port_info;

	if (is_vlan_dev(ndev))
		real_netdev = vlan_dev_real_dev(ndev);
	else
		real_netdev = ndev;

	down_write(&g_port_list_lock);
	list_for_each_entry(port_info, &dev->port_list, node) {
		if (port_info->ndev == real_netdev) {
			(void)memcpy(port_list, port_info->port_list, UBCORE_MAX_PORT_CNT);
			*port_cnt = port_info->port_cnt;
			up_write(&g_port_list_lock);
			ubcore_log_info("Success to fill in port_list with port cnt: %hhu and dev_name %s",
				*port_cnt, port_info->dev_name);
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

int ubcore_set_port_netdev(struct ubcore_device *dev, struct net_device *ndev,
	unsigned int port_id)
{
	struct ubcore_ndev_port *port_info, *new_node;

	if (dev == NULL || ndev == NULL ||
		strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME ||
		strnlen(netdev_name(ndev), UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
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
			up_write(&g_port_list_lock);
			/* sync to sip table */
			ubcore_update_netdev_addr(dev, dev->netdev, UBCORE_UPDATE_NET_ADDR, false);
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
	(void)memcpy(new_node->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	down_write(&g_port_list_lock);
	list_add_tail(&new_node->node, &dev->port_list);
	up_write(&g_port_list_lock);
	ubcore_log_info("ndev:%s bound port[0]: %hhu\n", netdev_name(ndev), new_node->port_list[0]);
	ubcore_update_netdev_addr(dev, dev->netdev, UBCORE_UPDATE_NET_ADDR, false);
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

	if (dev == NULL || ndev == NULL ||
		strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME ||
		strnlen(netdev_name(ndev), UBCORE_MAX_DEV_NAME) >= UBCORE_MAX_DEV_NAME) {
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
			ubcore_update_netdev_addr(dev, dev->netdev, UBCORE_UPDATE_NET_ADDR, false);
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
			}
			list_del(&port_info->node);
			kfree(port_info);
		}
	}
	up_write(&g_port_list_lock);

	ubcore_update_netdev_addr(dev, dev->netdev, UBCORE_UPDATE_NET_ADDR, false);
}
EXPORT_SYMBOL(ubcore_put_port_netdev);

int ubcore_sip_table_init(struct ubcore_sip_table *sip_table, uint32_t size)
{
	uint32_t tmp = UBCORE_MAX_SIP;

	if (size != 0 && size < UBCORE_MAX_SIP) {
		tmp = size;
		ubcore_log_info("sip size init %u complete.\n", tmp);
	} else {
		ubcore_log_warn("sip size %u err, use default value %u.\n", size, tmp);
	}
	bitmap_zero(sip_table->index_bitmap, UBCORE_MAX_SIP);
	sip_table->entry = kcalloc(tmp, sizeof(struct ubcore_sip_info), GFP_KERNEL);
	if (sip_table->entry == NULL)
		return -1;
	sip_table->max_sip_cnt = tmp;
	mutex_init(&sip_table->lock);
	return 0;
}

void ubcore_sip_table_uninit(struct ubcore_sip_table *sip_table)
{
	mutex_lock(&sip_table->lock);
	if (sip_table->entry != NULL) {
		kfree(sip_table->entry);
		sip_table->entry = NULL;
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
	mutex_lock(&sip_table->lock);
	if (idx >= sip_table->max_sip_cnt || sip_table->entry[idx].is_active) {
		mutex_unlock(&sip_table->lock);
		ubcore_log_err("Parameters are illegal.\n");
		return -EINVAL;
	}

	(void)memcpy(&sip_table->entry[idx], sip, sizeof(struct ubcore_sip_info));
	sip_table->entry[idx].is_active = true;
	mutex_unlock(&sip_table->lock);
	ubcore_log_info("tpf_dev_name: %s sip table add entry idx: %d. addr: %pI6c\n",
		sip->dev_name, idx, &sip->addr.net_addr);
	return 0;
}

int ubcore_del_sip_entry(struct ubcore_sip_table *sip_table, uint32_t idx)
{
	mutex_lock(&sip_table->lock);
	if (idx >= sip_table->max_sip_cnt || !sip_table->entry[idx].is_active) {
		mutex_unlock(&sip_table->lock);
		ubcore_log_err("Parameters are illegal.\n");
		return -EINVAL;
	}

	ubcore_log_info("tpf_name: %s del sip entry idx: %d, addr: %pI6c.\n",
		sip_table->entry[idx].dev_name, idx, &sip_table->entry[idx].addr.net_addr);
	sip_table->entry[idx].is_active = false;
	mutex_unlock(&sip_table->lock);
	return 0;
}

static bool ubcore_sip_compare(struct ubcore_sip_info *sip_entry,
	struct ubcore_sip_info *del_sip)
{
	if ((memcmp(sip_entry->dev_name, del_sip->dev_name,
		sizeof(char) * UBCORE_MAX_DEV_NAME) == 0) &&
		(memcmp(&sip_entry->addr.net_addr, &del_sip->addr.net_addr,
			sizeof(union ubcore_net_addr_union)) == 0) &&
		(memcmp(sip_entry->netdev_name, del_sip->netdev_name,
		sizeof(struct ubcore_net_addr)) == 0))
		return true;

	return false;
}

int ubcore_update_sip_entry(struct ubcore_sip_table *sip_table, struct ubcore_sip_info *new_sip,
	uint32_t *sip_idx, struct ubcore_sip_info *old_sip)
{
	uint32_t i;
	int ret = -ENOENT;

	if (!sip_table || !new_sip || !sip_idx || !old_sip)
		return -EINVAL;

	mutex_lock(&sip_table->lock);
	for (i = 0; i < sip_table->max_sip_cnt; i++) {
		if (!sip_table->entry[i].is_active ||
			!ubcore_sip_compare(&sip_table->entry[i], new_sip))
			continue;

		*sip_idx = i;
		*old_sip = sip_table->entry[i];

		sip_table->entry[i] = *new_sip;
		sip_table->entry[i].is_active = true;
		ret = 0;
		ubcore_log_info("tpf_name: %s update sip entry idx: %d, addr: %pI6c.",
			sip_table->entry[i].dev_name, i, &sip_table->entry[i].addr.net_addr);
		break;
	}
	mutex_unlock(&sip_table->lock);
	return ret;
}

int ubcore_lookup_sip_idx(struct ubcore_sip_table *sip_table, struct ubcore_sip_info *sip,
	uint32_t *idx)
{
	uint32_t i;

	mutex_lock(&sip_table->lock);
	for (i = 0; i < sip_table->max_sip_cnt; i++) {
		if (sip_table->entry[i].is_active &&
			ubcore_sip_compare(&sip_table->entry[i], sip)) {
			*idx = i;
			break;
		}
	}
	if (i == sip_table->max_sip_cnt) {
		mutex_unlock(&sip_table->lock);
		ubcore_log_warn("no available idx found.\n");
		return -EINVAL;
	}
	mutex_unlock(&sip_table->lock);
	return 0;
}
