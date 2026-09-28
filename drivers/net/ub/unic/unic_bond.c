// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <net/ipv6.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <ub/ubase/ubase_comm_ctrlq.h>

#include "unic_comm_addr.h"
#include "unic_ip.h"
#include "unic_bond.h"

static int unic_send_bond_ip_notify_msg(struct auxiliary_device *adev,
					struct unic_bond_ip_notify_req *req)
{
	struct ubase_ctrlq_msg msg = {0};
	int ret, tmp_resp;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_TP_ACL;
	msg.opcode = UBASE_CTRLQ_OPC_NOTIFY_BOND_IP;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.in_size = sizeof(struct unic_bond_ip_notify_req);
	msg.in = req;
	msg.out_size = sizeof(tmp_resp);
	msg.out = &tmp_resp;

	ret = ubase_ctrlq_send_msg(adev, &msg);
	if (ret)
		dev_err(&adev->dev,
			"failed to notify bond ip by ctrlq, ret = %d.\n", ret);

	return ret;
}

static void unic_fill_bond_ip_notify_req(struct unic_bond_ip_notify_req *req,
					 struct unic_comm_addr_node *ip_node,
					 u16 ip_cmd)
{
	__be32 *ip_addr = ip_node->ip_addr.s6_addr32;
	int i, j = UNIC_BOND_IP_REQ_SIZE;

	req->ip_cmd = cpu_to_le16(ip_cmd);
	req->ip_mask = cpu_to_le16(ip_node->node_mask);

	for (i = 0; i < UNIC_BOND_IP_REQ_SIZE; i++)
		req->ip_addr[i] = be32_to_le32(ip_addr[--j]);
}

static int unic_sync_bond_ip(struct unic_vport *vport,
			     struct unic_comm_addr_node *ip_node, u16 ip_cmd)
{
	struct auxiliary_device *adev = vport->back->comdev.adev;
	struct unic_bond_ip_notify_req req = {0};

	unic_fill_bond_ip_notify_req(&req, ip_node, ip_cmd);

	return unic_send_bond_ip_notify_msg(adev, &req);
}

static void unic_update_bond_addr_state(struct unic_comm_addr_node *addr_node,
					enum UNIC_COMM_ADDR_STATE state)
{
	switch (state) {
	case UNIC_COMM_ADDR_TO_ADD:
		if (addr_node->state == UNIC_COMM_ADDR_TO_DEL)
			addr_node->state = UNIC_COMM_ADDR_ACTIVE;
		break;
	case UNIC_COMM_ADDR_TO_DEL:
		if (addr_node->state == UNIC_COMM_ADDR_TO_ADD) {
			list_del(&addr_node->node);
			kfree(addr_node);
		} else {
			addr_node->state = UNIC_COMM_ADDR_TO_DEL;
		}
		break;
	case UNIC_COMM_ADDR_ACTIVE:
		if (addr_node->state == UNIC_COMM_ADDR_TO_ADD)
			addr_node->state = UNIC_COMM_ADDR_ACTIVE;
		break;
	default:
		break;
	}
}

static int unic_update_bond_addr_list(struct list_head *list,
				      spinlock_t *addr_list_lock,
				      enum UNIC_COMM_ADDR_STATE state,
				      const u8 *addr, u16 ip_mask)
{
	struct unic_comm_addr_node *addr_node;
	int ret = 0;

	spin_lock_bh(addr_list_lock);

	addr_node = unic_comm_find_addr_node(list, addr, ip_mask);
	if (addr_node) {
		unic_update_bond_addr_state(addr_node, state);
		goto out;
	}

	if (state == UNIC_COMM_ADDR_TO_DEL) {
		ret = -ENOENT;
		goto out;
	}

	addr_node = kzalloc(sizeof(*addr_node), GFP_ATOMIC);
	if (!addr_node) {
		ret = -ENOMEM;
		goto out;
	}

	addr_node->state = state;
	addr_node->node_mask = ip_mask;
	memcpy(addr_node->unic_addr, addr, UNIC_ADDR_LEN);
	list_add_tail(&addr_node->node, list);

out:
	spin_unlock_bh(addr_list_lock);
	return ret;
}

static void unic_notify_bond_ip_list(struct unic_vport *vport,
				     struct list_head *list,
				     enum unic_bond_ip_notify_cmd state)
{
	struct auxiliary_device *adev = vport->back->comdev.adev;
	char format_masked_ip_addr[UNIC_MASKED_FORMAT_IP_LEN];
	struct unic_comm_addr_node *ip_node, *tmp;

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		if (unic_sync_bond_ip(vport, ip_node, state)) {
			unic_format_masked_ip_addr(format_masked_ip_addr,
						   ip_node->unic_addr);
			dev_err_ratelimited(&adev->dev,
					    "failed to %s bond ip %s\n",
					    state == UNIC_BOND_IP_NOTIFY_CMD_ADD ?
					    "add" : "delete",
					    format_masked_ip_addr);
			set_bit(UNIC_VPORT_STATE_BOND_IP_CHANGE, &vport->state);
			continue;
		}

		if (state == UNIC_BOND_IP_NOTIFY_CMD_ADD) {
			ip_node->state = UNIC_COMM_ADDR_ACTIVE;
		} else {
			list_del(&ip_node->node);
			kfree(ip_node);
		}
	}
}

static void unic_bond_sync_from_del_list(struct list_head *del_list,
					 struct list_head *bond_list)
{
	struct unic_comm_addr_node *ip_node, *tmp, *new_node;

	list_for_each_entry_safe(ip_node, tmp, del_list, node) {
		new_node = unic_comm_find_addr_node(bond_list,
						    ip_node->unic_addr,
						    ip_node->node_mask);
		if (new_node) {
			new_node->state = UNIC_COMM_ADDR_ACTIVE;
			list_del(&ip_node->node);
			kfree(ip_node);
		} else {
			list_move_tail(&ip_node->node, bond_list);
		}
	}
}

static void unic_bond_sync_from_add_list(struct list_head *add_list,
					 struct list_head *bond_list)
{
	struct unic_comm_addr_node *ip_node, *tmp, *new_node;

	list_for_each_entry_safe(ip_node, tmp, add_list, node) {
		new_node = unic_comm_find_addr_node(bond_list,
						    ip_node->unic_addr,
						    ip_node->node_mask);
		if (new_node) {
			unic_update_bond_addr_state(new_node, ip_node->state);
			list_del(&ip_node->node);
			kfree(ip_node);
		} else if (ip_node->state == UNIC_COMM_ADDR_ACTIVE) {
			ip_node->state = UNIC_COMM_ADDR_TO_DEL;
			list_move_tail(&ip_node->node, bond_list);
		} else {
			list_del(&ip_node->node);
			kfree(ip_node);
		}
	}
}

static void unic_sync_bond_addr_table(struct unic_vport *vport,
				      struct list_head *list,
				      spinlock_t *addr_list_lock)
{
	struct unic_comm_addr_node *addr_node, *tmp, *new_node;
	struct list_head tmp_add_list, tmp_del_list;

	INIT_LIST_HEAD(&tmp_add_list);
	INIT_LIST_HEAD(&tmp_del_list);

	spin_lock_bh(addr_list_lock);
	list_for_each_entry_safe(addr_node, tmp, list, node) {
		switch (addr_node->state) {
		case UNIC_COMM_ADDR_TO_DEL:
			list_move_tail(&addr_node->node, &tmp_del_list);
			break;
		case UNIC_COMM_ADDR_TO_ADD:
			new_node = kzalloc(sizeof(*new_node), GFP_ATOMIC);
			if (!new_node)
				goto stop_traverse;
			memcpy(new_node->unic_addr, addr_node->unic_addr, UNIC_ADDR_LEN);
			new_node->state = addr_node->state;
			new_node->node_mask = addr_node->node_mask;
			list_add_tail(&new_node->node, &tmp_add_list);
			break;
		default:
			break;
		}
	}

stop_traverse:
	spin_unlock_bh(addr_list_lock);

	unic_notify_bond_ip_list(vport, &tmp_del_list, UNIC_BOND_IP_NOTIFY_CMD_DEL);
	unic_notify_bond_ip_list(vport, &tmp_add_list, UNIC_BOND_IP_NOTIFY_CMD_ADD);

	spin_lock_bh(addr_list_lock);

	unic_bond_sync_from_del_list(&tmp_del_list, list);
	unic_bond_sync_from_add_list(&tmp_add_list, list);

	spin_unlock_bh(addr_list_lock);
}

void unic_sync_bond_ip_table(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;

	if (test_and_clear_bit(UNIC_VPORT_STATE_BOND_IP_CHANGE, &vport->state))
		unic_sync_bond_addr_table(vport, &vport->addr_tbl.bond_ip_list,
					  &vport->addr_tbl.bond_ip_list_lock);
}

int unic_update_bond_ipaddr(struct unic_dev *unic_dev, struct sockaddr *sa,
			    u16 ip_mask, enum UNIC_COMM_ADDR_STATE state)
{
	char format_masked_ip_addr[UNIC_MASKED_FORMAT_IP_LEN];
	struct unic_vport *vport = &unic_dev->vport;
	struct in6_addr ip_addr;
	int ret;

	ret = unic_convert_ip_addr(unic_dev, sa, &ip_addr);
	if (ret)
		return ret;

	unic_format_masked_ip_addr(format_masked_ip_addr, (u8 *)&ip_addr);
	unic_info(unic_dev,
		  "stack %s a bond ip %s.\n",
		  state == UNIC_COMM_ADDR_TO_ADD ? "added" : "deleted",
		  format_masked_ip_addr);

	ret = unic_update_bond_addr_list(&vport->addr_tbl.bond_ip_list,
					 &vport->addr_tbl.bond_ip_list_lock,
					 state, (u8 *)&ip_addr, ip_mask);
	if (!ret)
		set_bit(UNIC_VPORT_STATE_BOND_IP_CHANGE, &vport->state);

	return ret;
}

void unic_uninit_bond_ip_table(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;
	struct list_head *list = &vport->addr_tbl.bond_ip_list;
	struct unic_comm_addr_node *ip_node, *tmp;

	spin_lock_bh(&vport->addr_tbl.bond_ip_list_lock);

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		list_del(&ip_node->node);
		kfree(ip_node);
	}

	spin_unlock_bh(&vport->addr_tbl.bond_ip_list_lock);
}

static int unic_send_bond_status_change_notify(struct auxiliary_device *adev,
					       enum unic_bond_port_change_cmd bonding_cmd)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	struct unic_ctrlq_bond_status_notify_req req = {0};
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	struct ubase_ctrlq_msg msg = {0};
	int ret, tmp_resp;

	req.bonding_cmd = bonding_cmd;
	req.port_id = caps->io_port_id;
	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_PORT;
	msg.opcode = UBASE_CTRLQ_OPC_BOND_PORT;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(tmp_resp);
	msg.out = &tmp_resp;

	ret = ubase_ctrlq_send_msg(adev, &msg);
	if (ret)
		unic_err(unic_dev,
			 "failed to notify bond status change, port id = %u, bonding_cmd = %s, ret = %d.\n",
			 req.port_id, req.bonding_cmd == UNIC_CTRLQ_BOND_ADD_PORT ?
			 "ADD" : "DEL", ret);

	return ret;
}

int unic_sync_bond_status(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_bond_status *bond_status = &unic_dev->bond_status;
	enum unic_bond_port_change_cmd bond_cmd;
	u8 cur_status;
	int ret = 0;

	mutex_lock(&bond_status->mutex);
	cur_status = bond_status->cur_status;
	mutex_unlock(&bond_status->mutex);

	bond_cmd = cur_status ?
		   UNIC_CTRLQ_BOND_ADD_PORT : UNIC_CTRLQ_BOND_DEL_PORT;
	if (cur_status != bond_status->last_notify_status) {
		ret = unic_send_bond_status_change_notify(unic_dev->comdev.adev,
							  bond_cmd);
		if (!ret) {
			unic_dbg(unic_dev,
				 "update last_notify_status: %u -> %u.\n",
				 bond_status->last_notify_status, cur_status);
			bond_status->last_notify_status = cur_status;
		}
	}

	return ret;
}
