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
		if (addr_node->state != state) {
			list_del(&addr_node->node);
			kfree(addr_node);
		}
		ret = -EEXIST;
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

static void unic_restore_bond_addr_list(struct list_head *list,
					spinlock_t *addr_list_lock,
					struct unic_comm_addr_node *ip_node)
{
	struct unic_comm_addr_node *addr_node;

	spin_lock_bh(addr_list_lock);
	addr_node = unic_comm_find_addr_node(list, (u8 *)&ip_node->ip_addr,
					     ip_node->node_mask);
	if (addr_node) {
		list_del(&ip_node->node);
		kfree(ip_node);
		goto out;
	}

	list_move_tail(&ip_node->node, list);

out:
	spin_unlock_bh(addr_list_lock);
}

static void unic_notify_bond_ip_list(struct unic_vport *vport,
				     struct list_head *list,
				     struct list_head *bond_list,
				     spinlock_t *addr_list_lock,
				     enum unic_bond_ip_notify_cmd state)
{
	struct unic_comm_addr_node *ip_node, *tmp;
	bool bond_service_task_flag = false;

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		if (unic_sync_bond_ip(vport, ip_node, state)) {
			unic_restore_bond_addr_list(bond_list, addr_list_lock,
						    ip_node);
			bond_service_task_flag = true;
		} else {
			list_del(&ip_node->node);
			kfree(ip_node);
		}
	}

	if (bond_service_task_flag)
		set_bit(UNIC_VPORT_STATE_BOND_IP_CHANGE, &vport->state);
}

static void unic_sync_bond_addr_table(struct unic_vport *vport,
				      struct list_head *list,
				      spinlock_t *addr_list_lock)
{
	struct unic_comm_addr_node *addr_node, *tmp;
	struct list_head tmp_add_list, tmp_del_list;

	INIT_LIST_HEAD(&tmp_add_list);
	INIT_LIST_HEAD(&tmp_del_list);

	spin_lock_bh(addr_list_lock);
	list_for_each_entry_safe(addr_node, tmp, list, node) {
		if (addr_node->state == UNIC_COMM_ADDR_TO_DEL)
			list_move_tail(&addr_node->node, &tmp_del_list);
		else
			list_move_tail(&addr_node->node, &tmp_add_list);
	}
	spin_unlock_bh(addr_list_lock);

	unic_notify_bond_ip_list(vport, &tmp_del_list, list, addr_list_lock,
				 UNIC_BOND_IP_NOTIFY_CMD_DEL);
	unic_notify_bond_ip_list(vport, &tmp_add_list, list, addr_list_lock,
				 UNIC_BOND_IP_NOTIFY_CMD_ADD);
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
	struct unic_vport *vport = &unic_dev->vport;
	struct in6_addr ip_addr;
	int ret;

	ret = unic_convert_ip_addr(sa, &ip_addr);
	if (ret) {
		unic_err(unic_dev,
			 "invalid ip protocol type = %u.\n", sa->sa_family);
		return ret;
	}

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
	enum unic_bond_port_change_cmd bonding_cmd;
	struct net_device *master;

	rcu_read_lock();
	master = netdev_master_upper_dev_get_rcu(netdev);
	rcu_read_unlock();

	bonding_cmd = master && netif_is_bond_master(master) ?
		      UNIC_CTRLQ_BOND_ADD_PORT : UNIC_CTRLQ_BOND_DEL_PORT;

	return unic_send_bond_status_change_notify(unic_dev->comdev.adev,
						   bonding_cmd);
}
