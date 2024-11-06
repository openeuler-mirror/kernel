// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/netdevice.h>
#include "common/xsc_core.h"
#include "common/driver.h"
#include <net/bonding.h>
#include "common/xsc_lag.h"
#include "common/xsc_hsi.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_cmd.h"
#include "net/xsc_eth.h"

#include <linux/if_bonding.h>
#include <net/neighbour.h>
#include <net/arp.h>
#include <linux/kthread.h>

static struct xsc_board_lag *board_lag_array[MAX_BOARD_NUM];

struct xsc_board_lag *xsc_board_lag_get(struct xsc_core_device *xdev)
{
	return board_lag_array[xdev->board_info->board_id];
}
EXPORT_SYMBOL(xsc_board_lag_get);

void xsc_board_lag_set(struct xsc_core_device *xdev,
		       void *board_lag)
{
	struct xsc_board_lag *board_lag_new = board_lag;

	board_lag_new->board_id = xdev->board_info->board_id;
	board_lag_array[xdev->board_info->board_id] = board_lag_new;
}

void xsc_board_lag_reset(u32 board_id)
{
	board_lag_array[board_id] = NULL;
}

static u8 hash_type_map[] = {
	[NETDEV_LAG_HASH_NONE] = XSC_LAG_HASH_L23,
	[NETDEV_LAG_HASH_L2] = XSC_LAG_HASH_L23,
	[NETDEV_LAG_HASH_L34] = XSC_LAG_HASH_L34,
	[NETDEV_LAG_HASH_L23] = XSC_LAG_HASH_L23,
	[NETDEV_LAG_HASH_E23] = XSC_LAG_HASH_E23,
	[NETDEV_LAG_HASH_E34] = XSC_LAG_HASH_E34,
	[NETDEV_LAG_HASH_UNKNOWN] = XSC_LAG_HASH_L23,
};

static inline u8 xsc_lag_hashtype_convert(enum netdev_lag_hash hash_type)
{
	return hash_type_map[hash_type];
}

static enum netdev_lag_tx_type bond_lag_tx_type(struct bonding *bond)
{
	switch (BOND_MODE(bond)) {
	case BOND_MODE_ROUNDROBIN:
		return NETDEV_LAG_TX_TYPE_ROUNDROBIN;
	case BOND_MODE_ACTIVEBACKUP:
		return NETDEV_LAG_TX_TYPE_ACTIVEBACKUP;
	case BOND_MODE_BROADCAST:
		return NETDEV_LAG_TX_TYPE_BROADCAST;
	case BOND_MODE_XOR:
	case BOND_MODE_8023AD:
		return NETDEV_LAG_TX_TYPE_HASH;
	default:
		return NETDEV_LAG_TX_TYPE_UNKNOWN;
	}
}

enum netdev_lag_hash bond_lag_hash_type(struct bonding *bond)
{
	switch (bond->params.xmit_policy) {
	case BOND_XMIT_POLICY_LAYER2:
		return NETDEV_LAG_HASH_L23;
	case BOND_XMIT_POLICY_LAYER34:
		return NETDEV_LAG_HASH_L34;
	case BOND_XMIT_POLICY_LAYER23:
		return NETDEV_LAG_HASH_L23;
	case BOND_XMIT_POLICY_ENCAP23:
		return NETDEV_LAG_HASH_E23;
	case BOND_XMIT_POLICY_ENCAP34:
		return NETDEV_LAG_HASH_E34;
	default:
		return NETDEV_LAG_HASH_UNKNOWN;
	}
}

static inline bool __xsc_lag_is_active(struct xsc_lag *lag)
{
	return !!(lag->lag_type & XSC_LAG_MODE_FLAGS);
}

static inline bool __xsc_lag_is_roce(struct xsc_lag *lag)
{
	return !!(lag->lag_type & XSC_LAG_FLAG_ROCE);
}

static inline bool __xsc_lag_is_kernel(struct xsc_lag *lag)
{

	return !!(lag->lag_type & XSC_LAG_FLAG_KERNEL);
}

static inline struct xsc_lag *__xsc_get_lag(struct xsc_core_device *xdev)
{
	struct xsc_board_lag *board_lag;

	if (!xdev)
		return NULL;

	board_lag = xsc_board_lag_get(xdev);
	if (!board_lag || xdev->bond_id == BOND_ID_INVALID)
		return NULL;

	return &board_lag->xsc_lag[xdev->bond_id];
}

int xsc_cmd_create_lag(struct xsc_lag_event *entry)
{
	struct xsc_create_lag_mbox_in in = {};
	struct xsc_create_lag_mbox_out out = {};
	struct xsc_core_device *xdev = entry->xdev;
	struct net_device *netdev = xdev->netdev;
	int ret = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_CREATE);

	in.req.lag_id = cpu_to_be16(entry->lag_id);
	in.req.lag_type = entry->lag_type;
	in.req.lag_sel_mode = entry->lag_sel_mode;
	in.req.mac_idx = xdev->pf_id;
	in.req.bond_mode = entry->bond_mode;
	in.req.slave_status = entry->slave_status;

	memcpy(in.req.netdev_addr, netdev->dev_addr, ETH_ALEN);

	xsc_core_info(xdev, "create LAG: lag_id = %d, lag_type = %d, lag_sel_mode = %d, bond_mode = %d\n",
		      entry->lag_id, entry->lag_type, entry->lag_sel_mode, entry->bond_mode);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to create LAG, err =%d out.status= %u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

int xsc_cmd_add_lag_member(struct xsc_lag_event *entry)
{
	struct xsc_add_lag_member_mbox_in in = {};
	struct xsc_add_lag_member_mbox_out out = {};
	struct xsc_core_device *xdev = entry->xdev;
	struct net_device *netdev = xdev->netdev;
	int ret = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_ADD_MEMBER);

	in.req.lag_id = cpu_to_be16(entry->lag_id);
	in.req.lag_type = entry->lag_type;
	in.req.lag_sel_mode = entry->lag_sel_mode;
	in.req.mac_idx = xdev->pf_id;
	in.req.bond_mode = entry->bond_mode;
	in.req.slave_status = entry->slave_status;
	in.req.mad_mac_idx = entry->roce_lag_xdev->pf_id;

	memcpy(in.req.netdev_addr, netdev->dev_addr, ETH_ALEN);

	xsc_core_info(xdev, "add LAG member: lag_id = %d, lag_type = %d, bond_mode = %d\n",
		      entry->lag_id, entry->lag_type, entry->bond_mode);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to add LAG member, err =%d out.status= %u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

int xsc_cmd_remove_lag_member(struct xsc_lag_event *entry)
{
	struct xsc_remove_lag_member_mbox_in in = {};
	struct xsc_remove_lag_member_mbox_out out = {};
	struct xsc_core_device *xdev = entry->xdev;
	int ret = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_REMOVE_MEMBER);

	in.req.lag_id = cpu_to_be16(entry->lag_id);
	in.req.lag_type = entry->lag_type;
	in.req.mac_idx = xdev->pf_id;
	in.req.bond_mode = entry->bond_mode;
	if (entry->lag_type & XSC_LAG_FLAG_ROCE && entry->is_roce_lag_xdev) {
		in.req.is_roce_lag_xdev = entry->is_roce_lag_xdev;
		in.req.mad_mac_idx = entry->roce_lag_xdev->pf_id;
		in.req.not_roce_lag_xdev_mask = entry->not_roce_lag_xdev_mask;
	}

	xsc_core_info(xdev, "remove LAG member: lag_id = %d, lag_type = %d, bond_mode = %d\n",
		      entry->lag_id, entry->lag_type, entry->bond_mode);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to add LAG member, err =%d out.status= %u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

int xsc_cmd_update_lag_member_status(struct xsc_lag_event *entry)
{
	struct xsc_update_lag_member_status_mbox_in in = {};
	struct xsc_update_lag_member_status_mbox_out out = {};
	struct xsc_core_device *xdev = entry->xdev;
	int ret = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_UPDATE_MEMBER_STATUS);

	in.req.lag_type = entry->lag_type;
	in.req.bond_mode = entry->bond_mode;
	in.req.lag_id = cpu_to_be16(entry->lag_id);
	in.req.mac_idx = xdev->pf_id;
	in.req.slave_status = entry->slave_status;

	xsc_core_info(xdev, "update LAG member status: lag_id = %d, bond_mode = %d, lag_type = %d, slave_status = %d, mac_idx = %d\n",
		      entry->lag_id, entry->bond_mode, entry->lag_type,
		      entry->slave_status, xdev->pf_id);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to update LAG member status, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return ret;
}

int xsc_cmd_update_lag_hash_type(struct xsc_lag_event *entry)
{
	struct xsc_update_lag_hash_type_mbox_in in = {};
	struct xsc_update_lag_hash_type_mbox_out out = {};
	struct xsc_core_device *xdev = entry->xdev;
	int ret = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_UPDATE_HASH_TYPE);

	in.req.lag_id = cpu_to_be16(entry->lag_id);
	in.req.lag_sel_mode = entry->lag_sel_mode;

	xsc_core_info(xdev, "update LAG hash type: lag_id = %d, lag_sel_mode = %d\n",
		      entry->lag_id, in.req.lag_sel_mode);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to update LAG hash type, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return ret;
}

int xsc_cmd_destroy_lag(struct xsc_lag_event *entry)
{
	struct xsc_destroy_lag_mbox_in in = {};
	struct xsc_destroy_lag_mbox_out out = {};
	struct xsc_core_device *xdev = entry->xdev;
	int ret = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_DESTROY);

	in.req.lag_id = cpu_to_be16(entry->lag_id);
	in.req.lag_type = entry->lag_type;
	in.req.mac_idx = xdev->pf_id;
	in.req.bond_mode = entry->bond_mode;

	xsc_core_info(xdev, "destroy LAG: lag_id = %d\n", entry->lag_id);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to destroy LAG, err =%d out.status= %u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static int xsc_lag_set_qos(struct xsc_core_device *xdev, u16 lag_id, u8 member_idx, u8 lag_op)
{
	struct xsc_set_lag_qos_mbox_in in;
	struct xsc_set_lag_qos_mbox_out out;
	struct xsc_set_lag_qos_request *req;
	int ret;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	req = &in.req;

	req->lag_id = cpu_to_be16(lag_id);
	req->member_idx = member_idx;
	req->lag_op = lag_op;
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_SET_QOS);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	return ret;
}

void xsc_create_lag(struct xsc_lag_event *entry)
{
	int ret = 0;
	bool roce_lag = entry->lag_type & XSC_LAG_FLAG_ROCE;
	struct xsc_core_device *xdev = entry->xdev;

	if (roce_lag)
		xsc_remove_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);

	ret = xsc_cmd_create_lag(entry);
	if (ret) {
		xsc_core_err(xdev, "failed to create LAG, err =%d\n", ret);
		goto out;
	}

	if (xsc_lag_set_qos(xdev, entry->lag_id, 0, QOS_LAG_OP_CREATE)) {
		xsc_core_err(xdev, "failed to create QoS LAG %u\n", entry->lag_id);
		goto out;
	}

	if (entry->slave_status == XSC_LAG_SLAVE_ACTIVE) {
		if (xsc_lag_set_qos(xdev, entry->lag_id, xdev->pf_id, QOS_LAG_OP_ADD_MEMBER))
			xsc_core_err(xdev, "failed to add member %u for QoS LAG %u\n",
				     xdev->pf_id, entry->lag_id);
	}

out:
	if (roce_lag)
		xsc_add_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);
}

void xsc_add_lag_member(struct xsc_lag_event *entry)
{
	int ret = 0;
	bool roce_lag = entry->lag_type & XSC_LAG_FLAG_ROCE;
	struct xsc_core_device *xdev = entry->xdev;

	if (roce_lag)
		xsc_remove_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);

	ret = xsc_cmd_add_lag_member(entry);
	if (ret) {
		xsc_core_err(xdev, "failed to create LAG, err =%d\n", ret);
		goto out;
	}

	if (entry->slave_status == XSC_LAG_SLAVE_ACTIVE) {
		if (xsc_lag_set_qos(xdev, entry->lag_id, xdev->pf_id, QOS_LAG_OP_ADD_MEMBER))
			xsc_core_err(xdev, "failed to add member %u for QoS LAG %u\n",
				     xdev->pf_id, entry->lag_id);
	}

	return;

out:
	if (roce_lag)
		xsc_add_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);
}

void xsc_remove_lag_member(struct xsc_lag_event *entry)
{
	int ret = 0;
	bool roce_lag = entry->lag_type & XSC_LAG_FLAG_ROCE;
	struct xsc_core_device *xdev = entry->xdev;
	struct xsc_core_device *roce_lag_xdev = entry->roce_lag_xdev;

	if (roce_lag && entry->is_roce_lag_xdev)
		xsc_remove_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);

	ret = xsc_cmd_remove_lag_member(entry);
	if (ret) {
		xsc_core_err(xdev, "failed to create LAG, err =%d\n", ret);
		goto out;
	}

	if (roce_lag && entry->is_roce_lag_xdev) {
		xsc_add_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);
		xsc_add_dev_by_protocol(roce_lag_xdev, XSC_INTERFACE_PROTOCOL_IB);
	}

	if (roce_lag && !entry->is_roce_lag_xdev)
		xsc_add_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);

	if (xsc_lag_set_qos(xdev, entry->lag_id, xdev->pf_id, QOS_LAG_OP_DEL_MEMBER))
		xsc_core_err(xdev, "failed to del member %u for QoS LAG %u\n",
			     xdev->pf_id, entry->lag_id);

	return;

out:
	if (roce_lag && entry->is_roce_lag_xdev)
		xsc_add_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);
}

void xsc_update_lag_member_status(struct xsc_lag_event *entry)
{
	int ret = 0;
	struct xsc_core_device *xdev = entry->xdev;

	ret = xsc_cmd_update_lag_member_status(entry);
	if (ret)
		xsc_core_err(xdev, "failed to update LAG member status, err =%d\n", ret);

	if (entry->slave_status == XSC_LAG_SLAVE_ACTIVE) {
		if (xsc_lag_set_qos(xdev, entry->lag_id, xdev->pf_id, QOS_LAG_OP_ADD_MEMBER))
			xsc_core_err(xdev, "failed to add member %u for QoS LAG %u\n",
				     xdev->pf_id, entry->lag_id);
	} else if (entry->slave_status == XSC_LAG_SLAVE_INACTIVE) {
		if (xsc_lag_set_qos(xdev, entry->lag_id, xdev->pf_id, QOS_LAG_OP_DEL_MEMBER))
			xsc_core_err(xdev, "failed to del member %u for QoS LAG %u\n",
				     xdev->pf_id, entry->lag_id);
	}
}

void xsc_update_lag_hash_type(struct xsc_lag_event *entry)
{
	int ret = 0;
	struct xsc_core_device *xdev = entry->xdev;

	ret = xsc_cmd_update_lag_hash_type(entry);
	if (ret)
		xsc_core_err(xdev, "failed to update LAG member status, err =%d\n", ret);
}

void xsc_destroy_lag(struct xsc_lag_event *entry)
{
	int ret = 0;
	bool roce_lag = entry->lag_type & XSC_LAG_FLAG_ROCE;
	struct xsc_core_device *xdev = entry->xdev;

	if (roce_lag)
		xsc_remove_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);

	ret = xsc_cmd_destroy_lag(entry);
	if (ret) {
		xsc_core_err(xdev, "failed to create LAG, err =%d\n", ret);
		goto out;
	}

	if (xsc_lag_set_qos(xdev, entry->lag_id, 0, QOS_LAG_OP_DESTROY))
		xsc_core_err(xdev, "failed to destroy QoS LAG %u\n", entry->lag_id);

out:
	if (roce_lag)
		xsc_add_dev_by_protocol(xdev, XSC_INTERFACE_PROTOCOL_IB);
}

static void (*handlers[XSC_LAG_EVENT_MAX])(struct xsc_lag_event *entry) = {
	[XSC_LAG_CREATE] = xsc_create_lag,
	[XSC_LAG_ADD_MEMBER] = xsc_add_lag_member,
	[XSC_LAG_REMOVE_MEMBER] = xsc_remove_lag_member,
	[XSC_LAG_UPDATE_MEMBER_STATUS] = xsc_update_lag_member_status,
	[XSC_LAG_UPDATE_HASH_TYPE] = xsc_update_lag_hash_type,
	[XSC_LAG_DESTROY] = xsc_destroy_lag,
};

static int xsc_do_bond_thread(void *arg)
{
	struct xsc_lag_event *entry;
	struct xsc_board_lag *board_lag = arg;
	struct lag_event_list *lag_event_list;
	int status;

	lag_event_list = &board_lag->lag_event_list;

	while (!kthread_should_stop()) {
		if (need_resched())
			schedule();

		spin_lock(&lag_event_list->lock);
		entry = list_first_entry_or_null(&lag_event_list->head,
						 struct xsc_lag_event, node);
		if (!entry) {
			spin_unlock(&lag_event_list->lock);
			wait_event_interruptible(lag_event_list->wq,
						 lag_event_list->wait_flag != XSC_SLEEP);
			if (lag_event_list->wait_flag == XSC_EXIT)
				break;
			lag_event_list->wait_flag = XSC_SLEEP;
			continue;
		}

		spin_unlock(&lag_event_list->lock);

		if (entry->event_type >= XSC_LAG_EVENT_MAX)
			goto free_entry;

		status = xsc_dev_list_trylock();
		if (!status)
			continue;

		(*handlers[entry->event_type])(entry);
		xsc_dev_list_unlock();

free_entry:
		list_del(&entry->node);
		kfree(entry);
	}

	return 0;
}

static inline bool xsc_is_roce_lag_allowed(struct xsc_lag *lag)
{
	struct xsc_core_device *xdev;
	bool roce_lag_support = true;

	list_for_each_entry(xdev, &lag->slave_list, slave_node) {
		roce_lag_support &= !xsc_sriov_is_enabled(xdev);
		if (!roce_lag_support) {
			xsc_core_info(xdev, "create ROCE LAG while sriov is open\n");
			break;
		}

		roce_lag_support &=	radix_tree_empty(&xdev->priv_device.bdf_tree);
		if (!roce_lag_support) {
			xsc_core_info(xdev, "create ROCE LAG while the ib device is open\n");
			break;
		}
	}

	return roce_lag_support;
}

static bool xsc_is_sriov_lag_allowed(struct xsc_lag *lag)
{
	struct xsc_core_device *xdev;
	bool sriov_lag_support = true;

	list_for_each_entry(xdev, &lag->slave_list, slave_node) {
		sriov_lag_support &= (xdev->priv.eswitch->mode == XSC_ESWITCH_OFFLOADS);
		if (!sriov_lag_support)
			xsc_core_info(xdev, "create SRIOV LAG while the switchdev is not open\n");
	}

	return sriov_lag_support;
}

static u8 xsc_get_lag_type(struct xsc_lag *lag)
{
	u8 lag_type;
	bool roce_lag;
	bool sriov_lag;
	u8	lag_mode_support;

	lag_mode_support = (lag->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP ||
			 lag->tx_type == NETDEV_LAG_TX_TYPE_HASH);
	roce_lag = lag_mode_support && xsc_is_roce_lag_allowed(lag);
	sriov_lag = lag_mode_support && xsc_is_sriov_lag_allowed(lag);
	lag_type = sriov_lag ? XSC_LAG_FLAG_SRIOV :
		(roce_lag ? XSC_LAG_FLAG_ROCE : XSC_LAG_FLAG_KERNEL);

	return lag_type;
}

static inline void pack_add_and_wake_wq(struct xsc_board_lag *board_lag,
					struct xsc_lag_event *entry)
{
	spin_lock(&board_lag->lag_event_list.lock);
	list_add_tail(&entry->node, &board_lag->lag_event_list.head);
	spin_unlock(&board_lag->lag_event_list.lock);
	board_lag->lag_event_list.wait_flag = XSC_WAKEUP;
	wake_up(&board_lag->lag_event_list.wq);
}

static inline enum lag_slave_status lag_slave_status_get(struct net_device *ndev)
{
	struct slave *slave = NULL;
	enum lag_slave_status slave_status = XSC_LAG_SLAVE_STATUS_MAX;

	if (!netif_is_bond_slave(ndev))
		goto out;

	rcu_read_lock();
	slave = bond_slave_get_rtnl(ndev);
	rcu_read_unlock();
	if (bond_slave_is_up(slave) && bond_slave_can_tx(slave))
		slave_status = XSC_LAG_SLAVE_ACTIVE;
	else
		slave_status = XSC_LAG_SLAVE_INACTIVE;

out:
	return slave_status;
}

void pack_lag_create(struct xsc_lag *lag,
		     struct xsc_core_device *xdev, bool no_wq)
{
	struct net_device *ndev = xdev->netdev;
	struct xsc_lag_event *entry;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (lag->mode_changes_in_progress)
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	lag->lag_type = xsc_get_lag_type(lag);

	entry->event_type = XSC_LAG_CREATE;
	entry->xdev = xdev;
	entry->lag_sel_mode = lag->hash_type;
	entry->lag_id = lag->lag_id;
	entry->bond_mode = lag->bond_mode;
	entry->lag_type = lag->lag_type;
	entry->slave_status = lag_slave_status_get(ndev);

	xsc_core_info(xdev, "lag_sel_mode = %d, slave_status = %d, lag_type = %d\n",
		      entry->lag_sel_mode, entry->slave_status, entry->lag_type);

	if (!no_wq)
		pack_add_and_wake_wq(board_lag, entry);
	else
		xsc_create_lag(entry);
}

void pack_lag_add_member(struct xsc_lag *lag,
			 struct xsc_core_device *xdev, bool no_wq)
{
	struct xsc_lag_event *entry;
	struct net_device *ndev = xdev->netdev;
	struct xsc_core_device *roce_lag_xdev = NULL;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (lag->mode_changes_in_progress)
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	entry->lag_type = xsc_get_lag_type(lag);
	if (entry->lag_type != lag->lag_type) {
		xsc_core_err(xdev, "do not permit add slave to different type lag, xdev_lag_type = %d, lag_type = %d\n",
			     entry->lag_type, lag->lag_type);

		kfree(entry);
		return;
	}

	entry->event_type = XSC_LAG_ADD_MEMBER;
	entry->xdev = xdev;
	entry->lag_sel_mode = lag->hash_type;
	entry->slave_status = lag_slave_status_get(ndev);
	entry->lag_id = lag->lag_id;
	entry->bond_mode = lag->bond_mode;

	roce_lag_xdev = list_first_entry(&lag->slave_list,
					 struct xsc_core_device, slave_node);
	entry->roce_lag_xdev = roce_lag_xdev;
	entry->not_roce_lag_xdev_mask = lag->not_roce_lag_xdev_mask;

	xsc_core_info(xdev, "lag_sel_mode = %d, slave_status = %d, lag_type = %d\n",
		      entry->lag_sel_mode, entry->slave_status, entry->lag_type);

	if (!no_wq)
		pack_add_and_wake_wq(board_lag, entry);
	else
		xsc_add_lag_member(entry);
}

void pack_lag_remove_member(struct xsc_lag *lag,
			    struct xsc_core_device *xdev, bool no_wq)
{
	struct xsc_lag_event *entry;
	struct xsc_core_device *roce_lag_xdev = NULL;
	struct xsc_core_device *xdev_tmp = NULL;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);
	u8 cnt = 0;
	u8 not_roce_lag_xdev_mask = 0;

	if (lag->mode_changes_in_progress)
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	entry->event_type = XSC_LAG_REMOVE_MEMBER;
	entry->xdev = xdev;
	entry->lag_id = lag->lag_id;
	entry->bond_mode = lag->bond_mode;
	entry->lag_type = lag->lag_type;

	if (entry->lag_type & XSC_LAG_FLAG_ROCE) {
		roce_lag_xdev = list_first_entry(&lag->slave_list,
						 struct xsc_core_device, slave_node);
		if (roce_lag_xdev == xdev) {
			entry->is_roce_lag_xdev = 1;

			list_for_each_entry(xdev_tmp, &lag->slave_list, slave_node)	{
				cnt++;
				if (cnt == 1)
					continue;

				if (cnt == 2) {
					roce_lag_xdev = xdev_tmp;
					continue;
				}

				not_roce_lag_xdev_mask |= BIT(xdev_tmp->pf_id);
			}
			entry->roce_lag_xdev = roce_lag_xdev;
			entry->not_roce_lag_xdev_mask = not_roce_lag_xdev_mask;
		}
	}

	xsc_core_info(xdev, "lag_type = %d, is_roce_lag_xdev = %d, not_roce_lag_xdev_mask = %d\n",
		      entry->lag_type, entry->is_roce_lag_xdev, entry->not_roce_lag_xdev_mask);

	if (!no_wq)
		pack_add_and_wake_wq(board_lag, entry);
	else
		xsc_remove_lag_member(entry);
}

void pack_lag_update_member_status(struct xsc_lag *lag,
				   struct net_device *ndev, enum lag_slave_status slave_status)
{
	struct xsc_lag_event *entry;
	struct xsc_adapter *adapter = netdev_priv(ndev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (lag->mode_changes_in_progress || lag->lag_type & XSC_LAG_FLAG_KERNEL)
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	entry->event_type = XSC_LAG_UPDATE_MEMBER_STATUS;
	entry->xdev = xdev;
	entry->lag_id = lag->lag_id;
	entry->bond_mode = lag->bond_mode;
	entry->lag_type = lag->lag_type;
	entry->slave_status = slave_status;

	xsc_core_info(xdev, "lag_id = %d, slave_status = %d\n",
		      entry->lag_id, entry->slave_status);

	pack_add_and_wake_wq(board_lag, entry);
}

void pack_lag_update_hash_type(struct xsc_lag *lag,
			       u8 bond_id, enum netdev_lag_hash hash_type)
{
	struct xsc_lag_event *entry;
	struct xsc_core_device *xdev = NULL;
	struct xsc_board_lag *board_lag;

	if (lag->mode_changes_in_progress || lag->lag_type & XSC_LAG_FLAG_KERNEL)
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	xdev = list_first_entry(&lag->slave_list,
				struct xsc_core_device, slave_node);

	board_lag = xsc_board_lag_get(xdev);

	entry->event_type = XSC_LAG_UPDATE_HASH_TYPE;
	entry->xdev = xdev;
	entry->lag_id = lag->lag_id;
	entry->lag_sel_mode = lag->hash_type;

	xsc_core_info(xdev, "lag_id = %d, lag_sel_mode = %d\n",
		      entry->lag_id, entry->lag_sel_mode);

	pack_add_and_wake_wq(board_lag, entry);
}

void pack_lag_destroy(struct xsc_lag *lag, struct xsc_core_device *xdev, bool no_wq)
{
	struct xsc_lag_event *entry;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (lag->mode_changes_in_progress)
		return;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	entry->event_type = XSC_LAG_DESTROY;
	entry->xdev = xdev;
	entry->lag_id = lag->lag_id;
	entry->bond_mode = lag->bond_mode;
	entry->lag_type = lag->lag_type;

	lag->lag_type = 0;

	xsc_core_info(xdev, "lag_id = %d, board_id = %d, lag_type = %d\n",
		      lag->lag_id, lag->board_id, entry->lag_type);

	if (!no_wq)
		pack_add_and_wake_wq(board_lag, entry);
	else
		xsc_destroy_lag(entry);
}

static u8 xsc_get_valid_bond_id(struct xsc_board_lag *board_lag)
{
	u8 bond_valid_mask = board_lag->bond_valid_mask;
	u8 i;

	for (i = 0; i < XSC_BOARD_LAG_MAX; i++) {
		if (!(bond_valid_mask & BIT(i))) {
			board_lag->bond_valid_mask = (bond_valid_mask | BIT(i));
			return i;
		}
	}
	return BOND_ID_INVALID;
}

static void xsc_lag_setup(struct xsc_board_lag *board_lag,
			  struct net_device *upper, struct xsc_core_device *xdev, bool no_wq)
{
	struct bonding *bond = netdev_priv(upper);
	struct xsc_lag *lag = NULL;
	u8 bond_id;

	bond_id = xsc_get_valid_bond_id(board_lag);

	if (bond_id == BOND_ID_INVALID)
		return;

	xdev->bond_id = bond_id;
	lag  = &board_lag->xsc_lag[xdev->bond_id];

	INIT_LIST_HEAD(&lag->slave_list);
	list_add(&xdev->slave_node, &lag->slave_list);
	lag->xsc_member_cnt = 1;
	lag->bond_dev = upper;
	lag->bond_mode = BOND_MODE(bond);
	lag->tx_type = bond_lag_tx_type(bond);
	lag->hash_type = xsc_lag_hashtype_convert(bond_lag_hash_type(bond));
	lag->board_id = xdev->board_info->board_id;
	lag->lag_id = xdev->caps.lag_logic_port_ofst + xdev->bond_id;

	xsc_core_info(xdev, "lag_id = %d, board_id = %d, bond_mode = %d\n",
		      lag->lag_id, lag->board_id, lag->bond_mode);

	pack_lag_create(lag, xdev, false);
}

static bool xsc_is_ndev_xsc_pf(struct net_device *slave_ndev)
{
	struct device *dev = &slave_ndev->dev;
	struct pci_dev *pdev = to_pci_dev(dev->parent);

	return (pdev->device == XSC_MS_PF_DEV_ID ||
		pdev->device == XSC_MV_SOC_PF_DEV_ID);
}

static u8 xsc_get_bond_board_xsc_cnt(struct net_device *upper,
				     u32 board_id)
{
	struct xsc_adapter *adapter;
	struct xsc_core_device *xdev;
	struct net_device *ndev_tmp;
	u8 slave_cnt = 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper, ndev_tmp) {
		if (!ndev_tmp)
			continue;
		if (xsc_is_ndev_xsc_pf(ndev_tmp)) {
			adapter = netdev_priv(ndev_tmp);
			xdev = adapter->xdev;
			if (xdev->board_info->board_id == board_id)
				slave_cnt++;
		}
	}
	rcu_read_unlock();

	return slave_cnt;
}

static void xsc_lag_member_add(struct xsc_lag *lag,
			       struct xsc_core_device *xdev, bool no_wq)
{
	list_add_tail(&xdev->slave_node, &lag->slave_list);
	lag->xsc_member_cnt++;
	lag->not_roce_lag_xdev_mask |= BIT(xdev->pf_id);

	xsc_core_dbg(xdev, "xsc_member_cnt = %d\n",
		     lag->xsc_member_cnt);

	pack_lag_add_member(lag, xdev, no_wq);
}

static void xsc_lag_member_remove(struct xsc_lag *lag,
				  struct xsc_core_device *xdev, bool no_wq)
{
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);
	u8 bond_valid_mask;

	lag->xsc_member_cnt--;

	xsc_core_info(xdev, "xsc_member_cnt = %d\n",
		      lag->xsc_member_cnt);

	if (lag->xsc_member_cnt > 0) {
		pack_lag_remove_member(lag, xdev, no_wq);
	} else {
		pack_lag_destroy(lag, xdev, no_wq);

		lag->lag_id = LAG_ID_INVALID;
		lag->board_id = BOARD_ID_INVALID;

		bond_valid_mask = board_lag->bond_valid_mask;
		board_lag->bond_valid_mask = bond_valid_mask & ~BIT(xdev->bond_id);
	}

	list_del(&xdev->slave_node);
	xdev->bond_id = BOND_ID_INVALID;
}

static void xsc_lag_update_member(struct xsc_lag *lag,
				  struct net_device *ndev, struct net_device *upper, u8 bond_id)
{

	struct xsc_adapter *adapter = netdev_priv(ndev);
	struct xsc_core_device *xdev = adapter->xdev;
	u8 xsc_slave_cnt = xsc_get_bond_board_xsc_cnt(upper, lag->board_id);

	xsc_core_dbg(xdev, "xsc_slave_cnt = %d, old_xsc_slave_cnt = %d\n",
		     xsc_slave_cnt, lag->xsc_member_cnt);

	if (xsc_slave_cnt > lag->xsc_member_cnt)
		xsc_lag_member_add(lag, xdev, false);

	if (xsc_slave_cnt < lag->xsc_member_cnt)
		xsc_lag_member_remove(lag, xdev, false);
}

static u8 xsc_get_upper_bond_id(struct net_device *bond_ndev,
				struct net_device *ndev, struct xsc_board_lag *board_lag,
				bool hash_change)
{
	u8	i;
	struct xsc_lag *lag;
	u8 bond_valid_mask = board_lag->bond_valid_mask;
	struct xsc_adapter *adapter;
	struct xsc_core_device *xdev;
	u8 bond_id = BOND_ID_INVALID;

	for (i = 0; i < XSC_BOARD_LAG_MAX; i++) {
		if (bond_valid_mask & BIT(i)) {
			lag = &board_lag->xsc_lag[i];
			if (!hash_change) {
				adapter = netdev_priv(ndev);
				xdev = adapter->xdev;
				if (lag->bond_dev == bond_ndev &&
				    lag->board_id == xdev->board_info->board_id) {
					bond_id = i;
					break;
				}
			} else {
				if (lag->bond_dev == bond_ndev) {
					bond_id = i;
					break;
				}
			}
		}
	}

	return bond_id;
}

static struct xsc_board_lag *xsc_board_lag_filter(struct xsc_board_lag *board_lag,
						  struct net_device *ndev)
{
	struct xsc_adapter *adapter;
	struct xsc_core_device *xdev;

	if (xsc_is_ndev_xsc_pf(ndev)) {
		adapter = netdev_priv(ndev);
		xdev = adapter->xdev;
		if (xdev->board_info->board_id == board_lag->board_id)
			return board_lag;
	}

	return NULL;
}

static void xsc_handle_changeupper_event(struct xsc_board_lag *board_lag,
					 struct net_device *ndev,
					 struct netdev_notifier_changeupper_info *info)
{
	struct xsc_adapter *adapter;
	struct xsc_core_device *xdev;
	struct net_device *upper = info->upper_dev;
	u8 bond_id;
	struct xsc_lag *lag;

	if (!netif_is_lag_master(upper) || !ndev)
		return;

	mutex_lock(&board_lag->lock);
	if (!xsc_board_lag_filter(board_lag, ndev)) {
		mutex_unlock(&board_lag->lock);
		return;
	}

	adapter = netdev_priv(ndev);
	xdev = adapter->xdev;

	bond_id = xsc_get_upper_bond_id(upper, ndev, board_lag, false);
	xdev->bond_id = bond_id;

	xsc_core_dbg(xdev, "bond_id = %d\n", bond_id);

	if (bond_id != BOND_ID_INVALID) {
		lag = &board_lag->xsc_lag[bond_id];
		xsc_lag_update_member(lag, ndev, upper, bond_id);
		if (lag->xsc_member_cnt == 0)
			memset(lag, 0, sizeof(*lag));
	} else {
		xsc_lag_setup(board_lag, upper, xdev, false);
	}
	mutex_unlock(&board_lag->lock);
}

static void xsc_handle_changelowerstate_event(struct xsc_board_lag *board_lag,
					      struct net_device *ndev,
					      struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info;
	struct net_device *bond_dev;
	struct slave *slave;
	struct xsc_lag *lag;
	u8 bond_id;
	enum lag_slave_status slave_status = XSC_LAG_SLAVE_INACTIVE;

	if (!netif_is_lag_port(ndev) || !info->lower_state_info)
		return;

	rcu_read_lock();
	slave = bond_slave_get_rtnl(ndev);
	rcu_read_unlock();
	if (!slave || !slave->bond || !slave->bond->dev)
		return;

	bond_dev = slave->bond->dev;

	lag_lower_info = info->lower_state_info;
	if (lag_lower_info->link_up && lag_lower_info->tx_enabled)
		slave_status = XSC_LAG_SLAVE_ACTIVE;

	mutex_lock(&board_lag->lock);
	if (!xsc_board_lag_filter(board_lag, ndev)) {
		mutex_unlock(&board_lag->lock);
		return;
	}

	bond_id = xsc_get_upper_bond_id(bond_dev, ndev, board_lag, false);
	if (bond_id == BOND_ID_INVALID) {
		mutex_unlock(&board_lag->lock);
		return;
	}

	lag = &board_lag->xsc_lag[bond_id];
	pack_lag_update_member_status(lag, ndev, slave_status);
	mutex_unlock(&board_lag->lock);

	return;
}

static void xsc_handle_changehash_event(struct xsc_board_lag *board_lag,
					struct net_device *ndev)
{
	struct bonding *bond;
	enum netdev_lag_hash hash_type;
	struct xsc_lag *lag;
	u8 bond_id;

	if (!netif_is_lag_master(ndev))
		return;

	bond = netdev_priv(ndev);
	if (!bond_mode_uses_xmit_hash(bond))
		return;

	mutex_lock(&board_lag->lock);
	bond_id = xsc_get_upper_bond_id(ndev, NULL, board_lag, true);
	if (bond_id == BOND_ID_INVALID) {
		mutex_unlock(&board_lag->lock);
		return;
	}

	lag = &board_lag->xsc_lag[bond_id];
	hash_type = xsc_lag_hashtype_convert(bond_lag_hash_type(bond));

	if (hash_type != lag->hash_type) {
		lag->hash_type = hash_type;
		pack_lag_update_hash_type(lag, bond_id, hash_type);
	}
	mutex_unlock(&board_lag->lock);

	return;
}

static int xsc_lag_netdev_event(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct xsc_board_lag *board_lag;

	if (event != NETDEV_CHANGE && event != NETDEV_CHANGEUPPER &&
	    event != NETDEV_CHANGELOWERSTATE)
		return NOTIFY_DONE;

	board_lag = container_of(this, struct xsc_board_lag, nb);
	if (!board_lag)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		xsc_handle_changeupper_event(board_lag, ndev, ptr);
		break;
	case NETDEV_CHANGELOWERSTATE:
		xsc_handle_changelowerstate_event(board_lag, ndev, ptr);
		break;
	case NETDEV_CHANGE:
		xsc_handle_changehash_event(board_lag, ndev);
		break;
	}

	return NOTIFY_DONE;
}

static struct xsc_board_lag *xsc_board_lag_dev_alloc(struct xsc_core_device *xdev)
{
	struct xsc_board_lag *board_lag;
	struct lag_event_list *lag_event_list;
	int err;

	board_lag = kzalloc(sizeof(*board_lag), GFP_KERNEL);
	if (!board_lag)
		return NULL;

	lag_event_list = &board_lag->lag_event_list;

	INIT_LIST_HEAD(&lag_event_list->head);
	spin_lock_init(&lag_event_list->lock);
	init_waitqueue_head(&lag_event_list->wq);
	lag_event_list->wait_flag = XSC_SLEEP;
	lag_event_list->bond_poll_task =
		kthread_create(xsc_do_bond_thread, (void *)board_lag, "xsc board lag");
	if (lag_event_list->bond_poll_task)
		wake_up_process(lag_event_list->bond_poll_task);

	board_lag->nb.notifier_call = xsc_lag_netdev_event;
	err = register_netdevice_notifier(&board_lag->nb);
	if (err)
		goto err_create_notifier;

	kref_init(&board_lag->ref);
	mutex_init(&board_lag->lock);
	board_lag->bond_valid_mask = 0;

	return board_lag;

err_create_notifier:
	xsc_core_err(xdev, "failed to register LAG netdev notifier\n");
	board_lag->nb.notifier_call = NULL;
	kthread_stop(lag_event_list->bond_poll_task);
	kfree(board_lag);

	return NULL;
}

static int __xsc_lag_add_xdev(struct xsc_core_device *xdev)
{
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (!board_lag) {
		board_lag = xsc_board_lag_dev_alloc(xdev);
		if (!board_lag)
			return -EPIPE;
		xsc_board_lag_set(xdev, board_lag);
	} else {
		kref_get(&board_lag->ref);
	}

	xdev->bond_id = BOND_ID_INVALID;

	return 0;
}

void xsc_lag_add_xdev(struct xsc_core_device *xdev)
{
	int err;

	xsc_dev_list_lock();
	err = __xsc_lag_add_xdev(xdev);
	xsc_dev_list_unlock();

	if (err)
		xsc_core_dbg(xdev, "add xdev err=%d\n", err);

}
EXPORT_SYMBOL(xsc_lag_add_xdev);

static void xsc_lag_dev_free(struct kref *ref)
{
	struct xsc_board_lag *board_lag = container_of(ref, struct xsc_board_lag, ref);
	struct lag_event_list *lag_event_list = &board_lag->lag_event_list;

	if (board_lag->nb.notifier_call)
		unregister_netdevice_notifier(&board_lag->nb);

	lag_event_list->wait_flag = XSC_EXIT;
	wake_up(&lag_event_list->wq);
	if (lag_event_list->bond_poll_task)
		kthread_stop(lag_event_list->bond_poll_task);

	board_lag->nb.notifier_call = NULL;
	mutex_destroy(&board_lag->lock);

	xsc_board_lag_reset(board_lag->board_id);
	kfree(board_lag);
}

void xsc_lag_remove_xdev(struct xsc_core_device *xdev)
{
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	xsc_dev_list_lock();
	if (board_lag)
		kref_put(&board_lag->ref, xsc_lag_dev_free);
	xsc_dev_list_unlock();
}
EXPORT_SYMBOL(xsc_lag_remove_xdev);

void xsc_lag_disable(struct xsc_core_device *xdev)
{
	struct xsc_lag *lag;
	struct xsc_core_device *xdev_tmp = NULL;
	u8 cnt = 0;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	mutex_lock(&board_lag->lock);
	lag = __xsc_get_lag(xdev);
	if (!lag || !__xsc_lag_is_active(lag)) {
		mutex_unlock(&board_lag->lock);
		return;
	}

	list_for_each_entry(xdev_tmp, &lag->slave_list, slave_node) {
		cnt++;
		if (cnt == lag->xsc_member_cnt)
			pack_lag_destroy(lag, xdev_tmp, false);
		else
			pack_lag_remove_member(lag, xdev_tmp, false);
	}

	lag->mode_changes_in_progress++;
	mutex_unlock(&board_lag->lock);
}
EXPORT_SYMBOL(xsc_lag_disable);

void xsc_lag_enable(struct xsc_core_device *xdev)
{
	struct xsc_lag *lag;
	struct xsc_core_device *xdev_tmp = NULL;
	u8 cnt = 0;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	mutex_lock(&board_lag->lock);
	lag = __xsc_get_lag(xdev);
	if (!lag || __xsc_lag_is_active(lag)) {
		mutex_unlock(&board_lag->lock);
		return;
	}

	lag->mode_changes_in_progress--;
	list_for_each_entry(xdev_tmp, &lag->slave_list, slave_node) {
		if (cnt == 0)
			pack_lag_create(lag, xdev_tmp, false);
		else
			pack_lag_add_member(lag, xdev_tmp, false);

		cnt++;
	}
	mutex_unlock(&board_lag->lock);
}
EXPORT_SYMBOL(xsc_lag_enable);

void xsc_lag_add_netdev(struct net_device *ndev)
{
	struct xsc_adapter *adapter = netdev_priv(ndev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct bonding *bond = NULL;
	struct net_device *upper = NULL;
	struct slave *slave;
	u8 bond_id = BOND_ID_INVALID;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);
	struct xsc_lag *lag;

	if (!board_lag || ndev->reg_state != NETREG_REGISTERED ||
	    !netif_is_bond_slave(ndev))
		return;

	rcu_read_lock();
	slave = bond_slave_get_rcu(ndev);
	rcu_read_unlock();
	bond = bond_get_bond_by_slave(slave);
	upper = bond->dev;

	mutex_lock(&board_lag->lock);
	bond_id = xsc_get_upper_bond_id(upper, ndev, board_lag, false);
	xdev->bond_id = bond_id;
	lag = __xsc_get_lag(xdev);

	if (bond_id != BOND_ID_INVALID)
		xsc_lag_member_add(lag, xdev, true);
	else
		xsc_lag_setup(board_lag, upper, xdev, true);
	mutex_unlock(&board_lag->lock);
}
EXPORT_SYMBOL(xsc_lag_add_netdev);

void xsc_lag_remove_netdev(struct net_device *ndev)
{
	struct xsc_adapter *adapter = netdev_priv(ndev);
	struct xsc_core_device *xdev = adapter->xdev;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);
	struct xsc_lag *lag;

	if (!board_lag)
		return;

	mutex_lock(&board_lag->lock);
	lag = __xsc_get_lag(xdev);
	if (!lag)
		goto out;

	if (__xsc_lag_is_active(lag)) {
		xsc_lag_member_remove(lag, xdev, true);
		if (lag->xsc_member_cnt == 0)
			memset(lag, 0, sizeof(*lag));
	}

out:
	mutex_unlock(&board_lag->lock);
}
EXPORT_SYMBOL(xsc_lag_remove_netdev);

bool xsc_lag_is_roce(struct xsc_core_device *xdev)
{
	struct xsc_lag *lag;

	lag = __xsc_get_lag(xdev);
	if (!lag)
		return false;

	return __xsc_lag_is_roce(lag);
}
EXPORT_SYMBOL(xsc_lag_is_roce);

struct xsc_lag *xsc_get_lag(struct xsc_core_device *xdev)
{
	return __xsc_get_lag(xdev);
}
EXPORT_SYMBOL(xsc_get_lag);

u16 xsc_get_lag_id(struct xsc_core_device *xdev)
{
	struct xsc_lag *lag;
	u16 lag_id = LAG_ID_INVALID;

	xsc_board_lag_lock(xdev);
	lag = __xsc_get_lag(xdev);
	if (lag && __xsc_lag_is_active(lag) && !__xsc_lag_is_kernel(lag))
		lag_id = lag->lag_id;
	xsc_board_lag_unlock(xdev);

	return lag_id;
}
EXPORT_SYMBOL(xsc_get_lag_id);

struct xsc_core_device *xsc_get_roce_lag_xdev(struct xsc_core_device *xdev)
{
	struct xsc_core_device *roce_lag_xdev;
	struct xsc_lag *lag;

	xsc_board_lag_lock(xdev);
	if (xsc_lag_is_roce(xdev)) {
		lag = __xsc_get_lag(xdev);
		roce_lag_xdev = list_first_entry(&lag->slave_list,
						 struct xsc_core_device, slave_node);
	} else {
		roce_lag_xdev = xdev;
	}
	xsc_board_lag_unlock(xdev);

	return roce_lag_xdev;
}
EXPORT_SYMBOL(xsc_get_roce_lag_xdev);

