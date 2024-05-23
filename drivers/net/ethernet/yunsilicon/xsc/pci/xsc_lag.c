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

#include <linux/if_bonding.h>
#include <net/neighbour.h>
#include <net/arp.h>

#ifdef fib_nh_dev
#define HAVE_FIB_NH_DEV
#endif

static DEFINE_MUTEX(lag_mutex);

static inline u8 xsc_lag_hashtype_convert(struct xsc_core_device *xdev, struct xsc_lag *ldev)
{
	enum netdev_lag_hash hash_type = ldev->tracker.hash_type;
	u8 lag_sel_mode;

	xsc_core_info(xdev, "hash_type = %d\n", hash_type);

	switch (hash_type) {
	case NETDEV_LAG_HASH_L23:
		lag_sel_mode = XSC_LAG_HASH_L23;
		break;

	case NETDEV_LAG_HASH_L34:
		lag_sel_mode = XSC_LAG_HASH_L34;
		break;

	case NETDEV_LAG_HASH_E23:
		lag_sel_mode = XSC_LAG_HASH_E23;
		break;

	case NETDEV_LAG_HASH_E34:
		lag_sel_mode = XSC_LAG_HASH_E34;
		break;

	default:
		lag_sel_mode = XSC_LAG_HASH_L23;
		break;
	}

	return lag_sel_mode;
}

int xsc_cmd_create_lag(struct xsc_lag *ldev, u8 flags)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	struct xsc_core_device *xdev1 = ldev->pf[1].xdev;
	struct net_device *netdev0 = xdev0->netdev;
	struct net_device *netdev1 = xdev1->netdev;
	struct lag_tracker *tracker = &ldev->tracker;
	u8 remap_port1 = ldev->v2p_map[0];
	u8 remap_port2 = ldev->v2p_map[1];
	int ret = -1;

	struct xsc_create_lag_mbox_in in = {};
	struct xsc_create_lag_mbox_out out = {};
	struct xsc_lag_port_info *info_mac0 = &in.req.info_mac0;
	struct xsc_lag_port_info *info_mac1 = &in.req.info_mac1;

	bool mp_lag = flags & XSC_LAG_FLAG_MULTIPATH;
	bool roce_lag = flags & XSC_LAG_FLAG_ROCE;
	bool sriov_lag = flags & XSC_LAG_FLAG_SRIOV;
	bool kernel_bond = flags & XSC_BOND_FLAG_KERNEL;

	u16 lag_id = XSC_LAG_PORT_START;
	u8 lag_num = XSC_LAG_NUM_MAX;

	if (!(flags & XSC_LAG_MODE_FLAGS) && !kernel_bond)
		return -EINVAL;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_CREATE);

	if (!kernel_bond) {
		in.req.mp_lag = mp_lag;
		in.req.roce_lag = roce_lag;
		in.req.lag_id = cpu_to_be16(lag_id);
		in.req.lag_num = lag_num;
		in.req.lag_start = cpu_to_be16(lag_id);
		in.req.lag_sel_mode =
			mp_lag ? XSC_LAG_HASH_L34 : xsc_lag_hashtype_convert(xdev0, ldev);
		in.req.remap_port1 = remap_port1;
		in.req.remap_port2 = remap_port2;

		xsc_core_info(xdev0, "create lag: lag_id = %d, mp_lag=%d, roce_lag=%d, sriov_lag=%d, lag_sel_mode = %d\n",
			      lag_id, mp_lag, roce_lag, sriov_lag, in.req.lag_sel_mode);
	} else {
		in.req.kernel_bond = true;
		xsc_core_info(xdev0, "create kernel bond\n");
	}

	memcpy(info_mac0->netdev_addr, netdev0->dev_addr, ETH_ALEN);
	memcpy(info_mac1->netdev_addr, netdev1->dev_addr, ETH_ALEN);
	memcpy(info_mac0->gw_dmac, tracker->gw_dmac0, ETH_ALEN);
	memcpy(info_mac1->gw_dmac, tracker->gw_dmac1, ETH_ALEN);
	info_mac0->glb_func_id	= cpu_to_be16(xdev0->glb_func_id);
	info_mac1->glb_func_id	= cpu_to_be16(xdev1->glb_func_id);

	ret = xsc_cmd_exec(xdev0, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev0, "Failed to create lag, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	if (!kernel_bond)
		ldev->lag_id = lag_id;

	return ret;
}

int xsc_cmd_modify_lag(struct xsc_lag *ldev)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	u16 lag_id = ldev->lag_id;
	bool mp_lag = ldev->flags & XSC_LAG_FLAG_MULTIPATH;
	bool roce_lag = ldev->flags & XSC_LAG_FLAG_ROCE;
	bool sriov_lag = ldev->flags & XSC_LAG_FLAG_SRIOV;
	u8 remap_port1 = ldev->v2p_map[0];
	u8 remap_port2 = ldev->v2p_map[1];
	struct xsc_modify_lag_mbox_in in = {};
	struct xsc_modify_lag_mbox_out out = {};
	int ret = -1;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_MODIFY);

	in.req.mp_lag = mp_lag;
	in.req.roce_lag = roce_lag;
	in.req.lag_id = cpu_to_be16(lag_id);
	in.req.remap_port1 = remap_port1;
	in.req.remap_port2 = remap_port2;
	in.req.lag_sel_mode = mp_lag ? XSC_LAG_HASH_L34 : xsc_lag_hashtype_convert(xdev0, ldev);

	xsc_core_info(xdev0, "modify lag: lag_id = %d, mp_lag=%d, roce_lag=%d, sriov_lag=%d, lag_sel_mode = %d\n",
		      lag_id, mp_lag, roce_lag, sriov_lag, in.req.lag_sel_mode);

	ret = xsc_cmd_exec(xdev0, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev0, "Failed to modify lag, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return ret;
}

int xsc_cmd_destroy_lag(struct xsc_lag *ldev, u8 bond_flags)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	u8 flags = ldev->flags;
	int ret = -1;

	struct xsc_destroy_lag_mbox_in in = {};
	struct xsc_destroy_lag_mbox_out out = {};

	if (!(flags & XSC_LAG_MODE_FLAGS) && !(flags & XSC_BOND_FLAG_KERNEL))
		return -EINVAL;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_DESTROY);

	if (bond_flags & XSC_LAG_MODE_FLAGS) {
		in.req.lag_id = ldev->lag_id;
		xsc_core_info(xdev0, "destroy lag: lag_id = %d\n", ldev->lag_id);
	} else {
		in.req.kernel_bond = true;
		xsc_core_info(xdev0, "destroy kernel bond\n");
	}

	ret = xsc_cmd_exec(xdev0, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev0, "Failed to destroy lag, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	ldev->lag_id = U16_MAX;

	return ret;
}

static inline bool xsc_is_roce_lag_allowed(struct xsc_lag *ldev)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	struct xsc_core_device *xdev1 = ldev->pf[1].xdev;

	return !xsc_sriov_is_enabled(xdev0) && !xsc_sriov_is_enabled(xdev1);
}

static int xsc_lag_set_qos(struct xsc_core_device *xdev, u16 lag_id, u8 member_bitmap, u8 lag_del)
{
	struct xsc_set_lag_qos_mbox_in in;
	struct xsc_set_lag_qos_mbox_out out;
	struct xsc_set_lag_qos_request *req;
	int ret;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	req = &in.req;

	req->lag_id = cpu_to_be16(lag_id);
	req->member_bitmap = member_bitmap;
	req->lag_del = lag_del;
	req->pcie_no = xdev->pcie_no;
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_LAG_SET_QOS);

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	return ret;
}

static bool xsc_lag_check_prereq(struct xsc_lag *ldev)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	struct xsc_core_device *xdev1 = ldev->pf[1].xdev;

	if (!xdev0 || !xdev1)
		return false;

	if (xsc_is_roce_lag_allowed(ldev))
		return true;

#ifdef CONFIG_XSC_ESWITCH
	if ((xdev0->priv.eswitch->mode == XSC_ESWITCH_OFFLOADS &&
	     xdev1->priv.eswitch->mode != XSC_ESWITCH_OFFLOADS) ||
	    (xdev0->priv.eswitch->mode != XSC_ESWITCH_OFFLOADS &&
	     xdev1->priv.eswitch->mode == XSC_ESWITCH_OFFLOADS))
		xsc_core_info(xdev0, "lag is permitted by both pf is in switchdev mode\n");

	return (xdev0->priv.eswitch->mode  == XSC_ESWITCH_OFFLOADS) &&
			(xdev1->priv.eswitch->mode == XSC_ESWITCH_OFFLOADS);
#else
#ifdef XSC_VF_ECMP_TEST
	return true;
#else
	return false;
#endif
#endif
}

static void xsc_infer_tx_affinity_mapping(struct xsc_core_device *xdev0, struct xsc_lag *ldev,
					  u8 *port1, u8 *port2)
{
	struct lag_tracker *tracker = &ldev->tracker;
	*port1 = MAC_INVALID;
	*port2 = MAC_INVALID;

	if (tracker->netdev_state[0].tx_enabled &&
	    tracker->netdev_state[0].link_up)
		*port1 = MAC_0_LOGIC;

	if (tracker->netdev_state[1].tx_enabled &&
	    tracker->netdev_state[1].link_up)
		*port2 = MAC_1_LOGIC;

	xsc_core_info(xdev0, "tx_affinity_mapping: port1 = %d, port2 = %d\n",
		      *port1, *port2);
}

static int xsc_create_lag(struct xsc_lag *ldev, u8 flags)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	int err;

	xsc_infer_tx_affinity_mapping(xdev0, ldev, &ldev->v2p_map[0],
				      &ldev->v2p_map[1]);

	xsc_core_info(xdev0, "xsc create lag 1:%d port 2:%d",
		      ldev->v2p_map[0], ldev->v2p_map[1]);

	err = xsc_cmd_create_lag(ldev, flags);
	if (err)
		xsc_core_err(xdev0, "Failed to create LAG (%d)\n", err);

	return err;
}

void xsc_activate_lag(struct xsc_lag *ldev, u8 flags)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	u8 member_bitmap;

	if (xsc_create_lag(ldev, flags)) {
		xsc_core_err(xdev0, "Failed to activate LAG\n"
				"Make sure all VFs are unbound prior to LAG activation or deactivation\n");
		return;
	}

	ldev->flags |= flags;

	member_bitmap = GET_LAG_MEMBER_BITMAP(ldev->v2p_map[0], ldev->v2p_map[1]);
	if (xsc_lag_set_qos(xdev0, ldev->lag_id, member_bitmap, false))
		xsc_core_err(xdev0, "failed to set QoS for LAG %u\n", ldev->lag_id);
}

void xsc_modify_lag(struct xsc_lag *ldev)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	struct lag_tracker *tracker = &ldev->tracker;
	u8 v2p_port1, v2p_port2;
	u8 member_bitmap;
	int err;

	xsc_infer_tx_affinity_mapping(xdev0, ldev, &v2p_port1,
				      &v2p_port2);

	if (v2p_port1 != ldev->v2p_map[0] ||
	    v2p_port2 != ldev->v2p_map[1] ||
	    tracker->hash_type != tracker->old_hash_type) {
		ldev->v2p_map[0] = v2p_port1;
		ldev->v2p_map[1] = v2p_port2;

	xsc_core_info(xdev0, "modify lag map port 1:%d port 2:%d",
		      ldev->v2p_map[0], ldev->v2p_map[1]);

	err = xsc_cmd_modify_lag(ldev);
		if (err) {
			xsc_core_err(xdev0, "Failed to modify LAG (%d)\n", err);
			return;
		}
	}

	member_bitmap = GET_LAG_MEMBER_BITMAP(ldev->v2p_map[0], ldev->v2p_map[1]);
	if (xsc_lag_set_qos(xdev0, ldev->lag_id, member_bitmap, false))
		xsc_core_err(xdev0, "failed to set QoS for LAG %u\n", ldev->lag_id);
}

static void xsc_deactivate_lag(struct xsc_lag *ldev,  u8 flags)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;

	if (xsc_lag_set_qos(xdev0, ldev->lag_id, 0, true))
		xsc_core_err(xdev0, "failed to set QoS for LAG %u\n", ldev->lag_id);

	if (xsc_cmd_destroy_lag(ldev, flags))
		xsc_core_err(xdev0, "Failed to deactivate LAG; driver restart required, Make sure all VFs are unbound prior to LAG activation or deactivation\n");

	ldev->flags &= ~flags;
}

static void xsc_lag_remove_ib_devices(struct xsc_lag *ldev)
{
	int i;

	for (i = 0; i < XSC_MAX_PORTS; i++)
		if (ldev->pf[i].xdev)
			xsc_remove_dev_by_protocol(ldev->pf[i].xdev, XSC_INTERFACE_PROTOCOL_IB);
}

static void xsc_lag_add_ib_devices(struct xsc_lag *ldev)
{
	int i;

	for (i = 0; i < XSC_MAX_PORTS; i++)
		if (ldev->pf[i].xdev)
			xsc_add_dev_by_protocol(ldev->pf[i].xdev, XSC_INTERFACE_PROTOCOL_IB);
}

static void xsc_do_bond(struct xsc_lag *ldev)
{
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;
	struct xsc_core_device *xdev1 = ldev->pf[1].xdev;
	struct lag_tracker tracker;
	bool do_lag, do_bond;
	bool roce_lag;

	if (!xdev0 || !xdev1)
		return;

	mutex_lock(&lag_mutex);
	tracker = ldev->tracker;
	mutex_unlock(&lag_mutex);

	do_bond = tracker.is_kernel_bonded;

	do_lag = tracker.is_hw_bonded &&
		!tracker.lag_disable &&
		ldev->pf[0].netdev &&
		ldev->pf[1].netdev &&
		ldev->pf[0].netdev == tracker.ndev[0] &&
		ldev->pf[1].netdev == tracker.ndev[1] &&
		xsc_lag_check_prereq(ldev);

	roce_lag = xsc_is_roce_lag_allowed(ldev);

	if (roce_lag &&
	    (!radix_tree_empty(&xdev0->priv_device.bdf_tree) ||
	     !radix_tree_empty(&xdev1->priv_device.bdf_tree))) {
		xsc_core_err(xdev0, "Failed to create roce lag because the ib device is open\n");
		return;
	}

	xsc_core_info(xdev0, "do_bond = %d, do_lag = %d, is_hw_bonded = %d, lag_disable = %d, lag_check = %d\n",
		      do_bond, do_lag, tracker.is_hw_bonded, tracker.lag_disable,
		      xsc_lag_check_prereq(ldev));

	if ((do_bond && !__xsc_bond_is_active(ldev)) ||
	    (do_lag && !__xsc_lag_is_active(ldev))) {
		if (do_lag && roce_lag) {
			xsc_lag_remove_ib_devices(ldev);
			xsc_activate_lag(ldev, XSC_LAG_FLAG_ROCE);
			xsc_add_dev_by_protocol(xdev0, XSC_INTERFACE_PROTOCOL_IB);
		} else {
			xsc_activate_lag(ldev, (do_lag ?
				XSC_LAG_FLAG_SRIOV : XSC_BOND_FLAG_KERNEL));
		}
	} else if (do_lag && __xsc_lag_is_active(ldev)) {
		xsc_modify_lag(ldev);
	} else if (!do_lag && __xsc_lag_is_active(ldev)) {
		if (roce_lag)
			xsc_remove_dev_by_protocol(xdev0, XSC_INTERFACE_PROTOCOL_IB);

		xsc_deactivate_lag(ldev, XSC_LAG_MODE_FLAGS);

		if (roce_lag)
			xsc_lag_add_ib_devices(ldev);
	} else if (!do_bond && __xsc_bond_is_active(ldev)) {
		xsc_deactivate_lag(ldev, XSC_BOND_FLAG_KERNEL);
	}
}

static void xsc_do_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct xsc_lag *ldev = container_of(delayed_work, struct xsc_lag,
					    bond_work);
	int status;

	status = mutex_trylock(&xsc_intf_mutex);
	if (!status) {
		/* 1 sec delay. */
		queue_delayed_work(ldev->wq, &ldev->bond_work, HZ / 2);
		return;
	}

	xsc_do_bond(ldev);
	mutex_unlock(&xsc_intf_mutex);
}

static struct xsc_lag *xsc_lag_dev_alloc(void)
{
	struct xsc_lag *ldev;

	ldev = kzalloc(sizeof(*ldev), GFP_KERNEL);
	if (!ldev)
		return NULL;

	ldev->wq = create_singlethread_workqueue("xsc_lag");
	if (!ldev->wq) {
		kfree(ldev);
		return NULL;
	}

	kref_init(&ldev->ref);
	INIT_DELAYED_WORK(&ldev->bond_work, xsc_do_bond_work);

	return ldev;
}

static void xsc_lag_dev_add_xdev(struct xsc_lag *ldev,
				 struct xsc_core_device *xdev)
{
	unsigned int fn = PCI_FUNC(xdev->pdev->devfn) % XSC_MAX_PORTS;

	if (fn >= XSC_MAX_PORTS)
		return;

	mutex_lock(&lag_mutex);
	ldev->pf[fn].xdev = xdev;
	xdev->priv.lag = ldev;
	mutex_unlock(&lag_mutex);
}

int xsc_lag_dev_get_netdev_idx(struct xsc_lag *ldev,
			       struct net_device *ndev)
{
	int i;

	for (i = 0; i < XSC_MAX_PORTS; i++)
		if (ldev->pf[i].netdev == ndev)
			return i;

	return -1;
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

static bool xsc_lag_eval_bonding_conds(struct xsc_lag *ldev,
				       struct lag_tracker *tracker,
				       struct net_device *upper)
{
	int bond_status = 0, num_slaves = 0, idx;
	struct net_device *ndev_tmp;
	bool is_hw_bonded = false, is_kernel_bonded = false;
	struct xsc_core_device *xdev0 = ldev->pf[0].xdev;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper, ndev_tmp) {
		idx = xsc_lag_dev_get_netdev_idx(ldev, ndev_tmp);
		if (idx > -1)
			bond_status |= (1 << idx);

		num_slaves++;
	}
	rcu_read_unlock();

	xsc_core_info(xdev0, "num_slaves = %d, bond_status = %d\n",
		      num_slaves, bond_status);
	/* None of this lagdev's netdevs are slaves of this master. */

	if (tracker->is_hw_bonded &&
	    (!tracker->netdev_state[0].link_up || !tracker->netdev_state[0].tx_enabled) &&
	    (!tracker->netdev_state[1].link_up || !tracker->netdev_state[1].tx_enabled)) {
		tracker->is_hw_bonded = false;
		return true;
	}

	if (!(bond_status & 0x3))
		return false;

	/* Determine bonding status:
	 * A device is considered bonded if both its physical ports are slaves
	 * of the same lag master, and only them.
	 * Lag mode must be activebackup or hash.
	 */
	if (!tracker->is_kernel_bonded && !tracker->is_hw_bonded)
		is_kernel_bonded = (num_slaves == XSC_MAX_PORTS) &&
			(bond_status == 0x3);

	if (!tracker->is_hw_bonded)
		is_hw_bonded = (num_slaves == XSC_MAX_PORTS) &&
			(bond_status == 0x3) &&
			((tracker->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) ||
			(tracker->tx_type == NETDEV_LAG_TX_TYPE_HASH));

	xsc_core_info(xdev0, "is_hw_bonded = %d, is_kernel_bonded = %d\n", is_hw_bonded,
		      is_kernel_bonded);

	if (tracker->is_hw_bonded != is_hw_bonded) {
		tracker->is_hw_bonded = is_hw_bonded;
		return true;
	}

	if (tracker->is_kernel_bonded != is_kernel_bonded) {
		tracker->is_kernel_bonded = is_kernel_bonded;
		return true;
	}

	return false;
}

static bool xsc_handle_changeupper_event(struct xsc_lag *ldev,
					 struct lag_tracker *tracker,
					 struct net_device *ndev,
					 struct netdev_notifier_changeupper_info *info)
{
	enum netdev_lag_tx_type tx_type = NETDEV_LAG_TX_TYPE_UNKNOWN;
	struct netdev_lag_upper_info *lag_upper_info;
	struct net_device *upper = info->upper_dev;

	if (!netif_is_lag_master(upper))
		return false;

	if (info->linking) {
		lag_upper_info = info->upper_info;

		if (lag_upper_info) {
			tx_type = lag_upper_info->tx_type;
			tracker->hash_type = lag_upper_info->hash_type;
		}
	}

	tracker->tx_type = tx_type;

	return xsc_lag_eval_bonding_conds(ldev, tracker, upper);
}

static bool xsc_handle_changelowerstate_event(struct xsc_lag *ldev,
					      struct lag_tracker *tracker,
					      struct net_device *ndev,
					      struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info;
	int idx;

	if (!netif_is_lag_port(ndev))
		return 0;

	idx = xsc_lag_dev_get_netdev_idx(ldev, ndev);
	if (idx == -1)
		return 0;

	/* This information is used to determine virtual to physical
	 * port mapping.
	 */
	lag_lower_info = info->lower_state_info;
	if (!lag_lower_info)
		return 0;

	tracker->netdev_state[idx] = *lag_lower_info;

	return 1;
}

static bool xsc_handle_changehash_event(struct xsc_lag *ldev,
					struct lag_tracker *tracker,
					struct net_device *ndev,
					struct netdev_notifier_change_info *change_info)
{
	struct bonding *bond;
	enum netdev_lag_hash hash_type;

	if (!netif_is_lag_master(ndev))
		return false;

	bond = netdev_priv(ndev);

	if (!bond_mode_uses_xmit_hash(bond))
		return false;

	hash_type = bond_lag_hash_type(bond);

	if (hash_type != tracker->hash_type) {
		tracker->old_hash_type = tracker->hash_type;
		tracker->hash_type = hash_type;
		return true;
	}

	return false;
}

static int xsc_lag_netdev_event(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct lag_tracker tracker;
	struct xsc_lag *ldev;
	bool changed = 0;

	if (event != NETDEV_CHANGE && event != NETDEV_CHANGEUPPER &&
	    event != NETDEV_CHANGELOWERSTATE)
		return NOTIFY_DONE;

	ldev    = container_of(this, struct xsc_lag, nb);
	tracker = ldev->tracker;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		changed = xsc_handle_changeupper_event(ldev, &tracker, ndev,
						       ptr);
		break;
	case NETDEV_CHANGELOWERSTATE:
		changed = xsc_handle_changelowerstate_event(ldev, &tracker,
							    ndev, ptr);
		break;
	case NETDEV_CHANGE:
		changed = xsc_handle_changehash_event(ldev, &tracker, ndev, ptr);
	break;
	}

	mutex_lock(&lag_mutex);
	ldev->tracker = tracker;
	ldev->tracker.ndev[0] = ldev->pf[0].netdev;
	ldev->tracker.ndev[1] = ldev->pf[1].netdev;
	mutex_unlock(&lag_mutex);

	if (changed)
		queue_delayed_work(ldev->wq, &ldev->bond_work, 0);

	return NOTIFY_DONE;
}

static void xsc_lag_fib_event_flush(struct notifier_block *nb)
{
	struct lag_mp *mp = container_of(nb, struct lag_mp, fib_nb);

	flush_workqueue(mp->wq);
}

bool xsc_esw_multipath_prereq(struct xsc_core_device *xdev0,
			      struct xsc_core_device *xdev1)
{
#ifdef CONFIG_XSC_ESWITCH
	return (xdev0->priv.eswitch->mode == XSC_ESWITCH_OFFLOADS &&
		xdev1->priv.eswitch->mode == XSC_ESWITCH_OFFLOADS);
#else
	return false;
#endif
}

bool xsc_lag_multipath_check_prereq(struct xsc_lag *ldev)
{
	if (!ldev->pf[0].xdev || !ldev->pf[1].xdev)
		return false;

#ifdef XSC_VF_ECMP_TEST
	return xsc_esw_multipath_prereq(ldev->pf[0].xdev, ldev->pf[1].xdev);
#else
	return true;
#endif
}

static void xsc_lag_set_port_affinity(struct xsc_lag *ldev, int port)
{
	struct lag_tracker *tracker = &ldev->tracker;

	if (!__xsc_lag_is_multipath(ldev))
		return;

	switch (port) {
	case MAC_0_1_LOGIC:
		tracker->netdev_state[0].tx_enabled = true;
		tracker->netdev_state[0].link_up = true;
		tracker->netdev_state[1].tx_enabled = true;
		tracker->netdev_state[1].link_up = true;
		break;
	case MAC_0_LOGIC:
		tracker->netdev_state[0].tx_enabled = true;
		tracker->netdev_state[0].link_up = true;
		tracker->netdev_state[1].tx_enabled = false;
		tracker->netdev_state[1].link_up = false;
		break;
	case MAC_1_LOGIC:
		tracker->netdev_state[0].tx_enabled = false;
		tracker->netdev_state[0].link_up = false;
		tracker->netdev_state[1].tx_enabled = true;
		tracker->netdev_state[1].link_up = true;
		break;

	default:
		xsc_core_warn(ldev->pf[0].xdev, "Invalid affinity port %d",	port);
	return;
	}

	xsc_modify_lag(ldev);
}

static void xsc_lag_fib_route_event(struct xsc_lag *ldev,
				    unsigned long event,
				    struct fib_info *fi)
{
	struct lag_mp *mp = &ldev->lag_mp;
	struct fib_nh *fib_nh0, *fib_nh1;
	unsigned int nhs;
	struct neighbour *neigh0, *neigh1;

	 /* Handle add/replace event */
#ifdef HAVE_FIB_INFO_NH
	nhs = fib_info_num_path(fi);
#else
	nhs = fi->fib_nhs;
#endif
	/* Handle delete event */
	if (event == FIB_EVENT_ENTRY_DEL && __xsc_lag_is_active(ldev) && nhs == 2) {
		/* stop track */
		if (mp->mfi == fi)
			mp->mfi = NULL;
		xsc_deactivate_lag(ldev, XSC_LAG_MODE_FLAGS);
		return;
	}

	xsc_core_info(ldev->pf[0].xdev, "nhs=%d\n", nhs);

	if (nhs == 1 && event != FIB_EVENT_ENTRY_DEL) {
		if (__xsc_lag_is_active(ldev)) {
#ifdef HAVE_FIB_INFO_NH
			struct net_device *nh_dev = fib_info_nh(fi, 0)->fib_nh_dev;
#elif defined HAVE_FIB_NH_DEV
			struct net_device *nh_dev = fi->fib_nh[0].fib_nh_dev;
#else
			struct net_device *nh_dev = fi->fib_nh[0].nh_dev;
#endif
			int i = xsc_lag_dev_get_netdev_idx(ldev, nh_dev);

			xsc_lag_set_port_affinity(ldev, ++i);
		}
		return;
	}

	if (nhs != 2)
		return;

	/* Verify next hops are ports of the same hca */
#ifdef HAVE_FIB_INFO_NH
		fib_nh0 = fib_info_nh(fi, 0);
		fib_nh1 = fib_info_nh(fi, 1);
#else
		fib_nh0 = &fi->fib_nh[0];
		fib_nh1 = &fi->fib_nh[1];
#endif

#ifdef HAVE_FIB_NH_DEV
		if (!(fib_nh0->fib_nh_dev == ldev->pf[0].netdev &&
		      fib_nh1->fib_nh_dev == ldev->pf[1].netdev) &&
		    !(fib_nh0->fib_nh_dev == ldev->pf[1].netdev &&
		      fib_nh1->fib_nh_dev == ldev->pf[0].netdev)) {
#else
		if (!(fib_nh0->nh_dev == ldev->pf[0].netdev &&
		      fib_nh1->nh_dev == ldev->pf[1].netdev) &&
		    !(fib_nh0->nh_dev == ldev->pf[1].netdev &&
		      fib_nh1->nh_dev == ldev->pf[0].netdev)) {
#endif
			xsc_core_err(ldev->pf[0].xdev,
				     "Multipath offload require two ports of the same HCA\n");
			return;
		}

	/* First time we see multipath route */
	if (!mp->mfi && !__xsc_lag_is_active(ldev)) {
		struct lag_tracker  *tracker = &ldev->tracker;
#ifdef fib_nh_gw4
		neigh0 = neigh_lookup(&arp_tbl, &fib_nh0->fib_nh_gw4, ldev->pf[0].netdev);
		neigh1 = neigh_lookup(&arp_tbl, &fib_nh1->fib_nh_gw4, ldev->pf[1].netdev);
#else
		neigh0 = neigh_lookup(&arp_tbl, &fib_nh0->nh_gw, ldev->pf[0].netdev);
		neigh1 = neigh_lookup(&arp_tbl, &fib_nh1->nh_gw, ldev->pf[1].netdev);
#endif
		if (!neigh0 || !neigh1) {
			xsc_core_err(ldev->pf[0].xdev,
				     "Multipath offload require two ports with valid neighbor\n");
			return;
		}

		if (neigh0) {
			if (!(neigh0->nud_state & NUD_NOARP)) {
				read_lock_bh(&neigh0->lock);
				memcpy(&tracker->gw_dmac0[0], neigh0->ha, ETH_ALEN);
				read_unlock_bh(&neigh0->lock);
			} else {
				neigh_release(neigh0);
				neigh_release(neigh1);
				xsc_core_err(ldev->pf[0].xdev,
					     "Multipath offload require two ports with valid gw\n");
				return;
			}
		}

		if (neigh1) {
			if (!(neigh1->nud_state & NUD_NOARP)) {
				read_lock_bh(&neigh1->lock);
				memcpy(&tracker->gw_dmac1[0], neigh1->ha, ETH_ALEN);
				read_unlock_bh(&neigh1->lock);
			}  else {
				neigh_release(neigh0);
				neigh_release(neigh1);
				xsc_core_err(ldev->pf[0].xdev,
					     "Multipath offload require two ports with valid gw\n");
				return;
			}
		}

		neigh_release(neigh0);
		neigh_release(neigh1);

		xsc_activate_lag(ldev, XSC_LAG_FLAG_MULTIPATH);
	}

	xsc_lag_set_port_affinity(ldev, MAC_0_1_LOGIC);
	mp->mfi = fi;
}

static void xsc_lag_fib_nexthop_event(struct xsc_lag *ldev,
				      unsigned long event,
				      struct fib_nh *fib_nh,
				      struct fib_info *fi)
{
	struct lag_mp *mp = &ldev->lag_mp;

	/* Check the nh event is related to the route */
	if (!mp->mfi || mp->mfi != fi)
		return;

	/* nh added/removed */
	if (event == FIB_EVENT_NH_DEL) {
#ifdef HAVE_FIB_NH_DEV
		int i = xsc_lag_dev_get_netdev_idx(ldev, fib_nh->fib_nh_dev);
#else
		int i = xsc_lag_dev_get_netdev_idx(ldev, fib_nh->nh_dev);
#endif
		if (i >= 0) {
			i = (i + 1) % 2 + 1; /* peer port */
			xsc_lag_set_port_affinity(ldev, i);
		}
	} else if (event == FIB_EVENT_NH_ADD &&
#ifdef HAVE_FIB_INFO_NH
		fib_info_num_path(fi) == 2) {
#else
		fi->fib_nhs == 2) {
#endif
		xsc_lag_set_port_affinity(ldev, MAC_0_1_LOGIC);
	}
}

static void xsc_lag_fib_update(struct work_struct *work)
{
	struct xsc_fib_event_work *fib_work =
		container_of(work, struct xsc_fib_event_work, work);
	struct xsc_lag *ldev = fib_work->ldev;
	struct fib_nh *fib_nh;

		/* Protect internal structures from changes */
	rtnl_lock();
	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE:
		fallthrough;
	case FIB_EVENT_ENTRY_APPEND:
		fallthrough;
	case FIB_EVENT_ENTRY_ADD:
		fallthrough;
	case FIB_EVENT_ENTRY_DEL:
		xsc_lag_fib_route_event(ldev, fib_work->event,
					fib_work->fen_info.fi);
		fib_info_put(fib_work->fen_info.fi);
		break;
	case FIB_EVENT_NH_ADD:
		fallthrough;
	case FIB_EVENT_NH_DEL:
		fib_nh = fib_work->fnh_info.fib_nh;
		xsc_lag_fib_nexthop_event(ldev,
					  fib_work->event,
					  fib_work->fnh_info.fib_nh,
					  fib_nh->nh_parent);
		fib_info_put(fib_work->fnh_info.fib_nh->nh_parent);
		break;
	}

	rtnl_unlock();
	kfree(fib_work);
}

struct xsc_fib_event_work *xsc_lag_init_fib_work(struct xsc_lag *ldev, unsigned long event)
{
	struct xsc_fib_event_work *fib_work =
		kzalloc(sizeof(struct xsc_fib_event_work), GFP_ATOMIC);
	if (WARN_ON(!fib_work))
		return NULL;

	INIT_WORK(&fib_work->work, xsc_lag_fib_update);
	fib_work->ldev = ldev;
	fib_work->event = event;

	return fib_work;
}

int xsc_lag_fib_event(struct notifier_block *nb,
		      unsigned long event,
		      void *ptr)
{
	struct lag_mp *mp = container_of(nb, struct lag_mp, fib_nb);
	struct xsc_lag *ldev = container_of(mp, struct xsc_lag, lag_mp);
	struct fib_notifier_info *info = ptr;
	struct xsc_fib_event_work *fib_work;
	struct fib_entry_notifier_info *fen_info;
	struct fib_nh_notifier_info *fnh_info;
	struct fib_info *fi;
	struct net_device *fib_net_dev;

	if (info->family != AF_INET)
		return NOTIFY_DONE;

	if (!xsc_lag_multipath_check_prereq(ldev))
		return NOTIFY_DONE;

	xsc_core_dbg(ldev->pf[0].xdev, "lag fib event=%ld\n", event);

	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
		fallthrough;
	case FIB_EVENT_ENTRY_APPEND:
		fallthrough;
	case FIB_EVENT_ENTRY_ADD:
		fallthrough;
	case FIB_EVENT_ENTRY_DEL:
		fen_info = container_of(info, struct fib_entry_notifier_info, info);
		fi = fen_info->fi;
#ifdef HAVE_FIB_INFO_NH
		fib_net_dev = fib_info_nh(fi, 0)->fib_nh_dev;
#elif defined HAVE_FIB_NH_DEV
		fib_net_dev = fi->fib_nh[0].fib_nh_dev;
#else
		fib_net_dev = fi->fib_nh[0].nh_dev;
#endif
		if (fib_net_dev != ldev->pf[0].netdev &&
		    fib_net_dev != ldev->pf[1].netdev) {
			return NOTIFY_DONE;
		}
		fib_work = xsc_lag_init_fib_work(ldev, event);
		if (!fib_work)
			return NOTIFY_DONE;
		fib_work->fen_info = *fen_info;
		/* Take reference on fib_info to prevent it from being
		 * freed while work is queued. Release it afterwards.
		 */
		fib_info_hold(fib_work->fen_info.fi);
		break;
	case FIB_EVENT_NH_ADD:
		fallthrough;
	case FIB_EVENT_NH_DEL:
		fnh_info = container_of(info, struct fib_nh_notifier_info,
					info);
		fib_work = xsc_lag_init_fib_work(ldev, event);
		if (!fib_work)
			return NOTIFY_DONE;
		fib_work->fnh_info = *fnh_info;
		fib_info_hold(fib_work->fnh_info.fib_nh->nh_parent);
		break;
	default:
		return NOTIFY_DONE;
	}

	queue_work(mp->wq, &fib_work->work);

	return NOTIFY_DONE;
}

int xsc_lag_mp_init(struct xsc_lag *ldev)
{
	struct lag_mp *mp = &ldev->lag_mp;
	int err;

	if (mp->fib_nb.notifier_call)
		return 0;

	mp->wq = create_singlethread_workqueue("xsc_lag_mp");
	if (!mp->wq)
		return -ENOMEM;

	mp->fib_nb.notifier_call = xsc_lag_fib_event;
	err = register_fib_notifier(&init_net, &mp->fib_nb,
				    xsc_lag_fib_event_flush, NULL);
	if (err) {
		destroy_workqueue(mp->wq);
		mp->fib_nb.notifier_call = NULL;
	}

	return err;
}

static void xsc_ldev_get(struct xsc_lag *ldev)
{
	kref_get(&ldev->ref);
}

int __xsc_lag_add_xdev(struct xsc_core_device *xdev)
{
	struct xsc_lag *ldev = NULL;
	struct xsc_core_device *tmp_xdev;
	int err;

	if (!xsc_core_is_pf(xdev))
		return 0;

	tmp_xdev = xsc_get_next_phys_dev(xdev);
	if (tmp_xdev)
		ldev = tmp_xdev->priv.lag;

	if (!ldev) {
		ldev = xsc_lag_dev_alloc();
		if (!ldev)
			return -EPIPE;
	} else {
		xsc_ldev_get(ldev);
	}

	xsc_lag_dev_add_xdev(ldev, xdev);
	ldev->lag_id = U16_MAX;

	if (!ldev->nb.notifier_call) {
		ldev->nb.notifier_call = xsc_lag_netdev_event;
#ifdef HAVE_NETDEVICE_NOTIFIER_RH
		err = register_netdevice_notifier_rh(&ldev->nb);
#else
		err = register_netdevice_notifier(&ldev->nb);
#endif
		if (err) {
			ldev->nb.notifier_call = NULL;
			xsc_core_err(xdev, "Failed to register LAG netdev notifier\n");
		}
	}

	err = xsc_lag_mp_init(ldev);
	if (err)
		xsc_core_err(xdev, "Failed to init multipath lag err=%d\n", err);
	return err;
}

void xsc_lag_add_xdev(struct xsc_core_device *xdev)
{
	int err;

	mutex_lock(&xsc_intf_mutex);
	err = __xsc_lag_add_xdev(xdev);
	if (err)
		xsc_core_dbg(xdev, "xsc lag add xdev failed: err=%d\n", err);
	mutex_unlock(&xsc_intf_mutex);
}

void xsc_lag_dev_add_pf(struct xsc_lag *ldev,
			struct xsc_core_device *xdev, struct net_device *netdev)
{
	unsigned int fn = PCI_FUNC(xdev->pdev->devfn) % XSC_MAX_PORTS;

	if (fn > XSC_MAX_PORTS)
		return;

	mutex_lock(&lag_mutex);
	ldev->pf[fn].netdev = netdev;
	ldev->tracker.netdev_state[fn].link_up = 0;
	ldev->tracker.netdev_state[fn].tx_enabled = 0;
	mutex_unlock(&lag_mutex);
}

void xsc_lag_update_trackers(struct xsc_lag *ldev)
{
	enum netdev_lag_tx_type tx_type = NETDEV_LAG_TX_TYPE_UNKNOWN;
	struct net_device *upper = NULL, *ndev;
	struct lag_tracker *tracker;
	struct bonding *bond;
	struct slave *slave;
	int i;

	rtnl_lock();
	tracker = &ldev->tracker;

	for (i = 0; i < XSC_MAX_PORTS; i++) {
		ndev = ldev->pf[i].netdev;
		if (!ndev)
			continue;

		if (ndev->reg_state != NETREG_REGISTERED)
			continue;

		if (!netif_is_bond_slave(ndev))
			continue;

		rcu_read_lock();
		slave = bond_slave_get_rcu(ndev);
		rcu_read_unlock();
		bond = bond_get_bond_by_slave(slave);

		tracker->netdev_state[i].link_up = bond_slave_is_up(slave);
		tracker->netdev_state[i].tx_enabled = bond_slave_can_tx(slave);

		if (bond_mode_uses_xmit_hash(bond)) {
			tx_type = NETDEV_LAG_TX_TYPE_HASH;
			tracker->hash_type = bond_lag_hash_type(bond);
			tracker->old_hash_type = tracker->hash_type;
		} else if (BOND_MODE(bond) == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
			tx_type = NETDEV_LAG_TX_TYPE_ACTIVEBACKUP;
		}

		upper = bond->dev;
	}

	if (!upper)
		goto out;

	tracker->tx_type = tx_type;

	if (xsc_lag_eval_bonding_conds(ldev, tracker, upper))
		queue_delayed_work(ldev->wq, &ldev->bond_work, 0);

out:
	rtnl_unlock();
}

void xsc_lag_add(struct xsc_core_device *xdev, struct net_device *netdev)
{
	struct xsc_lag *ldev = xdev->priv.lag;

	if (!ldev || !xsc_core_is_pf(xdev))
		return;

	xsc_ldev_get(ldev);
	xsc_lag_dev_add_pf(ldev, xdev, netdev);

	xsc_lag_update_trackers(ldev);
}
EXPORT_SYMBOL(xsc_lag_add);

void xsc_lag_dev_remove_pf(struct xsc_lag *ldev, struct xsc_core_device *xdev)
{
	int i;

	for (i = 0; i < XSC_MAX_PORTS; i++)
		if (ldev->pf[i].xdev == xdev)
			break;

	if (i == XSC_MAX_PORTS)
		return;

	mutex_lock(&lag_mutex);
	ldev->pf[i].netdev = NULL;
	mutex_unlock(&lag_mutex);
}

void xsc_lag_mp_cleanup(struct xsc_lag *ldev)
{
	struct lag_mp *mp = &ldev->lag_mp;

	if (!mp->fib_nb.notifier_call)
		return;
	unregister_fib_notifier(&init_net, &mp->fib_nb);
	destroy_workqueue(mp->wq);
	mp->fib_nb.notifier_call = NULL;
}

void xsc_lag_dev_free(struct kref *ref)
{
	struct xsc_lag *ldev = container_of(ref, struct xsc_lag, ref);

	if (ldev->nb.notifier_call)
#ifdef HAVE_NETDEVICE_NOTIFIER_RH
		unregister_netdevice_notifier_rh(&ldev->nb);
#else
		unregister_netdevice_notifier(&ldev->nb);
#endif

	xsc_lag_mp_cleanup(ldev);
	cancel_delayed_work_sync(&ldev->bond_work);
	destroy_workqueue(ldev->wq);
	ldev->nb.notifier_call = NULL;
	kfree(ldev);
}

void xsc_lag_dev_put(struct xsc_lag *ldev)
{
	kref_put(&ldev->ref, xsc_lag_dev_free);
}

void xsc_lag_remove(struct xsc_core_device *xdev)
{
	struct xsc_lag *ldev = xsc_lag_dev_get(xdev);

	if (!ldev)
		return;

	if (__xsc_lag_is_active(ldev))
		xsc_deactivate_lag(ldev, XSC_LAG_MODE_FLAGS);

	if (__xsc_bond_is_active(ldev))
		xsc_deactivate_lag(ldev, XSC_BOND_FLAG_KERNEL);

	xsc_lag_dev_remove_pf(ldev, xdev);
	xsc_lag_dev_put(ldev);
}
EXPORT_SYMBOL(xsc_lag_remove);

void xsc_lag_dev_remove_xdev(struct xsc_lag *ldev, struct xsc_core_device *xdev)
{
	int i;

	for (i = 0; i < XSC_MAX_PORTS; i++) {
		if (ldev->pf[i].xdev == xdev)
			break;
	}

	if (i == XSC_MAX_PORTS)
		return;

	mutex_lock(&lag_mutex);
	ldev->pf[i].xdev = NULL;
	xdev->priv.lag = NULL;
	mutex_unlock(&lag_mutex);
}

void __xsc_lag_remove_xdev(struct xsc_core_device *xdev)
{
	struct xsc_lag *ldev = xsc_lag_dev_get(xdev);

	if (!ldev)
		return;

	xsc_lag_dev_remove_xdev(ldev, xdev);
	xsc_lag_dev_put(ldev);
}

void xsc_lag_remove_xdev(struct xsc_core_device *xdev)
{
	mutex_lock(&xsc_intf_mutex);
	__xsc_lag_remove_xdev(xdev);
	mutex_unlock(&xsc_intf_mutex);
}

void xsc_lag_disable(struct xsc_core_device *xdev)
{
	struct xsc_lag *ldev;
	struct lag_tracker *tracker;

	mutex_lock(&xsc_intf_mutex);
	ldev = xsc_lag_dev_get(xdev);
	if (!ldev)
		goto unlock;

	if (!__xsc_lag_is_active(ldev))
		goto unlock;

	mutex_lock(&lag_mutex);
	tracker = &ldev->tracker;
	tracker->lag_disable = 1;
	mutex_unlock(&lag_mutex);

	xsc_do_bond(ldev);

unlock:
	mutex_unlock(&xsc_intf_mutex);
}

void xsc_lag_enable(struct xsc_core_device *xdev)
{
	struct xsc_lag *ldev;
	struct lag_tracker *tracker;

	mutex_lock(&xsc_intf_mutex);
	ldev = xsc_lag_dev_get(xdev);
	if (!ldev)
		goto unlock;

	if (__xsc_lag_is_active(ldev))
		goto unlock;

	mutex_lock(&lag_mutex);
	tracker = &ldev->tracker;
	tracker->lag_disable = 0;
	mutex_unlock(&lag_mutex);

	xsc_do_bond(ldev);

unlock:
	mutex_unlock(&xsc_intf_mutex);
}
