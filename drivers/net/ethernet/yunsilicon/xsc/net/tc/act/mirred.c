// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/if_macvlan.h>
#include <linux/if_vlan.h>
#include <net/bareudp.h>
#include <net/bonding.h>
#include "act.h"
#include "vlan.h"
#include "common/tc_priv.h"
#include "common/xsc_eswitch.h"
#include "../../rep/xsc_eth_rep.h"
#include "../../../pci/eswitch_offloads.h"
#include "common/fs_core.h"
#include "common/fs_cmd.h"
#include "common/tc_flow.h"

static bool
same_vf_reps(struct xsc_adapter *adapter, struct net_device *out_dev)
{
	return xsc_is_vf_rep(adapter->netdev) &&
	       adapter->netdev == out_dev;
}

static int
verify_uplink_forwarding(struct xsc_adapter *priv,
			 struct xsc_flow_attr *attr,
			 struct net_device *out_dev,
			 struct netlink_ext_ack *extack)
{
	struct xsc_rep_priv *rep_priv;

	/* Forwarding non encapsulated traffic between
	 * uplink ports is allowed only if
	 * termination_table_raw_traffic cap is set.
	 *
	 * Input vport was stored attr->in_rep.
	 * In LAG case, *priv* is the private data of
	 * uplink which may be not the input vport.
	 */
	rep_priv = xsc_rep_to_rep_priv(attr->esw_attr->in_rep);

	if (!(xsc_eswitch_uplink_rep(rep_priv->netdev) &&
	      xsc_eswitch_uplink_rep(out_dev)))
		return 0;

	if (out_dev != rep_priv->netdev) {
		NL_SET_ERR_MSG_MOD(extack,
				   "devices are not the same uplink, can't offload forwarding");
		netdev_err(priv->netdev,
			   "devices are not the same uplink, can't offload forwarding\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

static bool
is_duplicated_output_device(struct net_device *dev,
			    struct net_device *out_dev,
			    int *ifindexes, int if_count,
			    struct netlink_ext_ack *extack)
{
	int i;

	for (i = 0; i < if_count; i++) {
		if (ifindexes[i] == out_dev->ifindex) {
			NL_SET_ERR_MSG_MOD(extack, "can't duplicate output to same device");
			netdev_err(dev, "can't duplicate output to same device: %s\n",
				   out_dev->name);
			return true;
		}
	}

	return false;
}

static struct net_device *
get_fdb_out_dev(struct net_device *uplink_dev, struct net_device *out_dev, u8 *outdev_bond)
{
	struct net_device *fdb_out_dev = out_dev;
	struct net_device *uplink_upper;

	rcu_read_lock();
	uplink_upper = netdev_master_upper_dev_get_rcu(uplink_dev);
	if (uplink_upper && netif_is_lag_master(uplink_upper) &&
	    uplink_upper == out_dev) {
		fdb_out_dev = uplink_dev;
		*outdev_bond = 1;
	} else if (netif_is_lag_master(out_dev)) {
		fdb_out_dev = bond_option_active_slave_get_rcu(netdev_priv(out_dev));
		if (fdb_out_dev &&
		    (!is_xsc_eswitch_rep(fdb_out_dev) ||
		     !netdev_port_same_parent_id(fdb_out_dev, uplink_dev)))
			fdb_out_dev = NULL;
	}
	rcu_read_unlock();
	return fdb_out_dev;
}

static bool
tc_act_can_offload_mirred(struct xsc_tc_act_parse_state *parse_state,
			  const struct flow_action_entry *act,
			  int act_index,
			  struct xsc_flow_attr *attr)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct xsc_tc_flow *flow = parse_state->flow;
	struct xsc_tc_flow_parse_attr *parse_attr;
	struct net_device *out_dev = act->dev;
	struct xsc_adapter *priv = flow->priv;
	struct xsc_esw_flow_attr *esw_attr;

	parse_attr = attr->parse_attr;
	esw_attr = attr->esw_attr;

	if (!out_dev) {
		/* out_dev is NULL when filters with
		 * non-existing mirred device are replayed to
		 * the driver.
		 */
		goto fail;
	}

	if (xsc_is_ft_flow(flow) && out_dev == priv->netdev) {
		/* Ignore forward to self rules generated
		 * by adding both xsc devs to the flow table
		 * block on a normal nft offload setup.
		 */
		goto fail;
	}

	if (esw_attr->out_count >= XSC_MAX_FLOW_FWD_VPORTS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't support more output ports, can't offload forwarding");
		netdev_warn(priv->netdev,
			    "can't support more than %d output ports, can't offload forwarding\n",
			    esw_attr->out_count);
		return false;
	}

	if (parse_state->encap ||
	    netdev_port_same_parent_id(priv->netdev, out_dev) ||
	    netif_is_ovs_master(out_dev))
		return true;

	if (parse_attr->filter_dev != priv->netdev) {
		/* All xsc devices are called to configure
		 * high level device filters. Therefore, the
		 * *attempt* to  install a filter on invalid
		 * eswitch should not trigger an explicit error
		 */
		goto fail;
	}

	return true;

fail:

	NL_SET_ERR_MSG_MOD(extack, "devices are not on same switch HW, can't offload forwarding");
	pr_err_once("devices %s %s not on same switch HW, can't offload forwarding\n",
		    priv->netdev->name, out_dev->name);

	return false;
}

static int
parse_mirred_encap(struct xsc_tc_act_parse_state *parse_state,
		   const struct flow_action_entry *act,
		   struct xsc_flow_attr *attr)
{
#ifdef CONFIG_XSC_OFFLOAD_TUN
	struct xsc_tc_flow_parse_attr *parse_attr = attr->parse_attr;
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct net_device *out_dev = act->dev;

	parse_attr->mirred_ifindex[esw_attr->out_count] = out_dev->ifindex;
	parse_attr->tun_info[esw_attr->out_count] =
		xsc_dup_tun_info(parse_state->tun_info);

	if (!parse_attr->tun_info[esw_attr->out_count])
		return -ENOMEM;

	parse_state->encap = false;

	esw_attr->dests[esw_attr->out_count].flags |= XSC_ESW_DEST_ENCAP;
	esw_attr->out_count++;
	/* attr->dests[].vport is resolved when we handle encap */

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int
parse_mirred(struct xsc_tc_act_parse_state *parse_state,
	     const struct flow_action_entry *act,
	     struct xsc_adapter *priv,
	     struct xsc_flow_attr *attr)
{
	struct xsc_tc_flow_parse_attr *parse_attr = attr->parse_attr;
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct netlink_ext_ack *extack = parse_state->extack;
	struct xsc_rep_priv *rpriv = priv->ppriv;
	struct net_device *out_dev = act->dev;
	u8 outdev_is_bond = 0;
	struct net_device *uplink_dev;
	struct xsc_adapter *out_priv;
	struct xsc_eswitch *esw;
	int *ifindexes;
	int if_count;
	int err;

	esw = priv->xdev->priv.eswitch;
	uplink_dev = xsc_eswitch_uplink_get_proto_dev(esw, REP_ETH);
	ifindexes = parse_state->ifindexes;
	if_count = parse_state->if_count;

	if (is_duplicated_output_device(priv->netdev, out_dev, ifindexes, if_count, extack))
		return -EOPNOTSUPP;

	parse_state->ifindexes[if_count] = out_dev->ifindex;
	parse_state->if_count++;

	if (netif_is_macvlan(out_dev))
		out_dev = macvlan_dev_real_dev(out_dev);

	out_dev = get_fdb_out_dev(uplink_dev, out_dev, &outdev_is_bond);
	if (!out_dev)
		return -ENODEV;

	if (is_vlan_dev(out_dev)) {
		err = xsc_tc_act_vlan_add_push_action(priv, attr, &out_dev, extack);
		if (err)
			return err;
	}

	if (is_vlan_dev(parse_attr->filter_dev)) {
		err = xsc_tc_act_vlan_add_pop_action(priv, attr, extack);
		if (err)
			return err;
	}

	err = verify_uplink_forwarding(priv, attr, out_dev, extack);
	if (err)
		return err;

	if (!xsc_is_valid_eswitch_fwd_dev(priv, out_dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "devices are not on same switch HW, can't offload forwarding");
		netdev_err(priv->netdev,
			   "devices are not on same switch HW, can't offload forwarding\n");
		return -EOPNOTSUPP;
	}

	if (same_vf_reps(priv, out_dev)) {
		NL_SET_ERR_MSG_MOD(extack, "can't forward from a VF to itself");
		netdev_err(priv->netdev, "can't forward from a VF to itself\n");
		return -EOPNOTSUPP;
	}

	out_priv = netdev_priv(out_dev);
	rpriv = out_priv->ppriv;
	esw_attr->dests[esw_attr->out_count].vport_valid = true;
	esw_attr->dests[esw_attr->out_count].vport = rpriv->rep->vport;
	esw_attr->dests[esw_attr->out_count].xdev = out_priv->xdev;
	if (outdev_is_bond)
		esw_attr->dests[esw_attr->out_count].flags = XSC_ESW_DEST_LAG;

	esw_attr->out_count++;

	return 0;
}

static int
parse_mirred_ovs_master(struct xsc_tc_act_parse_state *parse_state,
			const struct flow_action_entry *act,
			struct xsc_adapter *priv,
			struct xsc_flow_attr *attr)
{
#ifdef CONFIG_XSC_OFFLOAD_OVS
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct net_device *out_dev = act->dev;
	int err;

	err = xsc_set_fwd_to_int_port_actions(priv, attr, out_dev->ifindex,
					      XSC_TC_INT_PORT_EGRESS,
					      &attr->action, esw_attr->out_count);
	if (err)
		return err;

	parse_state->if_count = 0;
	esw_attr->out_count++;

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int
tc_act_parse_mirred(struct xsc_tc_act_parse_state *parse_state,
		    const struct flow_action_entry *act,
		    struct xsc_adapter *priv,
		    struct xsc_flow_attr *attr)
{
	struct net_device *out_dev = act->dev;
	int err = -EOPNOTSUPP;

	if (parse_state->encap)
		err = parse_mirred_encap(parse_state, act, attr);
	else if (netdev_port_same_parent_id(priv->netdev, out_dev))
		err = parse_mirred(parse_state, act, priv, attr);
	else if (netif_is_ovs_master(out_dev))
		err = parse_mirred_ovs_master(parse_state, act, priv, attr);

	if (err) {
		netdev_err(priv->netdev,
			   "%s: Failed to parse mirred action from %s to %s, err=%d\n",
			   __func__, priv->netdev->name, out_dev->name, err);
		return err;
	}

	attr->action |= XSC_FLOW_CONTEXT_ACTION_FWD_DEST;

	return 0;
}

struct xsc_tc_act xsc_tc_act_mirred = {
	.can_offload = tc_act_can_offload_mirred,
	.parse_action = tc_act_parse_mirred,
	.is_terminating_action = false,
};

struct xsc_tc_act xsc_tc_act_redirect = {
	.can_offload = tc_act_can_offload_mirred,
	.parse_action = tc_act_parse_mirred,
	.is_terminating_action = true,
};
