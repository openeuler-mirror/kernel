// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/if_vlan.h>
#include "act.h"
#include "vlan.h"
#include "common/tc_priv.h"
#include "common/fs_cmd.h"

static int parse_tc_vlan_action(struct xsc_adapter *priv,
				const struct flow_action_entry *act,
				struct xsc_esw_flow_attr *attr,
				u32 *action, struct netlink_ext_ack *extack,
				struct xsc_tc_act_parse_state *parse_state)
{
	u8 vlan_idx = attr->total_vlan;

	if (vlan_idx >= XSC_FS_VLAN_DEPTH) {
		NL_SET_ERR_MSG_MOD(extack, "Total vlans used is greater than supported");
		netdev_err(priv->netdev, "Total vlans used is greater than supported\n");
		return -EOPNOTSUPP;
	}

	if (!xsc_eswitch_vlan_actions_supported(priv->xdev, vlan_idx)) {
		NL_SET_ERR_MSG_MOD(extack, "firmware vlan actions is not supported");
		netdev_err(priv->netdev, "firmware vlan actions is not supported\n");
		return -EOPNOTSUPP;
	}

	switch (act->id) {
	case FLOW_ACTION_VLAN_POP:
		if (*action & XSC_FLOW_CONTEXT_ACTION_VLAN_POP)
			*action |= XSC_FLOW_CONTEXT_ACTION_VLAN_POP_2;
		else
			*action |= XSC_FLOW_CONTEXT_ACTION_VLAN_POP;
		break;
	case FLOW_ACTION_VLAN_PUSH:
		attr->vlan_vid[vlan_idx] = act->vlan.vid;
		attr->vlan_prio[vlan_idx] = act->vlan.prio;
		attr->vlan_proto[vlan_idx] = act->vlan.proto;
		if (!attr->vlan_proto[vlan_idx])
			attr->vlan_proto[vlan_idx] = htons(ETH_P_8021Q);

		if (*action & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH)
			*action |= XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH_2;
		else
			*action |= XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH;
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unexpected action id for VLAN");
		netdev_err(priv->netdev, "Unexpected action id for VLAN\n");
		return -EINVAL;
	}

	attr->total_vlan = vlan_idx + 1;

	return 0;
}

int xsc_tc_act_vlan_add_push_action(struct xsc_adapter *priv,
				    struct xsc_flow_attr *attr,
				    struct net_device **out_dev,
				    struct netlink_ext_ack *extack)
{
	struct net_device *vlan_dev = *out_dev;
	struct flow_action_entry vlan_act = {
		.id = FLOW_ACTION_VLAN_PUSH,
		.vlan.vid = vlan_dev_vlan_id(vlan_dev),
		.vlan.proto = vlan_dev_vlan_proto(vlan_dev),
		.vlan.prio = 0,
	};
	int err;

	err = parse_tc_vlan_action(priv, &vlan_act, attr->esw_attr, &attr->action, extack, NULL);
	if (err)
		return err;

	rcu_read_lock();
	*out_dev = dev_get_by_index_rcu(dev_net(vlan_dev), dev_get_iflink(vlan_dev));
	rcu_read_unlock();
	if (!*out_dev)
		return -ENODEV;

	if (is_vlan_dev(*out_dev))
		err = xsc_tc_act_vlan_add_push_action(priv, attr, out_dev, extack);

	return err;
}

int xsc_tc_act_vlan_add_pop_action(struct xsc_adapter *priv, struct xsc_flow_attr *attr,
				   struct netlink_ext_ack *extack)
{
	struct flow_action_entry vlan_act = {
		.id = FLOW_ACTION_VLAN_POP,
	};
	int nest_level = 1, err = 0;

	nest_level = attr->parse_attr->filter_dev->lower_level -
						priv->netdev->lower_level;
	while (nest_level--) {
		err = parse_tc_vlan_action(priv, &vlan_act, attr->esw_attr, &attr->action,
					   extack, NULL);
		if (err)
			return err;
	}

	return err;
}

static int tc_act_parse_vlan(struct xsc_tc_act_parse_state *parse_state,
			     const struct flow_action_entry *act,
			     struct xsc_adapter *priv, struct xsc_flow_attr *attr)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	int err;

	if (act->id == FLOW_ACTION_VLAN_PUSH &&
	    (attr->action & XSC_FLOW_CONTEXT_ACTION_VLAN_POP)) {
		/* Replace vlan pop+push with vlan modify */
		attr->action &= ~XSC_FLOW_CONTEXT_ACTION_VLAN_POP;
		err = xsc_tc_act_vlan_add_rewrite_action(priv, XSC_FLOW_NAMESPACE_FDB, act,
							 attr->parse_attr, &attr->action,
							 parse_state->extack);
	} else {
		err = parse_tc_vlan_action(priv, act, esw_attr, &attr->action,
					   parse_state->extack, parse_state);
	}

	if (err)
		return err;

	esw_attr->split_count = esw_attr->out_count;
	parse_state->if_count = 0;

	return 0;
}

struct xsc_tc_act xsc_tc_act_vlan = {
	.parse_action = tc_act_parse_vlan,
};
