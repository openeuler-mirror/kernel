// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "act.h"
#include "common/tc_priv.h"
#include "common/xsc_eswitch.h"
#include "../../../pci/fs_chains.h"
#include "common/fs_cmd.h"
#include "common/tc_flow.h"

static int
validate_goto_chain(struct xsc_adapter *priv,
		    struct xsc_tc_flow *flow,
		    struct xsc_flow_attr *attr,
		    const struct flow_action_entry *act,
		    struct netlink_ext_ack *extack)
{
	bool ft_flow = xsc_is_ft_flow(flow);
	u32 dest_chain = act->chain_index;
	struct xsc_fs_chains *chains;
	struct xsc_eswitch *esw;
	u32 max_chain;

	esw = priv->xdev->priv.eswitch;
	chains = esw_chains(esw);
	max_chain = xsc_chains_get_chain_range(chains);

	if (ft_flow) {
		NL_SET_ERR_MSG_MOD(extack, "Goto action is not supported");
		netdev_err(priv->netdev, "Goto action is not supported\n");
		return -EOPNOTSUPP;
	}

	if (!xsc_chains_backwards_supported(chains) &&
	    dest_chain <= attr->chain) {
		NL_SET_ERR_MSG_MOD(extack, "Goto lower numbered chain isn't supported");
		netdev_err(priv->netdev, "Goto lower numbered chain isn't supported\n");
		return -EOPNOTSUPP;
	}

	if (dest_chain >= max_chain) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Requested destination chain is out of supported range");
		netdev_err(priv->netdev,
			   "Requested destination chain is out of supported range\n");
		return -EOPNOTSUPP;
	}

	if (attr->action & XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Goto chain is not allowed if action has reformat");
		netdev_err(priv->netdev,
			   "Goto chain is not allowed if action has reformat\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static bool
tc_act_can_offload_goto(struct xsc_tc_act_parse_state *parse_state,
			const struct flow_action_entry *act,
			int act_index,
			struct xsc_flow_attr *attr)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct xsc_tc_flow *flow = parse_state->flow;

	if (validate_goto_chain(flow->priv, flow, attr, act, extack))
		return false;

	return true;
}

static int
tc_act_parse_goto(struct xsc_tc_act_parse_state *parse_state,
		  const struct flow_action_entry *act,
		  struct xsc_adapter *priv,
		  struct xsc_flow_attr *attr)
{
	attr->action |= XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
	attr->dest_chain = act->chain_index;

	return 0;
}

static int
tc_act_post_parse_goto(struct xsc_tc_act_parse_state *parse_state,
		       struct xsc_adapter *priv,
		       struct xsc_flow_attr *attr)
{
	struct xsc_tc_flow_parse_attr *parse_attr = attr->parse_attr;
	struct netlink_ext_ack *extack = parse_state->extack;
	struct xsc_tc_flow *flow = parse_state->flow;

	if (!attr->dest_chain)
		return 0;

	if (parse_state->encap) {
		NL_SET_ERR_MSG_MOD(extack, "Encap with goto isn't supported");
		netdev_warn(priv->netdev, "Encap with goto isn't supported");
		return -EOPNOTSUPP;
	}

	if (!xsc_is_eswitch_flow(flow) && parse_attr->mirred_ifindex[0]) {
		NL_SET_ERR_MSG_MOD(extack, "Mirroring goto chain rules isn't supported");
		netdev_warn(priv->netdev, "Mirroring goto chain rules isn't supported");
		return -EOPNOTSUPP;
	}

	return 0;
}

struct xsc_tc_act xsc_tc_act_goto = {
	.can_offload = tc_act_can_offload_goto,
	.parse_action = tc_act_parse_goto,
	.post_parse = tc_act_post_parse_goto,
	.is_terminating_action = true,
};
