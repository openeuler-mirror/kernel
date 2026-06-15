// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/tc_act/tc_csum.h>
#include "act.h"
#include "common/fs_cmd.h"
#include "common/tc_flow.h"
#include "common/tc_priv.h"

static bool csum_offload_supported(struct xsc_adapter *priv, u32 action,
				   u32 update_flags, struct netlink_ext_ack *extack)
{
	u32 prot_flags = TCA_CSUM_UPDATE_FLAG_IPV4HDR | TCA_CSUM_UPDATE_FLAG_TCP |
			 TCA_CSUM_UPDATE_FLAG_UDP;

	/*  The HW recalcs checksums only if re-writing headers */
	if (!(action & XSC_FLOW_CONTEXT_ACTION_MOD_HDR)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "TC csum action is only offloaded with pedit");
		netdev_warn(priv->netdev,
			    "TC csum action is only offloaded with pedit\n");
		return false;
	}

	if (update_flags & ~prot_flags) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't offload TC csum action for some header/s");
		netdev_warn(priv->netdev,
			    "can't offload TC csum action for some header/s - flags %#x\n",
			    update_flags);
		return false;
	}

	return true;
}

static bool tc_act_can_offload_csum(struct xsc_tc_act_parse_state *parse_state,
				    const struct flow_action_entry *act,
				    int act_index, struct xsc_flow_attr *attr)
{
	struct xsc_tc_flow *flow = parse_state->flow;

	return csum_offload_supported(flow->priv, attr->action,
				      act->csum_flags, parse_state->extack);
}

static int tc_act_parse_csum(struct xsc_tc_act_parse_state *parse_state,
			     const struct flow_action_entry *act,
			     struct xsc_adapter *priv, struct xsc_flow_attr *attr)
{
	return 0;
}

struct xsc_tc_act xsc_tc_act_csum = {
	.can_offload = tc_act_can_offload_csum,
	.parse_action = tc_act_parse_csum,
};
