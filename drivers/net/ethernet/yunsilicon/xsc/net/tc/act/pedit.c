// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/if_vlan.h>
#include "act.h"
#include "pedit.h"
#include "common/mod_hdr.h"
#include "common/tc_flow.h"
#include "common/tc_priv.h"
#include "common/fs_cmd.h"

static int pedit_header_offsets[] = {
	[FLOW_ACT_MANGLE_HDR_TYPE_ETH] = offsetof(struct pedit_headers, eth),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP4] = offsetof(struct pedit_headers, ip4),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP6] = offsetof(struct pedit_headers, ip6),
	[FLOW_ACT_MANGLE_HDR_TYPE_TCP] = offsetof(struct pedit_headers, tcp),
	[FLOW_ACT_MANGLE_HDR_TYPE_UDP] = offsetof(struct pedit_headers, udp),
};

#define pedit_header(_ph, _htype) ((void *)(_ph) + pedit_header_offsets[_htype])

static int
set_pedit_val(u8 hdr_type, u32 mask, u32 val, u32 offset,
	      struct pedit_headers_action *hdrs,
	      struct netlink_ext_ack *extack)
{
	u32 *curr_pmask, *curr_pval;

	curr_pmask = (u32 *)(pedit_header(&hdrs->masks, hdr_type) + offset);
	curr_pval  = (u32 *)(pedit_header(&hdrs->vals, hdr_type) + offset);

	if (*curr_pmask & mask) { /* disallow acting twice on the same location */
		NL_SET_ERR_MSG_MOD(extack,
				   "curr_pmask and new mask same. Acting twice on same location");
		pr_err("curr_pmask and new mask same. Acting twice on same location\n");
		goto out_err;
	}

	*curr_pmask |= mask;
	*curr_pval  |= (val & mask);

	return 0;

out_err:
	return -EOPNOTSUPP;
}

int xsc_tc_act_pedit_parse_action(struct xsc_adapter *priv,
				  const struct flow_action_entry *act, int namespace,
				  struct pedit_headers_action *hdrs,
				  struct netlink_ext_ack *extack)
{
	u8 cmd = (act->id == FLOW_ACTION_MANGLE) ? TCA_PEDIT_KEY_EX_CMD_SET :
						   TCA_PEDIT_KEY_EX_CMD_ADD;
	u8 htype = act->mangle.htype;
	int err = -EOPNOTSUPP;
	u32 mask, val, offset;

	if (htype == FLOW_ACT_MANGLE_UNSPEC) {
		NL_SET_ERR_MSG_MOD(extack, "legacy pedit isn't offloaded");
		netdev_err(priv->netdev, "legacy pedit isn't offloaded\n");
		goto out_err;
	}

	if (!xsc_mod_hdr_max_actions(priv->xdev, namespace)) {
		NL_SET_ERR_MSG_MOD(extack, "The pedit offload action is not supported");
		netdev_err(priv->netdev, "The pedit offload action is not supported\n");
		goto out_err;
	}

	mask = act->mangle.mask;
	val = act->mangle.val;
	offset = act->mangle.offset;

	err = set_pedit_val(htype, ~mask, val, offset, &hdrs[cmd], extack);
	if (err)
		goto out_err;

	hdrs[cmd].pedits++;

	return 0;
out_err:
	return err;
}

static int
tc_act_parse_pedit(struct xsc_tc_act_parse_state *parse_state,
		   const struct flow_action_entry *act,
		   struct xsc_adapter *priv,
		   struct xsc_flow_attr *attr)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_tc_flow *flow = parse_state->flow;
	enum xsc_flow_namespace_type ns_type;
	int err;

	ns_type = xsc_get_flow_namespace_id(flow);

	err = xsc_tc_act_pedit_parse_action(flow->priv, act, ns_type, attr->parse_attr->hdrs,
					    parse_state->extack);
	if (err)
		return err;

	attr->action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;

	if (ns_type == XSC_FLOW_NAMESPACE_FDB) {
		esw_attr->split_count = esw_attr->out_count;
		parse_state->if_count = 0;
	}

	return 0;
}

struct xsc_tc_act xsc_tc_act_pedit = {
	.parse_action = tc_act_parse_pedit,
};
