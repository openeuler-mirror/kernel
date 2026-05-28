// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/if_vlan.h>
#include "act.h"
#include "vlan.h"
#include "common/tc_priv.h"
#include "common/fs_cmd.h"

struct pedit_headers_action;

int xsc_tc_act_vlan_add_rewrite_action(struct xsc_adapter *priv, int namespace,
				       const struct flow_action_entry *act,
				       struct xsc_tc_flow_parse_attr *parse_attr,
				       u32 *action, struct netlink_ext_ack *extack)
{
	u16 mask16 = VLAN_VID_MASK;
	u16 val16 = act->vlan.vid & VLAN_VID_MASK;
	const struct flow_action_entry pedit_act = {
		.id = FLOW_ACTION_MANGLE,
		.mangle.htype = FLOW_ACT_MANGLE_HDR_TYPE_ETH,
		.mangle.offset = offsetof(struct vlan_ethhdr, h_vlan_TCI),
		.mangle.mask = ~(u32)be16_to_cpu(*(__be16 *)&mask16),
		.mangle.val = (u32)be16_to_cpu(*(__be16 *)&val16),
	};
	u8 match_prio_mask, match_prio_val;
	void *headers_c, *headers_v;
	int err;

	headers_c = xsc_get_match_headers_criteria(*action, &parse_attr->spec);
	headers_v = xsc_get_match_headers_value(*action, &parse_attr->spec);

	match_prio_mask = XSC_GET(fte_match_set_lyr_2_4, headers_c, vlan_pcp);
	match_prio_val = XSC_GET(fte_match_set_lyr_2_4, headers_v, vlan_pcp);
	if (act->vlan.prio != (match_prio_val & match_prio_mask)) {
		NL_SET_ERR_MSG_MOD(extack, "Changing VLAN prio is not supported");
		netdev_err(priv->netdev, "Changing VLAN prio is not supported\n");
		return -EOPNOTSUPP;
	}

	err = xsc_tc_act_pedit_parse_action(priv, &pedit_act, namespace,
					    parse_attr->hdrs, extack);
	*action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;

	return err;
}

static int tc_act_parse_vlan_mangle(struct xsc_tc_act_parse_state *parse_state,
				    const struct flow_action_entry *act,
				    struct xsc_adapter *priv, struct xsc_flow_attr *attr)
{
	enum xsc_flow_namespace_type ns_type;
	int err;

	ns_type = xsc_get_flow_namespace_id(parse_state->flow);
	err = xsc_tc_act_vlan_add_rewrite_action(priv, ns_type, act, attr->parse_attr,
						 &attr->action, parse_state->extack);
	if (err)
		return err;

	if (ns_type == XSC_FLOW_NAMESPACE_FDB) {
		attr->esw_attr->split_count = attr->esw_attr->out_count;
		parse_state->if_count = 0;
	}

	return 0;
}

struct xsc_tc_act xsc_tc_act_vlan_mangle = {
	.parse_action = tc_act_parse_vlan_mangle,
};
