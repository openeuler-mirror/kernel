// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "act.h"
#include "../post_act.h"
#include "common/tc_priv.h"
#include "common/xsc_core.h"
#include "common/fs_core.h"
#include "common/fs_cmd.h"
#include "common/tc_flow.h"

static struct xsc_tc_act *tc_acts_fdb[NUM_FLOW_ACTIONS] = {
	[FLOW_ACTION_ACCEPT] = &xsc_tc_act_accept,
	[FLOW_ACTION_DROP] = &xsc_tc_act_drop,
	[FLOW_ACTION_GOTO] = &xsc_tc_act_goto,
	[FLOW_ACTION_REDIRECT] = &xsc_tc_act_redirect,
	[FLOW_ACTION_VLAN_PUSH] = &xsc_tc_act_vlan,
	[FLOW_ACTION_VLAN_POP] = &xsc_tc_act_vlan,
	[FLOW_ACTION_VLAN_MANGLE] = &xsc_tc_act_vlan_mangle,
	[FLOW_ACTION_MANGLE] = &xsc_tc_act_pedit,
	[FLOW_ACTION_ADD] = &xsc_tc_act_pedit,
	[FLOW_ACTION_CSUM] = &xsc_tc_act_csum,
#ifdef HAVE_FLOW_ACTION_PTYPE
	[FLOW_ACTION_PTYPE] = &xsc_tc_act_ptype,
#endif
	[FLOW_ACTION_MIRRED] = &xsc_tc_act_mirred,
#ifdef CONFIG_XSC_OFFLOAD_TUN
	[FLOW_ACTION_TUNNEL_ENCAP] = &xsc_tc_act_tun_encap,
	[FLOW_ACTION_TUNNEL_DECAP] = &xsc_tc_act_tun_decap,
#endif
#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
	[FLOW_ACTION_SAMPLE] = &xsc_tc_act_sample,
#endif
#ifdef CONFIG_XSC_OFFLOAD_METER
	[FLOW_ACTION_POLICE] = &xsc_tc_act_police,
#endif
#ifdef CONFIG_XSC_OFFLOAD_CT
	[FLOW_ACTION_CT] = &xsc_tc_act_ct,
#endif
#ifdef CONFIG_XSC_OFFLOAD_OVS
	[FLOW_ACTION_REDIRECT_INGRESS] = &xsc_tc_act_redirect_ingress,
#endif
};

static struct xsc_tc_act *tc_acts_nic[NUM_FLOW_ACTIONS] = {
	[FLOW_ACTION_ACCEPT] = &xsc_tc_act_accept,
	[FLOW_ACTION_DROP] = &xsc_tc_act_drop,
	[FLOW_ACTION_MANGLE] = &xsc_tc_act_pedit,
	[FLOW_ACTION_ADD] = &xsc_tc_act_pedit,
	[FLOW_ACTION_CSUM] = &xsc_tc_act_csum,
};

/**
 * xsc_tc_act_get() - Get an action parser for an action id.
 * @act_id: Flow action id.
 * @ns_type: flow namespace type.
 */
struct xsc_tc_act *
xsc_tc_act_get(enum flow_action_id act_id, enum xsc_flow_namespace_type ns_type)
{
	struct xsc_tc_act **tc_acts;

	tc_acts = ns_type == XSC_FLOW_NAMESPACE_FDB ? tc_acts_fdb : tc_acts_nic;

	return tc_acts[act_id];
}

/**
 * xsc_tc_act_init_parse_state() - Init a new parse_state.
 * @parse_state: Parsing state.
 * @flow:        xsce tc flow being handled.
 * @flow_action: flow action to parse.
 * @extack:      to set an error msg.
 *
 * The same parse_state should be passed to action parsers
 * for tracking the current parsing state.
 */
void xsc_tc_act_init_parse_state(struct xsc_tc_act_parse_state *parse_state,
				 struct xsc_tc_flow *flow,
				 struct flow_action *flow_action,
				 struct netlink_ext_ack *extack)
{
	memset(parse_state, 0, sizeof(*parse_state));
	parse_state->flow = flow;
	parse_state->extack = extack;
	parse_state->flow_action = flow_action;
}

int xsc_tc_act_post_parse(struct xsc_tc_act_parse_state *parse_state,
			  struct flow_action *flow_action, int from, int to,
			  struct xsc_flow_attr *attr,
			  enum xsc_flow_namespace_type ns_type)
{
	struct flow_action_entry *act;
	struct xsc_tc_act *tc_act;
	struct xsc_adapter *priv;
	int err = 0, i;

	priv = parse_state->flow->priv;

	flow_action_for_each(i, act, flow_action) {
		if (i < from)
			continue;
		else if (i > to)
			break;

		tc_act = xsc_tc_act_get(act->id, ns_type);
		if (!tc_act || !tc_act->post_parse)
			continue;

		err = tc_act->post_parse(parse_state, priv, attr);
		if (err)
			goto out;
	}

out:
	return err;
}

int xsc_tc_act_set_next_post_act(struct xsc_tc_flow *flow,
				 struct xsc_flow_attr *attr,
				 struct xsc_flow_attr *next_attr)
{
	struct xsc_core_device *xdev = flow->priv->xdev;
	struct xsc_tc_mod_hdr_acts *mod_acts;
	int err;

	mod_acts = &attr->parse_attr->mod_hdr_acts;

	/* Set handle on current post act rule to next post act rule. */
	err = xsc_tc_post_act_set_handle(xdev, next_attr->post_act_handle, mod_acts);
	if (err) {
		xsc_core_warn(xdev, "Failed setting post action handle");
		return err;
	}

	attr->action |= XSC_FLOW_CONTEXT_ACTION_FWD_DEST |
			XSC_FLOW_CONTEXT_ACTION_MOD_HDR;

	return 0;
}
