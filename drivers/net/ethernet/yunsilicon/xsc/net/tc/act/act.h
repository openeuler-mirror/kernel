/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __TC_ACT_H__
#define __TC_ACT_H__

#include <net/tc_act/tc_pedit.h>
#include <net/flow_offload.h>
#include <linux/netlink.h>
#include "pedit.h"
#include "common/xsc_eswitch.h"

struct xsc_flow_attr;

struct xsc_tc_act_parse_state {
	struct flow_action *flow_action;
	struct xsc_tc_flow *flow;
	struct netlink_ext_ack *extack;
	u32 actions;
	bool encap;
	bool decap;
	bool eth_push;
	bool eth_pop;
	bool ptype_host;
	const struct ip_tunnel_info *tun_info;
	int ifindexes[XSC_MAX_FLOW_FWD_VPORTS];
	int if_count;
#ifdef CONFIG_XSC_OFFLOAD_CT
	struct xsc_tc_ct_priv *ct_priv;
#endif
};

struct xsc_tc_act_branch_ctrl {
	enum flow_action_id act_id;
	u32 extval;
};

struct xsc_tc_act {
	bool (*can_offload)(struct xsc_tc_act_parse_state *parse_state,
			    const struct flow_action_entry *act,
			    int act_index,
			    struct xsc_flow_attr *attr);

	int (*parse_action)(struct xsc_tc_act_parse_state *parse_state,
			    const struct flow_action_entry *act,
			    struct xsc_adapter *priv,
			    struct xsc_flow_attr *attr);

	int (*post_parse)(struct xsc_tc_act_parse_state *parse_state,
			  struct xsc_adapter *priv,
			  struct xsc_flow_attr *attr);

	bool (*is_multi_table_act)(struct xsc_adapter *priv,
				   const struct flow_action_entry *act,
				   struct xsc_flow_attr *attr);

	bool (*is_missable)(const struct flow_action_entry *act);

#ifdef	CONFIG_XSC_OFFLOAD_OVS
	int (*offload_action)(struct xsc_adapter *priv,
			      struct flow_offload_action *fl_act,
			      struct flow_action_entry *act);

	int (*destroy_action)(struct xsc_adapter *priv,
			      struct flow_offload_action *fl_act);

	int (*stats_action)(struct xsc_adapter *priv,
			    struct flow_offload_action *fl_act);
#endif

	bool (*get_branch_ctrl)(const struct flow_action_entry *act,
				struct xsc_tc_act_branch_ctrl *cond_true,
				struct xsc_tc_act_branch_ctrl *cond_false);

	bool is_terminating_action;
};

struct xsc_tc_flow_action {
	unsigned int num_entries;
	struct flow_action_entry **entries;
};

extern struct xsc_tc_act xsc_tc_act_drop;
extern struct xsc_tc_act xsc_tc_act_accept;
extern struct xsc_tc_act xsc_tc_act_mark;
extern struct xsc_tc_act xsc_tc_act_goto;
extern struct xsc_tc_act xsc_tc_act_csum;
extern struct xsc_tc_act xsc_tc_act_pedit;
extern struct xsc_tc_act xsc_tc_act_vlan;
extern struct xsc_tc_act xsc_tc_act_vlan_mangle;
extern struct xsc_tc_act xsc_tc_act_mirred;
extern struct xsc_tc_act xsc_tc_act_redirect;
extern struct xsc_tc_act xsc_tc_act_ptype;
#ifdef CONFIG_XSC_OFFLOAD_TUN
extern struct xsc_tc_act xsc_tc_act_tun_encap;
extern struct xsc_tc_act xsc_tc_act_tun_decap;
#endif
#ifdef CONFIG_XSC_OFFLOAD_CT
extern struct xsc_tc_act xsc_tc_act_ct;
#endif
#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
extern struct xsc_tc_act xsc_tc_act_sample;
#endif
#ifdef CONFIG_XSC_OFFLOAD_METER
extern struct xsc_tc_act xsc_tc_act_police;
#endif
#ifdef CONFIG_XSC_OFFLOAD_OVS
extern struct xsc_tc_act xsc_tc_act_redirect_ingress;
#endif

struct xsc_tc_act *xsc_tc_act_get(enum flow_action_id act_id,
				  enum xsc_flow_namespace_type ns_type);

void xsc_tc_act_init_parse_state(struct xsc_tc_act_parse_state *parse_state,
				 struct xsc_tc_flow *flow,
				 struct flow_action *flow_action,
				 struct netlink_ext_ack *extack);

int xsc_tc_act_post_parse(struct xsc_tc_act_parse_state *parse_state,
			  struct flow_action *flow_action, int from, int to,
			  struct xsc_flow_attr *attr,
			  enum xsc_flow_namespace_type ns_type);

int xsc_tc_act_set_next_post_act(struct xsc_tc_flow *flow,
				 struct xsc_flow_attr *attr,
				 struct xsc_flow_attr *next_attr);

#endif /* __TC_ACT_H__ */
