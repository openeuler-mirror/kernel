// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <linux/etherdevice.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include "eswitch.h"
#include "common/tc_flow.h"
#include "devlink.h"
#include "eswitch_offloads.h"
#include "common/fs_cmd.h"
#include "fs_chains.h"
#include "common/xsc_lag.h"
#include "common/xsc_eswitch.h"

#define XSC_ESW_VPORT_TBL_SIZE 128
#define XSC_ESW_VPORT_TBL_NUM_GROUPS  4

#define XSC_ESW_FT_OFFLOADS_DROP_RULE (1)

static void __esw_offloads_unload_rep(struct xsc_eswitch *esw,
				      struct xsc_eswitch_rep *rep, u8 rep_type)
{
	if (atomic_read(&rep->rep_data[rep_type].state) == REP_LOADED) {
		atomic_set(&rep->rep_data[rep_type].state, REP_REGISTERED);
		esw->offloads.rep_ops[rep_type]->unload(rep);
	}
}

static void __unload_reps_all_vport(struct xsc_eswitch *esw, u8 rep_type)
{
	struct xsc_eswitch_rep *rep;
	unsigned long i;

	xsc_esw_for_all_reps(esw, i, rep)
		__esw_offloads_unload_rep(esw, rep, rep_type);
}

void xsc_eswitch_register_vport_reps(struct xsc_core_device *xdev,
				     const struct xsc_eswitch_rep_ops *ops,
				     u8 rep_type)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;
	struct xsc_eswitch_rep_data *rep_data;
	struct xsc_eswitch_rep *rep;
	unsigned long i;

	esw->offloads.rep_ops[rep_type] = ops;
	xsc_esw_for_all_reps(esw, i, rep) {
		rep->esw = esw;
		rep_data = &rep->rep_data[rep_type];
		atomic_set(&rep_data->state, REP_REGISTERED);
	}
}
EXPORT_SYMBOL(xsc_eswitch_register_vport_reps);

void xsc_eswitch_unregister_vport_reps(struct xsc_core_device *xdev, u8 rep_type)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;
	struct xsc_eswitch_rep *rep;
	struct xsc_eswitch_rep_data *rep_data;
	unsigned long i;

	if (esw->mode == XSC_ESWITCH_OFFLOADS)
		__unload_reps_all_vport(esw, rep_type);

	xsc_esw_for_all_reps(esw, i, rep) {
		rep_data = &rep->rep_data[rep_type];
		atomic_set(&rep_data->state, REP_UNREGISTERED);
	}
}
EXPORT_SYMBOL(xsc_eswitch_unregister_vport_reps);

static struct esw_vport_tbl_namespace xsc_esw_vport_tbl_mirror_ns = {
	.max_fte = XSC_ESW_VPORT_TBL_SIZE,
	.max_num_groups = XSC_ESW_VPORT_TBL_NUM_GROUPS,
	.flags = 0,
};

static int esw_offloads_steering_create_rep(struct xsc_eswitch *esw)
{
	struct xsc_create_esw_sterring_in in = {};
	struct xsc_create_esw_sterring_out out = {};
	struct xsc_core_device *xdev = esw->dev;
	int ret = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ESW_STERRING_CREATE);
	in.req.esw_rep_mode = XSC_REP_MODE_KERNEL;

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || (out.hdr.status != 0 && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)) {
		xsc_core_err(xdev, "failed to init esw offload steering, err =%d out.status= %u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

static int esw_offloads_steering_cleanup_rep(struct xsc_eswitch *esw)
{
	struct xsc_create_esw_sterring_in in = {};
	struct xsc_create_esw_sterring_out out = {};
	struct xsc_core_device *xdev = esw->dev;
	int ret = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ESW_STERRING_DESTROY);
	in.req.esw_rep_mode = XSC_REP_MODE_KERNEL;

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || (out.hdr.status != 0 && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)) {
		xsc_core_err(xdev, "failed to clean up esw offload steering, err =%d out.status= %u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

#define XSC_MAX_PEER_MISS_RULES (1024 + 2) /* max 2048 vf + pf + ecpf) */

/* There are two match-all miss flows, one for unicast dst mac and
 * one for multicast.
 */
#define XSC_ESW_BYPASS_MISS_FLOWS (XSC_MAX_PORTS * 2)

#define XSC_ESW_MISS_FLOWS (XSC_MAX_PORTS * 2)
#define UPLINK_REP_INDEX 0

#define XSC_ESW_VPORT_TBL_SIZE 128
#define XSC_ESW_VPORT_TBL_NUM_GROUPS  4

#define XSC_ESW_FT_OFFLOADS_DROP_RULE (1)

#define XSC_ESW_MAX_CTRL_EQS 4

static void
xsc_eswitch_set_rule_flow_source(struct xsc_eswitch *esw,
				 struct xsc_flow_spec *spec,
				 struct xsc_flow_attr *attr)
{
	struct xsc_ifc_flow_attr *match_attr = &spec->match_attr;
	u16 vport = attr->esw_attr->in_rep->vport;

#ifdef CONFIG_XSC_OFFLOAD_OVS
	if (attr->int_port) {
		spec->flow_context.flow_source = xsce_tc_int_port_get_flow_source(attr->int_port);

		return;
	}
#endif

	spec->flow_context.flow_source = (vport == XSC_VPORT_UPLINK) ?
					 XSC_FLOW_CONTEXT_FLOW_SOURCE_UPLINK :
					 XSC_FLOW_CONTEXT_FLOW_SOURCE_LOCAL_VPORT;

	XSC_SET(flow_attr, match_attr, vhca_id,
		(esw->dev->pcie_no << 8 | esw->dev->pf_id));

	XSC_SET(flow_attr, match_attr, vport, vport);
	if (vport > 0 && vport < XSC_VPORT_UPLINK) {
		XSC_SET(flow_attr, match_attr, egress, 1);
	} else {
		XSC_SET(flow_attr, match_attr, ingress, 1);
		attr->flags |= XSC_ATTR_FLAG_IN_PORT;
	}
}

static void xsc_eswitch_set_rule_source_port(struct xsc_eswitch *esw,
					     struct xsc_flow_spec *spec,
					     struct xsc_flow_attr *attr,
					     struct xsc_eswitch *src_esw,
					     u16 vport)
{
	u16 vhca_id = src_esw->dev->pf_id | src_esw->dev->pcie_no << 8;
	void *misc_value, *misc_mask;

	misc_value = XSC_ADDR_OF(fte_match_param, spec->match_value, misc);
	XSC_SET(fte_match_set_misc, misc_value, vport, vport);
	XSC_SET(fte_match_set_misc, misc_value, vhca_id, vhca_id);

	misc_mask = XSC_ADDR_OF(fte_match_param, spec->match_mask, misc);
	XSC_SET_TO_ONES(fte_match_set_misc, misc_mask, vport);
	XSC_SET_TO_ONES(fte_match_set_misc, misc_mask, vhca_id);

	spec->match_mask_enable |= XSC_MATCH_MISC_PARAMETERS;
}

static int esw_setup_ft_dest(struct xsc_flow_destination *dest,
			     struct xsc_flow_act *flow_act,
			     struct xsc_eswitch *esw,
			     struct xsc_flow_attr *attr, int i)
{
	flow_act->flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	dest[i].type = XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[i].ft = attr->dest_ft;

	return 0;
}

static void esw_setup_accept_dest(struct xsc_flow_destination *dest,
				  struct xsc_flow_act *flow_act,
				  struct xsc_fs_chains *chains, int i)
{
	if (xsc_chains_ignore_flow_level_supported(chains))
		flow_act->flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	dest[i].type = XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE;
	dest[i].ft = xsc_chains_get_tc_end_ft(chains);
}

static void
esw_setup_slow_path_dest(struct xsc_flow_destination *dest, struct xsc_flow_act *flow_act,
			 struct xsc_eswitch *esw, int i)
{
	if (XSC_ESW_FT_CAP(esw->esw_caps, XSC_ESW_CAP_IGNORE_FT_LEVEL))
		flow_act->flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	dest[i].type = XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[i].ft = xsc_eswitch_get_slow_fdb(esw);
}

static int
esw_setup_chain_dest(struct xsc_flow_destination *dest,
		     struct xsc_flow_act *flow_act,
		     struct xsc_fs_chains *chains,
		     u32 chain, u32 prio, u32 level,
		     int i)
{
	struct xsc_flow_table *ft;

	flow_act->flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	ft = xsc_chains_get_table(chains, chain, prio, level);
	if (IS_ERR(ft))
		return PTR_ERR(ft);

	dest[i].type = XSC_FLOW_DESTINATION_TYPE_FLOW_CHAIN;
	dest[i].ft = ft;
	return  0;
}

static void esw_put_dest_tables_loop(struct xsc_eswitch *esw, struct xsc_flow_attr *attr,
				     int from, int to)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_fs_chains *chains = esw_chains(esw);
	int i;

	for (i = from; i < to; i++)
		if (esw_attr->dests[i].flags & XSC_ESW_DEST_CHAIN_WITH_SRC_PORT_CHANGE)
			xsc_chains_put_table(chains, 0, 1, 0);
}

static bool
esw_is_chain_src_port_rewrite(struct xsc_eswitch *esw, struct xsc_esw_flow_attr *esw_attr)
{
	int i;

	for (i = esw_attr->split_count; i < esw_attr->out_count; i++)
		if (esw_attr->dests[i].flags & XSC_ESW_DEST_CHAIN_WITH_SRC_PORT_CHANGE)
			return true;
	return false;
}

static int
esw_setup_chain_src_port_rewrite(struct xsc_flow_destination *dest,
				 struct xsc_flow_act *flow_act,
				 struct xsc_eswitch *esw,
				 struct xsc_fs_chains *chains,
				 struct xsc_flow_attr *attr,
				 int *i)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	int err;

	if (!(attr->flags & XSC_ATTR_FLAG_SRC_REWRITE)) {
		err = -EOPNOTSUPP;
		goto err;
	}

	/* flow steering cannot handle more than one dest with the same ft
	 * in a single flow
	 */
	if (esw_attr->out_count - esw_attr->split_count > 1) {
		err = -EOPNOTSUPP;
		goto err;
	}

	err = esw_setup_chain_dest(dest, flow_act, chains, attr->dest_chain, 1, 0, *i);
	if (err)
		return err;

	if (esw_attr->dests[esw_attr->split_count].pkt_reformat) {
		flow_act->action |= XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT;
		flow_act->pkt_reformat = esw_attr->dests[esw_attr->split_count].pkt_reformat;
	}
	(*i)++;

	return 0;
err:
	esw_warn(esw->dev, "No support ops, attr_flags=0x%x, out_cnt=(%d, %d)\n",
		 attr->flags, esw_attr->out_count, esw_attr->split_count);
	return err;
}

static void esw_cleanup_chain_src_port_rewrite(struct xsc_eswitch *esw,
					       struct xsc_flow_attr *attr)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;

	esw_put_dest_tables_loop(esw, attr, esw_attr->split_count, esw_attr->out_count);
}

static void
esw_cleanup_chain_dest(struct xsc_fs_chains *chains, u32 chain, u32 prio, u32 level)
{
	xsc_chains_put_table(chains, chain, prio, level);
}

static void
esw_setup_dest_fwd_vport(struct xsc_flow_destination *dest, struct xsc_flow_act *flow_act,
			 struct xsc_eswitch *esw, struct xsc_esw_flow_attr *esw_attr,
			 int attr_idx, int dest_idx, bool pkt_reformat)
{
	dest[dest_idx].vport.num = esw_attr->dests[attr_idx].vport;

	if (esw_attr->dests[attr_idx].flags & XSC_ESW_DEST_LAG) {
		dest[dest_idx].type = XSC_FLOW_DESTINATION_TYPE_UPLINK;
		dest[dest_idx].vport.flags = XSC_FLOW_DEST_VPORT_LAG_ID;
		dest[dest_idx].vport.vhca_id = xsc_get_lag_id(esw_attr->dests[attr_idx].xdev);
	} else {
		dest[dest_idx].type = XSC_FLOW_DESTINATION_TYPE_VPORT;
		dest[dest_idx].vport.vhca_id = (esw_attr->dests[attr_idx].xdev->pf_id |
						esw_attr->dests[attr_idx].xdev->pcie_no << 8);
		dest[dest_idx].vport.flags |= XSC_FLOW_DEST_VPORT_VHCA_ID;
	}

	if (esw_attr->dests[attr_idx].flags & XSC_ESW_DEST_ENCAP_VALID) {
		if (pkt_reformat) {
			flow_act->action |= XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT;
			flow_act->pkt_reformat = esw_attr->dests[attr_idx].pkt_reformat;
		}
		dest[dest_idx].vport.flags |= XSC_FLOW_DEST_VPORT_REFORMAT_ID;
		dest[dest_idx].vport.pkt_reformat = esw_attr->dests[attr_idx].pkt_reformat;
	}
}

static void
esw_setup_vport_dest(struct xsc_flow_destination *dest, struct xsc_flow_act *flow_act,
		     struct xsc_eswitch *esw, struct xsc_esw_flow_attr *esw_attr,
		     int attr_idx, int dest_idx, bool pkt_reformat)
{
	esw_setup_dest_fwd_vport(dest, flow_act, esw, esw_attr,
				 attr_idx, dest_idx, pkt_reformat);
}

static int
esw_setup_vport_dests(struct xsc_flow_destination *dest, struct xsc_flow_act *flow_act,
		      struct xsc_eswitch *esw, struct xsc_esw_flow_attr *esw_attr,
		      int i)
{
	int j;

	for (j = esw_attr->split_count; j < esw_attr->out_count; j++, i++)
		esw_setup_vport_dest(dest, flow_act, esw, esw_attr, j, i, true);
	return i;
}

static bool
esw_src_port_rewrite_supported(struct xsc_eswitch *esw)
{
	return true;
}

static int
esw_setup_dests(struct xsc_flow_destination *dest,
		struct xsc_flow_act *flow_act,
		struct xsc_eswitch *esw,
		struct xsc_flow_attr *attr,
		struct xsc_flow_spec *spec,
		int *i)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_fs_chains *chains = esw_chains(esw);
	int err = 0;

	if (esw_src_port_rewrite_supported(esw))
		attr->flags |= XSC_ATTR_FLAG_SRC_REWRITE;

	if (attr->flags & XSC_ATTR_FLAG_SLOW_PATH) {
		esw_setup_slow_path_dest(dest, flow_act, esw, *i);
		(*i)++;
		goto out;
	}

	if (attr->flags & XSC_ATTR_FLAG_SAMPLE) {
#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
		esw_setup_sampler_dest(dest, flow_act, attr->sample_attr.sampler_id, *i);
		(*i)++;
#endif
	} else if (attr->flags & XSC_ATTR_FLAG_ACCEPT) {
		esw_setup_accept_dest(dest, flow_act, chains, *i);
		(*i)++;
	} else if (esw_is_chain_src_port_rewrite(esw, esw_attr)) {//for ovs bridge
		err = esw_setup_chain_src_port_rewrite(dest, flow_act, esw, chains, attr, i);
	} else {
		*i = esw_setup_vport_dests(dest, flow_act, esw, esw_attr, *i);

		if (attr->dest_ft) {
			err = esw_setup_ft_dest(dest, flow_act, esw, attr, *i);
			(*i)++;
		} else if (attr->dest_chain) {
			err = esw_setup_chain_dest(dest, flow_act, chains, attr->dest_chain,
						   1, 0, *i);
			XSC_SET(flow_attr, &spec->match_attr, dest_type,
				XSC_FLOW_DESTINATION_TYPE_FLOW_CHAIN);
			(*i)++;
		}
	}

out:
	if (err)
		esw_err(esw->dev,
			"Failed to setup dest, attr_flag=0x%x, count=(%d, %d), err=%d\n",
			attr->flags, esw_attr->split_count,
			esw_attr->out_count, err);
	return err;
}

static void
esw_cleanup_dests(struct xsc_eswitch *esw,
		  struct xsc_flow_attr *attr)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_fs_chains *chains = esw_chains(esw);

	if (!xsc_tc_attr_flags_skip(attr->flags)) {
		if (attr->dest_chain)
			esw_cleanup_chain_dest(chains, attr->dest_chain, 1, 0);
		else if (esw_is_chain_src_port_rewrite(esw, esw_attr))
			esw_cleanup_chain_src_port_rewrite(esw, attr);
	}
}

#ifdef CONFIG_XSC_OFFLOAD_METER
static void
esw_setup_meter(struct xsc_flow_attr *attr, struct xsc_flow_act *flow_act)
{
	struct xsce_flow_meter_handle *meter;

	meter = attr->meter_attr.meter;
	flow_act->exe_aso.type = attr->exe_aso_type;
	flow_act->exe_aso.object_id = meter->obj_id;
	flow_act->exe_aso.flow_meter.meter_idx = meter->idx;
	flow_act->exe_aso.flow_meter.init_color = XSC_FLOW_METER_COLOR_GREEN;
	/* use metadata reg 5 for packet color */
	flow_act->exe_aso.return_reg_id = 5;
}
#endif

struct xsc_flow_handle *xsc_eswitch_add_offloaded_rule(struct xsc_eswitch *esw,
						       struct xsc_flow_spec *spec,
						       struct xsc_flow_attr *attr)
{
	struct xsc_flow_act flow_act = { .flags = FLOW_ACT_NO_APPEND, };
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_fs_chains *chains = esw_chains(esw);
	struct xsc_flow_destination *dest;
	struct xsc_flow_handle *rule;
	struct xsc_flow_table *fdb;
	void *match_attr = &spec->match_attr;
	int i = 0;

	if (esw->mode != XSC_ESWITCH_OFFLOADS)
		return ERR_PTR(-EOPNOTSUPP);

	if (!xsc_eswitch_vlan_actions_supported(esw->dev, 1)) {
		esw_warn(esw->dev, "Not support more than one vlan match\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	dest = kcalloc(XSC_MAX_FLOW_FWD_VPORTS + 1, sizeof(*dest), GFP_KERNEL);
	if (!dest)
		return ERR_PTR(-ENOMEM);

	flow_act.action = attr->action;

	if (flow_act.action & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH) {
		flow_act.vlan[0].ethtype = ntohs(esw_attr->vlan_proto[0]);
		flow_act.vlan[0].vid = esw_attr->vlan_vid[0];
		flow_act.vlan[0].prio = esw_attr->vlan_prio[0];
		if (flow_act.action & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH_2) {
			flow_act.vlan[1].ethtype = ntohs(esw_attr->vlan_proto[1]);
			flow_act.vlan[1].vid = esw_attr->vlan_vid[1];
			flow_act.vlan[1].prio = esw_attr->vlan_prio[1];
		}
	}

	xsc_eswitch_set_rule_flow_source(esw, spec, attr);

	if (flow_act.action & XSC_FLOW_CONTEXT_ACTION_FWD_DEST) {
		int err;

		err = esw_setup_dests(dest, &flow_act, esw, attr, spec, &i);
		if (err) {
			rule = ERR_PTR(err);
			goto err_create_goto_table;
		}
	}

	if (esw_attr->decap_pkt_reformat)
		flow_act.pkt_reformat = esw_attr->decap_pkt_reformat;

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	if (flow_act.action & XSC_FLOW_CONTEXT_ACTION_COUNT) {
		dest[i].type = XSC_FLOW_DESTINATION_TYPE_COUNTER;
		dest[i].counter_id = xsc_fc_id(attr->counter);
		i++;
	}
#endif

	if (attr->outer_match_level != XSC_MATCH_NONE)
		spec->match_mask_enable |= XSC_MATCH_OUTER_HEADERS;
	if (attr->inner_match_level != XSC_MATCH_NONE)
		spec->match_mask_enable |= XSC_MATCH_INNER_HEADERS;

	if (flow_act.action & XSC_FLOW_CONTEXT_ACTION_MOD_HDR) {
		flow_act.modify_hdr = attr->modify_hdr;
		flow_act.mh = attr->mh;
	}

#ifdef CONFIG_XSC_OFFLOAD_METER
	if ((flow_act.action & XSC_FLOW_CONTEXT_ACTION_EXECUTE_ASO) &&
	    attr->exe_aso_type == XSC_EXE_ASO_FLOW_METER)
		esw_setup_meter(attr, &flow_act);
#endif

	if (attr->chain || attr->prio)
		fdb = xsc_chains_get_table(chains, attr->chain,
					   attr->prio, 0);
	else
		fdb = attr->ft;
	XSC_SET(flow_attr, match_attr, chain_no, attr->chain);
	XSC_SET(flow_attr, match_attr, priority, attr->prio);

	if (attr->flags & XSC_ATTR_FLAG_IN_PORT)
		xsc_eswitch_set_rule_source_port(esw, spec, attr,
						 esw_attr->in_xdev->priv.eswitch,
						 esw_attr->in_rep->vport);

	if (IS_ERR(fdb)) {
		rule = ERR_CAST(fdb);
		esw_err(esw->dev, "Failed to create ft, err=%ld\n", PTR_ERR(fdb));
		goto err_esw_get;
	}

	if (!i) {
		kfree(dest);
		dest = NULL;
	}

	rule = xsc_add_flow_rules(fdb, spec, &flow_act, dest, i);
	if (IS_ERR(rule)) {
		esw_err(esw->dev,
			"Failed to add flow rule, prio=(%d, %d), action=0x%x, err=%ld\n",
			attr->chain, attr->prio, flow_act.action, PTR_ERR(rule));
		goto err_add_rule;
	} else {
		atomic64_inc(&esw->offloads.num_flows);
	}

	kfree(dest);
	return rule;

err_add_rule:
	if (attr->chain || attr->prio)
		xsc_chains_put_table(chains, attr->chain, attr->prio, 0);
err_esw_get:
	esw_cleanup_dests(esw, attr);
err_create_goto_table:
	kfree(dest);
	return rule;
}
EXPORT_SYMBOL(xsc_eswitch_add_offloaded_rule);

struct xsc_flow_handle *xsc_eswitch_add_fwd_rule(struct xsc_eswitch *esw,
						 struct xsc_flow_spec *spec,
						 struct xsc_flow_attr *attr)
{
	struct xsc_flow_act flow_act = { .flags = FLOW_ACT_NO_APPEND, };
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_fs_chains *chains = esw_chains(esw);
	struct xsc_vport_tbl_attr fwd_attr;
	struct xsc_flow_destination *dest;
	struct xsc_flow_table *fast_fdb;
	struct xsc_flow_table *fwd_fdb = NULL;
	struct xsc_flow_handle *rule;
	int i, err = 0;

	dest = kcalloc(XSC_MAX_FLOW_FWD_VPORTS + 1, sizeof(*dest), GFP_KERNEL);
	if (!dest)
		return ERR_PTR(-ENOMEM);

	fast_fdb = xsc_chains_get_table(chains, attr->chain, attr->prio, 0);
	if (IS_ERR(fast_fdb)) {
		rule = ERR_CAST(fast_fdb);
		goto err_get_fast;
	}

	fwd_attr.chain = attr->chain;
	fwd_attr.prio = attr->prio;
	fwd_attr.vport = esw_attr->in_rep->vport;
	fwd_attr.vport_ns = &xsc_esw_vport_tbl_mirror_ns;
#ifdef CONFIG_XSC_OFFLOAD_METER
	fwd_fdb = xsc_esw_vporttbl_get(esw, &fwd_attr);
	if (IS_ERR(fwd_fdb)) {
		rule = ERR_CAST(fwd_fdb);
		goto err_get_fwd;
	}
#endif

	flow_act.action = XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
	for (i = 0; i < esw_attr->split_count; i++) {
		if (esw_attr->dests[i].flags & XSC_ESW_DEST_CHAIN_WITH_SRC_PORT_CHANGE)
			/* Source port rewrite (forward to ovs internal port or statck device) isn't
			 * supported in the rule of split action.
			 */
			err = -EOPNOTSUPP;
		else
			esw_setup_vport_dest(dest, &flow_act, esw, esw_attr, i, i, false);

		if (err) {
			esw_warn(esw->dev, "Not support dest forward flag=0x%x\n",
				 esw_attr->dests[i].flags);
			rule = ERR_PTR(err);
			goto err_chain_src_rewrite;
		}
	}
	dest[i].type = XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[i].ft = fwd_fdb;
	i++;

	xsc_eswitch_set_rule_source_port(esw, spec, attr,
					 esw_attr->in_xdev->priv.eswitch,
					 esw_attr->in_rep->vport);

	if (attr->outer_match_level != XSC_MATCH_NONE)
		spec->match_mask_enable |= XSC_MATCH_OUTER_HEADERS;

	flow_act.flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	rule = xsc_add_flow_rules(fast_fdb, spec, &flow_act, dest, i);

	if (IS_ERR(rule)) {
		i = esw_attr->split_count;
		goto err_chain_src_rewrite;
	}

	atomic64_inc(&esw->offloads.num_flows);

	kfree(dest);
	return rule;
err_chain_src_rewrite:
#ifdef CONFIG_XSC_OFFLOAD_METER
	xsc_esw_vporttbl_put(esw, &fwd_attr);
err_get_fwd:
#endif
	xsc_chains_put_table(chains, attr->chain, attr->prio, 0);
err_get_fast:
	kfree(dest);
	return rule;
}
EXPORT_SYMBOL(xsc_eswitch_add_fwd_rule);

static void __xsc_eswitch_del_rule(struct xsc_eswitch *esw,
				   struct xsc_flow_handle *rule,
				   struct xsc_flow_attr *attr, bool fwd_rule)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_fs_chains *chains = esw_chains(esw);
	bool split = (esw_attr->split_count > 0);
	struct xsc_vport_tbl_attr fwd_attr;
#ifdef CONFIG_XSC_OFFLOAD_METER
	int i;
#endif

	xsc_del_flow_rules(rule);

#ifdef CONFIG_XSC_OFFLOAD_METER
	if (!xsc_tc_attr_flags_skip(attr->flags)) {
		/* unref the term table */
		for (i = 0; i < XSC_MAX_FLOW_FWD_VPORTS; i++) {
			if (esw_attr->dests[i].termtbl)
				xsc_eswitch_termtbl_put(esw, esw_attr->dests[i].termtbl);
		}
	}
#endif

	atomic64_dec(&esw->offloads.num_flows);

	if (fwd_rule || split) {
		fwd_attr.chain = attr->chain;
		fwd_attr.prio = attr->prio;
		fwd_attr.vport = esw_attr->in_rep->vport;
		fwd_attr.vport_ns = &xsc_esw_vport_tbl_mirror_ns;
	}

	if (fwd_rule)  {
#ifdef CONFIG_XSC_OFFLOAD_METER
		xsc_esw_vporttbl_put(esw, &fwd_attr);
#endif
		xsc_chains_put_table(chains, attr->chain, attr->prio, 0);
	} else {
#ifdef CONFIG_XSC_OFFLOAD_METER
		if (split)
			xsc_esw_vporttbl_put(esw, &fwd_attr);
		else if (attr->chain || attr->prio)
#else
		if (attr->chain || attr->prio)
#endif
			xsc_chains_put_table(chains, attr->chain, attr->prio, 0);
		esw_cleanup_dests(esw, attr);
	}
}

void xsc_eswitch_del_offloaded_rule(struct xsc_eswitch *esw,
				    struct xsc_flow_handle *rule,
				    struct xsc_flow_attr *attr)
{
	__xsc_eswitch_del_rule(esw, rule, attr, false);
}
EXPORT_SYMBOL(xsc_eswitch_del_offloaded_rule);

void xsc_eswitch_del_fwd_rule(struct xsc_eswitch *esw,
			      struct xsc_flow_handle *rule,
			      struct xsc_flow_attr *attr)
{
	__xsc_eswitch_del_rule(esw, rule, attr, true);
}
EXPORT_SYMBOL(xsc_eswitch_del_fwd_rule);

static void xsc_esw_set_flow_group_source_port(struct xsc_eswitch *esw,
					       u32 *flow_group_in,
					       int match_params)
{
	void *match_mask = XSC_ADDR_OF(create_flow_group_in,
				       flow_group_in, match_mask);
	void *match_attr = XSC_ADDR_OF(create_flow_group_in,
				       flow_group_in, match_attr);

	XSC_SET(flow_attr, match_attr, match_mask_enable,
		XSC_MATCH_MISC_PARAMETERS | match_params);
	XSC_SET_FTE_MATCH_ATTR(&((struct xsc_ifc_flow_attr *)match_attr)->match_fields,
			       IN_PORT);

	XSC_SET_TO_ONES(fte_match_param, match_mask, misc.vport);
}

static int esw_add_fdb_miss_bypass_rule(struct xsc_eswitch *esw, bool add_peer)
{
	struct xsc_flow_act flow_act = {0};
	struct xsc_flow_destination dest = {};
	struct xsc_flow_handle *flow_rule = NULL;
	struct xsc_flow_spec *spec;
	int err = 0;
	struct xsc_eswitch *esw_peer = xsc_get_peer_esw(esw->dev);

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	spec->match_mask_enable = XSC_MATCH_MISC_PARAMETERS;
	XSC_SET_FTE_MATCH_ATTR(&spec->match_attr.match_fields, IN_PORT);

	XSC_SET_TO_ONES(fte_match_param, spec->match_mask, misc.vport);
	XSC_SET_TO_ONES(fte_match_param, spec->match_mask, misc.vhca_id);

	XSC_SET(fte_match_param, spec->match_value, misc.vport, XSC_VPORT_UPLINK);
	if (!add_peer || !esw_peer) {
		XSC_SET(fte_match_param, spec->match_value, misc.vhca_id,
			(esw->dev->pcie_no << 8 | esw->dev->pf_id));
		dest.vport.vhca_id = (esw->dev->pcie_no << 8 | esw->dev->pf_id);
	} else {
		XSC_SET(fte_match_param, spec->match_value, misc.vhca_id,
			(esw_peer->dev->pcie_no << 8 | esw_peer->dev->pf_id));
		dest.vport.vhca_id = (esw_peer->dev->pcie_no << 8 | esw_peer->dev->pf_id);
	}

	dest.type = XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE;
	dest.vport.num = XSC_VPORT_PF;

	flow_act.action = XSC_FLOW_CONTEXT_ACTION_FWD_DEST;

	flow_rule = add_to_miss_fg(xsc_eswitch_get_bypass_fdb(esw),
				   esw->fdb_table.offloads.miss_bypass_grp,
				   spec, &flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		esw_warn(esw->dev,
			 "Failed to add bypass miss flow rule on uplink, err=%d\n", err);
		goto add_uplink_miss_rule;
	}

	if (!add_peer || !esw_peer)
		esw->fdb_table.offloads.miss_rule_bypass_uplink = flow_rule;
	else
		esw->fdb_table.offloads.peer_miss_rule_bypass_uplink = flow_rule;

	XSC_SET(fte_match_param, spec->match_value, misc.vport, XSC_VPORT_PF);
	dest.vport.num = XSC_VPORT_UPLINK;

	flow_rule = add_to_miss_fg(xsc_eswitch_get_bypass_fdb(esw),
				   esw->fdb_table.offloads.miss_bypass_grp,
				   spec, &flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		esw_warn(esw->dev,
			 "Failed to add bypass miss flow rule, err=%d\n", err);
		goto add_miss_rule;
	}

	if (!add_peer || !esw_peer)
		esw->fdb_table.offloads.miss_rule_bypass = flow_rule;
	else
		esw->fdb_table.offloads.peer_miss_rule_bypass = flow_rule;

	kvfree(spec);

	return 0;

add_miss_rule:
	xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass_uplink);
add_uplink_miss_rule:
	kvfree(spec);
out:
	return err;
}

static int esw_create_miss_bypass_group(struct xsc_eswitch *esw,
					struct xsc_flow_table *fdb,
					u32 *flow_group_in, int *ix)
{
	int inlen = XSC_ST_SZ_BYTES(create_flow_group_in);
	struct xsc_flow_group *g;
	int match_mask_enable = 0;
	int err = 0;
	void *match_attr;
	struct xsc_eswitch *esw_peer = xsc_get_peer_esw(esw->dev);
	bool set_esw_local = false, set_esw_peer = false;

	memset(flow_group_in, 0, inlen);

	match_attr = XSC_ADDR_OF(create_flow_group_in, flow_group_in,
				 match_attr);
	XSC_SET(flow_attr, match_attr, start_flow_index, *ix);
	XSC_SET(flow_attr, match_attr, end_flow_index,
		*ix + XSC_ESW_BYPASS_MISS_FLOWS - 1);

	XSC_SET(flow_attr, match_attr, priority, 0xffff);
	XSC_SET(flow_attr, match_attr, dest_type,
		XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE);

	xsc_set_flow_attr_vport(esw, flow_group_in, XSC_VPORT_UPLINK);

	xsc_esw_set_flow_group_source_port(esw, flow_group_in, match_mask_enable);

	g = xsc_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to create miss flow group err(%d)\n", err);
		goto miss_err;
	}
	esw->fdb_table.offloads.miss_bypass_grp = g;

	if (unlikely(!esw_peer)) {
		err = esw_add_fdb_miss_bypass_rule(esw, false);
		if (err)
			goto miss_rule_err1;
	} else {
		set_esw_local = !esw_peer->fdb_table.offloads.peer_miss_rule_bypass_uplink &&
		    !esw_peer->fdb_table.offloads.peer_miss_rule_bypass;
		set_esw_peer = !esw_peer->fdb_table.offloads.miss_rule_bypass_uplink &&
		    !esw_peer->fdb_table.offloads.miss_rule_bypass;

		if (set_esw_local) {
			err = esw_add_fdb_miss_bypass_rule(esw, false);
			if (err)
				goto miss_rule_err1;
		}

		if (set_esw_peer) {
			err = esw_add_fdb_miss_bypass_rule(esw, true);
			if (err)
				goto miss_rule_err2;
		}
	}

	return 0;

miss_rule_err2:
	if (set_esw_local) {
		xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass_uplink);
		xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass);
	}
miss_rule_err1:
	xsc_destroy_flow_group(esw->fdb_table.offloads.miss_bypass_grp);
miss_err:
	return err;
}

#ifdef CONFIG_XSC_OFFLOAD_TUN
static int esw_add_fdb_miss_rule(struct xsc_eswitch *esw)
{
	struct xsc_flow_act flow_act = {0};
	struct xsc_flow_destination dest = {};
	struct xsc_flow_handle *flow_rule = NULL;
	struct xsc_flow_spec *spec;
	void *headers_c;
	void *headers_v;
	int err = 0;
	u8 *dmac_c;
	u8 *dmac_v;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	spec->match_mask_enable = XSC_MATCH_OUTER_HEADERS;
	headers_c = XSC_ADDR_OF(fte_match_param, spec->match_mask,
				outer_headers);
	dmac_c = XSC_ADDR_OF(fte_match_param, headers_c,
			     outer_headers.dst_mac);
	dmac_c[0] = 0x01;

	dest.type = XSC_FLOW_DESTINATION_TYPE_VPORT;
	dest.vport.num = esw->manager_vport;
	flow_act.action = XSC_FLOW_CONTEXT_ACTION_FWD_DEST;

	flow_rule = xsc_add_flow_rules(xsc_eswitch_get_slow_fdb(esw),
				       spec, &flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		esw_warn(esw->dev,  "FDB: Failed to add unicast miss flow rule err %d\n", err);
		goto out;
	}

	esw->fdb_table.offloads.miss_rule_uni = flow_rule;

	headers_v = XSC_ADDR_OF(fte_match_param, spec->match_value, outer_headers);
	dmac_v = XSC_ADDR_OF(fte_match_param, headers_v, outer_headers.dst_mac);
	dmac_v[0] = 0x01;
	flow_rule = xsc_add_flow_rules(xsc_eswitch_get_slow_fdb(esw),
				       spec, &flow_act, &dest, 1);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		esw_warn(esw->dev, "FDB: Failed to add multicast miss flow rule err %d\n", err);
		xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_uni);
		goto out;
	}

	esw->fdb_table.offloads.miss_rule_multi = flow_rule;

out:
	kvfree(spec);
	return err;
}

static int
esw_create_miss_group(struct xsc_eswitch *esw,
		      struct xsc_flow_table *fdb,
		      u32 *flow_group_in,
		      int *ix)
{
	int inlen = XSC_ST_SZ_BYTES(create_flow_group_in);
	struct xsc_flow_group *g;
	void *match_mask, *match_attr;
	int err = 0;
	u8 *dmac;

	memset(flow_group_in, 0, inlen);
	match_attr = XSC_ADDR_OF(create_flow_group_in, flow_group_in,
				 match_attr);

	XSC_SET(flow_attr, match_attr, match_mask_enable,
		XSC_MATCH_OUTER_HEADERS);
	match_mask = XSC_ADDR_OF(create_flow_group_in, flow_group_in,
				 match_mask);
	dmac = XSC_ADDR_OF(fte_match_param, match_mask,
			   outer_headers.dst_mac);
	dmac[0] = 0x01;

	XSC_SET(flow_attr, match_attr, start_flow_index, *ix);
	XSC_SET(flow_attr, match_attr, end_flow_index,
		*ix + XSC_ESW_MISS_FLOWS - 1);

	g = xsc_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(esw->dev, "Failed to create miss flow group err(%d)\n", err);
		goto miss_err;
	}
	esw->fdb_table.offloads.miss_grp = g;

	err = esw_add_fdb_miss_rule(esw);
	if (err)
		goto miss_rule_err;

	return 0;

miss_rule_err:
	xsc_destroy_flow_group(esw->fdb_table.offloads.miss_grp);
miss_err:
	return err;
}
#endif

#ifdef CONFIG_XSC_OFFLOAD_METER
static int esw_create_miss_meter_fdb_tables(struct xsc_eswitch *esw)
{
	int inlen = XSC_ST_SZ_BYTES(create_flow_group_in);
	struct xsc_flow_table_attr ft_attr = {};
	int num_vfs, table_size, err = 0;
	struct xsc_core_device *dev = esw->dev;
	struct xsc_flow_namespace *root_ns;
	struct xsc_flow_table *fdb = NULL;
	struct xsc_flow_group *g;
	void *match_mask;
	void *misc2;
	u32 *flow_group_in;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	num_vfs = xsc_core_max_vfs(esw->dev);
	root_ns = esw->fdb_table.offloads.ns;

	/* Create miss meter table and group */
	table_size = num_vfs + 1;
	if (xsc_core_is_ecpf(dev))
		table_size++;

	ft_attr.max_fte = table_size;
	ft_attr.prio = FDB_MISS_METER;

	fdb = xsc_create_flow_table(root_ns, &ft_attr);
	if (IS_ERR(fdb)) {
		err = PTR_ERR(fdb);
		esw_warn(dev, "Failed to create miss meter FDB Table err %d\n", err);
		goto meter_fdb_err;
	}

	esw->fdb_table.offloads.miss_meter_fdb = fdb;

	match_mask = XSC_ADDR_OF(create_flow_group_in, flow_group_in, match_mask);
	xsc_esw_set_flow_group_source_port(esw, flow_group_in, 0);
	XSC_SET(create_flow_group_in, flow_group_in, match_attr.start_flow_index, 0);
	XSC_SET(create_flow_group_in, flow_group_in,
		match_attr.end_flow_index, table_size - 1);

	g = xsc_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "Failed to create miss meter flow group err(%d)\n", err);
		goto meter_g_err;
	}
	esw->fdb_table.offloads.miss_meter_grp = g;

	/* Create post meter table and group - we only
	 * need 1 rule per rep to match on red color since
	 * green will continue to slow_fdb via miss on this
	 * table.
	 */

	ft_attr.level = 1;

	fdb = xsc_create_flow_table(root_ns, &ft_attr);
	if (IS_ERR(fdb)) {
		err = PTR_ERR(fdb);
		esw_warn(dev, "Failed to create post miss meter FDB Table err %d\n", err);
		goto post_meter_fdb_err;
	}
	esw->fdb_table.offloads.post_miss_meter_fdb = fdb;

	XSC_SET(create_flow_group_in, flow_group_in, match_attr.match_mask_enable,
		XSC_GET(create_flow_group_in, flow_group_in, match_mask_enable) |
		XSC_MATCH_MISC_PARAMETERS);
	misc2 = XSC_ADDR_OF(fte_match_param, match_mask, misc_2);
	XSC_SET(fte_match_set_misc2, misc2, metadata_reg_c_5, 0x3);

	/* Use the already masked source vport and add the
	 * meter color to the match criteria.
	 */
	g = xsc_create_flow_group(fdb, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "Failed to create post miss meter flow group err(%d)\n", err);
		goto post_meter_g_err;
	}
	esw->fdb_table.offloads.post_miss_meter_grp = g;

	kvfree(flow_group_in);
	return 0;

post_meter_g_err:
	xsc_destroy_flow_table(esw->fdb_table.offloads.post_miss_meter_fdb);

post_meter_fdb_err:
	xsc_destroy_flow_group(esw->fdb_table.offloads.miss_meter_grp);

meter_g_err:
	xsc_destroy_flow_table(esw->fdb_table.offloads.miss_meter_fdb);

meter_fdb_err:
	kvfree(flow_group_in);

	return err;
}

static void esw_destroy_miss_meter_fdb_tables(struct xsc_eswitch *esw)
{
	xsc_destroy_flow_group(esw->fdb_table.offloads.post_miss_meter_grp);
	xsc_destroy_flow_table(esw->fdb_table.offloads.post_miss_meter_fdb);

	xsc_destroy_flow_group(esw->fdb_table.offloads.miss_meter_grp);
	xsc_destroy_flow_table(esw->fdb_table.offloads.miss_meter_fdb);
}
#endif

static void esw_init_chains_offload_flags(struct xsc_eswitch *esw, u32 *flags)
{
	if (XSC_ESW_FT_CAP(esw->esw_caps, XSC_ESW_CAP_IGNORE_FT_LEVEL))
		*flags |= XSC_CHAINS_IGNORE_FLOW_LEVEL_SUPPORTED;

	*flags |= XSC_CHAINS_AND_PRIOS_SUPPORTED;

	*flags |= XSC_CHAINS_FT_TUNNEL_SUPPORTED;
}

static int esw_chains_create(struct xsc_eswitch *esw, struct xsc_flow_table *miss_fdb)
{
	struct xsc_core_device *dev = esw->dev;
#ifdef CONDIF_XSC_OFFLOAD_CT
	struct xsc_flow_table *nf_ft;
#endif
	struct xsc_flow_table *ft;
	struct xsc_chains_attr attr = {};
	struct xsc_fs_chains *chains;
	int err;

	esw_init_chains_offload_flags(esw, &attr.flags);
	attr.ns = XSC_FLOW_NAMESPACE_FDB;
	attr.max_grp_num = esw->esw_caps.large_group_num;
	attr.default_ft = miss_fdb;

	chains = xsc_chains_create(dev, &attr);
	if (IS_ERR(chains)) {
		err = PTR_ERR(chains);
		esw_warn(dev, "Failed to create fdb chains err(%d)\n", err);
		return err;
	}
	xsc_chains_print_info(chains);

	esw->fdb_table.offloads.esw_chains_priv = chains;

#ifdef CONDIF_XSC_OFFLOAD_CT
	/* Create tc_end_ft which is the always created ft chain */
	nf_ft = xsc_chains_get_table(chains, xsc_chains_get_nf_ft_chain(chains), 1, 0);
	if (IS_ERR(nf_ft)) {
		err = PTR_ERR(nf_ft);
		goto nf_ft_err;
	}
#endif

	/* Always open the root for fast path */
	ft = xsc_chains_get_table(chains, 0, 1, 0);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		goto level_0_err;
	}

#ifdef CONFIG_XSC_OFFLOAD_CT
	xsc_chains_set_end_ft(chains, nf_ft);
#endif

	return 0;

level_0_err:
#ifdef CONFIG_XSC_OFFLOAD_CT
	xsc_chains_put_table(chains, xsc_chains_get_nf_ft_chain(chains), 1, 0);
nf_ft_err:
#endif
	xsc_chains_destroy(chains);
	esw->fdb_table.offloads.esw_chains_priv = NULL;

	return err;
}

static void esw_chains_destroy(struct xsc_eswitch *esw, struct xsc_fs_chains *chains)
{
	xsc_chains_put_table(chains, 0, 1, 0);
#ifdef CONFIG_XSC_OFFLOAD_CT
	xsc_chains_put_table(chains, xsc_chains_get_nf_ft_chain(chains), 1, 0);
#endif
	xsc_chains_destroy(chains);
}

static int esw_create_offloads_fdb_tables(struct xsc_eswitch *esw)
{
	int inlen = XSC_ST_SZ_BYTES(create_flow_group_in);
	struct xsc_flow_table_attr ft_attr = {};
	struct xsc_core_device *dev = esw->dev;
	struct xsc_flow_namespace *root_ns;
	struct xsc_flow_table *fdb = NULL;
	struct xsc_flow_table *bypass_fdb = NULL;
	int ix = 0, err = 0;
	u32 *flow_group_in;
#ifdef CONFIG_XSC_OFFLOAD_METER
	bool miss_meter_supp = 0;
#endif
#if defined(CONFIG_XSC_OFFLOAD_TUN) || defined(CONFIG_XSC_OFFLOAD_METER)
	struct xsc_flow_table *miss_fdb;
#endif

	esw_debug(dev, "Create offloads FDB Tables\n");

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	root_ns = xsc_get_flow_namespace(dev, XSC_FLOW_NAMESPACE_FDB);
	if (!root_ns) {
		esw_warn(dev, "Failed to get FDB flow namespace\n");
		err = -EOPNOTSUPP;
		goto ns_err;
	}
	esw->fdb_table.offloads.ns = root_ns;
	err = xsc_flow_namespace_set_mode(root_ns, XSC_FLOW_STEERING_MODE_SMFS);
	if (err) {
		esw_warn(dev, "Failed to set FDB namespace steering mode\n");
		goto ns_err;
	}

	ft_attr.flags = XSC_FLOW_TABLE_TUNNEL_EN_DECAP;
	ft_attr.max_fte = XSC_MAX_PORTS * XSC_BY_PASS_NUM_PRIOS +
			  XSC_ESW_BYPASS_MISS_FLOWS;
	ft_attr.prio = FDB_BYPASS_PATH;

	bypass_fdb = xsc_create_flow_table(root_ns, &ft_attr);
	if (IS_ERR(fdb)) {
		err = PTR_ERR(fdb);
		esw_warn(dev, "Failed to create bypass path FDB Table err %d\n", err);
		goto bypass_fdb_err;
	}
	esw->fdb_table.offloads.bypass_fdb = bypass_fdb;

	ix += XSC_MAX_PORTS * XSC_BY_PASS_NUM_PRIOS;
	err = esw_create_miss_bypass_group(esw, bypass_fdb, flow_group_in, &ix);
	if (err)
		goto bypass_miss_err;

#ifdef CONFIG_XSC_OFFLOAD_TUN
	/* To be strictly correct:
	 *	XSC_MAX_PORTS * (esw->total_vports * MAX_SQ_NVPORTS + MAX_PF_SQ)
	 * should be:
	 *	esw->total_vports * MAX_SQ_NVPORTS + MAX_PF_SQ +
	 *	peer_esw->total_vports * MAX_SQ_NVPORTS + MAX_PF_SQ
	 * but as the peer device might not be in switchdev mode it's not
	 * possible. We use the fact that by default FW sets max vfs and max sfs
	 * to the same value on both devices. If it needs to be changed in the future note
	 * the peer miss group should also be created based on the number of
	 * total vports of the peer (currently is also uses esw->total_vports).
	 */

	/* create the slow path fdb with encap set, so further table instances
	 * can be created at run time while VFs are probed if the FW allows that.
	 */

	ft_attr.flags = (XSC_FLOW_TABLE_TUNNEL_EN_REFORMAT |
		  XSC_FLOW_TABLE_TUNNEL_EN_DECAP);
	ft_attr.max_fte = XSC_MAX_PORTS * esw->total_vports +
		esw->total_vports + XSC_MAX_PEER_MISS_RULES * (XSC_MAX_PORTS - 1) +
		XSC_ESW_MISS_FLOWS;
	ft_attr.prio = FDB_SLOW_PATH;

	fdb = xsc_create_flow_table(root_ns, &ft_attr);
	if (IS_ERR(fdb)) {
		err = PTR_ERR(fdb);
		esw_warn(dev, "Failed to create slow path FDB Table err %d\n", err);
		goto slow_fdb_err;
	}
	esw->fdb_table.offloads.slow_fdb = fdb;
	miss_fdb = esw->fdb_table.offloads.slow_fdb;
#endif

#ifdef CONFIG_XSC_OFFLOAD_METER
	miss_meter_supp = XSC_ESW_FT_CAP(esw->esw_caps, XSC_ESW_CAP_FT_METER_MISS);
	if (miss_meter_supp) {
		err = esw_create_miss_meter_fdb_tables(esw);
		if (err) {
			esw_warn(dev, "Failed to open miss meter fdb err(%d)\n", err);
			goto miss_meter_fdb_err;
		}

		miss_fdb = esw->fdb_table.offloads.miss_meter_fdb;
	}
#endif
	/* Create empty TC-miss managed table. This allows plugging in following
	 * priorities without directly exposing their level 0 table to
	 * eswitch_offloads and passing it as miss_fdb to following call to
	 * esw_chains_create().
	 */
	memset(&ft_attr, 0, sizeof(ft_attr));
	ft_attr.prio = FDB_TC_MISS;
	esw->fdb_table.offloads.tc_miss_table = xsc_create_flow_table(root_ns, &ft_attr);
	if (IS_ERR(esw->fdb_table.offloads.tc_miss_table)) {
		err = PTR_ERR(esw->fdb_table.offloads.tc_miss_table);
		esw_warn(dev, "Failed to create TC miss FDB Table err %d\n", err);
		goto tc_miss_table_err;
	}

	err = esw_chains_create(esw, esw->fdb_table.offloads.tc_miss_table);
	if (err) {
		esw_warn(dev, "Failed to open fdb chains err(%d)\n", err);
		goto fdb_chains_err;
	}

	kvfree(flow_group_in);
	return 0;

fdb_chains_err:
	xsc_destroy_flow_table(esw->fdb_table.offloads.tc_miss_table);
tc_miss_table_err:
#ifdef CONFIG_XSC_OFFLOAD_METER
	if (miss_meter_supp)
		esw_destroy_miss_meter_fdb_tables(esw);
#endif

#if defined(CONFIG_XSC_OFFLOAD_TUN) && defined(CONFIG_XSC_OFFLOAD_METER)
miss_meter_fdb_err:
	xsc_destroy_flow_table(xsc_eswitch_get_slow_fdb(esw));
#endif

#ifdef CONFIG_XSC_OFFLOAD_TUN
slow_fdb_err:
#endif
	xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass);
	xsc_destroy_flow_group(esw->fdb_table.offloads.miss_bypass_grp);
bypass_miss_err:
	xsc_destroy_flow_table(xsc_eswitch_get_bypass_fdb(esw));
bypass_fdb_err:
	/* Holds true only as long as DMFS is the default */
	xsc_flow_namespace_set_mode(root_ns, XSC_FLOW_STEERING_MODE_SMFS);
ns_err:
	kvfree(flow_group_in);
	return err;
}

static void esw_destroy_offloads_fdb_tables(struct xsc_eswitch *esw)
{
	struct xsc_eswitch *esw_peer = xsc_get_peer_esw(esw->dev);

	esw_debug(esw->dev, "Destroy offloads FDB Tables\n");

	xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_multi);
	xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_uni);
	xsc_destroy_flow_group(esw->fdb_table.offloads.send_to_vport_grp);
	if (esw->fdb_table.offloads.send_to_vport_meta_grp)
		xsc_destroy_flow_group(esw->fdb_table.offloads.send_to_vport_meta_grp);
	if (esw->esw_caps.merged_eswitch)
		xsc_destroy_flow_group(esw->fdb_table.offloads.peer_miss_grp);
	xsc_destroy_flow_group(esw->fdb_table.offloads.miss_grp);

	esw_chains_destroy(esw, esw_chains(esw));

#ifdef CONFIG_XSC_OFFLOAD_METER
	esw_destroy_miss_meter_fdb_tables(esw);
#endif

	xsc_destroy_flow_table(esw->fdb_table.offloads.tc_miss_table);
	xsc_destroy_flow_table(xsc_eswitch_get_slow_fdb(esw));

	if (likely(esw_peer && esw_peer->mode != XSC_ESWITCH_OFFLOADS)) {
		xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass);
		xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass_uplink);
		xsc_del_flow_rules(esw->fdb_table.offloads.peer_miss_rule_bypass);
		xsc_del_flow_rules(esw->fdb_table.offloads.peer_miss_rule_bypass_uplink);
		xsc_del_flow_rules(esw_peer->fdb_table.offloads.miss_rule_bypass);
		xsc_del_flow_rules(esw_peer->fdb_table.offloads.miss_rule_bypass_uplink);
		xsc_del_flow_rules(esw_peer->fdb_table.offloads.peer_miss_rule_bypass);
		xsc_del_flow_rules(esw_peer->fdb_table.offloads.peer_miss_rule_bypass_uplink);
		esw->fdb_table.offloads.miss_rule_bypass = NULL;
		esw->fdb_table.offloads.miss_rule_bypass_uplink = NULL;
		esw->fdb_table.offloads.peer_miss_rule_bypass = NULL;
		esw->fdb_table.offloads.peer_miss_rule_bypass_uplink = NULL;
		esw_peer->fdb_table.offloads.miss_rule_bypass = NULL;
		esw_peer->fdb_table.offloads.miss_rule_bypass_uplink = NULL;
		esw_peer->fdb_table.offloads.peer_miss_rule_bypass = NULL;
		esw_peer->fdb_table.offloads.peer_miss_rule_bypass_uplink = NULL;

		xsc_destroy_flow_group(esw->fdb_table.offloads.miss_bypass_grp);
		xsc_destroy_flow_group(esw_peer->fdb_table.offloads.miss_bypass_grp);
		esw->fdb_table.offloads.miss_bypass_grp = NULL;
		esw_peer->fdb_table.offloads.miss_bypass_grp = NULL;

		xsc_destroy_flow_table(esw->fdb_table.offloads.bypass_fdb);
		xsc_destroy_flow_table(esw_peer->fdb_table.offloads.bypass_fdb);
		esw->fdb_table.offloads.bypass_fdb = NULL;
		esw_peer->fdb_table.offloads.bypass_fdb = NULL;

		xsc_flow_namespace_set_mode(esw->fdb_table.offloads.ns,
					    XSC_FLOW_STEERING_MODE_SMFS);
		if (esw_peer->fdb_table.offloads.ns)
			xsc_flow_namespace_set_mode(esw_peer->fdb_table.offloads.ns,
						    XSC_FLOW_STEERING_MODE_SMFS);
	} else if (!esw_peer) {
		xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass);
		xsc_del_flow_rules(esw->fdb_table.offloads.miss_rule_bypass_uplink);
		esw->fdb_table.offloads.miss_rule_bypass = NULL;
		esw->fdb_table.offloads.miss_rule_bypass_uplink = NULL;

		xsc_destroy_flow_group(esw->fdb_table.offloads.miss_bypass_grp);
		esw->fdb_table.offloads.miss_bypass_grp = NULL;

		xsc_destroy_flow_table(esw->fdb_table.offloads.bypass_fdb);
		esw->fdb_table.offloads.bypass_fdb = NULL;

		xsc_flow_namespace_set_mode(esw->fdb_table.offloads.ns,
					    XSC_FLOW_STEERING_MODE_SMFS);
	}

	atomic64_set(&esw->user_count, 0);
}

static int esw_offloads_steering_init(struct xsc_eswitch *esw)
{
	int err;

	err = esw_offloads_steering_create_rep(esw);
	if (err)
		goto create_rep_err;

	memset(&esw->fdb_table.offloads, 0, sizeof(struct offloads_fdb));
	mutex_init(&esw->fdb_table.offloads.vports.lock);
	hash_init(esw->fdb_table.offloads.vports.table);
	atomic64_set(&esw->user_count, 0);

	err = xsc_flow_grp_idx_range_init(esw->dev, esw->esw_caps.pct_start,
					  esw->esw_caps.pct_end);
	if (err)
		goto create_fdb_err;

	err = esw_create_offloads_fdb_tables(esw);
	if (err)
		goto create_fdb_err;

	return 0;

create_fdb_err:
	mutex_destroy(&esw->fdb_table.offloads.vports.lock);
	esw_offloads_steering_cleanup_rep(esw);
create_rep_err:
	return err;
}

static int esw_offloads_steering_cleanup(struct xsc_eswitch *esw)
{
	esw_destroy_offloads_fdb_tables(esw);
	esw_offloads_steering_cleanup_rep(esw);
	mutex_destroy(&esw->fdb_table.offloads.vports.lock);

	return 0;
}

static struct xsc_eswitch_rep *xsc_eswitch_get_rep(struct xsc_eswitch *esw,
						   u16 vport_num)
{
	int idx = xsc_eswitch_vport_num_to_index(esw, vport_num);

	WARN_ON(idx > esw->total_vports - 1);
	return &esw->offloads.vport_reps[idx];
}

void *xsc_eswitch_get_uplink_priv(struct xsc_eswitch *esw, u8 rep_type)
{
	struct xsc_eswitch_rep *rep;

	rep = xsc_eswitch_get_rep(esw, XSC_VPORT_UPLINK);
	return rep->rep_data[rep_type].priv;
}
EXPORT_SYMBOL(xsc_eswitch_get_uplink_priv);

void *xsc_eswitch_get_proto_dev(struct xsc_eswitch *esw,
				u16 vport, u8 rep_type)
{
	struct xsc_eswitch_rep *rep;

	rep = xsc_eswitch_get_rep(esw, vport);

	if (atomic_read(&rep->rep_data[rep_type].state) == REP_LOADED &&
	    esw->offloads.rep_ops[rep_type]->get_proto_dev)
		return esw->offloads.rep_ops[rep_type]->get_proto_dev(rep);
	return NULL;
}
EXPORT_SYMBOL(xsc_eswitch_get_proto_dev);

void *xsc_eswitch_uplink_get_proto_dev(struct xsc_eswitch *esw, u8 rep_type)
{
	return xsc_eswitch_get_proto_dev(esw, XSC_VPORT_UPLINK, rep_type);
}
EXPORT_SYMBOL(xsc_eswitch_uplink_get_proto_dev);

void esw_offloads_unload_rep(struct xsc_eswitch *esw, u16 vport_num)
{
	struct xsc_eswitch_rep *rep;
	int rep_type;

	if (esw->mode != XSC_ESWITCH_OFFLOADS ||
	    esw->offloads.rep_mode != XSC_REP_MODE_KERNEL)
		return;

	rep = xsc_eswitch_get_rep(esw, vport_num);
	for (rep_type = NUM_REP_TYPES - 1; rep_type >= 0; rep_type--)
		__esw_offloads_unload_rep(esw, rep, rep_type);
}

static void xsc_esw_offloads_rep_unload(struct xsc_eswitch *esw, u16 vport_num)
{
	struct xsc_eswitch_rep *rep;
	int rep_type;

	rep = xsc_eswitch_get_rep(esw, vport_num);
	for (rep_type = NUM_REP_TYPES - 1; rep_type >= 0; rep_type--)
		__esw_offloads_unload_rep(esw, rep, rep_type);
}

int esw_offloads_rep_load(struct xsc_eswitch *esw, u16 vport_num)
{
	struct xsc_eswitch_rep *rep;
	int rep_type;
	int err;

	if (esw->mode != XSC_ESWITCH_OFFLOADS ||
	    esw->offloads.rep_mode != XSC_REP_MODE_KERNEL)
		return 0;

	rep = xsc_eswitch_get_rep(esw, vport_num);
	for (rep_type = 0; rep_type < NUM_REP_TYPES; rep_type++)
		if (atomic_read(&rep->rep_data[rep_type].state) == REP_REGISTERED) {
			err = esw->offloads.rep_ops[rep_type]->load(esw->dev, rep);
			if (err)
				goto err_reps;
			atomic_set(&rep->rep_data[rep_type].state, REP_LOADED);
		}

	return 0;

err_reps:
	for (--rep_type; rep_type >= 0; rep_type--)
		__esw_offloads_unload_rep(esw, rep, rep_type);
	return err;
}

int esw_offloads_enable(struct xsc_eswitch *esw)
{
	struct xsc_vport *vport;
	unsigned long i;
	int err;

	err = esw_offloads_steering_init(esw);
	if (err)
		goto err_steering_init;

	/* Representor will control the vport link state */
	xsc_esw_for_each_vf_vport(esw, i, vport, esw->num_vfs)
		vport->info.link_state = XSC_VPORT_ADMIN_STATE_DOWN;

	/* Uplink vport rep must load first. */
	err = esw_offloads_rep_load(esw, XSC_VPORT_UPLINK);
	if (err)
		goto err_uplink;

	err = xsc_eswitch_enable_pf_vf_vports(esw, XSC_VPORT_UC_ADDR_CHANGE);
	if (err)
		goto err_vports;

	esw->offloads.rep_established = true;

	return 0;

err_vports:
	esw_offloads_unload_rep(esw, XSC_VPORT_UPLINK);

err_uplink:
	esw_offloads_steering_cleanup(esw);

err_steering_init:
	return err;
}

void esw_offloads_disable(struct xsc_eswitch *esw)
{
	bool is_switchdev_kernel = false;

	xsc_eswitch_disable_pf_vf_vports(esw);

	is_switchdev_kernel = (esw->mode == XSC_ESWITCH_OFFLOADS) &&
	    (esw->offloads.rep_mode == XSC_REP_MODE_KERNEL) &&
	    is_support_tc_offload(esw->dev);

	if (!is_switchdev_kernel)
		return;

	xsc_esw_offloads_rep_unload(esw, XSC_VPORT_UPLINK);
	esw_offloads_steering_cleanup(esw);
	esw->offloads.rep_established = false;
}

int esw_offloads_start(struct xsc_eswitch *esw)
{
	struct xsc_core_device *dev = esw->dev;
	int err = 0;

	err = xsc_eswitch_enable_locked(esw, esw->num_vfs);
	if (err)
		xsc_core_err(dev, "Failed setting eswitch to offloads");

	return err;
}

