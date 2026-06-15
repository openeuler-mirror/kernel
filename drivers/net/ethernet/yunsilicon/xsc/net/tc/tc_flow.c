// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <net/flow_dissector.h>
#include <net/flow_offload.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <linux/completion.h>
#include <net/arp.h>
#include <net/ipv6_stubs.h>
#include <net/bareudp.h>
#include <net/bonding.h>
#include <net/dst_metadata.h>
#include <asm/div64.h>
#include "post_act.h"
#include "../rep/xsc_eth_rep.h"
#include "../rep/xsc_rep_tc.h"
#include "../rep/neigh.h"
#include "common/tc_priv.h"
#include "common/fs_core.h"
#include "act/act.h"
#include "../../pci/fs_chains.h"
#include "common/xsc_eswitch.h"
#include "../../pci/eswitch_offloads.h"
#include "common/fs_cmd.h"
#include "common/xsc_lag.h"
#include "../../pci/xsc_flow.h"

#ifdef CONFIG_XSC_TRACE_DEBUG
#define CREATE_TRACE_POINTS
#include "../diag/xsc_tc_tracepoint.h"
#endif

#define XSC_TC_TABLE_NUM_GROUPS 4
#define XSC_TC_TABLE_MAX_GROUP_SIZE BIT(18)

struct xsc_tc_attr_to_reg_mapping xsc_tc_attr_to_reg_mappings[8] = {0};

struct xsc_tc_jump_state {
	u32 jump_count;
	bool jump_target;
	struct xsc_flow_attr *jumping_attr;

	enum flow_action_id last_id;
	u32 last_index;
};

/* To avoid false lock dependency warning set the tc_ht lock
 * class different than the lock class of the ht being used when deleting
 * last flow from a group and then deleting a group, we get into del_sw_flow_group()
 * which call rhashtable_destroy on fg->ftes_hash which will take ht->mutex but
 * it's different than the ht->mutex here.
 */
static struct lock_class_key tc_ht_lock_key;
static struct lock_class_key tc_ht_wq_key;

static void free_flow_post_acts(struct xsc_tc_flow *flow);
static void xsc_free_flow_attr_actions(struct xsc_tc_flow *flow, struct xsc_flow_attr *attr);

void xsc_tc_match_to_reg_match(struct xsc_flow_spec *spec, enum xsc_tc_attr_to_reg type,
			       u32 val, u32 mask)
{
	void *headers_c = spec->match_mask, *headers_v = spec->match_value, *fmask, *fval;
	int soffset = xsc_tc_attr_to_reg_mappings[type].soffset;
	int moffset = xsc_tc_attr_to_reg_mappings[type].moffset;
	int match_len = xsc_tc_attr_to_reg_mappings[type].mlen;
	u32 max_mask = GENMASK(match_len - 1, 0);
	__be32 curr_mask_be, curr_val_be;
	u32 curr_mask, curr_val;

	fmask = headers_c + soffset;
	fval = headers_v + soffset;

	memcpy(&curr_mask_be, fmask, 4);
	memcpy(&curr_val_be, fval, 4);

	curr_mask = be32_to_cpu(curr_mask_be);
	curr_val = be32_to_cpu(curr_val_be);

	//move to correct offset
	WARN_ON(mask > max_mask);
	mask <<= moffset;
	val <<= moffset;
	max_mask <<= moffset;

	//zero val and mask
	curr_mask &= ~max_mask;
	curr_val &= ~max_mask;

	//add current to mask
	curr_mask |= mask;
	curr_val |= val;

	//back to be32 and write
	curr_mask_be = cpu_to_be32(curr_mask);
	curr_val_be = cpu_to_be32(curr_val);

	memcpy(fmask, &curr_mask_be, 4);
	memcpy(fval, &curr_val_be, 4);

	spec->match_mask_enable |= XSC_MATCH_MISC_PARAMETERS;
}

void xsc_tc_match_to_reg_get_match(struct xsc_flow_spec *spec,
				   enum xsc_tc_attr_to_reg type,
				   u32 *val, u32 *mask)
{
	void *headers_c = spec->match_mask, *headers_v = spec->match_value, *fmask, *fval;
	int soffset = xsc_tc_attr_to_reg_mappings[type].soffset;
	int moffset = xsc_tc_attr_to_reg_mappings[type].moffset;
	int match_len = xsc_tc_attr_to_reg_mappings[type].mlen;
	u32 max_mask = GENMASK(match_len - 1, 0);
	__be32 curr_mask_be, curr_val_be;
	u32 curr_mask, curr_val;

	fmask = headers_c + soffset;
	fval = headers_v + soffset;

	memcpy(&curr_mask_be, fmask, 4);
	memcpy(&curr_val_be, fval, 4);

	curr_mask = be32_to_cpu(curr_mask_be);
	curr_val = be32_to_cpu(curr_val_be);

	*mask = (curr_mask >> moffset) & max_mask;
	*val = (curr_val >> moffset) & max_mask;
}

int xsc_tc_match_to_reg_set_and_get_id(struct xsc_core_device *xdev,
				       struct xsc_tc_mod_hdr_acts *mod_hdr_acts,
				       enum xsc_flow_namespace_type ns,
				       enum xsc_tc_attr_to_reg type,
				       u32 data)
{
	int moffset = xsc_tc_attr_to_reg_mappings[type].moffset;
	int mfield = xsc_tc_attr_to_reg_mappings[type].mfield;
	int mlen = xsc_tc_attr_to_reg_mappings[type].mlen;
	char *modact;
	int err;

	modact = xsc_mod_hdr_alloc(xdev, ns, mod_hdr_acts);
	if (IS_ERR(modact))
		return PTR_ERR(modact);

	/* Firmware has 5bit length field and 0 means 32bits */
	if (mlen == 32)
		mlen = 0;

	XSC_SET(set_action_in, modact, action_type, XSC_ACTION_TYPE_SET);
	XSC_SET(set_action_in, modact, field, mfield);
	XSC_SET(set_action_in, modact, offset, moffset);
	XSC_SET(set_action_in, modact, length, mlen);
	XSC_SET(set_action_in, modact, data, data);
	err = mod_hdr_acts->num_actions;
	mod_hdr_acts->num_actions++;

	return err;
}

#ifdef CONFIG_XSC_OFFLOAD_ACT_COUNTER
static struct xsc_tc_act_stats_handle  *
get_act_stats_handle(struct xsc_adapter *priv)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *uplink_rpriv;

	if (is_xdev_switchdev_mode(priv->xdev)) {
		uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
		uplink_priv = &uplink_rpriv->uplink_priv;

		return uplink_priv->action_stats_handle;
	}

	return NULL;
}
#endif

#ifdef CONFIG_XSC_OFFLOAD_OVS
struct xsc_tc_int_port_priv *xsc_get_int_port_priv(struct xsc_adapter *priv)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *uplink_rpriv;

	if (is_xdev_switchdev_mode(priv->xdev)) {
		uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
		uplink_priv = &uplink_rpriv->uplink_priv;

		return uplink_priv->int_port_priv;
	}

	return NULL;
}
#endif

#ifdef CONFIG_XSC_OFFLOAD_CT
static struct xsc_tc_ct_priv *get_ct_priv(struct xsc_adapter *priv)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *uplink_rpriv;

	if (is_xdev_switchdev_mode(priv->xdev)) {
		uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
		uplink_priv = &uplink_rpriv->uplink_priv;

		return uplink_priv->ct_priv;
	}

	return NULL;
}
#endif

#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
static struct xsc_tc_psample *
get_sample_priv(struct xsc_adapter *priv)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *uplink_rpriv;

	if (is_xdev_switchdev_mode(priv->xdev)) {
		uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
		uplink_priv = &uplink_rpriv->uplink_priv;

		return uplink_priv->tc_psample;
	}

	return NULL;
}
#endif

static struct xsc_post_act *get_post_action(struct xsc_adapter *priv)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *uplink_rpriv;

	if (is_xdev_switchdev_mode(priv->xdev)) {
		uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
		uplink_priv = &uplink_rpriv->uplink_priv;

		return uplink_priv->post_act;
	}

	return NULL;
}

static struct xsc_flow_handle *
xsc_add_offloaded_nic_rule(struct xsc_adapter *priv,
			   struct xsc_flow_spec *spec,
			   struct xsc_flow_attr *attr)
{
	return NULL;
}

struct xsc_flow_handle *xsc_tc_rule_insert(struct xsc_adapter *priv,
					   struct xsc_flow_spec *spec,
					   struct xsc_flow_attr *attr)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	if (is_xdev_switchdev_mode(priv->xdev))
		return xsc_eswitch_add_offloaded_rule(esw, spec, attr);

	return	xsc_add_offloaded_nic_rule(priv, spec, attr);
}

static void xsc_del_offloaded_nic_rule(struct xsc_adapter *priv,
				       struct xsc_flow_handle *rule,
				       struct xsc_flow_attr *attr)
{
}

void xsc_tc_rule_delete(struct xsc_adapter *priv, struct xsc_flow_handle *rule,
			struct xsc_flow_attr *attr)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	if (is_xdev_switchdev_mode(priv->xdev)) {
		xsc_eswitch_del_offloaded_rule(esw, rule, attr);
		return;
	}

	xsc_del_offloaded_nic_rule(priv, rule, attr);
}

#ifdef CONFIG_XSC_OFFLOAD_METER
struct xsc_flow_meters *xsc_get_flow_meters(struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *uplink_rpriv;
	struct xsc_adapter *priv;

	if (is_xdev_switchdev_mode(dev)) {
		uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
		uplink_priv = &uplink_rpriv->uplink_priv;
		priv = netdev_priv(uplink_rpriv->netdev);
		if (!uplink_priv->flow_meters)
			uplink_priv->flow_meters =
				xsc_flow_meters_init(priv,
						     XSC_FLOW_NAMESPACE_FDB,
						     uplink_priv->post_act);
		if (!IS_ERR(uplink_priv->flow_meters))
			return uplink_priv->flow_meters;
	}

	return NULL;
}

static bool is_flow_meter_action(struct xsc_flow_attr *attr)
{
	return (((attr->action & XSC_FLOW_CONTEXT_ACTION_EXECUTE_ASO) &&
		 (attr->exe_aso_type == XSC_EXE_ASO_FLOW_METER)) ||
		attr->flags & XSC_ATTR_FLAG_MTU);
}

static int xsc_tc_add_flow_meter(struct xsc_adapter *priv,
				 struct xsc_flow_attr *attr)
{
	struct xsc_post_act *post_act = get_post_action(priv);
	struct xsc_post_meter_priv *post_meter;
	enum xsc_flow_namespace_type ns_type;
	struct xsc_flow_meter_handle *meter;
	enum xsc_post_meter_type type;

	if (IS_ERR(post_act))
		return PTR_ERR(post_act);

	meter = xsc_tc_meter_replace(priv->xdev, &attr->meter_attr.params);
	if (IS_ERR(meter)) {
		xsc_core_err(priv->xdev, "Failed to get flow meter\n");
		return PTR_ERR(meter);
	}

	ns_type = xsc_tc_meter_get_namespace(meter->flow_meters);
	type = meter->params.mtu ? XSC_POST_METER_MTU : XSC_POST_METER_RATE;
	post_meter = xsc_post_meter_init(priv, ns_type, post_act, type,
					 meter->act_counter, meter->drop_counter,
					 attr->branch_true, attr->branch_false);
	if (IS_ERR(post_meter)) {
		xsc_core_err(priv->xdev, "Failed to init post meter\n");
		goto err_meter_init;
	}

	attr->meter_attr.meter = meter;
	attr->meter_attr.post_meter = post_meter;
	attr->dest_ft = xsc_post_meter_get_ft(post_meter);
	attr->action |= XSC_FLOW_CONTEXT_ACTION_FWD_DEST;

	return 0;

err_meter_init:
	xsc_tc_meter_put(meter);
	return PTR_ERR(post_meter);
}

static void xsc_tc_del_flow_meter(struct xsc_eswitch *esw, struct xsc_flow_attr *attr)
{
	xsc_post_meter_cleanup(esw, attr->meter_attr.post_meter);
	xsc_tc_meter_put(attr->meter_attr.meter);
}
#endif

struct xsc_flow_handle *xsc_tc_rule_offload(struct xsc_adapter *priv,
					    struct xsc_flow_spec *spec,
					    struct xsc_flow_attr *attr)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	if (!is_xdev_switchdev_mode(priv->xdev))
		return ERR_PTR(-EOPNOTSUPP);

#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
	if (attr->flags & XSC_ATTR_FLAG_SAMPLE)
		return xsc_tc_sample_offload(get_sample_priv(priv), spec, attr);
#endif

#ifdef CONFIG_XSC_OFFLOAD_METER
	if (is_flow_meter_action(attr)) {
		err = xsc_tc_add_flow_meter(priv, attr);
		if (err)
			return ERR_PTR(err);
	}
#endif

	return xsc_eswitch_add_offloaded_rule(esw, spec, attr);
}

void xsc_tc_rule_unoffload(struct xsc_adapter *priv,
			   struct xsc_flow_handle *rule,
			   struct xsc_flow_attr *attr)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	if (!is_xdev_switchdev_mode(priv->xdev)) {
		xsc_del_offloaded_nic_rule(priv, rule, attr);
		return;
	}

#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
	if (attr->flags & XSC_ATTR_FLAG_SAMPLE) {
		xsc_tc_sample_unoffload(get_sample_priv(priv), rule, attr);
		return;
	}
#endif

	xsc_eswitch_del_offloaded_rule(esw, rule, attr);

#ifdef CONFIG_XSC_OFFLOAD_METER
	if (attr->meter_attr.meter)
		xsc_tc_del_flow_meter(esw, attr);
#endif
}

int xsc_tc_match_to_reg_set(struct xsc_core_device *xdev,
			    struct xsc_tc_mod_hdr_acts *mod_hdr_acts,
			    enum xsc_flow_namespace_type ns,
			    enum xsc_tc_attr_to_reg type,
			    u32 data)
{
	int ret = xsc_tc_match_to_reg_set_and_get_id(xdev, mod_hdr_acts, ns, type, data);

	return ret < 0 ? ret : 0;
}

void xsc_tc_match_to_reg_mod_hdr_change(struct xsc_core_device *xdev,
					struct xsc_tc_mod_hdr_acts *mod_hdr_acts,
					enum xsc_tc_attr_to_reg type,
					int act_id, u32 data)
{
	int moffset = xsc_tc_attr_to_reg_mappings[type].moffset;
	int mfield = xsc_tc_attr_to_reg_mappings[type].mfield;
	int mlen = xsc_tc_attr_to_reg_mappings[type].mlen;
	char *modact;

	modact = xsc_mod_hdr_get_item(mod_hdr_acts, act_id);

	/* Firmware has 5bit length field and 0 means 32bits */
	if (mlen == 32)
		mlen = 0;

	XSC_SET(set_action_in, modact, action_type, XSC_ACTION_TYPE_SET);
	XSC_SET(set_action_in, modact, field, mfield);
	XSC_SET(set_action_in, modact, offset, moffset);
	XSC_SET(set_action_in, modact, length, mlen);
	XSC_SET(set_action_in, modact, data, data);
}

static void xsc_tc_del_flow(struct xsc_adapter *priv, struct xsc_tc_flow *flow);

struct xsc_tc_flow *xsc_flow_get(struct xsc_tc_flow *flow)
{
	if (!flow || !refcount_inc_not_zero(&flow->refcnt))
		return ERR_PTR(-EINVAL);
	return flow;
}

void xsc_flow_put(struct xsc_adapter *priv, struct xsc_tc_flow *flow)
{
	if (refcount_dec_and_test(&flow->refcnt)) {
		xsc_tc_del_flow(priv, flow);
		kfree_rcu(flow, rcu_head);
	}
}

bool xsc_is_eswitch_flow(struct xsc_tc_flow *flow)
{
	return flow_flag_test(flow, ESWITCH);
}

bool xsc_is_ft_flow(struct xsc_tc_flow *flow)
{
	return flow_flag_test(flow, FT);
}

bool xsc_is_offloaded_flow(struct xsc_tc_flow *flow)
{
	return flow_flag_test(flow, OFFLOADED);
}

enum xsc_flow_namespace_type xsc_get_flow_namespace_id(struct xsc_tc_flow *flow)
{
	return xsc_is_eswitch_flow(flow) ?
		XSC_FLOW_NAMESPACE_FDB : XSC_FLOW_NAMESPACE_KERNEL;
}

static struct xsc_core_device *
get_flow_counter_dev(struct xsc_tc_flow *flow)
{
	return xsc_is_eswitch_flow(flow) ? flow->attr->esw_attr->counter_dev : flow->priv->xdev;
}

static struct mod_hdr_tbl *
get_mod_hdr_table(struct xsc_adapter *priv, struct xsc_tc_flow *flow)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	return xsc_get_flow_namespace_id(flow) == XSC_FLOW_NAMESPACE_FDB ?
		&esw->offloads.mod_hdr : NULL;
}

int xsc_tc_attach_mod_hdr(struct xsc_adapter *priv, struct xsc_tc_flow *flow,
			  struct xsc_flow_attr *attr)
{
	struct xsc_mod_hdr_handle *mh;

	mh = xsc_mod_hdr_attach(priv->xdev, get_mod_hdr_table(priv, flow),
				xsc_get_flow_namespace_id(flow),
				&attr->parse_attr->mod_hdr_acts);
	if (IS_ERR(mh))
		return PTR_ERR(mh);

	WARN_ON(attr->modify_hdr);
	attr->modify_hdr = xsc_mod_hdr_get(mh);
	attr->mh = mh;

	return 0;
}

void xsc_tc_detach_mod_hdr(struct xsc_adapter *priv, struct xsc_tc_flow *flow,
			   struct xsc_flow_attr *attr)
{
	/* flow wasn't fully initialized */
	if (!attr->mh)
		return;

	xsc_mod_hdr_detach(priv->xdev, get_mod_hdr_table(priv, flow), attr->mh);
	attr->mh = NULL;
}

static int alloc_flow_attr_counter(struct xsc_core_device *counter_dev,
				   struct xsc_flow_attr *attr)

{
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	struct xsc_fc *counter;

	counter = xsc_fc_create(counter_dev, true);
	if (IS_ERR(counter))
		return PTR_ERR(counter);

	attr->counter = counter;
#endif
	return 0;
}

struct xsc_flow_handle *xsc_tc_offload_fdb_rules(struct xsc_eswitch *esw,
						 struct xsc_tc_flow *flow,
						 struct xsc_flow_spec *spec,
						 struct xsc_flow_attr *attr)
{
	struct xsc_flow_handle *rule;

	if (attr->flags & XSC_ATTR_FLAG_SLOW_PATH)
		return xsc_eswitch_add_offloaded_rule(esw, spec, attr);

	rule = xsc_tc_rule_offload(flow->priv, spec, attr);

	if (IS_ERR(rule))
		return rule;

	if (attr->esw_attr->split_count) {
		flow->rule[1] = xsc_eswitch_add_fwd_rule(esw, spec, attr);
		if (IS_ERR(flow->rule[1]))
			goto err_rule1;
	}

	return rule;

err_rule1:
	xsc_tc_rule_unoffload(flow->priv, rule, attr);
	return flow->rule[1];
}

void xsc_tc_unoffload_fdb_rules(struct xsc_eswitch *esw, struct xsc_tc_flow *flow,
				struct xsc_flow_attr *attr)
{
	flow_flag_clear(flow, OFFLOADED);

	if (attr->flags & XSC_ATTR_FLAG_SLOW_PATH)
		return xsc_eswitch_del_offloaded_rule(esw, flow->rule[0], attr);

	if (attr->esw_attr->split_count)
		xsc_eswitch_del_fwd_rule(esw, flow->rule[1], attr);

	xsc_tc_rule_unoffload(flow->priv, flow->rule[0], attr);
}

struct xsc_flow_handle *xsc_tc_offload_to_slow_path(struct xsc_eswitch *esw,
						    struct xsc_tc_flow *flow,
						    struct xsc_flow_spec *spec)
{
#ifdef CONFIG_XSC_OFFLOAD_TUN
	struct xsc_tc_mod_hdr_acts mod_acts = {};
	struct xsc_mod_hdr_handle *mh = NULL;
	struct xsc_flow_attr *slow_attr;
	struct xsc_flow_handle *rule;
	bool fwd_and_modify_cap;
	u32 chain_mapping = 0;
	int err;

	slow_attr = xsc_alloc_flow_attr(XSC_FLOW_NAMESPACE_FDB);
	if (!slow_attr)
		return ERR_PTR(-ENOMEM);

	memcpy(slow_attr, flow->attr, ESW_FLOW_ATTR_SZ);
	slow_attr->action = XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
	slow_attr->esw_attr->split_count = 0;
	slow_attr->flags |= XSC_ATTR_FLAG_SLOW_PATH;

	fwd_and_modify_cap = esw->esw_caps.fdb_modify_header_fwd_to_table;
	if (!fwd_and_modify_cap)
		goto skip_restore;

	err = xsc_chains_get_chain_mapping(esw_chains(esw), flow->attr->chain, &chain_mapping);
	if (err)
		goto err_get_chain;

	err = xsc_tc_match_to_reg_set(esw->dev, &mod_acts, XSC_FLOW_NAMESPACE_FDB,
				      MAPPED_OBJ_TO_REG, chain_mapping);
	if (err)
		goto err_reg_set;

	mh = xsc_mod_hdr_attach(esw->dev, get_mod_hdr_table(flow->priv, flow),
				XSC_FLOW_NAMESPACE_FDB, &mod_acts);
	if (IS_ERR(mh)) {
		err = PTR_ERR(mh);
		goto err_attach;
	}

	slow_attr->action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;
	slow_attr->modify_hdr = xsc_mod_hdr_get(mh);

skip_restore:
	rule = xsc_tc_offload_fdb_rules(esw, flow, spec, slow_attr);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		goto err_offload;
	}

	flow->attr->slow_mh = mh;
	flow->chain_mapping = chain_mapping;
	flow_flag_set(flow, SLOW);

	xsc_mod_hdr_dealloc(&mod_acts);
	kfree(slow_attr);

	return rule;

err_offload:
	if (fwd_and_modify_cap)
		xsc_mod_hdr_detach(esw->dev, get_mod_hdr_table(flow->priv, flow), mh);
err_attach:
err_reg_set:

	if (fwd_and_modify_cap)
		xsc_chains_put_chain_mapping(esw_chains(esw), chain_mapping);

err_get_chain:
	xsc_mod_hdr_dealloc(&mod_acts);
	kfree(slow_attr);
	return ERR_PTR(err);
#else
	return NULL;
#endif
}

void xsc_tc_unoffload_from_slow_path(struct xsc_eswitch *esw, struct xsc_tc_flow *flow)
{
#ifdef CONFIG_XSC_OFFLOAD_TUN
	struct xsc_mod_hdr_handle *slow_mh = flow->attr->slow_mh;
	struct xsc_flow_attr *slow_attr;

	slow_attr = xsc_alloc_flow_attr(XSC_FLOW_NAMESPACE_FDB);
	if (!slow_attr) {
		xsc_core_warn(flow->priv->xdev, "Unable to alloc attr to unoffload slow path rule\n");
		return;
	}

	memcpy(slow_attr, flow->attr, ESW_FLOW_ATTR_SZ);
	slow_attr->action = XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
	slow_attr->esw_attr->split_count = 0;
	slow_attr->flags |= XSC_ATTR_FLAG_SLOW_PATH;
	if (slow_mh) {
		slow_attr->action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;
		slow_attr->modify_hdr = xsc_mod_hdr_get(slow_mh);
	}
	xsc_tc_unoffload_fdb_rules(esw, flow, slow_attr);
	if (slow_mh) {
		xsc_mod_hdr_detach(esw->dev, get_mod_hdr_table(flow->priv, flow), slow_mh);
		xsc_chains_put_chain_mapping(esw_chains(esw), flow->chain_mapping);
		flow->chain_mapping = 0;
		flow->attr->slow_mh = NULL;
	}
	flow_flag_clear(flow, SLOW);
	kfree(slow_attr);
#endif
}

/* Caller must obtain uplink_priv->unready_flows_lock mutex before calling this
 * function.
 */
static void unready_flow_add(struct xsc_tc_flow *flow,
			     struct list_head *unready_flows)
{
	flow_flag_set(flow, NOT_READY);
	list_add_tail(&flow->unready, unready_flows);
}

/* Caller must obtain uplink_priv->unready_flows_lock mutex before calling this
 * function.
 */
void unready_flow_del(struct xsc_tc_flow *flow)
{
	list_del(&flow->unready);
	flow_flag_clear(flow, NOT_READY);
}

static void add_unready_flow(struct xsc_tc_flow *flow)
{
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *rpriv;
	struct xsc_eswitch *esw;

	esw = flow->priv->xdev->priv.eswitch;
	rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &rpriv->uplink_priv;

	mutex_lock(&uplink_priv->unready_flows_lock);
	unready_flow_add(flow, &uplink_priv->unready_flows);
	mutex_unlock(&uplink_priv->unready_flows_lock);
}

static void remove_unready_flow(struct xsc_tc_flow *flow)
{
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *rpriv;
	struct xsc_eswitch *esw;

	esw = flow->priv->xdev->priv.eswitch;
	rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &rpriv->uplink_priv;

	mutex_lock(&uplink_priv->unready_flows_lock);
	if (flow_flag_test(flow, NOT_READY))
		unready_flow_del(flow);
	mutex_unlock(&uplink_priv->unready_flows_lock);
}

static int
verify_attr_actions(u32 actions, struct netlink_ext_ack *extack)
{
	if (!(actions &
	      (XSC_FLOW_CONTEXT_ACTION_FWD_DEST | XSC_FLOW_CONTEXT_ACTION_DROP))) {
		NL_SET_ERR_MSG_MOD(extack, "Rule must have at least one forward/drop action");
		pr_err("Rule must have at least one forward/drop action\n");
		return -EOPNOTSUPP;
	}

	if (!(~actions &
	      (XSC_FLOW_CONTEXT_ACTION_FWD_DEST | XSC_FLOW_CONTEXT_ACTION_DROP))) {
		NL_SET_ERR_MSG_MOD(extack, "Rule cannot support forward+drop action");
		pr_err("Rule cannot support forward+drop action\n");
		return -EOPNOTSUPP;
	}

	if (actions & XSC_FLOW_CONTEXT_ACTION_MOD_HDR &&
	    actions & XSC_FLOW_CONTEXT_ACTION_DROP) {
		NL_SET_ERR_MSG_MOD(extack, "Drop with modify header action is not supported");
		pr_err("Drop with modify header action is not supported\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

#ifdef CONFIG_XSC_OFFLOAD_TUN
static bool has_encap_dests(struct xsc_flow_attr *attr)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	int out_index;

	for (out_index = 0; out_index < XSC_MAX_FLOW_FWD_VPORTS; out_index++)
		if (esw_attr->dests[out_index].flags & XSC_ESW_DEST_ENCAP)
			return true;

	return false;
}
#endif

static int
post_process_attr(struct xsc_tc_flow *flow,
		  struct xsc_flow_attr *attr,
		  struct netlink_ext_ack *extack)
{
	int err = 0;

	err = verify_attr_actions(attr->action, extack);
	if (err)
		goto err_out;

#ifdef CONFIG_XSC_OFFLOAD_TUN
	if (xsc_is_eswitch_flow(flow) && has_encap_dests(attr)) {
		err = xsc_tc_tun_encap_dests_set(flow->priv, flow, attr, extack, &vf_tun);
		if (err)
			goto err_out;
	}
#endif

	if (attr->action & XSC_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = xsc_tc_attach_mod_hdr(flow->priv, flow, attr);
		if (err)
			goto err_out;
	}

	if (attr->branch_true &&
	    attr->branch_true->action & XSC_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = xsc_tc_attach_mod_hdr(flow->priv, flow, attr->branch_true);
		if (err)
			goto err_out;
	}

	if (attr->branch_false &&
	    attr->branch_false->action & XSC_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = xsc_tc_attach_mod_hdr(flow->priv, flow, attr->branch_false);
		if (err)
			goto err_out;
	}

	if (attr->action & XSC_FLOW_CONTEXT_ACTION_COUNT) {
		err = alloc_flow_attr_counter(get_flow_counter_dev(flow), attr);
		if (err)
			goto err_out;
	}

err_out:
	return err;
}

int xsc_tc_add_fdb_flow(struct xsc_adapter *priv, struct xsc_tc_flow *flow,
			struct netlink_ext_ack *extack)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct xsc_tc_flow_parse_attr *parse_attr;
	struct xsc_flow_attr *attr = flow->attr;
	struct xsc_esw_flow_attr *esw_attr;
	u32 max_prio, max_chain;
	int err = 0;

	esw_debug(priv->xdev, "add tc flow offload\n");

	parse_attr = attr->parse_attr;
	esw_attr = attr->esw_attr;

	/* We check chain range only for tc flows.
	 * For ft flows, we checked attr->chain was originally 0 and set it to
	 * FDB_FT_CHAIN which is outside tc range.
	 * See xsc_rep_setup_ft_cb().
	 */
	max_chain = xsc_chains_get_chain_range(esw_chains(esw));
	if (!xsc_is_ft_flow(flow) && attr->chain > max_chain) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Requested chain is out of supported range");
		netdev_err(priv->netdev, "Requested chain is out of supported range\n");
		err = -EOPNOTSUPP;
		goto err_out;
	}

	max_prio = xsc_chains_get_prio_range(esw_chains(esw));
	if (attr->prio > max_prio) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Requested priority is out of supported range");
		netdev_err(priv->netdev, "Requested priority is out of supported range\n");
		err = -EOPNOTSUPP;
		goto err_out;
	}

#ifdef CONFIG_XSC_OFFLOAD_TUN
	if (flow_flag_test(flow, TUN_RX)) {
		err = xsc_attach_decap_route(priv, flow);
		if (err)
			goto err_out;

		if (!attr->chain && esw_attr->int_port &&
		    attr->action & XSC_FLOW_CONTEXT_ACTION_FWD_DEST) {
			/* If decap route device is internal port, change the
			 * source vport value in reg_c0 back to uplink just in
			 * case the rule performs goto chain > 0. If we have a miss
			 * on chain > 0 we want the metadata regs to hold the
			 * chain id so SW will resume handling of this packet
			 * from the proper chain.
			 */
			u32 metadata =
				xsc_eswitch_get_vport_metadata_for_set(esw,
								       esw_attr->in_rep->vport);

			err = xsc_tc_match_to_reg_set(priv->xdev, &parse_attr->mod_hdr_acts,
						      XSC_FLOW_NAMESPACE_KERNEL, VPORT_TO_REG,
						      metadata);
			if (err)
				goto err_out;

			attr->action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;
		}
	}
#endif

#ifdef CONFIG_XSC_OFFLOAD_OVS
	if (netif_is_ovs_master(parse_attr->filter_dev)) {
		struct xsc_tc_int_port *int_port;

		if (attr->chain) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Internal port rule is only supported on chain 0");
			netdev_err(priv->netdev,
				   "Internal port rule is only supported on chain 0\n");
			err = -EOPNOTSUPP;
			goto err_out;
		}

		if (attr->dest_chain) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Internal port rule offload doesn't support goto action");
			netdev_err(priv->netdev,
				   "Internal port rule offload doesn't support goto action\n");
			err = -EOPNOTSUPP;
			goto err_out;
		}

		int_port = xsc_tc_int_port_get(xsc_get_int_port_priv(priv),
					       parse_attr->filter_dev->ifindex,
					       flow_flag_test(flow, EGRESS) ?
					       XSC_TC_INT_PORT_EGRESS : XSC_TC_INT_PORT_INGRESS);
		if (IS_ERR(int_port)) {
			err = PTR_ERR(int_port);
			goto err_out;
		}

		esw_attr->int_port = int_port;
	}
#endif

	err = post_process_attr(flow, attr, extack);
	if (err)
		goto err_out;

#ifdef CONFIG_XSC_OFFLOAD_ACT_COUNTER
	err = xsc_tc_act_stats_add_flow(get_act_stats_handle(priv), flow);
	if (err)
		goto err_out;
#endif

	/* we get here if one of the following takes place:
	 * (1) there's no error
	 * (2) there's an encap action and we don't have valid neigh
	 */
	if (flow_flag_test(flow, SLOW))
		flow->rule[0] = xsc_tc_offload_to_slow_path(esw, flow, &parse_attr->spec);
	else
		flow->rule[0] = xsc_tc_offload_fdb_rules(esw, flow, &parse_attr->spec, attr);

	if (IS_ERR(flow->rule[0])) {
		err = PTR_ERR(flow->rule[0]);
		goto err_out;
	}
	flow_flag_set(flow, OFFLOADED);

	return 0;

err_out:
	netdev_err(priv->netdev, "Failed to add offload rule, err=%d\n", err);
	flow_flag_set(flow, FAILED);
	return err;
}

#ifdef CONFIG_XSC_OFFLOAD_GENEVE
static bool xsc_flow_has_geneve_opt(struct xsc_tc_flow *flow)
{
	void *headers_v = XSC_ADDR_OF(fte_match_param,
				       spec->match_value,
				       misc_3);
	u32 geneve_tlv_opt_0_data = XSC_GET(fte_match_set_misc3,
					     headers_v,
					     geneve_tlv_option_0_data);

	return !!geneve_tlv_opt_0_data;
}
#endif

static void free_branch_attr(struct xsc_tc_flow *flow, struct xsc_flow_attr *attr)
{
	if (!attr)
		return;

	xsc_free_flow_attr_actions(flow, attr);
	kvfree(attr->parse_attr);
	kfree(attr);
}

static void xsc_tc_del_fdb_flow(struct xsc_adapter *priv, struct xsc_tc_flow *flow)
{
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct xsc_flow_attr *attr = flow->attr;

#ifdef CONFIG_XSC_OFFLOAD_TUN
	xsc_put_flow_tunnel_id(flow);
#endif

	remove_unready_flow(flow);

	if (xsc_is_offloaded_flow(flow)) {
		if (flow_flag_test(flow, SLOW))
			xsc_tc_unoffload_from_slow_path(esw, flow);
		else
			xsc_tc_unoffload_fdb_rules(esw, flow, attr);
	}
	complete_all(&flow->del_hw_done);

#ifdef CONFIG_XSC_OFFLOAD_GENEVE
	if (xsc_flow_has_geneve_opt(flow))
		xsc_geneve_tlv_option_del(priv->xdev->geneve);
#endif

#ifdef CONFIG_XSC_OFFLOAD_TUN
	if (flow->decap_route)
		xsc_detach_decap_route(priv, flow);
#endif

#ifdef CONFIG_XSC_OFFLOAD_CT
	xsc_tc_ct_match_del(get_ct_priv(priv), &flow->attr->ct_attr);
#endif

#ifdef CONFIG_XSC_OFFLOAD_TUN
	if (flow_flag_test(flow, L3_TO_L2_DECAP))
		xsc_detach_decap(priv, flow);
#endif

#ifdef CONFIG_XSC_OFFLOAD_ACT_COUNTER
	xsc_tc_act_stats_del_flow(get_act_stats_handle(priv), flow);
#endif

	free_flow_post_acts(flow);
	xsc_free_flow_attr_actions(flow, attr);

	kvfree(attr->esw_attr->rx_tun_attr);
	kvfree(attr->parse_attr);
	kfree(flow->attr);
}

#ifdef CONFIG_XSC_OFFLOAD_TUN
/* Iterate over tmp_list of flows attached to flow_list head. */
void xsc_put_flow_list(struct xsc_adapter *priv, struct list_head *flow_list)
{
	struct xsc_tc_flow *flow, *tmp;

	list_for_each_entry_safe(flow, tmp, flow_list, tmp_list)
		xsc_flow_put(priv, flow);
}

static bool flow_requires_tunnel_mapping(u32 chain, struct flow_cls_offload *f)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_action *flow_action = &rule->action;
	const struct flow_action_entry *act;
	int i;

	if (chain)
		return false;

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
		case FLOW_ACTION_GOTO:
			return true;
		case FLOW_ACTION_SAMPLE:
			return true;
		default:
			continue;
		}
	}

	return false;
}

static int
enc_opts_is_dont_care_or_full_match(struct xsc_adapter *priv,
				    struct flow_dissector_key_enc_opts *opts,
				    struct netlink_ext_ack *extack,
				    bool *dont_care)
{
	struct geneve_opt *opt;
	int off = 0;

	*dont_care = true;

	while (opts->len > off) {
		opt = (struct geneve_opt *)&opts->data[off];

		if (!(*dont_care) || opt->opt_class || opt->type ||
		    memchr_inv(opt->opt_data, 0, opt->length * 4)) {
			*dont_care = false;

			if (opt->opt_class != htons(U16_MAX) ||
			    opt->type != U8_MAX) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Partial match of tunnel options in chain > 0 isn't supported");
				netdev_warn(priv->netdev,
					    "Partial match of tunnel options in chain > 0 isn't supported");
				return -EOPNOTSUPP;
			}
		}

		off += sizeof(struct geneve_opt) + opt->length * 4;
	}

	return 0;
}

#define COPY_DISSECTOR(rule, diss_key, dst)\
({ \
	struct flow_rule *__rule = (rule);\
	typeof(dst) __dst = dst;\
\
	memcpy(__dst,\
	       skb_flow_dissector_target(__rule->match.dissector,\
					 diss_key,\
					 __rule->match.key),\
	       sizeof(*__dst));\
})

static int xsc_get_flow_tunnel_id(struct xsc_adapter *priv,
				  struct xsc_tc_flow *flow,
				  struct flow_cls_offload *f,
				  struct net_device *filter_dev)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct netlink_ext_ack *extack = f->common.extack;
	struct xsc_tc_mod_hdr_acts *mod_hdr_acts;
	struct flow_match_enc_opts enc_opts_match;
	struct tunnel_match_enc_opts tun_enc_opts;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_flow_attr *attr = flow->attr;
	struct xsc_rep_priv *uplink_rpriv;
	struct tunnel_match_key tunnel_key;
	bool enc_opts_is_dont_care = true;
	u32 tun_id, enc_opts_id = 0;
	struct xsc_eswitch *esw;
	u32 value, mask;
	int err;

	esw = priv->xdev->priv.eswitch;
	uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &uplink_rpriv->uplink_priv;

	memset(&tunnel_key, 0, sizeof(tunnel_key));
	COPY_DISSECTOR(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL,
		       &tunnel_key.enc_control);
	if (tunnel_key.enc_control.addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS)
		COPY_DISSECTOR(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS,
			       &tunnel_key.enc_ipv4);
	else
		COPY_DISSECTOR(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS,
			       &tunnel_key.enc_ipv6);
	COPY_DISSECTOR(rule, FLOW_DISSECTOR_KEY_ENC_IP, &tunnel_key.enc_ip);
	COPY_DISSECTOR(rule, FLOW_DISSECTOR_KEY_ENC_PORTS,
		       &tunnel_key.enc_tp);
	COPY_DISSECTOR(rule, FLOW_DISSECTOR_KEY_ENC_KEYID,
		       &tunnel_key.enc_key_id);
	tunnel_key.filter_ifindex = filter_dev->ifindex;

	flow_rule_match_enc_opts(rule, &enc_opts_match);
	err = enc_opts_is_dont_care_or_full_match(priv,
						  enc_opts_match.mask,
						  extack,
						  &enc_opts_is_dont_care);
	if (err)
		goto err_enc_opts;

	if (!enc_opts_is_dont_care) {
		memset(&tun_enc_opts, 0, sizeof(tun_enc_opts));
		memcpy(&tun_enc_opts.key, enc_opts_match.key,
		       sizeof(*enc_opts_match.key));
		memcpy(&tun_enc_opts.mask, enc_opts_match.mask,
		       sizeof(*enc_opts_match.mask));
	}

	value = tun_id << ENC_OPTS_BITS | enc_opts_id;
	mask = enc_opts_id ? TUNNEL_ID_MASK :
			     (TUNNEL_ID_MASK & ~ENC_OPTS_BITS_MASK);

	if (attr->chain) {
		xsc_tc_match_to_reg_match(&attr->parse_attr->spec,
					  TUNNEL_TO_REG, value, mask);
	} else {
		mod_hdr_acts = &attr->parse_attr->mod_hdr_acts;
		err = xsc_tc_match_to_reg_set(priv->xdev,
					      mod_hdr_acts, XSC_FLOW_NAMESPACE_FDB,
					      TUNNEL_TO_REG, value);
		if (err)
			goto err_set;

		attr->action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;
	}

	flow->attr->tunnel_id = value;
	return 0;

err_set:
err_enc_opts:
	return err;
}

static void xsc_put_flow_tunnel_id(struct xsc_tc_flow *flow)
{
	u32 enc_opts_id = flow->attr->tunnel_id & ENC_OPTS_BITS_MASK;
	u32 tun_id = flow->attr->tunnel_id >> ENC_OPTS_BITS;
	struct xsc_rep_uplink_priv *uplink_priv;
	struct xsc_rep_priv *uplink_rpriv;
	struct xsc_eswitch *esw;

	esw = flow->priv->xdev->priv.eswitch;
	uplink_rpriv = xsc_eswitch_get_uplink_priv(esw, REP_ETH);
	uplink_priv = &uplink_rpriv->uplink_priv;
}

/* Tunnel device follows RFC 6040, see include/net/inet_ecn.h.
 * And changes inner ip_ecn depending on inner and outer ip_ecn as follows:
 *      +---------+----------------------------------------+
 *      |Arriving |         Arriving Outer Header          |
 *      |   Inner +---------+---------+---------+----------+
 *      |  Header | Not-ECT | ECT(0)  | ECT(1)  |   CE     |
 *      +---------+---------+---------+---------+----------+
 *      | Not-ECT | Not-ECT | Not-ECT | Not-ECT | <drop>   |
 *      |  ECT(0) |  ECT(0) | ECT(0)  | ECT(1)  |   CE*    |
 *      |  ECT(1) |  ECT(1) | ECT(1)  | ECT(1)* |   CE*    |
 *      |    CE   |   CE    |  CE     | CE      |   CE     |
 *      +---------+---------+---------+---------+----------+
 *
 * Tc matches on inner after decapsulation on tunnel device, but hw offload matches
 * the inner ip_ecn value before hardware decap action.
 *
 * Cells marked are changed from original inner packet ip_ecn value during decap, and
 * so matching those values on inner ip_ecn before decap will fail.
 *
 * The following helper allows offload when inner ip_ecn won't be changed by outer ip_ecn,
 * except for the outer ip_ecn = CE, where in all cases inner ip_ecn will be changed to CE,
 * and such we can drop the inner ip_ecn=CE match.
 */

static int xsc_tc_verify_tunnel_ecn(struct xsc_adapter *priv,
				    struct flow_cls_offload *f,
				    bool *match_inner_ecn)
{
	u8 outer_ecn_mask = 0, outer_ecn_key = 0, inner_ecn_mask = 0, inner_ecn_key = 0;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_match_ip match;

	*match_inner_ecn = true;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_IP)) {
		flow_rule_match_enc_ip(rule, &match);
		outer_ecn_key = match.key->tos & INET_ECN_MASK;
		outer_ecn_mask = match.mask->tos & INET_ECN_MASK;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		flow_rule_match_ip(rule, &match);
		inner_ecn_key = match.key->tos & INET_ECN_MASK;
		inner_ecn_mask = match.mask->tos & INET_ECN_MASK;
	}

	if (outer_ecn_mask != 0 && outer_ecn_mask != INET_ECN_MASK) {
		NL_SET_ERR_MSG_MOD(extack, "Partial match on enc_tos ecn bits isn't supported");
		netdev_warn(priv->netdev, "Partial match on enc_tos ecn bits isn't supported");
		return -EOPNOTSUPP;
	}

	if (!outer_ecn_mask) {
		if (!inner_ecn_mask)
			return 0;

		NL_SET_ERR_MSG_MOD(extack,
				   "Matching on tos ecn bits without also matching enc_tos ecn bits isn't supported");
		netdev_warn(priv->netdev,
			    "Matching on tos ecn bits without also matching enc_tos ecn bits isn't supported");
		return -EOPNOTSUPP;
	}

	if (inner_ecn_mask && inner_ecn_mask != INET_ECN_MASK) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Partial match on tos ecn bits with match on enc_tos ecn bits isn't supported");
		netdev_warn(priv->netdev,
			    "Partial match on tos ecn bits with match on enc_tos ecn bits isn't supported");
		return -EOPNOTSUPP;
	}

	if (!inner_ecn_mask)
		return 0;

	/* Both inner and outer have full mask on ecn */

	if (outer_ecn_key == INET_ECN_ECT_1) {
		/* inner ecn might change by DECAP action */

		NL_SET_ERR_MSG_MOD(extack, "Match on enc_tos ecn = ECT(1) isn't supported");
		netdev_warn(priv->netdev, "Match on enc_tos ecn = ECT(1) isn't supported");
		return -EOPNOTSUPP;
	}

	if (outer_ecn_key != INET_ECN_CE)
		return 0;

	if (inner_ecn_key != INET_ECN_CE) {
		/* Can't happen in software, as packet ecn will be changed to CE after decap */
		NL_SET_ERR_MSG_MOD(extack,
				   "Match on tos enc_tos ecn = CE while match on tos ecn != CE isn't supported");
		netdev_warn(priv->netdev,
			    "Match on tos enc_tos ecn = CE while match on tos ecn != CE isn't supported");
		return -EOPNOTSUPP;
	}

	/* outer ecn = CE, inner ecn = CE, as decap will change inner ecn to CE in anycase,
	 * drop match on inner ecn
	 */
	*match_inner_ecn = false;

	return 0;
}

static int parse_tunnel_attr(struct xsc_adapter *priv,
			     struct xsc_tc_flow *flow,
			     struct xsc_flow_spec *spec,
			     struct flow_cls_offload *f,
			     struct net_device *filter_dev,
			     u8 *match_level,
			     bool *match_inner)
{
	struct xsc_tc_tunnel *tunnel = xsc_get_tc_tun(filter_dev);
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;
	struct netlink_ext_ack *extack = f->common.extack;
	bool needs_mapping, sets_mapping;
	int err;

	if (!xsc_is_eswitch_flow(flow)) {
		NL_SET_ERR_MSG_MOD(extack, "Match on tunnel is not supported");
		return -EOPNOTSUPP;
	}

	needs_mapping = !!flow->attr->chain;
	sets_mapping = flow_requires_tunnel_mapping(flow->attr->chain, f);
	*match_inner = !needs_mapping;

	if (needs_mapping || sets_mapping) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Chains on tunnel devices isn't supported, need loopback support");
		netdev_warn(priv->netdev,
			    "Chains on tunnel devices isn't supported, need loopback support");
		return -EOPNOTSUPP;
	}

	if (!flow->attr->chain) {
		err = xsc_tc_tun_parse(filter_dev, priv, spec, f, match_level);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Failed to parse tunnel attributes");
			netdev_warn(priv->netdev,
				    "Failed to parse tunnel attributes");
			return err;
		}

		flow->attr->action |= XSC_FLOW_CONTEXT_ACTION_DECAP;
		err = xsc_tc_set_attr_rx_tun(flow, spec);
		if (err)
			return err;
	} else if (tunnel) {
		struct xsc_flow_spec *tmp_spec;

		tmp_spec = kvzalloc(sizeof(*tmp_spec), GFP_KERNEL);
		if (!tmp_spec) {
			NL_SET_ERR_MSG_MOD(extack, "Failed to allocate memory for tunnel tmp spec");
			netdev_warn(priv->netdev, "Failed to allocate memory for tunnel tmp spec");
			return -ENOMEM;
		}
		memcpy(tmp_spec, spec, sizeof(*tmp_spec));

		err = xsc_tc_tun_parse(filter_dev, priv, tmp_spec, f, match_level);
		if (err) {
			kvfree(tmp_spec);
			NL_SET_ERR_MSG_MOD(extack, "Failed to parse tunnel attributes");
			netdev_warn(priv->netdev, "Failed to parse tunnel attributes");
			return err;
		}
		err = xsc_tc_set_attr_rx_tun(flow, tmp_spec);
		kvfree(tmp_spec);
		if (err)
			return err;
	}

	if (!needs_mapping && !sets_mapping)
		return 0;

	return xsc_get_flow_tunnel_id(priv, flow, f, filter_dev);
}
#endif

void xsc_tc_set_ethertype(struct xsc_core_device *xdev,
			  struct flow_match_basic *match, bool outer,
			  void *headers_c, void *headers_v, u64 *attr)
{
	if (match->mask->n_proto == htons(0xFFFF) &&
	    (match->key->n_proto == htons(ETH_P_IP) ||
	     match->key->n_proto == htons(ETH_P_IPV6))) {
		XSC_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_type);
		XSC_SET(fte_match_set_lyr_2_4, headers_v, ip_type,
			match->key->n_proto == htons(ETH_P_IP) ? 4 : 6);
		XSC_SET_FTE_MATCH_ATTR(attr, IP_TYPE);
	} else {
		XSC_SET(fte_match_set_lyr_2_4, headers_c, ethertype,
			ntohs(match->mask->n_proto));
		XSC_SET(fte_match_set_lyr_2_4, headers_v, ethertype,
			ntohs(match->key->n_proto));
		XSC_SET_FTE_MATCH_ATTR(attr, ETH_TYPE);
	}
}

u8 xsc_tc_get_ip_version(struct xsc_flow_spec *spec, bool outer)
{
	void *headers_v;
	u16 ethertype;
	u8 ip_type;

	if (outer)
		headers_v = XSC_ADDR_OF(fte_match_param, spec->match_value, outer_headers);
	else
		headers_v = XSC_ADDR_OF(fte_match_param, spec->match_value, inner_headers);

	ip_type = XSC_GET(fte_match_set_lyr_2_4, headers_v, ip_type);
	/* Return ip_version converted from ethertype anyway */
	if (!ip_type) {
		ethertype = XSC_GET(fte_match_set_lyr_2_4, headers_v, ethertype);
		if (ethertype == ETH_P_IP || ethertype == ETH_P_ARP)
			ip_type = 4;
		else if (ethertype == ETH_P_IPV6)
			ip_type = 6;
	}
	return ip_type;
}

static void *get_match_inner_headers_criteria(struct xsc_flow_spec *spec)
{
	return XSC_ADDR_OF(fte_match_param, spec->match_mask,
			    inner_headers);
}

static void *get_match_inner_headers_value(struct xsc_flow_spec *spec)
{
	return XSC_ADDR_OF(fte_match_param, spec->match_value,
			    inner_headers);
}

static void *get_match_outer_headers_criteria(struct xsc_flow_spec *spec)
{
	return XSC_ADDR_OF(fte_match_param, spec->match_mask,
			    outer_headers);
}

static void *get_match_outer_headers_value(struct xsc_flow_spec *spec)
{
	return XSC_ADDR_OF(fte_match_param, spec->match_value,
			    outer_headers);
}

void *xsc_get_match_headers_value(u32 flags, struct xsc_flow_spec *spec)
{
	return (flags & XSC_FLOW_CONTEXT_ACTION_DECAP) ?
		get_match_inner_headers_value(spec) :
		get_match_outer_headers_value(spec);
}

void *xsc_get_match_headers_criteria(u32 flags, struct xsc_flow_spec *spec)
{
	return (flags & XSC_FLOW_CONTEXT_ACTION_DECAP) ?
		get_match_inner_headers_criteria(spec) :
		get_match_outer_headers_criteria(spec);
}

static int xsc_flower_parse_meta(struct net_device *filter_dev,
				 struct flow_cls_offload *f,
				 struct xsc_flow_attr *attr)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct netlink_ext_ack *extack = f->common.extack;
	struct net_device *ingress_dev;
	struct flow_match_meta match;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return 0;

	flow_rule_match_meta(rule, &match);
	if (!match.mask->ingress_ifindex)
		return 0;

	if (match.mask->ingress_ifindex != 0xFFFFFFFF) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported ingress ifindex mask");
		netdev_err(filter_dev, "Unsupported ingress ifindex mask\n");
		return -EOPNOTSUPP;
	}

	ingress_dev = __dev_get_by_index(dev_net(filter_dev),
					 match.key->ingress_ifindex);
	if (!ingress_dev) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Can't find the ingress port to match on");
		netdev_err(filter_dev, "Can't find the ingress port to match on\n");
		return -ENOENT;
	}

	if (ingress_dev != filter_dev) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Can't match on the ingress filter port");
		netdev_err(filter_dev, "Can't match on the ingress filter port\n");
		return -EOPNOTSUPP;
	}

	attr->flags |= XSC_ATTR_FLAG_IN_PORT;

	return 0;
}

static int __parse_cls_flower(struct xsc_adapter *priv,
			      struct xsc_tc_flow *flow,
			      struct xsc_flow_spec *spec,
			      struct flow_cls_offload *f,
			      struct net_device *filter_dev,
			      u8 *inner_match_level, u8 *outer_match_level)
{
	struct netlink_ext_ack *extack = f->common.extack;
	void *headers_c = XSC_ADDR_OF(fte_match_param, spec->match_mask,
				       outer_headers);
	void *headers_v = XSC_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	void *misc_c = XSC_ADDR_OF(fte_match_param, spec->match_mask,
				    misc);
	void *misc_v = XSC_ADDR_OF(fte_match_param, spec->match_value,
				    misc);
	struct xsc_ifc_flow_attr *attr = &spec->match_attr;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_dissector *dissector = rule->match.dissector;
	enum fs_flow_table_type fs_type;
	bool match_inner_ecn = false;
	u16 addr_type = 0;
	u8 ip_proto = 0;
	u8 *match_level;
	u64 used_keys = 0;
	int err;
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	fs_type = xsc_is_eswitch_flow(flow) ? FS_FT_FDB : FS_FT_NIC_RX;
	match_level = outer_match_level;

	if (dissector->used_keys &
	    ~(BIT_ULL(FLOW_DISSECTOR_KEY_META) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IP)  |
#ifdef CONFIG_XSC_OFFLOAD_CT
	      BIT_ULL(FLOW_DISSECTOR_KEY_CT) |
#endif
#ifdef CONFIG_XSC_OFFLOAD_TUN
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_PORTS)	|
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IP) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_OPTS) |
#endif
	      BIT_ULL(FLOW_DISSECTOR_KEY_ICMP))) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported key");
		used_keys = (u64)dissector->used_keys;
		netdev_err(priv->netdev, "Unsupported key used: 0x%llx\n",
			   used_keys);
		return -EOPNOTSUPP;
	}

	esw_debug(priv->xdev, "start to parse cls flower\n");

#ifdef CONFIG_XSC_OFFLOAD_TUN
	if (xsc_get_tc_tun(filter_dev)) {
		bool match_inner = false;

		err = parse_tunnel_attr(priv, flow, spec, f, filter_dev,
					outer_match_level, &match_inner);
		if (err)
			return err;

		if (match_inner) {
			/* header pointers should point to the inner headers
			 * if the packet was decapsulated already.
			 * outer headers are set by parse_tunnel_attr.
			 */
			match_level = inner_match_level;
			headers_c = get_match_inner_headers_criteria(spec);
			headers_v = get_match_inner_headers_value(spec);
		}

		err = xsc_tc_verify_tunnel_ecn(priv, f, &match_inner_ecn);
		if (err)
			return err;
	}
#endif

	err = xsc_flower_parse_meta(filter_dev, f, flow->attr);
	if (err)
		return err;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		addr_type = match.key->addr_type;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		xsc_tc_set_ethertype(priv->xdev, &match,
				     match_level == outer_match_level,
				     headers_c, headers_v, (u64 *)&attr->match_fields);

		if (match.mask->n_proto)
			*match_level = XSC_MATCH_L2;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN) ||
	    is_vlan_dev(filter_dev)) {
		struct flow_dissector_key_vlan filter_dev_mask;
		struct flow_dissector_key_vlan filter_dev_key;
		struct flow_match_vlan match;

		if (is_vlan_dev(filter_dev)) {
			match.key = &filter_dev_key;
			match.key->vlan_id = vlan_dev_vlan_id(filter_dev);
			match.key->vlan_tpid = vlan_dev_vlan_proto(filter_dev);
			match.key->vlan_priority = 0;
			match.mask = &filter_dev_mask;
			memset(match.mask, 0xff, sizeof(*match.mask));
			match.mask->vlan_priority = 0;
		} else {
			flow_rule_match_vlan(rule, &match);
		}
		if (match.mask->vlan_id ||
		    match.mask->vlan_priority ||
		    match.mask->vlan_tpid) {
			XSC_SET(fte_match_set_lyr_2_4, headers_c, vlan_id,
				match.mask->vlan_id);
			XSC_SET(fte_match_set_lyr_2_4, headers_v, vlan_id,
				match.key->vlan_id);
			if (match.mask->vlan_id)
				XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, VLAN_ID);

			XSC_SET(fte_match_set_lyr_2_4, headers_c, vlan_pcp,
				match.mask->vlan_priority);
			XSC_SET(fte_match_set_lyr_2_4, headers_v, vlan_pcp,
				match.key->vlan_priority);
			if (match.mask->vlan_priority)
				XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, VLAN_PCP);

			*match_level = XSC_MATCH_L2;
		}
	} else if (*match_level != XSC_MATCH_NONE) {
		/* cvlan_tag enabled in match criteria and
		 * disabled in match value means both S & C tags
		 * don't exist (untagged of both)
		 */
		*match_level = XSC_MATCH_L2;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_cvlan(rule, &match);
		if (match.mask->vlan_id ||
		    match.mask->vlan_priority ||
		    match.mask->vlan_tpid) {
			if (!esw->esw_caps.outer_second_vid) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Matching on CVLAN is not supported");
				netdev_err(priv->netdev, "Matching on CVLAN is not supported\n");
				return -EOPNOTSUPP;
			}

			XSC_SET(fte_match_set_lyr_2_4, misc_c, cvlan_id,
				match.mask->vlan_id);
			XSC_SET(fte_match_set_lyr_2_4, misc_v, cvlan_id,
				match.key->vlan_id);
			if (match.mask->vlan_id)
				XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, CVLAN_ID);

			XSC_SET(fte_match_set_lyr_2_4, misc_c, cvlan_pcp,
				match.mask->vlan_priority);
			XSC_SET(fte_match_set_lyr_2_4, misc_v, cvlan_pcp,
				match.key->vlan_priority);
			if (match.mask->vlan_priority)
				XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, CVLAN_PCP);
			//TODO: need add cvlan_ethtype value and mask
			*match_level = XSC_MATCH_L2;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);
		memcpy(XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_c, dst_mac),
		       match.mask->dst, 6);
		memcpy(XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_v, dst_mac),
		       match.key->dst, 6);

		memcpy(XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_c, src_mac),
		       match.mask->src, 6);
		memcpy(XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_v, src_mac),
		       match.key->src, 6);

		if (!is_zero_ether_addr(match.mask->src)) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, ETH_SRC);
			*match_level = XSC_MATCH_L2;
		}

		if (!is_zero_ether_addr(match.mask->dst)) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, ETH_DST);
			*match_level = XSC_MATCH_L2;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		ip_proto = match.key->ip_proto;

		XSC_SET(fte_match_set_lyr_2_4, headers_c, tp_type,
			match.mask->ip_proto);
		XSC_SET(fte_match_set_lyr_2_4, headers_v, tp_type,
			match.key->ip_proto);

		if (match.mask->ip_proto) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, TP_TYPE);
			*match_level = XSC_MATCH_L3;
		}
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		XSC_SET(fte_match_set_lyr_2_4, headers_c, ipv4.sip,
			match.mask->src);
		XSC_SET(fte_match_set_lyr_2_4, headers_v, ipv4.sip,
			match.key->src);

		XSC_SET(fte_match_set_lyr_2_4, headers_c, ipv4.dip,
			match.mask->dst);
		XSC_SET(fte_match_set_lyr_2_4, headers_v, ipv4.dip,
			match.key->dst);

		if (match.mask->src) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, SRC_IPV4);
			*match_level = XSC_MATCH_L3;
		}

		if (match.mask->dst) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, DST_IPV4);
			*match_level = XSC_MATCH_L3;
		}
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);
		memcpy((u8 *)XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_c, ipv6.src_addr),
		       (u8 *)&match.mask->src, 16);

		memcpy((u8 *)XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_v, ipv6.src_addr),
		       (u8 *)&match.key->src, 16);

		memcpy((u8 *)XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_c, ipv6.dst_addr),
		       (u8 *)&match.mask->dst, 16);

		memcpy((u8 *)XSC_ADDR_OF(fte_match_set_lyr_2_4, headers_v, ipv6.dst_addr),
		       (u8 *)&match.key->dst, 16);

		if (ipv6_addr_type(&match.mask->src) != IPV6_ADDR_ANY) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, SRC_IPV6);
			*match_level = XSC_MATCH_L3;
		}

		if (ipv6_addr_type(&match.mask->dst) != IPV6_ADDR_ANY) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, DST_IPV6);
			*match_level = XSC_MATCH_L3;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);
		if (match_inner_ecn) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Matching on ECN is not supported");
			netdev_err(priv->netdev, "Matching on ECN is not supported\n");
			return -EOPNOTSUPP;
		}

		XSC_SET(fte_match_set_lyr_2_4, headers_c, dscp,
			match.mask->tos >> 2);
		XSC_SET(fte_match_set_lyr_2_4, headers_v, dscp,
			match.key->tos >> 2);

		XSC_SET(fte_match_set_lyr_2_4, headers_c, ttl_hoplimit,
			match.mask->ttl);
		XSC_SET(fte_match_set_lyr_2_4, headers_v, ttl_hoplimit,
			match.key->ttl);

		if (match.mask->tos) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, DSCP);
			*match_level = XSC_MATCH_L3;
		}

		if (match.mask->ttl) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, TTL);
			*match_level = XSC_MATCH_L3;
		}
	}

	/* ***  L3 attributes parsing up to here *** */

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		switch (ip_proto) {
		case IPPROTO_TCP:
			XSC_SET(fte_match_set_lyr_2_4, headers_c, sport, ntohs(match.mask->src));
			XSC_SET(fte_match_set_lyr_2_4, headers_v, sport, ntohs(match.key->src));

			XSC_SET(fte_match_set_lyr_2_4, headers_c, dport, ntohs(match.mask->dst));
			XSC_SET(fte_match_set_lyr_2_4, headers_v, dport, ntohs(match.key->dst));
			break;

		case IPPROTO_UDP:
			XSC_SET(fte_match_set_lyr_2_4, headers_c, sport, ntohs(match.mask->src));
			XSC_SET(fte_match_set_lyr_2_4, headers_v, sport, ntohs(match.key->src));

			XSC_SET(fte_match_set_lyr_2_4, headers_c, dport, ntohs(match.mask->dst));
			XSC_SET(fte_match_set_lyr_2_4, headers_v, dport, ntohs(match.key->dst));
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack,
					   "Only UDP and TCP transports are supported for L4 matching");
			netdev_err(priv->netdev,
				   "Only UDP and TCP transport are supported\n");
			return -EINVAL;
		}

		if (match.mask->src) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, SPORT);
			*match_level = XSC_MATCH_L4;
		}
		if (match.mask->dst) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, DPORT);
			*match_level = XSC_MATCH_L4;
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ICMP)) {
		struct flow_match_icmp match;

		flow_rule_match_icmp(rule, &match);
		switch (ip_proto) {
		case IPPROTO_ICMP:
			XSC_SET(fte_match_set_lyr_2_4, misc_c, icmp_type, match.mask->type);
			XSC_SET(fte_match_set_lyr_2_4, misc_v, icmp_type, match.key->type);

			XSC_SET(fte_match_set_lyr_2_4, misc_c, icmp_code, match.mask->code);
			XSC_SET(fte_match_set_lyr_2_4, misc_v, icmp_code, match.key->code);
			break;
		case IPPROTO_ICMPV6:
			XSC_SET(fte_match_set_lyr_2_4, misc_c, icmp_type, match.mask->type);
			XSC_SET(fte_match_set_lyr_2_4, misc_v, icmp_type, match.key->type);

			XSC_SET(fte_match_set_lyr_2_4, misc_c, icmp_code, match.mask->code);
			XSC_SET(fte_match_set_lyr_2_4, misc_v, icmp_code, match.key->code);
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack,
					   "Code and type matching only with ICMP and ICMPv6");
			netdev_err(priv->netdev,
				   "Code and type matching only with ICMP and ICMPv6\n");
			return -EINVAL;
		}

		if (match.mask->type) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, ICMP_TYPE);
			*match_level = XSC_MATCH_L4;
		}
		if (match.mask->code) {
			XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, ICMP_CODE);
			*match_level = XSC_MATCH_L4;
		}
	}

	return 0;
}

static int parse_cls_flower(struct xsc_adapter *priv, struct xsc_tc_flow *flow,
			    struct xsc_flow_spec *spec, struct flow_cls_offload *f,
			    struct net_device *filter_dev)
{
	u8 inner_match_level, outer_match_level;
	int err;

	inner_match_level = XSC_MATCH_NONE;
	outer_match_level = XSC_MATCH_NONE;

	err = __parse_cls_flower(priv, flow, spec, f, filter_dev,
				 &inner_match_level, &outer_match_level);

	flow->attr->inner_match_level = inner_match_level;
	flow->attr->outer_match_level = outer_match_level;

	return err;
}

struct xsc_fields {
	u8  field;
	u16 field_bsize;
	u32 field_mask;
	u16 offset;
	u32 match_offset;
};

#define OFFLOAD(fw_field, field_bsize, field_mask, field, off, match_field) \
		{XSC_ACTION_SET_ ## fw_field, field_bsize, field_mask, \
		 offsetof(struct pedit_headers, field) + (off), \
		 XSC_BYTE_OFF(fte_match_set_lyr_2_4, match_field)}

/* masked values are the same and there are no rewrites that do not have a
 * match.
 */
#define SAME_VAL_MASK(type, valp, maskp, matchvalp, matchmaskp) ({ \
	type matchmaskx = *(type *)(matchmaskp); \
	type matchvalx = *(type *)(matchvalp); \
	type maskx = *(type *)(maskp); \
	type valx = *(type *)(valp); \
	\
	(valx & maskx) == (matchvalx & matchmaskx) && !(maskx & (maskx ^ \
								 matchmaskx)); \
})

static bool cmp_val_mask(void *valp, void *maskp, void *matchvalp,
			 void *matchmaskp, u8 bsize)
{
	bool same = false;

	switch (bsize) {
	case 8:
		same = SAME_VAL_MASK(u8, valp, maskp, matchvalp, matchmaskp);
		break;
	case 16:
		same = SAME_VAL_MASK(u16, valp, maskp, matchvalp, matchmaskp);
		break;
	case 32:
		same = SAME_VAL_MASK(u32, valp, maskp, matchvalp, matchmaskp);
		break;
	}

	return same;
}

static struct xsc_fields fields[] = {
	OFFLOAD(DST_MAC, 32, U32_MAX, eth.h_dest[0], 0, dst_mac[0]),
	OFFLOAD(DST_MAC, 16, U16_MAX, eth.h_dest[4], 0, dst_mac[4]),
	OFFLOAD(SRC_MAC, 32, U32_MAX, eth.h_source[0], 0, src_mac[0]),
	OFFLOAD(SRC_MAC, 16, U16_MAX, eth.h_source[4], 0, src_mac[4]),
	OFFLOAD(VLAN_VID, 12, 0x1fff, vlan.h_vlan_TCI, 0, vlan_id),
	OFFLOAD(VLAN_PCP, 3, 0xe000, vlan.h_vlan_TCI, 0, vlan_pcp),

	OFFLOAD(DSCP, 8, 0xfc, ip4.tos, 0, dscp),
	OFFLOAD(TTL,  8, U8_MAX, ip4.ttl, 0, ttl_hoplimit),
	OFFLOAD(SRC_IPV4,  32, U32_MAX, ip4.saddr, 0, ipv4.sip),
	OFFLOAD(DST_IPV4,  32, U32_MAX, ip4.daddr, 0, ipv4.dip),

	OFFLOAD(SRC_IPV6, 32, U32_MAX, ip6.saddr.s6_addr32[0], 0,
		ipv6.src_addr[0]),
	OFFLOAD(SRC_IPV6,  32, U32_MAX, ip6.saddr.s6_addr32[1], 0,
		ipv6.src_addr[4]),
	OFFLOAD(SRC_IPV6,  32, U32_MAX, ip6.saddr.s6_addr32[2], 0,
		ipv6.src_addr[8]),
	OFFLOAD(SRC_IPV6,   32, U32_MAX, ip6.saddr.s6_addr32[3], 0,
		ipv6.src_addr[12]),
	OFFLOAD(DST_IPV6, 32, U32_MAX, ip6.daddr.s6_addr32[0], 0,
		ipv6.dst_addr[0]),
	OFFLOAD(DST_IPV6,  32, U32_MAX, ip6.daddr.s6_addr32[1], 0,
		ipv6.dst_addr[4]),
	OFFLOAD(DST_IPV6,  32, U32_MAX, ip6.daddr.s6_addr32[2], 0,
		ipv6.dst_addr[8]),
	OFFLOAD(DST_IPV6,   32, U32_MAX, ip6.daddr.s6_addr32[3], 0,
		ipv6.dst_addr[12]),

	OFFLOAD(TTL, 8,  U8_MAX, ip6.hop_limit, 0, ttl_hoplimit),
	OFFLOAD(DSCP, 16,  0x0fc0, ip6, 0, dscp),

	OFFLOAD(TP_SPORT, 16, U16_MAX, tcp.source,  0, sport),
	OFFLOAD(TP_DPORT, 16, U16_MAX, tcp.dest,    0, dport),

	OFFLOAD(TP_SPORT, 16, U16_MAX, udp.source, 0, sport),
	OFFLOAD(TP_DPORT, 16, U16_MAX, udp.dest,   0, dport),
};

static u32 mask_field_get(void *mask, struct xsc_fields *f)
{
	switch (f->field_bsize) {
	case 32:
		return be32_to_cpu(*(__be32 *)mask) & f->field_mask;
	case 16:
		return be16_to_cpu(*(__be16 *)mask) & (u16)f->field_mask;
	default:
		return *(u8 *)mask & (u8)f->field_mask;
	}
}

static void mask_field_clear(void *mask, struct xsc_fields *f)
{
	switch (f->field_bsize) {
	case 32:
		*(__be32 *)mask &= ~cpu_to_be32(f->field_mask);
		break;
	case 16:
		*(__be16 *)mask &= ~cpu_to_be16((u16)f->field_mask);
		break;
	default:
		*(u8 *)mask &= ~(u8)f->field_mask;
		break;
	}
}

static int offload_pedit_fields(struct xsc_adapter *priv,
				int namespace,
				struct xsc_tc_flow_parse_attr *parse_attr,
				u32 *action_flags,
				struct netlink_ext_ack *extack)
{
	struct pedit_headers *set_masks, *add_masks, *set_vals, *add_vals;
	struct pedit_headers_action *hdrs = parse_attr->hdrs;
	void *headers_c, *headers_v, *vals_p;
	struct xsc_ifc_set_action_in *action;
	struct xsc_tc_mod_hdr_acts *mod_acts;
	void *s_masks_p, *a_masks_p;
	int i, first;
	struct xsc_fields *f;
	unsigned long mask;
	u32 s_mask, a_mask;
	u8 cmd;

	mod_acts = &parse_attr->mod_hdr_acts;
	headers_c = xsc_get_match_headers_criteria(*action_flags, &parse_attr->spec);
	headers_v = xsc_get_match_headers_value(*action_flags, &parse_attr->spec);

	set_masks = &hdrs[TCA_PEDIT_KEY_EX_CMD_SET].masks;
	add_masks = &hdrs[TCA_PEDIT_KEY_EX_CMD_ADD].masks;
	set_vals = &hdrs[TCA_PEDIT_KEY_EX_CMD_SET].vals;
	add_vals = &hdrs[TCA_PEDIT_KEY_EX_CMD_ADD].vals;

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		bool skip;

		f = &fields[i];
		s_masks_p = (void *)set_masks + f->offset;
		a_masks_p = (void *)add_masks + f->offset;

		s_mask = mask_field_get(s_masks_p, f);
		a_mask = mask_field_get(a_masks_p, f);

		if (a_mask) {
			NL_SET_ERR_MSG_MOD(extack,
					   "can't support add new field");
			netdev_warn(priv->netdev,
				    "xsc: can't support add new field (%d)\n",
				    f->field);
			return -EOPNOTSUPP;
		}
		if (!s_mask)
			continue;

		skip = false;
		if (s_mask) {
			void *match_mask = headers_c + f->match_offset;
			void *match_val = headers_v + f->match_offset;

			cmd  = XSC_ACTION_TYPE_SET;
			mask = s_mask;
			vals_p = (void *)set_vals + f->offset;
			/* don't rewrite if we have a match on the same value */
			if (f->field != XSC_ACTION_SET_SRC_IPV6 &&
			    f->field != XSC_ACTION_SET_DST_IPV6 &&
			    f->field != XSC_ACTION_SET_SRC_MAC &&
			    f->field != XSC_ACTION_SET_DST_MAC &&
			    cmp_val_mask(vals_p, s_masks_p, match_val, match_mask, f->field_bsize))
				skip = false;
			/* clear to denote we consumed this field */
			mask_field_clear(s_masks_p, f);
		} else {
			cmd  = XSC_ACTION_TYPE_ADD;
			mask = a_mask;
			vals_p = (void *)add_vals + f->offset;
			/* add 0 is no change */
			if (!mask_field_get(vals_p, f))
				skip = true;
			/* clear to denote we consumed this field */
			mask_field_clear(a_masks_p, f);
		}
		if (skip)
			continue;

		if (mask != f->field_mask) {
			NL_SET_ERR_MSG_MOD(extack,
					   "rewrite of few sub-fields isn't supported");
			netdev_warn(priv->netdev,
				    "xsc: rewrite of few sub-fields (mask %lx) isn't offloaded\n",
				    mask);
			return -EOPNOTSUPP;
		}

		action = (struct xsc_ifc_set_action_in *)xsc_mod_hdr_alloc(priv->xdev,
									   namespace, mod_acts);
		if (IS_ERR(action)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "too many pedit actions, can't offload");
			netdev_err(priv->netdev, "xsc: parsed %d pedit actions, can't do more\n",
				   mod_acts->num_actions);
			return PTR_ERR(action);
		}

		action->action_type = cmd;
		action->field = f->field;

		if (cmd == XSC_ACTION_TYPE_SET) {
			action->offset = 0;
			/* length is num of bits to be written, zero means length of 32 */
			action->length = f->field_bsize;
		}

		first = find_first_bit(&mask, f->field_bsize);
		if (f->field_bsize == 32)
			*(u32 *)action->data = (ntohl(*(__be32 *)vals_p) & f->field_mask) >> first;
		else if (f->field_bsize == 16)
			*(u16 *)action->data = (ntohs(*(__be16 *)vals_p) & f->field_mask) >> first;
		else if (f->field_bsize == 8)
			*(u8 *)action->data = (*(u8 *)vals_p & f->field_mask) >> first;
		++mod_acts->num_actions;
	}

	return 0;
}

static const struct pedit_headers zero_masks = {};

static int verify_offload_pedit_fields(struct xsc_adapter *priv,
				       struct xsc_tc_flow_parse_attr *parse_attr,
				       struct netlink_ext_ack *extack)
{
	struct pedit_headers *cmd_masks;
	u8 cmd = TCA_PEDIT_KEY_EX_CMD_SET;

//	for (cmd = 0; cmd < __PEDIT_CMD_MAX; cmd++) {
		cmd_masks = &parse_attr->hdrs[cmd].masks;
		if (memcmp(cmd_masks, &zero_masks, sizeof(zero_masks))) {
			NL_SET_ERR_MSG_MOD(extack, "attempt to offload an unsupported field");
			netdev_warn(priv->netdev,
				    "attempt to offload an unsupported field (cmd %d)\n", cmd);
			print_hex_dump(KERN_WARNING, "mask: ", DUMP_PREFIX_ADDRESS,
				       16, 1, cmd_masks, sizeof(zero_masks), true);
			return -EOPNOTSUPP;
		}
//	}

	return 0;
}

static int alloc_tc_pedit_action(struct xsc_adapter *priv, int namespace,
				 struct xsc_tc_flow_parse_attr *parse_attr,
				 u32 *action_flags,
				 struct netlink_ext_ack *extack)
{
	int err;

	err = offload_pedit_fields(priv, namespace, parse_attr, action_flags, extack);
	if (err)
		goto out_dealloc_parsed_actions;

	err = verify_offload_pedit_fields(priv, parse_attr, extack);
	if (err)
		goto out_dealloc_parsed_actions;

	return 0;

out_dealloc_parsed_actions:
	xsc_mod_hdr_dealloc(&parse_attr->mod_hdr_acts);
	return err;
}

struct ip_ttl_word {
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
};

struct ipv6_hoplimit_word {
	__be16	payload_len;
	__u8	nexthdr;
	__u8	hop_limit;
};

static bool
is_flow_action_modify_ip_header(struct flow_action *flow_action)
{
	const struct flow_action_entry *act;
	u32 mask, offset;
	u8 htype;
	int i;

	/* For IPv4 & IPv6 header check 4 byte word,
	 * to determine that modified fields
	 * are NOT ttl & hop_limit only.
	 */
	flow_action_for_each(i, act, flow_action) {
		if (act->id != FLOW_ACTION_MANGLE &&
		    act->id != FLOW_ACTION_ADD)
			continue;

		htype = act->mangle.htype;
		offset = act->mangle.offset;
		mask = ~act->mangle.mask;

		if (htype == FLOW_ACT_MANGLE_HDR_TYPE_IP4) {
			struct ip_ttl_word *ttl_word =
				(struct ip_ttl_word *)&mask;

			if (offset != offsetof(struct iphdr, ttl) ||
			    ttl_word->protocol ||
			    ttl_word->check)
				return true;
		} else if (htype == FLOW_ACT_MANGLE_HDR_TYPE_IP6) {
			struct ipv6_hoplimit_word *hoplimit_word =
				(struct ipv6_hoplimit_word *)&mask;

			if (offset != offsetof(struct ipv6hdr, payload_len) ||
			    hoplimit_word->payload_len ||
			    hoplimit_word->nexthdr)
				return true;
		}
	}

	return false;
}

static bool modify_header_match_supported(struct xsc_adapter *priv,
					  struct xsc_flow_spec *spec,
					  struct flow_action *flow_action,
					  u32 actions,
					  struct netlink_ext_ack *extack)
{
	bool modify_ip_header;
	void *headers_c;
	void *headers_v;
	u16 ethertype;
	u8 ip_proto;

	headers_c = xsc_get_match_headers_criteria(actions, spec);
	headers_v = xsc_get_match_headers_value(actions, spec);
	ethertype = XSC_GET(fte_match_set_lyr_2_4, headers_v, ethertype);

	/* for non-IP we only re-write MACs, so we're okay */
	if (XSC_GET(fte_match_set_lyr_2_4, headers_c, ip_type) == 0 &&
	    ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		goto out_ok;

	modify_ip_header = is_flow_action_modify_ip_header(flow_action);
	ip_proto = XSC_GET(fte_match_set_lyr_2_4, headers_v, tp_type);
	if (modify_ip_header && ip_proto != IPPROTO_TCP &&
	    ip_proto != IPPROTO_UDP && ip_proto != IPPROTO_ICMP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "can't offload re-write of non TCP/UDP");
		netdev_info(priv->netdev, "can't offload re-write of ip proto %d\n",
			    ip_proto);
		return false;
	}

out_ok:
	return true;
}

static bool actions_match_supported_fdb(struct xsc_adapter *priv,
					struct xsc_tc_flow *flow,
					struct netlink_ext_ack *extack)
{
	struct xsc_esw_flow_attr *esw_attr = flow->attr->esw_attr;
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	if (esw_attr->split_count > 0 && !esw->esw_caps.fdb_multi_path_to_table) {
		NL_SET_ERR_MSG_MOD(extack,
				   "current firmware doesn't support split rule for port mirroring");
		netdev_warn_once(priv->netdev,
				 "current firmware doesn't support split rule for port mirroring\n");
		return false;
	}

	return true;
}

static bool
actions_match_supported(struct xsc_adapter *priv,
			struct flow_action *flow_action,
			u32 actions,
			struct xsc_tc_flow_parse_attr *parse_attr,
			struct xsc_tc_flow *flow,
			struct netlink_ext_ack *extack)
{
	if (actions & XSC_FLOW_CONTEXT_ACTION_MOD_HDR &&
	    !modify_header_match_supported(priv, &parse_attr->spec, flow_action, actions,
					   extack))
		return false;

	if (xsc_is_eswitch_flow(flow) &&
	    !actions_match_supported_fdb(priv, flow, extack))
		return false;

	return true;
}

u64 xsc_query_nic_system_image_guid(struct xsc_core_device *xdev)
{
	if (xdev->board_info->guid)
		return xdev->board_info->guid;

	xsc_cmd_query_guid(xdev);
	return xdev->board_info->guid;
}

bool xsc_same_hw_devs(struct xsc_adapter *priv, struct xsc_adapter *peer_priv)
{
	struct xsc_core_device *fxdev, *pxdev;
	u64 fsystem_guid, psystem_guid;

	fxdev = priv->xdev;
	pxdev = peer_priv->xdev;

	fsystem_guid = xsc_query_nic_system_image_guid(fxdev);
	psystem_guid = xsc_query_nic_system_image_guid(pxdev);

	return (fsystem_guid == psystem_guid);
}

static int
actions_prepare_mod_hdr_actions(struct xsc_adapter *priv,
				struct xsc_tc_flow *flow,
				struct xsc_flow_attr *attr,
				struct netlink_ext_ack *extack)
{
	struct xsc_tc_flow_parse_attr *parse_attr = attr->parse_attr;
	struct pedit_headers_action *hdrs = parse_attr->hdrs;
	enum xsc_flow_namespace_type ns_type;
	int err;

	if (!hdrs[TCA_PEDIT_KEY_EX_CMD_SET].pedits &&
	    !hdrs[TCA_PEDIT_KEY_EX_CMD_ADD].pedits)
		return 0;

	ns_type = xsc_get_flow_namespace_id(flow);

	err = alloc_tc_pedit_action(priv, ns_type, parse_attr, &attr->action, extack);
	if (err)
		return err;

	if (parse_attr->mod_hdr_acts.num_actions > 0)
		return 0;

	/* In case all pedit actions are skipped, remove the MOD_HDR flag. */
	attr->action &= ~XSC_FLOW_CONTEXT_ACTION_MOD_HDR;
	xsc_mod_hdr_dealloc(&parse_attr->mod_hdr_acts);

	if (ns_type != XSC_FLOW_NAMESPACE_FDB)
		return 0;

	if (!((attr->action & XSC_FLOW_CONTEXT_ACTION_VLAN_POP) ||
	      (attr->action & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH)))
		attr->esw_attr->split_count = 0;

	return 0;
}

static struct xsc_flow_attr*
xsc_clone_flow_attr_for_post_act(struct xsc_flow_attr *attr,
				 enum xsc_flow_namespace_type ns_type)
{
	struct xsc_tc_flow_parse_attr *parse_attr;
	u32 attr_sz = ns_to_attr_sz(ns_type);
	struct xsc_flow_attr *attr2;

	attr2 = xsc_alloc_flow_attr(ns_type);
	parse_attr = kvzalloc(sizeof(*parse_attr), GFP_KERNEL);
	if (!attr2 || !parse_attr) {
		kvfree(parse_attr);
		kfree(attr2);
		return NULL;
	}

	memcpy(attr2, attr, attr_sz);
	INIT_LIST_HEAD(&attr2->list);
	parse_attr->filter_dev = attr->parse_attr->filter_dev;
	attr2->action = 0;
	attr2->flags = 0;
	attr2->parse_attr = parse_attr;
	return attr2;
}

struct xsc_flow_attr *xsc_tc_get_encap_attr(struct xsc_tc_flow *flow)
{
	struct xsc_esw_flow_attr *esw_attr;
	struct xsc_flow_attr *attr;
	int i;

	list_for_each_entry(attr, &flow->attrs, list) {
		esw_attr = attr->esw_attr;
		for (i = 0; i < XSC_MAX_FLOW_FWD_VPORTS; i++) {
			if (esw_attr->dests[i].flags & XSC_ESW_DEST_ENCAP)
				return attr;
		}
	}

	return NULL;
}

void
xsc_tc_unoffload_flow_post_acts(struct xsc_tc_flow *flow)
{
	struct xsc_post_act *post_act = get_post_action(flow->priv);
	struct xsc_flow_attr *attr;

	list_for_each_entry(attr, &flow->attrs, list) {
		if (list_is_last(&attr->list, &flow->attrs))
			break;

		xsc_tc_post_act_unoffload(post_act, attr->post_act_handle);
	}
}

static void
free_flow_post_acts(struct xsc_tc_flow *flow)
{
	struct xsc_flow_attr *attr, *tmp;

	list_for_each_entry_safe(attr, tmp, &flow->attrs, list) {
		if (list_is_last(&attr->list, &flow->attrs))
			break;

		xsc_free_flow_attr_actions(flow, attr);

		list_del(&attr->list);
		kvfree(attr->parse_attr);
		kfree(attr);
	}
}

int
xsc_tc_offload_flow_post_acts(struct xsc_tc_flow *flow)
{
	struct xsc_post_act *post_act = get_post_action(flow->priv);
	struct xsc_flow_attr *attr;
	int err = 0;

	list_for_each_entry(attr, &flow->attrs, list) {
		if (list_is_last(&attr->list, &flow->attrs))
			break;

		err = xsc_tc_post_act_offload(post_act, attr->post_act_handle);
		if (err)
			break;
	}

	return err;
}

/* TC filter rule HW translation:
 *
 * +---------------------+
 * + ft prio (tc chain)  +
 * + original match      +
 * +---------------------+
 *           |
 *           | if multi table action
 *           |
 *           v
 * +---------------------+
 * + post act ft         |<----.
 * + match fte id        |     | split on multi table action
 * + do actions          |-----'
 * +---------------------+
 *           |
 *           |
 *           v
 * Do rest of the actions after last multi table action.
 */
static int
alloc_flow_post_acts(struct xsc_tc_flow *flow, struct netlink_ext_ack *extack)
{
	struct xsc_post_act *post_act = get_post_action(flow->priv);
	struct xsc_flow_attr *attr, *next_attr = NULL;
	struct xsc_post_act_handle *handle;
	int err;

	/* This is going in reverse order as needed.
	 * The first entry is the last attribute.
	 */
	list_for_each_entry(attr, &flow->attrs, list) {
		if (!next_attr) {
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
			/* Set counter action on last post act rule. */
			attr->action |= XSC_FLOW_CONTEXT_ACTION_COUNT;
#endif
		}

		if (next_attr && !(attr->flags & XSC_ATTR_FLAG_TERMINATING)) {
			err = xsc_tc_act_set_next_post_act(flow, attr, next_attr);
			if (err)
				goto out_free;
		}

		/* Don't add post_act rule for first attr (last in the list).
		 * It's being handled by the caller.
		 */
		if (list_is_last(&attr->list, &flow->attrs))
			break;

		err = actions_prepare_mod_hdr_actions(flow->priv, flow, attr, extack);
		if (err)
			goto out_free;

		err = post_process_attr(flow, attr, extack);
		if (err)
			goto out_free;

		handle = xsc_tc_post_act_add(post_act, attr);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto out_free;
		}

		attr->post_act_handle = handle;

		if (attr->jumping_attr) {
			err = xsc_tc_act_set_next_post_act(flow, attr->jumping_attr, attr);
			if (err)
				goto out_free;
		}

		next_attr = attr;
	}

	if (flow_flag_test(flow, SLOW))
		goto out;

	err = xsc_tc_offload_flow_post_acts(flow);
	if (err)
		goto out_free;

out:
	return 0;

out_free:
	free_flow_post_acts(flow);
	return err;
}

static int
set_branch_dest_ft(struct xsc_adapter *priv, struct xsc_flow_attr *attr)
{
	struct xsc_post_act *post_act = get_post_action(priv);

	if (IS_ERR(post_act))
		return PTR_ERR(post_act);

	attr->action |= XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
	attr->dest_ft = xsc_tc_post_act_get_ft(post_act);

	return 0;
}

static int
alloc_branch_attr(struct xsc_tc_flow *flow,
		  struct xsc_tc_act_branch_ctrl *cond,
		  struct xsc_flow_attr **cond_attr,
		  u32 *jump_count,
		  struct netlink_ext_ack *extack)
{
	struct xsc_flow_attr *attr;
	int err = 0;

	*cond_attr = xsc_clone_flow_attr_for_post_act(flow->attr,
						      xsc_get_flow_namespace_id(flow));
	if (!(*cond_attr))
		return -ENOMEM;

	attr = *cond_attr;

	switch (cond->act_id) {
	case FLOW_ACTION_DROP:
		attr->action |= XSC_FLOW_CONTEXT_ACTION_DROP;
		break;
	case FLOW_ACTION_ACCEPT:
		err = set_branch_dest_ft(flow->priv, attr);
		if (err)
			goto out_err;
		break;
	default:
		err = -EOPNOTSUPP;
		goto out_err;
	}

	return err;
out_err:
	kfree(*cond_attr);
	*cond_attr = NULL;
	return err;
}

#ifdef CONFIG_XSC_OFFLOAD_CT_JUMP
static void dec_jump_count(struct flow_action_entry *act, struct xsc_tc_act *tc_act,
			   struct xsc_flow_attr *attr, struct xsc_adapter *priv,
			   struct xsc_tc_jump_state *jump_state)
{
	if (!jump_state->jump_count)
		return;

	/* Single tc action can instantiate multiple offload actions (e.g. pedit)
	 * Jump only over a tc action
	 */
	if (act->id == jump_state->last_id && act->hw_index == jump_state->last_index)
		return;

	jump_state->last_id = act->id;
	jump_state->last_index = act->hw_index;

	/* nothing to do for intermediate actions */
	if (--jump_state->jump_count > 1)
		return;

	if (jump_state->jump_count == 1) { /* last action in the jump action list */

		/* create a new attribute after this action */
		jump_state->jump_target = true;

		if (tc_act->is_terminating_action) { /* the branch ends here */
			attr->flags |= XSC_ATTR_FLAG_TERMINATING;
			attr->action |= XSC_FLOW_CONTEXT_ACTION_COUNT;
		} else { /* the branch continues executing the rest of the actions */
			struct xsc_post_act *post_act;

			attr->action |= XSC_FLOW_CONTEXT_ACTION_FWD_DEST;
			post_act = get_post_action(priv);
			attr->dest_ft = xsc_tc_post_act_get_ft(post_act);
		}
	} else if (jump_state->jump_count == 0) { /* first attr after the jump action list */
		/* This is the post action for the jumping attribute (either red or green)
		 * Use the stored jumping_attr to set the post act id on the jumping attribute
		 */
		attr->jumping_attr = jump_state->jumping_attr;
	}
}
#endif

static int
parse_branch_ctrl(struct flow_action_entry *act, struct xsc_tc_act *tc_act,
		  struct xsc_tc_flow *flow, struct xsc_flow_attr *attr,
		  struct xsc_tc_jump_state *jump_state,
		  struct netlink_ext_ack *extack)
{
	struct xsc_tc_act_branch_ctrl cond_true, cond_false;
	u32 jump_count = jump_state->jump_count;
	int err;

	if (!tc_act->get_branch_ctrl)
		return 0;

	tc_act->get_branch_ctrl(act, &cond_true, &cond_false);

	err = alloc_branch_attr(flow, &cond_true,
				&attr->branch_true, &jump_count, extack);
	if (err)
		goto out_err;

	if (jump_count)
		jump_state->jumping_attr = attr->branch_true;

	err = alloc_branch_attr(flow, &cond_false,
				&attr->branch_false, &jump_count, extack);
	if (err)
		goto err_branch_false;

	if (jump_count && !jump_state->jumping_attr)
		jump_state->jumping_attr = attr->branch_false;

	jump_state->jump_count = jump_count;

	/* branching action requires its own counter */
	attr->action |= XSC_FLOW_CONTEXT_ACTION_COUNT;
	flow_flag_set(flow, USE_ACT_STATS);

	return 0;

err_branch_false:
	free_branch_attr(flow, attr->branch_true);
out_err:
	return err;
}

static int
parse_tc_actions(struct xsc_tc_act_parse_state *parse_state,
		 struct flow_action *flow_action)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct xsc_tc_flow *flow = parse_state->flow;
	struct xsc_tc_jump_state jump_state = {};
	struct xsc_flow_attr *attr = flow->attr;
	enum xsc_flow_namespace_type ns_type;
	struct xsc_adapter *priv = flow->priv;
	struct xsc_flow_attr *prev_attr;
	struct flow_action_entry *act;
	struct xsc_tc_act *tc_act;
	int err, i, i_split = 0;
	bool is_missable;

	ns_type = xsc_get_flow_namespace_id(flow);
	list_add(&attr->list, &flow->attrs);

	flow_action_for_each(i, act, flow_action) {
		jump_state.jump_target = false;
		is_missable = false;
		prev_attr = attr;

		tc_act = xsc_tc_act_get(act->id, ns_type);
		if (!tc_act) {
			NL_SET_ERR_MSG_MOD(extack, "Not implemented offload action");
			netdev_err(priv->netdev, "Not implemented offload action\n");
			err = -EOPNOTSUPP;
			goto out_free_post_acts;
		}

		if (tc_act->can_offload && !tc_act->can_offload(parse_state, act, i, attr)) {
			err = -EOPNOTSUPP;
			goto out_free_post_acts;
		}

		err = tc_act->parse_action(parse_state, act, priv, attr);
		if (err)
			goto out_free_post_acts;

#ifdef CONFIG_XSC_OFFLOAD_CT_JUMP
		dec_jump_count(act, tc_act, attr, priv, &jump_state);
#endif

		err = parse_branch_ctrl(act, tc_act, flow, attr, &jump_state, extack);
		if (err)
			goto out_free_post_acts;

		parse_state->actions |= attr->action;

		/* Split attr for multi table act if not the last act. */
		if (jump_state.jump_target ||
		    (tc_act->is_multi_table_act &&
		    tc_act->is_multi_table_act(priv, act, attr) &&
		    i < flow_action->num_entries - 1)) {
			is_missable = tc_act->is_missable ? tc_act->is_missable(act) : false;

			err = xsc_tc_act_post_parse(parse_state, flow_action, i_split, i, attr,
						    ns_type);
			if (err)
				goto out_free_post_acts;

			attr = xsc_clone_flow_attr_for_post_act(flow->attr, ns_type);
			if (!attr) {
				err = -ENOMEM;
				goto out_free_post_acts;
			}

			i_split = i + 1;
			parse_state->if_count = 0;
			list_add(&attr->list, &flow->attrs);
		}

#ifdef CONFIG_XSC_OFFLOAD_ACT_COUNTER
		if (is_missable) {
			/* Add counter to prev, and assign act to new (next) attr */
			prev_attr->action |= XSC_FLOW_CONTEXT_ACTION_COUNT;
			flow_flag_set(flow, USE_ACT_STATS);

			attr->tc_act_cookies[attr->tc_act_cookies_count++] = act->cookie;
		}
#endif
#ifdef	CONFIG_XSC_OFFLOAD_OVS
		else if (!tc_act->stats_action)
			prev_attr->tc_act_cookies[prev_attr->tc_act_cookies_count++] = act->cookie;
#endif
	}

	err = xsc_tc_act_post_parse(parse_state, flow_action, i_split, i, attr, ns_type);
	if (err)
		goto out_free_post_acts;

	err = alloc_flow_post_acts(flow, extack);
	if (err)
		goto out_free_post_acts;

	return 0;

out_free_post_acts:
	free_flow_post_acts(flow);

	return err;
}

static int
flow_action_supported(struct flow_action *flow_action,
		      struct netlink_ext_ack *extack)
{
	if (!flow_action_has_entries(flow_action)) {
		NL_SET_ERR_MSG_MOD(extack, "Flow action doesn't have any entries");
		pr_err("Flow action doesn't have any entries\n");
		return -EINVAL;
	}

	if (!flow_action_hw_stats_check(flow_action, extack,
					FLOW_ACTION_HW_STATS_DELAYED_BIT)) {
		NL_SET_ERR_MSG_MOD(extack, "Flow action HW stats type is not supported");
		pr_err("Flow action HW stats type is not supported\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

bool same_port_devs(struct xsc_adapter *priv, struct xsc_adapter *peer_priv)
{
	return priv->xdev == peer_priv->xdev;
}

static bool same_hw_reps(struct xsc_adapter *priv,
			 struct net_device *peer_netdev)
{
	struct xsc_adapter *peer_priv;

	peer_priv = netdev_priv(peer_netdev);

	return is_xsc_eswitch_rep(priv->netdev) &&
	       is_xsc_eswitch_rep(peer_netdev) &&
	       xsc_same_hw_devs(priv, peer_priv);
}

bool xsc_is_valid_eswitch_fwd_dev(struct xsc_adapter *priv, struct net_device *out_dev)
{
	if (same_hw_reps(priv, out_dev) && xsc_lag_is_mpesw(priv->xdev))
		return true;

	return is_xsc_eswitch_rep(out_dev) &&
	       same_port_devs(priv, netdev_priv(out_dev));
}

#ifdef CONFIG_XSC_OFFLOAD_OVS
int xsc_set_fwd_to_int_port_actions(struct xsc_adapter *priv, struct xsc_flow_attr *attr,
				    int ifindex, enum xsc_tc_int_port_type type,
				    u32 *action, int out_index)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_tc_int_port_priv *int_port_priv;
	struct xsc_tc_flow_parse_attr *parse_attr;
	struct xsc_tc_int_port *dest_int_port;
	int err;

	parse_attr = attr->parse_attr;
	int_port_priv = xsc_get_int_port_priv(priv);

	dest_int_port = xsc_tc_int_port_get(int_port_priv, ifindex, type);
	if (IS_ERR(dest_int_port))
		return PTR_ERR(dest_int_port);

	err = xsc_tc_match_to_reg_set(priv->xdev, &parse_attr->mod_hdr_acts,
				      XSC_FLOW_NAMESPACE_FDB, VPORT_TO_REG,
				      xsc_tc_int_port_get_metadata(dest_int_port));
	if (err) {
		xsc_tc_int_port_put(int_port_priv, dest_int_port);
		return err;
	}

	*action |= XSC_FLOW_CONTEXT_ACTION_MOD_HDR;

	esw_attr->dest_int_port = dest_int_port;
	esw_attr->dests[out_index].flags |= XSC_ESW_DEST_CHAIN_WITH_SRC_PORT_CHANGE;
	esw_attr->split_count = out_index;

	/* Forward to root fdb for matching against the new source vport */
	attr->dest_chain = 0;

	return 0;
}
#endif

static int
parse_tc_fdb_actions(struct xsc_adapter *priv,
		     struct flow_action *flow_action,
		     struct xsc_tc_flow *flow,
		     struct netlink_ext_ack *extack)
{
	struct xsc_tc_act_parse_state *parse_state;
	struct xsc_tc_flow_parse_attr *parse_attr;
	struct xsc_flow_attr *attr = flow->attr;
	struct xsc_esw_flow_attr *esw_attr;
	struct net_device *filter_dev;
	int err;

	esw_debug(priv->xdev, "start to parse tc actions\n");

	err = flow_action_supported(flow_action, extack);
	if (err)
		return err;

	esw_attr = attr->esw_attr;
	parse_attr = attr->parse_attr;
	filter_dev = parse_attr->filter_dev;
	parse_state = &parse_attr->parse_state;
	xsc_tc_act_init_parse_state(parse_state, flow, flow_action, extack);
#ifdef CONFIG_XSC_OFFLOAD_CT
	parse_state->ct_priv = get_ct_priv(priv);
#endif

	err = parse_tc_actions(parse_state, flow_action);
	if (err) {
		esw_warn(priv->xdev, "Failed to parse tc actions, err=%d\n", err);
		return err;
	}

#ifdef CONFIG_XSC_OFFLOAD_OVS
	/* Forward to/from internal port can only have 1 dest */
	if ((netif_is_ovs_master(filter_dev) || esw_attr->dest_int_port) &&
	    esw_attr->out_count > 1) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Rules with internal port can have only one destination");
		return -EOPNOTSUPP;
	}
#endif

	/* Forward from tunnel/internal port to internal port is not supported */
#ifdef CONFIG_XSC_OFFLOAD_TUN
	if ((xsc_get_tc_tun(filter_dev) || netif_is_ovs_master(filter_dev)) &&
	    esw_attr->dest_int_port) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Forwarding from tunnel/internal port to internal port is not supported");
		return -EOPNOTSUPP;
	}
#endif

	err = actions_prepare_mod_hdr_actions(priv, flow, attr, extack);
	if (err) {
		esw_warn(priv->xdev, "Failed to parse prepare_mod_hdr_action, err=%d\n", err);
		return err;
	}

	if (!actions_match_supported(priv, flow_action, parse_state->actions,
				     parse_attr, flow, extack))
		return -EOPNOTSUPP;

	return 0;
}

static void get_flags(int flags, unsigned long *flow_flags)
{
	unsigned long __flow_flags = 0;

	if (flags & XSC_TC_FLAG(INGRESS))
		__flow_flags |= BIT(XSC_TC_FLOW_FLAG_INGRESS);
	if (flags & XSC_TC_FLAG(EGRESS))
		__flow_flags |= BIT(XSC_TC_FLOW_FLAG_EGRESS);

	if (flags & XSC_TC_FLAG(ESW_OFFLOAD))
		__flow_flags |= BIT(XSC_TC_FLOW_FLAG_ESWITCH);
	if (flags & XSC_TC_FLAG(NIC_OFFLOAD))
		__flow_flags |= BIT(XSC_TC_FLOW_FLAG_NIC);
	if (flags & XSC_TC_FLAG(FT_OFFLOAD))
		__flow_flags |= BIT(XSC_TC_FLOW_FLAG_FT);

	*flow_flags = __flow_flags;
}

static const struct rhashtable_params tc_ht_params = {
	.head_offset = offsetof(struct xsc_tc_flow, node),
	.key_offset = offsetof(struct xsc_tc_flow, cookie),
	.key_len = sizeof(((struct xsc_tc_flow *)0)->cookie),
	.automatic_shrinking = true,
};

static struct rhashtable *get_tc_ht(struct xsc_adapter *priv,
				    unsigned long flags)
{
	struct xsc_rep_priv *rpriv;

	if (flags & XSC_TC_FLAG(ESW_OFFLOAD)) {
		rpriv = priv->ppriv;
		return &rpriv->tc_ht;
	} else {
		return NULL;
	}
}

struct xsc_flow_attr *
xsc_alloc_flow_attr(enum xsc_flow_namespace_type type)
{
	u32 ex_attr_size = (type == XSC_FLOW_NAMESPACE_FDB)  ?
				sizeof(struct xsc_esw_flow_attr) :
				sizeof(struct xsc_nic_flow_attr);
	struct xsc_flow_attr *attr;

	attr = kzalloc(sizeof(*attr) + ex_attr_size, GFP_KERNEL);
	if (!attr)
		return attr;

	INIT_LIST_HEAD(&attr->list);
	return attr;
}

static void
xsc_free_flow_attr_actions(struct xsc_tc_flow *flow, struct xsc_flow_attr *attr)
{
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	struct xsc_core_device *counter_dev = get_flow_counter_dev(flow);
#endif

#ifdef CONFIG_XSC_OFFLOAD_OVS
	struct xsc_esw_flow_attr *esw_attr;
#endif

	if (!attr)
		return;

	if (attr->post_act_handle)
		xsc_tc_post_act_del(get_post_action(flow->priv), attr->post_act_handle);

#ifdef CONFIG_XSC_OFFLOAD_TUN
	xsc_tc_tun_encap_dests_unset(flow->priv, flow, attr);
#endif
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	if (attr->action & XSC_FLOW_CONTEXT_ACTION_COUNT)
		xsc_fc_destroy(counter_dev, attr->counter);
#endif
	if (attr->action & XSC_FLOW_CONTEXT_ACTION_MOD_HDR) {
		xsc_mod_hdr_dealloc(&attr->parse_attr->mod_hdr_acts);
		xsc_tc_detach_mod_hdr(flow->priv, flow, attr);
	}

#ifdef CONFIG_XSC_OFFLOAD_OVS
	if (xsc_is_eswitch_flow(flow)) {
		esw_attr = attr->esw_attr;

		if (esw_attr->int_port)
			xsc_tc_int_port_put(xsc_get_int_port_priv(flow->priv),
					    esw_attr->int_port);

		if (esw_attr->dest_int_port)
			xsc_tc_int_port_put(xsc_get_int_port_priv(flow->priv),
					    esw_attr->dest_int_port);
	}
#endif
#ifdef CONFIG_XSC_OFFLOAD_CT
	xsc_tc_ct_delete_flow(get_ct_priv(flow->priv), attr);
#endif
	free_branch_attr(flow, attr->branch_true);
	free_branch_attr(flow, attr->branch_false);
}

static int xsc_alloc_flow(struct xsc_adapter *priv, int attr_size,
			  struct flow_cls_offload *f, unsigned long flow_flags,
			  struct xsc_tc_flow_parse_attr **__parse_attr,
			  struct xsc_tc_flow **__flow)
{
	struct xsc_tc_flow_parse_attr *parse_attr;
	struct xsc_flow_attr *attr;
	struct xsc_tc_flow *flow;
	int err = -ENOMEM;
	int out_index;

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	parse_attr = kvzalloc(sizeof(*parse_attr), GFP_KERNEL);
	if (!parse_attr || !flow)
		goto err_free;

	flow->flags = flow_flags;
	flow->cookie = f->cookie;
	flow->priv = priv;

	attr = xsc_alloc_flow_attr(xsc_get_flow_namespace_id(flow));
	if (!attr)
		goto err_free;

	flow->attr = attr;

	for (out_index = 0; out_index < XSC_MAX_FLOW_FWD_VPORTS; out_index++)
		INIT_LIST_HEAD(&flow->encaps[out_index].list);

	INIT_LIST_HEAD(&flow->attrs);
	INIT_LIST_HEAD(&flow->peer_flows);
	refcount_set(&flow->refcnt, 1);
	init_completion(&flow->init_done);
	init_completion(&flow->del_hw_done);

	*__flow = flow;
	*__parse_attr = parse_attr;

	return 0;

err_free:
	kfree(flow);
	kvfree(parse_attr);
	return err;
}

static void xsc_flow_attr_init(struct xsc_flow_attr *attr,
			       struct xsc_tc_flow_parse_attr *parse_attr,
			       struct flow_cls_offload *f)
{
	attr->parse_attr = parse_attr;
	attr->chain = f->common.chain_index;
	attr->prio = f->common.prio;
}

static void xsc_flow_esw_attr_init(struct xsc_flow_attr *attr,
				   struct xsc_adapter *priv,
				   struct xsc_tc_flow_parse_attr *parse_attr,
				   struct flow_cls_offload *f,
				   struct xsc_eswitch_rep *in_rep,
				   struct xsc_core_device *in_xdev)
{
	struct xsc_esw_flow_attr *esw_attr = attr->esw_attr;
	struct xsc_eswitch *esw = priv->xdev->priv.eswitch;

	xsc_flow_attr_init(attr, parse_attr, f);

	esw_attr->in_rep = in_rep;
	esw_attr->in_xdev = in_xdev;

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	if (esw->esw_caps.counter_eswitch_affinity == XSC_COUNTER_SOURCE_ESWITCH)
		esw_attr->counter_dev = in_xdev;
	else
		esw_attr->counter_dev = priv->xdev;
#endif
}

static struct xsc_tc_flow *__xsc_add_fdb_flow(struct xsc_adapter *priv,
					      struct flow_cls_offload *f,
					      unsigned long flow_flags,
					      struct net_device *filter_dev,
					      struct xsc_eswitch_rep *in_rep,
					      struct xsc_core_device *in_xdev)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct netlink_ext_ack *extack = f->common.extack;
	struct xsc_tc_flow_parse_attr *parse_attr;
	struct xsc_tc_flow *flow;
	int attr_size, err;

	flow_flags |= BIT(XSC_TC_FLOW_FLAG_ESWITCH);
	attr_size  = sizeof(struct xsc_esw_flow_attr);
	err = xsc_alloc_flow(priv, attr_size, f, flow_flags, &parse_attr, &flow);
	if (err)
		goto out;

	parse_attr->filter_dev = filter_dev;
	xsc_flow_esw_attr_init(flow->attr, priv, parse_attr,
			       f, in_rep, in_xdev);

	err = parse_cls_flower(flow->priv, flow, &parse_attr->spec,
			       f, filter_dev);
	if (err)
		goto err_free;

#ifdef CONFIG_XSC_OFFLOAD_CT
	/* actions validation depends on parsing the ct matches first */
	err = xsc_tc_ct_match_add(get_ct_priv(priv), &parse_attr->spec, f,
				  &flow->attr->ct_attr, extack);
	if (err)
		goto err_free;
#endif

	err = parse_tc_fdb_actions(priv, &rule->action, flow, extack);
	if (err)
		goto err_free;

	err = xsc_tc_add_fdb_flow(priv, flow, extack);
	complete_all(&flow->init_done);
	if (err) {
		if (err == -ENETUNREACH)
			add_unready_flow(flow);
	}

	return flow;

err_free:
	xsc_flow_put(priv, flow);
out:
	return ERR_PTR(err);
}

static int xsc_add_fdb_flow(struct xsc_adapter *priv, struct flow_cls_offload *f,
			    unsigned long flow_flags, struct net_device *filter_dev,
			    struct xsc_tc_flow **__flow)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;
	struct xsc_eswitch_rep *in_rep = rpriv->rep;
	struct xsc_core_device *in_xdev = priv->xdev;
	struct xsc_tc_flow *flow;

	flow = __xsc_add_fdb_flow(priv, f, flow_flags, filter_dev, in_rep, in_xdev);
	if (IS_ERR(flow))
		return PTR_ERR(flow);

	*__flow = flow;
	return 0;
}

static int xsc_tc_add_flow(struct xsc_adapter *priv, struct flow_cls_offload *f,
			   unsigned long flags, struct net_device *filter_dev,
			   struct xsc_tc_flow **flow)
{
	unsigned long flow_flags;
	int err;

	get_flags(flags, &flow_flags);

	if (!tc_can_offload_extack(priv->netdev, f->common.extack))
		return -EOPNOTSUPP;

	if (is_xdev_switchdev_mode(priv->xdev))
		err = xsc_add_fdb_flow(priv, f, flow_flags, filter_dev, flow);
	else
		err = -EOPNOTSUPP;

	return err;
}

static bool is_flow_rule_duplicate_allowed(struct net_device *dev,
					   struct xsc_rep_priv *rpriv)
{
	/* Offloaded flow rule is allowed to duplicate on non-uplink representor
	 * sharing tc block with other slaves of a lag device. Rpriv can be NULL if this
	 * function is called from NIC mode.
	 */
	return netif_is_lag_port(dev) && rpriv && rpriv->rep->vport != XSC_VPORT_UPLINK;
}

int xsc_configure_flower(struct net_device *dev, struct xsc_adapter *priv,
			 struct flow_cls_offload *f, unsigned long flags)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct xsc_rep_priv *rpriv = priv->ppriv;
	struct xsc_tc_flow *flow;
	int err = 0;

	if (!xsc_esw_hold(priv->xdev))
		return -EBUSY;

	xsc_esw_get(priv->xdev);

	esw_debug(priv->xdev, "configure cls_flower cookie=%lx\n", f->cookie);
	rcu_read_lock();
	flow = rhashtable_lookup(tc_ht, &f->cookie, tc_ht_params);
	if (flow) {
		/* Same flow rule offloaded to non-uplink representor sharing tc block,
		 * just return 0.
		 */
		if (is_flow_rule_duplicate_allowed(dev, rpriv) && flow->orig_dev != dev)
			goto rcu_unlock;

		NL_SET_ERR_MSG_MOD(extack,
				   "flow cookie already exists, ignoring");
		netdev_warn_once(priv->netdev,
				 "flow cookie %lx already exists, ignoring\n",
				 f->cookie);
		err = -EEXIST;
		goto rcu_unlock;
	}
rcu_unlock:
	rcu_read_unlock();
	if (flow)
		goto out;

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_configure_flower(f);
#endif

	err = xsc_tc_add_flow(priv, f, flags, dev, &flow);
	if (err)
		goto out;

	/* Flow rule offloaded to non-uplink representor sharing tc block,
	 * set the flow's owner dev.
	 */
	if (is_flow_rule_duplicate_allowed(dev, rpriv))
		flow->orig_dev = dev;

	err = rhashtable_lookup_insert_fast(tc_ht, &flow->node, tc_ht_params);
	if (err)
		goto err_free;

	xsc_esw_release(priv->xdev);
	return 0;

err_free:
	xsc_flow_put(priv, flow);
	esw_warn(priv->xdev, "Failed to configure cls_flower cookie=0x%lx\n", f->cookie);
out:
	esw_warn(priv->xdev, "configure cls_flower cookie=0x%lx\n", f->cookie);
	xsc_esw_put(priv->xdev);
	xsc_esw_release(priv->xdev);
	return err;
}

static bool same_flow_direction(struct xsc_tc_flow *flow, int flags)
{
	bool dir_ingress = !!(flags & XSC_TC_FLAG(INGRESS));
	bool dir_egress = !!(flags & XSC_TC_FLAG(EGRESS));

	return flow_flag_test(flow, INGRESS) == dir_ingress &&
		flow_flag_test(flow, EGRESS) == dir_egress;
}

int xsc_delete_flower(struct net_device *dev, struct xsc_adapter *priv,
		      struct flow_cls_offload *f, unsigned long flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct xsc_tc_flow *flow;
	int err;

	rcu_read_lock();
	flow = rhashtable_lookup(tc_ht, &f->cookie, tc_ht_params);
	if (!flow || !same_flow_direction(flow, flags)) {
		err = -EINVAL;
		goto errout;
	}

	/* Only delete the flow if it doesn't have XSC_TC_FLOW_DELETED flag
	 * set.
	 */
	if (flow_flag_test_and_set(flow, DELETED)) {
		err = -EINVAL;
		goto errout;
	}
	rhashtable_remove_fast(tc_ht, &flow->node, tc_ht_params);
	rcu_read_unlock();

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_delete_flower(f);
#endif

	xsc_flow_put(priv, flow);

	xsc_esw_put(priv->xdev);
	return 0;

errout:
	rcu_read_unlock();
	return err;
}

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
struct xsc_fc *xsc_tc_get_counter(struct xsc_tc_flow *flow)
{
	struct xsc_flow_attr *attr;

	attr = list_first_entry(&flow->attrs, struct xsc_flow_attr, list);
	return attr->counter;
}

#ifdef	CONFIG_XSC_OFFLOAD_OVS
int xsc_tc_fill_action_stats(struct xsc_adapter *priv,
			     struct flow_offload_action *fl_act)
{
	return xsc_tc_act_stats_fill_stats(get_act_stats_handle(priv), fl_act);
}
#endif

int xsc_stats_flower(struct net_device *dev, struct xsc_adapter *priv,
		     struct flow_cls_offload *f, unsigned long flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);
	struct xsc_tc_flow *flow;
	struct xsc_fc *counter;
	u64 lastuse = 0;
	u64 packets = 0;
	u64 bytes = 0;
	int err = 0;

	rcu_read_lock();
	flow = xsc_flow_get(rhashtable_lookup(tc_ht, &f->cookie, tc_ht_params));
	rcu_read_unlock();
	if (IS_ERR(flow))
		return PTR_ERR(flow);

	if (!same_flow_direction(flow, flags)) {
		err = -EINVAL;
		goto errout;
	}

	if (xsc_is_offloaded_flow(flow)) {
#ifdef CONFIG_XSC_OFFLOAD_ACT_COUNTER
		if (flow_flag_test(flow, USE_ACT_STATS)) {
			f->use_act_stats = true;
		} else {
#else
		{
#endif
			counter = xsc_tc_get_counter(flow);
			if (!counter)
				goto errout;

			xsc_fc_query_cached(counter, &bytes, &packets, &lastuse);
			esw_debug(priv->xdev,
				  "id=%d, pakcets=%lld, bytes=%lld, lastuse=%lld\n",
				  counter->id, packets, bytes, lastuse);
		}
	}

	flow_stats_update(&f->stats, bytes, packets, 0, lastuse,
			  FLOW_ACTION_HW_STATS_DELAYED);

#ifdef CONFIG_XSC_TRACE_DEBUG
	trace_xsc_stats_flower(f);
#endif
errout:
	xsc_flow_put(priv, flow);
	return err;
}
EXPORT_SYMBOL(xsc_stats_flower);
#endif

#ifdef CONFIG_XSC_OFFLOAD_METER
static int apply_police_params(struct xsc_adapter *priv, u64 rate,
			       struct netlink_ext_ack *extack)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;
	struct xsc_eswitch *esw;
	u32 rate_mbps = 0;
	u16 vport_num;
	int err;

	vport_num = rpriv->rep->vport;
	if (vport_num >= XSC_VPORT_ECPF) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Ingress rate limit is supported only for Eswitch ports connected to VFs");
		return -EOPNOTSUPP;
	}

	esw = priv->xdev->priv.eswitch;
	/* rate is given in bytes/sec.
	 * First convert to bits/sec and then round to the nearest mbit/secs.
	 * mbit means million bits.
	 * Moreover, if rate is non zero we choose to configure to a minimum of
	 * 1 mbit/sec.
	 */
	if (rate) {
		rate = (rate * BITS_PER_BYTE) + 500000;
		do_div(rate, 1000000);
		rate_mbps = max_t(u32, rate, 1);
	}

	err = xsc_esw_qos_modify_vport_rate(esw, vport_num, rate_mbps);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "failed applying action to hardware");

	return err;
}

static int
tc_matchall_police_validate(const struct flow_action *action,
			    const struct flow_action_entry *act,
			    struct netlink_ext_ack *extack)
{
	if (act->police.notexceed.act_id != FLOW_ACTION_CONTINUE) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when conform action is not continue");
		return -EOPNOTSUPP;
	}

	if (act->police.exceed.act_id != FLOW_ACTION_DROP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when exceed action is not drop");
		return -EOPNOTSUPP;
	}

	if (act->police.notexceed.act_id == FLOW_ACTION_ACCEPT &&
	    !flow_action_is_last_entry(action, act)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when conform action is ok, but action is not last");
		return -EOPNOTSUPP;
	}

	if (act->police.peakrate_bytes_ps ||
	    act->police.avrate || act->police.overhead) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when peakrate/avrate/overhead is configured");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int scan_tc_matchall_fdb_actions(struct xsc_adapter *priv,
					struct flow_action *flow_action,
					struct netlink_ext_ack *extack)
{
	struct xsc_rep_priv *rpriv = priv->ppriv;
	const struct flow_action_entry *act;
	int err;
	int i;

	if (!flow_action_has_entries(flow_action)) {
		NL_SET_ERR_MSG_MOD(extack, "matchall called with no action");
		return -EINVAL;
	}

	if (!flow_offload_has_one_action(flow_action)) {
		NL_SET_ERR_MSG_MOD(extack, "matchall policing support only a single action");
		return -EOPNOTSUPP;
	}

	if (!flow_action_basic_hw_stats_check(flow_action, extack)) {
		NL_SET_ERR_MSG_MOD(extack, "Flow action HW stats type is not supported");
		return -EOPNOTSUPP;
	}

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
		case FLOW_ACTION_POLICE:
			err = tc_matchall_police_validate(flow_action, act, extack);
			if (err)
				return err;

			err = apply_police_params(priv, act->police.rate_bytes_ps, extack);
			if (err)
				return err;

			xsc_stats_copy_rep_stats(&rpriv->prev_vf_vport_stats,
						 &priv->stats.rep_stats);
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack, "xsc supports only police action for matchall");
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

int xsc_tc_configure_matchall(struct xsc_adapter *priv, struct tc_cls_matchall_offload *ma)
{
	struct netlink_ext_ack *extack = ma->common.extack;

	if (ma->common.prio != 1) {
		NL_SET_ERR_MSG_MOD(extack, "only priority 1 is supported");
		return -EINVAL;
	}

	return scan_tc_matchall_fdb_actions(priv, &ma->rule->action, extack);
}

int xsc_tc_delete_matchall(struct xsc_adapter *priv, struct tc_cls_matchall_offload *ma)
{
	struct netlink_ext_ack *extack = ma->common.extack;

	return apply_police_params(priv, 0, extack);
}
#endif

static void xsc_tc_del_flow(struct xsc_adapter *priv, struct xsc_tc_flow *flow)
{
	if (xsc_is_eswitch_flow(flow))
		xsc_tc_del_fdb_flow(priv, flow);
}

static void _xsc_tc_del_flow(void *ptr, void *arg)
{
	struct xsc_tc_flow *flow = ptr;
	struct xsc_adapter *priv = flow->priv;

	xsc_tc_del_flow(priv, flow);
	kfree(flow);
}

int xsc_tc_ht_init(struct rhashtable *tc_ht)
{
	int err;

	err = rhashtable_init(tc_ht, &tc_ht_params);
	if (err)
		return err;

	lockdep_set_class(&tc_ht->mutex, &tc_ht_lock_key);
	lockdep_init_map(&tc_ht->run_work.lockdep_map, "tc_ht_wq_key", &tc_ht_wq_key, 0);

	return 0;
}

void xsc_tc_ht_cleanup(struct rhashtable *tc_ht)
{
	rhashtable_free_and_destroy(tc_ht, _xsc_tc_del_flow, NULL);
}

int xsc_tc_esw_init(struct xsc_rep_uplink_priv *uplink_priv)
{
	struct xsc_rep_priv *rpriv;
	struct xsc_eswitch *esw;
	struct xsc_adapter *priv;
	int err = 0;

	rpriv = container_of(uplink_priv, struct xsc_rep_priv, uplink_priv);
	priv = netdev_priv(rpriv->netdev);
	esw = priv->xdev->priv.eswitch;

	uplink_priv->post_act = xsc_tc_post_act_init(priv, esw_chains(esw),
						     XSC_FLOW_NAMESPACE_FDB);

#ifdef CONFIG_XSC_OFFLOAD_ACT_COUNTER
	uplink_priv->action_stats_handle = xsc_tc_act_stats_create();
	if (IS_ERR(uplink_priv->action_stats_handle)) {
		err = PTR_ERR(uplink_priv->action_stats_handle);
		goto err_action_counter;
	}

err_action_counter:
	netdev_warn(priv->netdev,
		    "Failed to initialize tc (eswitch), err: %d", err);
	xsc_tc_post_act_destroy(uplink_priv->post_act);
#endif

	return err;
}

void xsc_tc_esw_cleanup(struct xsc_rep_uplink_priv *uplink_priv)
{
	struct xsc_rep_priv *rpriv;
	struct xsc_eswitch *esw;
	struct xsc_adapter *priv;

	rpriv = container_of(uplink_priv, struct xsc_rep_priv, uplink_priv);
	priv = netdev_priv(rpriv->netdev);
	esw = priv->xdev->priv.eswitch;

	xsc_tc_post_act_destroy(uplink_priv->post_act);
#ifdef CONFIG_XSC_OFFLOAD_ACT_COUNTER
	xsc_tc_act_stats_free(uplink_priv->action_stats_handle);
#endif
}

int xsc_tc_num_filters(struct xsc_adapter *priv, unsigned long flags)
{
	struct rhashtable *tc_ht = get_tc_ht(priv, flags);

	return tc_ht ? atomic_read(&tc_ht->nelems) : 0;
}

static int xsc_setup_tc_cls_flower(struct xsc_adapter *priv,
				   struct flow_cls_offload *cls_flower,
				   unsigned long flags)
{
	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return xsc_configure_flower(priv->netdev, priv, cls_flower, flags);
	case FLOW_CLS_DESTROY:
		return xsc_delete_flower(priv->netdev, priv, cls_flower, flags);
	case FLOW_CLS_STATS:
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
		return xsc_stats_flower(priv->netdev, priv, cls_flower, flags);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

int xsc_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	unsigned long flags = XSC_TC_FLAG(INGRESS);
	struct xsc_adapter *priv = cb_priv;

	if (!priv->netdev || !netif_device_present(priv->netdev))
		return -EOPNOTSUPP;

	if (xsc_is_uplink_rep(priv))
		flags |= XSC_TC_FLAG(ESW_OFFLOAD);
	else
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return xsc_setup_tc_cls_flower(priv, type_data, flags);
	default:
		return -EOPNOTSUPP;
	}
}

