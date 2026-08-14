// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_fdir.h"
#include "mce_lib.h"
#include "mce_eswitch.h"
#include "mce_switch.h"
#include "mce_fltr.h"
#include "mce_vf_lib.h"
#include "mce_tc_lib.h"

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

/* L2 */
static enum mce_flow_item_type eswitch_pattern_eth[] = {
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_END,
};

/* IPV4-VXLAN */
static enum mce_flow_item_type eswitch_pattern_eth_ipv4_vxlan[] = {
	MCE_FLOW_ITEM_TYPE_ETH, MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_UDP, MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_END,
};

#define MCE_SW_OUT_IPV4 \
	(MCE_OPT_OUT_IPV4_SIP | MCE_OPT_OUT_IPV4_DIP | MCE_OPT_DMAC)
#define MCE_SW_IPV4_VXLAN (MCE_SW_OUT_IPV4 | MCE_OPT_VXLAN_VNI)

static struct mce_flow_ptype_match mce_eswitch_ptype_support[] = {
	{ eswitch_pattern_eth, MCE_ESW_MODE_LEGACY,
	  MCE_OPT_SMAC | MCE_OPT_DMAC },
	{ eswitch_pattern_eth_ipv4_vxlan, MCE_ESW_MODE_SWITCHDEV,
	  MCE_SW_IPV4_VXLAN },
};

static void __maybe_unused
mce_eswitch_print_filter_info(struct mce_eswitch_pattern *lkup_pattern)
{
	pr_info("==========lkup_pattern addr:%p============", lkup_pattern);
	pr_info("dst_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
		lkup_pattern->formatted.dst_mac[0],
		lkup_pattern->formatted.dst_mac[1],
		lkup_pattern->formatted.dst_mac[2],
		lkup_pattern->formatted.dst_mac[3],
		lkup_pattern->formatted.dst_mac[4],
		lkup_pattern->formatted.dst_mac[5]);
	pr_info("vlan_id:%d\n", lkup_pattern->formatted.vlan_id);
	pr_info("tunnel_tag:%d\n", lkup_pattern->formatted.tunnel_tag);
	pr_info("ether_type:%d\n", lkup_pattern->formatted.ether_type);
	pr_info("dst_addr:%d\n", lkup_pattern->formatted.dst_addr);
	pr_info("src_addr:%d\n", lkup_pattern->formatted.src_addr);
	pr_info("l4_sport:%d\n", lkup_pattern->formatted.l4_sport);
	pr_info("l4_dport:%d\n", lkup_pattern->formatted.l4_dport);
	pr_info("vni:%d\n", lkup_pattern->formatted.vni);
	pr_info("tni:%d\n", lkup_pattern->formatted.tni);
	pr_info("teid:%d\n", lkup_pattern->formatted.teid);
	pr_info("is_ipv6:%d\n", lkup_pattern->formatted.is_ipv6);
	pr_info("svport_id:%d\n", lkup_pattern->formatted.svport_id);
	pr_info("dvport_id:%d\n", lkup_pattern->dvport_id);
}

struct mce_flow_ptype_match *
mce_eswitch_check_pattern_support(struct mce_pf *pf, u8 *compose,
				  struct mce_tc_flower_fltr *tc_fltr)
{
	struct mce_flow_ptype_match *ptype_support = NULL;
	enum mce_flow_item_type *pattern = NULL;
	int arry_size, i, j;

	ptype_support = mce_eswitch_ptype_support;
	arry_size = ARRAY_SIZE(mce_eswitch_ptype_support);

	for (i = 0; i < arry_size; i++) {
		pattern = ptype_support[i].pattern_list;

		for (j = 0; j < MCE_FLOW_ITEM_TYPE_MAX_NUM; j++) {
			if (pattern[j] == MCE_FLOW_ITEM_TYPE_END)
				break;
			if (pattern[j] != compose[j])
				break;
		}

		if (pattern[j] == MCE_FLOW_ITEM_TYPE_END &&
		    compose[j] == MCE_FLOW_ITEM_TYPE_END) {
			return &ptype_support[i];
		}
	}
	return NULL;
}

struct mce_eswitch_filter *
mce_meta_to_eswitch_legacy(struct mce_hw *hw,
			   struct mce_tc_flower_fltr *tc_fltr,
			   struct mce_eswitch_handle *handle, u16 meta_num,
			   bool is_ipv6, bool is_tunnel)
{
	struct mce_eswitch_filter *filter = NULL;
	struct mce_eswitch_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	int i;

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return NULL;

	lkup_pattern = &filter->lkup_pattern;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		if (meta->type == MCE_META_TYPE_MAX)
			continue;
		switch (meta->type) {
		case MCE_ETH_META:
			memcpy(lkup_pattern->formatted.dst_mac,
			       meta->hdr.eth_meta.dst_addr, ETH_ALEN);
			break;
		case MCE_VLAN_META:
			lkup_pattern->formatted.vlan_id =
				meta->hdr.vlan_meta.vlan_id;
			break;
		default:
			dev_err(hw->dev,
				"%s eswitch the rule type:0x%x is not exist option.\n",
				__func__, meta->type);
			break;
		}
	}

	lkup_pattern->formatted.svport_id = tc_fltr->src_vsi->vport_id;
	lkup_pattern->dvport_id = tc_fltr->dest_vsi->vport_id;
	filter->drop_en = !!(tc_fltr->action.fltr_act == MCE_DROP_PACKET);

	return filter;
}

struct mce_eswitch_filter *
mce_meta_to_eswitch_switchdev(struct mce_hw *hw,
			      struct mce_tc_flower_fltr *tc_fltr,
			      struct mce_eswitch_handle *handle, u16 meta_num,
			      bool is_ipv6, bool is_tunnel)
{
	struct mce_eswitch_filter *filter = NULL;
	struct mce_eswitch_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	int i;

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return NULL;

	lkup_pattern = &filter->lkup_pattern;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		if (meta->type == MCE_META_TYPE_MAX)
			continue;
		switch (meta->type) {
		case MCE_ETH_META:
			memcpy(lkup_pattern->formatted.dst_mac,
			       meta->hdr.eth_meta.dst_addr, ETH_ALEN);
			break;
		case MCE_VLAN_META:
			lkup_pattern->formatted.vlan_id =
				meta->hdr.vlan_meta.vlan_id;
			break;
		case MCE_IPV4_META:
			lkup_pattern->formatted.src_addr =
				meta->hdr.ipv4_meta.src_addr;
			lkup_pattern->formatted.dst_addr =
				meta->hdr.ipv4_meta.dst_addr;
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv4_meta.protocol;
			break;
		case MCE_UDP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.udp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.udp_meta.src_port;
			break;
		case MCE_TCP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.tcp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.tcp_meta.src_port;
			break;
		case MCE_SCTP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.sctp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.sctp_meta.src_port;
			break;
		case MCE_VXLAN_META:
			lkup_pattern->formatted.vni = meta->hdr.vxlan_meta.vni;
			break;
		case MCE_GENEVE_META:
			lkup_pattern->formatted.vni = meta->hdr.geneve_meta.vni;
			break;
		case MCE_NVGRE_META:
			lkup_pattern->formatted.tni = meta->hdr.nvgre_meta.key;
			break;
		case MCE_GTPC_META:
		case MCE_GTPU_META:
			lkup_pattern->formatted.teid = meta->hdr.gtp_meta.teid;
			break;
		default:
			dev_err(hw->dev,
				"%s eswitch the rule type:0x%x is not exist option.\n",
				__func__, meta->type);
			break;
		}
	}
	return filter;
}

static int mce_eswitch_flow_engine_init(struct mce_pf *pf, void **handle)
{
	struct mce_eswitch_handle *eswitch_handle;
	struct mce_eswitch_filter filter;
	struct mce_hw *hw = &pf->hw;

	eswitch_handle = kzalloc(sizeof(*eswitch_handle), GFP_KERNEL);
	if (!eswitch_handle)
		return -ENOMEM;

	eswitch_handle->max_eswitch_rule = MCE_ESWITCH_RULES_ENTRIES;
	eswitch_handle->max_switchdev_rule = MCE_ESWITCH_RULES_SWITCHDEV_ENTRIES;
	eswitch_handle->max_legacy_rule = MCE_ESWITCH_RULES_LEGACY_ENTRIES;
	INIT_LIST_HEAD(&eswitch_handle->eswitch_legacy_head);
	INIT_LIST_HEAD(&eswitch_handle->eswitch_switchdev_head);
	/* init eswitch uplink bcmc rules */
	memset(&filter, 0, sizeof(filter));
	filter.options = MCE_OPT_DMAC;
	memset(filter.lkup_pattern.formatted.dst_mac, 0xff, ETH_ALEN);
	filter.rule_loc =
		MCE_ESWITCH_ACTION_ENTRIES - MCE_ESWITCH_RULES_BCMC_ENTRIES;
	filter.lkup_pattern.formatted.svport_id = MCE_MAX_VF_NUM;
	filter.lkup_pattern.dvport_id = MCE_MAX_VF_NUM;
	hw->eswitch.ops->eswitch_update_legacy(hw, &filter, true);
	*handle = eswitch_handle;
	return 0;
}

static void mce_eswitch_flow_engine_deinit(struct mce_pf *pf,
					   enum mce_flow_module module)
{
	struct mce_eswitch_handle *handle;
	struct mce_eswitch_filter filter;
	struct mce_hw *hw = &pf->hw;

	handle = (struct mce_eswitch_handle *)mce_get_engine_handle(pf, module);
	kfree(handle);
	memset(&filter, 0, sizeof(filter));
	filter.rule_loc =
		MCE_ESWITCH_ACTION_ENTRIES - MCE_ESWITCH_RULES_BCMC_ENTRIES;
	hw->eswitch.ops->eswitch_update_legacy(hw, &filter, false);
}

static struct mce_eswitch_filter *
mce_eswitch_entry_lookup(struct list_head *list_head,
			 const struct mce_eswitch_filter *filter)
{
	struct mce_eswitch_filter *entry = NULL, *t_entry = NULL;

	list_for_each_entry_safe(entry, t_entry, list_head, fltr_node) {
		if (!memcmp((u8 *)&filter->lkup_pattern,
			    (u8 *)&entry->lkup_pattern,
			    sizeof(struct mce_eswitch_pattern))) {
			return entry;
		}
	}

	return NULL;
}

static int mce_eswitch_macvlan_program(struct mce_pf *pf,
				       struct mce_eswitch_filter *filter,
				       struct mce_tc_flower_fltr *fltr,
				       bool add)
{
	struct mce_eswitch_handle *handle = NULL;
	struct mce_eswitch_filter *entry;
	struct mce_hw *hw = &pf->hw;
	int rule_loc;

	if (!filter)
		return -ENOENT;

	handle = (struct mce_eswitch_handle *)mce_get_engine_handle(pf, MCE_FLOW_ESWITCH);

	entry = mce_eswitch_entry_lookup(&handle->eswitch_legacy_head, filter);

	if (add) {
		if (entry) {
			dev_err(hw->dev,
				"eswitch add macvlan rule is exist!\n");
			kfree(filter);
			return -EEXIST;
		}
		rule_loc = find_first_zero_bit(handle->avail_legacy,
					       handle->max_legacy_rule);
		set_bit(rule_loc, handle->avail_legacy);
		/* calc real loc in switch table */
		filter->rule_loc = handle->max_eswitch_rule - 1 -
				   MCE_ESWITCH_RULES_BCMC_ENTRIES - rule_loc;
		hw->eswitch.ops->eswitch_update_legacy(hw, filter, true);
		fltr->dest_vsi->bcmc_ref_cnf++;

		if (fltr->dest_vsi->bcmc_ref_cnf == 1) {
			hw->eswitch.ops->eswitch_update_bcmc_redir(hw,
								fltr->dest_vsi->vport_id, true);
		}
		list_add_tail(&filter->fltr_node, &handle->eswitch_legacy_head);

	} else {
		if (!entry) {
			dev_err(hw->dev,
				"eswitch del macvlan rule is no-exist!\n");
			return -EEXIST;
		}
		rule_loc = handle->max_eswitch_rule - 1 -
			   MCE_ESWITCH_RULES_BCMC_ENTRIES - entry->rule_loc;
		clear_bit(rule_loc, handle->avail_legacy);
		hw->eswitch.ops->eswitch_update_legacy(hw, entry, false);
		if (fltr->dest_vsi->bcmc_ref_cnf)
			fltr->dest_vsi->bcmc_ref_cnf--;
		if (fltr->dest_vsi->bcmc_ref_cnf == 0) {
			hw->eswitch.ops->eswitch_update_bcmc_redir(hw,
								fltr->dest_vsi->vport_id, false);
		}
		list_del(&entry->fltr_node);
		kfree(entry);
	}
	return 0;
}

static int mce_eswitch_eswitch_program(struct mce_pf *pf,
				       struct mce_eswitch_filter *filter,
				       struct mce_tc_flower_fltr *fltr,
				       bool add)
{
	return -EOPNOTSUPP;
}

static int mce_eswitch_flow_create(struct mce_pf *pf, void *p_filter,
				   struct mce_tc_flower_fltr *fltr)
{
	struct mce_eswitch_filter *filter =
		(struct mce_eswitch_filter *)p_filter;

	if (filter->eswitch_type == MCE_ESW_MODE_LEGACY)
		return mce_eswitch_macvlan_program(pf, filter, fltr, true);
	else
		return mce_eswitch_eswitch_program(pf, filter, fltr, true);
}

static int mce_eswitch_flow_delete(struct mce_pf *pf, void *p_filter,
				   struct mce_tc_flower_fltr *fltr)
{
	struct mce_eswitch_filter *filter =
		(struct mce_eswitch_filter *)p_filter;

	if (filter->eswitch_type == MCE_ESW_MODE_LEGACY)
		return mce_eswitch_macvlan_program(pf, filter, fltr, false);
	else
		return mce_eswitch_eswitch_program(pf, filter, fltr, false);
}

struct mce_flow_engine_module mce_eswitch_engine = {
	.create = mce_eswitch_flow_create,
	.destroy = mce_eswitch_flow_delete,
	.init = mce_eswitch_flow_engine_init,
	.uinit = mce_eswitch_flow_engine_deinit,
	.type = MCE_FLOW_ESWITCH,
};

#endif /* CONFIG_NET_CLS_FLOWER */
