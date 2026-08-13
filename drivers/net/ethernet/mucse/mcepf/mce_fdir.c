// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_fdir.h"

static void mce_fdir_del_tcpsyc_fltrs(struct mce_hw *hw, bool del_fltr_node)
{
	struct mce_pf *pf = hw->back;
	struct mce_tcpsync tcpsync;
	struct mce_vf *vf;
	int vfid;

	vf = mce_pf_to_vf(pf);
	if (!vf->vfinfo)
		return;

	memset(&tcpsync, 0, sizeof(struct mce_tcpsync));
	mce_for_each_pf_vf_id(pf, vfid) {
		if (del_fltr_node)
			memset(&vf->vfinfo[vfid].tcpsync, 0,
			       sizeof(struct mce_tcpsync));

		vf->vfinfo[vfid].tcpsync.valid = 0;
		hw->vf.ops->set_vf_rqa_tcp_sync_remapping(hw, vfid, &tcpsync);
	}
	clear_bit(MCE_FLAG_PF_RQA_TCPSYNC_ENA, pf->flags);
}

static void mce_fdir_restore_tcpsyc_fltrs(struct mce_hw *hw)
{
	struct mce_pf *pf = hw->back;
	struct mce_vf *vf;
	int vfid;

	vf = mce_pf_to_vf(pf);
	if (!vf->vfinfo)
		return;

	mce_for_each_pf_vf_id(pf, vfid)
		hw->vf.ops->set_vf_rqa_tcp_sync_remapping(hw, vfid, &vf->vfinfo[vfid].tcpsync);
}

/**
 * mce_fdir_del_fltrs - Delete Flow Director filters.
 * @hw: pointer to hardware structure
 * @del_fltr_node: whether to remove filter nodes from the list
 *
 * Returns void
 */
void mce_fdir_del_fltrs(struct mce_hw *hw, bool del_fltr_node)
{
	struct mce_fdir_fltr *rule, *tmp;

	mutex_lock(&hw->fdir_fltr_lock);
	list_for_each_entry_safe(rule, tmp, &hw->fdir_list_head, fltr_node) {
		mce_handle_acl_filter(hw, rule, false);
		if (del_fltr_node) {
			list_del(&rule->fltr_node);
			devm_kfree(hw->dev, rule);
		}
	}
	/* del tcpsync */
	mce_fdir_del_tcpsyc_fltrs(hw, del_fltr_node);
	mutex_unlock(&hw->fdir_fltr_lock);
}

/**
 * mce_fdir_restore_fltr - Restore Flow Director filters.
 * @hw: pointer to hardware structure
 *
 * Returns void
 */
void mce_fdir_restore_fltr(struct mce_hw *hw)
{
	struct mce_fdir_fltr *rule;

	mutex_lock(&hw->fdir_fltr_lock);
	list_for_each_entry(rule, &hw->fdir_list_head, fltr_node)
		mce_handle_acl_filter(hw, rule, true);
	mce_fdir_restore_tcpsyc_fltrs(hw);
	mutex_unlock(&hw->fdir_fltr_lock);
}

/**
 * mce_fdir_find_fltr_by_idx - find filter with idx
 * @hw: pointer to hardware structure
 * @fltr_idx: index to find.
 *
 * Returns pointer to filter if found or null
 */
struct mce_fdir_fltr *
mce_fdir_find_fltr_by_idx(struct mce_hw *hw, u32 fltr_idx)
{
	struct mce_fdir_fltr *rule;

	list_for_each_entry(rule, &hw->fdir_list_head, fltr_node) {
		/* rule ID found in the list */
		if (fltr_idx == rule->fltr_id)
			return rule;
	}
	return NULL;
}

/**
 * mce_fdir_comp_rules - compare 2 filters
 * @a: a Flow Director filter data structure
 * @b: a Flow Director filter data structure
 *
 * Returns: true if the filters match
 */
static bool mce_fdir_comp_rules(struct mce_fdir_fltr *a,
				struct mce_fdir_fltr *b)
{
	enum mce_fltr_ptype flow_type = a->flow_type;
	bool ret = false;

	switch (flow_type) {
	case MCE_FLTR_PTYPE_IPV4_TCP:
	case MCE_FLTR_PTYPE_IPV4_UDP:
	case MCE_FLTR_PTYPE_IPV4_SCTP:
		if (a->ip.v4.dst_ip == b->ip.v4.dst_ip &&
		    a->ip.v4.src_ip == b->ip.v4.src_ip &&
				a->ip.v4.dst_port == b->ip.v4.dst_port &&
				a->ip.v4.src_port == b->ip.v4.src_port) {
			ret = true;
		}
		break;
	case MCE_FLTR_PTYPE_IPV4_OTHER:
		if (a->ip.v4.dst_ip == b->ip.v4.dst_ip &&
		    a->ip.v4.src_ip == b->ip.v4.src_ip &&
				a->ip.v4.l4_header == b->ip.v4.l4_header &&
				a->ip.v4.proto == b->ip.v4.proto &&
				a->ip.v4.ip_ver == b->ip.v4.ip_ver &&
				a->ip.v4.tos == b->ip.v4.tos) {
			ret = true;
		}
		break;
	case MCE_FLTR_PTYPE_IPV6_TCP:
	case MCE_FLTR_PTYPE_IPV6_UDP:
	case MCE_FLTR_PTYPE_IPV6_SCTP:
		if (a->ip.v6.dst_port == b->ip.v6.dst_port &&
		    a->ip.v6.src_port == b->ip.v6.src_port &&
		    !(memcmp(a->ip.v6.dst_ip, b->ip.v6.dst_ip,
			     (4 * sizeof(__be32)))) &&
		    !(memcmp(a->ip.v6.src_ip, b->ip.v6.src_ip,
			     (4 * sizeof(__be32))))) {
			ret = true;
		}
		break;
	case MCE_FLTR_PTYPE_IPV6_OTHER:
		if (a->ip.v6.dst_port == b->ip.v6.dst_port &&
		    a->ip.v6.src_port == b->ip.v6.src_port &&
		    a->ip.v6.proto == b->ip.v6.proto) {
			ret = true;
		}
		break;
	case MCE_FLTR_PTYPE_NONF_ETH:
		if (a->eth.type == b->eth.type)
			ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

/**
 * mce_fdir_is_dup_fltr - test if filter is already in list for PF
 * @hw: hardware data structure
 * @input: Flow Director filter data structure
 *
 * Returns: true if the filter is found in the list
 */
bool mce_fdir_is_dup_fltr(struct mce_hw *hw,
			  struct mce_fdir_fltr *input)
{
	struct mce_fdir_fltr *rule = NULL;
	bool ret = false;

	list_for_each_entry(rule, &hw->fdir_list_head, fltr_node) {
		if (rule->flow_type != input->flow_type)
			continue;

		ret = mce_fdir_comp_rules(rule, input);
		if (ret) {
			if (rule->vfid == input->vfid)
				break;
			ret = false;
		}
	}

	return ret;
}
