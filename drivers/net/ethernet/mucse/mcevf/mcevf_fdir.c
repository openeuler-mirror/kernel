// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_fdir.h"

/**
 * mcevf_fdir_find_fltr_by_idx - find filter with idx
 * @hw: pointer to hardware structure
 * @fltr_idx: index to find.
 *
 * Returns pointer to filter if found or null
 */
struct mcevf_fdir_fltr *mcevf_fdir_find_fltr_by_idx(struct mcevf_hw *hw,
						    u32 fltr_idx)
{
	struct mcevf_fdir_fltr *rule;

	list_for_each_entry(rule, &hw->fdir_list_head, fltr_node) {
		/* rule ID found in the list */
		if (fltr_idx == rule->fltr_id)
			return rule;
		if (fltr_idx < rule->fltr_id)
			break;
	}
	return NULL;
}

/**
 * mcevf_fdir_comp_rules - compare 2 filters
 * @a: a Flow Director filter data structure
 * @b: a Flow Director filter data structure
 *
 * Returns true if the filters match
 */
static bool mcevf_fdir_comp_rules(struct mcevf_fdir_fltr *a,
				  struct mcevf_fdir_fltr *b)
{
	enum mcevf_fltr_ptype flow_type = a->flow_type;
	bool ret = false;

	switch (flow_type) {
	case MCEVF_FLTR_PTYPE_IPV4_TCP:
	case MCEVF_FLTR_PTYPE_IPV4_UDP:
	case MCEVF_FLTR_PTYPE_IPV4_SCTP:
		if (a->ip.v4.dst_ip == b->ip.v4.dst_ip &&
		    a->ip.v4.src_ip == b->ip.v4.src_ip &&
		    a->ip.v4.dst_port == b->ip.v4.dst_port &&
		    a->ip.v4.src_port == b->ip.v4.src_port) {
			ret = true;
		}
		break;
	case MCEVF_FLTR_PTYPE_IPV4_OTHER:
		if (a->ip.v4.dst_ip == b->ip.v4.dst_ip &&
		    a->ip.v4.src_ip == b->ip.v4.src_ip &&
		    a->ip.v4.l4_header == b->ip.v4.l4_header &&
		    a->ip.v4.proto == b->ip.v4.proto &&
		    a->ip.v4.ip_ver == b->ip.v4.ip_ver &&
		    a->ip.v4.tos == b->ip.v4.tos) {
			ret = true;
		}
		break;
	case MCEVF_FLTR_PTYPE_IPV6_TCP:
	case MCEVF_FLTR_PTYPE_IPV6_UDP:
	case MCEVF_FLTR_PTYPE_IPV6_SCTP:
		if (a->ip.v6.dst_port == b->ip.v6.dst_port &&
		    a->ip.v6.src_port == b->ip.v6.src_port &&
		    !memcmp(a->ip.v6.dst_ip, b->ip.v6.dst_ip,
			    4 * sizeof(__be32)) &&
		    !memcmp(a->ip.v6.src_ip, b->ip.v6.src_ip,
			    4 * sizeof(__be32))) {
			ret = true;
		}
		break;
	case MCEVF_FLTR_PTYPE_IPV6_OTHER:
		if (a->ip.v6.dst_port == b->ip.v6.dst_port &&
		    a->ip.v6.src_port == b->ip.v6.src_port) {
			ret = true;
		}
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

/**
 * mcevf_fdir_is_dup_fltr - test if filter is already in list for PF
 * @hw: hardware data structure
 * @input: Flow Director filter data structure
 *
 * Returns true if the filter is found in the list
 */
bool mcevf_fdir_is_dup_fltr(struct mcevf_hw *hw,
			    struct mcevf_fdir_fltr *input)
{
	struct mcevf_fdir_fltr *rule = NULL;
	bool ret = false;

	list_for_each_entry(rule, &hw->fdir_list_head, fltr_node) {
		if (rule->flow_type != input->flow_type)
			continue;

		ret = mcevf_fdir_comp_rules(rule, input);
		if (ret) {
			if (rule->fltr_id == input->fltr_id &&
			    rule->q_id != input->q_id)
				ret = false;
			else
				break;
		}
	}

	return ret;
}
