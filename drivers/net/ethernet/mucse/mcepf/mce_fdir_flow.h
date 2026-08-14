/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_FDIR_FLOW_H_
#define _MCE_FDIR_FLOW_H_

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

#include "mce_parse.h"
#include "mce_profile_mask.h"
#include "mce_pattern.h"

struct mce_fdir_filter {
	struct mce_rule_date data;
	struct mce_hw_rule_inset hw_inset;
	union mce_fdir_pattern lkup_pattern;
	struct hlist_node hl_node;
	u64 key;
	bool is_ipv6;

	struct mce_flow_action actions;
	u32 fdirhash; /* hash value for fdir */
	u32 signhash;
	bool hash_child;
	u16 profile_id;
	struct mce_lkup_meta *meta;
	struct mce_field_bitmask_info *mask_info;
	u64 options;
	u16 meta_num;
	u16 loc;
	int rule_engine;
};

struct mce_fdir_hash_entry {
	u32 fdir_hash;
	bool is_ipv6;
	struct list_head entry;
	struct list_head node_entries;
};

struct mce_fdir_field_mask {
	u16 key_off;
	u16 mask;
	u16 loc;
	bool used;
	u64 ref_count;
};

enum mce_fdir_usage_owner {
	MCE_FDIR_USAGE_TC,
	MCE_FDIR_USAGE_ARFS,
	MCE_FDIR_USAGE_OWNER_MAX,
};

struct mce_fdir_rule_usage {
	atomic_t ipv4_cnt;
	atomic_t ipv6_cnt;
};

struct mce_fdir_handle {
	DECLARE_HASHTABLE(fdir_exact_tb, MCE_FDIR_EXACT_ENTRAYS_BITS);
	DECLARE_HASHTABLE(fdir_sign_tb, MCE_FDIR_SIGN_ENTRAYS_BITS);
	struct list_head hash_node_v4_list;
	struct list_head hash_node_v6_list;
	enum mce_fdir_mode_type mode;
	enum mce_fdir_hash_mode hash_mode;
	struct mce_fdir_field_mask field_mask[32];
	struct mce_lkup_meta meta_db[2][MCE_META_TYPE_MAX];
	struct mce_hw_profile *profiles[64];
	u32 entry_bitmap[128];
	struct mce_fdir_rule_usage usage[MCE_FDIR_MAX_MODE]
					 [MCE_FDIR_USAGE_OWNER_MAX];
	bool fdir_flush_en;
};

static inline unsigned int __user_popcount(u64 x)
{
	unsigned int count = 0;

	while (x) {
		count += x & 1;
		x >>= 1;
	}
	return count;
}

typedef int (*mce_fdir_profile_key_encode)(struct mce_fdir_filter *filter);
struct mce_fdir_key_encode {
	u64 profile_id;
	mce_fdir_profile_key_encode key_encode;
};

struct mce_flow_ptype_match;
int mce_fdir_find_prof_id(struct mce_pf *pf, u8 *compose, u16 *prof_id,
			  struct mce_tc_flower_fltr *tc_fltr);
struct mce_fdir_filter *
mce_meta_to_fdir_rule(struct mce_hw *hw,
		      struct mce_fdir_handle *handle, u16 meta_num,
			bool is_ipv6, bool is_tunnel);
struct mce_fdir_filter *
mce_meta_to_fdir_rule_l2(struct mce_hw *hw, struct mce_fdir_handle *handle,
			 u16 meta_num, bool is_ipv6, bool is_tunnel);
int mce_fdir_key_setup(struct mce_fdir_filter *filter);
int mce_fdir_flow_force_delete(struct mce_pf *pf,
			       struct mce_fdir_filter *filter,
			       struct mce_tc_flower_fltr *fltr);
#endif /* CONFIG_NET_CLS_FLOWER */
#endif /* _MCE_FDIR_FLOW__H_ */
