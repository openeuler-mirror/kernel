/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_PROFILE_MASK_H_
#define _MCE_PROFILE_MASK_H_
#include "mce_fdir_flow.h"

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

struct mce_field_bitmask_block {
	u64 options;
	u16 key_off;
	u16 mask;
	bool used;
};

struct mce_field_bitmask_info {
	struct mce_field_bitmask_block *field_bitmask;

	u16 ref_cnt;
	u16 used_block;
};

struct mce_hw_profile {
	u64 profile_id;
	u64 options;
	u64 fied_mask;

	struct mce_field_bitmask_info *mask_info;
	u64 bitmask_options;
	u32 ref_cnt;
};

struct mce_fdir_filter;
struct mce_hw_profile *
mce_fdir_alloc_profile(struct mce_fdir_handle *handle,
		       struct mce_fdir_filter *filter);
int mce_fdir_remove_profile(struct mce_hw *hw,
			    struct mce_fdir_handle *handle,
			    struct mce_fdir_filter *filter);
int mce_fdir_restore_hw_profile(struct mce_pf *pf,
				struct mce_fdir_handle *handle,
				struct mce_fdir_filter *filter);
int mce_prof_bitmask_alloc(struct mce_hw *hw,
			   struct mce_fdir_handle *handle,
			   struct mce_field_bitmask_info *mask_info);
int mce_check_conflct_filed_bitmask(struct mce_hw_profile *profile,
				    struct mce_field_bitmask_info *mask_info);
int mce_check_field_bitmask_valid(struct mce_lkup_meta *meta);
int mce_fdir_field_mask_init(struct mce_lkup_meta *meta, u16 meta_num,
			     struct mce_field_bitmask_info *mask_info);
int mce_conflict_profile_check(struct mce_fdir_handle *handle,
			       struct mce_fdir_filter *filter);
bool mce_fdir_profile_mask_conflict(struct mce_fdir_handle *handle,
				    struct mce_fdir_filter *filter);
#endif /* CONFIG_NET_CLS_FLOWER */
#endif /* _MCE_PROFILE_MASK_H_ */
