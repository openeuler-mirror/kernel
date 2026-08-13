/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_ARFS_H_
#define _MCE_ARFS_H_

extern bool mce_arfs_enable;

struct mce_arfs_active_fltr_cntrs;

static inline int mce_rx_flow_steer(struct net_device *netdev,
				    const struct sk_buff *skb, u16 rxq_idx,
				    u32 flow_id)
{
	return -EOPNOTSUPP;
}

static inline bool mce_is_arfs_using_perfect_flow(struct mce_pf *pf,
						  u16 profile_id)
{
	return false;
}

static inline bool mce_has_arfs_active_fltrs(struct mce_pf *pf)
{
	return false;
}

static inline bool mce_is_arfs_enabled(struct mce_pf *pf)
{
	return false;
}

static inline void mce_clear_arfs(struct mce_vsi *vsi) { }
static inline void mce_free_cpu_rx_rmap(struct mce_vsi *vsi) { }
static inline void mce_init_arfs(struct mce_vsi *vsi) { }
static inline void mce_sync_arfs_fltrs(struct mce_pf *pf) { }
static inline int mce_set_cpu_rx_rmap(struct mce_vsi *vsi) { return 0; }
static inline void mce_remove_arfs(struct mce_pf *pf) { }
static inline void mce_rebuild_arfs(struct mce_pf *pf) { }
#endif /* _MCE_ARFS_H_ */
