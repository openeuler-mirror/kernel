/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_ARFS_H_
#define _MCE_ARFS_H_

extern bool mce_arfs_enable;

#if IS_ENABLED(CONFIG_RFS_ACCEL) && IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#include "mce_tc_lib.h"

enum mce_arfs_fltr_state {
	MCE_ARFS_INACTIVE,
	MCE_ARFS_ACTIVE,
	MCE_ARFS_TODEL,
};

struct mce_arfs_entry {
	struct mce_tc_flower_fltr fltr_info;
	struct hlist_node list_entry;
	struct mce_lkup_meta meta[MCE_META_TYPE_MAX];
	u64 time_activated;
	u64 options;
	u32 flow_id;
	u16 profile_id;
	u16 hash_idx;
	u8 fltr_state;
	bool hw_rule;
};

struct mce_arfs_entry_ptr {
	struct mce_arfs_entry *arfs_entry;
	struct hlist_node list_entry;
};

struct mce_arfs_active_fltr_cntrs {
	atomic_t active_tcpv4_cnt;
	atomic_t active_tcpv6_cnt;
	atomic_t active_udpv4_cnt;
	atomic_t active_udpv6_cnt;
};

int mce_rx_flow_steer(struct net_device *netdev, const struct sk_buff *skb,
		      u16 rxq_idx, u32 flow_id);
bool mce_is_arfs_using_perfect_flow(struct mce_pf *pf, u16 profile_id);
bool mce_has_arfs_active_fltrs(struct mce_pf *pf);
bool mce_is_arfs_enabled(struct mce_pf *pf);
int mce_clear_arfs(struct mce_vsi *vsi);
void mce_reset_clear_arfs(struct mce_vsi *vsi);
void mce_free_cpu_rx_rmap(struct mce_vsi *vsi);
void mce_init_arfs(struct mce_vsi *vsi);
void mce_sync_arfs_fltrs(struct mce_pf *pf);
int mce_set_cpu_rx_rmap(struct mce_vsi *vsi);
void mce_remove_arfs(struct mce_pf *pf);
int mce_rebuild_arfs(struct mce_pf *pf);

#else
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

static inline int mce_clear_arfs(struct mce_vsi *vsi) { return 0; }
static inline void mce_reset_clear_arfs(struct mce_vsi *vsi) { }
static inline void mce_free_cpu_rx_rmap(struct mce_vsi *vsi) { }
static inline void mce_init_arfs(struct mce_vsi *vsi) { }
static inline void mce_sync_arfs_fltrs(struct mce_pf *pf) { }
static inline int mce_set_cpu_rx_rmap(struct mce_vsi *vsi) { return 0; }
static inline void mce_remove_arfs(struct mce_pf *pf) { }
static inline int mce_rebuild_arfs(struct mce_pf *pf) { return 0; }
#endif
#endif /* _MCE_ARFS_H_ */
