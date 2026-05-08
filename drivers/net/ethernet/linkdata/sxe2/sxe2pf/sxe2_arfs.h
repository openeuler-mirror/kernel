/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_arfs.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_ARFS_H__
#define __SXE2_ARFS_H__

#include "sxe2_fnav.h"

#define SXE2_MAX_RFS_FILTERS (0xFFFF)
#define SXE2_MAX_ARFS_LIST   (1024)
#define SXE2_ARFS_LIST_MASK  (SXE2_MAX_ARFS_LIST - 1)

#define LOG_ARFS(fmt, ...) LOG_DEBUG_BDF("ARFS_LOG: " fmt, ##__VA_ARGS__)

enum sxe2_arfs_filter_state {
	SXE2_ARFS_FILTER_INACTIVE,
	SXE2_ARFS_FILTER_ACTIVE,
	SXE2_ARFS_FILTER_MODIFY,
	SXE2_ARFS_FILTER_CONFLICT,
	SXE2_ARFS_FILTER_TODEL,
};

struct sxe2_arfs_filter {
	struct hlist_node hl_node;
	struct sxe2_fnav_filter filter_info;
	u64 time_activated;
	u32 filter_idx;
	u32 flow_id;
	enum sxe2_arfs_filter_state filter_state;
};

struct sxe2_arfs_entry_ptr {
	struct sxe2_arfs_filter *arfs_filter;
	struct hlist_node hl_node;
};

struct sxe2_arfs_active_filter_cnt {
	u32 tcp4_cnt;
	u32 tcp6_cnt;
	u32 udp4_cnt;
	u32 udp6_cnt;
};

struct sxe2_arfs_ctxt {
	struct hlist_head *filter_list;

	/* in order to protect the data */
	spinlock_t filter_lock;
	u32 last_filter_id;
	struct sxe2_arfs_active_filter_cnt filter_cnt;

	/* in order to protect the data */
	struct mutex update_list_lock;
	u16 vsi_id_in_pf;
};

#ifdef CONFIG_RFS_ACCEL
s32 sxe2_arfs_init(struct sxe2_adapter *adapter);

void sxe2_arfs_deinit(struct sxe2_adapter *adapter);

void sxe2_arfs_clean(struct sxe2_adapter *adapter);

s32 sxe2_arfs_enable(struct sxe2_adapter *adapter);

void sxe2_arfs_disable(struct sxe2_adapter *adapter);

s32 sxe2_cpu_rx_rmap_set(struct sxe2_vsi *vsi);

void sxe2_cpu_rx_rmap_free(struct sxe2_vsi *vsi);

int sxe2_rx_flow_steer(struct net_device *netdev,
		       const struct sk_buff *skb, u16 rxq_idx, u32 flow_id);

void sxe2_arfs_filters_sync(struct sxe2_adapter *adapter);

bool sxe2_arfs_flow_cfg_used(struct sxe2_adapter *adapter, u16 vsi_id,
			     enum sxe2_fnav_flow_type flow_type);

void sxe2_arfs_stats_dump(struct sxe2_adapter *adapter);
#else
static inline s32 sxe2_arfs_init(struct sxe2_adapter *adapter)
{
	return 0;
}

static inline void sxe2_arfs_deinit(struct sxe2_adapter *adapter)
{
}

static inline void sxe2_arfs_clean(struct sxe2_adapter *adapter)
{
}

static inline s32 sxe2_arfs_enable(struct sxe2_adapter *adapter)
{
	return 0;
}

static inline void sxe2_arfs_disable(struct sxe2_adapter *adapter)
{
}

static inline s32 sxe2_cpu_rx_rmap_set(struct sxe2_vsi *vsi)
{
	return 0;
}

static inline void sxe2_cpu_rx_rmap_free(struct sxe2_vsi *vsi)
{
}

static inline int sxe2_rx_flow_steer(struct net_device *netdev,
				     const struct sk_buff *skb,
				     u16 rxq_idx, u32 flow_id)
{
	return -EOPNOTSUPP;
}

static inline void sxe2_arfs_filters_sync(struct sxe2_adapter *adapter)
{
}

static inline bool sxe2_arfs_flow_cfg_used(struct sxe2_adapter *adapter, u16 vsi_id,
					   enum sxe2_fnav_flow_type flow_type)
{
	return false;
}

static inline void sxe2_arfs_stats_dump(struct sxe2_adapter *adapter)
{
}
#endif

#endif
