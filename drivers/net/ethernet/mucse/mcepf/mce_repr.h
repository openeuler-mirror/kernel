/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_REPR_H_
#define _MCE_REPR_H_
#include "mce_switch.h"

#define MCE_REPR_DRIVERINFO "mce_n20_rep"

#define MCE_REPR_PF_BASE_PORT 127
#define MCE_REP_DEFAULT_PSEUDO_RING_SIZE 64

struct mce_rep_sw_stats {
	u64 rx_packets, tx_packets;
	u64 rx_bytes, tx_bytes;
	u64 rx_dropped, tx_errors;
	u64 rx_csum_err;
};

struct mce_repr {
	struct mce_vsi *src_vsi;
	struct vf_info *vfinfo;
	int vfid;
	int dft_ring_id;
	struct mce_q_vector *q_vector;
	struct net_device *netdev;
	struct metadata_dst *dst;
	/* info about slow path rule */
	struct mce_rule_query_data sp_rule;
	struct sk_buff *skb;
	/* Protects the representor receive pseudo-ring and list. */
	spinlock_t rx_lock;
	u64 write_index, read_index;
	u64 rx_pring_size;
	struct list_head list;
	struct list_head rx_list;
	struct mce_rep_sw_stats stats;
};

#if IS_ENABLED(CONFIG_NET_DEVLINK)
int mce_repr_poll(struct napi_struct *napi, int weight);
void mce_repr_rx_packet(struct mce_pf *pf, int repr_port,
			struct mce_ring *rx_ring,
			struct mce_rx_desc_up *rx_desc,
			struct sk_buff *skb);
#endif
int mce_repr_add_for_all_vfs(struct mce_pf *pf);
void mce_repr_rem_from_all_vfs(struct mce_pf *pf);
#if IS_ENABLED(CONFIG_NET_DEVLINK)
struct mce_repr *mce_netdev_to_repr(struct net_device *netdev);
bool mce_is_port_repr_netdev(struct net_device *netdev);
#else
static inline struct mce_repr *
mce_netdev_to_repr(struct net_device *netdev)
{
	return NULL;
}

static inline bool mce_is_port_repr_netdev(struct net_device *netdev)
{
	return false;
}
#endif /* CONFIG_NET_DEVLINK */

#endif /* _MCE_REPR_H_ */
