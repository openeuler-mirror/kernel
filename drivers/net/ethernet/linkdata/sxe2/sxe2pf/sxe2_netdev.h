/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_netdev.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_NETDEV_H__
#define __SXE2_NETDEV_H__

#include "sxe2_compat.h"
#include "sxe2_vsi.h"
#include "sxe2_mbx_public.h"

#define NETIF_VLAN_FILTERING_FEATURES                                          \
	(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER)

#define NETIF_VLAN_STRIPPING_FEATURES                                          \
	(NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_STAG_RX)

#define NETIF_VLAN_OFFLOAD_FEATURES                                            \
	(NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX |                   \
	 NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX)

#define SXE2_PACKET_HDR_PAD (ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))

#define SXE2_XDP_PASS	  (0)
#define SXE2_XDP_CONSUMED BIT(0)
#define SXE2_XDP_TX	  BIT(1)
#define SXE2_XDP_REDIR	  BIT(2)

struct sxe2_indr_block_priv {
	struct net_device *netdev;
	struct sxe2_netdev_priv *np;
	struct list_head list;
};

struct sxe2_netdev_priv {
	struct sxe2_vsi *vsi;
	struct sxe2_vf_repr *repr;
	struct list_head tc_indr_block_priv_list;
#ifndef HAVE_TC_FLOW_INDIR_DEV
	struct notifier_block netdevice_nb;
#endif
};

s32 sxe2_open(struct net_device *netdev);

s32 sxe2_stop(struct net_device *netdev);

s32 sxe2_netdev_init(struct sxe2_vsi *vsi);

void sxe2_netdev_deinit(struct sxe2_vsi *vsi);

s32 sxe2_netdev_register(struct sxe2_vsi *vsi);

void sxe2_fetch_u64_data_per_ring(struct u64_stats_sync *syncp,
				  struct sxe2_queue_stats *stats, u64 *pkts,
				  u64 *bytes);

void sxe2_set_vlan_offload_features(struct sxe2_vsi *vsi,
				    netdev_features_t current_features,
				    netdev_features_t requested_features);

s32 sxe2_set_vlan_filter_features(struct sxe2_vsi *vsi,
				  netdev_features_t features);

bool netif_is_sxe2(struct net_device *netdev);

#ifdef HAVE_NETDEV_MIN_MAX_MTU
void sxe2_netdev_mtu_init(struct net_device *netdev);
#endif

void sxe2_netdev_feature_init(struct net_device *netdev);

#ifdef HAVE_TC_INDIR_BLOCK
s32 sxe2_tc_indir_block_register(struct sxe2_vsi *vsi);

void sxe2_tc_indir_block_unregister(struct sxe2_vsi *vsi);
#endif

bool sxe2_netdev_is(struct net_device *dev);

s32 sxe2_check_vf_ready_for_cfg(struct sxe2_vf_node *vf);

#ifdef HAVE_XDP_SUPPORT
s32 sxe2_xmit_xdp_buff(struct xdp_buff *xdp, struct sxe2_queue *xdp_ring);

s32 sxe2_xmit_xdp_ring(void *data, u16 size, struct sxe2_queue *xdp_ring);

s32 sxe2_destroy_xdp_rings(struct sxe2_vsi *vsi, bool is_rebuild);

s32 sxe2_prepare_xdp_rings(struct sxe2_vsi *vsi, struct bpf_prog *prog);

void sxe2_vsi_xdp_qs_stats_deinit(struct sxe2_vsi *vsi);
#endif

s32 sxe2_netdev_q_cnt_set(struct net_device *netdev, u16 txq_cnt, u16 rxq_cnt,
			  bool is_locked);

s32 sxe2_set_mtu_cfg(struct sxe2_adapter *adapter, u32 set_mtu);

s32 sxe2_cfg_vf_bw(struct sxe2_adapter *adapter, s32 vf_idx,
		   s32 min_tx_rate, s32 max_tx_rate);

s32 sxe2_net_link_down(struct sxe2_adapter *adapter);

s32 sxe2_link_up(struct sxe2_adapter *adapter);

#endif
