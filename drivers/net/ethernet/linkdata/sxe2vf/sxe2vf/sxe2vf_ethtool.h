/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_ethtool.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_ETHTOOL_H__
#define __SXE2VF_ETHTOOL_H__
#include <linux/ethtool.h>

#include "sxe2vf.h"
#include "sxe2vf_netdev.h"

#define SXE2VF_Q_STATS_LEN	      (2)

#define SXE2VF_IPV6_PRIORITY_SHIFT (4)
#define SXE2VF_IPPROTO_L2TPV3      (115)
#define SXE2VF_FNAV_HAS_FLEX_FIELD (1)
#define SXE2VF_FNAV_NO_FLEX_FIELD  (0)

static inline u32 sxe2vf_q_stats_len(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi	       = adapter->vsi_ctxt.vf_vsi;

	return (vsi->txqs.q_cnt + vsi->rxqs.q_cnt) * SXE2VF_Q_STATS_LEN;
}

static inline u32 sxe2vf_txq_stats_len(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi	       = adapter->vsi_ctxt.vf_vsi;

	return ((vsi->txqs.q_cnt) *
		(sizeof(struct sxe2vf_txq_stats) / sizeof(u64)));
}

static inline u32 sxe2vf_rxq_stats_len(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi	       = adapter->vsi_ctxt.vf_vsi;

	return ((vsi->rxqs.q_cnt) *
		(sizeof(struct sxe2vf_rxq_stats) / sizeof(u64)));
}

enum sxe2vf_priv_flag_index {
	SXE2VF_PRIV_FLAGS_LEGACY_RX,
	SXE2VF_PRIV_FLAGS_FNAV_TUNNEL,
};

struct sxe2vf_priv_flag {
	char name[ETH_GSTRING_LEN];
	enum sxe2vf_adapter_flags adapter_flag_bitno;
	enum sxe2vf_priv_flag_index priv_flag_bitno;
};

static const struct sxe2vf_priv_flag sxe2vf_gstrings_priv_flags[] = {
	{"legacy-rx", SXE2VF_FLAG_LEGACY_RX_ENABLE, SXE2VF_PRIV_FLAGS_LEGACY_RX},
	{"fnav-tunnel", SXE2VF_FLAG_FNAV_TUNNEL, SXE2VF_PRIV_FLAGS_FNAV_TUNNEL},
};

enum sxe2_link_vf_get_speed {
	SXE2_LINK_SPEED_VF_UNKNOWN = 0,
	SXE2_LINK_SPEED_VF_10G	  = 10000,
	SXE2_LINK_SPEED_VF_25G	  = 25000,
	SXE2_LINK_SPEED_VF_50G	  = 50000,
	SXE2_LINK_SPEED_VF_100G	  = 100000,
	SXE2_LINK_SPEED_VF_AUTO	  = 200000,
};

enum sxe2_vf_flm_autoneg { FLM_VF_DISAN = 0, FLM_VF_ENAN = 1 };

struct sxe2vf_stats {
	char stats_string[ETH_GSTRING_LEN];
	u32 sizeof_stats;
	u32 stats_offset;
};

#define SXE2VF_STAT(_type, _name, type)                                      \
	{                                                                      \
		.stats_string = _name,                                         \
		.sizeof_stats = sizeof_field(_type, type),                   \
		.stats_offset = offsetof(_type, type)                        \
	}
#define SXE2VF_VSI_SW_STAT(_name, _stat)                                       \
	SXE2VF_STAT(struct sxe2vf_vsi_sw_stats, _name, _stat)
#define SXE2VF_VSI_HW_STAT(_name, _stat)                                       \
	SXE2VF_STAT(struct sxe2_vf_vsi_hw_stats, _name, _stat)

static const struct sxe2vf_stats sxe2vf_gstrings_vsi_hw_stats[] = {
	SXE2VF_VSI_HW_STAT("rx_vport_unicast_packets", rx_vsi_unicast_packets),
	SXE2VF_VSI_HW_STAT("rx_vport_bytes", rx_vsi_bytes),
	SXE2VF_VSI_HW_STAT("tx_vport_unicast_packets", tx_vsi_unicast_packets),
	SXE2VF_VSI_HW_STAT("tx_vport_bytes", tx_vsi_bytes),
	SXE2VF_VSI_HW_STAT("rx_vport_multicast_packets",
			   rx_vsi_multicast_packets),
	SXE2VF_VSI_HW_STAT("tx_vport_multicast_packets",
			   tx_vsi_multicast_packets),
	SXE2VF_VSI_HW_STAT("rx_vport_broadcast_packets",
			   rx_vsi_broadcast_packets),
	SXE2VF_VSI_HW_STAT("tx_vport_broadcast_packets",
			   tx_vsi_broadcast_packets),
};

static const struct sxe2vf_stats sxe2vf_gstrings_vsi_sw_stats[] = {
	SXE2VF_VSI_SW_STAT("rx_packets", rx_packets),
	SXE2VF_VSI_SW_STAT("rx_bytes", rx_bytes),
	SXE2VF_VSI_SW_STAT("tx_packets", tx_packets),
	SXE2VF_VSI_SW_STAT("tx_bytes", tx_bytes),

	SXE2VF_VSI_SW_STAT("rx_csum_unnecessary", rx_csum_unnecessary),
	SXE2VF_VSI_SW_STAT("rx_csum_none", rx_csum_none),
	SXE2VF_VSI_SW_STAT("rx_csum_complete", rx_csum_complete),
	SXE2VF_VSI_SW_STAT("rx_csum_unnecessary_inner",
			   rx_csum_unnecessary_inner),
	SXE2VF_VSI_SW_STAT("rx_csum_err", rx_csum_err),
	SXE2VF_VSI_SW_STAT("rx_lro_packets", rx_lro_packets),
	SXE2VF_VSI_SW_STAT("rx_lro_bytes", rx_lro_bytes),
	SXE2VF_VSI_SW_STAT("rx_lro_count", rx_lro_count),
	SXE2VF_VSI_SW_STAT("rx_removed_vlan_packets", rx_vlan_strip),
	SXE2VF_VSI_SW_STAT("rx_pkts_sw_drop", rx_pkts_sw_drop),
	SXE2VF_VSI_SW_STAT("rx_buff_alloc_err", rx_buff_alloc_err),
	SXE2VF_VSI_SW_STAT("rx_pg_alloc_fail", rx_pg_alloc_fail),
	SXE2VF_VSI_SW_STAT("rx_page_alloc", rx_page_alloc),
	SXE2VF_VSI_SW_STAT("rx_non_eop_descs", rx_non_eop_descs),
	SXE2VF_VSI_SW_STAT("rx_pa_err", rx_pa_err),

	SXE2VF_VSI_SW_STAT("tx_tso_packets", tx_tso_packets),
	SXE2VF_VSI_SW_STAT("tx_tso_bytes", tx_tso_bytes),
	SXE2VF_VSI_SW_STAT("tx_tso_linearize_chk", tx_tso_linearize_chk),
	SXE2VF_VSI_SW_STAT("tx_added_vlan_packets", tx_vlan_insert),
	SXE2VF_VSI_SW_STAT("tx_csum_none", tx_csum_none),
	SXE2VF_VSI_SW_STAT("tx_csum_partial", tx_csum_partial),
	SXE2VF_VSI_SW_STAT("tx_csum_partial_inner", tx_csum_partial_inner),
	SXE2VF_VSI_SW_STAT("tx_stopped", tx_busy),
	SXE2VF_VSI_SW_STAT("tx_dropped", tx_queue_dropped),
	SXE2VF_VSI_SW_STAT("tx_xmit_more", tx_xmit_more),
	SXE2VF_VSI_SW_STAT("tx_wake", tx_restart),
	SXE2VF_VSI_SW_STAT("tx_linearize", tx_linearize),
};

#define SXE2VF_VSI_HW_STATS_LEN ARRAY_SIZE(sxe2vf_gstrings_vsi_hw_stats)
#define SXE2VF_VSI_SW_STATS_LEN ARRAY_SIZE(sxe2vf_gstrings_vsi_sw_stats)

#define SXE2VF_IPSEC_STATS_LEN                                                 \
	((sizeof_field(struct sxe2vf_queue_ipsec_stats, tx_error_invalid_sp) + \
	  sizeof_field(struct sxe2vf_queue_ipsec_stats,                        \
		       tx_error_invalid_state) +                               \
	  sizeof_field(struct sxe2vf_queue_ipsec_stats, tx_offload_success) +  \
	  sizeof_field(struct sxe2vf_queue_ipsec_stats, rx_error_invalid_sp) + \
	  sizeof_field(struct sxe2vf_queue_ipsec_stats,                        \
		       rx_error_invalid_state) +                               \
	  sizeof_field(struct sxe2vf_queue_ipsec_stats,                        \
		       rx_error_decrypt_fail) +                                \
	  sizeof_field(struct sxe2vf_queue_ipsec_stats, rx_offload_success)) / \
	 sizeof(__le64))

#define SXE2VF_FNAV_MATCH_STATS_LEN                                            \
	(sizeof_field(struct sxe2vf_fnav_context, fnav_match) / sizeof(u64))

#define SXE2VF_ALL_STATS_LEN(n)                                                \
	({ \
		typeof(n) _n = (n); \
		((SXE2VF_VSI_HW_STATS_LEN + SXE2VF_IPSEC_STATS_LEN +           \
		  SXE2VF_VSI_SW_STATS_LEN + sxe2vf_q_stats_len(_n)) +          \
		 sxe2vf_rxq_stats_len(_n) + sxe2vf_txq_stats_len(_n) +         \
		 SXE2VF_FNAV_MATCH_STATS_LEN); \
	})

#define SXE2VF_PRIV_FLAG_LEN ARRAY_SIZE(sxe2vf_gstrings_priv_flags)

void sxe2vf_ethtool_ops_init(struct net_device *netdev);
s32 sxe2vf_stats_push_sync(struct sxe2vf_adapter *adapter);

s32 sxe2vf_fill_fnav_filter_full_msg(struct sxe2vf_adapter *adapter,
				     struct sxe2vf_fnav_filter *filter);

s32 sxe2vf_fnav_add_filter_with_packet(struct sxe2vf_adapter *adapter,
				       struct sxe2vf_fnav_filter *filter);

void sxe2vf_vsi_sw_stats_update(struct sxe2vf_vsi *vsi);

#endif
