/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ethtool.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_ETHTOOL_H__
#define __SXE2_ETHTOOL_H__
#include <linux/ethtool.h>

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_netdev.h"
#include "sxe2_common.h"
#include "sxe2_vsi.h"
#include "sxe2_log.h"
#include "sxe2_msg.h"

#define SXE2_PF_DOWN_ETHTOOL_BASE_SPEED (0xffffffff)
#define SXE2_LB_FRAME_SIZE (64)
#define SXE2_Q_STATS_LEN   (2)
#define SXE2_STATS(_type, _name, type)                                       \
	{                                                                      \
		.stats_string = _name,                                         \
		.sizeof_stats = sizeof_field(_type, type),                   \
		.stats_offset = offsetof(_type, type)                        \
	}
#define SXE2_VSI_SW_STATS(_name, _stats)                                       \
	SXE2_STATS(struct sxe2_vsi_sw_stats, _name, _stats)
#define SXE2_PF_HW_STATS(_name, _stats)                                        \
	SXE2_STATS(struct sxe2_pf_hw_stats, _name, _stats)
#define SXE2_VSI_HW_STATS(_name, _stats)                                       \
	SXE2_STATS(struct sxe2_vsi_hw_stats, _name, _stats)
#define SXE2_PF_SW_STATS(_name, _stats)                                        \
	SXE2_STATS(struct sxe2_pf_sw_stats, _name, _stats)

struct sxe2_stats {
	char stats_string[ETH_GSTRING_LEN];
	u32 sizeof_stats;
	u32 stats_offset;
};

struct sxe2_eth_link {
	u32 link_speed;
	u16 link_duplex;
	u16 link_autoneg;
	u16 link_status;
};

enum sxe2_flm_autoneg { FLM_DISAN = 0, FLM_ENAN = 1 };

enum sxe2_media_get_type {
	SXE2_MEDIA_GET_NONE = 0,
	SXE2_MEDIA_GET_UNKNOWN,
	SXE2_MEDIA_GET_FIBER,
	SXE2_MEDIA_GET_BASET,
	SXE2_MEDIA_GET_BACKPLANE,
	SXE2_MEDIA_GET_DA,
	SXE2_MEDIA_GET_AUI,
};

enum sxe2_fw_link_speed_type {
	SXE2_SET_LINK_SPEED_CFG_10G = 0,
	SXE2_SET_LINK_SPEED_CFG_25G,
	SXE2_SET_LINK_SPEED_CFG_50G,
	SXE2_SET_LINK_SPEED_CFG_100G,
	SXE2_SET_LINK_SPEED_CFG_AUTO = 15,
	SXE2_SET_LINK_SPEED_CFG_MAX,
};

enum sxe2_priv_flag_index {
	SXE2_ETHTOOL_PRIV_FLAG_LEGACY_RX,
	SXE2_ETHTOOL_PRIV_FLAG_MDD_AUTO_RESET_VF,
	SXE2_ETHTOOL_PRIV_FLAG_DCBX_AGENT,
	SXE2_ETHTOOL_PRIV_FLAG_FNAV_TUNNEL,
	SXE2_ETHTOOL_PRIV_FLAG_LINK_DOWN_ON_CLOSE,
};

struct sxe2_priv_flag {
	char name[ETH_GSTRING_LEN];
	enum sxe2_adapter_flags adapter_flag_bitno;
	enum sxe2_priv_flag_index priv_flag_bitno;
};

static const struct sxe2_priv_flag sxe2_gstrings_priv_flags[] = {
	{ "legacy-rx", SXE2_FLAG_LEGACY_RX_ENABLE,
	  SXE2_ETHTOOL_PRIV_FLAG_LEGACY_RX },
	{ "mdd-auto-reset-vf", SXE2_FLAG_MDD_AUTO_RESET_VF,
	  SXE2_ETHTOOL_PRIV_FLAG_MDD_AUTO_RESET_VF },
	{ "dcbx-agent", SXE2_FLAG_FW_DCBX_AGENT,
	  SXE2_ETHTOOL_PRIV_FLAG_DCBX_AGENT },
	{ "fnav-tunnel", SXE2_FLAG_FNAV_TUNNEL_ENABLE,
	  SXE2_ETHTOOL_PRIV_FLAG_FNAV_TUNNEL },
	{ "link-down-on-close", SXE2_FLAG_LINK_DOWN_ON_CLOSE,
	  SXE2_ETHTOOL_PRIV_FLAG_LINK_DOWN_ON_CLOSE },
};

#define SXE2_PRIV_FLAG_ARRAY_SIZE ARRAY_SIZE(sxe2_gstrings_priv_flags)
static const struct sxe2_stats sxe2_gstrings_vsi_sw_stats[] = {
	SXE2_VSI_SW_STATS("rx_packets", rx_packets),
	SXE2_VSI_SW_STATS("rx_bytes", rx_bytes),
	SXE2_VSI_SW_STATS("tx_packets", tx_packets),
	SXE2_VSI_SW_STATS("tx_bytes", tx_bytes),

	SXE2_VSI_SW_STATS("rx_csum_unnecessary", rx_csum_unnecessary),
	SXE2_VSI_SW_STATS("rx_csum_none", rx_csum_none),
	SXE2_VSI_SW_STATS("rx_csum_complete", rx_csum_complete),
	SXE2_VSI_SW_STATS("rx_csum_unnecessary_inner",
			  rx_csum_unnecessary_inner),
	SXE2_VSI_SW_STATS("rx_csum_err", rx_csum_err),
	SXE2_VSI_SW_STATS("rx_lro_packets", rx_lro_packets),
	SXE2_VSI_SW_STATS("rx_lro_bytes", rx_lro_bytes),
	SXE2_VSI_SW_STATS("rx_lro_count", rx_lro_count),
	SXE2_VSI_SW_STATS("rx_removed_vlan_packets", rx_vlan_strip),
	SXE2_VSI_SW_STATS("rx_pkts_sw_drop", rx_pkts_sw_drop),
	SXE2_VSI_SW_STATS("rx_buff_alloc_err", rx_buff_alloc_err),
	SXE2_VSI_SW_STATS("rx_pg_alloc_fail", rx_pg_alloc_fail),
	SXE2_VSI_SW_STATS("rx_page_alloc", rx_page_alloc),
	SXE2_VSI_SW_STATS("rx_non_eop_descs", rx_non_eop_descs),

	SXE2_VSI_SW_STATS("rx_xdp_drop", rx_xdp_drop),
	SXE2_VSI_SW_STATS("rx_xdp_redirect", rx_xdp_redirect),
	SXE2_VSI_SW_STATS("rx_xdp_redirect_fail", rx_xdp_redirect_fail),
	SXE2_VSI_SW_STATS("rx_xdp_pkts", rx_xdp_pkts),
	SXE2_VSI_SW_STATS("rx_xdp_bytes", rx_xdp_bytes),
	SXE2_VSI_SW_STATS("rx_xdp_pass", rx_xdp_pass),
	SXE2_VSI_SW_STATS("rx_xdp_unknown", rx_xdp_unknown),
	SXE2_VSI_SW_STATS("rx_xdp_tx_xmit", rx_xdp_tx_xmit),
	SXE2_VSI_SW_STATS("rx_xdp_tx_xmit_fail", rx_xdp_tx_xmit_fail),

	SXE2_VSI_SW_STATS("rx_xsk_drop", rx_xsk_drop),
	SXE2_VSI_SW_STATS("rx_xsk_redirect", rx_xsk_redirect),
	SXE2_VSI_SW_STATS("rx_xsk_redirect_fail", rx_xsk_redirect_fail),
	SXE2_VSI_SW_STATS("rx_xsk_packets", rx_xsk_packets),
	SXE2_VSI_SW_STATS("rx_xsk_bytes", rx_xsk_bytes),
	SXE2_VSI_SW_STATS("rx_xsk_pass", rx_xsk_pass),
	SXE2_VSI_SW_STATS("rx_xsk_unknown", rx_xsk_unknown),
	SXE2_VSI_SW_STATS("rx_xsk_tx_xmit", rx_xsk_tx_xmit),
	SXE2_VSI_SW_STATS("rx_xsk_tx_xmit_fail", rx_xsk_tx_xmit_fail),
	SXE2_VSI_SW_STATS("rx_pa_err", rx_pa_err),

	SXE2_VSI_SW_STATS("tx_tso_packets", tx_tso_packets),
	SXE2_VSI_SW_STATS("tx_tso_bytes", tx_tso_bytes),
	SXE2_VSI_SW_STATS("tx_tso_linearize_chk", tx_tso_linearize_chk),
	SXE2_VSI_SW_STATS("tx_added_vlan_packets", tx_vlan_insert),
	SXE2_VSI_SW_STATS("tx_csum_none", tx_csum_none),
	SXE2_VSI_SW_STATS("tx_csum_partial", tx_csum_partial),
	SXE2_VSI_SW_STATS("tx_csum_partial_inner", tx_csum_partial_inner),
	SXE2_VSI_SW_STATS("tx_stopped", tx_busy),
	SXE2_VSI_SW_STATS("tx_dropped", tx_queue_dropped),
	SXE2_VSI_SW_STATS("tx_xmit_more", tx_xmit_more),
	SXE2_VSI_SW_STATS("tx_wake", tx_restart),
	SXE2_VSI_SW_STATS("tx_linearize", tx_linearize),
};

static const struct sxe2_stats sxe2_gstrings_pf_hw_stats[] = {
	SXE2_PF_HW_STATS("tx_packets_phy", tx_frame_good),
	SXE2_PF_HW_STATS("rx_packets_phy", rx_frame_good),
	SXE2_PF_HW_STATS("tx_bytes_phy", tx_bytes_good),
	SXE2_PF_HW_STATS("rx_bytes_phy", rx_bytes_good),

	SXE2_PF_HW_STATS("tx_multicast_phy", tx_multicast_good),
	SXE2_PF_HW_STATS("rx_multicast_phy", rx_multicast_good),
	SXE2_PF_HW_STATS("tx_broadcast_phy", tx_broadcast_good),
	SXE2_PF_HW_STATS("rx_broadcast_phy", rx_broadcast_good),
	SXE2_PF_HW_STATS("rx_unicast_phy", rx_unicast_good),

	SXE2_PF_HW_STATS("tx_multicast_all_phy", tx_multicast),
	SXE2_PF_HW_STATS("tx_broadcast_all_phy", tx_broadcast),
	SXE2_PF_HW_STATS("tx_unicast_all_phy", tx_unicast),

	SXE2_PF_HW_STATS("tx_packets_all_phy", tx_frame_good_bad),
	SXE2_PF_HW_STATS("rx_packets_all_phy", rx_frame_good_bad),
	SXE2_PF_HW_STATS("tx_bytes_all_phy", tx_bytes_good_bad),
	SXE2_PF_HW_STATS("rx_bytes_all_phy", rx_byte_good_bad),

	SXE2_PF_HW_STATS("tx_64_bytes_phy", tx_size_64),
	SXE2_PF_HW_STATS("tx_65_to_127_bytes_phy", tx_size_65_127),
	SXE2_PF_HW_STATS("tx_128_to_255_bytes_phy", tx_size_128_255),
	SXE2_PF_HW_STATS("tx_256_to_511_bytes_phy", tx_size_256_511),
	SXE2_PF_HW_STATS("tx_512_to_1023_bytes_phy", tx_size_512_1023),
	SXE2_PF_HW_STATS("tx_1024_to_1522_bytes_phy", tx_size_1024_1522),
	SXE2_PF_HW_STATS("tx_1523_to_max_bytes_phy", tx_size_1523_max),
	SXE2_PF_HW_STATS("rx_64_bytes_phy", rx_size_64),

	SXE2_PF_HW_STATS("rx_65_to_127_bytes_phy", rx_size_65_127),
	SXE2_PF_HW_STATS("rx_128_to_255_bytes_phy", rx_size_128_255),
	SXE2_PF_HW_STATS("rx_256_to_511_bytes_phy", rx_size_256_511),
	SXE2_PF_HW_STATS("rx_512_to_1023_bytes_phy", rx_size_512_1023),
	SXE2_PF_HW_STATS("rx_1024_to_1522_bytes_phy", rx_size_1024_1522),
	SXE2_PF_HW_STATS("rx_1523_to_max_bytes_phy", rx_size_1523_max),

	SXE2_PF_HW_STATS("tx_vlan_packets_good_phy", tx_vlan_packet_good),
	SXE2_PF_HW_STATS("rx_vlan_packets_phy", rx_vlan_packets),

	SXE2_PF_HW_STATS("rx_pcs_symbol_err_phy", rx_pcs_symbol_err_phy),
	SXE2_PF_HW_STATS("rx_corrected_bits_phy", rx_corrected_bits_phy),
	SXE2_PF_HW_STATS("rx_undersize_pkts_phy", rx_undersize_good),
	SXE2_PF_HW_STATS("rx_fragments_phy", rx_runt_error),
	SXE2_PF_HW_STATS("rx_crc_errors_phy", rx_crc_errors),
	SXE2_PF_HW_STATS("rx_jabbers_phy", rx_jabbers),
	SXE2_PF_HW_STATS("rx_oversize_good_phy", rx_oversize_good),
	SXE2_PF_HW_STATS("rx_illegal_bytes_phy", rx_illegal_bytes),
	SXE2_PF_HW_STATS("rx_in_range_len_errs_phy", rx_len_errors),
	SXE2_PF_HW_STATS("rx_out_of_range_len_phy", rx_out_of_range_errors),
	SXE2_PF_HW_STATS("rx_oversize_pkts_phy", rx_oversize_pkts_phy),
	SXE2_PF_HW_STATS("rx_symbol_err_phy", rx_symbol_err),
	SXE2_PF_HW_STATS("rx_out_of_buffer", rx_out_of_buffer),
	SXE2_PF_HW_STATS("rx_discards_phy", rx_discards_phy),
	SXE2_PF_HW_STATS("tx_dropped_link_down_phy", tx_dropped_link_down),
	SXE2_PF_HW_STATS("tx_underflow_error_phy", tx_underflow_error),
	SXE2_PF_HW_STATS("tx_pause_ctrl_phy", tx_pause_frame),
	SXE2_PF_HW_STATS("rx_pause_ctrl_phy", rx_pause_frame),
	SXE2_PF_HW_STATS("rx_err_lane_0_phy", rx_err_lane_0_phy),
	SXE2_PF_HW_STATS("rx_err_lane_1_phy", rx_err_lane_1_phy),
	SXE2_PF_HW_STATS("rx_err_lane_2_phy", rx_err_lane_2_phy),
	SXE2_PF_HW_STATS("rx_err_lane_3_phy", rx_err_lane_3_phy),
	SXE2_PF_HW_STATS("fnav_match", fnav_match),
};

static const struct sxe2_stats sxe2_gstrings_pf_sw_stats[] = {
	SXE2_PF_SW_STATS("fnav_prgm_err", fnav_prgm_err),
};

static const struct sxe2_stats sxe2_gstrings_vsi_hw_stats[] = {
	SXE2_VSI_HW_STATS("rx_vport_unicast_packets", rx_vsi_unicast_packets),
	SXE2_VSI_HW_STATS("rx_vport_bytes", rx_vsi_bytes),
	SXE2_VSI_HW_STATS("tx_vport_unicast_packets", tx_vsi_unicast_packets),
	SXE2_VSI_HW_STATS("tx_vport_bytes", tx_vsi_bytes),
	SXE2_VSI_HW_STATS("rx_vport_multicast_packets",
			  rx_vsi_multicast_packets),
	SXE2_VSI_HW_STATS("tx_vport_multicast_packets",
			  tx_vsi_multicast_packets),
	SXE2_VSI_HW_STATS("rx_vport_broadcast_packets",
			  rx_vsi_broadcast_packets),
	SXE2_VSI_HW_STATS("tx_vport_broadcast_packets",
			  tx_vsi_broadcast_packets),
};

#ifdef SUPPORT_ETHTOOL_GET_RMON_STATS
static const struct ethtool_rmon_hist_range sxe2_rmon_ranges[] = {
	{ 0, 64 },     { 65, 127 },    { 128, 255 },   { 256, 511 },
	{ 512, 1023 }, { 1024, 1522 }, { 1523, 9728 }, {}
};
#endif

static inline u32 sxe2_q_stats_len(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;

	return (vsi->txqs.q_cnt + vsi->rxqs.q_cnt) * SXE2_Q_STATS_LEN;
}

static inline u32 sxe2_txq_stats_len(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;

	return ((vsi->txqs.q_cnt) *
		(sizeof(struct sxe2_txq_stats) / sizeof(u64)));
}

static inline u32 sxe2_rxq_stats_len(struct net_device *netdev)
{
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_vsi *vsi	      = priv->vsi;

	return ((vsi->rxqs.q_cnt) *
		(sizeof(struct sxe2_rxq_stats) / sizeof(u64)));
}

#define SXE2_PFC_STAT_FIELD(stat, dir)                                         \
	(sizeof_field(struct sxe2_dcb_stats,                                   \
		      curr_pause_stats.prio_x##stat##_##dir))
#define SXE2_PFC_STATS_LEN                                                     \
	((SXE2_PFC_STAT_FIELD(off, rx) + SXE2_PFC_STAT_FIELD(on, rx) +         \
	  SXE2_PFC_STAT_FIELD(off, tx) + SXE2_PFC_STAT_FIELD(on, tx)) /        \
	 sizeof(__le64))

#define SXE2_VSI_SW_STATS_LEN ARRAY_SIZE(sxe2_gstrings_vsi_sw_stats)
#define SXE2_PF_HW_STATS_LEN  ARRAY_SIZE(sxe2_gstrings_pf_hw_stats)
#define SXE2_VSI_HW_STATS_LEN ARRAY_SIZE(sxe2_gstrings_vsi_hw_stats)
#define SXE2_PF_SW_STATS_LEN  ARRAY_SIZE(sxe2_gstrings_pf_sw_stats)

#define SXE2_IPSEC_STATS_LEN                                                   \
	((sizeof_field(struct sxe2_queue_ipsec_stats, tx_error_invalid_sp) +   \
	  sizeof_field(struct sxe2_queue_ipsec_stats,                          \
		       tx_error_invalid_state) +                               \
	  sizeof_field(struct sxe2_queue_ipsec_stats, tx_offload_success) +    \
	  sizeof_field(struct sxe2_queue_ipsec_stats, rx_error_invalid_sp) +   \
	  sizeof_field(struct sxe2_queue_ipsec_stats,                          \
		       rx_error_invalid_state) +                               \
	  sizeof_field(struct sxe2_queue_ipsec_stats, rx_error_decrypt_fail) + \
	  sizeof_field(struct sxe2_queue_ipsec_stats, rx_offload_success)) /   \
	 sizeof(__le64))

#define SXE2_ALL_STATS_LEN(n)                                                  \
	({ \
		typeof(n) _n = (n); \
		((SXE2_PF_HW_STATS_LEN + SXE2_VSI_HW_STATS_LEN + IEEE_8021QAZ_MAX_TCS +     \
		  SXE2_VSI_SW_STATS_LEN + SXE2_PFC_STATS_LEN + SXE2_IPSEC_STATS_LEN +  \
		  SXE2_PF_SW_STATS_LEN + sxe2_q_stats_len(_n)) +                        \
		 sxe2_rxq_stats_len(_n) + sxe2_txq_stats_len(_n)); \
	})

#define sxe2_for_each_prioirty(type)                                              \
		for ((type) = 0; (type) < IEEE_8021Q_MAX_PRIORITIES; (type)++)

enum sxe2_ethtool_test_id {
	SXE2_ETH_TEST_REG = 0,
	SXE2_ETH_TEST_INTR,
	SXE2_ETH_TEST_LOOP,
	SXE2_ETH_TEST_LINK,
};

static const u32 sxe2_regs_dump_list[] = { SXE2_PF_INT_OICR_ENABLE,
					   SXE2_PF_INT_TQCTL(0),
					   SXE2_PF_INT_RQCTL(0) };

void sxe2_hw_pf_stats_update(struct sxe2_adapter *adapter);

void sxe2_hw_vsi_stats_update(struct sxe2_vsi *vsi);

void sxe2_stats_update(struct sxe2_adapter *adapter);
void sxe2_repr_vf_vsis_stats_acculate_update(struct sxe2_adapter *adapter);

void sxe2_ethtool_ops_set(struct net_device *netdev);

void sxe2_ethtool_ops_set_for_safe_mode(struct net_device *netdev);

void sxe2_ethtool_selftest(struct net_device *netdev,
			   struct ethtool_test *eth_test, u64 *data);
int sxe2_ethtool_selftest_count(struct net_device *netdev);
void sxe2_ethtool_selftest_strings(struct net_device *netdev, u8 *data);

s32 sxe2_vsi_qs_reassign(struct net_device *netdev,
			 struct ethtool_channels *ch);

s32 sxe2_fwc_sff_eeprom_get(struct sxe2_adapter *adapter, bool is_qsfp,
			    u16 bus_addr, u16 page, u16 offset, u16 data_len,
			    struct sxe2_sfp_resp *sff_value);

void __sxe2_get_drvinfo(struct net_device *netdev,
			struct ethtool_drvinfo *drvinfo, struct sxe2_adapter *adapter);

void __sxe2_get_strings(struct net_device *netdev, u32 stringset, u8 *data);
void __sxe2_repr_get_strings(struct net_device *netdev, u32 stringset,
			     u8 *data);

void __sxe2_get_ethtool_stats(struct net_device *netdev,
			      struct ethtool_stats __always_unused *stats,
			      u64 *data, struct sxe2_vsi *vsi);

void __sxe2_repr_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats __always_unused *stats,
				   u64 *data, struct sxe2_vsi *vsi);

void sxe2_stop_lfc(struct sxe2_adapter *adapter);

void sxe2_sw_vsi_stats_update(struct sxe2_vsi *vsi);

s32 sxe2_fwc_get_pf_stats(struct sxe2_adapter *adapter);

s32 sxe2_link_set_fc_pasist(struct sxe2_adapter *adapter, u8 rx_en, u8 tx_en);

s32 sxe2_link_set_fec_pasist(struct sxe2_adapter *adapter, u8 fec);

u32 sxe2_speed_switch_set_configure(u32 speed);

s32 sxe2_get_support_speed_ability(struct sxe2_adapter *adapter,
				   struct support_speed_ability_mode *speed_ability);

s32 sxe2_phy_type_to_ethtool(struct net_device *netdev,
			     struct ethtool_link_ksettings *ks);

s32 sxe2_get_link_configure(struct sxe2_adapter *adapter,
			    struct flm_ethtool_get_link_resp *link_cfg);

s32 sxe2_set_link_autoneg_en(struct sxe2_adapter *adapter, u32 an_en);

s32 sxe2_link_set_fc_configure(struct sxe2_adapter *adapter, u8 tx_fc,
			       u8 rx_fc);

u32 sxe2_speed_dut_switch_cfg(s32 speed);

s32 sxe2_get_cur_link_state(struct sxe2_adapter *adapter,
			    struct ethtool_flm_link_info *currect_info);

s32 sxe2_link_get_pasist_info(struct sxe2_adapter *adapter, struct flm_link_info_pasist *cfg);

u32 sxe2_ksettings_find_adv_link_speed(const struct ethtool_link_ksettings *ks);

#ifdef SXE2_SUPPORT_ACL
s32 sxe2_acl_add_rule_ethtool(struct sxe2_vsi *vsi, struct ethtool_rx_flow_spec *fsp);
#endif
#endif
