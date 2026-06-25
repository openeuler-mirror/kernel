/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_drv_cmd.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DRV_CMD_H__
#define __SXE2_DRV_CMD_H__

#ifdef SXE2_DPDK_DRIVER
#include "sxe2_type.h"
#include "sxe2_cmd.h"
#include "sxe2_flow_public.h"

#define SXE2_DPDK_RESOURCE_INSUFFICIENT
#endif

#ifdef SXE2_LINUX_DRIVER
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/if_ether.h>
#endif
#endif

#ifdef __KERNEL__
#define _SXE2_PACK     __packed__
#define _SXE2_ALIGN    __aligned__(4)
#define SXE2_ATTRIBUTE __attribute__((_SXE2_PACK, _SXE2_ALIGN))
#else
#define SXE2_ATTRIBUTE
#pragma pack(4)
#endif

#define SXE2_DRV_CMD_MODULE_S        (16)
#define SXE2_MK_DRV_CMD(module, cmd) ((module) << SXE2_DRV_CMD_MODULE_S | (cmd))

#define SXE2_DEV_CAPS_OFFLOAD_L2    BIT(0)
#define SXE2_DEV_CAPS_OFFLOAD_VLAN  BIT(1)
#define SXE2_DEV_CAPS_OFFLOAD_RSS   BIT(2)
#define SXE2_DEV_CAPS_OFFLOAD_IPSEC BIT(3)
#define SXE2_DEV_CAPS_OFFLOAD_FNAV  BIT(4)
#define SXE2_DEV_CAPS_OFFLOAD_TM    BIT(5)
#define SXE2_DEV_CAPS_OFFLOAD_PTP   BIT(6)
#define SXE2_DEV_CAPS_OFFLOAD_Q_MAP	BIT(7)
#define SXE2_DEV_CAPS_OFFLOAD_FC_STATE	BIT(8)

#define SXE2_TXQ_STATS_MAP_MAX_NUM 16
#define SXE2_RXQ_STATS_MAP_MAX_NUM 4
#define SXE2_RXQ_MAP_Q_MAX_NUM	256

#define SXE2_STAT_MAP_INVALID_QID 0xFFFF

#define SXE2_SCHED_MODE_DEFAULT				0
#define SXE2_SCHED_MODE_TM					1
#define SXE2_SCHED_MODE_HIGH_PERFORMANCE	2
#define SXE2_SCHED_MODE_INVALID				3

#define SXE2_SRCVSI_PRUNE_MAX_NUM			2

#define SXE2_PTYPE_UNKNOWN                   BIT(0)
#define SXE2_PTYPE_L2_ETHER                  BIT(1)
#define SXE2_PTYPE_L3_IPV4                   BIT(2)
#define SXE2_PTYPE_L3_IPV6                   BIT(4)
#define SXE2_PTYPE_L4_TCP                    BIT(6)
#define SXE2_PTYPE_L4_UDP                    BIT(7)
#define SXE2_PTYPE_L4_SCTP                   BIT(8)
#define SXE2_PTYPE_INNER_L2_ETHER            BIT(9)
#define SXE2_PTYPE_INNER_L3_IPV4             BIT(10)
#define SXE2_PTYPE_INNER_L3_IPV6             BIT(12)
#define SXE2_PTYPE_INNER_L4_TCP              BIT(14)
#define SXE2_PTYPE_INNER_L4_UDP              BIT(15)
#define SXE2_PTYPE_INNER_L4_SCTP             BIT(16)
#define SXE2_PTYPE_TUNNEL_GRENAT             BIT(17)

#define SXE2_PTYPE_L2_MASK       (SXE2_PTYPE_L2_ETHER)
#define SXE2_PTYPE_L3_MASK       (SXE2_PTYPE_L3_IPV4 | SXE2_PTYPE_L3_IPV6)
#define SXE2_PTYPE_L4_MASK       (SXE2_PTYPE_L4_TCP | SXE2_PTYPE_L4_UDP | \
		SXE2_PTYPE_L4_SCTP)
#define SXE2_PTYPE_INNER_L2_MASK (SXE2_PTYPE_INNER_L2_ETHER)
#define SXE2_PTYPE_INNER_L3_MASK (SXE2_PTYPE_INNER_L3_IPV4 | \
		SXE2_PTYPE_INNER_L3_IPV6)
#define SXE2_PTYPE_INNER_L4_MASK (SXE2_PTYPE_INNER_L4_TCP | \
		SXE2_PTYPE_INNER_L4_UDP | \
		SXE2_PTYPE_INNER_L4_SCTP)
#define SXE2_PTYPE_TUNNEL_MASK   (SXE2_PTYPE_TUNNEL_GRENAT)

enum sxe2_dev_type {
	SXE2_DEV_T_PF = 0,
	SXE2_DEV_T_VF,
	SXE2_DEV_T_PF_BOND,
	SXE2_DEV_T_MAX,
};

struct sxe2_drv_queue_caps {
	__le16 queues_cnt;
	__le16 base_idx_in_pf;
} SXE2_ATTRIBUTE;

struct sxe2_drv_msix_caps {
	__le16 msix_vectors_cnt;
	__le16 base_idx_in_func;
} SXE2_ATTRIBUTE;

struct sxe2_drv_rss_hash_caps {
	__le16 hash_key_size;
	__le16 lut_key_size;
} SXE2_ATTRIBUTE;

enum sxe2_vf_vsi_valid {
	SXE2_VF_VSI_BOTH = 0,
	SXE2_VF_VSI_ONLY_DPDK,
	SXE2_VF_VSI_ONLY_KERNEL,
	SXE2_VF_VSI_MAX,
};

struct sxe2_drv_vsi_caps {
	__le16 func_id;
	__le16 dpdk_vsi_id;
	__le16 kernel_vsi_id;
	__le16 vsi_type;
} SXE2_ATTRIBUTE;

struct sxe2_drv_representor_caps {
	__le16 cnt_repr_vf;
	u8 rsv[2];
	struct sxe2_drv_vsi_caps repr_vf_id[256];
} SXE2_ATTRIBUTE;

enum sxe2_phys_port_name_type {
	SXE2_PHYS_PORT_NAME_TYPE_NOTSET = 0,
	SXE2_PHYS_PORT_NAME_TYPE_LEGACY,
	SXE2_PHYS_PORT_NAME_TYPE_UPLINK,
	SXE2_PHYS_PORT_NAME_TYPE_PFVF,
	SXE2_PHYS_PORT_NAME_TYPE_UNKNOWN,
};

struct sxe2_switchdev_info {
	u8 is_switchdev;
	u8 master;
	u8 representor;
	u8 port_name_type;
	__le32 ctrl_num;
	__le32 pf_num;
	__le32 vf_num;
	__le32 mpesw_owner;
} SXE2_ATTRIBUTE;

struct sxe2_switchdev_uplink_info {
	u8 pf_id;
	u8 is_set;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_switchdev_repr_info {
	u8 pf_id;
	u8 is_set;
	u8 rsv[2];
	__le16 cp_vsi_id;
	__le16 repr_pf_id;
	__le16 repr_vf_id;
	__le16 repr_q_id;
} SXE2_ATTRIBUTE;

struct sxe2_switchdev_mode_info {
	u8 pf_id;
	u8 is_switchdev;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_switchdev_cpvsi_info {
	__le16 cp_vsi_id;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_txsch_caps {
	u8 layer_cap;
	u8 tm_mid_node_num;
	u8 prio_num;
	u8 rev;
} SXE2_ATTRIBUTE;

struct sxe2_drv_dev_caps_resp {
	struct sxe2_drv_queue_caps queue_caps;
	struct sxe2_drv_msix_caps msix_caps;
	struct sxe2_drv_rss_hash_caps rss_hash_caps;
	struct sxe2_drv_vsi_caps vsi_caps;
	struct sxe2_txsch_caps   txsch_caps;
	struct sxe2_drv_representor_caps repr_caps;
	u8 port_idx;
	u8 pf_idx;
	u8 dev_type;
	u8 rev;
	__le32 cap_flags;
} SXE2_ATTRIBUTE;

struct sxe2_drv_dev_info_resp {
	__le64 dsn;
	__le16 vsi_id;
	u8 rsv[2];
	u8 mac_addr[ETH_ALEN];
	u8 rsv2[2];
} SXE2_ATTRIBUTE;

struct sxe2_drv_dev_fw_info_resp {
	u8 main_version_id;
	u8 sub_version_id;
	u8 fix_version_id;
	u8 build_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_rxq_ctxt {
	__le64 dma_addr;
	__le32 max_lro_size;
	__le32 split_type_mask;
	__le16 hdr_len;
	__le16 buf_len;
	__le16 depth;
	__le16 queue_id;
	u8 lro_en;
	u8 keep_crc_en;
	u8 split_en;
	u8 desc_size;
} SXE2_ATTRIBUTE;

struct sxe2_drv_rxq_cfg_req {
	__le16 q_cnt;
	__le16 vsi_id;
	__le16 max_frame_size;
	u8 rsv[2];
	struct sxe2_drv_rxq_ctxt cfg[];
} SXE2_ATTRIBUTE;

struct sxe2_drv_txq_ctxt {
	__le64 dma_addr;
	__le32 sched_mode;
	__le16 queue_id;
	__le16 depth;
	__le16 vsi_id;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_drv_txq_cfg_req {
	__le16 q_cnt;
	__le16 vsi_id;
	struct sxe2_drv_txq_ctxt cfg[];
} SXE2_ATTRIBUTE;

struct sxe2_drv_q_switch_req {
	__le16 q_idx;
	__le16 vsi_id;
	u8 is_enable;
	u8 sched_mode;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_drv_queue_irq_bind_req {
	__le16 q_idx;
	__le16 msix_idx;
	u8 itr_idx;
	u8 bind;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_create_req_resp {
	__le16 vsi_id;
	__le16 vsi_type;
	struct sxe2_drv_queue_caps used_queues;
	struct sxe2_drv_msix_caps used_msix;
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_free_req {
	__le16 vsi_id;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_info_get_req {
	__le16 vsi_id;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_info_get_resp {
	__le16 vsi_id;
	__le16 vsi_type;
	struct sxe2_drv_queue_caps used_queues;
	struct sxe2_drv_msix_caps used_msix;
} SXE2_ATTRIBUTE;

struct sxe2_drv_udp_tunnel_req {
	u8 type;
	u8 rsv;
	__le16 port;
} SXE2_ATTRIBUTE;

struct sxe2_drv_udp_tunnel_resp {
	u8 type;
	u8 enable;
	u8 dst;
	u8 src;
	u16 port;
	u8 fw_used;
	u8 rsv;
} SXE2_ATTRIBUTE;

struct sxe2_drv_rx_map_req {
	__le16 queue_id;
	u8 pool_idx;
} SXE2_ATTRIBUTE;

struct sxe2_drv_tx_map_req {
	__le16 queue_id;
	u8 pool_idx;
} SXE2_ATTRIBUTE;

struct sxe2_drv_vlan_cfg_query_resp {
	__le16 vsi_id;
	u8 port_vlan_exist;
	u8 is_switchdev;
	__le16 tpid;
	__le16 vid;
	u8 outer_insert;
	u8 outer_strip;
	u8 inner_insert;
	u8 inner_strip;
} SXE2_ATTRIBUTE;

struct sxe2_drv_vlan_offload_cfg_req {
	__le16 vsi_id;
	__le16 tpid;
	u8 outer_insert;
	u8 outer_strip;
	u8 inner_insert;
	u8 inner_strip;
} SXE2_ATTRIBUTE;

struct sxe2_drv_port_vlan_cfg_req {
	__le16 vsi_id;
	__le16 tpid;
	__le16 vid;
	u8 prio;
	u8 rsv;
} SXE2_ATTRIBUTE;

enum sxe2_mac_filter_type {
	SXE2_MAC_FILTER_TYPE_UC = 0,
	SXE2_MAC_FILTER_TYPE_MC,
	SXE2_MAC_FILTER_TYPE_MAX,
};

struct sxe2_mac_filter_cfg_req {
	__le16 vsi_id;
	u8 addr[ETH_ALEN];
	u8 type;
	u8 is_add;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

enum sxe2_promisc_filter_type {
	SXE2_PROMISC_FILTER_TYPE_PROMISC = 0,
	SXE2_PROMISC_FILTER_TYPE_ALLMULTI,
	SXE2_PROMISC_FILTER_TYPE_MAX,
};

struct sxe2_promisc_filter_cfg_req {
	__le16 vsi_id;
	u8 type;
	u8 is_add;
} SXE2_ATTRIBUTE;

struct sxe2_srcvsi_ext_cfg_req {
	__le16 vsi_id;
	__le16 srcvsi_list[SXE2_SRCVSI_PRUNE_MAX_NUM];
	u8 srcvsi_cnt;
	u8 is_add;
} SXE2_ATTRIBUTE;

struct sxe2_vlan_filter_cfg_req {
	__le16 vsi_id;
	__le16 vlan_id;
	__le16 tpid_id;
	u8 prio;
	u8 is_add;
} SXE2_ATTRIBUTE;

struct sxe2_vlan_filter_switch_req {
	__le16 vsi_id;
	u8 is_oper_enable;
	u8 rsv;
} SXE2_ATTRIBUTE;

struct sxe2_rss_key_req {
	__le16 vsi_id;
	__le16 key_size;
	u8 key[];
} SXE2_ATTRIBUTE;

struct sxe2_rss_lut_req {
	__le16 vsi_id;
	__le16 lut_size;
	u8 lut[];
} SXE2_ATTRIBUTE;

struct sxe2_rss_func_req {
	__le16 vsi_id;
	u8 func;
	u8 rsv[1];
} SXE2_ATTRIBUTE;

struct sxe2_rss_hf_req {
	__le16 vsi_id;
	u8 rsv[2];
	__le32 headers[BITS_TO_U32(SXE2_FLOW_HDR_MAX)];
	__le32 hash_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	__le32 hdr_type;
	u8 symm;
	u8 rsv1[3];
} SXE2_ATTRIBUTE;

struct sxe2_drv_ipsec_capa_resq {
	__le16 tx_sa_cnt;
	__le16 rx_sa_cnt;
	__le16 ip_id_cnt;
	__le16 udp_group_cnt;
} SXE2_ATTRIBUTE;

struct sxe2_drv_ipsec_txsa_add_req {
	__le32 mode;
	u8 encrypt_keys[SXE2_IPSEC_KEY_LEN];
	u8 auth_keys[SXE2_IPSEC_KEY_LEN];
	bool func_type;
	u8 func_id;
	u8 drv_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_ipsec_txsa_add_resp {
	__le16 index;
} SXE2_ATTRIBUTE;

struct sxe2_drv_ipsec_rxsa_add_req {
	__le32 mode;
	__le32 spi;
	__le32 ipaddr[SXE2_IPV6_ADDR_LEN];
	__le32 udp_port;
	u8 sport_en;
	u8 dport_en;
	u8 is_over_sdn;
	u8 sdn_group_id;
	u8 encrypt_keys[SXE2_IPSEC_KEY_LEN];
	u8 auth_keys[SXE2_IPSEC_KEY_LEN];
	bool func_type;
	u8 func_id;
	u8 drv_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_ipsec_rxsa_add_resp {
	u8 ip_id;
	u8 udp_group_id;
	__le16 sa_idx;
} SXE2_ATTRIBUTE;

struct sxe2_drv_ipsec_txsa_del_req {
	__le16 sa_idx;
	bool func_type;
	u8 func_id;
	u8 drv_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_ipsec_rxsa_del_req {
	u8 ip_id;
	u8 group_id;
	__le16 sa_idx;
	__le32 spi;
	bool func_type;
	u8 func_id;
	u8 drv_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_link_info_resp {
	__le32 speed;
	u8 status;
} SXE2_ATTRIBUTE;

struct sxe2_drv_flow_filter_req {
	__le32 flow_id;
	struct sxe2_flow_meta meta;
	enum sxe2_flow_engine_type engine_type;
	struct sxe2_flow_pattern pattern_outer;
	struct sxe2_flow_pattern pattern_inner;
	struct sxe2_flow_action action;
} SXE2_ATTRIBUTE;

struct sxe2_drv_flow_filter_resp {
	enum sxe2_flow_engine_type engine_type;
	__le32 flow_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_flow_fnav_get_stat_id_req {
	u8 need_update;
} SXE2_ATTRIBUTE;

struct sxe2_drv_flow_fnav_get_stat_id_resp {
	__le32 stat_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_flow_fnav_free_stat_id_req {
	__le32 stat_id;
} SXE2_ATTRIBUTE;

struct sxe2_drv_flow_fnav_query_stat_req {
	__le32 stat_id;
	__le32 stat_ctrl;
	__le32 is_clear;
} SXE2_ATTRIBUTE;

struct sxe2_drv_flow_fnav_query_stat_resp {
	__le32 stat_index;
	__le64 stat_hits;
	__le64 stat_bytes;
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_sw_stats {
	__le64 rx_packets;
	__le64 rx_bytes;
	__le64 tx_packets;
	__le64 tx_bytes;
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_stats_req {
	__le16 vsi_id;
	u8 rsv[2];
	struct sxe2_drv_vsi_sw_stats sw_stats;
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_stats_resp {
	__le64 rx_vsi_unicast_packets;
	__le64 rx_vsi_bytes;
	__le64 tx_vsi_unicast_packets;
	__le64 tx_vsi_bytes;
	__le64 rx_vsi_multicast_packets;
	__le64 tx_vsi_multicast_packets;
	__le64 rx_vsi_broadcast_packets;
	__le64 tx_vsi_broadcast_packets;
} SXE2_ATTRIBUTE;

struct sxe2_drv_mac_stats_resp {
	__le64 rx_out_of_buffer;
	__le64 rx_qblock_drop;
	__le64 tx_frame_good;
	__le64 rx_frame_good;
	__le64 rx_crc_errors;
	__le64 tx_bytes_good;
	__le64 rx_bytes_good;
	__le64 tx_multicast_good;
	__le64 tx_broadcast_good;
	__le64 rx_multicast_good;
	__le64 rx_broadcast_good;
	__le64 rx_len_errors;
	__le64 rx_out_of_range_errors;
	__le64 rx_oversize_pkts_phy;
	__le64 rx_symbol_err;
	__le64 rx_pause_frame;
	__le64 tx_pause_frame;
	__le64 rx_discards_phy;
	__le64 rx_discards_ips_phy;
	__le64 tx_dropped_link_down;
	__le64 rx_undersize_good;
	__le64 rx_runt_error;
	__le64 tx_bytes_good_bad;
	__le64 tx_frame_good_bad;
	__le64 rx_jabbers;
	__le64 rx_size_64;
	__le64 rx_size_65_127;
	__le64 rx_size_128_255;
	__le64 rx_size_256_511;
	__le64 rx_size_512_1023;
	__le64 rx_size_1024_1522;
	__le64 rx_size_1523_max;
	__le64 rx_pcs_symbol_err_phy;
	__le64 rx_corrected_bits_phy;
	__le64 rx_err_lane_0_phy;
	__le64 rx_err_lane_1_phy;
	__le64 rx_err_lane_2_phy;
	__le64 rx_err_lane_3_phy;
	__le64 rx_prio_buf_discard[SXE2_MAX_USER_PRIORITY];
	__le64 rx_illegal_bytes;
	__le64 rx_oversize_good;
	__le64 tx_unicast;
	__le64 tx_broadcast;
	__le64 tx_multicast;
	__le64 tx_vlan_packet_good;
	__le64 tx_size_64;
	__le64 tx_size_65_127;
	__le64 tx_size_128_255;
	__le64 tx_size_256_511;
	__le64 tx_size_512_1023;
	__le64 tx_size_1024_1522;
	__le64 tx_size_1523_max;
	__le64 tx_underflow_error;
	__le64 rx_byte_good_bad;
	__le64 rx_frame_good_bad;
	__le64 rx_unicast_good;
	__le64 rx_vlan_packets;
	__le64 prio_xoff_rx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xon_rx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xon_tx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xoff_tx[SXE2_MAX_USER_PRIORITY];
	__le64 prio_xon_2_xoff[SXE2_MAX_USER_PRIORITY];
} SXE2_ATTRIBUTE;

enum sxe2_fc_type {
	SXE2_FC_T_DIS = 0,
	SXE2_FC_T_LFC,
	SXE2_FC_T_PFC,

	SXE2_FC_T_UNKNOWN = 255,
};

struct sxe2_drv_vsi_fc_get_req {
	__le16 vsi_id;
	u8 rsv[2];
} SXE2_ATTRIBUTE;

struct sxe2_drv_vsi_fc_get_resp {
	u8 fc_enable;
	u8 rsv[3];
} SXE2_ATTRIBUTE;

struct sxe2_tm_res {
	__le16 teid;
};

struct sxe2_tm_info {
	__le32 committed;
	__le32 peak;
	u8 priority;
	u8 reserve;
	__le16 weight;
};

struct sxe2_tm_add_mid_msg {
	__le16 parent_teid;
	u8 adj_lvl;
	struct sxe2_tm_info info;
};

struct sxe2_tm_add_queue_msg {
	__le16 parent_teid;
	__le16 queue_id;
	u8 adj_lvl;
	struct sxe2_tm_info info;
};

struct sxe2_stats_txq_map_pool {
	__le16 queue_id_pool[SXE2_TXQ_STATS_MAP_MAX_NUM];
	u8 curr_map_idx;
};

struct sxe2_stats_hw_txq_map_pool {
	__le16 txq_id;
};

struct sxe2_stats_hw_txq_map {
	struct sxe2_stats_hw_txq_map_pool hw_txq_map_pool[SXE2_TXQ_STATS_MAP_MAX_NUM];
	u8 curr_map_idx;
};

struct sxe2_stats_rxq_map_pool {
	u8 pool_id;
	__le16 queue_id_pool[SXE2_RXQ_MAP_Q_MAX_NUM];
	__le16 curr_map_idx;
};

struct sxe2_stats_txq_map {
	struct sxe2_stats_txq_map_pool txq_map_pool[SXE2_TXQ_STATS_MAP_MAX_NUM];
	struct sxe2_stats_hw_txq_map hw_txq_map;
};

struct sxe2_stats_rxq_map {
	struct sxe2_stats_rxq_map_pool rxq_map_pool[SXE2_RXQ_STATS_MAP_MAX_NUM];
};

struct sxe2_txq_map_info {
	__le32 txq_lan_pkt_cnt;
	__le32 txq_lan_byte_cnt;
};

struct sxe2_rxq_map_info {
	__le64 rxq_lan_in_pkt_cnt;
	__le64 rxq_lan_in_byte_cnt;

	__le64 rxq_fd_in_pkt_cnt;

	__le64 rxq_mng_in_pkt_cnt;
	__le64 rxq_mng_in_byte_cnt;
	__le64 rxq_mng_out_pkt_cnt;
};

struct sxe2_queue_map_info {
	struct sxe2_rxq_map_info
		rxq_stats_map_info[SXE2_RXQ_STATS_MAP_MAX_NUM];
	struct sxe2_txq_map_info
		txq_stats_map_info[SXE2_TXQ_STATS_MAP_MAX_NUM];
};

struct sxe2_stats_map {
	struct sxe2_stats_txq_map txq_map;
	struct sxe2_stats_rxq_map rxq_map;

	struct sxe2_queue_map_info q_info;
};

struct sxe2_drv_sfp_req {
	u8 is_wr;
	u8 is_qsfp;
	__le16 bus_addr;
	__le16 page_cnt;
	__le16 offset;
	__le16 data_len;
	__le16 rvd;
	u8 data[];
};

struct sxe2_drv_sfp_resp {
	u8 is_wr;
	u8 is_qsfp;
	__le16 data_len;
	u8 data[];
};

enum sxe2_drv_cmd_module {
	SXE2_DRV_CMD_MODULE_HANDSHAKE = 0,
	SXE2_DRV_CMD_MODULE_DEV = 1,
	SXE2_DRV_CMD_MODULE_VSI = 2,
	SXE2_DRV_CMD_MODULE_QUEUE = 3,
	SXE2_DRV_CMD_MODULE_STATS = 4,
	SXE2_DRV_CMD_MODULE_SUBSCRIBE = 5,
	SXE2_DRV_CMD_MODULE_RSS = 6,
	SXE2_DRV_CMD_MODULE_FLOW = 7,
	SXE2_DRV_CMD_MODULE_TM = 8,
	SXE2_DRV_CMD_MODULE_IPSEC = 9,
	SXE2_DRV_CMD_MODULE_PTP = 10,

	SXE2_DRV_CMD_MODULE_VLAN = 11,
	SXE2_DRV_CMD_MODULE_RDMA = 12,
	SXE2_DRV_CMD_MODULE_LINK = 13,
	SXE2_DRV_CMD_MODULE_MACADDR = 14,
	SXE2_DRV_CMD_MODULE_PROMISC = 15,

	SXE2_DRV_CMD_MODULE_LED = 16,
	SXE2_DEV_CMD_MODULE_OPT = 17,
	SXE2_DEV_CMD_MODULE_SWITCH = 18,
	SXE2_DRV_CMD_MODULE_ACL = 19,
	SXE2_DRV_CMD_MODULE_UDPTUNEEL = 20,
	SXE2_DRV_CMD_MODULE_QUEUE_MAP = 21,

	SXE2_DRV_CMD_MODULE_SCHED = 22,

	SXE2_DRV_CMD_MODULE_IRQ = 23,

	SXE2_DRV_CMD_MODULE_OPT = 24,
};

enum sxe2_drv_cmd_code {
	SXE2_DRV_CMD_HANDSHAKE_ENABLE =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_HANDSHAKE, 1),
	SXE2_DRV_CMD_HANDSHAKE_DISABLE,

	SXE2_DRV_CMD_DEV_GET_CAPS =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_DEV, 1),
	SXE2_DRV_CMD_DEV_GET_INFO,
	SXE2_DRV_CMD_DEV_GET_FW_INFO,
	SXE2_DRV_CMD_DEV_RESET,
	SXE2_DRV_CMD_DEV_GET_SWITCHDEV_INFO,

	SXE2_DRV_CMD_VSI_CREATE =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_VSI, 1),
	SXE2_DRV_CMD_VSI_FREE,
	SXE2_DRV_CMD_VSI_INFO_GET,
	SXE2_DRV_CMD_VSI_SRCVSI_PRUNE,
	SXE2_DRV_CMD_VSI_FC_GET,

	SXE2_DRV_CMD_RX_MAP_SET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_QUEUE_MAP, 1),
	SXE2_DRV_CMD_TX_MAP_SET,
	SXE2_DRV_CMD_TX_RX_MAP_GET,
	SXE2_DRV_CMD_TX_RX_MAP_RESET,
	SXE2_DRV_CMD_TX_RX_MAP_INFO_CLEAR,

	SXE2_DRV_CMD_SCHED_ROOT_TREE_ALLOC =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_SCHED, 1),
	SXE2_DRV_CMD_SCHED_ROOT_TREE_RELEASE,
	SXE2_DRV_CMD_SCHED_ROOT_CHILDREN_DELETE,
	SXE2_DRV_CMD_SCHED_TM_ADD_MID_NODE,
	SXE2_DRV_CMD_SCHED_TM_ADD_QUEUE_NODE,

	SXE2_DRV_CMD_RXQ_CFG_ENABLE =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_QUEUE, 1),
	SXE2_DRV_CMD_TXQ_CFG_ENABLE,
	SXE2_DRV_CMD_RXQ_DISABLE,
	SXE2_DRV_CMD_TXQ_DISABLE,

	SXE2_DRV_CMD_VSI_STATS_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_STATS, 1),
	SXE2_DRV_CMD_VSI_STATS_CLEAR,
	SXE2_DRV_CMD_MAC_STATS_GET,
	SXE2_DRV_CMD_MAC_STATS_CLEAR,

	SXE2_DRV_CMD_RSS_KEY_SET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_RSS, 1),
	SXE2_DRV_CMD_RSS_LUT_SET,
	SXE2_DRV_CMD_RSS_FUNC_SET,
	SXE2_DRV_CMD_RSS_HF_ADD,
	SXE2_DRV_CMD_RSS_HF_DEL,
	SXE2_DRV_CMD_RSS_HF_CLEAR,

	SXE2_DRV_CMD_FLOW_FILTER_ADD =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_FLOW, 1),
	SXE2_DRV_CMD_FLOW_FILTER_DEL,
	SXE2_DRV_CMD_FLOW_FILTER_CLEAR,
	SXE2_DRV_CMD_FLOW_FNAV_STAT_ALLOC,
	SXE2_DRV_CMD_FLOW_FNAV_STAT_FREE,
	SXE2_DRV_CMD_FLOW_FNAV_STAT_QUERY,

	SXE2_DRV_CMD_DEL_TM_ROOT =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_TM, 1),
	SXE2_DRV_CMD_ADD_TM_ROOT,
	SXE2_DRV_CMD_ADD_TM_NODE,
	SXE2_DRV_CMD_ADD_TM_QUEUE,

	SXE2_DRV_CMD_GET_PTP_CLOCK =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_PTP, 1),

	SXE2_DRV_CMD_VLAN_FILTER_ADD_DEL =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_VLAN, 1),
	SXE2_DRV_CMD_VLAN_FILTER_SWITCH,
	SXE2_DRV_CMD_VLAN_OFFLOAD_CFG,
	SXE2_DRV_CMD_VLAN_PORTVLAN_CFG,
	SXE2_DRV_CMD_VLAN_CFG_QUERY,

	SXE2_DRV_CMD_RDMA_DUMP_PCAP =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_RDMA, 1),

	SXE2_DRV_CMD_LINK_STATUS_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_LINK, 1),

	SXE2_DRV_CMD_MAC_ADDR_UC =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_MACADDR, 1),
	SXE2_DRV_CMD_MAC_ADDR_MC,

	SXE2_DRV_CMD_PROMISC_CFG =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_PROMISC, 1),
	SXE2_DRV_CMD_ALLMULTI_CFG,

	SXE2_DRV_CMD_LED_CTRL =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_LED, 1),

	SXE2_DRV_CMD_OPT_EEP =
		SXE2_MK_DRV_CMD(SXE2_DEV_CMD_MODULE_OPT, 1),

	SXE2_DRV_CMD_SWITCH =
		SXE2_MK_DRV_CMD(SXE2_DEV_CMD_MODULE_SWITCH, 1),
	SXE2_DRV_CMD_SWITCH_UPLINK,
	SXE2_DRV_CMD_SWITCH_REPR,
	SXE2_DRV_CMD_SWITCH_MODE,
	SXE2_DRV_CMD_SWITCH_CPVSI,

	SXE2_DRV_CMD_UDPTUNNEL_ADD =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_UDPTUNEEL, 1),
	SXE2_DRV_CMD_UDPTUNNEL_DEL,
	SXE2_DRV_CMD_UDPTUNNEL_GET,

	SXE2_DRV_CMD_IPSEC_CAP_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_IPSEC, 1),
	SXE2_DRV_CMD_IPSEC_TXSA_ADD,
	SXE2_DRV_CMD_IPSEC_RXSA_ADD,
	SXE2_DRV_CMD_IPSEC_TXSA_DEL,
	SXE2_DRV_CMD_IPSEC_RXSA_DEL,
	SXE2_DRV_CMD_IPSEC_RESOURCE_CLEAR,

	SXE2_DRV_CMD_EVT_IRQ_BAND_RXQ =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_IRQ, 1),

	SXE2_DRV_CMD_OPT_EEP_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_OPT, 1),

};

#ifndef __KERNEL__
#pragma pack()
#endif

#endif
