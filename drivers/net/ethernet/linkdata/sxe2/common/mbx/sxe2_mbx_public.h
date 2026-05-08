/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_mbx_public.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_VF_PUBLIC_H__
#define __SXE2_VF_PUBLIC_H__

#include "sxe2_spec.h"
#ifdef __KERNEL__
#include "sxe2_compat.h"
#endif

#include "sxe2_host_regs.h"
#include "sxe2_flow_public.h"

#pragma pack(1)

#define SXE2_VF_VERSION_MAJOR 1
#define SXE2_VF_VERSION_MINOR 1

#define SXE2_VF_MAX_VSI_CNT   4

#define SXE2_VF_VLAN_STATUS_INVALID  (0xFF)

#define SXE2_VF_ETH_Q_NUM 16
#define SXE2_VF_DPDK_Q_NUM 16

#define SXE2_VF_DRV_TO_HW      (0x3)
#define SXE2_VF_VF_TO_PF       (0x0801)
#define SXE2_VF_PF_TO_VF       (0x0802)

#define SXE2_VF_MBX_MAGIC      (0xFEFEEFEF)

#define SXE2_VF_PROMISC		    BIT_ULL(0)
#define SXE2_VF_PROMISC_MULTICAST	BIT_ULL(1)
#define SXE2_VF_VLAN_FILTER		BIT_ULL(2)

#define SXE2_VF_OFFLOAD_L2    BIT(0)
#define SXE2_VF_OFFLOAD_VLAN  BIT(1)
#define SXE2_VF_OFFLOAD_RSS   BIT(2)
#define SXE2_VF_OFFLOAD_IPSEC BIT(3)
#define SXE2_VF_OFFLOAD_FNAV  BIT(4)
#define SXE2_VF_OFFLOAD_TM    BIT(5)
#define SXE2_VF_OFFLOAD_PTP   BIT(6)

#define SXE2_IPSEC_DIR_TX (0)
#define SXE2_IPSEC_DIR_RX (1)
#define SXE2_IPSEC_INVALID_SA_IDX (0xFFFF)

enum sxe2vf_vsi_type {
	SXE2VF_VSI_TYPE_ETH = 0,
	SXE2VF_VSI_TYPE_DPDK,
	SXE2VF_VSI_TYPE_NR,
};

#define SXE2_VF_VSI_CNT_USED  SXE2VF_VSI_TYPE_NR

enum sxe2_vf_opcode {
	SXE2_VF_UNKNOWN = 0,
	SXE2_VF_RESET_REQUEST = 0x1,
	SXE2_VF_VERSION_MATCH = 0x2,
	SXE2_VF_HW_RES_GET = 0x3,
	SXE2_VF_IRQ_MAP = 0x4,
	SXE2_VF_QUEUES_DISABLE = 0x5,
	SXE2_VF_RXQ_CFG_AND_ENABLE = 0x6,
	SXE2_VF_TXQ_CFG_AND_ENABLE = 0x7,
	SXE2_VF_MAC_ADDR_ADD = 0x8,
	SXE2_VF_MAC_ADDR_DEL = 0x9,
	SXE2_VF_VLAN_ADD = 0xa,
	SXE2_VF_VLAN_DEL = 0xb,
	SXE2_VF_STATS_GET = 0xc,
	SXE2_VF_LINK_UPDATE_NOTIFY = 0xd,
	SXE2_VF_PROMISC_CFG = 0xe,
	SXE2_VF_VLAN_CAPS_GET = 0xf,
	SXE2_VF_VLAN_OFFLOAD_CFG = 0x10,
	SXE2_VF_VLAN_FILTER_CFG = 0x11,
	SXE2_VF_LINK_STATUS_GET = 0x12,
	SXE2_VF_RESET_NOTIFY = 0x13,
	SXE2_VF_RDMA = 0x14,
	SXE2_VF_QV_MAP = 0x15,
	SXE2_VF_QV_UNMAP = 0x16,
	SXE2_VF_RDMA_MGR_CMD = 0x17,

	SXE2_VF_GET_RSS_KEY = 0x18,
	SXE2_VF_GET_RSS_LUT = 0x19,
	SXE2_VF_SET_RSS_KEY = 0x1a,
	SXE2_VF_SET_RSS_LUT = 0x1b,
	SXE2_VF_ADD_RSS_CFG = 0x1c,

	SXE2_VF_DEL_RSS_CFG = 0x1d,
	SXE2_VF_CLEAR_RSS_CFG = 0x1e,
	SXE2_VF_SET_RSS_HASH_CTRL = 0X1f,

	SXE2_VF_FNAV_FILTER_ADD = 0x20,
	SXE2_VF_FNAV_FILTER_DEL = 0x21,
	SXE2_VF_FNAV_FILTER_CLEAR = 0X22,
	SXE2_VF_FNAV_ALLOC_STAT = 0X23,
	SXE2_VF_FNAV_FREE_STAT = 0X24,
	SXE2_VF_FNAV_QUERY_STAT = 0x25,

	SXE2_VF_STATS_CLEAR = 0x26,
	SXE2_VF_RXQ_DISABLE = 0x27,
	SXE2_VF_TXQ_DISABLE = 0x28,

	SXE2_VF_GET_PTP_CLOCK = 0x29,
	SXE2_VF_IPSEC_SA_ADD = 0x2a,
	SXE2_VF_IPSEC_SA_CLEAR = 0x2b,
	SXE2_VF_IPSEC_GET_CAPA = 0x2c,

	SXE2_VF_RDMA_DUMP_PCAP = 0x2d,

	SXE2_VF_IRQ_UNMAP = 0x2e,

	SXE2_VF_ADD_DEFAULT_RSS_CFG = 0x2f,
	SXE2_VF_REPLAY_RSS_CFG = 0x30,
	SXE2_VF_STATS_PUSH = 0x31,
	SXE2_VF_GET_ETHTOOL_INFO = 0x32,
	SXE2_VF_FNAV_MATCH_CLEAR = 0x33,
	SXE2_VF_VSI_CFG = 0x34,
	SXE2_VF_USER_DRIVER_RELEASE = 0x35,

	SXE2_VF_MAC_ADDR_UPDATE = 0x36,
	SXE2_VF_PROMISC_UPDATE = 0x37,
	SXE2_VF_USER_VLAN_PROCESS = 0x38,

	SXE2_VF_ACL_FILTER_ADD = 0x39,
	SXE2_VF_ACL_FILTER_DEL = 0x3a,
	SXE2_VF_ACL_FILTER_CLEAR = 0x3b,

	SXE2_VF_PASSTHROUGH_USER_VF_DATA = 0x3c,

	SXE2_VF_DRV_MODE_SET = 0x3d,
	SXE2_VF_DRV_MODE_GET = 0x3e,

	SXE2_VF_OPCODE_NR,

	SXE2_VF_MBX_DISABLE = 0xFFFF,
};

enum sxe2_vf_err_code {
	SXE2_VF_ERR_SUCCESS = 0,
	SXE2_VF_ERR_PARAM = 1024,
	SXE2_VF_ERR_NO_MEMORY,
	SXE2_VF_ERR_HANDLE_ERROR,
	SXE2_VF_ERR_CQP_COMPL_ERROR,
	SXE2_VF_ERR_INVALID_VF_ID,
	SXE2_VF_ERR_ADMIN_QUEUE_ERROR,
	SXE2_VF_ERR_NOT_SUPPORTED,
	SXE2_VF_ERR_PF_STATUS_ABNORMAL,
	SXE2_VF_ERR_VF_STATUS_ABNORMAL,
};

enum sxe2_vf_msg_type {
	SXE2VF_MSG_TYPE_PF_TO_VF = 3,
	SXE2VF_MSG_TYPE_VF_TO_PF,
	SXE2VF_MSG_TYPE_DRV_TO_HW,
	SXE2VF_MSG_TYPE_PF_REPLY_VF,
};

#define SXE2VF_CMD_HDR_SIZE sizeof(struct sxe2vf_cmd_hdr)

#define SXE2VF_MBX_MSG_HDR_SIZE \
			sizeof(struct sxe2vf_mbx_msg_hdr)

#define SXE2VF_MBX_RAW_MSG_MAX_SPEC     (4096)

#define SXE2VF_MBX_RAW_MSG_OFFSET (SXE2VF_CMD_HDR_SIZE + SXE2VF_MBX_MSG_HDR_SIZE)

#define SXE2VF_MBX_FULL_HDR_SIZE   SXE2VF_MBX_RAW_MSG_OFFSET

#define SXE2VF_MBX_RAW_MSG_MAX_SIZE      \
				(SXE2VF_MBX_RAW_MSG_MAX_SPEC - SXE2VF_MBX_RAW_MSG_OFFSET)

#define SXE2_MBX_MSG_HDR_PTR(cmd_hdr_ptr) \
	({ \
		typeof(cmd_hdr_ptr) ptr = (cmd_hdr_ptr); \
		((struct sxe2vf_mbx_msg_hdr *)((u8 *)(ptr) + (ptr)->hdr_len)); \
	}) \

#define SXE2VF_MBX_DATA_OFFSET(buf)                                   \
	({                                                                \
		struct sxe2_cmd_hdr *_buf = (struct sxe2_cmd_hdr *)(buf);     \
		((_buf->hdr_len) + (SXE2_MBX_MSG_HDR_PTR(_buf)->data_offset)); \
	})

#define SXE2_FNAV_MAX_NUM_PROTO_HDRS    (9)
#define SXE2_FNAV_MAX_NUM_ACTIONS       (3)
#define SXE2_FNAV_IPV6_ADDR_LEN_TO_U32  (4)
#define SXE2_FNAV_ETH_ADDR_LEN          (6)
#define SXE2_VF_FNAV_INVALID_LOC        (0xFFFF)
#define SXE2_VF_FNAV_INVALID_FLOW_ID    (0xFFFF)
#define SXE2_VF_FNAV_INVALID_STAT_IDX   (0xFFFF)

#define SXE2_CMD_HDR_MULTI_END BIT(6)
#define SXE2_CMD_HDR_MULTI_START BIT(7)
#define SXE2_CMD_HDR_MULTI_CMD_ID_MASK 0x3F

struct sxe2vf_cmd_hdr {
	__le32 magic_code;
	__le16 in_len;
	__le16 out_len;
	__le16 hdr_len;
	u8     cmd_type;
	u8     multi_packet;
	__le64 trace_id;
	__le64 session_id;
	__le32 ret;
	__le32 timeout;
	u8     resv[28];
	u8     body[];
};

struct sxe2vf_mbx_msg_hdr {
	__le32 op_code;
	__le32 err_code;
	__le32 data_offset;
	__le32 data_len;
	__le16 vf_id;
	u8     recv[14];
	u8     body[];
};

enum sxe2_driver_type {
	SXE2_DRIVER_TYPE_VF = 0,
};

struct sxe2_vf_vfres_msg_req {
	u8 driver_type;
	u8 support_sw_stats;
	u8 reserve[2];
};

struct sxe2_vf_drv_mode_req {
	u8 drv_mode;
	u8 reserve[3];
};

struct sxe2_vf_drv_mode_resp {
	u8 drv_mode;
	u8 reserve[3];
};

struct sxe2_vf_ver_msg {
	__le16 major;
	__le16 minor;
};

struct sxe2_vf_rxq_ctxt {
	u8 lro_status;
	u8 keep_crc_en;
	__le16 queue_id;
	__le16 depth;
	__le16 buf_len;
	__le64 dma_addr;
};

struct sxe2_vf_rxq_msg {
	__le16 q_cnt;
	__le16 vsi_id;
	__le16 max_frame_size;
	struct sxe2_vf_rxq_ctxt ctxt[];
};

struct sxe2_vf_vsi_sw_stats {
	__le64 rx_packets;
	__le64 rx_bytes;
	__le64 tx_packets;
	__le64 tx_bytes;
};

struct sxe2_vf_sw_stats {
	__le16 vsi_id;
	struct sxe2_vf_vsi_sw_stats sw_stats;
	__le16 fnav_stats_idx;
};

struct sxe2_vf_vsi_res {
	__le16 vsi_id;
};

struct sxe2_vf_vsi_hw_stats {
	__le64 rx_vsi_unicast_packets;
	__le64 rx_vsi_bytes;
	__le64 tx_vsi_unicast_packets;
	__le64 tx_vsi_bytes;
	__le64 rx_vsi_multicast_packets;
	__le64 tx_vsi_multicast_packets;
	__le64 rx_vsi_broadcast_packets;
	__le64 tx_vsi_broadcast_packets;
};

struct sxe2_vf_hw_stats_rsp {
	struct sxe2_vf_vsi_hw_stats hw_stats;
	__le64 fnav_match;
};

struct sxe2_fw_ver_msg {
	u8 main_version_id;
	u8 sub_version_id;
	u8 fix_version_id;
	u8 build_id;
};

struct sxe2_vf_txsch_caps {
	u8 layer_cap;
	u8 tm_mid_node_num;
	u8 prio_num;
};

struct sxe2_vf_rxft_caps {
	__le16 rss_lut_type;
	__le16 rss_key_size;
	__le16 rss_lut_size;
	__le16 fnav_space_gsize;
	__le16 fnav_space_bsize;
};

struct sxe2_vf_vfres_msg {
	__le16 num_vsis;
	__le16 max_vectors;
	__le16 q_cnt;
	__le16 itr_gran;
	u8 addr[ETH_ALEN];
	__le16 max_vlan_cnt;
	u8 port_vlan_exsit;
	u8 is_switchdev;
	u8 pf_cnt;
	u8 parent_pfid;
	__le16 vf_id_in_dev;
	struct sxe2_vf_rxft_caps rxft_cap;
	struct sxe2_vf_vsi_res vsi_res[SXE2_VF_MAX_VSI_CNT];
	struct sxe2_vf_txsch_caps vf_txsch_cap;
	struct sxe2_fw_ver_msg fw_ver;
	__le32 cap_flags;
	u8 tm_layers;
	u8 parent_portid;
	u8 mode;
};

struct sxe2_vf_irq_map {
	__le16 irq_id;
	__le16 txq_map;
	__le16 rxq_map;
	__le16 rxitr_idx;
	__le16 txitr_idx;
};

struct sxe2_vf_irq_map_msg {
	__le16 num_irqs;
	__le16 vsi_id;
	struct sxe2_vf_irq_map irq_maps[];
};

struct sxe2_vf_irq_unmap_msg {
	__le16 vsi_id;
};

enum {
	SXE2_VF_MAC_TYPE_P = 0,
	SXE2_VF_MAC_TYPE_C,
};

struct sxe2_vf_addr {
	u8 addr[ETH_ALEN];
	u8 type;
};

struct sxe2_vf_addr_msg {
	bool is_user;
	__le16 vsi_id;
	__le16 addr_cnt;
	struct sxe2_vf_addr elem[];
};

struct sxe2_vf_addr_update_msg {
	bool to_user;
	__le16 vsi_id;
	u8 addr[ETH_ALEN];
};

struct sxe2_vf_promisc_update_msg {
	bool to_user;
	bool is_promisc;
	__le16 vsi_id;
};

struct sxe2_vf_link_msg {
	__le32 speed;
	u8 status;
};

struct sxe2_vf_txq_stop_msg {
	__le16 q_cnt;
	__le16 vsi_id;
};

struct sxe2_vf_txq_ctxt {
	__le16 vsi_id;
	__le16 queue_id;
	__le16 depth;
	__le64 dma_addr;
	__le32 sched_mode;
};

struct sxe2_vf_txq_ctxt_msg {
	__le16 q_cnt;
	__le16 vsi_id;
	struct sxe2_vf_txq_ctxt ctxs[];
};

struct sxe2_vf_qps_dis_msg {
	__le16 qps_cnt;
	__le16 vsi_id;
};

struct sxe2_vf_q_stop_msg {
	__le16 vsi_id;
	__le16 q_idx;
};

struct sxe2_vf_promisc_msg {
	bool is_user;
	__le16 vsi_id;
	u8 resv[2];
	__le32 flags;
};

struct sxe2_vf_vlan_caps {
	u8 port_vlan_exsit;
	__le16 max_cnt;
};

struct sxe2_vf_vlan_offload_cfg {
	u8 stag_strip_enable;
	u8 ctag_strip_enable;
	u8 stag_insert_enable;
	u8 ctag_insert_enable;
};

struct sxe2_vf_vlan_filter_cfg {
	bool is_user;
	u8 ctag_filter_enable;
	u8 stag_filter_enable;
};

struct sxe2_vf_vlan {
	__le16 vid;
	__le16 tpid;
};

struct sxe2_vf_vlan_filter_msg {
	__le16 vsi_id;
	__le16 vlan_cnt;
	struct sxe2_vf_vlan elem[];
};

struct sxe2_vf_user_vlan_msg {
	bool is_add;
	__le16 vsi_id;
	struct sxe2_vf_vlan vlan;
};

struct sxe2_vf_user_vlan_fltr_msg {
	bool is_en;
	__le16 vsi_id;
};

struct sxe2_vf_rss_hash_ctrl {
	u8 hash_func;
};

struct sxe2_vf_rss_hash_msg {
	__le32 headers[BITS_TO_U32(SXE2_FLOW_HDR_MAX)];
	__le32 hash_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	__le32 hdr_type;
	u8 symm;
};

enum sxe2_fnav_flow_type {
	SXE2_FNAV_FLOW_TYPE_NONE        = SXE2_FLOW_TYPE_NONE,
	SXE2_FNAV_FLOW_TYPE_FRAG_IPV4   = SXE2_FLOW_MAC_IPV4_FRAG_PAY,
	SXE2_FNAV_FLOW_TYPE_ETH         = SXE2_FLOW_MAC_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV4_OTHER  = SXE2_FLOW_MAC_IPV4_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV4_UDP    = SXE2_FLOW_MAC_IPV4_UDP_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV4_TCP    = SXE2_FLOW_MAC_IPV4_TCP_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV4_SCTP   = SXE2_FLOW_MAC_IPV4_SCTP_PAY,

	SXE2_FNAV_FLOW_TYPE_FRAG_IPV6   = SXE2_FLOW_MAC_IPV6_FRAG_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV6_OTHER  = SXE2_FLOW_MAC_IPV6_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV6_UDP    = SXE2_FLOW_MAC_IPV6_UDP_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV6_TCP    = SXE2_FLOW_MAC_IPV6_TCP_PAY,
	SXE2_FNAV_FLOW_TYPE_IPV6_SCTP   = SXE2_FLOW_MAC_IPV6_SCTP_PAY,

	SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP = SXE2_FLOW_TYPE_MAX,
	SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP,
	SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_TCP,
	SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP,
	SXE2_FNAV_FLOW_TYPE_MAX,
};

enum sxe2_fnav_act_type {
	SXE2_FNAV_ACTION_DROP = 0,
	SXE2_FNAV_ACTION_TC_REDIRECT,
	SXE2_FNAV_ACTION_PASSTHRU,
	SXE2_FNAV_ACTION_QUEUE,
	SXE2_FNAV_ACTION_Q_REGION,
	SXE2_FNAV_ACTION_MARK,
	SXE2_FNAV_ACTION_COUNT,
};

enum sxe2_fnav_tunnel_level {
	SXE2_FNAV_TUNNEL_OUTER,
	SXE2_FNAV_TUNNEL_INNER,
	SXE2_FNAV_TUNNEL_ANY,
};

enum sxe2_fnav_tunnel_flag_type {
	SXE2_FNAV_TUN_FLAG_NO_TUNNEL,
	SXE2_FNAV_TUN_FLAG_TUNNEL,
	SXE2_FNAV_TUN_FLAG_ANY,
};

struct sxe2_fnav_comm_eth {
	u8 dst[SXE2_FNAV_ETH_ADDR_LEN];
	u8 src[SXE2_FNAV_ETH_ADDR_LEN];
	__be16 etype;
};

struct sxe2_fnav_comm_vlan {
	__be16 vlan_vid;
	__be16 vlan_tci;
	__be16 vlan_type;
};

struct sxe2_fnav_comm_ipv4 {
	__be32 saddr;
	__be32 daddr;
	u8 tos;
	u8 ttl;
	u8 proto;
};

struct sxe2_fnav_comm_ipv6 {
	__be32 dst_ip[SXE2_FNAV_IPV6_ADDR_LEN_TO_U32];
	__be32 src_ip[SXE2_FNAV_IPV6_ADDR_LEN_TO_U32];
	u8 tc;
	u8 proto;
	u8 hlim;
};

struct sxe2_fnav_comm_l4 {
	__be16 dst_port;
	__be16 src_port;
};

struct sxe2_fnav_comm_vxlan {
	__be32 vni;
};

struct sxe2_fnav_comm_geneve {
	__be32 vni;
};

struct sxe2_fnav_comm_gtpu {
	__be32 teid;
};

struct sxe2_fnav_comm_gre {
	__be32 tni;
};

struct sxe2_fnav_comm_proto_hdr {
	u8 tunnel_level;
	u8 type;
	__le32 flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	union {
		struct sxe2_fnav_comm_eth eth;
		struct sxe2_fnav_comm_vlan vlan;
		struct sxe2_fnav_comm_ipv4 ipv4;
		struct sxe2_fnav_comm_ipv6 ipv6;
		struct sxe2_fnav_comm_l4 l4;
		struct sxe2_fnav_comm_vxlan vxlan;
		struct sxe2_fnav_comm_geneve geneve;
		struct sxe2_fnav_comm_gtpu gtpu;
		struct sxe2_fnav_comm_gre gre;
	};
};

struct sxe2_fnav_comm_action_queue {
	__le16 q_index;
};

struct sxe2_fnav_comm_action_queue_region {
	__le16 q_index;
	u8 region;
};

struct sxe2_fnav_comm_action_mark {
	__le32 mark_id;
};

struct sxe2_fnav_comm_action_count {
	__le32 stat_index;
	__le32 stat_ctrl;
};

struct sxe2_fnav_comm_action {
	__le32 type;
	union {
		struct sxe2_fnav_comm_action_queue act_queue;
		struct sxe2_fnav_comm_action_queue_region act_q_region;
		struct sxe2_fnav_comm_action_mark act_mark;
		struct sxe2_fnav_comm_action_count act_count;
	};
};

struct sxe2_fnav_comm_user_data {
	u8 has_flex_filed;
	u8 resv[3];
	__le16 flex_offset;
	__be16 flex_word;
};

struct sxe2_fnav_comm_full_msg {
	__le32 filter_loc;
	__le32 flow_type;
	__le32 tunn_flag;
	u8 action_cnt;
	u8 proto_cnt;
	u8 rsv[2];
	struct sxe2_fnav_comm_action action[SXE2_FNAV_MAX_NUM_ACTIONS];
	struct sxe2_fnav_comm_proto_hdr proto_hdr[SXE2_FNAV_MAX_NUM_PROTO_HDRS];
	struct sxe2_fnav_comm_user_data usr_data;
};

struct sxe2_vf_fnav_filter_del_msg {
	__le32 flow_id;
};

struct sxe2_vf_fnav_add_filter_resp {
	__le32 flow_id;
};

struct sxe2_vf_fnav_stat_alloc_req_msg {
	u8 need_update;
};

struct sxe2_vf_fnav_stat_msg {
	__le16 stat_index;
};

struct sxe2_vf_fnav_stat_query_req_msg {
	__le16 stat_index;
	__le32 stat_ctrl;
	__le32 is_clear;
};

struct sxe2_vf_fnav_stat_query_resp_msg {
	__le16 stat_index;
	__le64 stat_hits;
	__le64 stat_bytes;
};

struct sxe2_vf_qv_info {
	__le32 v_idx;
	__le16 ceq_idx;
	__le16 aeq_idx;
	u8 itr_idx;
	u8 pad[3];
};

struct sxe2_vf_qv_map_msg {
	__le32 num_vectors;
	struct sxe2_vf_qv_info qv_info[];
};

struct sxe2_vf_rdma_mgr_cmd_msg {
	__le32 opcode;
	__le32 msg_len;
	__le32 resv_len;
	u8 msg[];
};

struct sxe2_vf_tm_res {
	__le16 teid;
};

struct sxe2_vf_tm_info {
	__le32 committed;
	__le32 peak;
	u8 priority;
	u8 reserve;
	__le16 weight;
};

struct sxe2_vf_tm_add_root_msg {
	struct sxe2_vf_tm_info info;
};

struct sxe2_vf_tm_add_node_msg {
	__le16 parent_teid;
	struct sxe2_vf_tm_info info;
};

struct sxe2_vf_tm_add_queue_msg {
	__le16 parent_teid;
	__le16 queue_id;
	struct sxe2_vf_tm_info info;
};

struct sxe2_vf_ptp_clock_res {
	__le32 clock_ns;
	__le64 clock_s;
};

struct sxe2_mbx_obj {
	__le32 func_type : 2;
	__le32 resv : 2;
	__le32 pf_id : 4;
	__le32 vf_id : 12;
	__le32 resv1 : 4;
	__le32 drv_type : 2;
	__le32 drv_id : 6;
};

struct sxe2_com_user_data_passthrough_req {
	struct sxe2_mbx_obj obj;
	u32 opcode;
	u16 func_id;
	u16 vsi_id;
	u32 req_len;
	u32 resp_len;
	u32 buff_len;
	u8 cmd_buff[];
};

struct sxe2_com_user_data_passthrough_resp {
	u32 buff_len;
	u8 cmd_buff[];
};

#define SXE2_MBX_IPSEC_IPV6 BIT(0)
#define SXE2_MBX_IPSEC_SM4 BIT(1)
#define SXE2_MBX_IPSEC_AUTH BIT(2)
#define SXE2_MBX_IPSEC_KEY_LEN (32)
#define SCBGE_MBX_IPSEC_IPV4_LEN (4)
#define SCBGE_MBX_IPSEC_IPV6_LEN (16)

struct sxe2_vf_ipsec_sa_add_msg {
	__le32 spi;
	u8 dir;
	u8 mode;
	u8 rsvd[2];
	__le32 addr[SCBGE_MBX_IPSEC_IPV6_LEN / 4];
	u8 enc_key[SXE2_MBX_IPSEC_KEY_LEN];
	u8 auth_key[SXE2_MBX_IPSEC_KEY_LEN];
	__le32 sa_idx;
};

struct sxe2_vf_ipsec_sa_add_resp {
	__le32 sa_idx;
};

struct sxe2_vf_ipsec_sa_del_msg {
	u8 dir;
	u8 rsvd[3];
	__le32 sa_idx;
};

struct sxe2vf_get_capa_response {
	__le16 tx_sa_cnt;
	__le16 rx_sa_cnt;
};

struct sxe2vf_acl_filter_del_req {
	__le32 filter_id;
};

#define SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021Q SXE2_VSI_L2TAGSTXVALID_ID_OUT_VLAN1
#define SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021AD SXE2_VSI_L2TAGSTXVALID_ID_STAG
#define SXE2_DPDK_OFFLOAD_OUTER_INSERT_QINQ1 SXE2_VSI_L2TAGSTXVALID_ID_OUT_VLAN2
#define SXE2_DPDK_OFFLOAD_OUTER_INSERT_VLAN  SXE2_VSI_L2TAGSTXVALID_ID_VLAN

#define SXE2_DPDK_OFFLOAD_OUTER_INSERT_ENABLE SXE2_VSI_L2TAGSTXVALID_L2TAG1_VALID

#define SXE2_DPDK_OFFLOAD_OUTER_STRIP_8021Q SXE2_VSI_TSR_ID_OUT_VLAN1
#define SXE2_DPDK_OFFLOAD_OUTER_STRIP_8021AD SXE2_VSI_TSR_ID_STAG
#define SXE2_DPDK_OFFLOAD_OUTER_STRIP_QINQ1 SXE2_VSI_TSR_ID_OUT_VLAN2

#define SXE2_DPDK_OFFLOAD_INNER_INSERT_QINQ1  SXE2_VSI_L2TAGSTXVALID_ID_VLAN
#define SXE2_DPDK_OFFLOAD_INNER_INSERT_ENABLE SXE2_VSI_L2TAGSTXVALID_L2TAG2_VALID

#define SXE2_DPDK_OFFLOAD_INNER_STRIP_QINQ1 SXE2_VSI_TSR_ID_VLAN

#define SXE2_DPDK_OFFLOAD_FIELD                (0X0F)
#define SXE2_DPDK_OFFLOAD_TAGID_FIELD          (0X07)

#define SXE2_DPDK_OFFLOAD_OUTER_STRIP_MASK (SXE2_DPDK_OFFLOAD_OUTER_STRIP_8021Q | \
					SXE2_DPDK_OFFLOAD_OUTER_STRIP_8021AD | \
					SXE2_DPDK_OFFLOAD_OUTER_STRIP_QINQ1)
#define SXE2_DPDK_OFFLOAD_STRIP_OFFSET SXE2_VSI_TSR_SHOW_TAG_S

#define SXE2_DPDK_OFFLOAD_INSERT_ENABLE (BIT(3))

struct sxe2_dpdk_portvlan_cfg {
	u16 vf_idx;
	u16 tpid;
	u16 vid;
	u8 prio;
	u8 rsv;
};

struct sxe2vf_rdma_dump_pcap_msg {
	u8 mac[ETH_ALEN];
	u8 rsvd[2];
	bool is_add;
	u8 rsvd1[3];
};

struct sxe2_vf_vsi_cfg {
	bool is_clear;
	__le16 txq_base_idx;
	__le16 txq_cnt;
	__le16 rxq_base_idx;
	__le16 rxq_cnt;
	__le16 irq_base_idx;
	__le16 irq_cnt;
	__le16 vsi_id;
};

struct sxe2_vf_user_driver_release {
	u8 func_id;
	u8 drv_id;
};

#pragma pack()
#endif

