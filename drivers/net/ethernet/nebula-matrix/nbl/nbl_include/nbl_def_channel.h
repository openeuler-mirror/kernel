/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_CHANNEL_H_
#define _NBL_DEF_CHANNEL_H_

#include "nbl_include.h"

#define NBL_CHAN_OPS_TBL_TO_OPS(chan_ops_tbl)	((chan_ops_tbl)->ops)
#define NBL_CHAN_OPS_TBL_TO_PRIV(chan_ops_tbl)	((chan_ops_tbl)->priv)

#define NBL_CHAN_SEND(chan_send, dst_id, mesg_type,						\
		      argument, arg_length, response, resp_length, need_ack)			\
do {												\
	typeof(chan_send)	*__chan_send = &(chan_send);					\
	__chan_send->dstid	= (dst_id);							\
	__chan_send->msg_type	= (mesg_type);							\
	__chan_send->arg	= (argument);							\
	__chan_send->arg_len	= (arg_length);							\
	__chan_send->resp	= (response);							\
	__chan_send->resp_len	= (resp_length);						\
	__chan_send->ack	= (need_ack);							\
} while (0)

#define NBL_CHAN_ACK(chan_ack, dst_id, mesg_type, msg_id, err_code, ack_data, data_length)	\
do {												\
	typeof(chan_ack)	*__chan_ack = &(chan_ack);					\
	__chan_ack->dstid	= (dst_id);							\
	__chan_ack->msg_type	= (mesg_type);							\
	__chan_ack->msgid	= (msg_id);							\
	__chan_ack->err		= (err_code);							\
	__chan_ack->data	= (ack_data);							\
	__chan_ack->data_len	= (data_length);						\
} while (0)

typedef void (*nbl_chan_resp)(void *, u16, u16, void *, u32);

enum {
	NBL_CHAN_RESP_OK,
	NBL_CHAN_RESP_ERR,
};

enum nbl_chan_msg_type {
	NBL_CHAN_MSG_ACK,
	NBL_CHAN_MSG_ADD_MACVLAN,
	NBL_CHAN_MSG_DEL_MACVLAN,
	NBL_CHAN_MSG_ADD_MULTI_RULE,
	NBL_CHAN_MSG_DEL_MULTI_RULE,
	NBL_CHAN_MSG_SETUP_MULTI_GROUP,
	NBL_CHAN_MSG_REMOVE_MULTI_GROUP,
	NBL_CHAN_MSG_REGISTER_NET,
	NBL_CHAN_MSG_UNREGISTER_NET,
	NBL_CHAN_MSG_ALLOC_TXRX_QUEUES,
	NBL_CHAN_MSG_FREE_TXRX_QUEUES,
	NBL_CHAN_MSG_SETUP_QUEUE,
	NBL_CHAN_MSG_REMOVE_ALL_QUEUES,
	NBL_CHAN_MSG_CFG_DSCH,
	NBL_CHAN_MSG_SETUP_CQS,
	NBL_CHAN_MSG_REMOVE_CQS,
	NBL_CHAN_MSG_CFG_QDISC_MQPRIO,
	NBL_CHAN_MSG_CONFIGURE_MSIX_MAP,
	NBL_CHAN_MSG_DESTROY_MSIX_MAP,
	NBL_CHAN_MSG_MAILBOX_ENABLE_IRQ,
	NBL_CHAN_MSG_GET_GLOBAL_VECTOR,
	NBL_CHAN_MSG_GET_VSI_ID,
	NBL_CHAN_MSG_SET_PROSISC_MODE,
	NBL_CHAN_MSG_GET_FIRMWARE_VERSION,
	NBL_CHAN_MSG_GET_QUEUE_ERR_STATS,
	NBL_CHAN_MSG_GET_COALESCE,
	NBL_CHAN_MSG_SET_COALESCE,
	NBL_CHAN_MSG_SET_SPOOF_CHECK_ADDR,
	NBL_CHAN_MSG_SET_VF_SPOOF_CHECK,
	NBL_CHAN_MSG_GET_RXFH_INDIR_SIZE,
	NBL_CHAN_MSG_GET_RXFH_INDIR,
	NBL_CHAN_MSG_GET_RXFH_RSS_KEY,
	NBL_CHAN_MSG_GET_RXFH_RSS_ALG_SEL,
	NBL_CHAN_MSG_GET_PHY_CAPS,
	NBL_CHAN_MSG_GET_PHY_STATE,
	NBL_CHAN_MSG_REGISTER_RDMA,
	NBL_CHAN_MSG_UNREGISTER_RDMA,
	NBL_CHAN_MSG_GET_REAL_HW_ADDR,
	NBL_CHAN_MSG_GET_REAL_BDF,
	NBL_CHAN_MSG_GRC_PROCESS,
	NBL_CHAN_MSG_SET_SFP_STATE,
	NBL_CHAN_MSG_SET_ETH_LOOPBACK,
	NBL_CHAN_MSG_CHECK_ACTIVE_VF,
	NBL_CHAN_MSG_GET_PRODUCT_FLEX_CAP,
	NBL_CHAN_MSG_ALLOC_KTLS_TX_INDEX,
	NBL_CHAN_MSG_FREE_KTLS_TX_INDEX,
	NBL_CHAN_MSG_CFG_KTLS_TX_KEYMAT,
	NBL_CHAN_MSG_ALLOC_KTLS_RX_INDEX,
	NBL_CHAN_MSG_FREE_KTLS_RX_INDEX,
	NBL_CHAN_MSG_CFG_KTLS_RX_KEYMAT,
	NBL_CHAN_MSG_CFG_KTLS_RX_RECORD,
	NBL_CHAN_MSG_ADD_KTLS_RX_FLOW,
	NBL_CHAN_MSG_DEL_KTLS_RX_FLOW,
	NBL_CHAN_MSG_ALLOC_IPSEC_TX_INDEX,
	NBL_CHAN_MSG_FREE_IPSEC_TX_INDEX,
	NBL_CHAN_MSG_ALLOC_IPSEC_RX_INDEX,
	NBL_CHAN_MSG_FREE_IPSEC_RX_INDEX,
	NBL_CHAN_MSG_CFG_IPSEC_TX_SAD,
	NBL_CHAN_MSG_CFG_IPSEC_RX_SAD,
	NBL_CHAN_MSG_ADD_IPSEC_TX_FLOW,
	NBL_CHAN_MSG_DEL_IPSEC_TX_FLOW,
	NBL_CHAN_MSG_ADD_IPSEC_RX_FLOW,
	NBL_CHAN_MSG_DEL_IPSEC_RX_FLOW,
	NBL_CHAN_MSG_NOTIFY_IPSEC_HARD_EXPIRE,
	NBL_CHAN_MSG_GET_MBX_IRQ_NUM,
	NBL_CHAN_MSG_CLEAR_FLOW,
	NBL_CHAN_MSG_CLEAR_QUEUE,
	NBL_CHAN_MSG_GET_ETH_ID,
	NBL_CHAN_MSG_SET_OFFLOAD_STATUS,

	NBL_CHAN_MSG_INIT_OFLD,
	NBL_CHAN_MSG_INIT_CMDQ,
	NBL_CHAN_MSG_DESTROY_CMDQ,
	NBL_CHAN_MSG_RESET_CMDQ,
	NBL_CHAN_MSG_INIT_FLOW,
	NBL_CHAN_MSG_DEINIT_FLOW,
	NBL_CHAN_MSG_OFFLOAD_FLOW_RULE,
	NBL_CHAN_MSG_GET_ACL_SWITCH,
	NBL_CHAN_MSG_GET_VSI_GLOBAL_QUEUE_ID,
	NBL_CHAN_MSG_INIT_REP,
	NBL_CHAN_MSG_GET_LINE_RATE_INFO,

	NBL_CHAN_MSG_REGISTER_NET_REP,
	NBL_CHAN_MSG_UNREGISTER_NET_REP,
	NBL_CHAN_MSG_REGISTER_ETH_REP,
	NBL_CHAN_MSG_UNREGISTER_ETH_REP,
	NBL_CHAN_MSG_REGISTER_UPCALL_PORT,
	NBL_CHAN_MSG_UNREGISTER_UPCALL_PORT,
	NBL_CHAN_MSG_GET_PORT_STATE,
	NBL_CHAN_MSG_SET_PORT_ADVERTISING,
	NBL_CHAN_MSG_GET_MODULE_INFO,
	NBL_CHAN_MSG_GET_MODULE_EEPROM,
	NBL_CHAN_MSG_GET_LINK_STATE,
	NBL_CHAN_MSG_NOTIFY_LINK_STATE,

	NBL_CHAN_MSG_GET_QUEUE_CXT,
	NBL_CHAN_MSG_CFG_LOG,
	NBL_CHAN_MSG_INIT_VDPAQ,
	NBL_CHAN_MSG_DESTROY_VDPAQ,
	NBL_CHAN_GET_UPCALL_PORT,
	NBL_CHAN_MSG_NOTIFY_ETH_REP_LINK_STATE,
	NBL_CHAN_MSG_SET_ETH_MAC_ADDR,
	NBL_CHAN_MSG_GET_FUNCTION_ID,
	NBL_CHAN_MSG_GET_CHIP_TEMPERATURE,

	NBL_CHAN_MSG_DISABLE_PHY_FLOW,
	NBL_CHAN_MSG_ENABLE_PHY_FLOW,
	NBL_CHAN_MSG_SET_UPCALL_RULE,
	NBL_CHAN_MSG_UNSET_UPCALL_RULE,

	NBL_CHAN_MSG_GET_REG_DUMP,
	NBL_CHAN_MSG_GET_REG_DUMP_LEN,

	NBL_CHAN_MSG_CFG_LAG_HASH_ALGORITHM,
	NBL_CHAN_MSG_CFG_LAG_MEMBER_FWD,
	NBL_CHAN_MSG_CFG_LAG_MEMBER_LIST,
	NBL_CHAN_MSG_CFG_LAG_MEMBER_UP_ATTR,
	NBL_CHAN_MSG_ADD_LAG_FLOW,
	NBL_CHAN_MSG_DEL_LAG_FLOW,

	NBL_CHAN_MSG_SWITCHDEV_INIT_CMDQ,
	NBL_CHAN_MSG_SWITCHDEV_DEINIT_CMDQ,
	NBL_CHAN_MSG_SET_TC_FLOW_INFO,
	NBL_CHAN_MSG_UNSET_TC_FLOW_INFO,
	NBL_CHAN_MSG_INIT_ACL,
	NBL_CHAN_MSG_UNINIT_ACL,

	NBL_CHAN_MSG_CFG_LAG_MCC,

	NBL_CHAN_MSG_REGISTER_VSI2Q,
	NBL_CHAN_MSG_SETUP_Q2VSI,
	NBL_CHAN_MSG_REMOVE_Q2VSI,
	NBL_CHAN_MSG_SETUP_RSS,
	NBL_CHAN_MSG_REMOVE_RSS,
	NBL_CHAN_MSG_GET_REP_QUEUE_INFO,
	NBL_CHAN_MSG_CTRL_PORT_LED,
	NBL_CHAN_MSG_NWAY_RESET,
	NBL_CHAN_MSG_SET_INTL_SUPPRESS_LEVEL,
	NBL_CHAN_MSG_GET_ETH_STATS,
	NBL_CHAN_MSG_GET_MODULE_TEMPERATURE,
	NBL_CHAN_MSG_GET_BOARD_INFO,

	NBL_CHAN_MSG_GET_P4_USED,
	NBL_CHAN_MSG_GET_VF_BASE_VSI_ID,

	NBL_CHAN_MSG_ADD_LLDP_FLOW,
	NBL_CHAN_MSG_DEL_LLDP_FLOW,

	NBL_CHAN_MSG_CFG_ETH_BOND_INFO,
	NBL_CHAN_MSG_CFG_DUPPKT_MCC,

	NBL_CHAN_MSG_ADD_ND_UPCALL_FLOW,
	NBL_CHAN_MSG_DEL_ND_UPCALL_FLOW,

	NBL_CHAN_MSG_GET_BOARD_ID,

	NBL_CHAN_MSG_SET_SHAPING_DPORT_VLD,
	NBL_CHAN_MSG_SET_DPORT_FC_TH_VLD,

	NBL_CHAN_MSG_REGISTER_RDMA_BOND,
	NBL_CHAN_MSG_UNREGISTER_RDMA_BOND,

	NBL_CHAN_MSG_RESTORE_NETDEV_QUEUE,
	NBL_CHAN_MSG_RESTART_NETDEV_QUEUE,
	NBL_CHAN_MSG_RESTORE_HW_QUEUE,

	NBL_CHAN_MSG_KEEP_ALIVE,

	NBL_CHAN_MSG_GET_BASE_MAC_ADDR,

	NBL_CHAN_MSG_CFG_BOND_SHAPING,
	NBL_CHAN_MSG_CFG_BGID_BACK_PRESSURE,

	NBL_CHAN_MSG_ALLOC_KT_BLOCK,
	NBL_CHAN_MSG_FREE_KT_BLOCK,

	NBL_CHAN_MSG_GET_USER_QUEUE_INFO,
	NBL_CHAN_MSG_GET_ETH_BOND_INFO,

	NBL_CHAN_MSG_CLEAR_ACCEL_FLOW,
	NBL_CHAN_MSG_SET_BRIDGE_MODE,

	NBL_CHAN_MSG_GET_VF_FUNCTION_ID,
	NBL_CHAN_MSG_NOTIFY_LINK_FORCED,

	NBL_CHAN_MSG_SET_PMD_DEBUG,

	NBL_CHAN_MSG_REGISTER_FUNC_MAC,
	NBL_CHAN_MSG_SET_TX_RATE,

	NBL_CHAN_MSG_REGISTER_FUNC_LINK_FORCED,
	NBL_CHAN_MSG_GET_LINK_FORCED,

	NBL_CHAN_MSG_REGISTER_FUNC_VLAN,

	NBL_CHAN_MSG_GET_FD_FLOW,
	NBL_CHAN_MSG_GET_FD_FLOW_CNT,
	NBL_CHAN_MSG_GET_FD_FLOW_ALL,
	NBL_CHAN_MSG_GET_FD_FLOW_MAX,
	NBL_CHAN_MSG_REPLACE_FD_FLOW,
	NBL_CHAN_MSG_REMOVE_FD_FLOW,
	NBL_CHAN_MSG_CFG_FD_FLOW_STATE,

	NBL_CHAN_MSG_REGISTER_FUNC_RATE,
	NBL_CHAN_MSG_NOTIFY_VLAN,
	NBL_CHAN_MSG_GET_XDP_QUEUE_INFO,

	NBL_CHAN_MSG_STOP_ABNORMAL_SW_QUEUE,
	NBL_CHAN_MSG_STOP_ABNORMAL_HW_QUEUE,
	NBL_CHAN_MSG_NOTIFY_RESET_EVENT,
	NBL_CHAN_MSG_ACK_RESET_EVENT,
	NBL_CHAN_MSG_GET_VF_VSI_ID,

	NBL_CHAN_MSG_CONFIGURE_QOS,
	NBL_CHAN_MSG_GET_PFC_BUFFER_SIZE,
	NBL_CHAN_MSG_SET_PFC_BUFFER_SIZE,
	NBL_CHAN_MSG_GET_VF_STATS,
	NBL_CHAN_MSG_REGISTER_FUNC_TRUST,
	NBL_CHAN_MSG_NOTIFY_TRUST,
	NBL_CHAN_CHECK_VF_IS_ACTIVE,
	NBL_CHAN_MSG_GET_ETH_ABNORMAL_STATS,
	NBL_CHAN_MSG_GET_ETH_CTRL_STATS,
	NBL_CHAN_MSG_GET_PAUSE_STATS,
	NBL_CHAN_MSG_GET_ETH_MAC_STATS,
	NBL_CHAN_MSG_GET_FEC_STATS,
	NBL_CHAN_MSG_CFG_MULTI_MCAST_RULE,
	NBL_CHAN_MSG_GET_LINK_DOWN_COUNT,
	NBL_CHAN_MSG_GET_LINK_STATUS_OPCODE,
	NBL_CHAN_MSG_GET_RMON_STATS,
	NBL_CHAN_MSG_REGISTER_PF_NAME,
	NBL_CHAN_MSG_GET_PF_NAME,
	NBL_CHAN_MSG_CONFIGURE_RDMA_BW,
	NBL_CHAN_MSG_SET_RATE_LIMIT,
	NBL_CHAN_MSG_SET_TC_WGT,
	NBL_CHAN_MSG_REMOVE_QUEUE,
	NBL_CHAN_MSG_GET_MIRROR_TABLE_ID,
	NBL_CHAN_MSG_CONFIGURE_MIRROR,
	NBL_CHAN_MSG_CONFIGURE_MIRROR_TABLE,
	NBL_CHAN_MSG_CLEAR_MIRROR_CFG,
	NBL_CHAN_MSG_MIRROR_OUTPUTPORT_NOTIFY,
	NBL_CHAN_MSG_CHECK_FLOWTABLE_SPEC,
	NBL_CHAN_CHECK_VF_IS_VDPA,
	NBL_CHAN_MSG_GET_VDPA_VF_STATS,
	NBL_CHAN_MSG_SET_RX_RATE,
	NBL_CHAN_GET_UVN_PKT_DROP_STATS,
	NBL_CHAN_GET_PKT_DROP_STATS,
	NBL_CHAN_GET_TOTAL_PKT_DROP_STATS,
	NBL_CHAN_MSG_SET_WOL,
	NBL_CHAN_MSG_INIT_VF_MSIX_MAP,
	NBL_CHAN_MSG_GET_ST_NAME,
	NBL_CHAN_MSG_LOG_MODULE_ALARM,
	NBL_CHAN_MSG_SWITCHDEV_SET_OFFLOAD_MODE,
	NBL_CHAN_MSG_SWITCHDEV_ADD_BRIDGE_FLOW_RULE,
	NBL_CHAN_MSG_SWITCHDEV_DEL_BRIDGE_FLOW_RULE,
	NBL_CHAN_MSG_SWITCHDEV_QUERY_BRIDGE_FDB_LASTUSE,
	NBL_CHAN_MSG_CFG_TNL_OFFLOAD_PROFILE,
	NBL_CHAN_MSG_SET_DECAP_SET,

	NBL_CHAN_MSG_CFG_DRACO_BEGIN = 500,
	NBL_CHAN_MSG_CFG_RX_VLAN_PARSE = NBL_CHAN_MSG_CFG_DRACO_BEGIN,
	NBL_CHAN_MSG_MTU_SET,
	NBL_CHAN_MSG_CFG_RSS_HASH,
	NBL_CHAN_MSG_RESTORE_FLOW,
	NBL_CHAN_MSG_INIT_CHIP_MODULES,
	NBL_CHAN_MSG_SET_SLAVE_SWD,
	NBL_CHAN_MSG_SET_RXFH_INDIR,
	NBL_CHAN_MSG_SET_RXFH_RSS_KEY,
	NBL_CHAN_MSG_SET_RXFH_RSS_ALG_SEL,
	NBL_CHAN_MSG_GET_HASH_FIELDS,
	NBL_CHAN_MSG_SET_HASH_FIELDS,
	NBL_CHAN_MSG_INIT_FLOW_DRACO,
	NBL_CHAN_MSG_GET_MY_PF,
	NBL_CHAN_MSG_NOTIFY_RSM_STAT,

	/* mailbox msg end */
	NBL_CHAN_MSG_MAILBOX_MAX,

	/* adminq msg */
	NBL_CHAN_MSG_ADMINQ_BEGIN = 0x8000,
	NBL_CHAN_MSG_ADMINQ_GET_EMP_VERSION = 0x8101,	/* Deprecated, should not be used */
	NBL_CHAN_MSG_ADMINQ_GET_NVM_VERSION = 0x8102,
	NBL_CHAN_MSG_ADMINQ_REBOOT = 0x8104,
	NBL_CHAN_MSG_ADMINQ_FLR_NOTIFY = 0x8105,
	NBL_CHAN_MSG_ADMINQ_NOTITY_FW_RESET = 0x8106,
	NBL_CHAN_MSG_ADMINQ_LOAD_P4 = 0x8107,
	NBL_CHAN_MSG_ADMINQ_LOAD_P4_DEFAULT = 0x8108,
	NBL_CHAN_MSG_ADMINQ_EXT_ALERT = 0x8109,
	NBL_CHAN_MSG_ADMINQ_FLASH_ERASE = 0x8201,
	NBL_CHAN_MSG_ADMINQ_FLASH_READ = 0x8202,
	NBL_CHAN_MSG_ADMINQ_FLASH_WRITE = 0x8203,
	NBL_CHAN_MSG_ADMINQ_FLASH_ACTIVATE = 0x8204,
	NBL_CHAN_MSG_ADMINQ_RESOURCE_WRITE = 0x8205,
	NBL_CHAN_MSG_ADMINQ_RESOURCE_READ = 0x8206,
	NBL_CHAN_MSG_ADMINQ_REGISTER_WRITE = 0x8207,
	NBL_CHAN_MSG_ADMINQ_REGISTER_READ = 0x8208,
	NBL_CHAN_MSG_ADMINQ_GET_NVM_BANK_INDEX = 0x820B,
	NBL_CHAN_MSG_ADMINQ_VERIFY_NVM_BANK = 0x820C,
	NBL_CHAN_MSG_ADMINQ_FLASH_LOCK = 0x820D,
	NBL_CHAN_MSG_ADMINQ_FLASH_UNLOCK = 0x820E,
	NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES = 0x8300,
	NBL_CHAN_MSG_ADMINQ_PORT_NOTIFY = 0x8301,
	NBL_CHAN_MSG_ADMINQ_GET_MODULE_EEPROM = 0x8302,
	NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS = 0x8303,
	NBL_CHAN_MSG_ADMINQ_GET_FEC_STATS = 0x8305,

	NBL_CHAN_MSG_MAX,
};

#define NBL_CHAN_ADMINQ_FUNCTION_ID (0xFFFF)

struct nbl_ch_prm_get_vsi_global_qid {
	u16 vsi_id;
	u16 local_qid;
};

#define NBL_CHANNEL_FREEZE_FAILED_CNT	3

enum nbl_chan_state {
	NBL_CHAN_INTERRUPT_READY,
	NBL_CHAN_RESETTING,
	NBL_CHAN_ABNORMAL,
	NBL_CHAN_STATE_NBITS
};

struct nbl_chan_param_add_macvlan {
	u8 mac[ETH_ALEN];
	u16 vlan;
	u16 vsi;
};

struct nbl_chan_param_del_macvlan {
	u8 mac[ETH_ALEN];
	u16 vlan;
	u16 vsi;
};

struct nbl_ch_prm_set_decap_set {
	u8 mac[ETH_ALEN];
	u16 vlan_0;
	u16 vlan_1;
	u8 vlan_layer;
	u8 idx;
	u8 is_add;

	u16 sfid;
};

struct nbl_ch_prm_cfg_multi_mcast {
	u16 vsi;
	u16 enable;
};

struct nbl_ch_prm_register_net_info {
	u16 pf_bdf;
	u64 vf_bar_start;
	u64 vf_bar_size;
	u16 total_vfs;
	u16 offset;
	u16 stride;
	u64 pf_bar_start;
	u16 is_vdpa;
	u16 rsv;
	u16 sfid; /* always must be in last */
};

struct nbl_ch_prm_alloc_txrx_queues {
	u16 vsi_id;
	u16 queue_num;
};

struct nbl_chan_param_register_vsi2q {
	u16 vsi_index;
	u16 vsi_id;
	u16 queue_offset;
	u16 queue_num;
};

struct nbl_ch_prm_setup_queue {
	struct nbl_txrx_queue_param param;
	bool is_tx;
	u8 rsv[7];
	bool interleave_seg_disable;
};

struct nbl_ch_prm_flow_table_spec {
	u16 vlan_list_cnt;
	u16 unicast_mac_cnt;
	u16 multi_mac_cnt;
};

struct nbl_chan_param_cfg_dsch {
	u16 vsi_id;
	bool vld;
};

struct nbl_chan_param_setup_cqs {
	u16 vsi_id;
	u16 real_qps;
	bool rss_indir_set;
};

struct nbl_ch_prm_set_promisc_mode {
	u16 vsi_id;
	u16 mode;
};

struct nbl_ch_prm_init_vf_msix_map {
	u16 sfid;
	bool enable;
};

struct nbl_ch_prm_cfg_msix_map {
	u16 num_net_msix;
	u16 num_others_msix;
	u16 net_msix_mask_en;
	u16 sfid;
};

struct nbl_chan_param_log_module_alarm {
	u16 temp;
	u64 up_time;
	u8 logic_eth_id;
	u8 status;
	u16 temp_th;
} __packed;

struct nbl_ch_prm_enable_irq {
	u16 vector_id;
	bool enable_msix;
	bool rsv;
	u16 sfid;
};

struct nbl_ch_prm_get_global_vec {
	u16 vsi_id;
	u16 vector_id;
};

struct nbl_ch_prm_get_vsi {
	u16 vsi_id;
	u16 type;
	u16 sfid;
};

struct nbl_ch_prm_get_vf_base_vsi_id {
	u16 vf_base_vsi_id;
	u16 sfid;
};

struct nbl_ch_prm_get_owned_pf_bitmap {
	unsigned long *owned_pf_bitmap;
	u8 max_pf;
	u16 bdf;
};

struct nbl_ch_prm_get_eth_id {
	u16 vsi_id;
	u8 eth_mode;
	u8 eth_id;
	u8 logic_eth_id;
};

struct nbl_ch_prm_enable_lag_protocol {
	u16 eth_id;
	bool lag_en;
};

struct nbl_ch_prm_get_queue_info {
	u16 queue_num;
	u16 queue_size;
};

struct nbl_ch_prm_set_eth_loopback {
	u32 eth_port_id;
	u32 enable;
};

struct nbl_ch_prm_get_queue_err_stats {
	u8 queue_id;
	bool is_tx;
	u16 sfid;
};

struct nbl_ch_prm_set_coalesce {
	u16 local_vector_id;
	u16 vector_num;
	u16 rx_max_coalesced_frames;
	u16 rx_coalesce_usecs;
	u16 sfid;				/* srcid_map 回填 */
};

struct nbl_ch_prm_set_spoof_check_addr {
	u16 vsi_id;
	u8 mac[ETH_ALEN];
};

struct nbl_ch_prm_set_vf_spoof_check {
	u16 vsi_id;
	u16 vf_id;
	bool enable;
};

struct nbl_ch_prm_get_rxfh_rss_key {
	u32 rss_key_size;
	u16 vsi_id;
};

struct nbl_ch_prm_get_rxfh_key {
	u8 rss_key[NBL_EPRO_RSS_SK_SIZE];
};

struct nbl_chan_param_get_rxfh_indir {
	u16 vsi_id;
	u32 rxfh_indir_size;
};

struct nbl_ch_prm_set_rxfh_rss_alg_sel {
	u16 vsi_id;
	u8 rss_alg_sel;
};

struct nbl_ch_prm_get_real_bdf {
	u8 bus;
	u8 dev;
	u8 function;
};

struct nbl_ch_prm_set_upcall {
	u16 vsi_id;
	u8 eth_id;
};

struct nbl_ch_prm_set_func_vld {
	u8 eth_id;
	bool vld;
};

struct nbl_chan_param_nvm_version_resp {
	char magic[8];		/* "M181FWV0" */
	u32 version;		/* major << 16 | minor << 8 | revision */
	u32 build_date;		/* 0x20231231 - 2023.12.31 */
	u32 build_time;		/* 0x00123456 - 12:34:56 */
	u32 build_hash;		/* git commit hash */
	u32 rsv[2];
};

struct nbl_chan_param_flash_read {
	u32 bank_id;
	u32 offset;
	u32 len;
#define NBL_CHAN_FLASH_READ_LEN		0x800
};

struct nbl_chan_param_flash_erase {
	u32 bank_id;
	u32 offset;
	u32 len;
#define NBL_CHAN_FLASH_ERASE_LEN	0x1000
};

struct nbl_chan_resource_write_param {
	u32 resid;
	u32 offset;
	u32 len;
	u8 data[];
};

struct nbl_chan_resource_read_param {
	u32 resid;
	u32 offset;
	u32 len;
};

struct nbl_chan_adminq_reg_read_param {
	u32 reg;
};

struct nbl_chan_adminq_reg_write_param {
	u32 reg;
	u32 value;
};

struct nbl_chan_param_flash_write {
	u32 bank_id;
	u32 offset;
	u32 len;
#define NBL_CHAN_FLASH_WRITE_LEN	0x800
	u8 data[NBL_CHAN_FLASH_WRITE_LEN];
};

struct nbl_chan_param_load_p4 {
	u8 name[NBL_P4_SECTION_NAME_LEN];
	u32 addr;
	u32 size;
	u32 section_index;
	u32 section_offset;
	u32 load_start;
	u32 load_end;
	u8 data[];
};

struct nbl_chan_result_flash_activate {
	u32 err_code;
	u32 reset_flag;
};

struct nbl_ch_prm_set_sfp_state {
	u8 eth_id;
	u8 state;
};

struct nbl_chan_param_get_module_eeprom {
	u8 eth_id;
	struct ethtool_eeprom eeprom;
};

struct nbl_chan_param_module_eeprom_info {
	u8 eth_id;
	u8 i2c_address;
	u8 page;
	u8 bank;
	u32 write:1;
	u32 version:2;
	u32 rsvd:29;
	u16 offset;
	u16 length;
#define NBL_MODULE_EEPRO_WRITE_MAX_LEN (4)
	u8 data[NBL_MODULE_EEPRO_WRITE_MAX_LEN];
};

struct nbl_chan_param_eth_rep_notify_link_state {
	u8 eth_id;
	u8 link_state;
};

struct nbl_chan_param_set_rxfh_indir {
	u16 vsi_id;
	u32 indir_size;
#define NBL_RXFH_INDIR_MAX_SIZE		(512)
	u32 indir[NBL_RXFH_INDIR_MAX_SIZE];
};

struct nbl_ch_prm_set_rxfh_rss_key {
	u16 vsi_id;
	u8 rss_key[NBL_EPRO_RSS_SK_SIZE];
};

struct nbl_chan_param_get_hash_fields {
	u16 vsi_id;
	int flow_type;
};

struct nbl_chan_param_set_hash_fields {
	u16 vsi_id;
	int flow_type;
	u64 hash_fields;
};

struct nbl_ch_prm_cfg_ktls_keymat {
	u32 index;
	u8 mode;
#define NBL_CHAN_SALT_LEN	4
#define NBL_CHAN_KEY_LEN	32
	u8 salt[NBL_CHAN_SALT_LEN];
	u8 key[NBL_CHAN_KEY_LEN];
	u8 key_len;
};

struct nbl_ch_prm_cfg_ktls_record {
	bool init;
	u32 index;
	u32 tcp_sn;
	u64 rec_num;
};

struct nbl_ch_prm_cfg_ktls_flow {
	u32 index;
	u32 vsi;
#define NBL_CHAN_KTLS_FLOW_LEN	12
	u32 data[NBL_CHAN_KTLS_FLOW_LEN];
};

struct nbl_ch_prm_ipsec_index {
	int index;
	struct nbl_ipsec_cfg_info cfg_info;
};

struct nbl_ch_prm_cfg_ipsec_sad {
	u32 index;
	struct nbl_ipsec_sa_entry sa_entry;
};

struct nbl_ch_prm_cfg_ipsec_flow {
	u32 index;
	u32 vsi;
#define NBL_CHAN_IPSEC_FLOW_LEN	12
	u32 data[NBL_CHAN_IPSEC_FLOW_LEN];
};

/* for PMD driver */
struct nbl_chan_param_get_rep_vsi_id {
	u16 pf_id;
	u16 vf_id;
};

struct nbl_chan_param_register_net_rep {
	u16 pf_id;
	u16 vf_id;
};

struct nbl_chan_param_set_eth_mac_addr {
	u8 mac[ETH_ALEN];
	u8 eth_id;
};

struct nbl_chan_cmdq_init_info {
	u64 pa;
	u32 len;
	u16 vsi_id;
	u16 bdf_num;
};

struct nbl_chan_rep_cfg_info {
	u16 vsi_id;
	u8 inner_type;
	u8 outer_type;
	u8 rep_type;
};

struct nbl_flow_prf_data {
	u16 pp_id;
	u16 prf_id;
};

struct nbl_chan_param_slave_swd {
	u16 mgt_pf;
	u16 swd_id;
};

struct nbl_flow_prf_upcall_info {
	u32 item_cnt;
#define NBL_MAX_PP_NUM 64
	struct nbl_flow_prf_data prf_data[NBL_MAX_PP_NUM];
};

struct nbl_acl_cfg_param {
	u32 acl_enable:1;
	u32 acl_key_width:9;
	u32 acl_key_cap:16;
	u32 acl_tcam_idx:4;
	u32 acl_stage:1;
	u32 loop_en:1;
	u32 tcam_cfg[4];
	u32 action_cfg[4];
};

struct nbl_chan_flow_init_info_leonis {
	u8 acl_switch;
	u16 vsi_id;
	u16 acl_loop_en;
	struct nbl_acl_cfg_param acl_cfg[2];
	struct nbl_flow_prf_upcall_info flow_cfg;
};

struct nbl_acl_cfg_param_full {
	u32 acl_enable:1;
	u32 acl_key_width:9;
	u32 acl_key_cap:16;
	u32 acl_tcam_idx:4;  /* basically the same as tcam_start */
	u32 acl_stage:1;
	u32 loop_en:1;
#define NBL_ACL_TCAM_CFG_NUM 16
#define NBL_ACL_AD_CFG_NUM 16
	u32 tcam_cfg[NBL_ACL_TCAM_CFG_NUM];
	u32 action_cfg[NBL_ACL_AD_CFG_NUM];
	u8 profile_id;
	u8 tcam_start;
	u8 tcam_cnt;
	u8 tcam_depth_need;
	u8 tcam_width_need;
	u8 act_start;
	u8 act_cnt;
	u16 tcam_bitmap; /* acl tcam bitmap */
	u16 act_bitmap;
};

struct nbl_chan_flow_init_info_draco {
	u8 acl_switch;
	u8 eth_id;
	u16 vsi_id;
	u16 acl_loop_en;
#define NBL_ACL_CFG_CNT 16
	struct nbl_acl_cfg_param_full acl_cfg[NBL_ACL_CFG_CNT];
	struct nbl_flow_prf_upcall_info flow_cfg;
};

#pragma pack(1)

struct nbl_chan_regs_info {
	union {
		u16 depth;
		struct {
			u16 ram_id:5;
			u16 s_depth:11;
		};
	};
	u16 data_len:6;		/* align to u32 */
	u16 tbl_name:7;
	u16 mode:3;
	u32 data[];
};

struct nbl_chan_bulk_regs_info {
	u32 item_cnt:9;
	u32 rsv:7;
	u32 data_len:16;	/* align to u32 */
	u32 data[];
};

#pragma pack()

struct nbl_chan_param_get_queue_cxt {
	u16 vsi_id;
	u16 local_queue;
};

struct nbl_chan_param_cfg_log {
	u16 vsi_id;
	u16 qps;
	bool vld;
};

struct nbl_chan_vdpaq_init_info {
	u64 pa;
	u32 size;
};

struct nbl_ch_prm_cfg_lag_hash_algorithm {
	u16 eth_id;
	u16 lag_id;
	enum netdev_lag_hash hash_type;
};

struct nbl_ch_prm_cfg_lag_member_fwd {
	u16 eth_id;
	u16 lag_id;
	u8 fwd;
};

struct nbl_ch_prm_cfg_lag_member_up_attr {
	u16 eth_id;
	u16 lag_id;
	bool enable;
};

struct nbl_ch_prm_cfg_lag_mcc {
	u16 eth_id;
	u16 lag_id;
	bool enable;
};

struct nbl_ch_prm_cfg_bond_shaping {
	u8 eth_id;
	bool enable;
};

struct nbl_ch_prm_cfg_bgid_back_pressure {
	u8 main_eth_id;
	u8 other_eth_id;
	bool enable;
};

struct nbl_chan_param_ctrl_port_led {
	u32 eth_id;
	enum nbl_led_reg_ctrl led_status;
};

struct nbl_ch_prm_set_intr_suppress_level {
	u16 local_vector_id;
	u16 vector_num;
	u16 level;
	u16 sfid;				/* srcid_map 回填 */
};

struct nbl_chan_param_get_private_stat_data {
	u32 eth_id;
	u32 data_len;
};

struct nbl_ch_prm_get_hwmon {
	u32 senser_id;
	enum nbl_hwmon_type type;
};

struct nbl_chan_param_nd_upcall {
	u16 vsi_id;
	bool for_pmd;
};

struct nbl_chan_param_restore_queue {
	u16 local_queue_id;
	int type;
};

struct nbl_chan_param_restart_queue {
	u16 local_queue_id;
	int type;
};

struct nbl_ch_prm_restore_hw_queue {
	u16 vsi_id;
	u16 local_queue_id;
	u64 dma;
	int type;
};

struct nbl_chan_param_stop_abnormal_sw_queue {
	u16 local_queue_id;
	int type;
};

struct nbl_ch_prm_stop_abnormal_hw_queue {
	u16 vsi_id;
	u16 local_queue_id;
	int type;
};

struct nbl_chan_param_get_vf_func_id {
	u16 vsi_id;
	int vf_id;
};

struct nbl_chan_param_get_vf_vsi_id {
	u16 vsi_id;
	int vf_id;
};

struct nbl_ch_prm_cfg_rx_vlan_parse {
	u16 vsi_id;
	u16 rx_vlan_mode;
};

struct nbl_ch_prm_cfg_rss_hash {
	u16 vsi_id;
	u16 rss_hash_mode;
};

struct nbl_chan_param_register_func_mac {
	u16 func_id;
	u8 mac[ETH_ALEN];
};

struct nbl_chan_param_register_trust {
	u16 func_id;
	bool trusted;
};

struct nbl_chan_param_register_vlan {
	u16 func_id;
	u16 vlan_tci;
	u16 vlan_proto;
};

struct nbl_chan_param_set_tx_rate {
	u16 func_id;
	int tx_rate;
};

struct nbl_chan_param_set_txrx_rate {
	u16 func_id;
	int txrx_rate;
	int burst;
};

struct nbl_chan_param_register_func_link_forced {
	u16 func_id;
	u8 link_forced;
	bool should_notify;
};

struct nbl_chan_param_notify_link_state {
	u8 link_state;
	u32 link_speed;
};

struct nbl_chan_param_set_mtu {
	u16 vsi_id;
	u16 mtu;
};

struct nbl_chan_param_get_uvn_pkt_drop_stats {
	u16 vsi_id;
	u16 num_queues;
};

struct nbl_chan_param_get_total_drop {
	u8 eth_id;
	u8 rsv[3];
	enum nbl_stat_type op_type;
};

struct nbl_ch_prm_int_comm {
	int val;
};

struct nbl_ch_prm_u64_comm {
	u64 val;
};

struct nbl_ch_prm_u16_comm {
	u16 val;
};

struct nbl_ch_prm_bool_comm {
	bool val;
};

struct nbl_register_net_result {
	u16 tx_queue_num;
	u16 rx_queue_num;
	u16 queue_size;
	u16 rdma_enable;

	u64 hw_features;
	u64 features;

	u16 max_mtu;
	u16 queue_offset;

	u8 mac[ETH_ALEN];
	u16 vlan_proto;
	u16 vlan_tci;
	u32 rate;
	bool trusted;

	/* draco add */
	u64 vlan_features;
	u64 hw_enc_features;
};

#define NBL_CHAN_FDIR_FLOW_RULE_SIZE 1024
enum nbl_chan_fdir_flow_type {
	NBL_CHAN_FDIR_FLOW_FULL, /* for DPDK isolate flow */
	NBL_CHAN_FDIR_FLOW_ETHER,
	NBL_CHAN_FDIR_FLOW_IPv4,
	NBL_CHAN_FDIR_FLOW_IPv6,
	NBL_CHAN_FDIR_FLOW_TCP_IPv4,
	NBL_CHAN_FDIR_FLOW_TCP_IPv6,
	NBL_CHAN_FDIR_FLOW_UDP_IPv4,
	NBL_CHAN_FDIR_FLOW_UDP_IPv6,
	NBL_CHAN_FDIR_FLOW_MAX_TYPE,
};

enum nbl_chan_fdir_rule_type {
	NBL_CHAN_FDIR_RULE_NORMAL,
	NBL_CHAN_FDIR_RULE_ISOLATE,
	NBL_CHAN_FDIR_RULE_MAX,
};

enum nbl_chan_fdir_component_type {
	NBL_CHAN_FDIR_KEY_SRC_MAC,
	NBL_CHAN_FDIR_KEY_DST_MAC,
	NBL_CHAN_FDIR_KEY_PROTO,
	NBL_CHAN_FDIR_KEY_SRC_IPv4,
	NBL_CHAN_FDIR_KEY_DST_IPv4,
	NBL_CHAN_FDIR_KEY_L4PROTO,
	NBL_CHAN_FDIR_KEY_SRC_IPv6,
	NBL_CHAN_FDIR_KEY_DST_IPv6,
	NBL_CHAN_FDIR_KEY_SPORT,
	NBL_CHAN_FDIR_KEY_DPORT,
	NBL_CHAN_FDIR_KEY_UDF,
	NBL_CHAN_FDIR_ACTION_QUEUE,
	NBL_CHAN_FDIR_ACTION_VSI,
	NBL_CHAN_FDIR_KEY_SVLAN
};

enum {
	NBL_FD_STATE_OFF = 0,
	NBL_FD_STATE_ON,
	NBL_FD_STATE_FLUSH,
	NBL_FD_STATE_MAX,
};

struct nbl_chan_param_fdir_replace {
	enum nbl_chan_fdir_flow_type flow_type;
	enum nbl_chan_fdir_rule_type rule_type;
	u32 base_length;
	u32 vsi;
	u32 location;
	u16 vf;
	/* ring is local_queue_id */
	u16 ring;
	/* dport is vsi_id */
	u16 dport;
	u16 global_queue_id;
	bool order;
	u32 tlv_length;
	u8 tlv[];
};

#define NBL_CHAN_FDIR_FLOW_TLV_SIZE (1024 - sizeof(struct nbl_chan_param_fdir_replace))
#define NBL_CHAN_FDIR_TLV_HEADER_LEN 4

struct nbl_chan_param_fdir_del {
	enum nbl_chan_fdir_rule_type rule_type;
	u32 location;
	u16 vsi;
};

struct nbl_chan_param_fdir_flowcnt {
	enum nbl_chan_fdir_rule_type rule_type;
	u16 vsi;
};

struct nbl_chan_param_get_fd_flow {
	u32 location;
	enum nbl_chan_fdir_rule_type rule_type;
	u16 vsi_id;
};

#define NBL_CHAN_GET_FD_LOCS_MAX		512
struct nbl_chan_param_get_fd_flow_all {
	enum nbl_chan_fdir_rule_type rule_type;
	u16 start;
	u16 num;
	u16 vsi_id;
};

struct nbl_chan_result_get_fd_flow_all {
	u32 rule_locs[NBL_CHAN_GET_FD_LOCS_MAX];
};

struct nbl_chan_param_config_fd_flow_state {
	enum nbl_chan_fdir_rule_type rule_type;
	u16 vsi_id;
	u16 state;
};

struct nbl_chan_send_info {
	void *arg;
	size_t arg_len;
	void *resp;
	size_t resp_len;
	u16 dstid;
	u16 msg_type;
	u16 ack;
	u16 ack_len;
};

struct nbl_lag_mem_list_info {
	u16 vsi_id;
	u8 eth_id;
	bool active;
};

struct nbl_lag_member_list_param {
	u16 lag_num;
	u16 lag_id;
	/* member_list always contains all registered member */
	struct nbl_lag_mem_list_info member_list[NBL_LAG_MAX_PORTS];
	bool duppkt_enable;
};

struct nbl_queue_err_stats {
	u16 dvn_pkt_drop_cnt;
	u32 uvn_stat_pkt_drop;
};

struct nbl_ch_prm_get_firmware_version {
	char version[NBL_FRIMWARE_VERSION_LEN];
	u16 sfid;
};

struct nbl_eth_mac_stats {
	u64 frames_txd_ok;
	u64 frames_rxd_ok;
	u64 octets_txd_ok;
	u64 octets_rxd_ok;
	u64 multicast_frames_txd_ok;
	u64 broadcast_frames_txd_ok;
	u64 multicast_frames_rxd_ok;
	u64 broadcast_frames_rxd_ok;
	u32 frames_rxd_ok_is_valid;
	u32 octets_txd_ok_is_valid;
	u32 octets_rxd_ok_is_valid;
};

enum rmon_range {
	ETHER_STATS_PKTS_64_OCTETS,
	ETHER_STATS_PKTS_65_TO_127_OCTETS,
	ETHER_STATS_PKTS_128_TO_255_OCTETS,
	ETHER_STATS_PKTS_256_TO_511_OCTETS,
	ETHER_STATS_PKTS_512_TO_1023_OCTETS,
	ETHER_STATS_PKTS_1024_TO_1518_OCTETS,
	ETHER_STATS_PKTS_1024_TO_MAX_OCTETS = ETHER_STATS_PKTS_1024_TO_1518_OCTETS,
	ETHER_STATS_PKTS_1519_TO_2047_OCTETS,
	ETHER_STATS_PKTS_2048_TO_MAX_OCTETS,
	ETHER_STATS_PKTS_MAX,
};

struct nbl_rmon_stats {
	u64 undersize_frames_rxd_goodfcs;
	u64 oversize_frames_rxd_goodfcs;
	u64 undersize_frames_rxd_badfcs;
	u64 oversize_frames_rxd_badfcs;

	u64 rmon_rx_range[ETHER_STATS_PKTS_MAX];
	u64 rmon_tx_range[ETHER_STATS_PKTS_MAX];
	u32 rmon_rx_range2048_is_valid;
};

struct nbl_rdma_register_param {
	bool has_rdma;
	u32 mem_type;
	int intr_num;
	int id;
	u32 internal_cfg;
};

struct nbl_phy_caps {
	u32 speed; /* enum nbl_eth_speed */
	u32 fec_ability;
	u32 pause_param; /* bit0 tx, bit1 rx */
};

struct nbl_fc_info {
	u32 rx_pause;
	u32 tx_pause;
};

/* for pmd driver */
struct nbl_register_net_rep_result {
	u16 vsi_id;
	u16 func_id;
};

/* emp to ctrl dev notify */
struct nbl_port_notify {
	u32 id;
	u32 speed; /* in 10 Mbps units */
	u8 link_state:1; /* 0:down, 1:up */
	u8 module_inplace:1; /* 0: not inplace, 1:inplace */
	u8 revd0:6;
	u8 flow_ctrl; /* enum nbl_flow_ctrl */
	u8 fec; /* enum nbl_port_fec */
	u8 active_lanes;
	u8 rsvd1[4];
	u64 advertising; /* enum nbl_port_cap */
	u64 lp_advertising; /* enum nbl_port_cap */
};

#define NBL_EMP_LOG_MAX_SIZE (256)
struct nbl_emp_alert_log_event {
	u64 uptime;
	u8 level;
	u8 data[256];
};

#define NBL_EMP_ALERT_DATA_MAX_SIZE (4032)
struct nbl_chan_param_emp_alert_event {
	u16 type;
	u16 len;
	u8 data[NBL_EMP_ALERT_DATA_MAX_SIZE];
};

struct nbl_fec_stats {
	u32 corrected_blocks;
	u32 uncorrectable_blocks;
	u32 corrected_bits;
	u32 corrected_lane[4];
	u32 uncorrectable_lane[4];
	u32 corrected_bits_lane[4];
};

struct nbl_port_state {
	u64 port_caps;
	u64 port_advertising;
	u64 port_lp_advertising;
	u32 link_speed;
	u8 active_fc;
	u8 active_fec; /* enum nbl_port_fec */
	u8 link_state;
	u8 module_inplace;
	u8 port_type; /* enum nbl_port_type */
	u8 port_max_rate; /* enum nbl_port_max_rate */
	u8 fw_port_max_speed; /* enum nbl_fw_port_speed */
	u8 module_repluged;
};

struct nbl_eth_ctrl_stats {
	u64 macctrl_frames_txd_ok;
	u64 macctrl_frames_rxd;
	u64 unsupported_opcodes_rx;
};

struct nbl_pause_stats {
	u64 rx_pause_frames;
	u64 tx_pause_frames;
};

struct nbl_port_advertising {
	u8 eth_id;
	u64 speed_advert;
	u8 active_fc;
	u8 active_fec; /* enum nbl_port_fec */
	u8 autoneg;
	u8 resv;
	/* develop add for bootis, so need to add in new dw for request and response driver version
	 * no match
	 */
	u8 fec_sub_mode; /* enum nbl_port_mode */
};

struct nbl_eth_link_info {
	u8 link_status;
	u32 link_speed;
};

struct nbl_board_port_info {
	u8 eth_num;
	u8 eth_speed;
	u8 p4_version;
	u8 port_type;
	u8 rsv[4];
};

struct nbl_bond_port_info {
	u16 vsi_id;
	u8 eth_id;
	u8 is_active;
};

struct nbl_bond_info {
	struct nbl_bond_port_info port[NBL_LAG_MAX_PORTS];
	u8 lag_id;
	u8 mem_num;
};

struct nbl_bond_param {
	struct nbl_bond_info info[NBL_LAG_MAX_NUM];
	u8 lag_num;
};

/* to support channel req and response use different driver version,
 * to define the struct to same with struct ethtool_coalesce
 */
struct nbl_ch_prm_get_coalesce {
	u32   cmd;
	u32   rx_coalesce_usecs;
	u32   rx_max_coalesced_frames;
	u32   rx_coalesce_usecs_irq;
	u32   rx_max_coalesced_frames_irq;
	u32   tx_coalesce_usecs;
	u32   tx_max_coalesced_frames;
	u32   tx_coalesce_usecs_irq;
	u32   tx_max_coalesced_frames_irq;
	u32   stats_block_coalesce_usecs;
	u32   use_adaptive_rx_coalesce;
	u32   use_adaptive_tx_coalesce;
	u32   pkt_rate_low;
	u32   rx_coalesce_usecs_low;
	u32   rx_max_coalesced_frames_low;
	u32   tx_coalesce_usecs_low;
	u32   tx_max_coalesced_frames_low;
	u32   pkt_rate_high;
	u32   rx_coalesce_usecs_high;
	u32   rx_max_coalesced_frames_high;
	u32   tx_coalesce_usecs_high;
	u32   tx_max_coalesced_frames_high;
	u32   rate_sample_interval;
};

struct nbl_ch_prm_get_coalesce_req {
	u16 vector_id;
	u16 sfid;				/* srcid_map 回填 */
};

enum nbl_fw_reset_type {
	NBL_FW_HIGH_TEMP_RESET,
	NBL_FW_RESET_TYPE_MAX,
};

struct nbl_chan_param_notify_fw_reset_info {
	u16 type; /* enum nbl_fw_reset_type */
	u16 len;
	u16 data[];
};

struct nbl_ch_prm_configure_rdma_bw {
	u8 eth_id;
	int rdma_bw;
};

struct nbl_ch_prm_configure_qos {
	u8 eth_id;
	u8 trust;
	u8 pfc[NBL_MAX_PFC_PRIORITIES];
	u8 dscp2prio_map[NBL_DSCP_MAX];
};

struct nbl_ch_prm_set_pfc_buffer_size {
	u8 eth_id;
	u8 prio;
	int xoff;
	int xon;
};

struct nbl_ch_prm_get_pfc_buffer_size {
	u8 eth_id;
	u8 prio;
};

struct nbl_ch_prm_get_pfc_buffer_size_resp {
	int xoff;
	int xon;
};

struct nbl_chan_param_drop_stats_resp {
	u64 rx_drop_packets;
	u64 rx_trun_packets;
};

struct nbl_ch_prm_set_rate_limit {
	enum nbl_traffic_type type;
	u32 rate;
	u16 resv;
	u16 sfid;
};

struct nbl_ch_prm_pf_name {
	u16 vsi_id;
	char dev_name[IFNAMSIZ];
};

struct nbl_ch_prm_get_perf_dump_data {
	u8 *buffer;
	u32 size;
};

struct nbl_ch_prm_set_tc_wgt {
	u16 vsi_id;
	u8 num_tc;
	u8 weight[NBL_MAX_TC_NUM];
};

struct nbl_ch_prm_get_mirror_table_id {
	u16 vsi_id;
	int dir;
	bool mirror_en;
	u8 mt_id;
};

struct nbl_ch_prm_mirror {
	int dir;
	bool mirror_en;
	u8 mt_id;
	u16 resv;
	u16 sfid;
};

struct nbl_ch_prm_mirror_table {
	bool mirror_en;
	u8 mt_id;
	u16 func_id;
};

struct nbl_ch_prm_tx_mirror_to_rdma {
	u8 mt_id;
	bool enable;
};

struct nbl_chan_param_check_flow_spec {
	u16 vlan_list_cnt;
	u16 unicast_mac_cnt;
	u16 multi_mac_cnt;
};

struct nbl_chan_param_set_wol {
	u8 eth_id;
	bool enable;
};

struct nbl_chan_ack_info {
	void *data;
	int err;
	u32 data_len;
	u16 dstid;
	u16 msg_type;
	u16 msgid;
};

enum nbl_channel_type {
	NBL_CHAN_TYPE_MAILBOX,
	NBL_CHAN_TYPE_ADMINQ,
	NBL_CHAN_TYPE_MAX
};

#define NBL_LINE_RATE_INFO_LENGTH (3)
struct nbl_rep_line_rate_info {
	u16 vsi_id;
	u16 func_id;
	u32 data[NBL_LINE_RATE_INFO_LENGTH];
};

struct nbl_channel_ops {
	int (*send_msg)(void *priv, struct nbl_chan_send_info *chan_send);
	int (*send_ack)(void *priv, struct nbl_chan_ack_info *chan_ack);
	int (*register_msg)(void *priv, u16 msg_type, nbl_chan_resp func, void *callback_priv);
	void (*unregister_msg)(void *priv, u16 msg_type);
	int (*cfg_chan_qinfo_map_table)(void *priv, u8 chan_type,
					unsigned long *owned_pf_bitmap, u8 max_pf, u16 bdf);
	bool (*check_queue_exist)(void *priv, u8 chan_type);
	int (*setup_queue)(void *priv, u8 chan_type);
	int (*set_listener_info)(void *priv, void *shm_ring, struct eventfd_ctx *eventfd);
	int (*set_listener_msgtype)(void *priv, int msgtype);
	void (*clear_listener_info)(void *priv);
	int (*teardown_queue)(void *priv, u8 chan_type);
	void (*clean_queue_subtask)(void *priv, u8 chan_type);
	int (*dump_txq)(void *priv, struct seq_file *m, u8 type);
	int (*set_txq)(void *priv, u8 type, u32 value);
	int (*dump_rxq)(void *priv, struct seq_file *m, u8 type);
	u32 (*get_adminq_tx_buf_size)(void *priv);
	int (*init_cmdq)(struct device *dev, void *priv);
	int (*deinit_cmdq)(struct device *dev, void *priv, u8 inst_id);
	int (*send_cmd)(void *priv, const void *hdr, void *cmd);
	void (*register_chan_task)(void *priv, u8 chan_type, struct work_struct *task);
	void (*set_queue_state)(void *priv, enum nbl_chan_state state, u8 chan_type, u8 set);
};

struct nbl_channel_ops_tbl {
	struct nbl_channel_ops *ops;
	void *priv;
};

int nbl_chan_init_common(void *p, struct nbl_init_param *param);
void nbl_chan_remove_common(void *p);
int nbl_chan_init_draco(void *p, struct nbl_init_param *param);

enum nbl_cmdq_module {
	NBL_CMDQ_MODULE_FEM = 1,
	NBL_CMDQ_MODULE_ACL,
	NBL_CMDQ_MODULE_PED,
};

enum nbl_cmd_opcode_list {
	NBL_CMD_OP_WRITE,
	NBL_CMD_OP_READ,
	NBL_CMD_OP_SEARCH,
	NBL_CMD_OP_DELETE,
};

enum nbl_flow_opcode_list {
	NBL_OPCODE_QUERY,
	NBL_OPCODE_ADD,
	NBL_OPCODE_UPDATE,
	NBL_OPCODE_DELETE,
};

/* command header structure */
struct nbl_cmd_hdr {
	u8 block;
	u8 module;
	u8 table;
	u16 opcode;
	bool is_from_tcam_eviction_cb;
};

struct nbl_cmd_content {
	u32 in_length;
	u32 out_length;
	u64 in_params;
	u64 out_params;
	u16 entries;
	u32 idx;
	u64 in;
	u64 out;
	void *in_va;
	void *out_va;
	u32 wait;
};

#define NBL_CMDQ_MAX_OP_CODE	16
/* register block, module and table info */
enum nbl_flow_opcode {
	NBL_FEM_KTAT_WRITE,
	NBL_FEM_KTAT_READ,
	NBL_FEM_KTAT_SEARCH,
	NBL_FEM_HT_WRITE,
	NBL_FEM_HT_READ,
	NBL_ACL_TCAM_WRITE,
	NBL_ACL_TCAM_READ,
	NBL_ACL_TCAM_QUERY,
	NBL_ACL_FLOWID_READ,
	NBL_ACL_STATID_READ,
};

#define NBL_BLOCK_PPE 0
#define NBL_BLOCK_DP 1
#define NBL_BLOCK_IFC 2
#define NBL_MODULE_FEM 0
#define NBL_MODULE_ACL 1
#define NBL_TABLE_FEM_KTAT 0
#define NBL_TABLE_FEM_HT 1
#define NBL_TABLE_ACL_TCAM 0
#define NBL_TABLE_ACL_FLOWID 1
#define NBL_TABLE_ACL_STATID 2

#define NBL_CMDQ_DIF_MODE_VALUE			(2)
#define NBL_CMDQ_DELAY_200US			(200)
#define NBL_CMDQ_DELAY_300US			(300)
#define NBL_CMDQ_RESET_MAX_WAIT			(30)
#define NBL_CMD_NOTIFY_ADDR			(0x00001000)
#define NBL_CMDQ_FLIGHT_DELAY			500
#endif
