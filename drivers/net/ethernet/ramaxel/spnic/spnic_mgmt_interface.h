/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_MGMT_INTERFACE_H
#define SPNIC_MGMT_INTERFACE_H

#include <linux/if_ether.h>

#include "sphw_mgmt_msg_base.h"

#define SPNIC_CMD_OP_SET	MGMT_MSG_CMD_OP_SET
#define SPNIC_CMD_OP_GET	MGMT_MSG_CMD_OP_GET

#define SPNIC_CMD_OP_ADD	1
#define SPNIC_CMD_OP_DEL	0

enum nic_feature_cap {
	NIC_F_CSUM = BIT(0),
	NIC_F_SCTP_CRC = BIT(1),
	NIC_F_TSO = BIT(2),
	NIC_F_LRO = BIT(3),
	NIC_F_UFO = BIT(4),
	NIC_F_RSS = BIT(5),
	NIC_F_RX_VLAN_FILTER = BIT(6),
	NIC_F_RX_VLAN_STRIP = BIT(7),
	NIC_F_TX_VLAN_INSERT = BIT(8),
	NIC_F_VXLAN_OFFLOAD = BIT(9),
	NIC_F_IPSEC_OFFLOAD = BIT(10),
	NIC_F_FDIR = BIT(11),
	NIC_F_PROMISC = BIT(12),
	NIC_F_ALLMULTI = BIT(13),
};

#define NIC_F_ALL_MASK		0x3FFF

#define NIC_MAX_FEATURE_QWORD	4
struct spnic_cmd_feature_nego {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;	/* 1: set, 0: get */
	u8 rsvd;
	u64 s_feature[NIC_MAX_FEATURE_QWORD];
};

struct spnic_port_mac_set {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 vlan_id;
	u16 rsvd1;
	u8 mac[ETH_ALEN];
};

struct spnic_port_mac_update {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 vlan_id;
	u16 rsvd1;
	u8 old_mac[ETH_ALEN];
	u16 rsvd2;
	u8 new_mac[ETH_ALEN];
};

struct spnic_vport_state {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u8 state; /* 0--disable, 1--enable */
	u8 rsvd2[3];
};

struct spnic_port_state {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u8 state; /* 0--disable, 1--enable */
	u8 rsvd2[3];
};

struct spnic_cmd_clear_qp_resource {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
};

struct spnic_port_stats_info {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
};

struct spnic_vport_stats {
	u64 tx_unicast_pkts_vport;
	u64 tx_unicast_bytes_vport;
	u64 tx_multicast_pkts_vport;
	u64 tx_multicast_bytes_vport;
	u64 tx_broadcast_pkts_vport;
	u64 tx_broadcast_bytes_vport;

	u64 rx_unicast_pkts_vport;
	u64 rx_unicast_bytes_vport;
	u64 rx_multicast_pkts_vport;
	u64 rx_multicast_bytes_vport;
	u64 rx_broadcast_pkts_vport;
	u64 rx_broadcast_bytes_vport;

	u64 tx_discard_vport;
	u64 rx_discard_vport;
	u64 tx_err_vport;
	u64 rx_err_vport;
};

struct spnic_cmd_vport_stats {
	struct mgmt_msg_head msg_head;

	u32 stats_size;
	u32 rsvd1;
	struct spnic_vport_stats stats;
	u64 rsvd2[6];
};

struct spnic_cmd_qpn {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 base_qpn;
};

enum spnic_func_tbl_cfg_bitmap {
	FUNC_CFG_INIT,
	FUNC_CFG_RX_BUF_SIZE,
	FUNC_CFG_MTU,
};

struct spnic_func_tbl_cfg {
	u16 rx_wqe_buf_size;
	u16 mtu;
	u32 rsvd[9];
};

struct spnic_cmd_set_func_tbl {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd;

	u32 cfg_bitmap;
	struct spnic_func_tbl_cfg tbl_cfg;
};

struct spnic_cmd_cons_idx_attr {
	struct mgmt_msg_head msg_head;

	u16 func_idx;
	u8 dma_attr_off;
	u8 pending_limit;
	u8 coalescing_time;
	u8 intr_en;
	u16 intr_idx;
	u32 l2nic_sqn;
	u32 rsvd;
	u64 ci_addr;
};

struct spnic_cmd_vlan_offload {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 vlan_offload;
	u8 rsvd1[5];
};

struct spnic_cmd_lro_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u8 lro_ipv4_en;
	u8 lro_ipv6_en;
	u8 lro_max_pkt_len; /* unit is 1K */
	u8 resv2[13];
};

struct spnic_cmd_lro_timer {
	struct mgmt_msg_head msg_head;

	u8 opcode; /* 1: set timer value, 0: get timer value */
	u8 rsvd1;
	u16 rsvd2;
	u32 timer;
};

struct spnic_cmd_vf_vlan_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u16 vlan_id;
	u8 qos;
	u8 rsvd2[5];
};

struct spnic_cmd_spoofchk_set {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 state;
	u8 rsvd1;
};

struct spnic_cmd_tx_rate_cfg {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u32 min_rate;
	u32 max_rate;
	u8 rsvd2[8];
};

struct spnic_cmd_port_info {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 rsvd1[3];
	u8 port_type;
	u8 autoneg_cap;
	u8 autoneg_state;
	u8 duplex;
	u8 speed;
	u8 fec;
	u16 rsvd2;
	u32 rsvd3[4];
};

struct spnic_cmd_register_vf {
	struct mgmt_msg_head msg_head;

	u8 op_register; /* 0 - unregister, 1 - register */
	u8 rsvd[39];
};

struct spnic_cmd_link_state {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 state;
	u16 rsvd1;
};

struct spnic_cmd_vlan_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u16 vlan_id;
	u16 rsvd2;
};

/* set vlan filter */
struct spnic_cmd_set_vlan_filter {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 resvd[2];
	u32 vlan_filter_ctrl; /* bit0:vlan filter en; bit1:broadcast_filter_en */
};

struct spnic_cmd_link_ksettings_info {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 rsvd1[3];

	u32 valid_bitmap;
	u8 speed;          /* enum nic_speed_level */
	u8 autoneg;        /* 0 - off, 1 - on */
	u8 fec;            /* 0 - RSFEC, 1 - BASEFEC, 2 - NOFEC */
	u8 rsvd2[21];      /* reserved for duplex, port, etc. */
};

struct mpu_lt_info {
	u8 node;
	u8 inst;
	u8 entry_size;
	u8 rsvd;
	u32 lt_index;
	u32 offset;
	u32 len;
};

struct nic_mpu_lt_opera {
	struct mgmt_msg_head msg_head;
	struct mpu_lt_info net_lt_cmd;
	u8 data[100];
};

struct spnic_rx_mode_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u32 rx_mode;
};

/* rss */
struct spnic_rss_context_table {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u32 context;
};

struct spnic_cmd_rss_engine_type {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 hash_engine;
	u8 rsvd1[4];
};

#define SPNIC_RSS_INDIR_SIZE	256
#define SPNIC_RSS_KEY_SIZE	40

struct spnic_cmd_rss_hash_key {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u8 key[SPNIC_RSS_KEY_SIZE];
};

struct spnic_rss_indir_table {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u8 indir[SPNIC_RSS_INDIR_SIZE];
};

#define SPNIC_DCB_UP_MAX		0x8
#define SPNIC_DCB_COS_MAX		0x8
#define SPNIC_DCB_TC_MAX		0x8

struct spnic_cmd_rss_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 rss_en;
	u8 rq_priority_number;
	u8 prio_tc[SPNIC_DCB_COS_MAX];
	u16 num_qps;
	u16 rsvd1;
};

struct spnic_dcb_state {
	u8 dcb_on;
	u8 default_cos;
	u16 rsvd1;
	u8 up_cos[SPNIC_DCB_UP_MAX];
	u32 rsvd2[7];
};

struct spnic_cmd_vf_dcb_state {
	struct mgmt_msg_head msg_head;

	struct spnic_dcb_state state;
};

struct spnic_up_ets_cfg {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 rsvd1[3];

	u8 cos_tc[SPNIC_DCB_COS_MAX];
	u8 tc_bw[SPNIC_DCB_TC_MAX];
	u8 cos_prio[SPNIC_DCB_COS_MAX];
	u8 cos_bw[SPNIC_DCB_COS_MAX];
	u8 tc_prio[SPNIC_DCB_TC_MAX];
};

struct spnic_cmd_set_pfc {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 rsvd1;
	u8 pfc_en;
	u8 pfc_bitmap;
	u8 rsvd2[4];
};

struct spnic_cos_up_map {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	/* every bit indicate index of map is valid 1 or not 0*/
	u8 cos_valid_mask;
	u16 rsvd1;

	/* user priority in cos(index:cos, value: up pri) */
	u8 map[SPNIC_DCB_UP_MAX];
};

struct spnic_cmd_pause_config {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 opcode;
	u16 rsvd1;
	u8 auto_neg;
	u8 rx_pause;
	u8 tx_pause;
	u8 rsvd2[5];
};

struct nic_cmd_tx_pause_notice {
	struct mgmt_msg_head head;

	u32 tx_pause_except;
	u32 except_level;
	u32 rsvd;
};

#define SPNIC_CMD_OP_FREE 0
#define SPNIC_CMD_OP_ALLOC 1

struct spnic_cmd_cfg_qps {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode; /* 1: alloc qp, 0: free qp */
	u8 rsvd1;
	u16 num_qps;
	u16 rsvd2;
};

struct spnic_cmd_led_config {
	struct mgmt_msg_head msg_head;

	u8 port;
	u8 type;
	u8 mode;
	u8 rsvd1;
};

struct spnic_cmd_port_loopback {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 opcode;
	u8 mode;
	u8 en;
	u32 rsvd1[2];
};

struct spnic_cmd_get_light_module_abs {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 abs_status; /* 0:present, 1:absent */
	u8 rsv[2];
};

#define STD_SFP_INFO_MAX_SIZE 640
struct spnic_cmd_get_std_sfp_info {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 wire_type;
	u16 eeprom_len;
	u32 rsvd;
	u8 sfp_info[STD_SFP_INFO_MAX_SIZE];
};

struct spnic_cable_plug_event {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 plugged; /* 0: unplugged, 1: plugged */
	u8 port_id;
};

struct nic_cmd_mac_info {
	struct mgmt_msg_head head;

	u32 valid_bitmap;
	u16 rsvd;

	u8 host_id[32];
	u8 port_id[32];
	u8 mac_addr[192];
};

#define SPNIC_TCAM_BLOCK_ENABLE      1
#define SPNIC_TCAM_BLOCK_DISABLE     0
#define SPNIC_TCAM_BLOCK_NORMAL_TYPE 0
#define SPNIC_MAX_TCAM_RULES_NUM   4096

struct nic_cmd_set_tcam_enable {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 tcam_enable;
	u8 rsvd1;
	u32 rsvd2;
};

/* alloc tcam block input struct */
struct nic_cmd_ctrl_tcam_block_in {
	struct mgmt_msg_head head;

	u16 func_id;  /* func_id */
	u8 alloc_en;  /* 0: free tcam block, 1: alloc tcam block */
	u8 tcam_type; /* 0: alloc 16 size tcam block, 1: alloc 0 size tcam block */
	u16 tcam_block_index;
	u16 alloc_block_num;
};

/* alloc tcam block output struct */
struct nic_cmd_ctrl_tcam_block_out {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 alloc_en;
	u8 tcam_type;
	u16 tcam_block_index;
	u16 mpu_alloc_block_size;
};

struct nic_cmd_flush_tcam_rules {
	struct mgmt_msg_head head;

	u16 func_id; /* func_id */
	u16 rsvd;
};

struct nic_cmd_dfx_fdir_tcam_block_table {
	struct mgmt_msg_head head;
	u8 tcam_type;
	u8 valid;
	u16 tcam_block_index;
	u16 use_function_id;
	u16 rsvd;
};

struct tcam_result {
	u32 qid;
	u32 rsvd;
};

#define TCAM_FLOW_KEY_SIZE	44

struct tcam_key_x_y {
	u8 x[TCAM_FLOW_KEY_SIZE];
	u8 y[TCAM_FLOW_KEY_SIZE];
};

struct nic_tcam_cfg_rule {
	u32 index;
	struct tcam_result data;
	struct tcam_key_x_y key;
};

struct nic_cmd_fdir_add_rule {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd;
	struct nic_tcam_cfg_rule rule;
};

struct nic_cmd_fdir_del_rules {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd;
	u32 index_start;
	u32 index_num;
};

struct nic_cmd_fdir_get_rule {
	struct mgmt_msg_head head;

	u32 index;
	u32 valid;
	struct tcam_key_x_y key;
	struct tcam_result data;
	u64 packet_count;
	u64 byte_count;
};

#endif /* SPNIC_MGMT_INTERFACE_H */
