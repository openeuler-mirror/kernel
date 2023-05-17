/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_HW_H_
#define _NBL_HW_H_

#include <linux/types.h>
#include <linux/if_ether.h>

#define NBL_VENDOR_ID 0x1F0F

#define NBL_DEVICE_ID_X4_PF 0x1600
#define NBL_DEVICE_ID_X4_VF 0x1601

#define NBL_MAC_X4_MAGIC "ndx4lid"
#define NBL_MAC_MAGIC_LEN	7

#define NBL_X4_MEMORY_BAR (0)
#define NBL_X4_MAILBOX_BAR (2)
#define NBL_X4_MSIX_BAR (4)

#define NBL_ETH_PORT_NUM (4)

#define NBL_MAX_PF_FUNC (4)
#define NBL_MAX_VF_PER_PF (16)
#define NBL_MAX_FUNC 68
#define NBL_MAX_TXRX_QUEUE 128
#define NBL_MAX_INTERRUPT 512
#define NBL_MAX_MACVLAN_ENTRY 512

#define NBL_VF_BASE_FUNC_ID (NBL_MAX_PF_FUNC)

#define NBL_DEFAULT_VLAN_ID 0

#define NBL_PF_MAX_MACVLAN_ENTRIES 16
#define NBL_VF_MAX_MACVLAN_ENTRIES 7

#define NBL_VF_MACVLAN_START_INDEX (NBL_MAX_PF_FUNC * NBL_PF_MAX_MACVLAN_ENTRIES)

#define BYTES_PER_DWORD (4)
#define BITS_PER_DWORD (BYTES_PER_DWORD * 8)

#define NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN 16

#define NBL_PAUSE_CNT_REG_WIDTH 8

/* grep module related structures and values */
struct nbl_dynamic_version {
	u32 sub_version:8;
	u32 date:8;
	u32 month:8;
	u32 year:8;
};

#define NBL_GOLDEN_SUB_VERSION (0xEE)

#define NBL_DYNAMIC_INIT_DONE (0xFFFFFFFF)

/* pro module related structures and values */
struct nbl_pro_ctrl {
	u32 mac_mismatch_drop_en:4;
	u32 rsv:28;
};

enum nbl_txd_port_type {
	NBL_PORT_ETH,
	NBL_PORT_HOST,
};

enum nbl_ingress_eth_port_cos_map_mode {
	NBL_COS_MODE_DEFAULT_ETH_PRI,
	NBL_COS_MODE_EXTERNAL_VLAN,
	NBL_COS_MODE_RESERVE,
};

struct nbl_ingress_eth_port {
	u32 default_vlanid:12;
	u32 vlan_type:2;
	u32 vlan_check_en:1;
	u32 lag:1;
	u32 lag_id:2;
	u32 cos_map_mode:2;
	u32 default_pri:3;
	u32 veb_num:2;
	u32 rsv0:4;
	u32 default_vlan_en:1;
	u32 rsv1:2;
};

enum nbl_ingress_eth_port_fwd_type {
	NBL_INGRESS_FWD_DROP,
	NBL_INGRESS_FWD_NORMAL,
	NBL_INGRESS_FWD_CPU,
	NBL_INGRESS_FWD_RESERVE,
};

struct nbl_ingress_eth_port_fwd {
	u32 dport:1;
	u32 dport_id:7;
	u32 forward_queue_id:7;
	u32 forward_queue_id_en:1;
	u32 rsv:14;
	u32 fwd:2;
};

enum nbl_src_vsi_cos_mode_type {
	NBL_SRC_VSI_COS_MODE_DEFAULT_PORT_PRI,
	NBL_SRC_VSI_COS_MODE_VLAN,
	NBL_SRC_VSI_COS_MODE_QUEUE_PRI,
};

struct nbl_src_vsi_port {
	u32 default_vlanid:12;
	u32 vlan_type:2;
	u32 vlan_check_en:1;
	u32 cos_map_mode:3;
	u32 default_pri:3;
	u32 default_cfi:1;
	u32 lag:1;
	u32 dport_id:2;
	u32 mac_lut_en:1;
	u32 default_vlan_en:1;
	u32 vlan_push_en:1;
	u32 veb_num:2;
	u32 rsv0:2;
	u32 catch_vsi_idx:7;
	u32 vlanid_match_en:1;
	u32 vlanid_match_val:12;
	u32 forward_queue_id:7;
	u32 forward_queue_id_en:1;
	u32 rsv1:3;
	u32 smac_match_en:1;
	u8 smac[ETH_ALEN];
	u16 rsv2;
};

struct nbl_dest_vsi_port {
	u32 push_ovlan:16;
	u32 vlan_pop_cnt:2;
	u32 vlan_push_cnt:2;
	u32 rsv0:11;
	u32 vsi_en:1;
	u32 pkt_len:16;
	u32 pkt_len_chk_en:1;
	u32 pf_id:2;
	u32 rsv1:13;
};

#define RSS_ENTRIES_PER_VSI (16)

struct nbl_rss_entry {
	u32 rx_queue_id:7;
	u32 rsv:25;
};

/* ped module related structures and values */
struct nbl_ped_port_smac {
	u8 smac[ETH_ALEN];
	u16 rsv;
};

struct nbl_pause_cnt {
	u8 eth_pause_cnt[NBL_ETH_PORT_NUM];
};

/* pa module related structures and values */
enum nbl_pcmrt_slot {
	NBL_PCMRT_BROADCAST_SLOT,
	NBL_PCMRT_MULTICAST_SLOT,
	NBL_PCMRT_LACP_SLOT,
	NBL_PCMRT_LLDP_SLOT,
	NBL_PCMRT_MAX_SLOT = 32,
};

#define NBL_ETYPE_EXT_BIT_LEN (16)
#define NBL_ETYPE_EXT_MASK ((1U << NBL_ETYPE_EXT_BIT_LEN) - 1)
#define NBL_ETYPE_EXTS_PER_REG (2)

enum nbl_etype_ext_slot {
	NBL_ETYPE_EXT_LACP_SLOT,
	NBL_ETYPE_EXT_LLDP_SLOT,
	NBL_ETYPE_EXT_MAX_SLOT = 8,
};

enum nbl_pcmrt_action_type {
	NBL_PCMRT_ACTION_DROP,
	NBL_PCMRT_ACTION_NORMAL,
	NBL_PCMRT_ACTION_CAPTURE,
	NBL_PCMRT_ACTION_RESERVE,
};

#define NBL_PCMRT_ACTION_BIT_LEN (2)
#define NBL_PCMRT_ACTION_MASK ((u64)((1 << NBL_PCMRT_ACTION_BIT_LEN) - 1))

struct nbl_pcmrt_action {
	u64 action_bitmap;
};

enum nbl_pcmrt_key_dmac_type {
	NBL_PCMRT_DMAC_UNICAST,
	NBL_PCMRT_DMAC_MULTICAST,
	NBL_PCMRT_DMAC_BROADCAST,
	NBL_PCMRT_DMAC_THIRD_LAYER_MULTICAST,
	NBL_PCMRT_DMAC_SPECIAL_MAC,
	NBL_PCMRT_DMAC_RESERVE,
};

enum nbl_pcmrt_key_etype_type {
	NBL_PCMRT_ETYPE_IP,
	NBL_PCMRT_ETYPE_ARP,
	NBL_PCMRT_ETYPE_RARP,
	NBL_PCMRT_ETYPE_IPV6,
	NBL_PCMRT_ETYPE_EXT_BASE,
};

struct nbl_pcmrt_key {
	u32 dmac_type:4;
	u32 etype_type:4;
	u32 ip_protocol_type:4;
	u32 dport_type:4;
	u32 tcp_ctrl_bits_type:2;
	u32 up_down_type:1;
	u32 valid:1;
	u32 rsv:12;
};

struct nbl_pcmrt_mask {
	u32 dmac_mask:1;
	u32 etype_mask:1;
	u32 ip_protocol_mask:1;
	u32 dport_mask:1;
	u32 tcp_ctrl_bits_mask:1;
	u32 up_down_mask:1;
	u32 rsv:26;
};

/* memt module related structures and values */
enum nbl_macvlan_direction {
	NBL_MACVLAN_UP_DIRECTION,
	NBL_MACVLAN_DOWN_DIRECTION,
};

enum nbl_macvlan_dport_type {
	NBL_MACVLAN_DPORT_ETH,
	NBL_MACVLAN_DPORT_HOST,
};

enum nbl_macvlan_operation_type {
	NBL_MACVLAN_OP_LOOKUP,
	NBL_MACVLAN_OP_ADD,
	NBL_MACVLAN_OP_CHANGE,
	NBL_MACVLAN_OP_DELETE,
};

struct nbl_macvlan_key {
	u32 vlan_id:12;
	u32 mac5:8;
	u32 mac4:8;
	u32 mac3_l:4;
	u32 mac3_h:4;
	u32 mac2:8;
	u32 mac1:8;
	u32 mac0:8;
	u32 eth_port_id:2;
	u32 direction:1;
	u32 rsv:1;
};

struct nbl_macvlan_result {
	u32 dport:1;
	u32 dport_id:7;
	u32 lag_id:2;
	u32 lag_enable:1;
	u32 rsv0:21;
	u32 rsv1;
};

struct nbl_macvlan_table_index {
	u32 index:9;
	u32 rsv:23;
};

struct nbl_macvlan_control {
	u32 op_type:2;
	u32 rsv0:1;
	u32 start:1;
	u32 flush_enable:1;
	u32 rsv1:27;
};

struct nbl_macvlan_status {
	u32 up_mac_op_type:2;
	u32 up_mac_op_success:1;
	u32 up_mac_op_done:1;
	u32 dn_mac_op_type:2;
	u32 dn_mac_op_success:1;
	u32 dn_mac_op_done:1;
	u32 rsv:24;
};

/* dvn module related structures and values */
struct nbl_queue_reset {
	u32 queue_rst_id:7;
	u32 rsv:25;
};

struct tx_queue_info {
	u32 base_addr_l;
	u32 base_addr_h;
	u32 log2_size:4;
	u32 rsv0:12;
	u32 src_vsi_idx:7;
	u32 rsv1:1;
	u32 priority:3;
	u32 rsv2:1;
	u32 enable:1;
	u32 rsv3:3;
	u32 tail_ptr:16;
	u32 head_ptr:16;
};

struct nbl_tx_queue_stat {
	u32 pkt_get;
	u32 pkt_out;
	u32 pkt_drop;
	u32 sw_notify;
	u32 pkt_dsch;
	u32 hd_notify;
	u32 hd_notify_empty;
	u32 rsv;
};

/* uvn module related structures and values */
struct nbl_rx_queue_reset {
	u32 queue_rst_id:7;
	u32 rsv0:1;
	u32 valid:1;
	u32 rsv:23;
};

struct rx_queue_info {
	u32 base_addr_l;
	u32 base_addr_h;
	u32 log2_size:4;
	u32 buf_length_pow:4;
	u32 rsv0:8;
	u32 enable:1;
	u32 rsv1:15;
	u32 tail_ptr:16;
	u32 head_ptr:16;
};

/* eth module related structures and values */
#define NBL_SUB_ETH_LEN (0x00010000)

enum nbl_eth_speed_mode {
	NBL_ETH_SPEED_MODE_25G,
	NBL_ETH_SPEED_MODE_1G,
	NBL_ETH_SPEED_MODE_10G,
};

struct nbl_eth_reset_ctl_and_status {
	u32 rsv0:1;
	u32 rx_reset:1;
	u32 tx_reset:1;
	u32 gtwiz_reset_rx_datapath:1;
	u32 gtwiz_reset_tx_datapath:1;
	u32 rsv1:3;
	u32 eth_recovery_flash_mask:1;
	u32 rsv2:3;
	u32 gt_rxpcsreset:1;
	u32 gt_txpcsreset:1;
	u32 gt_rxbufreset:1;
	u32 gt_txpmareset:1;
	u32 gt_rxresetdone:1;
	u32 gr_txresetdone:1;
	u32 eth_statistics_vld:1;
	u32 rsv3:13;
};

struct nbl_loopback_mode {
	u32 loopback_ctrl:3;
	u32 rsv0:1;
	u32 speed_sel:2;
	u32 rsv1:2;
	u32 speed_stat:2;
	u32 rsv2:6;
	u32 txpolarity:1;
	u32 rxpolarity:1;
	u32 rsv3:14;
};

struct nbl_tx_ctrl {
	u32 tx_enable:1;
	u32 tx_fcs_ins_enable:1;
	u32 tx_ignore_fcs:1;
	u32 tx_custom_preamble_enable:1;
	u32 tx_send_lfi:1;
	u32 tx_send_rfi:1;
	u32 tx_send_idle:1;
	u32 rsv0:9;
	u32 tx_ipg_value:4;
	u32 rsv1:12;
};

struct nbl_rx_ctrl {
	u32 rx_enable:1;
	u32 rx_delete_fcs:1;
	u32 rx_ignore_fcs:1;
	u32 rx_custom_preamble_enable:1;
	u32 rx_check_sfd:1;
	u32 rx_check_preamble:1;
	u32 rx_process_lfi:1;
	u32 rx_force_resync:1;
	u32 rsv:24;
};

struct nbl_pkt_len_limit {
	u32 min_pkt_len:8;
	u32 rsv1:8;
	u32 max_pkt_len:15;
	u32 rsv2:1;
};

#define NBL_GE_PCS_PMA_LINK_STATUS_SHIFT (0)
struct nbl_eth_rx_stat {
	u32 rx_status:1;
	u32 rx_block_lock:1;
	u32 rx_high_ber:1;
	u32 rx_valid_ctrl_code:1;
	u32 rx_remote_fault:1;
	u32 rx_local_fault:1;
	u32 rx_internal_local_fault:1;
	u32 rx_received_local_fault:1;
	u32 power_good:1;
	u32 tx_unfout:1;
	u32 gpcs_reset_done:1;
	u32 switching:1;
	u32 init_done_eth:1;
	u32 rsv0:3;
	u32 ge_pcs_pma_status:16;
};

/* dsch module related structures and values */
struct nbl_port_map {
	u32 port_id:2;
	u32 rsv:30;
};

/* mailbox module related structures and values */
struct nbl_mailbox_qinfo_map {
	u32 function:3;
	u32 devid:5;
	u32 bus:8;
	u32 msix_idx:11;
	u32 valid:1;
	u32 rsv:4;
};

/* pcompleter module related structures and values */
struct nbl_queue_table_ready {
	u32 ready:1;
	u32 rsv:31;
};

enum nbl_qid_map_table_type {
	NBL_MASTER_QID_MAP_TABLE,
	NBL_SLAVE_QID_MAP_TABLE,
};

struct nbl_queue_table_select {
	u32 select:1;
	u32 rsv:31;
};

#define NBL_MSIX_MAP_TABLE_MAX_ENTRIES (64)

struct nbl_function_msix_map {
	u64 msix_map_base_addr;
	u32 function:3;
	u32 devid:5;
	u32 bus:8;
	u32 valid:1;
	u32 rsv0:15;
	u32 rsv1;
};

struct nbl_msix_map {
	u16 valid:1;
	u16 global_msix_index:9;
	u16 rsv:6;
};

#define NBL_QID_MAP_TABLE_ENTRIES (NBL_MAX_TXRX_QUEUE)

#define NBL_QID_MAP_NOTIFY_ADDR_SHIFT (5)
#define NBL_QID_MAP_NOTIFY_ADDR_LOW_PART_LEN (27)

struct nbl_qid_map {
	u32 local_qid:5;
	u32 notify_addr_l:27;
	u32 notify_addr_h:16;
	u32 global_qid:7;
	u32 rsv:9;
};

/* padpt module related structures and values */
struct nbl_msix_entry {
	u32 lower_address;
	u32 upper_address;
	u32 message_data;
	u32 vector_mask;
};

struct nbl_msix_info {
	u32 intrl_pnum:16;
	u32 intrl_rate:16;
	u32 function:3;
	u32 devid:5;
	u32 bus:8;
	u32 msix_mask_en:1;
	u32 rsv:14;
	u32 valid:1;
};

#define NBL_MSIX_INTR_CTRL_PNUM_SHIFT 0
#define NBL_MSIX_INTR_CTRL_PNUM_MASK (0xFFFF << 0)
#define NBL_MSIX_INTR_CTRL_RATE_SHIFT 16
#define NBL_MSIX_INTR_CTRL_RATE_MASK (0xFFFF << 16)
#define NBL_MSIX_INTR_CTRL_RATE_GRANUL 8

struct nbl_queue_map {
	u32 function:3;
	u32 devid:5;
	u32 bus:8;
	u32 msix_idx:11;
	u32 msix_idx_valid:1;
	u32 rsv:3;
	u32 valid:1;
};

/* lsp module related structures and values */
#define NBL_SFP_CONFIGURE_TAB_LEN (0x40)

#define NBL_SFP_READ_MAXLEN_ONE_TIME 4
#define NBL_SFP_RW_DONE_CHN0_MASK     0x1

enum NBL_MODULE_INPLACE_STATUS {
	NBL_MODULE_INPLACE = 0,
	NBL_MODULE_NOT_INPLACE = 1,
};

enum SFF_RW_MODE {
	SFF_I2C_WRITE = 0,
	SFF_I2C_READ,
};

struct nbl_iic_phy_regs {
	u32 request;
	u32 rdata;
	u32 done;
};

struct nbl_sfp_iic_data {
	u32 wdata : 8; /* iic write data */
	u32 target_addr : 8;
	u32 rw_mode : 1;
	u32 slave_addr : 7;
	u32 access_bytes : 4; /* the bytes to access for one times ,up to 4 */
	u32 iic_chn : 4; /* kernel driver use chn0 to access iic */
};

#define NBL_ETH_RMON_LEN (0x100)

/* slave address: 7 bit valid */
#define SFF_8472_A0			0x50
#define SFF_8472_A2			0x51

/* SFF moudle register addresses: 8 bit valid */
#define SFF_8472_IDENTIFIER		0x0
#define SFF_8472_10GB_CAPABILITY	0x3  /* check sff-8472 table 5-3 */
#define SFF_8472_1GB_CAPABILITY		0x6  /* check sff-8472 table 5-3 */
#define SFF_8472_CABLE_TECHNOLOGY	0x8  /* check sff-8472 table 5-3 */
#define SFF_8472_EXTENDED_CAPA		0x24  /* check sff-8024 table 4-4 */
#define SFF_8472_CABLE_SPEC_COMP	0x3C
#define SFF_8472_DIAGNOSTIC		0x5C  /* digital diagnostic monitoring, relates to A2 */
#define SFF_8472_COMPLIANCE		0x5E  /* the specification revision version */
#define SFF_8472_VENDOR_NAME		0x14
#define SFF_8472_VENDOR_NAME_LEN	16  /* 16 bytes, from offset 0x14 to offset 0x23 */
#define SFF_8472_VENDOR_PN		0x28
#define SFF_8472_VENDOR_PN_LEN		16
#define SFF_8472_VENDOR_OUI		0x25  /* name and oui cannot all be empty */
#define SFF_8472_VENDOR_OUI_LEN		3
#define SFF_8472_SIGNALING_RATE		0xC
#define SFF_8472_SIGNALING_RATE_MAX	0x42
#define SFF_8472_SIGNALING_RATE_MIN	0x43
/* optional status/control bits: soft rate select and tx disable */
#define SFF_8472_OSCB			0x6E
/* extended status/control bits */
#define SFF_8472_ESCB			0x76

/* SFF status code */
#define SFF_IDENTIFIER_SFP		0x3
#define SFF_PASSIVE_CABLE		0x4
#define SFF_ACTIVE_CABLE		0x8
#define SFF_8472_ADDRESSING_MODE	0x4
#define SFF_8472_UNSUPPORTED		0x00
#define SFF_8472_10G_SR_BIT		4  /* 850nm, short reach */
#define SFF_8472_10G_LR_BIT		5  /* 1310nm, long reach */
#define SFF_8472_10G_LRM_BIT		6  /* 1310nm, long reach multimode */
#define SFF_8472_10G_ER_BIT		7  /* 1550nm, extended reach */
#define SFF_8472_1G_SX_BIT		0
#define SFF_8472_1G_LX_BIT		1
#define SFF_8472_1G_CX_BIT		2
#define SFF_8472_1G_T_BIT		3
#define SFF_8472_SOFT_TX_DISABLE	6
#define SFF_8472_SOFT_RATE_SELECT	4
#define SFF_8472_EMPTY_ASCII		20
#define SFF_DDM_IMPLEMENTED		0x40
#define SFF_COPPER_UNSPECIFIED		0
#define SFF_COPPER_8431_APPENDIX_E	1
#define SFF_COPPER_8431_LIMITING	4

#define NBL_FORCE_LED_EN	BIT(8) /* set means control LED by software */
#define NBL_FORCE_ACT_LED_LEVEL	BIT(4) /* 1: led on; 0: led off */

/* grep module related macros */
#define NBL_GREG_MODULE (0x00000000)

#define NBL_GREG_DYNAMIC_PRJ_ID_REG (NBL_GREG_MODULE + 0x00000000)
#define NBL_GREG_DYNAMIC_VERSION_REG (NBL_GREG_MODULE + 0x00000004)
#define NBL_GREG_DYNAMIC_INIT_REG (NBL_GREG_MODULE + 0x00000010)
#define NBL_GREG_DYNAMIC_CLR_CNT_REG (NBL_GREG_MODULE + 0x0000001C)

/* pro module related macros */
#define NBL_PRO_MODULE (0x00020000)

#define NBL_PRO_CTRL_REG (NBL_PRO_MODULE + 0x00002000)
#define NBL_PRO_MAX_PKT_LEN_REG (NBL_PRO_MODULE + 0x0000200C)

#define NBL_PRO_INGRESS_ETH_PORT_FWD_REG_ARR(i) \
	(NBL_PRO_MODULE + 0x00003000 + (i) * sizeof(struct nbl_ingress_eth_port_fwd))
#define NBL_PRO_INGRESS_ETH_PORT_REG_ARR(i) \
	(NBL_PRO_MODULE + 0x00003010 + (i) * sizeof(struct nbl_ingress_eth_port))

#define NBL_PRO_SRC_VSI_PORT_REG_ARR(i) \
	(NBL_PRO_MODULE + 0x00004000 + (i) * sizeof(struct nbl_src_vsi_port))
#define NBL_PRO_DEST_VSI_PORT_REG_ARR(i) \
	(NBL_PRO_MODULE + 0x00005000 + (i) * sizeof(struct nbl_dest_vsi_port))

#define NBL_PRO_RSS_GROUP_REG_ARR(vsi, i) \
	(NBL_PRO_MODULE + 0x00006000 + \
	((vsi) * RSS_ENTRIES_PER_VSI + (i)) * sizeof(struct nbl_rss_entry))

/* qm module related macros */
#define NBL_QM_MODULE (0x00030000)

#define NBL_QM_PORT_TX_PAUSE_EN (NBL_QM_MODULE + 0x000000C0)

/* ped module related macros */
#define NBL_PED_MOUDULE (0x00050000)

#define NBL_PED_PAUSE_TX_CNT (NBL_PED_MOUDULE + 0x000000BC)
#define NBL_PED_PORT_SMAC_REG_H(eth_port_id) \
	(NBL_PED_MOUDULE + 0x000000E0 + (eth_port_id) * sizeof(struct nbl_ped_port_smac))
#define NBL_PED_PORT_SMAC_REG_L(eth_port_id) \
	(NBL_PED_MOUDULE + 0x000000E4 + (eth_port_id) * sizeof(struct nbl_ped_port_smac))
#define NBL_PED_ETH_PAUSE_TX_L_REG(eth_port_id) \
	(NBL_PED_MOUDULE + (eth_port_id) * NBL_PAUSE_CNT_REG_WIDTH + 0x00000140)
#define NBL_PED_ETH_PAUSE_TX_H_REG(eth_port_id) \
	(NBL_PED_MOUDULE + (eth_port_id) * NBL_PAUSE_CNT_REG_WIDTH + 0x00000144)

/* pa module related macros */
#define NBL_PA_MODULE (0x00060000)

#define NBL_PA_PAUSE_RX_CNT (NBL_PA_MODULE + 0x00000130)
#define NBL_PA_PAUSE_RX_EN (NBL_PA_MODULE + 0x00000524)

#define NBL_PA_ETYPE_EXT_REG_ARR(i) (NBL_PA_MODULE + 0x0000050C + (i) * 4)

#define NBL_PA_PCMRT_ACTION_REG (NBL_PA_MODULE + 0x0000052C)
#define NBL_PA_PCMRT_KEY_REG_ARR(i) \
	(NBL_PA_MODULE + 0x00001000 + (i) * sizeof(struct nbl_pcmrt_key))
#define NBL_PA_PCMRT_MASK_REG_ARR(i) \
	(NBL_PA_MODULE + 0x00002000 + (i) * sizeof(struct nbl_pcmrt_mask))
#define NBL_PA_ETH_PAUSE_RX_L_REG(eth_port_id) \
	(NBL_PA_MODULE + (eth_port_id) * NBL_PAUSE_CNT_REG_WIDTH + 0x00000200)
#define NBL_PA_ETH_PAUSE_RX_H_REG(eth_port_id) \
	(NBL_PA_MODULE + (eth_port_id) * NBL_PAUSE_CNT_REG_WIDTH + 0x00000204)

/* memt module related macros */
#define NBL_MEMT_MODULE (0x00080000)

#define NBL_MEMT_OPERATION_REG (NBL_MEMT_MODULE + 0x00003010)
#define NBL_MEMT_KEY_REG (NBL_MEMT_MODULE + 0x00003100)
#define NBL_MEMT_TABLE_INDEX_REG (NBL_MEMT_MODULE + 0x00003200)
#define NBL_MEMT_RESULT_REG (NBL_MEMT_MODULE + 0x00003300)
#define NBL_MEMT_STATUS_REG (NBL_MEMT_MODULE + 0x00003400)

/* urmux module related macros */
#define NBL_URMUX_MODULE (0x00090000)

#define NBL_URMUX_PRO_MAX_PKT_KEN_REG (NBL_URMUX_MODULE + 0x00000050)
#define NBL_URMUX_CFG_SYNC_REG (NBL_URMUX_MODULE + 0x00000060)
#define NBL_URMUX_ETHX_RX_BYTE_L_REG(eth) \
	(NBL_URMUX_MODULE + 0x00000100 + (eth) * NBL_ETH_RMON_LEN)
#define NBL_URMUX_ETHX_RX_BYTE_H_REG(eth) \
	(NBL_URMUX_MODULE + 0x00000104 + (eth) * NBL_ETH_RMON_LEN)
#define NBL_URMUX_ETHX_RX_PKT_REG(eth) \
	(NBL_URMUX_MODULE + 0x00000114 + (eth) * NBL_ETH_RMON_LEN)
#define NBL_URMUX_ETHX_RX_UNDERSIZE_REG(eth) \
	(NBL_URMUX_MODULE + 0x00000118 + (eth) * NBL_ETH_RMON_LEN)
#define NBL_URMUX_ETHX_RX_OVERSIZE_REG(eth) \
	(NBL_URMUX_MODULE + 0x00000150 + (eth) * NBL_ETH_RMON_LEN)
#define NBL_URMUX_ETHX_RX_CRC_ERR_REG(eth) \
	(NBL_URMUX_MODULE + 0x00000154 + (eth) * NBL_ETH_RMON_LEN)

/* dmux module related macros */
#define NBL_DMUX_MODULE (0x000A0000)

#define NBL_DMUX_ETHX_TX_BYTE_L_REG(eth) \
	(NBL_DMUX_MODULE + 0x00000100 + (eth) * NBL_ETH_RMON_LEN)
#define NBL_DMUX_ETHX_TX_BYTE_H_REG(eth) \
	(NBL_DMUX_MODULE + 0x00000104 + (eth) * NBL_ETH_RMON_LEN)
#define NBL_DMUX_ETHX_TX_PKT_REG(eth) \
	(NBL_DMUX_MODULE + 0x00000114 + (eth) * NBL_ETH_RMON_LEN)

/* dvn module related macros */
#define NBL_DVN_MODULE (0x000B0000)

#define NBL_DVN_QUEUE_RESET_REG (NBL_DVN_MODULE + 0x00000104)
#define NBL_DVN_QUEUE_INFO_ARR(i) \
	(NBL_DVN_MODULE + 0x00001000 + (i) * sizeof(struct tx_queue_info))
#define NBL_DVN_QUEUE_STAT_REG_ARR(i) \
	(NBL_DVN_MODULE + 0x00003000 + (i) * sizeof(struct nbl_tx_queue_stat))

/* uvn module related macros */
#define NBL_UVN_MODULE (0x000C0000)

#define NBL_UVN_QUEUE_RESET_REG (NBL_UVN_MODULE + 0x00000104)
#define NBL_UVN_QUEUE_INFO_ARR(i) \
	(NBL_UVN_MODULE + 0x00001000 + (i) * sizeof(struct rx_queue_info))
#define NBL_UVN_QUEUE_STATE_REG_ARR(i) \
	(NBL_UVN_MODULE + 0x00000110 + (i) * BYTES_PER_DWORD)
#define NBL_UVN_DROP_CNT_REG_ARR(i) \
	(NBL_UVN_MODULE + 0x00003000 + (i) * BYTES_PER_DWORD)

/* eth module related macros */
#define NBL_ETH_MODULE (0x000D0000)

#define NBL_ETH_RESET_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00000000)
#define NBL_ETH_LOOPBACK_MODE_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00000004)
#define NBL_ETH_RX_CTRL_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00000008)
#define NBL_ETH_PKT_LEN_LIMIT(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000000C)
#define NBL_ETH_RX_STAT_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00000010)
#define NBL_ETH_TX_CTRL_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00000014)
#define NBL_ETH_SELF_STIMU_REG2(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00000038)
#define NBL_ETH_LED_CTRL_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00000058)

/* rx stat reg */
#define NBL_ETH_RX_TOTAL_PKT_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001000)
#define NBL_ETH_RX_TOTAL_PKT_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001004)
#define NBL_ETH_RX_TOTAL_GOOD_PKT_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001008)
#define NBL_ETH_RX_TOTAL_GOOD_PKT_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000100C)
#define NBL_ETH_RX_TOTAL_BYTES_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001010)
#define NBL_ETH_RX_TOTAL_BYTES_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001014)
#define NBL_ETH_RX_TOTAL_GOOD_BYTES_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001018)
#define NBL_ETH_RX_TOTAL_GOOD_BYTES_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000101C)
#define NBL_ETH_RX_BAD_FCS_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001020)
#define NBL_ETH_RX_BAD_FCS_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001024)
#define NBL_ETH_RX_FRAMING_ERR_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001028)
#define NBL_ETH_RX_FRAMING_ERR_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000102C)
#define NBL_ETH_RX_BADCODE_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001030)
#define NBL_ETH_RX_BADCODE_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001034)
#define NBL_ETH_RX_OVERSIZE_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001050)
#define NBL_ETH_RX_OVERSIZE_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001054)
#define NBL_ETH_RX_UNDERSIZE_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00001058)
#define NBL_ETH_RX_UNDERSIZE_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000105C)
#define NBL_ETH_RX_UNICAST_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010D0)
#define NBL_ETH_RX_UNICAST_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010D4)
#define NBL_ETH_RX_MULTICAST_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010D8)
#define NBL_ETH_RX_MULTICAST_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010DC)
#define NBL_ETH_RX_BROADCAST_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010E0)
#define NBL_ETH_RX_BROADCAST_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010E4)
#define NBL_ETH_RX_VLAN_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010E8)
#define NBL_ETH_RX_VLAN_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000010EC)

/* tx stat reg */
#define NBL_ETH_TX_TOTAL_PKT_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002000)
#define NBL_ETH_TX_TOTAL_PKT_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002004)
#define NBL_ETH_TX_TOTAL_BYTES_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002008)
#define NBL_ETH_TX_TOTAL_BYTES_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000200C)
#define NBL_ETH_TX_TOTAL_GOOD_PKT_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002010)
#define NBL_ETH_TX_TOTAL_GOOD_PKT_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002014)
#define NBL_ETH_TX_TOTAL_GOOD_BYTES_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002018)
#define NBL_ETH_TX_TOTAL_GOOD_BYTES_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000201C)
#define NBL_ETH_TX_UNICAST_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002090)
#define NBL_ETH_TX_UNICAST_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002094)
#define NBL_ETH_TX_MULTICAST_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x00002098)
#define NBL_ETH_TX_MULTICAST_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x0000209C)
#define NBL_ETH_TX_BROADCAST_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020A0)
#define NBL_ETH_TX_BROADCAST_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020A4)
#define NBL_ETH_TX_VLAN_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020A8)
#define NBL_ETH_TX_VLAN_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020AC)
#define NBL_ETH_TX_BAD_FCS_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020B0)
#define NBL_ETH_TX_BAD_FCS_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020B4)
#define NBL_ETH_TX_FRAME_ERROR_CNT_L_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020B8)
#define NBL_ETH_TX_FRAME_ERROR_CNT_H_REG(eth_port_id) \
	(NBL_ETH_MODULE + (eth_port_id) * NBL_SUB_ETH_LEN + 0x000020BC)

/* dsch module related macros */
#define NBL_DSCH_MODULE (0x00110000)

#define NBL_DSCH_NOTIFY_BITMAP_ARR(i) \
	(NBL_DSCH_MODULE + 0x00003000 + (i) * BYTES_PER_DWORD)
#define NBL_DSCH_FLY_BITMAP_ARR(i) \
	(NBL_DSCH_MODULE + 0x00004000 + (i) * BYTES_PER_DWORD)
#define NBL_DSCH_PORT_MAP_REG_ARR(i) \
	(NBL_DSCH_MODULE + 0x00005000 + (i) * sizeof(struct nbl_port_map))

/* mailbox module related macros */
#define NBL_MAILBOX_MODULE (0x00120000)

#define NBL_MAILBOX_M_QINFO_MAP_REG_ARR(func_id) \
	(NBL_MAILBOX_MODULE + 0x00001000 + (func_id) * sizeof(struct nbl_mailbox_qinfo_map))

/* pcompleter module related macros */
#define NBL_PCOMPLETER_MODULE (0x00130000)

#define NBL_PCOMPLETER_AF_NOTIFY_REG (NBL_PCOMPLETER_MODULE + 0x00001000)
#define NBL_PCOMPLETER_QUEUE_TABLE_READY_REG \
	(NBL_PCOMPLETER_MODULE + 0x00000800)
#define NBL_PCOMPLETER_QUEUE_TABLE_SELECT_REG \
	(NBL_PCOMPLETER_MODULE + 0x00000804)
#define NBL_PCOMPLETER_FUNCTION_MSIX_MAP_REG_ARR(i) \
	(NBL_PCOMPLETER_MODULE + 0x00004000 + (i) * sizeof(struct nbl_function_msix_map))
#define NBL_PCOMPLETER_QID_MAP_REG_ARR(select, i) \
	(NBL_PCOMPLETER_MODULE + 0x00008000 + \
	 (select) * NBL_QID_MAP_TABLE_ENTRIES * sizeof(struct nbl_qid_map) + \
	 (i) * sizeof(struct nbl_qid_map))

/* padpt module related macros */
#define NBL_PADPT_MODULE (0x00150000)

#define NBL_FC_CPLH_UP_TH_REG_OFS 0x15c
#define NBL_FC_CPLH_UP_TH_REG_ADDR (NBL_PADPT_MODULE + NBL_FC_CPLH_UP_TH_REG_OFS)

enum nbl_fc_cplh_up_eth_value {
	NBL_FC_CPLH_UP_TH_B8 = 0x100b8,
	NBL_FC_CPLH_UP_TH_C0 = 0x100c0,
	NBL_FC_CPLH_UP_TH_D0 = 0x100d0,
};

#define NBL_PADPT_MSIX_TABLE_REG_ADDR(vector_id) \
	(NBL_PADPT_MODULE + 0x00004000 + (vector_id) * sizeof(struct nbl_msix_entry))
#define NBL_PADPT_MSIX_TABLE_MASK_FIELD_ARR(vector_id) \
	(NBL_PADPT_MODULE + 0x00004000 + 12 + (vector_id) * sizeof(struct nbl_msix_entry))
#define NBL_PADPT_MSIX_INFO_REG_ARR(vector_id) \
	(NBL_PADPT_MODULE + 0x00008000 + (vector_id) * sizeof(struct nbl_msix_info))
#define NBL_PADPT_QUEUE_MAP_REG_ARR(queue_id) \
	(NBL_PADPT_MODULE + 0x0000C000 + (queue_id) * sizeof(struct nbl_queue_map))

/* lsp module related macros */
#define NBL_LSP_MODULE (0x00160000)

#define NBL_LSP_SFP_I2C_REQUEST_REG(sfp_id)	\
	(NBL_LSP_MODULE + (sfp_id) * NBL_SFP_CONFIGURE_TAB_LEN + 0x140)
#define NBL_LSP_SFP_I2C_RDATA_CHN_REG(sfp_id, chn_id) \
	(NBL_LSP_MODULE + (sfp_id) * NBL_SFP_CONFIGURE_TAB_LEN + 0x144 + (chn_id) * 4)
#define NBL_LSP_SFP_I2C_DONE_REG(sfp_id) \
	(NBL_LSP_MODULE + (sfp_id) * NBL_SFP_CONFIGURE_TAB_LEN + 0x158)
#define NBL_LSP_SFP_MOD_REG(sfp_id) \
	(NBL_LSP_MODULE + (sfp_id) * NBL_SFP_CONFIGURE_TAB_LEN + 0x16c)  /* module inplace */
#define NBL_LSP_SFP_RXLOS_REG(sfp_id) \
	(NBL_LSP_MODULE + (sfp_id) * NBL_SFP_CONFIGURE_TAB_LEN + 0x170)

#define NBL_LSP_EEPROM_REQ_REG (NBL_LSP_MODULE + 0x00000250)
#define NBL_LSP_EEPROM_RW_REG (NBL_LSP_MODULE + 0x00000254)
#define NBL_LSP_EEPROM_SLAVE_ADDR_REG (NBL_LSP_MODULE + 0x00000258)
#define NBL_LSP_EEPROM_ADDR_REG (NBL_LSP_MODULE + 0x0000025C)
#define NBL_LSP_EEPROM_WDATA_REG (NBL_LSP_MODULE + 0x00000260)
#define NBL_LSP_EEPROM_RDATA_REG (NBL_LSP_MODULE + 0x00000264)
#define NBL_LSP_EEPROM_STATUS_REG (NBL_LSP_MODULE + 0x00000268)

/* prcfg module related macros */
#define NBL_PRCFG_MODULE (0x00180000)

#define NBL_PRCFG_TEMPERATURE_REG (NBL_PRCFG_MODULE + 0x00004400)
#define NBL_PRCFG_VCCINT_REG (NBL_PRCFG_MODULE + 0x00004404)
#define NBL_PRCFG_VCCAUX_REG (NBL_PRCFG_MODULE + 0x00004408)
#define NBL_PRCFG_VCCBRAM_REG (NBL_PRCFG_MODULE + 0x00004418)
#define NBL_PRCFG_VUSER0_REG (NBL_PRCFG_MODULE + 0x00004600)
#define NBL_PRCFG_VUSER1_REG (NBL_PRCFG_MODULE + 0x00004604)
#define NBL_PRCFG_VUSER2_REG (NBL_PRCFG_MODULE + 0x00004608)
#define NBL_PRCFG_VUSER3_REG (NBL_PRCFG_MODULE + 0x0000460C)

struct nbl_eeprom_status {
	u32 done:1;
	u32 rsv:31;
};

#define NBL_EEPROM_LENGTH (0x100)
enum nbl_eeprom_access_type {
	NBL_EEPROM_WRITE,
	NBL_EEPROM_READ,
};

enum nbl_board_version {
	NBL_X4_BOARD = 0x01,
};

union nbl_board_info {
	struct {
		u8 version;
		u8 magic[7];
		u8 pn[16];
		u8 sn[16];
		u8 mac1[8];  /* pf1 */
		u8 mac2[8];  /* pf2 */
		u8 mac3[8];  /* pf3 */
		u8 mac4[8];  /* pf4 */
		u8 mac5[8];  /* pf5 */
		u8 mac6[8];  /* pf6 */
		u8 mac7[8];  /* pf7 */
		u8 mac8[8];  /* pf8 */
	};
	struct {
		u8 data[252];
		u32 crc;
	};
};

/* mailbox BAR related macros and structures */
struct nbl_mailbox_qinfo {
	u16 qid;
	u16 tail_ptr;
	u32 rx_base_addr_l;
	u32 rx_base_addr_h;
	u32 rx_size_bwid;
	u32 rx_cmd;
	u32 rsv0;
	u32 tx_base_addr_l;
	u32 tx_base_addr_h;
	u32 tx_size_bwid;
	u32 tx_cmd;
	u32 rsv1;
	u32 rx_head_ptr;
	u32 tx_head_ptr;
	u32 rx_tail_ptr;
	u32 tx_tail_ptr;
	u32 rsv2;
} __packed;

#define NBL_MAILBOX_TX_RESET BIT(0)
#define NBL_MAILBOX_RX_RESET BIT(0)
#define NBL_MAILBOX_TX_ENABLE BIT(1)
#define NBL_MAILBOX_RX_ENABLE BIT(1)

#define NBL_MAILBOX_TX_DESC_AVAIL BIT(0)
#define NBL_MAILBOX_TX_DESC_USED BIT(1)
#define NBL_MAILBOX_RX_DESC_AVAIL BIT(3)
#define NBL_MAILBOX_RX_DESC_USED BIT(4)

#define NBL_MAILBOX_NOTIFY_ADDR (0x00000000)

#define NBL_MAILBOX_QINFO_CFG_REG (0x00000000)
#define NBL_MAILBOX_QINFO_CFG_RX_BASE_ADDR_L_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, rx_base_addr_l))
#define NBL_MAILBOX_QINFO_CFG_RX_BASE_ADDR_H_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, rx_base_addr_h))
#define NBL_MAILBOX_QINFO_CFG_RX_SIZE_BWID_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, rx_size_bwid))
#define NBL_MAILBOX_QINFO_CFG_RX_CMD_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, rx_cmd))
#define NBL_MAILBOX_QINFO_CFG_TX_BASE_ADDR_L_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, tx_base_addr_l))
#define NBL_MAILBOX_QINFO_CFG_TX_BASE_ADDR_H_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, tx_base_addr_h))
#define NBL_MAILBOX_QINFO_CFG_TX_SIZE_BWID_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, tx_size_bwid))
#define NBL_MAILBOX_QINFO_CFG_TX_CMD_FIELD \
	(NBL_MAILBOX_QINFO_CFG_REG + offsetof(struct nbl_mailbox_qinfo, tx_cmd))

/* msix BAR related macros and structures */
#define NBL_MSIX_VECTOR_TABLE_OFFSET (0x00000000)

#define NBL_MSIX_VECTOR_TABLE_MASK_FIELD_ARR(vector_id) \
	(NBL_MSIX_VECTOR_TABLE_OFFSET + (vector_id) * sizeof(struct nbl_msix_entry) + \
	 offsetof(struct nbl_msix_entry, vector_mask))

#endif
