/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_PHY_DRACO_H_
#define _NBL_PHY_DRACO_H_

#include "nbl_core.h"
#include "nbl_hw.h"
#include "nbl_phy.h"

#define NBL_DRACO_RSS_TMPT_MASK			(0x3fffffffffffffff)
#define NBL_DRACO_RSS_ALG_OFT			(62)
#define NBL_PF_NUM_DRACO			(4)
#define NBL_MAX_MSIX_NUM_DRACO			(2560)
#define NBL_MAX_QUEUEU_NUM_DRACO		(512)

/*  ----------  REG BASE ADDR  ----------  */
#define NBL_TOP_CTRL_BASE			(0x01300000)
/* PPE modules base addr */
#define NBL_PPE_FEM_BASE			(0x00400000)
#define NBL_PPE_PA_BASE				(0x00500000)
#define NBL_PPE_IPRO_BASE			(0x00510000)
#define NBL_PPE_PP_BASE				(0x00520000)
#define NBL_PPE_MCC_BASE			(0x00530000)
#define NBL_PPE_ACL_BASE			(0x00540000)
#define NBL_PPE_EPRO_BASE			(0x00e40000)
#define NBL_PPE_UMACSEC_BASE			(0x01400000)
#define NBL_PPE_DMACSEC_BASE			(0x01490000)
#define NBL_PPE_UPRBAC_BASE			(0x01410000)
#define NBL_PPE_DPRBAC_BASE			(0x01450000)
#define NBL_PPE_UTLS_BASE			(0x00200000)
#define NBL_PPE_DTLS_BASE			(0x00240000)
/* Interface modules base addr */
#define NBL_INTF_PCOMPLETER_BASE		(0x00f20000)
#define NBL_INTF_PTLP_BASE			(0x00f40000)
#define NBL_INTF_PADPT_BASE			(0x00f44000)
#define NBL_INTF_CMDQ_BASE			(0x00f64000)
#define NBL_INTF_MAILBOX_BASE			(0x00f68000)
#define NBL_INTF_VDPA_BASE			(0x00f78000)
#define NBL_INTF_PCIE_BASE			(0X01500000)
/* DP modules base addr */
#define NBL_DP_STORE_BASE			(0x00004000)
#define NBL_DP_BM_BASE				(0x00014000)
#define NBL_DP_PMEM_BASE			(0x00024000)
#define NBL_DP_QM_BASE				(0x00034000)
#define NBL_DP_PED_BASE				(0x00074000)
#define NBL_DP_DSCH_BASE			(0x00100000)
#define NBL_DP_DVN_BASE				(0x00280000)
#define NBL_DP_UVN_BASE				(0x00300000)
#define NBL_DP_SHAPING_BASE			(0x00380000)
#define NBL_DP_RMUX_BASE			(0x01700000)
#define NBL_DP_DMUX_BASE			(0x01710000)

#pragma pack(1)

/*  ----------  TOP  CTRL ----------  */
#define NBL_TOP_CTRL_LB_RST_REG			(NBL_TOP_CTRL_BASE + 0X0104)
#define NBL_TOP_CTRL_MDL_CLK_EN			(NBL_TOP_CTRL_BASE + 0X010c)
#define NBL_TOP_CTRL_MDL_BYPASS_MODE		(NBL_TOP_CTRL_BASE + 0X0110)
#define NBL_TOP_CTRL_INT_VECTOR_EN(pf_id)	(NBL_TOP_CTRL_BASE + 0X0410 + 4 * (pf_id))
#define NBL_TOP_CTRL_INT_VECTOR(pf_id)		(NBL_TOP_CTRL_BASE + 0X0420 + 4 * (pf_id))
#define NBL_TOP_CTRL_VERSION_INFO		(NBL_TOP_CTRL_BASE + 0X0900)
#define NBL_TOP_CTRL_VERSION_DATE		(NBL_TOP_CTRL_BASE + 0X0904)
#define NBL_TOP_CTRL_TVSENSOR0_VAU		(NBL_TOP_CTRL_BASE + 0X025C)
#define NBL_TOP_CTRL_TBL_ADDR_PF_OFT(addr_id, pf_id) \
	(NBL_TOP_CTRL_BASE + 0X0A20 + 32 * (addr_id) + 8 * (pf_id))
#define NBL_TOP_CTRL_TBL_ADDR0_PF_SIZE(addr_id, pf_id) \
	(NBL_TOP_CTRL_BASE + 0X0A24 + 32 * (addr_id) + 8 * (pf_id))
#define NBL_FW_HEARTBEAT_PONG(func_id)		(NBL_TOP_CTRL_BASE + 0x0494 + ((func_id) * 4))

#define NBL_DRACO_TEMP_MAX			(105)
#define NBL_DRACO_TEMP_CRIT			(115)

#define NBL_EPRO_ERRCODE_DROP_INDEX (15)
#define NBL_EPRO_ERRCODE_TBL0_ADDR  (0xe40300)
#define NBL_EPRO_ERRCODE_TBL0_DWLEN (1)
#define NBL_EPRO_ERRCODE_TBL0_REG(r) (NBL_EPRO_ERRCODE_TBL0_ADDR + \
		(NBL_EPRO_ERRCODE_TBL0_DWLEN * 4) * (r))

#define NBL_EPRO_ERRCODE_TBL1_ADDR  (0xe40340)
#define NBL_EPRO_ERRCODE_TBL1_DWLEN (1)
#define NBL_EPRO_ERRCODE_TBL1_REG(r) (NBL_EPRO_ERRCODE_TBL1_ADDR + \
		(NBL_EPRO_ERRCODE_TBL1_DWLEN * 4) * (r))

#define NBL_EPRO_ERRCODE_TBL2_ADDR  (0xe40380)
#define NBL_EPRO_ERRCODE_TBL2_DWLEN (1)
#define NBL_EPRO_ERRCODE_TBL2_REG(r) (NBL_EPRO_ERRCODE_TBL2_ADDR + \
		(NBL_EPRO_ERRCODE_TBL2_DWLEN * 4) * (r))

#define NBL_IPRO_ERRCODE_TBL_ADDR  (0x512000)
#define NBL_IPRO_ERRCODE_TBL_DWLEN (4)
#define NBL_IPRO_ERRCODE_TBL_REG(r) (NBL_IPRO_ERRCODE_TBL_ADDR + \
		(NBL_IPRO_ERRCODE_TBL_DWLEN * 4) * (r))

#define NBL_IPRO_ERRCODE_1_HDL_ADDR  (0x510284)  /* vlan error */
#define NBL_IPRO_ERRCODE_2_HDL_ADDR  (0x510288)  /* ip4hdr error */
#define NBL_IPRO_ERRCODE_3_HDL_ADDR  (0x51028c)  /* csum error */
#define NBL_IPRO_ERRCODE_4_HDL_ADDR  (0x510290)  /* ttl error */
#define NBL_IPRO_ERRCODE_5_HDL_ADDR  (0x510294)  /* esp intg */
#define NBL_IPRO_ERRCODE_6_HDL_ADDR  (0x510298)  /* mac spoof */
#define NBL_IPRO_ERRCODE_7_HDL_ADDR  (0x51029c)  /* decap fail */
#define NBL_IPRO_ERRCODE_9_HDL_ADDR  (0x5102a4)  /* ipro mtu error */
#define NBL_IPRO_ERRCODE_10_HDL_ADDR  (0x5102a8)  /* invalid sport error */
#define NBL_IPRO_ERRCODE_12_HDL_ADDR  (0x5102b0)  /* rdma sip error */
#define NBL_EPRO_ERRCODE_8_HDL_ADDR  (0xe402a0)  /* epro mtu err */
#define NBL_EPRO_ERRCODE_11_HDL_ADDR  (0xe402ac)  /* invalid dpoort err */
#define NBL_EPRO_ERRCODE_15_HDL_ADDR  (0xe402bc)  /* herr err */
#define NBL_IPRO_ERRCODE_DROP_INDEX (15)
#define NBL_IPRO_ERRCODE_SMAC_SPOOF_STAT (5)
#define NBL_IPRO_UDF_PROFILE_SMAC_SPOOF_STAT_ID (5)
#define NBL_SMAC_SPOOF_STAT_ID	(131071)

#define NBL_TNL_MAX_SPORT			(61000)
#define NBL_TNL_MIN_SPORT			(32768)

/* draco car */
#define NBL_LR_DRACO_VSI_CAR_CYCLE_NUM		450.0  // 1M bytes/s
#define NBL_LR_DRACO_VSI_CAR_CYCLE_CC_NUM	8.0
#define NBL_LR_DRACO_FLOW_CAR_CYCLE_NUM		2250.0 // 200k bytes/s
#define NBL_LR_DRACO_FLOW_CAR_CYCLE_CC_NUM	8.0
/* draco shaping */
#define NBL_LR_DRACO_NET_SHAPING_CYCLE_MAX	8.0    // 1M bytes/s
#define NBL_LR_DRACO_NET_SHAPING_DEPTH		450.0

#define NBL_LR_DRACO_GRP_SHAPING_CYCLE_MAX	8.0
#define NBL_LR_DRACO_GRP_SHAPING_DEPTH		450.0

#define NBL_LR_DRACO_DPORT_SHAPING_CYCLE_MAX	900.0
#define NBL_LR_DRACO_DPORT_SHAPING_DEPTH	4.0

#define NBL_DRACO_BASE_ETH_PORT_ID 278

#define NBL_DRACO_CMDQ_EN(qid) \
	(NBL_CMDQ_QINFO_TABLE_ADDR + (NBL_CMDQ_QINFO_TABLE_DWLEN * 4) * (qid) + 0x10)

struct nbl_chip_tempmap {
	int val;
	int deg;
};

struct nbl_top_ctrl_int_vector_en_table {
	u32 en:1;
	u32 rsv:31;
};

struct nbl_top_ctrl_tvsensor0 {
	u32 temp:10;
	u32 rsv:6;
	u32 max_temp:10;
	u32 rsv1:6;
};

struct nbl_top_ctrl_int_vector_table {
	u32 msix:16;
	u32 rsv:16;
};

union nbl_action_bits_base {
	struct {
		u8 VLAN_OP:4;
		u8 SET_UDF:3;
		u8 SET_DEST:1;
	} baseab;

	u8 data;
};

union nbl_action_datas {
	struct {
		u16 resreved0;
		u16 resreved1;
		u16 resreved2;
		union dport_action dport;
	};

	u64 data;

	u32 u32_arr[2];
};

struct nbl_draco_acl_dft_acts {
	union nbl_action_datas ad0;
	union nbl_action_bits_base ab0;
	union nbl_action_datas ad1;
	union nbl_action_bits_base ab1;
	u16 reserved;
};

union nbl_acl_tcam_config {
	struct {
		u32 tcam_id:8;
		u32 enable:8;
		u32 start_compare:8;
		u32 start_set:8;
	} info;
	u32 data;
};

union nbl_acl_act_config {
	struct {
		u32 act_id:8;
		u32 enable:8;
		u16 rsv;
	} info;
	u32 data;
};

/*  --------  PCIE  --------  */
#define NBL_PCIE_K_PF_PCICONF_255_224(pf_id)	(NBL_INTF_PCIE_BASE + 0x000004b8 + 36 * (pf_id))
#define NBL_PCIE_K_PF_SRIOV_287_256(pf_id)	(NBL_INTF_PCIE_BASE + 0x0000039c + 36 * (pf_id))

/*  -----------  MAILBOX ----------  */
#define NBL_NOTIFY_DELAY_MIN_TIME_FOR_REGS	200 /* 200us for palladium,3us for s2c */

/*  --------  MAILBOX BAR2 --------  */
#define NBL_MAILBOX_NOTIFY_ADDR			(0x00000000)
#define NBL_MBX_QINFO_CFG_RX_TABLE_ADDR		(0x10)
#define NBL_MBX_QINFO_CFG_TX_TABLE_ADDR		(0x20)
#define NBL_MBX_QINFO_CFG_DBG_TABLE_ADDR	(0x30)
/* Mailbox bar phy register offset begin */
#define NBL_FW_HEARTBEAT_PING			(0x84)
#define NBL_REG_DRV_STATUS			(0x88)
#define NBL_FW_BOARD_CONFIG			(0x200)
#define NBL_FW_BOARD_DW3_OFFSET			(NBL_FW_BOARD_CONFIG + 12)
#define NBL_FW_BOARD_DW6_OFFSET			(NBL_FW_BOARD_CONFIG + 24)

/* mailbox BAR qinfo_cfg_table */
struct nbl_mailbox_qinfo_cfg_table {
	u32 queue_base_addr_l;
	u32 queue_base_addr_h;
	u32 queue_size_bwind:4;
	u32 rsv1:28;
	u32 queue_rst:1;
	u32 queue_en:1;
	u32 dif_err:1;
	u32 rsv2:29;
};

/* mailbox BAR qinfo_cfg_dbg_table */
struct nbl_mailbox_qinfo_cfg_dbg_tbl {
	u16 rx_pkt_drop;
	u16 rx_pkt_get;
	u16 tx_pkt_drop;
	u16 tx_pkt_out;
	u16 rx_queue_hd_ptr;
	u16 tx_queue_hd_ptr;
	u16 rx_queue_tail_ptr;
	u16 tx_queue_tail_ptr;
};

union nbl_fw_board_cfg_dw3 {
	struct board_cfg_dw3 {
		u32 port_type:1;
		u32 port_num:7;
		u32 port_speed:2;
		u32 gpio_type:3;
		u32 p4_version:1; /* 0: low version; 1: high version */
		u32 rsv:18;
	} __packed info;
	u32 data;
};

union nbl_fw_board_cfg_dw6 {
	struct board_cfg_dw6 {
		u8 eth_lane_bitmap;
		u8 eth_bitmap;
		u16 rsv;
	} __packed info;
	u32 data;
};

/*  --------  MAILBOX BAR0 -----  */
/* mailbox bar0 qinfo_map_table */
#define NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id) \
	(NBL_INTF_MAILBOX_BASE + 0x00001000 + \
	(func_id) * sizeof(struct nbl_mailbox_qinfo_map_table))

/* MAILBOX qinfo_map_table */
struct nbl_mailbox_qinfo_map_table {
	u32 function:3;
	u32 devid:5;
	u32 bus:8;
	u32 msix_idx:13;
	u32 msix_idx_vaild:1;
	u32 rsv:2;
};

/*  --------  PCOMPLETER  --------  */
/* vf bar0 bdf_capture offset */
#define NBL_PCOMPLETER_BDF_CAPTURE_OFFSET	(0x1010)
#define NBL_PCOMPLETER_MSIX_NOTIRY_OFFSET	(0x1020)
#define NBL_PCOMPLETER_MSIX_FAST_RATE		(0x1024)
#define NBL_PCOMPLETER_MSIX_FAST_PNUM		(0x1028)

#define NBL_PCOMPLETER_MSIX_MAP_TABLE_ADDR(i) \
	(NBL_INTF_PCOMPLETER_BASE + 0x00004000 + (i) * sizeof(struct nbl_pcompleter_msix_map_table))
#define NBL_PCOMPLETER_MSIX_FID_TABLE_ADDR(i) \
	(NBL_INTF_PCOMPLETER_BASE + 0x00008000 + \
	(i) * sizeof(struct nbl_pcompleter_msix_fid_table))

#define NBL_PCOMPLETER_NET_QID_SIZE	sizeof(struct nbl_pcompleter_net_qid_table)
#define NBL_PCOMPLETER_NET_QID_TABLE_VF(local_id, func_id) \
	(NBL_INTF_PCOMPLETER_BASE + 0x0000b000 + \
	(4 * 384 + 4 * 32) * NBL_PCOMPLETER_NET_QID_SIZE + \
	((func_id) - 8) * 32 * NBL_PCOMPLETER_NET_QID_SIZE + \
	(local_id) * NBL_PCOMPLETER_NET_QID_SIZE)
#define NBL_PCOMPLETER_NET_QID_TABLE_PF0_PF3(local_id, func_id) \
	(NBL_INTF_PCOMPLETER_BASE + 0x0000b000 + \
	(func_id) * 384 * NBL_PCOMPLETER_NET_QID_SIZE + \
	(local_id) * NBL_PCOMPLETER_NET_QID_SIZE)
#define NBL_PCOMPLETER_NET_QID_TABLE_PF4_PF7(local_id, func_id) \
	(NBL_INTF_PCOMPLETER_BASE + 0x0000b000 + \
	4 * 384 * NBL_PCOMPLETER_NET_QID_SIZE + \
	((func_id) - 4) * 32 * NBL_PCOMPLETER_NET_QID_SIZE + \
	(local_id) * NBL_PCOMPLETER_NET_QID_SIZE)

/* vf bar0 bdf_capture */
struct nbl_pcompleter_bdf_capture {
	u32 bdf:16;
	u32 fid:12;
	u32 pf_num:4;
};

/* nbl_pcompleter_msix_map_table */
struct nbl_pcompleter_msix_map_table {
	u64 msix_map_base_addr;
	u32 function:3;
	u32 devid:5;
	u32 bus:8;
	u32 valid:1;
	u32 rsv0:15;
	u32 rsv1;
};

struct nbl_pcompleter_msix_fid_table {
	u32 fid:9;
	u32 vld:1;
	u32 rsv:22;
};

struct nbl_pcompleter_net_qid_table {
	u32 global_qid:9;
	u32 vld:1;
	u32 rsv:22;
};

struct nbl_msix_notify {
	u32 glb_msix_idx:12;
	u32 rsv1:4;
	u32 mask:1;
	u32 rsv2:15;
};

struct nbl_msix_fast_restrain {
	u32 glb_msix_idx:12;
	u32 rsv1:4;
	u32 data:16;
};

/*  --------  PADPT  --------  */
/* padpt vnet_qinfo */
#define NBL_PADPT_VNET_QINFO_TABLE_ADDR(queue_id) \
	(NBL_INTF_PADPT_BASE + 0x00004000 + (queue_id) * sizeof(struct nbl_padpt_vnet_qinfo))
/* padpt_msix_info */
#define NBL_PADPT_MSIX_INFO_TABLE_ADDR(vector_id) \
	(NBL_INTF_PADPT_BASE + 0x00008000 + (vector_id) * sizeof(struct nbl_padpt_msix_info))
#define NBL_PADPT_ROD_CH0_TAG_MAX_REQ		(NBL_INTF_PADPT_BASE + 0x00000780)
#define NBL_PADPT_ROD_CH1_TAG_MAX_REQ		(NBL_INTF_PADPT_BASE + 0x00000790)
#define NBL_PADPT_ROD_IS_AGED_TAG_VLD		(NBL_INTF_PADPT_BASE + 0x00000824)
#define NBL_PADPT_ROD_CH0_AGED_VLD		(NBL_INTF_PADPT_BASE + 0x00000840)
#define NBL_PADPT_ROD_CH1_AGED_VLD		(NBL_INTF_PADPT_BASE + 0x00000844)
#define NBL_PADPT_ROD_CH0_TAG_MAX_TIMES		(NBL_INTF_PADPT_BASE + 0x00000850)
#define NBL_PADPT_ROD_CH0_TAG_AVR_TIMES		(NBL_INTF_PADPT_BASE + 0x00000854)
#define NBL_PADPT_ROD_CH0_TAG_MIN_TIMES		(NBL_INTF_PADPT_BASE + 0x00000858)
#define NBL_PADPT_ROD_CH1_TAG_MAX_TIMES		(NBL_INTF_PADPT_BASE + 0x0000085C)
#define NBL_PADPT_ROD_CH1_TAG_AVR_TIMES		(NBL_INTF_PADPT_BASE + 0x00000860)
#define NBL_PADPT_ROD_CH1_TAG_MIN_TIMES		(NBL_INTF_PADPT_BASE + 0x00000864)
#define NBL_PADPT_ROD_CH2_TAG_MAX_TIMES		(NBL_INTF_PADPT_BASE + 0x00000868)
#define NBL_PADPT_ROD_CH2_TAG_AVR_TIMES		(NBL_INTF_PADPT_BASE + 0x0000086C)
#define NBL_PADPT_ROD_CH2_TAG_MIN_TIMES		(NBL_INTF_PADPT_BASE + 0x00000870)

struct nbl_padpt_rod_ch_tag_max_req {
	u32 req0;
	u32 req1;
	u32 req2;
	u32 req3;
};

/* padpt vnet_qinfo */
struct nbl_padpt_vnet_qinfo {
	u32 function_id:3;
	u32 device_id:5;
	u32 bus_id:8;
	u32 msix_idx:12;
	u32 rsv0:1;
	u32 msix_idx_valid:1;
	u32 log_en:1;
	u32 valid:1;
	u32 tph_en:1;
	u32 ido_en:1;
	u32 rlo_en:1;
	u32 rsv1:29;
};

struct nbl_padpt_msix_info {
	u32 intrl_pnum:16;
	u32 intrl_rate:16;
	u32 function:3;
	u32 devid:5;
	u32 bus:8;
	u32 valid:1;
	u32 self_mask_en:1;
	u32 pba_relimit_en:1;
	u32 rsv:13;
};

/*  ----------  VDPA  ----------  */
#define NBL_VDPA_LOG_INFO_TABLE_RAM(i) \
	(NBL_INTF_VDPA_BASE + 0x00001000 + (i) * sizeof(struct log_info_table_ram))
#define NBL_VDPA_LOG_INFO_TABLE_CAM(i) \
	(NBL_INTF_VDPA_BASE + 0x00002000 + (i) * sizeof(struct log_info_table_cam))
#define NBL_VDPA_LOG_INFO_DIS_TABLE_CAM(i) \
	(NBL_INTF_VDPA_BASE + 0x00002800 + (i) * sizeof(struct log_info_dis_table_cam))
#define NBL_VDPA_FIFO_NAFULL (NBL_INTF_VDPA_BASE + 0x00000028)

struct log_info_table_ram {
	u64 log_info_addr;
	u64 log_info_size;
};

struct log_info_table_cam {
	u32 log_info_bdf:16;
	u32 log_info_vld:1;
	u32 rsv:15;
};

struct log_info_dis_table_cam {
	u32 log_info_disable:1;
	u32 rsv:31;
};

/*  ----------  DVN  ----------  */
/* DVN dvn_queue_table */
#define NBL_DVN_QUEUE_TABLE_ARR(i) \
	(NBL_DP_DVN_BASE + 0x00010000 + (i) * sizeof(struct dvn_queue_table))
#define NBL_DVN_QUEUE_CXT_TABLE_ARR(i) \
	(NBL_DP_DVN_BASE + 0x00014000 + (i) * sizeof(struct dvn_queue_context))
#define NBL_DVN_STAT_CNT(i) (NBL_DP_DVN_BASE + 0x00020000 + (i) * sizeof(struct nbl_dvn_stat_cnt))
#define NBL_DVN_LSO_CONTEXT_TABLE_ARR(i) \
	(NBL_DP_DVN_BASE + 0x00018000 + (i) * sizeof(struct nbl_dvn_seg_context))
#define NBL_DVN_VDPA_IDX_TABLE_ARR(i) \
	(NBL_DP_DVN_BASE + 0x00050000 + (i) * sizeof(struct nbl_dvn_vdpa_idx))
/* DVN dvn_queue_reset */
#define NBL_DVN_QUEUE_RESET_REG (NBL_DP_DVN_BASE + 0x00022000)
#define NBL_DVN_DESCREQ_NUM_CFG			(NBL_DP_DVN_BASE + 0x00000418)
#define NBL_DVN_DIF_REQ_RO_FLAG_CFG		(NBL_DP_DVN_BASE + 0x00000438)
#define NBL_DVN_WR_MERGE_TIMEOUT_CFG		(NBL_DP_DVN_BASE + 0x00000448)
#define NBL_DVN_MERGE_DESC_NUM_CFG		(NBL_DP_DVN_BASE + 0x00000464)
#define NBL_DVN_SELF_QUEUE_PTR_CFG		(NBL_DP_DVN_BASE + 0x00000474)
#define NBL_DVN_INT_STATUS			(NBL_DP_DVN_BASE + 0x00000000)
#define NBL_DVN_DESC_DIF_ERR_CNT		(NBL_DP_DVN_BASE + 0x00000034)
#define NBL_DVN_DESC_DIF_ERR_INFO		(NBL_DP_DVN_BASE + 0x00000030)

/* 0、1、2、3、4、5、6 represent 8、12、16、20、24、28、32 */
#define DEFAULT_DVN_DESCREQ_NUM			(6)

/* DVN dvn_queue_table */
struct dvn_queue_table {
	u64 queue_used_baddr;
	u64 queue_avail_baddr;
	u64 queue_desc_baddr;
	u32 desc_ring_size:4;
	u32 queue_type:1;
	u32 queue_en:1;
	u32 extend_header_en:1;
	u32 interleave_seg_disable:1;
	u32 seg_disable:1;
	u32 vsi_id:9;
	u32 rsv0:14;
	u32 rsv1;
};

/* DVN dvn_queue_context */
struct dvn_queue_context {
	u32 dvn_descrd_num:3;
	u32 dvn_firstdescid:16;
	u32 dvn_firstdescflag:16;
	u32 dvn_avail_ring_idx:16;
	u32 dvn_used_ring_idx:16;
	u32 dvn_lastdesc_id:16;
	u32 dvn_rcb_back_flag:1;
	u32 dvn_avail_read_ptr:16;
	u32 dvn_queue_err_type:5;
	u32 dvn_queue_err:1;
	u32 dvn_ring_read_ptr:16;
	u32 dvn_ring_wrap_counter:1;
	u32 dvn_seg_flag:1;
	u32 dvn_descrd_disable:1;
	u32 dvn_drop:1;
	u32 dvn_protected_bit:1;
	u32 rsv0:1;
};

struct nbl_dvn_stat_cnt {
	u32 dvn_desc_fwd_cnt:16;
	u32 rsv0:16;
	u32 dvn_desc_drop_cnt:16;
	u32 rsv1:16;
	u32 dvn_pkt_fwd_cnt:16;
	u32 rsv2:16;
	u32 dvn_whole_req_pkt_cnt:16;
	u32 rsv3:16;
	u32 rsv4[4];
};

struct nbl_dvn_seg_context {
	u32 dvn_maclen:5;
	u32 dvn_iplen:5;
	u32 dvn_l4len:4;
	u32 dvn_l4type:2;
	u32 dvn_iiptype:2;
	u32 dvn_eiptype:2;
	u32 dvn_eiplen:5;
	u32 dvn_l4tunlen:7;
	u32 dvn_l4tuntype:2;
	u32 dvn_l4s_sid:15;
	u32 dvn_l4s_sync_ind:1;
	u32 dvn_l4s_redun_ind:1;
	u32 dvn_l4s_redun_head_ind:1;
	u32 dvn_l4s_handle_ind:1;
	u32 dvn_l4s_pbrac_mode:1;
	u32 dvn_acl_tag:8;
	u32 dvn_dport_info:9;
	u32 dvn_dport_id:9;
	u32 dvn_dport:2;
	u32 dvn_fwd:2;
	u32 dvn_rss_lag_en:1;
	u32 dvn_cs_en:2;
	u32 dvn_t_cs_en:2;
	u32 dvn_macsec_sc_idx:3;
	u32 dvn_macsec_sc_vld:1;
	u32 dvn_header_len:8;
	u32 dvn_tcp_sn:22;
	u32 dvn_ip_id:16;
	u32 dvn_eip_id:16;
	u32 dvn_mss:14;
	u32 dvn_last_desc_flag:1;
	u32 dvn_desc_buflen_left:19;
	u32 dvn_desc_payaddr_leftl:25;
	u32 dvn_desc_payaddr_leftm;
	u32 dvn_desc_payaddr_lefth:7;
	u32 dvn_uso_seg_flag:1;
	u32 dvn_rsv0:24;
	u32 dvn_rsv1[7];
};

struct nbl_dvn_vdpa_idx {
	u32 next_idx_offset:16;
	u32 last_idx_offset:16;
	u32 idx_vld_flag:1;
	u32 reserve:31;
};

/* DVN dvn_queue_reset */
struct nbl_dvn_queue_reset {
	u32 dvn_queue_index:9;
	u32 rsv:23;
};

struct nbl_dvn_descreq_num_cfg {
	u32 descreq_num:3; /* 0、1、2、3、4、5、6 represent 8、12、16、20、24、28、32 */
	u32 rsv:29;
};

struct nbl_dvn_dif_req_rd_ro_flag_cfg {
	u32 rd_desc_ro_en:1;
	u32 rd_data_ro_en:1;
	u32 wr_desc_ro_en:1;
	u32 rsv:29;
};

struct nbl_dvn_desc_wr_merge_timeout_cfg {
	u32 cfg_cycle:10;
	u32 rsv:22;
};

struct nbl_dvn_merge_desc_num_cfg {
	u32 split_num:8;
	u32 packed_num:8;
	u32 rsv:16;
};

/*  ----------  UVN  ----------  */
/* UVN uvn_queue_table */
#define NBL_UVN_QUEUE_TABLE_ARR(i) \
	(NBL_DP_UVN_BASE + 0x00010000 + (i) * sizeof(struct uvn_queue_table))
/* UVN uvn_queue_cxt */
#define NBL_UVN_QUEUE_CXT_TABLE_ARR(i) \
	(NBL_DP_UVN_BASE + 0x00014000 + (i) * sizeof(struct uvn_queue_cxt))
/* UVN uvn_desc_cxt */
#define NBL_UVN_DESC_CXT_TABLE_ARR(i) \
	(NBL_DP_UVN_BASE + 0x00016000 + (i) * sizeof(struct uvn_desc_cxt))
/* UVN uvn descwb_uidx */
#define NBL_UVN_DESCWB_UIDX(i) \
	(NBL_DP_UVN_BASE + 0x0001e000 + (i) * sizeof(struct uvn_descwb_uidx))
/* UVN uvn_queue_reset */
#define NBL_UVN_QUEUE_RESET_REG		(NBL_DP_UVN_BASE + 0x0001d000)
#define NBL_UVN_STATIS_PKT_DROP(i)	(NBL_DP_UVN_BASE + 0x0001c000 + (i) * sizeof(u32))
#define NBL_UVN_DVN_PKT_RDLY_TIME		(NBL_DP_UVN_BASE + 0x00001158)
#define NBL_UVN_DVN_PKT_RDLY_MAX_TIME		(NBL_DP_UVN_BASE + 0x00001160)
#define NBL_UVN_DVN_PKT_RDLY_MIN_TIME		(NBL_DP_UVN_BASE + 0x00001164)
#define NBL_UVN_DVN_DESC_RDLY_TIME		(NBL_DP_UVN_BASE + 0x00001168)
#define NBL_UVN_DVN_DESC_RDLY_MAX_TIME		(NBL_DP_UVN_BASE + 0x00001170)
#define NBL_UVN_DVN_DESC_RDLY_MIN_TIME		(NBL_DP_UVN_BASE + 0x00001174)
#define NBL_UVN_UVN_DESC_RDLY_TIME		(NBL_DP_UVN_BASE + 0x00001178)
#define NBL_UVN_UVN_DESC_RDLY_MAX_TIME		(NBL_DP_UVN_BASE + 0x00001180)
#define NBL_UVN_UVN_DESC_RDLY_MIN_TIME		(NBL_DP_UVN_BASE + 0x00001184)
#define NBL_UVN_DESC_PRE_SUB_DIF_ACK		(NBL_DP_UVN_BASE + 0x000012A8)
#define NBL_UVN_DESC_PRE_SUB_DIF_REOB		(NBL_DP_UVN_BASE + 0x000012AC)
#define NBL_UVN_DESC_PRE_SUB_DIF_RERR		(NBL_DP_UVN_BASE + 0x000012B0)
#define NBL_UVN_DESC_RD_ENTRY			(NBL_DP_UVN_BASE + 0x000012D0)
#define NBL_UVN_DESC_RD_DROP_QUEUE_DISABLE	(NBL_DP_UVN_BASE + 0x000012D4)
#define NBL_UVN_DESC_WR_TIMEOUT			(NBL_DP_UVN_BASE + 0x00000214)
#define NBL_UVN_DESC_WR_PACKED_TH		(NBL_DP_UVN_BASE + 0x0000021C)
#define NBL_UVN_DESC_RD_TH			(NBL_DP_UVN_BASE + 0x00000208)
#define NBL_UVN_DESC_PREFETCH_INIT		(NBL_DP_UVN_BASE + 0x00000204)
#define NBL_UVN_DESC_RD_WAIT			(NBL_DP_UVN_BASE + 0x0000020C)
#define NBL_UVN_DIF_REQ_RO_FLAG			(NBL_DP_UVN_BASE + 0x00000250)

/* UVN performance dump registers */
#define NBL_UVN_DIF_DLY_ACC_NUM			(NBL_DP_UVN_BASE + 0x00000254)
#define NBL_UVN_DIFDLY0				(NBL_DP_UVN_BASE + 0x00001158)
#define NBL_UVN_DIFDLY1				(NBL_DP_UVN_BASE + 0x00001160)
#define NBL_UVN_DIFDLY2				(NBL_DP_UVN_BASE + 0x00001164)
#define NBL_UVN_DIFDLY3				(NBL_DP_UVN_BASE + 0x00001168)
#define NBL_UVN_DIFDLY4				(NBL_DP_UVN_BASE + 0x00001170)
#define NBL_UVN_DIFDLY5				(NBL_DP_UVN_BASE + 0x00001174)
#define NBL_UVN_DIFDLY6				(NBL_DP_UVN_BASE + 0x00001178)
#define NBL_UVN_DIFDLY7				(NBL_DP_UVN_BASE + 0x00001180)
#define NBL_UVN_DIFDLY8				(NBL_DP_UVN_BASE + 0x00001184)
#define NBL_UVN_DESC_PRE_DESC_REQ_NULL		(NBL_DP_UVN_BASE + 0x000012C8)
#define NBL_UVN_DESC_PRE_DESC_REQ_LACK		(NBL_DP_UVN_BASE + 0x000012CC)
#define NBL_UVN_DESC_RD_DROP_DESC_LACK		(NBL_DP_UVN_BASE + 0x000012E0)

/* UVN uvn_queue_table */
struct uvn_queue_table {
	u64 used_baddr;
	u64 avail_baddr;
	u64 queue_baddr;
	u32 queue_size_mask_pow:4;
	u32 queue_type:1;
	u32 queue_enable:1;
	u32 extend_header_en:1;
	u32 guest_csum_en:1;
	u32 half_offload_en:1;
	u32 gvsp_offload_en:1;
	u32 rsv0:22;
	u32 rsv1:32;
};

/* uvn uvn_queue_cxt */
struct uvn_queue_cxt {
	u32 queue_head:16;
	u32 wrap_count:1;
	u32 queue_err:1;
	u32 prefetch_null_cnt:2;
	u32 ntf_finish:1;
	u32 spnd_flag:1;
	u32 packed_next_flag:1;  /* [22] Default:0x0 RW */
	u32 packed_next_flag_valid:1; /* [23] Default:0x0 RW */
	u32 reserve0:8;
	u32 avail_idx:16;
	u32 avail_idx_spnd_flag:1;
	u32 reserve1:15;
	u32 reserve2[2];
};

/* uvn uvn_queue_reset */
struct nbl_uvn_queue_reset {
	u32 index:9;
	u32 rsv0:23;
};

/* uvn uvn_desc_cxt */
struct uvn_desc_cxt {
	u32 cache_head:9;
	u32 reserve0:7;
	u32 cache_tail:9;
	u32 reserve1:7;
	u32 cache_pref_num_prev:9;
	u32 reserve2:7;
	u32 cache_pref_num_post:9;
	u32 reserve3:7;
	u32 cache_head_byte:30;
	u32 reserve4:2;
	u32 cache_tail_byte:30;
	u32 reserve5:2;
};

struct uvn_descwb_uidx {
	u32 pkt_fst_descwb_used_idx:16;
	u32 nxt_pkt_descwb_used_idx:16;
	u32 used_idx_valid:1;
	u32 rsv:31;
};

struct uvn_desc_wr_timeout {
	u32 num:15;
	u32 mask:1;
	u32 rsv:16;
};

struct uvn_desc_wr_packed_th {
	u32 num:8;
	u32 rsv:24;
};

struct uvn_desc_rd_th {
	u32 num:8;
	u32 rsv:24;
};

struct uvn_desc_prefetch_init {
	u32 num:8;
	u32 rsv1:8;
	u32 sel:1;
	u32 rsv:15;
};

struct uvn_dif_req_ro_flag {
	u32 avail_rd:1;
	u32 desc_rd:1;
	u32 pkt_wr:1;
	u32 desc_wr:1;
	u32 rsv:28;
};

/*  ----------  DSCH  ----------  */
#define NBL_DRAIN_WAIT_TIMES			(10000)

#define	NBL_DSCH_INT_STATUS			(NBL_DP_DSCH_BASE + 0x00000000)
/* DSCH dsch_vn_q2tc_cfg_tbl */
#define NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00010000 + (i) * sizeof(struct dsch_vn_q2tc_cfg_tbl))
/* DSCH dsch_vn_n2g_cfg_tbl */
#define NBL_DSCH_VN_N2G_CFG_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00060000 + (i) * sizeof(struct dsch_vn_n2g_cfg_tbl))
/* DSCH dsch_vn_g2p_cfg_tbl */
#define NBL_DSCH_VN_G2P_CFG_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00064000 + (i) * sizeof(struct dsch_vn_g2p_cfg_tbl))
/* DSCH dsch_vn_tc_wgt_cfg_tbl */
#define NBL_DSCH_VN_TC_WGT_CFG_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00068000 + (i) * sizeof(union dsch_vn_tc_wgt_cfg_tbl_u))
/* DSCH dsch_vn_tc_q_list_tbl */
#define NBL_DSCH_VN_TC_Q_LIST_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00040000 + (i) * sizeof(struct dsch_vn_tc_q_list_tbl))
/* DSCH dsch_vn_sha2net_map_tbl */
#define NBL_DSCH_VN_SHA2NET_MAP_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00070000 + (i) * sizeof(struct dsch_vn_sha2net_map_tbl))
/* DSCH dsch_vn_net2sha_map_tbl */
#define NBL_DSCH_VN_NET2SHA_MAP_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00074000 + (i) * sizeof(struct dsch_vn_net2sha_map_tbl))
#define NBL_DSCH_VN_TC_Q_LIST_ATTR_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x00020000 + (i) * sizeof(struct dsch_vn_tc_q_list_attr_tbl))
#define NBL_DSCH_VN_DPT_GRP_LIST_ATTR_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x000A8000 + (i) * sizeof(struct dsch_vn_dpt_grp_list_attr_tbl))
#define NBL_DSCH_VN_DPT_GRP_LIST_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x000Ac000 + (i) * sizeof(struct dsch_vn_dpt_grp_list_tbl))
#define NBL_DSCH_VN_GRP_NET_LIST_ATTR_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x000B0000 + (i) * sizeof(struct dsch_vn_grp_net_list_attr_tbl))
#define NBL_DSCH_VN_GRP_NET_LIST_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x000B4000 + (i) * sizeof(struct dsch_vn_grp_net_list_tbl))
#define NBL_DSCH_VN_PFC_NET_LIST_ATTR_TABLE_ADDR(i) \
	(NBL_DP_DSCH_BASE + 0x000B8000 + (i) * sizeof(struct dsch_vn_pfc_net_list_attr_tbl))
#define NBL_DSCH_VN_QUANTA				(NBL_DP_DSCH_BASE + 0x00000134)
#define	NBL_DSCH_DSTORE_DSCH_LINK_FC			(NBL_DP_DSCH_BASE + 0x00000810)
#define	NBL_DSCH_DSTORE_DSCH_PFC			(NBL_DP_DSCH_BASE + 0x00000814)
#define	NBL_DSCH_DQM_DSCH_LINK_FC			(NBL_DP_DSCH_BASE + 0x00000818)
#define	NBL_DSCH_DQM_DSCH_PFC				(NBL_DP_DSCH_BASE + 0x0000081C)
#define	NBL_DSCH_DSTORE_DSCH_BG_FC			(NBL_DP_DSCH_BASE + 0x00000820)
#define	NBL_DSCH_DSTORE_DSCH_PHY_FC			(NBL_DP_DSCH_BASE + 0x00000824)
#define	NBL_DSCH_VN_VNQM_DB_UPD_TCIVLD			(NBL_DP_DSCH_BASE + 0x00000960)
#define	NBL_DSCH_VN_SCH_DB_UPD_NGIVLD			(NBL_DP_DSCH_BASE + 0x00000964)
#define	NBL_DSCH_VN_SHA_DSCH_NET_RESP_JVLD		(NBL_DP_DSCH_BASE + 0x00000968)

#define	NBL_DSCH_VN_SW_H_DB_VLD				(NBL_DP_DSCH_BASE + 0x00000900)
#define	NBL_DSCH_VN_ENQ					(NBL_DP_DSCH_BASE + 0x00000910)
#define	NBL_DSCH_VN_H_ENQ				(NBL_DP_DSCH_BASE + 0x00000914)
#define	NBL_DSCH_VN_DEQ					(NBL_DP_DSCH_BASE + 0x00000920)
#define	NBL_DSCH_VN_H_DEQ				(NBL_DP_DSCH_BASE + 0x00000924)
#define	NBL_DSCH_VN_H_DEQ_IVLD				(NBL_DP_DSCH_BASE + 0x00000930)
#define	NBL_DSCH_VN_HDB_H				(NBL_DP_DSCH_BASE + 0x00000938)

#define NBL_HOST_QUANTA_FOR_GEN4		(0x4000)

/*  ----------  SHAPING  ----------  */
#define NBL_SHAPING_NET(i) \
	(NBL_DP_SHAPING_BASE + 0x00001000 + (i) * sizeof(struct nbl_shaping_net))
#define NBL_SHAPING_DPORT(i) \
	(NBL_DP_SHAPING_BASE + 0x00000700 + (i) * sizeof(struct nbl_shaping_dport))
#define NBL_SHAPING_DVN_DPORT(i) \
	(NBL_DP_SHAPING_BASE + 0x00000750 + (i) * sizeof(struct nbl_shaping_dvn_dport))
#define NBL_SHAPING_RDMA_DPORT(i) \
	(NBL_DP_SHAPING_BASE + 0x000007A0 + (i) * sizeof(struct nbl_shaping_rdma_dport))

struct nbl_shaping_net_timming_add {
	u32 cycle_max:12;        /* [11:0]  Default:0x9 RW */
	u32 rsv1:4;              /* [15:12] Default:0x0 RO */
	u32 depth:12;            /* [27:16] Default:0x190 RW */
	u32 rsv:4;               /* [31:28] Default:0x0 RO */
};

/* SHAPING shaping_net */
struct nbl_shaping_net {
	u32 valid:1;
	u32 depth:19;
	u32 cir:19;
	u32 pir:19;
	u32 cbs:21;
	u32 pbs:21;
	u32 rsv:28;
};

struct nbl_shaping_dport {
	u32 valid:1;
	u32 depth:19;
	u32 cir:19;
	u32 pir:19;
	u32 cbs:21;
	u32 pbs:21;
	u32 rsv:28;
};

struct nbl_shaping_dvn_dport {
	u32 valid:1;
	u32 depth:19;
	u32 cir:19;
	u32 pir:19;
	u32 cbs:21;
	u32 pbs:21;
	u32 rsv:28;
};

struct nbl_shaping_rdma_dport {
	u32 valid:1;
	u32 depth:19;
	u32 cir:19;
	u32 pir:19;
	u32 cbs:21;
	u32 pbs:21;
	u32 rsv:28;
};

/* cir 1, bandwidth 1Mb/s */
/* cir 1, bandwidth 1kB/s in prototype environment */
#define NBL_DRACO_SYS_CLK			450000000.0
#define NBL_DRACO_SYS_CLK_CURRENT		184400.0   /* emu unit hz */
#define NBL_DRACO_NET_BUCKET_DEPTH		16000

#define NBL_SHAPING_DPORT_10G_RATE		0x2710
#define NBL_SHAPING_DPORT_HALF_10G_RATE		0x1388
#define NBL_SHAPING_DPORT_25G_RATE		0x61A8
#define NBL_SHAPING_DPORT_HALF_25G_RATE		0x30D4

#define NBL_UCAR_MAX_BUCKET_DEPTH		524287
#define NBL_NET_SHAPING_RDMA_BASE_ID		276
/*  ----------  PA  ----------  */
#define NBL_PA_UDF_FILTER_TPID(i) \
	(NBL_PPE_PA_BASE + 0x00000200 + (i) * sizeof(struct nbl_pa_udf_filter_tpid))
#define NBL_PA_UDF_FILTER_TPID_EN		(NBL_PPE_PA_BASE + 0x0000020C)
#define NBL_PA_ERR_REPORT			(NBL_PPE_PA_BASE + 0x00000280)

struct nbl_pa_udf_filter_tpid {
	u32 type0:16;
	u32 type1:16;
};

struct nbl_pa_udf_filter_tpid_en {
	u32 en:6;
	u32 rsv:26;
};

struct nbl_pa_err_report {
	u32 en:14;
	u32 rsv:18;
};

/*  ----------  STORE  ----------  */
#define NBL_STORE_PKT_LEN_ETH			(NBL_DP_STORE_BASE + 0x00000108)
#define NBL_STORE_ETH_PORT_FC(i) \
	(NBL_DP_STORE_BASE + 0x00000158 + (i) * sizeof(struct nbl_store_eth_port_fc))
#define NBL_STORE_ETH_COS_FC(i) \
	(NBL_DP_STORE_BASE + 0x00000200 + (i) * sizeof(struct nbl_store_eth_cos_fc))
#define NBL_STORE_UP_FC_MODE			(NBL_DP_STORE_BASE + 0x0000075c)
#define NBL_STORE_PRI_CONF(i) \
	(NBL_DP_STORE_BASE + 0x00000790 + (i) * sizeof(struct nbl_store_pri_conf))
#define NBL_STORE_TBL_PRI_CONF(i) \
	(NBL_DP_STORE_BASE + 0x00003E00 + (i) * sizeof(struct nbl_store_tbl_pri_conf))
#define NBL_STORE_D_DPORT_FC(i) \
	(NBL_DP_STORE_BASE + 0x0000073C + (i) * sizeof(struct nbl_store_d_dport_fc))
#define NBL_USTORE_BUF_PORT_DROP_PKT(eth_id) \
	(NBL_DP_STORE_BASE + 0x00002500 + (eth_id) * sizeof(u32))
#define NBL_USTORE_BUF_PORT_TRUN_PKT(eth_id) \
	(NBL_DP_STORE_BASE + 0x00002540 + (eth_id) * sizeof(u32))
#define NBL_STORE_RCV_COS_PKT(i) \
	(NBL_DP_STORE_BASE + 0x00003080 + (i) * sizeof(struct nbl_store_rcv_cos_pkt))
#define NBL_STORE_RCV_COS_BYTE(i) \
	(NBL_DP_STORE_BASE + 0x00003140 + (i) * sizeof(struct nbl_store_rcv_cos_byte))
#define NBL_STORE_RCV_COS_DROP_PKT(i) \
	(NBL_DP_STORE_BASE + 0x00003300 + (i) * sizeof(struct nbl_store_rcv_drop_pkt))
#define NBL_STORE_RCV_COS_TRUN_PKT(i) \
	(NBL_DP_STORE_BASE + 0x00003400 + (i) * sizeof(struct nbl_store_rcv_trun_pkt))

/* STORE performance dump registers */
#define NBL_STORE_BUF_TOTAL_DROP_PKT		(NBL_DP_STORE_BASE + 0x00001048)
#define NBL_STORE_BUF_TOTAL_TRUN_PKT		(NBL_DP_STORE_BASE + 0x0000104C)

struct nbl_store_pkt_len_eth {
	u32 min:8;
	u32 rsv1:7;
	u32 min_chk_en:1;
	u32 max:14;
	u32 rsv:1;
	u32 max_chk_en:1;
};

struct nbl_store_eth_port_fc {
	u32 xoff_th:12;
	u32 rsv:4;
	u32 xon_th:12;
	u32 rsv1:2;
	u32 fc_set:1;
	u32 fc_en:1;
};

#define NBL_MAX_STORE_COS_FC_TH (4017)

struct nbl_store_eth_cos_fc {
	u32 xoff_th:12;
	u32 rsv:4;
	u32 xon_th:12;
	u32 rsv1:2;
	u32 fc_set:1;
	u32 fc_en:1;
};

struct nbl_store_up_fc_mode {
	u32 link:1;
	u32 pfc:1;
	u32 rsv:30;
};

struct nbl_store_pri_conf {
	u32 sel:1;
#define STORE_PRI_CONF_RX_PRI_MODE_DSCP		(0)
#define STORE_PRI_CONF_RX_PRI_MODE_8021P	(1)
	u32 cpu_set:3;
	u32 en:1;
	u32 rsv:27;
};

struct nbl_store_tbl_pri_conf {
	u32 pri0:4;
	u32 pri1:4;
	u32 pri2:4;
	u32 pri3:4;
	u32 pri4:4;
	u32 pri5:4;
	u32 pri6:4;
	u32 pri7:4;
};

struct nbl_store_d_dport_fc {
	u32 xoff_th:13;
	u32 rsv1:3;
	u32 xon_th:13;
	u32 rsv:1;
	u32 fc_set:1;
	u32 fc_en:1;
};

struct nbl_store_rcv_cos_pkt {
	u32 cnt;
};

struct nbl_store_rcv_cos_byte {
	u64 cnt;
};

struct nbl_store_rcv_drop_pkt {
	u32 cnt;
};

struct nbl_store_rcv_trun_pkt {
	u32 cnt;
};

/*  ----------  QM  ----------  */
#define NBL_QM_RXMAC_PORT_BP_EN			(NBL_DP_QM_BASE + 0x00000144)
#define NBL_QM_RXMAC_COS_BP_EN			(NBL_DP_QM_BASE + 0x00000148)
#define NBL_QM_TX_RXMAC_PORT_BP_EN		(NBL_DP_QM_BASE + 0x00000150)
#define NBL_QM_TX_RXMAC_COS_BP_EN		(NBL_DP_QM_BASE + 0x00000160)
#define NBL_QM_DN_COS_MAPPING_0(i) \
	(NBL_DP_QM_BASE + 0x00000514 + (i) * sizeof(struct nbl_qm_dn_cos_mapping_0))
#define NBL_QM_DN_COS_MAPPING_1(i) \
	(NBL_DP_QM_BASE + 0x00000524 + (i) * sizeof(struct nbl_qm_dn_cos_mapping_1))
#define NBL_QM_DN_COS_MAPPING_2(i) \
	(NBL_DP_QM_BASE + 0x00000534 + (i) * sizeof(struct nbl_qm_dn_cos_mapping_2))
#define NBL_QM_QUE_PKT_CNT_TBL(i) \
	(NBL_DP_QM_BASE + 0x0000E600 + (i) * sizeof(struct nbl_qm_que_pkt_cnt_tbl))
#define NBL_QM_OUTQUE_QUE_PKT_BYTE_CNT(i) \
	(NBL_DP_QM_BASE + 0x00000BB0 + (i) * sizeof(struct nbl_qm_outque_que_pkt_byte_cnt))
#define NBL_QM_STAT_S_VSI(vsi_id)	\
	(NBL_DP_QM_BASE + 0x0000C200 + (vsi_id) * sizeof(struct nbl_qm_stat_s_vsi_tbl))
#define NBL_QM_STAT_D_VSI(vsi_id)	\
	(NBL_DP_QM_BASE + 0x0000D400 + (vsi_id) * sizeof(struct nbl_qm_stat_d_vsi_tbl))

struct nbl_qm_rxmac_port_bp_en {
	u32 eth0:1;
	u32 eth1:1;
	u32 eth2:1;
	u32 eth3:1;
	u32 rsv:28;
};

struct nbl_qm_rxmac_cos_bp_en {
	u32 eth0:8;
	u32 eth1:8;
	u32 eth2:8;
	u32 eth3:8;
};

struct nbl_qm_tx_rxmac_port_bp_en {
	u32 eth0:1;
	u32 eth1:1;
	u32 eth2:1;
	u32 eth3:1;
	u32 rsv:28;
};

struct nbl_qm_tx_rxmac_cos_bp_en {
	u32 eth0:8;
	u32 eth1:8;
	u32 eth2:8;
	u32 eth3:8;
};

struct nbl_qm_dn_cos_mapping_0 {
	u32 cos0:9;
	u32 cos1:9;
	u32 cos2:9;
	u32 rsv:5;
};

struct nbl_qm_dn_cos_mapping_1 {
	u32 cos3:9;
	u32 cos4:9;
	u32 cos5:9;
	u32 rsv:5;
};

struct nbl_qm_dn_cos_mapping_2 {
	u32 cos6:9;
	u32 cos7:9;
	u32 rsv:14;
};

struct nbl_qm_que_pkt_cnt_tbl {
	u32 cnt;
};

struct nbl_qm_outque_que_pkt_byte_cnt {
	u64 cnt;
};

struct nbl_qm_stat_s_vsi_tbl {
	u32 byte_cnt_low;
	u32 byte_cnt_high;
	u32 pkt_cnt_low;
	u32 pkt_cnt_high;
};

struct nbl_qm_stat_d_vsi_tbl {
	u32 byte_cnt_low;
	u32 byte_cnt_high;
	u32 pkt_cnt_low;
	u32 pkt_cnt_high;
};

/*  ----------  PED  ----------  */
#define NBL_PED_UDF_EXT_TABLE(i) \
	(NBL_DP_PED_BASE + 0x000001B0 + (i) * sizeof(struct nbl_ped_udf_ext))
#define NBL_PED_TBL_UDF_EXT(i) \
	(NBL_DP_PED_BASE + 0x00002000 + (i) * sizeof(struct nbl_ped_tbl_udf_ext))

struct nbl_ped_udf_ext {
	u32 st:6;
	u32 rsv0:10;
	u32 len:4;
	u32 rsv1:12;
};

struct nbl_ped_tbl_udf_ext {
	u32 sel0:3;
	u32 en0:1;
	u32 sel1:3;
	u32 en1:1;
	u32 rsv:24;
};

/*  ----------  IPRO  ----------  */
#define NBL_IPRO_IETH_TABLE(i) \
	(NBL_PPE_IPRO_BASE + 0x00004000 + (i) * sizeof(struct nbl_ipro_ieth_tbl))
#define NBL_IPRO_IVSI_TABLE(i) \
	(NBL_PPE_IPRO_BASE + 0x00008000 + (i) * sizeof(struct nbl_ipro_ivsi_tbl))

/* IPRO ieth_tbl */
struct nbl_ipro_ieth_tbl {
	u64 base_ad;
	u32 base_ab:8;
	u32 not_use0:1;
	u32 t_lx_sel:1;
#define IETH_USE_LX_OFT		(0)
#define IETH_USE_T_LX_OFT	(1)
	u32 sw_id:2;
	u32 lag_vld:1;
	u32 lag_id:1;
	u32 vlan_lmt:2;
	u32 decap_en:1;
	u32 phy_flow:1;
	u32 t_s3:3;
	u32 vld:1;
	u32 rsv0:10;
	u32 rsv1:32;
};

/* IPRO ivsi_tbl */
struct nbl_ipro_ivsi_tbl {
	u64 base_ad;
	u64 base_ab:8;
	u64 not_use0:1;
	u64 t_lx_sel:1;
#define IVSI_USE_LX_OFT		(0)
#define IVSI_USE_T_LX_OFT	(1)
	u64 vlan_lmt:2;
	u64 sw_id:2;
	u64 rsv0:1;
	u64 smac_vld:1;
	u64 smac:48;
	/* mtu = 0, means donot check mtu */
	u64 mtu:16;
	u64 cpu_nstg:3;
	u64 cpu_bps:1;
	u64 phy_flow:1;
	u64 t_s3:3;
	u64 vld:1;
	u64 rsv1:39;
	u64 rsv2;
};

enum nbl_ipro_error_code_e {
	NBL_IPRO_ERROR_CODE_NONE,
	NBL_IPRO_ERROR_CODE_VLAN,
	NBL_IPRO_ERROR_CODE_IPV4_HLEN_ERR,
	NBL_IPRO_ERROR_CODE_CSUM_ERR,
	NBL_IPRO_ERROR_CODE_TTL_EXP_ERR,
	NBL_IPRO_ERROR_CODE_ESP_INTG_ERR,
	NBL_IPRO_ERROR_CODE_MAC_SPOOF_ERR,
	NBL_IPRO_ERROR_CODE_DECAP_FAIL_ERR,
	NBL_IPRO_ERROR_CODE_ING_MTU_ERR,
	NBL_IPRO_ERROR_CODE_ERG_MTU_ERR,
	NBL_IPRO_ERROR_CODE_ING_PORT_INV_ERR,
	NBL_IPRO_ERROR_CODE_EGR_PORT_INV_ERR,
	NBL_IPRO_ERROR_CODE_RDMA_SIP_ERR,
	NBL_IPRO_ERROR_CODE_HERR_ERR = 15,
};

#define NBL_CSUM_ERR_DIR_RX			0
#define NBL_CSUM_ERR_DIR_TX			1
#define NBL_IPRO_ERRCODE_3_HDL_BITS_PER_MD	4
#define NBL_IPRO_ERRCODE_3_HDL_RX_MD_BASE	4
#define NBL_IPRO_ERRCODE_3_HDL_TX_MD_BASE	0
#define NBL_IPRO_ERRCODE_3_HDL_PF_MASK		0xF

/*  ----------  EPRO  ----------  */
#define NBL_EPRO_RSS_KEY_TABLE(i)		(NBL_PPE_EPRO_BASE + 0x00001400 + (i) * 64)
/* epro epro_eeth_table */
#define NBL_EPRO_EETH_TABLE(i) \
	(NBL_PPE_EPRO_BASE + 0x00001100 + (i) * sizeof(struct nbl_epro_eeth_tbl))
/* epro epro_evsi_table */
#define NBL_EPRO_EVSI_TABLE(i) \
	(NBL_PPE_EPRO_BASE + 0x00002000 + (i) * sizeof(struct nbl_epro_evsi_tbl))
/* EPRO q_group_tbl */
#define NBL_EPRO_Q_GROUP_TABLE(i) \
	(NBL_PPE_EPRO_BASE + 0x0006000 + (i) * sizeof(struct nbl_epro_q_group_tbl))
/* EPRO mhash_upcall_tbl */
#define NBL_EPRO_MHASH_UPCALL_TABLE(i) \
	(NBL_PPE_EPRO_BASE + 0x0007800 + (i) * sizeof(struct nbl_epro_mhash_upcall_tbl))
/* EPRO q_map_tbl */
#define NBL_EPRO_Q_MAP_TABLE(i) \
	(NBL_PPE_EPRO_BASE + 0x0008000 + (i) * sizeof(struct nbl_epro_q_map_tbl))
#define NBL_EPRO_LAG_MAP_CFG(i) \
	(NBL_PPE_EPRO_BASE + 0x00000120 + (i) * sizeof(struct nbl_epro_lag_map_cfg))

/* EPRO rss_hash_key */
struct nbl_epro_rss_key {
	u64 key0;
	u64 key1;
	u64 key2;
	u64 key3;
	u64 key4;
};

#define NBL_EPRO_EETH_LAG_OFFSET		(4)

/* EPRO eeth table */
struct nbl_epro_eeth_tbl {
	u64 base_ad;
	u64 base_ab:8;
	u64 def_cos:3;
	u64 pfc_mode:1;
#define EETH_PFC_MODE_8021P			(0)
#define EETH_PFC_MODE_DSCP			(1)
	u64 pfc_en:1;
	u64 vld:1;
	u64 rsv0:50;
};

/* mirror */
enum nbl_mirror_dir {
	MIRROR_DIR_INGRESS = 0,
	MIRROR_DIR_EGRESS  = 1
};

#define NBL_MIRROR_ID_BASE			(112)
#define NBL_MIRROR_ID_OFFSET			(4)

#define NBL_UDF_MIRROR_ENABLE			0x8f
#define NBL_UDF_MIRROR_DISABLE			0x00

#define NBL_MIRROR_ID_ENABLE			0x80
#define NBL_IPRO_UDF_ACTION_MASK		(0xFFULL << 40)
#define NBL_EPRO_UDF_ACTION_MASK		(0xFFULL << 56)

#define NBL_UDF_PRF_ID_MIRROR			(6)

#define NBL_EPRO_MIRROR_ACTION_MASK		(0xFFFFULL << 16)

/* EPRO evsi table */
struct nbl_epro_evsi_tbl {
	u64 base_ad;
	u64 base_ab:8;
	u64 mtu:16;
	u64 act_mode:2;
#define EVSI_ACT_MODE_BASE_ABAD			(0)
#define EVSI_ACT_MODE_POP_CVLAN			(1)
#define EVSI_ACT_MODE_POP_SVLAN			(2)
#define EVSI_ACT_MODE_POP_CVLAN_SVLAN		(3)
	u64 port_mac:48;
	u64 prune_mc:2;
#define EVSI_PRUNE_MC_DONOT_PRUNE		(0)
#define EVSI_PRUNE_MC_VSI_PRUNE			(1)
#define EVSI_PRUNE_MC_SMAC_PRUNE		(2)
#define EVSI_PRUNE_MC_VSI_AND_SMAC_PRUNE	(3)
	u64 prune_uc:2;
#define EVSI_PRUNE_UC_DONOT_PRUNE		(0)
#define EVSI_PRUNE_UC_VSI_PRUNE			(1)
#define EVSI_PRUNE_UC_SMAC_PRUNE		(2)
#define EVSI_PRUNE_UC_VSI_AND_SMAC_PRUNE	(3)
	u64 vld:1;
	u64 rsv0:49;
	u64 rsv1;
};

/* EPRO q_group_tbl */
struct nbl_epro_q_group_tbl {
	u64 rsv0:1;
	u64 sqg1_oft:7;
	u64 sqg1_sz:3;
	u64 sqg0_oft:7;
	u64 sqg0_sz:3;
	u64 alg:2;
#define NBL_EPRO_RSS_ALG_TOEPLITZ		(0)
#define NBL_EPRO_RSS_ALG_CRC32			(1)
#define NBL_EPRO_RSS_ALG_XOR32			(2)
#define NBL_EPRO_RSS_ALG_RSV			(3)
	u64 hash_key_sel:4;
	u64 tmpt_sel_sctpv6_dp:1;
	u64 tmpt_sel_sctpv6_sp:1;
	u64 tmpt_sel_sctpv6_dip:1;
	u64 tmpt_sel_sctpv6_sip:1;
	u64 tmpt_sel_udpv6_dp:1;
	u64 tmpt_sel_udpv6_sp:1;
	u64 tmpt_sel_udpv6_dip:1;
	u64 tmpt_sel_udpv6_sip:1;
	u64 tmpt_sel_tcpv6_dp:1;
	u64 tmpt_sel_tcpv6_sp:1;
	u64 tmpt_sel_tcpv6_dip:1;
	u64 tmpt_sel_tcpv6_sip:1;
	u64 tmpt_sel_ipv6_dip:1;
	u64 tmpt_sel_ipv6_sip:1;
	u64 tmpt_sel_sctpv4_dp:1;
	u64 tmpt_sel_sctpv4_sp:1;
	u64 tmpt_sel_sctpv4_dip:1;
	u64 tmpt_sel_sctpv4_sip:1;
	u64 tmpt_sel_udpv4_dp:1;
	u64 tmpt_sel_udpv4_sp:1;
	u64 tmpt_sel_udpv4_dip:1;
	u64 tmpt_sel_udpv4_sip:1;
	u64 tmpt_sel_tcpv4_dp:1;
	u64 tmpt_sel_tcpv4_sp:1;
	u64 tmpt_sel_tcpv4_dip:1;
	u64 tmpt_sel_tcpv4_sip:1;
	u64 tmpt_sel_ipv4_dip:1;
	u64 tmpt_sel_ipv4_sip:1;
	u64 dft_qid:10;
	u64 t_ptype_sel:1;
	u64 pd_sel:1;
	u64 vld:1;
	u64 rsv1:60;
};

/* EPRO mhash_upcall */
struct nbl_epro_mhash_upcall_tbl {
	u32 mod:1;
#define NBL_EPRO_MASH_UPCALL_RSS		(0)
#define NBL_EPRO_MASH_UPCALL_MHASH		(1)
	u32 en:1;
#define NBL_EPRO_MASH_UPCALL_DISABLE		(0)
#define NBL_EPRO_MASH_UPCALL_ENABLE		(1)
	u32 rsv:30;
};

struct nbl_epro_lag_map_cfg {
	u32 pd_sel:1;
#define NBL_EPRO_LAG_ALG_LINUX_L2_HASH		(3)
#define NBL_EPRO_LAG_ALG_LINUX_L23_HASH		(4)
#define NBL_EPRO_LAG_ALG_LINUX_L34_HASH		(5)
#define NBL_EPRO_LAG_ALG_LINUX_VLANSMAC		(6)
	u32 dft_alg:2;
	u32 alg:3;
	u32 eth_btm:4;
	u32 t_ptype_sel:1;
	u32 hash_shift_en:1;
	u32 l2_etype_end_mod:1;
	u32 vld:1;
	u32 rsv:18;
};

#define NBL_EPRO_RSS_RET_TBL_DEPTH_DRACO \
	(NBL_EPRO_Q_MAP_TBL_DEPTH * (NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL))
#define NBL_EPRO_Q_MAP_TBL_DEPTH		(312)
#define NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL	(32)

/* EPRO q_map_tbl */
struct nbl_epro_q_map_tbl {
	u64 glb_qid_0:9;
	u64 glb_qid_1:9;
	u64 glb_qid_2:9;
	u64 glb_qid_3:9;
	u64 glb_qid_4:9;
	u64 glb_qid_5:9;
	u64 glb_qid_6:9;
	u64 glb_qid_7:9;
	u64 glb_qid_8:9;
	u64 glb_qid_9:9;
	u64 glb_qid_10:9;
	u64 glb_qid_11:9;
	u64 glb_qid_12:9;
	u64 glb_qid_13:9;
	u64 glb_qid_14:9;
	u64 glb_qid_15:9;
	u64 glb_qid_16:9;
	u64 glb_qid_17:9;
	u64 glb_qid_18:9;
	u64 glb_qid_19:9;
	u64 glb_qid_20:9;
	u64 glb_qid_21:9;
	u64 glb_qid_22:9;
	u64 glb_qid_23:9;
	u64 glb_qid_24:9;
	u64 glb_qid_25:9;
	u64 glb_qid_26:9;
	u64 glb_qid_27:9;
	u64 glb_qid_28:9;
	u64 glb_qid_29:9;
	u64 glb_qid_30:9;
	u64 glb_qid_31:9;
	u64 vld:1;
	u64 rsv0:31;
	u64 rsv1[3];
};

struct nbl_phy_ped_epro_tbl {
	u64 addr:56;
	u64 addr_len:8;
};

/*  ----------  ACL  ----------  */
#define NBL_ACL_INDIR_CTRL_WRITE		(0)
#define NBL_ACL_INDIR_CTRL_READ			(1)
#define NBL_ACL_RD_RETRY			(500)
#define NBL_ACL_RD_WAIT_100US			(100)
#define NBL_ACL_RD_WAIT_200US			(200)
#define NBL_ACL_DELAY_US			(200)
#define NBL_ACL_TCAM_DEPTH			(512)
#define NBL_ACL_FLUSH_ALL_BTM			(0xffff)
#define NBL_ACL_PROFILE_NUM			(16)
#define NBL_ACL_FLUSH_FLOW_BTM			(0x7fff)
#define NBL_ACL_FLUSH_RDMA_BTM			(0x8000)

#define NBL_ACL_ACTION_RAM_TBL(r, i)		(NBL_PPE_ACL_BASE + 0x00002000 + 0x2000 * (r) + \
							(NBL_ACL_AT0_DWLEN * 4 * (i)))

struct nbl_acl_tcam_common_data {
	u8 data[4];
};

/*  ----------  FEM  ----------  */
#define NBL_EM_MAX_WAIT_TIMES			(1000)
#define NBL_FEM_WORK_MODE		(NBL_PPE_FEM_BASE + 0x00000230)
#define NBL_FEM_PF_CMD_REQ(i)		(NBL_PPE_FEM_BASE + 0x00000300 + (i) * 84)
#define NBL_FEM_PF_CMD_HEAD(i)		(NBL_PPE_FEM_BASE + 0x00000304 + (i) * 84)
#define NBL_FEM_PF_CMD_PARAM(i)		(NBL_PPE_FEM_BASE + 0x0000030C + (i) * 84)

/* fem pfx_cmd_req */
struct nbl_fem_pf_cmd_req {
	u32 en:1;
	u32 rsv:31;
};

/* fem pfx_cmd_head */
union nbl_fem_pf_cmd_head_u {
	struct nbl_fem_pf_cmd_head {
		u32 data[2];
	} info;
#define NBL_FEM_PF_CMD_HEAD_TBL_WIDTH (sizeof(struct nbl_fem_pf_cmd_head))
	u8 data[NBL_FEM_PF_CMD_HEAD_TBL_WIDTH];
};

/* fem pfx_cmd_param */
union nbl_fem_pf_cmd_param_u {
	struct nbl_fem_pf_cmd_param {
		u32 data[18];
	} info;
#define NBL_FEM_PF_CMD_PARAM_TBL_WIDTH (sizeof(struct nbl_fem_pf_cmd_param))
	u8 data[NBL_FEM_PF_CMD_PARAM_TBL_WIDTH];
};

/*  ----------  MCC  ----------  */
#define NBL_MCC_GROUP_TABLE(mcc_id) \
	(NBL_PPE_MCC_BASE + 0x0001000 + (mcc_id) * sizeof(struct nbl_mcc_group_table))

/* mcc group_table */
struct nbl_mcc_group_table {
	u64 vld:1;
	u64 leaf_dport_eth:4;
	u64 leaf_dport_lag:2;
	u64 leaf_dport_vsi_0_56:57;
	u64 leaf_dport_vsi_57_120:64;
	u64 leaf_dport_vsi_121_184:64;
	u64 leaf_dport_vsi_185_248:64;
	u64 leaf_dport_vsi_249_277:29;
	u64 clr_udf_btm:4;
	u64 mcc_pri:1;
	u64 udf_prune_en:1;
	u64 rsv0:29;
	u64 rsv1[3];
};

#define NBL_DRACO_UDF_WIDTH		(160)
#define NBL_DRACO_UDF_UNIT		(4)
#define NBL_DRACO_UDF_SIZE_8B		(0)
#define NBL_DRACO_UDF_SIZE_8B_MASK	(1)
#define NBL_DRACO_UDF_SIZE_16B		(2)
#define NBL_DRACO_UDF_SIZE_32B		(3)
#define NBL_DRACO_UDF_FLAG_OFT		(0)
#define NBL_DRACO_UDF_LOC_VTEP_OFT	(4)
#define NBL_DRACO_UDF_MCC_PRUNE_OFT	(4)
#define NBL_DRACO_UDF_SEC_ID_OFT	(16)
#define NBL_DRACO_UDF_FLOW_STAT_ID_OFT	(28)
#define NBL_DRACO_UDF_PP0_IDX_OFT	(32)
#define NBL_DRACO_UDF_CAP_INFO_OFT	(40)
#define NBL_DRACO_UDF_FLOW_CAR_OFT	(48)
#define NBL_DRACO_UDF_MIRR_ID_OFT	(60)
#define NBL_DRACO_UDF_T_OVN_DATA_OFT	(68)
#define NBL_DRACO_UDF_UDP_SP_OFT	(68)
#define NBL_DRACO_UDF_NVGRE_FLOW_ID_OFT	(84)
#define NBL_DRACO_UDF_ACL_TAG_OFT	(92)
#define NBL_DRACO_UDF_ECN_OFT		(100)
#define NBL_DRACO_UDF_TCP_LEN_OFT	(100)
#define NBL_DRACO_UDF_QPN_OFT		(104)
#define NBL_DRACO_UDF_DP_HASH_OFT	(128)

#define NBL_DRACO_UDF_ID_SET_PP0_IDX		(1)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR	(2)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR_FLAG	(3)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR		(4)

#define NBL_DRACO_UDF_ID_SET_PP0_IDX_LEN	(16)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR_LEN	(32)
#define NBL_DRACO_UDF_ID_SET_MIRR_ID_LEN	(8)
#define NBL_DRACO_UDF_ID_FLOW_STAT_ID_LEN	(20)

#define NBL_BYTES_IN_REG (4)

#define NBL_ACL_KGEN_FLAG_CFG_ADDR  (0x540140)
#define NBL_ACL_KGEN_FLAG_CFG_DEPTH (1)
#define NBL_ACL_KGEN_FLAG_CFG_WIDTH (32)
#define NBL_ACL_KGEN_FLAG_CFG_DWLEN (1)
union acl_kgen_flag_cfg_u {
	struct acl_kgen_flag_cfg {
		u32 flag_oft:6;          /* [05:00] Default:0x0 RW */
		u32 rsv:26;              /* [31:06] Default:0x0 RO */
	} info;
	u32 data[NBL_ACL_KGEN_FLAG_CFG_DWLEN];
};

union nbl_draco_ptype_u {
	struct {
		u16 l4:2;
		u16 l3:2;
		u16 nxt_proto:3;
		u16 l2:2;
		u16 tnl_type:2;
		u16 tnl_base:1;
		u16 tnl_l3:1;
		u16 tnl_l2:2;
		u16 tnl:1;
	} tnl;

	struct {
		u16 l4:2;
		u16 l3:2;
		u16 nxt_proto:3;
		u16 l2:2;
		u16 spec_l2:5;
		u16 spec_l2_hit:1;
		u16 tnl:1;
	} nontnl;

	u16 data;
};

union nbl_pa_udf_ext_idxs {
	struct pa_udf_ext_idxs {
		u32 idx0:4;
		u32 vld0:1;
		u32 idx1:4;
		u32 vld1:1;
		u32 idx2:4;
		u32 vld2:1;
		u32 idx3:4;
		u32 vld3:1;
		u32 rsv:12;
	} info;

	u32 data;
};

#define NBL_PA_UDF_EXT_IDX_ADDR  (0x501080)
#define NBL_PA_UDF_EXT_IDX_DEPTH (16)
#define NBL_PA_UDF_EXT_IDX_WIDTH (32)
#define NBL_PA_UDF_EXT_IDX_DWLEN (1)
#define NBL_PA_UDF_EXT_IDX_REG(r) (NBL_PA_UDF_EXT_IDX_ADDR + \
		(NBL_PA_UDF_EXT_IDX_DWLEN * 4) * (r))

union ipro_epro_err_sel_array {
	struct {
		u8 sel0:4;
		u8 sel1:4;
		u8 sel2:4;
		u8 sel3:4;
		u8 sel4:4;
		u8 sel5:4;
		u8 sel6:4;
		u8 sel7:4;
	} info;
	u32 data;
};

union nbl_draco_sport_simple_u {
	struct {
		u8 lag_id:1;
		u8 lag:1;
		u8 dir:1;
#define NBL_DRACO_SPORT_DIR_TX	(0)
#define NBL_DRACO_SPORT_DIR_RX	(1)
		u8 sw_id:2;
		u8 phy_flow:1;
		u8 rsv:2;
	} rx;

	struct {
		u8 cpu:1;
		u8 rdma:1;
		u8 dir:1;
#define NBL_DRACO_SPORT_DIR_TX	(0)
#define NBL_DRACO_SPORT_DIR_RX	(1)
		u8 sw_id:2;
		u8 phy_flow:1;
		u8 rsv:2;
	} tx;

	u8 data;
};

union nbl_base_action_data {
	struct {
		u16 resreved0;
		u16 resreved1;
		u16 resreved2;
		union dport_action dport;
	};

	u64 data;

	u32 u32_arr[2];
};

/* dl4s */
#define NBL_DTLS_KEY_SALT(_i)		(NBL_PPE_DTLS_BASE + 0x00010000 + (_i) * 64)
/* ul4s */
#define NBL_UTLS_SYNC_TRIG(_i)		(NBL_PPE_UTLS_BASE + 0x00000700 + (_i) * 32)
#define NBL_UTLS_SYNC_SID(_i)		(NBL_PPE_UTLS_BASE + 0x00000704 + (_i) * 32)
#define NBL_UTLS_SYNC_TCP_SN(_i)	(NBL_PPE_UTLS_BASE + 0x00000710 + (_i) * 32)
#define NBL_UTLS_SYNC_REC_NUMH(_i)	(NBL_PPE_UTLS_BASE + 0x00000714 + (_i) * 32)
#define NBL_UTLS_SYNC_REC_NUML(_i)	(NBL_PPE_UTLS_BASE + 0x00000718 + (_i) * 32)
#define NBL_UTLS_KEY_SALT(_i)		(NBL_PPE_UTLS_BASE + 0x00010000 + (_i) * 64)

struct nbl_ktls_keymat {
	u8 key[32];
	u8 salt[4];
	u32 mode:2;
	u32 ena:1;
	u32 rsv:29;
};

union nbl_ktls_sync_trig {
	u32 data;
	struct {
		u32 trig : 1;
		u32 init_sync : 1;
		u32 rsv2 : 30;
	};
};

/* dprbac */
#define NBL_DPRBAC_INT_STATUS		(NBL_PPE_DPRBAC_BASE + 0x00000000)
#define NBL_DPRBAC_ENABLE		(NBL_PPE_DPRBAC_BASE + 0x00000114)
#define NBL_DPRBAC_NAT			(NBL_PPE_DPRBAC_BASE + 0x0000012C)
#define NBL_DPRBAC_DROP			(NBL_PPE_DPRBAC_BASE + 0x00000180)
#define NBL_DPRBAC_SAD_LIFEDIFF		(NBL_PPE_DPRBAC_BASE + 0x00000204)
#define NBL_DPRBAC_LIFETIME_DIFF	(NBL_PPE_DPRBAC_BASE + 0x00000208)
#define NBL_DPRBAC_DBG_CNT_EN		(NBL_PPE_DPRBAC_BASE + 0x00000680)

#define NBL_DPRBAC_LIFETIME_INFO(_i)	(NBL_PPE_DPRBAC_BASE + 0x00000048 + (_i) * 4)
#define NBL_DPRBAC_SAD_IV(_i)		(NBL_PPE_DPRBAC_BASE + 0x00001000 + (_i) * 8)
#define NBL_DPRBAC_SAD_ESN(_i)		(NBL_PPE_DPRBAC_BASE + 0x00003000 + (_i) * 16)
#define NBL_DPRBAC_SAD_LIFETIME(_i)	(NBL_PPE_DPRBAC_BASE + 0x00007000 + (_i) * 16)
#define NBL_DPRBAC_SAD_CRYPTO_INFO(_i)	(NBL_PPE_DPRBAC_BASE + 0x0000B000 + (_i) * 64)
#define NBL_DPRBAC_SAD_ENCAP_INFO(_i)	(NBL_PPE_DPRBAC_BASE + 0x0001B000 + (_i) * 64)

union nbl_dprbac_enable {
	u32 data;
	struct {
		u32 prbac : 1;
		u32 rsv1 : 1;
		u32 ipv4_nat_csm : 1;
		u32 ipv6_nat_csm : 1;
		u32 tunnel_mf_type : 1;
		u32 tunnel_mf_action : 1;
		u32 lifetime_int_mask : 1;
		u32 rsv2 : 25;
	};
};

union nbl_dprbac_nat {
	u32 data;
	struct {
		u32 rsv : 16;
		u32 sport : 16;
	};
};

struct nbl_dprbac_drop {
	u32 prbac_bp:1;
	u32 md_drop:1;
	u32 md_errcode:1;
	u32 rsv:29;
};

union nbl_dprbac_dbg_cnt_en {
	u32 data;
	struct {
		u32 total : 1;
		u32 in_right_bypass : 1;
		u32 in_drop_bypass : 1;
		u32 in_drop_prbac : 1;
		u32 out_drop_prbac : 1;
		u32 out_right_prbac : 1;
		u32 rsv : 26;
	};
};

struct nbl_dprbac_sad_iv {
	u64 iv;
};

struct nbl_dprbac_sad_esn {
	u32 sn;
	u32 esn;
	u32 wrap_en : 1;
	u32 enable : 1;
	u32 rsv1 : 30;
	u32 rsv2;
};

struct nbl_dprbac_sad_lifetime {
	u32 diff;
	u32 cnt;
	u32 flag : 1;
	u32 unit : 1;
	u32 enable : 1;
	u32 pf : 1;
	u32 rsv1 : 28;
	u32 rsv2;
};

struct nbl_dprbac_sad_crypto_info {
	u32 key[8];
	u32 salt;
	u32 crypto_type : 3;
	u32 tunnel_mode : 1;
	u32 icv_len : 2;
	u32 rsv1 : 26;
	u32 rsv2[6];
};

struct nbl_dprbac_sad_encap_info {
	u32 dip_addr[4];
	u32 sip_addr[4];
	u32 spi;
	u32 dport : 16;
	u32 nat_flag : 1;
	u32 padding_align : 1;
	u32 rsv1 : 14;
	u32 rsv2[6];
};

/* uprbac */
#define NBL_UPRBAC_INT_STATUS		(NBL_PPE_UPRBAC_BASE + 0x00000000)
#define NBL_UPRBAC_ENABLE		(NBL_PPE_UPRBAC_BASE + 0x00000114)
#define NBL_UPRBAC_NAT			(NBL_PPE_UPRBAC_BASE + 0x0000012C)
#define NBL_UPRBAC_SAD_LIFEDIFF		(NBL_PPE_UPRBAC_BASE + 0x00000204)
#define NBL_UPRBAC_LIFETIME_DIFF	(NBL_PPE_UPRBAC_BASE + 0x00000208)
#define NBL_UPRBAC_DBG_CNT_EN		(NBL_PPE_UPRBAC_BASE + 0x00000680)

#define NBL_UPRBAC_LIFETIME_INFO(_i)	(NBL_PPE_UPRBAC_BASE + 0x00000048 + (_i) * 4)
#define NBL_UPRBAC_CMD_REQ(_i)		(NBL_PPE_UPRBAC_BASE + 0x00000500 + (_i) * 48)
#define NBL_UPRBAC_CMD_HEAD(_i)		(NBL_PPE_UPRBAC_BASE + 0x00000504 + (_i) * 48)
#define NBL_UPRBAC_TBL_CLR(_i)		(NBL_PPE_UPRBAC_BASE + 0x000005C0 + (_i) * 4)
#define NBL_UPRBAC_SAD_BOTTOM(_i)	(NBL_PPE_UPRBAC_BASE + 0x00001000 + (_i) * 16)
#define NBL_UPRBAC_SAD_LIFETIME(_i)	(NBL_PPE_UPRBAC_BASE + 0x00005000 + (_i) * 16)
#define NBL_UPRBAC_SAD_CRYPTO_INFO(_i)	(NBL_PPE_UPRBAC_BASE + 0x00009000 + (_i) * 64)
#define NBL_UPRBAC_SAD_SLIDE_WINDOW(_i)	(NBL_PPE_UPRBAC_BASE + 0x00019000 + (_i) * 64)

#define NBL_UPRBAC_EM_TCAM(_i)		(NBL_PPE_UPRBAC_BASE + 0x00002800 + (_i) * 16)
#define NBL_UPRBAC_EM_AD(_i)		(NBL_PPE_UPRBAC_BASE + 0x00003000 + (_i) * 4)
#define NBL_UPRBAC_HT(_i, _j)		(NBL_PPE_UPRBAC_BASE + 0x00004000 + \
					(_i) * 0x00004000 + (_j) * 16)
#define NBL_UPRBAC_KT(_i)		(NBL_PPE_UPRBAC_BASE + 0x00010000 + (_i) * 32)

union nbl_uprbac_enable {
	u32 data;
	struct {
		u32 prbac : 1;
		u32 padding_check : 1;
		u32 pa_am : 1;
		u32 dm_am : 1;
		u32 icv_err : 1;
		u32 pad_err : 1;
		u32 ipv6_nat_csm0 : 1;
		u32 lifetime_int_mask : 1;
		u32 rsv : 24;
	};
};

union nbl_uprbac_nat {
	u32 data;
	struct {
		u32 enable : 1;
		u32 rsv : 15;
		u32 dport : 16;
	};
};

union nbl_uprbac_dbg_cnt_en {
	u32 data;
	struct {
		u32 drop_prbac : 1;
		u32 right_prbac : 1;
		u32 replay : 1;
		u32 right_misc : 1;
		u32 error_misc : 1;
		u32 xoff_drop : 1;
		u32 intf_cell : 1;
		u32 sad_miss : 1;
		u32 lifetime_drop : 1;
		u32 icv_err : 1;
		u32 pad_err : 1;
		u32 pad_len_err : 1;
		u32 ics_err : 1;
		u32 ucs_err : 1;
		u32 esn_ovf : 1;
		u32 esn_uvf : 1;
		u32 rsv : 16;
	};
};

struct nbl_uprbac_sad_bottom {
	u32 sn;
	u32 esn;
	u32 overlap : 1;
	u32 enable : 1;
	u32 rsv1 : 30;
	u32 rsv2;
};

struct nbl_uprbac_sad_lifetime {
	u32 diff;
	u32 cnt;
	u32 flag : 1;
	u32 unit : 1;
	u32 enable : 1;
	u32 rsv1 : 29;
	u32 rsv2;
};

struct nbl_uprbac_sad_crypto_info {
	u32 key[8];
	u32 salt;
	u32 crypto_type : 3;
	u32 tunnel_mode : 1;
	u32 icv_len : 2;
	u32 rsv1 : 26;
	u32 rsv2[6];
};

struct nbl_uprbac_sad_slide_window {
	u32 bitmap[8];
	u32 option : 2;
	u32 enable : 1;
	u32 rsv1 : 29;
	u32 rsv2[7];
};

struct nbl_uprbac_em_tcam {
	u32 key_dat0;
	u32 key_dat1;
	u32 key_dat2 : 16;
	u32 key_vld : 1;
	u32 key_size : 1;
	u32 rsv1 : 14;
	u32 rsv2;
};

union nbl_uprbac_em_ad {
	u32 data;
	struct {
		u32 sad_index : 11;
		u32 rsv : 21;
	};
};

union nbl_uprbac_ht {
	u8 data[16];
	struct {
		u32 kt_index0 : 11;
		u32 ht_other_index0 : 9;
		u32 vld0 : 1;

		u32 kt_index1 : 11;
		u32 ht_other_index1 : 9;
		u32 vld1 : 1;

		u32 kt_index2 : 11;
		u32 ht_other_index2 : 9;
		u32 vld2 : 1;

		u32 kt_index3 : 11;
		u32 ht_other_index3 : 9;
		u32 vld3 : 1;

		u32 rsv1 : 12;
		u32 rsv2;
	};
};

struct nbl_uprbac_kt {
	u32 key[5];
	u32 sad_index : 11;
	u32 rsv1 : 21;
	u32 rsv[2];
};

union nbl_ipsec_lifetime_diff {
	u32 data[2];
	struct {
		u32 sad_index : 11;
		u32 rsv1 : 5;
		u32 msb_value : 1;
		u32 flag_value : 1;
		u32 rsv2 : 2;
		u32 msb_wen : 1;
		u32 flag_wen : 1;
		u32 rsv3 : 10;
		u32 lifetime_diff;
	};
};

/* hol macros & registers */
#define NBL_PED_HOL_TIMEOUT_TH			(0xF4240)
#define NBL_PED_HOL_ACTIVE_TH			(0x2710)
#define NBL_VERSION_4FPGA			(0xF4AF)
#define NBL_VERSION_1FPGA_HIGH			(0xF121)
#define NBL_VERSION_1FPGA			(0xF120)
#define NBL_DMUX_ETH_HOL_BP_TH			(0x400)

#define NBL_QM_HOL_BP_TH			(0x40)

#define NBL_DMUX_ETH_HOL_BP_ADDR  (0x1710234)
#define NBL_DMUX_ETH_HOL_BP_DEPTH (4)
union dmux_eth_hol_bp_u {
	struct dmux_eth_hol_bp {
		u32 th:16;               /* [15:00] Default:0x180 RW */
		u32 rsv:15;              /* [30:16] Default:0x0 RO */
		u32 en:1;                /* [31:31] Default:0x0 RW */
	} __packed info;
	u32 data;
} __packed;
#define NBL_DMUX_ETH_HOL_BP_REG(r) (NBL_DMUX_ETH_HOL_BP_ADDR + 4 * (r))

#define NBL_DVN_HOL_PORT_QID_RESPONSE_CFG_ADDR  (0x280478)
union dvn_hol_port_qid_response_cfg_u {
	struct dvn_hol_port_qid_response_cfg {
		u32 mask:1;              /* [0] Default:0x1 RW */
		u32 rsv:31;              /* [31:1] Default:0x0 RO */
	} __packed info;
	u32 data;
} __packed;

#define NBL_STORE_QID_ADDR  (0x47c8)
union store_qid_u {
	struct store_qid {
		u32 en:1;                /* [00:00] Default:0x0 RW */
		u32 rsv:31;              /* [31:01] Default:0x0 RO */
	} __packed info;
	u32 data;
} __packed;

/* ptype table index */
#define NBL_PTYPE_LACP_START_ID	(4)
#define NBL_PTYPE_LLDP_START_ID	(8)

/* umacsec */
#define NBL_UMACSEC_EN			(NBL_PPE_UMACSEC_BASE + 0x0000021C)
#define NBL_UMACSEC_ETH_EN		(NBL_PPE_UMACSEC_BASE + 0x00000220)
#define NBL_UMACSEC_ETH_CNT		(NBL_PPE_UMACSEC_BASE + 0x0000022C)
#define NBL_UMACSEC_SC(_i)		(NBL_PPE_UMACSEC_BASE + 0x00001000 + (_i) * 16)
#define NBL_UMACSEC_SA(_i)		(NBL_PPE_UMACSEC_BASE + 0x00002000 + (_i) * 64)
#define NBL_UMACSEC_SA_PN(_i)		(NBL_PPE_UMACSEC_BASE + 0x00003000 + (_i) * 8)
#define NBL_UMACSEC_BTM(_i)		(NBL_PPE_UMACSEC_BASE + 0x00003800 + (_i) * 32)

/* dmacsec */
#define NBL_DMACSEC_MODE		(NBL_PPE_DMACSEC_BASE + 0x00000354)
#define NBL_DMACSEC_ID0_EN		(NBL_PPE_DMACSEC_BASE + 0x00000358)
#define NBL_DMACSEC_ID1_EN		(NBL_PPE_DMACSEC_BASE + 0x0000035C)
#define NBL_DMACSEC_ID2_EN		(NBL_PPE_DMACSEC_BASE + 0x00000360)
#define NBL_DMACSEC_ID3_EN		(NBL_PPE_DMACSEC_BASE + 0x00000364)
#define NBL_DMACSEC_FS(_i)		(NBL_PPE_DMACSEC_BASE + 0x00001000 + (_i) * 32)
#define NBL_DMACSEC_SC(_i)		(NBL_PPE_DMACSEC_BASE + 0x00002000 + (_i) * 4)
#define NBL_DMACSEC_SA(_i)		(NBL_PPE_DMACSEC_BASE + 0x00004000 + (_i) * 64)
#define NBL_DMACSEC_SA_PN(_i)		(NBL_PPE_DMACSEC_BASE + 0x00004a00 + (_i) * 8)

#pragma pack()

#endif
