/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UDMA_HW_H
#define _UDMA_HW_H

#include "urma/ubcore_types.h"

extern bool dfx_switch;

struct udma_query_version {
	uint16_t udma_vendor_id;
	uint16_t udma_hw_version;
	uint32_t rsv[5];
};

struct udma_query_fw_info {
	uint32_t fw_ver;
	uint32_t rsv[5];
};

struct udma_func_clear {
	uint32_t rst_funcid_en;
	uint32_t func_done;
	uint32_t rsv[4];
};

struct udma_pf_func_info {
	uint32_t own_func_num;
	uint32_t own_mac_id;
	uint32_t rsv[4];
};

struct udma_cmq_req {
	uint32_t data[6];
};

struct udma_vf_switch {
	uint32_t udma_sel;
	uint32_t fun_id;
	uint32_t cfg;
	uint32_t resv1;
	uint32_t resv2;
	uint32_t resv3;
};

struct udma_hw_id_query_cmq {
	uint8_t		chip_id;
	uint8_t		die_id;
	uint8_t		mac_id;
	uint8_t		reserved;
	uint32_t	func_id;
	uint32_t	rsv[4];
};

struct udma_query_oor_cmq {
	uint8_t		oor_en;
	uint8_t		reorder_cq_buffer_en;
	uint8_t		reorder_cap;
	uint8_t		reorder_cq_shift;
	uint32_t	on_flight_size;
	uint8_t		dynamic_ack_timeout;
	uint8_t		rsv[15];
};

#define UDMA_MAX_MTT_SEGS		0x1000000
#define UDMA_MAX_SRQWQE_SEGS		0x1000000
#define UDMA_MAX_IDX_SEGS		0x1000000
#define UDMA_MTT_ENTRY_SZ		64
#define UDMA_EID_SIZE_IDX		4

#define UDMA_PBL_HOP_NUM		2
#define UDMA_EQE_HOP_NUM		2

#define UDMA_QPC_TIMER_ENTRY_SZ		PAGE_SIZE
#define UDMA_CQC_TIMER_ENTRY_SZ		PAGE_SIZE

#define UDMA_EQE_SIZE			0x40
#define UDMA_EQ_OVER_IGNORE_0		0
#define UDMA_EQ_COALESCE_0		0
#define UDMA_EQ_ALWAYS_ARMED		3
#define UDMA_EQN_M			GENMASK(23, 0)

#define UDMA_CEQ_CEQE_OWNER_S		31
#define UDMA_AEQ_AEQE_OWNER_S		31

#define NIC_ICL_SWITCH_CMD_UDMA_SEL_SHIFT	0
#define NIC_ICL_SWITCH_CMD_UDMA_SEL	BIT(NIC_ICL_SWITCH_CMD_UDMA_SEL_SHIFT)

#define VF_SWITCH_DATA_FUN_ID_VF_ID_S 3
#define VF_SWITCH_DATA_FUN_ID_VF_ID_M GENMASK(10, 3)

#define VF_SWITCH_DATA_CFG_ALW_LPBK_S 1
#define VF_SWITCH_DATA_CFG_ALW_LCL_LPBK_S 2
#define VF_SWITCH_DATA_CFG_ALW_DST_OVRD_S 3

#define CMQ_REQ_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

/* Fields of UDMA_OPC_CFG_GLOBAL_PARAM */
#define CFG_GLOBAL_PARAM_1US_CYCLES CMQ_REQ_FIELD_LOC(9, 0)
#define CFG_GLOBAL_PARAM_UDP_PORT CMQ_REQ_FIELD_LOC(31, 16)

#define FUNC_CLEAR_RST_FUN_DONE_S 0
#define UDMA_FUNC_CLEAR_TIMEOUT_MSECS	(249 * 2 * 100)
#define UDMA_READ_FUNC_CLEAR_FLAG_INTERVAL	40
#define UDMA_READ_FUNC_CLEAR_FLAG_FAIL_WAIT	20

#define UDMA_HW_RST_TIMEOUT		1000
#define UDMA_HW_RST_UNINT_DELAY		100

#define UDMA_HW_RST_COMPLETION_WAIT	20

#define UDMA_FUNC_IRQ_RSV 2
#define UDMA_1US_CFG 999

#define UDMA_EXT_LLM_ENTRY_SZ		8
#define UDMA_EXT_LLM_MAX_DEPTH		4096

#define UDMA_BA_PG_SZ_SUPPORTED_256K	6
#define UDMA_BA_PG_SZ_SUPPORTED_16K	2

#define UDMA_QUERY_PORT_INFO	1
#define SPEED_100G  100000
#define SPEED_200G  200000

#define UDMA_QUERY_COUNTER 8
#define UDMA_QX_RESP 1
#define UDMA_TX_RESP 3
#define UDMA_TX_ERR_RESP 4

/* Fields of UDMA_OPC_EXT_CFG */
#define EXT_CFG_VF_ID CMQ_REQ_FIELD_LOC(31, 0)
#define EXT_CFG_QP_PI_INDEX CMQ_REQ_FIELD_LOC(45, 32)
#define EXT_CFG_QP_PI_NUM CMQ_REQ_FIELD_LOC(63, 48)
#define EXT_CFG_QP_NUM CMQ_REQ_FIELD_LOC(87, 64)
#define EXT_CFG_QP_INDEX CMQ_REQ_FIELD_LOC(119, 96)
#define EXT_CFG_LLM_INDEX CMQ_REQ_FIELD_LOC(139, 128)
#define EXT_CFG_LLM_NUM CMQ_REQ_FIELD_LOC(156, 144)

#define CFG_LLM_A_BA_L CMQ_REQ_FIELD_LOC(31, 0)
#define CFG_LLM_A_BA_H CMQ_REQ_FIELD_LOC(63, 32)
#define CFG_LLM_A_DEPTH CMQ_REQ_FIELD_LOC(76, 64)
#define CFG_LLM_A_PG_SZ CMQ_REQ_FIELD_LOC(83, 80)
#define CFG_LLM_A_INIT_EN CMQ_REQ_FIELD_LOC(84, 84)
#define CFG_LLM_A_HEAD_BA_L CMQ_REQ_FIELD_LOC(127, 96)
#define CFG_LLM_A_HEAD_BA_H CMQ_REQ_FIELD_LOC(147, 128)
#define CFG_LLM_A_HEAD_NXT_PTR CMQ_REQ_FIELD_LOC(159, 148)
#define CFG_LLM_A_HEAD_PTR CMQ_REQ_FIELD_LOC(171, 160)
#define CFG_LLM_B_TAIL_BA_L CMQ_REQ_FIELD_LOC(31, 0)
#define CFG_LLM_B_TAIL_BA_H CMQ_REQ_FIELD_LOC(63, 32)
#define CFG_LLM_B_TAIL_PTR CMQ_REQ_FIELD_LOC(75, 64)

/*
 * Fields of UDMA_OPC_QUERY_PF_RES, UDMA_OPC_QUERY_VF_RES
 * and UDMA_OPC_ALLOC_VF_RES
 */
#define FUNC_RES_A_VF_ID CMQ_REQ_FIELD_LOC(7, 0)
#define FUNC_RES_A_QPC_BT_INDEX CMQ_REQ_FIELD_LOC(42, 32)
#define FUNC_RES_A_QPC_BT_NUM CMQ_REQ_FIELD_LOC(59, 48)
#define FUNC_RES_A_SRQC_BT_INDEX CMQ_REQ_FIELD_LOC(72, 64)
#define FUNC_RES_A_SRQC_BT_NUM CMQ_REQ_FIELD_LOC(89, 80)
#define FUNC_RES_A_CQC_BT_INDEX CMQ_REQ_FIELD_LOC(104, 96)
#define FUNC_RES_A_CQC_BT_NUM CMQ_REQ_FIELD_LOC(121, 112)
#define FUNC_RES_A_MPT_BT_INDEX CMQ_REQ_FIELD_LOC(136, 128)
#define FUNC_RES_A_MPT_BT_NUM CMQ_REQ_FIELD_LOC(153, 144)
#define FUNC_RES_A_EQC_BT_INDEX CMQ_REQ_FIELD_LOC(168, 160)
#define FUNC_RES_A_EQC_BT_NUM CMQ_REQ_FIELD_LOC(185, 176)
#define FUNC_RES_B_SMAC_NUM CMQ_REQ_FIELD_LOC(48, 40)
#define FUNC_RES_B_SGID_NUM CMQ_REQ_FIELD_LOC(80, 72)
#define FUNC_RES_B_QID_INDEX CMQ_REQ_FIELD_LOC(105, 96)
#define FUNC_RES_B_QID_NUM CMQ_REQ_FIELD_LOC(122, 112)
#define FUNC_RES_V_QID_NUM CMQ_REQ_FIELD_LOC(115, 112)

#define FUNC_RES_B_SCCC_BT_INDEX CMQ_REQ_FIELD_LOC(136, 128)
#define FUNC_RES_B_SCCC_BT_NUM CMQ_REQ_FIELD_LOC(145, 137)
#define FUNC_RES_B_GMV_BT_INDEX CMQ_REQ_FIELD_LOC(167, 160)
#define FUNC_RES_B_GMV_BT_NUM CMQ_REQ_FIELD_LOC(176, 168)
#define FUNC_RES_V_GMV_BT_NUM CMQ_REQ_FIELD_LOC(184, 176)

/* Fields of UDMA_OPC_QUERY_PF_TIMER_RES */
#define PF_TIMER_RES_QPC_ITEM_NUM CMQ_REQ_FIELD_LOC(60, 48)
#define PF_TIMER_RES_CQC_ITEM_NUM CMQ_REQ_FIELD_LOC(91, 80)

/* Fields of UDMA_QUERY_RAM_ECC */
#define QUERY_RAM_ECC_1BIT_ERR CMQ_REQ_FIELD_LOC(31, 0)
#define QUERY_RAM_ECC_RES_TYPE CMQ_REQ_FIELD_LOC(63, 32)
#define QUERY_RAM_ECC_TAG CMQ_REQ_FIELD_LOC(95, 64)

enum {
	UDMA_CMD_FLAG_IN = BIT(0),
	UDMA_CMD_FLAG_NEXT = BIT(2),
	UDMA_CMD_FLAG_WR = BIT(3),
	UDMA_CMD_FLAG_NO_INTR = BIT(4),
};

enum udma_cmd_return_status {
	CMD_EXEC_SUCCESS	= 0,
	CMD_NOT_EXIST		= 2,
};

enum {
	QP_ST_RST	= 0,
	QP_ST_ERR	= 6,
};

/* CMQ command */
enum udma_opcode_type {
	UDMA_QUERY_FW_VER				= 0x0001,
	UDMA_OPC_CFG_DCQCN_PARAM			= 0x1A80,
	UDMA_OPC_CFG_LDCP_PARAM				= 0x1A81,
	UDMA_OPC_CFG_HC3_PARAM				= 0x1A82,
	UDMA_OPC_CFG_DIP_PARAM				= 0x1A83,
	UDMA_OPC_QUERY_HW_ID				= 0x7032,
	UDMA_OPC_QUERY_HW_VER				= 0x8000,
	UDMA_OPC_CFG_GLOBAL_PARAM			= 0x8001,
	UDMA_OPC_QUERY_PF_RES				= 0x8400,
	UDMA_OPC_ALLOC_VF_RES				= 0x8401,
	UDMA_OPC_CFG_EXT_LLM				= 0x8403,
	UDMA_OPC_QUERY_PF_TIMER_RES			= 0x8406,
	UDMA_OPC_QUERY_FUNC_INFO			= 0x8407,
	UDMA_OPC_QUERY_PF_CAPS_NUM			= 0x8408,
	UDMA_OPC_CFG_ENTRY_SIZE				= 0x8409,
	UDMA_OPC_QUERY_VF_CAPS_NUM			= 0x8410,
	UDMA_OPC_POST_MB				= 0x8504,
	UDMA_OPC_QUERY_MB_ST				= 0x8505,
	UDMA_OPC_CFG_BT_ATTR				= 0x8506,
	UDMA_OPC_FUNC_CLEAR				= 0x8508,
	UDMA_OPC_CLEAR_EXTDB_LIST_INFO			= 0x850d,
	UDMA_OPC_QUERY_VF_RES				= 0x850e,
	UDMA_OPC_CFG_GMV_BT				= 0x8510,
	UDMA_OPC_EXT_CFG				= 0x8512,
	UDMA_QUERY_RAM_ECC				= 0x8513,
	UDMA_SWITCH_PARAMETER_CFG			= 0x1033,
	UDMA_QUERY_OOR_CAPS				= 0xA002,
	UDMA_OPC_DEID_TBL_ADD				= 0xA110,
	UDMA_OPC_CFG_GMV_TBL				= 0xA140,
	UDMA_OPC_CFG_POE_ADDR				= 0x801B,
	UDMA_OPC_CFG_POE_ATTR				= 0x801C,
	UDMA_OPC_QUERY_COUNTER				= 0x8206,
	UDMA_OPC_QUERY_PORT_INFO			= 0x7104,
};

#define UDMA_QUERY_PF_CAPS_CMD_NUM 5
struct udma_query_pf_caps_a {
	uint8_t		number_ports;
	uint8_t		local_ca_ack_delay;
	uint16_t	max_sq_sg;
	uint16_t	max_sq_inline;
	uint16_t	max_rq_sg;
	uint32_t	max_extend_sg;
	uint16_t	num_qpc_timer;
	uint16_t	num_cqc_timer;
	uint16_t	max_srq_sges;
	uint8_t		num_aeq_vectors;
	uint8_t		num_other_vectors;
	uint8_t		max_sq_desc_sz;
	uint8_t		max_rq_desc_sz;
	uint8_t		max_srq_desc_sz;
	uint8_t		cqe_sz;
};

struct udma_query_pf_caps_b {
	uint8_t		mtpt_entry_sz;
	uint8_t		irrl_entry_sz;
	uint8_t		trrl_entry_sz;
	uint8_t		cqc_entry_sz;
	uint8_t		srqc_entry_sz;
	uint8_t		idx_entry_sz;
	uint8_t		sccc_sz;
	uint8_t		max_mtu;
	uint16_t	qpc_sz;
	uint16_t	qpc_timer_entry_sz;
	uint16_t	cqc_timer_entry_sz;
	uint8_t		min_cqes;
	uint8_t		min_wqes;
	uint32_t	page_size_cap;
	uint8_t		pkey_table_len;
	uint8_t		phy_num_uars;
	uint8_t		ctx_hop_num;
	uint8_t		pbl_hop_num;
};

struct udma_query_pf_caps_c {
	uint32_t cap_flags_num_pds;
	uint32_t max_gid_num_cqs;
	uint32_t cq_depth;
	uint32_t num_mrws;
	uint32_t ord_num_qps;
	uint16_t sq_depth;
	uint16_t rq_depth;
};

struct udma_query_pf_caps_d {
	uint32_t wq_hop_num_max_srqs;
	uint16_t srq_depth;
	uint16_t cap_flags_ex;
	uint32_t num_ceqs_ceq_depth;
	uint32_t arm_st_aeq_depth;
	uint32_t num_uars_rsv_pds;
	uint32_t rsv_uars_rsv_qps;
};

struct udma_query_pf_caps_e {
	uint32_t chunk_size_shift_rsv_mrws;
	uint32_t rsv_cqs;
	uint32_t rsv_srqs;
	uint32_t rsv_lkey;
	uint16_t ceq_max_cnt;
	uint16_t ceq_period;
	uint16_t aeq_max_cnt;
	uint16_t aeq_period;
};

#define UDMA_EXT_LLM_ENTRY(addr, id) (((id) << (64 - 12)) | ((addr) >> 12))
#define UDMA_EXT_LLM_MIN_PAGES(que_num) ((que_num) * 4 + 2)

#define QUERY_PF_CAPS_C_NUM_PDS_S 0
#define QUERY_PF_CAPS_C_NUM_PDS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_C_CAP_FLAGS_S 20
#define QUERY_PF_CAPS_C_CAP_FLAGS_M GENMASK(31, 20)

#define QUERY_PF_CAPS_C_NUM_CQS_S 0
#define QUERY_PF_CAPS_C_NUM_CQS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_C_CQ_DEPTH_S 0
#define QUERY_PF_CAPS_C_CQ_DEPTH_M GENMASK(22, 0)

#define QUERY_PF_CAPS_C_NUM_MRWS_S 0
#define QUERY_PF_CAPS_C_NUM_MRWS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_C_NUM_QPS_S 0
#define QUERY_PF_CAPS_C_NUM_QPS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_C_MAX_ORD_S 20
#define QUERY_PF_CAPS_C_MAX_ORD_M GENMASK(27, 20)

#define QUERY_PF_CAPS_D_NUM_SRQS_S 0
#define QUERY_PF_CAPS_D_NUM_SRQS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_D_RQWQE_HOP_NUM_S 20
#define QUERY_PF_CAPS_D_RQWQE_HOP_NUM_M GENMASK(21, 20)

#define QUERY_PF_CAPS_D_EX_SGE_HOP_NUM_S 22
#define QUERY_PF_CAPS_D_EX_SGE_HOP_NUM_M GENMASK(23, 22)

#define QUERY_PF_CAPS_D_SQWQE_HOP_NUM_S 24
#define QUERY_PF_CAPS_D_SQWQE_HOP_NUM_M GENMASK(25, 24)

#define QUERY_PF_CAPS_D_CONG_TYPE_S 26
#define QUERY_PF_CAPS_D_CONG_TYPE_M GENMASK(29, 26)

/* default cap configuration for vf only */
#define DEFAULT_AEQ_ARM_ST 0x3
#define DEFAULT_CEQ_ARM_ST 0x3
#define DEFAULT_CEQ_MAX_CNT 0x1
#define DEFAULT_CEQ_PERIOD 0x10
#define DEFAULT_AEQ_MAX_CNT 0x1
#define DEFAULT_AEQ_PERIOD 0x10

#define QUERY_PF_CAPS_D_CEQ_DEPTH_S 0
#define QUERY_PF_CAPS_D_CEQ_DEPTH_M GENMASK(21, 0)

#define QUERY_PF_CAPS_D_NUM_CEQS_S 22
#define QUERY_PF_CAPS_D_NUM_CEQS_M GENMASK(31, 22)

#define QUERY_PF_CAPS_D_AEQ_DEPTH_S 0
#define QUERY_PF_CAPS_D_AEQ_DEPTH_M GENMASK(21, 0)

#define QUERY_PF_CAPS_D_AEQ_ARM_ST_S 22
#define QUERY_PF_CAPS_D_AEQ_ARM_ST_M GENMASK(23, 22)

#define QUERY_PF_CAPS_D_CEQ_ARM_ST_S 24
#define QUERY_PF_CAPS_D_CEQ_ARM_ST_M GENMASK(25, 24)

#define QUERY_PF_CAPS_D_RSV_PDS_S 0
#define QUERY_PF_CAPS_D_RSV_PDS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_D_NUM_UARS_S 20
#define QUERY_PF_CAPS_D_NUM_UARS_M GENMASK(27, 20)

#define QUERY_PF_CAPS_D_RSV_QPS_S 0
#define QUERY_PF_CAPS_D_RSV_QPS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_D_RSV_UARS_S 20
#define QUERY_PF_CAPS_D_RSV_UARS_M GENMASK(27, 20)

#define QUERY_PF_CAPS_E_RSV_MRWS_S 0
#define QUERY_PF_CAPS_E_RSV_MRWS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_E_CHUNK_SIZE_SHIFT_S 20
#define QUERY_PF_CAPS_E_CHUNK_SIZE_SHIFT_M GENMASK(31, 20)

#define QUERY_PF_CAPS_E_RSV_CQS_S 0
#define QUERY_PF_CAPS_E_RSV_CQS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_E_RSV_SRQS_S 0
#define QUERY_PF_CAPS_E_RSV_SRQS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_E_RSV_LKEYS_S 0
#define QUERY_PF_CAPS_E_RSV_LKEYS_M GENMASK(19, 0)

/* Fields of UDMA_OPC_CFG_BT_ATTR */
#define CFG_BT_QPC_BA_PGSZ CMQ_REQ_FIELD_LOC(3, 0)
#define CFG_BT_QPC_BUF_PGSZ CMQ_REQ_FIELD_LOC(7, 4)
#define CFG_BT_QPC_HOPNUM CMQ_REQ_FIELD_LOC(9, 8)
#define CFG_BT_SRQC_BA_PGSZ CMQ_REQ_FIELD_LOC(35, 32)
#define CFG_BT_SRQC_BUF_PGSZ CMQ_REQ_FIELD_LOC(39, 36)
#define CFG_BT_SRQC_HOPNUM CMQ_REQ_FIELD_LOC(41, 40)
#define CFG_BT_CQC_BA_PGSZ CMQ_REQ_FIELD_LOC(67, 64)
#define CFG_BT_CQC_BUF_PGSZ CMQ_REQ_FIELD_LOC(71, 68)
#define CFG_BT_CQC_HOPNUM CMQ_REQ_FIELD_LOC(73, 72)
#define CFG_BT_MPT_BA_PGSZ CMQ_REQ_FIELD_LOC(99, 96)
#define CFG_BT_MPT_BUF_PGSZ CMQ_REQ_FIELD_LOC(103, 100)
#define CFG_BT_MPT_HOPNUM CMQ_REQ_FIELD_LOC(105, 104)
#define CFG_BT_SCCC_BA_PGSZ CMQ_REQ_FIELD_LOC(131, 128)
#define CFG_BT_SCCC_BUF_PGSZ CMQ_REQ_FIELD_LOC(135, 132)
#define CFG_BT_SCCC_HOPNUM CMQ_REQ_FIELD_LOC(137, 136)

/* Fields of UDMA_OPC_CFG_ENTRY_SIZE */
#define CFG_HEM_ENTRY_SIZE_TYPE CMQ_REQ_FIELD_LOC(31, 0)
enum {
	UDMA_CFG_QPC_SIZE = BIT(0),
	UDMA_CFG_SCCC_SIZE = BIT(1),
};

#define CFG_HEM_ENTRY_SIZE_VALUE CMQ_REQ_FIELD_LOC(191, 160)

#define CFG_GMV_BT_BA_L CMQ_REQ_FIELD_LOC(31, 0)
#define CFG_GMV_BT_BA_H CMQ_REQ_FIELD_LOC(51, 32)
#define CFG_GMV_BT_IDX CMQ_REQ_FIELD_LOC(95, 64)
#define CFG_GMV_BT_VF_ID CMQ_REQ_FIELD_LOC(103, 96)

#define UDMA_INT_NAME_LEN		32

#define SGID_H_SHIFT 12

struct udma_poe_cfg_addr_cmq {
	uint32_t channel_id;
	uint32_t poe_addr_l;
	uint32_t poe_addr_h;
	uint32_t rsv[3];
};

struct udma_poe_cfg_attr_cmq {
	uint32_t channel_id;
	uint32_t rsv_en_outstd;
	uint32_t rsv[4];
};

struct udma_port_info_cmq {
	uint32_t speed;
	uint8_t query_type;
	uint8_t rsv[19];
};

struct udma_rx_cnt_cmd_data {
	uint64_t rsv;
	uint64_t pkt_rx_cnt;
	uint64_t err_pkt_rx_cnt;
};

struct udma_tx_cnt_cmd_data {
	uint64_t rsv[2];
	uint64_t pkt_tx_cnt;
};

struct udma_tx_err_cnt_cmd_data {
	uint64_t err_pkt_tx_cnt;
	uint64_t rsv[2];
};

#endif /* _UDMA_HW_H */
