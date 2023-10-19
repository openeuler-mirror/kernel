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

struct udma_query_version {
	uint16_t udma_vendor_id;
	uint16_t udma_hw_version;
	uint32_t rsv[5];
};

struct udma_query_fw_info {
	uint32_t fw_ver;
	uint32_t rsv[5];
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

#define UDMA_1US_CFG 999

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

/* CMQ command */
enum udma_opcode_type {
	UDMA_QUERY_FW_VER				= 0x0001,
	UDMA_OPC_QUERY_HW_ID				= 0x7032,
	UDMA_OPC_QUERY_HW_VER				= 0x8000,
	UDMA_OPC_CFG_GLOBAL_PARAM			= 0x8001,
	UDMA_OPC_QUERY_FUNC_INFO			= 0x8407,
	UDMA_OPC_QUERY_PF_CAPS_NUM			= 0x8408,
	UDMA_OPC_QUERY_MB_ST				= 0x8505,
	UDMA_SWITCH_PARAMETER_CFG			= 0x1033,
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

#define QUERY_PF_CAPS_C_NUM_PDS_S 0
#define QUERY_PF_CAPS_C_NUM_PDS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_C_CAP_FLAGS_S 20
#define QUERY_PF_CAPS_C_CAP_FLAGS_M GENMASK(31, 20)

#define QUERY_PF_CAPS_C_NUM_CQS_S 0
#define QUERY_PF_CAPS_C_NUM_CQS_M GENMASK(19, 0)

#define QUERY_PF_CAPS_C_MAX_GID_S 20
#define QUERY_PF_CAPS_C_MAX_GID_M GENMASK(28, 20)

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

#endif /* _UDMA_HW_H */
