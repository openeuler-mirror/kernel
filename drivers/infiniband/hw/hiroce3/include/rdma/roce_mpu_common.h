/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_MPU_COMMON_H
#define ROCE_MPU_COMMON_H

#include "mpu_cmd_base_defs.h"

enum {
	/* FUNC CFG */
	ROCE_MPU_CMD_SET_FUNC_STATE = 0,
	ROCE_MPU_CMD_SET_CPU_ENDIAN,
	ROCE_MPU_CMD_GET_CFG_INFO,
	ROCE_MPU_CMD_DEL_FUNC_RES,
	ROCE_MPU_CMD_GET_FUNC_TABLE,
	ROCE_MPU_CMD_ADD_MAC = 10,
	ROCE_MPU_CMD_DEL_MAC,
	ROCE_MPU_CMD_ADD_IPSU_MAC,
	ROCE_MPU_CMD_DEL_IPSU_MAC,
	ROCE_MPU_CMD_GET_MAC_VNI,

	/* BOND */
	ROCE_MPU_CMD_BOND_SET_STATE = 20,
	ROCE_MPU_CMD_BOND_GET_ER_FWD_ID,
	ROCE_MPU_CMD_BOND_SET_ER_FWD_ID,
	ROCE_MPU_CMD_BOND_ER_FWD_ID_COMBINE,
	ROCE_MPU_CMD_BOND_ER_FWD_ID_COMPACT,
	ROCE_MPU_CMD_GET_GROUP_ID,

	/* CC */
	ROCE_MPU_CMD_CC_CFG_CCF_PARAM = 40,
	ROCE_MPU_CMD_CC_CFG_DCQCN_PARAM,
	ROCE_MPU_CMD_CC_CFG_IPQCN_PARAM,
	ROCE_MPU_CMD_CC_CFG_LDCP_PARAM,
	ROCE_MPU_CMD_CC_SET_BW_CTRL,
	ROCE_MPU_CMD_CC_QUERY_BW_CTRL,

	/* DFX */
	ROCE_MPU_CMD_DFX_CACHE_OUT = 55,
	ROCE_MPU_CMD_DFX_SET_CAP_CFG,
	ROCE_MPU_CMD_DFX_GET_CAP_CFG,
	ROCE_MPU_CMD_DFX_READ_CAP_CTR,
	ROCE_MPU_CMD_DFX_CLEAR_CAP_CTR,

	/* ULP */
	ROCE_MPU_CMD_ULP_AA_SET_DD_CFG = 128,
	ROCE_MPU_CMD_ULP_AA_CTRL_READY,
	ROCE_MPU_CMD_ULP_AA_SWITCH_IO,
	ROCE_MPU_CMD_ULP_AA_FAKE_DATA,
	ROCE_MPU_CMD_ULP_AA_CLAER_ACT_CTRL_BMP,

	ROCE_MPU_CMD_MAX
};

#define MAX_ROCE_PHY_PORT 8

/* *********************** Func cmd between driver and mpu ************************** */
struct roce_set_func_state_cmd {
	struct comm_info_head head;

	u16 func_id;
	u8 func_en;
	u8 tag;
};

struct roce_get_func_table_cmd {
	struct comm_info_head head;

	u16 func_id;
	u8 rsvd[2];
};

struct roce_get_func_table_rsp {
	struct comm_info_head head;
	u32 func_tbl_value;
};

struct roce_get_cfg_info_cmd {
	struct comm_info_head head;

	u16 func_id;
	u8 rsvd[2];
};

struct roce_get_cfg_info_resp {
	struct comm_info_head head;

	u8 scence_id;
	u8 lb_en;
	u8 lb_mode;
	u8 container_mode;

	u8 fake_en;
	u8 pf_start_bit;
	u8 pf_end_bit;
	u8 page_bit;

	u8 port_num;
	u8 host_num;
	u16 rsvd;
};

struct roce_set_cpu_endian_cmd {
	struct comm_info_head head;

	u16 func_id;
	u8 cpu_endian;
	u8 rsvd;
};

struct roce_cfg_mac_cmd {
	struct comm_info_head head;

	u16 func_id;
	u16 rsvd;
	u16 er_fwd_id;
	u8 mac[6];
	u8 vni_en;
	u32 vlan_id;
};

struct roce_cfg_ipsu_mac_cmd {
	struct comm_info_head head;

	u16 func_id;
	u8 er_id;
	u8 vni_en; /* vni enable */
	u8 mac[6];
	u8 rsvd[2];
	u32 vlanid_vni;
};

struct vroce_mac_cfg_vni_info {
	struct comm_info_head head;
	u16 func_id;
	u16 rsvd;

	u32 vlan_vni	: 24;
	u32 vni_en	: 8;
};

/* ************************* Bond cmd between driver and mpu ************************* */
struct roce_bond_cfg_state_cmd {
	struct comm_info_head head;

	u16 func_id;
	u8 bond_en;
	u8 rsvd;
};

struct roce_bond_set_ipsu_mac_cmd {
	struct comm_info_head head;

	u16 func_id;
	u16 vlan_id;
	u16 er_fwd_id;
	u8 mac[6];
};

struct roce_bond_cfg_er_fwd_id_cmd {
	struct comm_info_head head;

	u16 func_id;
	u16 er_fwd_id;
	u32 bond_tbl_val;
};

struct roce_bond_combine_er_fwd_id_cmd {
	struct comm_info_head head;
	u16 func_id_src;
	u16 func_id_dst;
	u16 er_fwd_id;
	u8 rsvd[2];
};

struct roce_bond_compact_er_fwd_id_cmd {
	struct comm_info_head head;

	u16 func_id;
	u16 rsvd;
	u32 value; /* dw14 value */
};

/* ************************* CC cmd between driver and mpu ************************** */
struct roce_cc_cfg_param_cmd {
	struct comm_info_head head;
	u16 func_id;
	u16 rsvd;
	u32 param[4];
};

struct roce_cc_cfg_bw_ctrl_cmd {
	struct comm_info_head head;

	u16 func_id;
	u8 cmd;
	u8 rsvd;

	u8 color_type;
	u16 ptype;
	u8 hw_wred_mode;

	u32 cir;
	u32 pir;
	u32 cbs;
	u32 xbs;
	u32 cnp;
	u32 enable;
};

/* *************************** DFX cmd between driver and mpu ***************************** */
struct roce_dfx_cache_out_cmd {
	struct comm_info_head head;

	u16 func_idx;
	u8 cache_index;
	u8 rsvd;
};

struct roce_dfx_cfg_cap_param_cmd {
	struct comm_info_head head;
	u16 index;
	u16 rsvd;
	u32 param[4];
};

struct roce_dfx_cap_ctr_cmd {
	struct comm_info_head head;
	u16 index;
	u16 rsvd;
	u32 value;
};

#endif /* ROCE_MPU_COMMON_H */
