/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_mpu_tc_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef NIC_MPU_TC_CMD_DEFS_H
#define NIC_MPU_TC_CMD_DEFS_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#endif

#include "nic_cfg_comm.h"

#define TCAM_KEY_MEM_PAD_2BYTE 2
#define TCAM_KEY_MEM_PAD_ALIGN_4BYTE 4
#define SHIFT_16 16

#define TCAM_INVLD_INDEX 0xFFFF

enum tcam_clock_gating_ops {
	TCAM_CLOCK_GATING_OPS_GET,
	TCAM_CLOCK_GATING_OPS_SET,
	TCAM_CLOCK_GATING_OPS_MAX
};

enum tcam_clock_gating_status {
	TCAM_CLOCK_GATING_DISABLED,
	TCAM_CLOCK_GATING_ENABLED
};

/* Action address in struct hinic5_tc_default_action_info */
#define ACTION_REG_TX1_1 0
#define ACTION_REG_TX1_2 1
#define ACTION_REG_TX1_3 2
#define ACTION_REG_TX2_1 3
#define ACTION_REG_TX2_2 4
#define ACTION_REG_TX2_3 5
#define ACTION_REG_RX1 6
#define ACTION_REG_RX2 7
#define ACTION_REG_RX3 8

/* Default ACTION address in corresponding register */
enum hinic5_tc_default_action_addr {
	HINIC5_TC_DEFAULT_ACTION_ADDR_TX1 = 0, /**< tx default action1 */
	HINIC5_TC_DEFAULT_ACTION_ADDR_TX2, /**< tx default action2 */
	HINIC5_TC_DEFAULT_ACTION_ADDR_RX, /**< rx default action */
	HINIC5_TC_DEFAULT_ACTION_ADDR_MAX,
};

enum hinic5_tc_default_action_ops {
	HINIC5_TC_DEFAULT_ACTION_OPS_DROP = 0,
	HINIC5_TC_DEFAULT_ACTION_OPS_UPCALL,
	HINIC5_TC_DEFAULT_ACTION_OPS_SHOW,
	HINIC5_TC_DEFAULT_ACTION_OPS_PORT,
	HINIC5_TC_DEFAULT_ACTION_OPS_MAX,
};

enum hinic5_tc_cfg_rule_ops {
	HINIC5_TC_CFG_RULE_OPS_DEL,
	HINIC5_TC_CFG_RULE_OPS_ADD
};

enum pfe_cnt_ops {
	PFE_CNT_OPS_GET,
	PFE_CNT_OPS_RESET,
	PFE_CNT_OPS_MAX
};

/* TCAM 3 frequency modes: 1:500MHz, 2:250MHz, 3:125MHz */
#define MAX_PFE_TCAM_FREQ_MODE_NUM 3

enum pfe_tcam_freq_ops {
	PFE_TCAM_FREQ_OPS_GET,
	PFE_TCAM_FREQ_OPS_SET,
	PFE_TCAM_FREQ_OPS_MAX
};

enum hinic5_tc_vxlan_tbl_cfg_ops {
	HINIC5_TC_VXLAN_TBL_CFG_OPS_DEL,
	HINIC5_TC_VXLAN_TBL_CFG_OPS_ADD,
	HINIC5_TC_VXLAN_TBL_CFG_OPS_GET
};

enum pfe_tcam_cfg_ops {
	PFE_TCAM_CFG_OPS_DEL,
	PFE_TCAM_CFG_OPS_ADD,
	PFE_TCAM_CFG_OPS_GROUP,
	PFE_TCAM_CFG_OPS_GET
};

#define PFE_VTEP_TBL_IP_SIZE 4
#define PFE_VTEP_TBL_IP_NUM 8

enum pfe_vtep_ops {
	PFE_VTEP_OPS_DEL,
	PFE_VTEP_OPS_ADD,
	PFE_VTEP_OPS_GET,
	PFE_VTEP_OPS_MAX,
};

enum pfe_aging_tbl_ops {
	PFE_AGING_TBL_GET,
	PFE_AGING_TBL_SET,
	PFE_AGING_TBL_STATUS,
	PFE_AGING_TBL_CHECK,
	PFE_AGING_TBL_MAX
};

/* action flag[9 : 0], queue bit 9, decap bit 0 */
enum hinic5_tc_action_flag {
	HINIC5_TC_ACTION_VXLAN_DECAP = 0,
	HINIC5_TC_ACTION_VXLAN_ENCAP,
	HINIC5_TC_ACTION_FLOW_UPCALL,
	HINIC5_TC_ACTION_FLOW_VLAN_POP,
	HINIC5_TC_ACTION_FLOW_VLAN_PUSH,
	HINIC5_TC_ACTION_FLOW_OUTPUT,
	HINIC5_TC_ACTION_FLOW_COUNT,
	HINIC5_TC_ACTION_FLOW_DROP,
	HINIC5_TC_ACTION_FLOW_MARK,
	HINIC5_TC_ACTION_FLOW_QUEUE,
	HINIC5_TC_ACTION_TYPE_MAX
};

enum hinic5_tc_pfe_cfg_flag {
	HINIC5_TC_PFE_GLB_MODE_CFG_REG = 0,
	HINIC5_TC_PFE_GLB_MODE_CFG_REG2,
	HINIC5_TC_PFE_CFG_MAX
};

enum pfe_cfg_ops_profile {
	PFE_CFG_OPS_PROFILE_OPTION = 0,
	PFE_CFG_OPS_PROFILE_SHIFT,
	PFE_CFG_OPS_PROFILE_SHIFT2,
	PFE_CFG_OPS_PROFILE_MAX
};

#endif /* NIC_MPU_TC_CMD_DEFS_H */