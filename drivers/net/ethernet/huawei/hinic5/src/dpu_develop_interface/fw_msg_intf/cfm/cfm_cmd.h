/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cfm_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : cfm cmd define
 */

#ifndef CFM_CMD_H
#define CFM_CMD_H

#define HINIC5_BOND_MSG_TIMEOUT_MS   (60000)

/* TODO: bond ccp qos to be integrated into the same enum */
typedef enum tag_cfm_mpu_drv_cmd {
	CFM_MPU_CMD_BOND_CREATE = 0,
	CFM_MPU_CMD_BOND_DELETE = 1,
	CFM_MPU_CMD_BOND_SET = 2,
	CFM_MPU_CMD_BOND_GET = 3,
	CFM_MPU_CMD_BOND_CFG = 4, /* bond config and query */
	CFM_MPU_CMD_BOND_LINK_INFO_GET = 5,
	CFM_MPU_CMD_PASS_ARP_PKT = 6, /* send arp packet through mpu */
	CFM_MPU_CMD_CCP_COMM_PARA_GET = 16,
	CFM_MPU_CMD_CCP_ALGO_PARA_GET = 17,
	CFM_MPU_CMD_QOS_VPORT_MAPPING_SET = 32,
	CFM_MPU_CMD_QOS_VPORT_SHAPER_SET = 33,
	CFM_MPU_CMD_QOS_VPORT_SHAPER_CLR = 34,
	CFM_MPU_CMD_QOS_VPORT_SHAPER_GET = 35, /* qos_base config and query */
	CFM_MPU_CMD_QOS_CC_L2D_SET = 36, /* CFM QoS CC L2DMEM write operation */
	CFM_MPU_CMD_QOS_CC_L2D_GET = 37, /* CFM QoS CC L2DMEM read operation */
	CFM_MPU_CMD_EXTEND_END = 64
} cfm_mpu_drv_cmd_e;

typedef enum tag_cfm_npu_cmdq_cmd {
	CFM_NPU_CMD_CCP_CTX = 0,
	CFM_NPU_CMD_CCP_STATISTICS = 1,
	CFM_NPU_CMD_HMM_OPS = 2,
	CFM_NPU_CMD_MAX,
} cfm_npu_drv_cmd_e;

#endif