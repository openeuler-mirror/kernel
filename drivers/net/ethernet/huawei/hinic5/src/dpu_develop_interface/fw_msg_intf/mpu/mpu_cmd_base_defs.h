/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_cmd_base_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : MPU common definitions
 */
#ifndef MPU_CMD_BASE_DEFS_H
#define MPU_CMD_BASE_DEFS_H

#include "base_type.h"

typedef enum {
	RES_TYPE_FLUSH_BIT = 0, /* flush function reset flag bit */
	RES_TYPE_MQM, /* mqm function reset flag bit */
	RES_TYPE_SMF, /* smf function reset flag bit */
	RES_TYPE_PF_BW_CFG, /* bandwidth configuration function reset flag bit */

	RES_TYPE_COMM = 10, /* common function reset flag bit */
	RES_TYPE_COMM_MGMT_CH,  /* bandwidth configuration function reset flag bit,
				 * clear mbox and aeq, The RES_TYPE_COMM bit must be set
				 */
	RES_TYPE_COMM_CMD_CH,   /* bandwidth configuration function reset flag bit,
				 * clear cmdq and ceq, The RES_TYPE_COMM bit must be set
				 */
	RES_TYPE_NIC, /* nic function reset flag bit */
	RES_TYPE_OVS, /* ovs function reset flag bit */
	RES_TYPE_VBS, /* vbs function reset flag bit */
	RES_TYPE_ROCE, /* roce function reset flag bit */
	RES_TYPE_FC, /* fc function reset flag bit */
	RES_TYPE_TOE, /* toe function reset flag bit */
	RES_TYPE_IPSEC, /* ipsec function reset flag bit */
	RES_TYPE_SMF_CACHE_INVALID, /* smf cache invalid function reset flag bit */
	RES_TYPE_MAX, /* maximum function reset flag bit value */
} func_reset_flag_e; /* function reset flag, used to indicate which resource to clear */

#define DEVICE_TYPE_L2NIC                   0 /* L2NIC device */
#define DEVICE_TYPE_NVME                    1 /* nvme device */
#define DEVICE_TYPE_VIRTIO_NET              2 /* virtio net device */
#define DEVICE_TYPE_VIRTIO_BLK              3 /* virtio blk device */
#define DEVICE_TYPE_VIRTIO_VSOCK            4 /* virtio vsock device */
#define DEVICE_TYPE_VIRTIO_NET_TRANSITION   5 /* virtio net transition device */
#define DEVICE_TYPE_VIRTIO_BLK_TRANSITION   6 /* virtio blk transition device */
#define DEVICE_TYPE_VIRTIO_SCSI_TRANSITION  7 /* virtio scsi transition device */
#define DEVICE_TYPE_VIRTIO_HPC              8 /* virtio nhpc device */
#define DEVICE_TYPE_VIRTIO_FS               9 /* virtio fs device */

/**
 * @brief Check if device is virtio net device
 * @param device: device type
 * @return true or false
 */
#define MPU_DEVICE_IS_VIRTIO_NET(device) \
	(((device) == DEVICE_TYPE_VIRTIO_NET) || ((device) == DEVICE_TYPE_VIRTIO_NET_TRANSITION))

/**
 * @brief Check if device is virtio blk device
 * @param device: device type
 * @return true or false
 */
#define MPU_DEVICE_IS_VIRTIO_BLK(device) \
	(((device) == DEVICE_TYPE_VIRTIO_BLK) || ((device) == DEVICE_TYPE_VIRTIO_BLK_TRANSITION))

/**
 * @brief Check if device is virtio scsi device
 * @param device: device type
 * @return true or false
 */
#define MPU_DEVICE_IS_VIRTIO_SCSI(device) \
	((device) == DEVICE_TYPE_VIRTIO_SCSI_TRANSITION)

/**
 * @brief Check if device is virtio storage device
 * @param device: device type
 * @return true or false
 */
#define MPU_DEVICE_IS_VIRTIO_STORAGE(device) \
	(MPU_DEVICE_IS_VIRTIO_BLK(device) || MPU_DEVICE_IS_VIRTIO_SCSI(device))

/**
 * @brief Check if device is virtio device
 * @param device: device type
 * @return true or false
 */
#define MPU_DEVICE_IS_VIRTIO(device) \
	(MPU_DEVICE_IS_VIRTIO_NET(device) || MPU_DEVICE_IS_VIRTIO_BLK(device) || \
	 MPU_DEVICE_IS_VIRTIO_SCSI(device))

enum hinic5_svc_type {
	SVC_T_COMM = 0,
	SVC_T_NIC,
	SVC_T_OVS,
	SVC_T_ROCE,
	SVC_T_TOE,
	SVC_T_IOE,
	SVC_T_FC,
	SVC_T_VBS,
	SVC_T_IPSEC,
	SVC_T_VIRTIO,
	SVC_T_MIGRATE,
	SVC_T_PPA,
	SVC_T_MAX,
};

#define MGMT_MSG_CMD_OP_SET	1 /* Set command */
#define MGMT_MSG_CMD_OP_GET	0 /* Get command */
#define MGMT_MSG_CMD_OP_START	1 /* Start command */
#define MGMT_MSG_CMD_OP_STOP	0 /* Stop command */

/* Get die id, input parameter is mgmt_msg_head structure */
#define MGMT_GET_DIE_ID(msg_head) \
		(((msg_head)->die_id_valid != 0) ? (msg_head)->die_id : 0)

struct mgmt_msg_head {
	u8 status; /* Response message return value */
	u8 version; /* Message version number */
	u8 rep_aeq_num; /* response aeq number, unused for now */
	u8 rsvd0; /* Reserved field */
	u8 die_id_valid : 1; /* Dual die selection valid bit (tool command selects primary/secondary die) */
	u8 die_id : 1; /* When die_id_valid is valid: die_id:0, primary die; die_id:1, secondary die */
	u8 rsvd1 : 6; /* Reserved field */
	u8 rsvd2[3]; /* Reserved field */
};

enum hinic5_fw_ver_type {
	HINIC5_FW_VER_TYPE_BOOT, /* BOOT firmware */
	HINIC5_FW_VER_TYPE_MPU, /* MPU firmware */
	HINIC5_FW_VER_TYPE_NPU, /* NPU firmware */
	HINIC5_FW_VER_TYPE_SMU_L0, /* SMU L0 firmware */
	HINIC5_FW_VER_TYPE_SMU_L1, /* SMU L1 firmware */
	HINIC5_FW_VER_TYPE_CFG, /* SMU configuration firmware */
	HINIC5_FW_VER_TYPE_PLATFORM,  /* Basic platform */
	HINIC5_FW_VER_TYPE_ROCE_SCC, /* roce scc firmware */
	HINIC5_FW_VER_TYPE_ROCE_SCC_CS, /* roce scc customer firmware */
	HINIC5_FW_VER_TYPE_ROCE_IMP, /* roce imp firmware */
	HINIC5_FW_VER_TYPE_UBC_IMP, /* ubc imp firmware */
	HINIC5_FW_VER_TYPE_IMP, /* imp firmware */
	HINIC5_FW_VER_TYPE_PSM, /* PSM firmware */
	HINIC5_FW_VER_TYPE_UBG_IMP, /* ubg imp firmware */
	HINIC5_FW_VER_TYPE_UB_SCC, /* ub scc firmware */
	HINIC5_FW_VER_TYPE_GRAY_NPU = 100, /* Gray card NPU firmware */
};

#define PCIE_MODE_PORT_NUM 32
#ifdef HI1825V100
#define PCIE_MODE_HOST_NUM 6
#else
#define PCIE_MODE_HOST_NUM 4
#endif
#define PCIE_MODE_PF_NUM 32
#define PCIE_MODE1_VF_NUM 128
#define PCIE_MODE2_VF_NUM 256
#define PCIE_MODE_HOST2PORT_MAP 4
#define FLR_CUR_REG_NUM 128
#define MPU_FLR_INTR_BIT_NUM 32
#define FLR_STAT_CUR_REG_OFFSET 4
#define PCIE_MODE_FLR_STAT_REG_NUM 8
#define PCIE_FLR_MODE2_REG_OFFSET 64

#define PCIE_MODE_ALL_PORT_MAP 0x1111

/**
 * @brief enum bus_type_e - Host side bus type
 * @details Used to distinguish different bus types on host side
 */
typedef enum {
	BUS_TYPE_PCIE = 0,      /**< pcie bus */
	BUS_TYPE_UBC = 1,       /**< ubc bus */
} bus_type_e;

#endif