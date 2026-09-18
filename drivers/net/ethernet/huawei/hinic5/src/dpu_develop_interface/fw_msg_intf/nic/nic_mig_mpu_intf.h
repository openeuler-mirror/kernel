/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_mig_mpu_intf.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : NIC migration MPU interface
 */

#ifndef NIC_MIG_MPU_INTF_H
#define NIC_MIG_MPU_INTF_H

#include "nic_cfg_comm.h"

#ifndef MAX_CEQ_PER_FUNC
#define MAX_CEQ_PER_FUNC 0x20
#endif

/**
 * @brief Defines an enum type to represent the operation type of the MSIX control register.
 * @details
 * This enum type contains two members, representing the operations of getting and setting the MSIX control register.
 */
enum mig_nic_msix_op {
	MSIX_CTRL_CSR_GET,      /**< Get the value of the MSIX control register */
	MSIX_CTRL_CSR_SET       /**< Set the value of the MSIX control register */
};

#define MAX_CMDQ_NUM 0x4    /**< Maximum cmdq count */

#define MAX_SQ_NUM 0x40     /**< Maximum sq count */

/**
 * @struct mig_nic_mac_vlan
 * @brief Defines a struct to store the MAC address, VLAN ID and reserved fields of the NIC
 * @details This struct is mainly used for configuration and management of network devices, containing MAC address, VLAN ID and reserved fields.
 */
struct mig_nic_mac_vlan {
	u8 mac[6]; /**< MAC address, 6 bytes long */
	u16 vlan_id; /**< VLAN ID, used to identify different networks in the network */
	u16 rsvd; /**< Reserved field, currently unused */
};

#define MIG_FAST_MSG_MAX_PAGE_SIZE (256 * 1024)
#endif
