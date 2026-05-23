/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : bond_common_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : South Interface---ovs mpu bond interface between mpu and driver
 */

#ifndef BOND_COMMON_DEFS_H
#define BOND_COMMON_DEFS_H

#define BOND_PORT_MAX_NUM       4
#define BOND_NAME_MAX_LEN       16
#define BOND_ID_INVALID         0xFFFF
#define OVS_PORT_NUM_MAX        BOND_PORT_MAX_NUM
#define BOND_DEFAULT_ROCE_FUNC  0xFFFFFFFF

#define BOND_ID_IS_VALID(_id)   (((_id) >= BOND_FIRST_ID) && ((_id) <= BOND_MAX_ID))
#define BOND_ID_IS_INVALID(_id) (!(BOND_ID_IS_VALID(_id)))

/**
 * @brief enum bond_group_id
 * @details bond id
 */
enum bond_group_id {
	BOND_FIRST_ID = 1,
	BOND_MAX_ID = BOND_FIRST_ID,
	BOND_MAX_NUM,
};

/**
 * @brief enum hinic5_bond_user
 * @details Bond user enumeration, for compatibility with version 23, not using common definition
 */
enum hinic5_bond_user {
	HINIC5_BOND_USER_OVS,
	HINIC5_BOND_USER_TOE,
	HINIC5_BOND_USER_ROCE,
	HINIC5_BOND_USER_UB,
	HINIC5_BOND_USER_NIC,
	HINIC5_BOND_USER_NUM
};

/**
 * @brief enum tag_bond_mode
 * @details Bond mode enumeration type
 */
typedef enum tag_bond_mode {
	BOND_MODE_NONE      = 0, /**< Disable network bonding */
	BOND_MODE_BACKUP    = 1, /**< Active-backup mode, 1 indicates active-backup bonding */
	BOND_MODE_BALANCE   = 2, /**< Load balancing mode, 2 indicates XOR load balancing bonding */
	BOND_MODE_LACP      = 4, /**< LACP mode, 4 indicates 802.3ad bonding */
	BOND_MODE_MAX            /**< Maximum value for network bonding mode */
} bond_mode_e;

/**
 * @brief enum tag_bond_hash
 * @details Bond hash policy enumeration type
 */
typedef enum tag_bond_hash {
	BOND_HASH_L2   = 0,   /**< Use L2 address for hashing */
	BOND_HASH_L23  = 1,   /**< Use L2 and L3 addresses for hashing */
	BOND_HASH_L34  = 2,   /**< Use L3 and L4 addresses for hashing */
	BOND_HASH_MAX  = 3    /**< Maximum hash policy value */
} bond_hash_e;

/**
 * ovs bond hash policy
 */
typedef enum ovs_bond_hash_policy {
	OVS_BOND_HASH_POLICY_L2       = 0, /**< 0 for layer 2 */
	OVS_BOND_HASH_POLICY_L34      = 1, /**< 1 for layer 3+4 */
	OVS_BOND_HASH_POLICY_L23      = 2, /**< 2 for layer 2+3 */
	OVS_BOND_HASH_POLICY_VFID_SQN = 3, /**< 3 for vfid ^ sqn */
	OVS_BOND_HASH_POLICY_MAX
} ovs_bond_hash_policy_e;

/**
 * @brief enum bond_port_duplex_state
 * @details Port duplex state enumeration type
 */
enum bond_port_duplex_state {
	BOND_PORT_HALF_DUPLEX = 0, /**< Half duplex */
	BOND_PORT_FULL_DUPLEX,     /**< Full duplex */
};

#endif /* BOND_COMMON_DEFS_H */
