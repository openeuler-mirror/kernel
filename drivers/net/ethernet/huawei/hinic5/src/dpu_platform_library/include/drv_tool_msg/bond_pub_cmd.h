/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : bond_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : bond tool and driver interaction interface definition
 */

#ifndef BOND_PUB_CMD_H
#define BOND_PUB_CMD_H

#include "bond_common_defs.h"
#include "hinic5_mt.h"

#define MAX_NETDEV_NUM 4

/**
 * @brief enum hinic5_bond_cmd_to_custom_e
 * @details Defines command types related to custom devices
 */
enum hinic5_bond_cmd_to_custom_e {
	CMD_CUSTOM_BOND_DEV_CREATE = 1,     /**< create custom device */
	CMD_CUSTOM_BOND_DEV_DELETE,         /**< delete custom device */
	CMD_CUSTOM_BOND_GET_CHIP_NAME,      /**< get chip name */
	CMD_CUSTOM_BOND_GET_CARD_INFO,      /**< get card info */
	CMD_CUSTOM_BOND_GET_ULD_DEV_NAME
};

#define BOND_NAME_LEN (16)
#define BOND_DFX_OP_ADD (0)
#define BOND_DFX_OP_DEL (1)

/**
 * @brief struct bond_dfx_ops_info
 * @details dfx operations for bond binding and unbinding
 */
struct bond_dfx_ops_info {
	struct mt_msg_head head;
	char bond_name[BOND_NAME_LEN];
	u32 ops;
	u32 user;
};

#endif