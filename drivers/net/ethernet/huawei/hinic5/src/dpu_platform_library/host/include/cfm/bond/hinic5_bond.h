/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_bond.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_BOND_H
#define HINIC5_BOND_H

#include "nic_mpu_cmd_structs.h"
#include "drv_bond_api.h"

/**
 * @brief Bond initialization interface
 * @param[in] void
 * @details Called during nic initialization, used for bond module initialization
 * @attention N/A
 * @return	Returns initialization result, 0 for success, non-zero for failure
 **/
int hinic5_bond_init(void);

/**
 * @brief Bond deinitialization interface
 * @param[in] void
 * @details Called during nic driver unload, used for bond module deinitialization
 * @attention N/A
 * @return	void
 **/
void hinic5_bond_deinit(void);

/**
 * @brief Get bond id by bond name
 * @param[in] bond_name bond name
 * @param[out] bond_id found bond id
 * @details The returned bond id is maintained by the driver side
 * @attention N/A
 * @return	Returns get result, 0 for found, non-zero for not found
 **/
int hinic5_bond_get_id_by_name(u8 *bond_name, u16 *bond_id);

#endif /**< HINIC5_BOND_H */
