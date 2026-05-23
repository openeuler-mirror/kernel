/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_mag_cfg.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_MAG_CFG_H
#define HINIC5_MAG_CFG_H

#include <linux/types.h>

#define CAP_INFO_MAX_LEN	512
#define VENDOR_MAX_LEN		17

#define LOOP_MODE_MIN 1
#define LOOP_MODE_MAX 6

/**
 * @brief Set device physical port state
 *
 * @param hwdev device pointer to hwdev
 * @param enable Set port state value, true--enable, false--disable
 * @param channel, mailbox channel id used for sending
 *
 * @details Set the physical port state associated with this device, sent to MPU via mailbox to configure MAG port state
 *
 * @attention: Only PF is supported, VF returns 0; This function involves sending mailbox messages and may sleep,
 * prohibited from being called in interrupt context or other contexts where sleeping is not allowed
 * @return: Returns success or failure for device physical port state setting.
 *     @retval 0 Success
 *     @retval non-zero Failure
 */
int hinic5_set_port_enable(void *hwdev, bool enable, u16 channel);
int hinic5_get_fec(void *hwdev, u8 *advertised_fec, u8 *supported_fec);
int hinic5_set_fec(void *hwdev, u8 advertised_fec);

#endif
