/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_mag_cfg.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : hinic5 MAG configuration definitions
 */

#ifndef HINIC5_MAG_CFG_H
#define HINIC5_MAG_CFG_H

#include <linux/types.h>

#define CAP_INFO_MAX_LEN	512
#define VENDOR_MAX_LEN		17

#define LOOP_MODE_MIN 1
#define LOOP_MODE_MAX 6

/* This structure adds page_id on top of mgmt_tlv_info to make page_id matching more convenient */
struct tlv_block {
	u16 type;
	u16 length;     /* length is the total length of page_id and page_data, note this when calculating offset */
	u32 page_id;
	u8 page_data[];
};

/**
 * @brief Set device physical port status
 *
 * @param hwdev device pointer to hwdev
 * @param enable port status value to set, true--enable, false--disable
 * @param channel channel id, channel id used for mailbox sending
 *
 * @details Set the physical port status associated with this device, sent to MPU via mailbox to set MAG port status
 *
 * @attention: Only supported by PF, VF call returns 0; This function involves sending mailbox messages and will sleep. It is forbidden to call it in interrupt context or other contexts where sleeping is not allowed
 *
 * @return: Returns success or failure of device physical port status setting.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_set_port_enable(void *hwdev, bool enable, u16 channel);
int hinic5_get_fec(void *hwdev, u8 *advertised_fec, u8 *supported_fec);
int hinic5_set_fec(void *hwdev, u8 advertised_fec);

#endif