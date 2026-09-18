/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_crm_pub.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CRM public interface declarations
 */

#ifndef HINIC5_CRM_PUB_H
#define HINIC5_CRM_PUB_H

#include "hinic5_crm.h"

/**
* @brief Obtains the CoS allocated to the NIC feature.
* @param hwdev Indicates the pointer to the hardware device.
*
* @return Returns the CoS allocated to the NIC feature.
*/
u8 hinic5_func_cos_mask_bitmap(void *hwdev);

#endif