/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_event.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_EVENT_H
#define HINIC5_NIC_EVENT_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>

#include "hinic5_common.h"
#include "hinic5_mt.h"
#include "hinic5_hw.h"

int hinic5_nic_aeq_register_swe_cb(void *hwdev, void *pri_handle,
				   enum hinic5_ucode_event_type event,
				   hinic5_aeq_swe_cb nic_aeq_swe_cb);

void hinic5_nic_aeq_unregister_swe_cb(void *hwdev, enum hinic5_ucode_event_type event);

#endif
