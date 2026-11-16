/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_IDC_H_
#define _NSEVF_IDC_H_

#include "iidc.h"

struct nsevf_adapter;

void nsevf_idc_init_task(struct work_struct *work);
void nsevf_idc_init(struct nsevf_adapter *adapter);
void nsevf_idc_deinit(struct nsevf_adapter *adapter,
		      unsigned int unplug_preset_reset);
void nsevf_idc_vc_receive(struct nsevf_adapter *adapter, u8 *msg, u16 msglen);

#endif /* _NSEVF_IDC_H_ */
