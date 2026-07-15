/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_irq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_IRQ_H
#define	HINIC5_IRQ_H

#include "hinic5_nic_dev.h"

int hinic5_qps_irq_init(struct hinic5_nic_dev *nic_dev);

void hinic5_qps_irq_deinit(struct hinic5_nic_dev *nic_dev);

#endif
