/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_irq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : HINIC5 IRQ (interrupt) control header file
 */

#ifndef HINIC5_IRQ_H
#define	HINIC5_IRQ_H

struct hinic5_nic_dev;

#ifdef HAVE_DIM_SUPPORT

#if defined(HAVE_DIM)
#include <linux/dim.h>
#elif defined(HAVE_NET_DIM)
#include <linux/net_dim.h>
#endif

#if defined(HAVE_NET_DIM)
#define DIM_START_MEASURE NET_DIM_START_MEASURE
#endif
#define DIM_START_PROFILE 0

#endif

int hinic5_qps_irq_init(struct hinic5_nic_dev *nic_dev);

void hinic5_qps_irq_deinit(struct hinic5_nic_dev *nic_dev);

#endif
