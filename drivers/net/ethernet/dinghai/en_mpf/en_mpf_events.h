/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_MPF_EVENTS_H__
#define __EN_MPF_EVENTS_H__
#include <linux/dinghai/driver.h>

s32 dh_mpf_events_init(struct dh_core_dev *dev);
void dh_mpf_events_uninit(struct dh_core_dev *dev);
void zxdh_events_start(struct dh_core_dev *dev);

#endif
