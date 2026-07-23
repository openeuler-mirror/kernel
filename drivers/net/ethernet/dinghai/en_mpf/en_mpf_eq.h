/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_MPF_EQ_H__
#define __EN_MPF_EQ_H__
#include <linux/dinghai/driver.h>

s32 dh_mpf_eq_table_init(struct dh_core_dev *dev);

s32 dh_mpf_eq_table_create(struct dh_core_dev *dev);
void dh_mpf_eq_table_destroy(struct dh_core_dev *dev);

#endif
