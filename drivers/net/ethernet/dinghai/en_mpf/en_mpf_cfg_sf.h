/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_MPF_CFG_SF_H__
#define __EN_MPF_CFG_SF_H__
#include <linux/dinghai/zxdh_auxiliary_bus.h>
#include <linux/dinghai/driver.h>

struct cfg_sf_ops {
};

struct cfg_sf_dev {
	struct zxdh_auxiliary_device adev;
	struct dh_core_dev *dh_dev;
	struct cfg_sf_ops *ops;
};

s32 zxdh_mpf_sf_driver_register(void);
void zxdh_mpf_sf_driver_uregister(void);

#endif
