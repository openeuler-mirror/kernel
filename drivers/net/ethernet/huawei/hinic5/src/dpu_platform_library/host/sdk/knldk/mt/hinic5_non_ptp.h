/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_non_ptp.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NON_PTP_H
#define HINIC5_NON_PTP_H

#if !defined(__UEFI__) && !defined(__VMWARE__) && !defined(__WIN__)

#include <linux/cdev.h>
#include "hinic5_hwdev.h"

#define HINIC5_NON_PTP_CDEV_MAX_DEVICES 1

struct hinic5_non_ptp_cdev {
	dev_t devid;
	struct cdev dev;
	struct class *cdev_class;
	struct device *cdev_device;
};

int hinic5_non_ptp_cdev_init(struct hinic5_hwdev *hwdev);
void hinic5_non_ptp_cdev_deinit(struct hinic5_hwdev *hwdev);
int hinic5_sync_kernel_time(struct hinic5_hwdev *hwdev);
#endif
#endif
