/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_CDEV_EXTENSION_H
#define ROCE_CDEV_EXTENSION_H

#include "roce.h"

#define NOT_SUPOORT_TYPE 0xFFFFFFFF

long ioctl_non_bonding_extend(unsigned int cmd, struct roce3_device *rdev, unsigned long arg);

#endif
