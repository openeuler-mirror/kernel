/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_cdev.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_CDEV_H__
#define __SXE2_CDEV_H__

#include <linux/semaphore.h>

struct sxe2_cdev_info {
	struct cdev cdev;
	dev_t dev_no;
	struct device *device;
	struct semaphore cdev_sem;
};

#endif
