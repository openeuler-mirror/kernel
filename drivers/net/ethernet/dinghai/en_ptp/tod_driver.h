/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _TOD_DRIVER_H_
#define _TOD_DRIVER_H_

#include <linux/types.h>

#define TOD_DEVICE_MSG_OPEN ((u32)(0))
#define TOD_DEVICE_MSG_CLOSE ((u32)(1))
#define TOD_DEVICE_MSG_READ ((u32)(2))
#define TOD_DEVICE_MSG_WRITE ((u32)(3))
#define TOD_DEVICE_MSG_POLL ((u32)(4))
#define TOD_DEVICE_MSG_IOCTL ((u32)(5))

#define TOD_DEVICE_DATA_LEN ((u32)(512))

struct tod_device_msg {
	u32 type;
	u32 command;
	size_t count;
	void *file;
	u8 data[TOD_DEVICE_DATA_LEN];
};

#endif
