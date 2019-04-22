/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:
 */

#ifndef __ERR_LOG_H__
#define __ERR_LOG_H__

#include <linux/kernel.h>
#include <linux/jiffies.h>

/**
 * edac_pr_err - print err level
 * @format: log fromat
 * @arg:	log parameters
 */
#define edac_pr_err(format, arg...) pr_err("EDAC: " format, ##arg)

/**
 * edac_pr_debug - print debug level
 * @format: log fromat
 * @arg:	log parameters
 */
#define edac_pr_debug(format, arg...) pr_debug("EDAC: " format, ##arg)

/**
 * edac_pr_info - print info level
 * @format: log fromat
 * @arg:	log parameters
 */
#define edac_pr_info(format, arg...) pr_info("EDAC: " format, ##arg);

/**
 * edac_dev_err - print err level with device
 * @dev: device info
 * @format: log fromat
 * @arg:	log parameters
 */
#define edac_dev_err(dev, format, arg...) dev_err(dev, "EDAC: "  format, ##arg)

/**
 * edac_dev_info - print info level with device
 * @dev: device info
 * @format: log fromat
 * @arg:	log parameters
 */
#define edac_dev_info(dev, format, arg...) dev_info(dev, "EDAC: "  format, ##arg)

/**
 * edac_dev_dbg - print debug level with device
 * @dev: device info
 * @format: log fromat
 * @arg:	log parameters
 */
#define edac_dev_dbg(dev, format, arg...) dev_dbg(dev, "EDAC: "  format, ##arg)

/**
 * edac_panic - print err level with device
 * @dev: device info
 * @format: log fromat
 * @arg:	log parameters
 */
#define edac_panic(format, arg...) panic("EDAC trigger system reboot: " format, ##arg)

/**
 * TRACE_FRQLIMIT - print frequency control interface
 * @interval: print interval
 * @X: log fromat
 * @args: log parameters
 */
#define TRACE_FRQLIMIT(interval, X, args...) \
do { \
	static unsigned long last; \
	if (time_after_eq(jiffies, last+(interval))) { \
		last = jiffies; \
		edac_pr_err(X, ##args);\
	 } \
} while (0)

/**
 * TRACE_FRQLIMIT - print frequency count control interface
 * @interval: print interval
 * @count: print count
 * @X: log fromat
 * @args: log parameters
 */
#define TRACE_LIMIT(interval, count, X, args...) \
do { \
	static unsigned long last; \
	static unsigned long local_count; \
	if (local_count < count) {  \
		local_count++;  \
		edac_pr_err(X, ##args);\
	 } \
	if (time_after_eq(jiffies, last+(interval))) { \
		last = jiffies; \
		local_count = 0; \
	} \
} while (0)

#ifndef UINT32
typedef unsigned int UINT32;
typedef int INT32;
typedef unsigned short UINT16;
typedef unsigned char UINT8;
#endif

#endif /* __ERR_LOG_H__ */
