/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2026 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_LOG_H__
#define __UDMA_LOG_H__

#include <linux/dev_printk.h>
#include <linux/ratelimit_types.h>
#include "udma_cmd.h"

#define UDMA_RATELIMIT_INTERVAL (1 * HZ)
#define UDMA_RATELIMIT_BURST 2

#define udma_err_rl(_udev, fmt, ...) do {			\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      UDMA_RATELIMIT_INTERVAL,	\
				      UDMA_RATELIMIT_BURST);	\
	if (debug_switch || (__ratelimit(&_rs)))		\
		dev_err(_udev, fmt, ##__VA_ARGS__);		\
} while (0)

#define udma_info_rl(_udev, fmt, ...) do {			\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      UDMA_RATELIMIT_INTERVAL,	\
				      UDMA_RATELIMIT_BURST);	\
	if (debug_switch || (__ratelimit(&_rs)))		\
		dev_info(_udev, fmt, ##__VA_ARGS__);		\
} while (0)

#define udma_warn_rl(_udev, fmt, ...) do {			\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      UDMA_RATELIMIT_INTERVAL,	\
				      UDMA_RATELIMIT_BURST);	\
	if (debug_switch || (__ratelimit(&_rs)))		\
		dev_warn(_udev, fmt, ##__VA_ARGS__);		\
} while (0)

#endif /* __UDMA_LOG_H__ */
