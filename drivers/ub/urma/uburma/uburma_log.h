/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: uburma log head file
 * Author: Qian Guoxin
 * Create: 2021-8-3
 * Note:
 * History: 2021-8-3: Create file
 */

#ifndef UBURMA_LOG_H
#define UBURMA_LOG_H

#include <linux/types.h>
#include <linux/printk.h>
#include <linux/sched.h>

enum uburma_log_level {
	UBURMA_LOG_LEVEL_EMERG = 0,
	UBURMA_LOG_LEVEL_ALERT = 1,
	UBURMA_LOG_LEVEL_CRIT = 2,
	UBURMA_LOG_LEVEL_ERR = 3,
	UBURMA_LOG_LEVEL_WARNING = 4,
	UBURMA_LOG_LEVEL_NOTICE = 5,
	UBURMA_LOG_LEVEL_INFO = 6,
	UBURMA_LOG_LEVEL_DEBUG = 7,
	UBURMA_LOG_LEVEL_MAX = 8,
};

/* add log head info, "URMA|uburma|thread_id|function:[line]|format */
#define UBURMA_LOG_TAG "URMA"
#define UBURMA_LOG     "uburma"

#define uburma_log(l, format, args...) \
	pr_##l("%s|%s|%d|%d|%s:[%d]|" format, UBURMA_LOG_TAG, UBURMA_LOG, \
		((int)current->pid), ((int)task_pid_vnr(current)), \
		__func__, __LINE__, ##args)

#define UBURMA_RATELIMIT_INTERVAL (5 * HZ)
#define UBURMA_RATELIMIT_BURST 100

extern uint32_t g_uburma_log_level;

#define uburma_log_info(...)                                     \
	do {                                                         \
		if (g_uburma_log_level >= UBURMA_LOG_LEVEL_INFO)         \
			uburma_log(info, __VA_ARGS__);                       \
	} while (0)

#define uburma_log_err(...)                                      \
	do {                                                         \
		if (g_uburma_log_level >= UBURMA_LOG_LEVEL_ERR)          \
			uburma_log(err, __VA_ARGS__);                        \
	} while (0)

#define uburma_log_warn(...)                                     \
	do {                                                         \
		if (g_uburma_log_level >= UBURMA_LOG_LEVEL_WARNING)      \
			uburma_log(warn, __VA_ARGS__);                       \
	} while (0)

/* No need to record debug log by printk_ratelimited */
#define uburma_log_debug(...)                                    \
	do {                                                         \
		if (g_uburma_log_level >= UBURMA_LOG_LEVEL_DEBUG)        \
			uburma_log(debug, __VA_ARGS__);                      \
	} while (0)

/* Rate Limited log to avoid soft lockup crash by quantities of printk */
/* Current limit is 100 log every 5 seconds */
#define uburma_log_info_rl(...)                                           \
	do {                                                                  \
		static DEFINE_RATELIMIT_STATE(_rs, UBURMA_RATELIMIT_INTERVAL,     \
					      UBURMA_RATELIMIT_BURST);                        \
		if ((__ratelimit(&_rs)) &&                                        \
		    (g_uburma_log_level >= UBURMA_LOG_LEVEL_INFO))                \
			uburma_log(info, __VA_ARGS__);                                \
	} while (0)

#define uburma_log_err_rl(...)                                            \
	do {                                                                  \
		static DEFINE_RATELIMIT_STATE(_rs, UBURMA_RATELIMIT_INTERVAL,     \
					      UBURMA_RATELIMIT_BURST);                        \
		if ((__ratelimit(&_rs)) &&                                        \
		    (g_uburma_log_level >= UBURMA_LOG_LEVEL_ERR))                 \
			uburma_log(err, __VA_ARGS__);                                 \
	} while (0)

#define uburma_log_warn_rl(...)                                           \
	do {                                                                  \
		static DEFINE_RATELIMIT_STATE(_rs, UBURMA_RATELIMIT_INTERVAL,     \
					      UBURMA_RATELIMIT_BURST);                        \
		if ((__ratelimit(&_rs)) &&                                        \
		    (g_uburma_log_level >= UBURMA_LOG_LEVEL_WARNING))             \
			uburma_log(warn, __VA_ARGS__);                                \
	} while (0)

#endif /* UBURMA_LOG_H */
