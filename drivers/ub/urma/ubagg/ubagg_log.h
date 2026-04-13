/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg log head file
 * Author: Dongxu Li
 * Create: 2025-1-14
 * Note:
 * History: 2025-1-14: Create file
 */

#ifndef UBAGG_LOG_H
#define UBAGG_LOG_H

#include <linux/types.h>
#include <linux/printk.h>
#include <linux/sched.h>

enum ubagg_log_level {
	UBAGG_LOG_LEVEL_EMERG = 0,
	UBAGG_LOG_LEVEL_ALERT = 1,
	UBAGG_LOG_LEVEL_CRIT = 2,
	UBAGG_LOG_LEVEL_ERR = 3,
	UBAGG_LOG_LEVEL_WARNING = 4,
	UBAGG_LOG_LEVEL_NOTICE = 5,
	UBAGG_LOG_LEVEL_INFO = 6,
	UBAGG_LOG_LEVEL_DEBUG = 7,
	UBAGG_LOG_LEVEL_MAX = 8,
};

/* add log head info, "URMA|ubagg|thread_id|function:[line]|format */
#define UBAGG_LOG_TAG "URMA"
#define UBAGG_LOG     "ubagg"

#define ubagg_log(l, format, args...) \
	pr_##l("%s|%s|%d|%d|%s:[%d]|" format, UBAGG_LOG_TAG, UBAGG_LOG, \
		((int)current->pid), ((int)task_pid_vnr(current)), \
		__func__, __LINE__, ##args)

#define UBAGG_RATELIMIT_INTERVAL (5 * HZ)
#define UBAGG_RATELIMIT_BURST 100

extern uint32_t g_ubagg_log_level;

#define ubagg_log_info(...)                                \
	do {                                                   \
		if (g_ubagg_log_level >= UBAGG_LOG_LEVEL_INFO)     \
			ubagg_log(info, __VA_ARGS__);                  \
	} while (0)

#define ubagg_log_err(...)                                 \
	do {                                                   \
		if (g_ubagg_log_level >= UBAGG_LOG_LEVEL_ERR)      \
			ubagg_log(err, __VA_ARGS__);                   \
	} while (0)

#define ubagg_log_warn(...)                                \
	do {                                                   \
		if (g_ubagg_log_level >= UBAGG_LOG_LEVEL_WARNING)  \
			ubagg_log(warn, __VA_ARGS__);                  \
	} while (0)

/* No need to record debug log by printk_ratelimited */
#define ubagg_log_debug(...)                               \
	do {                                                   \
		if (g_ubagg_log_level >= UBAGG_LOG_LEVEL_DEBUG)    \
			ubagg_log(debug, __VA_ARGS__);                 \
	} while (0)

/* Rate Limited log to avoid soft lockup crash by quantities of printk */
/* Current limit is 100 log every 5 seconds */
#define ubagg_log_info_rl(...)                                           \
	do {                                                                 \
		static DEFINE_RATELIMIT_STATE(_rs, UBAGG_RATELIMIT_INTERVAL,     \
					      UBAGG_RATELIMIT_BURST);                        \
		if ((__ratelimit(&_rs)) &&                                       \
		    (g_ubagg_log_level >= UBAGG_LOG_LEVEL_INFO))                 \
			ubagg_log(info, __VA_ARGS__);                                \
	} while (0)

#define ubagg_log_err_rl(...)                                            \
	do {                                                                 \
		static DEFINE_RATELIMIT_STATE(_rs, UBAGG_RATELIMIT_INTERVAL,     \
					      UBAGG_RATELIMIT_BURST);                        \
		if ((__ratelimit(&_rs)) &&                                       \
		    (g_ubagg_log_level >= UBAGG_LOG_LEVEL_ERR))                  \
			ubagg_log(err, __VA_ARGS__);                                 \
	} while (0)

#define ubagg_log_warn_rl(...)                                           \
	do {                                                                 \
		static DEFINE_RATELIMIT_STATE(_rs, UBAGG_RATELIMIT_INTERVAL,     \
					      UBAGG_RATELIMIT_BURST);                        \
		if ((__ratelimit(&_rs)) &&                                       \
		    (g_ubagg_log_level >= UBAGG_LOG_LEVEL_WARNING))              \
			ubagg_log(warn, __VA_ARGS__);                                \
	} while (0)

#endif /* UBAGG_LOG_H */
