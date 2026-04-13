/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: ubcore log head file
 * Author: Qian Guoxin
 * Create: 2021-8-3
 * Note:
 * History: 2021-8-3: Create file
 */

#ifndef UBCORE_LOG_H
#define UBCORE_LOG_H

#include <linux/types.h>
#include <linux/printk.h>
#include <linux/sched.h>

enum ubcore_log_level {
	UBCORE_LOG_LEVEL_EMERG = 0,
	UBCORE_LOG_LEVEL_ALERT = 1,
	UBCORE_LOG_LEVEL_CRIT = 2,
	UBCORE_LOG_LEVEL_ERR = 3,
	UBCORE_LOG_LEVEL_WARNING = 4,
	UBCORE_LOG_LEVEL_NOTICE = 5,
	UBCORE_LOG_LEVEL_INFO = 6,
	UBCORE_LOG_LEVEL_DEBUG = 7,
	UBCORE_LOG_LEVEL_MAX = 8,
};

/* add log head info, "LogTag_UBCORE|function:[line]|format */
#define UBCORE_LOG_TAG "URMA"
#define UBCORE_LOG     "ubcore"
/* only use debug log */
/* add log head info: URMA|ubcore|thread_id|vnr_thread_id|function:[line]|format */
#define ubcore_log(l, format, args...) \
	pr_##l("%s|%s|%d|%d|%s:[%d]|" format, UBCORE_LOG_TAG, UBCORE_LOG, \
		((int)current->pid), ((int)task_pid_vnr(current)), \
		__func__, __LINE__, ##args)
/* use default log, info/warn/err */
#define ubcore_default_log(l, format, args...)                        \
	((void)pr_##l("%s|%s|%d|%d|%s[%d]|" format, UBCORE_LOG_TAG, UBCORE_LOG, \
		((int)current->pid), ((int)task_pid_vnr(current)), \
		__func__, __LINE__, ##args))

#define UBCORE_RATELIMIT_INTERVAL (5 * HZ)
#define UBCORE_RATELIMIT_BURST 100

extern uint32_t g_ubcore_log_level;

#define ubcore_log_info(...)                                     \
	do {                                                     \
		if (g_ubcore_log_level >= UBCORE_LOG_LEVEL_INFO) \
			ubcore_default_log(info, __VA_ARGS__);   \
	} while (0)

#define ubcore_log_err(...)                                     \
	do {                                                    \
		if (g_ubcore_log_level >= UBCORE_LOG_LEVEL_ERR) \
			ubcore_default_log(err, __VA_ARGS__);   \
	} while (0)

#define ubcore_log_warn(...)                                        \
	do {                                                        \
		if (g_ubcore_log_level >= UBCORE_LOG_LEVEL_WARNING) \
			ubcore_default_log(warn, __VA_ARGS__);      \
	} while (0)

#define ubcore_log_debug(...)                                     \
	do {                                                      \
		if (g_ubcore_log_level >= UBCORE_LOG_LEVEL_DEBUG) \
			ubcore_log(debug, __VA_ARGS__);           \
	} while (0)

/* Rate Limited log to avoid soft lockup crash by quantities of printk */
/* Current limit is 100 log every 5 seconds */
#define ubcore_log_info_rl(...)                                               \
	do {                                                                  \
		static DEFINE_RATELIMIT_STATE(_rs, UBCORE_RATELIMIT_INTERVAL, \
					      UBCORE_RATELIMIT_BURST);        \
		if ((__ratelimit(&_rs)) &&                                    \
		    (g_ubcore_log_level >= UBCORE_LOG_LEVEL_INFO))            \
			ubcore_log(info, __VA_ARGS__);                        \
	} while (0)

#define ubcore_log_err_rl(...)                                                \
	do {                                                                  \
		static DEFINE_RATELIMIT_STATE(_rs, UBCORE_RATELIMIT_INTERVAL, \
					      UBCORE_RATELIMIT_BURST);        \
		if ((__ratelimit(&_rs)) &&                                    \
		    (g_ubcore_log_level >= UBCORE_LOG_LEVEL_ERR))             \
			ubcore_log(err, __VA_ARGS__);                         \
	} while (0)

#define ubcore_log_warn_rl(...)                                               \
	do {                                                                  \
		static DEFINE_RATELIMIT_STATE(_rs, UBCORE_RATELIMIT_INTERVAL, \
					      UBCORE_RATELIMIT_BURST);        \
		if ((__ratelimit(&_rs)) &&                                    \
		    (g_ubcore_log_level >= UBCORE_LOG_LEVEL_WARNING))         \
			ubcore_log(warn, __VA_ARGS__);                        \
	} while (0)

#endif
