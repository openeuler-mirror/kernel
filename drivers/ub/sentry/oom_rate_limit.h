/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Description: OOM Event Rate Limit Header File
 * Author: Luckky
 * Create: 2026-03-20
 */

#ifndef OOM_RATE_LIMIT_H
#define OOM_RATE_LIMIT_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ratelimit.h>

#define MAX_EVENT_TYPES 3
#define RATE_LIMIT_WINDOW_SEC 1
#define OOM_RATE_LIMIT_RAW_STR_MAX_LEN 256

extern struct ratelimit_state oom_log_rs;

struct event_rate_limit_config {
	int limit;
};

struct event_rate_limit_state {
	unsigned long last_update_time;
	int count;
};

int oom_rate_limit_init(void);

int oom_rate_limit_check(enum reclaim_reason reason, int nid);

int oom_rate_limit_config_write(const char *buf, size_t len);
int oom_rate_limit_config_read(char *buf, size_t len);

#endif
