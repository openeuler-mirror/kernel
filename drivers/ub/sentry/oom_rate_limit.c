// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * Description: OOM Event Rate Limit Implementation
 * Author: Luckky
 * Create: 2026-03-20
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/jiffies.h>

#include "oom_rate_limit.h"
#include "smh_common_type.h"

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][oom_limit]: " fmt

static struct event_rate_limit_config g_event_config[MAX_EVENT_TYPES];
static struct event_rate_limit_state g_event_state[MAX_EVENT_TYPES][OOM_EVENT_MAX_NUMA_NODES];

static int g_config_event_num;

const char *event_type_names[] = {
	"RR_KSWAPD",
	"RR_DIRECT_RECLAIM",
	"RR_HUGEPAGE_RECLAIM"
};


/**
 * parse_config_string - Parse configuration string and fill config structure
 * @buf: Input buffer containing configuration information
 * @len: Length of the input buffer
 * @config: Output parameter, stores parsed configuration
 *
 * Configuration string format: "event_name1:limit1,event_name2:limit2,..."
 * Example: "RR_KSWAPD:10,RR_DIRECT_RECLAIM:5"
 *
 * Return: Number of parsed events on success, negative error code on failure
 */
static int parse_config_string(const char *buf, size_t len,
				   struct event_rate_limit_config *config)
{
	char *copy_str;
	char *token;
	char *event_name;
	char *limit_str;
	int limit;
	int event_idx;
	int ret = 0;
	int config_event_limit_num = 0;

	copy_str = kzalloc(len + 1, GFP_KERNEL);
	if (!copy_str)
		return -ENOMEM;

	memcpy(copy_str, buf, len);
	copy_str[len] = '\0';

	token = strsep(&copy_str, ",");
	while (token) {
		event_name = strsep(&token, ":");
		if (!event_name || !token) {
			pr_err("parse oom event name failed\n");
			ret = -EINVAL;
			goto out;
		}

		limit_str = strsep(&token, ":");
		if (!limit_str) {
			pr_err("parse oom event limit value failed\n");
			ret = -EINVAL;
			goto out;
		}

		if (kstrtoint(limit_str, 10, &limit)) {
			pr_err("covert limit value failed\n");
			ret = -EINVAL;
			goto out;
		}
		if (limit < 0) {
			pr_err("invalid limit config (%s), it can't be an negative number\n",
				limit_str);
			ret = -EINVAL;
			goto out;
		}
		for (event_idx = 0; event_idx < MAX_EVENT_TYPES; event_idx++) {
			if (strcmp(event_name, event_type_names[event_idx]) == 0) {
				config[event_idx].limit = limit;
				config_event_limit_num++;
				break;
			}
		}

		token = strsep(&copy_str, ",");
	}
	ret = config_event_limit_num;

out:
	kfree(copy_str);
	return ret;
}

/**
 * oom_rate_limit_init - Initialize OOM rate limit module
 *
 * Initializes configuration array, and state array.
 * Configuration array limit is initialized to -1 indicating not configured (unlimited).
 * State array timestamps and counts are initialized to 0.
 *
 * Return: Always returns 0 (success)
 */
int oom_rate_limit_init(void)
{
	int i, j;

	for (i = 0; i < MAX_EVENT_TYPES; i++)
		g_event_config[i].limit = -1;

	for (i = 0; i < MAX_EVENT_TYPES; i++) {
		for (j = 0; j < OOM_EVENT_MAX_NUMA_NODES; j++) {
			g_event_state[i][j].last_update_time = 0;
			g_event_state[i][j].count = 0;
		}
	}

	return 0;
}

/**
 * oom_rate_limit_check - Check whether specified event should be reported
 * @reason: Event reason type (reclaim type)
 * @nid: NUMA node ID
 *
 * Checks whether the specified event should be reported based on the configured
 * rate limiting policy.
 * Rate limit semantics:
 * - limit = 0: Reporting completely disabled
 * - limit = -1: Unlimited, always report
 * - limit = n: Report at most n times per second (counted independently per NUMA node)
 *
 * The global variables g_event_config and g_event_state ara not locked. It is acceptable
 * that the number of reported oom events msg exceeds the configured limit. Locking these
 * variables will affect the performance.
 *
 * Return: 0 if should report, -EINVAL if shouldn't report
 */
int oom_rate_limit_check(enum reclaim_reason reason, int nid)
{
	unsigned long current_time;
	unsigned long time_diff;
	int should_report = 0;

	if (nid < 0 || nid >= OOM_EVENT_MAX_NUMA_NODES) {
		pr_err("invalid params\n");
		return -EINVAL;
	}

	if (g_event_config[reason].limit == 0) {
		if (__ratelimit(&oom_log_rs))
			pr_warn("sentry not report %s type oom event msg\n",
					event_type_names[reason]);
		return -EINVAL;
	}

	if (g_event_config[reason].limit == -1)
		return 0;

	current_time = jiffies;
	time_diff = current_time - g_event_state[reason][nid].last_update_time;

	if (time_diff >= HZ * RATE_LIMIT_WINDOW_SEC) {
		g_event_state[reason][nid].count = 0;
		g_event_state[reason][nid].last_update_time = current_time;
	}

	if (g_event_state[reason][nid].count < g_event_config[reason].limit) {
		g_event_state[reason][nid].count++;
		should_report = 1;
	}

	return should_report ? 0 : -EINVAL;
}

/**
 * oom_rate_limit_config_write - Write rate limit configuration
 * @buf: Buffer containing configuration information
 * @len: Buffer length
 *
 * Parses user-provided configuration string and updates global rate limit configuration.
 * Configuration string format: "event1:limit1,event2:limit2,..."
 *
 * Return: 0 on success, negative error code on failure
 */
int oom_rate_limit_config_write(const char *buf, size_t len)
{
	struct event_rate_limit_config new_config[MAX_EVENT_TYPES];
	int i;
	int ret;

	for (i = 0; i < MAX_EVENT_TYPES; i++)
		new_config[i].limit = -1;

	ret = parse_config_string(buf, len, new_config);
	if (ret < 0) {
		pr_err("parse limit config failed\n");
		return ret;
	}
	g_config_event_num = ret;

	for (i = 0; i < MAX_EVENT_TYPES; i++) {
		g_event_config[i].limit = new_config[i].limit;
		pr_info("config oom event (%s type) limit to %d\n",
			event_type_names[i], new_config[i].limit);
	}
	return 0;
}

/**
 * oom_rate_limit_config_read - Read current rate limit configuration
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Formats the current active rate limit configuration as a string and writes it
 * to the output buffer.
 * Output format matches the write format: "event1:limit1,event2:limit2,..."
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
int oom_rate_limit_config_read(char *buf, size_t len)
{
	int pos = 0;
	int i;
	int ret;

	for (i = 0; i < MAX_EVENT_TYPES; i++) {
		if (g_event_config[i].limit != -1) {
			ret = snprintf(buf + pos, len - pos, "%s:%d%s",
					   event_type_names[i],
					   g_event_config[i].limit,
					   (i < g_config_event_num - 1) ? "," : "\n");
			if (ret < 0 || ret >= len - pos)
				return -ENOSPC;
			pos += ret;
		}
	}
	return pos;
}
