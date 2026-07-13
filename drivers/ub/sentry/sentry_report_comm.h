/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Description: Header File for sentry module
 * Author: sxt1001
 * Create: 2026-07-10
 */

#ifndef SENTRY_REPORTER_COMMON_H
#define SENTRY_REPORTER_COMMON_H

#include <linux/proc_fs.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <uapi/ub/sentry/smh_common_type.h>

#define PROC_FILE_PERMISSION 0600
#define PROC_DIR_PERMISSION 0550
#define ENABLE_VALUE_MAX_LEN 4 // 'off' + '\0'
#define REPORT_COMM_TIME  5000
#define MILLISECONDS_OF_EACH_MDELAY 1000

/*
 * The main version of the sentry driver.
 * It increases by 1 whenever there is an interface change in the Sentry driver or sysSentry package
 */
#define SMH_VERSION_MAJOR  1
/*
 * Defined as the number of message types supported for reporting by the sentry driver.
 * The current Sentry driver supports reporting the following types of abnormal event msg:
 * (1) panic
 * (2) reboot
 * (3) poweroff
 * (4) oom
 * (5) ub mem err
 * (6) ub link
 */
#define SMH_VERSION_MINOR  6

static inline int sentry_create_proc_file(const char *name, struct proc_dir_entry *parent,
					  const struct proc_ops *proc_ops)
{
	int ret = 0;

	if (!proc_create(name, PROC_FILE_PERMISSION, parent, proc_ops)) {
		pr_err("create proc file %s failed.\n", name);
		ret = -ENOMEM;
	}
	return ret;
}

/**
 * check_msg_is_timeout - Check if message has timed out
 * @msg: Message to check
 *
 * Return: true if timeout, false otherwise
 */
static inline bool check_msg_is_timeout(struct sentry_msg_helper_msg *msg)
{
	uint64_t now = ktime_get_ns();
	uint64_t interval_time = (now - msg->start_send_time) / NSEC_PER_MSEC;

	return interval_time > msg->timeout_time;
}
#endif
