// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: report oom and reboot event to userspace
 * Author: Luckky
 * Create: 2025-02-17
 */

#include <acpi/button.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>

#include "smh_message.h"
#include "oom_rate_limit.h"

#define REBOOT_RESULT_SUCCESS	0
#define MAX_TIMEOUT		3600000
#define FD_MODE			0
#define NUMA_MODE		1

#define WAIT_TIME_TO_GET_ACK 300   // sleep time before get ack msg

DEFINE_RATELIMIT_STATE(oom_log_rs, HZ, 5);

static unsigned int reboot_timeout_ms = 30000;
static unsigned int oom_timeout_ms = 30000;
module_param(reboot_timeout_ms, uint, 0444);
module_param(oom_timeout_ms, uint, 0444);

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][reporter]: " fmt

static struct proc_dir_entry *g_sentry_reporter_proc_dir;

static int g_ub_mem_fault_with_kill = 1;
static bool g_oom_enable;
static bool g_power_off_enable;
static bool g_ub_mem_fault_enable;

/**
 * check_if_timeout_param_valid - Validate timeout parameters
 *
 * Return: 0 if valid, negative error code otherwise
 */
static int check_if_timeout_param_valid(void)
{
	if (reboot_timeout_ms > MAX_TIMEOUT) {
		pr_err("reboot timeout is out of range! (valid range: [0, %u], current value: %u)\n",
		       MAX_TIMEOUT, reboot_timeout_ms);
		return -EINVAL;
	}

	if (oom_timeout_ms > MAX_TIMEOUT) {
		pr_err("oom timeout is out of range! (valid range: [0, %u], current value: %u)\n",
		       MAX_TIMEOUT, oom_timeout_ms);
		return -EINVAL;
	}

	return 0;
}

/**
 * smh_message_retry_send - Send message with retry mechanism
 * @msg: Message to send
 * @ack: Whether acknowledgment is required
 *
 * Return: 0 on success, negative error code on failure
 */
static int smh_message_retry_send(struct sentry_msg_helper_msg *msg, bool ack)
{
	int ret;
	int i;
	int times = msg->timeout_time / MILLISECONDS_OF_EACH_MDELAY;

	msg->start_send_time = ktime_get_ns();
	msg->msgid = smh_get_new_msg_id();

	for (i = 0; i < times; i++) {
		uint64_t cur_time = ktime_get_ns();

		ret = smh_message_send(msg, ack);
		if (!ack)
			return ret;

		msleep_interruptible(WAIT_TIME_TO_GET_ACK);

		ret = smh_message_get_ack(msg);
		if (ret)
			return 0;

		msleep_interruptible(MILLISECONDS_OF_EACH_MDELAY -
				     (ktime_get_ns() - cur_time) / NSEC_PER_MSEC);
	}

	if (msg->type == SMH_MESSAGE_OOM && __ratelimit(&oom_log_rs))
		pr_info("message %llu is timeout\n", msg->msgid);

	return -ETIMEDOUT;
}

/**
 * acpi_power_notifier_callback - ACPI power button notification handler
 * @nb: Notifier block
 * @action: Action type
 * @data: Callback data
 *
 * Return: NOTIFY_OK on success, NOTIFY_BAD on failure
 */
static int acpi_power_notifier_callback(struct notifier_block *nb,
					unsigned long action, void *data)
{
	int ret;
	struct sentry_msg_helper_msg msg = {0};

	if (!g_power_off_enable)
		return NOTIFY_OK;

	msg.type = SMH_MESSAGE_POWER_OFF;
	msg.timeout_time = reboot_timeout_ms + REPORT_COMM_TIME;

	pr_info("send sentry reboot message\n");
	ret = smh_message_retry_send(&msg, true);
	if (ret || msg.res != REBOOT_RESULT_SUCCESS)
		return NOTIFY_BAD;

	return NOTIFY_OK;
}

static struct notifier_block acpi_power_notifier = {
	.notifier_call = acpi_power_notifier_callback,
	.priority = INT_MAX,
};

/**
 * lowmem_notifier_callback - Low memory notification handler
 * @nb: Notifier block
 * @action: Action type
 * @parm: Callback data containing reclaim information
 *
 * Return: NOTIFY_OK
 */
static int lowmem_notifier_callback(struct notifier_block *nb,
				    unsigned long action, void *parm)
{
	struct reclaim_notify_data *data = parm;
	struct sentry_msg_helper_msg msg = {0};
	int ret, i;
	bool should_report = false;

	if (!g_oom_enable)
		return NOTIFY_OK;

	if (data->reason > RR_HUGEPAGE_RECLAIM)
		return NOTIFY_OK;

	if (__ratelimit(&oom_log_rs)) {
		pr_info("got lowmem message. pid=%d sync=%d reason=%d\n",
			current->pid, data->sync, data->reason);
	}

	for (i = 0; i < OOM_EVENT_MAX_NUMA_NODES; i++)
		msg.helper_msg_info.oom_info.nid[i] = -1;

	msg.type = SMH_MESSAGE_OOM;
	msg.helper_msg_info.oom_info.nr_nid = data->nr_nid > OOM_EVENT_MAX_NUMA_NODES ?
					 OOM_EVENT_MAX_NUMA_NODES : data->nr_nid;
	for (i = 0; i < msg.helper_msg_info.oom_info.nr_nid; i++)
		msg.helper_msg_info.oom_info.nid[i] = data->nid[i];

	for (i = 0; i < msg.helper_msg_info.oom_info.nr_nid; i++) {
		ret = oom_rate_limit_check(data->reason, data->nid[i]);
		if (ret == 0) {
			should_report = true;
			break;
		}
	}

	if (!should_report)
		return NOTIFY_OK;

	msg.helper_msg_info.oom_info.sync = data->sync;
	msg.helper_msg_info.oom_info.timeout = oom_timeout_ms;
	msg.helper_msg_info.oom_info.reason = data->reason;
	msg.timeout_time = oom_timeout_ms + REPORT_COMM_TIME;

	ret = smh_message_retry_send(&msg, data->sync);
	if (ret)
		data->nr_freed = 0;
	else
		data->nr_freed = msg.res;

	return NOTIFY_OK;
}

static struct notifier_block lowmem_notifier = {
	.notifier_call = lowmem_notifier_callback,
	.priority = INT_MAX,
};

/**
 * proc_oom_enable_write - Write handler for oom proc file
 * @file: File structure
 * @ubuf: User buffer
 * @cnt: Number of bytes to write
 * @ppos: File position
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t proc_oom_enable_write(struct file *file,
						 const char __user *ubuf,
						 size_t cnt, loff_t *ppos)
{
	int ret;
	char oom_enable[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for oom, the value can only be 'off' or 'on'.\n");
		return -EINVAL;
	}

	ret = copy_from_user(oom_enable, ubuf, cnt);
	if (ret) {
		pr_err("set oom failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && oom_enable[cnt - 1] == '\n')
		oom_enable[cnt - 1] = '\0';

	if (strcmp(oom_enable, "on") == 0) {
		g_oom_enable = true;
	} else if (strcmp(oom_enable, "off") == 0) {
		g_oom_enable = false;
	} else {
		pr_err("invalid value for oom\n");
		return -EINVAL;
	}

	pr_info("%s oom event report\n", g_oom_enable ? "enable" : "disable");
	return cnt;
}

/**
 * proc_oom_enable_show - Read handler for oom proc file
 * @file: File structure
 * @buf: User buffer
 * @count: Number of bytes to read
 * @ppos: File position
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t proc_oom_enable_show(struct file *file,
						char __user *buf,
						size_t count, loff_t *ppos)
{
	const char *value = g_oom_enable ? "on" : "off";
	size_t len = g_oom_enable ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, value, len);
}

static const struct proc_ops proc_oom_file_operations = {
	.proc_read	= proc_oom_enable_show,
	.proc_write	= proc_oom_enable_write,
};

/**
 * proc_power_off_enable_write - Write handler for power_off proc file
 * @file: File structure
 * @ubuf: User buffer
 * @cnt: Number of bytes to write
 * @ppos: File position
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t proc_power_off_enable_write(struct file *file,
						 const char __user *ubuf,
						 size_t cnt, loff_t *ppos)
{
	int ret;
	char power_off_enable[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for power_off, the value can only be 'off' or 'on'.\n");
		return -EINVAL;
	}

	ret = copy_from_user(power_off_enable, ubuf, cnt);
	if (ret) {
		pr_err("set power_off failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && power_off_enable[cnt - 1] == '\n')
		power_off_enable[cnt - 1] = '\0';

	if (strcmp(power_off_enable, "on") == 0) {
		g_power_off_enable = true;
	} else if (strcmp(power_off_enable, "off") == 0) {
		g_power_off_enable = false;
	} else {
		pr_err("invalid value for power_off\n");
		return -EINVAL;
	}

	pr_info("%s powef off event report\n", g_power_off_enable ? "enable" : "disable");
	return cnt;
}

/**
 * proc_power_off_enable_show - Read handler for power_off proc file
 * @file: File structure
 * @buf: User buffer
 * @count: Number of bytes to read
 * @ppos: File position
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t proc_power_off_enable_show(struct file *file,
						char __user *buf,
						size_t count, loff_t *ppos)
{
	const char *value = g_power_off_enable ? "on" : "off";
	size_t len = g_power_off_enable ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, value, len);
}

static const struct proc_ops proc_power_off_enable_file_operations = {
	.proc_read	= proc_power_off_enable_show,
	.proc_write	= proc_power_off_enable_write,
};

/**
 * proc_ub_mem_fault_enable_write - Write handler for ub_mem_fault proc file
 * @file: File structure
 * @ubuf: User buffer
 * @cnt: Number of bytes to write
 * @ppos: File position
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t proc_ub_mem_fault_enable_write(struct file *file,
						 const char __user *ubuf,
						 size_t cnt, loff_t *ppos)
{
	int ret;
	char ub_mem_fault_enable[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for ub_mem_fault, the value can only be 'off' or 'on'.\n");
		return -EINVAL;
	}

	ret = copy_from_user(ub_mem_fault_enable, ubuf, cnt);
	if (ret) {
		pr_err("set ub_mem_fault failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && ub_mem_fault_enable[cnt - 1] == '\n')
		ub_mem_fault_enable[cnt - 1] = '\0';

	if (strcmp(ub_mem_fault_enable, "on") == 0) {
		g_ub_mem_fault_enable = true;
	} else if (strcmp(ub_mem_fault_enable, "off") == 0) {
		g_ub_mem_fault_enable = false;
	} else {
		pr_err("invalid value for ub_mem_fault\n");
		return -EINVAL;
	}

	pr_info("%s UB memory fault event report\n", g_ub_mem_fault_enable ? "enable" : "disable");
	return cnt;
}

/**
 * proc_ub_mem_fault_enable_show - Read handler for ub_mem_fault proc file
 * @file: File structure
 * @buf: User buffer
 * @count: Number of bytes to read
 * @ppos: File position
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t proc_ub_mem_fault_enable_show(struct file *file,
						char __user *buf,
						size_t count, loff_t *ppos)
{
	const char *value = g_ub_mem_fault_enable ? "on" : "off";
	size_t len = g_ub_mem_fault_enable ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, value, len);
}

static const struct proc_ops proc_ub_mem_fault_enable_file_operations = {
	.proc_read	= proc_ub_mem_fault_enable_show,
	.proc_write	= proc_ub_mem_fault_enable_write,
};

/**
 * proc_ub_mem_fault_with_kill_write - Write handler for ub_mem_fault_with_kill proc file
 * @file: File structure
 * @ubuf: User buffer
 * @cnt: Number of bytes to write
 * @ppos: File position
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t proc_ub_mem_fault_with_kill_write(struct file *file,
						 const char __user *ubuf,
						 size_t cnt, loff_t *ppos)
{
	int ret;
	char ub_mem_fault_with_kill[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for ub_mem_fault_with_kill, the value can only be 'off' or 'on'.\n");
		return -EINVAL;
	}

	ret = copy_from_user(ub_mem_fault_with_kill, ubuf, cnt);
	if (ret) {
		pr_err("set ub_mem_fault_with_kill failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && ub_mem_fault_with_kill[cnt - 1] == '\n')
		ub_mem_fault_with_kill[cnt - 1] = '\0';

	if (strcmp(ub_mem_fault_with_kill, "on") == 0) {
		g_ub_mem_fault_with_kill = 1;
	} else if (strcmp(ub_mem_fault_with_kill, "off") == 0) {
		g_ub_mem_fault_with_kill = 0;
	} else {
		pr_err("invalid value for ub_mem_fault_with_kill\n");
		return -EINVAL;
	}

	return cnt;
}

/**
 * proc_ub_mem_fault_with_kill_show - Read handler for ub_mem_fault_with_kill proc file
 * @file: File structure
 * @buf: User buffer
 * @count: Number of bytes to read
 * @ppos: File position
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t proc_ub_mem_fault_with_kill_show(struct file *file,
						char __user *buf,
						size_t count, loff_t *ppos)
{
	const char *value = g_ub_mem_fault_with_kill ? "on" : "off";
	size_t len = g_ub_mem_fault_with_kill ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, value, len);
}

static const struct proc_ops proc_ub_mem_fault_with_kill_file_operations = {
	.proc_read	= proc_ub_mem_fault_with_kill_show,
	.proc_write	= proc_ub_mem_fault_with_kill_write,
};

/**
 * proc_oom_rate_limit_write - Write handler for proc interface to configure OOM rate limit
 * @file: Proc file structure (unused)
 * @ubuf: User-space buffer containing configuration string
 * @cnt: Number of bytes to write
 * @ppos: File position (unused)
 *
 * This function handles write operations to the proc file for OOM rate limit configuration.
 * It copies the user buffer, removes trailing newline if present, and passes the configuration
 * string to the rate limit configuration handler.
 *
 * Configuration string format: "event1:limit1,event2:limit2,..."
 * Example: "RR_KSWAPD:10,RR_DIRECT_RECLAIM:5"
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t proc_oom_rate_limit_write(struct file *file,
					 const char __user *ubuf,
					 size_t cnt, loff_t *ppos)
{
	char *buf;
	int ret;

	if (cnt == 0 || cnt > OOM_RATE_LIMIT_RAW_STR_MAX_LEN) {
		pr_err("invalid input length for oom_rate_limit, max %d\n",
		       OOM_RATE_LIMIT_RAW_STR_MAX_LEN);
		return -EINVAL;
	}

	buf = kzalloc(cnt + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, ubuf, cnt)) {
		kfree(buf);
		return -EFAULT;
	}

	if (cnt > 0 && buf[cnt - 1] == '\n')
		buf[cnt - 1] = '\0';

	ret = oom_rate_limit_config_write(buf, cnt);
	kfree(buf);

	if (ret)
		return ret;

	return cnt;
}

/**
 * proc_oom_rate_limit_show - Read handler for proc interface to show OOM rate limit config
 * @file: Proc file structure (unused)
 * @buf: User-space buffer to receive configuration data
 * @count: Maximum number of bytes to read
 * @ppos: File position (updated by simple_read_from_buffer)
 *
 * This function handles read operations from the proc file for OOM rate limit configuration.
 * It retrieves the current configuration, formats it as a string, and copies it to user space.
 *
 * Output format: "event1:limit1,event2:limit2,..." followed by newline
 * Example: "RR_KSWAPD:10,RR_DIRECT_RECLAIM:5\n"
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t proc_oom_rate_limit_show(struct file *file,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char *kbuf;
	int ret;

	kbuf = kzalloc(OOM_RATE_LIMIT_RAW_STR_MAX_LEN, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = oom_rate_limit_config_read(kbuf, OOM_RATE_LIMIT_RAW_STR_MAX_LEN);
	if (ret < 0) {
		kfree(kbuf);
		return ret;
	}

	ret = simple_read_from_buffer(buf, count, ppos, kbuf, ret);
	kfree(kbuf);

	return ret;
}

static const struct proc_ops proc_oom_rate_limit_file_operations = {
	.proc_read	= proc_oom_rate_limit_show,
	.proc_write	= proc_oom_rate_limit_write,
};

/**
 * ub_mem_ras_handler - UB memory RAS error handler
 * @phys_addr: Physical address of the error
 * @err_type: Error type
 *
 * Return: 0 on success
 */
static int ub_mem_ras_handler(uint64_t phys_addr, enum ras_err_type err_type)
{
	struct sentry_msg_helper_msg msg = {0};
	struct page *page;
	unsigned long pfn;
	int ret;

	if (!g_ub_mem_fault_enable)
		return 0;

	pr_info("ub mem error: type=%d\n", err_type);

	msg.helper_msg_info.ub_mem_info.pa = phys_addr;
	msg.helper_msg_info.ub_mem_info.raw_ubus_mem_err_type = err_type;
	msg.msgid = smh_get_new_msg_id();
	msg.type = SMH_MESSAGE_UB_MEM_ERR;
	msg.start_send_time = ktime_get_ns();
	msg.timeout_time = ULLONG_MAX;

	if ((err_type == REMOTE_READ_DATA_ERR_OR_WRITE_RESPONSE_ERR ||
	     err_type == UB_MEM_READ_DATA_ERR ||
	     err_type == UB_MEM_FLOW_POISON ||
	     err_type == UB_MEM_READ_DATA_POISON ||
	     err_type == UB_MEM_READ_DATA_RESPERR) && g_ub_mem_fault_with_kill) {
		msg.helper_msg_info.ub_mem_info.fault_with_kill = 1;
	} else {
		msg.helper_msg_info.ub_mem_info.fault_with_kill = 0;
	}

	/* Check mode (FD or NUMA) */
	page = pfn_to_online_page(PHYS_PFN(phys_addr));

	if (!page) {
		/* FD mode */
		msg.helper_msg_info.ub_mem_info.mem_type = FD_MODE;
		pr_info("ub mem error: mem mode is fd mode\n");
	} else {
		/* NUMA mode */
		pfn = PHYS_PFN(phys_addr);
		msg.helper_msg_info.ub_mem_info.mem_type = NUMA_MODE;
		pr_info("ub mem error: mem mode is numa mode\n");
		if (pfn != 0) {
			if (msg.helper_msg_info.ub_mem_info.fault_with_kill)
				memory_failure_queue(pfn, 0);
		} else {
			pr_warn("pfn is 0x0, skip memory_failure processing\n");
		}
	}

	ret = smh_message_send(&msg, false);
	if (ret)
		pr_err("Failed to send remote message to userspace. %d\n", ret);

	return 0;
}

/**
 * sentry_reporter_init - Module initialization function
 *
 * Return: 0 on success, negative error code on failure
 */
static int __init sentry_reporter_init(void)
{
	int ret;

	ret = check_if_timeout_param_valid();
	if (ret)
		return ret;

	oom_rate_limit_init();

	g_sentry_reporter_proc_dir = proc_mkdir_mode("sentry_reporter",
						     PROC_DIR_PERMISSION, NULL);
	if (!g_sentry_reporter_proc_dir) {
		pr_err("create /proc/sentry_reporter dir failed\n");
		return -ENOMEM;
	}

	ret = sentry_create_proc_file("ub_mem_fault_with_kill",
				      g_sentry_reporter_proc_dir,
				      &proc_ub_mem_fault_with_kill_file_operations);
	ret |= sentry_create_proc_file("oom",
				      g_sentry_reporter_proc_dir,
				      &proc_oom_file_operations);
	ret |= sentry_create_proc_file("power_off",
				      g_sentry_reporter_proc_dir,
				      &proc_power_off_enable_file_operations);
	ret |= sentry_create_proc_file("ub_mem_fault",
				      g_sentry_reporter_proc_dir,
				      &proc_ub_mem_fault_enable_file_operations);
	ret |= sentry_create_proc_file("oom_rate_limit",
				      g_sentry_reporter_proc_dir,
				      &proc_oom_rate_limit_file_operations);
	if (ret < 0)
		goto remove_proc_dir;

	ret = register_acpi_power_notifier(&acpi_power_notifier);
	pr_info("power notifier register %s\n", ret ? "failed" : "successful");
	if (ret)
		goto remove_proc_dir;

	ret = register_reclaim_notifier(&lowmem_notifier);
	pr_info("lowmem notifier register %s\n", ret ? "failed" : "successful");
	if (ret)
		goto unregister_power_notifier;

	ub_mem_ras_handler_register(ub_mem_ras_handler);
	pr_info("ubus notifier register successful\n");

	return 0;

unregister_power_notifier:
	unregister_acpi_power_notifier(&acpi_power_notifier);
	pr_info("power notifier unregistered\n");
remove_proc_dir:
	proc_remove(g_sentry_reporter_proc_dir);
	pr_info("proc file removed\n");
	return ret;
}

/**
 * sentry_reporter_exit - Module cleanup function
 */
static void __exit sentry_reporter_exit(void)
{
	unregister_acpi_power_notifier(&acpi_power_notifier);
	pr_info("power notifier unregistered\n");

	unregister_reclaim_notifier(&lowmem_notifier);
	pr_info("lowmem notifier unregistered\n");

	ub_mem_ras_handler_unregister();
	pr_info("ub_mem notifier unregistered\n");

	proc_remove(g_sentry_reporter_proc_dir);
	pr_info("proc file removed\n");
}

module_init(sentry_reporter_init);
module_exit(sentry_reporter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luckky");
MODULE_DESCRIPTION("sentry reporter: report kernel events to userspace");
MODULE_VERSION("1.0");
