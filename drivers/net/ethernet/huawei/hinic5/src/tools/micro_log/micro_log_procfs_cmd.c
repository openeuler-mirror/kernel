/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : micro_log_procfs_cmd.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Used to dynamically change host log state: supports dynamic switching between info and err logs
 */
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stat.h>

#include "micro_log_procfs_cmd.h"
#include "micro_log_comm.h"
#include "hinic5_hwdev.h"
#include "hinic5_chip_info.h"

/****************************for proc fs****************************************/
#define MICRO_LOG_PROCFS_NAME			"micro_log"
#define LOG_LEVEL_PROCFS_NAME			"log_level"
#define LOG_LEVEL_MAX_LEN 2 /* Normally only two characters are used:
			     * one for log level, one for newline from echo
			     */
#define DEC_CODE 10
#define HINIC_DEV_NAME_LEN 32
static struct proc_dir_entry *proc_micro_log_dir;
static struct proc_dir_entry *proc_hinic_dev_dir;
static struct proc_dir_entry *proc_log_level_file;
void *g_micro_log_dev;

#define PROCFS_RD_BUFFER_SIZE	(LOG_LEVEL_INFO_MAX_SIZE + 1)
static char log_level_procfs_buffer_rd[PROCFS_RD_BUFFER_SIZE] = {0};

static char hinic_dev_name[HINIC_DEV_NAME_LEN + 1] = {0};
static struct log_level_message log_level_msg[] = {
	{ALL_LOG_DROP, "ALL_LOG_DROP"}, {ERR_LOG_PRINT, "ERR_LOG"},
	{WARN_LOG_PRINT, "WARN_LOG"}, {INFO_LOG_PRINT, "INFO_LOG"}
};

/* 1) state = 0, do not print logs
 * 2) state = 1, print err logs
 * 3) state = 2, warn logs: include err and warn logs
 * 4) state = 3, info logs: include err, warn, and info logs
 */
static int micro_log_state_set(void *hwdev, enum log_level_type state)
{
	int err;
	struct card_node *chip_node;
	struct micro_log_info *log_info;

	if (!hwdev) {
		microlog_err("hwdev is NULL!");
		return -ENOMEM;
	}

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	if (!chip_node) {
		microlog_err("chip_node is NULL!");
		return -ENOMEM;
	}

	log_info = chip_node->log_info;
	if (!log_info) {
		microlog_err("log_info is NULL!");
		return -ENOMEM;
	}

	err = hinic5_microlog_ctrl_info_set(hwdev, log_info->nic_micro_log_enable,
					    log_info->all_ci, state);
	if (err) {
		microlog_err("cmdq return fail(0x%x), state: %u", err, state);
		return err;
	}
	microlog_info("set state(%u) ok", state);
	return 0;
}

static ssize_t log_level_proc_write(struct file *file, const char __user *buff,
				    size_t len, loff_t *off)
{
	ssize_t wr_len;
	char log_level_buffer[LOG_LEVEL_MAX_LEN + 1] = { 0 };
	u32 num;

	if (!buff || len == 0) {
		microlog_err("proc parameter incorrect: buff is null or size is zero");
		return -EINVAL;
	}

	wr_len = (len > LOG_LEVEL_MAX_LEN) ? LOG_LEVEL_MAX_LEN : len;
	if (copy_from_user(&log_level_buffer, buff, wr_len) != 0) {
		microlog_err("copy_from_user failed");
		return -EFAULT;
	}

	log_level_buffer[wr_len] = '\0';
	microlog_info("procfile write: %c, %s, wr_len:0x%x",
		      log_level_buffer[0],  log_level_buffer, (u32)wr_len);
	/* Convert string to decimal number */
	num = simple_strtoul(log_level_buffer, NULL, DEC_CODE);

	if (num > INFO_LOG_PRINT) {
		microlog_err("get wrong log_level:%s", log_level_buffer);
		return -EINVAL;
	}

	if (micro_log_state_set(g_micro_log_dev, num) != 0)
		return -EINVAL;

	(void)snprintf(log_level_procfs_buffer_rd, PROCFS_RD_BUFFER_SIZE,
		       "%s\n", log_level_msg[num].level_info);
	return wr_len;
}

static ssize_t log_level_proc_read(struct file *file, char __user *buff, size_t len, loff_t *off)
{
	unsigned long plen = strlen(log_level_procfs_buffer_rd);
	ssize_t bytes_to_copy;

	if (*off >= plen) {
		/* If all data has been read, return 0, otherwise keep looping */
		return 0;
	}

	bytes_to_copy = (len < plen) ? len : plen;
	microlog_info("copy_to_user bytes_to_copy:%d.", (u32)bytes_to_copy);

	if (copy_to_user(buff, log_level_procfs_buffer_rd, bytes_to_copy) != 0) {
		microlog_err("copy to user failed!");
		bytes_to_copy = 0;
	}

	*off += bytes_to_copy;
	return bytes_to_copy;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
static const struct file_operations log_level_proc_fops = {
	.read = log_level_proc_read,
	.write = log_level_proc_write,
};
#else
static const struct proc_ops log_level_proc_fops = {
	.proc_read = log_level_proc_read,
	.proc_write = log_level_proc_write,
};
#endif

static int check_params_valid(void *hwdev)
{
	struct card_node *chip_node;
	struct micro_log_info *log_info;
	int cpy_len;

	if (!hwdev) {
		microlog_err("hwdev is NULL!");
		return -ENOMEM;
	}

	chip_node = (struct card_node *)(((struct hinic5_hwdev *)hwdev)->chip_node);
	if (!chip_node) {
		microlog_err("chip_node is NULL!");
		return -ENOMEM;
	}

	log_info = chip_node->log_info;
	if (!log_info || !log_info->hinic_micro_log_task.name) {
		microlog_err("log_info is NULL!");
		return -ENOMEM;
	}

	cpy_len = strlen(log_info->hinic_micro_log_task.name);
	if (cpy_len >= HINIC_DEV_NAME_LEN) {
		microlog_err("len beyond HINIC_DEV_NAME_LEN");
		return -EINVAL;
	}
	(void)strscpy(hinic_dev_name, log_info->hinic_micro_log_task.name, HINIC_DEV_NAME_LEN);
	hinic_dev_name[cpy_len + 1] = '\0';
	return 0;
}

int micro_log_procfs_init(void *hwdev)
{
	int ret = check_params_valid(hwdev);

	if (ret != 0)
		return ret;

	proc_micro_log_dir = proc_mkdir(MICRO_LOG_PROCFS_NAME, NULL);
	if (!proc_micro_log_dir) {
		microlog_err("Failed to create /proc/%s directory", MICRO_LOG_PROCFS_NAME);
		return -ENOMEM;
	}

	proc_hinic_dev_dir = proc_mkdir(hinic_dev_name, proc_micro_log_dir);
	if (!proc_hinic_dev_dir) {
		microlog_err("Failed to create /proc/%s directory", MICRO_LOG_PROCFS_NAME);
		return -ENOMEM;
	}

	proc_log_level_file = proc_create(LOG_LEVEL_PROCFS_NAME, 0644,
					  proc_hinic_dev_dir,
					  &log_level_proc_fops);
	if (!proc_log_level_file) {
		remove_proc_entry(MICRO_LOG_PROCFS_NAME, NULL);
		microlog_err("Failed to create /proc/micro_log/%s file", LOG_LEVEL_PROCFS_NAME);
		return -ENOMEM;
	}

	microlog_info("/proc/micro_log/%s created", LOG_LEVEL_PROCFS_NAME);
	g_micro_log_dev = hwdev;
	(void)snprintf(log_level_procfs_buffer_rd, PROCFS_RD_BUFFER_SIZE,
		       "%s\n", log_level_msg[INFO_LOG_PRINT].level_info);
	return 0;
}

void micro_log_procfs_exit(void)
{
	remove_proc_entry(LOG_LEVEL_PROCFS_NAME, proc_hinic_dev_dir);
	remove_proc_entry(hinic_dev_name, proc_micro_log_dir);
	remove_proc_entry(MICRO_LOG_PROCFS_NAME, NULL);
	microlog_info("Micro Log Module removed");
}
