// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include <linux/debugfs.h>
#include <linux/sizes.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>
#include <asm/kvm_rme_hisi_cca.h>

#undef pr_fmt
#define pr_fmt(fmt) "rme: " fmt

#define RME_LOG_MODE_BUFFER (2U)
#define DEBUGFS_CFG_BUF_SIZE (32U)
#define RME_LOG_BUFFER_SIZE SZ_2M

/* Control how rme logs are exported from ring buffer */
enum log_read_mode {
	RB_LOG_COPY,
	RB_LOG_CONSUME,
	RB_LOG_MODE_MAX
};

struct rme_log {
	atomic_t active_readers;
	/* 0: none, 10: error, 20: notice, 30: warn, 40:info, 50:verbose */
	atomic_t level;
	/* 0: none, 1: uart, 2: buffer, 3: uart+buffer */
	atomic_t mode;
};

struct rme_log rme_logger;

struct rme_log_state {
	bool has_been_read;
	unsigned long log_order;
	char *log_buf; /* Physically contiguous buffer for firmware read */
};

static ssize_t rme_get_log_contents(char *buf, size_t size)
{
	unsigned long phy_addr;
	unsigned long resp_len;
	int ret;

	phy_addr = virt_to_phys(buf);
	if (!phy_addr) {
		pr_err_ratelimited("Invalid physical address\n");
		return -EFAULT;
	}

	ret = rmi_cca_hisi_read_log(phy_addr, size, RB_LOG_COPY, &resp_len);
	if (ret == SMCCC_RET_NOT_SUPPORTED)
		return -EOPNOTSUPP;
	if (RMI_RETURN_STATUS(ret) != RMI_SUCCESS) {
		pr_err_ratelimited("Failed to read rmm log: %d\n", ret);
		return -EIO;
	}

	if (resp_len > size) {
		pr_err_ratelimited("Firmware overflow: %lu > %zu\n", resp_len, size);
		return -EIO;
	}

	return (ssize_t)resp_len;
}

static int rme_log_read(struct seq_file *m, void *v)
{
	struct rme_log_state *state = m->private;
	ssize_t ret;

	/* Enforce single-read per open(): subsequent reads return EOF */
	if (state->has_been_read)
		return 0;

	ret = rme_get_log_contents(state->log_buf, RME_LOG_BUFFER_SIZE);
	if (ret == -EOPNOTSUPP)
		seq_puts(m, "RMM firmware does not support log control interface\n");
	else if (ret < 0)
		seq_printf(m, "RME log read failed: %zd\n", ret);
	else if (ret == 0)
		seq_puts(m, "RME log is empty\n");
	else
		seq_write(m, state->log_buf, ret);

	state->has_been_read = true;
	return 0;
}

static int rme_log_open(struct inode *inode, struct file *file)
{
	struct rme_log_state *state;
	int ret;

	if (atomic_inc_return(&rme_logger.active_readers) > 1) {
		ret = -EBUSY;
		goto out_dec;
	}

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		ret = -ENOMEM;
		goto out_dec;
	}

	state->log_order = get_order(RME_LOG_BUFFER_SIZE);
	state->log_buf = (char *)__get_free_pages(
		GFP_KERNEL | __GFP_ZERO, state->log_order);
	if (!state->log_buf) {
		ret = -ENOMEM;
		goto out_free_state;
	}

	/*
	 * Use single_open_size to ensure seq_file's internal buffer
	 * is large enough to hold the entire log (2MB + 1 byte safety margin).
	 * This allows seq_write() to succeed without truncation.
	 */
	ret = single_open_size(file, rme_log_read, state,
		RME_LOG_BUFFER_SIZE + 1);
	if (ret)
		goto out_free_buf;

	return 0;

out_free_buf:
	free_pages((unsigned long)state->log_buf, state->log_order);
out_free_state:
	kfree(state);
out_dec:
	atomic_dec(&rme_logger.active_readers);
	return ret;
}

static int rme_log_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct rme_log_state *state = m->private;

	if (state) {
		free_pages((unsigned long)state->log_buf, state->log_order);
		kfree(state);
		m->private = NULL;
	}
	atomic_dec(&rme_logger.active_readers);
	return single_release(inode, file);
}

static const struct file_operations rme_log_fops = {
	.open = rme_log_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = rme_log_release,
};

static int rme_set_log_level(void *data, int val)
{
	int ret;

	ret = rmi_cca_hisi_set_log_level(val);
	if (ret == SMCCC_RET_NOT_SUPPORTED)
		return -EOPNOTSUPP;
	if (RMI_RETURN_STATUS(ret) != RMI_SUCCESS) {
		pr_err_ratelimited("Failed to set log level: %d\n", ret);
		return -EIO;
	}
	atomic_set((atomic_t *)data, val);
	return 0;
}

static int rme_set_log_mode(void *data, int val)
{
	int ret;

	ret = rmi_cca_hisi_set_log_mode(val);
	if (ret == SMCCC_RET_NOT_SUPPORTED)
		return -EOPNOTSUPP;
	if (RMI_RETURN_STATUS(ret) != RMI_SUCCESS) {
		pr_err_ratelimited("Failed to set log mode: %d\n", ret);
		return -EIO;
	}
	atomic_set((atomic_t *)data, val);
	return 0;
}

static int atomic_val_get(void *data)
{
	return atomic_read((atomic_t *)data);
}

struct debugfs_var_attr {
	void *data;
	int (*get)(void *data);
	int (*set)(void *data, int val);
	int min_val;
	int max_val;
};

static ssize_t debugfs_var_read(struct file *file, char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct debugfs_var_attr *attr = file->private_data;
	char buf[DEBUGFS_CFG_BUF_SIZE];
	int val = attr->get(attr->data);
	int len;

	len = snprintf(buf, sizeof(buf), "%d\n", val);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t debugfs_var_write(struct file *file,
				 const char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	struct debugfs_var_attr *attr = file->private_data;
	char buf[DEBUGFS_CFG_BUF_SIZE];
	int val;
	int ret;

	if (count >= sizeof(buf) - 1)
		return -EINVAL;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	buf[count] = '\0';

	if (kstrtos32(buf, 0, &val))
		return -EINVAL;

	if (val < attr->min_val || val > attr->max_val)
		return -EINVAL;

	ret = attr->set(attr->data, val);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations debugfs_var_fops = {
	.read = debugfs_var_read,
	.write = debugfs_var_write,
	.open = simple_open,
};

#define DEFINE_DEBUGFS_VAR(name, data, min, max, get_func, set_func) \
static struct debugfs_var_attr name##_attr = { \
	(void *)(data), \
	(int (*)(void *))(get_func), \
	(int (*)(void *, int))(set_func), \
	(min), \
	(max) \
}

DEFINE_DEBUGFS_VAR(log_level, &rme_logger.level, 0, 50,
	atomic_val_get, rme_set_log_level);
DEFINE_DEBUGFS_VAR(log_mode, &rme_logger.mode, 0, 3,
	atomic_val_get, rme_set_log_mode);

static int rme_log_init(void)
{
	atomic_set(&rme_logger.level, -1);
	atomic_set(&rme_logger.mode, -1);
	return 0;
}

/* RME is built-in only; debugfs entries persist until shutdown. */
void realm_hisi_cca_init_debug(void)
{
	struct dentry *rme_dir;
	int ret;

	rme_dir = debugfs_create_dir("rme", NULL);
	if (!rme_dir) {
		pr_err("Failed to create debugfs dir.\n");
		return;
	}

	rme_log_init();

	debugfs_create_file("rme_log", 0400, rme_dir,
			    NULL, &rme_log_fops);
	debugfs_create_file("log_level", 0600, rme_dir,
			    &log_level_attr, &debugfs_var_fops);
	debugfs_create_file("log_mode", 0600, rme_dir,
			    &log_mode_attr, &debugfs_var_fops);

	ret = rme_set_log_mode(&rme_logger.mode, RME_LOG_MODE_BUFFER);
	if (ret == -EOPNOTSUPP)
		pr_info("RMM does not support log control, debugfs entries are informational only\n");
}

