// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include "common/driver.h"

#define QPTS_ELEMENT_MAX_NUM   0x4000 //16384 = 16k

static struct proc_dir_entry *g_entry;
static DECLARE_WAIT_QUEUE_HEAD(g_ring_buff_wait);
static struct xsc_qpt_update_msg *g_ring_buff;
static spinlock_t g_ring_buff_lock;

static unsigned long R;
static unsigned long R_cur;
static unsigned long W;
static unsigned long open_once_flag;

static int read_buff(struct xsc_qpt_update_msg *msg)
{
	spin_lock_irq(&g_ring_buff_lock);
	if (R_cur == W) {
		spin_unlock_irq(&g_ring_buff_lock);
		return 0;
	}

	*msg = g_ring_buff[R_cur];
	R_cur = (R_cur + 1) % QPTS_ELEMENT_MAX_NUM;
	spin_unlock_irq(&g_ring_buff_lock);

	return 1;
}

static void write_buff(struct xsc_qpt_update_msg *msg)
{
	spin_lock_irq(&g_ring_buff_lock);
	g_ring_buff[W] = *msg;
	W = (W + 1) % QPTS_ELEMENT_MAX_NUM;
	if (R == W)
		R = (R + 1) % QPTS_ELEMENT_MAX_NUM;

	if (R_cur == W)
		R_cur = (R_cur + 1) % QPTS_ELEMENT_MAX_NUM;

	spin_unlock_irq(&g_ring_buff_lock);

	wake_up_interruptible(&g_ring_buff_wait);
}

int qpts_write_one_msg(struct xsc_qpt_update_msg *msg)
{
	if (!msg)
		return -1;

	write_buff(msg);

	return 0;
}
EXPORT_SYMBOL(qpts_write_one_msg);

static int qpts_open(struct inode *inode, struct file *file)
{
	spin_lock_irq(&g_ring_buff_lock);
	if (open_once_flag) {
		spin_unlock_irq(&g_ring_buff_lock);
		return -1;
	}
	open_once_flag = 1;
	R_cur = R;
	spin_unlock_irq(&g_ring_buff_lock);

	return 0;
}

static int qpts_release(struct inode *inode, struct file *file)
{
	spin_lock_irq(&g_ring_buff_lock);
	open_once_flag = 0;
	spin_unlock_irq(&g_ring_buff_lock);

	wake_up_poll(&g_ring_buff_wait, EPOLLHUP);

	return 0;
}

static ssize_t qpts_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int error = -EINVAL, i = 0;
	struct xsc_qpt_update_msg qpt_msg = {0};

	if ((file->f_flags & O_NONBLOCK) && R_cur == W)
		goto out;

	if (!buf || !count) {
		pr_err("%s error, null buffer or count!\n", __func__);
		goto out;
	}

	error = wait_event_interruptible(g_ring_buff_wait, (R_cur != W));
	if (error)
		goto out;

	while (!error && i < count && read_buff(&qpt_msg)) {
		error = copy_to_user(buf, &qpt_msg, sizeof(qpt_msg));
		buf += sizeof(qpt_msg);
		i += sizeof(qpt_msg);
	}

	if (!error)
		error = i;

out:
	return error;
}

static __poll_t qpts_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &g_ring_buff_wait, wait);

	if (R_cur != W)
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}

const struct proc_ops qpts_ops = {
	.proc_open = qpts_open,
	.proc_read = qpts_read,
	.proc_poll = qpts_poll,
	.proc_release = qpts_release,
};

int qpts_init(void)
{
	g_ring_buff = kcalloc(QPTS_ELEMENT_MAX_NUM, sizeof(struct xsc_qpt_update_msg), GFP_KERNEL);
	if (!g_ring_buff)
		return -ENOMEM;

	spin_lock_init(&g_ring_buff_lock);

	g_entry = proc_create_data("qpts_kmsg", 0400, NULL, &qpts_ops, NULL);
	if (!g_entry) {
		pr_err("Could not create /proc/qpts_kmsg file!\n");
		goto error_qpts_init;
	}

	return 0;

error_qpts_init:
	kfree(g_ring_buff);
	g_ring_buff = NULL;
	return -1;
}

void qpts_fini(void)
{
	remove_proc_entry("qpts_kmsg", NULL);

	kfree(g_ring_buff);
	g_ring_buff = NULL;
	g_entry = NULL;
}

