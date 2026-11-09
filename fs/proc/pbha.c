// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/kstrtox.h>
#include <linux/pbha.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "internal.h"

static int pbha_bit0_check(struct task_struct *task)
{
	if (!system_support_pbha_bit0())
		return -EACCES;

	if (is_global_init(task))
		return -EACCES;

	if (!task->mm || (task->flags & PF_KTHREAD) ||
	    (task->flags & PF_EXITING))
		return -EACCES;

	return 0;
}

static ssize_t pbha_bit0_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	char buffer[PROC_NUMBUF];
	struct mm_struct *mm;
	size_t len;
	short val;
	int err;

	if (!task)
		return -ESRCH;

	err = pbha_bit0_check(task);
	if (err) {
		put_task_struct(task);
		return err;
	}

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -ESRCH;
	}

	val = mm->def_flags & VM_PBHA_BIT0 ? 1 : 0;
	mmput(mm);
	put_task_struct(task);
	len = snprintf(buffer, sizeof(buffer), "%hd\n", val);

	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t pbha_bit0_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	char buffer[PROC_NUMBUF];
	struct mm_struct *mm;
	int val, err;

	if (!task)
		return -ESRCH;

	err = pbha_bit0_check(task);
	if (err)
		goto out;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		err = -EFAULT;
		goto out;
	}

	err = kstrtoint(strstrip(buffer), 0, &val);
	if (err)
		goto out;
	if (val != 0 && val != 1) {
		err = -EINVAL;
		goto out;
	}

	mm = get_task_mm(task);
	if (!mm) {
		err = -ENOENT;
		goto out;
	}

	err = pbha_bit0_update_vma(mm, val);
	mmput(mm);
out:
	put_task_struct(task);
	return err < 0 ? err : count;
}

const struct file_operations proc_pbha_bit0_ops = {
	.read       = pbha_bit0_read,
	.write      = pbha_bit0_write,
	.llseek     = generic_file_llseek,
};

bool pbha_bit0_hide_file(const char *name)
{
	if (!system_support_pbha_bit0() && !strncmp("pbha_bit0", name, 9))
		return true;

	return false;
}
