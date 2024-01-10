// SPDX-License-Identifier: GPL-2.0-only
#include <linux/mem_reliable.h>

#include "internal.h"

static inline int reliable_check(struct task_struct *task, struct pid *pid)
{
	if (!mem_reliable_is_enabled())
		return -EACCES;

	if (is_global_init(task))
		return -EINVAL;

	if (!task->mm || (task->flags & PF_KTHREAD) ||
	    (task->flags & PF_EXITING))
		return -EINVAL;

	return 0;
}

static ssize_t reliable_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	struct pid *pid = proc_pid(file_inode(file));
	char buffer[PROC_NUMBUF];
	size_t len;
	short val;
	int err;

	if (!task)
		return -ESRCH;

	err = reliable_check(task, pid);
	if (err) {
		put_task_struct(task);
		return err;
	}

	val = task->flags & PF_RELIABLE ? 1 : 0;
	put_task_struct(task);
	len = snprintf(buffer, sizeof(buffer), "%hd\n", val);
	return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static ssize_t reliable_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	struct pid *pid = proc_pid(file_inode(file));
	char buffer[PROC_NUMBUF];
	int val;
	int err;

	if (!task)
		return -ESRCH;

	err = reliable_check(task, pid);
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

	if (val == 1)
		task->flags |= PF_RELIABLE;
	else
		task->flags &= ~PF_RELIABLE;

out:
	put_task_struct(task);
	return err < 0 ? err : count;
}

struct file_operations proc_reliable_operations = {
	.read       = reliable_read,
	.write      = reliable_write,
	.llseek     = generic_file_llseek,
};

bool mem_reliable_hide_file(const char *name)
{
	if (!mem_reliable_is_enabled() && !strncmp("reliable", name, 8))
		return true;

	return false;
}
