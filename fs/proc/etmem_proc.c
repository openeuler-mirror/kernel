// SPDX-License-Identifier: GPL-2.0
#include <linux/seq_file.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/swap.h>
#include <linux/sched/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/uaccess.h>
#include <linux/pkeys.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/etmem.h>

#include "internal.h"

static DEFINE_SPINLOCK(scan_lock);

static int page_scan_lock(struct file *file, int is_lock, struct file_lock *flock)
{
	if (is_lock)
		spin_lock(&scan_lock);
	else
		spin_unlock(&scan_lock);

	return 0;
}

/* will be filled when kvm_ept_idle module loads */
struct file_operations proc_page_scan_operations = {
	.flock = page_scan_lock,
};
EXPORT_SYMBOL_GPL(proc_page_scan_operations);

static ssize_t mm_idle_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct mm_struct *mm = file->private_data;
	int ret = 0;

	if (!mm || !mmget_not_zero(mm)) {
		ret = -ESRCH;
		return ret;
	}
	if (proc_page_scan_operations.read)
		ret = proc_page_scan_operations.read(file, buf, count, ppos);

	mmput(mm);
	return ret;
}

static int mm_idle_open(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = NULL;
	struct module *module = NULL;
	int ret = -1;

	if (!file_ns_capable(file, &init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	page_scan_lock(NULL, 1, NULL);
	module = proc_page_scan_operations.owner;
	if (module != NULL && try_module_get(module))
		ret = 0;
	page_scan_lock(NULL, 0, NULL);
	if (ret != 0) {
		/* no scan ko installed, avoid to return valid file */
		return -ENODEV;
	}

	mm = proc_mem_open(inode, PTRACE_MODE_READ);
	if (IS_ERR(mm)) {
		module_put(module);
		return PTR_ERR(mm);
	}

	file->private_data = mm;

	if (proc_page_scan_operations.open)
		ret = proc_page_scan_operations.open(inode, file);

	if (ret != 0)
		module_put(module);

	return ret;
}

static int mm_idle_release(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = file->private_data;
	int ret = 0;

	if (mm) {
		if (!mm_kvm(mm))
			flush_tlb_mm(mm);
		mmdrop(mm);
	}

	if (proc_page_scan_operations.release)
		ret = proc_page_scan_operations.release(inode, file);

	if (proc_page_scan_operations.owner)
		module_put(proc_page_scan_operations.owner);

	return ret;
}

static long mm_idle_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (proc_page_scan_operations.unlocked_ioctl)
		return proc_page_scan_operations.unlocked_ioctl(filp, cmd, arg);

	return 0;
}

const struct file_operations proc_mm_idle_operations = {
	.llseek		= mem_lseek, /* borrow this */
	.read		= mm_idle_read,
	.open		= mm_idle_open,
	.release	= mm_idle_release,
	.unlocked_ioctl = mm_idle_ioctl,
};

static DEFINE_SPINLOCK(swap_lock);

static int page_swap_lock(struct file *file, int is_lock, struct file_lock *flock)
{
	if (is_lock)
		spin_lock(&swap_lock);
	else
		spin_unlock(&swap_lock);

	return 0;
}
/*swap pages*/
struct file_operations proc_swap_pages_operations = {
	.flock = page_swap_lock,
};
EXPORT_SYMBOL_GPL(proc_swap_pages_operations);

static ssize_t mm_swap_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	if (proc_swap_pages_operations.write)
		return proc_swap_pages_operations.write(file, buf, count, ppos);

	return -1;
}

static int mm_swap_open(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = NULL;
	struct module *module = NULL;
	int ret = -1;

	if (!file_ns_capable(file, &init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	page_swap_lock(NULL, 1, NULL);
	module = proc_swap_pages_operations.owner;
	if (module != NULL && try_module_get(module))
		ret = 0;
	page_swap_lock(NULL, 0, NULL);
	if (ret != 0) {
		/* no swap ko installed, avoid to return valid file */
		return -ENODEV;
	}

	mm = proc_mem_open(inode, PTRACE_MODE_READ);
	if (IS_ERR(mm)) {
		module_put(module);
		return PTR_ERR(mm);
	}

	file->private_data = mm;

	if (proc_swap_pages_operations.open)
		ret = proc_swap_pages_operations.open(inode, file);

	if (ret != 0)
		module_put(module);

	return ret;
}

static int mm_swap_release(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = file->private_data;
	int ret = 0;

	if (mm)
		mmdrop(mm);

	if (proc_swap_pages_operations.release)
		ret = proc_swap_pages_operations.release(inode, file);

	if (proc_swap_pages_operations.owner)
		module_put(proc_swap_pages_operations.owner);

	return ret;
}

static long mm_swap_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (proc_swap_pages_operations.unlocked_ioctl)
		return proc_swap_pages_operations.unlocked_ioctl(filp, cmd, arg);
	return 0;
}

const struct file_operations proc_mm_swap_operations = {
	.llseek     = mem_lseek,
	.write      = mm_swap_write,
	.open       = mm_swap_open,
	.release    = mm_swap_release,
	.unlocked_ioctl = mm_swap_ioctl,
};
