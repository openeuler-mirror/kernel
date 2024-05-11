// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mempolicy.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/etmem.h>
#include <linux/freezer.h>
#include <linux/kthread.h>

#define RECLAIM_SWAPCACHE_MAGIC 0X77
#define SET_SWAPCACHE_WMARK	_IOW(RECLAIM_SWAPCACHE_MAGIC, 0x02, unsigned int)
#define RECLAIM_SWAPCACHE_ON	_IOW(RECLAIM_SWAPCACHE_MAGIC, 0x01, unsigned int)
#define RECLAIM_SWAPCACHE_OFF	_IOW(RECLAIM_SWAPCACHE_MAGIC, 0x00, unsigned int)

#define WATERMARK_MAX           100
#define SWAP_SCAN_NUM_MAX       32

static struct task_struct *reclaim_swapcache_tk;
static bool enable_swapcache_reclaim;
static unsigned long swapcache_watermark[ETMEM_SWAPCACHE_NR_WMARK];

static DECLARE_WAIT_QUEUE_HEAD(reclaim_queue);

static ssize_t swap_pages_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char *p, *data, *data_ptr_res;
	unsigned long vaddr;
	struct mm_struct *mm = file->private_data;
	struct page *page;
	LIST_HEAD(pagelist);
	int ret = 0;

	if (!mm || !mmget_not_zero(mm)) {
		ret = -ESRCH;
		goto out;
	}

	if (count < 0) {
		ret = -EOPNOTSUPP;
		goto out_mm;
	}

	data = memdup_user_nul(buf, count);
	if (IS_ERR(data)) {
		ret = PTR_ERR(data);
		goto out_mm;
	}

	data_ptr_res = data;
	while ((p = strsep(&data, "\n")) != NULL) {
		if (!*p)
			continue;

		ret = kstrtoul(p, 16, &vaddr);
		if (ret != 0)
			continue;

		/* If get page struct failed, ignore it, get next page */
		page = get_page_from_vaddr(mm, vaddr);
		if (!page)
			continue;

		add_page_for_swap(page, &pagelist);
	}

	if (!list_empty(&pagelist))
		reclaim_pages(&pagelist, false);

	ret = count;
	kfree(data_ptr_res);
out_mm:
	mmput(mm);
out:
	return ret;
}

static int swap_pages_open(struct inode *inode, struct file *file)
{
	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	return 0;
}

static int swap_pages_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}

extern struct file_operations proc_swap_pages_operations;

/* check if swapcache meet requirements */
static bool swapcache_balanced(void)
{
	return total_swapcache_pages() < swapcache_watermark[ETMEM_SWAPCACHE_WMARK_HIGH];
}

/* the flag present if swapcache reclaim is started */
static bool swapcache_reclaim_enabled(void)
{
	return  READ_ONCE(enable_swapcache_reclaim);
}

static void start_swapcache_reclaim(void)
{
	if (swapcache_balanced())
		return;
	/* RECLAIM_SWAPCACHE_ON trigger the thread to start running. */
	if (!waitqueue_active(&reclaim_queue))
		return;

	WRITE_ONCE(enable_swapcache_reclaim, true);
	wake_up_interruptible(&reclaim_queue);
}

static void stop_swapcache_reclaim(void)
{
	WRITE_ONCE(enable_swapcache_reclaim, false);
}

static bool should_goto_sleep(void)
{
	if (swapcache_balanced())
		stop_swapcache_reclaim();

	if (swapcache_reclaim_enabled())
		return false;

	return true;
}

static int get_swapcache_watermark(unsigned int ratio)
{
	unsigned int low_watermark;
	unsigned int high_watermark;

	low_watermark = ratio & 0xFF;
	high_watermark = (ratio >> 8) & 0xFF;
	if (low_watermark > WATERMARK_MAX ||
		high_watermark > WATERMARK_MAX ||
		low_watermark > high_watermark)
		return -EPERM;

	swapcache_watermark[ETMEM_SWAPCACHE_WMARK_LOW] = totalram_pages() *
						low_watermark / WATERMARK_MAX;
	swapcache_watermark[ETMEM_SWAPCACHE_WMARK_HIGH] = totalram_pages() *
						high_watermark / WATERMARK_MAX;

	return 0;
}

static void reclaim_swapcache_try_to_sleep(void)
{
	DEFINE_WAIT(wait);

	if (freezing(current) || kthread_should_stop())
		return;

	prepare_to_wait(&reclaim_queue, &wait, TASK_INTERRUPTIBLE);
	if (should_goto_sleep()) {
		if (!kthread_should_stop())
			schedule();
	}
	finish_wait(&reclaim_queue, &wait);
}

static void etmem_reclaim_swapcache(void)
{
	do_swapcache_reclaim(swapcache_watermark,
			ARRAY_SIZE(swapcache_watermark));
	stop_swapcache_reclaim();
}

static int reclaim_swapcache_proactive(void *para)
{
	set_freezable();

	while (1) {
		bool ret;

		reclaim_swapcache_try_to_sleep();
		ret = try_to_freeze();
		if (kthread_freezable_should_stop(NULL))
			break;

		if (ret)
			continue;

		etmem_reclaim_swapcache();
	}

	return 0;
}

static int reclaim_swapcache_run(void)
{
	int ret = 0;

	reclaim_swapcache_tk = kthread_run(reclaim_swapcache_proactive, NULL,
						"etmem_recalim_swapcache");
	if (IS_ERR(reclaim_swapcache_tk)) {
		ret = PTR_ERR(reclaim_swapcache_tk);
		reclaim_swapcache_tk = NULL;
	}
	return ret;
}

static long swap_page_ioctl(struct file *filp, unsigned int cmd,
			unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	unsigned int ratio;

	switch (cmd) {
	case RECLAIM_SWAPCACHE_ON:
		if (swapcache_reclaim_enabled())
			return 0;
		start_swapcache_reclaim();
		break;
	case RECLAIM_SWAPCACHE_OFF:
		stop_swapcache_reclaim();
		break;
	case SET_SWAPCACHE_WMARK:
		if (get_user(ratio, (unsigned int __user *)argp))
			return -EFAULT;

		if (get_swapcache_watermark(ratio) != 0)
			return -EFAULT;
		break;
	default:
		return -EPERM;
	}

	return 0;
}


static int swap_pages_entry(void)
{
	proc_swap_pages_operations.flock(NULL, 1, NULL);
	proc_swap_pages_operations.owner = THIS_MODULE;
	proc_swap_pages_operations.write = swap_pages_write;
	proc_swap_pages_operations.open = swap_pages_open;
	proc_swap_pages_operations.release = swap_pages_release;
	proc_swap_pages_operations.unlocked_ioctl = swap_page_ioctl;
	proc_swap_pages_operations.flock(NULL, 0, NULL);

	enable_swapcache_reclaim = false;
	reclaim_swapcache_run();

	return 0;
}

static void swap_pages_exit(void)
{
	proc_swap_pages_operations.flock(NULL, 1, NULL);
	proc_swap_pages_operations.owner = NULL;
	proc_swap_pages_operations.write = NULL;
	proc_swap_pages_operations.open = NULL;
	proc_swap_pages_operations.release = NULL;
	proc_swap_pages_operations.unlocked_ioctl = NULL;
	proc_swap_pages_operations.flock(NULL, 0, NULL);

	if (!IS_ERR(reclaim_swapcache_tk)) {
		kthread_stop(reclaim_swapcache_tk);
		reclaim_swapcache_tk = NULL;
	}
	return;
}

MODULE_LICENSE("GPL");
module_init(swap_pages_entry);
module_exit(swap_pages_exit);
