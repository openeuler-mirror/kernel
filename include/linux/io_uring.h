/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_H
#define _LINUX_IO_URING_H

#include <linux/sched.h>
#include <linux/xarray.h>

struct io_identity {
	struct files_struct		*files;
	struct mm_struct		*mm;
#ifdef CONFIG_BLK_CGROUP
	struct cgroup_subsys_state	*blkcg_css;
#endif
	const struct cred		*creds;
	struct nsproxy			*nsproxy;
	struct fs_struct		*fs;
	unsigned long			fsize;
#ifdef CONFIG_AUDIT
	kuid_t				loginuid;
	unsigned int			sessionid;
#endif
	refcount_t			count;
};

#ifdef __GENKSYMS__
struct io_uring_task {
	/* submission side */
	struct xarray			xa;
	struct wait_queue_head		wait;
	struct file			*last;
	struct percpu_counter		inflight;
	struct io_identity		 __identity;
	struct io_identity		*identity;
	atomic_t			in_idle;
	bool				sqpoll;
};
#endif

#if defined(CONFIG_IO_URING)
void __io_uring_cancel(bool cancel_all);
void __io_uring_free(struct task_struct *tsk);
bool io_is_uring_fops(struct file *file);

static inline void io_uring_files_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(false);
}
static inline void io_uring_task_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(true);
}
static inline void io_uring_free(struct task_struct *tsk)
{
	if (tsk->io_uring)
		__io_uring_free(tsk);
}
#else
static inline void io_uring_task_cancel(void)
{
}
static inline void io_uring_files_cancel(void)
{
}
static inline void io_uring_free(struct task_struct *tsk)
{
}
static inline bool io_is_uring_fops(struct file *file)
{
	return false;
}
#endif

#endif
