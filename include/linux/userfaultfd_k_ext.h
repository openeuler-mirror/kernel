/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _LINUX_USERFAULTFD_K_EXT_H
#define _LINUX_USERFAULTFD_K_EXT_H

#ifdef CONFIG_USERFAULTFD
/*
 * Start with fault_pending_wqh and fault_wqh so they're more likely
 * to be in the same cacheline.
 *
 * Locking order:
 *	fd_wqh.lock
 *		fault_pending_wqh.lock
 *			fault_wqh.lock
 *		event_wqh.lock
 *
 * To avoid deadlocks, IRQs must be disabled when taking any of the above locks,
 * since fd_wqh.lock is taken by aio_poll() while it's holding a lock that's
 * also taken in IRQ context.
 */
struct userfaultfd_ctx {
	/* waitqueue head for the pending (i.e. not read) userfaults */
	wait_queue_head_t fault_pending_wqh;
	/* waitqueue head for the userfaults */
	wait_queue_head_t fault_wqh;
	/* waitqueue head for the pseudo fd to wakeup poll/read */
	wait_queue_head_t fd_wqh;
	/* waitqueue head for events */
	wait_queue_head_t event_wqh;
	/* a refile sequence protected by fault_pending_wqh lock */
	seqcount_spinlock_t refile_seq;
	/* pseudo fd refcounting */
	refcount_t refcount;
	/* userfaultfd syscall flags */
	unsigned int flags;
	/* features requested from the userspace */
	unsigned int features;
	/* released */
	bool released;
	/* memory mappings are changing because of non-cooperative event */
	atomic_t mmap_changing;
	/* mm with one ore more vmas attached to this userfaultfd_ctx */
	struct mm_struct *mm;
};

static inline bool vma_has_uffd_without_event_remap(struct vm_area_struct *vma)
{
	struct userfaultfd_ctx *uffd_ctx = vma->vm_userfaultfd_ctx.ctx;

	return uffd_ctx && (uffd_ctx->features & UFFD_FEATURE_EVENT_REMAP) == 0;
}

#else /* CONFIG_USERFAULTFD */

static inline bool vma_has_uffd_without_event_remap(struct vm_area_struct *vma)
{
	return false;
}

#endif /* CONFIG_USERFAULTFD */

#endif /* __LINUX_USERFAULTFD_K_EXT_H */
