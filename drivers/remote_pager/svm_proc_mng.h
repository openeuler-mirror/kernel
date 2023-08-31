/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Jiangtian Feng
 * Co-Author: Jun Chen
 */

#ifndef _REMOTE_PAGER_PROC_MNG_H_
#define _REMOTE_PAGER_PROC_MNG_H_

#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/mmu_notifier.h>

struct page_info {
	struct rb_node node;
	unsigned long va;
	unsigned long len;
	struct mutex lock;
	struct page *page;
};

struct page_mng {
	struct rw_semaphore rw_sem;
	struct rb_root rbtree;
};

struct local_pair_proc {
	struct list_head node;
	pid_t pid;
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct mmu_notifier notifier;
};

struct svm_proc {
	int pid;
	int nid;
	int peer_pid;
	int peer_nid;
	struct mm_struct *mm; /* never dereference */
	struct task_struct *tsk;
	struct list_head tasks_list; /* bind to svm_proc local tasks */
	struct mmu_notifier notifier;

	struct page_mng pager;
};

struct page_info *search_page_info(struct page_mng *pager,
		unsigned long va, unsigned long len);
struct page_info *get_page_info(struct page_mng *pager,
		unsigned long va, unsigned long len, unsigned int page_size);
void free_page_info(struct page_mng *pager, struct page_info *page_info);

struct svm_proc *alloc_svm_proc(int nid, int pid, int peer_nid, int peer_pid);
struct svm_proc *search_svm_proc_by_mm(struct mm_struct *mm);
struct svm_proc *search_svm_proc_by_pid(unsigned int pid);
struct local_pair_proc *insert_local_proc(struct svm_proc *proc,
		unsigned int local_pid);
struct svm_proc *search_svm_proc_by_local_mm(struct mm_struct *mm);

#endif
