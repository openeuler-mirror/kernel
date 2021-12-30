/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Huawei Ascend Share Pool Memory
 *
 * Copyright (C) 2020 Huawei Limited
 * Author: Tang Yizhou <tangyizhou@huawei.com>
 *         Zefan Li <lizefan@huawei.com>
 *         Wu Peng <wupeng58@huawei.com>
 *         Ding Tianhong <dingtgianhong@huawei.com>
 *         Zhou Guanghui <zhouguanghui1@huawei.com>
 *         Li Ming <limingming.li@huawei.com>
 *
 * This code is based on the hisilicon ascend platform.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) "share pool: " fmt

#include <linux/share_pool.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/mm_types.h>
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/shmem_fs.h>
#include <linux/file.h>
#include <linux/printk.h>
#include <linux/hugetlb.h>
#include <linux/vmalloc.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/atomic.h>
#include <linux/lockdep.h>
#include <linux/kernel.h>
#include <linux/falloc.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rmap.h>
#include <linux/compaction.h>
#include <linux/preempt.h>
#include <linux/swapops.h>
#include <linux/mmzone.h>
#include <linux/timekeeping.h>
#include <linux/time64.h>
#include <linux/pagewalk.h>

/* access control mode macros  */
#define AC_NONE			0
#define AC_SINGLE_OWNER		1

#define spg_valid(spg)		((spg)->is_alive == true)

#define byte2kb(size)		((size) >> 10)
#define byte2mb(size)		((size) >> 20)
#define page2kb(page_num)	((page_num) << (PAGE_SHIFT - 10))

#define SINGLE_GROUP_MODE	1
#define MULTI_GROUP_MODE	2

#define MAX_GROUP_FOR_SYSTEM	50000
#define MAX_GROUP_FOR_TASK	3000
#define MAX_PROC_PER_GROUP	1024

#define GROUP_NONE		0

#define SEC2US(sec)		((sec) * 1000000)
#define NS2US(ns)		((ns) / 1000)

#define PF_DOMAIN_CORE		0x10000000	/* AOS CORE processes in sched.h */

/* mdc scene hack */
static int __read_mostly enable_mdc_default_group;
static const int mdc_default_group_id = 1;

/* share the uva to the whole group */
static int __read_mostly enable_share_k2u_spg = 1;

static int share_pool_group_mode = SINGLE_GROUP_MODE;

static unsigned int sp_device_number;
static unsigned long sp_dev_va_start[MAX_DEVID];
static unsigned long sp_dev_va_size[MAX_DEVID];

static bool is_sp_dev_addr_enabled(int device_id)
{
	return sp_dev_va_size[device_id];
}

/* idr of all sp_groups */
static DEFINE_IDR(sp_group_idr);
/* rw semaphore for sp_group_idr and mm->sp_group_master */
static DECLARE_RWSEM(sp_group_sem);

static BLOCKING_NOTIFIER_HEAD(sp_notifier_chain);

static DEFINE_IDA(sp_group_id_ida);

/*** Statistical and maintenance tools ***/

/* idr of all sp_proc_stats */
static DEFINE_IDR(sp_proc_stat_idr);
/* rw semaphore for sp_proc_stat_idr */
static DECLARE_RWSEM(sp_proc_stat_sem);

/* idr of all sp_spg_stats */
static DEFINE_IDR(sp_spg_stat_idr);
/* rw semaphore for sp_spg_stat_idr */
static DECLARE_RWSEM(sp_spg_stat_sem);

/* for kthread buff_module_guard_work */
static struct sp_proc_stat kthread_stat;

/* The caller must hold sp_group_sem */
static struct sp_group_master *sp_init_group_master_locked(
	struct mm_struct *mm, bool *exist)
{
	struct sp_group_master *master = mm->sp_group_master;

	if (master) {
		*exist = true;
		return master;
	}

	master = kmalloc(sizeof(struct sp_group_master), GFP_KERNEL);
	if (master == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&master->node_list);
	master->count = 0;
	master->stat = NULL;
	master->mm = mm;
	mm->sp_group_master = master;

	*exist = false;
	return master;
}

static struct sp_proc_stat *create_proc_stat(struct mm_struct *mm,
					     struct task_struct *tsk)
{
	struct sp_proc_stat *stat;

	stat = kmalloc(sizeof(*stat), GFP_KERNEL);
	if (stat == NULL)
		return ERR_PTR(-ENOMEM);

	atomic_set(&stat->use_count, 1);
	atomic64_set(&stat->alloc_size, 0);
	atomic64_set(&stat->k2u_size, 0);
	stat->tgid = tsk->tgid;
	stat->mm = mm;
	mutex_init(&stat->lock);
	hash_init(stat->hash);
	get_task_comm(stat->comm, tsk);

	return stat;
}

static struct sp_proc_stat *sp_init_proc_stat(struct sp_group_master *master,
	struct mm_struct *mm, struct task_struct *tsk)
{
	struct sp_proc_stat *stat;
	int alloc_id, tgid = tsk->tgid;

	down_write(&sp_proc_stat_sem);
	stat = master->stat;
	if (stat) {
		up_write(&sp_proc_stat_sem);
		return stat;
	}

	stat = create_proc_stat(mm, tsk);
	if (IS_ERR(stat)) {
		up_write(&sp_proc_stat_sem);
		return stat;
	}

	alloc_id = idr_alloc(&sp_proc_stat_idr, stat, tgid, tgid + 1, GFP_KERNEL);
	if (alloc_id < 0) {
		up_write(&sp_proc_stat_sem);
		pr_err_ratelimited("proc stat idr alloc failed %d\n", alloc_id);
		kfree(stat);
		return ERR_PTR(alloc_id);
	}

	master->stat = stat;
	up_write(&sp_proc_stat_sem);

	return stat;
}

static void update_spg_stat_alloc(unsigned long size, bool inc,
	bool huge, struct sp_spg_stat *stat)
{
	if (inc) {
		atomic_inc(&stat->spa_num);
		atomic64_add(size, &stat->size);
		atomic64_add(size, &stat->alloc_size);
		if (huge)
			atomic64_add(size, &stat->alloc_hsize);
		else
			atomic64_add(size, &stat->alloc_nsize);
	} else {
		atomic_dec(&stat->spa_num);
		atomic64_sub(size, &stat->size);
		atomic64_sub(size, &stat->alloc_size);
		if (huge)
			atomic64_sub(size, &stat->alloc_hsize);
		else
			atomic64_sub(size, &stat->alloc_nsize);
	}
}

static void update_spg_stat_k2u(unsigned long size, bool inc,
	struct sp_spg_stat *stat)
{
	if (inc) {
		atomic_inc(&stat->spa_num);
		atomic64_add(size, &stat->size);
		atomic64_add(size, &stat->k2u_size);
	} else {
		atomic_dec(&stat->spa_num);
		atomic64_sub(size, &stat->size);
		atomic64_sub(size, &stat->k2u_size);
	}
}

/* per process/sp-group memory usage statistics */
struct spg_proc_stat {
	int tgid;
	int spg_id;  /* 0 for non-group data, such as k2u_task */
	struct hlist_node pnode;  /* hlist node in sp_proc_stat->hash */
	struct hlist_node gnode;  /* hlist node in sp_spg_stat->hash */
	struct sp_proc_stat *proc_stat;
	struct sp_spg_stat *spg_stat;
	/*
	 * alloc amount minus free amount, may be negative when freed by
	 * another task in the same sp group.
	 */
	atomic64_t alloc_size;
	atomic64_t k2u_size;
};

static void update_spg_proc_stat_alloc(unsigned long size, bool inc,
	struct spg_proc_stat *stat)
{
	struct sp_proc_stat *proc_stat = stat->proc_stat;

	if (inc) {
		atomic64_add(size, &stat->alloc_size);
		atomic64_add(size, &proc_stat->alloc_size);
	} else {
		atomic64_sub(size, &stat->alloc_size);
		atomic64_sub(size, &proc_stat->alloc_size);
	}
}

static void update_spg_proc_stat_k2u(unsigned long size, bool inc,
	struct spg_proc_stat *stat)
{
	struct sp_proc_stat *proc_stat = stat->proc_stat;

	if (inc) {
		atomic64_add(size, &stat->k2u_size);
		atomic64_add(size, &proc_stat->k2u_size);
	} else {
		atomic64_sub(size, &stat->k2u_size);
		atomic64_sub(size, &proc_stat->k2u_size);
	}
}

static struct spg_proc_stat *find_spg_proc_stat(
	struct sp_proc_stat *proc_stat, int tgid, int spg_id)
{
	struct spg_proc_stat *stat = NULL;

	mutex_lock(&proc_stat->lock);
	hash_for_each_possible(proc_stat->hash, stat, pnode, spg_id) {
		if (stat->spg_id == spg_id)
			break;
	}
	mutex_unlock(&proc_stat->lock);

	return stat;
}

static struct spg_proc_stat *create_spg_proc_stat(int tgid, int spg_id)
{
	struct spg_proc_stat *stat;

	stat = kmalloc(sizeof(struct spg_proc_stat), GFP_KERNEL);
	if (stat == NULL)
		return ERR_PTR(-ENOMEM);

	stat->tgid = tgid;
	stat->spg_id = spg_id;
	atomic64_set(&stat->alloc_size, 0);
	atomic64_set(&stat->k2u_size, 0);

	return stat;
}

static struct spg_proc_stat *sp_init_spg_proc_stat(
	struct sp_proc_stat *proc_stat, int tgid, struct sp_group *spg)
{
	struct spg_proc_stat *stat;
	int spg_id = spg->id;  /* visit spg id locklessly */
	struct sp_spg_stat *spg_stat = spg->stat;

	stat = find_spg_proc_stat(proc_stat, tgid, spg_id);
	if (stat)
		return stat;

	stat = create_spg_proc_stat(tgid, spg_id);
	if (IS_ERR(stat))
		return stat;

	stat->proc_stat = proc_stat;
	stat->spg_stat = spg_stat;

	mutex_lock(&proc_stat->lock);
	hash_add(proc_stat->hash, &stat->pnode, stat->spg_id);
	mutex_unlock(&proc_stat->lock);

	mutex_lock(&spg_stat->lock);
	hash_add(spg_stat->hash, &stat->gnode, stat->tgid);
	mutex_unlock(&spg_stat->lock);
	return stat;
}

/*
 * The caller must
 * 1. ensure no concurrency problem for task_struct and mm_struct.
 * 2. hold sp_group_sem for sp_group_master (pay attention to ABBA deadlock)
 */
static struct spg_proc_stat *sp_init_process_stat(struct task_struct *tsk,
	struct mm_struct *mm, struct sp_group *spg)
{
	struct sp_group_master *master;
	bool exist;
	struct sp_proc_stat *proc_stat;
	struct spg_proc_stat *spg_proc_stat;

	master = sp_init_group_master_locked(mm, &exist);
	if (IS_ERR(master))
		return (struct spg_proc_stat *)master;

	proc_stat = sp_init_proc_stat(master, mm, tsk);
	if (IS_ERR(proc_stat))
		return (struct spg_proc_stat *)proc_stat;

	spg_proc_stat = sp_init_spg_proc_stat(proc_stat, tsk->tgid, spg);
	return spg_proc_stat;
}

static struct sp_spg_stat *create_spg_stat(int spg_id)
{
	struct sp_spg_stat *stat;

	stat = kmalloc(sizeof(*stat), GFP_KERNEL);
	if (stat == NULL)
		return ERR_PTR(-ENOMEM);

	stat->spg_id = spg_id;
	atomic_set(&stat->hugepage_failures, 0);
	atomic_set(&stat->spa_num, 0);
	atomic64_set(&stat->size, 0);
	atomic64_set(&stat->alloc_nsize, 0);
	atomic64_set(&stat->alloc_hsize, 0);
	atomic64_set(&stat->alloc_size, 0);
	mutex_init(&stat->lock);
	hash_init(stat->hash);

	return stat;
}

static int sp_init_spg_stat(struct sp_group *spg)
{
	struct sp_spg_stat *stat;
	int ret, spg_id = spg->id;

	stat = create_spg_stat(spg_id);
	if (IS_ERR(stat))
		return PTR_ERR(stat);

	down_write(&sp_spg_stat_sem);
	ret = idr_alloc(&sp_spg_stat_idr, stat, spg_id, spg_id + 1,
			GFP_KERNEL);
	up_write(&sp_spg_stat_sem);
	if (ret < 0) {
		pr_err_ratelimited("group %d idr alloc failed, ret %d\n",
				   spg_id, ret);
		kfree(stat);
	}

	spg->stat = stat;
	return ret;
}

static void free_spg_stat(int spg_id)
{
	struct sp_spg_stat *stat;

	down_write(&sp_spg_stat_sem);
	stat = idr_remove(&sp_spg_stat_idr, spg_id);
	up_write(&sp_spg_stat_sem);
	WARN_ON(!stat);
	kfree(stat);
}

/*
 * Group '0' for k2u_task and pass through. No process will be actually
 * added to.
 */
static struct sp_group *spg_none;

/* statistics of all sp area, protected by sp_area_lock */
struct sp_spa_stat {
	unsigned int total_num;
	unsigned int alloc_num;
	unsigned int k2u_task_num;
	unsigned int k2u_spg_num;
	unsigned long total_size;
	unsigned long alloc_size;
	unsigned long k2u_task_size;
	unsigned long k2u_spg_size;
	unsigned long dvpp_size;
	unsigned long dvpp_va_size;
};

static struct sp_spa_stat spa_stat;

/* statistics of all sp group born from sp_alloc and k2u(spg) */
struct sp_overall_stat {
	atomic_t spa_total_num;
	atomic64_t spa_total_size;
};

static struct sp_overall_stat sp_overall_stat;

/*** Global share pool VA allocator ***/

enum spa_type {
	SPA_TYPE_ALLOC = 1,
	SPA_TYPE_K2TASK,
	SPA_TYPE_K2SPG,
};

/*
 * We bump the reference when each mmap succeeds, and it will be dropped
 * when vma is about to release, so sp_area object will be automatically
 * freed when all tasks in the sp group has exited.
 */
struct sp_area {
	unsigned long va_start;
	unsigned long va_end;		/* va_end always align to hugepage */
	unsigned long real_size;	/* real size with alignment */
	unsigned long region_vstart;	/* belong to normal region or DVPP region */
	unsigned long flags;
	bool is_hugepage;
	bool is_dead;
	atomic_t use_count;		/* How many vmas use this VA region */
	struct rb_node rb_node;		/* address sorted rbtree */
	struct list_head link;		/* link to the spg->head */
	struct sp_group *spg;
	enum spa_type type;		/* where spa born from */
	struct mm_struct *mm;		/* owner of k2u(task) */
	unsigned long kva;		/* shared kva */
	pid_t applier;			/* the original applier process */
	int node_id;			/* memory node */
	int device_id;
};
static DEFINE_SPINLOCK(sp_area_lock);
static struct rb_root sp_area_root = RB_ROOT;

static unsigned long spa_size(struct sp_area *spa)
{
	return spa->real_size;
}

static struct file *spa_file(struct sp_area *spa)
{
	if (spa->is_hugepage)
		return spa->spg->file_hugetlb;
	else
		return spa->spg->file;
}

static inline void check_interrupt_context(void)
{
	if (unlikely(in_interrupt()))
		panic("function can't be used in interrupt context\n");
}

static struct sp_group *create_spg(int spg_id)
{
	return NULL;
}

static bool is_online_node_id(int node_id)
{
	return node_id >= 0 && node_id < MAX_NUMNODES && node_online(node_id);
}

static bool is_device_addr(unsigned long addr)
{
	int i;

	for (i = 0; i < sp_device_number; i++) {
		if (addr >= sp_dev_va_start[i] &&
		    addr < sp_dev_va_start[i] + sp_dev_va_size[i])
			return true;
	}
	return false;
}

/**
 * sp_group_id_by_pid() - Get the sp_group ID of a process.
 * @pid: pid of target process.
 *
 * Return:
 * 0		 the sp_group ID.
 * -ENODEV	 target process doesn't belong to any sp_group.
 */
int sp_group_id_by_pid(int pid)
{
	return 0;
}
EXPORT_SYMBOL_GPL(sp_group_id_by_pid);

/**
 * mp_sp_group_id_by_pid() - Get the sp_group ID array of a process.
 * @pid: pid of target process.
 * @spg_ids: point to an array to save the group ids the process belongs to
 * @num: input the spg_ids array size; output the spg number of the process
 *
 * Return:
 * >0		- the sp_group ID.
 * -ENODEV	- target process doesn't belong to any sp_group.
 * -EINVAL	- spg_ids or num is NULL.
 * -E2BIG	- the num of groups process belongs to is larger than *num
 */
int mg_sp_group_id_by_pid(int pid, int *spg_ids, int *num)
{
	return 0;
}
EXPORT_SYMBOL_GPL(mg_sp_group_id_by_pid);

int mg_sp_group_add_task(int pid, unsigned long prot, int spg_id)
{
	return 0;
}
EXPORT_SYMBOL_GPL(mg_sp_group_add_task);

int sp_group_add_task(int pid, int spg_id)
{
	return 0;
}
EXPORT_SYMBOL_GPL(sp_group_add_task);

static void __sp_area_drop_locked(struct sp_area *spa)
{
}

/**
 * mg_sp_group_del_task() - delete a process from a sp group.
 * @pid: the pid of the task to be deleted
 * @spg_id: sharepool group id
 *
 * the group's spa list must be empty, or deletion will fail.
 *
 * Return:
 * * if success, return 0.
 * * -EINVAL, spg_id invalid or spa_lsit not emtpy or spg dead
 * * -ESRCH, the task group of pid is not in group / process dead
 */
int mg_sp_group_del_task(int pid, int spg_id)
{
	return 0;
}
EXPORT_SYMBOL_GPL(mg_sp_group_del_task);

int sp_group_del_task(int pid, int spg_id)
{
	return mg_sp_group_del_task(pid, spg_id);
}
EXPORT_SYMBOL_GPL(sp_group_del_task);

/**
 * sp_free() - Free the memory allocated by sp_alloc().
 * @addr: the starting VA of the memory.
 *
 * Return:
 * * 0		- success.
 * * -EINVAL	- the memory can't be found or was not allocted by share pool.
 * * -EPERM	- the caller has no permision to free the memory.
 */
int sp_free(unsigned long addr)
{
	return 0;
}
EXPORT_SYMBOL_GPL(sp_free);

int mg_sp_free(unsigned long addr)
{
	return sp_free(addr);
}
EXPORT_SYMBOL_GPL(mg_sp_free);

/**
 * sp_alloc() - Allocate shared memory for all the processes in a sp_group.
 * @size: the size of memory to allocate.
 * @sp_flags: how to allocate the memory.
 * @spg_id: the share group that the memory is allocated to.
 *
 * Use pass through allocation if spg_id == SPG_ID_DEFAULT in multi-group mode.
 *
 * Return:
 * * if succeed, return the starting address of the shared memory.
 * * if fail, return the pointer of -errno.
 */
void *sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id)
{
	return NULL;
}
EXPORT_SYMBOL_GPL(sp_alloc);

void *mg_sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id)
{
	return sp_alloc(size, sp_flags, spg_id);
}
EXPORT_SYMBOL_GPL(mg_sp_alloc);

/**
 * sp_make_share_k2u() - Share kernel memory to current process or an sp_group.
 * @kva: the VA of shared kernel memory.
 * @size: the size of shared kernel memory.
 * @sp_flags: how to allocate the memory. We only support SP_DVPP.
 * @pid:  the pid of the specified process (Not currently in use).
 * @spg_id: the share group that the memory is shared to.
 *
 * Return: the shared target user address to start at
 *
 * Share kernel memory to current task if spg_id == SPG_ID_NONE
 * or SPG_ID_DEFAULT in multi-group mode.
 *
 * Return:
 * * if succeed, return the shared user address to start at.
 * * if fail, return the pointer of -errno.
 */
void *sp_make_share_k2u(unsigned long kva, unsigned long size,
			unsigned long sp_flags, int pid, int spg_id)
{
	return NULL;
}
EXPORT_SYMBOL_GPL(sp_make_share_k2u);

void *mg_sp_make_share_k2u(unsigned long kva, unsigned long size,
	unsigned long sp_flags, int pid, int spg_id)
{
	return sp_make_share_k2u(kva, size, sp_flags, pid, spg_id);
}
EXPORT_SYMBOL_GPL(mg_sp_make_share_k2u);

static int sp_pmd_entry(pmd_t *pmd, unsigned long addr,
			unsigned long next, struct mm_walk *walk)
{
	struct sp_walk_data *sp_walk_data = walk->private;

	sp_walk_data->pmd = pmd;
	return 0;
}

static int sp_pte_entry(pte_t *pte, unsigned long addr,
			unsigned long next, struct mm_walk *walk)
{
	struct page *page;
	struct sp_walk_data *sp_walk_data = walk->private;
	pmd_t *pmd = sp_walk_data->pmd;

retry:
	if (unlikely(!pte_present(*pte))) {
		swp_entry_t entry;

		if (pte_none(*pte))
			goto no_page;
		entry = pte_to_swp_entry(*pte);
		if (!is_migration_entry(entry))
			goto no_page;
		migration_entry_wait(walk->mm, pmd, addr);
		goto retry;
	}

	page = pte_page(*pte);
	get_page(page);
	sp_walk_data->pages[sp_walk_data->page_count++] = page;
	return 0;

no_page:
	pr_debug("the page of addr %lx unexpectedly not in RAM\n",
		 (unsigned long)addr);
	return -EFAULT;
}

static int sp_test_walk(unsigned long addr, unsigned long next,
			struct mm_walk *walk)
{
	/*
	 * FIXME: The devmm driver uses remap_pfn_range() but actually there
	 * are associated struct pages, so they should use vm_map_pages() or
	 * similar APIs. Before the driver has been converted to correct APIs
	 * we use this test_walk() callback so we can treat VM_PFNMAP VMAs as
	 * normal VMAs.
	 */
	return 0;
}

static int sp_pte_hole(unsigned long start, unsigned long end,
		       int depth, struct mm_walk *walk)
{
	pr_debug("hole [%lx, %lx) appeared unexpectedly\n", (unsigned long)start, (unsigned long)end);
	return -EFAULT;
}

static int sp_hugetlb_entry(pte_t *ptep, unsigned long hmask,
			    unsigned long addr, unsigned long next,
			    struct mm_walk *walk)
{
	pte_t pte = huge_ptep_get(ptep);
	struct page *page = pte_page(pte);
	struct sp_walk_data *sp_walk_data;

	if (unlikely(!pte_present(pte))) {
		pr_debug("the page of addr %lx unexpectedly not in RAM\n", (unsigned long)addr);
		return -EFAULT;
	}

	sp_walk_data = walk->private;
	get_page(page);
	sp_walk_data->pages[sp_walk_data->page_count++] = page;
	return 0;
}

/*
 * __sp_walk_page_range() - Walk page table with caller specific callbacks.
 * @uva: the start VA of user memory.
 * @size: the size of user memory.
 * @mm: mm struct of the target task.
 * @sp_walk_data: a structure of a page pointer array.
 *
 * the caller must hold mm->mmap_lock
 *
 * Notes for parameter alignment:
 * When size == 0, let it be page_size, so that at least one page is walked.
 *
 * When size > 0, for convenience, usually the parameters of uva and
 * size are not page aligned. There are four different alignment scenarios and
 * we must handler all of them correctly.
 *
 * The basic idea is to align down uva and align up size so all the pages
 * in range [uva, uva + size) are walked. However, there are special cases.
 *
 * Considering a 2M-hugepage addr scenario. Assuming the caller wants to
 * traverse range [1001M, 1004.5M), so uva and size is 1001M and 3.5M
 * accordingly. The aligned-down uva is 1000M and the aligned-up size is 4M.
 * The traverse range will be [1000M, 1004M). Obviously, the final page for
 * [1004M, 1004.5M) is not covered.
 *
 * To fix this problem, we need to walk an additional page, size should be
 * ALIGN(uva+size) - uva_aligned
 */
static int __sp_walk_page_range(unsigned long uva, unsigned long size,
	struct mm_struct *mm, struct sp_walk_data *sp_walk_data)
{
	int ret = 0;
	struct vm_area_struct *vma;
	unsigned long page_nr;
	struct page **pages = NULL;
	bool is_hugepage = false;
	unsigned long uva_aligned;
	unsigned long size_aligned;
	unsigned int page_size = PAGE_SIZE;
	struct mm_walk_ops sp_walk = {};

	/*
	 * Here we also support non share pool memory in this interface
	 * because the caller can't distinguish whether a uva is from the
	 * share pool or not. It is not the best idea to do so, but currently
	 * it simplifies overall design.
	 *
	 * In this situation, the correctness of the parameters is mainly
	 * guaranteed by the caller.
	 */
	vma = find_vma(mm, uva);
	if (!vma) {
		pr_debug("u2k input uva %lx is invalid\n", (unsigned long)uva);
		return -EINVAL;
	}
	if (is_vm_hugetlb_page(vma))
		is_hugepage = true;

	sp_walk.pte_hole = sp_pte_hole;
	sp_walk.test_walk = sp_test_walk;
	if (is_hugepage) {
		sp_walk_data->is_hugepage = true;
		sp_walk.hugetlb_entry = sp_hugetlb_entry;
		page_size = PMD_SIZE;
	} else {
		sp_walk_data->is_hugepage = false;
		sp_walk.pte_entry = sp_pte_entry;
		sp_walk.pmd_entry = sp_pmd_entry;
	}

	sp_walk_data->page_size = page_size;
	uva_aligned = ALIGN_DOWN(uva, page_size);
	sp_walk_data->uva_aligned = uva_aligned;
	if (size == 0)
		size_aligned = page_size;
	else
		/* special alignment handling */
		size_aligned = ALIGN(uva + size, page_size) - uva_aligned;

	if (uva_aligned + size_aligned < uva_aligned) {
		pr_err_ratelimited("overflow happened in walk page range\n");
		return -EINVAL;
	}

	page_nr = size_aligned / page_size;
	pages = kvmalloc(page_nr * sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		pr_err_ratelimited("alloc page array failed in walk page range\n");
		return -ENOMEM;
	}
	sp_walk_data->pages = pages;

	ret = walk_page_range(mm, uva_aligned, uva_aligned + size_aligned,
			      &sp_walk, sp_walk_data);
	if (ret)
		kvfree(pages);

	return ret;
}

static void __sp_walk_page_free(struct sp_walk_data *data)
{
	int i = 0;
	struct page *page;

	while (i < data->page_count) {
		page = data->pages[i++];
		put_page(page);
	}

	kvfree(data->pages);
	/* prevent repeated release */
	data->page_count = 0;
	data->pages = NULL;
}

/**
 * sp_make_share_u2k() - Share user memory of a specified process to kernel.
 * @uva: the VA of shared user memory
 * @size: the size of shared user memory
 * @pid: the pid of the specified process(Not currently in use)
 *
 * Return:
 * * if success, return the starting kernel address of the shared memory.
 * * if failed, return the pointer of -errno.
 */
void *sp_make_share_u2k(unsigned long uva, unsigned long size, int pid)
{
	return NULL;
}
EXPORT_SYMBOL_GPL(sp_make_share_u2k);

void *mg_sp_make_share_u2k(unsigned long uva, unsigned long size, int pid)
{
	return sp_make_share_u2k(uva, size, pid);
}
EXPORT_SYMBOL_GPL(mg_sp_make_share_u2k);

/**
 * sp_unshare() - Unshare the kernel or user memory which shared by calling
 *                sp_make_share_{k2u,u2k}().
 * @va: the specified virtual address of memory
 * @size: the size of unshared memory
 *
 * Use spg_id of current thread if spg_id == SPG_ID_DEFAULT.
 *
 * Return: 0 for success, -errno on failure.
 */
int sp_unshare(unsigned long va, unsigned long size, int pid, int spg_id)
{
	return 0;
}
EXPORT_SYMBOL_GPL(sp_unshare);

int mg_sp_unshare(unsigned long va, unsigned long size)
{
	return sp_unshare(va, size, 0, 0);
}
EXPORT_SYMBOL_GPL(mg_sp_unshare);

/**
 * sp_walk_page_range() - Walk page table with caller specific callbacks.
 * @uva: the start VA of user memory.
 * @size: the size of user memory.
 * @tsk: task struct of the target task.
 * @sp_walk_data: a structure of a page pointer array.
 *
 * Return: 0 for success, -errno on failure.
 *
 * When return 0, sp_walk_data describing [uva, uva+size) can be used.
 * When return -errno, information in sp_walk_data is useless.
 */
int sp_walk_page_range(unsigned long uva, unsigned long size,
	struct task_struct *tsk, struct sp_walk_data *sp_walk_data)
{
	struct mm_struct *mm;
	int ret = 0;

	check_interrupt_context();

	if (unlikely(!sp_walk_data)) {
		pr_err_ratelimited("null pointer when walk page range\n");
		return -EINVAL;
	}
	if (!tsk || (tsk->flags & PF_EXITING))
		return -ESRCH;

	get_task_struct(tsk);
	mm = get_task_mm(tsk);
	if (!mm) {
		put_task_struct(tsk);
		return -ESRCH;
	}

	sp_walk_data->page_count = 0;
	down_write(&mm->mmap_lock);
	if (likely(!mm->core_state))
		ret = __sp_walk_page_range(uva, size, mm, sp_walk_data);
	else {
		pr_err("walk page range: encoutered coredump\n");
		ret = -ESRCH;
	}
	up_write(&mm->mmap_lock);

	mmput(mm);
	put_task_struct(tsk);

	return ret;
}
EXPORT_SYMBOL_GPL(sp_walk_page_range);

int mg_sp_walk_page_range(unsigned long uva, unsigned long size,
	struct task_struct *tsk, struct sp_walk_data *sp_walk_data)
{
	return sp_walk_page_range(uva, size, tsk, sp_walk_data);
}
EXPORT_SYMBOL_GPL(mg_sp_walk_page_range);

/**
 * sp_walk_page_free() - Free the sp_walk_data structure.
 * @sp_walk_data: a structure of a page pointer array to be freed.
 */
void sp_walk_page_free(struct sp_walk_data *sp_walk_data)
{
	check_interrupt_context();

	if (!sp_walk_data)
		return;

	__sp_walk_page_free(sp_walk_data);
}
EXPORT_SYMBOL_GPL(sp_walk_page_free);

void mg_sp_walk_page_free(struct sp_walk_data *sp_walk_data)
{
	sp_walk_page_free(sp_walk_data);
}
EXPORT_SYMBOL_GPL(mg_sp_walk_page_free);

int sp_register_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&sp_notifier_chain, nb);
}
EXPORT_SYMBOL_GPL(sp_register_notifier);

int sp_unregister_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&sp_notifier_chain, nb);
}
EXPORT_SYMBOL_GPL(sp_unregister_notifier);

/**
 * sp_config_dvpp_range() - User can config the share pool start address
 *                          of each Da-vinci device.
 * @start: the value of share pool start
 * @size: the value of share pool
 * @device_id: the num of Da-vinci device
 * @pid: the pid of device process
 *
 * Return true for success.
 * Return false if parameter invalid or has been set up.
 * This functuon has no concurrent problem.
 */
bool sp_config_dvpp_range(size_t start, size_t size, int device_id, int pid)
{
	if (pid < 0 ||
	    size <= 0 || size > MMAP_SHARE_POOL_16G_SIZE ||
	    device_id < 0 || device_id >= sp_device_number ||
	    !is_online_node_id(device_id) ||
	    is_sp_dev_addr_enabled(device_id))
		return false;

	sp_dev_va_start[device_id] = start;
	sp_dev_va_size[device_id] = size;
	return true;
}
EXPORT_SYMBOL_GPL(sp_config_dvpp_range);

bool mg_sp_config_dvpp_range(size_t start, size_t size, int device_id, int pid)
{
	return sp_config_dvpp_range(start, size, device_id, pid);
}
EXPORT_SYMBOL_GPL(mg_sp_config_dvpp_range);

static bool is_sp_normal_addr(unsigned long addr)
{
	return addr >= MMAP_SHARE_POOL_START &&
		addr < MMAP_SHARE_POOL_16G_START +
			sp_device_number * MMAP_SHARE_POOL_16G_SIZE;
}

/**
 * is_sharepool_addr() - Check if a user memory address belongs to share pool.
 * @addr: the userspace address to be checked.
 *
 * Return true if addr belongs to share pool, or false vice versa.
 */
bool is_sharepool_addr(unsigned long addr)
{
	return is_sp_normal_addr(addr) || is_device_addr(addr);
}
EXPORT_SYMBOL_GPL(is_sharepool_addr);

bool mg_is_sharepool_addr(unsigned long addr)
{
	return is_sharepool_addr(addr);
}
EXPORT_SYMBOL_GPL(mg_is_sharepool_addr);

static int __init mdc_default_group(char *s)
{
	enable_mdc_default_group = 1;
	return 1;
}
__setup("enable_mdc_default_group", mdc_default_group);

static int __init enable_share_k2u_to_group(char *s)
{
	enable_share_k2u_spg = 1;
	return 1;
}
__setup("enable_sp_share_k2u_spg", enable_share_k2u_to_group);

static int __init enable_sp_multi_group_mode(char *s)
{
	share_pool_group_mode = MULTI_GROUP_MODE;
	return 1;
}
__setup("enable_sp_multi_group_mode", enable_sp_multi_group_mode);

/*** Statistical and maintenance functions ***/

static void free_process_spg_proc_stat(struct sp_proc_stat *proc_stat)
{
	int i;
	struct spg_proc_stat *stat;
	struct hlist_node *tmp;
	struct sp_spg_stat *spg_stat;

	/* traverse proc_stat->hash locklessly as process is exiting */
	hash_for_each_safe(proc_stat->hash, i, tmp, stat, pnode) {
		spg_stat = stat->spg_stat;
		mutex_lock(&spg_stat->lock);
		hash_del(&stat->gnode);
		mutex_unlock(&spg_stat->lock);

		hash_del(&stat->pnode);
		kfree(stat);
	}
}

static void free_sp_proc_stat(struct sp_proc_stat *stat)
{
	free_process_spg_proc_stat(stat);

	down_write(&sp_proc_stat_sem);
	stat->mm->sp_group_master->stat = NULL;
	idr_remove(&sp_proc_stat_idr, stat->tgid);
	up_write(&sp_proc_stat_sem);
	kfree(stat);
}

/* the caller make sure stat is not NULL */
void sp_proc_stat_drop(struct sp_proc_stat *stat)
{
	if (atomic_dec_and_test(&stat->use_count))
		free_sp_proc_stat(stat);
}

static void get_mm_rss_info(struct mm_struct *mm, unsigned long *anon,
	unsigned long *file, unsigned long *shmem, unsigned long *total_rss)
{
	*anon = get_mm_counter(mm, MM_ANONPAGES);
	*file = get_mm_counter(mm, MM_FILEPAGES);
	*shmem = get_mm_counter(mm, MM_SHMEMPAGES);
	*total_rss = *anon + *file + *shmem;
}

static long get_proc_alloc(struct sp_proc_stat *stat)
{
	return byte2kb(atomic64_read(&stat->alloc_size));
}

static long get_proc_k2u(struct sp_proc_stat *stat)
{
	return byte2kb(atomic64_read(&stat->k2u_size));
}

static long get_spg_alloc(struct sp_spg_stat *stat)
{
	return byte2kb(atomic64_read(&stat->alloc_size));
}

static long get_spg_alloc_nsize(struct sp_spg_stat *stat)
{
	return byte2kb(atomic64_read(&stat->alloc_nsize));
}

static long get_spg_proc_alloc(struct spg_proc_stat *stat)
{
	return byte2kb(atomic64_read(&stat->alloc_size));
}

static long get_spg_proc_k2u(struct spg_proc_stat *stat)
{
	return byte2kb(atomic64_read(&stat->k2u_size));
}

static void get_process_sp_res(struct sp_proc_stat *stat,
	long *sp_res_out, long *sp_res_nsize_out)
{
	int i;
	struct spg_proc_stat *spg_proc_stat;
	struct sp_spg_stat *spg_stat;
	long sp_res = 0, sp_res_nsize = 0;

	mutex_lock(&stat->lock);
	hash_for_each(stat->hash, i, spg_proc_stat, pnode) {
		spg_stat = spg_proc_stat->spg_stat;
		sp_res += get_spg_alloc(spg_stat);
		sp_res_nsize += get_spg_alloc_nsize(spg_stat);
	}
	mutex_unlock(&stat->lock);

	*sp_res_out = sp_res;
	*sp_res_nsize_out = sp_res_nsize;
}

/*
 *  Statistics of RSS has a maximum 64 pages deviation (256KB).
 *  Please check_sync_rss_stat().
 */
static void get_process_non_sp_res(unsigned long total_rss, unsigned long shmem,
	long sp_res_nsize, long *non_sp_res_out, long *non_sp_shm_out)
{
	long non_sp_res, non_sp_shm;

	non_sp_res = page2kb(total_rss) - sp_res_nsize;
	non_sp_res = non_sp_res < 0 ? 0 : non_sp_res;
	non_sp_shm = page2kb(shmem) - sp_res_nsize;
	non_sp_shm = non_sp_shm < 0 ? 0 : non_sp_shm;

	*non_sp_res_out = non_sp_res;
	*non_sp_shm_out = non_sp_shm;
}

static long get_sp_res_by_spg_proc(struct spg_proc_stat *stat)
{
	return byte2kb(atomic64_read(&stat->spg_stat->alloc_size));
}

static unsigned long get_process_prot_locked(int spg_id, struct mm_struct *mm)
{
	unsigned long prot = 0;
	struct sp_group_node *spg_node;
	struct sp_group_master *master = mm->sp_group_master;

	list_for_each_entry(spg_node, &master->node_list, group_node) {
		if (spg_node->spg->id == spg_id) {
			prot = spg_node->prot;
			break;
		}
	}
	return prot;
}

static void print_process_prot(struct seq_file *seq, unsigned long prot)
{
	if (prot == PROT_READ)
		seq_puts(seq, "R");
	else if (prot == (PROT_READ | PROT_WRITE))
		seq_puts(seq, "RW");
	else  /* e.g. spg_none */
		seq_puts(seq, "-");
}

int proc_sp_group_state(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	struct sp_group_master *master;
	struct sp_proc_stat *proc_stat;
	struct spg_proc_stat *spg_proc_stat;
	int i;
	unsigned long anon, file, shmem, total_rss, prot;
	long sp_res, sp_res_nsize, non_sp_res, non_sp_shm;

	if (!mm)
		return 0;

	master = mm->sp_group_master;
	if (!master)
		return 0;

	get_mm_rss_info(mm, &anon, &file, &shmem, &total_rss);
	proc_stat = master->stat;
	get_process_sp_res(proc_stat, &sp_res, &sp_res_nsize);
	get_process_non_sp_res(total_rss, shmem, sp_res_nsize,
			       &non_sp_res, &non_sp_shm);

	seq_puts(m, "Share Pool Aggregate Data of This Process\n\n");
	seq_printf(m, "%-8s %-16s %-9s %-9s %-9s %-10s %-10s %-8s\n",
		   "PID", "COMM", "SP_ALLOC", "SP_K2U", "SP_RES", "Non-SP_RES",
		   "Non-SP_Shm", "VIRT");
	seq_printf(m, "%-8d %-16s %-9ld %-9ld %-9ld %-10ld %-10ld %-8ld\n",
		   proc_stat->tgid, proc_stat->comm,
		   get_proc_alloc(proc_stat),
		   get_proc_k2u(proc_stat),
		   sp_res, non_sp_res, non_sp_shm,
		   page2kb(mm->total_vm));

	seq_puts(m, "\n\nProcess in Each SP Group\n\n");
	seq_printf(m, "%-8s %-9s %-9s %-9s %-4s\n",
		   "Group_ID", "SP_ALLOC", "SP_K2U", "SP_RES", "PROT");

	/* to prevent ABBA deadlock, first hold sp_group_sem */
	down_read(&sp_group_sem);
	mutex_lock(&proc_stat->lock);
	hash_for_each(proc_stat->hash, i, spg_proc_stat, pnode) {
		prot = get_process_prot_locked(spg_proc_stat->spg_id, mm);
		seq_printf(m, "%-8d %-9ld %-9ld %-9ld ",
			spg_proc_stat->spg_id,
			get_spg_proc_alloc(spg_proc_stat),
			get_spg_proc_k2u(spg_proc_stat),
			get_sp_res_by_spg_proc(spg_proc_stat));
		print_process_prot(m, prot);
		seq_putc(m, '\n');
	}
	mutex_unlock(&proc_stat->lock);
	up_read(&sp_group_sem);

	return 0;
}

static void rb_spa_stat_show(struct seq_file *seq)
{
	struct rb_node *node;
	struct sp_area *spa, *prev = NULL;

	spin_lock(&sp_area_lock);

	for (node = rb_first(&sp_area_root); node; node = rb_next(node)) {
		__sp_area_drop_locked(prev);

		spa = rb_entry(node, struct sp_area, rb_node);
		prev = spa;
		atomic_inc(&spa->use_count);
		spin_unlock(&sp_area_lock);

		if (spa->spg == spg_none)  /* k2u to task */
			seq_printf(seq, "%-10s ", "None");
		else {
			down_read(&spa->spg->rw_lock);
			if (spg_valid(spa->spg))  /* k2u to group */
				seq_printf(seq, "%-10d ", spa->spg->id);
			else  /* spg is dead */
				seq_printf(seq, "%-10s ", "Dead");
			up_read(&spa->spg->rw_lock);
		}

		seq_printf(seq, "%2s%-14lx %2s%-14lx %-10ld ",
			   "0x", spa->va_start,
			   "0x", spa->va_end,
			   byte2kb(spa->real_size));

		switch (spa->type) {
		case SPA_TYPE_ALLOC:
			seq_printf(seq, "%-7s ", "ALLOC");
			break;
		case SPA_TYPE_K2TASK:
			seq_printf(seq, "%-7s ", "TASK");
			break;
		case SPA_TYPE_K2SPG:
			seq_printf(seq, "%-7s ", "SPG");
			break;
		default:
			/* usually impossible, perhaps a developer's mistake */
			break;
		}

		if (spa->is_hugepage)
			seq_printf(seq, "%-5s ", "Y");
		else
			seq_printf(seq, "%-5s ", "N");

		seq_printf(seq, "%-8d ",  spa->applier);
		seq_printf(seq, "%-8d\n", atomic_read(&spa->use_count));

		spin_lock(&sp_area_lock);
	}
	__sp_area_drop_locked(prev);
	spin_unlock(&sp_area_lock);
}

void spa_overview_show(struct seq_file *seq)
{
	unsigned int total_num, alloc_num, k2u_task_num, k2u_spg_num;
	unsigned long total_size, alloc_size, k2u_task_size, k2u_spg_size;
	unsigned long dvpp_size, dvpp_va_size;

	if (!sp_is_enabled())
		return;

	spin_lock(&sp_area_lock);
	total_num     = spa_stat.total_num;
	alloc_num     = spa_stat.alloc_num;
	k2u_task_num  = spa_stat.k2u_task_num;
	k2u_spg_num   = spa_stat.k2u_spg_num;
	total_size    = spa_stat.total_size;
	alloc_size    = spa_stat.alloc_size;
	k2u_task_size = spa_stat.k2u_task_size;
	k2u_spg_size  = spa_stat.k2u_spg_size;
	dvpp_size     = spa_stat.dvpp_size;
	dvpp_va_size  = spa_stat.dvpp_va_size;
	spin_unlock(&sp_area_lock);

	if (seq != NULL) {
		seq_printf(seq, "Spa total num %u.\n", total_num);
		seq_printf(seq, "Spa alloc num %u, k2u(task) num %u, k2u(spg) num %u.\n",
			   alloc_num, k2u_task_num, k2u_spg_num);
		seq_printf(seq, "Spa total size:     %13lu KB\n", byte2kb(total_size));
		seq_printf(seq, "Spa alloc size:     %13lu KB\n", byte2kb(alloc_size));
		seq_printf(seq, "Spa k2u(task) size: %13lu KB\n", byte2kb(k2u_task_size));
		seq_printf(seq, "Spa k2u(spg) size:  %13lu KB\n", byte2kb(k2u_spg_size));
		seq_printf(seq, "Spa dvpp size:      %13lu KB\n", byte2kb(dvpp_size));
		seq_printf(seq, "Spa dvpp va size:   %13lu MB\n", byte2mb(dvpp_va_size));
		seq_puts(seq, "\n");
	} else {
		pr_info("Spa total num %u.\n", total_num);
		pr_info("Spa alloc num %u, k2u(task) num %u, k2u(spg) num %u.\n",
			alloc_num, k2u_task_num, k2u_spg_num);
		pr_info("Spa total size:     %13lu KB\n", byte2kb(total_size));
		pr_info("Spa alloc size:     %13lu KB\n", byte2kb(alloc_size));
		pr_info("Spa k2u(task) size: %13lu KB\n", byte2kb(k2u_task_size));
		pr_info("Spa k2u(spg) size:  %13lu KB\n", byte2kb(k2u_spg_size));
		pr_info("Spa dvpp size:      %13lu KB\n", byte2kb(dvpp_size));
		pr_info("Spa dvpp va size:   %13lu MB\n", byte2mb(dvpp_va_size));
		pr_info("\n");
	}
}

/* the caller must hold sp_group_sem */
static int idr_spg_stat_cb(int id, void *p, void *data)
{
	struct sp_spg_stat *s = p;
	struct seq_file *seq = data;

	if (seq != NULL) {
		if (id == 0)
			seq_puts(seq, "Non Group ");
		else
			seq_printf(seq, "Group %6d ", id);

		seq_printf(seq, "size: %lld KB, spa num: %d, total alloc: %lld KB, normal alloc: %lld KB, huge alloc: %lld KB\n",
			   byte2kb(atomic64_read(&s->size)),
			   atomic_read(&s->spa_num),
			   byte2kb(atomic64_read(&s->alloc_size)),
			   byte2kb(atomic64_read(&s->alloc_nsize)),
			   byte2kb(atomic64_read(&s->alloc_hsize)));
	} else {
		if (id == 0)
			pr_info("Non Group ");
		else
			pr_info("Group %6d ", id);

		pr_info("size: %lld KB, spa num: %d, total alloc: %lld KB, normal alloc: %lld KB, huge alloc: %lld KB\n",
			byte2kb(atomic64_read(&s->size)),
			atomic_read(&s->spa_num),
			byte2kb(atomic64_read(&s->alloc_size)),
			byte2kb(atomic64_read(&s->alloc_nsize)),
			byte2kb(atomic64_read(&s->alloc_hsize)));
	}

	return 0;
}

void spg_overview_show(struct seq_file *seq)
{
	if (!sp_is_enabled())
		return;

	if (seq != NULL) {
		seq_printf(seq, "Share pool total size: %lld KB, spa total num: %d.\n",
			   byte2kb(atomic64_read(&sp_overall_stat.spa_total_size)),
			   atomic_read(&sp_overall_stat.spa_total_num));
	} else {
		pr_info("Share pool total size: %lld KB, spa total num: %d.\n",
			byte2kb(atomic64_read(&sp_overall_stat.spa_total_size)),
			atomic_read(&sp_overall_stat.spa_total_num));
	}

	down_read(&sp_group_sem);
	idr_for_each(&sp_spg_stat_idr, idr_spg_stat_cb, seq);
	up_read(&sp_group_sem);

	if (seq != NULL)
		seq_puts(seq, "\n");
	else
		pr_info("\n");
}

static int spa_stat_show(struct seq_file *seq, void *offset)
{
	spg_overview_show(seq);
	spa_overview_show(seq);
	/* print the file header */
	seq_printf(seq, "%-10s %-16s %-16s %-10s %-7s %-5s %-8s %-8s\n",
		   "Group ID", "va_start", "va_end", "Size(KB)", "Type", "Huge", "PID", "Ref");
	rb_spa_stat_show(seq);
	return 0;
}

static int idr_proc_stat_cb(int id, void *p, void *data)
{
	struct sp_spg_stat *spg_stat = p;
	struct seq_file *seq = data;
	int i, tgid;
	struct sp_proc_stat *proc_stat;
	struct spg_proc_stat *spg_proc_stat;

	struct mm_struct *mm;
	unsigned long anon, file, shmem, total_rss, prot;
	/*
	 * non_sp_res: resident memory size excluding share pool memory
	 * sp_res:     resident memory size of share pool, including normal
	 *             page and hugepage memory
	 * non_sp_shm: resident shared memory size excluding share pool
	 *             memory
	 */
	long sp_res, sp_res_nsize, non_sp_res, non_sp_shm;

	/* to prevent ABBA deadlock, first hold sp_group_sem */
	down_read(&sp_group_sem);
	mutex_lock(&spg_stat->lock);
	hash_for_each(spg_stat->hash, i, spg_proc_stat, gnode) {
		proc_stat = spg_proc_stat->proc_stat;
		tgid = proc_stat->tgid;
		mm = proc_stat->mm;

		get_mm_rss_info(mm, &anon, &file, &shmem, &total_rss);
		get_process_sp_res(proc_stat, &sp_res, &sp_res_nsize);
		get_process_non_sp_res(total_rss, shmem, sp_res_nsize,
				       &non_sp_res, &non_sp_shm);
		prot = get_process_prot_locked(id, mm);

		seq_printf(seq, "%-8d ", tgid);
		if (id == 0)
			seq_printf(seq, "%-8c ", '-');
		else
			seq_printf(seq, "%-8d ", id);
		seq_printf(seq, "%-9ld %-9ld %-9ld %-10ld %-10ld %-8ld %-7ld %-7ld %-10ld ",
			   get_spg_proc_alloc(spg_proc_stat),
			   get_spg_proc_k2u(spg_proc_stat),
			   get_sp_res_by_spg_proc(spg_proc_stat),
			   sp_res, non_sp_res,
			   page2kb(mm->total_vm), page2kb(total_rss),
			   page2kb(shmem), non_sp_shm);
		print_process_prot(seq, prot);
		seq_putc(seq, '\n');
	}
	mutex_unlock(&spg_stat->lock);
	up_read(&sp_group_sem);
	return 0;
}

static int proc_stat_show(struct seq_file *seq, void *offset)
{
	spg_overview_show(seq);
	spa_overview_show(seq);
	/* print the file header */
	seq_printf(seq, "%-8s %-8s %-9s %-9s %-9s %-10s %-10s %-8s %-7s %-7s %-10s %-4s\n",
		   "PID", "Group_ID", "SP_ALLOC", "SP_K2U", "SP_RES", "SP_RES_T",
		   "Non-SP_RES", "VIRT", "RES", "Shm", "Non-SP_Shm", "PROT");
	/* print kthread buff_module_guard_work */
	seq_printf(seq, "%-8s %-8s %-9lld %-9lld\n",
		   "guard", "-",
		   byte2kb(atomic64_read(&kthread_stat.alloc_size)),
		   byte2kb(atomic64_read(&kthread_stat.k2u_size)));

	/* pay attention to potential ABBA deadlock */
	down_read(&sp_spg_stat_sem);
	idr_for_each(&sp_spg_stat_idr, idr_proc_stat_cb, seq);
	up_read(&sp_spg_stat_sem);
	return 0;
}

static int idr_proc_overview_cb(int id, void *p, void *data)
{
	struct sp_proc_stat *proc_stat = p;
	struct seq_file *seq = data;
	struct mm_struct *mm = proc_stat->mm;
	unsigned long anon, file, shmem, total_rss;
	long sp_res, sp_res_nsize, non_sp_res, non_sp_shm;

	get_mm_rss_info(mm, &anon, &file, &shmem, &total_rss);
	get_process_sp_res(proc_stat, &sp_res, &sp_res_nsize);
	get_process_non_sp_res(total_rss, shmem, sp_res_nsize,
			       &non_sp_res, &non_sp_shm);

	seq_printf(seq, "%-8d %-16s %-9ld %-9ld %-9ld %-10ld %-10ld %-8ld\n",
		   id, proc_stat->comm,
		   get_proc_alloc(proc_stat),
		   get_proc_k2u(proc_stat),
		   sp_res, non_sp_res, non_sp_shm,
		   page2kb(mm->total_vm));
	return 0;
}

static int proc_overview_show(struct seq_file *seq, void *offset)
{
	seq_printf(seq, "%-8s %-16s %-9s %-9s %-9s %-10s %-10s %-8s\n",
		   "PID", "COMM", "SP_ALLOC", "SP_K2U", "SP_RES", "Non-SP_RES",
		   "Non-SP_Shm", "VIRT");

	down_read(&sp_proc_stat_sem);
	idr_for_each(&sp_proc_stat_idr, idr_proc_overview_cb, seq);
	up_read(&sp_proc_stat_sem);
	return 0;
}

static void __init proc_sharepool_init(void)
{
	if (!proc_mkdir("sharepool", NULL))
		return;

	proc_create_single_data("sharepool/proc_stat", 0400, NULL, proc_stat_show, NULL);
	proc_create_single_data("sharepool/spa_stat", 0400, NULL, spa_stat_show, NULL);
	proc_create_single_data("sharepool/proc_overview", 0400, NULL, proc_overview_show, NULL);
}

/*** End of tatistical and maintenance functions ***/

DEFINE_STATIC_KEY_FALSE(share_pool_enabled_key);

static int __init enable_share_pool(char *s)
{
	static_branch_enable(&share_pool_enabled_key);
	pr_info("Ascend enable share pool features via bootargs\n");

	return 1;
}
__setup("enable_ascend_share_pool", enable_share_pool);

static void __init sp_device_number_detect(void)
{
	/* NOTE: TO BE COMPLETED */
	sp_device_number = 4;

	if (sp_device_number > MAX_DEVID) {
		pr_warn("sp_device_number %d exceed, truncate it to %d\n",
				sp_device_number, MAX_DEVID);
		sp_device_number = MAX_DEVID;
	}
}

static int __init share_pool_init(void)
{
	/* lockless, as init kthread has no sp operation else */
	spg_none = create_spg(GROUP_NONE);
	/* without free spg_none, not a serious problem */
	if (IS_ERR(spg_none) || !spg_none)
		goto fail;

	sp_device_number_detect();
	proc_sharepool_init();

	return 0;
fail:
	pr_err("Ascend share pool initialization failed\n");
	static_branch_disable(&share_pool_enabled_key);
	return 1;
}
late_initcall(share_pool_init);
