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

/* access control mode macros  */
#define AC_NONE			0
#define AC_SINGLE_OWNER		1

#define spg_valid(spg)		((spg)->is_alive == true)

/* Use spa va address as mmap offset. This can work because spa_file
 * is setup with 64-bit address space. So va shall be well covered.
 */
#define addr_offset(spa)	((spa)->va_start)

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

/* access control mode */
int sysctl_ac_mode = AC_NONE;
/* debug mode */
int sysctl_sp_debug_mode;
EXPORT_SYMBOL(sysctl_sp_debug_mode);

int sysctl_share_pool_map_lock_enable;

int sysctl_sp_perf_alloc;

int sysctl_sp_perf_k2u;

static int share_pool_group_mode = SINGLE_GROUP_MODE;

static int system_group_count;

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

static struct sp_proc_stat *sp_get_proc_stat(struct mm_struct *mm)
{
	struct sp_proc_stat *stat;

	if (!mm->sp_group_master)
		return NULL;

	down_read(&sp_proc_stat_sem);
	stat = mm->sp_group_master->stat;
	up_read(&sp_proc_stat_sem);

	/* maybe NULL or not, we always return it */
	return stat;
}

/* user must call sp_proc_stat_drop() after use */
struct sp_proc_stat *sp_get_proc_stat_ref(struct mm_struct *mm)
{
	struct sp_proc_stat *stat;

	if (!mm->sp_group_master)
		return NULL;

	down_read(&sp_proc_stat_sem);
	stat = mm->sp_group_master->stat;
	up_read(&sp_proc_stat_sem);

	if (!stat || !atomic_inc_not_zero(&stat->use_count))
		stat = NULL;

	/* maybe NULL or not, we always return it */
	return stat;
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

/* the caller should hold sp_area_lock */
static void spa_inc_usage(struct sp_area *spa)
{
	enum spa_type type = spa->type;
	unsigned long size = spa->real_size;
	bool is_dvpp = spa->flags & SP_DVPP;
	bool is_huge = spa->is_hugepage;

	switch (type) {
	case SPA_TYPE_ALLOC:
		spa_stat.alloc_num += 1;
		spa_stat.alloc_size += size;
		update_spg_stat_alloc(size, true, is_huge, spa->spg->stat);
		break;
	case SPA_TYPE_K2TASK:
		spa_stat.k2u_task_num += 1;
		spa_stat.k2u_task_size += size;
		update_spg_stat_k2u(size, true, spg_none->stat);
		break;
	case SPA_TYPE_K2SPG:
		spa_stat.k2u_spg_num += 1;
		spa_stat.k2u_spg_size += size;
		update_spg_stat_k2u(size, true, spa->spg->stat);
		break;
	default:
		WARN(1, "invalid spa type");
	}

	if (is_dvpp) {
		spa_stat.dvpp_size += size;
		spa_stat.dvpp_va_size += PMD_ALIGN(size);
	}

	/*
	 * all the calculations won't overflow due to system limitation and
	 * parameter checking in sp_alloc_area()
	 */
	spa_stat.total_num += 1;
	spa_stat.total_size += size;

	if (spa->spg != spg_none) {
		atomic_inc(&sp_overall_stat.spa_total_num);
		atomic64_add(size, &sp_overall_stat.spa_total_size);
	}
}

/* the caller should hold sp_area_lock */
static void spa_dec_usage(struct sp_area *spa)
{
	enum spa_type type = spa->type;
	unsigned long size = spa->real_size;
	bool is_dvpp = spa->flags & SP_DVPP;
	bool is_huge = spa->is_hugepage;

	switch (type) {
	case SPA_TYPE_ALLOC:
		spa_stat.alloc_num -= 1;
		spa_stat.alloc_size -= size;
		update_spg_stat_alloc(size, false, is_huge, spa->spg->stat);
		break;
	case SPA_TYPE_K2TASK:
		spa_stat.k2u_task_num -= 1;
		spa_stat.k2u_task_size -= size;
		update_spg_stat_k2u(size, false, spg_none->stat);
		break;
	case SPA_TYPE_K2SPG:
		spa_stat.k2u_spg_num -= 1;
		spa_stat.k2u_spg_size -= size;
		update_spg_stat_k2u(size, false, spa->spg->stat);
		break;
	default:
		WARN(1, "invalid spa type");
	}

	if (is_dvpp) {
		spa_stat.dvpp_size -= size;
		spa_stat.dvpp_va_size -= PMD_ALIGN(size);
	}

	spa_stat.total_num -= 1;
	spa_stat.total_size -= size;

	if (spa->spg != spg_none) {
		atomic_dec(&sp_overall_stat.spa_total_num);
		atomic64_sub(spa->real_size, &sp_overall_stat.spa_total_size);
	}
}

static void update_spg_proc_stat(unsigned long size, bool inc,
	struct spg_proc_stat *stat, enum spa_type type)
{
	if (unlikely(!stat)) {
		sp_dump_stack();
		WARN(1, "null process stat\n");
		return;
	}

	switch (type) {
	case SPA_TYPE_ALLOC:
		update_spg_proc_stat_alloc(size, inc, stat);
		break;
	case SPA_TYPE_K2TASK:
	case SPA_TYPE_K2SPG:
		update_spg_proc_stat_k2u(size, inc, stat);
		break;
	default:
		WARN(1, "invalid stat type\n");
	}
}

static void sp_update_process_stat(struct task_struct *tsk, bool inc,
	struct sp_area *spa)
{
	struct spg_proc_stat *stat;
	unsigned long size = spa->real_size;
	enum spa_type type = spa->type;

	down_write(&sp_group_sem);
	stat = sp_init_process_stat(tsk, tsk->mm, spa->spg);
	up_write(&sp_group_sem);
	if (unlikely(IS_ERR(stat)))
		return;

	update_spg_proc_stat(size, inc, stat, type);
}

static inline void check_interrupt_context(void)
{
	if (unlikely(in_interrupt()))
		panic("function can't be used in interrupt context\n");
}

static inline bool check_aoscore_process(struct task_struct *tsk)
{
	if (tsk->flags & PF_DOMAIN_CORE)
		return true;
	else
		return false;
}

static unsigned long sp_mmap(struct mm_struct *mm, struct file *file,
			     struct sp_area *spa, unsigned long *populate,
			     unsigned long prot);
static void sp_munmap(struct mm_struct *mm, unsigned long addr, unsigned long size);

#define K2U_NORMAL	0
#define K2U_COREDUMP	1

struct sp_k2u_context {
	unsigned long kva;
	unsigned long kva_aligned;
	unsigned long size;
	unsigned long size_aligned;
	unsigned long sp_flags;
	int state;
	int spg_id;
	bool to_task;
	struct timespec64 start;
	struct timespec64 end;
};

static unsigned long sp_remap_kva_to_vma(unsigned long kva, struct sp_area *spa,
				struct mm_struct *mm, unsigned long prot, struct sp_k2u_context *kc);

static void free_sp_group_id(int spg_id)
{
	/* ida operation is protected by an internal spin_lock */
	if (spg_id >= SPG_ID_AUTO_MIN && spg_id <= SPG_ID_AUTO_MAX)
		ida_free(&sp_group_id_ida, spg_id);
}

static void free_new_spg_id(bool new, int spg_id)
{
	if (new)
		free_sp_group_id(spg_id);
}

static void free_sp_group_locked(struct sp_group *spg)
{
	fput(spg->file);
	fput(spg->file_hugetlb);
	free_spg_stat(spg->id);
	idr_remove(&sp_group_idr, spg->id);
	free_sp_group_id((unsigned int)spg->id);
	kfree(spg);
	system_group_count--;
	WARN(system_group_count < 0, "unexpected group count\n");
}

static void free_sp_group(struct sp_group *spg)
{
	down_write(&sp_group_sem);
	free_sp_group_locked(spg);
	up_write(&sp_group_sem);
}

static void sp_group_drop(struct sp_group *spg)
{
	if (atomic_dec_and_test(&spg->use_count))
		free_sp_group(spg);
}

/* use with put_task_struct(task) */
static int get_task(int pid, struct task_struct **task)
{
	struct task_struct *tsk;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (!tsk || (tsk->flags & PF_EXITING)) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(tsk);
	rcu_read_unlock();

	*task = tsk;
	return 0;
}

static struct sp_group *get_first_group(struct mm_struct *mm)
{
	struct sp_group *spg = NULL;
	struct sp_group_master *master = mm->sp_group_master;

	if (master && master->count >= 1) {
		struct sp_group_node *spg_node = NULL;

		spg_node = list_first_entry(&master->node_list,
					struct sp_group_node, group_node);
		spg = spg_node->spg;

		/* don't revive a dead group */
		if (!spg || !atomic_inc_not_zero(&spg->use_count))
			spg = NULL;
	}

	return spg;
}

/*
 * the caller must:
 * 1. hold spg->rw_lock
 * 2. ensure no concurrency problem for mm_struct
 */
static struct sp_group_node *is_process_in_group(struct sp_group *spg,
						 struct mm_struct *mm)
{
	struct sp_group_node *spg_node;

	list_for_each_entry(spg_node, &spg->procs, proc_node)
		if (spg_node->master->mm == mm)
			return spg_node;

	return NULL;
}

/* user must call sp_group_drop() after use */
static struct sp_group *__sp_find_spg_locked(int pid, int spg_id)
{
	struct sp_group *spg = NULL;
	struct task_struct *tsk = NULL;
	int ret = 0;

	ret = get_task(pid, &tsk);
	if (ret)
		return NULL;

	if (spg_id == SPG_ID_DEFAULT) {
		/*
		 * Once we encounter a concurrency problem here.
		 * To fix it, we believe get_task_mm() and mmput() is too
		 * heavy because we just get the pointer of sp_group.
		 */
		task_lock(tsk);
		if (tsk->mm == NULL)
			spg = NULL;
		else
			spg = get_first_group(tsk->mm);
		task_unlock(tsk);
	} else {
		spg = idr_find(&sp_group_idr, spg_id);
		/* don't revive a dead group */
		if (!spg || !atomic_inc_not_zero(&spg->use_count))
			goto fail;
	}

	put_task_struct(tsk);
	return spg;

fail:
	put_task_struct(tsk);
	return NULL;
}

static struct sp_group *__sp_find_spg(int pid, int spg_id)
{
	struct sp_group *spg;

	down_read(&sp_group_sem);
	spg = __sp_find_spg_locked(pid, spg_id);
	up_read(&sp_group_sem);
	return spg;
}

/**
 * sp_group_id_by_pid() - Get the sp_group ID of a process.
 * @pid: pid of target process.
 *
 * Return:
 * >0		- the sp_group ID.
 * -ENODEV	- target process doesn't belong to any sp_group.
 */
int sp_group_id_by_pid(int pid)
{
	struct sp_group *spg;
	int spg_id = -ENODEV;

	check_interrupt_context();

	spg = __sp_find_spg(pid, SPG_ID_DEFAULT);
	if (!spg)
		return -ENODEV;

	down_read(&spg->rw_lock);
	if (spg_valid(spg))
		spg_id = spg->id;
	up_read(&spg->rw_lock);

	sp_group_drop(spg);
	return spg_id;
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
	int ret = 0;
	struct sp_group_node *node;
	struct sp_group_master *master = NULL;
	struct task_struct *tsk;

	check_interrupt_context();

	if (!spg_ids || num <= 0)
		return -EINVAL;

	ret = get_task(pid, &tsk);
	if (ret)
		return ret;

	down_read(&sp_group_sem);
	task_lock(tsk);
	if (tsk->mm)
		master = tsk->mm->sp_group_master;
	task_unlock(tsk);

	if (!master) {
		ret = -ENODEV;
		goto out_up_read;
	}

	if (!master->count) {
		ret = -ENODEV;
		goto out_up_read;
	}
	if ((unsigned int)*num < master->count) {
		ret = -E2BIG;
		goto out_up_read;
	}
	*num = master->count;

	list_for_each_entry(node, &master->node_list, group_node)
		*(spg_ids++) = node->spg->id;

out_up_read:
	up_read(&sp_group_sem);
	put_task_struct(tsk);
	return ret;
}
EXPORT_SYMBOL_GPL(mg_sp_group_id_by_pid);

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

static struct sp_group *create_spg(int spg_id)
{
	int ret;
	struct sp_group *spg;
	char name[20];
	struct user_struct *user = NULL;
	int hsize_log = MAP_HUGE_2MB >> MAP_HUGE_SHIFT;

	if (unlikely(system_group_count + 1 == MAX_GROUP_FOR_SYSTEM)) {
		pr_err_ratelimited("reach system max group num\n");
		return ERR_PTR(-ENOSPC);
	}

	spg = kzalloc(sizeof(*spg), GFP_KERNEL);
	if (spg == NULL) {
		pr_err_ratelimited("no memory for spg\n");
		return ERR_PTR(-ENOMEM);
	}
	ret = idr_alloc(&sp_group_idr, spg, spg_id, spg_id + 1, GFP_KERNEL);
	if (ret < 0) {
		pr_err_ratelimited("group %d idr alloc failed %d\n",
				   spg_id, ret);
		goto out_kfree;
	}

	spg->id = spg_id;
	spg->is_alive = true;
	spg->proc_num = 0;
	spg->owner = current->group_leader;
	atomic_set(&spg->use_count, 1);
	INIT_LIST_HEAD(&spg->procs);
	INIT_LIST_HEAD(&spg->spa_list);
	init_rwsem(&spg->rw_lock);

	sprintf(name, "sp_group_%d", spg_id);
	spg->file = shmem_kernel_file_setup(name, MAX_LFS_FILESIZE,
					    VM_NORESERVE);
	if (IS_ERR(spg->file)) {
		pr_err("spg file setup failed %ld\n", PTR_ERR(spg->file));
		ret = PTR_ERR(spg->file);
		goto out_idr;
	}

	spg->file_hugetlb = hugetlb_file_setup(name, MAX_LFS_FILESIZE,
					       VM_NORESERVE, &user, HUGETLB_ANONHUGE_INODE, hsize_log);
	if (IS_ERR(spg->file_hugetlb)) {
		pr_err("spg file_hugetlb setup failed %ld\n",
		       PTR_ERR(spg->file_hugetlb));
		ret = PTR_ERR(spg->file_hugetlb);
		goto out_fput;
	}

	ret = sp_init_spg_stat(spg);
	if (ret < 0)
		goto out_fput_all;

	system_group_count++;
	return spg;

out_fput_all:
	fput(spg->file_hugetlb);
out_fput:
	fput(spg->file);
out_idr:
	idr_remove(&sp_group_idr, spg_id);
out_kfree:
	kfree(spg);
	return ERR_PTR(ret);
}

/* the caller must hold sp_group_sem */
static struct sp_group *find_or_alloc_sp_group(int spg_id)
{
	struct sp_group *spg;

	spg = __sp_find_spg_locked(current->pid, spg_id);

	if (!spg) {
		spg = create_spg(spg_id);
	} else {
		down_read(&spg->rw_lock);
		if (!spg_valid(spg)) {
			up_read(&spg->rw_lock);
			sp_group_drop(spg);
			return ERR_PTR(-ENODEV);
		}
		up_read(&spg->rw_lock);
		/* spg->use_count has increased due to __sp_find_spg() */
	}

	return spg;
}

static void __sp_area_drop_locked(struct sp_area *spa);

/* The caller must down_write(&mm->mmap_sem) */
static void sp_munmap_task_areas(struct mm_struct *mm, struct sp_group *spg, struct list_head *stop)
{
	struct sp_area *spa, *prev = NULL;
	int err;


	spin_lock(&sp_area_lock);
	list_for_each_entry(spa, &spg->spa_list, link) {
		if (&spa->link == stop)
			break;

		__sp_area_drop_locked(prev);
		prev = spa;

		atomic_inc(&spa->use_count);
		spin_unlock(&sp_area_lock);

		err = do_munmap(mm, spa->va_start, spa_size(spa), NULL);
		if (err) {
			/* we are not supposed to fail */
			pr_err("failed to unmap VA %pK when munmap task areas\n",
			       (void *)spa->va_start);
		}

		spin_lock(&sp_area_lock);
	}
	__sp_area_drop_locked(prev);

	spin_unlock(&sp_area_lock);
}

/* the caller must hold sp_group_sem */
static int mm_add_group_init(struct mm_struct *mm, struct sp_group *spg)
{
	struct sp_group_master *master = mm->sp_group_master;
	bool exist = false;

	if (share_pool_group_mode == SINGLE_GROUP_MODE && master &&
	    master->count == 1) {
		pr_err_ratelimited("at most one sp group for a task is allowed in single mode\n");
		return -EEXIST;
	}

	master = sp_init_group_master_locked(mm, &exist);
	if (IS_ERR(master))
		return PTR_ERR(master);

	if (!exist)
		return 0;

	if (is_process_in_group(spg, mm)) {
		pr_err_ratelimited("task already in target group, id=%d\n", spg->id);
		return -EEXIST;
	}

	if (master->count + 1 == MAX_GROUP_FOR_TASK) {
		pr_err("task reaches max group num\n");
		return -ENOSPC;
	}

	return 0;
}

/* the caller must hold sp_group_sem */
static struct sp_group_node *create_spg_node(struct mm_struct *mm,
	unsigned long prot, struct sp_group *spg)
{
	struct sp_group_master *master = mm->sp_group_master;
	struct sp_group_node *spg_node;

	spg_node = kzalloc(sizeof(struct sp_group_node), GFP_KERNEL);
	if (spg_node == NULL) {
		pr_err_ratelimited("no memory for spg node\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&spg_node->group_node);
	INIT_LIST_HEAD(&spg_node->proc_node);
	spg_node->spg = spg;
	spg_node->master = master;
	spg_node->prot = prot;

	list_add_tail(&spg_node->group_node, &master->node_list);
	master->count++;

	return spg_node;
}

/* the caller must down_write(&spg->rw_lock) */
static int insert_spg_node(struct sp_group *spg, struct sp_group_node *node)
{
	if (spg->proc_num + 1 == MAX_PROC_PER_GROUP) {
		pr_err_ratelimited("add group: group reaches max process num\n");
		return -ENOSPC;
	}

	spg->proc_num++;
	list_add_tail(&node->proc_node, &spg->procs);
	return 0;
}

/* the caller must down_write(&spg->rw_lock) */
static void delete_spg_node(struct sp_group *spg, struct sp_group_node *node)
{
	list_del(&node->proc_node);
	spg->proc_num--;
}

/* the caller must hold sp_group_sem */
static void free_spg_node(struct mm_struct *mm, struct sp_group *spg,
	struct sp_group_node *spg_node)
{
	struct sp_group_master *master = mm->sp_group_master;

	list_del(&spg_node->group_node);
	master->count--;

	kfree(spg_node);
}

/**
 * sp_group_add_task() - Add a process to an share group (sp_group).
 * @pid: the pid of the task to be added.
 * @prot: the prot of task for this spg.
 * @spg_id: the ID of the sp_group.
 *
 * A process can't be added to more than one sp_group in single group mode
 * and can in multiple group mode.
 *
 * Return: A postive group number for success, -errno on failure.
 *
 * The manually specified ID is between [SPG_ID_MIN, SPG_ID_MAX].
 * The automatically allocated ID is between [SPG_ID_AUTO_MIN, SPG_ID_AUTO_MAX].
 * When negative, the return value is -errno.
 */
int mg_sp_group_add_task(int pid, unsigned long prot, int spg_id)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct sp_group *spg;
	struct sp_group_node *node = NULL;
	int ret = 0;
	bool id_newly_generated = false;
	struct sp_area *spa, *prev = NULL;
	struct spg_proc_stat *stat;

	check_interrupt_context();

	/* only allow READ, READ | WRITE */
	if (!((prot == PROT_READ)
	      || (prot == (PROT_READ | PROT_WRITE)))) {
		pr_err_ratelimited("prot is invalid 0x%lx\n", prot);
		return -EINVAL;
	}

	/* mdc scene hack */
	if (enable_mdc_default_group)
		spg_id = mdc_default_group_id;

	if (spg_id < SPG_ID_MIN || spg_id > SPG_ID_AUTO) {
		pr_err_ratelimited("add group failed, invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	if (spg_id >= SPG_ID_AUTO_MIN && spg_id <= SPG_ID_AUTO_MAX) {
		spg = __sp_find_spg(pid, spg_id);

		if (!spg) {
			pr_err_ratelimited("spg %d hasn't been created\n", spg_id);
			return -EINVAL;
		}

		down_read(&spg->rw_lock);
		if (!spg_valid(spg)) {
			up_read(&spg->rw_lock);
			pr_err_ratelimited("add group failed, group id %d is dead\n", spg_id);
			sp_group_drop(spg);
			return -EINVAL;
		}
		up_read(&spg->rw_lock);

		sp_group_drop(spg);
	}

	if (spg_id == SPG_ID_AUTO) {
		spg_id = ida_alloc_range(&sp_group_id_ida, SPG_ID_AUTO_MIN,
					 SPG_ID_AUTO_MAX, GFP_ATOMIC);
		if (spg_id < 0) {
			pr_err_ratelimited("add group failed, auto generate group id failed\n");
			return spg_id;
		}
		id_newly_generated = true;
	}

	down_write(&sp_group_sem);

	ret = get_task(pid, &tsk);
	if (ret) {
		up_write(&sp_group_sem);
		free_new_spg_id(id_newly_generated, spg_id);
		goto out;
	}

	if (check_aoscore_process(tsk)) {
		up_write(&sp_group_sem);
		ret = -EACCES;
		free_new_spg_id(id_newly_generated, spg_id);
		sp_dump_stack();
		goto out_put_task;
	}

	/*
	 * group_leader: current thread may be exiting in a multithread process
	 *
	 * DESIGN IDEA
	 * We increase mm->mm_users deliberately to ensure it's decreased in
	 * share pool under only 2 circumstances, which will simply the overall
	 * design as mm won't be freed unexpectedly.
	 *
	 * The corresponding refcount decrements are as follows:
	 * 1. the error handling branch of THIS function.
	 * 2. In sp_group_exit(). It's called only when process is exiting.
	 */
	mm = get_task_mm(tsk->group_leader);
	if (!mm) {
		up_write(&sp_group_sem);
		ret = -ESRCH;
		free_new_spg_id(id_newly_generated, spg_id);
		goto out_put_task;
	}

	spg = find_or_alloc_sp_group(spg_id);
	if (IS_ERR(spg)) {
		up_write(&sp_group_sem);
		ret = PTR_ERR(spg);
		free_new_spg_id(id_newly_generated, spg_id);
		goto out_put_mm;
	}

	/* access control permission check */
	if (sysctl_ac_mode == AC_SINGLE_OWNER) {
		if (spg->owner != current->group_leader) {
			ret = -EPERM;
			goto out_drop_group;
		}
	}

	ret = mm_add_group_init(mm, spg);
	if (ret)
		goto out_drop_group;

	node = create_spg_node(mm, prot, spg);
	if (unlikely(IS_ERR(node))) {
		ret = PTR_ERR(node);
		goto out_drop_spg_node;
	}

	/* per process statistics initialization */
	stat = sp_init_process_stat(tsk, mm, spg);
	if (IS_ERR(stat)) {
		ret = PTR_ERR(stat);
		pr_err_ratelimited("init process stat failed %lx\n", PTR_ERR(stat));
		goto out_drop_spg_node;
	}

	down_write(&spg->rw_lock);
	ret = insert_spg_node(spg, node);
	if (unlikely(ret)) {
		up_write(&spg->rw_lock);
		goto out_drop_spg_node;
	}

	/*
	 * create mappings of existing shared memory segments into this
	 * new process' page table.
	 */
	spin_lock(&sp_area_lock);

	list_for_each_entry(spa, &spg->spa_list, link) {
		unsigned long populate = 0;
		struct file *file = spa_file(spa);
		unsigned long addr;

		__sp_area_drop_locked(prev);
		prev = spa;

		atomic_inc(&spa->use_count);

		if (spa->is_dead == true)
			continue;

		spin_unlock(&sp_area_lock);

		if (spa->type == SPA_TYPE_K2SPG && spa->kva) {
			addr = sp_remap_kva_to_vma(spa->kva, spa, mm, prot, NULL);
			if (IS_ERR_VALUE(addr))
				pr_warn("add group remap k2u failed %ld\n", addr);

			spin_lock(&sp_area_lock);
			continue;
		}

		down_write(&mm->mmap_sem);
		if (unlikely(mm->core_state)) {
			sp_munmap_task_areas(mm, spg, &spa->link);
			up_write(&mm->mmap_sem);
			ret = -EBUSY;
			pr_err("add group: encountered coredump, abort\n");
			spin_lock(&sp_area_lock);
			break;
		}

		addr = sp_mmap(mm, file, spa, &populate, prot);
		if (IS_ERR_VALUE(addr)) {
			sp_munmap_task_areas(mm, spg, &spa->link);
			up_write(&mm->mmap_sem);
			ret = addr;
			pr_err("add group: sp mmap failed %d\n", ret);
			spin_lock(&sp_area_lock);
			break;
		}
		up_write(&mm->mmap_sem);

		if (populate) {
			ret = do_mm_populate(mm, spa->va_start, populate, 0);
			if (ret) {
				if (unlikely(fatal_signal_pending(current)))
					pr_warn_ratelimited("add group failed, current thread is killed\n");
				else
					pr_warn_ratelimited("add group failed, mm populate failed "
							    "(potential no enough memory when -12): %d, spa type is %d\n",
					ret, spa->type);
				down_write(&mm->mmap_sem);
				sp_munmap_task_areas(mm, spg, spa->link.next);
				up_write(&mm->mmap_sem);
				spin_lock(&sp_area_lock);
				break;
			}
		}

		spin_lock(&sp_area_lock);
	}
	__sp_area_drop_locked(prev);
	spin_unlock(&sp_area_lock);

	if (unlikely(ret))
		delete_spg_node(spg, node);
	up_write(&spg->rw_lock);

out_drop_spg_node:
	if (unlikely(ret))
		free_spg_node(mm, spg, node);
	/*
	 * to simplify design, we don't release the resource of
	 * group_master and proc_stat, they will be freed when
	 * process is exiting.
	 */
out_drop_group:
	if (unlikely(ret)) {
		up_write(&sp_group_sem);
		sp_group_drop(spg);
	} else
		up_write(&sp_group_sem);
out_put_mm:
	/* No need to put the mm if the sp group adds this mm successfully */
	if (unlikely(ret))
		mmput(mm);
out_put_task:
	put_task_struct(tsk);
out:
	return ret == 0 ? spg_id : ret;
}
EXPORT_SYMBOL_GPL(mg_sp_group_add_task);

int sp_group_add_task(int pid, int spg_id)
{
	return mg_sp_group_add_task(pid, PROT_READ | PROT_WRITE, spg_id);
}
EXPORT_SYMBOL_GPL(sp_group_add_task);

static void free_spg_proc_stat(struct mm_struct *mm, int spg_id)
{
	int i;
	struct sp_proc_stat *proc_stat = sp_get_proc_stat(mm);
	struct spg_proc_stat *stat;
	struct sp_spg_stat *spg_stat;
	struct hlist_node *tmp;

	hash_for_each_safe(proc_stat->hash, i, tmp, stat, pnode) {
		if (stat->spg_id == spg_id) {
			spg_stat = stat->spg_stat;
			mutex_lock(&spg_stat->lock);
			hash_del(&stat->gnode);
			mutex_unlock(&spg_stat->lock);
			hash_del(&stat->pnode);
			kfree(stat);
			break;
		}
	}
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
	int ret = 0;
	struct sp_group *spg;
	struct sp_group_node *spg_node;
	struct task_struct *tsk = NULL;
	struct mm_struct *mm = NULL;
	bool is_alive = true;

	if (spg_id < SPG_ID_MIN || spg_id > SPG_ID_AUTO) {
		pr_err_ratelimited("del from group failed, invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	spg = __sp_find_spg(pid, spg_id);
	if (!spg) {
		pr_err_ratelimited("spg not found or get task failed.");
		return -EINVAL;
	}
	down_write(&sp_group_sem);

	if (!spg_valid(spg)) {
		up_write(&sp_group_sem);
		pr_err_ratelimited("spg dead.");
		ret = -EINVAL;
		goto out;
	}

	if (!list_empty(&spg->spa_list)) {
		up_write(&sp_group_sem);
		pr_err_ratelimited("spa is not empty");
		ret = -EINVAL;
		goto out;
	}

	ret = get_task(pid, &tsk);
	if (ret) {
		up_write(&sp_group_sem);
		pr_err_ratelimited("task is not found");
		goto out;
	}
	mm = get_task_mm(tsk->group_leader);
	if (!mm) {
		up_write(&sp_group_sem);
		pr_err_ratelimited("mm is not found");
		ret = -ESRCH;
		goto out_put_task;
	}

	spg_node = is_process_in_group(spg, mm);
	if (!spg_node) {
		up_write(&sp_group_sem);
		pr_err_ratelimited("process not in group");
		ret = -ESRCH;
		goto out_put_mm;
	}

	down_write(&spg->rw_lock);
	if (list_is_singular(&spg->procs))
		is_alive = spg->is_alive = false;
	spg->proc_num--;
	list_del(&spg_node->proc_node);
	sp_group_drop(spg);
	up_write(&spg->rw_lock);
	if (!is_alive)
		blocking_notifier_call_chain(&sp_notifier_chain, 0, spg);

	list_del(&spg_node->group_node);
	mm->sp_group_master->count--;
	kfree(spg_node);
	if (atomic_sub_and_test(1, &mm->mm_users)) {
		up_write(&sp_group_sem);
		WARN(1, "Invalid user counting\n");
		return -EINVAL;
	}

	free_spg_proc_stat(mm, spg_id);
	up_write(&sp_group_sem);

out_put_mm:
	mmput(mm);
out_put_task:
	put_task_struct(tsk);
out:
	sp_group_drop(spg); /* if spg dead, freed here */
	return ret;
}
EXPORT_SYMBOL_GPL(mg_sp_group_del_task);

int sp_group_del_task(int pid, int spg_id)
{
	return mg_sp_group_del_task(pid, spg_id);
}
EXPORT_SYMBOL_GPL(sp_group_del_task);

/* the caller must hold sp_area_lock */
static void __insert_sp_area(struct sp_area *spa)
{
	struct rb_node **p = &sp_area_root.rb_node;
	struct rb_node *parent = NULL;

	while (*p) {
		struct sp_area *tmp;

		parent = *p;
		tmp = rb_entry(parent, struct sp_area, rb_node);
		if (spa->va_start < tmp->va_end)
			p = &(*p)->rb_left;
		else if (spa->va_end > tmp->va_start)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	rb_link_node(&spa->rb_node, parent, p);
	rb_insert_color(&spa->rb_node, &sp_area_root);
}

/* The sp_area cache globals are protected by sp_area_lock */
static struct rb_node *free_sp_area_cache;
static unsigned long cached_hole_size;
static unsigned long cached_vstart;  /* affected by SP_DVPP and sp_config_dvpp_range() */

/**
 * sp_alloc_area() - Allocate a region of VA from the share pool.
 * @size: the size of VA to allocate.
 * @flags: how to allocate the memory.
 * @spg: the share group that the memory is allocated to.
 * @type: the type of the region.
 * @applier: the pid of the task which allocates the region.
 *
 * Return: a valid pointer for success, NULL on failure.
 */
static struct sp_area *sp_alloc_area(unsigned long size, unsigned long flags,
				     struct sp_group *spg, enum spa_type type,
				     pid_t applier)
{
	struct sp_area *spa, *first, *err;
	struct rb_node *n;
	unsigned long vstart = MMAP_SHARE_POOL_START;
	unsigned long vend = MMAP_SHARE_POOL_16G_START;
	unsigned long addr;
	unsigned long size_align = PMD_ALIGN(size); /* va aligned to 2M */
	int device_id, node_id;

	device_id = sp_flags_device_id(flags);
	node_id = flags & SP_SPEC_NODE_ID ? sp_flags_node_id(flags) : device_id;

	if (!is_online_node_id(node_id)) {
		pr_err_ratelimited("invalid numa node id %d\n", node_id);
		return ERR_PTR(-EINVAL);
	}

	if ((flags & SP_DVPP)) {
		if (!is_sp_dev_addr_enabled(device_id)) {
			vstart = MMAP_SHARE_POOL_16G_START +
				device_id * MMAP_SHARE_POOL_16G_SIZE;
			vend = vstart + MMAP_SHARE_POOL_16G_SIZE;
		} else {
			vstart = sp_dev_va_start[device_id];
			vend = vstart + sp_dev_va_size[device_id];
		}
	}

	spa = __kmalloc_node(sizeof(struct sp_area), GFP_KERNEL, node_id);
	if (unlikely(!spa))
		return ERR_PTR(-ENOMEM);

	spin_lock(&sp_area_lock);

	/*
	 * Invalidate cache if we have more permissive parameters.
	 * cached_hole_size notes the largest hole noticed _below_
	 * the sp_area cached in free_sp_area_cache: if size fits
	 * into that hole, we want to scan from vstart to reuse
	 * the hole instead of allocating above free_sp_area_cache.
	 * Note that sp_free_area may update free_sp_area_cache
	 * without updating cached_hole_size.
	 */
	if (!free_sp_area_cache || size_align < cached_hole_size ||
	    vstart != cached_vstart) {
		cached_hole_size = 0;
		free_sp_area_cache = NULL;
	}

	/* record if we encounter less permissive parameters */
	cached_vstart = vstart;

	/* find starting point for our search */
	if (free_sp_area_cache) {
		first = rb_entry(free_sp_area_cache, struct sp_area, rb_node);
		addr = first->va_end;
		if (addr + size_align < addr) {
			err = ERR_PTR(-EOVERFLOW);
			goto error;
		}
	} else {
		addr = vstart;
		if (addr + size_align < addr) {
			err = ERR_PTR(-EOVERFLOW);
			goto error;
		}

		n = sp_area_root.rb_node;
		first = NULL;

		while (n) {
			struct sp_area *tmp;
			tmp = rb_entry(n, struct sp_area, rb_node);
			if (tmp->va_end >= addr) {
				first = tmp;
				if (tmp->va_start <= addr)
					break;
				n = n->rb_left;
			} else
				n = n->rb_right;
		}

		if (!first)
			goto found;
	}

	/* from the starting point, traverse areas until a suitable hole is found */
	while (addr + size_align > first->va_start && addr + size_align <= vend) {
		if (addr + cached_hole_size < first->va_start)
			cached_hole_size = first->va_start - addr;
		addr = first->va_end;
		if (addr + size_align < addr) {
			err = ERR_PTR(-EOVERFLOW);
			goto error;
		}

		n = rb_next(&first->rb_node);
		if (n)
			first = rb_entry(n, struct sp_area, rb_node);
		else
			goto found;
	}

found:
	if (addr + size_align > vend) {
		err = ERR_PTR(-EOVERFLOW);
		goto error;
	}

	spa->va_start = addr;
	spa->va_end = addr + size_align;
	spa->real_size = size;
	spa->region_vstart = vstart;
	spa->flags = flags;
	spa->is_hugepage = (flags & SP_HUGEPAGE);
	spa->is_dead = false;
	spa->spg = spg;
	atomic_set(&spa->use_count, 1);
	spa->type = type;
	spa->mm = NULL;
	spa->kva = 0;   /* NULL pointer */
	spa->applier = applier;
	spa->node_id = node_id;
	spa->device_id = device_id;

	spa_inc_usage(spa);
	__insert_sp_area(spa);
	free_sp_area_cache = &spa->rb_node;
	if (spa->spg != spg_none)
		list_add_tail(&spa->link, &spg->spa_list);

	spin_unlock(&sp_area_lock);

	return spa;

error:
	spin_unlock(&sp_area_lock);
	kfree(spa);
	return err;
}

/* the caller should hold sp_area_lock */
static struct sp_area *__find_sp_area_locked(unsigned long addr)
{
	struct rb_node *n = sp_area_root.rb_node;

	while (n) {
		struct sp_area *spa;

		spa = rb_entry(n, struct sp_area, rb_node);
		if (addr < spa->va_start) {
			n = n->rb_left;
		} else if (addr > spa->va_start) {
			n = n->rb_right;
		} else {
			return spa;
		}
	}

	return NULL;
}

static struct sp_area *__find_sp_area(unsigned long addr)
{
	struct sp_area *n;
	spin_lock(&sp_area_lock);
	n = __find_sp_area_locked(addr);
	if (n)
		atomic_inc(&n->use_count);
	spin_unlock(&sp_area_lock);
	return n;
}

static bool vmalloc_area_clr_flag(unsigned long kva, unsigned long flags)
{
	struct vm_struct *area;

	area = find_vm_area((void *)kva);
	if (area) {
		area->flags &= ~flags;
		return true;
	}

	return false;
}

/*
 * Free the VA region starting from addr to the share pool
 */
static void sp_free_area(struct sp_area *spa)
{
	lockdep_assert_held(&sp_area_lock);

	if (free_sp_area_cache) {
		struct sp_area *cache;
		cache = rb_entry(free_sp_area_cache, struct sp_area, rb_node);
		if (spa->va_start <= cache->va_start) {
			free_sp_area_cache = rb_prev(&spa->rb_node);
			/*
			 * the new cache node may be changed to another region,
			 * i.e. from DVPP region to normal region
			 */
			if (free_sp_area_cache) {
				cache = rb_entry(free_sp_area_cache,
						 struct sp_area, rb_node);
				cached_vstart = cache->region_vstart;
			}
			/*
			 * We don't try to update cached_hole_size,
			 * but it won't go very wrong.
			 */
		}
	}

	if (spa->kva) {
		if (!vmalloc_area_clr_flag(spa->kva, VM_SHAREPOOL))
			pr_debug("clear spa->kva %ld is not valid\n", spa->kva);
	}

	spa_dec_usage(spa);
	if (spa->spg != spg_none)
		list_del(&spa->link);

	rb_erase(&spa->rb_node, &sp_area_root);
	RB_CLEAR_NODE(&spa->rb_node);
	kfree(spa);
}

static void __sp_area_drop_locked(struct sp_area *spa)
{
	/*
	 * Considering a situation where task A and B are in the same spg.
	 * A is exiting and calling remove_vma(). Before A calls this func,
	 * B calls sp_free() to free the same spa. So spa maybe NULL when A
	 * calls this func later.
	 */
	if (!spa)
		return;

	if (atomic_dec_and_test(&spa->use_count))
		sp_free_area(spa);
}

static void __sp_area_drop(struct sp_area *spa)
{
	spin_lock(&sp_area_lock);
	__sp_area_drop_locked(spa);
	spin_unlock(&sp_area_lock);
}

void sp_area_drop(struct vm_area_struct *vma)
{
	struct sp_area *spa;

	if (!(vma->vm_flags & VM_SHARE_POOL))
		return;

	/*
	 * Considering a situation where task A and B are in the same spg.
	 * A is exiting and calling remove_vma() -> ... -> sp_area_drop().
	 * Concurrently, B is calling sp_free() to free the same spa.
	 * __find_sp_area_locked() and __sp_area_drop_locked() should be
	 * an atomic operation.
	 */
	spin_lock(&sp_area_lock);
	spa = __find_sp_area_locked(vma->vm_start);
	__sp_area_drop_locked(spa);
	spin_unlock(&sp_area_lock);
}

int sysctl_sp_compact_enable;
unsigned long sysctl_sp_compact_interval = 30UL;
unsigned long sysctl_sp_compact_interval_max = 1000UL;
static unsigned long compact_last_jiffies;
static unsigned long compact_daemon_status;
#define COMPACT_START	1
#define COMPACT_STOP	0

static void sp_compact_nodes(struct work_struct *work)
{
	sysctl_compaction_handler(NULL, 1, NULL, NULL, NULL);

	kfree(work);

	compact_last_jiffies = jiffies;
	cmpxchg(&compact_daemon_status, COMPACT_START, COMPACT_STOP);
}

static void sp_add_work_compact(void)
{
	struct work_struct *compact_work;

	if (!sysctl_sp_compact_enable)
		return;

	/* experimental compaction time: 4GB->1.7s, 8GB->3.4s */
	if (!time_after(jiffies,
		compact_last_jiffies + sysctl_sp_compact_interval * HZ))
		return;

	if (cmpxchg(&compact_daemon_status, COMPACT_STOP, COMPACT_START) ==
		    COMPACT_START)
		return;

	compact_work = kzalloc(sizeof(*compact_work), GFP_KERNEL);
	if (!compact_work)
		return;

	INIT_WORK(compact_work, sp_compact_nodes);
	schedule_work(compact_work);
}

static void sp_try_to_compact(void)
{
	unsigned long totalram;
	unsigned long freeram;

	totalram = totalram_pages;
	freeram = global_zone_page_state(NR_FREE_PAGES);

	/* free < total / 3 */
	if ((freeram + (freeram << 1)) > totalram)
		return;

	sp_add_work_compact();
}

/*
 * The function calls of do_munmap() won't change any non-atomic member
 * of struct sp_group. Please review the following chain:
 * do_munmap -> remove_vma_list -> remove_vma -> sp_area_drop ->
 * __sp_area_drop_locked -> sp_free_area
 */
static void sp_munmap(struct mm_struct *mm, unsigned long addr,
			   unsigned long size)
{
	int err;

	down_write(&mm->mmap_sem);
	if (unlikely(mm->core_state)) {
		up_write(&mm->mmap_sem);
		pr_info("munmap: encoutered coredump\n");
		return;
	}

	err = do_munmap(mm, addr, size, NULL);
	/* we are not supposed to fail */
	if (err)
		pr_err("failed to unmap VA %pK when sp munmap\n", (void *)addr);

	up_write(&mm->mmap_sem);
}

static void __sp_free(struct sp_group *spg, unsigned long addr,
		      unsigned long size, struct mm_struct *stop)
{
	struct mm_struct *mm;
	struct sp_group_node *spg_node = NULL;

	list_for_each_entry(spg_node, &spg->procs, proc_node) {
		mm = spg_node->master->mm;
		if (mm == stop)
			break;
		sp_munmap(mm, addr, size);
	}
}

/* Free the memory of the backing shmem or hugetlbfs */
static void sp_fallocate(struct sp_area *spa)
{
	int ret;
	unsigned long mode = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;
	unsigned long offset = addr_offset(spa);

	ret = vfs_fallocate(spa_file(spa), mode, offset, spa_size(spa));
	if (ret)
		WARN(1, "sp fallocate failed %d\n", ret);
}

static void sp_free_unmap_fallocate(struct sp_area *spa)
{
	if (spa->spg != spg_none) {
		down_read(&spa->spg->rw_lock);
		__sp_free(spa->spg, spa->va_start, spa_size(spa), NULL);
		sp_fallocate(spa);
		up_read(&spa->spg->rw_lock);
	} else {
		sp_munmap(current->mm, spa->va_start, spa_size(spa));
		sp_fallocate(spa);
	}
}

static int sp_check_caller_permission(struct sp_group *spg, struct mm_struct *mm)
{
	int ret = 0;

	down_read(&spg->rw_lock);
	if (!is_process_in_group(spg, mm))
		ret = -EPERM;
	up_read(&spg->rw_lock);
	return ret;
}


#define FREE_CONT	1
#define FREE_END	2

struct sp_free_context {
	unsigned long addr;
	struct sp_area *spa;
	int state;
};

/* when success, __sp_area_drop(spa) should be used */
static int sp_free_get_spa(struct sp_free_context *fc)
{
	int ret = 0;
	unsigned long addr = fc->addr;
	struct sp_area *spa;

	fc->state = FREE_CONT;

	spa = __find_sp_area(addr);
	if (!spa) {
		pr_debug("sp free invalid input addr %lx\n", addr);
		return -EINVAL;
	}

	if (spa->type != SPA_TYPE_ALLOC) {
		ret = -EINVAL;
		pr_debug("sp free failed, %lx is not sp alloc addr\n", addr);
		goto drop_spa;
	}
	fc->spa = spa;

	if (spa->spg != spg_none) {
		/*
		 * Access control: an sp addr can only be freed by
		 * 1. another task in the same spg
		 * 2. a kthread
		 *
		 * a passthrough addr can only be freed by the applier process
		 */
		if (!current->mm)
			goto check_spa;

		ret = sp_check_caller_permission(spa->spg, current->mm);
		if (ret < 0)
			goto drop_spa;

check_spa:
		down_write(&spa->spg->rw_lock);
		if (!spg_valid(spa->spg)) {
			fc->state = FREE_END;
			up_write(&spa->spg->rw_lock);
			goto drop_spa;
			/* we must return success(0) in this situation */
		}
		/* the life cycle of spa has a direct relation with sp group */
		if (unlikely(spa->is_dead)) {
			up_write(&spa->spg->rw_lock);
			pr_err_ratelimited("unexpected double sp free\n");
			dump_stack();
			ret = -EINVAL;
			goto drop_spa;
		}
		spa->is_dead = true;
		up_write(&spa->spg->rw_lock);

	} else {
		if (current->tgid != spa->applier) {
			ret = -EPERM;
			goto drop_spa;
		}
	}
	return 0;

drop_spa:
	__sp_area_drop(spa);
	return ret;
}

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
	int ret = 0;
	struct sp_free_context fc = {
		.addr = addr,
	};

	check_interrupt_context();

	ret = sp_free_get_spa(&fc);
	if (ret || fc.state == FREE_END)
		goto out;

	sp_free_unmap_fallocate(fc.spa);

	/* current->mm == NULL: allow kthread */
	if (current->mm == NULL)
		atomic64_sub(fc.spa->real_size, &kthread_stat.alloc_size);
	else
		sp_update_process_stat(current, false, fc.spa);

	__sp_area_drop(fc.spa);  /* match __find_sp_area in sp_free_get_spa */
out:
	sp_dump_stack();
	sp_try_to_compact();
	return ret;
}
EXPORT_SYMBOL_GPL(sp_free);

int mg_sp_free(unsigned long addr)
{
	return sp_free(addr);
}
EXPORT_SYMBOL_GPL(mg_sp_free);

/* wrapper of __do_mmap() and the caller must hold down_write(&mm->mmap_sem). */
static unsigned long sp_mmap(struct mm_struct *mm, struct file *file,
			     struct sp_area *spa, unsigned long *populate,
			     unsigned long prot)
{
	unsigned long addr = spa->va_start;
	unsigned long size = spa_size(spa);
	unsigned long flags = MAP_FIXED | MAP_SHARED | MAP_POPULATE |
			      MAP_SHARE_POOL;
	unsigned long vm_flags = VM_NORESERVE | VM_SHARE_POOL | VM_DONTCOPY;
	unsigned long pgoff = addr_offset(spa) >> PAGE_SHIFT;

	/* Mark the mapped region to be locked. After the MAP_LOCKED is enable,
	 * multiple tasks will preempt resources, causing performance loss.
	 */
	if (sysctl_share_pool_map_lock_enable)
		flags |= MAP_LOCKED;

	atomic_inc(&spa->use_count);
	addr = __do_mmap(mm, file, addr, size, prot, flags, vm_flags, pgoff,
			 populate, NULL);
	if (IS_ERR_VALUE(addr)) {
		atomic_dec(&spa->use_count);
		pr_err("do_mmap fails %ld\n", addr);
	} else {
		BUG_ON(addr != spa->va_start);
	}

	return addr;
}

#define ALLOC_NORMAL	1
#define ALLOC_RETRY	2
#define ALLOC_NOMEM	3
#define ALLOC_COREDUMP	4

struct sp_alloc_context {
	struct sp_group *spg;
	struct file *file;
	unsigned long size;
	unsigned long size_aligned;
	unsigned long sp_flags;
	unsigned long populate;
	int state;
	bool need_fallocate;
	struct timespec64 start;
	struct timespec64 end;
	bool have_mbind;
};

static void trace_sp_alloc_begin(struct sp_alloc_context *ac)
{
	if (!sysctl_sp_perf_alloc)
		return;

	ktime_get_ts64(&ac->start);
}

static void trace_sp_alloc_finish(struct sp_alloc_context *ac, unsigned long va)
{
	unsigned long cost;
	bool is_pass_through = ac->spg == spg_none ? true : false;

	if (!sysctl_sp_perf_alloc)
		return;

	ktime_get_ts64(&ac->end);

	cost = SEC2US(ac->end.tv_sec - ac->start.tv_sec) +
		NS2US(ac->end.tv_nsec - ac->start.tv_nsec);
	if (cost >= (unsigned long)sysctl_sp_perf_alloc) {
		pr_err("Task %s(%d/%d) sp_alloc returns 0x%lx consumes %luus, size is %luKB, "
		       "size_aligned is %luKB, sp_flags is %lx, pass through is %d\n",
		       current->comm, current->tgid, current->pid,
		       va, cost, byte2kb(ac->size), byte2kb(ac->size_aligned), ac->sp_flags, is_pass_through);
	}
}

static int sp_alloc_prepare(unsigned long size, unsigned long sp_flags,
	int spg_id, struct sp_alloc_context *ac)
{
	struct sp_group *spg;

	check_interrupt_context();

	trace_sp_alloc_begin(ac);

	/* mdc scene hack */
	if (enable_mdc_default_group)
		spg_id = mdc_default_group_id;

	if (unlikely(!size || (size >> PAGE_SHIFT) > totalram_pages)) {
		pr_err_ratelimited("allocation failed, invalid size %lu\n", size);
		return -EINVAL;
	}

	if (spg_id != SPG_ID_DEFAULT && spg_id < SPG_ID_MIN) {
		pr_err_ratelimited("allocation failed, invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	if (sp_flags & (~SP_FLAG_MASK)) {
		pr_err_ratelimited("allocation failed, invalid flag %lx\n", sp_flags);
		return -EINVAL;
	}

	if (sp_flags & SP_HUGEPAGE_ONLY)
		sp_flags |= SP_HUGEPAGE;

	if (share_pool_group_mode == SINGLE_GROUP_MODE) {
		spg = __sp_find_spg(current->pid, SPG_ID_DEFAULT);
		if (spg) {
			if (spg_id != SPG_ID_DEFAULT && spg->id != spg_id) {
				sp_group_drop(spg);
				return -ENODEV;
			}

			/* up_read will be at the end of sp_alloc */
			down_read(&spg->rw_lock);
			if (!spg_valid(spg)) {
				up_read(&spg->rw_lock);
				sp_group_drop(spg);
				pr_err_ratelimited("allocation failed, spg is dead\n");
				return -ENODEV;
			}
		} else {  /* alocation pass through scene */
			if (enable_mdc_default_group) {
				int ret = 0;

				ret = sp_group_add_task(current->tgid, spg_id);
				if (ret < 0) {
					pr_err_ratelimited("add group failed in pass through\n");
					return ret;
				}

				spg = __sp_find_spg(current->pid, SPG_ID_DEFAULT);

				/* up_read will be at the end of sp_alloc */
				down_read(&spg->rw_lock);
				if (!spg_valid(spg)) {
					up_read(&spg->rw_lock);
					sp_group_drop(spg);
					pr_err_ratelimited("pass through allocation failed, spg is dead\n");
					return -ENODEV;
				}
			} else {
				spg = spg_none;
			}
		}
	} else {
		if (spg_id != SPG_ID_DEFAULT) {
			spg = __sp_find_spg(current->pid, spg_id);
			if (!spg) {
				pr_err_ratelimited("allocation failed, can't find group\n");
				return -ENODEV;
			}

			/* up_read will be at the end of sp_alloc */
			down_read(&spg->rw_lock);
			if (!spg_valid(spg)) {
				up_read(&spg->rw_lock);
				sp_group_drop(spg);
				pr_err_ratelimited("allocation failed, spg is dead\n");
				return -ENODEV;
			}

			if (!is_process_in_group(spg, current->mm)) {
				up_read(&spg->rw_lock);
				sp_group_drop(spg);
				pr_err_ratelimited("allocation failed, task not in group\n");
				return -ENODEV;
			}
		} else {  /* alocation pass through scene */
			spg = spg_none;
		}
	}

	if (sp_flags & SP_HUGEPAGE) {
		ac->file = spg->file_hugetlb;
		ac->size_aligned = ALIGN(size, PMD_SIZE);
	} else {
		ac->file = spg->file;
		ac->size_aligned = ALIGN(size, PAGE_SIZE);
	}

	ac->spg = spg;
	ac->size = size;
	ac->sp_flags = sp_flags;
	ac->state = ALLOC_NORMAL;
	ac->need_fallocate = false;
	ac->have_mbind = false;
	return 0;
}

static void sp_alloc_unmap(struct mm_struct *mm, struct sp_area *spa,
	struct sp_group_node *spg_node)
{
	if (spa->spg != spg_none)
		__sp_free(spa->spg, spa->va_start, spa->real_size, mm);
}

static int sp_alloc_mmap(struct mm_struct *mm, struct sp_area *spa,
	struct sp_group_node *spg_node, struct sp_alloc_context *ac)
{
	int ret = 0;
	unsigned long mmap_addr;
	/* pass through default permission */
	unsigned long prot = PROT_READ | PROT_WRITE;
	unsigned long sp_addr = spa->va_start;
	unsigned long populate = 0;
	struct vm_area_struct *vma;

	down_write(&mm->mmap_sem);
	if (unlikely(mm->core_state)) {
		up_write(&mm->mmap_sem);
		ac->state = ALLOC_COREDUMP;
		pr_info("allocation encountered coredump\n");
		return -EFAULT;
	}

	if (spg_node)
		prot = spg_node->prot;

	/* when success, mmap_addr == spa->va_start */
	mmap_addr = sp_mmap(mm, spa_file(spa), spa, &populate, prot);
	if (IS_ERR_VALUE(mmap_addr)) {
		up_write(&mm->mmap_sem);
		sp_alloc_unmap(mm, spa, spg_node);
		pr_err("sp mmap in allocation failed %ld\n", mmap_addr);
		return PTR_ERR((void *)mmap_addr);
	}

	if (unlikely(populate == 0)) {
		up_write(&mm->mmap_sem);
		pr_err("allocation sp mmap populate failed\n");
		ret = -EFAULT;
		goto unmap;
	}
	ac->populate = populate;

	vma = find_vma(mm, sp_addr);
	if (unlikely(!vma)) {
		up_write(&mm->mmap_sem);
		WARN(1, "allocation failed, can't find %lx vma\n", sp_addr);
		ret = -EINVAL;
		goto unmap;
	}
	/* clean PTE_RDONLY flags or trigger SMMU event */
	if (prot & PROT_WRITE)
		vma->vm_page_prot = __pgprot(((~PTE_RDONLY) & vma->vm_page_prot.pgprot) | PTE_DIRTY);
	up_write(&mm->mmap_sem);

	return ret;

unmap:
	if (spa->spg != spg_none)
		sp_alloc_unmap(list_next_entry(spg_node, proc_node)->master->mm, spa, spg_node);
	else
		sp_munmap(mm, spa->va_start, spa->real_size);
	return ret;
}

static void sp_alloc_fallback(struct sp_area *spa, struct sp_alloc_context *ac)
{
	struct sp_spg_stat *stat = ac->spg->stat;

	if (ac->file == ac->spg->file) {
		ac->state = ALLOC_NOMEM;
		return;
	}

	atomic_inc(&stat->hugepage_failures);
	if (!(ac->sp_flags & SP_HUGEPAGE_ONLY)) {
		ac->file = ac->spg->file;
		ac->size_aligned = ALIGN(ac->size, PAGE_SIZE);
		ac->sp_flags &= ~SP_HUGEPAGE;
		ac->state = ALLOC_RETRY;
		__sp_area_drop(spa);
		return;
	}
	ac->state = ALLOC_NOMEM;
}

static int sp_alloc_populate(struct mm_struct *mm, struct sp_area *spa,
			     struct sp_alloc_context *ac)
{
	int ret = 0;
	unsigned long sp_addr = spa->va_start;
	unsigned int noreclaim_flag = 0;

	/*
	 * The direct reclaim and compact may take a long
	 * time. As a result, sp mutex will be hold for too
	 * long time to casue the hung task problem. In this
	 * case, set the PF_MEMALLOC flag to prevent the
	 * direct reclaim and compact from being executed.
	 * Since direct reclaim and compact are not performed
	 * when the fragmentation is severe or the memory is
	 * insufficient, 2MB continuous physical pages fail
	 * to be allocated. This situation is allowed.
	 */
	if (spa->is_hugepage)
		noreclaim_flag = memalloc_noreclaim_save();

	/*
	 * We are not ignoring errors, so if we fail to allocate
	 * physical memory we just return failure, so we won't encounter
	 * page fault later on, and more importantly sp_make_share_u2k()
	 * depends on this feature (and MAP_LOCKED) to work correctly.
	 */
	ret = do_mm_populate(mm, sp_addr, ac->populate, 0);
	if (spa->is_hugepage) {
		memalloc_noreclaim_restore(noreclaim_flag);
		if (ret)
			sp_add_work_compact();
	}
	return ret;
}

static long sp_mbind(struct mm_struct *mm, unsigned long start, unsigned long len, unsigned long node)
{
	nodemask_t nmask;

	nodes_clear(nmask);
	node_set(node, nmask);
	return __do_mbind(start, len, MPOL_BIND, MPOL_F_STATIC_NODES,
			&nmask, MPOL_MF_STRICT, mm);
}

static int __sp_alloc_mmap_populate(struct mm_struct *mm, struct sp_area *spa,
	struct sp_group_node *spg_node, struct sp_alloc_context *ac)
{
	int ret;

	ret = sp_alloc_mmap(mm, spa, spg_node, ac);
	if (ret < 0) {
		if (ac->need_fallocate) {
			/* e.g. second sp_mmap fail */
			sp_fallocate(spa);
			ac->need_fallocate = false;
		}
		return ret;
	}

	if (!ac->have_mbind) {
		ret = sp_mbind(mm, spa->va_start, spa->real_size, spa->node_id);
		if (ret < 0) {
			pr_err("cannot bind the memory range to specified node:%d, err:%d\n",
				spa->node_id, ret);
			goto err;
		}
		ac->have_mbind = true;
	}

	ret = sp_alloc_populate(mm, spa, ac);
	if (ret) {
err:
		if (spa->spg != spg_none)
			sp_alloc_unmap(list_next_entry(spg_node, proc_node)->master->mm, spa, spg_node);
		else
			sp_munmap(mm, spa->va_start, spa->real_size);

		if (unlikely(fatal_signal_pending(current)))
			pr_warn_ratelimited("allocation failed, current thread is killed\n");
		else
			pr_warn_ratelimited("allocation failed due to mm populate failed(potential no enough memory when -12): %d\n",
					    ret);
		sp_fallocate(spa);  /* need this, otherwise memleak */
		sp_alloc_fallback(spa, ac);
	} else
		ac->need_fallocate = true;

	return ret;
}

static int sp_alloc_mmap_populate(struct sp_area *spa,
				  struct sp_alloc_context *ac)
{
	int ret = -EINVAL;
	int mmap_ret = 0;
	struct mm_struct *mm;
	struct sp_group_node *spg_node;

	if (spa->spg == spg_none) {
		ret = __sp_alloc_mmap_populate(current->mm, spa, NULL, ac);
	} else {
		/* create mapping for each process in the group */
		list_for_each_entry(spg_node, &spa->spg->procs, proc_node) {
			mm = spg_node->master->mm;
			mmap_ret = __sp_alloc_mmap_populate(mm, spa, spg_node, ac);
			if (mmap_ret) {
				if (ac->state != ALLOC_COREDUMP)
					return mmap_ret;
				ac->state = ALLOC_NORMAL;
				continue;
			}
			ret = mmap_ret;
		}
	}
	return ret;
}

/* spa maybe an error pointer, so introduce variable spg */
static void sp_alloc_finish(int result, struct sp_area *spa,
	struct sp_alloc_context *ac)
{
	struct sp_group *spg = ac->spg;
	bool is_pass_through = spg == spg_none ? true : false;

	/* match sp_alloc_check_prepare */
	if (!is_pass_through)
		up_read(&spg->rw_lock);

	if (!result)
		sp_update_process_stat(current, true, spa);

	/* this will free spa if mmap failed */
	if (spa && !IS_ERR(spa)) {
		__sp_area_drop(spa);
		trace_sp_alloc_finish(ac, spa->va_start);
	}

	if (!is_pass_through)
		sp_group_drop(spg);

	sp_dump_stack();
	sp_try_to_compact();
}

/**
 * sp_alloc() - Allocate shared memory for all the processes in a sp_group.
 * @size: the size of memory to allocate.
 * @sp_flags: how to allocate the memory.
 * @spg_id: the share group that the memory is allocated to.
 *
 * Use pass through allocation if spg_id == SPG_ID_DEFAULT in multi-group mode.
 *
 * Return:
 * * if succeed, return the starting kernel address of the shared memory.
 * * if fail, return the pointer of -errno.
 */
void *sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id)
{
	struct sp_area *spa = NULL;
	int ret = 0;
	struct sp_alloc_context ac;

	ret = sp_alloc_prepare(size, sp_flags, spg_id, &ac);
	if (ret)
		return ERR_PTR(ret);

try_again:
	spa = sp_alloc_area(ac.size_aligned, ac.sp_flags, ac.spg,
			    SPA_TYPE_ALLOC, current->tgid);
	if (IS_ERR(spa)) {
		pr_err_ratelimited("alloc spa failed in allocation"
			"(potential no enough virtual memory when -75): %ld\n", PTR_ERR(spa));
		ret = PTR_ERR(spa);
		goto out;
	}

	ret = sp_alloc_mmap_populate(spa, &ac);
	if (ret && ac.state == ALLOC_RETRY)
		goto try_again;

out:
	sp_alloc_finish(ret, spa, &ac);
	if (ret)
		return ERR_PTR(ret);
	else
		return (void *)(spa->va_start);
}
EXPORT_SYMBOL_GPL(sp_alloc);

void *mg_sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id)
{
	return sp_alloc(size, sp_flags, spg_id);
}
EXPORT_SYMBOL_GPL(mg_sp_alloc);

/**
 * is_vmap_hugepage() - Check if a kernel address belongs to vmalloc family.
 * @addr: the kernel space address to be checked.
 *
 * Return:
 * * >0		- a vmalloc hugepage addr.
 * * =0		- a normal vmalloc addr.
 * * -errno	- failure.
 */
static int is_vmap_hugepage(unsigned long addr)
{
	struct vm_struct *area;

	if (unlikely(!addr)) {
		pr_err_ratelimited("null vmap addr pointer\n");
		return -EINVAL;
	}

	area = find_vm_area((void *)addr);
	if (unlikely(!area)) {
		pr_debug("can't find vm area(%lx)\n", addr);
		return -EINVAL;
	}

	if (area->flags & VM_HUGE_PAGES)
		return 1;
	else
		return 0;
}

static unsigned long __sp_remap_get_pfn(unsigned long kva)
{
	unsigned long pfn;
	if (is_vmalloc_addr((void *)kva))
		pfn = vmalloc_to_pfn((void *)kva);
	else
		pfn = virt_to_pfn(kva);

	return pfn;
}

/* when called by k2u to group, always make sure rw_lock of spg is down */
static unsigned long sp_remap_kva_to_vma(unsigned long kva, struct sp_area *spa,
					 struct mm_struct *mm, unsigned long prot, struct sp_k2u_context *kc)
{
	struct vm_area_struct *vma;
	unsigned long ret_addr;
	unsigned long populate = 0;
	int ret = 0;
	unsigned long addr, buf, offset;

	down_write(&mm->mmap_sem);
	if (unlikely(mm->core_state)) {
		pr_err("k2u mmap: encountered coredump, abort\n");
		ret_addr = -EBUSY;
		if (kc)
			kc->state = K2U_COREDUMP;
		goto put_mm;
	}

	ret_addr = sp_mmap(mm, spa_file(spa), spa, &populate, prot);
	if (IS_ERR_VALUE(ret_addr)) {
		pr_debug("k2u mmap failed %lx\n", ret_addr);
		goto put_mm;
	}
	BUG_ON(ret_addr != spa->va_start);

	vma = find_vma(mm, ret_addr);
	BUG_ON(vma == NULL);
	if (prot & PROT_WRITE)
		vma->vm_page_prot = __pgprot(((~PTE_RDONLY) & vma->vm_page_prot.pgprot) | PTE_DIRTY);

	if (is_vm_hugetlb_page(vma)) {
		ret = remap_vmalloc_hugepage_range(vma, (void *)kva, 0);
		if (ret) {
			do_munmap(mm, ret_addr, spa_size(spa), NULL);
			pr_debug("remap vmalloc hugepage failed, "
				 "ret %d, kva is %lx\n", ret, (unsigned long)kva);
			ret_addr = ret;
			goto put_mm;
		}
		vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	} else {
		buf = ret_addr;
		addr = kva;
		offset = 0;
		do {
			ret = remap_pfn_range(vma, buf, __sp_remap_get_pfn(addr), PAGE_SIZE,
					__pgprot(vma->vm_page_prot.pgprot));
			if (ret) {
				do_munmap(mm, ret_addr, spa_size(spa), NULL);
				pr_err("remap_pfn_range failed %d\n", ret);
				ret_addr = ret;
				goto put_mm;
			}
			offset += PAGE_SIZE;
			buf += PAGE_SIZE;
			addr += PAGE_SIZE;
		} while (offset < spa_size(spa));
	}

put_mm:
	up_write(&mm->mmap_sem);

	return ret_addr;
}

/**
 * sp_make_share_kva_to_task() - Share kernel memory to current task.
 * @kva: the VA of shared kernel memory
 * @size: the size of area to share, should be aligned properly
 * @sp_flags: the flags for the opreation
 *
 * Return:
 * * if succeed, return the shared user address to start at.
 * * if fail, return the pointer of -errno.
 */
static void *sp_make_share_kva_to_task(unsigned long kva, unsigned long size, unsigned long sp_flags)
{
	void *uva;
	struct sp_area *spa;
	struct spg_proc_stat *stat;
	unsigned long prot = PROT_READ | PROT_WRITE;

	down_write(&sp_group_sem);
	stat = sp_init_process_stat(current, current->mm, spg_none);
	up_write(&sp_group_sem);
	if (IS_ERR(stat)) {
		pr_err_ratelimited("k2u_task init process stat failed %lx\n",
				PTR_ERR(stat));
		return stat;
	}

	spa = sp_alloc_area(size, sp_flags, spg_none, SPA_TYPE_K2TASK, current->tgid);
	if (IS_ERR(spa)) {
		pr_err_ratelimited("alloc spa failed in k2u_task "
				"(potential no enough virtual memory when -75): %ld\n", PTR_ERR(spa));
		return spa;
	}

	spa->kva = kva;

	uva = (void *)sp_remap_kva_to_vma(kva, spa, current->mm, prot, NULL);
	__sp_area_drop(spa);
	if (IS_ERR(uva))
		pr_err("remap k2u to task failed %ld\n", PTR_ERR(uva));
	else {
		update_spg_proc_stat(size, true, stat, SPA_TYPE_K2TASK);
		spa->mm = current->mm;
	}

	return uva;
}

/**
 * Share kernel memory to a spg, the current process must be in that group
 * @kva: the VA of shared kernel memory
 * @size: the size of area to share, should be aligned properly
 * @sp_flags: the flags for the opreation
 * @spg: the sp group to be shared with
 *
 * Return: the shared user address to start at
 */
static void *sp_make_share_kva_to_spg(unsigned long kva, unsigned long size,
				      unsigned long sp_flags, struct sp_group *spg)
{
	struct sp_area *spa;
	struct mm_struct *mm;
	struct sp_group_node *spg_node;
	void *uva = ERR_PTR(-ENODEV);
	struct sp_k2u_context kc;
	unsigned long ret_addr = -ENODEV;

	down_read(&spg->rw_lock);
	spa = sp_alloc_area(size, sp_flags, spg, SPA_TYPE_K2SPG, current->tgid);
	if (IS_ERR(spa)) {
		up_read(&spg->rw_lock);
		pr_err_ratelimited("alloc spa failed in k2u_spg "
				"(potential no enough virtual memory when -75): %ld\n", PTR_ERR(spa));
		return spa;
	}

	spa->kva = kva;

	list_for_each_entry(spg_node, &spg->procs, proc_node) {
		mm = spg_node->master->mm;
		kc.state = K2U_NORMAL;
		ret_addr = sp_remap_kva_to_vma(kva, spa, mm, spg_node->prot, &kc);
		if (IS_ERR_VALUE(ret_addr)) {
			if (kc.state == K2U_COREDUMP)
				continue;
			uva = (void *)ret_addr;
			pr_err("remap k2u to spg failed %ld\n", PTR_ERR(uva));
			__sp_free(spg, spa->va_start, spa_size(spa), mm);
			goto out;
		}
		uva = (void *)ret_addr;
	}

out:
	up_read(&spg->rw_lock);
	__sp_area_drop(spa);
	if (!IS_ERR(uva))
		sp_update_process_stat(current, true, spa);

	return uva;
}

static bool vmalloc_area_set_flag(unsigned long kva, unsigned long flags)
{
	struct vm_struct *area;

	area = find_vm_area((void *)kva);
	if (area) {
		area->flags |= flags;
		return true;
	}

	return false;
}

static void trace_sp_k2u_begin(struct sp_k2u_context *kc)
{
	if (!sysctl_sp_perf_k2u)
		return;

	ktime_get_ts64(&kc->start);
}

static void trace_sp_k2u_finish(struct sp_k2u_context *kc, void *uva)
{
	unsigned long cost;

	if (!sysctl_sp_perf_k2u)
		return;

	ktime_get_ts64(&kc->end);

	cost = SEC2US(kc->end.tv_sec - kc->start.tv_sec) +
		NS2US(kc->end.tv_nsec - kc->start.tv_nsec);
	if (cost >= (unsigned long)sysctl_sp_perf_k2u) {
		pr_err("Task %s(%d/%d) sp_k2u returns 0x%lx consumes %luus, size is %luKB, size_aligned is %luKB, "
		       "sp_flags is %lx, to_task is %d\n",
		       current->comm, current->tgid, current->pid,
		       (unsigned long)uva, cost, byte2kb(kc->size), byte2kb(kc->size_aligned),
		       kc->sp_flags, kc->to_task);
	}
}
static int sp_k2u_prepare(unsigned long kva, unsigned long size,
	unsigned long sp_flags, int spg_id, struct sp_k2u_context *kc)
{
	int is_hugepage;
	unsigned int page_size = PAGE_SIZE;
	unsigned long kva_aligned, size_aligned;

	trace_sp_k2u_begin(kc);

	if (sp_flags & ~SP_FLAG_MASK) {
		pr_err_ratelimited("k2u sp_flags %lx error\n", sp_flags);
		return -EINVAL;
	}
	sp_flags &= ~SP_HUGEPAGE;

	if (!current->mm) {
		pr_err_ratelimited("k2u: kthread is not allowed\n");
		return -EPERM;
	}

	is_hugepage = is_vmap_hugepage(kva);
	if (is_hugepage > 0) {
		sp_flags |= SP_HUGEPAGE;
		page_size = PMD_SIZE;
	} else if (is_hugepage == 0) {
		/* do nothing */
	} else {
		pr_err_ratelimited("k2u kva is not vmalloc address\n");
		return is_hugepage;
	}

	/* aligned down kva is convenient for caller to start with any valid kva */
	kva_aligned = ALIGN_DOWN(kva, page_size);
	size_aligned = ALIGN(kva + size, page_size) - kva_aligned;

	if (!vmalloc_area_set_flag(kva_aligned, VM_SHAREPOOL)) {
		pr_debug("k2u_task kva %lx is not valid\n", kva_aligned);
		return -EINVAL;
	}

	kc->kva = kva;
	kc->kva_aligned = kva_aligned;
	kc->size = size;
	kc->size_aligned = size_aligned;
	kc->sp_flags = sp_flags;
	kc->spg_id = spg_id;
	kc->to_task = false;
	return 0;
}

static int sp_check_k2task(struct sp_k2u_context *kc)
{
	int ret = 0;
	int spg_id = kc->spg_id;

	if (share_pool_group_mode == SINGLE_GROUP_MODE) {
		struct sp_group *spg = get_first_group(current->mm);

		if (!spg) {
			if (spg_id != SPG_ID_NONE && spg_id != SPG_ID_DEFAULT)
				ret = -EINVAL;
			else
				kc->to_task = true;
		} else {
			if (spg_id != SPG_ID_DEFAULT && spg_id != spg->id)
				ret = -EINVAL;
			sp_group_drop(spg);
		}
	} else {
		if (spg_id == SPG_ID_DEFAULT || spg_id == SPG_ID_NONE)
			kc->to_task = true;
	}
	return ret;
}

static void *sp_k2u_finish(void *uva, struct sp_k2u_context *kc)
{
	if (IS_ERR(uva))
		vmalloc_area_clr_flag(kc->kva_aligned, VM_SHAREPOOL);
	else
		uva = uva + (kc->kva - kc->kva_aligned);

	trace_sp_k2u_finish(kc, uva);
	sp_dump_stack();
	return uva;
}

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
	void *uva;
	int ret;
	struct sp_k2u_context kc;

	check_interrupt_context();

	ret = sp_k2u_prepare(kva, size, sp_flags, spg_id, &kc);
	if (ret)
		return ERR_PTR(ret);

	ret = sp_check_k2task(&kc);
	if (ret) {
		uva = ERR_PTR(ret);
		goto out;
	}

	if (kc.to_task)
		uva = sp_make_share_kva_to_task(kc.kva_aligned, kc.size_aligned, kc.sp_flags);
	else {
		struct sp_group *spg;

		spg = __sp_find_spg(current->pid, kc.spg_id);
		if (spg) {
			ret = sp_check_caller_permission(spg, current->mm);
			if (ret < 0) {
				sp_group_drop(spg);
				uva = ERR_PTR(ret);
				goto out;
			}
			uva = sp_make_share_kva_to_spg(kc.kva_aligned, kc.size_aligned, kc.sp_flags, spg);
			sp_group_drop(spg);
		} else
			uva = ERR_PTR(-ENODEV);
	}

out:
	return sp_k2u_finish(uva, &kc);
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
	spinlock_t *ptl;

retry:
	pte = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);

	if (unlikely(!pte_present(*pte))) {
		swp_entry_t entry;

		if (pte_none(*pte))
			goto no_page;
		entry = pte_to_swp_entry(*pte);
		if (!is_migration_entry(entry))
			goto no_page;
		pte_unmap_unlock(pte, ptl);
		migration_entry_wait(walk->mm, pmd, addr);
		goto retry;
	}

	page = pte_page(*pte);
	get_page(page);
	pte_unmap_unlock(pte, ptl);
	sp_walk_data->pages[sp_walk_data->page_count++] = page;
	return 0;

no_page:
	pte_unmap_unlock(pte, ptl);
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
		       struct mm_walk *walk)
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

/**
 * __sp_walk_page_range() - Walk page table with caller specific callbacks.
 * @uva: the start VA of user memory.
 * @size: the size of user memory.
 * @mm: mm struct of the target task.
 * @sp_walk_data: a structure of a page pointer array.
 *
 * the caller must hold mm->mmap_sem
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
	struct mm_walk sp_walk = {};

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
	if ((is_vm_hugetlb_page(vma)) || is_vm_huge_special(vma))
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

	sp_walk.mm = mm;
	sp_walk.private = sp_walk_data;

	ret = walk_page_range(uva_aligned, uva_aligned + size_aligned,
			      &sp_walk);
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
	int ret = 0;
	struct mm_struct *mm = current->mm;
	void *p = ERR_PTR(-ESRCH);
	struct sp_walk_data sp_walk_data = {
		.page_count = 0,
	};
	struct vm_struct *area;

	check_interrupt_context();

	if (mm == NULL) {
		pr_err("u2k: kthread is not allowed\n");
		return ERR_PTR(-EPERM);
	}

	down_write(&mm->mmap_sem);
	if (unlikely(mm->core_state)) {
		up_write(&mm->mmap_sem);
		pr_err("u2k: encountered coredump, abort\n");
		return p;
	}

	ret = __sp_walk_page_range(uva, size, mm, &sp_walk_data);
	if (ret) {
		pr_err_ratelimited("walk page range failed %d\n", ret);
		up_write(&mm->mmap_sem);
		return ERR_PTR(ret);
	}

	if (sp_walk_data.is_hugepage)
		p = vmap_hugepage(sp_walk_data.pages, sp_walk_data.page_count,
				  VM_MAP | VM_HUGE_PAGES, PAGE_KERNEL);
	else
		p = vmap(sp_walk_data.pages, sp_walk_data.page_count, VM_MAP,
			 PAGE_KERNEL);
	up_write(&mm->mmap_sem);

	if (!p) {
		pr_err("vmap(huge) in u2k failed\n");
		__sp_walk_page_free(&sp_walk_data);
		return ERR_PTR(-ENOMEM);
	}

	p = p + (uva - sp_walk_data.uva_aligned);

	/*
	 * kva p may be used later in k2u. Since p comes from uva originally,
	 * it's reasonable to add flag VM_USERMAP so that p can be remapped
	 * into userspace again.
	 */
	area = find_vm_area(p);
	area->flags |= VM_USERMAP;

	kvfree(sp_walk_data.pages);
	return p;
}
EXPORT_SYMBOL_GPL(sp_make_share_u2k);

void *mg_sp_make_share_u2k(unsigned long uva, unsigned long size, int pid)
{
	return sp_make_share_u2k(uva, size, pid);
}
EXPORT_SYMBOL_GPL(mg_sp_make_share_u2k);

/*
 * Input parameters uva, pid and spg_id are now useless. spg_id will be useful
 * when supporting a process in multiple sp groups.
 *
 * Procedure of unshare uva must be compatible with:
 *
 * 1. Process A once was the target of k2u(to group), then it exits.
 * Guard worker kthread tries to free this uva and it must succeed, otherwise
 * spa of this uva leaks.
 *
 * This also means we must trust guard worker code.
 */
static int sp_unshare_uva(unsigned long uva, unsigned long size)
{
	int ret = 0;
	struct mm_struct *mm;
	struct sp_area *spa;
	unsigned long uva_aligned;
	unsigned long size_aligned;
	unsigned int page_size;

	/*
	 * at first we guess it's a hugepage addr
	 * we can tolerate at most PMD_SIZE or PAGE_SIZE which is matched in k2u
	 */
	spa = __find_sp_area(ALIGN_DOWN(uva, PMD_SIZE));
	if (!spa) {
		spa = __find_sp_area(ALIGN_DOWN(uva, PAGE_SIZE));
		if (!spa) {
			ret = -EINVAL;
			pr_debug("invalid input uva %lx in unshare uva\n", (unsigned long)uva);
			goto out;
		}
	}

	if (spa->type != SPA_TYPE_K2TASK && spa->type != SPA_TYPE_K2SPG) {
		pr_err_ratelimited("unshare wrong type spa\n");
		ret = -EINVAL;
		goto out_drop_area;
	}
	/*
	 * 1. overflow actually won't happen due to an spa must be valid.
	 * 2. we must unshare [spa->va_start, spa->va_start + spa->real_size) completely
	 *    because an spa is one-to-one correspondence with an vma.
	 *    Thus input paramter size is not necessarily needed.
	 */
	page_size = (spa->is_hugepage ? PMD_SIZE : PAGE_SIZE);
	uva_aligned = spa->va_start;
	size_aligned = spa->real_size;

	if (size_aligned < ALIGN(size, page_size)) {
		ret = -EINVAL;
		pr_err_ratelimited("unshare uva failed, invalid parameter size %lu\n", size);
		goto out_drop_area;
	}

	if (spa->type == SPA_TYPE_K2TASK) {
		/*
		 * Only allow the original k2task applier process to unshare this uva.
		 * Kthreads or other processes are not allowed to unshare the uva.
		 */
		if (spa->applier != current->tgid) {
			pr_err_ratelimited("unshare uva(to task) no permission\n");
			ret = -EPERM;
			goto out_drop_area;
		}

		if (!spa->mm) {
			pr_err_ratelimited("unshare uva(to task) failed, none spa owner\n");
			ret = -EINVAL;
			goto out_drop_area;
		}

		/*
		 * current thread may be exiting in a multithread process
		 *
		 * 1. never need a kthread to make unshare when process has exited
		 * 2. in dvpp channel destroy procedure, exit_mm() has been called
		 *    and don't need to make unshare
		 */
		mm = get_task_mm(current->group_leader);
		if (!mm) {
			pr_info_ratelimited("no need to unshare uva(to task), "
					    "target process mm is exiting\n");
			goto out_clr_flag;
		}

		if (spa->mm != mm) {
			pr_err_ratelimited("unshare uva(to task) failed, spa not belong to the task\n");
			ret = -EINVAL;
			mmput(mm);
			goto out_drop_area;
		}

		down_write(&mm->mmap_sem);
		if (unlikely(mm->core_state)) {
			ret = 0;
			up_write(&mm->mmap_sem);
			mmput(mm);
			goto out_drop_area;
		}

		ret = do_munmap(mm, uva_aligned, size_aligned, NULL);
		up_write(&mm->mmap_sem);
		mmput(mm);
		/* we are not supposed to fail */
		if (ret)
			pr_err("failed to unmap VA %pK when munmap in unshare uva\n",
			       (void *)uva_aligned);
		sp_update_process_stat(current, false, spa);

	} else if (spa->type == SPA_TYPE_K2SPG) {
		down_read(&spa->spg->rw_lock);
		/* always allow kthread and dvpp channel destroy procedure */
		if (current->mm) {
			if (!is_process_in_group(spa->spg, current->mm)) {
				up_read(&spa->spg->rw_lock);
				pr_err_ratelimited("unshare uva(to group) failed, "
					"caller process doesn't belong to target group\n");
				ret = -EPERM;
				goto out_drop_area;
			}
		}
		up_read(&spa->spg->rw_lock);

		down_write(&spa->spg->rw_lock);
		if (!spg_valid(spa->spg)) {
			up_write(&spa->spg->rw_lock);
			pr_info_ratelimited("share pool: no need to unshare uva(to group), "
					    "sp group of spa is dead\n");
			goto out_clr_flag;
		}
		/* the life cycle of spa has a direct relation with sp group */
		if (unlikely(spa->is_dead)) {
			up_write(&spa->spg->rw_lock);
			pr_err_ratelimited("unexpected double sp unshare\n");
			dump_stack();
			ret = -EINVAL;
			goto out_drop_area;
		}
		spa->is_dead = true;
		up_write(&spa->spg->rw_lock);

		down_read(&spa->spg->rw_lock);
		__sp_free(spa->spg, uva_aligned, size_aligned, NULL);
		up_read(&spa->spg->rw_lock);

		if (current->mm == NULL)
			atomic64_sub(spa->real_size, &kthread_stat.k2u_size);
		else
			sp_update_process_stat(current, false, spa);
	} else {
		WARN(1, "unshare uva invalid spa type");
	}

	sp_dump_stack();

out_clr_flag:
	if (!vmalloc_area_clr_flag(spa->kva, VM_SHAREPOOL))
		pr_debug("clear spa->kva %ld is not valid\n", spa->kva);
	spa->kva = 0;

out_drop_area:
	__sp_area_drop(spa);
out:
	return ret;
}

/* No possible concurrent protection, take care when use */
static int sp_unshare_kva(unsigned long kva, unsigned long size)
{
	unsigned long addr, kva_aligned;
	struct page *page;
	unsigned long size_aligned;
	unsigned long step;
	bool is_hugepage = true;
	int ret;

	ret = is_vmap_hugepage(kva);
	if (ret > 0) {
		kva_aligned = ALIGN_DOWN(kva, PMD_SIZE);
		size_aligned = ALIGN(kva + size, PMD_SIZE) - kva_aligned;
		step = PMD_SIZE;
	} else if (ret == 0) {
		kva_aligned = ALIGN_DOWN(kva, PAGE_SIZE);
		size_aligned = ALIGN(kva + size, PAGE_SIZE) - kva_aligned;
		step = PAGE_SIZE;
		is_hugepage = false;
	} else {
		pr_err_ratelimited("check vmap hugepage failed %d\n", ret);
		return -EINVAL;
	}

	if (kva_aligned + size_aligned < kva_aligned) {
		pr_err_ratelimited("overflow happened in unshare kva\n");
		return -EINVAL;
	}

	for (addr = kva_aligned; addr < (kva_aligned + size_aligned); addr += step) {
		if (is_hugepage)
			page = vmalloc_to_hugepage((void *)addr);
		else
			page = vmalloc_to_page((void *)addr);
		if (page)
			put_page(page);
		else
			WARN(1, "vmalloc %pK to page/hugepage failed\n",
			       (void *)addr);
	}

	vunmap((void *)kva_aligned);

	return 0;
}

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
	int ret = 0;

	check_interrupt_context();

	if (va < TASK_SIZE) {
		/* user address */
		ret = sp_unshare_uva(va, size);
	} else if (va >= VA_START) {
		/* kernel address */
		ret = sp_unshare_kva(va, size);
	} else {
		/* regard user and kernel address ranges as bad address */
		pr_debug("unshare addr %lx is not a user or kernel addr\n", (unsigned long)va);
		ret = -EFAULT;
	}

	return ret;
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
	down_write(&mm->mmap_sem);
	if (likely(!mm->core_state))
		ret = __sp_walk_page_range(uva, size, mm, sp_walk_data);
	else {
		pr_err("walk page range: encoutered coredump\n");
		ret = -ESRCH;
	}
	up_write(&mm->mmap_sem);

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
	return sp_walk_page_free(sp_walk_data);
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

int sp_node_id(struct vm_area_struct *vma)
{
	struct sp_area *spa;
	int node_id = numa_node_id();

	if (!enable_ascend_share_pool)
		return node_id;

	if (vma) {
		spa = __find_sp_area(vma->vm_start);
		if (spa) {
			node_id = spa->node_id;
			__sp_area_drop(spa);
		}
	}

	return node_id;
}
EXPORT_SYMBOL_GPL(sp_node_id);

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

	if (unlikely(!mm))
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

	if (!enable_ascend_share_pool)
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

		seq_printf(seq, "size: %ld KB, spa num: %d, total alloc: %ld KB, "
			   "normal alloc: %ld KB, huge alloc: %ld KB\n",
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

		pr_info("size: %ld KB, spa num: %d, total alloc: %ld KB, "
			"normal alloc: %ld KB, huge alloc: %ld KB\n",
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
	if (!enable_ascend_share_pool)
		return;

	if (seq != NULL) {
		seq_printf(seq, "Share pool total size: %ld KB, spa total num: %d.\n",
			   byte2kb(atomic64_read(&sp_overall_stat.spa_total_size)),
			   atomic_read(&sp_overall_stat.spa_total_num));
	} else {
		pr_info("Share pool total size: %ld KB, spa total num: %d.\n",
			byte2kb(atomic64_read(&sp_overall_stat.spa_total_size)),
			atomic_read(&sp_overall_stat.spa_total_num));
	}

	down_read(&sp_spg_stat_sem);
	idr_for_each(&sp_spg_stat_idr, idr_spg_stat_cb, seq);
	up_read(&sp_spg_stat_sem);

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
	 * non_sp_shm: resident shared memory size size excluding share pool
	 *             memory
	 */
	long sp_res, sp_res_nsize, non_sp_res, non_sp_shm;

	/* to prevent ABBA deadlock, first hold sp_group_sem */
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
	seq_printf(seq, "%-8s %-8s %-9ld %-9ld\n",
		   "guard", "-",
		   byte2kb(atomic64_read(&kthread_stat.alloc_size)),
		   byte2kb(atomic64_read(&kthread_stat.k2u_size)));

	/*
	 * This ugly code is just for fixing the ABBA deadlock against
	 * sp_group_add_task.
	 */
	down_read(&sp_group_sem);
	down_read(&sp_spg_stat_sem);
	idr_for_each(&sp_spg_stat_idr, idr_proc_stat_cb, seq);
	up_read(&sp_spg_stat_sem);
	up_read(&sp_group_sem);

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

/*
 * Called by proc_root_init() to initialize the /proc/sharepool subtree
 */
void __init proc_sharepool_init(void)
{
	if (!proc_mkdir("sharepool", NULL))
		return;

	proc_create_single_data("sharepool/proc_stat", 0400, NULL, proc_stat_show, NULL);
	proc_create_single_data("sharepool/spa_stat", 0400, NULL, spa_stat_show, NULL);
	proc_create_single_data("sharepool/proc_overview", 0400, NULL, proc_overview_show, NULL);
}

/*** End of tatistical and maintenance functions ***/

bool sp_check_addr(unsigned long addr)
{
	if (enable_ascend_share_pool && is_sharepool_addr(addr) &&
	    !check_aoscore_process(current)) {
		sp_dump_stack();
		return true;
	} else
		return false;
}

bool sp_check_mmap_addr(unsigned long addr, unsigned long flags)
{
	if (enable_ascend_share_pool && is_sharepool_addr(addr) &&
	    !check_aoscore_process(current) && !(flags & MAP_SHARE_POOL)) {
		sp_dump_stack();
		return true;
	} else
		return false;
}

vm_fault_t sharepool_no_page(struct mm_struct *mm,
			struct vm_area_struct *vma,
			struct address_space *mapping, pgoff_t idx,
			unsigned long address, pte_t *ptep, unsigned int flags)
{
	struct hstate *h = hstate_vma(vma);
	vm_fault_t ret = VM_FAULT_SIGBUS;
	unsigned long size;
	struct page *page;
	pte_t new_pte;
	spinlock_t *ptl;
	unsigned long haddr = address & huge_page_mask(h);
	bool new_page = false;
	int err;
	int node_id;
	struct sp_area *spa;

	spa = __find_sp_area(vma->vm_start);
	if (!spa) {
		pr_err("share pool: vma is invalid, not from sp mmap\n");
		return ret;
	}
	node_id = spa->node_id;
	__sp_area_drop(spa);

retry:
	page = find_lock_page(mapping, idx);
	if (!page) {
		size = i_size_read(mapping->host) >> huge_page_shift(h);
		if (idx >= size)
			goto out;

		page = alloc_huge_page(vma, haddr, 0);
		if (IS_ERR(page)) {
			page = alloc_huge_page_node(hstate_file(vma->vm_file),
						    node_id);
			if (!page)
				page = ERR_PTR(-ENOMEM);
		}
		if (IS_ERR(page)) {
			ptl = huge_pte_lock(h, mm, ptep);
			if (!huge_pte_none(huge_ptep_get(ptep))) {
				ret = 0;
				spin_unlock(ptl);
				goto out;
			}
			spin_unlock(ptl);
			ret = vmf_error(PTR_ERR(page));
			goto out;
		}
		__SetPageUptodate(page);
		new_page = true;

		/* sharepool pages are all shared */
		err = huge_add_to_page_cache(page, mapping, idx);
		if (err) {
			put_page(page);
			if (err == -EEXIST)
				goto retry;
			goto out;
		}
	}


	ptl = huge_pte_lock(h, mm, ptep);
	size = i_size_read(mapping->host) >> huge_page_shift(h);
	if (idx >= size)
		goto backout;

	ret = 0;
	if (!huge_pte_none(huge_ptep_get(ptep)))
		goto backout;

	page_dup_rmap(page, true);
	new_pte = make_huge_pte(vma, page, ((vma->vm_flags & VM_WRITE)
				&& (vma->vm_flags & VM_SHARED)));
	set_huge_pte_at(mm, haddr, ptep, new_pte);

	hugetlb_count_add(pages_per_huge_page(h), mm);

	spin_unlock(ptl);

	if (new_page) {
		SetPagePrivate(&page[1]);
	}

	unlock_page(page);
out:
	return ret;

backout:
	spin_unlock(ptl);
	unlock_page(page);
	put_page(page);
	goto out;
}
EXPORT_SYMBOL(sharepool_no_page);

#define MM_WOULD_FREE	1

/*
 * Recall we add mm->users by 1 deliberately in sp_group_add_task().
 * If the mm_users == sp_group_master->count + 1, it means that the mm is ready
 * to be freed because the last owner of this mm is in exiting procedure:
 * do_exit() -> exit_mm() -> mmput() -> sp_group_exit -> THIS function.
 */
static bool need_free_sp_group(struct mm_struct *mm,
			      struct sp_group_master *master)
{
	/* thread exits but process is still alive */
	if ((unsigned int)atomic_read(&mm->mm_users) != master->count + MM_WOULD_FREE) {
		if (atomic_dec_and_test(&mm->mm_users))
			WARN(1, "Invalid user counting\n");
		return false;
	}

	return true;
}

/*
 * Return:
 * 1	- let mmput() return immediately
 * 0	- let mmput() decrease mm_users and try __mmput()
 */
int sp_group_exit(struct mm_struct *mm)
{
	struct sp_group *spg;
	struct sp_group_master *master;
	struct sp_group_node *spg_node, *tmp;
	bool is_alive = true;

	if (!enable_ascend_share_pool)
		return 0;

	down_write(&sp_group_sem);

	master = mm->sp_group_master;
	if (!master) {
		up_write(&sp_group_sem);
		return 0;
	}

	if (!need_free_sp_group(mm, master)) {
		up_write(&sp_group_sem);
		return 1;
	}

	list_for_each_entry_safe(spg_node, tmp, &master->node_list, group_node) {
		spg = spg_node->spg;

		down_write(&spg->rw_lock);
		/* a dead group should NOT be reactive again */
		if (spg_valid(spg) && list_is_singular(&spg->procs))
			is_alive = spg->is_alive = false;
		spg->proc_num--;
		list_del(&spg_node->proc_node);
		up_write(&spg->rw_lock);

		if (!is_alive)
			blocking_notifier_call_chain(&sp_notifier_chain, 0,
						     spg);
	}

	/* match with get_task_mm() in sp_group_add_task() */
	if (atomic_sub_and_test(master->count, &mm->mm_users)) {
		up_write(&sp_group_sem);
		WARN(1, "Invalid user counting\n");
		return 1;
	}

	up_write(&sp_group_sem);
	return 0;
}

void sp_group_post_exit(struct mm_struct *mm)
{
	struct sp_proc_stat *stat;
	long alloc_size, k2u_size;
	/* lockless visit */
	struct sp_group_master *master = mm->sp_group_master;
	struct sp_group_node *spg_node, *tmp;
	struct sp_group *spg;

	if (!enable_ascend_share_pool || !master)
		return;

	/*
	 * There are two basic scenarios when a process in the share pool is
	 * exiting but its share pool memory usage is not 0.
	 * 1. Process A called sp_alloc(), but it terminates without calling
	 *    sp_free(). Then its share pool memory usage is a positive number.
	 * 2. Process A never called sp_alloc(), and process B in the same spg
	 *    called sp_alloc() to get an addr u. Then A gets u somehow and
	 *    called sp_free(u). Now A's share pool memory usage is a negative
	 *    number. Notice B's memory usage will be a positive number.
	 *
	 * We decide to print an info when seeing both of the scenarios.
	 *
	 * A process not in an sp group doesn't need to print because there
	 * wont't be any memory which is not freed.
	 */
	stat = sp_get_proc_stat(mm);
	if (stat) {
		alloc_size = atomic64_read(&stat->alloc_size);
		k2u_size = atomic64_read(&stat->k2u_size);

		if (alloc_size != 0 || k2u_size != 0)
			pr_info("process %s(%d) exits. "
				"It applied %ld aligned KB, k2u shared %ld aligned KB\n",
				stat->comm, stat->tgid,
				byte2kb(alloc_size), byte2kb(k2u_size));

		/* match with sp_init_proc_stat, we expect stat is released after this call */
		sp_proc_stat_drop(stat);
	}

	down_write(&sp_group_sem);
	list_for_each_entry_safe(spg_node, tmp, &master->node_list, group_node) {
		spg = spg_node->spg;
		/* match with refcount inc in sp_group_add_task */
		if (atomic_dec_and_test(&spg->use_count))
			free_sp_group_locked(spg);
		kfree(spg_node);
	}
	up_write(&sp_group_sem);
	kfree(master);
}

struct page *sp_alloc_pages(struct vm_struct *area, gfp_t mask,
					  unsigned int page_order, int node)
{
	struct page *page;
	unsigned int noreclaim_flag = 0;

	if (area->flags & VM_HUGE_PAGES) {
		noreclaim_flag = memalloc_noreclaim_save();
		page = hugetlb_alloc_hugepage(NUMA_NO_NODE, HUGETLB_ALLOC_NONE);
		memalloc_noreclaim_restore(noreclaim_flag);
		sp_try_to_compact();
		return page;
	} else
		return alloc_pages_node(node, mask, page_order);
}

int enable_ascend_share_pool;

static int __init enable_share_pool(char *s)
{
	enable_ascend_share_pool = 1;

	pr_info("Ascend enable share pool features\n");

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

	return 0;
fail:
	pr_err("Ascend share pool initialization failed\n");
	enable_ascend_share_pool = 0;
	vmap_allow_huge = false;
	return 1;
}
late_initcall(share_pool_init);
