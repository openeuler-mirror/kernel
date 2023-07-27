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
#include <linux/preempt.h>
#include <linux/swapops.h>
#include <linux/mmzone.h>
#include <linux/timekeeping.h>
#include <linux/time64.h>
#include <linux/pagewalk.h>

#define spg_valid(spg)		((spg)->is_alive == true)

/* Use spa va address as mmap offset. This can work because spa_file
 * is setup with 64-bit address space. So va shall be well covered.
 */
#define addr_offset(spa)	((spa)->va_start)

#define byte2kb(size)		((size) >> 10)
#define byte2mb(size)		((size) >> 20)
#define page2kb(page_num)	((page_num) << (PAGE_SHIFT - 10))

#define MAX_GROUP_FOR_SYSTEM	50000
#define MAX_GROUP_FOR_TASK	3000
#define MAX_PROC_PER_GROUP	1024

#define GROUP_NONE		0

#define SEC2US(sec)		((sec) * 1000000)
#define NS2US(ns)		((ns) / 1000)

#define PF_DOMAIN_CORE		0x10000000	/* AOS CORE processes in sched.h */

static int system_group_count;

/* idr of all sp_groups */
static DEFINE_IDR(sp_group_idr);
/* rw semaphore for sp_group_idr and mm->sp_group_master */
static DECLARE_RWSEM(sp_group_sem);

static BLOCKING_NOTIFIER_HEAD(sp_notifier_chain);

static DEFINE_IDA(sp_group_id_ida);

/*** Statistical and maintenance tools ***/

/* list of all sp_group_masters */
static LIST_HEAD(master_list);
/* mutex to protect insert/delete ops from master_list */
static DEFINE_MUTEX(master_list_lock);

/* list of all spm-dvpp */
static LIST_HEAD(spm_dvpp_list);
/* mutex to protect insert/delete ops from master_list */
static DEFINE_MUTEX(spm_list_lock);

#define SEQ_printf(m, x...)			\
do {						\
	if (m)					\
		seq_printf(m, x);		\
	else					\
		pr_info(x);			\
} while (0)

struct sp_meminfo {
	/* not huge page size from sp_alloc */
	atomic64_t	alloc_nsize;
	/* huge page size from sp_alloc */
	atomic64_t	alloc_hsize;
	/* total size from sp_k2u */
	atomic64_t	k2u_size;
};

#ifndef __GENKSYMS__
enum sp_mapping_type {
	SP_MAPPING_START,
	SP_MAPPING_DVPP		= SP_MAPPING_START,
	SP_MAPPING_NORMAL,
	SP_MAPPING_RO,
	SP_MAPPING_END,
};

/*
 * address space management
 */
struct sp_mapping {
	unsigned long type;
	atomic_t user;
	unsigned long start[MAX_DEVID];
	unsigned long end[MAX_DEVID];
	struct rb_root area_root;

	struct rb_node *free_area_cache;
	unsigned long cached_hole_size;
	unsigned long cached_vstart;

	/* list head for all groups attached to this mapping, dvpp mapping only */
	struct list_head group_head;
	struct list_head spm_node;
};

/* Processes in the same sp_group can share memory.
 * Memory layout for share pool:
 *
 * |-------------------- 8T -------------------|---|------ 8T ------------|
 * |		Device 0	   |  Device 1 |...|                      |
 * |----------------------------------------------------------------------|
 * |------------- 16G -------------|    16G    |   |                      |
 * | DVPP GROUP0   | DVPP GROUP1   | ... | ... |...|  sp normal memory    |
 * |     sp        |    sp         |     |     |   |                      |
 * |----------------------------------------------------------------------|
 *
 * The host SVM feature reserves 8T virtual memory by mmap, and due to the
 * restriction of DVPP, while SVM and share pool will both allocate memory
 * for DVPP, the memory have to be in the same 32G range.
 *
 * Share pool reserves 16T memory, with 8T for normal uses and 8T for DVPP.
 * Within this 8T DVPP memory, SVM will call sp_config_dvpp_range() to
 * tell us which 16G memory range is reserved for share pool .
 *
 * In some scenarios where there is no host SVM feature, share pool uses
 * the default 8G memory setting for DVPP.
 */
struct sp_group {
	int		 id;
	unsigned long	 flag;
	struct file	 *file;
	struct file	 *file_hugetlb;
	/* number of process in this group */
	int		 proc_num;
	/* list head of processes (sp_group_node, each represents a process) */
	struct list_head procs;
	/* list head of sp_area. it is protected by spin_lock sp_area_lock */
	struct list_head spa_list;
	/* group statistics */
	struct sp_meminfo meminfo;
	/* is_alive == false means it's being destroyed */
	bool		 is_alive;
	atomic_t	 use_count;
	atomic_t	 spa_num;
	/* protect the group internal elements, except spa_list */
	struct rw_semaphore	rw_lock;
	/* list node for dvpp mapping */
	struct list_head	mnode;
	struct sp_mapping       *mapping[SP_MAPPING_END];
};

/* a per-process(per mm) struct which manages a sp_group_node list */
struct sp_group_master {
	pid_t tgid;
	/*
	 * number of sp groups the process belongs to,
	 * a.k.a the number of sp_node in node_list
	 */
	unsigned int count;
	/* list head of sp_node */
	struct list_head node_list;
	struct mm_struct *mm;
	/*
	 * Used to apply for the shared pool memory of the current process.
	 * For example, sp_alloc non-share memory or k2task.
	 */
	struct sp_group *local;
	struct sp_meminfo meminfo;
	struct list_head list_node;
	char comm[TASK_COMM_LEN];
};

/*
 * each instance represents an sp group the process belongs to
 * sp_group_master    : sp_group_node   = 1 : N
 * sp_group_node->spg : sp_group        = 1 : 1
 * sp_group_node      : sp_group->procs = N : 1
 */
struct sp_group_node {
	/* list node in sp_group->procs */
	struct list_head proc_node;
	/* list node in sp_group_maseter->node_list */
	struct list_head group_node;
	struct sp_group_master *master;
	struct sp_group *spg;
	unsigned long prot;

	/*
	 * alloc amount minus free amount, may be negative when freed by
	 * another task in the same sp group.
	 */
	struct sp_meminfo meminfo;
};
#endif

static inline void sp_add_group_master(struct sp_group_master *master)
{
	mutex_lock(&master_list_lock);
	list_add_tail(&master->list_node, &master_list);
	mutex_unlock(&master_list_lock);
}

static inline void sp_del_group_master(struct sp_group_master *master)
{
	mutex_lock(&master_list_lock);
	list_del(&master->list_node);
	mutex_unlock(&master_list_lock);
}

static void meminfo_init(struct sp_meminfo *meminfo)
{
	memset(meminfo, 0, sizeof(struct sp_meminfo));
}

static void meminfo_inc_usage(unsigned long size, bool huge, struct sp_meminfo *meminfo)
{
	if (huge)
		atomic64_add(size, &meminfo->alloc_hsize);
	else
		atomic64_add(size, &meminfo->alloc_nsize);
}

static void meminfo_dec_usage(unsigned long size, bool huge, struct sp_meminfo *meminfo)
{
	if (huge)
		atomic64_sub(size, &meminfo->alloc_hsize);
	else
		atomic64_sub(size, &meminfo->alloc_nsize);
}

static void meminfo_inc_k2u(unsigned long size, struct sp_meminfo *meminfo)
{
	atomic64_add(size, &meminfo->k2u_size);
}

static void meminfo_dec_k2u(unsigned long size, struct sp_meminfo *meminfo)
{
	atomic64_sub(size, &meminfo->k2u_size);
}

static inline long meminfo_alloc_sum(struct sp_meminfo *meminfo)
{
	return atomic64_read(&meminfo->alloc_nsize) +
			atomic64_read(&meminfo->alloc_hsize);
}

static inline long meminfo_alloc_sum_byKB(struct sp_meminfo *meminfo)
{
	return byte2kb(meminfo_alloc_sum(meminfo));
}

static inline long meminfo_k2u_size(struct sp_meminfo *meminfo)
{
	return byte2kb(atomic64_read(&meminfo->k2u_size));
}

static inline long long meminfo_total_size(struct sp_meminfo *meminfo)
{
	return atomic64_read(&meminfo->alloc_nsize) +
		atomic64_read(&meminfo->alloc_hsize) +
		atomic64_read(&meminfo->k2u_size);
}

static unsigned long sp_mapping_type(struct sp_mapping *spm)
{
	return spm->type;
}

static void sp_mapping_set_type(struct sp_mapping *spm, unsigned long type)
{
	spm->type = type;
}

static struct sp_mapping *sp_mapping_normal;
static struct sp_mapping *sp_mapping_ro;

static void sp_mapping_add_to_list(struct sp_mapping *spm)
{
	mutex_lock(&spm_list_lock);
	if (sp_mapping_type(spm) == SP_MAPPING_DVPP)
		list_add_tail(&spm->spm_node, &spm_dvpp_list);
	mutex_unlock(&spm_list_lock);
}

static void sp_mapping_remove_from_list(struct sp_mapping *spm)
{
	mutex_lock(&spm_list_lock);
	if (sp_mapping_type(spm) == SP_MAPPING_DVPP)
		list_del(&spm->spm_node);
	mutex_unlock(&spm_list_lock);
}

static void sp_mapping_range_init(struct sp_mapping *spm)
{
	int i;

	for (i = 0; i < MAX_DEVID; i++) {
		switch (sp_mapping_type(spm)) {
		case SP_MAPPING_RO:
			spm->start[i] = MMAP_SHARE_POOL_RO_START;
			spm->end[i]   = MMAP_SHARE_POOL_RO_END;
			break;
		case SP_MAPPING_NORMAL:
			spm->start[i] = MMAP_SHARE_POOL_NORMAL_START;
			spm->end[i]   = MMAP_SHARE_POOL_NORMAL_END;
			break;
		case SP_MAPPING_DVPP:
			spm->start[i] = MMAP_SHARE_POOL_DVPP_START + i * MMAP_SHARE_POOL_16G_SIZE;
			spm->end[i]   = spm->start[i] + MMAP_SHARE_POOL_16G_SIZE;
			break;
		default:
			pr_err("Invalid sp_mapping type [%lu]\n", sp_mapping_type(spm));
			break;
		}
	}
}

static struct sp_mapping *sp_mapping_create(unsigned long type)
{
	struct sp_mapping *spm;

	spm = kzalloc(sizeof(struct sp_mapping), GFP_KERNEL);
	if (!spm)
		return ERR_PTR(-ENOMEM);

	sp_mapping_set_type(spm, type);
	sp_mapping_range_init(spm);
	atomic_set(&spm->user, 0);
	spm->area_root = RB_ROOT;
	INIT_LIST_HEAD(&spm->group_head);
	sp_mapping_add_to_list(spm);

	return spm;
}

static void sp_mapping_destroy(struct sp_mapping *spm)
{
	sp_mapping_remove_from_list(spm);
	kfree(spm);
}

static void sp_mapping_attach(struct sp_group *spg, struct sp_mapping *spm)
{
	unsigned long type = sp_mapping_type(spm);
	atomic_inc(&spm->user);

	spg->mapping[type] = spm;
	if (type == SP_MAPPING_DVPP)
		list_add_tail(&spg->mnode, &spm->group_head);
}

static void sp_mapping_detach(struct sp_group *spg, struct sp_mapping *spm)
{
	unsigned long type;

	if (!spm)
		return;

	type = sp_mapping_type(spm);
	if (type == SP_MAPPING_DVPP)
		list_del(&spg->mnode);
	if (atomic_dec_and_test(&spm->user))
		sp_mapping_destroy(spm);

	spg->mapping[type] = NULL;
}

/* merge old mapping to new, and the old mapping would be destroyed */
static void sp_mapping_merge(struct sp_mapping *new, struct sp_mapping *old)
{
	struct sp_group *spg, *tmp;

	if (new == old)
		return;

	list_for_each_entry_safe(spg, tmp, &old->group_head, mnode) {
		list_move_tail(&spg->mnode, &new->group_head);
		spg->mapping[SP_MAPPING_DVPP] = new;
	}

	atomic_add(atomic_read(&old->user), &new->user);
	sp_mapping_destroy(old);
}

static bool is_mapping_empty(struct sp_mapping *spm)
{
	return RB_EMPTY_ROOT(&spm->area_root);
}

static bool can_mappings_merge(struct sp_mapping *m1, struct sp_mapping *m2)
{
	int i;

	for (i = 0; i < MAX_DEVID; i++)
		if (m1->start[i] != m2->start[i] || m1->end[i] != m2->end[i])
			return false;

	return true;
}

/*
 * 1. The mappings of local group is set on creating.
 * 2. This is used to setup the mapping for groups created during add_task.
 * 3. The normal mapping exists for all groups.
 * 4. The dvpp mappings for the new group and local group can merge _iff_ at
 *    least one of the mapping is empty.
 * the caller must hold sp_group_sem
 * NOTE: undo the mergeing when the later process failed.
 */
static int sp_mapping_group_setup(struct mm_struct *mm, struct sp_group *spg)
{
	struct sp_mapping *local_dvpp_mapping, *spg_dvpp_mapping;

	local_dvpp_mapping = mm->sp_group_master->local->mapping[SP_MAPPING_DVPP];
	spg_dvpp_mapping = spg->mapping[SP_MAPPING_DVPP];

	if (!list_empty(&spg->procs)) {
		/*
		 * Don't return an error when the mappings' address range conflict.
		 * As long as the mapping is unused, we can drop the empty mapping.
		 * This may change the address range for the task or group implicitly,
		 * give a warn for it.
		 */
		bool is_conflict = !can_mappings_merge(local_dvpp_mapping, spg_dvpp_mapping);

		if (is_mapping_empty(local_dvpp_mapping)) {
			sp_mapping_merge(spg_dvpp_mapping, local_dvpp_mapping);
			if (is_conflict)
				pr_warn_ratelimited("task address space conflict, spg_id=%d\n",
						spg->id);
		} else if (is_mapping_empty(spg_dvpp_mapping)) {
			sp_mapping_merge(local_dvpp_mapping, spg_dvpp_mapping);
			if (is_conflict)
				pr_warn_ratelimited("group address space conflict, spg_id=%d\n",
						spg->id);
		} else {
			pr_info_ratelimited("Duplicate address space, id=%d\n", spg->id);
			return -EINVAL;
		}
	} else {
		/* the mapping of local group is always set */
		sp_mapping_attach(spg, local_dvpp_mapping);
		if (!spg->mapping[SP_MAPPING_NORMAL])
			sp_mapping_attach(spg, sp_mapping_normal);
		if (!spg->mapping[SP_MAPPING_RO])
			sp_mapping_attach(spg, sp_mapping_ro);
	}

	return 0;
}

static struct sp_mapping *sp_mapping_find(struct sp_group *spg,
						 unsigned long addr)
{
	if (addr >= MMAP_SHARE_POOL_NORMAL_START && addr < MMAP_SHARE_POOL_NORMAL_END)
		return spg->mapping[SP_MAPPING_NORMAL];

	if (addr >= MMAP_SHARE_POOL_RO_START && addr < MMAP_SHARE_POOL_RO_END)
		return spg->mapping[SP_MAPPING_RO];

	return spg->mapping[SP_MAPPING_DVPP];
}

static struct sp_group *create_spg(int spg_id, unsigned long flag);
static void free_new_spg_id(bool new, int spg_id);
static void free_sp_group_locked(struct sp_group *spg);
static struct sp_group_node *group_add_task(struct mm_struct *mm, struct sp_group *spg,
					    unsigned long prot);
static int init_local_group(struct mm_struct *mm)
{
	int spg_id, ret;
	struct sp_group *spg;
	struct sp_mapping *spm;
	struct sp_group_node *spg_node;
	struct sp_group_master *master = mm->sp_group_master;

	spg_id = ida_alloc_range(&sp_group_id_ida, SPG_ID_LOCAL_MIN,
				 SPG_ID_LOCAL_MAX, GFP_ATOMIC);
	if (spg_id < 0) {
		pr_err_ratelimited("generate local group id failed %d\n", spg_id);
		return spg_id;
	}

	spg = create_spg(spg_id, 0);
	if (IS_ERR(spg)) {
		free_new_spg_id(true, spg_id);
		return PTR_ERR(spg);
	}

	master->local = spg;
	spm = sp_mapping_create(SP_MAPPING_DVPP);
	if (IS_ERR(spm)) {
		ret = PTR_ERR(spm);
		goto free_spg;
	}
	sp_mapping_attach(master->local, spm);
	sp_mapping_attach(master->local, sp_mapping_normal);
	sp_mapping_attach(master->local, sp_mapping_ro);

	spg_node = group_add_task(mm, spg, PROT_READ | PROT_WRITE);
	if (IS_ERR(spg_node)) {
		/* The spm would be released while destroying the spg */
		ret = PTR_ERR(spg_node);
		goto free_spg;
	}
	mmget(mm);

	return 0;

free_spg:
	/* spg_id is freed in free_sp_group_locked */
	free_sp_group_locked(spg);
	master->local = NULL;
	return ret;
}

/* The caller must hold sp_group_sem */
static int sp_init_group_master_locked(struct task_struct *tsk, struct mm_struct *mm)
{
	int ret;
	struct sp_group_master *master;

	if (mm->sp_group_master)
		return 0;

	master = kmalloc(sizeof(struct sp_group_master), GFP_KERNEL);
	if (!master)
		return -ENOMEM;

	INIT_LIST_HEAD(&master->node_list);
	master->count = 0;
	master->mm = mm;
	master->tgid = tsk->tgid;
	get_task_comm(master->comm, current);
	meminfo_init(&master->meminfo);
	mm->sp_group_master = master;
	sp_add_group_master(master);

	ret = init_local_group(mm);
	if (ret)
		goto free_master;

	return 0;

free_master:
	sp_del_group_master(master);
	mm->sp_group_master = NULL;
	kfree(master);

	return ret;
}

static inline bool is_local_group(int spg_id)
{
	return spg_id >= SPG_ID_LOCAL_MIN && spg_id <= SPG_ID_LOCAL_MAX;
}

static struct sp_group *sp_get_local_group(struct task_struct *tsk, struct mm_struct *mm)
{
	int ret;
	struct sp_group_master *master;

	down_read(&sp_group_sem);
	master = mm->sp_group_master;
	if (master && master->local) {
		atomic_inc(&master->local->use_count);
		up_read(&sp_group_sem);
		return master->local;
	}
	up_read(&sp_group_sem);

	down_write(&sp_group_sem);
	ret = sp_init_group_master_locked(tsk, mm);
	if (ret) {
		up_write(&sp_group_sem);
		return ERR_PTR(ret);
	}
	master = mm->sp_group_master;
	atomic_inc(&master->local->use_count);
	up_write(&sp_group_sem);

	return master->local;
}

static void update_mem_usage_alloc(unsigned long size, bool inc,
		bool is_hugepage, struct sp_group_node *spg_node)
{
	if (inc) {
		meminfo_inc_usage(size, is_hugepage, &spg_node->meminfo);
		meminfo_inc_usage(size, is_hugepage, &spg_node->master->meminfo);
	} else {
		meminfo_dec_usage(size, is_hugepage, &spg_node->meminfo);
		meminfo_dec_usage(size, is_hugepage, &spg_node->master->meminfo);
	}
}

static void update_mem_usage_k2u(unsigned long size, bool inc,
		struct sp_group_node *spg_node)
{
	if (inc) {
		meminfo_inc_k2u(size, &spg_node->meminfo);
		meminfo_inc_k2u(size, &spg_node->master->meminfo);
	} else {
		meminfo_dec_k2u(size, &spg_node->meminfo);
		meminfo_dec_k2u(size, &spg_node->master->meminfo);
	}
}

struct sp_spa_stat {
	atomic64_t alloc_num;
	atomic64_t k2u_task_num;
	atomic64_t k2u_spg_num;
	atomic64_t alloc_size;
	atomic64_t k2u_task_size;
	atomic64_t k2u_spg_size;
	atomic64_t dvpp_size;
	atomic64_t dvpp_va_size;
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
	/* NOTE: reorganize after the statisical structure is reconstructed. */
	SPA_TYPE_ALLOC_PRIVATE = SPA_TYPE_ALLOC,
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
	int preferred_node_id;			/* memory node */
	int device_id;
};
static DEFINE_SPINLOCK(sp_area_lock);

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
		atomic64_inc(&spa_stat.alloc_num);
		atomic64_add(size, &spa_stat.alloc_size);
		meminfo_inc_usage(size, is_huge, &spa->spg->meminfo);
		break;
	case SPA_TYPE_K2TASK:
		atomic64_inc(&spa_stat.k2u_task_num);
		atomic64_add(size, &spa_stat.k2u_task_size);
		meminfo_inc_k2u(size, &spa->spg->meminfo);
		break;
	case SPA_TYPE_K2SPG:
		atomic64_inc(&spa_stat.k2u_spg_num);
		atomic64_add(size, &spa_stat.k2u_spg_size);
		meminfo_inc_k2u(size, &spa->spg->meminfo);
		break;
	default:
		WARN(1, "invalid spa type");
	}

	if (is_dvpp) {
		atomic64_add(size, &spa_stat.dvpp_size);
		atomic64_add(ALIGN(size, PMD_SIZE), &spa_stat.dvpp_va_size);
	}

	atomic_inc(&spa->spg->spa_num);

	if (!is_local_group(spa->spg->id)) {
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
		atomic64_dec(&spa_stat.alloc_num);
		atomic64_sub(size, &spa_stat.alloc_size);
		meminfo_dec_usage(size, is_huge, &spa->spg->meminfo);
		break;
	case SPA_TYPE_K2TASK:
		atomic64_dec(&spa_stat.k2u_task_num);
		atomic64_sub(size, &spa_stat.k2u_task_size);
		meminfo_dec_k2u(size, &spa->spg->meminfo);
		break;
	case SPA_TYPE_K2SPG:
		atomic64_dec(&spa_stat.k2u_spg_num);
		atomic64_sub(size, &spa_stat.k2u_spg_size);
		meminfo_dec_k2u(size, &spa->spg->meminfo);
		break;
	default:
		WARN(1, "invalid spa type");
	}

	if (is_dvpp) {
		atomic64_sub(size, &spa_stat.dvpp_size);
		atomic64_sub(ALIGN(size, PMD_SIZE), &spa_stat.dvpp_va_size);
	}

	atomic_dec(&spa->spg->spa_num);

	if (!is_local_group(spa->spg->id)) {
		atomic_dec(&sp_overall_stat.spa_total_num);
		atomic64_sub(spa->real_size, &sp_overall_stat.spa_total_size);
	}
}

static void update_mem_usage(unsigned long size, bool inc, bool is_hugepage,
	struct sp_group_node *spg_node, enum spa_type type)
{
	switch (type) {
	case SPA_TYPE_ALLOC:
		update_mem_usage_alloc(size, inc, is_hugepage, spg_node);
		break;
	case SPA_TYPE_K2TASK:
	case SPA_TYPE_K2SPG:
		update_mem_usage_k2u(size, inc, spg_node);
		break;
	default:
		WARN(1, "invalid stat type\n");
	}
}

static struct sp_group_node *find_spg_node_by_spg(struct mm_struct *mm,
		struct sp_group *spg)
{
	struct sp_group_node *spg_node;

	list_for_each_entry(spg_node, &mm->sp_group_master->node_list, group_node) {
		if (spg_node->spg == spg)
			return spg_node;
	}
	return NULL;
}

static void sp_update_process_stat(struct task_struct *tsk, bool inc,
	struct sp_area *spa)
{
	struct sp_group_node *spg_node;
	unsigned long size = spa->real_size;
	enum spa_type type = spa->type;

	down_read(&sp_group_sem);
	spg_node = find_spg_node_by_spg(tsk->mm, spa->spg);
	if (spg_node != NULL)
		update_mem_usage(size, inc, spa->is_hugepage, spg_node, type);
	up_read(&sp_group_sem);
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
			     unsigned long prot, struct vm_area_struct **pvma);
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
	enum spa_type type;
};

static unsigned long sp_remap_kva_to_vma(struct sp_area *spa, struct mm_struct *mm,
					unsigned long prot, struct sp_k2u_context *kc);

static void free_sp_group_id(int spg_id)
{
	/* ida operation is protected by an internal spin_lock */
	if ((spg_id >= SPG_ID_AUTO_MIN && spg_id <= SPG_ID_AUTO_MAX) ||
	    (spg_id >= SPG_ID_LOCAL_MIN && spg_id <= SPG_ID_LOCAL_MAX))
		ida_free(&sp_group_id_ida, spg_id);
}

static void free_new_spg_id(bool new, int spg_id)
{
	if (new)
		free_sp_group_id(spg_id);
}

static void free_sp_group_locked(struct sp_group *spg)
{
	int type;

	fput(spg->file);
	fput(spg->file_hugetlb);
	idr_remove(&sp_group_idr, spg->id);
	free_sp_group_id((unsigned int)spg->id);

	for (type = SP_MAPPING_START; type < SP_MAPPING_END; type++)
		sp_mapping_detach(spg, spg->mapping[type]);

	if (!is_local_group(spg->id))
		system_group_count--;

	kfree(spg);
	WARN(system_group_count < 0, "unexpected group count\n");
}

static void free_sp_group(struct sp_group *spg)
{
	down_write(&sp_group_sem);
	free_sp_group_locked(spg);
	up_write(&sp_group_sem);
}

static void sp_group_put_locked(struct sp_group *spg)
{
	lockdep_assert_held_write(&sp_group_sem);

	if (atomic_dec_and_test(&spg->use_count))
		free_sp_group_locked(spg);
}

static void sp_group_put(struct sp_group *spg)
{
	if (atomic_dec_and_test(&spg->use_count))
		free_sp_group(spg);
}

/* use with put_task_struct(task) */
static int get_task(int tgid, struct task_struct **task)
{
	struct task_struct *tsk;
	struct pid *p;

	rcu_read_lock();
	p = find_pid_ns(tgid, &init_pid_ns);
	tsk = pid_task(p, PIDTYPE_TGID);
	if (!tsk || (tsk->flags & PF_EXITING)) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(tsk);
	rcu_read_unlock();

	*task = tsk;
	return 0;
}

/*
 * the caller must:
 * 1. hold spg->rw_lock
 * 2. ensure no concurrency problem for mm_struct
 */
static bool is_process_in_group(struct sp_group *spg,
						 struct mm_struct *mm)
{
	struct sp_group_node *spg_node;

	list_for_each_entry(spg_node, &spg->procs, proc_node)
		if (spg_node->master->mm == mm)
			return true;

	return false;
}

/* user must call sp_group_put() after use */
static struct sp_group *sp_group_get_locked(int tgid, int spg_id)
{
	struct sp_group *spg = NULL;
	struct task_struct *tsk = NULL;
	int ret = 0;

	if (spg_id == SPG_ID_DEFAULT) {
		ret = get_task(tgid, &tsk);
		if (ret)
			return NULL;

		task_lock(tsk);
		if (tsk->mm == NULL)
			spg = NULL;
		else if (tsk->mm->sp_group_master)
			spg = tsk->mm->sp_group_master->local;
		task_unlock(tsk);

		put_task_struct(tsk);
	} else {
		spg = idr_find(&sp_group_idr, spg_id);
	}

	if (!spg || !atomic_inc_not_zero(&spg->use_count))
		return NULL;

	return spg;
}

static struct sp_group *sp_group_get(int tgid, int spg_id)
{
	struct sp_group *spg;

	down_read(&sp_group_sem);
	spg = sp_group_get_locked(tgid, spg_id);
	up_read(&sp_group_sem);
	return spg;
}

/**
 * mp_sp_group_id_by_pid() - Get the sp_group ID array of a process.
 * @tgid: tgid of target process.
 * @spg_ids: point to an array to save the group ids the process belongs to
 * @num: input the spg_ids array size; output the spg number of the process
 *
 * Return:
 * >0		- the sp_group ID.
 * -ENODEV	- target process doesn't belong to any sp_group.
 * -EINVAL	- spg_ids or num is NULL.
 * -E2BIG	- the num of groups process belongs to is larger than *num
 */
int mg_sp_group_id_by_pid(int tgid, int *spg_ids, int *num)
{
	int ret = 0, real_count;
	struct sp_group_node *node;
	struct sp_group_master *master = NULL;
	struct task_struct *tsk;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	check_interrupt_context();

	if (!spg_ids || !num || *num <= 0)
		return -EINVAL;

	ret = get_task(tgid, &tsk);
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

	/*
	 * There is a local group for each process which is used for
	 * passthrough allocation. The local group is a internal
	 * implementation for convenience and is not attempt to bother
	 * the user.
	 */
	real_count = master->count - 1;
	if (real_count <= 0) {
		ret = -ENODEV;
		goto out_up_read;
	}
	if ((unsigned int)*num < real_count) {
		ret = -E2BIG;
		goto out_up_read;
	}
	*num = real_count;

	list_for_each_entry(node, &master->node_list, group_node) {
		if (is_local_group(node->spg->id))
			continue;
		*(spg_ids++) = node->spg->id;
	}

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

static void sp_group_init(struct sp_group *spg, int spg_id, unsigned long flag)
{
	spg->id = spg_id;
	spg->flag = flag;
	spg->is_alive = true;
	spg->proc_num = 0;
	atomic_set(&spg->use_count, 1);
	atomic_set(&spg->spa_num, 0);
	INIT_LIST_HEAD(&spg->procs);
	INIT_LIST_HEAD(&spg->spa_list);
	INIT_LIST_HEAD(&spg->mnode);
	init_rwsem(&spg->rw_lock);
	meminfo_init(&spg->meminfo);
}

static struct sp_group *create_spg(int spg_id, unsigned long flag)
{
	int ret;
	struct sp_group *spg;
	char name[DNAME_INLINE_LEN];
	struct user_struct *user = NULL;
	int hsize_log = MAP_HUGE_2MB >> MAP_HUGE_SHIFT;

	if (unlikely(system_group_count + 1 == MAX_GROUP_FOR_SYSTEM &&
		     !is_local_group(spg_id))) {
		pr_err("reach system max group num\n");
		return ERR_PTR(-ENOSPC);
	}

	spg = kzalloc(sizeof(*spg), GFP_KERNEL);
	if (spg == NULL)
		return ERR_PTR(-ENOMEM);

	sprintf(name, "sp_group_%d", spg_id);
	spg->file = shmem_kernel_file_setup(name, MAX_LFS_FILESIZE, VM_NORESERVE);
	if (IS_ERR(spg->file)) {
		pr_err("spg file setup failed %ld\n", PTR_ERR(spg->file));
		ret = PTR_ERR(spg->file);
		goto out_kfree;
	}

	sprintf(name, "sp_group_%d_huge", spg_id);
	spg->file_hugetlb = hugetlb_file_setup(name, MAX_LFS_FILESIZE,
				VM_NORESERVE, &user, HUGETLB_ANONHUGE_INODE, hsize_log);
	if (IS_ERR(spg->file_hugetlb)) {
		pr_err("spg file_hugetlb setup failed %ld\n", PTR_ERR(spg->file_hugetlb));
		ret = PTR_ERR(spg->file_hugetlb);
		goto out_fput;
	}

	sp_group_init(spg, spg_id, flag);

	ret = idr_alloc(&sp_group_idr, spg, spg_id, spg_id + 1, GFP_KERNEL);
	if (ret < 0) {
		pr_err("group %d idr alloc failed %d\n", spg_id, ret);
		goto out_fput_huge;
	}

	if (!is_local_group(spg_id))
		system_group_count++;

	return spg;

out_fput_huge:
	fput(spg->file_hugetlb);
out_fput:
	fput(spg->file);
out_kfree:
	kfree(spg);
	return ERR_PTR(ret);
}

/* the caller must hold sp_group_sem */
static struct sp_group *find_or_alloc_sp_group(int spg_id, unsigned long flag)
{
	struct sp_group *spg;

	spg = sp_group_get_locked(current->tgid, spg_id);

	if (!spg) {
		spg = create_spg(spg_id, flag);
	} else {
		down_read(&spg->rw_lock);
		if (!spg_valid(spg)) {
			up_read(&spg->rw_lock);
			sp_group_put_locked(spg);
			return ERR_PTR(-ENODEV);
		}
		up_read(&spg->rw_lock);
		/* spg->use_count has increased due to sp_group_get() */
	}

	return spg;
}

static void __sp_area_drop_locked(struct sp_area *spa);

/* The caller must down_write(&mm->mmap_lock) */
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
static int mm_add_group_init(struct task_struct *tsk, struct mm_struct *mm,
			     struct sp_group *spg)
{
	int ret;
	struct sp_group_master *master;

	if (!mm->sp_group_master) {
		ret = sp_init_group_master_locked(tsk, mm);
		if (ret)
			return ret;
	} else {
		if (is_process_in_group(spg, mm)) {
			pr_err_ratelimited("task already in target group, id=%d\n", spg->id);
			return -EEXIST;
		}

		master = mm->sp_group_master;
		if (master->count == MAX_GROUP_FOR_TASK) {
			pr_err("task reaches max group num\n");
			return -ENOSPC;
		}
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
	if (spg_node == NULL)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&spg_node->group_node);
	INIT_LIST_HEAD(&spg_node->proc_node);
	spg_node->spg = spg;
	spg_node->master = master;
	spg_node->prot = prot;
	meminfo_init(&spg_node->meminfo);

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

/* the caller must hold sp_group_sem and down_write(&spg->rw_lock) in order */
static struct sp_group_node *group_add_task(struct mm_struct *mm, struct sp_group *spg,
					    unsigned long prot)
{
	struct sp_group_node *node;
	int ret;

	node = create_spg_node(mm, prot, spg);
	if (IS_ERR(node))
		return node;

	ret = insert_spg_node(spg, node);
	if (unlikely(ret)) {
		free_spg_node(mm, spg, node);
		return ERR_PTR(ret);
	}

	return node;
}

/**
 * mg_sp_group_add_task() - Add a process to an share group (sp_group).
 * @tgid: the tgid of the task to be added.
 * @prot: the prot of task for this spg.
 * @spg_id: the ID of the sp_group.
 * @flag: to give some special message.
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
int mg_sp_group_add_task(int tgid, unsigned long prot, int spg_id)
{
	unsigned long flag = 0;
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct sp_group *spg;
	struct sp_group_node *node = NULL;
	int ret = 0;
	bool id_newly_generated = false;
	struct sp_area *spa, *prev = NULL;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	check_interrupt_context();

	/* only allow READ, READ | WRITE */
	if (!((prot == PROT_READ)
	      || (prot == (PROT_READ | PROT_WRITE)))) {
		pr_err_ratelimited("prot is invalid 0x%lx\n", prot);
		return -EINVAL;
	}

	if (spg_id < SPG_ID_MIN || spg_id > SPG_ID_AUTO) {
		pr_err_ratelimited("add group failed, invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	if (spg_id >= SPG_ID_AUTO_MIN && spg_id <= SPG_ID_AUTO_MAX) {
		spg = sp_group_get(tgid, spg_id);

		if (!spg) {
			pr_err_ratelimited("spg %d hasn't been created\n", spg_id);
			return -EINVAL;
		}

		down_read(&spg->rw_lock);
		if (!spg_valid(spg)) {
			up_read(&spg->rw_lock);
			pr_err_ratelimited("add group failed, group id %d is dead\n", spg_id);
			sp_group_put(spg);
			return -EINVAL;
		}
		up_read(&spg->rw_lock);

		sp_group_put(spg);
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

	ret = get_task(tgid, &tsk);
	if (ret) {
		up_write(&sp_group_sem);
		free_new_spg_id(id_newly_generated, spg_id);
		goto out;
	}

	if (check_aoscore_process(tsk)) {
		up_write(&sp_group_sem);
		ret = -EACCES;
		free_new_spg_id(id_newly_generated, spg_id);
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

	if (mm->sp_group_master && mm->sp_group_master->tgid != tgid) {
		up_write(&sp_group_sem);
		pr_err("add: task(%d) is a vfork child of the original task(%d)\n",
			tgid, mm->sp_group_master->tgid);
		ret = -EINVAL;
		free_new_spg_id(id_newly_generated, spg_id);
		goto out_put_mm;
	}

	spg = find_or_alloc_sp_group(spg_id, flag);
	if (IS_ERR(spg)) {
		up_write(&sp_group_sem);
		ret = PTR_ERR(spg);
		free_new_spg_id(id_newly_generated, spg_id);
		goto out_put_mm;
	}

	down_write(&spg->rw_lock);
	ret = mm_add_group_init(tsk, mm, spg);
	if (ret) {
		up_write(&spg->rw_lock);
		goto out_drop_group;
	}

	ret = sp_mapping_group_setup(mm, spg);
	if (ret) {
		up_write(&spg->rw_lock);
		goto out_drop_group;
	}

	node = group_add_task(mm, spg, prot);
	if (unlikely(IS_ERR(node))) {
		up_write(&spg->rw_lock);
		ret = PTR_ERR(node);
		goto out_drop_group;
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
		unsigned long prot_spa = prot;

		if ((spa->flags & (SP_PROT_RO | SP_PROT_FOCUS)) == (SP_PROT_RO | SP_PROT_FOCUS))
			prot_spa &= ~PROT_WRITE;

		__sp_area_drop_locked(prev);
		prev = spa;

		atomic_inc(&spa->use_count);

		if (spa->is_dead == true)
			continue;

		spin_unlock(&sp_area_lock);

		if (spa->type == SPA_TYPE_K2SPG && spa->kva) {
			addr = sp_remap_kva_to_vma(spa, mm, prot_spa, NULL);
			if (IS_ERR_VALUE(addr))
				pr_warn("add group remap k2u failed %ld\n", addr);

			spin_lock(&sp_area_lock);
			continue;
		}

		down_write(&mm->mmap_lock);
		if (unlikely(mm->core_state)) {
			sp_munmap_task_areas(mm, spg, &spa->link);
			up_write(&mm->mmap_lock);
			ret = -EBUSY;
			pr_err("add group: encountered coredump, abort\n");
			spin_lock(&sp_area_lock);
			break;
		}

		addr = sp_mmap(mm, file, spa, &populate, prot_spa, NULL);
		if (IS_ERR_VALUE(addr)) {
			sp_munmap_task_areas(mm, spg, &spa->link);
			up_write(&mm->mmap_lock);
			ret = addr;
			pr_err("add group: sp mmap failed %d\n", ret);
			spin_lock(&sp_area_lock);
			break;
		}
		up_write(&mm->mmap_lock);

		if (populate) {
			ret = do_mm_populate(mm, spa->va_start, populate, 0);
			if (ret) {
				if (unlikely(fatal_signal_pending(current)))
					pr_warn_ratelimited("add group failed, current thread is killed\n");
				else
					pr_warn_ratelimited("add group failed, mm populate failed (potential no enough memory when -12): %d, spa type is %d\n",
					ret, spa->type);
				down_write(&mm->mmap_lock);
				sp_munmap_task_areas(mm, spg, spa->link.next);
				up_write(&mm->mmap_lock);
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
		sp_group_put(spg);
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

/**
 * mg_sp_group_del_task() - delete a process from a sp group.
 * @tgid: the tgid of the task to be deleted
 * @spg_id: sharepool group id
 *
 * the group's spa list must be empty, or deletion will fail.
 *
 * Return:
 * * if success, return 0.
 * * -EINVAL, spg_id invalid or spa_lsit not emtpy or spg dead
 * * -ESRCH, the task group of tgid is not in group / process dead
 */
int mg_sp_group_del_task(int tgid, int spg_id)
{
	int ret = 0;
	struct sp_group *spg;
	struct sp_group_node *spg_node;
	struct task_struct *tsk = NULL;
	struct mm_struct *mm = NULL;
	bool is_alive = true;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	if (spg_id < SPG_ID_MIN || spg_id > SPG_ID_AUTO) {
		pr_err("del from group failed, invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	spg = sp_group_get(tgid, spg_id);
	if (!spg) {
		pr_err("spg not found or get task failed, tgid:%d, spg_id:%d\n",
			tgid, spg_id);
		return -EINVAL;
	}
	down_write(&sp_group_sem);

	if (!spg_valid(spg)) {
		up_write(&sp_group_sem);
		pr_err("spg dead, spg_id:%d\n", spg_id);
		ret = -EINVAL;
		goto out;
	}

	ret = get_task(tgid, &tsk);
	if (ret) {
		up_write(&sp_group_sem);
		pr_err("task is not found, tgid:%d\n", tgid);
		goto out;
	}
	mm = get_task_mm(tsk->group_leader);
	if (!mm) {
		up_write(&sp_group_sem);
		pr_err("mm is not found, tgid:%d\n", tgid);
		ret = -ESRCH;
		goto out_put_task;
	}

	if (!mm->sp_group_master) {
		up_write(&sp_group_sem);
		pr_err("task(%d) is not in any group(%d)\n", tgid, spg_id);
		ret = -EINVAL;
		goto out_put_mm;
	}

	if (mm->sp_group_master->tgid != tgid) {
		up_write(&sp_group_sem);
		pr_err("del: task(%d) is a vfork child of the original task(%d)\n",
			tgid, mm->sp_group_master->tgid);
		ret = -EINVAL;
		goto out_put_mm;
	}

	spg_node = find_spg_node_by_spg(mm, spg);
	if (!spg_node) {
		up_write(&sp_group_sem);
		pr_err("task(%d) not in group(%d)\n", tgid, spg_id);
		ret = -ESRCH;
		goto out_put_mm;
	}

	down_write(&spg->rw_lock);

	if (!list_empty(&spg->spa_list)) {
		up_write(&spg->rw_lock);
		up_write(&sp_group_sem);
		pr_err("spa is not empty, task:%d, spg_id:%d\n", tgid, spg_id);
		ret = -EINVAL;
		goto out_put_mm;
	}

	if (list_is_singular(&spg->procs))
		is_alive = spg->is_alive = false;
	delete_spg_node(spg, spg_node);
	sp_group_put(spg);
	up_write(&spg->rw_lock);
	if (!is_alive)
		blocking_notifier_call_chain(&sp_notifier_chain, 0, spg);

	list_del(&spg_node->group_node);
	mm->sp_group_master->count--;
	kfree(spg_node);
	atomic_dec(&mm->mm_users);

	up_write(&sp_group_sem);

out_put_mm:
	mmput(mm);
out_put_task:
	put_task_struct(tsk);
out:
	sp_group_put(spg); /* if spg dead, freed here */
	return ret;
}
EXPORT_SYMBOL_GPL(mg_sp_group_del_task);

int mg_sp_id_of_current(void)
{
	int ret, spg_id;
	struct sp_group_master *master;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	if ((current->flags & PF_KTHREAD) || !current->mm)
		return -EINVAL;

	down_read(&sp_group_sem);
	master = current->mm->sp_group_master;
	if (master) {
		spg_id = master->local->id;
		up_read(&sp_group_sem);
		return spg_id;
	}
	up_read(&sp_group_sem);

	down_write(&sp_group_sem);
	ret = sp_init_group_master_locked(current, current->mm);
	if (ret) {
		up_write(&sp_group_sem);
		return ret;
	}
	master = current->mm->sp_group_master;
	spg_id = master->local->id;
	up_write(&sp_group_sem);

	return spg_id;
}
EXPORT_SYMBOL_GPL(mg_sp_id_of_current);

/* the caller must hold sp_area_lock */
static void insert_sp_area(struct sp_mapping *spm, struct sp_area *spa)
{
	struct rb_node **p = &spm->area_root.rb_node;
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
	rb_insert_color(&spa->rb_node, &spm->area_root);
}

/**
 * sp_alloc_area() - Allocate a region of VA from the share pool.
 * @size: the size of VA to allocate.
 * @flags: how to allocate the memory.
 * @spg: the share group that the memory is allocated to.
 * @type: the type of the region.
 * @applier: the tgid of the task which allocates the region.
 *
 * Return: a valid pointer for success, NULL on failure.
 */
static struct sp_area *sp_alloc_area(unsigned long size, unsigned long flags,
				     struct sp_group *spg, enum spa_type type,
				     pid_t applier)
{
	struct sp_area *spa, *first, *err;
	struct rb_node *n;
	unsigned long vstart;
	unsigned long vend;
	unsigned long addr;
	unsigned long size_align = ALIGN(size, PMD_SIZE); /* va aligned to 2M */
	int device_id, node_id;
	struct sp_mapping *mapping;

	device_id = sp_flags_device_id(flags);
	node_id = flags & SP_SPEC_NODE_ID ? sp_flags_node_id(flags) : device_id;

	if (!is_online_node_id(node_id)) {
		pr_err_ratelimited("invalid numa node id %d\n", node_id);
		return ERR_PTR(-EINVAL);
	}

	if (flags & SP_PROT_FOCUS) {
		if ((flags & (SP_DVPP | SP_PROT_RO)) != SP_PROT_RO) {
			pr_err("invalid sp_flags [%lx]\n", flags);
			return ERR_PTR(-EINVAL);
		}
		mapping = spg->mapping[SP_MAPPING_RO];
	} else if (flags & SP_DVPP) {
		mapping = spg->mapping[SP_MAPPING_DVPP];
	} else {
		mapping = spg->mapping[SP_MAPPING_NORMAL];
	}

	if (!mapping) {
		pr_err_ratelimited("non DVPP spg, id %d\n", spg->id);
		return ERR_PTR(-EINVAL);
	}

	vstart = mapping->start[device_id];
	vend = mapping->end[device_id];
	spa = __kmalloc_node(sizeof(struct sp_area), GFP_KERNEL, node_id);
	if (unlikely(!spa))
		return ERR_PTR(-ENOMEM);

	spin_lock(&sp_area_lock);

	/*
	 * Invalidate cache if we have more permissive parameters.
	 * cached_hole_size notes the largest hole noticed _below_
	 * the sp_area cached in free_area_cache: if size fits
	 * into that hole, we want to scan from vstart to reuse
	 * the hole instead of allocating above free_area_cache.
	 * Note that sp_free_area may update free_area_cache
	 * without updating cached_hole_size.
	 */
	if (!mapping->free_area_cache || size_align < mapping->cached_hole_size ||
	    vstart != mapping->cached_vstart) {
		mapping->cached_hole_size = 0;
		mapping->free_area_cache = NULL;
	}

	/* record if we encounter less permissive parameters */
	mapping->cached_vstart = vstart;

	/* find starting point for our search */
	if (mapping->free_area_cache) {
		first = rb_entry(mapping->free_area_cache, struct sp_area, rb_node);
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

		n = mapping->area_root.rb_node;
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
		if (addr + mapping->cached_hole_size < first->va_start)
			mapping->cached_hole_size = first->va_start - addr;
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
	spa->preferred_node_id = node_id;
	spa->device_id = device_id;

	insert_sp_area(mapping, spa);
	mapping->free_area_cache = &spa->rb_node;
	list_add_tail(&spa->link, &spg->spa_list);

	spin_unlock(&sp_area_lock);

	spa_inc_usage(spa);
	return spa;

error:
	spin_unlock(&sp_area_lock);
	kfree(spa);
	return err;
}

/* the caller should hold sp_area_lock */
static struct sp_area *find_sp_area_locked(struct sp_group *spg,
		unsigned long addr)
{
	struct sp_mapping *spm = sp_mapping_find(spg, addr);
	struct rb_node *n = spm->area_root.rb_node;
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

static struct sp_area *get_sp_area(struct sp_group *spg, unsigned long addr)
{
	struct sp_area *n;

	spin_lock(&sp_area_lock);
	n = find_sp_area_locked(spg, addr);
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
	unsigned long addr = spa->va_start;
	struct sp_mapping *spm;

	lockdep_assert_held(&sp_area_lock);

	spm = sp_mapping_find(spa->spg, addr);
	if (spm->free_area_cache) {
		struct sp_area *cache;

		cache = rb_entry(spm->free_area_cache, struct sp_area, rb_node);
		if (spa->va_start <= cache->va_start) {
			spm->free_area_cache = rb_prev(&spa->rb_node);
			/*
			 * the new cache node may be changed to another region,
			 * i.e. from DVPP region to normal region
			 */
			if (spm->free_area_cache) {
				cache = rb_entry(spm->free_area_cache,
						 struct sp_area, rb_node);
				spm->cached_vstart = cache->region_vstart;
			}
			/*
			 * We don't try to update cached_hole_size,
			 * but it won't go very wrong.
			 */
		}
	}

	if (spa->kva && !vmalloc_area_clr_flag(spa->kva, VM_SHAREPOOL))
		pr_debug("clear spa->kva %ld is not valid\n", spa->kva);

	spa_dec_usage(spa);
	list_del(&spa->link);

	rb_erase(&spa->rb_node, &spm->area_root);
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
	if (!(vma->vm_flags & VM_SHARE_POOL))
		return;

	/*
	 * Considering a situation where task A and B are in the same spg.
	 * A is exiting and calling remove_vma() -> ... -> sp_area_drop().
	 * Concurrently, B is calling sp_free() to free the same spa.
	 * find_sp_area_locked() and __sp_area_drop_locked() should be
	 * an atomic operation.
	 */
	spin_lock(&sp_area_lock);
	__sp_area_drop_locked(vma->vm_private_data);
	spin_unlock(&sp_area_lock);
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

	down_write(&mm->mmap_lock);
	if (unlikely(mm->core_state)) {
		up_write(&mm->mmap_lock);
		pr_info("munmap: encoutered coredump\n");
		return;
	}

	err = do_munmap(mm, addr, size, NULL);
	/* we are not supposed to fail */
	if (err)
		pr_err("failed to unmap VA %pK when sp munmap\n", (void *)addr);

	up_write(&mm->mmap_lock);
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
	down_read(&spa->spg->rw_lock);
	__sp_free(spa->spg, spa->va_start, spa_size(spa), NULL);
	sp_fallocate(spa);
	up_read(&spa->spg->rw_lock);
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
	int spg_id;
};

/* when success, __sp_area_drop(spa) should be used */
static int sp_free_get_spa(struct sp_free_context *fc)
{
	int ret = 0;
	unsigned long addr = fc->addr;
	struct sp_area *spa;
	struct sp_group *spg;

	spg = sp_group_get(current->tgid, fc->spg_id);
	if (!spg) {
		pr_debug("sp free get group failed %d\n", fc->spg_id);
		return -EINVAL;
	}

	fc->state = FREE_CONT;

	spa = get_sp_area(spg, addr);
	sp_group_put(spg);
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

	if (!current->mm)
		goto check_spa;

	ret = sp_check_caller_permission(spa->spg, current->mm);
	if (ret < 0)
		goto drop_spa;

check_spa:
	if (is_local_group(spa->spg->id) && (current->tgid != spa->applier)) {
		ret = -EPERM;
		goto drop_spa;
	}

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

	return 0;

drop_spa:
	__sp_area_drop(spa);
	return ret;
}

/**
 * mg_sp_free() - Free the memory allocated by mg_sp_alloc() or
 * mg_sp_alloc_nodemask().
 *
 * @addr: the starting VA of the memory.
 * @id: Address space identifier, which is used to distinguish the addr.
 *
 * Return:
 * * 0		- success.
 * * -EINVAL	- the memory can't be found or was not allocted by share pool.
 * * -EPERM	- the caller has no permision to free the memory.
 */
int mg_sp_free(unsigned long addr, int id)
{
	int ret = 0;
	struct sp_free_context fc = {
		.addr = addr,
		.spg_id = id,
	};

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	check_interrupt_context();

	if (current->flags & PF_KTHREAD)
		return -EINVAL;

	ret = sp_free_get_spa(&fc);
	if (ret || fc.state == FREE_END)
		goto out;

	sp_free_unmap_fallocate(fc.spa);

	if (current->mm != NULL)
		sp_update_process_stat(current, false, fc.spa);

	__sp_area_drop(fc.spa);  /* match get_sp_area in sp_free_get_spa */
out:
	return ret;
}
EXPORT_SYMBOL_GPL(mg_sp_free);

/* wrapper of __do_mmap() and the caller must hold down_write(&mm->mmap_lock). */
static unsigned long sp_mmap(struct mm_struct *mm, struct file *file,
			     struct sp_area *spa, unsigned long *populate,
			     unsigned long prot, struct vm_area_struct **pvma)
{
	unsigned long addr = spa->va_start;
	unsigned long size = spa_size(spa);
	unsigned long flags = MAP_FIXED | MAP_SHARED | MAP_POPULATE |
			      MAP_SHARE_POOL;
	unsigned long vm_flags = VM_NORESERVE | VM_SHARE_POOL | VM_DONTCOPY;
	unsigned long pgoff = addr_offset(spa) >> PAGE_SHIFT;
	struct vm_area_struct *vma;

	atomic_inc(&spa->use_count);
	addr = __do_mmap_mm(mm, file, addr, size, prot, flags, vm_flags, pgoff,
			 populate, NULL);
	if (IS_ERR_VALUE(addr)) {
		atomic_dec(&spa->use_count);
		pr_err("do_mmap fails %ld\n", addr);
	} else {
		BUG_ON(addr != spa->va_start);
		vma = find_vma(mm, addr);
		vma->vm_private_data = spa;
		if (pvma)
			*pvma = vma;
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
	bool have_mbind;
	enum spa_type type;
};

static int sp_alloc_prepare(unsigned long size, unsigned long sp_flags,
	int spg_id, struct sp_alloc_context *ac)
{
	struct sp_group *spg;

	check_interrupt_context();

	if (current->flags & PF_KTHREAD) {
		pr_err_ratelimited("allocation failed, task is kthread\n");
		return -EINVAL;
	}

	if (unlikely(!size || (size >> PAGE_SHIFT) > totalram_pages())) {
		pr_err_ratelimited("allocation failed, invalid size %lu\n", size);
		return -EINVAL;
	}

	if (spg_id != SPG_ID_DEFAULT && (spg_id < SPG_ID_MIN || spg_id >= SPG_ID_AUTO)) {
		pr_err_ratelimited("allocation failed, invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	if (sp_flags & (~SP_FLAG_MASK)) {
		pr_err_ratelimited("allocation failed, invalid flag %lx\n", sp_flags);
		return -EINVAL;
	}

	if (sp_flags & SP_HUGEPAGE_ONLY)
		sp_flags |= SP_HUGEPAGE;

	if (spg_id != SPG_ID_DEFAULT) {
		spg = sp_group_get(current->tgid, spg_id);
		if (!spg) {
			pr_err_ratelimited("allocation failed, can't find group\n");
			return -ENODEV;
		}

		/* up_read will be at the end of sp_alloc */
		down_read(&spg->rw_lock);
		if (!spg_valid(spg)) {
			up_read(&spg->rw_lock);
			sp_group_put(spg);
			pr_err_ratelimited("allocation failed, spg is dead\n");
			return -ENODEV;
		}

		if (!is_process_in_group(spg, current->mm)) {
			up_read(&spg->rw_lock);
			sp_group_put(spg);
			pr_err_ratelimited("allocation failed, task not in group\n");
			return -ENODEV;
		}
		ac->type = SPA_TYPE_ALLOC;
	} else {  /* allocation pass through scene */
		spg = sp_get_local_group(current, current->mm);
		if (IS_ERR(spg))
			return PTR_ERR(spg);
		down_read(&spg->rw_lock);
		ac->type = SPA_TYPE_ALLOC_PRIVATE;
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
	ac->have_mbind = false;
	return 0;
}

static void sp_alloc_unmap(struct mm_struct *mm, struct sp_area *spa,
	struct sp_group_node *spg_node)
{
	__sp_free(spa->spg, spa->va_start, spa->real_size, mm);
}

static int sp_alloc_mmap(struct mm_struct *mm, struct sp_area *spa,
	struct sp_group_node *spg_node, struct sp_alloc_context *ac)
{
	int ret = 0;
	unsigned long mmap_addr;
	/* pass through default permission */
	unsigned long prot = PROT_READ | PROT_WRITE;
	unsigned long populate = 0;
	struct vm_area_struct *vma;

	down_write(&mm->mmap_lock);
	if (unlikely(mm->core_state)) {
		up_write(&mm->mmap_lock);
		ac->state = ALLOC_COREDUMP;
		pr_info("allocation encountered coredump\n");
		return -EFAULT;
	}

	if (spg_node)
		prot = spg_node->prot;

	if (ac->sp_flags & SP_PROT_RO)
		prot = PROT_READ;

	/* when success, mmap_addr == spa->va_start */
	mmap_addr = sp_mmap(mm, spa_file(spa), spa, &populate, prot, &vma);
	if (IS_ERR_VALUE(mmap_addr)) {
		up_write(&mm->mmap_lock);
		sp_alloc_unmap(mm, spa, spg_node);
		pr_err("sp mmap in allocation failed %ld\n", mmap_addr);
		return PTR_ERR((void *)mmap_addr);
	}

	if (unlikely(populate == 0)) {
		up_write(&mm->mmap_lock);
		pr_err("allocation sp mmap populate failed\n");
		ret = -EFAULT;
		goto unmap;
	}
	ac->populate = populate;

	if (ac->sp_flags & SP_PROT_RO)
		vma->vm_flags &= ~VM_MAYWRITE;

	/* clean PTE_RDONLY flags or trigger SMMU event */
	if (prot & PROT_WRITE)
		vma->vm_page_prot = __pgprot(((~PTE_RDONLY) & vma->vm_page_prot.pgprot) | PTE_DIRTY);
	up_write(&mm->mmap_lock);

	return ret;

unmap:
	sp_alloc_unmap(list_next_entry(spg_node, proc_node)->master->mm, spa, spg_node);
	return ret;
}

static void sp_alloc_fallback(struct sp_area *spa, struct sp_alloc_context *ac)
{
	if (ac->file == ac->spg->file) {
		ac->state = ALLOC_NOMEM;
		return;
	}

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
	/*
	 * We are not ignoring errors, so if we fail to allocate
	 * physical memory we just return failure, so we won't encounter
	 * page fault later on, and more importantly sp_make_share_u2k()
	 * depends on this feature (and MAP_LOCKED) to work correctly.
	 */
	return do_mm_populate(mm, spa->va_start, ac->populate, 0);
}

static long sp_mbind(struct mm_struct *mm, unsigned long start, unsigned long len,
		nodemask_t *nodemask)
{
	return __do_mbind(start, len, MPOL_BIND, MPOL_F_STATIC_NODES,
			nodemask, MPOL_MF_STRICT, mm);
}

static int __sp_alloc_mmap_populate(struct mm_struct *mm, struct sp_area *spa,
	struct sp_group_node *spg_node, struct sp_alloc_context *ac,
	nodemask_t *nodemask)
{
	int ret;

	ret = sp_alloc_mmap(mm, spa, spg_node, ac);
	if (ret < 0)
		return ret;

	if (!ac->have_mbind) {
		ret = sp_mbind(mm, spa->va_start, spa->real_size, nodemask);
		if (ret < 0) {
			pr_err("cannot bind the memory range to node[%*pbl], err:%d\n",
					nodemask_pr_args(nodemask), ret);
			return ret;
		}
		ac->have_mbind = true;
	}

	ret = sp_alloc_populate(mm, spa, ac);
	if (ret) {
		if (unlikely(fatal_signal_pending(current)))
			pr_warn_ratelimited("allocation failed, current thread is killed\n");
		else
			pr_warn_ratelimited("allocation failed due to mm populate failed(potential no enough memory when -12): %d\n",
					ret);
	}

	return ret;
}

static int sp_alloc_mmap_populate(struct sp_area *spa,
				  struct sp_alloc_context *ac,
				  nodemask_t *nodemask)
{
	int ret = -EINVAL;
	int mmap_ret = 0;
	struct mm_struct *mm, *end_mm = NULL;
	struct sp_group_node *spg_node;
	nodemask_t __nodemask;

	if (!nodemask) { /* mg_sp_alloc */
		nodes_clear(__nodemask);
		node_set(spa->preferred_node_id, __nodemask);
	} else /* mg_sp_alloc_nodemask */
		__nodemask = *nodemask;

	/* create mapping for each process in the group */
	list_for_each_entry(spg_node, &spa->spg->procs, proc_node) {
		mm = spg_node->master->mm;
		mmap_ret = __sp_alloc_mmap_populate(mm, spa, spg_node, ac, &__nodemask);
		if (mmap_ret) {

			/*
			 * Goto fallback procedure upon ERR_VALUE,
			 * but skip the coredump situation,
			 * because we don't want one misbehaving process to affect others.
			 */
			if (ac->state != ALLOC_COREDUMP)
				goto unmap;

			/* Reset state and discard the coredump error. */
			ac->state = ALLOC_NORMAL;
			continue;
		}
		ret = mmap_ret;
	}

	return ret;

unmap:
	/* use the next mm in proc list as end mark */
	if (!list_is_last(&spg_node->proc_node, &spa->spg->procs))
		end_mm = list_next_entry(spg_node, proc_node)->master->mm;
	sp_alloc_unmap(end_mm, spa, spg_node);

	/*
	 * Sometimes do_mm_populate() allocates some memory and then failed to
	 * allocate more. (e.g. memory use reaches cgroup limit.)
	 * In this case, it will return enomem, but will not free the
	 * memory which has already been allocated.
	 *
	 * So if __sp_alloc_mmap_populate fails, always call sp_fallocate()
	 * to make sure backup physical memory of the shared file is freed.
	 */
	sp_fallocate(spa);

	/* if hugepage allocation fails, this will transfer to normal page
	 * and try again. (only if SP_HUGEPAGE_ONLY is not flagged */
	sp_alloc_fallback(spa, ac);

	return mmap_ret;
}

/* spa maybe an error pointer, so introduce variable spg */
static void sp_alloc_finish(int result, struct sp_area *spa,
		struct sp_alloc_context *ac)
{
	struct sp_group *spg = ac->spg;

	/* match sp_alloc_prepare */
	up_read(&spg->rw_lock);

	if (!result)
		sp_update_process_stat(current, true, spa);

	/* this will free spa if mmap failed */
	if (spa && !IS_ERR(spa))
		__sp_area_drop(spa);

	sp_group_put(spg);
}

void *__mg_sp_alloc_nodemask(unsigned long size, unsigned long sp_flags, int spg_id,
		nodemask_t *nodemask)
{
	struct sp_area *spa = NULL;
	int ret = 0;
	struct sp_alloc_context ac;

	if (!sp_is_enabled())
		return ERR_PTR(-EOPNOTSUPP);

	ret = sp_alloc_prepare(size, sp_flags, spg_id, &ac);
	if (ret)
		return ERR_PTR(ret);

try_again:
	spa = sp_alloc_area(ac.size_aligned, ac.sp_flags, ac.spg,
			    ac.type, current->tgid);
	if (IS_ERR(spa)) {
		pr_err_ratelimited("alloc spa failed in allocation(potential no enough virtual memory when -75): %ld\n",
			PTR_ERR(spa));
		ret = PTR_ERR(spa);
		goto out;
	}

	ret = sp_alloc_mmap_populate(spa, &ac, nodemask);
	if (ret && ac.state == ALLOC_RETRY) {
		/*
		 * The mempolicy for shared memory is located at backend file, which varies
		 * between normal pages and huge pages. So we should set the mbind policy again
		 * when we retry using normal pages.
		 */
		ac.have_mbind = false;
		goto try_again;
	}

out:
	sp_alloc_finish(ret, spa, &ac);
	if (ret)
		return ERR_PTR(ret);
	else
		return (void *)(spa->va_start);
}

void *mg_sp_alloc_nodemask(unsigned long size, unsigned long sp_flags, int spg_id,
		nodemask_t nodemask)
{
	return __mg_sp_alloc_nodemask(size, sp_flags, spg_id, &nodemask);
}
EXPORT_SYMBOL_GPL(mg_sp_alloc_nodemask);

/**
 * mg_sp_alloc() - Allocate shared memory for all the processes in a sp_group.
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
void *mg_sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id)
{
	return __mg_sp_alloc_nodemask(size, sp_flags, spg_id, NULL);
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
	unsigned long pfn = -EINVAL;

	/* sp_make_share_k2u only support vmalloc address */
	if (is_vmalloc_addr((void *)kva))
		pfn = vmalloc_to_pfn((void *)kva);

	return pfn;
}

/* when called by k2u to group, always make sure rw_lock of spg is down */
static unsigned long sp_remap_kva_to_vma(struct sp_area *spa, struct mm_struct *mm,
					unsigned long prot, struct sp_k2u_context *kc)
{
	struct vm_area_struct *vma;
	unsigned long ret_addr;
	unsigned long populate = 0;
	int ret = 0;
	unsigned long addr, buf, offset;
	unsigned long kva = spa->kva;

	down_write(&mm->mmap_lock);
	if (unlikely(mm->core_state)) {
		pr_err("k2u mmap: encountered coredump, abort\n");
		ret_addr = -EBUSY;
		if (kc)
			kc->state = K2U_COREDUMP;
		goto put_mm;
	}

	if (kc && (kc->sp_flags & SP_PROT_RO))
		prot = PROT_READ;

	ret_addr = sp_mmap(mm, spa_file(spa), spa, &populate, prot, &vma);
	if (IS_ERR_VALUE(ret_addr)) {
		pr_debug("k2u mmap failed %lx\n", ret_addr);
		goto put_mm;
	}

	if (prot & PROT_WRITE)
		vma->vm_page_prot = __pgprot(((~PTE_RDONLY) & vma->vm_page_prot.pgprot) | PTE_DIRTY);

	if (kc && (kc->sp_flags & SP_PROT_RO))
		vma->vm_flags &= ~VM_MAYWRITE;

	if (is_vm_hugetlb_page(vma)) {
		ret = remap_vmalloc_hugepage_range(vma, (void *)kva, 0);
		if (ret) {
			do_munmap(mm, ret_addr, spa_size(spa), NULL);
			pr_debug("remap vmalloc hugepage failed, ret %d, kva is %lx\n",
				 ret, (unsigned long)kva);
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
	up_write(&mm->mmap_lock);

	return ret_addr;
}

/**
 * Share kernel memory to a spg, the current process must be in that group
 * @kc: the context for k2u, including kva, size, flags...
 * @spg: the sp group to be shared with
 *
 * Return: the shared user address to start at
 */
static void *sp_make_share_kva_to_spg(struct sp_k2u_context *kc, struct sp_group *spg)
{
	struct sp_area *spa;
	struct mm_struct *mm;
	struct sp_group_node *spg_node;
	unsigned long ret_addr = -ENODEV;

	down_read(&spg->rw_lock);
	spa = sp_alloc_area(kc->size_aligned, kc->sp_flags, spg, kc->type, current->tgid);
	if (IS_ERR(spa)) {
		up_read(&spg->rw_lock);
		pr_err("alloc spa failed in k2u_spg (potential no enough virtual memory when -75): %ld\n",
				PTR_ERR(spa));
		return spa;
	}

	spa->kva = kc->kva_aligned;
	list_for_each_entry(spg_node, &spg->procs, proc_node) {
		mm = spg_node->master->mm;
		kc->state = K2U_NORMAL;
		ret_addr = sp_remap_kva_to_vma(spa, mm, spg_node->prot, kc);
		if (IS_ERR_VALUE(ret_addr)) {
			if (kc->state == K2U_COREDUMP)
				continue;
			pr_err("remap k2u to spg failed %ld\n", ret_addr);
			__sp_free(spg, spa->va_start, spa_size(spa), mm);
			goto out;
		}
	}

out:
	up_read(&spg->rw_lock);
	if (!IS_ERR_VALUE(ret_addr))
		sp_update_process_stat(current, true, spa);
	__sp_area_drop(spa);

	return (void *)ret_addr;
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

static int sp_k2u_prepare(unsigned long kva, unsigned long size,
	unsigned long sp_flags, int spg_id, struct sp_k2u_context *kc)
{
	int is_hugepage;
	unsigned int page_size = PAGE_SIZE;
	unsigned long kva_aligned, size_aligned;

	if (!size) {
		pr_err_ratelimited("k2u input size is 0.\n");
		return -EINVAL;
	}

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

	kc->kva          = kva;
	kc->kva_aligned  = kva_aligned;
	kc->size         = size;
	kc->size_aligned = size_aligned;
	kc->sp_flags     = sp_flags;
	kc->type         = (spg_id == SPG_ID_DEFAULT || spg_id == SPG_ID_NONE)
				? SPA_TYPE_K2TASK : SPA_TYPE_K2SPG;

	return 0;
}

static void *sp_k2u_finish(void *uva, struct sp_k2u_context *kc)
{
	if (IS_ERR(uva))
		vmalloc_area_clr_flag(kc->kva_aligned, VM_SHAREPOOL);
	else
		uva = uva + (kc->kva - kc->kva_aligned);

	return uva;
}

/**
 * mg_sp_make_share_k2u() - Share kernel memory to current process or an sp_group.
 * @kva: the VA of shared kernel memory.
 * @size: the size of shared kernel memory.
 * @sp_flags: how to allocate the memory. We only support SP_DVPP.
 * @tgid:  the tgid of the specified process (Not currently in use).
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
void *mg_sp_make_share_k2u(unsigned long kva, unsigned long size,
			unsigned long sp_flags, int tgid, int spg_id)
{
	void *uva;
	int ret;
	struct sp_k2u_context kc;
	struct sp_group *spg;

	if (!sp_is_enabled())
		return ERR_PTR(-EOPNOTSUPP);

	check_interrupt_context();

	ret = sp_k2u_prepare(kva, size, sp_flags, spg_id, &kc);
	if (ret)
		return ERR_PTR(ret);

	if (kc.type == SPA_TYPE_K2TASK) {
		down_write(&sp_group_sem);
		ret = sp_init_group_master_locked(current, current->mm);
		up_write(&sp_group_sem);
		if (ret) {
			pr_err("k2u_task init local mapping failed %d\n", ret);
			uva = ERR_PTR(ret);
			goto out;
		}
		/* the caller could use SPG_ID_NONE */
		spg_id = SPG_ID_DEFAULT;
	}

	spg = sp_group_get(current->tgid, spg_id);
	if (spg) {
		ret = sp_check_caller_permission(spg, current->mm);
		if (ret < 0) {
			sp_group_put(spg);
			uva = ERR_PTR(ret);
			goto out;
		}
		uva = sp_make_share_kva_to_spg(&kc, spg);
		sp_group_put(spg);
	} else {
		uva = ERR_PTR(-ENODEV);
	}

out:
	return sp_k2u_finish(uva, &kc);
}
EXPORT_SYMBOL_GPL(mg_sp_make_share_k2u);

static int sp_pmd_entry(pmd_t *pmd, unsigned long addr,
			unsigned long next, struct mm_walk *walk)
{
	struct page *page;
	struct sp_walk_data *sp_walk_data = walk->private;

	/*
	 * There exist a scene in DVPP where the pagetable is huge page but its
	 * vma doesn't record it, something like THP.
	 * So we cannot make out whether it is a hugepage map until we access the
	 * pmd here. If mixed size of pages appear, just return an error.
	 */
	if (pmd_huge(*pmd)) {
		if (!sp_walk_data->is_page_type_set) {
			sp_walk_data->is_page_type_set = true;
			sp_walk_data->is_hugepage = true;
		} else if (!sp_walk_data->is_hugepage) {
			return -EFAULT;
		}

		/* To skip pte level walk */
		walk->action = ACTION_CONTINUE;

		page = pmd_page(*pmd);
		get_page(page);
		sp_walk_data->pages[sp_walk_data->page_count++] = page;

		return 0;
	}

	if (!sp_walk_data->is_page_type_set) {
		sp_walk_data->is_page_type_set = true;
		sp_walk_data->is_hugepage = false;
	} else if (sp_walk_data->is_hugepage)
		return -EFAULT;

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

	sp_walk_data->is_page_type_set = false;
	sp_walk_data->page_count = 0;
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
	if (ret) {
		while (sp_walk_data->page_count--)
			put_page(pages[sp_walk_data->page_count]);
		kvfree(pages);
		sp_walk_data->pages = NULL;
	}

	if (sp_walk_data->is_hugepage)
		sp_walk_data->uva_aligned = ALIGN_DOWN(uva, PMD_SIZE);

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
 * mg_sp_make_share_u2k() - Share user memory of a specified process to kernel.
 * @uva: the VA of shared user memory
 * @size: the size of shared user memory
 * @tgid: the tgid of the specified process(Not currently in use)
 *
 * Return:
 * * if success, return the starting kernel address of the shared memory.
 * * if failed, return the pointer of -errno.
 */
void *mg_sp_make_share_u2k(unsigned long uva, unsigned long size, int tgid)
{
	int ret = 0;
	struct mm_struct *mm = current->mm;
	void *p = ERR_PTR(-ESRCH);
	struct sp_walk_data sp_walk_data;
	struct vm_struct *area;

	if (!sp_is_enabled())
		return ERR_PTR(-EOPNOTSUPP);

	check_interrupt_context();

	if (mm == NULL) {
		pr_err("u2k: kthread is not allowed\n");
		return ERR_PTR(-EPERM);
	}

	down_write(&mm->mmap_lock);
	if (unlikely(mm->core_state)) {
		up_write(&mm->mmap_lock);
		pr_err("u2k: encountered coredump, abort\n");
		return p;
	}

	ret = __sp_walk_page_range(uva, size, mm, &sp_walk_data);
	if (ret) {
		pr_err_ratelimited("walk page range failed %d\n", ret);
		up_write(&mm->mmap_lock);
		return ERR_PTR(ret);
	}

	if (sp_walk_data.is_hugepage)
		p = vmap_hugepage(sp_walk_data.pages, sp_walk_data.page_count,
				  VM_MAP, PAGE_KERNEL);
	else
		p = vmap(sp_walk_data.pages, sp_walk_data.page_count, VM_MAP,
			 PAGE_KERNEL);
	up_write(&mm->mmap_lock);

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
EXPORT_SYMBOL_GPL(mg_sp_make_share_u2k);

/*
 * sp_unshare_uva - unshare a uva from sp_make_share_k2u
 * @uva: the uva to be unshared
 * @size: not used actually and we just check it
 * @group_id: specify the spg of the uva; for local group, it can be SPG_ID_DEFAULT
 *            unless current process is exiting.
 *
 * Procedure of unshare uva must be compatible with:
 *
 * 1. DVPP channel destroy procedure:
 * do_exit() -> exit_mm() (mm no longer in spg and current->mm == NULL) ->
 * exit_task_work() -> task_work_run() -> __fput() -> ... -> vdec_close() ->
 * sp_unshare(uva, local_spg_id)
 */
static int sp_unshare_uva(unsigned long uva, unsigned long size, int group_id)
{
	int ret = 0;
	struct sp_area *spa;
	unsigned int page_size;
	struct sp_group *spg;

	spg = sp_group_get(current->tgid, group_id);
	if (!spg) {
		pr_err("sp unshare find group failed %d\n", group_id);
		return -EINVAL;
	}

	/* All the spa are aligned to 2M. */
	spa = get_sp_area(spg, ALIGN_DOWN(uva, PMD_SIZE));
	if (!spa) {
		ret = -EINVAL;
		pr_err("invalid input uva %lx in unshare uva\n", (unsigned long)uva);
		goto out;
	}

	if (spa->type != SPA_TYPE_K2TASK && spa->type != SPA_TYPE_K2SPG) {
		pr_err("unshare wrong type spa\n");
		ret = -EINVAL;
		goto out_drop_area;
	}
	/*
	 * 1. overflow actually won't happen due to an spa must be valid.
	 * 2. we must unshare [spa->va_start, spa->va_start + spa->real_size) completely
	 *    because an spa is one-to-one correspondence with an vma.
	 *    Thus input parameter size is not necessarily needed.
	 */
	page_size = (spa->is_hugepage ? PMD_SIZE : PAGE_SIZE);

	if (spa->real_size < ALIGN(size, page_size)) {
		ret = -EINVAL;
		pr_err("unshare uva failed, invalid parameter size %lu\n", size);
		goto out_drop_area;
	}

	down_read(&spa->spg->rw_lock);
	/* always allow dvpp channel destroy procedure */
	if (current->mm && !is_process_in_group(spa->spg, current->mm)) {
		up_read(&spa->spg->rw_lock);
		pr_err("unshare uva failed, caller process doesn't belong to target group\n");
		ret = -EPERM;
		goto out_drop_area;
	}
	up_read(&spa->spg->rw_lock);

	down_write(&spa->spg->rw_lock);
	if (!spg_valid(spa->spg)) {
		up_write(&spa->spg->rw_lock);
		pr_info("no need to unshare uva, sp group of spa is dead\n");
		goto out_clr_flag;
	}
	/* the life cycle of spa has a direct relation with sp group */
	if (unlikely(spa->is_dead)) {
		up_write(&spa->spg->rw_lock);
		pr_err("unexpected double sp unshare\n");
		dump_stack();
		ret = -EINVAL;
		goto out_drop_area;
	}
	spa->is_dead = true;
	up_write(&spa->spg->rw_lock);

	down_read(&spa->spg->rw_lock);
	__sp_free(spa->spg, spa->va_start, spa->real_size, NULL);
	up_read(&spa->spg->rw_lock);

	if (current->mm != NULL)
		sp_update_process_stat(current, false, spa);

out_clr_flag:
	if (!vmalloc_area_clr_flag(spa->kva, VM_SHAREPOOL))
		pr_info("clear spa->kva %ld is not valid\n", spa->kva);
	spa->kva = 0;

out_drop_area:
	__sp_area_drop(spa);
out:
	sp_group_put(spg);
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
 * mg_sp_unshare() - Unshare the kernel or user memory which shared by calling
 *                sp_make_share_{k2u,u2k}().
 * @va: the specified virtual address of memory
 * @size: the size of unshared memory
 *
 * Use spg_id of current thread if spg_id == SPG_ID_DEFAULT.
 *
 * Return: 0 for success, -errno on failure.
 */
int mg_sp_unshare(unsigned long va, unsigned long size, int spg_id)
{
	int ret = 0;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	check_interrupt_context();

	if (current->flags & PF_KTHREAD)
		return -EINVAL;

	if (va < TASK_SIZE) {
		/* user address */
		ret = sp_unshare_uva(va, size, spg_id);
	} else if (va >= PAGE_OFFSET) {
		/* kernel address */
		ret = sp_unshare_kva(va, size);
	} else {
		/* regard user and kernel address ranges as bad address */
		pr_debug("unshare addr %lx is not a user or kernel addr\n", (unsigned long)va);
		ret = -EFAULT;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(mg_sp_unshare);

/**
 * mg_sp_walk_page_range() - Walk page table with caller specific callbacks.
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
int mg_sp_walk_page_range(unsigned long uva, unsigned long size,
	struct task_struct *tsk, struct sp_walk_data *sp_walk_data)
{
	struct mm_struct *mm;
	int ret = 0;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

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

	down_write(&mm->mmap_lock);
	if (likely(!mm->core_state)) {
		ret = __sp_walk_page_range(uva, size, mm, sp_walk_data);
	} else {
		pr_err("walk page range: encoutered coredump\n");
		ret = -ESRCH;
	}
	up_write(&mm->mmap_lock);

	mmput(mm);
	put_task_struct(tsk);

	return ret;
}
EXPORT_SYMBOL_GPL(mg_sp_walk_page_range);

/**
 * mg_sp_walk_page_free() - Free the sp_walk_data structure.
 * @sp_walk_data: a structure of a page pointer array to be freed.
 */
void mg_sp_walk_page_free(struct sp_walk_data *sp_walk_data)
{
	if (!sp_is_enabled())
		return;

	check_interrupt_context();

	if (!sp_walk_data)
		return;

	__sp_walk_page_free(sp_walk_data);
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

static bool is_sp_dynamic_dvpp_addr(unsigned long addr);
/**
 * mg_sp_config_dvpp_range() - User can config the share pool start address
 *                          of each Da-vinci device.
 * @start: the value of share pool start
 * @size: the value of share pool
 * @device_id: the num of Da-vinci device
 * @tgid: the tgid of device process
 *
 * Return true for success.
 * Return false if parameter invalid or has been set up.
 * This functuon has no concurrent problem.
 */
bool mg_sp_config_dvpp_range(size_t start, size_t size, int device_id, int tgid)
{
	int ret;
	bool err = false;
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct sp_group *spg;
	struct sp_mapping *spm;
	unsigned long default_start;

	if (!sp_is_enabled())
		return false;

	/* NOTE: check the start address */
	if (tgid < 0 || size <= 0 || size > MMAP_SHARE_POOL_16G_SIZE ||
	    device_id < 0 || device_id >= MAX_DEVID || !is_online_node_id(device_id)
		|| !is_sp_dynamic_dvpp_addr(start) || !is_sp_dynamic_dvpp_addr(start + size - 1))
		return false;

	ret = get_task(tgid, &tsk);
	if (ret)
		return false;

	mm = get_task_mm(tsk->group_leader);
	if (!mm)
		goto put_task;

	spg = sp_get_local_group(tsk, mm);
	if (IS_ERR(spg))
		goto put_mm;

	spm = spg->mapping[SP_MAPPING_DVPP];
	default_start = MMAP_SHARE_POOL_DVPP_START + device_id * MMAP_SHARE_POOL_16G_SIZE;
	/* The dvpp range of each group can be configured only once */
	if (spm->start[device_id] != default_start)
		goto put_spg;

	spm->start[device_id] = start;
	spm->end[device_id] = start + size;

	err = true;

put_spg:
	sp_group_put(spg);
put_mm:
	mmput(mm);
put_task:
	put_task_struct(tsk);

	return err;
}
EXPORT_SYMBOL_GPL(mg_sp_config_dvpp_range);

static bool is_sp_reserve_addr(unsigned long addr)
{
	return addr >= MMAP_SHARE_POOL_START && addr < MMAP_SHARE_POOL_END;
}

/*
 *	| 16G host | 16G device | ... |     |
 *	^
 *	|
 *	MMAP_SHARE_POOL_DVPP_BASE + 16G * 64
 *	We only check the device regions.
 */
static bool is_sp_dynamic_dvpp_addr(unsigned long addr)
{
	if (addr < MMAP_SHARE_POOL_DYNAMIC_DVPP_BASE || addr >= MMAP_SHARE_POOL_DYNAMIC_DVPP_END)
		return false;

	return (addr - MMAP_SHARE_POOL_DYNAMIC_DVPP_BASE) & MMAP_SHARE_POOL_16G_SIZE;
}

/**
 * mg_is_sharepool_addr() - Check if a user memory address belongs to share pool.
 * @addr: the userspace address to be checked.
 *
 * Return true if addr belongs to share pool, or false vice versa.
 */
bool mg_is_sharepool_addr(unsigned long addr)
{
	return sp_is_enabled() &&
		((is_sp_reserve_addr(addr) || is_sp_dynamic_dvpp_addr(addr)));
}
EXPORT_SYMBOL_GPL(mg_is_sharepool_addr);

int sp_node_id(struct vm_area_struct *vma)
{
	struct sp_area *spa;
	int node_id = numa_node_id();

	if (!sp_is_enabled())
		return node_id;

	if (vma && (vma->vm_flags & VM_SHARE_POOL) && vma->vm_private_data) {
		spa = vma->vm_private_data;
		node_id = spa->preferred_node_id;
	}

	return node_id;
}

/*** Statistical and maintenance functions ***/

static void get_mm_rss_info(struct mm_struct *mm, unsigned long *anon,
	unsigned long *file, unsigned long *shmem, unsigned long *total_rss)
{
	*anon = get_mm_counter(mm, MM_ANONPAGES);
	*file = get_mm_counter(mm, MM_FILEPAGES);
	*shmem = get_mm_counter(mm, MM_SHMEMPAGES);
	*total_rss = *anon + *file + *shmem;
}

static void get_process_sp_res(struct sp_group_master *master,
		long *sp_res_out, long *sp_res_nsize_out)
{
	struct sp_group *spg;
	struct sp_group_node *spg_node;

	*sp_res_out = 0;
	*sp_res_nsize_out = 0;

	list_for_each_entry(spg_node, &master->node_list, group_node) {
		spg = spg_node->spg;
		*sp_res_out += meminfo_alloc_sum_byKB(&spg->meminfo);
		*sp_res_nsize_out += byte2kb(atomic64_read(&spg->meminfo.alloc_nsize));
	}
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

static void print_process_prot(struct seq_file *seq, unsigned long prot)
{
	if (prot == PROT_READ)
		seq_puts(seq, "R");
	else if (prot == (PROT_READ | PROT_WRITE))
		seq_puts(seq, "RW");
	else
		seq_puts(seq, "-");
}

int proc_sp_group_state(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm;
	struct sp_group_master *master;
	struct sp_meminfo *meminfo;
	struct sp_group_node *spg_node;
	unsigned long anon, file, shmem, total_rss;
	long sp_res, sp_res_nsize, non_sp_res, non_sp_shm;

	if (!sp_is_enabled())
		return 0;

	mm = get_task_mm(task);
	if (!mm)
		return 0;

	down_read(&sp_group_sem);
	down_read(&mm->mmap_lock);
	master = mm->sp_group_master;
	if (!master)
		goto out;

	get_mm_rss_info(mm, &anon, &file, &shmem, &total_rss);
	meminfo = &master->meminfo;
	get_process_sp_res(master, &sp_res, &sp_res_nsize);
	get_process_non_sp_res(total_rss, shmem, sp_res_nsize,
			       &non_sp_res, &non_sp_shm);

	seq_puts(m, "Share Pool Aggregate Data of This Process\n\n");
	seq_printf(m, "%-8s %-16s %-9s %-9s %-9s %-10s %-10s %-8s\n",
		   "PID", "COMM", "SP_ALLOC", "SP_K2U", "SP_RES", "Non-SP_RES",
		   "Non-SP_Shm", "VIRT");
	seq_printf(m, "%-8d %-16s %-9ld %-9ld %-9ld %-10ld %-10ld %-8ld\n",
		   master->tgid, master->comm,
		   meminfo_alloc_sum_byKB(meminfo),
		   meminfo_k2u_size(meminfo),
		   sp_res, non_sp_res, non_sp_shm,
		   page2kb(mm->total_vm));

	seq_puts(m, "\n\nProcess in Each SP Group\n\n");
	seq_printf(m, "%-8s %-9s %-9s %-9s %-4s\n",
			"Group_ID", "SP_ALLOC", "SP_K2U", "SP_RES", "PROT");

	list_for_each_entry(spg_node, &master->node_list, group_node) {
		seq_printf(m, "%-8d %-9ld %-9ld %-9ld ",
				spg_node->spg->id,
				meminfo_alloc_sum_byKB(&spg_node->meminfo),
				meminfo_k2u_size(&spg_node->meminfo),
				meminfo_alloc_sum_byKB(&spg_node->spg->meminfo));
		print_process_prot(m, spg_node->prot);
		seq_putc(m, '\n');
	}

out:
	up_read(&mm->mmap_lock);
	up_read(&sp_group_sem);
	mmput(mm);
	return 0;
}

static void spa_stat_of_mapping_show(struct seq_file *seq, struct sp_mapping *spm)
{
	struct rb_node *node;
	struct sp_area *spa, *prev = NULL;

	spin_lock(&sp_area_lock);
	for (node = rb_first(&spm->area_root); node; node = rb_next(node)) {
		__sp_area_drop_locked(prev);

		spa = rb_entry(node, struct sp_area, rb_node);
		prev = spa;
		atomic_inc(&spa->use_count);
		spin_unlock(&sp_area_lock);

		if (spg_valid(spa->spg))  /* k2u to group */
			seq_printf(seq, "%-10d ", spa->spg->id);
		else  /* spg is dead */
			seq_printf(seq, "%-10s ", "Dead");

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

static void spa_ro_stat_show(struct seq_file *seq)
{
	spa_stat_of_mapping_show(seq, sp_mapping_ro);
}

static void spa_normal_stat_show(struct seq_file *seq)
{
	spa_stat_of_mapping_show(seq, sp_mapping_normal);
}

static void spa_dvpp_stat_show(struct seq_file *seq)
{
	struct sp_mapping *spm;

	mutex_lock(&spm_list_lock);
	list_for_each_entry(spm, &spm_dvpp_list, spm_node)
		spa_stat_of_mapping_show(seq, spm);
	mutex_unlock(&spm_list_lock);
}


static void spa_overview_show(struct seq_file *seq)
{
	s64 total_num, alloc_num, k2u_task_num, k2u_spg_num;
	s64 total_size, alloc_size, k2u_task_size, k2u_spg_size;
	s64 dvpp_size, dvpp_va_size;

	if (!sp_is_enabled())
		return;

	alloc_num     = atomic64_read(&spa_stat.alloc_num);
	k2u_task_num  = atomic64_read(&spa_stat.k2u_task_num);
	k2u_spg_num   = atomic64_read(&spa_stat.k2u_spg_num);
	alloc_size    = atomic64_read(&spa_stat.alloc_size);
	k2u_task_size = atomic64_read(&spa_stat.k2u_task_size);
	k2u_spg_size  = atomic64_read(&spa_stat.k2u_spg_size);
	dvpp_size     = atomic64_read(&spa_stat.dvpp_size);
	dvpp_va_size  = atomic64_read(&spa_stat.dvpp_va_size);
	total_num = alloc_num + k2u_task_num + k2u_spg_num;
	total_size = alloc_size + k2u_task_size + k2u_spg_size;

	SEQ_printf(seq, "Spa total num %lld.\n", total_num);
	SEQ_printf(seq, "Spa alloc num %lld, k2u(task) num %lld, k2u(spg) num %lld.\n",
		   alloc_num, k2u_task_num, k2u_spg_num);
	SEQ_printf(seq, "Spa total size:     %13lld KB\n", byte2kb(total_size));
	SEQ_printf(seq, "Spa alloc size:     %13lld KB\n", byte2kb(alloc_size));
	SEQ_printf(seq, "Spa k2u(task) size: %13lld KB\n", byte2kb(k2u_task_size));
	SEQ_printf(seq, "Spa k2u(spg) size:  %13lld KB\n", byte2kb(k2u_spg_size));
	SEQ_printf(seq, "Spa dvpp size:      %13lld KB\n", byte2kb(dvpp_size));
	SEQ_printf(seq, "Spa dvpp va size:   %13lld MB\n", byte2mb(dvpp_va_size));
	SEQ_printf(seq, "\n");
}

static int spg_info_show(int id, void *p, void *data)
{
	struct sp_group *spg = p;
	struct seq_file *seq = data;

	if (id >= SPG_ID_LOCAL_MIN && id <= SPG_ID_LOCAL_MAX)
		return 0;

	SEQ_printf(seq, "Group %6d ", id);

	down_read(&spg->rw_lock);
	SEQ_printf(seq, "size: %lld KB, spa num: %d, total alloc: %ld KB, normal alloc: %lld KB, huge alloc: %lld KB\n",
			byte2kb(meminfo_total_size(&spg->meminfo)),
			atomic_read(&spg->spa_num),
			meminfo_alloc_sum_byKB(&spg->meminfo),
			byte2kb(atomic64_read(&spg->meminfo.alloc_nsize)),
			byte2kb(atomic64_read(&spg->meminfo.alloc_hsize)));
	up_read(&spg->rw_lock);

	return 0;
}

static void spg_overview_show(struct seq_file *seq)
{
	if (!sp_is_enabled())
		return;

	SEQ_printf(seq, "Share pool total size: %lld KB, spa total num: %d.\n",
			byte2kb(atomic64_read(&sp_overall_stat.spa_total_size)),
			atomic_read(&sp_overall_stat.spa_total_num));

	down_read(&sp_group_sem);
	idr_for_each(&sp_group_idr, spg_info_show, seq);
	up_read(&sp_group_sem);

	SEQ_printf(seq, "\n");
}

static bool should_show_statistics(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return false;

	if (task_active_pid_ns(current) != &init_pid_ns)
		return false;

	return true;
}

static int spa_stat_show(struct seq_file *seq, void *offset)
{
	if (!should_show_statistics())
		return -EPERM;

	spg_overview_show(seq);
	spa_overview_show(seq);
	/* print the file header */
	seq_printf(seq, "%-10s %-16s %-16s %-10s %-7s %-5s %-8s %-8s\n",
			"Group ID", "va_start", "va_end", "Size(KB)", "Type", "Huge", "PID", "Ref");
	spa_ro_stat_show(seq);
	spa_normal_stat_show(seq);
	spa_dvpp_stat_show(seq);
	return 0;
}

static int proc_usage_by_group(int id, void *p, void *data)
{
	struct sp_group *spg = p;
	struct seq_file *seq = data;
	struct sp_group_node *spg_node;
	struct mm_struct *mm;
	struct sp_group_master *master;
	int tgid;
	unsigned long anon, file, shmem, total_rss;

	down_read(&spg->rw_lock);
	list_for_each_entry(spg_node, &spg->procs, proc_node) {
		master = spg_node->master;
		mm = master->mm;
		tgid = master->tgid;

		get_mm_rss_info(mm, &anon, &file, &shmem, &total_rss);

		seq_printf(seq, "%-8d ", tgid);
		seq_printf(seq, "%-8d ", id);
		seq_printf(seq, "%-9ld %-9ld %-9ld %-8ld %-7ld %-7ld ",
				meminfo_alloc_sum_byKB(&spg_node->meminfo),
				meminfo_k2u_size(&spg_node->meminfo),
				meminfo_alloc_sum_byKB(&spg_node->spg->meminfo),
				page2kb(mm->total_vm), page2kb(total_rss),
				page2kb(shmem));
		print_process_prot(seq, spg_node->prot);
		seq_putc(seq, '\n');
	}
	up_read(&spg->rw_lock);
	cond_resched();

	return 0;
}

static int proc_group_usage_show(struct seq_file *seq, void *offset)
{
	if (!should_show_statistics())
		return -EPERM;

	spg_overview_show(seq);
	spa_overview_show(seq);

	/* print the file header */
	seq_printf(seq, "%-8s %-8s %-9s %-9s %-9s %-8s %-7s %-7s %-4s\n",
			"PID", "Group_ID", "SP_ALLOC", "SP_K2U", "SP_RES",
			"VIRT", "RES", "Shm", "PROT");

	down_read(&sp_group_sem);
	idr_for_each(&sp_group_idr, proc_usage_by_group, seq);
	up_read(&sp_group_sem);

	return 0;
}

static int proc_usage_show(struct seq_file *seq, void *offset)
{
	struct sp_group_master *master = NULL;
	unsigned long anon, file, shmem, total_rss;
	long sp_res, sp_res_nsize, non_sp_res, non_sp_shm;
	struct sp_meminfo *meminfo;

	if (!should_show_statistics())
		return -EPERM;

	seq_printf(seq, "%-8s %-16s %-9s %-9s %-9s %-10s %-10s %-8s\n",
			"PID", "COMM", "SP_ALLOC", "SP_K2U", "SP_RES", "Non-SP_RES",
			"Non-SP_Shm", "VIRT");

	down_read(&sp_group_sem);
	mutex_lock(&master_list_lock);
	list_for_each_entry(master, &master_list, list_node) {
		meminfo = &master->meminfo;
		get_mm_rss_info(master->mm, &anon, &file, &shmem, &total_rss);
		get_process_sp_res(master, &sp_res, &sp_res_nsize);
		get_process_non_sp_res(total_rss, shmem, sp_res_nsize,
				&non_sp_res, &non_sp_shm);
		seq_printf(seq, "%-8d %-16s %-9ld %-9ld %-9ld %-10ld %-10ld %-8ld\n",
				master->tgid, master->comm,
				meminfo_alloc_sum_byKB(meminfo),
				meminfo_k2u_size(meminfo),
				sp_res, non_sp_res, non_sp_shm,
				page2kb(master->mm->total_vm));
	}
	mutex_unlock(&master_list_lock);
	up_read(&sp_group_sem);

	return 0;
}

static void __init proc_sharepool_init(void)
{
	if (!proc_mkdir("sharepool", NULL))
		return;

	proc_create_single_data("sharepool/spa_stat", 0400, NULL, spa_stat_show, NULL);
	proc_create_single_data("sharepool/proc_stat", 0400, NULL, proc_group_usage_show, NULL);
	proc_create_single_data("sharepool/proc_overview", 0400, NULL, proc_usage_show, NULL);
}

/*** End of tatistical and maintenance functions ***/

bool sp_check_addr(unsigned long addr)
{
	if (sp_is_enabled() && mg_is_sharepool_addr(addr) &&
	    !check_aoscore_process(current))
		return true;
	else
		return false;
}

bool sp_check_mmap_addr(unsigned long addr, unsigned long flags)
{
	if (sp_is_enabled() && mg_is_sharepool_addr(addr) &&
	    !check_aoscore_process(current) && !(flags & MAP_SHARE_POOL))
		return true;
	else
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
	struct sp_area *spa;
	bool charge_hpage;

	spa = vma->vm_private_data;
	if (!spa) {
		pr_err("share pool: vma is invalid, not from sp mmap\n");
		return ret;
	}

retry:
	page = find_lock_page(mapping, idx);
	if (!page) {
		size = i_size_read(mapping->host) >> huge_page_shift(h);
		if (idx >= size)
			goto out;

		charge_hpage = false;
		page = alloc_huge_page(vma, haddr, 0);
		if (IS_ERR(page)) {
			page = hugetlb_alloc_hugepage_vma(vma, haddr,
					HUGETLB_ALLOC_BUDDY | HUGETLB_ALLOC_NORECLAIM);
			if (!page)
				page = ERR_PTR(-ENOMEM);
			else if (!PageMemcgKmem(page))
				charge_hpage = true;
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

		if (charge_hpage && mem_cgroup_charge(page, vma->vm_mm, GFP_KERNEL)) {
			put_page(page);
			ret = vmf_error(-ENOMEM);
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

	if (new_page)
		SetPagePrivate(&page[1]);

	unlock_page(page);
out:
	return ret;

backout:
	spin_unlock(ptl);
	unlock_page(page);
	put_page(page);
	goto out;
}

/**
 * The caller must ensure that this function is called
 * when the last thread in the thread group exits.
 */
int sp_group_exit(void)
{
	struct mm_struct *mm;
	struct sp_group *spg;
	struct sp_group_master *master;
	struct sp_group_node *spg_node, *tmp;
	bool is_alive = true;

	if (!sp_is_enabled())
		return 0;

	if (current->flags & PF_KTHREAD)
		return 0;

	mm = current->mm;
	down_write(&sp_group_sem);

	master = mm->sp_group_master;
	if (!master) {
		up_write(&sp_group_sem);
		return 0;
	}

	if (master->tgid != current->tgid) {
		up_write(&sp_group_sem);
		return 0;
	}

	list_for_each_entry_safe(spg_node, tmp, &master->node_list, group_node) {
		spg = spg_node->spg;

		down_write(&spg->rw_lock);
		/* a dead group should NOT be reactive again */
		if (spg_valid(spg) && list_is_singular(&spg->procs))
			is_alive = spg->is_alive = false;
		delete_spg_node(spg, spg_node);
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
	struct sp_meminfo *meminfo;
	long alloc_size, k2u_size;
	/* lockless visit */
	struct sp_group_master *master = mm->sp_group_master;
	struct sp_group_node *spg_node, *tmp;
	struct sp_group *spg;

	if (!sp_is_enabled() || !master)
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
	meminfo = &master->meminfo;
	alloc_size = meminfo_alloc_sum(meminfo);
	k2u_size = atomic64_read(&meminfo->k2u_size);
	if (alloc_size != 0 || k2u_size != 0)
		pr_info("process %s(%d) exits. It applied %ld aligned KB, k2u shared %ld aligned KB\n",
			master->comm, master->tgid,
			byte2kb(alloc_size), byte2kb(k2u_size));

	down_write(&sp_group_sem);
	list_for_each_entry_safe(spg_node, tmp, &master->node_list, group_node) {
		spg = spg_node->spg;
		/* match with refcount inc in sp_group_add_task */
		if (atomic_dec_and_test(&spg->use_count))
			free_sp_group_locked(spg);
		list_del(&spg_node->group_node);
		kfree(spg_node);
	}
	up_write(&sp_group_sem);

	sp_del_group_master(master);

	kfree(master);
}

DEFINE_STATIC_KEY_FALSE(share_pool_enabled_key);

static int __init enable_share_pool(char *s)
{
	static_branch_enable(&share_pool_enabled_key);
	pr_info("Ascend enable share pool features via bootargs\n");

	return 1;
}
__setup("enable_ascend_share_pool", enable_share_pool);

static int __init share_pool_init(void)
{
	if (!sp_is_enabled())
		return 0;

	sp_mapping_normal = sp_mapping_create(SP_MAPPING_NORMAL);
	if (IS_ERR(sp_mapping_normal))
		goto fail;
	atomic_inc(&sp_mapping_normal->user);

	sp_mapping_ro = sp_mapping_create(SP_MAPPING_RO);
	if (IS_ERR(sp_mapping_ro))
		goto free_normal;
	atomic_inc(&sp_mapping_ro->user);

	proc_sharepool_init();

	return 0;

free_normal:
	kfree(sp_mapping_normal);
fail:
	pr_err("Ascend share pool initialization failed\n");
	static_branch_disable(&share_pool_enabled_key);
	return 1;
}
late_initcall(share_pool_init);
