// SPDX-License-Identifier: GPL-2.0
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
#include <linux/workqueue.h>

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
static DECLARE_RWSEM(sp_global_sem);

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
	spinlock_t sp_mapping_lock;
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
	int		id;
	struct file	*file;
	struct file	*file_hugetlb;
	/* number of process in this group */
	int		proc_num;
	/* list head of processes (sp_group_node, each represents a process) */
	struct list_head proc_head;
	/* it is protected by rw_lock of this spg */
	struct rb_root	spa_root;
	/* group statistics */
	struct sp_meminfo meminfo;
	atomic_t	use_count;
	atomic_t	spa_num;
	/* protect the group internal elements */
	struct rw_semaphore	rw_lock;
	/* list node for dvpp mapping */
	struct list_head	mnode;
	struct sp_mapping	*mapping[SP_MAPPING_END];
};

/* a per-process(per mm) struct which manages a sp_group_node list */
struct sp_group_master {
	pid_t tgid;
	/*
	 * number of sp groups the process belongs to,
	 * a.k.a the number of sp_node in group_head
	 */
	unsigned int group_num;
	/* list head of sp_node */
	struct list_head group_head;
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
 * sp_group_node      : sp_group->proc_head = N : 1
 */
struct sp_group_node {
	/* list node in sp_group->proc_head */
	struct list_head proc_node;
	/* list node in sp_group_maseter->group_head */
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
		return NULL;

	sp_mapping_set_type(spm, type);
	sp_mapping_range_init(spm);
	atomic_set(&spm->user, 0);
	spm->area_root = RB_ROOT;
	INIT_LIST_HEAD(&spm->group_head);
	spin_lock_init(&spm->sp_mapping_lock);
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
 * the caller must hold sp_global_sem
 * NOTE: undo the mergeing when the later process failed.
 */
static int sp_group_setup_mapping_normal(struct mm_struct *mm, struct sp_group *spg)
{
	struct sp_mapping *local_dvpp_mapping, *spg_dvpp_mapping;

	local_dvpp_mapping = mm->sp_group_master->local->mapping[SP_MAPPING_DVPP];
	spg_dvpp_mapping = spg->mapping[SP_MAPPING_DVPP];

	if (!list_empty(&spg->proc_head)) {
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

static int sp_group_setup_mapping_local(struct mm_struct *mm, struct sp_group *local)
{
	struct sp_mapping *spm;

	spm = sp_mapping_create(SP_MAPPING_DVPP);
	if (!spm)
		return -ENOMEM;

	sp_mapping_attach(local, spm);
	sp_mapping_attach(local, sp_mapping_normal);
	sp_mapping_attach(local, sp_mapping_ro);

	return 0;
}

static inline bool is_local_group(int spg_id)
{
	return spg_id >= SPG_ID_LOCAL_MIN && spg_id <= SPG_ID_LOCAL_MAX;
}

static int sp_group_setup_mapping(struct mm_struct *mm, struct sp_group *spg)
{
	if (is_local_group(spg->id))
		return sp_group_setup_mapping_local(mm, spg);
	else
		return sp_group_setup_mapping_normal(mm, spg);
}

static int sp_init_group_master(struct task_struct *tsk, struct mm_struct *mm)
{
	return -EOPNOTSUPP;
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
	SPA_TYPE_K2TASK,
	SPA_TYPE_K2SPG,
};

/*
 * The lifetime for a sp_area:
 * 1. The sp_area was created from a sp_mapping with sp_mapping_lock held.
 * 2. The sp_area was added into a sp_group (using rb_tree).
 * 3. The sp_area was mapped to all tasks in the sp_group and we bump its
 *    reference when each mmap succeeded.
 * 4. When a new task was added into the sp_group, we map the sp_area into
 *    the new task and increase its reference count.
 * 5. When a task was deleted from the sp_group, we unmap the sp_area for
 *    the task and decrease its reference count.
 * 6. Also, we can use sp_free/sp_unshare to unmap the sp_area for all the
 *    tasks in the sp_group. And the reference count was decreased for each
 *    munmap.
 * 7. When the refcount for sp_area reach zero:
 *      a. the sp_area would firstly be deleted from the sp_group and then
 *         deleted from sp_mapping.
 *      b. no one should use the sp_area from the view of sp_group.
 *      c. the spa->spg should not be used when the sp_area is not on a spg.
 *
 * The locking rules:
 * 1. The newly created sp_area with a refcount of one. This is to distinct
 *    the new sp_area from a dying sp_area.
 * 2. Use spg->rw_lock to protect all the sp_area in the sp_group. And the
 *    sp_area cannot be deleted without spg->rw_lock.
 */
struct sp_area {
	unsigned long va_start;
	unsigned long va_end;		/* va_end always align to hugepage */
	unsigned long real_size;	/* real size with alignment */
	unsigned long region_vstart;	/* belong to normal region or DVPP region */
	unsigned long flags;
	bool is_hugepage;
	atomic_t use_count;		/* How many vmas use this VA region */
	struct rb_node rb_node;		/* address sorted rbtree */
	struct rb_node spg_link;	/* link to the spg->rb_root */
	struct sp_group *spg;
	struct sp_mapping *spm;		/* where spa born from */
	enum spa_type type;
	unsigned long kva;		/* shared kva */
	pid_t applier;			/* the original applier process */
	int preferred_node_id;		/* memory node */
	struct work_struct work;
};

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

static inline void check_interrupt_context(void)
{
	if (unlikely(in_interrupt()))
		panic("function can't be used in interrupt context\n");
}

struct sp_alloc_context {
	unsigned long size;
	unsigned long size_aligned;
	unsigned long sp_flags;
	nodemask_t *nodemask;
	int preferred_node_id;
	bool have_mbind;
	enum spa_type type;
};

static int sp_map_spa_to_mm(struct mm_struct *mm, struct sp_area *spa,
			    unsigned long prot, struct sp_alloc_context *ac,
			    const char *str);

struct sp_k2u_context {
	unsigned long kva;
	unsigned long kva_aligned;
	unsigned long size;
	unsigned long size_aligned;
	unsigned long sp_flags;
	enum spa_type type;
};

static void free_sp_group_locked(struct sp_group *spg)
{
	int type;

	fput(spg->file);
	fput(spg->file_hugetlb);
	idr_remove(&sp_group_idr, spg->id);

	for (type = SP_MAPPING_START; type < SP_MAPPING_END; type++)
		sp_mapping_detach(spg, spg->mapping[type]);

	if (!is_local_group(spg->id))
		system_group_count--;

	kfree(spg);
	WARN(system_group_count < 0, "unexpected group count\n");
}

static void free_sp_group(struct sp_group *spg)
{
	down_write(&sp_global_sem);
	free_sp_group_locked(spg);
	up_write(&sp_global_sem);
}

static void sp_group_put_locked(struct sp_group *spg)
{
	lockdep_assert_held_write(&sp_global_sem);

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

	list_for_each_entry(spg_node, &spg->proc_head, proc_node)
		if (spg_node->master->mm == mm)
			return true;

	return false;
}

/*
 * Get the sp_group from the mm and return the associated sp_group_node.
 * The caller should promise the @mm would not be deleted from the @spg.
 */
static struct sp_group *sp_group_get_from_mm(struct mm_struct *mm, int spg_id,
					     struct sp_group_node **pnode)
{
	struct sp_group *spg = NULL;
	struct sp_group_node *spg_node;
	struct sp_group_master *master;

	down_read(&sp_global_sem);

	master = mm->sp_group_master;
	if (!master) {
		up_read(&sp_global_sem);
		return NULL;
	}

	if (spg_id == SPG_ID_DEFAULT) {
		atomic_inc(&master->local->use_count);
		/* There is only one task in the local group */
		*pnode = list_first_entry(&master->local->proc_head,
					  struct sp_group_node, proc_node);
		up_read(&sp_global_sem);
		return master->local;
	}

	list_for_each_entry(spg_node, &master->group_head, group_node)
		if (spg_node->spg->id == spg_id) {
			if (atomic_inc_not_zero(&spg_node->spg->use_count)) {
				spg = spg_node->spg;
				*pnode = spg_node;
			}
			break;
		}
	up_read(&sp_global_sem);

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

	down_read(&sp_global_sem);
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
	real_count = master->group_num - 1;
	if (real_count <= 0) {
		ret = -ENODEV;
		goto out_up_read;
	}
	if ((unsigned int)*num < real_count) {
		ret = -E2BIG;
		goto out_up_read;
	}
	*num = real_count;

	list_for_each_entry(node, &master->group_head, group_node) {
		if (is_local_group(node->spg->id))
			continue;
		*(spg_ids++) = node->spg->id;
	}

out_up_read:
	up_read(&sp_global_sem);
	put_task_struct(tsk);
	return ret;
}
EXPORT_SYMBOL_GPL(mg_sp_group_id_by_pid);

static bool is_online_node_id(int node_id)
{
	return node_id >= 0 && node_id < MAX_NUMNODES && node_online(node_id);
}

static void sp_group_init(struct sp_group *spg, int spg_id)
{
	spg->id = spg_id;
	spg->proc_num = 0;
	spg->spa_root = RB_ROOT;
	atomic_set(&spg->use_count, 1);
	atomic_set(&spg->spa_num, 0);
	INIT_LIST_HEAD(&spg->proc_head);
	INIT_LIST_HEAD(&spg->mnode);
	init_rwsem(&spg->rw_lock);
	meminfo_init(&spg->meminfo);
}

/*
 * sp_group_create - create a new sp_group
 * @spg_id: specify the id for the new sp_group
 *
 * valid @spg_id:
 * SPG_ID_AUTO:
 *	Allocate a id in range [SPG_ID_AUTO_MIN, APG_ID_AUTO_MAX]
 * SPG_ID_LOCAL:
 *	Allocate a id in range [SPG_ID_LOCAL_MIN, APG_ID_LOCAL_MAX]
 * [SPG_ID_MIN, SPG_ID_MAX]:
 *	Using the input @spg_id for the new sp_group.
 *
 * Return: the newly created sp_group or an errno.
 * Context: The caller should protect sp_group_idr from being access.
 */
static struct sp_group *sp_group_create(int spg_id)
{
	int ret, start, end;
	struct sp_group *spg;
	char name[DNAME_INLINE_LEN];
	int hsize_log = MAP_HUGE_2MB >> MAP_HUGE_SHIFT;

	if (unlikely(system_group_count + 1 == MAX_GROUP_FOR_SYSTEM &&
		     spg_id != SPG_ID_LOCAL)) {
		pr_err("reach system max group num\n");
		return ERR_PTR(-ENOSPC);
	}

	if (spg_id == SPG_ID_LOCAL) {
		start = SPG_ID_LOCAL_MIN;
		end = SPG_ID_LOCAL_MAX + 1;
	} else if (spg_id == SPG_ID_AUTO) {
		start = SPG_ID_AUTO_MIN;
		end = SPG_ID_AUTO_MAX + 1;
	} else if (spg_id >= SPG_ID_MIN && spg_id <= SPG_ID_MAX) {
		start = spg_id;
		end = spg_id + 1;
	} else {
		pr_err("invalid input spg_id:%d\n", spg_id);
		return ERR_PTR(-EINVAL);
	}

	spg = kzalloc(sizeof(*spg), GFP_KERNEL);
	if (spg == NULL)
		return ERR_PTR(-ENOMEM);

	ret = idr_alloc(&sp_group_idr, spg, start, end, GFP_KERNEL);
	if (ret < 0) {
		pr_err("group %d idr alloc failed %d\n", spg_id, ret);
		goto out_kfree;
	}
	spg_id = ret;

	sprintf(name, "sp_group_%d", spg_id);
	spg->file = shmem_kernel_file_setup(name, MAX_LFS_FILESIZE, VM_NORESERVE);
	if (IS_ERR(spg->file)) {
		pr_err("spg file setup failed %ld\n", PTR_ERR(spg->file));
		ret = PTR_ERR(spg->file);
		goto out_idr_remove;
	}

	sprintf(name, "sp_group_%d_huge", spg_id);
	spg->file_hugetlb = hugetlb_file_setup(name, MAX_LFS_FILESIZE,
				VM_NORESERVE, HUGETLB_ANONHUGE_INODE, hsize_log);
	if (IS_ERR(spg->file_hugetlb)) {
		pr_err("spg file_hugetlb setup failed %ld\n", PTR_ERR(spg->file_hugetlb));
		ret = PTR_ERR(spg->file_hugetlb);
		goto out_fput;
	}

	sp_group_init(spg, spg_id);

	if (!is_local_group(spg_id))
		system_group_count++;

	return spg;

out_fput:
	fput(spg->file);
out_idr_remove:
	idr_remove(&sp_group_idr, spg_id);
out_kfree:
	kfree(spg);
	return ERR_PTR(ret);
}

/* the caller must hold sp_global_sem */
static struct sp_group *sp_group_get_or_alloc(int spg_id)
{
	struct sp_group *spg;

	spg = idr_find(&sp_group_idr, spg_id);
	if (!spg || !atomic_inc_not_zero(&spg->use_count))
		spg = sp_group_create(spg_id);

	return spg;
}

/* the caller must hold sp_global_sem */
static struct sp_group_node *spg_node_alloc(struct mm_struct *mm,
	unsigned long prot, struct sp_group *spg)
{
	struct sp_group_master *master = mm->sp_group_master;
	struct sp_group_node *spg_node;

	spg_node = kzalloc(sizeof(struct sp_group_node), GFP_KERNEL);
	if (!spg_node)
		return NULL;

	INIT_LIST_HEAD(&spg_node->group_node);
	INIT_LIST_HEAD(&spg_node->proc_node);
	spg_node->spg = spg;
	spg_node->master = master;
	spg_node->prot = prot;
	meminfo_init(&spg_node->meminfo);

	return spg_node;
}

/*
 * sp_group_link_task - Actually add a task into a group
 * @mm: specify the input task
 * @spg: the sp_group
 * @prot: read/write protection for the task in the group
 *
 * The input @mm and @spg must have been initialized properly and could not
 * be freed during the sp_group_link_task().
 * the caller must hold sp_global_sem.
 */
static int sp_group_link_task(struct mm_struct *mm, struct sp_group *spg,
			      unsigned long prot, struct sp_group_node **pnode)
{
	int ret;
	struct sp_group_node *node;
	struct sp_group_master *master = mm->sp_group_master;

	if (master->group_num == MAX_GROUP_FOR_TASK) {
		pr_err("task reaches max group num\n");
		return -ENOSPC;
	}

	if (is_process_in_group(spg, mm)) {
		pr_err("task already in target group(%d)\n", spg->id);
		return -EEXIST;
	}

	if (spg->proc_num + 1 == MAX_PROC_PER_GROUP) {
		pr_err("add group: group(%d) reaches max process num\n", spg->id);
		return -ENOSPC;
	}

	node = spg_node_alloc(mm, prot, spg);
	if (!node)
		return -ENOMEM;

	ret = sp_group_setup_mapping(mm, spg);
	if (ret)
		goto out_kfree;

	/*
	 * We pin only the mm_struct instead of the memory space of the target mm.
	 * So we must ensure the existence of the memory space via mmget_not_zero
	 * before we would access it.
	 */
	mmgrab(mm);
	master->group_num++;
	list_add_tail(&node->group_node, &master->group_head);
	atomic_inc(&spg->use_count);
	spg->proc_num++;
	list_add_tail(&node->proc_node, &spg->proc_head);
	if (pnode)
		*pnode = node;

	return 0;

out_kfree:
	kfree(node);

	return ret;
}

static void sp_group_unlink_task(struct sp_group_node *spg_node)
{
	struct sp_group *spg = spg_node->spg;
	struct sp_group_master *master = spg_node->master;

	list_del(&spg_node->proc_node);
	spg->proc_num--;
	list_del(&spg_node->group_node);
	master->group_num--;

	mmdrop(master->mm);
	sp_group_put_locked(spg);
	kfree(spg_node);
}

/*
 * Find and initialize the mm of the task specified by @tgid.
 * We increace the usercount for the mm on success.
 */
static int mm_add_group_init(pid_t tgid, struct mm_struct **pmm)
{
	int ret;
	struct mm_struct *mm;
	struct task_struct *tsk;

	ret = get_task(tgid, &tsk);
	if (ret)
		return ret;

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
		ret = -ESRCH;
		goto out_put_task;
	}

	ret = sp_init_group_master(tsk, mm);
	if (ret)
		goto out_put_mm;

	if (mm->sp_group_master && mm->sp_group_master->tgid != tgid) {
		pr_err("add: task(%d) is a vfork child of the original task(%d)\n",
			tgid, mm->sp_group_master->tgid);
		ret = -EINVAL;
		goto out_put_mm;
	}
	*pmm = mm;

out_put_mm:
	if (ret)
		mmput(mm);
out_put_task:
	put_task_struct(tsk);

	return ret;
}

static void sp_area_put_locked(struct sp_area *spa);
static void sp_munmap(struct mm_struct *mm, unsigned long addr, unsigned long size);
/**
 * mg_sp_group_add_task() - Add a process to an share group (sp_group).
 * @tgid: the tgid of the task to be added.
 * @prot: the prot of task for this spg.
 * @spg_id: the ID of the sp_group.
 *
 * Return: A postive group number for success, -errno on failure.
 *
 * Valid @spg_id:
 * [SPG_ID_MIN, SPG_ID_MAX]:
 *              the task would be added to the group with @spg_id, if the
 *              group doesn't exist, just create it.
 * [SPG_ID_AUTO_MIN, SPG_ID_AUTO_MAX]:
 *              the task would be added to the group with @spg_id, if it
 *              doesn't exist ,return failed.
 * SPG_ID_AUTO:
 *              the task would be added into a new group with a new id in range
 *              [SPG_ID_AUTO_MIN, SPG_ID_AUTO_MAX].
 *
 * This function can be taken into four parts:
 * 1. Check and initlize the task specified by @tgid properly.
 * 2. Create or get the spg specified by @spg_id.
 * 3. Check the spg and task together and link the task into the spg if
 *    everything looks good.
 * 4. Map the existing sp_area from the spg into the new task.
 */
int mg_sp_group_add_task(int tgid, unsigned long prot, int spg_id)
{
	int ret = 0;
	struct sp_area *spa;
	struct mm_struct *mm;
	struct sp_group *spg;
	struct rb_node *p, *n;
	struct sp_group_node *spg_node;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	check_interrupt_context();

	/* only allow READ, READ | WRITE */
	if (!((prot == PROT_READ) || (prot == (PROT_READ | PROT_WRITE)))) {
		pr_err_ratelimited("prot is invalid 0x%lx\n", prot);
		return -EINVAL;
	}

	if (spg_id < SPG_ID_MIN || spg_id > SPG_ID_AUTO) {
		pr_err_ratelimited("add group failed, invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	ret = mm_add_group_init(tgid, &mm);
	if (ret < 0)
		return ret;

	down_write(&sp_global_sem);
	spg = sp_group_get_or_alloc(spg_id);
	if (IS_ERR(spg)) {
		ret = PTR_ERR(spg);
		goto out_unlock;
	}
	/* save spg_id before we release sp_global_sem, or UAF may occur */
	spg_id = spg->id;

	down_write(&spg->rw_lock);
	ret = sp_group_link_task(mm, spg, prot, &spg_node);
	if (ret < 0)
		goto put_spg;

	/*
	 * create mappings of existing shared memory segments into this
	 * new process' page table.
	 */
	for (p = rb_first(&spg->spa_root); p; p = n) {
		n = rb_next(p);
		spa = container_of(p, struct sp_area, spg_link);

		if (!atomic_inc_not_zero(&spa->use_count)) {
			pr_warn("be careful, add new task(%d) to an exiting group(%d)\n",
					tgid, spg_id);
			continue;
		}

		ret = sp_map_spa_to_mm(mm, spa, prot, NULL, "add_task");
		sp_area_put_locked(spa);
		if (ret) {
			pr_warn("mmap old spa to new task failed, %d\n", ret);
			/* it makes no scene to skip error for coredump here */
			ret = ret < 0 ? ret : -EFAULT;

			for (p = rb_prev(p); p; p = n) {
				n = rb_prev(p);
				spa = container_of(p, struct sp_area, spg_link);
				if (!atomic_inc_not_zero(&spa->use_count))
					continue;
				sp_munmap(mm, spa->va_start, spa_size(spa));
				sp_area_put_locked(spa);
			}
			sp_group_unlink_task(spg_node);
			break;
		}
	}
put_spg:
	up_write(&spg->rw_lock);
	sp_group_put_locked(spg);
out_unlock:
	up_write(&sp_global_sem);
	/* We put the mm_struct later to protect the mm from exiting while sp_mmap */
	mmput(mm);

	return ret < 0 ? ret : spg_id;
}
EXPORT_SYMBOL_GPL(mg_sp_group_add_task);

int mg_sp_id_of_current(void)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(mg_sp_id_of_current);

#define insert_sp_area(__root, __spa, node, rb_node_param)	\
	do {							\
		struct rb_node **p = &((__root)->rb_node);	\
		struct rb_node *parent = NULL;			\
		while (*p) {					\
			struct sp_area *tmp;			\
			parent = *p;				\
			tmp = rb_entry(parent, struct sp_area, rb_node_param);\
			if (__spa->va_start < tmp->va_end)	\
				p = &(*p)->rb_left;		\
			else if (__spa->va_end > tmp->va_start)	\
				p = &(*p)->rb_right;		\
			else					\
				WARN(1, "duplicate spa of tree " #__root);\
		}						\
		rb_link_node((node), parent, p);		\
		rb_insert_color((node), (__root));		\
	} while (0)

/* the caller must hold sp_mapping_lock */
static void spm_insert_area(struct sp_mapping *spm, struct sp_area *spa)
{
	insert_sp_area(&spm->area_root, spa, &spa->rb_node, rb_node);
}

static void sp_group_insert_area(struct sp_group *spg, struct sp_area *spa)
{
	insert_sp_area(&spg->spa_root, spa, &spa->spg_link, spg_link);
	atomic_inc(&spg->spa_num);
	spa_inc_usage(spa);
	if (atomic_read(&spg->spa_num) == 1)
		atomic_inc(&spg->use_count);
}

/*
 * The caller must hold spg->rw_lock.
 * Return true to indicate that ths spa_num in the spg reaches zero and the caller
 * should drop the extra spg->use_count added in sp_group_insert_area().
 */
static bool sp_group_delete_area(struct sp_group *spg, struct sp_area *spa)
{
	rb_erase(&spa->spg_link, &spg->spa_root);
	spa_dec_usage(spa);
	return atomic_dec_and_test(&spa->spg->spa_num);
}

/**
 * sp_area_alloc() - Allocate a region of VA from the share pool.
 * @size: the size of VA to allocate.
 * @flags: how to allocate the memory.
 * @spg: the share group that the memory is allocated to.
 * @type: the type of the region.
 * @applier: the tgid of the task which allocates the region.
 *
 * Return: a valid pointer for success, NULL on failure.
 */
static struct sp_area *sp_area_alloc(unsigned long size, unsigned long flags,
				     struct sp_group *spg, enum spa_type type,
				     pid_t applier, int node_id)
{
	int device_id;
	struct sp_area *spa, *first, *err;
	struct rb_node *n;
	unsigned long vstart;
	unsigned long vend;
	unsigned long addr;
	unsigned long size_align = ALIGN(size, PMD_SIZE); /* va aligned to 2M */
	struct sp_mapping *mapping;

	device_id = sp_flags_device_id(flags);
	if (device_id < 0 || device_id >= MAX_DEVID) {
		pr_err("invalid device id %d\n", device_id);
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
	spa = kmalloc(sizeof(struct sp_area), GFP_KERNEL);
	if (unlikely(!spa))
		return ERR_PTR(-ENOMEM);

	spin_lock(&mapping->sp_mapping_lock);

	/*
	 * Invalidate cache if we have more permissive parameters.
	 * cached_hole_size notes the largest hole noticed _below_
	 * the sp_area cached in free_area_cache: if size fits
	 * into that hole, we want to scan from vstart to reuse
	 * the hole instead of allocating above free_area_cache.
	 * Note that sp_area_free may update free_area_cache
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

	spa->va_start          = addr;
	spa->va_end            = addr + size_align;
	spa->real_size         = size;
	spa->region_vstart     = vstart;
	spa->flags             = flags;
	spa->is_hugepage       = (flags & SP_HUGEPAGE);
	spa->spg               = spg;
	spa->spm               = mapping;
	spa->type              = type;
	spa->kva               = 0;   /* NULL pointer */
	spa->applier           = applier;
	spa->preferred_node_id = node_id;
	atomic_set(&spa->use_count, 1);

	/* the link location could be saved before, to be optimized */
	spm_insert_area(mapping, spa);
	mapping->free_area_cache = &spa->rb_node;

	spin_unlock(&mapping->sp_mapping_lock);
	sp_group_insert_area(spg, spa);

	return spa;

error:
	spin_unlock(&mapping->sp_mapping_lock);
	kfree(spa);
	return err;
}

/*
 * Find a spa with key @addr from @spg and increase its use_count.
 * The caller should hold spg->rw_lock
 */
static struct sp_area *sp_area_get(struct sp_group *spg,
		unsigned long addr)
{
	struct rb_node *n = spg->spa_root.rb_node;

	while (n) {
		struct sp_area *spa;

		spa = rb_entry(n, struct sp_area, spg_link);
		if (addr < spa->va_start) {
			n = n->rb_left;
		} else if (addr > spa->va_start) {
			n = n->rb_right;
		} else {
			/* a spa without any user will die soon */
			if (atomic_inc_not_zero(&spa->use_count))
				return spa;
			else
				return NULL;
		}
	}

	return NULL;
}

/*
 * Free the VA region starting from addr to the share pool
 */
static void sp_area_free(struct sp_area *spa)
{
	struct sp_mapping *spm = spa->spm;

	spin_lock(&spm->sp_mapping_lock);
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

	rb_erase(&spa->rb_node, &spm->area_root);
	spin_unlock(&spm->sp_mapping_lock);
	RB_CLEAR_NODE(&spa->rb_node);
	kfree(spa);
}

static void sp_area_put_locked(struct sp_area *spa)
{
	if (atomic_dec_and_test(&spa->use_count)) {
		if (sp_group_delete_area(spa->spg, spa))
			/* the caller must hold a refcount for spa->spg under spg->rw_lock */
			atomic_dec(&spa->spg->use_count);
		sp_area_free(spa);
	}
}

static void sp_area_drop_func(struct work_struct *work)
{
	bool spa_zero;
	struct sp_area *spa = container_of(work, struct sp_area, work);
	struct sp_group *spg = spa->spg;

	down_write(&spg->rw_lock);
	spa_zero = sp_group_delete_area(spg, spa);
	up_write(&spg->rw_lock);
	sp_area_free(spa);
	if (spa_zero)
		sp_group_put(spg);
}

void sp_area_drop(struct vm_area_struct *vma)
{
	struct sp_area *spa = vma->spa;

	if (!(vma->vm_flags & VM_SHARE_POOL))
		return;

	/*
	 * Considering a situation where task A and B are in the same spg.
	 * A is exiting and calling remove_vma(). Before A calls this func,
	 * B calls sp_free() to free the same spa. So spa maybe NULL when A
	 * calls this func later.
	 */
	if (!spa)
		return;

	if (atomic_dec_and_test(&spa->use_count)) {
		INIT_WORK(&spa->work, sp_area_drop_func);
		schedule_work(&spa->work);
	}
}

/*
 * The function calls of do_munmap() won't change any non-atomic member
 * of struct sp_group. Please review the following chain:
 * do_munmap -> remove_vma_list -> remove_vma -> sp_area_drop ->
 * sp_area_free
 */
static void sp_munmap(struct mm_struct *mm, unsigned long addr,
			   unsigned long size)
{
	int err;

	down_write(&mm->mmap_lock);
	if (unlikely(!mmget_not_zero(mm))) {
		up_write(&mm->mmap_lock);
		pr_warn("munmap: target mm is exiting\n");
		return;
	}

	err = do_munmap(mm, addr, size, NULL);
	/* we are not supposed to fail */
	if (err)
		pr_err("failed to unmap VA %pK when sp munmap, %d\n", (void *)addr, err);

	up_write(&mm->mmap_lock);
	mmput_async(mm);
}

/* The caller should hold the write lock for spa->spg->rw_lock */
static void __sp_free(struct sp_area *spa, struct mm_struct *stop)
{
	struct mm_struct *mm;
	struct sp_group_node *spg_node = NULL;

	list_for_each_entry(spg_node, &spa->spg->proc_head, proc_node) {
		mm = spg_node->master->mm;
		if (mm == stop)
			break;
		sp_munmap(mm, spa->va_start, spa_size(spa));
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

static struct sp_group *sp_group_get_from_idr(int spg_id)
{
	struct sp_group *spg;

	down_read(&sp_global_sem);
	spg = idr_find(&sp_group_idr, spg_id);
	if (!spg || !atomic_inc_not_zero(&spg->use_count))
		spg = NULL;
	up_read(&sp_global_sem);

	return spg;
}

static int sp_free_inner(unsigned long addr, int spg_id, bool is_sp_free)
{
	int ret = 0;
	struct sp_area *spa;
	struct sp_group *spg;
	struct sp_group_node *spg_node;
	const char *str = is_sp_free ? "sp_free" : "unshare_uva";

	if (!current->mm)
		spg = sp_group_get_from_idr(spg_id);
	else
		spg = sp_group_get_from_mm(current->mm, spg_id, &spg_node);
	if (!spg) {
		pr_err("%s, get group failed %d\n", str, spg_id);
		return -EINVAL;
	}

	down_write(&spg->rw_lock);
	spa = sp_area_get(spg, addr);
	if (!spa) {
		pr_debug("%s, invalid input addr %lx\n", str, addr);
		ret = -EINVAL;
		goto drop_spg;
	}

	if ((is_sp_free && spa->type != SPA_TYPE_ALLOC) ||
	    (!is_sp_free && spa->type == SPA_TYPE_ALLOC)) {
		ret = -EINVAL;
		pr_warn("%s failed, spa_type is not correct\n", str);
		goto drop_spa;
	}

	if (!current->mm && spa->applier != current->tgid) {
		ret = -EPERM;
		pr_err("%s, free a spa allocated by other process(%d), current(%d)\n",
			str, spa->applier, current->tgid);
		goto drop_spa;
	}

	__sp_free(spa, NULL);
	if (spa->type == SPA_TYPE_ALLOC)
		sp_fallocate(spa);

	if (current->mm)
		update_mem_usage(spa_size(spa), false, spa->is_hugepage, spg_node, spa->type);

drop_spa:
	sp_area_put_locked(spa);
drop_spg:
	up_write(&spg->rw_lock);
	sp_group_put(spg);
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
 * * -EINVAL	- the memory can't be found or was not allocated by share pool.
 * * -EPERM	- the caller has no permision to free the memory.
 */
int mg_sp_free(unsigned long addr, int id)
{
	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	check_interrupt_context();

	if (current->flags & PF_KTHREAD)
		return -EINVAL;

	return sp_free_inner(addr, id, true);
}
EXPORT_SYMBOL_GPL(mg_sp_free);

static void __init proc_sharepool_init(void)
{
	if (!proc_mkdir("sharepool", NULL))
		return;
}

/* wrapper of __do_mmap() and the caller must hold down_write(&mm->mmap_lock). */
static unsigned long sp_mmap(struct mm_struct *mm, struct file *file,
			     struct sp_area *spa, unsigned long *populate,
			     unsigned long prot)
{
	unsigned long addr = spa->va_start;
	unsigned long size = spa_size(spa);
	unsigned long flags = MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_POPULATE |
			      MAP_SHARE_POOL;
	unsigned long vm_flags = VM_NORESERVE | VM_SHARE_POOL | VM_DONTCOPY;
	unsigned long pgoff = addr_offset(spa) >> PAGE_SHIFT;
	struct vm_area_struct *vma;

	if (spa->flags & SP_PROT_RO)
		prot &= ~PROT_WRITE;

	atomic_inc(&spa->use_count);
	addr = __do_mmap_mm(mm, file, addr, size, prot, flags, vm_flags, pgoff,
			 populate, NULL);
	if (IS_ERR_VALUE(addr)) {
		atomic_dec(&spa->use_count);
		pr_err("do_mmap fails %ld\n", addr);
		return addr;
	}

	vma = find_vma(mm, addr);
	vma->spa = spa;

	if (prot & PROT_WRITE)
		/* clean PTE_RDONLY flags or trigger SMMU event */
		vma->vm_page_prot = __pgprot(((~PTE_RDONLY) & vma->vm_page_prot.pgprot) |
						PTE_DIRTY);
	else
		vm_flags_clear(vma, VM_MAYWRITE);

	return addr;
}

static int sp_alloc_prepare(unsigned long size, unsigned long sp_flags,
	int spg_id, struct sp_alloc_context *ac)
{
	int device_id, node_id;

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

	check_interrupt_context();

	device_id = sp_flags_device_id(sp_flags);
	node_id = sp_flags & SP_SPEC_NODE_ID ? sp_flags_node_id(sp_flags) : device_id;
	if (!is_online_node_id(node_id)) {
		pr_err_ratelimited("invalid numa node id %d\n", node_id);
		return -EINVAL;
	}
	ac->preferred_node_id = node_id;

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

	if (spg_id == SPG_ID_DEFAULT) {
		/*
		 * We should first init the group_master in pass through scene and
		 * don't free it until we release the mm_struct.
		 */
		int ret = sp_init_group_master(current, current->mm);

		if (ret) {
			pr_err("sp_alloc init local mapping failed %d\n", ret);
			return ret;
		}
	}

	ac->type         = SPA_TYPE_ALLOC;
	ac->size         = size;
	ac->sp_flags     = sp_flags;
	ac->have_mbind   = false;
	ac->size_aligned = (sp_flags & SP_HUGEPAGE) ? ALIGN(size, PMD_SIZE) :
						      ALIGN(size, PAGE_SIZE);

	return 0;
}

static bool sp_alloc_fallback(struct sp_area *spa, struct sp_alloc_context *ac)
{
	/*
	 * If hugepage allocation fails, this will transfer to normal page
	 * and try again. (only if SP_HUGEPAGE_ONLY is not flagged
	 */
	if (!(ac->sp_flags & SP_HUGEPAGE) || (ac->sp_flags & SP_HUGEPAGE_ONLY))
		return false;

	ac->size_aligned = ALIGN(ac->size, PAGE_SIZE);
	ac->sp_flags &= ~SP_HUGEPAGE;
	/*
	 * The mempolicy for shared memory is located at backend file, which varies
	 * between normal pages and huge pages. So we should set the mbind policy again
	 * when we retry using normal pages.
	 */
	ac->have_mbind = false;
	sp_area_put_locked(spa);
	return true;
}

static long sp_mbind(struct mm_struct *mm, unsigned long start, unsigned long len,
		nodemask_t *nodemask)
{
	return __do_mbind(start, len, MPOL_BIND, MPOL_F_STATIC_NODES,
			nodemask, MPOL_MF_STRICT, mm);
}

static int sp_alloc_populate(struct mm_struct *mm, struct sp_area *spa,
			     unsigned long populate, struct sp_alloc_context *ac)
{
	int ret;

	if (ac && !ac->have_mbind) {
		ret = sp_mbind(mm, spa->va_start, spa->real_size, ac->nodemask);
		if (ret < 0) {
			pr_err("cannot bind the memory range to node[%*pbl], err:%d\n",
					nodemask_pr_args(ac->nodemask), ret);
			return ret;
		}
		ac->have_mbind = true;
	}

	/*
	 * We are not ignoring errors, so if we fail to allocate
	 * physical memory we just return failure, so we won't encounter
	 * page fault later on, and more importantly sp_make_share_u2k()
	 * depends on this feature (and MAP_LOCKED) to work correctly.
	 */
	ret = do_mm_populate(mm, spa->va_start, populate, 0);
	if (ret) {
		if (unlikely(fatal_signal_pending(current)))
			pr_warn("allocation failed, current thread is killed\n");
		else
			pr_warn("allocation failed due to mm populate failed(potential no enough memory when -12): %d\n",
					ret);
	}

	return ret;
}

static int sp_k2u_populate(struct mm_struct *mm, struct sp_area *spa);

#define SP_SKIP_ERR 1
/*
 * The caller should increase the refcnt of the spa to prevent that we map
 * a dead spa into a mm_struct.
 */
static int sp_map_spa_to_mm(struct mm_struct *mm, struct sp_area *spa,
			    unsigned long prot, struct sp_alloc_context *ac,
			    const char *str)
{
	int ret;
	unsigned long mmap_addr;
	unsigned long populate = 0;

	down_write(&mm->mmap_lock);
	if (unlikely(!mmget_not_zero(mm))) {
		up_write(&mm->mmap_lock);
		pr_warn("sp_map: target mm is exiting\n");
		return SP_SKIP_ERR;
	}

	/* when success, mmap_addr == spa->va_start */
	mmap_addr = sp_mmap(mm, spa_file(spa), spa, &populate, prot);
	if (IS_ERR_VALUE(mmap_addr)) {
		up_write(&mm->mmap_lock);
		mmput_async(mm);
		pr_err("%s, sp mmap failed %ld\n", str, mmap_addr);
		return (int)mmap_addr;
	}

	if (spa->type == SPA_TYPE_ALLOC) {
		up_write(&mm->mmap_lock);
		ret = sp_alloc_populate(mm, spa, populate, ac);
		if (ret) {
			down_write(&mm->mmap_lock);
			do_munmap(mm, mmap_addr, spa_size(spa), NULL);
			up_write(&mm->mmap_lock);
		}
	} else {
		ret = sp_k2u_populate(mm, spa);
		if (ret) {
			do_munmap(mm, mmap_addr, spa_size(spa), NULL);
			pr_info("k2u populate failed, %d\n", ret);
		}
		up_write(&mm->mmap_lock);
	}
	mmput_async(mm);

	return ret;
}

static int sp_alloc_mmap_populate(struct sp_area *spa, struct sp_alloc_context *ac)
{
	int ret = -EINVAL;
	int mmap_ret = 0;
	struct mm_struct *mm;
	struct sp_group_node *spg_node;

	/* create mapping for each process in the group */
	list_for_each_entry(spg_node, &spa->spg->proc_head, proc_node) {
		mm = spg_node->master->mm;
		mmap_ret = sp_map_spa_to_mm(mm, spa, spg_node->prot, ac, "sp_alloc");
		if (mmap_ret) {
			/*
			 * Goto fallback procedure upon ERR_VALUE,
			 * but skip the coredump situation,
			 * because we don't want one misbehaving process to affect others.
			 */
			if (mmap_ret != SP_SKIP_ERR)
				goto unmap;

			continue;
		}
		ret = mmap_ret;
	}

	return ret;

unmap:
	__sp_free(spa, mm);

	/*
	 * Sometimes do_mm_populate() allocates some memory and then failed to
	 * allocate more. (e.g. memory use reaches cgroup limit.)
	 * In this case, it will return enomem, but will not free the
	 * memory which has already been allocated.
	 *
	 * So if sp_map_spa_to_mm fails, always call sp_fallocate()
	 * to make sure backup physical memory of the shared file is freed.
	 */
	sp_fallocate(spa);

	return mmap_ret;
}

static void *__mg_sp_alloc_nodemask(unsigned long size, unsigned long sp_flags, int spg_id,
			     nodemask_t *nodemask)
{
	int ret = 0;
	struct sp_area *spa;
	struct sp_group *spg;
	nodemask_t __nodemask;
	struct sp_alloc_context ac;
	struct sp_group_node *spg_node;

	ret = sp_alloc_prepare(size, sp_flags, spg_id, &ac);
	if (ret)
		return ERR_PTR(ret);

	if (!nodemask) { /* mg_sp_alloc */
		nodes_clear(__nodemask);
		node_set(ac.preferred_node_id, __nodemask);
		ac.nodemask = &__nodemask;
	} else /* mg_sp_alloc_nodemask */
		ac.nodemask = nodemask;

	spg = sp_group_get_from_mm(current->mm, spg_id, &spg_node);
	if (!spg) {
		pr_err("allocation failed, can't find group(%d)\n", spg_id);
		return ERR_PTR(-ENODEV);
	}

	down_write(&spg->rw_lock);
try_again:
	spa = sp_area_alloc(ac.size_aligned, ac.sp_flags, spg,
			    ac.type, current->tgid, ac.preferred_node_id);
	if (IS_ERR(spa)) {
		up_write(&spg->rw_lock);
		pr_err("alloc spa failed in allocation(potential no enough virtual memory when -75): %ld\n",
			PTR_ERR(spa));
		ret = PTR_ERR(spa);
		goto out;
	}

	ret = sp_alloc_mmap_populate(spa, &ac);
	if (ret == -ENOMEM && sp_alloc_fallback(spa, &ac))
		goto try_again;

	if (!ret)
		update_mem_usage(spa_size(spa), true, spa->is_hugepage, spg_node, spa->type);

	sp_area_put_locked(spa);
	up_write(&spg->rw_lock);

out:
	sp_group_put(spg);
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

static int sp_k2u_populate(struct mm_struct *mm, struct sp_area *spa)
{
	int ret;
	struct vm_area_struct *vma;
	unsigned long kva = spa->kva;
	unsigned long addr, buf, offset;

	/* This should not fail because we hold the mmap_lock sicne mmap */
	vma = find_vma(mm, spa->va_start);
	if (is_vm_hugetlb_page(vma)) {
		ret = remap_vmalloc_hugepage_range(vma, (void *)kva, 0);
		if (ret) {
			pr_debug("remap vmalloc hugepage failed, ret %d, kva is %lx\n",
				 ret, (unsigned long)kva);
			return ret;
		}
		vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	} else {
		addr = kva;
		offset = 0;
		buf = spa->va_start;
		do {
			ret = remap_pfn_range(vma, buf, __sp_remap_get_pfn(addr), PAGE_SIZE,
					__pgprot(vma->vm_page_prot.pgprot));
			if (ret) {
				pr_err("remap_pfn_range failed %d\n", ret);
				return ret;
			}
			offset += PAGE_SIZE;
			buf += PAGE_SIZE;
			addr += PAGE_SIZE;
		} while (offset < spa_size(spa));
	}

	return 0;
}

static int sp_k2u_prepare(unsigned long kva, unsigned long size,
	unsigned long sp_flags, int spg_id, struct sp_k2u_context *kc)
{
	int is_hugepage, ret;
	unsigned int page_size = PAGE_SIZE;
	unsigned long kva_aligned, size_aligned;

	check_interrupt_context();

	if (!sp_is_enabled())
		return -EOPNOTSUPP;

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

	if (spg_id == SPG_ID_DEFAULT) {
		ret = sp_init_group_master(current, current->mm);
		if (ret) {
			pr_err("k2u_task init local mapping failed %d\n", ret);
			return ret;
		}
	}

	/* aligned down kva is convenient for caller to start with any valid kva */
	kva_aligned = ALIGN_DOWN(kva, page_size);
	size_aligned = ALIGN(kva + size, page_size) - kva_aligned;

	kc->kva          = kva;
	kc->kva_aligned  = kva_aligned;
	kc->size         = size;
	kc->size_aligned = size_aligned;
	kc->sp_flags     = sp_flags;
	kc->type         = (spg_id == SPG_ID_DEFAULT) ? SPA_TYPE_K2TASK : SPA_TYPE_K2SPG;

	return 0;
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
	int mmap_ret, ret;
	struct sp_area *spa;
	struct sp_group *spg;
	struct sp_k2u_context kc;
	struct sp_group_node *spg_node, *ori_node;

	spg_id = (spg_id == SPG_ID_NONE) ? SPG_ID_DEFAULT : spg_id;
	ret = sp_k2u_prepare(kva, size, sp_flags, spg_id, &kc);
	if (ret)
		return ERR_PTR(ret);

	spg = sp_group_get_from_mm(current->mm, spg_id, &ori_node);
	if (!spg) {
		pr_err("k2u failed, can't find group(%d)\n", spg_id);
		return ERR_PTR(-ENODEV);
	}

	down_write(&spg->rw_lock);
	spa = sp_area_alloc(kc.size_aligned, kc.sp_flags, spg, kc.type, current->tgid, 0);
	if (IS_ERR(spa)) {
		up_write(&spg->rw_lock);
		pr_err("alloc spa failed in k2u_spg (potential no enough virtual memory when -75): %ld\n",
				PTR_ERR(spa));
		sp_group_put(spg);
		return spa;
	}

	ret = -EINVAL;
	spa->kva = kc.kva_aligned;
	list_for_each_entry(spg_node, &spg->proc_head, proc_node) {
		struct mm_struct *mm = spg_node->master->mm;

		mmap_ret = sp_map_spa_to_mm(mm, spa, spg_node->prot, NULL, "k2u");
		if (mmap_ret) {
			if (mmap_ret == SP_SKIP_ERR)
				continue;
			pr_err("remap k2u to spg failed %d\n", mmap_ret);
			__sp_free(spa, mm);
			ret = mmap_ret;
			break;
		}
		ret = mmap_ret;
	}

	if (!ret)
		update_mem_usage(spa_size(spa), true, spa->is_hugepage, ori_node, spa->type);
	sp_area_put_locked(spa);
	up_write(&spg->rw_lock);
	sp_group_put(spg);

	return ret ? ERR_PTR(ret) : (void *)(spa->va_start + (kc.kva - kc.kva_aligned));
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
		spinlock_t *ptl = pte_lockptr(walk->mm, pmd);

		if (pte_none(*pte))
			goto no_page;
		entry = pte_to_swp_entry(*pte);
		if (!is_migration_entry(entry))
			goto no_page;

		pte_unmap_unlock(pte, ptl);
		migration_entry_wait(walk->mm, pmd, addr);
		pte = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);
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
	pr_debug("hole [%lx, %lx) appeared unexpectedly\n",
			(unsigned long)start, (unsigned long)end);
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
	pages = kvmalloc_array(page_nr, sizeof(struct page *), GFP_KERNEL);
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
		/* All the spa are aligned to 2M. */
		spg_id = (spg_id == SPG_ID_NONE) ? SPG_ID_DEFAULT : spg_id;
		ret = sp_free_inner(ALIGN_DOWN(va, PMD_SIZE), spg_id, false);
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
	ret = __sp_walk_page_range(uva, size, mm, sp_walk_data);
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
	return false;
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
	if (!sp_mapping_normal)
		goto fail;
	atomic_inc(&sp_mapping_normal->user);

	sp_mapping_ro = sp_mapping_create(SP_MAPPING_RO);
	if (!sp_mapping_ro)
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
