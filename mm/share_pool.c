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

#include <linux/share_pool.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/mm_types.h>
#include <linux/idr.h>
#include <linux/mutex.h>
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
#include <linux/idr.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rmap.h>
#include <linux/hugetlb.h>

/* access control mode macros  */
#define AC_NONE			0
#define AC_SINGLE_OWNER		1

#define spg_valid(spg)		((spg) && ((spg)->is_alive == true))
#define ESPGMMEXIT		4000

#define byte2kb(size)		((size) / 1024)
#define byte2mb(size)		((size) / 1024 / 1024)

/* mdc scene hack */
int enable_mdc_default_group;
static const int mdc_default_group_id = 1;

/* access control mode */
int sysctl_ac_mode = AC_NONE;
/* debug mode */
int sysctl_sp_debug_mode;

/* idr of all sp_groups */
static DEFINE_IDR(sp_group_idr);

static DEFINE_MUTEX(sp_mutex);

static BLOCKING_NOTIFIER_HEAD(sp_notifier_chain);

static DEFINE_IDA(sp_group_id_ida);

/*** Statistical and maintenance tools ***/

/* idr of all sp_proc_stats */
static DEFINE_IDR(sp_stat_idr);

/* per process memory usage statistics indexed by tgid */
struct sp_proc_stat {
	char comm[TASK_COMM_LEN];
	/*
	 * alloc amount minus free amount, may be negative when freed by
	 * another task in the same sp group.
	 */
	long amount;
};

/* for kthread buff_module_guard_work */
static struct sp_proc_stat kthread_stat = {0};

/*
 * The caller must hold sp_mutex and ensure no concurrency problem
 * for task_struct and mm_struct.
 */
static struct sp_proc_stat *sp_init_proc_stat(struct task_struct *tsk) {
	struct sp_proc_stat *stat;
	int id = tsk->mm->sp_stat_id;
	int tgid = tsk->tgid;
	int ret;

	if (id) {
		stat = idr_find(&sp_stat_idr, id);
		/* other threads in the same process may have initialized it */
		if (stat)
			return stat;
	}

	stat = kzalloc(sizeof(*stat), GFP_KERNEL);
	if (stat == NULL) {
		if (printk_ratelimit())
			pr_err("share pool: alloc proc stat failed due to lack of memory\n");
		return ERR_PTR(-ENOMEM);
	}

	stat->amount = 0;
	get_task_comm(stat->comm, tsk);
	ret = idr_alloc(&sp_stat_idr, stat, tgid, tgid + 1, GFP_KERNEL);
	if (ret < 0) {
		if (printk_ratelimit())
			pr_err("share pool: proc stat idr alloc failed %d\n", ret);
		kfree(stat);
		return ERR_PTR(ret);
	}

	tsk->mm->sp_stat_id = ret;
	return stat;
}

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

static struct sp_spa_stat spa_stat = {0};

/* statistics of all sp group born from sp_alloc and k2u(spg) */
struct sp_spg_stat {
	atomic_t spa_total_num;
	atomic64_t spa_total_size;
};

static struct sp_spg_stat spg_stat = {0};

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
	atomic_t use_count;		/* How many vmas use this VA region */
	struct rb_node rb_node;		/* address sorted rbtree */
	struct list_head link;		/* link to the spg->head */
	struct sp_group *spg;
	enum spa_type type;		/* where spa born from */
	struct mm_struct *mm;		/* owner of k2u(task) */
	unsigned long kva;		/* shared kva */
};
static DEFINE_SPINLOCK(sp_area_lock);
static struct rb_root sp_area_root = RB_ROOT;
static bool host_svm_sp_enable = false;

int sysctl_share_pool_hugepage_enable = 1;

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
static int spa_inc_usage(enum spa_type type, unsigned long size, bool is_dvpp)
{
	switch (type) {
	case SPA_TYPE_ALLOC:
		spa_stat.alloc_num += 1;
		spa_stat.alloc_size += size;
		break;
	case SPA_TYPE_K2TASK:
		spa_stat.k2u_task_num += 1;
		spa_stat.k2u_task_size += size;
		break;
	case SPA_TYPE_K2SPG:
		spa_stat.k2u_spg_num += 1;
		spa_stat.k2u_spg_size += size;
		break;
	default:
		/* usually impossible, perhaps a developer's mistake */
		return -EINVAL;
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
	return 0;
}

/* the caller should hold sp_area_lock */
static int spa_dec_usage(enum spa_type type, unsigned long size, bool is_dvpp)
{
	switch (type) {
	case SPA_TYPE_ALLOC:
		spa_stat.alloc_num -= 1;
		spa_stat.alloc_size -= size;
		break;
	case SPA_TYPE_K2TASK:
		spa_stat.k2u_task_num -= 1;
		spa_stat.k2u_task_size -= size;
		break;
	case SPA_TYPE_K2SPG:
		spa_stat.k2u_spg_num -= 1;
		spa_stat.k2u_spg_size -= size;
		break;
	default:
		/* usually impossible, perhaps a developer's mistake */
		return -EINVAL;
	}

	if (is_dvpp) {
		spa_stat.dvpp_size -= size;
		spa_stat.dvpp_va_size -= PMD_ALIGN(size);
	}

	spa_stat.total_num -= 1;
	spa_stat.total_size -= size;
	return 0;
}

static unsigned long sp_mmap(struct mm_struct *mm, struct file *file,
		     struct sp_area *spa, unsigned long *populate);

static void free_sp_group_id(unsigned int spg_id)
{
	if ((spg_id >= SPG_ID_AUTO_MIN && spg_id <= SPG_ID_AUTO_MAX) ||
	    (spg_id >= SPG_ID_DVPP_PASS_THROUGH_MIN &&
	     spg_id <= SPG_ID_DVPP_PASS_THROUGH_MAX))
		ida_free(&sp_group_id_ida, spg_id);
}

static void free_sp_group(struct sp_group *spg)
{
	fput(spg->file);
	fput(spg->file_hugetlb);
	idr_remove(&sp_group_idr, spg->id);
	free_sp_group_id((unsigned int)spg->id);
	kfree(spg);
}

/* The caller must hold sp_mutex. */
static struct sp_group *__sp_find_spg(int pid, int spg_id)
{
	struct sp_group *spg;
	int ret = 0;

	if (spg_id == SPG_ID_DEFAULT) {
		struct task_struct *tsk;
		rcu_read_lock();
		tsk = find_task_by_vpid(pid);
		if (!tsk || (tsk->flags & PF_EXITING))
			ret = -ESRCH;
		else
			get_task_struct(tsk);
		rcu_read_unlock();
		if (ret)
			return NULL;

		/*
		 * Once we encounter a concurrency problem here.
		 * To fix it, we believe get_task_mm() and mmput() is too
		 * heavy because we just get the pointer of sp_group.
		 */
		task_lock(tsk);
		if (tsk->mm == NULL)
			spg = NULL;
		else
			spg = tsk->mm->sp_group;
		task_unlock(tsk);

		put_task_struct(tsk);
	} else {
		spg = idr_find(&sp_group_idr, spg_id);
	}

	return spg;
}

int sp_group_id_by_pid(int pid)
{
	struct sp_group *spg;
	int spg_id = -ENODEV;

	mutex_lock(&sp_mutex);
	spg = __sp_find_spg(pid, SPG_ID_DEFAULT);
	if (spg_valid(spg))
		spg_id = spg->id;

	mutex_unlock(&sp_mutex);
	return spg_id;
}
EXPORT_SYMBOL_GPL(sp_group_id_by_pid);

/* The caller must hold sp_mutex. */
static struct sp_group *find_or_alloc_sp_group(int spg_id)
{
	struct sp_group *spg;
	int ret;
	char name[20];

	spg = idr_find(&sp_group_idr, spg_id);
	if (!spg) {
		struct user_struct *user = NULL;
		int hsize_log = MAP_HUGE_2MB >> MAP_HUGE_SHIFT;

		spg = kzalloc(sizeof(*spg), GFP_KERNEL);
		if (spg == NULL) {
			if (printk_ratelimit())
				pr_err("share pool: alloc spg failed due to lack of memory\n");
			return ERR_PTR(-ENOMEM);
		}
		spg->id = spg_id;
		atomic_set(&spg->spa_num, 0);
		atomic64_set(&spg->size, 0);
		spg->is_alive = true;
		spg->hugepage_failures = 0;
		spg->dvpp_multi_spaces = false;
		spg->owner = current->group_leader;
		atomic_set(&spg->use_count, 1);
		INIT_LIST_HEAD(&spg->procs);
		INIT_LIST_HEAD(&spg->spa_list);

		ret = idr_alloc(&sp_group_idr, spg, spg_id, spg_id+1,
				GFP_KERNEL);
		if (ret < 0) {
			if (printk_ratelimit())
				pr_err("share pool: create group idr alloc failed\n");
			goto out_kfree;
		}

		sprintf(name, "sp_group_%d", spg_id);
		spg->file = shmem_kernel_file_setup(name, MAX_LFS_FILESIZE,
						    VM_NORESERVE);
		if (IS_ERR(spg->file)) {
			if (printk_ratelimit())
				pr_err("share pool: file setup for small page failed %ld\n",
				       PTR_ERR(spg->file));
			ret = PTR_ERR(spg->file);
			goto out_idr;
		}

		spg->file_hugetlb = hugetlb_file_setup(name, MAX_LFS_FILESIZE,
					VM_NORESERVE, &user,
					HUGETLB_ANONHUGE_INODE, hsize_log);
		if (IS_ERR(spg->file_hugetlb)) {
			if (printk_ratelimit())
				pr_err("share pool: file setup for hugepage failed %ld\n",
				       PTR_ERR(spg->file_hugetlb));
			ret = PTR_ERR(spg->file_hugetlb);
			goto out_fput;
		}
	} else {
		if (!spg_valid(spg))
			return ERR_PTR(-ENODEV);
		atomic_inc(&spg->use_count);
	}

	return spg;

out_fput:
	fput(spg->file);
out_idr:
	idr_remove(&sp_group_idr, spg_id);
out_kfree:
	kfree(spg);
	return ERR_PTR(ret);
}

static void __sp_area_drop_locked(struct sp_area *spa);

/* The caller must hold sp_mutex. */
static void sp_munmap_task_areas(struct mm_struct *mm, struct list_head *stop)
{
	struct sp_area *spa, *prev = NULL;
	int err;

	spin_lock(&sp_area_lock);

	list_for_each_entry(spa, &mm->sp_group->spa_list, link) {
		if (&spa->link == stop)
			break;

		if (prev)
			__sp_area_drop_locked(prev);
		prev = spa;

		atomic_inc(&spa->use_count);
		spin_unlock(&sp_area_lock);

		err = do_munmap(mm, spa->va_start, spa_size(spa), NULL);
		if (err) {
			/* we are not supposed to fail */
			pr_err("share pool: failed to unmap VA %pK when munmap task areas\n",
			       (void *)spa->va_start);
		}

		spin_lock(&sp_area_lock);
	}
	if (prev)
		__sp_area_drop_locked(prev);

	spin_unlock(&sp_area_lock);
}

/* The caller must hold sp_mutex. */
static void __sp_group_drop_locked(struct sp_group *spg)
{
	bool is_alive = spg->is_alive;

	if (atomic_dec_and_test(&spg->use_count)) {
		BUG_ON(is_alive);
		free_sp_group(spg);
	}
}

/**
 * sp_group_add_task - add a process to an sp_group
 * @pid: the pid of the task to be added
 * @spg_id: the ID of the sp_group
 *
 * A thread group can't be added to more than one sp_group.
 *
 * Return: The manually allocated ID is between [SPG_ID_MIN, SPG_ID_MAX]
 * The automatically allocated ID is between [SPG_ID_AUTO_MIN, SPG_ID_AUTO_MAX]
 * When negative, the return value is -errno.
 */
int sp_group_add_task(int pid, int spg_id)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct sp_group *spg;
	int ret = 0;
	struct sp_area *spa, *prev = NULL;
	struct sp_proc_stat *stat;

	/* mdc scene hack */
	if (enable_mdc_default_group)
		spg_id = mdc_default_group_id;

	if ((spg_id < SPG_ID_MIN || spg_id > SPG_ID_AUTO)
	    && spg_id != SPG_ID_DVPP_PASS_THROUGH) {
		if (printk_ratelimit())
			pr_err("share pool: task add group failed due to invalid group id %d\n", spg_id);
		return -EINVAL;
	}

	if (spg_id >= SPG_ID_AUTO_MIN && spg_id <= SPG_ID_AUTO_MAX) {
		mutex_lock(&sp_mutex);
		spg = idr_find(&sp_group_idr, spg_id);
		if (!spg_valid(spg)) {
			mutex_unlock(&sp_mutex);
			if (printk_ratelimit())
				pr_err("share pool: task add group failed because group id %d "
				       "hasn't been create or dead\n", spg_id);
			return -EINVAL;
		}
		mutex_unlock(&sp_mutex);
	}

	if (spg_id == SPG_ID_AUTO) {
		spg_id = ida_alloc_range(&sp_group_id_ida, SPG_ID_AUTO_MIN,
					 SPG_ID_AUTO_MAX, GFP_ATOMIC);
		if (spg_id < 0) {
			if (printk_ratelimit())
				pr_err("share pool: task add group failed when automatically "
				       "generate group id failed\n");
			return spg_id;
		}
	}

	if (spg_id == SPG_ID_DVPP_PASS_THROUGH) {
		spg_id = ida_alloc_range(&sp_group_id_ida,
			SPG_ID_DVPP_PASS_THROUGH_MIN,
			SPG_ID_DVPP_PASS_THROUGH_MAX, GFP_ATOMIC);
		if (spg_id < 0) {
			if (printk_ratelimit())
				pr_err("share pool: task add group failed when automatically "
				       "generate group id failed in DVPP pass through\n");
			return spg_id;
		}
	}

	mutex_lock(&sp_mutex);

	rcu_read_lock();

	tsk = find_task_by_vpid(pid);
	if (!tsk || (tsk->flags & PF_EXITING))
		ret = -ESRCH;
	else if (tsk->mm->sp_group)	/* if it's already in a sp_group */
		ret = -EEXIST;
	else
		get_task_struct(tsk);

	rcu_read_unlock();
	if (ret) {
		free_sp_group_id((unsigned int)spg_id);
		goto out_unlock;
	}

	spg = find_or_alloc_sp_group(spg_id);
	if (IS_ERR(spg)) {
		ret = PTR_ERR(spg);
		free_sp_group_id((unsigned int)spg_id);
		goto out_put_task;
	}

	/* access control permission check */
	if (sysctl_ac_mode == AC_SINGLE_OWNER) {
		if (spg->owner != current->group_leader) {
			ret = -EPERM;
			goto out_drop_group;
		}
	}

	/* current thread may be exiting in a multithread process */
	mm = get_task_mm(tsk->group_leader);
	if (!mm) {
		ret = -ESRCH;
		goto out_drop_group;
	}

	/* per process statistics initialization */
	stat = sp_init_proc_stat(tsk);
	if (IS_ERR(stat)) {
		ret = PTR_ERR(stat);
		pr_err("share pool: init proc stat failed, ret %lx\n", PTR_ERR(stat));
		goto out_put_mm;
	}

	mm->sp_group = spg;
	list_add_tail(&tsk->mm->sp_node, &spg->procs);
	/*
	 * create mappings of existing shared memory segments into this
	 * new process' page table.
	 */
	spin_lock(&sp_area_lock);

	list_for_each_entry(spa, &spg->spa_list, link) {
		unsigned long populate = 0;
		struct file *file = spa_file(spa);
		unsigned long addr;

		if (prev)
			__sp_area_drop_locked(prev);
		prev = spa;

		atomic_inc(&spa->use_count);
		spin_unlock(&sp_area_lock);

		down_write(&mm->mmap_sem);
		addr = sp_mmap(mm, file, spa, &populate);
		if (IS_ERR_VALUE(addr)) {
			sp_munmap_task_areas(mm, &spa->link);
			up_write(&mm->mmap_sem);
			ret = addr;
			pr_err("share pool: task add group sp mmap failed, ret %d\n", ret);
			spin_lock(&sp_area_lock);
			break;
		}
		up_write(&mm->mmap_sem);

		if (populate) {
			ret = do_mm_populate(mm, spa->va_start, populate, 0);
			if (ret) {
				if (printk_ratelimit())
					pr_warn("share pool: task add group failed when mm populate "
						"failed (potential no enough memory): %d\n", ret);
				sp_munmap_task_areas(mm, spa->link.next);
				spin_lock(&sp_area_lock);
				break;
			}
		}

		spin_lock(&sp_area_lock);
	}
	if (prev)
		__sp_area_drop_locked(prev);
	spin_unlock(&sp_area_lock);

	if (unlikely(ret)) {
		idr_remove(&sp_stat_idr, mm->sp_stat_id);
		kfree(stat);
		mm->sp_stat_id = 0;
		list_del(&mm->sp_node);
		mm->sp_group = NULL;
	}

out_put_mm:
	mmput(mm);
out_drop_group:
	if (unlikely(ret))
		__sp_group_drop_locked(spg);
out_put_task:
	put_task_struct(tsk);
out_unlock:
	mutex_unlock(&sp_mutex);
	return ret == 0 ? spg_id : ret;
}
EXPORT_SYMBOL_GPL(sp_group_add_task);

static void spg_exit_lock(bool *unlock)
{
	switch (mutex_trylock_recursive(&sp_mutex)) {
	case MUTEX_TRYLOCK_RECURSIVE:
		*unlock = false;
		break;
	case MUTEX_TRYLOCK_FAILED:
		mutex_lock(&sp_mutex);
		*unlock = true;
		break;
	case MUTEX_TRYLOCK_SUCCESS:
		*unlock = true;
		break;
	default:
		BUG();
	}
}

static void spg_exit_unlock(bool unlock)
{
	if (unlock)
		mutex_unlock(&sp_mutex);
}

/*
 * Do cleanup when a process exits.
 */
void sp_group_exit(struct mm_struct *mm)
{
	bool is_alive = true;
	bool unlock;

	/*
	 * Nothing to do if this thread group doesn't belong to any sp_group.
	 * No need to protect this check with lock because we can add a task
	 * to a group if !PF_EXITING.
	 */
	if (!mm->sp_group)
		return;

	spg_exit_lock(&unlock);
	if (list_is_singular(&mm->sp_group->procs))
		is_alive = mm->sp_group->is_alive = false;
	list_del(&mm->sp_node);
	spg_exit_unlock(unlock);

	/*
	 * To avoid calling this with sp_mutex held, we first mark the
	 * sp_group as dead and then send the notification and then do
	 * the real cleanup in sp_group_post_exit().
	 */
	if (!is_alive)
		blocking_notifier_call_chain(&sp_notifier_chain, 0,
					     mm->sp_group);
}

void sp_group_post_exit(struct mm_struct *mm)
{
	struct sp_proc_stat *stat;
	bool unlock;

	if (!mm->sp_group)
		return;

	spg_exit_lock(&unlock);

	/* pointer stat must be valid, we don't need to check sanity */
	stat = idr_find(&sp_stat_idr, mm->sp_stat_id);
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
	 * We decide to print a info when seeing both of the scenarios.
	 */
	if (stat && stat->amount != 0)
		pr_info("share pool: process %s(%d) of sp group %d exits. "
			"It applied %ld aligned KB\n",
			stat->comm, mm->sp_stat_id,
			mm->sp_group->id, byte2kb(stat->amount));

	idr_remove(&sp_stat_idr, mm->sp_stat_id);

	__sp_group_drop_locked(mm->sp_group);
	spg_exit_unlock(unlock);

	kfree(stat);
}

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

/*
 * Allocate a region of VA from the share pool.
 * @size - the size of VA to allocate
 *
 * The caller must hold must sp_mutex when input parameter spg is not NULL
 *
 * Return NULL if fail.
 */
static struct sp_area *sp_alloc_area(unsigned long size, unsigned long flags,
				     struct sp_group *spg, enum spa_type type)
{
	struct sp_area *spa, *first, *err;
	struct rb_node *n;
	unsigned long vstart = MMAP_SHARE_POOL_START;
	unsigned long vend = MMAP_SHARE_POOL_16G_START;
	unsigned long addr;
	unsigned long size_align = PMD_ALIGN(size); /* va aligned to 2M */

	if ((flags & SP_DVPP)) {
		if (host_svm_sp_enable == false) {
			vstart = MMAP_SHARE_POOL_16G_START;
			vend = MMAP_SHARE_POOL_16G_START + MMAP_SHARE_POOL_16G_SIZE;
		} else {
			if (!spg) {
				if (printk_ratelimit())
					pr_err("share pool: don't allow k2u(task) in host svm multiprocess scene\n");
				return ERR_PTR(-EINVAL);
			}
			vstart = spg->dvpp_va_start;
			vend = spg->dvpp_va_start + spg->dvpp_size;
		}
	}

	spa = kmalloc(sizeof(struct sp_area), GFP_KERNEL);
	if (unlikely(!spa)) {
		if (printk_ratelimit())
			pr_err("share pool: alloc spa failed due to lack of memory\n");
		return ERR_PTR(-ENOMEM);
	}

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
	spa->spg = spg;
	atomic_set(&spa->use_count, 1);
	spa->type = type;
	spa->mm = NULL;
	spa->kva = 0;   /* NULL pointer */

	if (spa_inc_usage(type, size, (flags & SP_DVPP))) {
		err = ERR_PTR(-EINVAL);
		goto error;
	}

	__insert_sp_area(spa);
	free_sp_area_cache = &spa->rb_node;
	if (spa->spg) {
		atomic_inc(&spg->spa_num);
		atomic64_add(size, &spg->size);
		atomic_inc(&spg_stat.spa_total_num);
		atomic64_add(size, &spg_stat.spa_total_size);
		list_add_tail(&spa->link, &spg->spa_list);
	}
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

	spa_dec_usage(spa->type, spa->real_size, (spa->flags & SP_DVPP));  /* won't fail */
	if (spa->spg) {
		atomic_dec(&spa->spg->spa_num);
		atomic64_sub(spa->real_size, &spa->spg->size);
		atomic_dec(&spg_stat.spa_total_num);
		atomic64_sub(spa->real_size, &spg_stat.spa_total_size);
		list_del(&spa->link);
	}
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

/* The caller must hold sp_mutex. */
static void sp_munmap(struct mm_struct *mm, unsigned long addr,
			   unsigned long size)
{
	int err;

	if (!mmget_not_zero(mm))
		return;
	down_write(&mm->mmap_sem);

	err = do_munmap(mm, addr, size, NULL);
	if (err) {
		/* we are not supposed to fail */
		pr_err("share pool: failed to unmap VA %pK when sp munmap\n", (void *)addr);
	}

	up_write(&mm->mmap_sem);
	mmput(mm);
}

/* The caller must hold sp_mutex. */
static void __sp_free(struct sp_group *spg, unsigned long addr,
		      unsigned long size, struct mm_struct *stop)
{
	struct mm_struct *mm;
	struct mm_struct *tmp;

	list_for_each_entry_safe(mm, tmp, &spg->procs, sp_node) {
		if (mm == stop)
			break;
		sp_munmap(mm, addr, size);
	}
}

/*
 * Free the memory allocated by sp_alloc()
 * @addr - the starting VA of the memory
 *
 * Return fail if the memory can't be found or was not allocted by share pool.
 */
int sp_free(unsigned long addr)
{
	struct sp_area *spa;
	struct sp_proc_stat *stat;
	int mode;
	loff_t offset;
	int ret = 0;

	mutex_lock(&sp_mutex);

	/*
	 * Access control: a share pool addr can only be freed by another task
	 * in the same spg or a kthread (such as buff_module_guard_work)
	 */
	spa = __find_sp_area(addr);
	if (spa) {
		if (current->mm != NULL) {
			if (current->mm->sp_group != spa->spg) {
				ret = -EPERM;
				goto drop_spa;
			}
		}
	} else {  /* spa == NULL */
		ret = -EINVAL;
		if (printk_ratelimit())
			pr_err("share pool: sp free invalid input addr %pK\n", (void *)addr);
		goto out;
	}

	if (spa->type != SPA_TYPE_ALLOC) {
		ret = -EINVAL;
		if (printk_ratelimit())
			pr_err("share pool: sp free failed, addr %pK is not from sp_alloc\n",
			       (void *)addr);
		goto drop_spa;
	}

	if (!spg_valid(spa->spg))
		goto drop_spa;

	sp_dump_stack();

	__sp_free(spa->spg, spa->va_start, spa_size(spa), NULL);

	/* Free the memory of the backing shmem or hugetlbfs */
	mode = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;
	offset = addr - MMAP_SHARE_POOL_START;
	ret = vfs_fallocate(spa_file(spa), mode, offset, spa_size(spa));
	if (ret)
		pr_err("share pool: sp free fallocate failed: %d\n", ret);

	/* pointer stat may be invalid because of kthread buff_module_guard_work */
	if (current->mm == NULL) {
		kthread_stat.amount -= spa->real_size;
	} else {
		stat = idr_find(&sp_stat_idr, current->mm->sp_stat_id);
		if (stat)
			stat->amount -= spa->real_size;
		else
			BUG();
	}

drop_spa:
	__sp_area_drop(spa);
out:
	mutex_unlock(&sp_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(sp_free);

/* wrapper of __do_mmap() and the caller must hold down_write(&mm->mmap_sem). */
static unsigned long sp_mmap(struct mm_struct *mm, struct file *file,
			       struct sp_area *spa, unsigned long *populate)
{
	unsigned long addr = spa->va_start;
	unsigned long size = spa_size(spa);
	unsigned long prot = PROT_READ | PROT_WRITE;
	unsigned long flags = MAP_FIXED | MAP_SHARED | MAP_LOCKED |
			      MAP_POPULATE | MAP_SHARE_POOL;
	unsigned long vm_flags = VM_NORESERVE | VM_SHARE_POOL | VM_DONTCOPY;
	unsigned long pgoff = (addr - MMAP_SHARE_POOL_START) >> PAGE_SHIFT;

	atomic_inc(&spa->use_count);
	addr = __do_mmap(mm, file, addr, size, prot, flags, vm_flags, pgoff,
			 populate, NULL);
	if (IS_ERR_VALUE(addr)) {
		atomic_dec(&spa->use_count);
		pr_err("share pool: do_mmap fails %ld\n", addr);
	} else {
		BUG_ON(addr != spa->va_start);
	}

	return addr;
}

/**
 * Allocate shared memory for all the processes in the same sp_group
 * size - the size of memory to allocate
 * sp_flags - how to allocate the memory
 * spg_id - the share group that the memory is allocated to.
 *
 * Use spg_id of current thread if spg_id == SPG_ID_DEFAULT.
 */
void *sp_alloc(unsigned long size, unsigned long sp_flags, int spg_id)
{
	struct sp_group *spg = NULL;
	struct sp_area *spa = NULL;
	struct sp_proc_stat *stat;
	unsigned long sp_addr;
	unsigned long mmap_addr;
	void *p = ERR_PTR(-ENODEV);
	struct mm_struct *mm;
	struct file *file;
	unsigned long size_aligned;
	int ret = 0;
	struct mm_struct *tmp;
	unsigned long mode, offset;

	/* mdc scene hack */
	if (enable_mdc_default_group)
		spg_id = mdc_default_group_id;

	if (spg_id != SPG_ID_DEFAULT && spg_id < SPG_ID_MIN) {
		if (printk_ratelimit())
			pr_err("share pool: allocation failed due to invalid group id %d\n", spg_id);
		return ERR_PTR(-EINVAL);
	}

	if (sp_flags & ~(SP_HUGEPAGE_ONLY | SP_HUGEPAGE | SP_DVPP)) {
		if (printk_ratelimit())
			pr_err("share pool: allocation failed due to invalid flag %lu\n", sp_flags);
		return ERR_PTR(-EINVAL);
	}

	if (sp_flags & SP_HUGEPAGE_ONLY)
		sp_flags |= SP_HUGEPAGE;

	mutex_lock(&sp_mutex);
	spg = __sp_find_spg(current->pid, SPG_ID_DEFAULT);
	mutex_unlock(&sp_mutex);
	if (!spg) {  /* DVPP pass through scene: first call sp_alloc() */
		/* mdc scene hack */
		if (enable_mdc_default_group)
			ret = sp_group_add_task(current->tgid, spg_id);
		else
			ret = sp_group_add_task(current->tgid,
					SPG_ID_DVPP_PASS_THROUGH);
		/*
		 * The multi-thread contention may cause repeated joins to the group.
		 * The judgment is added to prevent exit in this case.
		 */
		if (ret < 0 && (ret != -EEXIST)) {
			pr_err("share pool: allocation failed due to add group error %d in DVPP pass through scenario",
			       ret);
			return ERR_PTR(ret);
		}
		mutex_lock(&sp_mutex);
		spg = current->mm->sp_group;
	} else {  /* other scenes */
		mutex_lock(&sp_mutex);
		if (spg_id != SPG_ID_DEFAULT) {
			/* the caller should be a member of the sp group */
			if (spg != idr_find(&sp_group_idr, spg_id))
				goto out;
		}
	}

	if (!spg_valid(spg)) {
		pr_err("share pool: sp alloc failed, spg is invalid\n");
		goto out;
	}

	if (sp_flags & SP_HUGEPAGE) {
		file = spg->file_hugetlb;
		size_aligned = ALIGN(size, PMD_SIZE);
	} else {
		file = spg->file;
		size_aligned = ALIGN(size, PAGE_SIZE);
	}
try_again:
	spa = sp_alloc_area(size_aligned, sp_flags, spg, SPA_TYPE_ALLOC);
	if (IS_ERR(spa)) {
		if (printk_ratelimit())
			pr_err("share pool: allocation failed due to alloc spa failure "
			       "(potential no enough virtual memory when -75): %ld\n",
			       PTR_ERR(spa));
		p = spa;
		goto out;
	}
	sp_addr = spa->va_start;

	/* create mapping for each process in the group */
	list_for_each_entry_safe(mm, tmp, &spg->procs, sp_node) {
		unsigned long populate = 0;
		struct vm_area_struct *vma;

		if (!mmget_not_zero(mm))
			continue;

		down_write(&mm->mmap_sem);
		mmap_addr = sp_mmap(mm, file, spa, &populate);
		if (IS_ERR_VALUE(mmap_addr)) {
			up_write(&mm->mmap_sem);
			p = (void *)mmap_addr;
			__sp_free(spg, sp_addr, size_aligned, mm);
			mmput(mm);
			pr_err("share pool: allocation sp mmap failed, ret %ld\n", mmap_addr);
			goto out;
		}

		p =(void *)mmap_addr;  /* success */
		if (populate == 0) {
			up_write(&mm->mmap_sem);
			mmput(mm);
			continue;
		}

		vma = find_vma(mm, sp_addr);
		if (unlikely(!vma)) {
			up_write(&mm->mmap_sem);
			mmput(mm);
			pr_err("share pool: allocation failed due to find %pK vma failure\n",
			       (void *)sp_addr);
			p = ERR_PTR(-EINVAL);
			goto out;
		}
		/* clean PTE_RDONLY flags or trigger SMMU event */
		vma->vm_page_prot = __pgprot(((~PTE_RDONLY) & vma->vm_page_prot.pgprot) | PTE_DIRTY);
		up_write(&mm->mmap_sem);
		/*
		 * We are not ignoring errors, so if we fail to allocate
		 * physical memory we just return failure, so we won't encounter
		 * page fault later on, and more importantly sp_make_share_u2k()
		 * depends on this feature (and MAP_LOCKED) to work correctly.
		 */
		ret = do_mm_populate(mm, sp_addr, populate, 0);
		if (ret) {
			__sp_free(spg, sp_addr, size_aligned,
					list_next_entry(mm, sp_node));

			if (printk_ratelimit())
				pr_warn("share pool: allocation failed due to mm populate failed"
					"(potential no enough memory when -12): %d\n", ret);
			p = ERR_PTR(ret);

			mode = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;
			offset = sp_addr - MMAP_SHARE_POOL_START;

			ret = vfs_fallocate(spa_file(spa), mode, offset, spa_size(spa));
			if (ret)
				pr_err("share pool: sp alloc normal page fallocate failed %d\n", ret);

			if (file == spg->file_hugetlb) {
				spg->hugepage_failures++;

				/* fallback to small pages */
				if (!(sp_flags & SP_HUGEPAGE_ONLY)) {
					file = spg->file;
					size_aligned = ALIGN(size, PAGE_SIZE);
					sp_flags &= ~SP_HUGEPAGE;
					__sp_area_drop(spa);
					mmput(mm);
					goto try_again;
				}
			}

			mmput(mm);
			break;
		}
		mmput(mm);
	}

	if (!IS_ERR(p)) {
		stat = idr_find(&sp_stat_idr, current->mm->sp_stat_id);
		if (stat)
			stat->amount += size_aligned;
	}

out:
	mutex_unlock(&sp_mutex);

	/* this will free spa if mmap failed */
	if (spa && !IS_ERR(spa))
		__sp_area_drop(spa);

	sp_dump_stack();
	return p;
}
EXPORT_SYMBOL_GPL(sp_alloc);

/*
 * return value: >0 means this is a hugepage addr
 * =0 means a normal addr. <0 means an errno.
 */
static int is_vmap_hugepage(unsigned long addr)
{
	struct vm_struct *area;

	if (unlikely(!addr)) {
		if (printk_ratelimit())
			pr_err("share pool: null pointer when judge vmap addr\n");
		return -EINVAL;
	}

	area = find_vm_area((void *)addr);
	if (unlikely(!area)) {
		if (printk_ratelimit())
			pr_err("share pool: failed to find vm area(%lx)\n", addr);
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

static unsigned long sp_remap_kva_to_vma(unsigned long kva, struct sp_area *spa,
					 struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	unsigned long ret_addr;
	unsigned long populate = 0;
	struct file *file = NULL;
	int ret = 0;
	struct user_struct *user = NULL;
	int hsize_log = MAP_HUGE_2MB >> MAP_HUGE_SHIFT;
	unsigned long addr, buf, offset;

	if (spa->is_hugepage) {
		file = hugetlb_file_setup(HUGETLB_ANON_FILE, spa_size(spa), VM_NORESERVE,
					  &user, HUGETLB_ANONHUGE_INODE, hsize_log);
		if (IS_ERR(file)) {
			pr_err("share pool: file setup for k2u hugepage failed %ld\n", PTR_ERR(file));
			return PTR_ERR(file);
		}
	}

	if (!mmget_not_zero(mm)) {
		ret_addr = -ESPGMMEXIT;
		goto put_file;
	}
	down_write(&mm->mmap_sem);

	ret_addr = sp_mmap(mm, file, spa, &populate);
	if (IS_ERR_VALUE(ret_addr)) {
		pr_err("share pool: k2u mmap failed %lx\n", ret_addr);
		goto put_mm;
	}
	BUG_ON(ret_addr != spa->va_start);

	vma = find_vma(mm, ret_addr);
	BUG_ON(vma == NULL);
	vma->vm_page_prot = __pgprot(((~PTE_RDONLY) & vma->vm_page_prot.pgprot) | PTE_DIRTY);

	if (is_vm_hugetlb_page(vma)) {
		ret = remap_vmalloc_hugepage_range(vma, (void *)kva, 0);
		if (ret) {
			do_munmap(mm, ret_addr, spa_size(spa), NULL);
			pr_err("share pool: remap vmalloc hugepage failed, ret %d\n", ret);
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
				pr_err("share pool: remap_pfn_range failed, ret %d\n", ret);
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
	mmput(mm);
put_file:
	if (file)
		fput(file);

	return ret_addr;
}

static void *sp_make_share_kva_to_task(unsigned long kva, struct sp_area *spa,
				       int pid)
{
	struct task_struct *tsk;
	unsigned long ret_addr;
	void *p = ERR_PTR(-ENODEV);
	int ret = 0;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (!tsk || (tsk->flags & PF_EXITING))
		ret = -ESRCH;
	else
		get_task_struct(tsk);

	rcu_read_unlock();
	if (ret)
		return ERR_PTR(ret);

	ret_addr = sp_remap_kva_to_vma(kva, spa, tsk->mm);
	if (IS_ERR_VALUE(ret_addr)) {
		pr_err("share pool: remap k2u to task failed, ret %ld\n", ret_addr);
		p = ERR_PTR(ret_addr);
		goto out;
	}

	p = (void *)ret_addr;

	task_lock(tsk);
	if (tsk->mm == NULL) {
		sp_munmap(tsk->mm, spa->va_start, spa_size(spa));
		p = ERR_PTR(-ESRCH);
	} else {
		spa->mm = tsk->mm;
	}
	task_unlock(tsk);
out:
	put_task_struct(tsk);
	return p;
}

static void *sp_make_share_kva_to_spg(unsigned long kva, struct sp_area *spa,
				      struct sp_group *spg)
{
	struct mm_struct *mm;
	struct mm_struct *tmp;
	unsigned long ret_addr = -ENODEV;
	unsigned long uva = -ENODEV;
	void *p = ERR_PTR(-ENODEV);

	list_for_each_entry_safe(mm, tmp, &spg->procs, sp_node) {
		ret_addr = sp_remap_kva_to_vma(kva, spa, mm);
		if (IS_ERR_VALUE(ret_addr) && (ret_addr != -ESPGMMEXIT)) {
			pr_err("share pool: remap k2u to spg failed, ret %ld \n", ret_addr);
			__sp_free(spg, spa->va_start, spa_size(spa), mm);
			p = ERR_PTR(ret_addr);
			goto out;
		}

		if (ret_addr == -ESPGMMEXIT) {
			pr_info("share pool: remap k2u, ret is -ESPGMMEXIT\n");
			continue;
		}

		uva = ret_addr;
	}
	p = (void *)uva;
out:
	return p;
}

/**
 * Share kernel memory to a specified process or sp_group
 * @kva: the VA of shared kernel memory
 * @size: the size of shared kernel memory
 * @sp_flags: how to allocate the memory. We only support SP_DVPP.
 * @pid:  the pid of the specified process
 * @spg_id: currently, only support default value(SPG_ID_DEFAULT) and other values
 * are useless.
 *
 * Return: the shared target user address to start at
 *
 * Use spg_id of current thread if spg_id == SPG_ID_DEFAULT.
 */
void *sp_make_share_k2u(unsigned long kva, unsigned long size,
			unsigned long sp_flags, int pid, int spg_id)
{
	void *uva = ERR_PTR(-ENODEV);
	struct sp_group *spg;
	struct sp_area *spa;
	unsigned long kva_aligned;
	unsigned long size_aligned;
	unsigned int page_size = PAGE_SIZE;
	int ret;
	struct vm_struct *area;

	if (sp_flags & ~SP_DVPP) {
		if (printk_ratelimit())
			pr_err("share pool: k2u sp_flags %lu error\n", sp_flags);
		return ERR_PTR(-EINVAL);
	}

	ret = is_vmap_hugepage(kva);
	if (ret > 0) {
		sp_flags |= SP_HUGEPAGE;
		page_size = PMD_SIZE;
	} else if (ret == 0) {
		/* do nothing */
	} else {
		pr_err("it is not vmalloc address\n");
		return ERR_PTR(ret);
	}
	/* aligned down kva is convenient for caller to start with any valid kva */
	kva_aligned = ALIGN_DOWN(kva, page_size);
	size_aligned = ALIGN(kva + size, page_size) - kva_aligned;

	mutex_lock(&sp_mutex);
	spg = __sp_find_spg(pid, SPG_ID_DEFAULT);
	if (spg == NULL) {
		/* k2u to task */
		if (spg_id != SPG_ID_NONE && spg_id != SPG_ID_DEFAULT) {
			mutex_unlock(&sp_mutex);
			if (printk_ratelimit())
				pr_err("share pool: k2task invalid spg id %d\n", spg_id);
			return ERR_PTR(-EINVAL);
		}
		spa = sp_alloc_area(size_aligned, sp_flags, NULL, SPA_TYPE_K2TASK);
		if (IS_ERR(spa)) {
			mutex_unlock(&sp_mutex);
			if (printk_ratelimit())
				pr_err("share pool: k2u(task) failed due to alloc spa failure "
				       "(potential no enough virtual memory when -75): %ld\n",
				       PTR_ERR(spa));
			return spa;
		}
		uva = sp_make_share_kva_to_task(kva_aligned, spa, pid);
		mutex_unlock(&sp_mutex);
	} else if (spg_valid(spg)) {
		/* k2u to group */
		if (spg_id != SPG_ID_DEFAULT && spg_id != spg->id) {
			mutex_unlock(&sp_mutex);
			if (printk_ratelimit())
				pr_err("share pool: k2spg invalid spg id %d\n", spg_id);
			return ERR_PTR(-EINVAL);
		}
		spa = sp_alloc_area(size_aligned, sp_flags, spg, SPA_TYPE_K2SPG);
		if (IS_ERR(spa)) {
			mutex_unlock(&sp_mutex);
			if (printk_ratelimit())
				pr_err("share pool: k2u(spg) failed due to alloc spa failure "
				       "(potential no enough virtual memory when -75): %ld\n",
				       PTR_ERR(spa));
			return spa;
		}

		uva = sp_make_share_kva_to_spg(kva_aligned, spa, spg);
		mutex_unlock(&sp_mutex);
	} else {
		mutex_unlock(&sp_mutex);
		pr_err("share pool: failed to make k2u\n");
		return NULL;
	}

	if (!IS_ERR(uva))
		uva = uva + (kva - kva_aligned);

	__sp_area_drop(spa);

	if (!IS_ERR(uva)) {
		/* associate vma and spa */
		area = find_vm_area((void *)kva);
		if (area)
			area->flags |= VM_SHAREPOOL;
		spa->kva = kva;
	}
	sp_dump_stack();

	return uva;
}
EXPORT_SYMBOL_GPL(sp_make_share_k2u);

static int sp_pte_entry(pte_t *pte, unsigned long addr,
			unsigned long next, struct mm_walk *walk)
{
	struct page *page = pte_page(*pte);
	struct sp_walk_data *sp_walk_data;

	if (unlikely(!pte_present(*pte))) {
		if (printk_ratelimit())
			pr_err("share pool: the page of addr %pK unexpectedly not in RAM\n", (void *)addr);
		return -EFAULT;
	}

	sp_walk_data = walk->private;
	get_page(page);
	sp_walk_data->pages[sp_walk_data->page_count++] = page;
	return 0;
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
	if (printk_ratelimit())
		pr_err("share pool: hole [%pK, %pK) appeared unexpectedly\n",
		       (void *)start, (void *)end);
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
		if (printk_ratelimit())
			pr_err("share pool: the page of addr %pK unexpectedly "
			       "not in RAM\n", (void *)addr);
		return -EFAULT;
	}

	sp_walk_data = walk->private;
	get_page(page);
	sp_walk_data->pages[sp_walk_data->page_count++] = page;
	return 0;
}

/**
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
	struct task_struct *tsk, struct sp_walk_data *sp_walk_data)
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
	vma = find_vma(tsk->mm, uva);
	if (!vma) {
		if (printk_ratelimit())
			pr_err("share pool: u2k input uva %pK is invalid\n", (void *)uva);
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
		if (printk_ratelimit())
			pr_err("share pool: overflow happened in walk page range\n");
		return -EINVAL;
	}

	page_nr = size_aligned / page_size;
	pages = kvmalloc(page_nr * sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		if (printk_ratelimit())
			pr_err("share pool: alloc page array failed in walk page range\n");
		return -ENOMEM;
	}
	sp_walk_data->pages = pages;

	sp_walk.mm = tsk->mm;
	sp_walk.private = sp_walk_data;

	ret = walk_page_range(uva_aligned, uva_aligned + size_aligned,
			      &sp_walk);
	if (ret)
		kvfree(pages);

	return ret;
}

/**
 * Share user memory of a specified process to kernel
 * @uva: the VA of shared user memory
 * @size: the size of shared user memory
 * @pid: the pid of the specified process
 *
 * Return: if success, return the starting kernel address of the shared memory.
 *         if failed, return the pointer of -errno.
 */
void *sp_make_share_u2k(unsigned long uva, unsigned long size, int pid)
{
	int ret = 0;
	struct task_struct *tsk;
	void *p = ERR_PTR(-ENODEV);
	struct sp_walk_data sp_walk_data = {
		.page_count = 0,
	};
	struct vm_struct *area;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (!tsk || (tsk->flags & PF_EXITING))
		ret = -ESRCH;
	else
		get_task_struct(tsk);
	rcu_read_unlock();
	if (ret) {
		p = ERR_PTR(ret);
		goto out;
	}

	if (!mmget_not_zero(tsk->mm))
		goto out_put_task;
	down_write(&tsk->mm->mmap_sem);
	ret = __sp_walk_page_range(uva, size, tsk, &sp_walk_data);
	if (ret) {
		pr_err("share pool: walk page range failed, ret %d\n", ret);
		up_write(&tsk->mm->mmap_sem);
		mmput(tsk->mm);
		p = ERR_PTR(ret);
		goto out_put_task;
	}

	if (sp_walk_data.is_hugepage)
		p = vmap_hugepage(sp_walk_data.pages, sp_walk_data.page_count,
				  VM_MAP | VM_HUGE_PAGES, PAGE_KERNEL);
	else
		p = vmap(sp_walk_data.pages, sp_walk_data.page_count, VM_MAP,
			 PAGE_KERNEL);
	up_write(&tsk->mm->mmap_sem);
	mmput(tsk->mm);

	if (!p) {
		if (printk_ratelimit())
			pr_err("share pool: vmap(huge) in u2k failed\n");
		p = ERR_PTR(-ENOMEM);
		goto out_free_pages;
	} else {
		p = p + (uva - sp_walk_data.uva_aligned);
	}

	/*
	 * kva p may be used later in k2u. Since p comes from uva originally,
	 * it's reasonable to add flag VM_USERMAP so that p can be remapped
	 * into userspace again.
	 */
	area = find_vm_area(p);
	area->flags |= VM_USERMAP;

out_free_pages:
	kvfree(sp_walk_data.pages);
out_put_task:
	put_task_struct(tsk);
out:
	return p;
}
EXPORT_SYMBOL_GPL(sp_make_share_u2k);

/*
 * Input parameters uva, pid and spg_id are now useless. spg_id will be useful
 * when supporting a process in multiple sp groups.
 *
 * Procedure of unshare uva must be compatible with:
 *
 * 1. DVPP channel destroy procedure:
 * do_exit() -> exit_mm() (mm no longer in spg and current->mm == NULL) ->
 * exit_task_work() -> task_work_run() -> __fput() -> ... -> vdec_close() ->
 * sp_unshare(uva, SPG_ID_DEFAULT)
 *
 * 2. Process A once was the target of k2u(to group), then it exits.
 * Guard worker kthread tries to free this uva and it must succeed, otherwise
 * spa of this uva leaks.
 *
 * This also means we must trust DVPP channel destroy and guard worker code.
 */
static int sp_unshare_uva(unsigned long uva, unsigned long size, int pid, int spg_id)
{
	int ret = 0;
	struct mm_struct *mm;
	struct sp_area *spa;
	unsigned long uva_aligned;
	unsigned long size_aligned;
	unsigned int page_size;
	struct vm_struct *area;

	mutex_lock(&sp_mutex);
	/*
	 * at first we guess it's a hugepage addr
	 * we can tolerate at most PMD_SIZE or PAGE_SIZE which is matched in k2u
	 */
	spa = __find_sp_area(ALIGN_DOWN(uva, PMD_SIZE));
	if (!spa) {
		spa = __find_sp_area(ALIGN_DOWN(uva, PAGE_SIZE));
		if (!spa) {
			ret = -EINVAL;
			if (printk_ratelimit())
				pr_err("share pool: invalid input uva %pK in unshare uva\n",
				       (void *)uva);
			goto out_unlock;
		}
	}

	if (spa->type != SPA_TYPE_K2TASK && spa->type != SPA_TYPE_K2SPG) {
		pr_err("share pool: this spa should not be unshare here\n");
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
		if (printk_ratelimit())
			pr_err("share pool: unshare uva failed due to invalid parameter size %lu\n",
			       size);
		goto out_drop_area;
	}

	if (spa->type == SPA_TYPE_K2TASK) {
		if (spg_id != SPG_ID_NONE && spg_id != SPG_ID_DEFAULT) {
			if (printk_ratelimit())
				pr_err("share pool: unshare uva(to task) failed, "
				       "invalid spg id %d\n", spg_id);
			ret = -EINVAL;
			goto out_drop_area;
		}

		if (!spa->mm) {
			if (printk_ratelimit())
				pr_err("share pool: unshare uva(to task) failed, "
				       "none spa owner\n");
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
			if (printk_ratelimit())
				pr_info("share pool: no need to unshare uva(to task), "
					"target process mm is exiting\n");
			goto out_drop_area;
		}

		if (spa->mm != mm) {
			if (printk_ratelimit())
				pr_err("share pool: unshare uva(to task) failed, "
				       "spa not belong to the task\n");
			ret = -EINVAL;
			mmput(mm);
			goto out_drop_area;
		}

		down_write(&mm->mmap_sem);
		ret = do_munmap(mm, uva_aligned, size_aligned, NULL);
		up_write(&mm->mmap_sem);
		mmput(mm);
		if (ret) {
			/* we are not supposed to fail */
			pr_err("share pool: failed to unmap VA %pK when munmap in unshare uva\n",
			       (void *)uva_aligned);
		}
	} else if (spa->type == SPA_TYPE_K2SPG) {
		if (spg_id < 0) {
			if (printk_ratelimit())
				pr_err("share pool: unshare uva(to group) failed, "
				       "invalid spg id %d\n", spg_id);
			ret = -EINVAL;
			goto out_drop_area;
		}

		if (!spg_valid(spa->spg)) {
			if (printk_ratelimit())
				pr_info("share pool: no need to unshare uva(to group), "
					"spa doesn't belong to a sp group or group is dead\n");
			goto out_drop_area;
		}

		/* alway allow kthread and dvpp channel destroy procedure */
		if (current->mm && current->mm->sp_group != spa->spg) {
			if (printk_ratelimit())
				pr_err("share pool: unshare uva(to group) failed, "
				       "caller process doesn't belong to target group\n");
			ret = -EINVAL;
			goto out_drop_area;
		}

		__sp_free(spa->spg, uva_aligned, size_aligned, NULL);
	}

	sp_dump_stack();

out_drop_area:
	/* deassociate vma and spa */
	area = find_vm_area((void *)spa->kva);
	if (area)
		area->flags &= ~VM_SHAREPOOL;
	__sp_area_drop(spa);
out_unlock:
	mutex_unlock(&sp_mutex);
	return ret;
}

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
		if (printk_ratelimit())
			pr_err("share pool: check vmap hugepage failed, ret %d\n", ret);
		return -EINVAL;
	}

	if (kva_aligned + size_aligned < kva_aligned) {
		if (printk_ratelimit())
			pr_err("share pool: overflow happened in unshare kva\n");
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
			pr_err("share pool: vmalloc %pK to page/hugepage failed\n",
			       (void *)addr);
	}

	vunmap((void *)kva_aligned);

	return 0;
}

/**
 * Unshare the kernel or user memory which shared by calling sp_make_share_{k2u,u2k}().
 * @va: the specified virtual address of memory
 * @size: the size of unshared memory
 * @pid:  the pid of the specified process if the VA is user address
 * @spg_id: the ID of the specified sp_group if the VA is user address
 *
 * Return -errno if fail.
 *
 * Use spg_id of current thread if spg_id == SPG_ID_DEFAULT.
 */
int sp_unshare(unsigned long va, unsigned long size, int pid, int spg_id)
{
	int ret = 0;

	if (va < TASK_SIZE) {
		/* user address */
		ret = sp_unshare_uva(va, size, pid, spg_id);
	} else if (va >= VA_START) {
		/* kernel address */
		ret = sp_unshare_kva(va, size);
	} else {
		/* regard user and kernel address ranges as bad address */
		if (printk_ratelimit())
			pr_err("share pool: unshare addr %pK is not a user or kernel addr", (void *)va);
		ret = -EFAULT;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sp_unshare);

/**
 * Return 0 when success.
 * When return value < 0, information in sp_walk_data is useless
 */
int sp_walk_page_range(unsigned long uva, unsigned long size,
	struct task_struct *tsk, struct sp_walk_data *sp_walk_data)
{
	int ret = 0;

	if (unlikely(!sp_walk_data)) {
		if (printk_ratelimit())
			pr_err("share pool: null pointer when walk page range\n");
		return -EINVAL;
	}
	if (!tsk || (tsk->flags & PF_EXITING))
		return -ESRCH;

	sp_walk_data->page_count = 0;

	get_task_struct(tsk);
	if (!mmget_not_zero(tsk->mm)) {
		put_task_struct(tsk);
		return -ESRCH;
	}
	down_write(&tsk->mm->mmap_sem);
	ret = __sp_walk_page_range(uva, size, tsk, sp_walk_data);
	up_write(&tsk->mm->mmap_sem);
	mmput(tsk->mm);
	put_task_struct(tsk);

	return ret;
}
EXPORT_SYMBOL_GPL(sp_walk_page_range);

void sp_walk_page_free(struct sp_walk_data *sp_walk_data)
{
	struct page *page;
	unsigned int i = 0;

	if (!sp_walk_data)
		return;

	while (i < sp_walk_data->page_count) {
		page = sp_walk_data->pages[i++];
		put_page(page);
	}

	kvfree(sp_walk_data->pages);
}
EXPORT_SYMBOL_GPL(sp_walk_page_free);

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
 * user can config the share pool start addrese of each Da-vinci device
 * @start: the value of share pool start
 * @size: the value of share pool
 * @device_id: the num of Da-vinci device
 * @pid: the pid of device process
 *
 * Return false if parameter invalid of has been set up.
 */
bool sp_config_dvpp_range(size_t start, size_t size, int device_id, int pid)
{
	struct sp_group *spg;

	if (device_id < 0 || device_id >= MAX_DEVID || pid < 0 || size <= 0 ||
	    size> MMAP_SHARE_POOL_16G_SIZE)
		return false;

	mutex_lock(&sp_mutex);
	spg = __sp_find_spg(pid, SPG_ID_DEFAULT);
	if (!spg_valid(spg) || spg->dvpp_multi_spaces == true) {
		mutex_unlock(&sp_mutex);
		return false;
	}
	spg->dvpp_va_start = start;
	spg->dvpp_size = size;
	spg->dvpp_multi_spaces = true;
	host_svm_sp_enable = true;
	mutex_unlock(&sp_mutex);

	return true;
}
EXPORT_SYMBOL_GPL(sp_config_dvpp_range);

/* Check whether the address belongs to the share pool. */
bool is_sharepool_addr(unsigned long addr)
{
       if (host_svm_sp_enable == false)
               return addr >= MMAP_SHARE_POOL_START && addr < (MMAP_SHARE_POOL_16G_START + MMAP_SHARE_POOL_16G_SIZE);
       return addr >= MMAP_SHARE_POOL_START && addr < MMAP_SHARE_POOL_END;
}
EXPORT_SYMBOL_GPL(is_sharepool_addr);

static int __init mdc_default_group(char *s)
{
	enable_mdc_default_group = 1;
	return 1;
}
__setup("enable_mdc_default_group", mdc_default_group);

int proc_sp_group_state(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	struct sp_group *spg = NULL;
	struct sp_proc_stat *stat;

	mutex_lock(&sp_mutex);
	spg = __sp_find_spg(task->pid, SPG_ID_DEFAULT);
	if (spg_valid(spg)) {
		/* print the file header */
		stat = idr_find(&sp_stat_idr, task->mm->sp_stat_id);
		if (!stat) {
			mutex_unlock(&sp_mutex);
			return 0;
		}
		seq_printf(m, "%-10s %-18s %-15s\n",
			   "Group ID", "Aligned Apply(KB)", "HugePage Fails");
		seq_printf(m, "%-10d %-18ld %-15d\n",
			   spg->id, byte2kb(stat->amount), spg->hugepage_failures);
	}
	mutex_unlock(&sp_mutex);

	return 0;
}

static int idr_proc_stat_cb(int id, void *p, void *data)
{
	struct sp_group *spg;
	struct sp_proc_stat *stat = p;
	struct seq_file *seq = data;

	mutex_lock(&sp_mutex);
	spg = __sp_find_spg(id, SPG_ID_DEFAULT);
	if (spg_valid(spg)) {
		seq_printf(seq, "%-12d %-10d %-18ld\n",
			   id, spg->id, byte2kb(stat->amount));
	}
	mutex_unlock(&sp_mutex);

	return 0;
}

static int proc_stat_show(struct seq_file *seq, void *offset)
{
	/* print the file header */
	seq_printf(seq, "%-12s %-10s %-18s\n",
		   "Process ID", "Group ID", "Aligned Apply(KB)");
	/* print kthread buff_module_guard_work */
	seq_printf(seq, "%-12s %-10s %-18ld\n",
		   "guard", "-", byte2kb(kthread_stat.amount));
	idr_for_each(&sp_stat_idr, idr_proc_stat_cb, seq);
	return 0;
}

static void rb_spa_stat_show(struct seq_file *seq) {
	struct rb_node *node;
	struct sp_area *spa;

	spin_lock(&sp_area_lock);

	for (node = rb_first(&sp_area_root); node; node = rb_next(node)) {
		spa = rb_entry(node, struct sp_area, rb_node);
		atomic_inc(&spa->use_count);
		spin_unlock(&sp_area_lock);

		mutex_lock(&sp_mutex);
		if (spg_valid(spa->spg))
			seq_printf(seq, "%-10d ", spa->spg->id);
		else /* k2u for task or spg is dead */
			seq_printf(seq, "%-10s ", "None");
		mutex_unlock(&sp_mutex);

		seq_printf(seq, "%2s%-14lx %2s%-14lx %-13ld ",
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

		seq_printf(seq, "%-10d\n", atomic_read(&spa->use_count));

		spin_lock(&sp_area_lock);
		__sp_area_drop_locked(spa);
	}

	spin_unlock(&sp_area_lock);
}

static void spa_overview_show(struct seq_file *seq)
{
	unsigned int total_num, alloc_num, k2u_task_num, k2u_spg_num;
	unsigned long total_size, alloc_size, k2u_task_size, k2u_spg_size;
	unsigned long dvpp_size, dvpp_va_size;

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

	seq_printf(seq, "Spa total num %u.\n", total_num);
	seq_printf(seq, "Spa alloc num %u, k2u(task) num %u, k2u(spg) num %u.\n",
		   alloc_num, k2u_task_num, k2u_spg_num);
	seq_printf(seq, "Spa total size:     %13lu KB\n", byte2kb(total_size));
	seq_printf(seq, "Spa alloc size:     %13lu KB\n", byte2kb(alloc_size));
	seq_printf(seq, "Spa k2u(task) size: %13lu KB\n", byte2kb(k2u_task_size));
	seq_printf(seq, "Spa k2u(spg) size:  %13lu KB\n", byte2kb(k2u_spg_size));
	seq_printf(seq, "Spa dvpp size:      %13lu KB\n", byte2kb(dvpp_size));
	seq_printf(seq, "Spa dvpp va size:   %13lu MB\n", byte2mb(dvpp_va_size));
	seq_printf(seq, "\n");
}

/* the caller must hold sp_mutex */
static int idr_spg_stat_cb(int id, void *p, void *data)
{
	struct sp_group *spg = p;
	struct seq_file *seq = data;

	seq_printf(seq, "Group %-10d size: %13ld KB, spa num: %d.\n",
		   id, byte2kb(atomic64_read(&spg->size)),
		   atomic_read(&spg->spa_num));

	return 0;
}

static void spg_overview_show(struct seq_file *seq)
{
	seq_printf(seq, "Share pool total size: %13ld KB, spa total num: %d.\n",
		   byte2kb(atomic64_read(&spg_stat.spa_total_size)),
		   atomic_read(&spg_stat.spa_total_num));
	mutex_lock(&sp_mutex);
	idr_for_each(&sp_group_idr, idr_spg_stat_cb, seq);
	mutex_unlock(&sp_mutex);
	seq_printf(seq, "\n");
}

static int spa_stat_show(struct seq_file *seq, void *offset)
{
	spg_overview_show(seq);
	spa_overview_show(seq);
	/* print the file header */
	seq_printf(seq, "%-10s %-16s %-16s %-13s %-7s %-5s %-10s\n",
		   "Group ID", "va_start", "va_end", "Aligned KB", "Type", "Huge", "Ref");
	rb_spa_stat_show(seq);
	return 0;
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

retry:
	page = find_lock_page(mapping, idx);
	if (!page) {
		size = i_size_read(mapping->host) >> huge_page_shift(h);
		if (idx >= size)
			goto out;

		page = alloc_huge_page(vma, haddr, 0);
		if (IS_ERR(page)) {
			page = alloc_huge_page_node(hstate_file(vma->vm_file),
						    numa_mem_id());
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

/*
 * Called by proc_root_init() to initialize the /proc/sharepool subtree
 */
void __init proc_sharepool_init(void)
{
	if (!proc_mkdir("sharepool", NULL))
		return;

	proc_create_single_data("sharepool/proc_stat", S_IRUSR, NULL, proc_stat_show, NULL);
	proc_create_single_data("sharepool/spa_stat", S_IRUSR, NULL, spa_stat_show, NULL);
}

struct page *sp_alloc_pages(struct vm_struct *area, gfp_t mask,
					  unsigned int page_order, int node)
{
	if (area->flags & VM_HUGE_PAGES)
		return hugetlb_alloc_hugepage(NUMA_NO_NODE, HUGETLB_ALLOC_NONE);
	else
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
