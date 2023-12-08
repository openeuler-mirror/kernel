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
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(mg_sp_group_id_by_pid);

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
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(mg_sp_group_add_task);

int mg_sp_id_of_current(void)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(mg_sp_id_of_current);

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
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(mg_sp_free);

static void __init proc_sharepool_init(void)
{
	if (!proc_mkdir("sharepool", NULL))
		return;
}

void *mg_sp_alloc_nodemask(unsigned long size, unsigned long sp_flags, int spg_id,
		nodemask_t nodemask)
{
	return ERR_PTR(-EOPNOTSUPP);
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
	return ERR_PTR(-EOPNOTSUPP);
}
EXPORT_SYMBOL_GPL(mg_sp_alloc);

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
	return ERR_PTR(-EOPNOTSUPP);
}
EXPORT_SYMBOL_GPL(mg_sp_make_share_k2u);

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
	return ERR_PTR(-EOPNOTSUPP);
}
EXPORT_SYMBOL_GPL(mg_sp_make_share_u2k);

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
	return -EOPNOTSUPP;
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
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(mg_sp_walk_page_range);

/**
 * mg_sp_walk_page_free() - Free the sp_walk_data structure.
 * @sp_walk_data: a structure of a page pointer array to be freed.
 */
void mg_sp_walk_page_free(struct sp_walk_data *sp_walk_data)
{
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

	proc_sharepool_init();

	return 0;
}
late_initcall(share_pool_init);
