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

static BLOCKING_NOTIFIER_HEAD(sp_notifier_chain);

/*
 * Group '0' for k2u_task and pass through. No process will be actually
 * added to.
 */
static struct sp_group *spg_none;

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
	return 0;
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
	return;
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

	return 0;
fail:
	pr_err("Ascend share pool initialization failed\n");
	static_branch_disable(&share_pool_enabled_key);
	return 1;
}
late_initcall(share_pool_init);
