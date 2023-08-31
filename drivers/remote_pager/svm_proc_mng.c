// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Jiangtian Feng
 * Co-Author: Jun Chen, Chuangchuang Fang
 *
 */

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>

#include "svm_proc_mng.h"

struct svm_proc_node {
	struct svm_proc svm_proc;
	struct hlist_node list;
};

static inline struct svm_proc_node *to_proc_node(struct svm_proc *proc)
{
	return list_entry(proc, struct svm_proc_node, svm_proc);
}

#define _PROC_LIST_MAX	0x0f
#define _PROC_LIST_SHIFT	4
static DEFINE_RWLOCK(svm_proc_hash_rwlock);
static DEFINE_HASHTABLE(svm_proc_hashtable, _PROC_LIST_SHIFT);

static unsigned int get_hash_tag(int pid)
{
	return (unsigned int)pid % _PROC_LIST_MAX;
}

static void add_to_hashtable(struct svm_proc *proc)
{
	struct svm_proc_node *node = to_proc_node(proc);
	unsigned int tag = get_hash_tag(proc->pid);

	write_lock(&svm_proc_hash_rwlock);
	hash_add(svm_proc_hashtable, &node->list, tag);
	write_unlock(&svm_proc_hash_rwlock);
}

static void del_from_hashtable(struct svm_proc *proc)
{
	struct svm_proc_node *node;

	write_lock(&svm_proc_hash_rwlock);
	node = to_proc_node(proc);
	hash_del(&node->list);
	write_unlock(&svm_proc_hash_rwlock);
}

struct svm_proc *search_svm_proc_by_mm(struct mm_struct *mm)
{
	struct svm_proc_node *node;
	unsigned int tag;

	read_lock(&svm_proc_hash_rwlock);
	hash_for_each(svm_proc_hashtable, tag, node, list) {
		if (node->svm_proc.mm == mm) {
			read_unlock(&svm_proc_hash_rwlock);
			return &node->svm_proc;
		}
	}
	read_unlock(&svm_proc_hash_rwlock);

	return search_svm_proc_by_local_mm(mm);
}

struct svm_proc *search_svm_proc_by_local_mm(struct mm_struct *mm)
{
	struct svm_proc_node *node;
	unsigned int hash_tag;
	struct local_pair_proc *item = NULL;
	struct local_pair_proc *next = NULL;

	read_lock(&svm_proc_hash_rwlock);
	hash_for_each(svm_proc_hashtable, hash_tag, node, list) {
		list_for_each_entry_safe(item, next, &node->svm_proc.tasks_list, node) {
			if (item->mm == mm) {
				read_unlock(&svm_proc_hash_rwlock);
				return &node->svm_proc;
			}
		}
	}
	read_unlock(&svm_proc_hash_rwlock);

	return NULL;
}

struct svm_proc *search_svm_proc_by_pid(unsigned int pid)
{
	struct svm_proc_node *node;
	unsigned int tag = get_hash_tag(pid);

	read_lock(&svm_proc_hash_rwlock);
	hash_for_each_possible(svm_proc_hashtable, node, list, tag) {
		if (node->svm_proc.pid == pid) {
			read_unlock(&svm_proc_hash_rwlock);
			return &node->svm_proc;
		}
	}
	read_unlock(&svm_proc_hash_rwlock);

	return NULL;
}

static struct page_info *__search_page_info(struct page_mng *pager,
		unsigned long va, unsigned long len)
{
	struct rb_node *node = pager->rbtree.rb_node;
	struct page_info *page_info = NULL;

	while (node) {
		page_info = rb_entry(node, struct page_info, node);

		if (va + len <= page_info->va)
			node = node->rb_left;
		else if (va >= page_info->va + page_info->len)
			node = node->rb_right;
		else
			break;
	}

	if (page_info) {
		if (va < page_info->va || va + len > page_info->va + page_info->len)
			return NULL;
	}
	return page_info;
}

struct page_info *search_page_info(struct page_mng *pager, unsigned long va, unsigned long len)
{
	struct page_info *page_info;

	if (!pager)
		return NULL;

	down_read(&pager->rw_sem);
	page_info = __search_page_info(pager, va, len);
	up_read(&pager->rw_sem);

	return page_info;
}

static int insert_page_info(struct page_mng *pager, struct page_info *page_info)
{
	struct rb_node **new_node;
	struct rb_node *parent = NULL;
	struct page_info *cur = NULL;

	down_write(&pager->rw_sem);
	new_node = &(pager->rbtree.rb_node);

	/* Figure out where to put new node */
	while (*new_node) {
		cur = rb_entry(*new_node, struct page_info, node);
		parent = *new_node;
		if (page_info->va + page_info->len <= cur->va) {
			new_node = &((*new_node)->rb_left);
		} else if (page_info->va >= cur->va + cur->len) {
			new_node = &((*new_node)->rb_right);
		} else {
			up_write(&pager->rw_sem);
			return -EFAULT;
		}
	}
	/* Add new node and rebalance tree. */
	rb_link_node(&page_info->node, parent, new_node);
	rb_insert_color(&page_info->node, &pager->rbtree);

	up_write(&pager->rw_sem);

	return 0;
}

static void erase_page_info(struct page_mng *pager, struct page_info *page_info)
{
	rb_erase(&page_info->node, &pager->rbtree);
}

static struct page_info *alloc_page_info(unsigned long va, unsigned long len,
		unsigned int page_size)
{

	struct page_info *page_info;
	size_t size;

	size = sizeof(struct page_info);
	page_info = kzalloc(size, GFP_KERNEL);
	if (!page_info) {
		pr_err("alloc page_info failed: (size=%lx)\n", (unsigned long)size);
		return NULL;
	}

	page_info->va = va;
	page_info->len = len;
	mutex_init(&page_info->lock);

	return page_info;
}

struct page_info *get_page_info(struct page_mng *pager,
		unsigned long va, unsigned long len, unsigned int page_size)
{
	struct page_info *page_info = search_page_info(pager, va, len);

	if (page_info)
		return page_info;

	page_info = alloc_page_info(va, len, page_size);
	if (page_info) {
		if (insert_page_info(pager, page_info)) {
			kfree(page_info);
			page_info = search_page_info(pager, va, len);
		}
	}

	return page_info;
}

void free_page_info(struct page_mng *pager, struct page_info *page_info)
{
	down_write(&pager->rw_sem);
	erase_page_info(pager, page_info);
	up_write(&pager->rw_sem);
	kfree(page_info);
}

static void free_pager(struct page_mng *pager)
{
	struct page_info *page_info = NULL;
	struct rb_node *node = NULL;

	down_write(&pager->rw_sem);
	node = rb_first(&pager->rbtree);
	while (node) {
		page_info = rb_entry(node, struct page_info, node);
		node = rb_next(node);
		erase_page_info(pager, page_info);
		kfree(page_info);
	}
	up_write(&pager->rw_sem);
}

static void free_svm_proc(struct svm_proc *proc)
{
	struct local_pair_proc *item = NULL;
	struct local_pair_proc *next = NULL;
	struct mm_struct *mm = proc->mm;
	int count;

	free_pager(&proc->pager);
	del_from_hashtable(proc);

	count = atomic_read(&mm->mm_users);
	if (count) {
		pr_err("mm_users is %d\n", count);
		mmput(mm);
	}

	if (!list_empty(&proc->tasks_list)) {
		list_for_each_entry_safe(item, next, &proc->tasks_list, node)
			list_del(&item->node);
	}
	pr_err("svm proc clean up done pid %d, peer_pid %d\n", proc->pid, proc->peer_pid);
}

static void svm_proc_mm_release(struct mmu_notifier *subscription, struct mm_struct *mm)
{
	struct svm_proc *proc = container_of(subscription, struct svm_proc, notifier);

	free_svm_proc(proc);
	kfree(proc);
}

static const struct mmu_notifier_ops svm_proc_mmu_notifier_ops = {
	.release = svm_proc_mm_release,
};

static int svm_proc_mmu_notifier_register(struct svm_proc *proc)
{
	proc->notifier.ops = &svm_proc_mmu_notifier_ops;

	return mmu_notifier_register(&proc->notifier, proc->mm);
}

static void local_pair_proc_mm_release(struct mmu_notifier *subscription, struct mm_struct *mm)
{
	struct local_pair_proc *local_proc =
		container_of(subscription, struct local_pair_proc, notifier);

	list_del(&local_proc->node);
	kfree(local_proc);
	pr_debug("clean pair proc resources\n");
}

static const struct mmu_notifier_ops local_pair_proc_mmu_notifier_ops = {
	.release = local_pair_proc_mm_release,
};

static int local_pair_proc_mmu_notifier_register(struct local_pair_proc *local_proc)
{
	local_proc->notifier.ops = &local_pair_proc_mmu_notifier_ops;

	return mmu_notifier_register(&local_proc->notifier, local_proc->mm);
}

struct local_pair_proc *insert_local_proc(struct svm_proc *proc, unsigned int pid)
{
	int ret = 0;
	struct local_pair_proc *local_proc = kzalloc(sizeof(struct local_pair_proc), GFP_KERNEL);

	if (!local_proc)
		return ERR_PTR(-ENOMEM);

	local_proc->tsk = find_get_task_by_vpid(pid);
	if (!local_proc->tsk) {
		pr_err("can not find process by pid %d\n", pid);
		ret = -EINVAL;
		goto free;
	}

	local_proc->pid = pid;
	local_proc->mm = get_task_mm(local_proc->tsk);
	/* task is exiting */
	if (!local_proc->mm) {
		pr_err("can not get process[%d] mm\n", pid);
		ret = -EINTR;
		goto put_task;
	}

	ret = local_pair_proc_mmu_notifier_register(local_proc);
	if (ret) {
		pr_err("register mmu notifier failed\n");
		goto put_mm;
	}

	mmput(local_proc->mm);
	put_task_struct(local_proc->tsk);

	list_add(&local_proc->node, &proc->tasks_list);
	pr_debug("%s bind_to_pid %d local_pid %d\n", __func__, proc->pid, local_proc->pid);

	return local_proc;

put_mm:
	mmput(local_proc->mm);
put_task:
	put_task_struct(local_proc->tsk);
free:
	kfree(local_proc);
	return ERR_PTR(ret);
}

struct svm_proc *alloc_svm_proc(int nid, int pid, int peer_nid, int peer_pid)
{
	struct svm_proc *proc;
	int ret;

	proc = kzalloc(sizeof(struct svm_proc), GFP_KERNEL);
	if (!proc)
		return ERR_PTR(-ENOMEM);

	proc->pager.rbtree = RB_ROOT;
	init_rwsem(&proc->pager.rw_sem);

	proc->pid = pid;
	proc->nid = nid;
	proc->peer_nid = peer_nid;
	proc->peer_pid = peer_pid;
	INIT_LIST_HEAD(&proc->tasks_list);

	proc->tsk = find_get_task_by_vpid(pid);
	if (!proc->tsk) {
		pr_err("can not find process by pid %d\n", pid);
		ret = -EINVAL;
		goto free;
	}

	proc->mm = get_task_mm(proc->tsk);
	/* task is exiting */
	if (!proc->mm) {
		pr_err("can not get process[%d] mm\n", pid);
		ret = -EINTR;
		goto put_task;
	}

	ret = svm_proc_mmu_notifier_register(proc);
	if (ret) {
		pr_err("register mmu notifier failed\n");
		goto put_mm;
	}

	/*
	 * destroying svm_proc depends on mmu_notifier.
	 * we have to put mm to make sure mmu_notifier can be called
	 */
	mmput(proc->mm);
	put_task_struct(proc->tsk);

	add_to_hashtable(proc);

	return proc;

put_mm:
	mmput(proc->mm);
put_task:
	put_task_struct(proc->tsk);
free:
	kfree(proc);
	return ERR_PTR(ret);
}
