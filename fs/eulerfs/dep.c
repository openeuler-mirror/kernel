// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/ratelimit.h>
#include <linux/writeback.h>
#include "euler.h"
#include "dep.h"
#include "lock.h"
#include "dax.h"
#include "dht.h"

static void do_dep_diradd_oneshot(struct inode *dir_inode, struct dep_node *dep,
				  u64 *bitset);

struct flush_list_head {
	int count;
	struct llist_head head;
};

DEFINE_PER_CPU(struct flush_list_head, flush_list_percpu);

#define IFMT_HAS_ROOT(ifmt)                                                    \
	((ifmt) == S_IFREG || (ifmt) == S_IFDIR || (ifmt) == S_IFLNK)

#define INODE_COND_TRYLOCK(inode, tag, enter_cond, exit_cond, exit_expr)       \
	do {                                                                   \
	tag:                                                                   \
		if (enter_cond) {                                              \
			if (likely(inode_trylock(inode))) {                    \
				/* get the lock, okay */                       \
			} else {                                               \
				if (exit_cond) {                               \
					exit_expr;                             \
				} else {                                       \
					cond_resched();                        \
					goto tag;                              \
				}                                              \
			}                                                      \
		}                                                              \
	} while (0)

static inline void fsync_dir_oneshot(struct inode *dir)
{
	eufs_dir_fsync_oneshot(dir);
}

static void do_dep_dirrem(struct inode *inode, struct dep_node *dep,
			  u64 *bitset)
{
	struct nv_dict_entry *prevde = dep->prevde;
	struct nv_dict_entry *de = dep->de;
	int idx;

	eufs_dbg("!! %s !!", __func__);
	NV_ASSERT(de);
	NV_ASSERT(de->inode);
	NV_ASSERT(de->name);

	idx = INDEX(de->hv);
	bitset[idx / 64] = bitset[idx / 64] | (0x1ull << (idx & 63));
	eufs_dbg("bitset-add: dict=%llx, %d %llx\n",
		 eufs_iread_dict(EUFS_PI(inode)), idx, bitset[idx / 64]);

	/*
	 * This is a removal of a newly created dentry, nothing to do,
	 * the prevde is already manipulated in dht.c
	 */
	if (de->volatile_next == EUFS_DIR_DELNEW)
		return;

	/*
	 * If dentries immediately following the deleted dentry are
	 * also deleted, prevde->volatile_next will be modified again.
	 * So if we assign prevde->volatile_next to prevde->next,
	 * these deletion will be persisted prematurely.
	 */
	if (prevde && !eufs_dentry_is_not_persist(prevde)) {
		prevde->next = de->next;
		persist_dentry(prevde);
	}
}

static void do_dep_dirrem_reclaim(struct super_block *sb, struct dep_node *dep)
{
	struct nv_dict_entry *de = dep->de;
	struct eufs_inode __maybe_unused *pi;
	struct inode *child;

	pi = s2p(sb, de->inode);
	child = dep->inode;
	NV_ASSERT(EUFS_PI(child) == pi);
	eufs_dbg("dirrem: child_inode=%px\n", child);
	BUG_ON(!child);
	eufs_free_name(sb, de);
	nv_free(sb, de);
}

#define EUFS_PRINT_BITSET(lvl, bitset)                                         \
	eufs_##lvl("bitsets: %llx %llx %llx %llx %llx %llx %llx %llx\n",       \
		   bitset[0], bitset[1], bitset[2], bitset[3], bitset[4],      \
		   bitset[5], bitset[6], bitset[7])

static void eufs_sync_buckets(struct eufs_inode_info *vi, u64 bitset[8])
{
	struct inode *inode = &vi->vfs_inode;
	struct super_block *sb = inode->i_sb;
	struct eufs_inode *pi = EUFS_FRESH_PI(EUFS_PI(inode));
	struct nv_dict *dict;
	int i;

	/* Volatile buckets */
	if (!vi->i_volatile_dict)
		return;

	EUFS_PRINT_BITSET(dbg, bitset);

	BUG_ON(!inode_is_header_locked(inode));
	dict = o2p(sb, eufs_iread_dict(pi));
	for (i = 0; i < 8; ++i) {
		int j;
		bool dirty;
		int idx;

		if (!bitset[i])
			continue;
		dirty = false;
		for (j = 0; j <= 64; ++j) {
			if (j % 8 == 0 && dirty) {
				dirty = false;
				eufs_flush_cacheline(&dict->table[idx]);
			}
			if (j == 64)
				break;
			if (!(bitset[i] & (0x1ull << j)))
				continue;
			idx = i * 64 + j;
			eufs_dbg_dir("handle index %d (i %d, j %d) of inode=%px\n",
				     idx, i, j, inode);

			eufs_dbg_dir(" idx=%d  dict[idx]=%px vdict[idx]=%px\n",
				     idx, dict->table[idx],
				     vi->i_volatile_dict->table[idx]);

			if (unlikely(vi->i_volatile_dict->table[idx] ==
				     EUFS_DIR_EOC_PTR))
				dict->table[idx] = NULL_VAL;
			else if (vi->i_volatile_dict->table[idx] != NULL)
				dict->table[idx] = COMPOSE_DICT_HEAD_le64(
					sb, vi->i_volatile_dict->table[idx]);
			vi->i_volatile_dict->table[idx] = NULL;
			dirty = true;
		}
	}
}

/*
 * Some ideas on fast fsync (of dir):
 *
 * 1. Batch and coalescence. The newly inserted dentry should be marked and
 * during its removal, it should be marked again so that unnecessary dep_diradd
 * an be prevented.
 *
 * 2. Split! The lock (only when there is one lock needed) can be temporarily
 * given up so between handling two deps. This requires that the dentry pointed
 * by dir_pi should not be reclaimed (like in RCU). Well, actually, combined
 * with the following one idea, this is quite acceptable.
 *
 * 3. Delayed free. The removal operations can be delayed until the locks are
 * released.
 *
 *
 * Parallel fsync for a vi is not throughly considered though.
 *
 * 4. Detach only if the list is empty?
 */
static void fsync_rename_inode(struct inode *dir)
{
	struct eufs_inode_info *vi = EUFS_I(dir);

	if (!vi->i_is_dirty)
		return;

	/* I'm holding the lock, so if it's dirty, it's dirty. */
	fsync_dir_oneshot(dir);
}

void fsync_rename_inodes(struct inode *old_dir, struct inode *new_dir,
			 struct inode **locked_inodes)
{
	int i;
	struct inode *inode;

	/*
	 * The two parent dirs, might have parent-child relations sometime
	 * before. So we need to transfer these two dirs too.
	 */
	for (i = 0; i < EUFS_INODE_CNT_IN_RENAME; i++) {
		inode = locked_inodes[i];
		if (inode)
			eufs_inode_mark_lock_transferable(inode);
	}

	if (old_dir == new_dir) {
		fsync_rename_inode(old_dir);
	} else {
		fsync_rename_inode(old_dir);
		fsync_rename_inode(new_dir);
	}

	for (i = 0; i < EUFS_INODE_CNT_IN_RENAME; i++) {
		inode = locked_inodes[i];
		if (inode)
			eufs_inode_wait_lock_transfer_done(inode);
	}
}

static void eufs_update_persisted_seq(struct eufs_inode_info *vi,
				      struct list_head *head)
{
	if (!list_empty(head)) {
		struct dep_node *dep =
			list_last_entry(head, struct dep_node, node);

		vi->i_persisted_dep_seq = dep->seq;
	}
}

static int fsync_dir_bg(struct inode *dir)
{
	struct dep_node *dep, *next;
	LIST_HEAD(detached_list);
	LIST_HEAD(dump_list);
	int i;
#define FSYNC_DIR_VI_LOOP_NUM (20)

	struct eufs_inode_info *vi = EUFS_I(dir);
	struct super_block *sb = dir->i_sb;
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct eufs_inode *pi = EUFS_PI(dir);
	u64 bitset[8] = { 0 };
	int dep_count = 0;

retry:
	inode_urgent_lock(dir);

	/* Phase 1 */
	for (i = FSYNC_DIR_VI_LOOP_NUM; i >= 0; --i) {
		/* Get all deps round by round */
		if (i == 0) {
			/* Last round */
			inode_header_lock(dir);
		}
		inode_dep_lock(dir);

		if (list_empty(&vi->i_dep_list) && i > 0) {
			/* Skip to last round */
			i = 1;
		}
		list_cut_position(&detached_list, &vi->i_dep_list,
				  vi->i_dep_list.prev);

		if (i > 0)
			inode_dep_unlock(dir);

		/* Do dep one by one. */
		list_for_each_entry_safe(dep, next, &detached_list, node) {
			if (dep->type == DEP_DIRADD) {
				/*
				 * FIXME: the lockset might be different since
				 * we might have released the inode lock.
				 */
				do_dep_diradd_oneshot(dir, dep, bitset);

			} else if (dep->type == DEP_DIRREM) {
				do_dep_dirrem(dir, dep, bitset);

			} else
				BUG();
		}

		list_splice_tail_init(&detached_list, &dump_list);

		if (i == 0) {
			eufs_pbarrier();

			if (!list_empty(&dump_list))
				/* Phase 2 */
				eufs_sync_buckets(vi, bitset);

			inode_dep_unlock(dir);
			inode_header_unlock(dir);
			break;
		}
	}

	inode_urgent_unlock(dir);

	/* Phase 3 */
	inode_lock(dir);

	if (!list_empty(&vi->i_dep_list)) {
		inode_unlock(dir);
		/* To handle new deps between phase 2 & 3 */
		/* FIXME: Live lock possible! */
		goto retry;
	}

	if (dir->i_nlink)
		eufs_sync_pinode(dir, pi, false);

	eufs_update_persisted_seq(vi, &dump_list);

	vi->i_is_persisting = false;
	vi->i_is_dirty = false;

	if (dir->i_nlink)
		persist_pinode(pi);

	inode_unlock(dir);

	eufs_pbarrier();

	/* Reclaim memory and clear the list */
	list_for_each_entry_safe(dep, next, &dump_list, node) {
		struct inode *child_inode = dep->inode;
		struct eufs_inode_info *child_vi = EUFS_I(child_inode);

		if (dep->type == DEP_DIRREM)
			do_dep_dirrem_reclaim(sb, dep);

		/* remove from owner list */
		spin_lock(&child_vi->i_owner_lock);
		list_del_init(&dep->owner_node);
		spin_unlock(&child_vi->i_owner_lock);

		iput(child_inode);

		list_del(&dep->node);

		eufs_free_dep_node(dep);
		dep_count++;
	}
	atomic_sub(dep_count, &sbi->s_nr_dep_nodes);
	eufs_dbg("@cpu=%d !! fsync dir vi done: inode=%px\n",
		 smp_processor_id(), &vi->vfs_inode);
	return 0;
}

static int fsync_nondir_oneshot(struct inode *inode)
{
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct eufs_inode *pi;

	/* For files other than dir */
	WARN(S_ISDIR(inode->i_mode), "%s on a dir!", __func__);

	/* Inode needs to remove. Nothing to do */
	if (!inode->i_nlink) {
		vi->i_is_dirty = false;
		return 0;
	}

	pi = EUFS_PI(inode);

	eufs_sync_pinode(inode, pi, false);

	persist_pinode(pi);

	vi->i_is_dirty = false;

	return 0;
}

static int fsync_nondir_bg(struct inode *inode)
{
	struct eufs_inode_info *vi = EUFS_I(inode);
	int r;

	inode_lock(inode);
	r = fsync_nondir_oneshot(inode);
	vi->i_is_persisting = false;
	inode_unlock(inode);

	return r;
}

static void fsync_bg(struct inode *inode)
{
	struct eufs_sb_info *sbi = EUFS_SB(inode->i_sb);

	wait_on_inode(inode);

	/* Reading i_mode may need no protection */
	if (S_ISDIR(inode->i_mode))
		fsync_dir_bg(inode);
	else
		fsync_nondir_bg(inode);

	/* Decrease */
	iput(inode);

	if (atomic_dec_and_test(&sbi->s_nr_dirty_inodes) && sbi->s_draining) {
		/* end of draining */
		sbi->s_draining = false;
	}
}

void fsync_oneshot(struct inode *inode)
{
	/* Reading i_mode may need no protection */
	if (S_ISDIR(inode->i_mode))
		fsync_dir_oneshot(inode);
	else
		fsync_nondir_oneshot(inode);
}

static void do_dep_diradd_oneshot(struct inode *dir_inode, struct dep_node *dep,
				  u64 *bitset)
{
	struct super_block *sb = dir_inode->i_sb;
	struct nv_dict_entry *de = dep->de;
	struct inode *inode = dep->inode;
	struct eufs_inode_info *dir_vi = EUFS_I(dir_inode);
	struct eufs_inode *pi;
	struct eufs_inode *fresh_pi;
	int idx;
	void *buffer[16];
	struct alloc_batch ab;
	bool lock_transferred = false;

	idx = INDEX(de->hv);
	bitset[idx / 64] = bitset[idx / 64] | (0x1ull << (idx & 63));

	if (de->volatile_next == EUFS_DIR_DELNEW) {
		/*
		 * The de is already invisible from both the latest view and
		 * the consistent view.
		 * Will be handled in the corresponding dirrem.
		 */
		return;
	}

	/* Meow? This equality is the sign of diradd */
	WARN(!eufs_dentry_is_not_persist(de), "diradd wrong sign");

	pi = s2p(sb, de->inode);

	wait_on_inode(inode);
retry:
	if (likely(inode_trylock(inode))) {
		/* Got the lock */
	} else {
		if (eufs_inode_mark_lock_transferring(inode)) {
			lock_transferred = true;
		} else {
			cond_resched();
			goto retry;
		}
	}

	eufs_sync_pinode(inode, pi, false);
	fresh_pi = EUFS_FRESH_PI(pi);

	if (!lock_transferred)
		inode_unlock(inode);
	else
		eufs_inode_lock_transfer_done(inode);

	ab.n_used = 0;
	ab.size = 16;
	ab.batch = buffer;

	eufs_alloc_batch_add(sb, &ab, de);
	/*
	 * force to persist the allocation without checking.
	 * TODO: we should differentiate the link and create syscall to agree
	 * with checking
	 */
	eufs_alloc_persist(sb, pi, true);

	if (S_ISLNK(fresh_pi->i_mode)) {
		void *root = o2p(sb, eufs_iread_root(fresh_pi));

		/* reg file's root is done in btree */
		/* In case of Hard link, we must force the allocation persitence */
		eufs_alloc_persist(sb, root, true);
		persist_symlink(root);
	} else if (S_ISDIR(fresh_pi->i_mode)) {
		void *root = o2p(sb, eufs_iread_root(fresh_pi));

		eufs_alloc_persist(sb, root, false);
		persist_page(root);
	}

	persist_name(sb, de, &ab);

	eufs_alloc_batch_persist_reset(sb, &ab);

	persist_pinode(pi);

	spin_lock(&dir_vi->i_dentry_persist_lock);
	eufs_dentry_clr_not_persist_flag(de);
	spin_unlock(&dir_vi->i_dentry_persist_lock);

	persist_dentry(de);
}

void eufs_dir_fsync_oneshot(struct inode *dir)
{
	struct dep_node *dep;
	struct dep_node *next;
	struct super_block *sb = dir->i_sb;
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct eufs_inode_info *vi = EUFS_I(dir);
	LIST_HEAD(detached_list);
	u64 bitset[8] = { 0 };
	int dep_count = 0;

	BUG_ON(!inode_is_locked(dir));

	inode_urgent_lock(dir);

	/* get all deps */
	inode_header_lock(dir);
	inode_dep_lock(dir);

	if (list_empty(&vi->i_dep_list))
		goto unlock_sync_pinode;

	list_for_each_entry(dep, &vi->i_dep_list, node) {
		if (dep->type == DEP_DIRADD)
			do_dep_diradd_oneshot(dir, dep, bitset);
		else if (dep->type == DEP_DIRREM)
			do_dep_dirrem(dir, dep, bitset);
		else
			BUG();
	}

	list_splice_init(&vi->i_dep_list, &detached_list);

	/* sync buckets */
	eufs_pbarrier();
	eufs_sync_buckets(vi, bitset);

unlock_sync_pinode:
	inode_dep_unlock(dir);
	inode_header_unlock(dir);

	/* sync pinode */
	if (dir->i_nlink)
		eufs_sync_pinode(dir, EUFS_PI(dir), false);

	eufs_pbarrier();

	eufs_update_persisted_seq(vi, &detached_list);

	vi->i_is_dirty = false;

	/* Reclaim memory and clear the list */
	list_for_each_entry_safe(dep, next, &detached_list, node) {
		struct inode *child_inode = dep->inode;
		struct eufs_inode_info *child_vinode = EUFS_I(child_inode);

		spin_lock(&child_vinode->i_owner_lock);
		list_del_init(&dep->owner_node);
		spin_unlock(&child_vinode->i_owner_lock);

		if (dep->type == DEP_DIRREM) {
			do_dep_dirrem_reclaim(sb, dep);
			iput(dep->inode);
		} else if (dep->type == DEP_DIRADD) {
			iput(dep->inode);
		}
		list_del(&dep->node);
		eufs_free_dep_node(dep);
		dep_count++;
	}
	atomic_sub(dep_count, &sbi->s_nr_dep_nodes);

	inode_urgent_unlock(dir);
}

void fsync_on_draining(struct inode *dir, struct inode *inode)
{
	BUG_ON(!dir);
	BUG_ON(!inode_is_locked(dir));
	BUG_ON(inode && !inode_is_locked(inode));

	/* for link/unlink/rmdir */
	if (inode)
		eufs_inode_mark_lock_transferable(inode);

	fsync_dir_oneshot(dir);

	if (inode)
		eufs_inode_wait_lock_transfer_done(inode);
}

#define NR_FLUSH_EACH_ROUND (16)
#define FLUSH_START_THRESHOLD (64)

static __always_inline int handle_persistees_for_each_cpu(
		struct super_block *sb, const struct cpumask *mask, int idx) {
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct llist_node *list;
	struct llist_head *head;
	struct eufs_inode_info *vi;
	struct eufs_inode_info *next;
	int n_active_list;
	int cpu;
	bool need;

retry:
	need = sbi->need_sync[idx];
	n_active_list = 0;
	for_each_cpu(cpu, mask) {
		head = per_cpu_ptr(sbi->persistee_list, cpu);

		if (unlikely(llist_empty(head)))
			continue;

		n_active_list++;

		list = llist_del_all(head);

		eufs_dbg("persister get list %px for cpu%d\n", list, cpu);

		/* reverse the ordering for better locality? */
		llist_for_each_entry_safe(vi, next, list, i_persistee_node)
			fsync_bg(&vi->vfs_inode);
		eufs_dbg("persister handled list %px\n", list);
	}
	/**
	 * We need a complete round of run for fssync. If
	 * need != sbi->need_sync[idx], need_sync was modified during our last
	 * round. We need to retry to ensure a complete round of run.
	 * It's okay if dirty inodes of a cpu is still being processed by
	 * another persister, since we will wait for all persisters to finish
	 * for fssync.
	 */
	if (need != READ_ONCE(sbi->need_sync[idx]))
		goto retry;
	if (need) {
		sbi->need_sync[idx] = false;
		wake_up(&sbi->sync_wq);
	}
	if (READ_ONCE(sbi->need_sync[idx]))
		goto retry;

	return n_active_list;
}

static int persister(void *data)
{
	struct super_block *sb = data;
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	const struct cpumask *mask = cpumask_of_node(numa_node_id());
	const int period =
		(persist_period == 0) ? /* default */ (HZ / 4) :
					/* less than a second */
			((persist_period < 0) ? (HZ / (-persist_period)) :
						/* more than a second */
				 (HZ * persist_period));
	int idx = 0;
	int num_persisters = num_sockets * persisters_per_socket;

	eufs_info("sb=%px cpu=%d cpumask=%*pbl period=%d\n", data,
		  smp_processor_id(), cpumask_pr_args(mask), period);

	while (idx < num_persisters && sbi->persisters[idx] != current)
		idx++;
	BUG_ON(idx >= num_persisters);

	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(period);
		handle_persistees_for_each_cpu(sb, mask, idx);
	}

	while (handle_persistees_for_each_cpu(sb, mask, idx))
		cpu_relax();

	eufs_info("finalizing on %d\n", smp_processor_id());

	return 0;
}

int dep_init(struct super_block *sb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	int cpu;
	int i, j;
	char name[BDEVNAME_SIZE];
	int err;

	sbi->persistee_list = alloc_percpu(struct llist_head);
	if (!sbi->persistee_list) {
		err = -ENOMEM;
		goto cleanup;
	}

	/* init each llist */
	for_each_possible_cpu(cpu)
		init_llist_head(per_cpu_ptr(sbi->persistee_list, cpu));

	sbi->persisters = kzalloc(sizeof(struct task_struct *) *
					  persisters_per_socket * num_sockets,
				  GFP_KERNEL);
	if (!sbi->persisters) {
		err = -ENOMEM;
		goto cleanup;
	}

	sbi->need_sync = kzalloc(
		sizeof(bool) * persisters_per_socket * num_sockets, GFP_KERNEL);
	if (!sbi->need_sync) {
		err = -ENOMEM;
		goto cleanup;
	}

	init_waitqueue_head(&sbi->sync_wq);

	bdevname(sb->s_bdev, name);
	for (i = 0; i < num_sockets; ++i) {
		for (j = 0; j < persisters_per_socket; ++j) {
			int idx = i * persisters_per_socket + j;

			sbi->persisters[idx] = kthread_create_on_node(
				persister, sb, i, "hmfs/%s-%d.%d", name, i, j);

			if (IS_ERR(sbi->persisters[idx])) {
				err = PTR_ERR(sbi->persisters[idx]);
				pr_err("create persister %s-%d.%d error %d",
				       name, i, j, err);
				sbi->persisters[idx] = NULL;
				goto cleanup;
			}

			set_cpus_allowed_ptr(sbi->persisters[idx],
					     cpumask_of_node(i));

			wake_up_process(sbi->persisters[idx]);
		}
	}

	return 0;

cleanup:
	dep_fini(sb);
	return err;
}

void dep_fini(struct super_block *sb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	if (sbi->persisters) {
		int i;

		for (i = 0; i < persisters_per_socket * num_sockets; ++i) {
			if (sbi->persisters[i]) {
				kthread_stop(sbi->persisters[i]);
				sbi->persisters[i] = NULL;
			}
		}

		kfree(sbi->persisters);
		sbi->persisters = NULL;
	}

	kfree(sbi->need_sync);
	sbi->need_sync = NULL;

	free_percpu(sbi->persistee_list);
	sbi->persistee_list = NULL;
}
