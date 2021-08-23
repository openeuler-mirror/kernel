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

#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/ratelimit.h>
#include <asm/cmpxchg.h>
#include "euler.h"
#include "dht.h"
#include "dep.h"

#define GET_CRASH_VER(ptr) (((unsigned long)ptr) >> 56)

void *fix_table(struct super_block *sb, struct nv_dict *dict, u32 idx)
{
	struct nv_dict_entry *he;
	void *real_head;
	u64 head_off;

	head_off = le64_to_cpu(dict->table[idx]);
	if (!head_off)
		return NULL;
	if (head_off == EUFS_DIR_EOC)
		return NULL;
	real_head = o2p(sb, DICT_HEAD_REAL_OFF(head_off));

	if (likely(GET_CRASH_VER(head_off) == EUFS_SB(sb)->s_crash_ver)) {
		/* No need fix */
		return real_head;
	}
	he = real_head;
	BUG_ON(he == EUFS_DIR_EOC_PTR);
	while (he && he != EUFS_DIR_EOC_PTR) {
		if (he->volatile_next) {
			he->volatile_next = NULL_VAL;
			eufs_flush_cacheline(he);
		}
		he = s2p(sb, he->next);
	}
	dict->table[idx] = COMPOSE_DICT_HEAD_le64(sb, real_head);
	eufs_flush_cacheline(&dict->table[idx]);
	eufs_pbarrier();
	return real_head;
}

/*
 * Insert to nv_dict using spinlocks.
 * NOTICE: No resizing supported yet!
 * Previous dentry is always the pointer
 */
struct nv_dict_entry *nv_dict_add(struct inode *dir, u64 **nv_header, u64 h,
				  const char *key, struct eufs_inode *pi)
{
	struct super_block *sb = dir->i_sb;
	struct nv_dict __pmem *dict =
		o2p(sb, eufs_iread_dict(EUFS_FRESH_PI(EUFS_PI(dir))));
	struct v_dict *volatile_dict = EUFS_I(dir)->i_volatile_dict;
	u32 idx;
	long err;
	struct nv_dict_entry __pmem *de;

	idx = INDEX(h);
	NV_ASSERT(dict);
	NV_ASSERT(volatile_dict);

	/* NOTICE: simplified version w/o resizing */
	de = eufs_malloc_dentry(sb);
	if (!de)
		return ERR_PTR(-ENOSPC);
	err = copy_filename(sb, de, h, key);
	if (IS_ERR_VALUE(err)) {
		nv_free(sb, de);
		return ERR_PTR(-ENOSPC);
	}
	WARN_ON(!EUFS_IS_HEAD_PI(pi));
	de->inode = p2s(sb, pi);

	de->next = p2s(sb,
		       (volatile_dict->table[idx]) ?
			       (volatile_dict->table[idx] == EUFS_DIR_EOC_PTR ?
					NULL :
					volatile_dict->table[idx]) :
			       fix_table(sb, dict, idx));
	eufs_dentry_set_not_persist_flag(de);

	PRINT_DENTRY(de, "new dentry: ");
	PRINT_PINODE(de->inode, "inode within dentry: ");

	*nv_header = &dict->table[idx];

	/* Lock the header. It's to be released right after dep is locked. */
	inode_header_lock(dir);
	volatile_dict->table[idx] = de;

	return de;
}

/*
 * Find from nv_dict with the protection of spinlock.
 * No resizing support yet!
 */
struct nv_dict_entry *nv_dict_find(struct inode *dir, hashlen_t h,
				   const char *key)
{
	struct super_block *sb = dir->i_sb;
	struct nv_dict __pmem *dict =
		o2p(sb, eufs_iread_dict(EUFS_FRESH_PI(EUFS_PI(dir))));
	struct v_dict *volatile_dict = EUFS_I(dir)->i_volatile_dict;

	struct nv_dict_entry *he;
	unsigned int idx;

	idx = INDEX(h);

	/*
	 * volatile_dict->table[idx] can be EOC after
	 * all entries have been deleted
	 */
	if (volatile_dict && volatile_dict->table[idx])
		he = volatile_dict->table[idx];
	else
		he = fix_table(sb, dict, idx);
	while (he && he != EUFS_DIR_EOC_PTR) {
		__le64 vnext;

		if (key_equals(sb, key, h, he))
			break;
		vnext = eufs_dentry_vnext(he);
		he = s2p(sb, vnext ? vnext : he->next);
	}

	if (he == EUFS_DIR_EOC_PTR)
		he = NULL;
	return he;
}

/*
 * Delete from nv_dict w/ spinlocks.
 * No resizing support yet!
 * Previous dentry is also returned
 */
struct nv_dict_entry *nv_dict_delete(struct inode *dir,
				     struct nv_dict_entry **prevde,
				     u64 **nv_header, hashlen_t h,
				     const char *key)
{
	struct super_block *sb = dir->i_sb;
	struct nv_dict __pmem *dict =
		o2p(sb, eufs_iread_dict(EUFS_FRESH_PI(EUFS_PI(dir))));
	struct eufs_inode_info *dir_vi = EUFS_I(dir);
	struct v_dict *volatile_dict = dir_vi->i_volatile_dict;

	struct nv_dict_entry *he;
	struct nv_dict_entry *prev = NULL;
	unsigned int idx;
	__le64 vnext;

	NV_ASSERT(dict);
	NV_ASSERT(volatile_dict);

	idx = INDEX(h);

	he = volatile_dict->table[idx] ? volatile_dict->table[idx] :
					 fix_table(sb, dict, idx);

	while (he && he != EUFS_DIR_EOC_PTR) {
		if (key_equals(sb, key, h, he))
			break;
		prev = he;
		vnext = eufs_dentry_vnext(he);
		/* EOC is not NULL, so it's okay. */
		he = s2p(sb, vnext ? vnext : he->next);
	}

	if (he && he != EUFS_DIR_EOC_PTR) {
		/* Lock the header. It's to be released right after dep is locked. */
		inode_header_lock(dir);

		vnext = eufs_dentry_vnext(he);
		if (!prev) {
			/*
			 * the first dentry (head of the chain).
			 * If the target is the end of chain, it is the only
			 * dentry in the chain, then either its volatile_next
			 * is EOC, or its next is NULL.
			 */
			volatile_dict->table[idx] =
				s2p(sb, vnext ? vnext : he->next);
			if (volatile_dict->table[idx] == NULL)
				volatile_dict->table[idx] = EUFS_DIR_EOC_PTR;
		} else {
			bool persist_prev = !eufs_dentry_is_not_persist(prev);

			if (!persist_prev) {
				/*
				 * Protect against the persistence of prev dentry
				 * by background persister.
				 */
				spin_lock(&dir_vi->i_dentry_persist_lock);

				persist_prev =
					!eufs_dentry_is_not_persist(prev);
				if (!persist_prev) {
					/*
					 * Prev is a newly created dentry,
					 * Keep the property,
					 * Two pointers are updated together,
					 * no need to worry about the EOC.
					 */
					prev->next =
						vnext ? (vnext == EUFS_DIR_EOC ?
								 NULL_VAL :
								 vnext) :
							he->next;
					eufs_dentry_set_not_persist_flag(prev);
				}

				spin_unlock(&dir_vi->i_dentry_persist_lock);
			}

			if (persist_prev)
				prev->volatile_next =
					vnext ? vnext :
						(he->next ? he->next :
							    EUFS_DIR_EOC);
		}

		if (eufs_dentry_is_not_persist(he))
			he->volatile_next = EUFS_DIR_DELNEW;

		*prevde = prev;
		/* table[idx] must have been fixed, so it's OK to return it. */
		*nv_header = &dict->table[idx];
	} else if (he == EUFS_DIR_EOC_PTR) {
		he = NULL;
	}

	return he;
}

void nv_dict_scan_via_ptr(struct inode *dir, u64 pos,
			  int (*fn)(void *privdata,
				    const struct nv_dict_entry *de),
			  void *privdata)
{
	struct super_block *sb = dir->i_sb;
	struct nv_dict __pmem *dict =
		o2p(sb, eufs_iread_dict(EUFS_FRESH_PI(EUFS_PI(dir))));
	struct v_dict *volatile_dict = EUFS_I(dir)->i_volatile_dict;

	const struct nv_dict_entry *de = 0;
	u64 idx;
	u64 i;
	u64 skip;
	struct dir_scan_data *data = (struct dir_scan_data *)privdata;
	struct dir_context *ctx = data->ctx;
	int err;

	if (ctx->pos == EUFS_DIR_DOTDOT) {
		idx = 0;
		skip = 0;
	} else {
		idx = CURSOR_IDX(pos);
		skip = CURSOR_CNT(pos);
	}

	/* Next to emit: the skip-th element in dict->table[idx] */
	while (idx < NV_DICT_CAPACITY) {
		if (!de) {
			eufs_ptr_fast_check(dict);
			eufs_ptr_fast_check(dict->table);
			de = (volatile_dict && volatile_dict->table[idx]) ?
				     volatile_dict->table[idx] :
				     fix_table(sb, dict, idx);
		}
		i = 0;
		while (de && de != EUFS_DIR_EOC_PTR) {
			__le64 vnext;

			/* current is the i-th de in list */
			/* skip de's remaining to skip */
			if (skip == 0) {
				err = fn(privdata, de);
				if (err)
					return;
				/* ctx->pos points to the next de */
				ctx->pos = CURSOR(idx, i + 1);
			} else
				skip--;
			i++;
			vnext = eufs_dentry_vnext(de);
			de = s2p(sb, vnext ? vnext : de->next);
		}
		if (de == EUFS_DIR_EOC_PTR)
			de = NULL;
		idx++; /* next idx */
		skip = 0;
	}

	ctx->pos = EUFS_DIR_EODIR;
}
