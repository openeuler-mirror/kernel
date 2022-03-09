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

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/pfn_t.h>
#include <linux/buffer_head.h>
#include <linux/iomap.h>
#include <linux/dax.h>
#include <linux/cpufeature.h>
#include <linux/pgtable.h>
#include "euler.h"
#include "dax.h"
#include "dep.h"
#include "wear.h"
#include "alloc_interface.h"

int eufs_persist_btree_node(void *root, int sta, int len);

static __always_inline void eufs_clear_pmem(void *addr, size_t size)
{
	memset(addr, 0, size);
	eufs_flush_range(addr, size);
}

static __always_inline void *eufs_find_data_block_btree(struct inode *inode,
							unsigned long blocknr,
							__le64 **parent)
{
	__le64 *bp;
	u32 height, bit_shift;
	unsigned int idx;
	struct eufs_inode_info *vi = EUFS_I(inode);

	/* inode must be a regular file */
	height = vi->i_volatile_height;
	bp = vi->i_volatile_root;

	NV_ASSERT(blocknr < (1UL << (height * EUFS_FILE_TREE_DEGREE_SHIFT)));

	if (height == 0) {
		BUG_ON(blocknr != 0);
		if (parent)
			*parent = NULL;
		return (void *)bp;
	}

	if (height == 1) {
		if (bp[blocknr] == NULL_VAL)
			BUG();

		if (parent)
			*parent = bp;
		return s2p(inode->i_sb, bp[blocknr]);
	}
	while (height > 0) {
		bit_shift = (height - 1) * EUFS_FILE_TREE_DEGREE_SHIFT;
		idx = blocknr >> bit_shift;
		if (parent)
			*parent = bp;
		bp = s2p(inode->i_sb, bp[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}
	return bp;
}

static int eufs_extend_btree_recursive_blind(struct inode *inode,
					     int level_left, __le64 *parent,
					     int sta_index,
					     int end_index, /* inclusive */
					     struct alloc_batch *ab)
{
	struct super_block *sb = inode->i_sb;
	void *p;
	long r;
	int i;

	for (i = sta_index; i <= end_index; ++i) {
		if (!level_left) {
			parent[i] = NULL_ADDR;
			continue;
		}
		/* level_left */
		p = eufs_alloc_batch_allocate_file_index(inode->i_sb, ab);
		if (!p)
			return -ENOSPC;
		parent[i] = p2s(sb, p);
		/* recur */
		r = eufs_extend_btree_recursive_blind(inode, level_left - 1, p,
						      0,
						      EUFS_FILE_TREE_DEGREE - 1,
						      ab);
		if (IS_ERR_VALUE(r))
			return r;
	}
	return 0;
}

/*
 * Allocate blocks from top to bottom.
 *
 * Only allocate the interior blocks which will have a leaf child block or
 * an interior child block. And the unused pointers for children will NOT
 * be zeroed.
 *
 * New leaf blocks are not allocated, and their values are set to NULL_ADDR.
 */
static int eufs_extend_btree_recursive(struct inode *inode, int level_left,
				       __le64 *parent, unsigned long origin,
				       unsigned long num_blocks,
				       struct alloc_batch *ab, bool blind)
{
	struct super_block *sb = inode->i_sb;
	const unsigned long nblocks_per_slot =
		1 << (level_left * EUFS_FILE_TREE_DEGREE_SHIFT);
	unsigned long off;
	int sta_index, end_index;
	int i;
	long r;
	void *p;

	if (blind) {
		return eufs_extend_btree_recursive_blind(
			inode, level_left, parent, 0, EUFS_FILE_TREE_DEGREE - 1,
			ab);
	}

	if (origin == 0) {
		/* end_index could be zero */
		end_index = (num_blocks - 1) / nblocks_per_slot;
		r = eufs_extend_btree_recursive_blind(inode, level_left, parent,
						      0, end_index - 1, ab);
		if (IS_ERR_VALUE(r))
			return r;
		if (!level_left) {
			parent[end_index] = NULL_ADDR;
		} else {
			p = eufs_alloc_batch_allocate_file_index(inode->i_sb,
								 ab);
			if (!p)
				return -ENOSPC;
			parent[end_index] = p2s(sb, p);
			off = nblocks_per_slot * end_index;
			r = eufs_extend_btree_recursive(inode, level_left - 1,
							p, 0, num_blocks - off,
							ab, false);
			if (IS_ERR_VALUE(r))
				return r;
		}
		return 0;
	}

	sta_index = (origin - 1) / nblocks_per_slot;
	end_index = (num_blocks - 1) / nblocks_per_slot;

	/*
	 * No need to create a new sub-tree, so descend to the sub-tree
	 * rooted in parent[sta_index]
	 */
	if (sta_index == end_index) {
		if (!level_left)
			return 0;

		/* calculate the needed block count in the sub-tree */
		off = sta_index * nblocks_per_slot;
		r = eufs_extend_btree_recursive(inode, level_left - 1,
						s2p(sb, parent[sta_index]),
						origin - off, num_blocks - off,
						ab, false);
		if (IS_ERR_VALUE(r))
			return r;
		return 0;
	}

	if (!level_left) {
		for (i = sta_index + 1; i <= end_index; ++i)
			parent[i] = NULL_ADDR;

		return 0;
	}

	/* extend sub-tree shared with existed blocks to its maximum size */
	off = sta_index * nblocks_per_slot;
	r = eufs_extend_btree_recursive(inode, level_left - 1,
					s2p(sb, parent[sta_index]),
					origin - off, nblocks_per_slot, ab,
					false);
	if (IS_ERR_VALUE(r))
		return r;

	/* new sub-trees which will be fully initialized */
	r = eufs_extend_btree_recursive_blind(inode, level_left, parent,
					      sta_index + 1, end_index - 1, ab);
	if (IS_ERR_VALUE(r))
		return r;

	/* the last new sub-tree which may only needs partial initialization */
	p = eufs_alloc_batch_allocate_file_index(inode->i_sb, ab);
	if (!p)
		return -ENOSPC;
	parent[end_index] = p2s(sb, p);

	off = end_index * nblocks_per_slot;
	r = eufs_extend_btree_recursive(inode, level_left - 1, p, 0,
					num_blocks - off, ab, false);
	if (IS_ERR_VALUE(r))
		return r;
	return 0;
}

static unsigned long eufs_count_pages(unsigned long leaf_blocks)
{
	unsigned long tot = leaf_blocks;

	while (leaf_blocks > 1) {
		leaf_blocks = DIV_ROUND_UP(leaf_blocks, EUFS_FILE_TREE_DEGREE);
		tot += leaf_blocks;
	}
	return tot;
}

/* So that we have page[0..num_blocks-1] */
int eufs_extend_btree(struct inode *inode, unsigned long num_blocks)
{
	struct eufs_inode_info *vi = EUFS_I(inode);
	unsigned long full_size;
	unsigned long need_blocks;
	__le64 *new_root;
	long r = 0;
	struct alloc_batch *ab = &vi->page_batch;

	if (!num_blocks)
		return 0;
	if (vi->i_volatile_tree_blocks >= num_blocks)
		/* already allocated */
		return 0;
	if (num_blocks > inode->i_sb->s_maxbytes >> EUFS_BLOCK_SIZE_BITS)
		return -EFBIG;

	/* Grow from vi->i_volatile_tree_blocks to num_blocks */
	need_blocks = eufs_count_pages(num_blocks) -
		      eufs_count_pages(vi->i_volatile_tree_blocks);

	/* Set NULL_ADDR for extended data blocks */
	need_blocks -= (num_blocks - vi->i_volatile_tree_blocks);

	r = eufs_alloc_batch_pre_allocate_begin(inode->i_sb, ab, need_blocks);
	if (IS_ERR_VALUE(r))
		return r;

	BUG_ON(!vi->i_volatile_root);
	if (!vi->i_volatile_root) {
		vi->i_volatile_root =
			eufs_alloc_batch_allocate_file_data(inode->i_sb, ab);
		BUG_ON(!vi->i_volatile_root);
		vi->i_volatile_height = 0;
	}
	if (num_blocks == 1) {
		/* Already allocated */
		goto out;
	}
	full_size = 1UL
		    << (vi->i_volatile_height * EUFS_FILE_TREE_DEGREE_SHIFT);
	while (full_size < num_blocks) {
		new_root =
			eufs_alloc_batch_allocate_file_index(inode->i_sb, ab);
		new_root[0] = p2s(inode->i_sb, vi->i_volatile_root);
		vi->i_volatile_root = new_root;
		vi->i_volatile_height++;
		full_size <<= EUFS_FILE_TREE_DEGREE_SHIFT;
	}
	BUG_ON(vi->i_volatile_height < 1);
	r = eufs_extend_btree_recursive(inode, vi->i_volatile_height - 1,
					vi->i_volatile_root,
					vi->i_volatile_tree_blocks, num_blocks,
					ab, false);
out:
	eufs_alloc_batch_pre_allocate_end(inode->i_sb, ab);
	vi->i_volatile_tree_blocks = num_blocks;
	num_blocks <<= (inode->i_blkbits - 9);
	if (num_blocks > inode->i_blocks)
		inode->i_blocks = num_blocks;
	return r;
}

int eufs_alloc_blocks_btree(struct inode *inode, unsigned long start_block,
			    unsigned long num_blocks, int zero)
{
	long r;
	unsigned long blocknr, need_blocks = 0,
			       end_block = start_block + num_blocks;
	long pi_tree_blocks =
		eufs_iread_tree_blocks(EUFS_FRESH_PI(EUFS_PI(inode)));
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct alloc_batch *ab = &vi->page_batch;
	__le64 *parent;
	unsigned int ofs;
	void *xmem;
	int last_ofs_line = -1;

	r = eufs_extend_btree(inode, start_block + num_blocks);
	if (r)
		return r;

	if (start_block == 0)
		vi->hole_at_sta = false;

	/* The 0th data block is always allocated. */
	blocknr = start_block ? start_block : 1;

	/* TODO: need optimization. */
	while (blocknr < end_block) {
		eufs_find_data_block_btree(inode, blocknr, &parent);
		BUG_ON(!parent);
		ofs = blocknr & (EUFS_FILE_TREE_DEGREE - 1);
		while (ofs < EUFS_FILE_TREE_DEGREE && blocknr < end_block) {
			if (parent[ofs] == NULL_ADDR) {
				/*
				 * The leaf blocks are not allocated before persist,
				 * e.g. through truncate() + fsync()
				 */
				if (blocknr < pi_tree_blocks) {
					xmem = eufs_zalloc_file_data(
						inode->i_sb);
					if (!xmem)
						return -ENOSPC;
					eufs_alloc_persist(inode->i_sb, xmem,
							   false);
					eufs_flush_page(xmem);
					parent[ofs] = p2s(inode->i_sb, xmem);
					eufs_flush_cacheline(&parent[ofs]);

					invalidate_inode_pages2_range(
						inode->i_mapping, blocknr,
						blocknr);

				} else
					need_blocks++;
			}
			ofs++;
			blocknr++;
		}
	}

	if (!need_blocks)
		return 0;

	/* TODO: need optimization. */
	r = eufs_alloc_batch_pre_allocate_begin(inode->i_sb, ab, need_blocks);
	if (IS_ERR_VALUE(r))
		return r;

	blocknr = start_block ? start_block : 1;
	while (blocknr < end_block) {
		eufs_find_data_block_btree(inode, blocknr, &parent);
		BUG_ON(!parent);
		last_ofs_line = -1;
		ofs = blocknr & (EUFS_FILE_TREE_DEGREE - 1);
		while (ofs < EUFS_FILE_TREE_DEGREE && blocknr < end_block) {
			if (parent[ofs] == NULL_ADDR) {
				xmem = eufs_alloc_batch_allocate_file_data(
					inode->i_sb, ab);
				if (zero == EUFS_ALLOC_BLOCKS_ZERO_ALL ||
				    ((zero == EUFS_ALLOC_BLOCKS_ZERO_EDGE) &&
				     (blocknr == start_block ||
				      blocknr == end_block - 1)))
					eufs_clear_pmem(xmem, PAGE_SIZE);

				parent[ofs] = p2s(inode->i_sb, xmem);

				invalidate_inode_pages2_range(inode->i_mapping,
							      blocknr, blocknr);

				if (last_ofs_line == -1)
					last_ofs_line =
						(ofs >>
						 EUFS_PTR_CNT_SHIFT_PER_CACHELINE);
			}
			ofs++;
			if (last_ofs_line != -1 &&
			    (ofs >> EUFS_PTR_CNT_SHIFT_PER_CACHELINE) !=
				    last_ofs_line) {
				eufs_flush_cacheline(&parent[ofs - 1]);
				last_ofs_line = -1;
			}
			blocknr++;
		}
		if (last_ofs_line != -1)
			eufs_flush_cacheline(&parent[ofs - 1]);
	}

	eufs_alloc_batch_pre_allocate_end(inode->i_sb, ab);
	return r;
}

static int eufs_alloc_blocks_btree_for_write(struct inode *inode, loff_t pos,
					     int len)
{
	long r;
	unsigned long blocknr, need_blocks = 0;
	long pi_tree_blocks =
		eufs_iread_tree_blocks(EUFS_FRESH_PI(EUFS_PI(inode)));
	size_t file_size_block = PAGE_DIV_ROUND_UP(inode->i_size);
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct alloc_batch *ab = &vi->page_batch;
	__le64 *parent;
	void *xmem;
	/* The page first byte resides in */
	unsigned long first_page = PAGE_DIV_ROUND_DOWN(pos);
	/* The page last byte resides in */
	unsigned long last_page = PAGE_DIV_ROUND_DOWN(pos + len - 1);
	unsigned long pending_flush_bits;
	int start_offset;
	int end_offset;
	int ofs;

	r = eufs_extend_btree(inode, last_page + 1);
	if (r)
		return r;

	/* hole_at_sta is used by SEEK_HOLE. */
	/* FIXME: We need a durable way to present hole_at_sta. */
	if (first_page == 0)
		vi->hole_at_sta = false;

	/* The 0th data block is always allocated. */
	blocknr = first_page ? first_page : 1;

	/*
	 * Can be optimized by saving the top-down parent pointers
	 * in a cursor and advancing by moving the cursor
	 */
	while (blocknr <= last_page) {
		eufs_find_data_block_btree(inode, blocknr, &parent);
		BUG_ON(!parent);

		/* One ofs, one block */
		for (ofs = blocknr & (EUFS_FILE_TREE_DEGREE - 1);
		     ofs < EUFS_FILE_TREE_DEGREE && blocknr <= last_page;
		     ++ofs, ++blocknr) {
			/* Not a hole */
			if (parent[ofs] != NULL_ADDR)
				continue;

			/* Hole */
			if (blocknr < pi_tree_blocks) {
				/*
				 * TODO: optimize option, instead of wrting
				 * zeros here, we can write the actual data
				 * instead.
				 */
				xmem = eufs_zalloc_file_data(inode->i_sb);
				if (!xmem)
					return -ENOSPC;
				eufs_alloc_persist(inode->i_sb, xmem, false);
				eufs_flush_page(xmem);
				parent[ofs] = p2s(inode->i_sb, xmem);
				eufs_flush_cacheline(&parent[ofs]);

				invalidate_inode_pages2_range(inode->i_mapping,
							      blocknr, blocknr);

			} else
				need_blocks++;
		}
	}

	if (!need_blocks)
		return 0;

	/* FIXME: This requries re-write */
	r = eufs_alloc_batch_pre_allocate_begin(inode->i_sb, ab, need_blocks);
	if (IS_ERR_VALUE(r))
		return r;

	start_offset = pos & (PAGE_SIZE - 1);
	end_offset = (pos + len) & (PAGE_SIZE - 1);
	blocknr = first_page ? first_page : 1;
	while (blocknr <= last_page) {
		unsigned long bit;

		eufs_find_data_block_btree(inode, blocknr, &parent);

		BUG_ON(!parent);

		/* No cacheline is pending to be flushed for this index block */
		pending_flush_bits = 0;

		for (ofs = blocknr & (EUFS_FILE_TREE_DEGREE - 1);
		     ofs < EUFS_FILE_TREE_DEGREE && blocknr <= last_page;
		     ++ofs, ++blocknr) {
			/* Not a hole */
			if (parent[ofs] != NULL_ADDR)
				continue;

			xmem = eufs_alloc_batch_allocate_file_data(inode->i_sb,
								   ab);
			if (unlikely(blocknr == first_page &&
				     (start_offset != 0)))
				eufs_clear_pmem(xmem, start_offset);

			/* Do not clear the last block which is after the EOF-block */
			if (unlikely(blocknr == last_page &&
				     (end_offset != 0) &&
				     blocknr < file_size_block))
				eufs_clear_pmem((char *)xmem + end_offset,
						PAGE_SIZE - end_offset);

			parent[ofs] = p2s(inode->i_sb, xmem);

			invalidate_inode_pages2_range(inode->i_mapping, blocknr,
						      blocknr);
			set_bit(ofs >> EUFS_PTR_CNT_SHIFT_PER_CACHELINE,
				&pending_flush_bits);
		}

		for (bit = find_first_bit(&pending_flush_bits, 64); bit < 64;
		     bit = find_next_bit(&pending_flush_bits, 64, bit + 1)) {
			ofs = bit << EUFS_PTR_CNT_SHIFT_PER_CACHELINE;
			eufs_flush_cacheline(&parent[ofs]);
		}
	}

	eufs_alloc_batch_pre_allocate_end(inode->i_sb, ab);
	return r;
}

static void eufs_free_recursive_btree_blind(struct super_block *sb,
					    __le64 *root, int level_left)
{
	int i;

	BUG_ON(!root);
	if (level_left == -1) {
		if (root != NULL_ADDR_PTR)
			nv_zfree(sb, root);
		return;
	}
	/* level_left */
	BUG_ON(root == NULL_ADDR_PTR);
	for (i = 0; i < EUFS_FILE_TREE_DEGREE; ++i) {
		eufs_free_recursive_btree_blind(sb, s2p(sb, root[i]),
						level_left - 1);
	}
	nv_zfree(sb, root);
}

static void eufs_free_recursive_btree(struct super_block *sb, __le64 *root,
				      int level_left, u64 blocks_left)
{
	u64 nblocks_per_slot;
	int i;

	BUG_ON(!root);
	BUG_ON(!blocks_left);
	if (level_left == -1) {
		if (root != NULL_ADDR_PTR)
			nv_zfree(sb, root);
		return;
	}
	/* level_left */
	BUG_ON(root == NULL_ADDR_PTR);
	nblocks_per_slot = 1 << (level_left * EUFS_FILE_TREE_DEGREE_SHIFT);
	for (i = 0; i < EUFS_FILE_TREE_DEGREE; ++i) {
		if (blocks_left >= nblocks_per_slot) {
			/* the whole sub-tree needs to be freed */
			eufs_free_recursive_btree_blind(sb, s2p(sb, root[i]),
							level_left - 1);
			blocks_left -= nblocks_per_slot;
			if (blocks_left == 0)
				break;
		} else {
			eufs_free_recursive_btree(sb, s2p(sb, root[i]),
						  level_left - 1, blocks_left);
			break;
		}
	}
	nv_zfree(sb, root);
}

int eufs_shrink_btree(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct eufs_inode *pi = EUFS_PI(inode);

	void *root;

	u64 capacity;
	__le64 *new_root;
	__le64 *old_root;
	int new_height;
	u64 size;
	u64 blocks;
	u64 count;
	u64 blocks_left;
	u64 __maybe_unused pi_root_o;

	BUG_ON(!inode_is_locked(inode));
	BUG_ON(vi->i_volatile_height > EUFS_MAX_FILE_TREE_HEIGHT);

	pi_root_o = eufs_iread_root(pi);
	eufs_dbg("shrink btree stage 1: pi=%px vi->{s=%lld b=%lld h=%d r=%px} pi->{s=%lld b=%lld h=%d r=0x%llx}\n",
		 pi, inode->i_size, vi->i_volatile_tree_blocks,
		 vi->i_volatile_height, vi->i_volatile_root,
		 eufs_iread_size(pi), eufs_iread_tree_blocks(pi),
		 root_height(pi_root_o), root_ptr(pi_root_o));
	eufs_sync_pinode(inode, pi, false);

	capacity = PAGE_SIZE
		   << (EUFS_FILE_TREE_DEGREE_SHIFT * vi->i_volatile_height);
	new_root = vi->i_volatile_root;
	old_root = vi->i_volatile_root;
	new_height = vi->i_volatile_height;
	size = inode->i_size == 0 ? 1 : inode->i_size;

	/* old block count */
	blocks = vi->i_volatile_tree_blocks;

	/* Check whether the height should be reduced */
	for (;;) {
		capacity >>= EUFS_FILE_TREE_DEGREE_SHIFT;
		if (capacity < size || capacity < PAGE_SIZE)
			break;
		new_root = s2p(sb, new_root[0]);
		new_height--;
	}
	vi->i_volatile_root = new_root;
	vi->i_volatile_height = new_height;
	vi->i_volatile_tree_blocks = DIV_ROUND_UP(size, PAGE_SIZE);

	eufs_sync_pinode(inode, pi, false);

	eufs_alloc_batch_persist_reset(sb, &vi->page_batch);

	/* new block count and it's greater than 0 */
	count = blocks_left = vi->i_volatile_tree_blocks;

	/* shrink from old_root/_height to new_root/_height */
	root = old_root;

	if (blocks_left == blocks)
		goto out;

	if (blocks == 1)
		goto out;

	if (blocks <= EUFS_FILE_BCNT_WITH_HEIGHT(1)) {
		int i;

		__le64 *proot = root;

		for (i = count; i < blocks; ++i) {
			nv_free(sb, s2p(sb, proot[i]));
			proot[i] = NULL_VAL;
		}
		goto out;
	}

	if (blocks <= EUFS_FILE_BCNT_WITH_HEIGHT(2)) {
		int i;
		__le64 *proot = root;

		for (i = EUFS_H2_INDEX_IN_L0(count); i < EUFS_FILE_TREE_DEGREE;
		     ++i) {
			__le64 *pages = s2p(sb, proot[i]);
			int j = EUFS_H2_INDEX_IN_L1(count);

			for (; j < EUFS_FILE_TREE_DEGREE; ++j) {
				nv_free(sb, s2p(sb, pages[j]));
				pages[j] = NULL_VAL;
				count++;
				if (count >= blocks)
					break;
			}
			if (EUFS_H2_IS_FREE_L1_SUBTREE(i, blocks_left)) {
				nv_free(sb, pages);
				proot[i] = NULL_VAL;
			}
			if (count >= blocks)
				break;
		}
		goto out;
	}

	if (blocks <= EUFS_FILE_BCNT_WITH_HEIGHT(3)) {
		int i, j, k;
		__le64 *pproot = root;

		for (i = EUFS_H3_INDEX_IN_L0(count); i < EUFS_FILE_TREE_DEGREE;
		     ++i) {
			__le64 *proot = s2p(sb, pproot[i]);

			j = EUFS_H3_INDEX_IN_L1(i, count);
			for (; j < EUFS_FILE_TREE_DEGREE; ++j) {
				__le64 *pages = s2p(sb, proot[j]);

				k = EUFS_H3_INDEX_IN_L2(count);
				for (; k < EUFS_FILE_TREE_DEGREE; ++k) {
					nv_free(sb, s2p(sb, pages[k]));
					pages[k] = NULL_VAL;
					count++;
					if (count >= blocks)
						break;
				}
				if (EUFS_H3_IS_FREE_L2_SUBTREE(i, j,
							       blocks_left)) {
					nv_free(sb, pages);
					proot[j] = NULL_VAL;
				}
				if (count >= blocks)
					break;
			}
			if (EUFS_H3_IS_FREE_L1_SUBTREE(i, blocks_left)) {
				nv_free(sb, proot);
				pproot[i] = NULL_VAL;
			}
			if (count >= blocks)
				break;
		}
	}

out:
	while (old_root != new_root) {
		__le64 *r = old_root;

		BUG_ON(!r);
		old_root = s2p(sb, r[0]);
		nv_free(sb, r);
	}

	return 0;
}

int eufs_free_btree(struct super_block *sb, void *root, int height, u64 blocks)
{
	NV_ASSERT(!(height < 0 || height > EUFS_MAX_FILE_TREE_HEIGHT));
	eufs_dbg("nvfree tree root: %px\n", root);
	if (blocks == 0)
		return 0;
	if (blocks == 1) {
		/* height == 0 */
		nv_free(sb, root);
		return 0;
	}
	eufs_free_recursive_btree(sb, (__le64 *)root, height - 1, blocks);
	return 0;
}

int eufs_persist_btree_node(void *root, int sta, int len)
{
	BUG_ON(len > EUFS_FILE_TREE_DEGREE);
	BUG_ON(len < 0);
	BUG_ON(sta + len > EUFS_FILE_TREE_DEGREE);
	BUG_ON(sta + len < 0);
	if (len == 0)
		return 0;
	eufs_ptr_fast_check(root);
	eufs_flush_range(((void **)root) + sta, len * sizeof(void *));
	return 0;
}

static void eufs_persist_btree_h2_subtree(struct super_block *sb, void *root,
					  int start0, int idx0, int idx1)
{
	__le64 *proot = root;
	int i;
	void *p;

	for (i = start0; i < idx0; ++i) {
		BUG_ON(proot[i] == 0);

		p = s2p(sb, proot[i]);
		eufs_ptr_fast_check(p);
		eufs_persist_btree_node(p, 0, EUFS_FILE_TREE_DEGREE);
	}

	/*
	 * According to the WARN_ON in eufs_persist_new_btree_h2,
	 * idx0 < EUFS_FILE_TREE_DEGREE if idx1 != 0. So the following code
	 * is safe.
	 */
	if (idx1 != 0) {
		p = s2p(sb, proot[idx0]);
		eufs_persist_btree_node(p, 0, idx1);
	}
}

static void eufs_persist_btree_h2_root(void *root, int start0, int idx0,
				       int idx1)
{
	int cnt = idx0 - start0;

	/*
	 * It's the L1 index of the next block, so when it's not equals with 0,
	 * the node[idx0] also needs persistence.
	 */
	if (idx1 != 0)
		cnt++;

	eufs_persist_btree_node(root, start0, cnt);
}

static void eufs_persist_new_btree_h2_by_idx(struct super_block *sb, void *root,
					     int start0, int idx0, int idx1)
{
	eufs_persist_btree_h2_subtree(sb, root, start0, idx0, idx1);
	/* It's a new btree, so persist the whole root node */
	eufs_persist_btree_h2_root(root, 0, idx0, idx1);
}

static void eufs_persist_new_btree_h2(struct super_block *sb, void *root,
				      int start0, unsigned long bcnt)
{
	/* the L0/L1 index of the next block in new tree with height 2 */
	int idx0 = EUFS_H2_INDEX_IN_L0(bcnt);
	int idx1 = EUFS_H2_INDEX_IN_L1(bcnt);

	/*
	 * Notice a corner case: bcnt == EUFS_FILE_BCNT_WITH_HEIGHT(2), in
	 * which (idx0 == EUFS_FILE_TREE_DEGREE && idx1 == 0)
	 */
	WARN_ON(idx0 == EUFS_FILE_TREE_DEGREE && idx1);

	eufs_persist_new_btree_h2_by_idx(sb, root, start0, idx0, idx1);
}

static void eufs_persist_inc_btree_h2_by_idx(struct super_block *sb, void *root,
					     int old_idx0, int old_idx1,
					     int new_idx0, int new_idx1)
{
	__le64 *proot = root;
	void *p;
	int start;

	p = s2p(sb, proot[old_idx0]);
	if (old_idx0 == new_idx0) {
		if (old_idx0 == EUFS_FILE_TREE_DEGREE)
			return;

		eufs_persist_btree_node(p, old_idx1, new_idx1 - old_idx1);

		/* node[old_idx0] needs persistence */
		if (!old_idx1)
			eufs_persist_btree_node(root, old_idx0, 1);

		return;
	}

	eufs_persist_btree_node(p, old_idx1, EUFS_FILE_TREE_DEGREE - old_idx1);

	eufs_persist_btree_h2_subtree(sb, root, old_idx0 + 1, new_idx0,
				      new_idx1);

	start = old_idx0;
	/* if old_idx0 is not 0, root[start] must have already been persisted */
	if (old_idx1)
		start++;
	eufs_persist_btree_h2_root(root, start, new_idx0, new_idx1);
}

static void eufs_persist_inc_btree_h2(struct super_block *sb, void *root,
				      unsigned long old_bcnt,
				      unsigned long new_bcnt)
{
	/* the L0/L1 index of the next block in tree */
	int old_idx0 = EUFS_H2_INDEX_IN_L0(old_bcnt);
	int old_idx1 = EUFS_H2_INDEX_IN_L1(old_bcnt);
	int new_idx0 = EUFS_H2_INDEX_IN_L0(new_bcnt);
	int new_idx1 = EUFS_H2_INDEX_IN_L1(new_bcnt);

	/*
	 * Notice a corner case: bcnt == EUFS_FILE_BCNT_WITH_HEIGHT(2), in
	 * which (idx0 == EUFS_FILE_TREE_DEGREE && idx1 == 0)
	 */
	WARN_ON(old_idx0 == EUFS_FILE_TREE_DEGREE && old_idx1);
	WARN_ON(new_idx0 == EUFS_FILE_TREE_DEGREE && new_idx1);

	eufs_persist_inc_btree_h2_by_idx(sb, root, old_idx0, old_idx1, new_idx0,
					 new_idx1);
}

static void eufs_persist_new_btree_h3(struct super_block *sb, void *root,
				      int start0, unsigned long bcnt_left)
{
	int i;
	unsigned long left = bcnt_left;
	__le64 *pproot = root;

	for (i = start0; i < EUFS_FILE_TREE_DEGREE; ++i) {
		__le64 *proot = s2p(sb, pproot[i]);
		int j;

		for (j = 0; j < EUFS_FILE_TREE_DEGREE; ++j) {
			void *p = s2p(sb, proot[j]);

			if (left >= EUFS_FILE_TREE_DEGREE) {
				eufs_persist_btree_node(p, 0,
							EUFS_FILE_TREE_DEGREE);
				left -= EUFS_FILE_TREE_DEGREE;
			} else {
				eufs_persist_btree_node(p, 0, left);
				left = 0;
				j++;
				break;
			}
		}

		eufs_persist_btree_node(proot, 0, j);
		if (!left) {
			i++;
			break;
		}
	}

	eufs_persist_btree_node(root, 0, i);
}

static void eufs_persist_inc_btree_h3(struct super_block *sb, void *root,
				      unsigned long old_bcnt,
				      unsigned long new_bcnt)
{
	/* The L0/L1/L2 position of the next block in tree */
	int o_idx0 = EUFS_H3_INDEX_IN_L0(old_bcnt);
	int o_idx1 = EUFS_H3_INDEX_IN_L1(o_idx0, old_bcnt);
	int o_idx2 = EUFS_H3_INDEX_IN_L2(old_bcnt);
	int n_idx0 = EUFS_H3_INDEX_IN_L0(new_bcnt);
	int n_idx1 = EUFS_H3_INDEX_IN_L1(n_idx0, new_bcnt);
	int n_idx2 = EUFS_H3_INDEX_IN_L2(new_bcnt);
	__le64 *pproot = root;
	__le64 *proot;
	void *p;
	int i;

	if (o_idx0 == n_idx0 && o_idx1 == n_idx1) {
		/* persist from the bottom up */
		proot = s2p(sb, pproot[o_idx0]);
		p = s2p(sb, proot[o_idx1]);
		eufs_persist_btree_node(p, o_idx2, n_idx2 - o_idx2);

		/* node[o_idx1] needs persistence */
		if (!o_idx2) {
			eufs_persist_btree_node(proot, o_idx1, 1);

			/* node[o_idx0] needs persistence */
			if (!o_idx1)
				eufs_persist_btree_node(root, o_idx0, 1);
		}

		return;
	}

	if (o_idx0 == n_idx0) {
		proot = s2p(sb, pproot[o_idx0]);
		eufs_persist_inc_btree_h2_by_idx(sb, proot, o_idx1, o_idx2,
						 n_idx1, n_idx2);

		/* node[o_idx0] needs persistence */
		if (!o_idx1 && !o_idx2)
			eufs_persist_btree_node(root, o_idx0, 1);

		return;
	}

	/*
	 * A corner case: o_idx1 == EUFS_FILE_TREE_DEGREE && o_idx2 == 0. This
	 * can be handled in the function eufs_persist_inc_btree_h2_by_idx, but
	 * we still check it here for efficiency.
	 */
	if (o_idx1 < EUFS_FILE_TREE_DEGREE) {
		proot = s2p(sb, pproot[o_idx0]);
		eufs_persist_inc_btree_h2_by_idx(sb, proot, o_idx1, o_idx2,
						 EUFS_FILE_TREE_DEGREE, 0);
	} else {
		WARN_ON(o_idx2 != 0);
	}

	for (i = o_idx0 + 1; i < n_idx0; ++i) {
		proot = s2p(sb, pproot[i]);
		eufs_persist_new_btree_h2_by_idx(sb, proot, 0,
						 EUFS_FILE_TREE_DEGREE, 0);
	}

	if (n_idx1 || n_idx2) {
		proot = s2p(sb, pproot[n_idx0]);
		eufs_persist_new_btree_h2_by_idx(sb, proot, 0, n_idx1, n_idx2);
		/* root[n_idx0] needs to be persisted */
		n_idx0++;
	}

	/* root[o_idx0] has been persisted */
	if (o_idx1 || o_idx2)
		o_idx0++;

	eufs_persist_btree_node(root, o_idx0, n_idx0 - o_idx0);
}

/* Only structure persistency is needed */
int eufs_persist_btree(struct super_block *sb, void *root, int height,
		       u64 old_size, u64 new_size)
{
	unsigned long old_nblocks, new_nblocks;
	__le64 *proot;
	__le64 *pproot;

	if (old_size == 0)
		old_size = 1; /* at least one block */
	NV_ASSERT(!(height < 0 || height > EUFS_MAX_FILE_TREE_HEIGHT));
	if (!root)
		return 0;
	/* don't support for persisting for shrink */
	if (old_size > new_size)
		return 0;
	old_nblocks = DIV_ROUND_UP(old_size, PAGE_SIZE);
	new_nblocks = DIV_ROUND_UP(new_size, PAGE_SIZE);
	if (old_nblocks == new_nblocks)
		return 0;
	proot = root;
	if (old_nblocks == 1) {
		/* data do not need flush */
		if (new_nblocks == 1)
			return 0;

		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(1)) {
			eufs_persist_btree_node(root, 0, new_nblocks);
			return 0;
		}
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(2)) {
			eufs_persist_new_btree_h2(sb, root, 0, new_nblocks);
			return 0;
		}
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(3)) {
			eufs_persist_new_btree_h3(sb, root, 0, new_nblocks);
			return 0;
		}
	} else if (old_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(1)) {
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(1)) {
			eufs_persist_btree_node(root, old_nblocks,
						new_nblocks - old_nblocks);
			return 0;
		}
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(2)) {
			__le64 *p = s2p(sb, proot[0]);

			eufs_persist_btree_node(p, old_nblocks,
						EUFS_FILE_TREE_DEGREE -
							old_nblocks);
			eufs_persist_new_btree_h2(sb, proot, 1, new_nblocks);
			return 0;
		}
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(3)) {
			void *p;

			pproot = root;
			proot = s2p(sb, pproot[0]);
			p = s2p(sb, proot[0]);
			eufs_persist_btree_node(p, old_nblocks,
						EUFS_FILE_TREE_DEGREE -
							old_nblocks);
			eufs_persist_new_btree_h2(
				sb, proot, 1, EUFS_FILE_BCNT_WITH_HEIGHT(2));

			eufs_persist_new_btree_h3(
				sb, root, 1,
				new_nblocks - EUFS_FILE_BCNT_WITH_HEIGHT(2));

			return 0;
		}
	} else if (old_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(2)) {
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(2)) {
			eufs_persist_inc_btree_h2(sb, root, old_nblocks,
						  new_nblocks);
			return 0;
		}
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(3)) {
			pproot = root;
			proot = s2p(sb, pproot[0]);
			eufs_persist_inc_btree_h2(
				sb, proot, old_nblocks,
				EUFS_FILE_BCNT_WITH_HEIGHT(2));

			eufs_persist_new_btree_h3(
				sb, root, 1,
				new_nblocks - EUFS_FILE_BCNT_WITH_HEIGHT(2));

			return 0;
		}
	} else if (old_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(3)) {
		if (new_nblocks <= EUFS_FILE_BCNT_WITH_HEIGHT(3)) {
			eufs_persist_inc_btree_h3(sb, root, old_nblocks,
						  new_nblocks);
			return 0;
		}
	}
	BUG();
	return 0;
}

static ssize_t do_mapping_read(struct address_space *mapping,
			       struct file_ra_state *_ra, struct file *filp,
			       char __user *buf, size_t len, loff_t *ppos)
{
	struct inode *inode = mapping->host;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;
	do {
		unsigned long nr, left;
		void *xmem;

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		if (index >= end_index) {
			if (index > end_index)
				goto out;

			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset)
				goto out;
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		xmem = eufs_find_data_block_btree(inode, index, NULL);

		BUG_ON(!eufs_access_ok(inode->i_sb, xmem, PAGE_SIZE));
		if (unlikely(!xmem))
			BUG();

		/*
		 * Ok, we have the mem, so now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		if (xmem != NULL_ADDR_PTR)
			left = __copy_to_user(buf + copied, xmem + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		if (left) {
			error = -EFAULT;
			goto out;
		}

		copied += nr;
		offset += nr;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return copied ? copied : error;
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * i_mutex.
 */
ssize_t eufs_file_read(struct file *filp, char __user *buf, size_t len,
			   loff_t *ppos)
{
	ssize_t res;

	inode_lock_shared(file_inode(filp));
	if (!access_ok(buf, len))
		res = -EFAULT;
	else
		res = do_mapping_read(filp->f_mapping, &filp->f_ra, filp, buf,
				      len, ppos);
	inode_unlock_shared(file_inode(filp));
	return res;
}

static __always_inline size_t memcpy_to_nvmm(char *kmem, loff_t offset,
					     const char __user *buf,
					     size_t bytes)
{
	size_t copied;

	if (support_clwb && !force_nocache_write) {
		copied = bytes - __copy_from_user(kmem + offset, buf, bytes);
		eufs_flush_buffer(kmem + offset, copied, 0);
	} else {
		copied = bytes - __copy_from_user_inatomic_nocache(
					 kmem + offset, buf, bytes);
	}

	return copied;
}

ssize_t __eufs_file_write_inode(struct inode *inode, const char __user *buf,
				size_t count, loff_t pos, loff_t *ppos,
				bool zero, bool keep)
{
	long status = 0;
	size_t bytes;
	ssize_t written = 0;

	if (!count)
		return 0;

	eufs_dbg("file write: inode=%px count=%lx pos=%llx, zero=%d keep=%d\n",
		 inode, count, pos, zero, keep);

	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		__le64 *parent;
		void __pmem *xmem;
		void __pmem *xmem_new = NULL;

		offset = (pos & (PAGE_SIZE - 1)); /* Within page */
		index = pos >> PAGE_SHIFT;
		bytes = PAGE_SIZE - offset;
		if (bytes > count)
			bytes = count;

		xmem = eufs_find_data_block_btree(inode, index, &parent);
		if (!eufs_access_ok(inode->i_sb, xmem, PAGE_SIZE)) {
			dump_stack();
			BUG();
		}

		/* do no wear leveling for 0-level btrees */
		if (xmem != NULL_ADDR_PTR && parent && !zero) {
			/* wear threshold! */
			if (!wear_inc(inode->i_sb, xmem))
				xmem_new = eufs_malloc_file_data(inode->i_sb);
		}
		if (zero) {
			copied = bytes;
			if (xmem != NULL_ADDR_PTR)
				eufs_clear_pmem((char *)xmem + offset, bytes);
		} else {
			BUG_ON(xmem == NULL_ADDR_PTR);
			copied = memcpy_to_nvmm((char *)xmem, offset, buf,
						bytes);
		}

		if (xmem_new) {
			struct eufs_inode_info *vi = EUFS_I(inode);

			eufs_dbg(
				"inode=%px pos=%llx xmem:[%px -> %px] weared\n",
				inode, pos, xmem, xmem_new);
			eufs_alloc_persist(inode->i_sb, xmem_new, true);

			WARN_ON(xmem !=
				s2p(inode->i_sb,
				    parent[index % EUFS_FILE_TREE_DEGREE]));

			/*
			 * disable page fault, clear all related PTEs, and remove the
			 * dax entry from the radix tree before replace the old block
			 */
			down_write(&vi->mmap_rwsem);
			invalidate_inode_pages2_range(inode->i_mapping,
						      pos / PAGE_SIZE,
						      pos / PAGE_SIZE);
			memcpy_to_nvmm(xmem_new, 0, xmem, PAGE_SIZE);
			parent[index % EUFS_FILE_TREE_DEGREE] =
				p2s(inode->i_sb, xmem_new);
			up_write(&vi->mmap_rwsem);

			eufs_flush_cacheline(
				&parent[index % EUFS_FILE_TREE_DEGREE]);
			eufs_pbarrier();

			/*
			 * It is important to persist all preivous alllocations
			 * here. Otherwise, the xmem might be freed before its
			 * information is handled in the page_batch, which will
			 * cause xmem being marked as allocated (page_batch does
			 * this) when it is in the free list.
			 * xfstests/generic/299 can trigger this.
			 */
			eufs_alloc_batch_persist_reset(
				inode->i_sb, &EUFS_I(inode)->page_batch);
			nv_free_rest(inode->i_sb, xmem);
		}

		eufs_dbg(
			"! file writing to pos=%ld xmem=%px, offset=%ld, buf=%px, bytes=%ld index=%ld, copied=%ld\n",
			(long)pos, xmem, (long)offset, buf, (long)bytes,
			(long)index, (long)copied);

		if (likely(copied > 0)) {
			written += copied;
			count -= copied;
			pos += copied;
			buf += copied;
		}

		if (unlikely(copied != bytes)) {
			status = -EFAULT;
			break;
		}
	} while (count);
	if (ppos)
		*ppos = pos;
	eufs_dbg("pos: %d inode->i_size: %d written: %d\n", (int)pos,
		 (int)inode->i_size, (int)written);
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_mutex.
	 */
	if (!keep && pos > inode->i_size)
		eufs_inode_size_write(inode, pos);

	return written ? written : status;
}

ssize_t __eufs_file_write(struct address_space *mapping,
			      const char __user *buf, size_t count, loff_t pos,
			      loff_t *ppos, bool zero, bool keep)
{
	return __eufs_file_write_inode(mapping->host, buf, count, pos, ppos,
				       zero, keep);
}

ssize_t eufs_file_write(struct file *filp, const char __user *buf,
			size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct super_block *sb = inode->i_sb;
	ssize_t written = 0;
	loff_t pos;
	size_t count, ret;
	bool osync = false;

	inode_lock(inode);

	if (!access_ok(buf, len)) {
		ret = -EFAULT;
		goto out;
	}

	if (filp->f_flags & O_APPEND)
		pos = inode->i_size;
	else
		pos = *ppos;

	if (filp->f_flags & __O_SYNC)
		osync = true;

	count = len;
	if (count == 0) {
		ret = 0;
		goto out;
	}

	NV_ASSERT(sb->s_blocksize == PAGE_SIZE);

	ret = file_remove_privs(filp);
	if (ret)
		goto out;

	inode->i_ctime = inode->i_mtime = current_time(inode);

	/*
	 * It's a little tricky here. We should use mmap_rwsem to protect
	 * the block allocation and i_size update, but mmap_rwsem can not
	 * be taken during block writing because that will lead to
	 * dead-lock. We only use mmap_rwsem to protect the block allocation,
	 * and there are two reasons we can do that:
	 * 1. mmap fault takes the mmap_rwsem before read i_size, so it
	 * can not read the updated i_size before the allocation is done.
	 * 2. write only extends the block tree, and will not remove or
	 * modify the existed block mappings.
	 */
	down_write(&vi->mmap_rwsem);
	/*
	 * Possible cases for writing [pos~pos+len)
	 *
	 * Definitions
	 * EOF: the byte after last valid byte
	 * EOF-page: page contains EOF
	 * first: the page pos belongs to
	 * last: the page pos+len belongs to
	 * Macro EOP(p): the last byte of p's page
	 *
	 * IMPORTANT NOTICE: we do not guarantee that [EOF~EOP(EOF)] are
	 * zeroed! When we mmap a file, we will erase that (in DRAM) in the
	 * mmap syscall. This can concurrently happen with a write syscall
	 * which may cause consistency problems (especially when it's an
	 * append). Concurrent mmap-access and read-/write-access should be
	 * protected by the application.
	 *
	 * 1) EOF-page | first | last
	 *   area-to-zero: [EOF~EOP(EOF)]
	 * 2) EOF-page=first| last
	 *   area-to-zero: [EOF~pos) if EOF<pos
	 * 3) first | EOF-page | last
	 *   area-to-zero: none
	 * 4) first | EOF-page=last
	 *   area-to-zero: none
	 * 5) first | last | EOF-page
	 *   area-to-zero:
	 * And for ALL cases, if first/last page is a hole, we need to zero
	 * the part that will not be written in this write.
	 */

	/* don't zero-out the allocated blocks */
	ret = eufs_alloc_blocks_btree_for_write(inode, pos, count);
	if (IS_ERR_VALUE(ret)) {
		up_write(&vi->mmap_rwsem);
		goto out;
	}

	/* If we decide to guarantee zeroed file tail, we may use this snippet. */
	/* zeroing part of the last block goes beyond the new EOF */
	if (PAGE_ALIGN(pos + count) > PAGE_ALIGN(inode->i_size))
		eufs_inode_zero_range(inode, pos + count,
				      PAGE_ALIGN(pos + count));

	/*
	 * zeroing the hole created by write.
	 * part of the hole is included in the last page that exceeds EOF,
	 * and it has already been zeroed, so only zeroing the remaining part.
	 */
	if (pos > inode->i_size) {
		loff_t offset = inode->i_size & (PAGE_SIZE - 1);

		if (offset || !inode->i_size) {
			/*
			 * Zero EOF~EOP(EOF).
			 * This also satisfies case 2), since [EOP(EOF)+1~pos]
			 * are holes.
			 */
			eufs_inode_zero_range_len(inode, inode->i_size,
						  PAGE_SIZE - offset);
		}
	}
	up_write(&vi->mmap_rwsem);

	written = __eufs_file_write(mapping, buf, count, pos, ppos, false,
				    false);
	if (written < 0 || written != count) {
		eufs_dbg("write incomplete/failed: written %ld len %ld pos %llx\n",
			 written, count, pos);
	}
	if (osync) {
		eufs_alloc_batch_persist_reset(sb, &EUFS_I(inode)->page_batch);
		eufs_sync_pinode(inode, EUFS_PI(inode), false);
	} else {
		request_persistence(inode);
	}

	ret = written;

out:
	inode_unlock(inode);
	return ret;
}

static int eufs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
			    unsigned int flags, struct iomap *iomap,
			    struct iomap *src)
{
	struct super_block *sb = inode->i_sb;
	struct eufs_sb_info *sbi = sb->s_fs_info;
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	bool new = false;
	void *__pmem xmem;
	__le64 *__pmem parent;

	eufs_dbg("fault: inode=%px addr=0x%llx rw=%d length=%lld\n", inode,
		 offset, flags & IOMAP_WRITE, length);
	inode_leaf_lock(inode);
	xmem = eufs_find_data_block_btree(inode, first_block, &parent);
	/* allocate a new block for write */
	if (xmem == NULL_ADDR_PTR && (flags & IOMAP_WRITE)) {
		int ofs = first_block & (EUFS_FILE_TREE_DEGREE - 1);

		/*
		 * We cannot use normal allocation here because they can send
		 * IPI to gather pages and blocks. So here we need to use
		 * non-blocking version, which uses reserved pages instead of
		 * gathering pages by IPI.
		 */
		xmem = eufs_zalloc_file_data(inode->i_sb);
		if (!xmem) {
			inode_leaf_unlock(inode);
			return -ENOSPC;
		}

		eufs_alloc_persist(inode->i_sb, xmem, false);
		/*
		 * the first block is preallocated during inode initialization,
		 * so parent should not be NULL when xmem is NULL_ADDR
		 */
		BUG_ON(!parent);
		eufs_flush_page(xmem);
		parent[ofs] = p2s(sb, xmem);
		eufs_flush_cacheline(&parent[ofs]);

		new = true;
	}
	inode_leaf_unlock(inode);

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = (u64)first_block << blkbits;
	iomap->dax_dev = sbi->s_dax_dev;
	iomap->length = 1 << blkbits;

	if (xmem == NULL_ADDR_PTR) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->addr = (xmem - sbi->virt_addr);
	}

	if (new)
		iomap->flags |= IOMAP_F_NEW;

	return 0;
}

static int eufs_iomap_end(struct inode *inode, loff_t offset, loff_t length,
			  ssize_t written, unsigned int flags,
			  struct iomap *iomap)
{
	return 0;
}

const struct iomap_ops eufs_iomap_ops = {
	.iomap_begin = eufs_iomap_begin,
	.iomap_end = eufs_iomap_end,
};

static unsigned int eufs_dax_fault(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct eufs_inode_info *vi = EUFS_I(inode);
	int ret;

	if (vmf->flags & FAULT_FLAG_WRITE) {
		sb_start_pagefault(inode->i_sb);
		file_update_time(vmf->vma->vm_file);
	}

	/*
	 * i_size and the block tree must be consistent during mmap fault,
	 * else eulerfs may map to a freed block or a hole instead of an
	 * allocated block.
	 *
	 * Now i_rwsem is used to protect against the update of i_size and
	 * the block tree, but it can NOT been used in mmap fault path,
	 * because mmap fault may be triggered in the middle of
	 * write or read operation when the dst or src buffer is a mapped
	 * range of the same file, and that will lead to dead-lock due to
	 * two acquisitions of the same lock (i_rwsem).
	 *
	 * So mmap_rwsem is provided. The read-lock will be used in mmap
	 * fault path, and the write-lock will be used in truncate &
	 * fallocate & write paths.
	 */
	down_read(&vi->mmap_rwsem);
	ret = dax_iomap_fault(vmf, PE_SIZE_PTE, NULL, &ret, &eufs_iomap_ops);
	up_read(&vi->mmap_rwsem);

	if (vmf->flags & FAULT_FLAG_WRITE)
		sb_end_pagefault(inode->i_sb);

	return ret;
}

const struct vm_operations_struct eufs_file_vm_ops = {
	.fault = eufs_dax_fault,
	.page_mkwrite = eufs_dax_fault,
	.pfn_mkwrite = eufs_dax_fault,
};

int eufs_dax_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_flags |= VM_MIXEDMAP;
	vma->vm_ops = &eufs_file_vm_ops;
	eufs_dbg("dax file mmaped!\n");
	return 0;
}

static loff_t eufs_seek_block(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t maxbytes = inode->i_sb->s_maxbytes;
	pgoff_t pgofs;
	loff_t data_ofs = offset, isize;
	__le64 *parent;
	void *addr;
	unsigned int ofs;

	inode_lock(inode);

	isize = i_size_read(inode);

	if (offset >= isize)
		goto fail;

	pgofs = (pgoff_t)(offset >> PAGE_SHIFT);

	if (EUFS_I(inode)->hole_at_sta && pgofs == 0) {
		if (whence == SEEK_HOLE)
			goto found;
		pgofs++;
		data_ofs = (loff_t)pgofs << PAGE_SHIFT;
	}

	while (data_ofs < isize) {
		addr = eufs_find_data_block_btree(inode, pgofs, &parent);
		ofs = pgofs & (EUFS_FILE_TREE_DEGREE - 1);
		while (ofs < EUFS_FILE_TREE_DEGREE && data_ofs < isize) {
			if (parent)
				addr = s2p(inode->i_sb, parent[ofs]);
			if (addr == NULL_ADDR_PTR && whence == SEEK_HOLE)
				goto found;
			if (addr && addr != NULL_ADDR_PTR &&
			    whence == SEEK_DATA)
				goto found;
			ofs++;
			pgofs++;
			data_ofs = (loff_t)pgofs << PAGE_SHIFT;
		}
	}
	if (whence == SEEK_DATA)
		goto fail;
found:
	if (whence == SEEK_HOLE && data_ofs > isize)
		data_ofs = isize;
	inode_unlock(inode);
	return vfs_setpos(file, data_ofs, maxbytes);
fail:
	inode_unlock(inode);
	return -ENXIO;
}

loff_t eufs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
	case SEEK_END:
		return generic_file_llseek_size(file, offset, whence, maxbytes,
						i_size_read(inode));
	case SEEK_DATA:
	case SEEK_HOLE:
		if (offset < 0)
			return -ENXIO;
		return eufs_seek_block(file, offset, whence);
	}
	return -EINVAL;
}
