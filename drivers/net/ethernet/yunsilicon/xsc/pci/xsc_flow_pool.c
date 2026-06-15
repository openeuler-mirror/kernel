// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_flow_pool.h"
#include "xsc_flow_tbl.h"
#include "xsc_flow.h"

static struct xsc_flow_pool_block *xsc_flow_pool_block_alloc(struct xsc_core_device *dev)
{
	struct xsc_flow_pool_block *block = NULL;
	u16 entry_idx;

	block = kzalloc(sizeof(*block), GFP_KERNEL);
	if (!block)
		return NULL;

	block->bitmap = kcalloc(BITS_TO_LONGS(XSC_FLOW_POOL_BLOCK_SIZE),
				sizeof(unsigned long), GFP_KERNEL);
	if (!block->bitmap)
		goto error;

	block->entry_array = kcalloc(XSC_FLOW_POOL_BLOCK_SIZE,
				     sizeof(struct xsc_flow_pool_entry),
				     GFP_KERNEL);
	if (!block->entry_array)
		goto error;

	for (entry_idx = 0; entry_idx < XSC_FLOW_POOL_BLOCK_SIZE; entry_idx++)
		spin_lock_init(&block->entry_array[entry_idx].lock);

	spin_lock_init(&block->lock);

	return block;
error:
	kfree(block->bitmap);
	kfree(block->entry_array);
	kfree(block);
	return NULL;
}

struct xsc_flow_pool *xsc_flow_pool_alloc(struct xsc_core_device *dev)
{
	struct xsc_flow_pool *pool = NULL;
	u16 block_idx;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;

	pool->blocks[0] = xsc_flow_pool_block_alloc(dev);
	for (block_idx = 1; block_idx < XSC_FLOW_POOL_BLOCK_NUM; block_idx++)
		pool->blocks[block_idx] = NULL;

	return pool;
}

void xsc_flow_pool_free(struct xsc_flow_pool *pool)
{
	struct xsc_flow_pool_block *block = NULL;
	u16 block_idx;
	u32 entry_idx;

	if (!pool)
		return;

	for (block_idx = 0; block_idx < XSC_FLOW_POOL_BLOCK_NUM; block_idx++) {
		block = pool->blocks[block_idx];
		if (!block)
			continue;

		for (entry_idx = 0; entry_idx < XSC_FLOW_GRP_POOL_BLOCK_SIZE; entry_idx++)
			kfree(block->entry_array[entry_idx].hw_flow);
		kfree(block->entry_array);
		kfree(block->bitmap);
		kfree(block);
	}
}

int xsc_flow_alloc_idx(struct xsc_core_device *dev,
		       struct xsc_flow_pool *pool,
		       struct xsc_hw_flow *flow, u32 *flow_idx)
{
	struct xsc_flow_pool_block *block = NULL;
	unsigned long flags;
	u32 offset;
	u16 blk_idx;

	if (!pool) {
		xsc_core_err(dev, "flow pool is null");
		return -EINVAL;
	}

	for (blk_idx = 0; blk_idx < XSC_FLOW_POOL_BLOCK_NUM; blk_idx++) {
		if (!pool->blocks[blk_idx])
			pool->blocks[blk_idx] = xsc_flow_pool_block_alloc(dev);
		block = pool->blocks[blk_idx];

		if (!block)
			return -ENOMEM;

		spin_lock_irqsave(&block->lock, flags);
		offset = find_first_zero_bit(block->bitmap, XSC_FLOW_POOL_BLOCK_SIZE);
		if (offset >= XSC_FLOW_POOL_BLOCK_SIZE) {
			spin_unlock_irqrestore(&block->lock, flags);
			continue;
		}

		set_bit(offset, block->bitmap);
		block->entry_array[offset].hw_flow = flow;
		spin_unlock_irqrestore(&block->lock, flags);

		*flow_idx = blk_idx * XSC_FLOW_POOL_BLOCK_SIZE + offset;

		return 0;
	}

	return -ENOMEM;
}

struct xsc_hw_flow *xsc_flow_free_idx(struct xsc_core_device *dev,
				      struct xsc_flow_pool *pool, u32 flow_id)
{
	struct xsc_flow_pool_block *block = NULL;
	struct xsc_hw_flow *hw_flow = NULL;
	u16 blk_idx = flow_id / XSC_FLOW_POOL_BLOCK_SIZE;
	u32 offset = flow_id % XSC_FLOW_POOL_BLOCK_SIZE;
	unsigned long flags;

	if (!pool) {
		xsc_core_err(dev, "flow pool is null");
		return NULL;
	}

	if (blk_idx >= XSC_FLOW_POOL_BLOCK_NUM) {
		xsc_core_err(dev, "invalid flow id %d", flow_id);
		return NULL;
	}

	block = pool->blocks[blk_idx];
	if (!block) {
		xsc_core_err(dev, "block is null, flow_id:%d, block_id:%d", flow_id, blk_idx);
		return NULL;
	}

	spin_lock_irqsave(&block->lock, flags);
	clear_bit(offset, block->bitmap);
	spin_unlock_irqrestore(&block->lock, flags);

	spin_lock_irqsave(&block->entry_array[offset].lock, flags);
	hw_flow = block->entry_array[offset].hw_flow;
	block->entry_array[offset].hw_flow = NULL;
	spin_unlock_irqrestore(&block->entry_array[offset].lock, flags);

	return hw_flow;
}

static struct xsc_flow_grp_pool_block *xsc_flow_grp_pool_block_alloc(struct xsc_core_device *dev)
{
	struct xsc_flow_grp_pool_block *block = NULL;

	block = kzalloc(sizeof(*block), GFP_KERNEL);
	if (!block)
		return NULL;

	block->bitmap = kcalloc(BITS_TO_LONGS(XSC_FLOW_GRP_POOL_BLOCK_SIZE),
				sizeof(unsigned long), GFP_KERNEL);
	if (!block->bitmap)
		goto error;

	block->entry_array = kcalloc(XSC_FLOW_GRP_POOL_BLOCK_SIZE,
				     sizeof(struct xsc_flow_grp_pool_entry),
				     GFP_KERNEL);
	if (!block->entry_array)
		goto error;

	spin_lock_init(&block->lock);

	return block;
error:
	kfree(block->bitmap);
	kfree(block->entry_array);
	kfree(block);
	return NULL;
}

struct xsc_flow_grp_pool *xsc_flow_grp_pool_alloc(struct xsc_core_device *dev)
{
	struct xsc_flow_grp_pool *pool;
	u16 block_idx;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;

	pool->blocks[0] = xsc_flow_grp_pool_block_alloc(dev);
	for (block_idx = 1; block_idx < XSC_FLOW_GRP_POOL_BLOCK_NUM; block_idx++)
		pool->blocks[block_idx] = NULL;

	return pool;
}

void xsc_flow_grp_pool_free(struct xsc_flow_grp_pool *pool)
{
	struct xsc_flow_grp_pool_block *block = NULL;
	u16 block_idx;
	u32 entry_idx;

	if (!pool)
		return;

	for (block_idx = 0; block_idx < XSC_FLOW_GRP_POOL_BLOCK_NUM; block_idx++) {
		block = pool->blocks[block_idx];
		if (!block)
			continue;

		kfree(block->bitmap);
		for (entry_idx = 0; entry_idx < XSC_FLOW_GRP_POOL_BLOCK_SIZE; entry_idx++)
			kfree(block->entry_array[entry_idx].grp);
		kfree(block->entry_array);
		kfree(block);
	}
}

int xsc_flow_grp_alloc_idx(struct xsc_core_device *dev,
			   struct xsc_flow_grp_pool *pool,
			   struct xsc_ifc_flow_group *grp)
{
	struct xsc_flow_grp_pool_block *block = NULL;
	unsigned long flags;
	u32 offset;
	u16 blk_idx;

	if (!pool) {
		xsc_core_err(dev, "flow group pool is null");
		return -EINVAL;
	}

	if (grp->is_reserved) {
		if (!pool->blocks[0])
			pool->blocks[0] = xsc_flow_grp_pool_block_alloc(dev);

		block = pool->blocks[0];
		if (!block) {
			xsc_core_err(dev, "failed to alloc mem for group pool");
			return -ENOMEM;
		}

		offset = grp->grp_id;
		spin_lock_irqsave(&block->lock, flags);
		set_bit(offset, block->bitmap);
		block->entry_array[offset].grp = grp;
		spin_unlock_irqrestore(&block->lock, flags);

		return 0;
	}

	for (blk_idx = 0; blk_idx < XSC_FLOW_GRP_POOL_BLOCK_NUM; blk_idx++) {
		if (!pool->blocks[blk_idx])
			pool->blocks[blk_idx] = xsc_flow_grp_pool_block_alloc(dev);
		block = pool->blocks[blk_idx];

		if (!block) {
			xsc_core_err(dev, "failed to alloc mem for group pool, blk_idx: %d",
				     blk_idx);
			return -ENOMEM;
		}

		spin_lock_irqsave(&block->lock, flags);
		if (blk_idx == 0)
			offset = find_next_zero_bit(block->bitmap, XSC_FLOW_GRP_POOL_BLOCK_SIZE,
						    FLOW_GRP_RESV_MAX);
		else
			offset = find_first_zero_bit(block->bitmap, XSC_FLOW_GRP_POOL_BLOCK_SIZE);
		if (offset >= XSC_FLOW_GRP_POOL_BLOCK_SIZE) {
			spin_unlock_irqrestore(&block->lock, flags);
			continue;
		}

		set_bit(offset, block->bitmap);
		block->entry_array[offset].grp = grp;
		spin_unlock_irqrestore(&block->lock, flags);

		grp->grp_id = blk_idx * XSC_FLOW_GRP_POOL_BLOCK_SIZE + offset;

		return 0;
	}

	return -ENOMEM;
}

void xsc_flow_grp_free_idx(struct xsc_core_device *dev,
			   struct xsc_flow_grp_pool *pool, u32 grp_id)
{
	struct xsc_flow_grp_pool_block *block = NULL;
	u16 blk_idx = grp_id / XSC_FLOW_POOL_BLOCK_SIZE;
	u32 offset = grp_id % XSC_FLOW_POOL_BLOCK_SIZE;
	unsigned long flags;

	if (!pool) {
		xsc_core_err(dev, "flow group pool is null");
		return;
	}

	if (blk_idx >= XSC_FLOW_GRP_POOL_BLOCK_NUM) {
		xsc_core_err(dev, "invlaid grp id %d", grp_id);
		return;
	}

	block = pool->blocks[blk_idx];

	spin_lock_irqsave(&block->lock, flags);
	clear_bit(offset, block->bitmap);
	kfree(block->entry_array[offset].grp);
	block->entry_array[offset].grp = NULL;
	spin_unlock_irqrestore(&block->lock, flags);
}

struct xsc_ifc_flow_group *xsc_flow_grp_find_with_idx(struct xsc_core_device *dev,
						      struct xsc_flow_grp_pool *pool,
						      u32 grp_id)
{
	struct xsc_flow_grp_pool_block *block = NULL;
	struct xsc_ifc_flow_group *grp = NULL;
	u16 blk_idx = grp_id / XSC_FLOW_POOL_BLOCK_SIZE;
	u32 offset = grp_id % XSC_FLOW_POOL_BLOCK_SIZE;
	unsigned long flags;

	if (!pool) {
		xsc_core_err(dev, "flow group pool is null");
		return NULL;
	}

	if (blk_idx >= XSC_FLOW_GRP_POOL_BLOCK_NUM) {
		xsc_core_err(dev, "invlaid grp id %d", grp_id);
		return NULL;
	}

	block = pool->blocks[blk_idx];

	spin_lock_irqsave(&block->lock, flags);
	if (test_bit(offset, block->bitmap))
		grp = block->entry_array[offset].grp;
	else
		xsc_core_err(dev, "grp id %d is not alloced", grp_id);
	spin_unlock_irqrestore(&block->lock, flags);

	return grp;
}
