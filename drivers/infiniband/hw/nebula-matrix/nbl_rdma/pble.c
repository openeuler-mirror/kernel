// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/kernel.h>
#include <linux/types.h>
#include <rdma/ib_umem.h>

#include "debug.h"
#include "pble.h"

static int nbl_init_pble_chunk(struct nbl_chunk *chunk, u32 pble_cnt)
{
	u32 bitmap_mem_size = pble_cnt >> BYTE_SIZE_SHIFT;

	chunk->bitmap_buf = kzalloc(bitmap_mem_size, GFP_ATOMIC);
	if (!chunk->bitmap_buf)
		return -ENOMEM;

	chunk->sizeof_bitmap = pble_cnt;

	return 0;
}

static struct nbl_chunk *
nbl_add_one_pble_chunk(struct nbl_hmc_obj_sd_info *pbl_sd_info,
		       struct nbl_hmc_pble_rsrc *pble_rsrc, int order, u32 idx)
{
	struct nbl_chunk *chunk = NULL;
	struct nbl_hmc_obj_sd_addr sd_addr;
	u32 total_pble_per_chunk = pble_rsrc->pinfo[order].pble_cnt_per_chunk;
	u32 chunk_size;
	int ret;

	if (unlikely(idx >= pble_rsrc->max_index)) {
		nbl_ib_err(pble_rsrc->sc_dev,
			   "invalid pd idx[%u], max_index[%llu]\n", idx,
			   pble_rsrc->max_index);
		return ERR_PTR(-EINVAL);
	}

	chunk_size = sizeof(*chunk);
	chunk = kzalloc(chunk_size, GFP_ATOMIC);
	if (!chunk)
		return ERR_PTR(-ENOMEM);

	chunk->sc_dev = pble_rsrc->sc_dev;
	sd_addr = pbl_sd_info->sd_addr[idx];
	ret = nbl_init_pble_chunk(chunk, total_pble_per_chunk);
	if (ret) {
		nbl_ib_err(pble_rsrc->sc_dev,
			   "init pble chunk failed, pd_idx[%u]\n", idx);
		goto error;
	}
	chunk->va = sd_addr.va;
	chunk->base_addr = sd_addr.dma_addr;
	chunk->base_idx = pble_rsrc->base_idx + idx * total_pble_per_chunk;
	chunk->pd_idx = idx;
	chunk->is_used = 0;
	list_add_tail(&chunk->list, &pble_rsrc->pinfo[order].clist);

	return chunk;
error:
	kfree(chunk);
	return ERR_PTR(ret);
}

static int nbl_prm_get_pbles(struct nbl_pble_prm *pprm,
			     struct nbl_pble_chunkinfo *chunkinfo, u32 pble_cnt,
			     u64 **addr, u64 *pble_idx)
{
	struct nbl_chunk *pchunk = NULL;
	struct list_head *chunk_entry = pprm->clist.next;
	u64 bits_needed = pble_cnt;
	u64 bit_idx = NBL_INVALID_IDX;
	u32 offset;

	while (chunk_entry != &pprm->clist) {
		pchunk = list_entry(chunk_entry, struct nbl_chunk, list);
		bit_idx = bitmap_find_next_zero_area(pchunk->bitmap_buf,
						     pchunk->sizeof_bitmap, 0,
						     bits_needed, 0);
		if (bit_idx < pchunk->sizeof_bitmap)
			break;

		/* check the nest list_head node */
		chunk_entry = pchunk->list.next;
	}

	if (!pchunk || (bit_idx >= pchunk->sizeof_bitmap))
		return -ENOMEM;

	bitmap_set(pchunk->bitmap_buf, bit_idx, bits_needed);
	offset = bit_idx << BYTE_SIZE_SHIFT;
	*addr = pchunk->va + offset;
	pchunk->is_used++;
	*pble_idx = bit_idx + pchunk->base_idx;

	chunkinfo->pchunk = pchunk;
	chunkinfo->bit_idx = bit_idx;
	chunkinfo->bits_used = bits_needed;

	return 0;
}

static int nbl_chunk_get_pbles(struct nbl_chunk *pchunk,
			       struct nbl_pble_chunkinfo *chunkinfo,
			       u32 pble_cnt, u64 *pble_idx)
{
	u64 bit_idx = NBL_INVALID_IDX;

	/* find the start idx of bitmap */
	bit_idx = bitmap_find_next_zero_area(
		pchunk->bitmap_buf, pchunk->sizeof_bitmap, 0, pble_cnt, 0);

	if (bit_idx >= pchunk->sizeof_bitmap) {
		nbl_pr_err("can not find available bit_idx.\n");
		return -ENOMEM;
	}

	bitmap_set(pchunk->bitmap_buf, bit_idx, pble_cnt);
	pchunk->is_used++;

	*pble_idx = bit_idx + pchunk->base_idx;

	chunkinfo->pchunk = pchunk;
	chunkinfo->bit_idx = bit_idx;
	chunkinfo->bits_used = pble_cnt;

	return 0;
}

static int nbl_get_pble_by_order(struct nbl_hmc_pble_rsrc *pble_rsrc,
				 struct nbl_pble_alloc *palloc, int order)
{
	int ret;
	u64 pble_idx;
	struct nbl_pble_info *pble_info = &palloc->pble_info;

	ret = nbl_prm_get_pbles(&pble_rsrc->pinfo[order],
				&pble_info->first_chunk, palloc->needed_cnt,
				&pble_info->addr, &pble_idx);
	if (ret)
		return -ENOMEM;
	pble_info->idx = (u32)(pble_idx - pble_rsrc->base_idx);
	pble_info->cnt = palloc->needed_cnt;
	pble_info->is_single = true;
	pble_info->order = order;

	return 0;
}

static void nbl_rel_chunk_and_pble_for_err(struct nbl_chunk *first_chunk,
					   struct nbl_chunk *last_chunk)
{
	struct list_head *chunk_entry = NULL;
	struct list_head *last_entry = last_chunk->list.next;
	struct nbl_chunk *chunk = NULL;

	if (!first_chunk)
		return;

	chunk_entry = &first_chunk->list;
	while (chunk_entry != last_entry) {
		chunk = list_entry(chunk_entry, struct nbl_chunk, list);
		chunk_entry = chunk->list.next;
		list_del(&chunk->list);

		kfree(chunk->bitmap_buf);
		kfree(chunk);
	}
}

static int nbl_get_pble_by_allocate_sd(struct nbl_pci_f *rf,
				       struct nbl_pble_alloc *palloc,
				       int chunk_num, int order)
{
	struct nbl_hmc_pble_rsrc *pble_rsrc = rf->pble_rsrc;
	struct nbl_hmc_obj_sd_info *pbl_sd_info = rf->pbl_sd_info;
	struct nbl_chunk *allocated_chunk = NULL;
	struct nbl_pble_info *pble_info = &palloc->pble_info;
	struct nbl_pble_chunkinfo chunkinfo;
	struct nbl_chunk *first_chunk = NULL;
	struct nbl_chunk *last_chunk = NULL;
	struct nbl_chunk *chunk = NULL;
	struct list_head *chunk_entry = NULL;
	u64 pble_idx = 0;
	u32 total_pble_cnt = palloc->needed_cnt;
	u32 tmp_pble_cnt = 0;
	u32 allocate_pble_cnt = 0;
	u32 pble_cnt_per_chunk = pble_rsrc->pinfo[order].pble_cnt_per_chunk;
	u64 bit_idx = NBL_INVALID_IDX;
	u64 pd_bmap_size, bits_needed;
	int pd_idx, cnt, ret;

	/* get pd rsrc */
	pd_bmap_size = pble_rsrc->pd_bmap_size;
	bits_needed = chunk_num;
	bit_idx = bitmap_find_next_zero_area(pble_rsrc->pd_bmap, pd_bmap_size,
					     0, bits_needed, 0);
	if (unlikely(bit_idx >= pd_bmap_size)) {
		nbl_ib_err(pble_rsrc->sc_dev, "alloc rsrc failed!\n");
		ret = -ENODATA;
		goto pd_rsrc_err;
	}

	/* create chunk and add it to clist */
	for (pd_idx = bit_idx; pd_idx < bit_idx + bits_needed; pd_idx++) {
		/* add one chunk to chunk list */
		allocated_chunk = nbl_add_one_pble_chunk(pbl_sd_info, pble_rsrc,
							 order, pd_idx);
		if (IS_ERR(allocated_chunk)) {
			nbl_ib_err(pble_rsrc->sc_dev,
				   "add one pble chunk failed!\n");
			ret = PTR_ERR(allocated_chunk);
			goto chunk_err;
		}
		bitmap_set(pble_rsrc->pd_bmap, pd_idx, 1);
		if (pd_idx == bit_idx)
			first_chunk = allocated_chunk;
		last_chunk = allocated_chunk;
	}

	/* pble cnt rsrc update */
	pble_rsrc->total_pble_cnt += pble_cnt_per_chunk * chunk_num;
	pble_rsrc->free_pble_cnt += pble_cnt_per_chunk * chunk_num;
	pble_rsrc->free_pd_cnt -= chunk_num;

	/* allocate pble */
	chunk_entry = &first_chunk->list;
	for (cnt = 0; cnt < chunk_num; cnt++) {
		if (unlikely(chunk_entry == last_chunk->list.next)) {
			nbl_ib_err(pble_rsrc->sc_dev,
				   "the free pbles is not enough.\n");
			ret = -ENOMEM;
			goto chunk_err;
		}

		tmp_pble_cnt = total_pble_cnt - pble_cnt_per_chunk * cnt;
		if (tmp_pble_cnt >= pble_cnt_per_chunk)
			allocate_pble_cnt = pble_cnt_per_chunk;
		else
			allocate_pble_cnt = tmp_pble_cnt;

		chunk = list_entry(chunk_entry, struct nbl_chunk, list);
		ret = nbl_chunk_get_pbles(chunk, &chunkinfo, allocate_pble_cnt,
					  &pble_idx);
		if (ret) {
			nbl_ib_err(
				pble_rsrc->sc_dev,
				"get pbles for multiple chunk failed, the value of i is %d.\n",
				cnt);
			goto chunk_err;
		}

		if (cnt == 0) {
			pble_info->first_chunk.pchunk = chunkinfo.pchunk;
			pble_info->first_chunk.bit_idx = chunkinfo.bit_idx;
			pble_info->first_chunk.bits_used = chunkinfo.bits_used;
			pble_info->idx = (u32)(pble_idx - pble_rsrc->base_idx);
		}
		pble_info->last_chunk.pchunk = chunkinfo.pchunk;
		pble_info->last_chunk.bit_idx = chunkinfo.bit_idx;
		pble_info->last_chunk.bits_used = chunkinfo.bits_used;

		chunk_entry = chunk->list.next;
	}

	pble_info->cnt = total_pble_cnt;
	pble_info->addr = pble_info->first_chunk.pchunk->va;
	if (chunk_num == 1)
		pble_info->is_single = true;
	else
		pble_info->is_single = false;
	pble_info->order = order;
	pble_info->allocated_chunk_num = chunk_num;

	return 0;

chunk_err:
	/* release chunk rsrc */
	nbl_rel_chunk_and_pble_for_err(first_chunk, last_chunk);
	pble_info->first_chunk.pchunk = NULL;
	pble_info->last_chunk.pchunk = NULL;

	/* clear pd_rsrc bitmap */
	bitmap_clear(pble_rsrc->pd_bmap, bit_idx, bits_needed);
pd_rsrc_err:
	return ret;
}

static int nbl_get_pble_by_single_chunk(struct nbl_pci_f *rf,
					struct nbl_pble_alloc *palloc)
{
	struct nbl_hmc_pble_rsrc *pble_rsrc = rf->pble_rsrc;
	u32 pble_cnt = palloc->needed_cnt;
	u32 tmp_pble_cnt;
	int order, i, chunk_num;
	int ret = 0;
	unsigned long flags;

	/* make sure tmp_pble_cnt is power of 2 */
	tmp_pble_cnt = roundup_pow_of_two(pble_cnt);

	/* get the order */
	order = ilog2(tmp_pble_cnt);
	/* order maybe too big, we must protect it */
	if (order > (NBL_PBLE_MAX_ORDER - 1))
		order = (NBL_PBLE_MAX_ORDER - 1);

	/*
	 * (1).get the pble by order;
	 * (2).if failed, allocate a new sd/pd and add it to chunk_list of order,
	 *     then get pble in this chunk;
	 * (3).if has not enough free sd/pd, then get pble from order + 1 to
	 *     NBL_PBLE_MAX_ORDER;
	 */
	spin_lock_irqsave(&pble_rsrc->pinfo[order].prm_lock, flags);
	ret = nbl_get_pble_by_order(pble_rsrc, palloc, order);
	if (!ret)
		goto exit;

	/* calculate the need chunk number, in this place the value is one */
	chunk_num = NBL_SINGLE_CHUNK_PD_CNT;
	if (pble_rsrc->free_pd_cnt >= chunk_num) {
		ret = nbl_get_pble_by_allocate_sd(rf, palloc, chunk_num, order);
		if (ret)
			nbl_ib_err(pble_rsrc->sc_dev,
				   "get pble by allocating sd failed!\n");
	} else {
		for (i = order + 1; i < NBL_PBLE_MAX_ORDER; i++) {
			ret = nbl_get_pble_by_order(pble_rsrc, palloc, i);
			if (!ret)
				goto exit;
		}

		for (i = order - 1; i >= 0; i--) {
			ret = nbl_get_pble_by_order(pble_rsrc, palloc, i);
			if (!ret)
				goto exit;
		}
		nbl_ib_err(pble_rsrc->sc_dev,
			   "failed to get pble througth all order clist\n");
	}

exit:
	spin_unlock_irqrestore(&pble_rsrc->pinfo[order].prm_lock, flags);
	return ret;
}

static int nbl_get_pble_by_multi_chunk(struct nbl_pci_f *rf,
				       struct nbl_pble_alloc *palloc)
{
	struct nbl_hmc_pble_rsrc *pble_rsrc = rf->pble_rsrc;
	u32 pble_cnt_per_chunk = pble_rsrc->pinfo[0].pble_cnt_per_chunk;
	u32 pble_cnt = palloc->needed_cnt;
	int order, chunk_num;
	int ret = 0;
	unsigned long flags;

	chunk_num = DIV_ROUND_UP_ULL(pble_cnt, pble_cnt_per_chunk);

	if (chunk_num <= 0) {
		nbl_pr_err("invalid chunk_num, the value is zero.\n");
		return -EINVAL;
	}

	if (pble_rsrc->free_pd_cnt < chunk_num) {
		nbl_pr_err(
			"can not get enough pd to alloca pable, free_pd_cnt[%llu], need_pd_num[%d].\n",
			pble_rsrc->free_pd_cnt, chunk_num);
		return -ENODATA;
	}

	/* allocate chunk_num chunks by last order */
	order = NBL_PBLE_MAX_ORDER - 1;
	spin_lock_irqsave(&pble_rsrc->pinfo[order].prm_lock, flags);
	ret = nbl_get_pble_by_allocate_sd(rf, palloc, chunk_num, order);
	if (ret)
		nbl_ib_err(pble_rsrc->sc_dev,
			   "get pble by allocating sd failed!\n");

	spin_unlock_irqrestore(&pble_rsrc->pinfo[order].prm_lock, flags);
	return ret;
}

int nbl_get_pble(struct nbl_pci_f *rf, struct nbl_pble_alloc *palloc,
		 u32 pble_cnt)
{
	struct nbl_hmc_pble_rsrc *pble_rsrc = rf->pble_rsrc;
	u32 pble_cnt_per_chunk = pble_rsrc->pinfo[0].pble_cnt_per_chunk;
	u32 needed_pble_cnt = ALIGN(pble_cnt, PBLE_CNT_ALIGN_SIZE);
	int ret = 0;

	palloc->total_cnt = pble_cnt;
	palloc->needed_cnt = needed_pble_cnt;
	palloc->pble_info.pble_cnt_per_chunk = pble_cnt_per_chunk;
	palloc->pble_info.first_chunk.pchunk = NULL;
	palloc->pble_info.last_chunk.pchunk = NULL;

	mutex_lock(&pble_rsrc->pble_mutex_lock);

	if (needed_pble_cnt <= pble_cnt_per_chunk) {
		/* just needs one chunk */
		ret = nbl_get_pble_by_single_chunk(rf, palloc);
		if (ret)
			nbl_ib_err(
				pble_rsrc->sc_dev,
				"get pble by single chunk failed, needed_pble_cnt[%u]!\n",
				needed_pble_cnt);
	} else {
		/* needs multi chunks */
		ret = nbl_get_pble_by_multi_chunk(rf, palloc);
		if (ret) {
			nbl_ib_err(
				pble_rsrc->sc_dev,
				"get pble by multi chunk failed, needed_pble_cnt[%u]!\n",
				needed_pble_cnt);
		}
	}

	if (!ret) {
		pble_rsrc->free_pble_cnt -= needed_pble_cnt;
		pble_rsrc->allocated_pble_cnt += needed_pble_cnt;
		pble_rsrc->stats_alloc_ok++;
	} else {
		pble_rsrc->stats_alloc_failed++;
		nbl_ib_err(
			&rf->sc_dev,
			"[pble] the needed_pble_cnt[%u], total_pble_cnt[%llu], allocated_pble_cnt(%llu), free_pble_cnt(%llu), free_pd_cnt[%llu]\n",
			needed_pble_cnt, pble_rsrc->total_pble_cnt,
			pble_rsrc->allocated_pble_cnt, pble_rsrc->free_pble_cnt,
			pble_rsrc->free_pd_cnt);
	}
	mutex_unlock(&pble_rsrc->pble_mutex_lock);

	return ret;
}

static void nbl_free_one_chunk(struct nbl_hmc_pble_rsrc *pble_rsrc,
			       struct nbl_chunk *chunk)
{
	u32 bit_idx = chunk->pd_idx;

	bitmap_clear(pble_rsrc->pd_bmap, bit_idx, 1);
	list_del(&chunk->list);
	kfree(chunk->bitmap_buf);
	kfree(chunk);
}

static void nbl_free_pbles_by_single_chunk(struct nbl_hmc_pble_rsrc *pble_rsrc,
					   struct nbl_pble_info *pble_info)
{
	struct nbl_pble_chunkinfo *chunkinfo = NULL;
	unsigned long flags;
	int order = pble_info->order;

	if (pble_info->first_chunk.pchunk == NULL)
		return;

	chunkinfo = &pble_info->first_chunk;

	mutex_lock(&pble_rsrc->pble_mutex_lock);
	spin_lock_irqsave(&pble_rsrc->pinfo[order].prm_lock, flags);

	bitmap_clear(chunkinfo->pchunk->bitmap_buf, chunkinfo->bit_idx,
		     chunkinfo->bits_used);
	pble_rsrc->free_pble_cnt += chunkinfo->bits_used;
	pble_rsrc->allocated_pble_cnt -= chunkinfo->bits_used;

	if (--chunkinfo->pchunk->is_used <= 0) {
		chunkinfo->pchunk->is_used = 0;
		nbl_free_one_chunk(pble_rsrc, chunkinfo->pchunk);
		pble_rsrc->free_pd_cnt++;
		pble_rsrc->total_pble_cnt -= pble_info->pble_cnt_per_chunk;
		pble_rsrc->free_pble_cnt -= pble_info->pble_cnt_per_chunk;
	}
	spin_unlock_irqrestore(&pble_rsrc->pinfo[order].prm_lock, flags);
	mutex_unlock(&pble_rsrc->pble_mutex_lock);

	chunkinfo->pchunk = NULL;
	chunkinfo->bit_idx = 0;
	chunkinfo->bits_used = 0;
}

static void nbl_free_pbles_by_multi_chunk(struct nbl_hmc_pble_rsrc *pble_rsrc,
					  struct nbl_pble_info *pble_info)
{
	struct list_head *chunk_entry = NULL;
	struct list_head *first_entry = NULL;
	struct list_head *last_entry = NULL;
	struct nbl_chunk *chunk = NULL;
	struct nbl_pble_prm *pinfo = NULL;
	unsigned long flags;
	int order, chunk_num, cnt;
	u32 pble_cnt_per_chunk;

	if (pble_info->first_chunk.pchunk == NULL)
		return;

	chunk_entry = &pble_info->first_chunk.pchunk->list;
	first_entry = &pble_info->first_chunk.pchunk->list;
	last_entry = &pble_info->last_chunk.pchunk->list;

	order = pble_info->order;
	pinfo = &pble_rsrc->pinfo[order];
	pble_cnt_per_chunk = pinfo->pble_cnt_per_chunk;
	chunk_num = pble_info->allocated_chunk_num;
	cnt = 0;

	mutex_lock(&pble_rsrc->pble_mutex_lock);
	spin_lock_irqsave(&pinfo->prm_lock, flags);

	for (cnt = 0; cnt < chunk_num; cnt++) {
		chunk = list_entry(chunk_entry, struct nbl_chunk, list);
		chunk_entry = chunk->list.next;

		if (cnt == 0) {
			bitmap_clear(chunk->bitmap_buf,
				     pble_info->first_chunk.bit_idx,
				     pble_info->first_chunk.bits_used);
			pble_rsrc->free_pble_cnt +=
				pble_info->first_chunk.bits_used;
			pble_rsrc->allocated_pble_cnt -=
				pble_info->first_chunk.bits_used;
		} else if (cnt == chunk_num - 1) {
			bitmap_clear(chunk->bitmap_buf,
				     pble_info->last_chunk.bit_idx,
				     pble_info->last_chunk.bits_used);
			pble_rsrc->free_pble_cnt +=
				pble_info->last_chunk.bits_used;
			pble_rsrc->allocated_pble_cnt -=
				pble_info->last_chunk.bits_used;
		} else {
			bitmap_zero(chunk->bitmap_buf, pble_cnt_per_chunk);
			pble_rsrc->free_pble_cnt += pble_cnt_per_chunk;
			pble_rsrc->allocated_pble_cnt -= pble_cnt_per_chunk;
		}

		if (--chunk->is_used <= 0) {
			chunk->is_used = 0;
			nbl_free_one_chunk(pble_rsrc, chunk);
			pble_rsrc->free_pd_cnt++;
			pble_rsrc->total_pble_cnt -= pble_cnt_per_chunk;
			pble_rsrc->free_pble_cnt -= pble_cnt_per_chunk;
		}
	}

	pble_info->first_chunk.pchunk = NULL;
	pble_info->first_chunk.bit_idx = 0;
	pble_info->first_chunk.bits_used = 0;

	pble_info->last_chunk.pchunk = NULL;
	pble_info->last_chunk.bit_idx = 0;
	pble_info->last_chunk.bits_used = 0;

	spin_unlock_irqrestore(&pinfo->prm_lock, flags);
	mutex_unlock(&pble_rsrc->pble_mutex_lock);
}

static void nbl_free_pbl_addr_info(struct nbl_pble_alloc *palloc)
{
	struct nbl_pble_info *pble_info = &palloc->pble_info;
	struct list_head *chunk_entry = NULL;
	struct nbl_chunk *pchunk = pble_info->first_chunk.pchunk;
	u64 *pbl;
	u32 total_cnt = palloc->needed_cnt;
	u32 idx = 0;
	u32 pbl_cnt = 0;

	/* get the first pble addr */
	pbl = pble_info->addr;
	*pbl = 0;

	while (pbl_cnt < total_cnt - 1) {
		idx++;
		pbl++;
		if (idx >= pble_info->pble_cnt_per_chunk) {
			idx = 0;
			chunk_entry = pchunk->list.next;
			pchunk =
				list_entry(chunk_entry, struct nbl_chunk, list);
			pbl = pchunk->va;
		}
		*pbl = 0;
		pbl_cnt++;
	}
}

void nbl_free_pble(struct nbl_hmc_pble_rsrc *pble_rsrc,
		   struct nbl_pble_alloc *palloc)
{
	if (!palloc)
		return;

	nbl_free_pbl_addr_info(palloc);
	if (palloc->pble_info.is_single)
		nbl_free_pbles_by_single_chunk(pble_rsrc, &palloc->pble_info);
	else
		nbl_free_pbles_by_multi_chunk(pble_rsrc, &palloc->pble_info);
}

void nbl_destroy_pble_prm(struct nbl_hmc_pble_rsrc *pble_rsrc)
{
	struct nbl_chunk *chunk = NULL;
	struct nbl_pble_prm *pble_info = NULL;
	int order;
	unsigned long flags;

	mutex_lock(&pble_rsrc->pble_mutex_lock);
	for (order = 0; order < NBL_PBLE_MAX_ORDER; order++) {
		spin_lock_irqsave(&pble_rsrc->pinfo[order].prm_lock, flags);
		pble_info = &pble_rsrc->pinfo[order];
		while (!list_empty(&pble_info->clist)) {
			chunk = (struct nbl_chunk *)pble_info->clist.next;
			nbl_free_one_chunk(pble_rsrc, chunk);
		}
		spin_unlock_irqrestore(&pble_rsrc->pinfo[order].prm_lock,
				       flags);
	}

	kfree(pble_rsrc->pd_bmap);

	mutex_unlock(&pble_rsrc->pble_mutex_lock);
}

static int nbl_init_pble_pd_info(struct nbl_hmc_obj_sd_info *pbl_sd_info,
				 struct nbl_hmc_pble_rsrc *pble_rsrc)
{
	u64 rsrc_size;

	rsrc_size = sizeof(unsigned long) * BITS_TO_LONGS(pbl_sd_info->cnt);
	pble_rsrc->max_index = pbl_sd_info->cnt;
	pble_rsrc->pd_bmap_size = pbl_sd_info->cnt;
	pble_rsrc->pd_bmap = kzalloc(rsrc_size, GFP_KERNEL);
	if (!pble_rsrc->pd_bmap)
		goto err;

	pble_rsrc->free_pd_cnt = pbl_sd_info->cnt;

	return 0;
err:
	nbl_pr_err("failed vzalloc mem of pd_bmap for pble_rsrc.\n");
	return NBL_ERR_ALLOCMEM_FAILED;
}

int nbl_init_pble_prm(struct nbl_hmc_obj_sd_info *pbl_sd_info,
		      struct nbl_hmc_pble_rsrc *pble_rsrc)
{
	u32 page_sz = pbl_sd_info->page_sz;
	u32 total_pble_per_chunk;
	int ret, order;

	total_pble_per_chunk = page_sz >> PBLE_SIZE_SHIFT;

	pble_rsrc->base_idx = 0;
	pble_rsrc->stats_alloc_ok = 0;
	pble_rsrc->stats_alloc_failed = 0;
	pble_rsrc->total_pble_cnt = 0;
	pble_rsrc->allocated_pble_cnt = 0;

	/* init pble pd info, use bitmap to record pble pd usage */
	ret = nbl_init_pble_pd_info(pbl_sd_info, pble_rsrc);
	if (ret) {
		nbl_ib_err(pble_rsrc->sc_dev, "init pble pd info failed!\n");
		goto init_pble_pd_err;
	}

	/* init pble prm */
	for (order = 0; order < NBL_PBLE_MAX_ORDER; order++) {
		/*
		 * one clist is required to record the allocated chunks,
		 * so that resources including pd and buf of chunks can be released
		 * in case of failure
		 */
		pble_rsrc->pinfo[order].pble_cnt_per_chunk =
			total_pble_per_chunk;
		INIT_LIST_HEAD(&pble_rsrc->pinfo[order].clist);
		spin_lock_init(&pble_rsrc->pinfo[order].prm_lock);
	}

	return 0;
init_pble_pd_err:
	return ret;
}

int nbl_hmc_init_pble(struct nbl_pci_f *rf)
{
	struct nbl_hmc_pble_rsrc *pble_rsrc = rf->pble_rsrc;
	int ret;

	rf->pbl_sd_info =
		kzalloc(sizeof(struct nbl_hmc_obj_sd_info), GFP_KERNEL);
	if (!rf->pbl_sd_info)
		return -ENOMEM;

	ret = nbl_get_obj_sd_addr(rf, NBL_HMC_PBL, rf->pbl_sd_info);
	if (ret) {
		nbl_ib_err(&rf->sc_dev, "get nbl pbl sd addr info failed!\n");
		goto get_sd_addr_err;
	}

	pble_rsrc->sc_dev = &rf->sc_dev;
	mutex_init(&pble_rsrc->pble_mutex_lock);
	ret = nbl_init_pble_prm(rf->pbl_sd_info, pble_rsrc);
	if (ret) {
		nbl_ib_err(&rf->sc_dev, "add nbl pble prm failed!\n");
		goto init_pble_prm_err;
	}

	return 0;

init_pble_prm_err:
	nbl_free_obj_sd_addr(rf->pbl_sd_info);
get_sd_addr_err:
	kfree(rf->pbl_sd_info);
	return ret;
}

void nbl_hmc_deinit_pble(struct nbl_pci_f *rf)
{
	nbl_destroy_pble_prm(rf->pble_rsrc);
	nbl_free_obj_sd_addr(rf->pbl_sd_info);
	kfree(rf->pbl_sd_info);
}

int nbl_dump_hmc_pble(struct nbl_pci_f *rf, u32 dump_mask)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_hmc_obj_sd_info *sd_info = rf->pbl_sd_info;
	u32 num_one_page; /* how many cqc in one page */
	u32 page_index; /* page index that cqc located */
	u32 pbl_index; /* pbl index in a page */
	struct nbl_hmc_obj_sd_addr *sd;
	u32 first_pble_index;

	first_pble_index = dump_mask;
	num_one_page = sd_info->page_sz / NBL_HMC_PBL_SZ; /* 4K/8=512*/
	page_index = first_pble_index / num_one_page;

	sd = &sd_info->sd_addr[page_index];
	pbl_index = first_pble_index % num_one_page;

	nbl_ib_err(sc_dev, "[pble] dump first pbl index(%u) pbl(sd va %p, 0x%llx, offset 0x%x)",
		first_pble_index, sd->va, (u64)((uintptr_t)sd->va), (pbl_index * NBL_HMC_PBL_SZ));
	nbl_pr_err("the addr of pble is %p.\n", (u64 *)sd->va + pbl_index);
	nbl_dump_hex(rf, (sd->va + (pbl_index * NBL_HMC_PBL_SZ)), 16);

	return 0;
}

int nbl_dump_pble_cnt(struct nbl_pci_f *rf)
{
	struct nbl_hmc_pble_rsrc *pble_rsrc = rf->pble_rsrc;

	nbl_ib_err(
		&rf->sc_dev,
		"[pble] total_pble_cnt[%llu], allocated_pble_cnt(%llu), free_pble_cnt(%llu), free_pd_cnt[%llu]\n",
		pble_rsrc->total_pble_cnt, pble_rsrc->allocated_pble_cnt,
		pble_rsrc->free_pble_cnt, pble_rsrc->free_pd_cnt);

	return 0;
}

int nbl_fill_pble_value(struct nbl_pble_alloc *palloc, u32 tpcnt, u64 addr)
{
	struct nbl_pble_info *pble_info = &palloc->pble_info;
	struct nbl_pble_chunkinfo *first_chnk = &pble_info->first_chunk;
	struct nbl_chunk *pchunk;
	u32 bidx;
	u32 curmax;
	u32 cnted;
	u64 *pbl_addr;
	int ret = -ENOMEM;

	if (pble_info->is_single) {
		pbl_addr = pble_info->addr;
		pbl_addr[tpcnt] = cpu_to_be64(addr | NBL_PBLE_VLD_FLAG);
		ret = 0;
	} else {
		cnted = 0;
		curmax = first_chnk->bits_used;
		bidx = first_chnk->bit_idx;

		pchunk = first_chnk->pchunk;
		while (pchunk) {
			if (tpcnt < curmax) {
				pbl_addr = pchunk->va;
				pbl_addr[tpcnt - cnted + bidx] =
					cpu_to_be64(addr | NBL_PBLE_VLD_FLAG);
				ret = 0;
				break;
			}

			cnted = curmax;
			curmax += pble_info->pble_cnt_per_chunk;
			bidx = 0; /* chunk except first begin from 0 */

			pchunk = list_next_entry(pchunk, list);
		}
	}

	return ret;
}
