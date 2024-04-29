// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <rdma/ib_umem.h>
#include "xsc_ib.h"

static inline int xsc_count_trailing_zeros(unsigned long x)
{
#define COUNT_TRAILING_ZEROS_0 (-1)

	if (sizeof(x) == 4)
		return ffs(x);
	else
		return (x != 0) ? __ffs(x) : COUNT_TRAILING_ZEROS_0;
}

int xsc_find_chunk_cont_0(struct xsc_pa_chunk *chunk,
			  int is_first,
			  int is_last)
{
	static const int max_count =  sizeof(int) << 3;
	dma_addr_t pa, end_pa;
	u64 va, end_va;
	size_t length;
	int start_count, end_count;
	int va_start_count, va_end_count;

	pa = chunk->pa;
	va = chunk->va;
	length = chunk->length;
	end_pa = pa + length;
	end_va = va + length;
	start_count = max_count;
	end_count = max_count;

	if (!is_first) {
		start_count = xsc_count_trailing_zeros((unsigned long)pa);
		va_start_count = xsc_count_trailing_zeros(va);
		start_count = min_t(int, start_count, va_start_count);
	}

	if (!is_last) {
		end_count = xsc_count_trailing_zeros((unsigned long)end_pa);
		va_end_count = xsc_count_trailing_zeros(end_va);
		end_count = min_t(int, end_count, va_end_count);
	}

	return start_count > end_count ? end_count : start_count;
}

int xsc_find_best_pgsz(struct ib_umem *umem,
		       unsigned long pgsz_bitmap,
		       unsigned long virt,
		       int *npages,
		       int *shift,
		       u64 **pas)
{
	struct scatterlist *sg;
	unsigned long va;
	dma_addr_t pa;
	struct xsc_pa_chunk *chunk, *tmp;
	struct list_head chunk_list;
	int i;
	int chunk_cnt;
	int min_count_0 = sizeof(int) << 3;
	int count_0;
	int is_first = 0, is_end = 0;
	size_t pgsz;
	u64 mask;
	int err = 0;
	int pa_index;
	u64 chunk_pa;
	int chunk_npages;
	unsigned long page_shift = PAGE_SHIFT;

	pgsz_bitmap &= GENMASK(BITS_PER_LONG - 1, 0);

	va = (virt >> page_shift) << page_shift;

	INIT_LIST_HEAD(&chunk_list);
	chunk = kzalloc(sizeof(*chunk), GFP_KERNEL);
	if (!chunk) {
		err = -ENOMEM;
		goto err_alloc;
	}
	list_add_tail(&chunk->list, &chunk_list);

	chunk_cnt = 1;
	for_each_sg(umem->sgt_append.sgt.sgl, sg, umem->sgt_append.sgt.nents, i) {
		pa = sg_dma_address(sg);
		if (i == 0) {
			chunk->va = va;
			chunk->pa = pa;
			chunk->length = sg_dma_len(sg);
			va += chunk->length;
			continue;
		}

		if (pa == chunk->pa + chunk->length) {
			chunk->length += sg_dma_len(sg);
			va += chunk->length;
		} else {
			chunk = kzalloc(sizeof(*chunk), GFP_KERNEL);
			if (!chunk) {
				err = -ENOMEM;
				goto err_alloc;
			}
			chunk->va = va;
			chunk->pa = pa;
			chunk->length = sg_dma_len(sg);
			va += chunk->length;
			list_add_tail(&chunk->list, &chunk_list);
			chunk_cnt++;
		}
	}

	i = 0;
	list_for_each_entry(chunk, &chunk_list, list) {
		is_first = (i == 0 ? 1 : 0);
		is_end = (i == chunk_cnt - 1 ? 1 : 0);
		count_0 = xsc_find_chunk_cont_0(chunk, is_first, is_end);
		if (count_0 < min_count_0)
			min_count_0 = count_0;
		i++;
	}

	pgsz_bitmap &= GENMASK(min_count_0, 0);
	pgsz = rounddown_pow_of_two(pgsz_bitmap);
	*shift = ilog2(pgsz);
	*npages = 0;

	if (chunk_cnt == 1) {
		list_for_each_entry(chunk, &chunk_list, list) {
			mask = GENMASK(*shift - 1, min_t(int, page_shift, *shift - 1));
			*npages += DIV_ROUND_UP(chunk->length + (virt & mask), pgsz);
			*pas = vmalloc(*npages * sizeof(u64));
			if (!*pas) {
				err = -ENOMEM;
				goto err_alloc;
			}

			chunk_pa = chunk->pa - (virt & mask);
			for (i = 0; i < *npages; i++)
				(*pas)[i] = chunk_pa + i * pgsz;
		}
	} else {
		list_for_each_entry(chunk, &chunk_list, list) {
			*npages += DIV_ROUND_UP(chunk->length, pgsz);
		}

		*pas = vmalloc(*npages * sizeof(u64));
		if (!*pas) {
			err = -ENOMEM;
			goto err_alloc;
		}

		pa_index = 0;
		list_for_each_entry(chunk, &chunk_list, list) {
			chunk_npages = DIV_ROUND_UP(chunk->length, pgsz);
			chunk_pa = chunk->pa;
			for (i = 0; i < chunk_npages; i++) {
				if (pa_index == 0) {
					mask = GENMASK(*shift - 1,
						       min_t(int, page_shift, *shift - 1));
					chunk_pa -= (virt & mask);
				}
				(*pas)[pa_index] = chunk_pa + i * pgsz;

				pa_index++;
			}
		}
	}

err_alloc:
	list_for_each_entry_safe(chunk, tmp, &chunk_list, list) {
		list_del(&chunk->list);
		kfree(chunk);
	}
	return err;
}

/* @umem: umem object to scan
 * @addr: ib virtual address requested by the user
 * @count: number of PAGE_SIZE pages covered by umem
 * @shift: page shift for the compound pages found in the region
 * @ncont: number of compund pages
 * @order: log2 of the number of compound pages
 */
void __xsc_ib_cont_pages(struct ib_umem *umem, u64 addr,
			 unsigned long max_page_shift,
			 int *count, int *shift,
			 int *ncont, int *order)
{
	unsigned long tmp;
	unsigned long m;
	u64 base = ~0, p = 0;
	u64 len, pfn;
	int i = 0;
	struct scatterlist *sg;
	int entry;
	unsigned long page_shift = PAGE_SHIFT;

	addr = addr >> page_shift;
	tmp = (unsigned long)addr;
	m = find_first_bit(&tmp, BITS_PER_LONG);
	if (max_page_shift)
		m = min_t(unsigned long, max_page_shift - page_shift, m);
	for_each_sg(umem->sgt_append.sgt.sgl, sg, umem->sgt_append.sgt.nents, entry) {
		len = sg_dma_len(sg) >> page_shift;
		pfn = sg_dma_address(sg) >> page_shift;
		if (base + p != pfn) {
			/* If either the offset or the new
			 * base are unaligned update m
			 */
			tmp = (unsigned long)(pfn | p);
			if (!IS_ALIGNED(tmp, 1 << m))
				m = find_first_bit(&tmp, BITS_PER_LONG);

			base = pfn;
			p = 0;
		}

		p += len;
		i += len;
	}

	if (i) {
		m = min_t(unsigned long, ilog2(roundup_pow_of_two(i)), m);

		if (order)
			*order = ilog2(roundup_pow_of_two(i) >> m);

		*ncont = DIV_ROUND_UP(i, (1 << m));
	} else {
		m  = 0;

		if (order)
			*order = 0;

		*ncont = 0;
	}
	*shift = page_shift + m;
	*count = i;
}

void xsc_ib_cont_pages(struct ib_umem *umem, u64 addr,
		       int *count, int *shift,
		       int *ncont, int *order)
{
	__xsc_ib_cont_pages(umem, addr, 0, count, shift, ncont, order);
}

void __xsc_ib_populate_pas(struct xsc_ib_dev *dev, struct ib_umem *umem,
			   int page_shift, size_t offset, size_t num_pages,
			   __be64 *pas, int access_flags, bool need_to_devide)
{
	unsigned long umem_page_shift = PAGE_SHIFT;
	int shift = page_shift - umem_page_shift;
	int mask = (1 << shift) - 1;
	int i = 0;
	int k, idx;
	u64 cur = 0;
	u64 base;
	int len;
	struct scatterlist *sg;
	int entry;

	for_each_sg(umem->sgt_append.sgt.sgl, sg, umem->sgt_append.sgt.nents, entry) {
		len = sg_dma_len(sg) >> umem_page_shift;
		if (need_to_devide)
			len = sg_dma_len(sg) >> PAGE_SHIFT_4K;
		else
			len = sg_dma_len(sg) >> umem_page_shift;
		base = sg_dma_address(sg);

		/* Skip elements below offset */
		if (i + len < offset << shift) {
			i += len;
			continue;
		}

		/* Skip pages below offset */
		if (i < offset << shift) {
			k = (offset << shift) - i;
			i = offset << shift;
		} else {
			k = 0;
		}

		for (; k < len; k++) {
			if (!(i & mask)) {
				if (need_to_devide)
					cur = base + (k << PAGE_SHIFT_4K);
				else
					cur = base + (k << umem_page_shift);
				cur |= access_flags;
				idx = (i >> shift) - offset;

				pas[idx] = cpu_to_be64(cur);
				xsc_ib_dbg(dev, "pas[%d] 0x%llx\n",
					   i >> shift, be64_to_cpu(pas[idx]));
			}
			i++;

			/* Stop after num_pages reached */
			if (i >> shift >= offset + num_pages)
				return;
		}
	}
}

void xsc_ib_populate_pas(struct xsc_ib_dev *dev, struct ib_umem *umem,
			 int page_shift, __be64 *pas, int npages, bool need_to_devide)
{
	return __xsc_ib_populate_pas(dev, umem, page_shift, 0,
				     npages, pas, 0, need_to_devide);
}

int xsc_ib_get_buf_offset(u64 addr, int page_shift, u32 *offset)
{
	u64 page_size;
	u64 page_mask;
	u64 off_size;
	u64 off_mask;
	u64 buf_off;

	page_size = 1 << page_shift;
	page_mask = page_size - 1;
	buf_off = addr & page_mask;
	off_size = page_size >> 6;
	off_mask = off_size - 1;

	if (buf_off & off_mask)
		return -EINVAL;

	*offset = buf_off >> ilog2(off_size);
	return 0;
}
