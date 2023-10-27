// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <rdma/ib_umem.h>
#include "xsc_ib.h"

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
	// TODO: need peer mem support
	unsigned long page_shift = PAGE_SHIFT;

	addr = addr >> page_shift;
	tmp = (unsigned long)addr;
	m = find_first_bit(&tmp, BITS_PER_LONG);
	if (max_page_shift)
		m = min_t(unsigned long, max_page_shift - page_shift, m);
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
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
	// no limit for page_shift
	__xsc_ib_cont_pages(umem, addr, 0, count, shift, ncont, order);
}

void __xsc_ib_populate_pas(struct xsc_ib_dev *dev, struct ib_umem *umem,
			    int page_shift, size_t offset, size_t num_pages,
			    __be64 *pas, int access_flags, bool need_to_devide)
{
	unsigned long umem_page_shift = PAGE_SHIFT;
	int shift = page_shift - umem_page_shift;
	int mask = (1 << shift) - 1;
	int k, idx;
	u64 cur = 0;
	u64 base;
	int len;
	struct scatterlist *sg;
	int entry;
	int i = 0;

	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
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
