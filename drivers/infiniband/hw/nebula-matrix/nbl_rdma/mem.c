// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Memory manage module
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: Peter.Pan <peter.pan@nebula-matrix.com>
 */

#include "mem.h"
#include "debug.h"
#include "hmc.h"
#include "main.h"

/**
 * nbl_get_wqe - get the kernel qp/cq/ceq/aeq wqe
 * @base: pointer to the level0 queue
 * @buf:  the list which save all of the 4k page
 * @wqe_size: the wqe_size of queue qp/cq 64 ceq/aeq 16
 * @wqe_idx: the wqe idx
 * @pa_continue: is pa_continue
 * Return: return the wqe address
 */
void *nbl_get_wqe(void *base, struct nbl_frag_buf *buf, int wqe_size,
		int wqe_idx, bool pa_continue)
{
	__be64 *wqe = NULL;
	int per_page_wqe;
	int page_idx;
	int wqe_idx_in_page;
	struct nbl_buf_list *frag;
	u8 *ptr;

	if (wqe_size <= 0)
		return NULL;

	if (pa_continue) {
		if (!base)
			return NULL;
		ptr = (u8 *)base;
		wqe = (__be64 *)(ptr + (wqe_size * wqe_idx));
	} else if (buf) {
		per_page_wqe = NBL_ADAPTER_PAGE_SIZE / wqe_size;
		page_idx = wqe_idx / per_page_wqe;
		if (page_idx >= buf->npages) {
			nbl_pr_err("wqe_idx:%d per_page_wqe:%d npages:%d page_idx:%d\n",
				wqe_idx, per_page_wqe, buf->npages, page_idx);
			return NULL;
		}
		wqe_idx_in_page = wqe_idx % per_page_wqe;
		frag = &buf->frags[page_idx];
		ptr = (u8 *)frag->buf;
		wqe = (__be64 *)(ptr + wqe_idx_in_page * wqe_size);
	}
	return wqe;
}

/**
 * nbl_get_umem_info - get the umem page number and whether is contiguous
 * @umem: pointer to the ib_umem structure
 * @pg_num: return the page number the umem have, attention page size is
 *          PAGE_SIZE of system, return val
 * @is_contiguous: return whether the memory is physical contiguous, return val
 * Return: return 0 is success, other value if fail
 */
void nbl_get_umem_info(struct ib_umem *umem, u32 *pg_num, bool *is_contiguous)
{
	int chunk_pages, entry, i;
	u32 page_cnt = 0;
	u64 pg_addr_first = 0;
	struct scatterlist *sg;

	*is_contiguous = true;
	for_each_sgtable_dma_sg(&umem->sgt_append.sgt, sg, entry) {
		chunk_pages = DIV_ROUND_UP(sg_dma_len(sg), NBL_ADAPTER_PAGE_SIZE);
		for (i = 0; i < chunk_pages; i++) {
			if ((entry + i) == 0) { /* first page */
				pg_addr_first = sg_dma_address(sg) + (i << NBL_ADAPTER_PAGE_SHIFT);
			} else { /* not first page */
				if (*is_contiguous) {
					if ((pg_addr_first + (page_cnt * NBL_ADAPTER_PAGE_SIZE)) !=
					    (sg_dma_address(sg) + (i << NBL_ADAPTER_PAGE_SHIFT)))
						*is_contiguous = false;
				}
			}
			page_cnt++;
		}
	}
	*pg_num = page_cnt;
}

/**
 * nbl_copy_user_pgaddrs - copy PAs to the given memory
 * @umem: pointer to the ib_umem structure
 * @pas: the memory where to place PAs
 * @pas_size: the pas memory size, this size must be big enough
 * @total_cnt: the number of PA we want to place
 * @copy_num: return the number of copyed PA, this is return val
 * Return: return 0 is success, other value if fail
 */
int nbl_copy_user_pgaddrs(struct ib_umem *umem, u64 *pas, u32 pas_size,
				u32 total_cnt, u32 *copy_num)
{
	int chunk_pages, entry, i;
	u32 page_cnt = 0;
	struct scatterlist *sg;
	u64 pd_entry;

	*copy_num = 0;
	if (total_cnt * NBL_MEM_PA_BYTE_CNT > pas_size)
		return -ENOMEM;
	for_each_sgtable_dma_sg(&umem->sgt_append.sgt, sg, entry) {
		chunk_pages = DIV_ROUND_UP(sg_dma_len(sg), NBL_ADAPTER_PAGE_SIZE);
		for (i = 0; i < chunk_pages; i++) {
			pd_entry = sg_dma_address(sg) + (i << NBL_ADAPTER_PAGE_SHIFT);
			pd_entry |= NBL_PD_VALID;
			pas[page_cnt++] = cpu_to_be64(pd_entry);
			if (page_cnt >= total_cnt) {
				*copy_num = page_cnt;
				return 0;
			}
		}
	}
	*copy_num = page_cnt;

	return 0;
}

dma_addr_t nbl_get_first_sg_dma_addr(struct ib_umem *umem)
{
	dma_addr_t dma_addr;

	dma_addr = sg_dma_address(umem->sgt_append.sgt.sgl);
	return dma_addr;
}

void *nbl_dma_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	struct nbl_dma_alloc_addr addr;

	addr.va = dma_alloc_coherent(dev, size, &addr.dma_addr, gfp);
	if (!addr.va)
		return NULL;

	if (addr.dma_addr >> NBL_DMA_ADDR_CHK_SHIFT == 0) {
		nbl_pr_err(
			"nbl dma alloc dma addr 0x%llx, high 48bit all zero\n",
			addr.dma_addr);
		dma_free_coherent(dev, size, addr.va, addr.dma_addr);
		return NULL;
	}
	*dma_handle = addr.dma_addr;
	return addr.va;
}


