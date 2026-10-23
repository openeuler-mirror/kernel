// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Memory manage module
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: Peter.Pan <peter.pan@nebula-matrix.com>
 */

#include "main.h"
#include "mem.h"
#include "debug.h"
#include "hmc.h"

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
 * @use_sys_page: use system page size in arm server when PAGE_SIZE != SZ_4K for pble
 * Return: return 0 is success, other value if fail
 */
void nbl_get_umem_info(struct ib_umem *umem, u32 *pg_num, bool *is_contiguous, bool use_sys_page)
{
	int chunk_pages, entry, i;
	u32 page_cnt = 0;
	u64 pg_addr_first = 0;
	struct scatterlist *sg;
	u32 mem_page_size = NBL_ADAPTER_PAGE_SIZE;
	u32 mem_page_shift = NBL_ADAPTER_PAGE_SHIFT;

	if (use_sys_page) {
		mem_page_size = PAGE_SIZE;
		mem_page_shift = PAGE_SHIFT;
	}

	*is_contiguous = true;
	for_each_sgtable_dma_sg(&umem->sgt_append.sgt, sg, entry) {
		chunk_pages = DIV_ROUND_UP(sg_dma_len(sg), mem_page_size);
		for (i = 0; i < chunk_pages; i++) {
			if ((entry + i) == 0) { /* first page */
				pg_addr_first = sg_dma_address(sg) + (i << mem_page_shift);
			} else { /* not first page */
				if (*is_contiguous) {
					if ((pg_addr_first + (page_cnt * mem_page_size))
						!= (sg_dma_address(sg) + (i << mem_page_shift)))
						*is_contiguous = false;
				}
			}
			page_cnt++;
		}
	}
	*pg_num = page_cnt;
}

static int check_umem_period_valid(struct ib_umem *umem, u32 offset, u32 size)
{
	if ((offset + size) > umem->length)
		return -ENOMEM;
	return 0;
}

/**
 * nbl_check_umem_period_contiguous - check if a period of umem is contiguous.
 * @umem: pointer to the ib_umem structure
 * @offset: start byte of the umem period
 * @size: size of the umem period
 * @is_contiguous: return whether the memory is physical contiguous, return val
 * Return: int
 */
int nbl_check_umem_period_contiguous(struct ib_umem *umem,
	u32 offset, u32 size, bool *is_contiguous)
{
	int entry;
	struct scatterlist *sg;
	int err = 0;
	dma_addr_t start, prev_end = 0, end;

	*is_contiguous = true;
	nbl_pr_dbg("offset: %d, size: %d", offset, size);
	err = check_umem_period_valid(umem, offset, size);
	if (err)
		return err;

	for_each_sgtable_dma_sg(&umem->sgt_append.sgt, sg, entry) {
		nbl_pr_dbg("entry %d sg len: %d", entry, sg_dma_len(sg));
		/* move to start sg */
		if (sg_dma_len(sg) <= offset) {
			offset -= sg_dma_len(sg);
			continue;
		}

		start = sg_dma_address(sg);
		end = start + sg_dma_len(sg);

		start += offset;
		offset = 0;

		/* cross sg check continues */
		if (prev_end && start != prev_end) {
			*is_contiguous = false;
			return 0;
		}
		prev_end = end;

		if (start + size > end)
			size = size - (end - start);
		else
			return 0;
	}
	return -ENOMEM;
}

/**
 * nbl_get_umem_period_start - Give start dma address of a period of umem.
 * @umem: pointer to the ib_umem structure
 * @offset: start byte of the umem period
 * Return: dma_addr_t
 */
int nbl_get_umem_period_start(struct ib_umem *umem, u32 offset, dma_addr_t *addr)
{
	int entry;
	struct scatterlist *sg;

	nbl_pr_dbg("offset: %d", offset);
	for_each_sgtable_dma_sg(&umem->sgt_append.sgt, sg, entry) {
		nbl_pr_dbg("entry %d sg len: %d", entry, sg_dma_len(sg));
		/* move to start sg */
		if (sg_dma_len(sg) <= offset) {
			offset -= sg_dma_len(sg);
			continue;
		}

		*addr = sg_dma_address(sg) + offset;
		return 0;
	}
	return -ENOMEM;
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

/**
 * nbl_copy_period_pgaddrs - copy period PAs to the given memory
 * @umem: pointer to the ib_umem structure
 * @pas: the memory where to place PAs
 * @offset: start byte of the umem period
 * @size: size of the umem period
 * Return: return 0 is success, other value if fail
 */
int nbl_copy_period_pgaddrs(struct ib_umem *umem, u64 *pas, u32 offset, u32 size)
{
	int chunk_pages, entry, i;
	u32 page_cnt = 0, total_cnt;
	struct scatterlist *sg;
	u64 pd_entry;
	u64 start;

	total_cnt = size / PAGE_SIZE;
	nbl_pr_dbg("offset: %d, size: %d, total_cnt: %d",
		offset, size, total_cnt);
	for_each_sgtable_dma_sg(&umem->sgt_append.sgt, sg, entry) {
		nbl_pr_dbg("entry %d sg len: %d", entry, sg_dma_len(sg));
		/* move to start sg */
		if (sg_dma_len(sg) <= offset) {
			offset -= sg_dma_len(sg);
			continue;
		}
		if (offset) {
			start = sg_dma_address(sg) + offset;
			chunk_pages = DIV_ROUND_UP(sg_dma_len(sg) - offset, PAGE_SIZE);
			offset = 0;
		} else {
			start = sg_dma_address(sg);
			chunk_pages = DIV_ROUND_UP(sg_dma_len(sg), PAGE_SIZE);
		}
		for (i = 0; i < chunk_pages; i++) {
			pd_entry = start + (i << PAGE_SHIFT);
			pd_entry |= NBL_PD_VALID;
			pas[page_cnt++] = cpu_to_be64(pd_entry);
			if (page_cnt >= total_cnt)
				return 0;
		}
	}
	return -ENOMEM;
}

dma_addr_t nbl_get_first_sg_dma_addr(struct ib_umem *umem)
{
	dma_addr_t dma_addr;

	dma_addr = sg_dma_address(umem->sgt_append.sgt.sgl);
	return dma_addr;
}

/**
 * nbl_user_buf_get - PIN and DMA map user mem and copy to PD if need
 * @dev: nbl device
 * @usr_addr: buffer addr from user space
 * @length: buffer length from user space
 * @info: buffer handle result
 */
int nbl_user_buf_get(struct ib_ucontext *ibctx,
	struct nbl_device *dev, u64 usr_addr, u64 length,
	struct nbl_buf_desc *info, struct ib_udata *udata)
{
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;
	u32 pg_num;
	bool is_contiguous = false;
	int status;
	u32 copy_num;
	u32 pas_size;

	info->buf.nbl_peer = false;

/* maybe gpu mem */
#ifdef CONFIG_INFINIBAND_PEER_MEMORY
	info->buf.umem = ib_umem_get_peer(&dev->ibdev, usr_addr, length,
				   IB_ACCESS_LOCAL_WRITE, 0);
#else
	info->buf.umem = ib_umem_get(&dev->ibdev, usr_addr, length,
				      IB_ACCESS_LOCAL_WRITE);
#endif
	if (IS_ERR(info->buf.umem))
		return PTR_ERR(info->buf.umem);

	nbl_get_umem_info(info->buf.umem, &pg_num, &is_contiguous, false);

	info->cq_pg_num = pg_num;

	if (is_contiguous) {
		info->kmem.pa = nbl_get_first_sg_dma_addr(info->buf.umem);
		info->pa_continuous = true;
		info->kmem.va = NULL;
	} else {
		info->pa_continuous = false;
		pas_size =
			NBL_ADAPTER_PAGE_SIZE; /* just support one page by now*/
		info->kmem.va = nbl_dma_alloc_coherent(sc_dev->hw,
						 NBL_ADAPTER_PAGE_SIZE,
						 &info->kmem.pa, GFP_KERNEL);
		if (!info->kmem.va) {
			status = NBL_ERR_ALLOCMEM_FAILED;
			nbl_ib_err(sc_dev, "[CQ_CREATE] CQ kmem va NULL\n");
			goto err_umem;
		}

		status = nbl_copy_user_pgaddrs(info->buf.umem, info->kmem.va,
					       pas_size, pg_num, &copy_num);
		if (status) {
			dma_free_coherent(sc_dev->hw->device,
					  NBL_ADAPTER_PAGE_SIZE, info->kmem.va,
					  info->kmem.pa);
			goto err_umem;
		}
	}

	return 0;

err_umem:
	nbl_ib_umem_release(info->buf.umem, info->buf.nbl_peer);
	return status;
}

/**
 * nbl_user_buf_release - unPIN user mem and free mem if need
 * @dev: nbl device
 * @bd: buffer handle result
 */
void nbl_user_buf_release(struct nbl_device *dev, struct nbl_buf_desc *bd)
{
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;

	if (!bd->pa_continuous) {
		dma_free_coherent(sc_dev->hw->device, NBL_ADAPTER_PAGE_SIZE,
					bd->kmem.va, bd->kmem.pa);
		nbl_ib_dbg(sc_dev, "destroy user, 0-level page freed ok.\n");
	}

	nbl_ib_umem_release(bd->buf.umem, bd->buf.nbl_peer);
	bd->kmem.va = NULL;
}

void *nbl_dma_alloc_coherent(struct nbl_hw *hw, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	struct device *dev = hw->device;
	struct nbl_dma_alloc_addr addr;

	if (!hw->jmp_h48zero_addr)
		return dma_alloc_coherent(dev, size, dma_handle, gfp);

	addr.va = dma_alloc_coherent(dev, size, &addr.dma_addr, gfp);
	if (!addr.va)
		return NULL;

	*dma_handle = addr.dma_addr;
	return addr.va;
}
