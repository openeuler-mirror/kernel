// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "alloc.h"
#include "debug.h"
#include "hmc.h"
#include "mem.h"

/**
 * nbl_frag_buf_free - free physical memory for pages
 * @nbl_hw: RDMA hw struct
 * @buf: info of buf allocated to be freed
 * return 0, if the bufs are successfully freed, otherwise return error
 */
void nbl_frag_buf_free(struct nbl_hw *hw, void *va, dma_addr_t dma_handle,
		       struct nbl_frag_buf *buf)
{
	int i;

	for (i = 0; i < buf->npages; i++) {
		dma_free_coherent(hw->device, NBL_ADAPTER_PAGE_SIZE,
				  buf->frags[i].buf, buf->frags[i].map);
	}

	dma_free_coherent(hw->device, NBL_ADAPTER_PAGE_SIZE, va, dma_handle);
	kfree(buf->frags);
}

/**
 * nbl_frag_buf_alloc - allloc physical memory for pages
 * @hw: RDMA hw struct
 * @va: DMA virtual address to be return
 * @dma_handle: DMA physical address to be return
 * @buf: info of buf which will be allocated
 * return 0, if the bufs are successfully created, otherwise return error
 */
int nbl_frag_buf_alloc(struct nbl_hw *hw, void **va, dma_addr_t *dma_handle,
		       struct nbl_frag_buf *buf)
{
	struct device *device = hw->device;
	int i;
	u64 *p;
	int npages;
	u64 pd_entry;
	void *first_level_va;

	npages = buf->npages;

	buf->frags = kcalloc(npages, sizeof(struct nbl_buf_list), GFP_KERNEL);
	if (!buf->frags)
		goto err_out;

	/* firt-level physical page, used to save physical address
	 * of second-level pages
	 */
	first_level_va = nbl_dma_alloc_coherent(hw,
				NBL_ADAPTER_PAGE_SIZE, dma_handle, GFP_KERNEL);
	if (!first_level_va) {
		kfree(buf->frags);
		goto err_out;
	}

	p = (u64 *)first_level_va;

	/* second-level physical pages*/
	for (i = 0; i < npages; i++) {
		struct nbl_buf_list *frag = &buf->frags[i];

		frag->buf = nbl_dma_alloc_coherent(hw, NBL_ADAPTER_PAGE_SIZE,
					       &frag->map, GFP_KERNEL);
		if (!frag->buf)
			goto err_free_buf;

		memset(frag->buf, 0, NBL_ADAPTER_PAGE_SIZE);

		pd_entry = frag->map;
		pd_entry |= NBL_PD_VALID;
		pd_entry = cpu_to_be64(pd_entry);
		/* save the physical-addres to the first page*/
		memcpy(p, &pd_entry, sizeof(pd_entry));
		p++;
	}
	*va = first_level_va;
	return 0;

err_free_buf:
	while (i--)
		dma_free_coherent(device, NBL_ADAPTER_PAGE_SIZE,
				  buf->frags[i].buf, buf->frags[i].map);
	kfree(buf->frags);
	dma_free_coherent(device, NBL_ADAPTER_PAGE_SIZE, first_level_va, *dma_handle);

err_out:
	return NBL_ERR_ALLOCMEM_FAILED;
}

/**
 * nbl_kernel_buf_alloc - alloc memery kernel queue
 * @hw: RDMA hw struct
 * @rsize: kernel queue size
 * @info: buf descriter
 */
int nbl_kernel_buf_alloc(struct nbl_hw *hw, int rsize,
	struct nbl_buf_desc *info)
{
	struct nbl_frag_buf *fbuf = &info->buf.frag_buf;
	int status;

	info->kmem.size = round_up(rsize, NBL_ADAPTER_PAGE_SIZE);
	info->kmem.va = nbl_dma_alloc_coherent(hw, info->kmem.size,
					    &info->kmem.pa, GFP_KERNEL);
	fbuf->size = info->kmem.size;
	fbuf->npages =
		DIV_ROUND_UP(fbuf->size, NBL_ADAPTER_PAGE_SIZE);
	if (info->kmem.va)
		info->pa_continuous = true;
	else {
		info->pa_continuous = false;
		status = nbl_frag_buf_alloc(hw, &info->kmem.va,
					    &info->kmem.pa, fbuf);
		if (status)
			return status;
	}

	info->cq_pg_num = fbuf->npages;

	return 0;
}

/**
 * nbl_kernel_buf_free - free memery resources for kernel buffer
 * @nbl_hw: RDMA hw struct
 * @bd: buf descriter
 */
void nbl_kernel_buf_free(struct nbl_hw *hw, struct nbl_buf_desc *bd)
{
	struct nbl_frag_buf *fbuf = &bd->buf.frag_buf;

	if (bd->pa_continuous)
		dma_free_coherent(hw->device, bd->kmem.size, bd->kmem.va,
					bd->kmem.pa);
	else
		nbl_frag_buf_free(hw, bd->kmem.va, bd->kmem.pa,
					fbuf);

	bd->kmem.va = NULL;
}
