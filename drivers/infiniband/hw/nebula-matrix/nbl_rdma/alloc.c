// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include "alloc.h"
#include "debug.h"
#include "hmc.h"
#include "mem.h"
/**
 * nbl_frag_buf_free - free physical memory for pages
 * @device: RDMA device
 * @buf: info of buf allocated to be freed
 * return 0, if the bufs are successfully freed, otherwise return error
 */
void nbl_frag_buf_free(struct device *device, void *va, dma_addr_t dma_handle,
		       struct nbl_frag_buf *buf)
{
	int i;

	for (i = 0; i < buf->npages; i++) {
		dma_free_coherent(device, NBL_ADAPTER_PAGE_SIZE,
				  buf->frags[i].buf, buf->frags[i].map);
	}

	dma_free_coherent(device, NBL_ADAPTER_PAGE_SIZE, va, dma_handle);
	kfree(buf->frags);
}

/**
 * nbl_frag_buf_alloc - allloc physical memory for pages
 * @device: RDMA device
 * @va: DMA virtual address to be return
 * @dma_handle: DMA physical address to be return
 * @buf: info of buf which will be allocated
 * return 0, if the bufs are successfully created, otherwise return error
 */
int nbl_frag_buf_alloc(struct device *device, void **va, dma_addr_t *dma_handle,
		       struct nbl_frag_buf *buf)
{
	int i;
	u64 *p;
	int npages;
	u64 pd_entry;
	void *first_level_va;

	npages = buf->npages;

	buf->frags = kcalloc(npages, sizeof(struct nbl_buf_list), GFP_KERNEL);
	if (!buf->frags)
		goto err_out;

	/* firt-level physical page, used to save physical address of second-level pages */
	first_level_va = nbl_dma_alloc_coherent(device, NBL_ADAPTER_PAGE_SIZE,
						dma_handle, GFP_KERNEL);
	if (!first_level_va) {
		kfree(buf->frags);
		goto err_out;
	}

	p = (u64 *)first_level_va;

	/* second-level physical pages*/
	for (i = 0; i < npages; i++) {
		struct nbl_buf_list *frag = &buf->frags[i];

		frag->buf = nbl_dma_alloc_coherent(
			device, NBL_ADAPTER_PAGE_SIZE, &frag->map, GFP_KERNEL);
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
