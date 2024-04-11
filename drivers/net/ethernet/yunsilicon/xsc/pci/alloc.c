// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/vmalloc.h>
#include "common/driver.h"

/* Handling for queue buffers -- we allocate a bunch of memory and
 * register it in a memory region at HCA virtual address 0.  If the
 * requested size is > max_direct, we split the allocation into
 * multiple pages, so we don't require too much contiguous memory.
 */

int xsc_buf_alloc(struct xsc_core_device *xdev, int size, int max_direct,
		  struct xsc_buf *buf)
{
	dma_addr_t t;

	buf->size = size;
	if (size <= max_direct) {
		buf->nbufs        = 1;
		buf->npages       = 1;
		buf->page_shift   = get_order(size) + PAGE_SHIFT;
		buf->direct.buf   = dma_alloc_coherent(&xdev->pdev->dev,
						       size, &t, GFP_KERNEL | __GFP_ZERO);
		if (!buf->direct.buf)
			return -ENOMEM;

		buf->direct.map = t;

		while (t & ((1 << buf->page_shift) - 1)) {
			--buf->page_shift;
			buf->npages *= 2;
		}
	} else {
		int i;

		buf->direct.buf  = NULL;
		buf->nbufs       = (size + PAGE_SIZE - 1) / PAGE_SIZE;
		buf->npages      = buf->nbufs;
		buf->page_shift  = PAGE_SHIFT;
		buf->page_list   = kcalloc(buf->nbufs, sizeof(*buf->page_list),
					   GFP_KERNEL);
		if (!buf->page_list)
			return -ENOMEM;

		for (i = 0; i < buf->nbufs; i++) {
			buf->page_list[i].buf =
				dma_alloc_coherent(&xdev->pdev->dev, PAGE_SIZE,
						   &t, GFP_KERNEL | __GFP_ZERO);
			if (!buf->page_list[i].buf)
				goto err_free;

			buf->page_list[i].map = t;
		}

		if (BITS_PER_LONG == 64) {
			struct page **pages;

			pages = kmalloc_array(buf->nbufs, sizeof(*pages), GFP_KERNEL);
			if (!pages)
				goto err_free;
			for (i = 0; i < buf->nbufs; i++)
				pages[i] = virt_to_page(buf->page_list[i].buf);
			buf->direct.buf = vmap(pages, buf->nbufs, VM_MAP, PAGE_KERNEL);
			kfree(pages);
			if (!buf->direct.buf)
				goto err_free;
		}
	}

	return 0;

err_free:
	xsc_buf_free(xdev, buf);

	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(xsc_buf_alloc);

void xsc_buf_free(struct xsc_core_device *xdev, struct xsc_buf *buf)
{
	int i;

	if (buf->nbufs == 1) {
		dma_free_coherent(&xdev->pdev->dev, buf->size, buf->direct.buf,
				  buf->direct.map);
	} else {
		if (BITS_PER_LONG == 64 && buf->direct.buf)
			vunmap(buf->direct.buf);

		for (i = 0; i < buf->nbufs; i++)
			if (buf->page_list[i].buf)
				dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE,
						  buf->page_list[i].buf,
						  buf->page_list[i].map);
		kfree(buf->page_list);
	}
}
EXPORT_SYMBOL_GPL(xsc_buf_free);

void xsc_fill_page_array(struct xsc_buf *buf, __be64 *pas, int npages)
{
	u64 addr;
	int i;
	int shift = PAGE_SHIFT - PAGE_SHIFT_4K;
	int mask = (1 << shift) - 1;

	for (i = 0; i < npages; i++) {
		if (buf->nbufs == 1)
			addr = buf->direct.map + (i << PAGE_SHIFT_4K);
		else
			addr = buf->page_list[i >> shift].map + ((i & mask) << PAGE_SHIFT_4K);

		pas[i] = cpu_to_be64(addr);
	}
}
EXPORT_SYMBOL_GPL(xsc_fill_page_array);

void xsc_fill_page_frag_array(struct xsc_frag_buf *buf, __be64 *pas, int npages)
{
	int i;
	dma_addr_t addr;
	int shift = PAGE_SHIFT - PAGE_SHIFT_4K;
	int mask = (1 << shift) - 1;

	for (i = 0; i < npages; i++) {
		addr = buf->frags[i >> shift].map + ((i & mask) << PAGE_SHIFT_4K);
		pas[i] = cpu_to_be64(addr);
	}
}
EXPORT_SYMBOL_GPL(xsc_fill_page_frag_array);

static void *xsc_dma_zalloc_coherent_node(struct xsc_core_device *xdev,
					  size_t size, dma_addr_t *dma_handle,
					  int node)
{
	struct xsc_dev_resource *dev_res = xdev->dev_res;
	struct device *device = &xdev->pdev->dev;
	int original_node;
	void *cpu_handle;

	/* WA for kernels that don't use numa_mem_id in alloc_pages_node */
	if (node == NUMA_NO_NODE)
#ifdef HAVE_NUMA_MEM_ID
		node = numa_mem_id();
#else
		node = first_memory_node;
#endif

	mutex_lock(&dev_res->alloc_mutex);
	original_node = dev_to_node(device);
	set_dev_node(device, node);
	cpu_handle = dma_alloc_coherent(device, size, dma_handle,
					GFP_KERNEL);
	set_dev_node(device, original_node);
	mutex_unlock(&dev_res->alloc_mutex);
	return cpu_handle;
}

int xsc_frag_buf_alloc_node(struct xsc_core_device *xdev, int size,
			    struct xsc_frag_buf *buf, int node)
{
	int i;

	buf->size = size;
	buf->npages = DIV_ROUND_UP(size, PAGE_SIZE);
	buf->page_shift = PAGE_SHIFT;
	buf->frags = kcalloc(buf->npages, sizeof(struct xsc_buf_list),
			     GFP_KERNEL);
	if (!buf->frags)
		goto err_out;

	for (i = 0; i < buf->npages; i++) {
		struct xsc_buf_list *frag = &buf->frags[i];
		int frag_sz = min_t(int, size, PAGE_SIZE);

		frag->buf = xsc_dma_zalloc_coherent_node(xdev, frag_sz,
							 &frag->map, node);
		if (!frag->buf)
			goto err_free_buf;
		if (frag->map & ((1 << buf->page_shift) - 1)) {
			dma_free_coherent(&xdev->pdev->dev, frag_sz,
					  buf->frags[i].buf, buf->frags[i].map);
			xsc_core_warn(xdev, "unexpected map alignment: %pad, page_shift=%d\n",
				      &frag->map, buf->page_shift);
			goto err_free_buf;
		}
		size -= frag_sz;
	}

	return 0;

err_free_buf:
	while (i--)
		dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE, buf->frags[i].buf,
				  buf->frags[i].map);
	kfree(buf->frags);
err_out:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(xsc_frag_buf_alloc_node);

void xsc_frag_buf_free(struct xsc_core_device *xdev, struct xsc_frag_buf *buf)
{
	int size = buf->size;
	int i;

	for (i = 0; i < buf->npages; i++) {
		int frag_sz = min_t(int, size, PAGE_SIZE);

		dma_free_coherent(&xdev->pdev->dev, frag_sz, buf->frags[i].buf,
				  buf->frags[i].map);
		size -= frag_sz;
	}
	kfree(buf->frags);
}
EXPORT_SYMBOL_GPL(xsc_frag_buf_free);

static struct xsc_db_pgdir *xsc_alloc_db_pgdir(struct xsc_core_device *xdev,
					       int node)
{
	u32 db_per_page = PAGE_SIZE / cache_line_size();
	struct xsc_db_pgdir *pgdir;

	pgdir = kzalloc(sizeof(*pgdir), GFP_KERNEL);
	if (!pgdir)
		return NULL;

	pgdir->bitmap = bitmap_zalloc(db_per_page, GFP_KERNEL);
	if (!pgdir->bitmap) {
		kfree(pgdir);
		return NULL;
	}

	bitmap_fill(pgdir->bitmap, db_per_page);

	pgdir->db_page = xsc_dma_zalloc_coherent_node(xdev, PAGE_SIZE,
						      &pgdir->db_dma, node);
	if (!pgdir->db_page) {
		bitmap_free(pgdir->bitmap);
		kfree(pgdir);
		return NULL;
	}

	return pgdir;
}

static int xsc_alloc_db_from_pgdir(struct xsc_db_pgdir *pgdir,
				   struct xsc_db *db)
{
	u32 db_per_page = PAGE_SIZE / cache_line_size();
	int offset;
	int i;

	i = find_first_bit(pgdir->bitmap, db_per_page);
	if (i >= db_per_page)
		return -ENOMEM;

	__clear_bit(i, pgdir->bitmap);

	db->u.pgdir = pgdir;
	db->index   = i;
	offset = db->index * cache_line_size();
	db->db      = pgdir->db_page + offset / sizeof(*pgdir->db_page);
	db->dma     = pgdir->db_dma  + offset;

	db->db[0] = 0;
	db->db[1] = 0;

	return 0;
}

int xsc_db_alloc_node(struct xsc_core_device *xdev, struct xsc_db *db, int node)
{
	struct xsc_db_pgdir *pgdir;
	int ret = 0;

	mutex_lock(&xdev->dev_res->pgdir_mutex);

	list_for_each_entry(pgdir, &xdev->dev_res->pgdir_list, list)
		if (!xsc_alloc_db_from_pgdir(pgdir, db))
			goto out;

	pgdir = xsc_alloc_db_pgdir(xdev, node);
	if (!pgdir) {
		ret = -ENOMEM;
		goto out;
	}

	list_add(&pgdir->list, &xdev->dev_res->pgdir_list);

	/* This should never fail -- we just allocated an empty page: */
	WARN_ON(xsc_alloc_db_from_pgdir(pgdir, db));

out:
	mutex_unlock(&xdev->dev_res->pgdir_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(xsc_db_alloc_node);

int xsc_db_alloc(struct xsc_core_device *xdev, struct xsc_db *db)
{
	return xsc_db_alloc_node(xdev, db, xdev->priv.numa_node);
}
EXPORT_SYMBOL_GPL(xsc_db_alloc);

void xsc_db_free(struct xsc_core_device *xdev, struct xsc_db *db)
{
	u32 db_per_page = PAGE_SIZE / cache_line_size();

	mutex_lock(&xdev->dev_res->pgdir_mutex);

	__set_bit(db->index, db->u.pgdir->bitmap);

	if (bitmap_full(db->u.pgdir->bitmap, db_per_page)) {
		dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE,
				  db->u.pgdir->db_page, db->u.pgdir->db_dma);
		list_del(&db->u.pgdir->list);
		bitmap_free(db->u.pgdir->bitmap);
		kfree(db->u.pgdir);
	}

	mutex_unlock(&xdev->dev_res->pgdir_mutex);
}
EXPORT_SYMBOL_GPL(xsc_db_free);
