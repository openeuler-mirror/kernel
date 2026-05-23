/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_bitmap_table.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#ifndef __UEFI__
#include <linux/numa.h>
#endif

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_hinic5_vram_api.h"

#include "hinic5_cqm_object.h"
#include "hinic5_cqm_bat_cla.h"
#include "hinic5_cqm_cmd.h"
#include "hinic5_cqm_object_intern.h"
#include "hinic5_cqm_main.h"
#include "hinic5_vram_common.h"
#include "hinic5_cqm_cmdq.h"

#include "comm_defs.h"
#include "hinic5_cqm_npu_cmd_defs.h"

#define common_section

#ifndef __WIN__
struct malloc_memory {
	bool (*check_alloc_mode)(const struct hinic5_hwdev *handle, const struct tag_hinic5_cqm_buf *buf);
	s32 (*malloc_func)(struct hinic5_hwdev *handle, struct tag_hinic5_cqm_buf *buf);
};

struct free_memory {
	bool (*check_alloc_mode)(const struct hinic5_hwdev *handle, const struct tag_hinic5_cqm_buf *buf);
	void (*free_func)(struct tag_hinic5_cqm_buf *buf);
};
#endif
/**
 * Prototype    : hinic5_cqm_swab64(Encapsulation of __swab64)
 * Description  : Perform big-endian conversion for a memory block (8 bytes).
 * Input        : u8 *addr: Start address of the memory block
 *		  u32 cnt: Number of 8 bytes in the memory block
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_swab64(u8 *addr, u32 cnt)
{
	u64 *temp = (u64 *)addr;
	u64 value = 0;
	u32 i;

	for (i = 0; i < cnt; i++) {
		value = __swab64(*temp);
		*temp = value;
		temp++;
	}
}

/**
 * Prototype    : hinic5_cqm_swab32(Encapsulation of __swab32)
 * Description  : Perform big-endian conversion for a memory block (4 bytes).
 * Input        : u8 *addr: Start address of the memory block
 *		  u32 cnt: Number of 4 bytes in the memory block
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/7/23
 *   Modification : Created function
 */
void hinic5_cqm_swab32(u8 *addr, u32 cnt)
{
	u32 *temp = (u32 *)addr;
	u32 value = 0;
	u32 i;

	for (i = 0; i < cnt; i++) {
		value = __swab32(*temp);
		*temp = value;
		temp++;
	}
}

/**
 * Prototype    : hinic5_cqm_shift
 * Description  : Calculates n in a 2^n number.(Find the logarithm of 2^n)
 * Input        : u32 data
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
u32 hinic5_cqm_shift(u32 data)
{
	u32 data_num = data;
	s32 shift = -1;

	do {
		data_num >>= 1;
		shift++;
	} while (data_num != 0);

	return (u32)shift;
}

/**
 * Prototype    : hinic5_cqm_check_align
 * Description  : Check whether the value is 2^n-aligned. If 0 or 1, false is
 *		  returned.
 * Input        : u32 data
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/9/15
 *   Modification : Created function
 */
bool hinic5_cqm_check_align(u32 data)
{
	u32 data_num = data;

	if (data == 0)
		return false;

	do {
		/* When the value can be exactly divided by 2,
		 * the value of data is shifted right by one bit, that is,
		 * divided by 2.
		 */
		if ((data_num & 0x1) == 0)
			data_num >>= 1;
			/* If the value cannot be divisible by 2, the value is
			 * not 2^n-aligned and false is returned.
			 */
		else
			return false;
	} while (data_num != 1);

	return true;
}

/**
 * Prototype    : hinic5_cqm_kmalloc_align
 * Description  : Allocates 2^n-byte-aligned memory for the start address.
 * Input        : size_t size
 *		  gfp_t flags
 *		  u16 align_order
 * Output       : None
 * Return Value : void *
 * 1.Date         : 2017/9/22
 *   Modification : Created function
 */
void *hinic5_cqm_kmalloc_align(size_t size, gfp_t flags, u16 align_order)
{
	void *orig_addr = NULL;
	void *align_addr = NULL;
	void *index_addr = NULL;

	orig_addr = kmalloc(size + ((u64)1 << align_order) + sizeof(void *),
			    flags);
	if (!orig_addr)
		return NULL;

	index_addr = (void *)((char *)orig_addr + sizeof(void *));
	align_addr =
	    (void *)(uintptr_t)((((u64)(uintptr_t)index_addr + ((u64)1 << align_order) - 1) >>
		      align_order) << align_order);

	/* Record the original memory address for memory release. */
	index_addr = (void *)((char *)align_addr - sizeof(void *));
	*(void **)index_addr = orig_addr;

	return align_addr;
}

/**
 * Prototype    : hinic5_cqm_kfree_align
 * Description  : Release the memory allocated for starting address alignment.
 * Input        : void *addr
 * Output       : None
 * Return Value : void
 * 1.Date         : 2017/9/22
 *   Modification : Created function
 */
void hinic5_cqm_kfree_align(void *addr)
{
	void *index_addr = NULL;

	/* Release the original memory address. */
	index_addr = (void *)((char *)addr - sizeof(void *));

	hinic5_cqm_dbg_pr_on(hinic5_cqm_verbose,
		"free aligned address: %p, original address: %p\n",
		addr, *(void **)index_addr);

	kfree(*(void **)index_addr);
}

static void hinic5_cqm_write_lock(rwlock_t *lock, bool bh)
{
	if (bh)
		write_lock_bh(lock);
	else
		write_lock(lock);
}

static void hinic5_cqm_write_unlock(rwlock_t *lock, bool bh)
{
	if (bh)
		write_unlock_bh(lock);
	else
		write_unlock(lock);
}

static void hinic5_cqm_read_lock(rwlock_t *lock, bool bh)
{
	if (bh)
		read_lock_bh(lock);
	else
		read_lock(lock);
}

static void hinic5_cqm_read_unlock(rwlock_t *lock, bool bh)
{
	if (bh)
		read_unlock_bh(lock);
	else
		read_unlock(lock);
}

s32 hinic5_cqm_buf_alloc_direct(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf, bool direct)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct page **pages = NULL;
	u32 i, j, order;

	order = (u32)get_order(buf->buf_size);

	if (!direct) {
		buf->direct.va = NULL;
		return HINIC5_CQM_SUCCESS;
	}

	pages = vmalloc(sizeof(struct page *) * buf->page_number);
	if (!pages) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(pages));
		return HINIC5_CQM_FAIL;
	}

	for (i = 0; i < buf->buf_number; i++) {
		for (j = 0; j < ((u32)1 << order); j++)
			pages[(ulong)(unsigned int)((i << order) + j)] =
			    (void *)virt_to_page((void *)((uintptr_t)buf->buf_list[i].va +
						 PAGE_SIZE * j));
	}

	buf->direct.va = vmap(pages, buf->page_number, VM_MAP, PAGE_KERNEL);
	vfree(pages);
	if (!buf->direct.va) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(buf->direct.va));
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

#ifndef __WIN__

static bool check_use_hinic5_vram(const struct hinic5_hwdev *handle, const struct tag_hinic5_cqm_buf *buf)
{
	return buf->buf_info.use_hinic5_vram != 0 ? true : false;
}

static bool check_use_non_hinic5_vram(const struct hinic5_hwdev *handle, const struct tag_hinic5_cqm_buf *buf)
{
	return buf->buf_info.use_hinic5_vram != 0 ? false : true;
}

static bool check_for_use_node_alloc(const struct hinic5_hwdev *handle, const struct tag_hinic5_cqm_buf *buf)
{
	if (buf->buf_info.use_hinic5_vram == 0 && handle->board_info.service_mode == 0)
		return true;

	return false;
}

static bool check_for_nouse_node_alloc(const struct hinic5_hwdev *handle, const struct tag_hinic5_cqm_buf *buf)
{
	if (buf->buf_info.use_hinic5_vram == 0 && handle->board_info.service_mode != 0)
		return true;

	return false;
}

#ifndef __UEFI__
static u8 hinic5_cqm_hinic5_vram_node(struct hinic5_hwdev *handle)
{
	if (nr_node_ids > 0) {
		u16 func_id = hinic5_global_func_id(handle);
		// nr_node_ids indicates the maximum number of available NUMA nodes, will not be greater than u8 max value
		return (u8)(func_id % nr_node_ids);
	}
	return HINIC5_VRAM_NUMA_NODE0;
}
#endif

static s32 hinic5_cqm_buf_hinic5_vram_kalloc(struct hinic5_hwdev *handle, struct tag_hinic5_cqm_buf *buf)
{
	void *vaddr = NULL;
	u32 i;

	vaddr = hinic5_hinic5_vram_kalloc_node(buf->buf_info.buf_hinic5_vram_name,
				    (u64)buf->buf_size * buf->buf_number,
				    hinic5_cqm_hinic5_vram_node(handle));
	if (!vaddr) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(buf_page));
		return HINIC5_CQM_FAIL;
	}

	for (i = 0; i < buf->buf_number; i++)
		buf->buf_list[i].va = (void *)((char *)vaddr + i * (u64)buf->buf_size);

	return HINIC5_CQM_SUCCESS;
}

static void hinic5_cqm_buf_hinic5_vram_free(struct tag_hinic5_cqm_buf *buf)
{
	s32 i;

	if (buf->buf_list == NULL)
		return;

	if (buf->buf_list[0].va)
		hinic5_hinic5_vram_kfree(buf->buf_list[0].va, buf->buf_info.buf_hinic5_vram_name,
			      (u64)buf->buf_size * buf->buf_number);

	for (i = 0; i < (s32)buf->buf_number; i++)
		buf->buf_list[i].va = NULL;
}

static void hinic5_cqm_buf_free_page_common(struct tag_hinic5_cqm_buf *buf)
{
	u32 order;
	u32 i;

	if (buf->buf_list == NULL)
		return;

	order = (u32)get_order(buf->buf_size);

	for (i = 0; i < buf->buf_number; i++) {
		if (buf->buf_list[i].va) {
			free_pages((ulong)(uintptr_t)(buf->buf_list[i].va), order);
			buf->buf_list[i].va = NULL;
		}
	}
}

static s32 hinic5_cqm_buf_use_node_alloc_page(struct hinic5_hwdev *handle, struct tag_hinic5_cqm_buf *buf)
{
	struct page *newpage = NULL;
	gfp_t flags = GFP_KERNEL | __GFP_ZERO;
	u32 order, i;
	void *va = NULL;
	s32 node = dev_to_node(handle->dev_hdl);

	order = (u32)get_order(buf->buf_size);
	if (order > 0)
		flags |= __GFP_COMP;

	for (i = 0; i < buf->buf_number; i++) {
		newpage = alloc_pages_node(node, flags, order);
		if (!newpage) {
			hinic5_cqm_warn(handle->dev_hdl,
				 "alloc buf pages fail (%u/%u)\n",
				 i, buf->buf_number);
			break;
		}
		va = (void *)page_address(newpage);
		/* Initialize the page after the page is applied for.
		 * If hash entries are involved, the initialization
		 * value must be 0.
		 */
		memset(va, 0, buf->buf_size);
		buf->buf_list[i].va = va;
	}

	if (i != buf->buf_number) {
		hinic5_cqm_buf_free_page_common(buf);
		return HINIC5_CQM_BUF_ALLOC_BUDDY_PAGES_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_buf_unused_node_alloc_page(struct hinic5_hwdev *handle, struct tag_hinic5_cqm_buf *buf)
{
	gfp_t flags = GFP_KERNEL | __GFP_ZERO;
	u32 order, i;
	void *va = NULL;

	order = (u32)get_order(buf->buf_size);
	if (order > 0)
		flags |= __GFP_COMP;

	for (i = 0; i < buf->buf_number; i++) {
		va = (void *)(uintptr_t)ossl_get_free_pages(flags, order);
		if (!va) {
			hinic5_cqm_warn(handle->dev_hdl,
				 "alloc buf pages fail (%u/%u)\n",
				 i, buf->buf_number);
			break;
		}
		/* Initialize the page after the page is applied for.
		 * If hash entries are involved, the initialization
		 * value must be 0.
		 */
		memset(va, 0, buf->buf_size);
		buf->buf_list[i].va = va;
	}

	if (i != buf->buf_number) {
		hinic5_cqm_buf_free_page_common(buf);
		return HINIC5_CQM_BUF_ALLOC_BUDDY_PAGES_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static const struct malloc_memory g_malloc_funcs[] = {
	{check_use_hinic5_vram, hinic5_cqm_buf_hinic5_vram_kalloc},
	{check_for_use_node_alloc, hinic5_cqm_buf_use_node_alloc_page},
	{check_for_nouse_node_alloc, hinic5_cqm_buf_unused_node_alloc_page}
};

static const struct free_memory g_free_funcs[] = {
	{check_use_hinic5_vram, hinic5_cqm_buf_hinic5_vram_free},
	{check_use_non_hinic5_vram, hinic5_cqm_buf_free_page_common}
};

static s32 hinic5_cqm_buf_alloc_page(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 malloc_funcs_num = ARRAY_SIZE(g_malloc_funcs);
	u32 i;

	for (i = 0; i < malloc_funcs_num; i++) {
		if (g_malloc_funcs[i].check_alloc_mode &&
		    g_malloc_funcs[i].malloc_func &&
		    g_malloc_funcs[i].check_alloc_mode(handle, buf))
			return g_malloc_funcs[i].malloc_func(handle, buf);
	}

	hinic5_cqm_err(handle->dev_hdl, "Unknown alloc mode\n");

	return HINIC5_CQM_FAIL;
}

static void hinic5_cqm_buf_free_page(struct tag_hinic5_cqm_buf *buf)
{
	u32 free_funcs_num = ARRAY_SIZE(g_free_funcs);
	u32 i;

	for (i = 0; i < free_funcs_num; i++) {
		if (g_free_funcs[i].check_alloc_mode &&
		    g_free_funcs[i].free_func &&
		    g_free_funcs[i].check_alloc_mode(NULL, buf))
			return g_free_funcs[i].free_func(buf);
	}
}

static s32 hinic5_cqm_buf_alloc_map(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct device *dev = hinic5_cqm_handle->dev;
	void *va = NULL;
	s32 i;

	for (i = 0; i < (s32)buf->buf_number; i++) {
		va = buf->buf_list[i].va;
		buf->buf_list[i].pa = dma_map_single(dev, va, buf->buf_size,
						     DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, buf->buf_list[i].pa) != 0) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(buf_list));
			break;
		}
	}

	if (i != (s32)buf->buf_number) {
		i--;
		for (; i >= 0; i--)
			dma_unmap_single(dev, buf->buf_list[i].pa,
					 buf->buf_size, DMA_BIDIRECTIONAL);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

/* Applying for the buffer list descriptor space */
s32 hinic5_cqm_buf_list_alloc(struct tag_hinic5_cqm_buf *buf)
{
	size_t size = buf->buf_number * sizeof(struct tag_hinic5_cqm_buf_list);

	if (WARN_ON_ONCE(buf->buf_list))
		return HINIC5_CQM_SUCCESS;

	buf->buf_list = vmalloc(size);
	if (unlikely(!buf->buf_list)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(linux_buf_list));
		return HINIC5_CQM_FAIL;
	}

	memset(buf->buf_list, 0, size);
	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_buf_alloc
 * Description  : Apply for buffer space and DMA mapping for the struct tag_hinic5_cqm_buf
 *		  structure.
 * Input        : struct tag_hinic5_cqm_buf *buf
 *		  struct device *dev
 *		  bool direct: Whether direct remapping is required
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_buf_alloc(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf, bool direct)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 i;
	s32 ret = HINIC5_CQM_FAIL;

	ret = hinic5_cqm_buf_list_alloc(buf);
	if (unlikely(ret != HINIC5_CQM_SUCCESS))
		return ret;

	/* Page for applying for each buffer */
	ret = hinic5_cqm_buf_alloc_page(hinic5_cqm_handle, buf);
	if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(linux_hinic5_cqm_buf_alloc_page));
		goto err1;
	}

	/* PCI mapping of the buffer */
	ret = hinic5_cqm_buf_alloc_map(hinic5_cqm_handle, buf);
	if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(linux_hinic5_cqm_buf_alloc_map));
		goto err2;
	}

	/* direct remapping */
	ret = hinic5_cqm_buf_alloc_direct(hinic5_cqm_handle, buf, direct);
	if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_buf_alloc_direct));
		goto err3;
	}

	return HINIC5_CQM_SUCCESS;

err3:
	for (i = 0; i < buf->buf_number; i++)
		dma_unmap_single(hinic5_cqm_handle->dev, buf->buf_list[i].pa, buf->buf_size,
				 DMA_BIDIRECTIONAL);
err2:
	hinic5_cqm_buf_free_page(buf);
err1:
	vfree(buf->buf_list);
	buf->buf_list = NULL;
	return ret;
}

/**
 * Prototype    : hinic5_cqm_buf_free
 * Description  : Release the buffer space and DMA mapping for the struct tag_hinic5_cqm_buf
 *		  structure.
 * Input        : struct tag_hinic5_cqm_buf *buf
 *		  struct device *dev
 *		  bool direct: Whether direct remapping is required
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_buf_free(struct tag_hinic5_cqm_buf *buf, struct device *dev)
{
	u32 i;

	if (buf->direct.va) {
		vunmap(buf->direct.va);
		buf->direct.va = NULL;
	}

	// A secure mem buf doesn't need to call dma ummap and free pages.
	// see hinic5_cqm_cla_secure_mem_buf_alloc()
	if (buf->secure_mem_flag == HINIC5_CQM_SECURE_BUFFER_EN)
		goto free_buf_list;

	if (buf->buf_list) {
		for (i = 0; i < buf->buf_number; i++) {
			if (buf->buf_list[i].va)
				dma_unmap_single(dev, buf->buf_list[i].pa,
						 buf->buf_size,
						 DMA_BIDIRECTIONAL);
		}
		hinic5_cqm_buf_free_page(buf);
	}

free_buf_list:
	if (buf->buf_list) {
		vfree(buf->buf_list);
		buf->buf_list = NULL;
	}
}

#else /* __WIN__ */

static s32 hinic5_cqm_buf_alloc_page(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct huge_buf_addr *bufs_addr = NULL;
	u32 total_size;
	u32 i;

	total_size = buf->buf_size * buf->buf_number;

	buf->huge_buf_number = (total_size / HINIC5_CQM_HUGE_BUF_SIZE) +
			       ((total_size % HINIC5_CQM_HUGE_BUF_SIZE) ? 1 : 0);
	if (!buf->huge_buf_number) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(buf->huge_buf_number));
		return HINIC5_CQM_FAIL;
	}

	buf->bufs_addr = vmalloc(buf->huge_buf_number *
				 sizeof(struct huge_buf_addr));
	if (!buf->bufs_addr) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(bufs_addr));
		return HINIC5_CQM_FAIL;
	}
	memset(buf->bufs_addr, 0,
		buf->huge_buf_number * sizeof(struct huge_buf_addr));

	bufs_addr = buf->bufs_addr;
	for (i = 0; i < buf->huge_buf_number; i++) {
		if ((i + 1) == buf->huge_buf_number)
			bufs_addr[i].huge_buf_size =
			    PAGE_SIZE <<
			    get_order(total_size - HINIC5_CQM_HUGE_BUF_SIZE * i);
		else
			bufs_addr[i].huge_buf_size = HINIC5_CQM_HUGE_BUF_SIZE;

		bufs_addr[i].huge_buf_vaddr =
			__get_free_pages(GFP_KERNEL | __GFP_ZERO,
					 get_order(bufs_addr[i].huge_buf_size));
		if (!bufs_addr[i].huge_buf_vaddr) {
			hinic5_cqm_err(handle->dev_hdl,
				HINIC5_CQM_ALLOC_FAIL(huge_buf_vaddr));
			break;
		}
	}

	/* exception processing */
	if (i != buf->huge_buf_number) {
		i--;
		for (; i >= 0; i--) {
			free_pages((ulong)(buf->bufs_addr[i].huge_buf_vaddr),
				   get_order(buf->bufs_addr[i].huge_buf_size));
			buf->bufs_addr[i].huge_buf_vaddr = NULL;
		}

		vfree(buf->bufs_addr);
		buf->bufs_addr = NULL;
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_buf_alloc_map(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct device *dev = hinic5_cqm_handle->dev;
	struct huge_buf_addr *bufs_addr = NULL;
	u32 i;

	bufs_addr = buf->bufs_addr;
	for (i = 0; i < buf->huge_buf_number; i++) {
		bufs_addr[i].huge_buf_paddr = dma_map_single(dev, bufs_addr[i].huge_buf_vaddr,
							     bufs_addr[i].huge_buf_size,
							     DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, bufs_addr[i].huge_buf_paddr)) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(huge_buf_paddr));
			break;
		}
	}

	if (i != buf->huge_buf_number) {
		i--;
		for (; i >= 0; i--)
			dma_unmap_single(dev, bufs_addr[i].huge_buf_paddr,
					 bufs_addr[i].huge_buf_size,
					 DMA_BIDIRECTIONAL);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

s32 hinic5_cqm_buf_alloc(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf, bool direct)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct huge_buf_addr *bufs_addr = NULL;
	u32 cnt;
	u32 i;
	s32 j = 0;

	if (buf->buf_size > HINIC5_CQM_HUGE_BUF_SIZE) {
		hinic5_cqm_err(handle->dev_hdl, "Buffer size(0x%x) is large than huge buffer size(0x%x)\n",
			buf->buf_size, HINIC5_CQM_HUGE_BUF_SIZE);
		return HINIC5_CQM_FAIL;
	}

	/* Applying for the buffer list descriptor space */
	buf->buf_list = vmalloc(buf->buf_number * sizeof(struct tag_hinic5_cqm_buf_list));
	if (unlikely(buf->buf_list == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(win_buf_list));
		return HINIC5_CQM_FAIL;
	}
	memset(buf->buf_list,
		0, buf->buf_number * sizeof(struct tag_hinic5_cqm_buf_list));

	/* Page for applying for each buffer */
	if (hinic5_cqm_buf_alloc_page(hinic5_cqm_handle, buf) == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(win_hinic5_cqm_buf_alloc_page));
		goto err1;
	}

	/* PCI mapping of the buffer */
	if (hinic5_cqm_buf_alloc_map(hinic5_cqm_handle, buf) == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(win_hinic5_cqm_buf_alloc_map));
		goto err2;
	}

	/* Assign a value to the buffer list space. */
	for (i = 0; i < buf->buf_number; i++) {
		bufs_addr = &buf->bufs_addr[j];
		cnt = bufs_addr->huge_buf_size / buf->buf_size;
		buf->buf_list[i].va = (void *)((u64)bufs_addr->huge_buf_vaddr +
					       buf->buf_size * (i % cnt));
		buf->buf_list[i].pa = bufs_addr->huge_buf_paddr +
				      buf->buf_size * (i % cnt);

		if (0 == ((i + 1) % cnt))
			j++;
	}

	return HINIC5_CQM_SUCCESS;

err2:
	for (i = 0; i < buf->huge_buf_number; i++) {
		free_pages((ulong)(buf->bufs_addr[i].huge_buf_vaddr),
			   get_order(buf->bufs_addr[i].huge_buf_size));
		buf->bufs_addr[i].huge_buf_vaddr = NULL;
	}

	vfree(buf->bufs_addr);
	buf->bufs_addr = NULL;

err1:
	vfree(buf->buf_list);
	buf->buf_list = NULL;
	return HINIC5_CQM_FAIL;
}

void hinic5_cqm_buf_free(struct tag_hinic5_cqm_buf *buf, struct device *dev)
{
	u32 i;

	if (buf->bufs_addr) {
		for (i = 0; i < buf->huge_buf_number; i++) {
			dma_unmap_single(dev, buf->bufs_addr[i].huge_buf_paddr,
					 buf->bufs_addr[i].huge_buf_size,
					 DMA_BIDIRECTIONAL);
			free_pages((ulong)(buf->bufs_addr[i].huge_buf_vaddr),
				   get_order(buf->bufs_addr[i].huge_buf_size));
			buf->bufs_addr[i].huge_buf_paddr = 0;
			buf->bufs_addr[i].huge_buf_vaddr = NULL;
		}
		vfree(buf->bufs_addr);
		buf->bufs_addr = NULL;
	}

	if (buf->buf_list) {
		vfree(buf->buf_list);
		buf->buf_list = NULL;
	}
}

#endif /* __WIN__ */

static s32 hinic5_cqm_cla_cache_invalid_cmd(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				     struct tag_hinic5_cqm_cmd_buf *buf_in,
				     hinic5_cqm_cla_cache_invalid_cmd_s *cmd_info)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	s32 ret;
	u8 cmd;

	hinic5_cqm_handle->cmdq_ops->prepare_cmd_cache_invalidate(cmd_info, buf_in, &cmd);

	/* Send the cmdq command. */
	ret = hinic5_cqm_send_cmd_box((void *)(hinic5_cqm_handle->ex_handle), HINIC5_CQM_MOD_HINIC5_CQM,
			       cmd, buf_in, NULL, NULL,
			       HINIC5_CQM_CMD_TIMEOUT, HINIC5_CHANNEL_DEFAULT);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_send_cmd_box));
		hinic5_cqm_err(handle->dev_hdl,
			"Cla cache invalid: hinic5_cqm_send_cmd_box_ret=%d\n",
			ret);
		hinic5_cqm_err(handle->dev_hdl,
			"Cla cache invalid: cla_cache_invalid_cmd: 0x%x 0x%x 0x%x\n",
			cmd_info->gpa_h, cmd_info->gpa_l, cmd_info->cache_size);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_cla_cache_invalid_all_smf(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					 struct tag_hinic5_cqm_cmd_buf *buf_in,
					 hinic5_cqm_cla_cache_invalid_cmd_s *cmd)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	u32 i;
	s32 ret = HINIC5_CQM_FAIL;

	for (i = 0; i < func_cap->smf_max_num; i++) {
		if ((func_cap->smf_pg & (1U << i)) != 0) {
			cmd->smf_id = i;
			ret = hinic5_cqm_cla_cache_invalid_cmd(hinic5_cqm_handle, buf_in, cmd);
			if (ret != HINIC5_CQM_SUCCESS)
				return ret;
		}
	}
	return ret;
}

s32 hinic5_cqm_cla_cache_invalid(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, dma_addr_t pa, u32 cache_size)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_cmd_buf *buf_in = NULL;
	struct hinic5_func_attr *func_attr = NULL;
	struct tag_hinic5_cqm_bat_entry_vf2pf gpa = {0};
	hinic5_cqm_cla_cache_invalid_cmd_s cmd;
	u32 cla_gpa_h = 0;
	s32 ret = HINIC5_CQM_FAIL;

	buf_in = hinic5_cqm_cmd_alloc((void *)(hinic5_cqm_handle->ex_handle));
	if (unlikely(buf_in == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(buf_in));
		return HINIC5_CQM_FAIL;
	}

	gpa.cla_gpa_h = HINIC5_CQM_ADDR_HI(pa) & HINIC5_CQM_CHIP_GPA_HIMASK;
	gpa.acs_spu_en = hinic5_cqm_get_acs_spu_en(hinic5_cqm_handle);

	/* In non-fake mode, set func_id to 0xffff.
	 * Indicate the current func fake mode.
	 * The value of func_id is a fake func ID.
	 */
	if (HINIC5_CQM_IS_FAKE_CHILD_AGENT(hinic5_cqm_handle)) {
		cmd.func_id = hinic5_cqm_handle->func_attribute.func_global_idx;
		func_attr = &hinic5_cqm_handle->parent_hinic5_cqm_handle->func_attribute;
		gpa.fake_vf_en = 1;
		gpa.pf_id = func_attr->func_global_idx;
	} else {
		cmd.func_id = 0xffff;
	}
	memcpy(&cla_gpa_h, &gpa, sizeof(u32));

	/* Fill command and convert it to big endian */
	cmd.cache_size = cache_size;
	cmd.gpa_l = HINIC5_CQM_ADDR_LW(pa);
	cmd.gpa_h = cla_gpa_h;

	/* The normal mode is the 1822 traditional mode and is all configured
	 * on SMF0.
	 */
	/* Mode 0 is hashed to 4 SMF engines (excluding PPF) by func ID. */
	if (HINIC5_CQM_IS_LB_MODE_NORMAL(hinic5_cqm_handle) ||
	    (HINIC5_CQM_IS_LB_MODE_0(hinic5_cqm_handle) && !HINIC5_CQM_IS_PPF(hinic5_cqm_handle))) {
		cmd.smf_id = hinic5_cqm_funcid2smfid(hinic5_cqm_handle);
		ret = hinic5_cqm_cla_cache_invalid_cmd(hinic5_cqm_handle, buf_in, &cmd);
	/* Mode 1/2 are allocated to 4 SMF engines by flow. Therefore,
	 * one function needs to be allocated to 4 SMF engines.
	 */
	/* The PPF in mode 0 needs to be configured on 4 engines,
	 * and the timer resources need to be shared by the 4 engines.
	 */
	} else if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle) ||
		   (HINIC5_CQM_IS_LB_MODE_0(hinic5_cqm_handle) && HINIC5_CQM_IS_PPF(hinic5_cqm_handle))) {
		ret = hinic5_cqm_cla_cache_invalid_all_smf(hinic5_cqm_handle, buf_in, &cmd);
	} else {
		hinic5_cqm_err(handle->dev_hdl, "Cla cache invalid: unsupport lb mode=%u\n", hinic5_cqm_handle->func_capability.lb_mode);
		ret = HINIC5_CQM_FAIL;
	}

	hinic5_cqm_cmd_free((void *)(hinic5_cqm_handle->ex_handle), buf_in);
	return ret;
}

static void free_cache_inv(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf,
			   s32 *inv_flag)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 order;
	u32 i;

	order = (u32)get_order(buf->buf_size);

	if (!hinic5_is_chip_present(handle))
		return;

	if (!buf->buf_list)
		return;

	for (i = 0; i < buf->buf_number; i++) {
		if (!buf->buf_list[i].va)
			continue;

		if (*inv_flag != HINIC5_CQM_SUCCESS)
			continue;

		/* In the Pangea environment, if the cmdq times out,
		 * no subsequent message is sent.
		 */
		*inv_flag = hinic5_cqm_cla_cache_invalid(hinic5_cqm_handle, buf->buf_list[i].pa,
						  (u32)(PAGE_SIZE << order));
		if (*inv_flag != HINIC5_CQM_SUCCESS)
			hinic5_cqm_err(handle->dev_hdl,
				"Buffer free: fail to invalid buf_list pa cache, inv_flag=%d\n",
				*inv_flag);
	}
}

void hinic5_cqm_buf_free_cache_inv(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf,
			    s32 *inv_flag)
{
	if (!COMM_SUPPORT_SMF_CACHE_INVALID(hinic5_cqm_handle->ex_handle)) {
		/* Send a command to the chip to kick out the cache. */
		free_cache_inv(hinic5_cqm_handle, buf, inv_flag);
	}

	/* Clear host resources */
	hinic5_cqm_buf_free(buf, hinic5_cqm_handle->dev);
}

#define bitmap_section

/**
 * Prototype    : hinic5_cqm_single_bitmap_init
 * Description  : Initialize a bitmap.
 * Input        : struct tag_hinic5_cqm_bitmap *bitmap
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/9/9
 *   Modification : Created function
 */
static s32 hinic5_cqm_single_bitmap_init(struct tag_hinic5_cqm_bitmap *bitmap)
{
	u32 nbytes;

	spin_lock_init(&bitmap->lock);

	nbytes = BITS_TO_LONGS(bitmap->max_num) * sizeof(long);
	if (bitmap->bitmap_info.use_hinic5_vram != 0)
		bitmap->table = hinic5_hinic5_vram_kalloc(bitmap->bitmap_info.buf_hinic5_vram_name, nbytes);
	else
		bitmap->table = vmalloc(nbytes);

	if (unlikely(bitmap->table == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(bitmap->table));
		return HINIC5_CQM_FAIL;
	}

	memset(bitmap->table, 0, nbytes);

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_bitmap_toe_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;

	/* SRQC of TOE services is not managed through the CLA table,
	 * but the bitmap is required to manage SRQid.
	 */
	if (hinic5_cqm_handle->service[HINIC5_CQM_SERVICE_T_TOE].valid) {
		bitmap = &hinic5_cqm_handle->toe_own_capability.srqc_bitmap;
		bitmap->max_num =
		    hinic5_cqm_handle->toe_own_capability.toe_srqc_number;
		bitmap->reserved_top = 0;
		bitmap->reserved_back = 0;
		bitmap->last = 0;
		if (bitmap->max_num == 0) {
			hinic5_cqm_info(handle->dev_hdl,
				 "Bitmap init: toe_srqc_number=0, don't init bitmap\n");
			return HINIC5_CQM_SUCCESS;
		}

		if (hinic5_cqm_single_bitmap_init(bitmap) != HINIC5_CQM_SUCCESS)
			return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static void hinic5_cqm_bitmap_toe_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;

	if (hinic5_cqm_handle->service[HINIC5_CQM_SERVICE_T_TOE].valid) {
		bitmap = &hinic5_cqm_handle->toe_own_capability.srqc_bitmap;
		if (bitmap->table) {
			spin_lock_deinit(&bitmap->lock);
			vfree(bitmap->table);
			bitmap->table = NULL;
		}
	}
}

static s32 hinic5_cqm_bitmap_init_by_type(u32 type, struct tag_hinic5_cqm_bitmap *bitmap, struct tag_hinic5_cqm_func_capability *capability)
{
	switch (type) {
	case HINIC5_CQM_BAT_ENTRY_T_QPC:
		bitmap->max_num = capability->qpc_number;
		bitmap->reserved_top = capability->qpc_reserved;
		bitmap->reserved_back = capability->qpc_reserved_back;
		bitmap->last = capability->qpc_reserved;
		bitmap->bitmap_info.use_hinic5_vram = get_use_hinic5_vram_flag();
		break;
	case HINIC5_CQM_BAT_ENTRY_T_MPT:
		bitmap->max_num = capability->mpt_number;
		bitmap->reserved_top = capability->mpt_reserved;
		bitmap->reserved_back = capability->mpt_reserved_back;
		bitmap->last = capability->mpt_reserved;
		break;
	case HINIC5_CQM_BAT_ENTRY_T_SCQC:
		bitmap->max_num = capability->scqc_number;
		bitmap->reserved_top = capability->scq_reserved;
		bitmap->reserved_back = capability->scq_reserved_back;
		bitmap->last = capability->scq_reserved;
		break;
	case HINIC5_CQM_BAT_ENTRY_T_SRQC:
		bitmap->max_num = capability->srqc_number;
		bitmap->reserved_top = capability->srq_reserved;
		bitmap->reserved_back = capability->srq_reserved_back;
		bitmap->last = capability->srq_reserved;
		break;
	default:
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}


/**
 * Prototype    : hinic5_cqm_bitmap_init
 * Description  : Initialize the bitmap.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_bitmap_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *capability = &hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	s32 ret = HINIC5_CQM_SUCCESS;
	u32 i;
	int err;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->obj_num == 0) {
			hinic5_cqm_info(handle->dev_hdl, "Cla alloc: cla_type %u, obj_num=0, don't init bitmap\n", cla_table->type);
			continue;
		}

		bitmap = &cla_table->bitmap;
		err = snprintf(bitmap->bitmap_info.buf_hinic5_vram_name,
			       HINIC5_VRAM_NAME_MAX_LEN, "%s%s%02u", cla_table->name,
			       HINIC5_VRAM_HINIC5_CQM_BITMAP_BASE, cla_table->type);
		if (err < 0) {
			hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm bitmap hinic5_vram name snprintf_s failed");
			return HINIC5_CQM_FAIL;
		}

		if (hinic5_cqm_bitmap_init_by_type(cla_table->type, bitmap, capability) == HINIC5_CQM_SUCCESS) {
			hinic5_cqm_info(handle->dev_hdl, "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
				cla_table->type, bitmap->max_num);
			ret = hinic5_cqm_single_bitmap_init(bitmap);
		}

		if (ret != HINIC5_CQM_SUCCESS) {
			hinic5_cqm_err(handle->dev_hdl, "Bitmap init: failed to init cla_table_type=%u, obj_num=0x%x\n",
				cla_table->type, cla_table->obj_num);
			goto err;
		}
	}

	if (hinic5_cqm_bitmap_toe_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS)
		goto err;

	return HINIC5_CQM_SUCCESS;

err:
	hinic5_cqm_bitmap_uninit(hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

static void hinic5_cqm_bitmap_table_free(struct tag_hinic5_cqm_bitmap *bitmap)
{
	if (bitmap->bitmap_info.use_hinic5_vram != 0)
		hinic5_hinic5_vram_kfree(bitmap->table, bitmap->bitmap_info.buf_hinic5_vram_name,
			      BITS_TO_LONGS(bitmap->max_num) * sizeof(long));
	else
		vfree(bitmap->table);
	bitmap->table = NULL;
}

/**
 * Prototype    : hinic5_cqm_bitmap_uninit
 * Description  : Deinitialize the bitmap.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_bitmap_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	u32 i;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		bitmap = &cla_table->bitmap;
		if (cla_table->type != HINIC5_CQM_BAT_ENTRY_T_INVALID) {
			if (bitmap->table) {
				spin_lock_deinit(&bitmap->lock);
				hinic5_cqm_bitmap_table_free(bitmap);
			}
		}
	}

	hinic5_cqm_bitmap_toe_uninit(hinic5_cqm_handle);
}

/**
 * Prototype	: hinic5_cqm_bitmap_check_range
 * Description	: Starting from begin, check whether the bits in number of count
 *		  are idle in the table. Requirement:
 *		  1. This group of bits cannot cross steps.
 *		  2. This group of bits must be 0.
 * Input	: const ulong *table,
 *		  u32 step,
 *		  u32 max_num,
 *		  u32 begin,
 *		  u32 count
 * Output	: None
 * Return Value : u32
 * 1.Date	  : 2015/4/15
 *   Modification : Created function
 */
static u32 hinic5_cqm_bitmap_check_range(const ulong *table, u32 step, u32 max_num, u32 begin,
				  u32 count)
{
	u32 end = (begin + (count - 1));
	u32 i;

	/* Single-bit check is not performed. */
	if (count == 1)
		return begin;

	/* The end value exceeds the threshold. */
	if (end >= max_num)
		return max_num;

	/* Bit check, the next bit is returned when a non-zero bit is found. */
	for (i = (begin + 1); i <= end; i++) {
		if (test_bit((int)i, table))
			return i + 1;
	}

	/* Check whether it's in different steps. */
	if ((begin & (~(step - 1))) != (end & (~(step - 1))))
		return (end & (~(step - 1)));

	/* If the check succeeds, begin is returned. */
	return begin;
}

static void hinic5_cqm_bitmap_find(struct tag_hinic5_cqm_bitmap *bitmap, u32 *index, u32 last,
			    u32 step, u32 count)
{
	u32 last_num = last;
	u32 max_num = bitmap->max_num - bitmap->reserved_back;
	ulong *table = bitmap->table;

	do {
		*index = (u32)find_next_zero_bit(table, max_num, last_num);
		if (*index < max_num)
			last_num = hinic5_cqm_bitmap_check_range(table, step, max_num,
							  *index, count);
		else
			break;
	} while (last_num != *index);
}

static u32 hinic5_cqm_bitmap_find_with_lowbits_forward(struct tag_hinic5_cqm_bitmap *bitmap,
						u32 start, u32 end, u32 lowbits, u32 lowbits_mask)
{
	ulong *table = bitmap->table;
	u32 offset = start;
	u32 index = HINIC5_CQM_INDEX_INVALID;

	while (offset < end) {
		index = (u32)find_next_zero_bit(table, end, offset);
		if (index >= end)
			return HINIC5_CQM_INDEX_INVALID;

		if ((index & lowbits_mask) == lowbits) /* match lowbits */
			break;

		offset = index + 1;
		if (offset == end)
			return HINIC5_CQM_INDEX_INVALID;
	}

	return index;
}

static inline u32 find_next_zero_bit_reverse(const unsigned long *addr, u32 end, u32 start)
{
	u32 i;

	for (i = start; i > end; i--) {
		if (test_bit(i, addr) == 0)
			return i;
	}

	return i;
}

static u32 hinic5_cqm_bitmap_find_with_lowbits_reverse(struct tag_hinic5_cqm_bitmap *bitmap,
						u32 start, u32 end, u32 lowbits, u32 lowbits_mask)
{
	ulong *table = bitmap->table;
	u32 offset = start;
	u32 index = HINIC5_CQM_INDEX_INVALID;

	while (offset > end) {
		index = (u32)find_next_zero_bit_reverse(table, end, offset);
		if (index <= end)
			return HINIC5_CQM_INDEX_INVALID;

		if ((index & lowbits_mask) == lowbits) /* match lowbits */
			break;

		offset = index - 1;
		if (offset == end)
			return HINIC5_CQM_INDEX_INVALID;
	}

	return index;
}

/* search range is [start, end) or (end, start] */
static u32 hinic5_cqm_bitmap_find_with_lowbits_align(struct tag_hinic5_cqm_bitmap *bitmap,
					      u32 start, u32 end, u32 xid)
{
	u32 lowbits_mode = HINIC5_CQM_DYNAMIC_XID_LB_MODE(xid);
	u32 lowbits_mask = HINIC5_CQM_DYNAMIC_XID_LOW_BIT_MASK(lowbits_mode);
	u32 lowbits = (HINIC5_CQM_DYNAMIC_XID_LOW_BITS(xid) & lowbits_mask);
	u32 index;

	if (start <= end)
		index = hinic5_cqm_bitmap_find_with_lowbits_forward(bitmap, start, end,
							     lowbits, lowbits_mask);
	else
		index = hinic5_cqm_bitmap_find_with_lowbits_reverse(bitmap, start, end,
							     lowbits, lowbits_mask);

	return index;
}

/**
 * Prototype	: hinic5_cqm_bitmap_alloc
 * Description	: Apply for a bitmap index. 0 and 1 must be left blank.
 *		  Scan backwards from where you last applied.
 *		  A string of consecutive indexes must be applied for and
 *		  cannot be applied for across trunks.
 * Input	: struct tag_hinic5_cqm_bitmap *bitmap,
 *		  u32 step,
 *		  u32 count
 * Output	: None
 * Return Value : u32
 *		  The obtained index is returned.
 *		  If a failure occurs, the value of max is returned.
 * 1.Date	  : 2015/4/15
 *   Modification : Created function
 */
u32 hinic5_cqm_bitmap_alloc(struct tag_hinic5_cqm_bitmap *bitmap, u32 step, u32 count, bool update_last)
{
	u32 index = 0;
	u32 max_num = bitmap->max_num - bitmap->reserved_back;
	u32 last = bitmap->last;
	ulong *table = bitmap->table;
	u32 i;

	spin_lock(&bitmap->lock);

	/* Search for an idle bit from the last position. */
	hinic5_cqm_bitmap_find(bitmap, &index, last, step, count);

	/* The preceding search fails. Search for an idle bit
	 * from the beginning.
	 */
	if (index >= max_num) {
		last = bitmap->reserved_top;
		hinic5_cqm_bitmap_find(bitmap, &index, last, step, count);
	}

	/* Set the found bit to 1 and reset last. */
	if (index < max_num) {
		for (i = index; i < (index + count); i++)
			set_bit(i, table);

		if (update_last) {
			bitmap->last = (index + count);
			if (bitmap->last >= max_num)
				bitmap->last = bitmap->reserved_top;
		}
	}

	spin_unlock(&bitmap->lock);
	return index;
}

/**
 * Prototype	: hinic5_cqm_bitmap_alloc_lowbits_align
 * Description	: Apply for a bitmap index with lowbits align.
 *		  Scan backwards from where you last applied if search all range.
 *		  A string of consecutive indexes must be applied for and
 *		  cannot be applied for across trunks.
 * Input	: struct tag_hinic5_cqm_bitmap *bitmap,
 *		  struct tag_hinic5_cqm_bitmap_range *bp_range,
 *		  struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
 *		  u32 xid,
 *		  bool update_last
 * Output	: None
 * Return Value : u32
 *		  The obtained index is returned.
 *		  If a failure occurs, the value of invalid_index is returned.
 * 1.Date	  : 2015/4/15
 *   Modification : Created function
 */
u32 hinic5_cqm_bitmap_alloc_lowbits_align(struct tag_hinic5_cqm_bitmap *bitmap,
				   struct tag_hinic5_cqm_bitmap_range *bp_range,
				   struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 xid, bool update_last)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	ulong *table = bitmap->table;
	u32 search_mode = HINIC5_CQM_DYNAMIC_XID_SEARCH_MODE(xid);
	u32 max_num = bitmap->max_num - bitmap->reserved_back;
	u32 index, last;

	spin_lock(&bitmap->lock);

	/* unsupport reverse search when search all range of bitmap */
	if (search_mode == HINIC5_CQM_XID_SEARCH_ALL) {
		last = bitmap->last;
		/* Search for an idle bit from the last position. */
		index = hinic5_cqm_bitmap_find_with_lowbits_align(bitmap, last, max_num, xid);
		/* The preceding search fails. Search for an idle bit from the beginning. */
		if (index == HINIC5_CQM_INDEX_INVALID) {
			last = bitmap->reserved_top;
			index = hinic5_cqm_bitmap_find_with_lowbits_align(bitmap, last, max_num, xid);
		}
	} else {
		if (HINIC5_CQM_BP_RANGE_VALID(bp_range->start, bp_range->end,
				       bitmap->reserved_top, max_num) == 0) {
			hinic5_cqm_err(handle->dev_hdl,
				"Bitmap alloc: range invalid, start=0x%x, end=0x%x, min=0x%x, max=0x%x\n",
				bp_range->start, bp_range->end, bitmap->reserved_top, max_num);
			spin_unlock(&bitmap->lock);
			return HINIC5_CQM_INDEX_INVALID;
		}
		index = hinic5_cqm_bitmap_find_with_lowbits_align(bitmap, bp_range->start, bp_range->end,
							   xid);
	}

	/* Set the found bit to 1 and reset last. */
	if (index != HINIC5_CQM_INDEX_INVALID) {
		set_bit(index, table);

		if (update_last && search_mode == HINIC5_CQM_XID_SEARCH_ALL) {
			bitmap->last = index + 1;
			if (bitmap->last >= max_num)
				bitmap->last = bitmap->reserved_top;
		}
	}

	spin_unlock(&bitmap->lock);
	return index;
}

static inline void bitmap_set_table(struct tag_hinic5_cqm_bitmap *bitmap, ulong *table, u32 *ret_index, u32 index)
{
	spin_lock(&bitmap->lock);
	if (test_bit((int)index, table)) {
		*ret_index = HINIC5_CQM_INDEX_INVALID;
	} else {
		set_bit(index, table);
		*ret_index = index;
	}
	spin_unlock(&bitmap->lock);
}

/**
 * Prototype	: hinic5_cqm_bitmap_alloc_reserved
 * Description	: Reserve bit applied for based on index.
 * Input	: struct tag_hinic5_cqm_bitmap *bitmap,
 *		  u32 count,
 *		  u32 index
 * Output	: None
 * Return Value : u32
 *		  The obtained index is returned.
 *		  If a failure occurs, the value of max is returned.
 * 1.Date	   : 2015/4/15
 *    Modification : Created function
 */
u32 hinic5_cqm_bitmap_alloc_reserved(struct tag_hinic5_cqm_bitmap *bitmap, u32 count, u32 index)
{
	u32 ret_index;

	if (index >= bitmap->max_num || count != 1)
		return HINIC5_CQM_INDEX_INVALID;

	if (index >= bitmap->reserved_top && (index < bitmap->max_num - bitmap->reserved_back))
		return HINIC5_CQM_INDEX_INVALID;

	bitmap_set_table(bitmap, bitmap->table, &ret_index, index);
	return ret_index;
}

u32 hinic5_cqm_bitmap_alloc_by_xid(struct tag_hinic5_cqm_bitmap *bitmap, u32 count, u32 index)
{
	u32 ret_index;

	if (index >= bitmap->max_num || count != 1)
		return HINIC5_CQM_INDEX_INVALID;
	bitmap_set_table(bitmap, bitmap->table, &ret_index, index);
	return ret_index;
}

/**
 * Prototype	: hinic5_cqm_bitmap_free
 * Description	: Releases a bitmap index.
 * Input	: struct tag_hinic5_cqm_bitmap *bitmap,
 *		  u32 index,
 *		  u32 count
 * Output	: None
 * Return Value : void
 * 1.Date	  : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_bitmap_free(struct tag_hinic5_cqm_bitmap *bitmap, u32 index, u32 count)
{
	u32 i;

	spin_lock(&bitmap->lock);

	for (i = index; i < (index + count); i++)
		clear_bit((s32)i, bitmap->table);

	spin_unlock(&bitmap->lock);
}

#define obj_table_section

/**
 * Prototype    : hinic5_cqm_single_object_table_init
 * Description  : Initialize a object table.
 * Input        : struct tag_hinic5_cqm_object_table *obj_table
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/9/9
 *   Modification : Created function
 */
static s32 hinic5_cqm_single_object_table_init(struct tag_hinic5_cqm_object_table *obj_table)
{
	rwlock_init(&obj_table->lock);

	obj_table->table = vmalloc(obj_table->max_num * sizeof(void *));
	if (unlikely(obj_table->table == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(table));
		return HINIC5_CQM_FAIL;
	}
	memset(obj_table->table, 0, obj_table->max_num * sizeof(void *));
	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_object_table_init
 * Description  : Initialize the association table between objects and indexes.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_object_table_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *capability = &hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object_table *obj_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	s32 ret = HINIC5_CQM_SUCCESS;
	u32 i;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->obj_num == 0) {
			hinic5_cqm_info(handle->dev_hdl,
				 "Obj table init: cla_table_type %u, obj_num=0, don't init obj table\n",
				 cla_table->type);
			continue;
		}

		obj_table = &cla_table->obj_table;

		switch (cla_table->type) {
		case HINIC5_CQM_BAT_ENTRY_T_QPC:
			obj_table->max_num = capability->qpc_number;
			ret = hinic5_cqm_single_object_table_init(obj_table);
			break;
		case HINIC5_CQM_BAT_ENTRY_T_MPT:
			obj_table->max_num = capability->mpt_number;
			ret = hinic5_cqm_single_object_table_init(obj_table);
			break;
		case HINIC5_CQM_BAT_ENTRY_T_SCQC:
			obj_table->max_num = capability->scqc_number;
			ret = hinic5_cqm_single_object_table_init(obj_table);
			break;
		case HINIC5_CQM_BAT_ENTRY_T_SRQC:
			obj_table->max_num = capability->srqc_number;
			ret = hinic5_cqm_single_object_table_init(obj_table);
			break;
		default:
			break;
		}

		if (ret != HINIC5_CQM_SUCCESS) {
			hinic5_cqm_err(handle->dev_hdl,
				"Obj table init: failed to init cla_table_type=%u, obj_num=0x%x\n",
				cla_table->type, cla_table->obj_num);
			goto err;
		}
	}

	return HINIC5_CQM_SUCCESS;

err:
	hinic5_cqm_object_table_uninit(hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_object_table_uninit
 * Description  : Deinitialize the association table between objects and
 *		  indexes.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_object_table_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_object_table *obj_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	u32 i;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		obj_table = &cla_table->obj_table;
		if (cla_table->type != HINIC5_CQM_BAT_ENTRY_T_INVALID) {
			if (obj_table->table) {
				rwlock_deinit(&obj_table->lock);
				vfree(obj_table->table);
				obj_table->table = NULL;
			}
		}
	}
}

/**
 * Prototype    : hinic5_cqm_object_table_insert
 * Description  : Insert an object
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 *		  struct tag_hinic5_cqm_object_table *object_table
 *		  u32 index
 *		  struct tag_hinic5_cqm_object *obj
 *		  bool bh
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_object_table_insert(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			    struct tag_hinic5_cqm_object_table *object_table,
			    u32 index, struct tag_hinic5_cqm_object *obj, bool bh)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	if (index >= object_table->max_num) {
		hinic5_cqm_err(handle->dev_hdl,
			"Obj table insert: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_write_lock(&object_table->lock, bh);

	if (!object_table->table[index]) {
		object_table->table[index] = obj;
		hinic5_cqm_write_unlock(&object_table->lock, bh);
		return HINIC5_CQM_SUCCESS;
	}

	hinic5_cqm_write_unlock(&object_table->lock, bh);
	hinic5_cqm_err(handle->dev_hdl,
		"Obj table insert: object_table->table[0x%x] has been inserted\n",
		index);

	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_object_table_remove
 * Description  : Remove an object
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 *		  struct tag_hinic5_cqm_object_table *object_table
 *		  u32 index
 *		  const struct tag_hinic5_cqm_object *obj
 *		  bool bh
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_object_table_remove(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			     struct tag_hinic5_cqm_object_table *object_table,
			     u32 index, const struct tag_hinic5_cqm_object *obj, bool bh)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	if (index >= object_table->max_num) {
		hinic5_cqm_err(handle->dev_hdl,
			"Obj table remove: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return;
	}

	hinic5_cqm_write_lock(&object_table->lock, bh);

	if (object_table->table[index] && object_table->table[index] == obj)
		object_table->table[index] = NULL;
	else
		hinic5_cqm_err(handle->dev_hdl,
			"Obj table remove: object_table->table[0x%x] has been removed\n",
			index);

	hinic5_cqm_write_unlock(&object_table->lock, bh);
}

/**
 * Prototype    : hinic5_cqm_object_table_get
 * Description  : Remove an object
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 *		  struct tag_hinic5_cqm_object_table *object_table
 *		  u32 index
 *		  bool bh
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_object *obj
 * 1.Date         : 2018/6/20
 *   Modification : Created function
 */
struct tag_hinic5_cqm_object *hinic5_cqm_object_table_get(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					    struct tag_hinic5_cqm_object_table *object_table,
					    u32 index, bool bh)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object *obj = NULL;

	if (index >= object_table->max_num) {
		hinic5_cqm_err(handle->dev_hdl,
			"Obj table get: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return NULL;
	}

	hinic5_cqm_read_lock(&object_table->lock, bh);

	obj = object_table->table[index];
	if (obj)
		atomic_inc(&obj->refcount);

	hinic5_cqm_read_unlock(&object_table->lock, bh);

	return obj;
}
