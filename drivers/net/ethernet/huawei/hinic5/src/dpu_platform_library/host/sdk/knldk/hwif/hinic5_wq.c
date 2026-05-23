/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_wq.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "ossl_knl.h"
#include "hinic5_common.h"
#include "hinic5_hwdev.h"
#include "hinic5_wq.h"

#define WQ_MIN_DEPTH		64
#define WQ_MAX_DEPTH		65536
#define WQ_MAX_NUM_PAGES	(PAGE_SIZE / sizeof(u64))

static int wq_init_wq_block(struct hinic5_wq *wq)
{
	int i;

	if (WQ_IS_0_LEVEL_CLA(wq)) {
		wq->wq_block_paddr = wq->wq_pages[0].align_paddr;
		wq->wq_block_vaddr = wq->wq_pages[0].align_vaddr;

		return 0;
	}

	if (wq->num_wq_pages > WQ_MAX_NUM_PAGES) {
		sdk_err(wq->dev_hdl, "num_wq_pages exceed limit: %lu\n",
			WQ_MAX_NUM_PAGES);
		return -EFAULT;
	}

	wq->wq_block_vaddr = dma_zalloc_coherent(wq->dev_hdl, PAGE_SIZE,
						 &wq->wq_block_paddr,
						 GFP_KERNEL);
	if (!wq->wq_block_vaddr) {
		sdk_err(wq->dev_hdl, "Failed to alloc wq block\n");
		return -ENOMEM;
	}

	for (i = 0; i < wq->num_wq_pages; i++)
		wq->wq_block_vaddr[i] =
			cpu_to_be64(wq->wq_pages[i].align_paddr);

	return 0;
}

static int wq_alloc_pages(struct hinic5_wq *wq)
{
	int i, page_idx, err;
	u32 wqe_page_size_align = ALIGN(wq->wq_page_size, PAGE_SIZE);

	wq->wq_pages = kcalloc(wq->num_wq_pages, sizeof(*wq->wq_pages),
			       GFP_KERNEL);
	if (!wq->wq_pages)
		return -ENOMEM;

	for (page_idx = 0; page_idx < wq->num_wq_pages; page_idx++) {
		err = hinic5_dma_zalloc_coherent_align(wq->dev_hdl,
						       wqe_page_size_align,
						       wqe_page_size_align,
						       GFP_KERNEL,
						       &wq->wq_pages[page_idx]);
		if (err != 0) {
			sdk_err(wq->dev_hdl, "Failed to alloc wq page\n");
			goto free_wq_pages;
		}
	}

	err = wq_init_wq_block(wq);
	if (err != 0)
		goto free_wq_pages;

	return 0;

free_wq_pages:
	for (i = 0; i < page_idx; i++)
		hinic5_dma_free_coherent_align(wq->dev_hdl, &wq->wq_pages[i]);

	kfree(wq->wq_pages);
	wq->wq_pages = NULL;

	return -ENOMEM;
}

static void wq_free_pages(struct hinic5_wq *wq)
{
	int i;

	if (!WQ_IS_0_LEVEL_CLA(wq))
		dma_free_coherent(wq->dev_hdl, PAGE_SIZE, wq->wq_block_vaddr,
				  wq->wq_block_paddr);

	for (i = 0; i < wq->num_wq_pages; i++)
		hinic5_dma_free_coherent_align(wq->dev_hdl, &wq->wq_pages[i]);

	kfree(wq->wq_pages);
	wq->wq_pages = NULL;
}

int hinic5_wq_create(void *hwdev, struct hinic5_wq *wq, u32 q_depth,
		     u16 wqebb_size)
{
	struct hinic5_hwdev *dev = hwdev;
	u32 wq_page_size;

	if (!wq || !dev) {
		pr_err("Invalid wq or dev_hdl\n");
		return -EINVAL;
	}
	wq_page_size = dev->wq_page_size;  // make sure HINIC5_HW_WQ_PAGE_SIZE align

	if (q_depth < WQ_MIN_DEPTH || q_depth > WQ_MAX_DEPTH ||
	    ((q_depth & (q_depth - 1)) != 0) || wqebb_size == 0 ||
	    ((wqebb_size & (wqebb_size - 1)) != 0)) {
		sdk_err(dev->dev_hdl, "Wq q_depth(%u) or wqebb_size(%u) is invalid\n",
			q_depth, wqebb_size);
		return -EINVAL;
	}

	memset(wq, 0, sizeof(struct hinic5_wq));
	wq->dev_hdl = dev->dev_hdl;
	wq->q_depth = q_depth;
	wq->idx_mask = (u16)(q_depth - 1);
	wq->wqebb_size = wqebb_size;
	wq->wqebb_size_shift = (u16)ilog2(wq->wqebb_size);
	wq->wq_page_size = wq_page_size;

	wq->wqebbs_per_page = wq_page_size / wqebb_size;
	/* In case of wq_page_size is larger than q_depth * wqebb_size  */
	if (wq->wqebbs_per_page > q_depth)
		wq->wqebbs_per_page = q_depth;
	wq->wqebbs_per_page_shift = (u16)ilog2(wq->wqebbs_per_page);
	wq->wqebbs_per_page_mask = (u16)(wq->wqebbs_per_page - 1);
	wq->num_wq_pages = (u16)(ALIGN(((u32)q_depth * wqebb_size),
				       wq_page_size) / wq_page_size);

	return wq_alloc_pages(wq);
}
EXPORT_SYMBOL(hinic5_wq_create);

void hinic5_wq_destroy(struct hinic5_wq *wq)
{
	if (!wq)
		return;

	wq_free_pages(wq);
}
EXPORT_SYMBOL(hinic5_wq_destroy);
