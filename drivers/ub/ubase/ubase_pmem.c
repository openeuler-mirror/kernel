// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/math.h>
#include <ub/ubase/ubase_comm_dev.h>

#include "ubase_rct.h"
#include "ubase_pmem.h"

struct ubase_pmem_init_func {
	int (*init)(struct ubase_dev *udev);
	void (*uninit)(struct ubase_dev *udev);
};

static u16 ubase_calc_comm_page_cnt(struct ubase_dev *udev)
{
	u32 ta_timer_size = ubase_ta_timer_align_size(udev);
	u32 jfs_ctx_size = ubase_jfs_ctx_align_size(udev);

	return DIV_ROUND_UP(jfs_ctx_size + ta_timer_size, UBASE_PMEM_PAGE_SIZE);
}

static inline u16 ubase_calc_que_page_cnt(u32 que_num, u64 que_size)
{
	if (!que_size)
		return 0;

	return que_size > UBASE_PMEM_PAGE_SIZE ?
	       DIV_ROUND_UP(que_size * que_num, UBASE_PMEM_PAGE_SIZE) :
	       DIV_ROUND_UP(que_num, UBASE_PMEM_PAGE_SIZE / que_size);
}

static u16 ubase_calc_udma_page_cnt(struct ubase_dev *udev)
{
	struct ubase_adev_caps *udma_caps = &udev->caps.udma_caps;
	u32 rcq_size;

	rcq_size = ALIGN(udma_caps->rc_que_depth * UBASE_RCE_SIZE, PAGE_SIZE);

	return ubase_calc_que_page_cnt(udma_caps->rc_max_cnt, rcq_size);
}

static int ubase_init_pmem_ctx(struct ubase_dev *udev, const char *type,
			       struct ubase_pmem_ctx *ctx, u16 page_cnt)
{
	if (!page_cnt)
		return 0;

	ctx->pgs = kcalloc(page_cnt, sizeof(struct page *), GFP_KERNEL);
	if (!ctx->pgs) {
		ubase_err(udev, "failed to alloc mem for %s pgs.page_cnt=%u\n",
			  type, page_cnt);
		return -ENOMEM;
	}

	ctx->sg = kcalloc(page_cnt, sizeof(struct scatterlist), GFP_KERNEL);
	if (!ctx->sg) {
		ubase_err(udev, "failed to alloc mem for %s sg.page_cnt=%u\n",
			  type, page_cnt);
		goto free_pgs;
	}

	ctx->page_cnt = page_cnt;
	return 0;

free_pgs:
	kfree(ctx->pgs);
	return -ENOMEM;
}

static int ubase_init_comm_pmem_ctx(struct ubase_dev *udev)
{
	return ubase_init_pmem_ctx(udev, "comm", &udev->pmem_info.comm,
				   ubase_calc_comm_page_cnt(udev));
}

static int ubase_init_udma_pmem_ctx(struct ubase_dev *udev)
{
	return ubase_init_pmem_ctx(udev, "udma", &udev->pmem_info.udma,
				   ubase_calc_udma_page_cnt(udev));
}

static void ubase_uninit_pmem_ctx(struct ubase_pmem_ctx *ctx)
{
	if (!ctx->page_cnt)
		return;

	kfree(ctx->pgs);
	ctx->pgs = NULL;

	kfree(ctx->sg);
	ctx->sg = NULL;

	ctx->page_cnt = 0;
}

static void ubase_uninit_comm_pmem_ctx(struct ubase_dev *udev)
{
	ubase_uninit_pmem_ctx(&udev->pmem_info.comm);
}

static void ubase_uninit_udma_pmem_ctx(struct ubase_dev *udev)
{
	ubase_uninit_pmem_ctx(&udev->pmem_info.udma);
}

static int ubase_alloc_pmem(struct ubase_dev *udev, const char *type,
			    struct page **pgs, int page_cnt)
{
	int order = get_order(UBASE_PMEM_PAGE_SIZE);
	int i;

	for (i = 0; i < page_cnt; i++) {
		pgs[i] = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
		if (!pgs[i]) {
			ubase_err(udev,
				  "failed to alloc %s pages[%d], page_cnt = %d, order = %d.\n",
				  type, i, page_cnt, order);
			goto free_pgs;
		}
	}

	return 0;

free_pgs:
	for (i -= 1; i >= 0; i--)
		__free_pages(pgs[i], order);

	return -ENOMEM;
}

static int ubase_alloc_comm_pmem(struct ubase_dev *udev)
{
	struct ubase_pmem_ctx *ctx = &udev->pmem_info.comm;

	return ubase_alloc_pmem(udev, "comm", ctx->pgs, ctx->page_cnt);
}

static int ubase_alloc_udma_pmem(struct ubase_dev *udev)
{
	struct ubase_pmem_ctx *ctx = &udev->pmem_info.udma;

	return ubase_alloc_pmem(udev, "udma", ctx->pgs, ctx->page_cnt);
}

static void ubase_free_pmem(struct ubase_pmem_ctx *ctx)
{
	int order = get_order(UBASE_PMEM_PAGE_SIZE);
	u32 i;

	for (i = 0; i < ctx->page_cnt; i++)
		__free_pages(ctx->pgs[i], order);
}

static void ubase_free_comm_pmem(struct ubase_dev *udev)
{
	ubase_free_pmem(&udev->pmem_info.comm);
}

static void ubase_free_udma_pmem(struct ubase_dev *udev)
{
	ubase_free_pmem(&udev->pmem_info.udma);
}

static int ubase_map_pmem(struct ubase_dev *udev, const char *type,
			  struct ubase_pmem_ctx *ctx)
{
	struct scatterlist *iter;
	unsigned int nents;
	u32 i;

	if (!ctx->page_cnt)
		return 0;

	sg_init_table(ctx->sg, ctx->page_cnt);

	for_each_sg(ctx->sg, iter, ctx->page_cnt, i)
		sg_set_page(iter, ctx->pgs[i], UBASE_PMEM_PAGE_SIZE, 0);

	nents = dma_map_sg(udev->dev, ctx->sg, ctx->page_cnt, DMA_BIDIRECTIONAL);
	if (!nents) {
		ubase_err(udev, "failed to map %s pages, page_cnt = %u.\n",
			  type, ctx->page_cnt);
		return -ENOMEM;
	}

	ctx->dma_addr = sg_dma_address(&ctx->sg[0]);
	return 0;
}

static int ubase_map_comm_pmem(struct ubase_dev *udev)
{
	return ubase_map_pmem(udev, "comm", &udev->pmem_info.comm);
}

static int ubase_map_udma_pmem(struct ubase_dev *udev)
{
	struct ubase_pmem_caps *pmem = &udev->caps.udma_caps.pmem;
	int ret;

	ret = ubase_map_pmem(udev, "udma", &udev->pmem_info.udma);
	if (ret)
		return ret;

	pmem->dma_addr = udev->pmem_info.udma.dma_addr;
	pmem->dma_len = udev->pmem_info.udma.page_cnt * UBASE_PMEM_PAGE_SIZE;

	return 0;
}

static void ubase_unmap_pmem(struct ubase_dev *udev, struct ubase_pmem_ctx *ctx)
{
	if (!ctx->page_cnt)
		return;

	dma_unmap_sg(udev->dev, ctx->sg, ctx->page_cnt, DMA_BIDIRECTIONAL);

	ctx->dma_addr = 0;
}

static void ubase_unmap_comm_pmem(struct ubase_dev *udev)
{
	ubase_unmap_pmem(udev, &udev->pmem_info.comm);
}

static void ubase_unmap_udma_pmem(struct ubase_dev *udev)
{
	struct ubase_pmem_caps *pmem = &udev->caps.udma_caps.pmem;

	ubase_unmap_pmem(udev, &udev->pmem_info.udma);

	pmem->dma_addr = 0;
	pmem->dma_len = 0;
}

static const struct ubase_pmem_init_func ubase_pmem_init_map[] = {
	{
		.init = ubase_init_comm_pmem_ctx,
		.uninit = ubase_uninit_comm_pmem_ctx,
	},
	{
		.init = ubase_init_udma_pmem_ctx,
		.uninit = ubase_uninit_udma_pmem_ctx,
	},
	{
		.init = ubase_alloc_comm_pmem,
		.uninit = ubase_free_comm_pmem,
	},
	{
		.init = ubase_alloc_udma_pmem,
		.uninit = ubase_free_udma_pmem,
	},
	{
		.init = ubase_map_comm_pmem,
		.uninit = ubase_unmap_comm_pmem,
	},
	{
		.init = ubase_map_udma_pmem,
		.uninit = ubase_unmap_udma_pmem,
	},
};

static int __ubase_prealloc_mem_init(struct ubase_dev *udev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ubase_pmem_init_map); i++) {
		if (ubase_pmem_init_map[i].init(udev))
			goto init_fail;
	}

	return 0;

init_fail:
	for (i -= 1; i >= 0; i--)
		ubase_pmem_init_map[i].uninit(udev);

	return -ENOMEM;
}

static void ubase_reset_pmem(struct ubase_pmem_ctx *ctx)
{
	void *va;
	u32 i;

	for (i = 0; i < ctx->page_cnt; i++) {
		va = page_address(ctx->pgs[i]);
		memset(va, 0, UBASE_PMEM_PAGE_SIZE);
	}
}

static void ubase_prealloc_mem_reinit(struct ubase_dev *udev)
{
	ubase_reset_pmem(&udev->pmem_info.comm);
	ubase_reset_pmem(&udev->pmem_info.udma);
}

int ubase_prealloc_mem_init(struct ubase_dev *udev)
{
	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		ubase_prealloc_mem_reinit(udev);
		return 0;
	}

	if (!ubase_dev_prealloc_supported(udev))
		return 0;

	ubase_info(udev, "pre-alloc memory feature is enabled.\n");

	if (__ubase_prealloc_mem_init(udev)) {
		ubase_warn(udev,
			   "warning: pre-alloc pages failed, will use normal pages.\n");
		return 0; /* use normal pages, must return success. */
	}

	set_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits);

	return 0;
}

void ubase_prealloc_mem_uninit(struct ubase_dev *udev)
{
	int i;

	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return;

	if (!test_and_clear_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits))
		return;

	for (i = ARRAY_SIZE(ubase_pmem_init_map) - 1; i >= 0; i--)
		ubase_pmem_init_map[i].uninit(udev);
}

/**
 * ubase_adev_prealloc_supported() - determine whether to prealloc buffer
 * @adev: auxiliary device
 *
 * This function is used to determine whether to prealloc buffer.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_prealloc_supported(struct auxiliary_device *adev)
{
	struct ubase_dev *udev;

	if (!adev)
		return false;

	udev = __ubase_get_udev_by_adev(adev);

	return test_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits);
}
EXPORT_SYMBOL(ubase_adev_prealloc_supported);
