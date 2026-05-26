// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/iommu.h>
#include <linux/ummu_core.h>
#include "cdma_segment.h"
#include "cdma_context.h"

static int cdma_alloc_seg_handle(struct cdma_dev *cdev,
				 struct cdma_segment *seg)
{
	struct cdma_table *seg_table = &cdev->seg_table;
	int handle;

	idr_preload(GFP_KERNEL);
	spin_lock(&seg_table->lock);

	handle = idr_alloc(&seg_table->idr_tbl.idr, seg, seg_table->idr_tbl.min,
			   seg_table->idr_tbl.max, GFP_NOWAIT);
	if (handle < 0)
		dev_err(cdev->dev, "alloc seg handle failed\n");

	spin_unlock(&seg_table->lock);
	idr_preload_end();

	return handle;
}

static inline void cdma_free_seg_handle(struct cdma_dev *cdev, u64 handle)
{
	spin_lock(&cdev->seg_table.lock);
	idr_remove(&cdev->seg_table.idr_tbl.idr, handle);
	spin_unlock(&cdev->seg_table.lock);
}

struct cdma_segment *cdma_register_seg(struct cdma_dev *cdev,
				       struct dma_seg_cfg *cfg, bool is_kernel,
				       struct cdma_context *ctx)
{
	struct cdma_segment *seg;
	int handle;

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return NULL;

	seg->umem = cdma_umem_get(cdev, cfg->sva, cfg->len, is_kernel, ctx);
	if (IS_ERR_OR_NULL(seg->umem)) {
		dev_err(cdev->dev, "pin seg failed\n");
		goto free_seg;
	}

	handle = cdma_alloc_seg_handle(cdev, seg);
	if (handle < 0)
		goto unpin_umem;

	seg->base.handle = (u64)handle;
	seg->base.token_value = cfg->token_value;
	seg->base.sva = cfg->sva;
	seg->base.len = cfg->len;
	seg->base.token_value_valid = cfg->token_value_valid;
	seg->is_kernel = is_kernel;

	return seg;

unpin_umem:
	cdma_put_umem(seg->umem, is_kernel);
free_seg:
	kfree(seg);

	return NULL;
}

void cdma_unregister_seg(struct cdma_dev *cdev, struct cdma_segment *seg)
{
	cdma_free_seg_handle(cdev, seg->base.handle);
	cdma_put_umem(seg->umem, seg->is_kernel);
	kfree(seg);
}

int cdma_seg_grant(struct cdma_dev *cdev, struct cdma_segment *seg,
		   struct dma_seg_cfg *cfg)
{
	struct ummu_token_info token_info = { 0 };
	struct ummu_seg_attr seg_attr = { 0 };
	int ret;

	seg->base.tid = seg->ctx->tid;
	seg->ksva = seg->ctx->sva;

	token_info.input = 0;
	token_info.tokenVal = cfg->token_value;
	seg_attr.token = &token_info;
	seg_attr.e_bit = UMMU_EBIT_OFF;

	ret = iommu_sva_grant(seg->ksva, (void *)cfg->sva, cfg->len,
			      MAPT_PERM_RW, (void *)&seg_attr);
	if (ret)
		dev_err(cdev->dev, "grant seg failed, ret = %d\n", ret);

	return ret;
}

void cdma_seg_ungrant(struct cdma_segment *seg)
{
	struct ummu_token_info token_info = { 0 };

	token_info.tokenVal = seg->base.token_value;

	iommu_sva_ungrant(seg->ksva, (void *)seg->base.sva, seg->base.len,
			  &token_info);
}

struct dma_seg *cdma_import_seg(struct dma_seg_cfg *cfg)
{
	struct dma_seg *seg;

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return NULL;

	seg->sva = cfg->sva;
	seg->len = cfg->len;
	seg->token_value = cfg->token_value;

	return seg;
}

void cdma_unimport_seg(struct dma_seg *seg)
{
	kfree(seg);
}
