// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/ummu_core.h>
#include "cdma.h"
#include "cdma_queue.h"
#include "cdma_jfc.h"
#include "cdma_jfs.h"
#include "cdma_tp.h"
#include "cdma_segment.h"
#include "cdma_context.h"

#define CDMA_CTX_START 0
#define CDMA_CTX_END 0xff

static void cdma_ctx_handle_free(struct cdma_dev *cdev,
				 struct cdma_context *ctx)
{
	spin_lock(&cdev->ctx_lock);
	idr_remove(&cdev->ctx_idr, ctx->handle);
	spin_unlock(&cdev->ctx_lock);
}

static int cdma_ctx_handle_alloc(struct cdma_dev *cdev,
				 struct cdma_context *ctx)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&cdev->ctx_lock);
	id = idr_alloc(&cdev->ctx_idr, ctx, CDMA_CTX_START, CDMA_CTX_END,
		       GFP_NOWAIT);
	spin_unlock(&cdev->ctx_lock);
	idr_preload_end();

	return id;
}

struct cdma_context *cdma_find_ctx_by_handle(struct cdma_dev *cdev, int handle)
{
	struct cdma_context *ctx;

	spin_lock(&cdev->ctx_lock);
	ctx = idr_find(&cdev->ctx_idr, handle);
	spin_unlock(&cdev->ctx_lock);

	return ctx;
}

static int cdma_ctx_ksva_bind(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	struct ummu_param drvdata = { .mode = MAPT_MODE_TABLE };
	int ret;

	ctx->sva = iommu_ksva_bind_device(cdev->dev, &drvdata);
	if (IS_ERR(ctx->sva)) {
		dev_err(cdev->dev, "ksva bind device failed\n");
		return -EFAULT;
	}

	ret = ummu_get_tid(cdev->dev, ctx->sva, &ctx->tid);
	if (ret) {
		dev_err(cdev->dev, "get ksva tid failed, ret = %d\n", ret);
		iommu_ksva_unbind_device(ctx->sva);
	}

	return ret;
}

static int cdma_ctx_sva_bind(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	int sva_mode;
	int ret;

	sva_mode = cdev->sva_mode;
	if (sva_mode == UMMU_SVA_SHARE_MODE) {
		ctx->vdev = NULL;
		ctx->sva = iommu_sva_bind_device_isolated(cdev->dev,
							  current->mm, NULL);
		if (IS_ERR(ctx->sva)) {
			dev_err(cdev->dev, "sva bind device failed\n");
			return -EFAULT;
		}

		ret = ummu_get_tid(cdev->dev, ctx->sva, &ctx->tid);
		if (ret) {
			dev_err(cdev->dev, "get sva tid failed, ret = %d\n",
				ret);
			iommu_sva_unbind_device_isolated(ctx->sva);
			return ret;
		}
	} else if (sva_mode == UMMU_SVA_SEPARATE_MODE) {
		ctx->sva = NULL;
		ctx->vdev = ummu_alloc_tdev_separated(&ctx->tid);
		if (!ctx->vdev) {
			dev_err(cdev->dev, "get vdev and tid failed\n");
			return -EFAULT;
		}
	} else {
		dev_err(cdev->dev, "bind invalid sva mode, mode = %d\n",
			sva_mode);
		return sva_mode;
	}

	return 0;
}

static int cdma_ctx_alloc_tid(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	int ret;

	if (ctx->is_kernel)
		ret = cdma_ctx_ksva_bind(cdev, ctx);
	else
		ret = cdma_ctx_sva_bind(cdev, ctx);

	if (ret)
		dev_err(cdev->dev, "cdma context alloc tid failed, ret = %d\n",
			ret);

	return ret;
}

static void cdma_ctx_ksva_unbind(struct cdma_context *ctx)
{
	iommu_ksva_unbind_device(ctx->sva);
}

static void cdma_ctx_sva_unbind(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	int sva_mode;

	sva_mode = cdev->sva_mode;
	if (sva_mode == UMMU_SVA_SHARE_MODE)
		iommu_sva_unbind_device_isolated(ctx->sva);
	else if (sva_mode == UMMU_SVA_SEPARATE_MODE)
		ummu_core_free_tdev(ctx->vdev);
	else
		dev_err(cdev->dev, "unbind invalid sva mode, mode = %d\n",
			sva_mode);
}

static void cdma_ctx_free_tid(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	if (ctx->is_kernel)
		cdma_ctx_ksva_unbind(ctx);
	else
		cdma_ctx_sva_unbind(cdev, ctx);
}

struct cdma_context *cdma_alloc_context(struct cdma_dev *cdev, bool is_kernel)
{
	struct cdma_context *ctx;
	int ret;

	if (!cdev)
		return ERR_PTR(-EINVAL);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->handle = cdma_ctx_handle_alloc(cdev, ctx);
	if (ctx->handle < 0) {
		dev_err(cdev->dev,
			"alloc context handle failed, ret = %d\n", ctx->handle);
		ret = ctx->handle;
		goto free_ctx;
	}

	ctx->cdev = cdev;
	ctx->is_kernel = is_kernel;
	ret = cdma_ctx_alloc_tid(cdev, ctx);
	if (ret) {
		dev_err(cdev->dev, "alloc ctx tid failed, ret = %d\n", ret);
		goto free_handle;
	}

	spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->pgdir_list);
	mutex_init(&ctx->pgdir_mutex);
	INIT_LIST_HEAD(&ctx->queue_list);
	INIT_LIST_HEAD(&ctx->seg_list);

	return ctx;

free_handle:
	cdma_ctx_handle_free(cdev, ctx);
free_ctx:
	kfree(ctx);
	return ERR_PTR(ret);
}

void cdma_free_context(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	if (!cdev || !ctx)
		return;

	cdma_ctx_free_tid(cdev, ctx);
	cdma_ctx_handle_free(cdev, ctx);
	mutex_destroy(&ctx->pgdir_mutex);
	kfree(ctx);
}

static void cdma_cleanup_queue_res(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	struct cdma_table *queue_tbl = &cdev->queue_table;
	struct cdma_queue *queue, *next_queue;

	list_for_each_entry_safe(queue, next_queue, &ctx->queue_list, list) {
		list_del(&queue->list);

		if (queue->jfs)
			cdma_delete_jfs(cdev, queue->jfs->id);

		if (queue->tp)
			cdma_delete_ctp(cdev, queue->tp->tp_id, ctx->invalid);

		if (queue->jfc)
			cdma_delete_jfc(cdev, queue->jfc->id, NULL);

		spin_lock(&queue_tbl->lock);
		idr_remove(&queue_tbl->idr_pool.idr, queue->id);
		spin_unlock(&queue_tbl->lock);
		kfree(queue);
	}
}

static void cdma_cleanup_segment_res(struct cdma_dev *cdev, struct cdma_context *ctx)
{
	struct cdma_segment *segment, *next_segment;

	list_for_each_entry_safe(segment, next_segment, &ctx->seg_list, list) {
		list_del(&segment->list);
		cdma_unregister_seg(cdev, segment);
	}
}

void cdma_cleanup_context_res(struct cdma_context *ctx)
{
	cdma_cleanup_queue_res(ctx->cdev, ctx);
	cdma_cleanup_segment_res(ctx->cdev, ctx);
	cdma_free_context(ctx->cdev, ctx);
}
