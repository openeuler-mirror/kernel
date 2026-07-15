/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_CONTEXT_H__
#define __CDMA_CONTEXT_H__

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/xarray.h>
#include <ub/cdma/cdma_api.h>
#include "cdma_event.h"

struct cdma_context {
	struct dma_context base_ctx;
	struct cdma_dev *cdev;
	struct iommu_sva *sva;
	struct list_head pgdir_list;
	struct mutex pgdir_mutex;
	spinlock_t lock;
	int handle;
	u32 tid;
	bool is_kernel;
	atomic_t ref_cnt;
	struct list_head queue_list;
	struct list_head seg_list;
	struct device *vdev;
	bool invalid;
};

struct cdma_ctx_res {
	struct cdma_context *ctx;
	struct xarray queue_xa;
	struct xarray seg_xa;
};

struct cdma_context *cdma_find_ctx_by_handle(struct cdma_dev *cdev, int handle);
struct cdma_context *cdma_alloc_context(struct cdma_dev *cdev, bool is_kernel);
void cdma_free_context(struct cdma_dev *cdev, struct cdma_context *ctx);
void cdma_cleanup_context_res(struct cdma_context *ctx);

#endif /* __CDMA_CONTEXT_H__ */
