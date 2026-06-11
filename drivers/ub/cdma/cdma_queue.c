// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include "cdma_common.h"
#include "cdma_context.h"
#include "cdma_jfc.h"
#include "cdma_jfs.h"
#include "cdma_tp.h"
#include "cdma_queue.h"
#include "cdma.h"

struct cdma_queue *cdma_find_queue(struct cdma_dev *cdev, u32 queue_id)
{
	struct cdma_queue *queue;

	spin_lock(&cdev->queue_table.lock);
	queue = idr_find(&cdev->queue_table.idr_pool.idr, queue_id);
	spin_unlock(&cdev->queue_table.lock);

	return queue;
}

static void cdma_k_assemble_jfs_cfg(struct cdma_jfs_cfg *jfs_cfg,
				    struct cdma_dev *cdev,
				    u32 eid_index,
				    struct queue_cfg *cfg,
				    struct cdma_queue *queue)
{
	jfs_cfg->eid_index = eid_index;
	jfs_cfg->max_rsge = cdev->base.attr.dev_cap.max_jfs_rsge;
	jfs_cfg->max_sge = cdev->base.attr.dev_cap.max_jfs_sge;
	jfs_cfg->depth = cfg->queue_depth;
	jfs_cfg->err_timeout = CDMA_TYPICAL_ERR_TIMEOUT;
	jfs_cfg->priority = cfg->priority;
	jfs_cfg->rnr_retry = CDMA_TYPICAL_RNR_RETRY;
	jfs_cfg->rmt_eid = cfg->rmt_eid.dw0;
	jfs_cfg->queue_id = queue->id;
	jfs_cfg->trans_mode = cfg->trans_mode;
}

static void cdma_k_assemble_jfc_cfg(struct cdma_jfc_cfg *jfc_cfg,
				    struct queue_cfg *cfg,
				    struct cdma_queue *queue)
{
	jfc_cfg->depth = cfg->queue_depth;
	jfc_cfg->queue_id = queue->id;
}

static void cdma_k_assemble_tp_cfg(struct cdma_tp_cfg *tp_cfg,
				    struct cdma_dev *cdev,
				    struct queue_cfg *cfg)
{
	tp_cfg->seid = cdev->base.attr.eu.eid.dw0;
	tp_cfg->dcna = cfg->dcna;
	tp_cfg->deid = cfg->rmt_eid.dw0;
}

static int cdma_create_queue_res(struct cdma_dev *cdev, struct queue_cfg *cfg,
				 struct cdma_queue *queue, u32 eid_index)
{
	struct cdma_jfc_cfg jfc_cfg = { 0 };
	struct cdma_jfs_cfg jfs_cfg = { 0 };
	struct cdma_tp_cfg tp_cfg = { 0 };
	int ret;

	cdma_k_assemble_jfs_cfg(&jfs_cfg, cdev, eid_index, cfg, queue);
	cdma_k_assemble_jfc_cfg(&jfc_cfg, cfg, queue);
	cdma_k_assemble_tp_cfg(&tp_cfg, cdev, cfg);

	queue->jfc = cdma_create_jfc(cdev, &jfc_cfg, NULL);
	if (!queue->jfc) {
		dev_err(cdev->dev, "create jfc failed, seid = %u, deid = %u\n",
			tp_cfg.seid, tp_cfg.deid);
		return -EFAULT;
	}

	queue->tp = cdma_create_ctp(cdev, &tp_cfg);
	if (!queue->tp) {
		dev_err(cdev->dev, "create tp failed, seid = %u, deid = %u\n",
			tp_cfg.seid, tp_cfg.deid);
		ret = -EFAULT;
		goto delete_jfc;
	}

	jfs_cfg.tpn = queue->tp->tpn;
	jfs_cfg.jfc_id = queue->jfc->id;
	queue->jfs = cdma_create_jfs(cdev, &jfs_cfg, NULL);
	if (!queue->jfs) {
		dev_err(cdev->dev, "create jfs failed, seid = %u, deid = %u\n",
			tp_cfg.seid, tp_cfg.deid);
		ret = -EFAULT;
		goto delete_tp;
	}

	queue->jfs_id = queue->jfs->id;
	queue->jfc_id = queue->jfc->id;

	dev_dbg(cdev->dev, "set queue %u jfs id: %u, jfc id: %u\n",
		queue->id, queue->jfs_id, queue->jfc_id);

	return 0;

delete_tp:
	cdma_delete_ctp(cdev, queue->tp->tp_id, false);
delete_jfc:
	cdma_delete_jfc(cdev, queue->jfc->id, NULL);

	return ret;
}

static void cdma_delete_queue_res(struct cdma_dev *cdev,
				  struct cdma_queue *queue)
{
	cdma_delete_jfs(cdev, queue->jfs->id);
	queue->jfs = NULL;
	cdma_delete_ctp(cdev, queue->tp->tp_id, false);
	queue->tp = NULL;
	cdma_delete_jfc(cdev, queue->jfc->id, NULL);
	queue->jfc = NULL;
}

static int cdma_alloc_queue_id(struct cdma_dev *cdev, struct cdma_queue *queue)
{
	struct cdma_table *queue_tbl = &cdev->queue_table;
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&queue_tbl->lock);
	id = idr_alloc(&queue_tbl->idr_pool.idr, queue, queue_tbl->idr_pool.min,
		       queue_tbl->idr_pool.max, GFP_NOWAIT);
	if (id < 0)
		dev_err(cdev->dev, "alloc queue id failed\n");
	spin_unlock(&queue_tbl->lock);
	idr_preload_end();

	return id;
}

static void cdma_delete_queue_id(struct cdma_dev *cdev, int queue_id)
{
	struct cdma_table *queue_tbl = &cdev->queue_table;

	spin_lock(&queue_tbl->lock);
	idr_remove(&queue_tbl->idr_pool.idr, queue_id);
	spin_unlock(&queue_tbl->lock);
}

struct cdma_queue *cdma_create_queue(struct cdma_dev *cdev,
				     struct cdma_context *uctx,
				     struct queue_cfg *cfg, u32 eid_index,
				     bool is_kernel)
{
	struct cdma_queue *queue;
	int ret;
	int id;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return NULL;

	id = cdma_alloc_queue_id(cdev, queue);
	if (id < 0) {
		kfree(queue);
		return NULL;
	}

	queue->ctx = uctx;
	queue->id = id;
	queue->cfg = *cfg;

	if (is_kernel) {
		ret = cdma_create_queue_res(cdev, cfg, queue, eid_index);
		if (ret) {
			dev_err(cdev->dev,
				"create queue res failed, ret = %d\n", ret);
			cdma_delete_queue_id(cdev, id);
			kfree(queue);
			return NULL;
		}
		queue->is_kernel = true;
	}

	return queue;
}

int cdma_delete_queue(struct cdma_dev *cdev, u32 queue_id)
{
	struct cdma_queue *queue;

	if (!cdev)
		return -EINVAL;

	if (queue_id >= cdev->caps.queue.start_idx + cdev->caps.queue.max_cnt) {
		dev_err(cdev->dev,
			"queue id invalid, queue_id = %u, start_idx = %u, max_cnt = %u\n",
			queue_id, cdev->caps.queue.start_idx,
			cdev->caps.queue.max_cnt);
		return -EINVAL;
	}

	spin_lock(&cdev->queue_table.lock);
	queue = idr_find(&cdev->queue_table.idr_pool.idr, queue_id);
	if (queue)
		idr_remove(&cdev->queue_table.idr_pool.idr, queue_id);
	spin_unlock(&cdev->queue_table.lock);
	if (!queue) {
		dev_err(cdev->dev, "get queue from table failed, id = %u\n",
			queue_id);
		return -EINVAL;
	}

	if (queue->is_kernel)
		cdma_delete_queue_res(cdev, queue);
	kfree(queue);

	return 0;
}

void cdma_set_queue_res(struct cdma_dev *cdev, struct cdma_queue *queue,
			enum cdma_queue_res_type type, void *res)
{
	dev_dbg(cdev->dev,
			"set queue %u resource type = %u, null flag = %u\n",
			queue->id, type, res == NULL);

	spin_lock(&cdev->queue_table.lock);
	switch (type) {
	case QUEUE_RES_TP:
		queue->tp = res;
		break;
	case QUEUE_RES_JFS:
		queue->jfs = res;
		if (queue->jfs)
			queue->jfs_id = queue->jfs->id;
		break;
	case QUEUE_RES_JFC:
		queue->jfc = res;
		if (queue->jfc)
			queue->jfc_id = queue->jfc->id;
		break;
	default:
		break;
	}
	spin_unlock(&cdev->queue_table.lock);
}
