// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include "cdma_jfs.h"
#include "cdma_common.h"
#include "cdma_handle.h"

static int cdma_rw_check(struct cdma_dev *cdev, struct dma_seg *rmt_seg,
			 struct dma_seg *local_seg)
{
	if (!rmt_seg->len || !local_seg->len) {
		dev_err(cdev->dev, "invalid len\n");
		return -EINVAL;
	}

	if (!rmt_seg->sva || !local_seg->sva) {
		dev_err(cdev->dev, "invalid address\n");
		return -EINVAL;
	}

	return 0;
}

static inline void cdma_fill_comm_wr(struct cdma_jfs_wr *wr,
				     struct cdma_queue *queue)
{
	wr->flag.bs.complete_enable = CDMA_ENABLE_FLAG;
	wr->flag.bs.inline_flag = CDMA_DISABLE_FLAG;
	wr->flag.bs.fence = CDMA_ENABLE_FLAG;
	wr->tpn = queue->tp->tpn;
	wr->rmt_eid = queue->cfg.rmt_eid.dw0;
	wr->next = NULL;
}

static inline void cdma_fill_sge(struct cdma_sge_info *rmt_sge,
				 struct cdma_sge_info *local_sge,
				 struct dma_seg *rmt_seg,
				 struct dma_seg *local_seg)
{
	local_sge->addr = local_seg->sva;
	local_sge->len = local_seg->len;
	local_sge->seg = local_seg;

	rmt_sge->addr = rmt_seg->sva;
	rmt_sge->len = rmt_seg->len;
	rmt_sge->seg = rmt_seg;
}

int cdma_write(struct cdma_dev *cdev, struct cdma_queue *queue,
	       struct dma_seg *local_seg, struct dma_seg *rmt_seg,
	       struct dma_notify_data *data)
{
	struct cdma_jfs_wr wr = { .opcode = CDMA_WR_OPC_WRITE };
	struct cdma_sge_info rmt_sge, local_sge;
	struct cdma_jfs_wr *bad_wr = NULL;
	int ret;

	if (cdma_rw_check(cdev, rmt_seg, local_seg)) {
		dev_err(cdev->dev, "write param check failed\n");
		return -EINVAL;
	}

	if (data) {
		wr.opcode = CDMA_WR_OPC_WRITE_NOTIFY;
		wr.rw.notify_addr = data->notify_seg->sva;
		wr.rw.notify_data = data->notify_data;
		wr.rw.notify_tokenid = data->notify_seg->tid;
		wr.rw.notify_tokenvalue = data->notify_seg->token_value;
	}

	cdma_fill_comm_wr(&wr, queue);

	cdma_fill_sge(&rmt_sge, &local_sge, rmt_seg, local_seg);

	wr.rw.src.num_sge = 1;
	wr.rw.src.sge = &local_sge;
	wr.rw.dst.num_sge = 1;
	wr.rw.dst.sge = &rmt_sge;

	ret = cdma_post_jfs_wr((struct cdma_jfs *)queue->jfs, &wr, &bad_wr);
	if (ret)
		dev_err(cdev->dev, "post jfs for write failed, ret = %d\n", ret);

	return ret;
}

int cdma_read(struct cdma_dev *cdev, struct cdma_queue *queue,
	      struct dma_seg *local_seg, struct dma_seg *rmt_seg)
{
	struct cdma_jfs_wr wr = { .opcode = CDMA_WR_OPC_READ };
	struct cdma_sge_info rmt_sge, local_sge;
	struct cdma_jfs_wr *bad_wr = NULL;
	int ret;

	if (cdma_rw_check(cdev, rmt_seg, local_seg)) {
		dev_err(cdev->dev, "read param check failed\n");
		return -EINVAL;
	}

	cdma_fill_comm_wr(&wr, queue);

	cdma_fill_sge(&rmt_sge, &local_sge, rmt_seg, local_seg);

	wr.rw.src.num_sge = 1;
	wr.rw.src.sge = &rmt_sge;
	wr.rw.dst.num_sge = 1;
	wr.rw.dst.sge = &local_sge;

	ret = cdma_post_jfs_wr((struct cdma_jfs *)queue->jfs, &wr, &bad_wr);
	if (ret)
		dev_err(cdev->dev, "post jfs for read failed, ret = %d\n", ret);

	return ret;
}

int cdma_cas(struct cdma_dev *cdev, struct cdma_queue *queue,
	     struct dma_seg *local_seg, struct dma_seg *rmt_seg,
	     struct dma_cas_data *data)
{
	struct cdma_jfs_wr wr = { .opcode = CDMA_WR_OPC_CAS };
	struct cdma_sge_info rmt_sge, local_sge;
	struct cdma_jfs_wr *bad_wr = NULL;
	int ret;

	if (cdma_rw_check(cdev, rmt_seg, local_seg)) {
		dev_err(cdev->dev, "cas param check failed\n");
		return -EINVAL;
	}

	cdma_fill_comm_wr(&wr, queue);

	cdma_fill_sge(&rmt_sge, &local_sge, rmt_seg, local_seg);

	wr.cas.src = &local_sge;
	wr.cas.dst = &rmt_sge;

	if (local_sge.len <= CDMA_ATOMIC_LEN_8) {
		wr.cas.cmp_data = data->compare_data;
		wr.cas.swap_data = data->swap_data;
	} else {
		wr.cas.cmp_addr = data->compare_data;
		wr.cas.swap_addr = data->swap_data;
	}

	ret = cdma_post_jfs_wr((struct cdma_jfs *)queue->jfs, &wr, &bad_wr);
	if (ret)
		dev_err(cdev->dev, "post jfs for cas failed, ret = %d\n", ret);

	return ret;
}

int cdma_faa(struct cdma_dev *cdev, struct cdma_queue *queue,
	     struct dma_seg *local_seg, struct dma_seg *rmt_seg, u64 add)
{
	struct cdma_jfs_wr wr = { .opcode = CDMA_WR_OPC_FADD };
	struct cdma_sge_info rmt_sge, local_sge;
	struct cdma_jfs_wr *bad_wr = NULL;
	int ret;

	if (cdma_rw_check(cdev, rmt_seg, local_seg)) {
		dev_err(cdev->dev, "faa param check failed\n");
		return -EINVAL;
	}

	cdma_fill_comm_wr(&wr, queue);

	cdma_fill_sge(&rmt_sge, &local_sge, rmt_seg, local_seg);

	wr.faa.src = &local_sge;
	wr.faa.dst = &rmt_sge;
	wr.faa.operand = add;

	ret = cdma_post_jfs_wr((struct cdma_jfs *)queue->jfs, &wr, &bad_wr);
	if (ret)
		dev_err(cdev->dev, "post jfs for faa failed, ret = %d\n", ret);

	return ret;
}
