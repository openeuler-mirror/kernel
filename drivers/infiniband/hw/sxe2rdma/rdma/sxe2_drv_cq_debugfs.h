/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_cq_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_CQ_DEBUGFS_H__
#define __SXE2_DRV_CQ_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

int drv_rdma_debug_cq_add(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_cq *cq);
void drv_rdma_debug_cq_remove(struct sxe2_rdma_device *rdma_dev,
			      struct sxe2_rdma_cq *cq);

int drv_rdma_debug_mcq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_mcq *mcq);
void drv_rdma_debug_mcq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_mcq *mcq);
u64 drv_rdma_cq_read_field(struct sxe2_rdma_device *rdma_dev, void *data,
			   enum drv_rdma_dbg_rsc_type type, char *buf);
int drv_rdma_cq_write_field(struct sxe2_rdma_device *rdma_dev, void *data,
			    enum drv_rdma_dbg_rsc_type type, char *buf);

#endif
