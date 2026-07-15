/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_eq_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_EQ_DEBUGFS_H__
#define __SXE2_DRV_EQ_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

int drv_rdma_debug_aeq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_aeq *aeq);
void drv_rdma_debug_aeq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_aeq *aeq);
int drv_rdma_debug_ceq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ceq *ceq);
void drv_rdma_debug_ceq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_ceq *ceq);
u64 drv_rdma_eq_read_field(struct sxe2_rdma_device *rdma_dev, void *data,
			   enum drv_rdma_dbg_rsc_type type, char *buf);
int drv_rdma_eq_write_field(struct sxe2_rdma_device *rdma_dev, void *data,
			    enum drv_rdma_dbg_rsc_type type, char *buf);

#ifdef SXE2_SUPPORT_INJECT
int sxe2_rdma_aeq_codes_inject_add(struct sxe2_rdma_device *rdma_dev);
void drv_rdma_aeq_codes_inject_del(struct sxe2_rdma_device *rdma_dev);
#endif

#endif
