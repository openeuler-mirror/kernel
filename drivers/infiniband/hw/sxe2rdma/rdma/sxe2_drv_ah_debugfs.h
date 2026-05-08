/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_ah_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_AH_DEBUGFS_H__
#define __SXE2_DRV_AH_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"
#ifdef SXE2_CFG_DEBUG
int sxe2_debbugfs_ah_add(struct sxe2_rdma_device *rdma_dev,
			 struct sxe2_ah *vendor_ah);
void sxe2_debugfs_ah_remove(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_ah *vendor_ah);
#endif
int sxe2_drv_ah_modify_op(struct sxe2_rdma_device *rdma_dev,
			  union sxe2_hw_ahc *ah_ctx);

int sxe2_debugfs_ah_write(struct sxe2_rdma_device *rdma_dev, void *data,
			  enum drv_rdma_dbg_rsc_type type, char *buf);

u64 sxe2_debugfs_ah_read(struct sxe2_rdma_device *rdma_dev, void *data,
			 enum drv_rdma_dbg_rsc_type type, char *buf);

#endif
