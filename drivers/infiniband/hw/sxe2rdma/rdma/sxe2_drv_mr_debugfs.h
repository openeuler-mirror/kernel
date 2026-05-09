/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mr_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_MR_DEBUGFS_H__
#define __SXE2_DRV_MR_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

int sxe2_debbugfs_mr_add(struct sxe2_rdma_device *rdma_dev,
			 struct sxe2_mr *vendor_mr);
void sxe2_debugfs_mr_remove(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_mr *vendor_mr);
#endif
