/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_qos_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_RCMS_DEBUGFS_H__
#define __SXE2_DRV_RCMS_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

#define SXE2_OK 0

int drv_rdma_debug_qos_add(struct sxe2_rdma_device *rdma_dev);

#ifdef SXE2_SUPPORT_INJECT
int drv_rdma_qos_err_code_inject_add(struct sxe2_rdma_device *rdma_dev);
#endif
#endif
