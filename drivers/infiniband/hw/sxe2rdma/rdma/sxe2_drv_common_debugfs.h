/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_common_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_COMMON_DEBUGFS_H__
#define __SXE2_DRV_COMMON_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

#define SXE2_OK						  0
#define COMMON_MAC_LOOP_BACK_EN_DEBUGFS_WRITE_BUF_MAX_LEN 4
#define COMMON_RESET_EN_DEBUGFS_WRITE_BUF_MAX_LEN	  4
#define COMMON_CONFIG_IP_DEBUGFS_WRITE_BUF_MAX_LEN	  16
#define COMMON_DUMP_PCAP_EN_DEBUGFS_WRITE_BUF_MAX_LEN	  4

#ifdef SXE2_CFG_DEBUG

extern struct sxe2_reset_debug g_reset_debug;

#endif

int drv_rdma_debug_common_add(struct sxe2_rdma_device *rdma_dev);

#endif
