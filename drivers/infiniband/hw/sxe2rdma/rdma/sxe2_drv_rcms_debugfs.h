/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rcms_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_RCMS_DEBUGFS_H__
#define __SXE2_DRV_RCMS_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

#define SXE2_OK				      0
#define RCMS_DEBUGFS_WRITE_BUF_MAX_LEN	      64
#define RCMS_DEBUGFS_READ_FPTE_MAX_CNT	      10
#define RCMS_DEBUGFS_SPTE_MAX_IDX	      511
#define RCMS_DEBUGFS_SPTE_MAX_CNT	      512
#define RCMS_DEBUGFS_READ_SPTE_MAXCNT	      10
#define RCMS_DEBUGFS_READ_LINER_ADDR_MAX_SIZE 512
#define RCMS_DEBUGFS_2M_PAGE_MAX_OFFSET	      0x1FFFFF
#define RCMS_DEBUGFS_4K_PAGE_MAX_OFFSET	      0xFFF

int drv_rdma_debug_rcms_add(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_rcms_info *rcms_info);

int sxe2_rcms_num_to_ctx_va_pointer(struct sxe2_rdma_device *rdma_dev,
				    u32 obj_type, u32 obj_num,
				    void **va_pointer);

u64 sxe2_rcms_num_to_liner_addr(struct sxe2_rcms_info *rcms_info, u32 obj_type,
				u32 obj_num);

#endif
