/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mq_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_MQ_DEBUGFS_H__
#define __SXE2_DRV_MQ_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
extern char *rcms_type_fields[];
extern int size_rcms_type;
extern int mq_rsc_wqe_size;
extern char *mq_rsc_wqe_err_fields[];
extern char *mq_mng_pbl_wqe_err_fields;
#endif

#define MQ_INJECT_ALL_OPCODE_CTRL_VAL 0xFF
#define MQ_STR_TO_LL_AUTO_BASE	      0

int sxe2_kadd_mq_rsc_debugfs(struct sxe2_rdma_device *rdma_dev,
			     struct sxe2_mq *mq);

void sxe2_kremove_mq_rsc_debugfs(struct sxe2_rdma_device *rdma_dev,
				 struct sxe2_mq *mq);

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
void sxe2_kadd_mq_nop_debugfs_files(struct sxe2_rdma_device *rdma_dev);

int sxe2_kadd_mq_err_debugfs(struct sxe2_rdma_device *rdma_dev);

void sxe2_kremove_mq_err_debugfs(struct sxe2_rdma_device *rdma_dev);
#endif
#endif
