/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_qp_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_QP_DEBUGFS_H__
#define __SXE2_DRV_QP_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"
void drv_rdma_qp_read_field_seg0(char *buf, size_t *len, struct sxe2_qpc *qpc);
void drv_rdma_qp_read_field_seg1(char *buf, size_t *len, struct sxe2_qpc *qpc);
void drv_rdma_qp_read_field_seg2(char *buf, size_t *len, struct sxe2_qpc *qpc);
void drv_rdma_qp_read_field_seg3(char *buf, size_t *len, struct sxe2_qpc *qpc);
void drv_rdma_qp_read_field_seg4(char *buf, size_t *len, struct sxe2_qpc *qpc);
void drv_rdma_qp_read_field_seg5(struct sxe2_rdma_device *rdma_dev, int qpn,
				 struct sxe2_qpc *qpc);
void drv_rdma_qp_read_field_seg6(struct sxe2_rdma_device *rdma_dev, int qpn,
				 struct sxe2_qpc *qpc);
void drv_rdma_qp_read_field_seg7(struct sxe2_rdma_device *rdma_dev, int qpn,
				 struct sxe2_qpc *qpc);
u64 drv_rdma_qp_read_field(struct sxe2_rdma_device *rdma_dev, void *data,
			   enum drv_rdma_dbg_rsc_type type, char *buf);

#endif
