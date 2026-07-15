/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_configfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_RDMA_CONFIGFS_H__
#define __SXE2_DRV_RDMA_CONFIGFS_H__
#ifdef SXE2_SUPPORT_CONFIGFS
int sxe2_rdma_create_configfs_subdir(const char *name, struct sxe2_rdma_device *dev);
void sxe2_rdma_remove_configfs_subdir(const char *name);
int sxe2_configfs_init(void);
void sxe2_configfs_exit(void);
void sxe2_rdma_set_irq_rate_limit(struct sxe2_rdma_ctx_dev *dev, u32 idx,
				  u32 interval);

#endif
#endif
