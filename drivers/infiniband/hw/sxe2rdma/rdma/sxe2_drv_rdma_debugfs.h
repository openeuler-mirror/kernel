/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_RDMA_DEBUGFS_H__
#define __SXE2_DRV_RDMA_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

#define SXE2_DEBUG_DUMP_BUF_SIZE   (8192)
#define SXE2_DEBUG_FILE_ONLY_WRITE (0200)
#define SXE2_DEBUG_FILE_ONLY_READ  (0400)
#define SXE2_DEBUG_FILE_READ_WRITE (0600)

#define DEBUG_ARGV_COUNT_MAX (32)
#define DEBUG_PARA_CONT1     (1)
#define DEBUG_PARA_CONT2     (2)
#define DEBUG_PARA_CONT3     (3)
#define DEBUG_PARA_CONT4     (4)

size_t dbg_vsnprintf(char *buf, size_t len, char *fmt, ...);
int split_command(char *cmd, int *argc, char *argv[]);

struct sxe2_rdma_rsc_debug *
drv_rdma_add_res_tree(struct sxe2_rdma_device *dev,
		      enum drv_rdma_dbg_rsc_type type, struct dentry *root,
		      sxe2_drv_rdma_debugfs_read rfunc,
		      sxe2_drv_rdma_debugfs_write wfunc, int rsn, void *data);
void drv_rdma_rm_res_tree(struct sxe2_rdma_rsc_debug *dbg);

struct dentry *
sxe2_rdma_debugfs_get_dev_root(struct sxe2_rdma_device *rdma_dev);

int sxe2_rdma_dbg_pf_init(struct sxe2_rdma_device *rdma_dev);
void sxe2_rdma_dgb_pf_exit(struct sxe2_rdma_device *rdma_dev);

int sxe2_rdma_dbg_init(void);
void sxe2_rdma_dbg_exit(void);

int drv_rdma_debug_qp_add(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_qp *qp);
void drv_rdma_debug_qp_remove(struct sxe2_rdma_device *rdma_dev,
			      struct sxe2_rdma_qp *qp);
void sxe2_debug_file_creat(struct sxe2_rdma_device *rdma_dev);

#endif
