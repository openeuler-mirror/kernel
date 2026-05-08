/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_stats.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_STATS_H
#define SXE2_DRV_STATS_H

#include <rdma/ib_verbs.h>
#include "sxe2_drv_rdma_common.h"

#define SXE2_STATS_BUF_ALIGN	    1
#define STATS_VF_RX_BUF_START_8BYTE 16
#define STATS_VF_TX_BUF_ALL_BYTE    128
#define STATS_VF_RX_BUF_ALL_BYTE    136

#define SXE2_RDMA_HW_MAJOR_VERSION_BITS                                        \
	GENMASK(31, 16)
#define SXE2_RDMA_HW_MINOR_VERSION_BITS                                        \
	GENMASK(15, 0)
#define SXE2_RDMA_FW_BUILD_NUMBER_BITS GENMASK(7, 0)
#define SXE2_RDMA_FW_FIX_VERSION_BITS  GENMASK(15, 8)
#define SXE2_RDMA_FW_SUB_VERSION_BITS  GENMASK(23, 16)
#define SXE2_RDMA_FW_MAIN_VERSION_BITS GENMASK(31, 24)

#pragma pack(1)
struct mq_wqe_gather_stats {
	u64 rsv0;
	u64 rsv1;
	u64 rsv2;
	u32 statistics_instance_index : 1;
	u32 rsv3 : 31;
	u32 op : 6;
	u32 rsv4 : 22;
	u32 use_rcms_func_index : 1;
	u32 use_statistics_instance : 1;
	u32 rsv5 : 1;
	u32 wqe_valid : 1;
	u64 physical_buffer_address;
	u32 rcms_fcn_index : 6;
	u64 rsv6 : 58;
	u64 rsv7;
	u64 rsv8;
};
#pragma pack(0)

struct sxe2_rdma_gather_stats {
	u64 val[SXE2_GATHER_STATS_BUF_SIZE / sizeof(u64)];
};

struct sxe2_rdma_gather_stats_vf {
	u64 val[SXE2_GATHER_STATS_BUF_VF_SIZE / sizeof(u64)];
};

struct sxe2_rdma_vsi_stats_info {
	struct sxe2_rdma_vsi_pestat *pestat;
	u16 fcn_id;
};

void sxe2_kupdate_vsi_stats(struct sxe2_rdma_ctx_vsi *vsi);

void sxe2_kprocess_mq_stats(struct sxe2_mq_request *mq_request);

int sxe2_kgather_stats(struct sxe2_mq_ctx *mq,
		       struct sxe2_rdma_stats_gather_info *info, u64 scratch);

int sxe2_kgather_stats_mq_cmd(struct sxe2_rdma_ctx_dev *dev,
			      struct sxe2_rdma_vsi_pestat *pestat, bool wait);

int sxe2_kgather_pf_for_vf_stats_val(
	struct sxe2_rdma_vchnl_dev *vc_dev, u32 stats_req_type,
	struct sxe2_rdma_gather_stats_vf *gather_stats_resp);

int sxe2_kgather_vf_stats_mq_cmd(struct sxe2_rdma_ctx_dev *dev,
				 struct sxe2_rdma_vsi_pestat *pestat,
				 bool wait);

int sxe2_kinit_vsi_stats(struct sxe2_rdma_device *rdma_dev);

void sxe2_kfree_vsi_stats(struct sxe2_rdma_device *rdma_dev);

#ifdef ALLOC_HW_STATS_V1
struct rdma_hw_stats *sxe2_kalloc_hw_port_stats(struct ib_device *ibdev,
						u8 port_num);
#else
struct rdma_hw_stats *sxe2_kalloc_hw_port_stats(struct ib_device *ibdev,
						u32 port_num);
#endif

#ifdef GET_HW_STATS_V1
int sxe2_kget_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats,
		       u8 port_num, int index);
#else
int sxe2_kget_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats,
		       u32 port_num, int index);
#endif

int sxe2_kget_rdma_features(struct sxe2_rdma_device *rdma_dev);

#ifdef SXE2_CFG_DEBUG
int drv_rdma_debug_stats_add(struct sxe2_rdma_device *rdma_dev);

int drv_rdma_stats_overflow_inject_debugfs_add(
	struct sxe2_rdma_device *rdma_dev);
#endif

#endif
