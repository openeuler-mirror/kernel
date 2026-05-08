/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_qp.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DRV_QP_H__
#define __SXE2_DRV_QP_H__

#include "sxe2_compat.h"

#define MIN_SQ_SIZE (8)
#define MIN_RQ_SIZE (8)
#define SQ_RSV_SIZE (8)
#define RQ_RSV_SIZE (8)
#define QP_QUANTA_SIZE (32)
#define SXE2_DEFAULT_PKEY (0xFFFF)
#define SXE2_INVALID_RD_ATOMIC (256)
#define SXE2_MIN_LOG_RD_ATOMIC (0)
#define SXE2_MAX_RD_ATOMIC (64)
#define SXE2_MIN_RD_ATOMIC (16)
#define SXE2_EVENT_TIMEOUT_MS (5000)
#define SXE2_QP_CTX_SIZE (512)
#define SXE2_FLUSH_DELAY_MS (20)
#define SXE2_QP_TYPE_RDMA_RC (3)
#define SXE2_QP_TYPE_RDMA_UD (4)
#define SXE2_QP_TYPE_RDMA_QP1 (7)
#define SXE2_QP_CC_CNP_ECN_ENABLE (1)
#define SXE2_QP_CC_CNP_ECN_DISABLE (0)
#define SXE2_QP_CC_ECN_ENABLE (1)
#define SXE2_QP_CC_ECN_DISABLE (0)
#define SXE2_QP_DCQCN_MAX_B    (0xFFFFFF)
#define SXE2_MAX_CC_QP_IDX      (4096)

#define SXE2_USER_PARM_TO_HW_VAL(val)		(val / 2 - 1)
#define SXE2_PF_DB_PAGE_BAR_OFFSET(idx)	(0x3F0000 + (idx) * 0x1000)
#define SXE2_VF_DB_PAGE_BAR_OFFSET(idx)	(0x010000 + (idx) * 0x1000)

#ifndef ether_addr_copy
#define ether_addr_copy(mac_addr, new_mac_addr) memcpy(mac_addr, new_mac_addr, ETH_ALEN)
#endif

#define ah_attr_to_dmac(attr) ((attr).roce.dmac)

#define SXE2_RETRY_MODE_GO_BACK_0 0
#define SXE2_RETRY_MODE_GO_BACK_N 1

enum sxe2_rdma_flush_op {
	SXE2_FLUSH_SQ = BIT(0),
	SXE2_FLUSH_RQ = BIT(1),
	SXE2_REFLUSH = BIT(2),
};

enum sxe2_rdma_encoding_read_max {
	SXE2_ENCODING_READ_0 = 0,
	SXE2_ENCODING_READ_1 = 1,
	SXE2_ENCODING_READ_2 = 2,
	SXE2_ENCODING_READ_3 = 3,
	SXE2_ENCODING_READ_4 = 4,
	SXE2_ENCODING_READ_5 = 5,
	SXE2_ENCODING_READ_6 = 6,
	SXE2_ENCODING_READ_7 = 7,
	SXE2_ENCODING_READ_8 = 8,
};

#define SXE2_QP_DISABLE_SW_CC				0
#define SXE2_QP_ENABLE_DCQCN				1
#define SXE2_QP_ENABLE_TIMELY				2
#define SXE2_QP_ENABLE_DCQCN_TIMLEY		3

#define DCQCN_B_L_MASK						0x3FFF
#define DCQCN_B_H_SHIFT						14
#define DCQCN_T_INTERVAL_L_MASK				0xF
#define DCQCN_T_INTERVAL_H_SHIFT			4
#define DCQCN_RHAI_L_MASK					0xFF
#define DCQCN_RHAI_H_SHIFT					8
#define DCQCN_RREDUCE_MPERIOD_L_MASK		0xFF
#define DCQCN_RREDUCE_MPERIOD_H_SHIFT		8
#define DCQCN_RC_L_MASK						0xFFFF
#define DCQCN_RC_H_SHIFT					16
#define DCQCN_RT_L_MASK						0xF
#define DCQCN_RT_H_SHIFT					4

#define TIMELY_MIN_RTT_L_MASK				0xF
#define TIMELY_MIN_RTT_H_SHIFT				4
#define TIMELY_THIGH_L_MASK					0xF
#define TIMELY_THIGH_H_SHIFT				4
#define TIMELY_PRE_RTT_L_MASK				0xFF
#define TIMELY_PRE_RTT_H_SHIFT				8

#define STATA_RATE_MAX_CNT					30
enum sxe2_stat_rate_rel_val {
	SXE2_RATE_2_5_GBPS  = 2500,
	SXE2_RATE_5_GBPS    = 5000,
	SXE2_RATE_10_GBPS   = 10000,
	SXE2_RATE_20_GBPS   = 20000,
	SXE2_RATE_30_GBPS   = 30000,
	SXE2_RATE_40_GBPS   = 40000,
	SXE2_RATE_60_GBPS   = 60000,
	SXE2_RATE_80_GBPS   = 80000,
	SXE2_RATE_120_GBPS  = 120000,
	SXE2_RATE_14_GBPS   = 14000,
	SXE2_RATE_56_GBPS   = 56000,
	SXE2_RATE_112_GBPS  = 112000,
	SXE2_RATE_168_GBPS  = 168000,
	SXE2_RATE_25_GBPS   = 25000,
	SXE2_RATE_100_GBPS  = 100000,
	SXE2_RATE_200_GBPS  = 200000,
	SXE2_RATE_300_GBPS  = 300000,
	SXE2_RATE_28_GBPS   = 28000,
	SXE2_RATE_50_GBPS   = 50000,
	SXE2_RATE_400_GBPS  = 400000,
	SXE2_RATE_600_GBPS  = 600000,
};

enum sxe2_ib_rate {
	SXE2_IB_RATE_PORT_CURRENT = 0,
	SXE2_IB_RATE_2_5_GBPS	 = 2,
	SXE2_IB_RATE_5_GBPS		 = 5,
	SXE2_IB_RATE_10_GBPS		 = 3,
	SXE2_IB_RATE_20_GBPS		 = 6,
	SXE2_IB_RATE_30_GBPS		 = 4,
	SXE2_IB_RATE_40_GBPS		 = 7,
	SXE2_IB_RATE_60_GBPS		 = 8,
	SXE2_IB_RATE_80_GBPS		 = 9,
	SXE2_IB_RATE_120_GBPS	 = 10,
	SXE2_IB_RATE_14_GBPS		 = 11,
	SXE2_IB_RATE_56_GBPS		 = 12,
	SXE2_IB_RATE_112_GBPS	 = 13,
	SXE2_IB_RATE_168_GBPS	 = 14,
	SXE2_IB_RATE_25_GBPS		 = 15,
	SXE2_IB_RATE_100_GBPS	 = 16,
	SXE2_IB_RATE_200_GBPS	 = 17,
	SXE2_IB_RATE_300_GBPS	 = 18,
	SXE2_IB_RATE_28_GBPS		 = 19,
	SXE2_IB_RATE_50_GBPS		 = 20,
	SXE2_IB_RATE_400_GBPS	 = 21,
	SXE2_IB_RATE_600_GBPS	 = 22,
};

enum sxe2_link_get_speed {
	SXE2_LINK_SPEED_UNKNOWN = 0,
	SXE2_LINK_SPEED_10G    = 10000,
	SXE2_LINK_SPEED_25G    = 25000,
	SXE2_LINK_SPEED_50G    = 50000,
	SXE2_LINK_SPEED_100G   = 100000,
	SXE2_LINK_SPEED_AUTO   = 200000,
};

enum sxe2_qp_bucket_type {
	SXE2_QP_BUCKET_4K = 0,
	SXE2_QP_BUCKET_8K = 1,
	SXE2_QP_BUCKET_16K = 2,
	SXE2_QP_BUCKET_32K = 3,
	SXE2_QP_BUCKET_64K = 4,
	SXE2_QP_BUCKET_128K = 5,
};

enum sxe2_log_msg {
	SXE2_LOG_MSG_8 = 8,
	SXE2_LOG_MSG_12 = 12,
	SXE2_LOG_MSG_31 = 31,
};

enum sxe2_rq_type {
	SXE2_REGULAR_RQ = 0,
	SXE2_SRQ		 = 1,
	SXE2_NO_RQ		 = 3,
};

enum inline_data_size {
	MAX_INLINE_DATA_8 = 8,
	MAX_INLINE_DATA_39 = 39,
	MAX_INLINE_DATA_101 = 101,
};

enum sge_size {
	MAX_SGE_SIZE_0 = 0,
	MAX_SGE_SIZE_1,
	MAX_SGE_SIZE_2,
	MAX_SGE_SIZE_3,
	MAX_SGE_SIZE_4,
	MAX_SGE_SIZE_5,
	MAX_SGE_SIZE_6,
	MAX_SGE_SIZE_7,
	MAX_SGE_SIZE_8,
	MAX_SGE_SIZE_9,
	MAX_SGE_SIZE_10,
	MAX_SGE_SIZE_11,
	MAX_SGE_SIZE_12,
	MAX_SGE_SIZE_13,
	MAX_SGE_SIZE_14,
};

enum wqe_size_shift {
	WQE_SIZE_32BYTE = 0,
	WQE_SIZE_64BYTE,
	WQE_SIZE_128BYTE,
	WQE_SIZE_256BYTE,
};

enum rqe_size {
	RQE_SIZE_32BYTE = 32,
	RQE_SIZE_64BYTE = 64,
	RQE_SIZE_128BYTE = 128,
	RQE_SIZE_256BYTE = 256,
};

enum sxe2_ib_rate_tag {
	SXE2_IB_RATE_TAG_0 = 0,
	SXE2_IB_RATE_TAG_1	= 1,
	SXE2_IB_RATE_TAG_2	= 2,
	SXE2_IB_RATE_TAG_3	= 3,
	SXE2_IB_RATE_TAG_4	= 4,
	SXE2_IB_RATE_TAG_5	= 5,
	SXE2_IB_RATE_TAG_6	= 6,
	SXE2_IB_RATE_TAG_7	= 7,
	SXE2_IB_RATE_TAG_8	= 8,
};

struct sxe2_destroy_cc_qp_info {
	u32 cc_qp_idx;
};

struct sxe2_qp_common_init_info {
	struct sxe2_qp_quanta *sq;
	struct sxe2_qp_quanta *rq;
	struct sxe2_srq_drv	*srq;
	struct sxe2_common_attrs *common_attrs;
	__u32 *qp_db_no_llwqe;
	__u32 *doorbell_note;
	struct sxe2_sq_common_wr_trk_info *sq_wrtrk_array;
	__u64 *rq_wrid_array;
	__u32 qpn;
	__u32 qp_caps;
	__u32 sq_size;
	__u32 rq_size;
	__u32 max_sq_sge_cnt;
	__u32 max_rq_sge_cnt;
	__u32 max_inline_data;
	__u32 sq_depth;
	__u32 rq_depth;
	__u8 qp_type;
	__u8 sq_shift;
	__u8 rq_shift;
	bool legacy_mode;
};

struct sxe2_qp_init_info {
	struct sxe2_qp_common_init_info qp_common_init_info;
	struct sxe2_rdma_ctx_pd *pd;
	struct sxe2_rdma_ctx_vsi *vsi;
	__u64 *host_ctx;
	__u64 host_ctx_pa;
	__u64 sq_pa;
	__u64 rq_pa;
	__u64 shadow_area_pa;
};

struct qp_disconn_work {
	struct work_struct work;
	struct sxe2_rdma_qp *qp;
};

int drv_rdma_debug_qp_add(struct sxe2_rdma_device *rdma_dev,
						  struct sxe2_rdma_qp *qp);
void drv_rdma_debug_qp_remove(struct sxe2_rdma_device *rdma_dev,
							  struct sxe2_rdma_qp *qp);

#ifdef CREATE_QP_VER_1
struct ib_qp *sxe2_kcreate_qp(struct ib_pd *ibpd, struct ib_qp_init_attr *init_attr,
					 struct ib_udata *udata);
#else
int sxe2_kcreate_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr,
					  struct ib_udata *udata);
#endif
int sxe2_kmodify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
					  int attr_mask, struct ib_udata *udata);
int sxe2_kquery_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
					 int qp_attr_mask, struct ib_qp_init_attr *init_attr);
#ifdef DESTROY_QP_V1
int sxe2_kdestroy_qp(struct ib_qp *ibqp);
#else
int sxe2_kdestroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);
#endif
int sxe2_ctx_qp_create(struct sxe2_rdma_ctx_qp *qp, struct sxe2_create_qp_info *info,
									u64 scratch, bool post_sq);
int sxe2_ctx_qp_modify(struct sxe2_rdma_ctx_qp *qp, struct sxe2_modify_qp_info *info,
									u64 scratch, bool post_sq);
int sxe2_ctx_qp_destroy(struct sxe2_rdma_ctx_qp *qp, struct sxe2_destroy_qp_info *info,
									u64 scratch, bool post_sq);
int sxe2_ctx_qp_query(struct sxe2_rdma_ctx_qp *qp, struct sxe2_query_qp_info *info,
									u64 scratch, bool post_sq);
int sxe2_mq_query_qp_cmd(struct sxe2_rdma_qp *qp);
int sxe2_mq_modify_qp_cmd(struct sxe2_rdma_qp *qp);

void sxe2_cm_disconn(struct sxe2_rdma_qp *qp);

void sxe2_ib_qp_event(struct sxe2_rdma_qp *qp, enum sxe2_qp_event_type event);

int sxe2_kset_attr_from_fragcnt(struct sxe2_rdma_device *rdma_dev);

void sxe2_ctx_qp_fill_cc_wqe(struct sxe2_rdma_ctx_qp *qp,
			     struct qp_mq_create_cc_qp_wqe *create_cc_qp_wqe);
int sxe2_qp_info_init(struct ib_qp_init_attr *init_attr,
		      struct sxe2_rdma_device *rdma_dev,
		      struct sxe2_rdma_ctx_dev *dev, struct sxe2_rdma_pd *pd,
		      u32 qpn, struct sxe2_qp_init_info *init_info);

int sxe2_rdma_qp_init(struct ib_qp_init_attr *init_attr, struct ib_udata *udata,
		      struct sxe2_rdma_device *rdma_dev,
		      struct sxe2_rdma_pd *pd, u32 qpn,
		      struct sxe2_qp_init_info *init_info,
		      struct sxe2_rdma_qp *qp);
int sxe2_qp_qset_init_and_resp(struct ib_udata *udata,
			       struct sxe2_rdma_device *rdma_dev, u32 qpn,
			       struct sxe2_rdma_ctx_qp *qp_ctx,
			       struct sxe2_rdma_qp *qp);

#endif

