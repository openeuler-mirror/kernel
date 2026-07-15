/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_cq.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_CQ_H__
#define __SXE2_DRV_CQ_H__

#include "sxe2_drv_rdma_common.h"

#define SXE2_RDMA_MIN_CQ_SIZE 4
#define SXE2_RDMA_MAX_CQ_SIZE 2097152

#define SXE2_MAX_CQ_PERIOD (0xFFF)

#define SXE2_RDMA_DB_NOTE_SIZE (64)

#define SXE2_RDMA_CQ_TYPE_IO (1)
#define SXE2_RDMA_CQ_TYPE_MQ (2)

#define SXE2_RDMA_DB_CQ_ARM_OFFSET  (8)
#define SXE2_RDMA_DB_CQ_INFO_OFFSET (12)

#define SXE2_RDMA_CQ_ARM_SN (3)

struct sxe2_rdma_cq_uk_init_info {
	__le64 *cqe_alloc_db;
	struct sxe2_cqe *cq_base;
	__le32 *doorbell_note;
	__u32 cq_id;
	__u32 ncqe;
};

struct sxe2_cq_init_info {
	struct sxe2_rdma_ctx_dev *dev;
	u64 cq_pa;
	u64 db_pa;
	struct sxe2_rdma_cq_uk_init_info cq_uk_init_info;
	struct drv_rdma_soft_cqc cqc;
};

struct sxe2_rdma_mcq_init_info {
	u64 cq_pa;
	u64 db_pa;
	__le64 *cqe_alloc_db;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct sxe2_cqe *cq_base;
	__le32 *doorbell_note;
	struct drv_rdma_soft_cqc cqc;
};

static inline struct sxe2_rdma_cq *to_scq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct sxe2_rdma_cq, ibcq);
}

#ifdef CREATE_CQ_V1
struct ib_cq *sxe2_kcreate_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
		    struct ib_ucontext *ibucontext, struct ib_udata *udata);
#else
int sxe2_kcreate_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata);
#endif
int sxe2_kmodify_cq(struct ib_cq *cq_in, u16 cq_count, u16 cq_period);

#ifdef RDMA_DESTROY_CQ_VER_3
void sxe2_kdestroy_cq(struct ib_cq *cq_in, struct ib_udata *udata);
#elif defined RDMA_DESTROY_CQ_VER_4
int sxe2_kdestroy_cq(struct ib_cq *cq_in);
#else
int sxe2_kdestroy_cq(struct ib_cq *cq_in, struct ib_udata *udata);
#endif

int sxe2_create_mcq(struct sxe2_rdma_device *rdma_dev);
void sxe2_destroy_mcq(struct sxe2_rdma_device *rdma_dev);

int sxe2_drv_cq_destroy(struct sxe2_rdma_ctx_cq *cq, u64 scratch, bool post_sq);
int sxe2_drv_cq_create(struct sxe2_rdma_ctx_cq *cq, u64 scratch,
		       bool check_overflow, bool post_sq);
int sxe2_drv_cq_query(struct sxe2_rdma_ctx_cq *cq, u64 query_pa, u64 scratch,
		      bool post_sq);
int sxe2_drv_cq_modify(struct sxe2_rdma_ctx_cq *cq, struct sxe2_rdma_cqc *cqc,
		       u64 scratch, bool post_sq);
void sxe2_drv_cq_add_ref(struct sxe2_rdma_cq *cq);
void sxe2_drv_cq_rem_ref(struct sxe2_rdma_cq *cq);

int sxe2_drv_cq_query_op(struct sxe2_rdma_device *rdma_dev,
			 struct sxe2_rdma_ctx_cq *cq, u64 query_pa);
int sxe2_drv_cq_modify_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_cq *cq,
			  struct sxe2_rdma_cqc *cqc);
void drv_rdma_cq_set_pbl(struct sxe2_pbl_pble_rsrc *pble_rsrc,
			 struct sxe2_rdma_cq *cq, size_t page_sz, u32 ncont,
			 struct drv_rdma_soft_cqc *cqc);
void sxe2_rdma_uk_cq_init(struct sxe2_rdma_cq_uk *cq,
			  struct sxe2_rdma_cq_uk_init_info *info);
void sxe2_drv_cq_ctx_init(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_cq *cq,
			  struct sxe2_cq_init_info *info);
void sxe2_drv_cq_destroy_op(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_rdma_ctx_cq *cq);
int sxe2_drv_cq_create_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_cq *cq);
void sxe2_cq_remove_cmpls_list(struct sxe2_rdma_cq *cq);
void sxe2_drv_cleanup_ceqes(struct sxe2_rdma_ctx_cq *cq,
			    struct sxe2_rdma_ctx_ceq *ceq);
int sxe2_drv_mcq_create(struct sxe2_rdma_ctx_cq *mcq, u64 scratch,
			bool check_overflow, bool post_sq);

void sxe2_drv_mcq_ctx_init(struct sxe2_rdma_ctx_cq *cq_ctx,
			   struct sxe2_rdma_mcq_init_info *info);

#endif
