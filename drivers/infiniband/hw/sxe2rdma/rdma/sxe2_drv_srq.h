/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_srq.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_SRQ_H
#define SXE2_DRV_SRQ_H

#include "sxe2_drv_rdma_common.h"

struct sxe2_srq_drv_init_info {
	struct sxe2_qp_quanta *srq;
	struct sxe2_common_attrs *common_attrs;
	__le64 *db_note;
	u32 srq_id;
	u32 srq_size;
	u32 max_srq_frag_cnt;
	u32 srq_buf_size;
};

struct sxe2_srq_init_info {
	struct sxe2_rdma_ctx_pd *pd;
	struct sxe2_rdma_ctx_vsi *vsi;
	u64 srq_pa;
	u64 db_note_pa;
	u16 srq_limit;
	u64 srq_cmpl_ctx;
	struct sxe2_srq_drv_init_info srq_drv_init_info;
};

void sxe2_kadd_srq_ref(struct ib_srq *ibsrq);

void sxe2_krem_srq_ref(struct ib_srq *ib_srq);

int sxe2_kdestroy_srq_ctx(struct sxe2_rdma_srq_ctx *srq, u64 scratch,
			  bool post_mq);

void sxe2_kdestroy_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			      struct sxe2_rdma_srq_ctx *srq);

#ifdef RDMA_DESTROY_SRQ_VER_2
void sxe2_kdestroy_srq(struct ib_srq *ib_srq, struct ib_udata *udata);
#elif defined RDMA_DESTROY_SRQ_VER_3
int sxe2_kdestroy_srq(struct ib_srq *ib_srq);
#else
int sxe2_kdestroy_srq(struct ib_srq *ib_srq, struct ib_udata *udata);
#endif
int sxe2_kcreate_srq_ctx(struct sxe2_rdma_srq_ctx *srq, u64 scratch,
			 bool post_mq);

int sxe2_kcreate_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			    struct sxe2_rdma_srq_ctx *srq);

#ifdef CREATE_SRQ_V1
struct ib_srq *sxe2_kcreate_srq(struct ib_pd *ib_pd, struct ib_srq_init_attr *init_attr,
			struct ib_udata *udata);
#else
int sxe2_kcreate_srq(struct ib_srq *ib_srq, struct ib_srq_init_attr *init_attr,
		     struct ib_udata *udata);
#endif
int sxe2_kquery_srq_ctx(struct sxe2_rdma_srq_ctx *srq, u64 query_pa,
			u64 scratch, bool post_mq);

int sxe2_kquery_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			   struct sxe2_rdma_srq_ctx *srq, u64 query_pa);

int sxe2_kquery_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr);

int sxe2_kmodify_srq_ctx(struct sxe2_rdma_srq_ctx *srq,
			 struct sxe2_rdma_srqc *srqc, u64 scratch,
			 bool post_mq);

int sxe2_kmodify_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			    struct sxe2_rdma_srq_ctx *srq,
			    struct sxe2_rdma_srqc *srqc);

int sxe2_kmodify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
		     enum ib_srq_attr_mask attr_mask, struct ib_udata *udata);

int drv_rdma_debug_srq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_srq *srq);

void drv_rdma_debug_srq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_srq *srq);
#endif
