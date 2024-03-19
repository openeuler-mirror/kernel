/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_IB_COMPAT_H
#define XSC_IB_COMPAT_H

/*
 * adaptive to different ib_core versions
 */

struct xsc_ib_ucontext;

int xsc_ib_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *ah_attr,
		     struct ib_udata *udata);
int xsc_ib_destroy_ah(struct ib_ah *ibah, u32 destroy_flags);
#define xsc_ib_create_ah_def() int xsc_ib_create_ah(\
	struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr, struct ib_udata *udata)
#define xsc_ib_destroy_ah_def() int xsc_ib_destroy_ah(struct ib_ah *ah, u32 flags)

int xsc_ib_destroy_qp(struct ib_qp *qp, struct ib_udata *udata);
int xsc_ib_create_cq(struct ib_cq *ibcq,
		     const struct ib_cq_init_attr *attr,
		     struct ib_udata *udata);
int xsc_ib_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata);

// from main.c static functions
int xsc_ib_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);
void xsc_ib_dealloc_ucontext(struct ib_ucontext *ibcontext);
int xsc_ib_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
int xsc_ib_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata);
int xsc_ib_destroy_cq(struct ib_cq *cq, struct ib_udata *udata);
struct ib_mr *xsc_ib_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type, u32 max_num_sg);
#define xsc_ib_alloc_mr_def() struct ib_mr *xsc_ib_alloc_mr(\
	struct ib_pd *pd, enum ib_mr_type mr_type, u32 max_num_sg)

#define xsc_ib_destroy_qp_def() int xsc_ib_destroy_qp(struct ib_qp *qp, struct ib_udata *udata)
#define xsc_ib_create_cq_def() int xsc_ib_create_cq(struct ib_cq *ibcq,\
	const struct ib_cq_init_attr *attr, struct ib_udata *udata)
#define xsc_ib_destroy_cq_def() int xsc_ib_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
#define xsc_ib_dereg_mr_def() int xsc_ib_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
#define xsc_ib_alloc_ucontext_def() int xsc_ib_alloc_ucontext(\
	struct ib_ucontext *uctx, struct ib_udata *udata)
#define xsc_ib_dealloc_ucontext_def() void xsc_ib_dealloc_ucontext(struct ib_ucontext *ibcontext)
#define xsc_ib_alloc_pd_def() int xsc_ib_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
#define xsc_ib_dealloc_pd_def() int xsc_ib_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
#define RET_VALUE(x) (x)

#endif
