/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_PD_H
#define NBL_IB_PD_H

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>

#include "nbl_adapt.h"
#include "main.h"

/**
 * protection domain info struct
 */
struct nbl_pd {
	struct ib_pd ibpd;
	struct nbl_sc_pd sc_pd;
	struct nbl_ucontext *uctx;
	struct ib_qp *umr_qp;
	struct semaphore sem;
};

static inline struct nbl_pd *to_nbl_pd(struct ib_pd *pd)
{
	return container_of(pd, struct nbl_pd, ibpd);
}

/* alloc pd */
int nbl_ib_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);

/* dealloc pd */
int nbl_ib_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata);

#endif /* NBL_IB_PD_H */
