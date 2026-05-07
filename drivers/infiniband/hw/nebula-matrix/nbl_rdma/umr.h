/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_UMR_H
#define NBL_IB_UMR_H

#include <rdma/ib_verbs.h>
#include "nbl_adapt.h"
#include "qp.h"
#include "ah.h"
#include "pble.h"
#include "mr.h"
#include "mem.h"

#define NBL_DEFF_QKEY 0x11111111

enum {
	MAX_UMR_WR = 16,
	MAX_UMR_CQE = 1024,
};

enum {
	NBL_UMR_STATE_UNINIT,
	NBL_UMR_STATE_ACTIVE,
	NBL_UMR_STATE_RECOVER,
	NBL_UMR_STATE_ERR,
};

enum {
	NBL_UMR_OP_REVOKE,
	NBL_UMR_OP_FLDPBL,
	NBL_UMR_OP_MAX
};

struct nbl_umr_context {
	struct ib_cqe cqe;
	enum ib_wc_status status;
	struct completion done;
};

void nbl_umr_resource_cleanup(struct nbl_device *dev);
int nbl_umr_resource_init(struct nbl_device *dev);
int nbl_umr_revoke_mr(struct nbl_mr *mr);
int nbl_umr_dmabuf_invcb_mr(struct nbl_mr *mr);
int nbl_create_umr_qp(struct nbl_device *nbl_dev, struct nbl_pd *pd);
void nbl_destroy_umr_qp(const struct nbl_pd *pd);
void nbl_test_umr_revoke(struct nbl_device *dev, u32 stag);
#endif /* NBL_IB_UMR_H */
