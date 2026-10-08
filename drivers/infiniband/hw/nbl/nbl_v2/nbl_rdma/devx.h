/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */

#ifndef NBL_DEVX_H
#define NBL_DEVX_H

#include <linux/types.h>
#include <rdma/ib_verbs.h>
#include "nbl_ifc.h"

enum devx_obj_type {
	DEVX_OBJ_TYPE_QP,
	DEVX_OBJ_TYPE_CQ,
};

struct nbl_device;

struct devx_obj {
	struct nbl_device *nbldev;
	enum devx_obj_type type;
	u32 obj_id; /* qpn or cqn */
	union {
		struct nbl_qp nblqp;
		struct nbl_cq nblcq;
	};
};

struct devx_umem {
	struct nbl_device *dev;
	struct ib_umem *umem;
	u32 umem_id;
	refcount_t refcnt;
	struct completion free_umem;
	bool nbl_peer;
};

#endif /* NBL_DEVX_H */
