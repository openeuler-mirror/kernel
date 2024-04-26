/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_XRC_H
#define ROCE_XRC_H

#include <rdma/ib_verbs.h>

#include "roce.h"

struct roce3_xrcd {
	struct ib_xrcd ibxrcd;
	u32 xrcdn;
	struct ib_pd *pd;
	struct ib_cq *cq;
};

static inline struct roce3_xrcd *to_roce3_xrcd(const struct ib_xrcd *ibxrcd)
{
	return container_of(ibxrcd, struct roce3_xrcd, ibxrcd);
}

#endif // ROCE_XRC_H
