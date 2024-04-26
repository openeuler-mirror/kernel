/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_PD_H
#define ROCE_PD_H

#include <rdma/ib_verbs.h>

#include "roce.h"

#define PD_RESP_SIZE (2 * sizeof(u32))
struct roce3_pd {
	struct ib_pd ibpd;
	u32 pdn;
	u16 func_id;
	u16 rsvd;
};

static inline struct roce3_pd *to_roce3_pd(const struct ib_pd *ibpd)
{
	return container_of(ibpd, struct roce3_pd, ibpd);
}

#endif // ROCE_PD_H
