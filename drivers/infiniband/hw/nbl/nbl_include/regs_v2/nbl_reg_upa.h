/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_UPA_LAYOUT_H
#define NBL_UPA_LAYOUT_H

#include <linux/types.h>

/* V4 RDMA dport valid bit in dport value */
#define NBL_UPA_RDMA_DPORT_VLD		BIT(16)

/* V4 RDMA dport register offsets from base */
#define NBL_UPA_RDMA_DPORT0_OFF		0x0540
#define NBL_UPA_RDMA_DPORT1_OFF		0x0544
#define NBL_UPA_RDMA_DPORT2_OFF		0x0548

/* Register address macro */
#define NBL_UPA_REG_ADDR(base, off)	((base) + (off))

/* V4 RDMA dport0 register address */
#define NBL_UPA_RDMA_DPORT0_ADDR(base) \
	NBL_UPA_REG_ADDR((base), NBL_UPA_RDMA_DPORT0_OFF)

#endif /* NBL_UPA_LAYOUT_H */
