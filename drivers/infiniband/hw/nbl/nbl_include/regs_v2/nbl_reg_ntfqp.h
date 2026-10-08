/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_NTFQP_LAYOUT_H
#define NBL_NTFQP_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_NTFQP_INT_MASK_OFF	0x0004

/* RQDB drop int mask bit */
#define NBL_NTFQP_RQDB_INT_MASK	BIT(11)

/* Register address macro */
#define NBL_NTFQP_REG_ADDR(base, off)	((base) + (off))

/* Int mask register address */
#define NBL_NTFQP_INT_MASK_ADDR(base) \
	NBL_NTFQP_REG_ADDR((base), NBL_NTFQP_INT_MASK_OFF)

#endif /* NBL_NTFQP_LAYOUT_H */
