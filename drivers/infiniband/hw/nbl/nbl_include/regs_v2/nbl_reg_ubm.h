/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_UBM_LAYOUT_H
#define NBL_UBM_LAYOUT_H

/* Register offsets from base */
#define NBL_UBM_PFC_TSH_OFF			0x0030

/* Register address macro */
#define NBL_UBM_REG_ADDR(base, off)		((base) + (off))

/* PFC TSH register address (base from nbl_reg_base.h) */
#define NBL_UBM_PFC_TSH_ADDR(base) \
	NBL_UBM_REG_ADDR((base), NBL_UBM_PFC_TSH_OFF)

#endif /* NBL_UBM_LAYOUT_H */
