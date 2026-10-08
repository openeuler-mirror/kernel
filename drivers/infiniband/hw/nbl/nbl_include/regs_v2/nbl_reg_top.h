/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_TOP_LAYOUT_H
#define NBL_TOP_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_TOP_DYN_VERSION_OFF			0x0004
#define NBL_TOP_CLEAR_LOGIC_OFF			0x0014
#define NBL_TOP_CLEAR_CONFIG_OFF		0x0018

/* Register address macro */
#define NBL_TOP_REG_ADDR(base, off)		((base) + (off))

/* Dynamic version register address (base from nbl_reg_base.h) */
#define NBL_TOP_DYN_VERSION_ADDR(base) \
	NBL_TOP_REG_ADDR((base), NBL_TOP_DYN_VERSION_OFF)

/* Clear logic/config register addresses (base from nbl_reg_base.h) */
#define NBL_TOP_CLEAR_LOGIC_ADDR(base) \
	NBL_TOP_REG_ADDR((base), NBL_TOP_CLEAR_LOGIC_OFF)
#define NBL_TOP_CLEAR_CONFIG_ADDR(base) \
	NBL_TOP_REG_ADDR((base), NBL_TOP_CLEAR_CONFIG_OFF)

/* Clear register write value */
#define NBL_TOP_CLEAR_VALUE			0x800

union nbl_rnic_dyn_version {
	u32 data[1];
	struct {
		u32 sub_version : 4;
		u32 sub_type : 4;
		u32 date : 8;
		u32 month : 8;
		u32 year : 8;
	};
};

_Static_assert(sizeof(union nbl_rnic_dyn_version) == sizeof(u32),
	       "nbl_rnic_dyn_version must be one dword");

#endif /* NBL_TOP_LAYOUT_H */
