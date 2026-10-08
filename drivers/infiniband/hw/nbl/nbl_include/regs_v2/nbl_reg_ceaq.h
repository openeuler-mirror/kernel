/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_CEAQ_LAYOUT_H
#define NBL_CEAQ_LAYOUT_H

#include <linux/types.h>

#define NBL_CEAQ_EOT_TBL_OFF		0x1000
#define RQDB_FLUSH_STATUS	0x03c8
#define ARMCQ_FLUSH_STATUS	0x03cc
#define ASIC_ARMCQ_FLUSH_STATUS_H	0x03cc
#define ASIC_ARMCQ_FLUSH_STATUS_L	0x03d0

#define NBL_CEAQ_EOT_TBL_STRIDE		0x4

#define NBL_CEAQ_REG_ADDR(base, off)	((base) + (off))

union nbl_eot_table_reg {
	u32 data[1];
	struct {
		u32 ae_flag : 1;
		u32 abnorm_cqe_flag : 1;
		u32 norm_cqe_flag : 1;
		u32 drop_flag : 1;
		u32 rsv : 28;
	};
};

_Static_assert(sizeof(union nbl_eot_table_reg) ==
	       NBL_CEAQ_EOT_TBL_STRIDE,
	       "nbl_eot_table_reg size must match CEAQ EOT stride");

#define NBL_CEAQ_EOT_TBL_ADDR(base, id) \
	(NBL_CEAQ_REG_ADDR((base), NBL_CEAQ_EOT_TBL_OFF) + \
	 (NBL_CEAQ_EOT_TBL_STRIDE * (id)))

#endif /* NBL_CEAQ_LAYOUT_H */
