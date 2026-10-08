/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_HDMA_LAYOUT_H
#define NBL_HDMA_LAYOUT_H

#include <linux/types.h>

#define NBL_HDMA_CPU_CTRL_OFF		0x0804
#define NBL_HDMA_VF_CLEAR_OFF		0x0828
#define NBL_HDMA_VF_ENABLE_OFF		0x08a8
#define NBL_HDMA_BDF_TBL_OFF		0x1000
#define NBL_HDMA_BDF_TBL_STRIDE		0x4
#define NBL_HDMA_PF_TBL_OFF		0x2000
#define NBL_HDMA_PF_TBL_STRIDE		0x4

#define NBL_HDMA_VF_BITMAP_BIT_NUM	32
#define NBL_HDMA_VF_REG_SIZE		4

#define NBL_HDMA_REG_ADDR(base, off)	((base) + (off))

union nbl_hdma_cpu_ctrl_reg {
	u32 data[1];
	struct hdma_cpu_ctrl_key {
		u32 rsv : 28;
		u32 retry_cnt : 4;
	} key;
};

union nbl_hdma_bdf_tbl_reg {
	struct hdma_bdf_tbl_key {
		u32 function_id : 3;
		u32 device_id : 5;
		u32 bus_id : 8;
		u32 host_en : 1;
		u32 tph_en : 1;
		u32 rlo_en : 1;
		u32 rsv : 13;
	} key;
#define HDMA_BDF_TBL_DW_SZ (sizeof(struct hdma_bdf_tbl_key) / sizeof(u32))
	u32 data[HDMA_BDF_TBL_DW_SZ];
};

_Static_assert(sizeof(union nbl_hdma_bdf_tbl_reg) ==
	       NBL_HDMA_BDF_TBL_STRIDE,
	       "nbl_hdma_bdf_tbl_reg size must match HDMA stride");

#define NBL_HDMA_BDF_TBL_ADDR(base, id) \
	(NBL_HDMA_REG_ADDR((base), NBL_HDMA_BDF_TBL_OFF) + \
	 (HDMA_BDF_TBL_DW_SZ * 4 * (id)))

union nbl_hdma_pf_tbl_reg {
	struct hdma_pf_tbl_key {
		u32 bdf_tbl_idx : 8;
		u32 resv : 24;
	} key;
#define HDMA_PF_TBL_DW_SZ (sizeof(struct hdma_pf_tbl_key) / sizeof(u32))
	u32 data[HDMA_PF_TBL_DW_SZ];
};

_Static_assert(sizeof(union nbl_hdma_pf_tbl_reg) ==
	       NBL_HDMA_PF_TBL_STRIDE,
	       "nbl_hdma_pf_tbl_reg size must match HDMA stride");

#define NBL_HDMA_PF_TBL_ADDR(base, id) \
	(NBL_HDMA_REG_ADDR((base), NBL_HDMA_PF_TBL_OFF) + \
	 (HDMA_PF_TBL_DW_SZ * 4 * (id)))

#define NBL_HDMA_VF_ENABLE_ADDR(base, id) \
	(NBL_HDMA_REG_ADDR((base), NBL_HDMA_VF_ENABLE_OFF) + \
	 NBL_HDMA_VF_REG_SIZE * ((id) / NBL_HDMA_VF_BITMAP_BIT_NUM))

#define NBL_HDMA_VF_CLEAR_ADDR(base, id) \
	(NBL_HDMA_REG_ADDR((base), NBL_HDMA_VF_CLEAR_OFF) + \
	 NBL_HDMA_VF_REG_SIZE * ((id) / NBL_HDMA_VF_BITMAP_BIT_NUM))

#define NBL_HDMA_VF_BITMAP_BIT(id)	((id) % NBL_HDMA_VF_BITMAP_BIT_NUM)

#endif /* NBL_HDMA_LAYOUT_H */
