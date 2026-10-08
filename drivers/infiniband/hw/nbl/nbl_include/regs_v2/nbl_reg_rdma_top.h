/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_RDMA_TOP_LAYOUT_H
#define NBL_RDMA_TOP_LAYOUT_H

#include <linux/types.h>

#define NBL_RDMA_TOP_GLB_SYSTIME_1US_OFF		0x0060
#define NBL_RDMA_TOP_GLB_SYSTIME_1US_OFF_DRACO	0x0070
#define NBL_RDMA_TOP_SRP_CFG_EN_OFF		0x007c
#define NBL_RDMA_TOP_DYN_VERSION_OFF		0x008c
#define NBL_RDMA_TOP_HDMA_DIF_VFID_OFF		0x0024
#define NBL_RDMA_TOP_PT_DSCH0_OFF 0x0098
#define NBL_RDMA_TOP_PT_SWITCH_OFF 0x00A0

#define NBL_RDMA_TOP_SRP_WRITE_ATOMIC_FENCE_MASK	BIT(24)

#define NBL_RDMA_TOP_REG_ADDR(base, off)		((base) + (off))

/* Hdma dif vfid register address */
#define NBL_RDMA_TOP_HDMA_DIF_VFID_ADDR(base) \
	NBL_RDMA_TOP_REG_ADDR((base), NBL_RDMA_TOP_HDMA_DIF_VFID_OFF)

/* Absolute address (original name kept, base from grc_hw_rdma.h) */
#define NBL_RDMA_TOP_HDMA_DIF_VFID \
	NBL_RDMA_TOP_HDMA_DIF_VFID_ADDR(NBL_REG_RDMA_TOP)

#define NBL_RDMA_TOP_PT_EN_V4		\
	NBL_RDMA_TOP_REG_ADDR(NBL_REG_RDMA_TOP_V4, NBL_RDMA_TOP_PT_SWITCH_OFF)
#define NBL_RDMA_TOP_PT_CODE_V4		\
	NBL_RDMA_TOP_REG_ADDR(NBL_REG_RDMA_TOP_V4, NBL_RDMA_TOP_PT_DSCH0_OFF)

/* Packet Trim (PT) register unions */
union nbl_pt_en_reg {
	struct {
		bool pt_en : 1;
		bool pt_nak_pri_same_as_cnp_en : 1;
		bool pt_event_to_cc_en : 1;
		u8 rsv : 5;
	};
	u8 data;
};

union nbl_pt_code_val_reg {
	struct {
		u32 pt_code_trimmed : 6;
		u32 rsv0 : 2;
		u32 pt_code_trimmed_last : 6;
		u32 rsv1 : 2;
		u32 pt_code_trimmable : 6;
		u32 rsv2 : 2;
		u32 pt_code_control : 6;
		u32 rsv3 : 2;
	};
	u32 data;
};

union nbl_rdma_dyn_version {
	u32 data[1];
	struct {
		u32 sub_type : 4;
		u32 rsv : 28;
	};
};

_Static_assert(sizeof(union nbl_rdma_dyn_version) == sizeof(u32),
	       "nbl_rdma_dyn_version must be one dword");

#endif /* NBL_RDMA_TOP_LAYOUT_H */
