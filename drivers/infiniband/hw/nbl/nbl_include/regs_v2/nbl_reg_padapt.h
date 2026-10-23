/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_PADAPT_LAYOUT_H
#define NBL_PADAPT_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_PADAPT_MSIX_INFO_TBL_OFF_ALT		0x00020000 /* V2/V3/V4 */
#define NBL_PADAPT_MSIX_CTRL_TBL_OFF_V4		0x00010000 /* RNIC400 */
#define NBL_PADAPT_IRQ_KERNEL_CTL_TBL_OFF	0x00010000 /* ECPU / host */

/* Table strides */
#define NBL_PADAPT_MSIX_INFO_TBL_STRIDE		0x8
#define NBL_PADAPT_MSIX_CTRL_TBL_STRIDE		0x10

/* Vector control field offset in MSI-X ctrl table entry */
#define NBL_PADAPT_MSIX_CTRL_MASK_OFF		0xC
#define NBL_PADAPT_IRQ_KERNEL_CTL_MASK		BIT(0)

/* Adapter config register offsets */
#define NBL_PADAPT_CFG_AGE_TIME_OFF		0x0144
#define NBL_PADAPT_CFG_FC_UP_8BTAG_TH_OFF	0x0164
#define NBL_PADAPT_CFG_FC_UP_10BTAG_TH_OFF	0x0168

/* Register address macro */
#define NBL_PADAPT_REG_ADDR(base, off)		((base) + (off))

/* MSI-X info table address */
#define NBL_PADAPT_MSIX_INFO_TBL_ADDR_ALT(base, idx) \
	(NBL_PADAPT_REG_ADDR((base), NBL_PADAPT_MSIX_INFO_TBL_OFF_ALT) + \
	 NBL_PADAPT_MSIX_INFO_TBL_STRIDE * (idx))

/* MSI-X ctrl table address (RNIC400) */
#define NBL_PADAPT_MSIX_CTRL_TBL_ADDR(base, idx) \
	(NBL_PADAPT_REG_ADDR((base), NBL_PADAPT_MSIX_CTRL_TBL_OFF_V4) + \
	 NBL_PADAPT_MSIX_CTRL_TBL_STRIDE * (idx))

/* Multi-product MSI-X info entry: field layout differs per hw version */
union nbl_padapt_msix_info_reg {
	struct {
		u32 intrl_pnum : 16;
		u32 intrl_rate : 16;
		u32 function_id : 3;
		u32 device_id : 5;
		u32 bus_id : 8;
		u32 valid : 1;
		u32 rsv : 15;
	} vl; /* asic v1r1 */
	struct {
		u32 intrl_pnum : 16;
		u32 intrl_rate : 16;
		u32 function_id : 3;
		u32 device_id : 5;
		u32 bus_id : 8;
		u32 rsv : 15;
		u32 valid : 1;
	} vh; /* df200, asic v2r1, taihang */
	struct {
		u32 intrl_pnum : 16;
		u32 intrl_rate : 16;
		u32 function_id : 3;
		u32 device_id : 5;
		u32 bus_id : 8;
		u32 mask_en : 1;
		u32 rsv : 14;
		u32 valid : 1;
	} vr; /* RNIC400 */
	u32 data[2];
};

_Static_assert(sizeof(union nbl_padapt_msix_info_reg) ==
	       NBL_PADAPT_MSIX_INFO_TBL_STRIDE,
	       "msix info size must match info table stride");

/* MSI-X ctrl table entry (RNIC400): addr + data + vector control */
union nbl_padapt_msix_ctrl_reg {
	struct nbl_padapt_msix_ctrl {
		u32 lower_address;
		u32 upper_address;
		u32 message_data;
		u32 vector_control_mask : 1;
		u32 rsv : 31;
	} info;
#define NBL_PADAPT_MSIX_CTRL_TBL_SIZE \
	(sizeof(struct nbl_padapt_msix_ctrl))
	u8 data[NBL_PADAPT_MSIX_CTRL_TBL_SIZE];
};

_Static_assert(sizeof(union nbl_padapt_msix_ctrl_reg) ==
	       NBL_PADAPT_MSIX_CTRL_TBL_STRIDE,
	       "msix ctrl size must match ctrl table stride");

#endif /* NBL_PADAPT_LAYOUT_H */
