/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_TXM_LAYOUT_H
#define NBL_TXM_LAYOUT_H

#include <linux/types.h>

#define NBL_TXM_RDMA_TIME_SEL_OFF		0x0068
#define NBL_TXM_SQ_RAQ_SEPARATE_OFF		0x00a0
#define NBL_TXM_NET_TC_TBL_OFF			0x0500
#define NBL_TXM_NET_TC_TBL_STRIDE		0x4
#define NBL_TXM_NET_TC_TBL_ENTRY_NUM		8
#define NBL_TXM_UDP_DESTPORT_OFF		0x070c
#define NBL_TXM_SRC_ADDR_TBL_OFF		0x1000
#define NBL_TXM_SRC_ADDR_TBL_STRIDE		0x20
#define NBL_TXM_SRC_ADDR_TBL_ENTRY_NUM		1024

#define NBL_TXM_SRC_ADDR_SEQ_NUM_MASK		0xf

#define NBL_TXM_REG_ADDR(base, off)		((base) + (off))

#define NBL_TXM_NET_TC_TBL_ADDR(base, id) \
	(NBL_TXM_REG_ADDR((base), NBL_TXM_NET_TC_TBL_OFF) + \
	 (NBL_TXM_NET_TC_TBL_STRIDE * (id)))

/* PT net_tc_tbl entry register layout */
union nbl_pt_net_tc_tbl_reg {
	struct {
		u32 ecn : 2;            /* [1:0] = 0 */
		u32 dscp_low : 3;       /* [4:2] = pt_control_val low 3 bits */
		u32 dscp_high : 3;      /* [7:5] = cc_oamack_net_tc */
		u32 vlan_pri : 3;       /* [10:8] = cc_oamack_net_tc */
		u32 rsv : 21;           /* [31:11] */
	};
	u32 data;
};

union nbl_src_addr_info_tbl_reg {
	struct src_addr_info_tbl_key {
		u8 smac[6];
		u8 sip[16];
		u8 seq_num : 4;
		u8 rsv1 : 4;
		u8 rsv2[9];
	} key;
#define NBL_TXM_SRC_ADDR_TBL_DW_SIZE \
	(sizeof(struct src_addr_info_tbl_key) / sizeof(u32))
	u32 data[NBL_TXM_SRC_ADDR_TBL_DW_SIZE];
};

_Static_assert(sizeof(union nbl_src_addr_info_tbl_reg) ==
	       NBL_TXM_SRC_ADDR_TBL_STRIDE,
	       "nbl_src_addr_info_tbl_reg size must match TXM stride");

#define NBL_TXM_SRC_ADDR_TBL_ADDR(base, id) \
	(NBL_TXM_REG_ADDR((base), NBL_TXM_SRC_ADDR_TBL_OFF) + \
	 (NBL_TXM_SRC_ADDR_TBL_STRIDE * (id)))

#endif /* NBL_TXM_LAYOUT_H */
