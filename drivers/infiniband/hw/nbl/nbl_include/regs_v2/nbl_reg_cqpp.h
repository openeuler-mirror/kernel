/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_CQPP_LAYOUT_H
#define NBL_CQPP_LAYOUT_H

#include <linux/bits.h>
#include <linux/types.h>

#define NBL_CQPP_INTERRUPT_MASK_OFF	0x0004
#define NBL_CQPP_CTRL_OFF		0x0108
#define NBL_CQPP_MAX_FUN_ID_OFF		0x010c
#define NBL_CQPP_TIMEOUT_CFG_OFF		0x011c

#define NBL_CQPP_CQPINFO_TBL_OFF	0x1000
#define NBL_CQPP_CQPINFO_TBL_STRIDE	0x10
#define NBL_CQPP_CQPINFO_VALID_DW_OFF	0xc
#define NBL_CQPP_SDBASE_TBL_OFF		0x2000
#define NBL_CQPP_SDBASE_TBL_STRIDE	0x4

#define NBL_CQPP_INST_VFID_OFF		0x3000
#define NBL_CQPP_GLOBAL_CFG_FLAG_OFF	0x3008
#define NBL_CQPP_INST_SMAC_IP_OFF	0x3020
#define NBL_CQPP_INST_STAT_ID_OFF	0x30a0
#define NBL_CQPP_INST_CEQ_ID_OFF	0x30b0

#define NBL_CQPP_REG_ADDR(base, off)		((base) + (off))

#define NBL_REG_CQPP_INFO_TABLE_RAM_PI_ODD	BIT_ULL(5)
#define NBL_REG_CQPP_INFO_TABLE_RAM_PI		GENMASK_ULL(4, 0)
#define NBL_CQPP_CQPINFO_LOW_PA_MASK		0xffffffff
#define NBL_CQPP_CQPINFO_PI_DW_INDEX		2
#define NBL_CQPP_CQPINFO_PI_DW_OFF		0x8
#define NBL_CQPP_GLOBAL_CFG_ENABLE		BIT(31)

union nbl_cqp_max_fun_id_reg {
	struct {
		u32 max_fun_id : 6;
		u32 rsv0 : 25;
		u32 max_fun_id_vld : 1;
	};
	u32 data;
};

union nbl_cqp_info_tbl_reg {
	struct cqp_info_tbl_key {
		u32 cqp_base_addr_low : 32;
		u32 cqp_base_addr_high : 32;

		u32 cqp_pi : 5;
		u32 cqp_pi_odd_even_flag : 1;
		u32 rsv1 : 26;

		u32 cqp_ci : 5;
		u32 cqp_ci_odd_even_flag : 1;
		u32 rsv0 : 24;
		u32 wqe_mem_type : 1;
		u32 cqp_info_vld : 1;
	} key;
#define CQP_INFO_TBL_KEY_REG_DW_SIZE (sizeof(struct cqp_info_tbl_key) / sizeof(u32))
	u32 data[CQP_INFO_TBL_KEY_REG_DW_SIZE];
};

_Static_assert(sizeof(union nbl_cqp_info_tbl_reg) ==
	       NBL_CQPP_CQPINFO_TBL_STRIDE,
	       "nbl_cqp_info_tbl_reg size must match CQPP stride");

#define NBL_CQPP_CQPINFO_TBL_ADDR(base, id) \
	(NBL_CQPP_REG_ADDR((base), NBL_CQPP_CQPINFO_TBL_OFF) + \
	 (CQP_INFO_TBL_KEY_REG_DW_SIZE * 4 * (id)))

union nbl_sd_range_tbl_reg {
	u32 data[1];
	struct {
		u32 sd_max_num : 12;
		u32 rsv1 : 4;
		u32 sd_base_idx : 11;
		u32 rsv2 : 4;
		u32 sd_base_info_vld : 1;
	};
};

_Static_assert(sizeof(union nbl_sd_range_tbl_reg) ==
	       NBL_CQPP_SDBASE_TBL_STRIDE,
	       "nbl_sd_range_tbl_reg size must match CQPP stride");

#define NBL_CQPP_SDBASE_TBL_ADDR(base, id) \
	(NBL_CQPP_REG_ADDR((base), NBL_CQPP_SDBASE_TBL_OFF) + \
	 (id) * NBL_CQPP_SDBASE_TBL_STRIDE)

#define NBL_INST_BM_DW_SZ	4
#define NBL_INST_BM_BIT_SZ	32
#define NBL_RDMA_FULL_INST_ID	0xffffffff
#define NBL_RDMA_STAT_ID_START	2

enum nbl_inst_type {
	NBL_INST_VFID,
	NBL_INST_SMAC_IP_INDEX,
	NBL_INST_STAT_ID,
	NBL_INST_CEQ_ID,
	NBL_INST_MAX
};

enum nbl_inst_size {
	NBL_INST_VFID_SZ = 64,
	NBL_INST_SMAC_IP_SZ = 1024,
	NBL_INST_STAT_ID_SZ = 80,
	NBL_INST_CEQ_ID_SZ = 1024
};

struct nbl_rdma_inst_info {
	u32 inst_base;
	u32 inst_size;
};

#endif /* NBL_CQPP_LAYOUT_H */
