/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_HMC_H
#define NBL_IB_HMC_H

#include "osdep.h"

#define NBL_HMC_QPC_SZ 512
#define NBL_HMC_CQC_SZ 64
#define NBL_HMC_PBL_SZ 8
#define NBL_HMC_MRTE_SZ_V2 64
#define NBL_HMC_SRQC_SZ 64
#define NBL_HMC_SRQ_SHADOW_SZ SZ_16
#define NBL_HMC_ADDRESS_LEVEL0 0
#define NBL_HMC_ADDRESS_LEVEL1 1
#define NBL_HMC_HUGEPAGE 1
#define NBL_HMC_STANDARD_PAGE 0

#define NBL_HMC_MAX_SD_CNT  SZ_2K
#define NBL_HMC_SD_CNT_PER_CMD 64

#define NBL_DBQ_SIZE SZ_4M
#define NBL_TQ_RTO_SIZE SZ_4M
#define NBL_TQ_RNR_SIZE SZ_4M
#define NBL_RQDB_ARM_SIZE SZ_4M
#define NBL_SD_TYPE_GLOBAL 1
#define NBL_SD_TYPE_HMC 0
#define NBL_HW_MAX_GLO_QUEUE_SIZE SZ_16M
#define NBL_HW_GLO_SD_SIZE SZ_2M
#define NBL_HW_MAX_GLO_QUEUE_SD_NUM (NBL_HW_MAX_GLO_QUEUE_SIZE / NBL_HW_GLO_SD_SIZE)

enum nbl_hmc_rsrc_type {
	NBL_HMC_QP = 0,
	NBL_HMC_CQ = 1,
	NBL_HMC_PBL = 2,
	NBL_HMC_MR = 3,
	NBL_HMC_SRQ = 4,
	NBL_HMC_MAX, /* must be last entry */
};

enum nbl_hmc_sd_mode {
	LEVEL0_WITH_SZ_2M = 0,
	LEVEL0_WITH_SZ_4K = 1,
	LEVEL1_WITH_SZ_4K = 2,
};

enum nbl_gl_sd_type {
	NBL_SD_TYPE_RQDB_ARM = 0,
	NBL_SD_TYPE_TQ_RTO = 1,
	NBL_SD_TYPE_DBQ = 2,
	NBL_SD_TYPE_TQ_RNR = 3,
	NBL_SD_TYPE_MAX,
};

struct nbl_gl_sdtbl_info {
	u16 sd_buf_idx;
	u16 pd_buf_idx;
	u32 cnt;
	u32 max_num;   /* total count of list */
	struct nbl_dma_mem *list;
};

struct nbl_hmc_obj_info {
	u64 base;
	u32 cnt;
	u64 size;
};

struct nbl_hmc_sd_range {
	u32 start;
	u32 cnt;
};

struct nbl_hmc_pdtbl {
	u32 bp_cnt;
	struct nbl_dma_mem pd_page;
	struct nbl_dma_mem *bp_ent;
};

enum nbl_sd_entry_type {
	NBL_SD_TYPE_INVALID = 0,
	NBL_SD_TYPE_PAGED   = 1,
	NBL_SD_TYPE_DIRECT  = 2,
};

struct nbl_hmc_sd_entry {
	enum nbl_sd_entry_type entry_type;
	struct nbl_hmc_pdtbl pd_tbl;
};

struct nbl_hmc_sd_tbl {
	u32 sd_cnt;
	struct nbl_hmc_sd_entry *sd_entry;
};

struct nbl_hmc_info {
	struct nbl_hmc_obj_info *hmc_obj;
	struct nbl_hmc_sd_tbl sd_tbl;
	struct nbl_hmc_sd_tbl glo_sd_tbl[NBL_SD_TYPE_MAX];
	struct nbl_gl_sdtbl_info glo_sd_res[NBL_SD_TYPE_MAX]; /* original sd info */
};

struct nbl_hmc_obj_sd_addr {
	void *va;
	dma_addr_t dma_addr;
};
struct nbl_hmc_obj_sd_info {
	u16 obj_sd_idx;
	u16 pg_idx;
	u32 page_sz; /* all sd_addr has same page_sz */
	u32 cnt; /* hmc object really used sd cnt */
	struct nbl_hmc_obj_sd_addr *sd_addr;
};

struct nbl_init_params {
	u8 sd_addr_mode;
	u8 ddr_mode;
	enum ib_atomic_cap atomic_cap; /* V2 ONLY: get cap from grc */
	u32 devx_umem_num;
};

#define NBL_SD_VALID 1
#define NBL_PD_VALID 1

/**
 * query sd/pd format
 * dump_mask(26:24) + pd_idx(23:12) + sd_idx(11:0)
 * sd_idx is relative sd index within one sd
 * query all data of one sd: echo 0x9000000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/hmc_sd
 * query all pd of one sd: echo 0x2000000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/hmc_sd
 * query all content of one pd: echo 0x4000000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/hmc_sd
 * query all sd of one vf in sw: echo 0x8000000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/hmc_sd
 * query all sd of one vf in hw: echo 0x10000000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/hmc_sd
 * query all pd of one sd in sw: echo 0xa000000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/hmc_sd
 * query all content of one sw pd: echo 0xc000000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/hmc_sd
 */
#define PRINT_ONE_SD_DATA BIT(24)
#define PRINT_ALL_PD_WITH_ONE_SD BIT(25)
#define PRINT_ONE_PD_PAGE_WITH_ONE_SD BIT(26)
#define PRINT_SW_HMC_SD BIT(27)
#define PRINT_HW_HMC_SD BIT(28)
#define PRINT_HW_GLOBAL_SD BIT(22)
/**
 * query global sd/pd format
 * dump_mask(23:20) + pd_idx(19:8) + sd_idx(7:0)
 * sd_idx is relative sd index within one sd
 * query all sd of one pf in sw: echo 0x100000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/global_sd
 * query all pd of one sd in sw: echo 0x200000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/global_sd
 * query all sd of one pf in hw: echo 0x400000 > /sys/kernel/debug/nbl/rdma/nbl0/fun_dbg/global_sd
 */
#define PRINT_SW_GLO_SD BIT(20)
#define PRINT_SW_GLO_ALL_PD_WITH_ONE_SD BIT(21)

#define SD_PD_DUMP_MASK_USE_BITS 3
#define PD_MASK_BITS 12
#define HMC_SD_MASK_BITS 12

#define DFX_HMC_PRINT_LEN 32
#define DFX_HMC_PRINT_GRP 8
#define NBL_PD_PRINT_PERIOD 128

void nbl_get_sd_range_tbl(void);

#endif /* NBL_IB_HMC_H */
