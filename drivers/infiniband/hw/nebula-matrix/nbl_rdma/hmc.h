/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_HMC_H
#define NBL_IB_HMC_H

#include "osdep.h"

#define NBL_HMC_OBJ_SD_CNT 32
#define NBL_HMC_ADDRESS_LEVEL0 0
#define NBL_HMC_ADDRESS_LEVEL1 1
#define NBL_HMC_HUGEPAGE 1
#define NBL_HMC_STANDARD_PAGE 0

#define NBL_HMC_QPC_SZ 512
#define NBL_HMC_CQC_SZ 64
#define NBL_HMC_PBL_SZ 8
#define NBL_HMC_MRTE_SZ 32

#define NBL_HMC_MAX_SD_CNT  SZ_2K
#define NBL_HMC_SD_CNT_PER_CMD 64

struct nbl_hmc_sdtbl {
	u32 index;
	u32 max_cnt;
	struct nbl_dma_mem *sd_ent;
};

enum nbl_hmc_rsrc_type {
	NBL_HMC_QP = 0,
	NBL_HMC_CQ = 1,
	NBL_HMC_PBL = 2,
	NBL_HMC_MR = 3,
	NBL_HMC_MAX, /* must be last entry */
};

enum nbl_cqp_hmc_profile {
	NBL_HMC_PROFILE_HUGEPAGE = 0,
	NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY = 1,
	NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY = 2,
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
	u32 ext_buf_num;
	u32 used_buf_num;
	struct nbl_hmc_sd_entry *sd_entry;
};

struct sys_page_node {
	struct list_head node;
	struct nbl_dma_mem mem;
	u32 offset;
};

struct sys_page_list {
	u32 total_size;
	u32 used_size;
	u32 page_cnt;
	struct list_head pg_list;
};

struct nbl_hmc_info {
	struct nbl_hmc_obj_info *hmc_obj;
	struct nbl_hmc_sd_tbl sd_tbl;
	struct sys_page_list sys_pages;
};

struct nbl_hmc_obj_sd_addr {
	void *va;
	dma_addr_t dma_addr;
};
struct nbl_hmc_obj_sd_info {
	u32 page_sz; /* all sd_addr has same page_sz */
	u32 cnt; /* hmc object really used sd cnt */
	struct nbl_hmc_obj_sd_addr *sd_addr;
};

struct nbl_init_params {
	u8 sd_addr_mode;
	u8 resv;
};

#define NBL_SD_VALID 1
#define NBL_PD_VALID 1

#define PRINT_ALL_SD (1 << 0)
#define PRINT_ALL_PD_WITH_ONE_SD (1 << 1)
#define PRINT_ONE_PD_PAGE_WITH_ONE_SD (1 << 2)

#define SD_PD_DUMP_MASK_USE_BITS 3
#define PD_MASK_BITS 9
#define HMC_SD_MASK_BITS 11

#define MAX_INLINE_SD_NUM_PER_CMD 4
#define START_OFFSET_IN_SD_CMD 32
#define SD_ENTRY_SIZE 8
#define NBL_QP_CQ_RESV_MEM_SZ SZ_4K
#define NBL_PD_PRINT_PERIOD 128

u16 nbl_hmc_get_rel_sd_idx(u32 dump_mask);
u16 nbl_hmc_get_rel_pd_idx(u32 dump_mask);

#endif /* NBL_IB_HMC_H */
