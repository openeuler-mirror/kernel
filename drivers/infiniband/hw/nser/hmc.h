/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2021 Wangxun Corporation */
#ifndef NSER_HMC_H
#define NSER_HMC_H

#include "defs.h"

#define NSER_HMC_MAX_BP_COUNT			512
#define NSER_MAX_SD_ENTRIES			11
#define NSER_HW_DBG_HMC_INVALID_BP_MARK		0xca
#define NSER_HMC_INFO_SIGNATURE			0x484d5347
#define NSER_HMC_PD_CNT_IN_SD			512
#define NSER_HMC_DIRECT_BP_SIZE			0x200000
#define NSER_HMC_MAX_SD_COUNT			8192
#define NSER_HMC_PAGED_BP_SIZE			4096
#define NSER_HMC_PD_BP_BUF_ALIGNMENT		4096
#define NSER_FIRST_VF_FPM_ID			4
#define FPM_MULTIPLIER				1024

enum nser_hmc_rsrc_type {
	NSER_HMC_IW_IRRQ_LITE			= 0,
	NSER_HMC_IW_IRRQ			= 1,
	NSER_HMC_IW_ORRQ			= 2,
	NSER_HMC_IW_XF				= 3,
	NSER_HMC_IW_SQCQE			= 4,
	NSER_HMC_IW_RQCQE			= 5,
	NSER_HMC_IW_CQP				= 6,
	NSER_HMC_IW_AEQ				= 7,
	NSER_HMC_IW_QP				= 8,
	NSER_HMC_IW_CQ				= 9,
	NSER_HMC_IW_CEQ				= 10,
	NSER_HMC_IW_MR				= 11,
	NSER_HMC_IW_MG				= 12,
	NSER_HMC_IW_MG_ID			= 13,
	NSER_HMC_IW_AH				= 14,
	NSER_HMC_IW_ARP			= 15,
	NSER_HMC_IW_DUP_IRRQ			= 16,
	NSER_HMC_IW_PBLE			= 17,
	NSER_HMC_IW_FW				= 18,
	NSER_HMC_IW_SQCQEFL			= 19,
	NSER_HMC_IW_RQCQEFL			= 20,
	NSER_HMC_IW_XFFL			= 21,
	NSER_HMC_IW_IRRQ_LITE_FL		= 22,
	NSER_HMC_IW_ORRQFL			= 23,
	NSER_HMC_IW_IRDSZ			= 24,

	NSER_HMC_IW_MAX, /* Must be last entry */
};

enum nser_sd_entry_type {
	NSER_SD_TYPE_INVALID = 0,
	NSER_SD_TYPE_PAGED   = 1,
	NSER_SD_TYPE_DIRECT  = 2,
};

enum nser_hmc_obj_mem {
	NSER_HOST_MEM = 0,
	NSER_CHIP_MEM = 1,
};

struct nser_hmc_obj_info {
	u64 base;
	u32 max_cnt;
	u32 cnt;
	u64 size;
};

struct nser_hmc_bp {
	enum nser_sd_entry_type entry_type;
	struct nser_dma_mem addr;
	u32 sd_pd_index;
	u32 use_cnt;
};

struct nser_hmc_pd_entry {
	struct nser_hmc_bp bp;
	u32 sd_index;
	bool rsrc_pg:1;
	bool valid:1;
};

struct nser_hmc_pd_table {
	struct nser_dma_mem pd_page_addr;
	struct nser_hmc_pd_entry *pd_entry;
	struct nser_virt_mem pd_entry_virt_mem;
	u32 use_cnt;
	u32 sd_index;
};

struct nser_hmc_sd_entry {
	enum nser_sd_entry_type entry_type;
	bool valid;
	union {
		struct nser_hmc_pd_table pd_table;
		struct nser_hmc_bp bp;
	} u;
};

struct nser_hmc_sd_table {
	struct nser_virt_mem addr;
	u32 sd_cnt;
	u32 use_cnt;
	struct nser_hmc_sd_entry *sd_entry;
};

struct nser_hmc_info {
	u32 signature;
	u8 hmc_fn_id;
	u16 first_sd_index;
	struct nser_hmc_obj_info *hmc_obj;
	struct nser_virt_mem hmc_obj_virt_mem;
	struct nser_hmc_sd_table sd_table;
	u16 sd_indexes[NSER_HMC_MAX_SD_COUNT];
	u8 __iomem *hmc_va;
	enum nser_hmc_obj_mem mem_type;
};

struct nser_update_sd_entry {
	u64 cmd;
	u64 data;
};

struct nser_update_sds_info {
	u32 cnt;
	u8 hmc_fn_id;
	struct nser_update_sd_entry entry[NSER_MAX_SD_ENTRIES];
};

struct nser_ccq_cqe_info;
struct nser_hmc_fcn_info {
	u32 vf_id;
	u8 free_fcn;
};

struct nser_hmc_create_obj_info {
	struct nser_hmc_info *hmc_info;
	struct nser_virt_mem add_sd_virt_mem;
	u32 rsrc_type;
	u32 start_idx;
	u32 count;
	u32 add_sd_cnt;
	enum nser_sd_entry_type entry_type;
	bool privileged;
};

struct nser_hmc_del_obj_info {
	struct nser_hmc_info *hmc_info;
	struct nser_virt_mem del_sd_virt_mem;
	u32 rsrc_type;
	u32 start_idx;
	u32 count;
	u32 del_sd_cnt;
	bool privileged;
};

int nser_copy_dma_mem(struct nser_hw *hw, void *dest_buf,
		       struct nser_dma_mem *src_mem, u64 src_offset, u64 size);
int nser_sc_create_hmc_obj(struct nser_sc_dev *dev,
			    struct nser_hmc_create_obj_info *info);
int nser_sc_del_hmc_obj(struct nser_sc_dev *dev,
			 struct nser_hmc_del_obj_info *info, bool reset);
int nser_hmc_sd_one(struct nser_sc_dev *dev, u8 hmc_fn_id, u64 pa, u32 sd_idx,
		     enum nser_sd_entry_type type,
		     bool setsd);
int nser_update_sds_noccq(struct nser_sc_dev *dev,
			   struct nser_update_sds_info *info);
struct nser_vfdev *nser_vfdev_from_fpm(struct nser_sc_dev *dev,
					 u8 hmc_fn_id);
struct nser_hmc_info *nser_vf_hmcinfo_from_fpm(struct nser_sc_dev *dev,
						 u8 hmc_fn_id);
int nser_add_sd_table_entry(struct nser_hw *hw,
			     struct nser_hmc_info *hmc_info, u32 sd_index,
			     enum nser_sd_entry_type type, u64 direct_mode_sz);
int nser_add_pd_table_entry(struct nser_sc_dev *dev,
			     struct nser_hmc_info *hmc_info, u32 pd_index,
			     struct nser_dma_mem *rsrc_pg);
int nser_remove_pd_bp(struct nser_sc_dev *dev,
		       struct nser_hmc_info *hmc_info, u32 idx);
int nser_prep_remove_sd_bp(struct nser_hmc_info *hmc_info, u32 idx);
int nser_prep_remove_pd_page(struct nser_hmc_info *hmc_info, u32 idx);
#endif /* NSER_HMC_H */
