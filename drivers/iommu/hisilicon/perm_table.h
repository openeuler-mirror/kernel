/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU permission table
 */

#ifndef __UMMU_PERM_TABLE_H__
#define __UMMU_PERM_TABLE_H__

#include <linux/ummu_core.h>
#include <linux/maple_tree.h>

#define UMMU_MAX_TOKEN_NUM 2
#define MAPT_PER_LVL_BLOCK_CNT 4

struct ummu_mapt_entry_node {
	u32 valid : 1;
	u32 reserved_0 : 2;
	u32 e_bit : 1;
	u32 permission : 6;
	u32 reserved_1 : 22;
	u32 reserved_2;

	u32 base_low;
	u32 base_high : 16;
	u32 reserved_3 : 12;
	u32 reserved_4 : 3;
	u32 token_check : 1;

	u32 limit_low;
	u32 limit_high : 16;
	u32 reserved_5 : 12;
	u32 reserved_6 : 2;
	u32 nonce : 2;

	u32 token_val_0;
	u32 token_val_1;
};

struct ummu_mapt_table_node {
	u32 valid : 1;
	u32 type : 1;
	u32 next_block : 1;
	u32 e_bit : 1;
	u32 permission : 6;
	u32 f_bit : 1;
	u32 reserved_0 : 1;
	u32 next_lv_offset_low : 20;

	u32 next_lv_offset_high : 10;
	u32 reserved_1 : 6;
	u32 next_lv_index : 16;

	u32 base_low;
	u32 base_high : 7;
	u32 reserved_2 : 21;
	u32 reserved_3 : 3;
	u32 token_check : 1;

	u32 limit_low;
	u32 limit_high : 7;
	u32 reserved_4 : 21;
	u32 flag : 2;
	u32 nonce : 2;

	u32 token_val_0;
	u32 token_val_1;
};

struct io_pt_blk_table {
	phys_addr_t blk_tbl_phys;
	u8 blk_tbl_size_order;
};

struct ummu_mapt_block {
	void *block_addr;
	size_t blk_size;
	u32 block_id;
	u16 level_cnt;
	u16 level_entry_cnt[MAPT_PER_LVL_BLOCK_CNT];
};

#define ADDR_FULL(low, high) (((u64)(high) << 32) | (u64)(low))

struct ummu_mapt_table_ctx {
	bool expan;
	u16 block_cnt;
	size_t blk_exp_size;
	unsigned long *level_block_bitmap;
	struct maple_tree *granted_addr_mng;

	struct ummu_mapt_block *mapt_block_base;
	struct xarray xa;
};

struct ummu_mapt_info {
	struct iommu_domain *domain;
	enum ummu_mapt_mode mode;
	union {
		struct ummu_mapt_entry_node *entry_block;
		struct ummu_mapt_table_ctx *table_ctx;
	} block_base;

	u16 valid;
	u8 positive_plbi;
	u8 free_bit;
};

struct ummu_seg_info {
	u64 start_addr;
	u64 grant_size;
	enum ummu_mapt_perm permission;
	enum ummu_ebit_state e_bit;
	u8 token_check; /* true: check token  false: not check token */
	u8 token_count;
	u32 token_val[UMMU_MAX_TOKEN_NUM];
};

enum ummu_grant_op_type {
	UMMU_GRANT = 0,
	UMMU_ADD_TOKEN = 1,
	UMMU_REMOVE_TOKEN = 2,
	UMMU_UNGRANT = 3,
	UMMU_OP_END
};

struct ummu_data_info {
	void *data;
	size_t data_size;
	enum ummu_mapt_perm perm;
	struct ummu_token_info *token;
	u32 tokenval;
	u64 data_base;
	u64 data_limit;
	u32 token_check;
	int bytoken;
	enum ummu_ebit_state e_bit;
	enum ummu_grant_op_type op;
	struct ummu_mapt_info *mapt_info;
	u8 lvl;
	u8 head_flag;
	struct ummu_plbi_gather *ummu_gather;
};

struct ummu_domain;

int ummu_init_sva_mapt_context(struct ummu_domain *ummu_domain, enum ummu_mapt_mode mode);

int ummu_alloc_mapt_blk_mem(struct ummu_domain *ummu_domain, struct block_args *blk_para);

void ummu_release_domain_mapt_mem(struct ummu_domain *ummu_domain);

void ummu_release_mapt_blk_mem(struct ummu_domain *ummu_domain, struct block_args *blk_para);

bool ummu_perm_table_mode_is_valid(enum ummu_mapt_mode mode);

int ummu_init_ksva_mapt(struct ummu_domain *domain, enum ummu_mapt_mode mode);

void ummu_release_ksva_mapt(struct ummu_domain *domain);

int ummu_perm_grant(struct iommu_domain *domain, void *va, size_t size,
		    int perm, void *cookie, struct iommu_plb_gather *plb_gather);

int ummu_perm_ungrant(struct iommu_domain *domain, void *va, size_t size,
		      void *cookie, struct iommu_plb_gather *plb_gather);

#endif /* __UMMU_PERM_TABLE_H__ */
