// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU permission table
 */

#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/cleanup.h>
#include <linux/random.h>

#include "trace/trace.h"
#include "ummu.h"
#include "flush.h"
#include "seg_mng.h"
#include "cfg_table.h"
#include "perm_table.h"
#include "queue.h"

/* allocate based on the 4 KB memory size. */
#define UMMU_BLKTBL_MAX_ENTRIES (1UL << 9)

#define UMMU_BLKTBL_ENTRY_SIZE 8
#define UMMU_BLKTBL_ENTRY_DWORD 1

#define BLK_TABLE_ENT_V (1UL << 0)
#define BLK_PHY_OFFSET 5
#define BLK_ADDR_MASK GENMASK_ULL(47, 5)
#define BLK_SIZE_ORDER_MASK GENMASK_ULL(63, 60)

/* the size of one mapt block is 64K */
#define MAPT_BLOCK_SIZE_SHIFT 16

/* the size of one level block is 16K */
#define MAPT_LEVEL_BLOCK_SHIFT 14

#define MAPT_VPAGE_SHIFT 12

/* the size of mapt is calculated at a granularity of 4KB */
#define MAPT_BLK_SZ_BASE_SHIFT 12

#define PAGE_ORDER_TO_MAPT_ORDER(page_order) \
	((int)(page_order) + PAGE_SHIFT - MAPT_BLK_SZ_BASE_SHIFT)

#define MAPT_ORDER_TO_PAGE_ORDER(mapt_order) \
	((int)(mapt_order) + MAPT_BLK_SZ_BASE_SHIFT - PAGE_SHIFT)

#define MAPT_MAX_LVL_INDEX 3
#define MAPT_MAX_ENTRY_INDEX 512
#define MAPT_MAX_LVL_ID_BIT_SIZE (UMMU_BLKTBL_MAX_ENTRIES << 2)

#define BITS_TO_BITMAP_SHIFT 6

#define INDEX_BITMAP_SIZE (UMMU_BLKTBL_MAX_ENTRIES >> BITS_TO_BITMAP_SHIFT)

#define INDEX_LEVEL_BITMAP_SIZE (UMMU_BLKTBL_MAX_ENTRIES >> 4)

#define MAX_ADDRESS_BITS 48
#define INVALID_ADDR 0xFFF

static const u32 g_mapt_range_bits[MAPT_MAX_LVL_INDEX + 1][2] = { { 47, 39 },
								 { 38, 30 },
								 { 29, 21 },
								 { 20, 12 } };

#define GET_BITS_MASK(bits) (((u64)1 << (bits)) - 1)

#define GET_LEVEL_RANGE_MASK(level) \
	(GET_BITS_MASK(g_mapt_range_bits[level][1]))

#define GET_LEVEL_BASE(addr, level)               \
	((u64)(addr) & \
	 (u64)GET_LEVEL_RANGE_MASK(level))

#define GET_LEVEL_BLOCK_INDEX(addr, level)                   \
	(((u64)(addr) >> g_mapt_range_bits[level][1]) & \
	 (GET_BITS_MASK(g_mapt_range_bits[level][0] -        \
			g_mapt_range_bits[level][1] + 1)))

#define ENTRY_ADDR_LOW(addr) FIELD_GET(GENMASK(31, 0), (addr))
#define ENTRY_ADDR_HIGH(addr) FIELD_GET(GENMASK(47, 32), (addr))

#define TABLE_ADDR_LOW(addr) FIELD_GET(GENMASK(31, 0), (addr))
#define TABLE_ADDR_HIGH(addr) FIELD_GET(GENMASK(38, 32), (addr))
#define LVL_OFFSET_LOW(offset) FIELD_GET(GENMASK(19, 0), (offset))
#define LVL_OFFSET_HIGH(offset) FIELD_GET(GENMASK(29, 20), (offset))

#define TABLE_LVL_OFFSET(low, high) (((u32)(high) << 20) | (u32)(low))
#define IS_RTE_IN_USE(addr) (((((uint64_t)(addr)) & INVALID_ADDR) == INVALID_ADDR) ? false : true)

static int ummu_alloc_mapt_block_tbl(struct io_pt_blk_table *blk_table)
{
	size_t size = UMMU_BLKTBL_MAX_ENTRIES * UMMU_BLKTBL_ENTRY_SIZE;
	void *addr;

	size = PAGE_ALIGN(size);
	addr = (__le64 *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(size));
	if (!addr) {
		pr_err("allocate mapt block table(%lu bytes) failed\n", size);
		return -ENOMEM;
	}
	blk_table->blk_tbl_phys = virt_to_phys(addr);
	blk_table->blk_tbl_size_order = get_order(size);

	return 0;
}

static void ummu_release_mapt_block_tbl(struct io_pt_blk_table *blk_table)
{
	unsigned long addr;
	u32 page_num_order;

	if (!blk_table->blk_tbl_phys)
		return;

	page_num_order = blk_table->blk_tbl_size_order;
	addr = (unsigned long)phys_to_virt(blk_table->blk_tbl_phys);

	free_pages(addr, page_num_order);
	blk_table->blk_tbl_phys = 0;
}

static void ummu_write_block_desc(__le64 *dst, struct block_args *blk_para)
{
	u64 val = BLK_TABLE_ENT_V;
	u32 page_order;

	page_order = PAGE_ORDER_TO_MAPT_ORDER(blk_para->block_size_order);
	val |= (BLK_ADDR_MASK & blk_para->out_addr);
	val |= FIELD_PREP(BLK_SIZE_ORDER_MASK, page_order);
	WRITE_ONCE(*dst, cpu_to_le64(val));
}

static int ummu_get_mapt_mem(struct ummu_domain *ummu_domain,
			     struct block_args *blk_para)
{
	struct ummu_tct_desc *tct_desc = &ummu_domain->cfgs.s1_cfg.tct;
	u8 order;

	order = (u8)PAGE_ORDER_TO_MAPT_ORDER(blk_para->block_size_order);
	if (tct_desc->mapt_blk_phys && order == tct_desc->blk_size_order) {
		blk_para->out_addr = tct_desc->mapt_blk_phys;
		return 0;
	}

	return -ENOMEM;
}

static int ummu_alloc_mapt_mem_for_entry(struct ummu_domain *ummu_domain,
					 struct block_args *blk_para)
{
	struct ummu_tct_desc *tct_desc = &ummu_domain->cfgs.s1_cfg.tct;
	struct page *page;
	void *alloc_ptr;

	if (tct_desc->mapt_en)
		return ummu_get_mapt_mem(ummu_domain, blk_para);

	/* allocate new mapt blk */
	page = alloc_pages(UMMU_GFP(GFP_KERNEL) | __GFP_ZERO | __GFP_COMP,
			   blk_para->block_size_order);
	if (!page) {
		pr_err("allocate mapt block(%lu bytes) failed\n",
		       (1U << blk_para->block_size_order) * PAGE_SIZE);
		return -ENOMEM;
	}
	alloc_ptr = page_address(page);
	blk_para->out_addr = virt_to_phys(alloc_ptr);
	tct_desc->mapt_en = 1;
	tct_desc->token_en = 0;
	tct_desc->mapt_mode = MAPT_MODE_ENTRY;
	tct_desc->mapt_blk_phys = blk_para->out_addr;
	tct_desc->blk_size_order =
		PAGE_ORDER_TO_MAPT_ORDER(blk_para->block_size_order);

	return 0;
}

static int ummu_alloc_mapt_mem_for_table(struct ummu_domain *ummu_domain,
					 struct block_args *blk_para)
{
	struct ummu_device *ummu = core_to_ummu_device(ummu_domain->base_domain.core_dev);
	struct ummu_tct_desc *tct_desc = &ummu_domain->cfgs.s1_cfg.tct;
	size_t blk_size = (1U << blk_para->block_size_order) * PAGE_SIZE;
	struct io_pt_blk_table blk_table;
	struct page *page;
	__le64 *cfg_ptr;
	void *alloc_ptr;
	int ret;

	if (blk_size < SZ_16K || blk_size > SZ_2M) {
		pr_err("mapt block size(%lu bytes) out of range\n", blk_size);
		return -EINVAL;
	}

	if (tct_desc->mapt_en && blk_para->index == 0)
		return ummu_get_mapt_mem(ummu_domain, blk_para);

	if (blk_para->index == 0 && ummu_alloc_mapt_block_tbl(&blk_table))
		return -ENOMEM;

	/* allocate new mapt blk */
	page = alloc_pages(UMMU_GFP(GFP_KERNEL) | __GFP_ZERO | __GFP_COMP,
			   blk_para->block_size_order);
	if (!page) {
		pr_err("allocate mapt block(%lu bytes) failed.\n",
		       (1U << blk_para->block_size_order) * PAGE_SIZE);
		ret = -ENOMEM;
		goto err_out;
	}

	alloc_ptr = page_address(page);
	if (ummu->cap.options & UMMU_OPT_CHK_MAPT_CONTINUITY) {
		ret = ummu_device_check_pa_continuity(ummu,
			virt_to_phys(alloc_ptr),
			PAGE_ORDER_TO_MAPT_ORDER(blk_para->block_size_order),
			blk_para->index);
		if (ret) {
			pr_err("mapt block is discontinuous ret = %d\n", ret);
			__free_pages(page, blk_para->block_size_order);
			goto err_out;
		}
	}

	blk_para->out_addr = virt_to_phys(alloc_ptr);

	if (blk_para->index == 0) {
		tct_desc->mapt_mode = MAPT_MODE_TABLE;
		tct_desc->mapt_en = 1;
		tct_desc->token_en = 0;
		tct_desc->mapt_blk_phys = blk_para->out_addr;
		tct_desc->blk_size_order =
			PAGE_ORDER_TO_MAPT_ORDER(blk_para->block_size_order);
		tct_desc->mapt_blk_tbl_phys = blk_table.blk_tbl_phys;
		tct_desc->blk_tbl_size_order =
			PAGE_ORDER_TO_MAPT_ORDER(blk_table.blk_tbl_size_order);
	}

	cfg_ptr = (__le64 *)phys_to_virt(tct_desc->mapt_blk_tbl_phys) +
		  blk_para->index * UMMU_BLKTBL_ENTRY_DWORD;
	ummu_write_block_desc(cfg_ptr, blk_para);
	return 0;
err_out:
	if (blk_para->index == 0)
		ummu_release_mapt_block_tbl(&blk_table);

	return ret;
}

int ummu_alloc_mapt_blk_mem(struct ummu_domain *ummu_domain,
			    struct block_args *blk_para)
{
	int mode;

	mode = ummu_domain->cfgs.s1_cfg.io_pt_cfg.mode;
	if (mode == MAPT_MODE_TABLE)
		return ummu_alloc_mapt_mem_for_table(ummu_domain, blk_para);
	else if (mode == MAPT_MODE_ENTRY)
		return ummu_alloc_mapt_mem_for_entry(ummu_domain, blk_para);
	else
		return -EINVAL;
}

int ummu_init_sva_mapt_context(struct ummu_domain *ummu_domain,
			       enum ummu_mapt_mode mode)
{
	struct block_args blk_para;
	int ret;

	if (mode == MAPT_MODE_TABLE) {
		blk_para.index = 0;
		blk_para.block_size_order = get_order(ummu_get_mapt_base_blk_size());
	} else {
		blk_para.block_size_order = get_order(PAGE_SIZE);
	}

	ret = ummu_alloc_mapt_blk_mem(ummu_domain, &blk_para);
	if (ret)
		pr_err("tid %u withe mode %u init sva mapt ctx failed, ret = %d.\n",
			ummu_domain->base_domain.tid, mode, ret);
	return ret;
}

static void ummu_free_blk_tbl_ent(__le64 *dst)
{
	phys_addr_t blk_phys;
	u32 free_page_order;
	struct page *page;
	bool ent_live;
	u64 val;

	val = le64_to_cpu(dst[0]);
	ent_live = !!(val & BLK_TABLE_ENT_V);
	if (!ent_live)
		return;

	WRITE_ONCE(dst[0], 0);

	blk_phys = FIELD_GET(BLK_ADDR_MASK, val) << BLK_PHY_OFFSET;
	page = virt_to_page(phys_to_virt(blk_phys));
	free_page_order = FIELD_GET(BLK_SIZE_ORDER_MASK, val);
	free_page_order = MAPT_ORDER_TO_PAGE_ORDER(free_page_order);
	__free_pages(page, free_page_order);
}

static void ummu_release_mapt_for_entry(struct ummu_domain *ummu_domain)
{
	struct ummu_tct_desc *tct_desc = &ummu_domain->cfgs.s1_cfg.tct;
	phys_addr_t phys_addr = tct_desc->mapt_blk_phys;
	struct page *page;
	u32 size_order;

	tct_desc->mapt_en = 0;
	tct_desc->mapt_blk_phys = 0;
	ummu_write_tct_desc(core_to_ummu_device(ummu_domain->base_domain.core_dev),
			    &ummu_domain->cfgs, true);

	size_order = MAPT_ORDER_TO_PAGE_ORDER(tct_desc->blk_size_order);
	page = virt_to_page(phys_to_virt(phys_addr));
	__free_pages(page, size_order);
}

static void ummu_release_mapt_for_table(struct ummu_domain *ummu_domain,
					u32 blk_index)
{
	struct ummu_tct_desc *tct_desc = &ummu_domain->cfgs.s1_cfg.tct;
	struct io_pt_blk_table blk_table;
	__le64 *tbl_ptr, *release_ptr;
	phys_addr_t phys_addr;

	phys_addr = tct_desc->mapt_blk_tbl_phys;
	tbl_ptr = phys_to_virt(phys_addr);
	if (!tbl_ptr)
		return;
	release_ptr = tbl_ptr + blk_index * UMMU_BLKTBL_ENTRY_DWORD;
	ummu_free_blk_tbl_ent(release_ptr);

	if (blk_index == 0) {
		blk_table.blk_tbl_phys = tct_desc->mapt_blk_tbl_phys;
		blk_table.blk_tbl_size_order =
			MAPT_ORDER_TO_PAGE_ORDER(tct_desc->blk_tbl_size_order);

		tct_desc->mapt_en = 0;
		tct_desc->mapt_blk_phys = 0;
		tct_desc->mapt_blk_tbl_phys = 0;
		ummu_write_tct_desc(core_to_ummu_device(ummu_domain->base_domain.core_dev),
				    &ummu_domain->cfgs, true);

		ummu_release_mapt_block_tbl(&blk_table);
	}
}

static void ummu_release_mapt_info_by_index(struct ummu_domain *ummu_domain,
					    u32 blk_index)
{
	enum ummu_mapt_mode mode;

	mode = ummu_domain->cfgs.s1_cfg.io_pt_cfg.mode;
	if (mode == MAPT_MODE_TABLE)
		ummu_release_mapt_for_table(ummu_domain, blk_index);
	else if (mode == MAPT_MODE_ENTRY)
		ummu_release_mapt_for_entry(ummu_domain);
	else
		pr_err("tid %u Get invalid mapt mode %u when release mapt\n",
		       ummu_domain->base_domain.tid, mode);
}

void ummu_release_domain_mapt_mem(struct ummu_domain *ummu_domain)
{
	struct ummu_tct_desc *tct_desc = &ummu_domain->cfgs.s1_cfg.tct;
	struct io_pt_blk_table blk_tbl;
	__le64 *blk_tbl_ptr, *ent_ptr;
	unsigned long addr;
	u32 size_order;
	int i, mode;

	guard(mutex)(&ummu_domain->init_mutex);

	if (!tct_desc->mapt_en || !tct_desc->mapt_blk_phys)
		return;

	/* copy tct config */
	mode = ummu_domain->cfgs.s1_cfg.io_pt_cfg.mode;
	if (mode == MAPT_MODE_TABLE) {
		blk_tbl_ptr = phys_to_virt(tct_desc->mapt_blk_tbl_phys);
		blk_tbl.blk_tbl_phys = tct_desc->mapt_blk_tbl_phys;
		blk_tbl.blk_tbl_size_order =
			MAPT_ORDER_TO_PAGE_ORDER(tct_desc->blk_tbl_size_order);
	}
	size_order = MAPT_ORDER_TO_PAGE_ORDER(tct_desc->blk_size_order);
	addr = (unsigned long)phys_to_virt(tct_desc->mapt_blk_phys);

	/* update tct to issue hardware stop */
	tct_desc->mapt_en = 0;
	tct_desc->mapt_blk_phys = 0;
	tct_desc->mapt_blk_tbl_phys = 0;
	ummu_write_tct_desc(core_to_ummu_device(ummu_domain->base_domain.core_dev),
			    &ummu_domain->cfgs, true);

	/* release mapt memory */
	if (mode == MAPT_MODE_TABLE) {
		for (i = 1; i < UMMU_BLKTBL_MAX_ENTRIES; i++) {
			ent_ptr = blk_tbl_ptr + i * UMMU_BLKTBL_ENTRY_DWORD;
			ummu_free_blk_tbl_ent(ent_ptr);
		}
		ummu_release_mapt_block_tbl(&blk_tbl);
	}
	free_pages(addr, size_order);
}

void ummu_release_mapt_blk_mem(struct ummu_domain *ummu_domain,
			       struct block_args *blk_para)
{
	struct ummu_tct_desc *tct_desc = &ummu_domain->cfgs.s1_cfg.tct;

	guard(mutex)(&ummu_domain->init_mutex);

	if (!tct_desc->mapt_en)
		return;

	ummu_release_mapt_info_by_index(ummu_domain, blk_para->index);
}

static int ummu_check_perm(enum ummu_mapt_perm perm)
{
	switch (perm) {
	case MAPT_PERM_R:
		break;
	case MAPT_PERM_W:
		break;
	case MAPT_PERM_RW:
		break;
	case MAPT_PERM_ATOMIC_R:
		break;
	case MAPT_PERM_ATOMIC_W:
		break;
	case MAPT_PERM_ATOMIC_RW:
		break;
	default:
		pr_err("failed to check perm = %u\n", perm);
		return -EINVAL;
	}

	return 0;
}

static int ummu_check_ebit(enum ummu_ebit_state e_bit)
{
	if (e_bit >= UMMU_EBIT_END || e_bit < UMMU_EBIT_OFF) {
		pr_err("e_bit = %d is invalid\n", e_bit);
		return -EINVAL;
	}

	return 0;
}

static void ummu_gen_random(u32 *value)
{
	u32 val;

	get_random_bytes(&val, sizeof(u32));
	*value = val;
}

static void ummu_get_token(struct ummu_token_info *token, u32 *value)
{
	if (token->input == 0) {
		*value = token->tokenVal;
	} else if (token->input == 1) {
		ummu_gen_random(value);
		token->tokenVal = *value;
	}
}

static int ummu_check_data(enum ummu_mapt_mode mode,
			   struct ummu_data_info *data_info)
{
	if (data_info->data_size == 0) {
		pr_err("invalid argument data_size\n");
		return -EINVAL;
	}

	if ((u64)data_info->data >> MAX_ADDRESS_BITS ||
	    ((u64)data_info->data_size - 1) >> MAX_ADDRESS_BITS ||
	    ((u64)data_info->data + (u64)data_info->data_size - 1) >> MAX_ADDRESS_BITS) {
		pr_err("the address or memory size exceeds the upper limit\n");
		return -EINVAL;
	}

	if (ummu_check_perm(data_info->perm) != 0 ||
	    ummu_check_ebit(data_info->e_bit) != 0)
		return -EINVAL;

	if (data_info->token != NULL &&
	    data_info->token->input != 0 && data_info->token->input != 1) {
		pr_err("token input invalid\n");
		return -EINVAL;
	}

	if (mode == MAPT_MODE_TABLE &&
	    !IS_ALIGNED((u64)data_info->data, BIT_ULL(MAPT_VPAGE_SHIFT))) {
		pr_err("table mode, data_base must be 4K aligned\n");
		return -EINVAL;
	}

	return 0;
}

bool ummu_perm_table_mode_is_valid(enum ummu_mapt_mode mode)
{
	if (mode >= MAPT_MODE_END || mode < MAPT_MODE_TABLE)
		return false;

	return true;
}

static void ummu_perm_data_preproc(struct ummu_data_info *data_info)
{
	data_info->token_check = (data_info->token != NULL) ? 1UL : 0UL;
	if (data_info->token_check)
		ummu_get_token(data_info->token, &data_info->tokenval);

	data_info->data_base = (u64)data_info->data;
	data_info->data_limit = (u64)data_info->data +
				(u64)data_info->data_size - 1;
}

static void ummu_entry_fill_node(struct ummu_mapt_entry_node *node,
				 struct ummu_data_info *data_info)
{
	node->permission = (u32)data_info->perm;
	node->base_low = ENTRY_ADDR_LOW(data_info->data_base);
	node->base_high = ENTRY_ADDR_HIGH(data_info->data_base);
	node->limit_low = ENTRY_ADDR_LOW(data_info->data_limit);
	node->limit_high = ENTRY_ADDR_HIGH(data_info->data_limit);
	node->token_check = data_info->token_check;
	node->e_bit = (u32)data_info->e_bit;
	if (data_info->token_check == 1) {
		node->token_val_0 = data_info->tokenval;
		node->token_val_1 = data_info->tokenval;
		node->nonce = 1;
	}
	node->valid = 1;
	dma_wmb();
}

static int ummu_add_token(void *mapt_node, struct ummu_data_info *data_info)
{
	struct ummu_mapt_entry_node *node =
		(struct ummu_mapt_entry_node *)mapt_node;

	if (node->valid == 1 && node->nonce == 1) {
		node->token_val_1 = data_info->tokenval;
		node->nonce = UMMU_MAX_TOKEN_NUM;
		return 0;
	}

	pr_err("node invalid or nonce error\n");
	return -EINVAL;
}

static int ummu_remove_token(void *mapt_node, struct ummu_data_info *data_info)
{
	struct ummu_mapt_entry_node *node = (struct ummu_mapt_entry_node *)mapt_node;

	if (node->token_val_0 == data_info->tokenval) {
		node->token_val_0 = node->token_val_1;
	} else if (node->token_val_1 == data_info->tokenval) {
		node->token_val_1 = node->token_val_0;
	} else {
		pr_err("invalid tokenval\n");
		return -EINVAL;
	}

	node->nonce = 1;
	return 0;
}

static int ummu_update_token(void *mapt_node, struct ummu_data_info *data_info)
{
	switch (data_info->op) {
	case UMMU_ADD_TOKEN:
		return ummu_add_token(mapt_node, data_info);
	case UMMU_REMOVE_TOKEN:
		return ummu_remove_token(mapt_node, data_info);
	default:
		pr_err("invalid op type = %d\n", data_info->op);
		return -EINVAL;
	}
}

static void ummu_table_fill_node(struct ummu_mapt_table_node *node,
	u64 base, u64 limit, struct ummu_data_info *data_info, bool new_node)
{
	node->permission = (u64)data_info->perm;
	node->base_low = TABLE_ADDR_LOW(base);
	node->base_high = TABLE_ADDR_HIGH(base);
	node->limit_low = TABLE_ADDR_LOW(limit);
	node->limit_high = TABLE_ADDR_HIGH(limit);
	node->token_check = data_info->token_check;
	node->e_bit = (u64)data_info->e_bit;
	if (data_info->token_check == 1) {
		node->token_val_0 = data_info->tokenval;
		node->token_val_1 = data_info->tokenval;
		node->nonce = 1;
	}
	node->f_bit = 0;

	if (new_node) {
		node->type = 1;
		node->valid = 1;
	}

	dma_wmb();
}

static inline void ummu_modify_entry_cnt(struct ummu_mapt_block *block,
					 u64 lv_offset, int cnt)
{
	u32 index = lv_offset / MAPT_MAX_ENTRY_INDEX;

	if (cnt > 0) {
		block->level_entry_cnt[index] += (u16)cnt;
		return;
	}
	block->level_entry_cnt[index] -= (u16)(-cnt);
}

static struct ummu_mapt_block *ummu_alloc_new_mapt_block(struct ummu_mapt_info *mapt_info,
							 size_t blk_size,
							 u32 blk_idx,
							 struct ummu_domain *domain)
{
	struct ummu_mapt_block *mapt_blk;
	struct block_args blk_para;
	int ret;

	if ((blk_idx != 0 && !mapt_info->block_base.table_ctx->expan) ||
	    blk_idx >= UMMU_BLKTBL_MAX_ENTRIES)
		return ERR_PTR(-ERANGE);

	mapt_blk = kcalloc(1, sizeof(*mapt_blk), GFP_KERNEL);
	if (!mapt_blk)
		return ERR_PTR(-ENOMEM);

	blk_para.index = blk_idx;
	blk_para.block_size_order = get_order(blk_size);
	ret = ummu_alloc_mapt_blk_mem(domain, &blk_para);
	if (ret) {
		pr_err("alloc mapt mgnt info failed, ret = %d\n", ret);
		goto err_free_blk;
	}

	mapt_blk->blk_size = blk_size;
	mapt_blk->block_id = blk_idx;
	mapt_blk->block_addr = phys_to_virt(blk_para.out_addr);
	if (mapt_info->block_base.table_ctx->block_cnt == 0)
		mapt_info->block_base.table_ctx->mapt_block_base = mapt_blk;

	ret = xa_err(xa_store(&mapt_info->block_base.table_ctx->xa, blk_idx, mapt_blk, GFP_KERNEL));
	if (ret) {
		pr_err("xa_store blk mem failed, ret = %d\n", ret);
		ret = -EFAULT;
		goto err_release_blk_mem;
	}
	mapt_info->block_base.table_ctx->block_cnt++;

	return mapt_blk;

err_release_blk_mem:
	ummu_release_mapt_blk_mem(domain, &blk_para);
err_free_blk:
	kfree(mapt_blk);
	mapt_blk = NULL;
	return ERR_PTR(ret);
}

static struct ummu_mapt_table_node *ummu_alloc_level_block(struct ummu_mapt_info *mapt_info,
						    struct ummu_mapt_table_node *pre_node,
						    struct ummu_mapt_block *pre_node_mapt_blk)
{
	struct ummu_mapt_table_node *node;
	struct ummu_mapt_block *mapt_blk;
	struct ummu_domain *u_domain;
	u32 blk_idx, lvl_id;
	u64 next_lvl_offset;
	size_t blk_size;

	lvl_id = find_first_zero_bit(mapt_info->block_base.table_ctx->level_block_bitmap,
				     MAPT_MAX_LVL_ID_BIT_SIZE);
	if (lvl_id >= MAPT_MAX_LVL_ID_BIT_SIZE) {
		pr_err("invalid level id = %u\n.", lvl_id);
		return ERR_PTR(-ERANGE);
	}

	pre_node->next_block = 0;
	blk_idx = lvl_id / MAPT_PER_LVL_BLOCK_CNT;
	blk_size = mapt_info->block_base.table_ctx->blk_exp_size;

	mapt_blk = xa_load(&mapt_info->block_base.table_ctx->xa, blk_idx);
	if (mapt_blk == NULL) {
		u_domain = to_ummu_domain(mapt_info->domain);
		mapt_blk = ummu_alloc_new_mapt_block(mapt_info, blk_size, blk_idx, u_domain);
		if (IS_ERR(mapt_blk)) {
			pr_err("alloc mapt block failed, tid = %u\n", u_domain->base_domain.tid);
			return ERR_PTR(PTR_ERR(mapt_blk));
		}
		pre_node->next_block = 1;
	} else {
		if (pre_node_mapt_blk != mapt_blk)
			pre_node->next_block = 1;
	}

	pre_node->next_lv_index = blk_idx;
	next_lvl_offset = MAPT_MAX_ENTRY_INDEX * (lvl_id % MAPT_PER_LVL_BLOCK_CNT);
	pre_node->next_lv_offset_low = LVL_OFFSET_LOW(next_lvl_offset);
	pre_node->next_lv_offset_high = LVL_OFFSET_HIGH(next_lvl_offset);

	set_bit(lvl_id, mapt_info->block_base.table_ctx->level_block_bitmap);
	node = (struct ummu_mapt_table_node *)mapt_blk->block_addr + next_lvl_offset;
	mapt_blk->level_cnt++;

	return node;
}

static void update_ummu_gather(struct ummu_plbi_gather *ummu_gather, u32 cmd_type,
			       u64 data1, u64 data2)
{
	if (ummu_gather->data_cnt >= UMMU_GATHER_MAX_CNT) {
		pr_warn("buffer is full, some plb may not be flushed.\n");
		return;
	}

	switch (cmd_type) {
	case CMD_PLBI_OS_VA:
		ummu_gather->plbis[ummu_gather->data_cnt].plbi_va.va = data1;
		ummu_gather->plbis[ummu_gather->data_cnt].plbi_va.size = data2;
		break;
	case CMD_PLBI_OS_N:
		ummu_gather->plbis[ummu_gather->data_cnt].plbi_f_bit.lvl_idx = data1;
		ummu_gather->plbis[ummu_gather->data_cnt].plbi_f_bit.lvl_offset = data2;
		break;
	default:
		pr_warn("wrong cmd op code.\n");
		return;
	}

	ummu_gather->plbis[ummu_gather->data_cnt].opcode = cmd_type;
	ummu_gather->data_cnt++;
}

static void ummu_table_type_switch_plbi(struct ummu_data_info *data_info,
					uint64_t node_base, uint64_t node_limit,
					uint32_t level)
{
	u64 va, size, full_addr;

	if (data_info->lvl < MAPT_MAX_LVL_INDEX && !data_info->head_flag)
		full_addr = data_info->data_limit;
	else
		full_addr = data_info->data_base;

	va = (full_addr & (~GET_LEVEL_RANGE_MASK(level))) | node_base;
	size = node_limit - node_base + 1;

	update_ummu_gather(data_info->ummu_gather, CMD_PLBI_OS_VA, va, size);
}

static int ummu_table_fill_node_by_level(struct ummu_data_info *data_info,
	u32 level, struct ummu_mapt_table_node *pre_node,
	u64 lvl_base, u64 lvl_limit);
static int ummu_table_fill_head_node_free_bit(struct ummu_data_info *data_info,
	u32 level, struct ummu_mapt_table_node *pre_node,
	struct ummu_mapt_table_node *cur_node, u64 node_base, u64 node_limit)
{
	struct ummu_mapt_table_node *next_lvl_blk_base;
	struct ummu_mapt_block *mapt_blk;
	u64 lvl_offset;

	mapt_blk = (struct ummu_mapt_block *)xa_load(
			&data_info->mapt_info->block_base.table_ctx->xa,
			pre_node->next_lv_index);
	lvl_offset = (u64)TABLE_LVL_OFFSET(pre_node->next_lv_offset_low,
						pre_node->next_lv_offset_high);

	if (cur_node->valid == 0) {
		ummu_table_fill_node(cur_node, node_base, node_limit,
					data_info, true);
		ummu_modify_entry_cnt(mapt_blk, lvl_offset, 1);
		return 0;
	}

	if (cur_node->f_bit) {
		ummu_table_fill_node(cur_node, node_base, node_limit,
					data_info, false);
		update_ummu_gather(data_info->ummu_gather, CMD_PLBI_OS_N,
		cur_node->next_lv_index,
		TABLE_LVL_OFFSET(cur_node->next_lv_offset_low,
				cur_node->next_lv_offset_high));
		return 0;
	}

	if (cur_node->type == 1) {
		next_lvl_blk_base = ummu_alloc_level_block(
			data_info->mapt_info, cur_node, mapt_blk);
		if (IS_ERR_OR_NULL(next_lvl_blk_base)) {
			pr_err("alloc new level_block failed\n");
			return -ENOMEM;
		}
		cur_node->type = 0;
	}

	return ummu_table_fill_node_by_level(data_info,
		level + 1U, cur_node, node_base, node_limit);
}

static int ummu_table_fill_head_node(struct ummu_data_info *data_info, u32 level,
	struct ummu_mapt_table_node *pre_node,
	struct ummu_mapt_table_node *cur_node, u64 node_base, u64 node_limit)
{
	struct ummu_mapt_table_node *next_lvl_blk_base;
	struct ummu_mapt_block *mapt_blk;
	uint64_t cur_base, cur_limit;
	u64 lvl_offset;

	mapt_blk = (struct ummu_mapt_block *)xa_load(
			&data_info->mapt_info->block_base.table_ctx->xa,
			pre_node->next_lv_index);
	lvl_offset = (u64)TABLE_LVL_OFFSET(pre_node->next_lv_offset_low,
						pre_node->next_lv_offset_high);

	cur_base = ADDR_FULL(cur_node->base_low, cur_node->base_high);
	cur_limit =  ADDR_FULL(cur_node->limit_low, cur_node->limit_high);
	if (cur_node->valid == 1) {
		if (!IS_RTE_IN_USE(cur_base) && !IS_RTE_IN_USE(cur_limit)) {
			ummu_table_fill_node(cur_node, node_base, node_limit,
				data_info, false);
			ummu_table_type_switch_plbi(data_info, 0,
				INVALID_ADDR, level);
			return 0;
		}

		if (cur_node->type == 1) {
			next_lvl_blk_base = ummu_alloc_level_block(
				data_info->mapt_info, cur_node, mapt_blk);
			if (IS_ERR_OR_NULL(next_lvl_blk_base)) {
				pr_err("alloc new level_block failed\n");
				return -ENOMEM;
			}
			cur_node->type = 0;
		}
		return ummu_table_fill_node_by_level(data_info,
			level + 1U, cur_node, node_base, node_limit);
	} else {
		ummu_table_fill_node(cur_node, node_base, node_limit,
					data_info, true);
		ummu_modify_entry_cnt(mapt_blk, lvl_offset, 1);
	}

	return 0;
}

static int ummu_table_fill_node_by_level(struct ummu_data_info *data_info,
					 u32 level, struct ummu_mapt_table_node *pre_node,
					 u64 lvl_base, u64 lvl_limit)
{
	struct ummu_mapt_table_node *lvl_blk_base, *cur_node;
	u64 node_base, node_limit, lvl_msk, lvl_offset;
	struct ummu_mapt_block *mapt_blk;
	u16 base_idx, limit_idx;
	int ret;

	if (level > MAPT_MAX_LVL_INDEX) {
		pr_err("level overflow\n");
		return -EINVAL;
	}

	lvl_offset = (u64)TABLE_LVL_OFFSET(pre_node->next_lv_offset_low,
					   pre_node->next_lv_offset_high);
	mapt_blk = xa_load(&data_info->mapt_info->block_base.table_ctx->xa,
			   pre_node->next_lv_index);
	if (mapt_blk == NULL) {
		pr_err("invalid mapt_block\n");
		return -EINVAL;
	}
	lvl_blk_base = (struct ummu_mapt_table_node *)mapt_blk->block_addr + lvl_offset;

	base_idx = (u16)GET_LEVEL_BLOCK_INDEX(lvl_base, level);
	limit_idx = (u16)GET_LEVEL_BLOCK_INDEX(lvl_limit, level);
	lvl_msk = GET_LEVEL_RANGE_MASK(level);

	if ((data_info->lvl >= MAPT_MAX_LVL_INDEX) && (base_idx != limit_idx))
		data_info->lvl = level;

	for (u16 i = base_idx; i <= limit_idx; i++) {
		cur_node = lvl_blk_base + i;
		node_base = (i == base_idx) ? (lvl_base & lvl_msk) : 0U;
		node_limit = (i == limit_idx) ? (lvl_limit & lvl_msk) : lvl_msk;
		/* middle rtes */
		if (base_idx < i && i < limit_idx) {
			if (cur_node->valid == 1) {
				pr_err("node suppose to be invalid\n");
				return -EINVAL;
			}
			ummu_table_fill_node(cur_node, node_base, node_limit,
					     data_info, true);
			ummu_modify_entry_cnt(mapt_blk, lvl_offset, 1);
			continue;
		}

		/* head or tail rte */
		if (data_info->lvl == level)
			data_info->head_flag = (i == base_idx) ? 1 : 0;

		if (data_info->mapt_info->free_bit)
			ret = ummu_table_fill_head_node_free_bit(data_info, level, pre_node,
								 cur_node, node_base, node_limit);
		else
			ret = ummu_table_fill_head_node(data_info, level, pre_node, cur_node,
							node_base, node_limit);

		if (ret)
			return ret;
	}

	return 0;
}

static void ummu_free_level_block(struct ummu_mapt_info *mapt_info,
				  struct ummu_mapt_table_node *prev_node)
{
	struct ummu_mapt_table_ctx *table_ctx = mapt_info->block_base.table_ctx;
	u32 lv_offset, lvl_id, lv_index;
	struct block_args blk_para = { 0 };
	struct ummu_mapt_block *mapt_blk;
	struct ummu_domain *u_domain;

	if (IS_ERR_OR_NULL(mapt_info->domain))
		return;

	lv_offset = 0;
	lv_index = 0;
	if (prev_node != NULL) {
		lv_offset = TABLE_LVL_OFFSET(prev_node->next_lv_offset_low,
					     prev_node->next_lv_offset_high);
		lv_index = prev_node->next_lv_index;
	}

	mapt_blk = xa_load(&table_ctx->xa, lv_index);
	if (mapt_blk == NULL) {
		pr_err("invalid level id = %u\n", lv_index);
		return;
	}

	lvl_id = (mapt_blk->block_id * MAPT_PER_LVL_BLOCK_CNT) +
		  (lv_offset / MAPT_MAX_ENTRY_INDEX);
	if (lvl_id) {
		mapt_blk->level_cnt--;
		clear_bit(lvl_id, table_ctx->level_block_bitmap);
	}

	u_domain = to_ummu_domain(mapt_info->domain);
	if (mapt_blk->level_cnt == 0 && table_ctx->block_cnt > 1) {
		xa_erase(&table_ctx->xa, mapt_blk->block_id);
		table_ctx->block_cnt--;
		blk_para.index = mapt_blk->block_id;
		ummu_release_mapt_blk_mem(u_domain, &blk_para);
		kfree(mapt_blk);
	}
}

static void ummu_table_clear_node(struct ummu_mapt_table_node *node,
				  struct ummu_mapt_info *mapt_info,
				  struct ummu_mapt_table_node *pre_node)
{
	u32 lv_offset = TABLE_LVL_OFFSET(pre_node->next_lv_offset_low,
					 pre_node->next_lv_offset_high);
	struct ummu_mapt_block *mapt_blk;

	mapt_blk = xa_load(&mapt_info->block_base.table_ctx->xa, pre_node->next_lv_index);
	if (mapt_blk == NULL) {
		pr_err("invalid mapt_block\n");
		return;
	}

	if (node->type == 1) {
		memset(node, 0, sizeof(*node));
		ummu_modify_entry_cnt(mapt_blk, lv_offset, -1);
		if (mapt_blk->level_entry_cnt[lv_offset / MAPT_MAX_ENTRY_INDEX] == 0) {
			ummu_free_level_block(mapt_info, pre_node);
			pre_node->type = 1;
			pre_node->next_block = 0;
			pre_node->next_lv_offset_high = 0;
			pre_node->next_lv_offset_low = 0;
			pre_node->next_lv_index = 0;
		}
		dma_wmb();
	} else {
		pr_err("Mapt block node type is invalid.\n");
	}
}

static int ummu_table_clear_node_by_level(struct ummu_data_info *data_info,
					  u32 level, struct ummu_mapt_table_node *pre_node,
					  u64 lvl_base, u64 lvl_limit);
static int ummu_table_clear_head_node(struct ummu_data_info *data_info,
				      u32 level, struct ummu_mapt_table_node *pre_node,
				      struct ummu_mapt_table_node *cur_node, u64 node_base,
				      u64 node_limit)
{
	uint32_t lvl_idx, lvl_offset;
	uint64_t cur_base, cur_limit;
	int ret;

	lvl_idx = cur_node->next_lv_index;
	lvl_offset = TABLE_LVL_OFFSET(cur_node->next_lv_offset_low,
			cur_node->next_lv_offset_high);
	cur_base = ADDR_FULL(cur_node->base_low, cur_node->base_high);
	cur_limit = ADDR_FULL(cur_node->limit_low, cur_node->limit_high);
	if (!IS_RTE_IN_USE(cur_base) && !IS_RTE_IN_USE(cur_limit)) {
		if (cur_node->type == 1) {
			pr_err("Next level not exist.\n");
			return -EINVAL;
		}

		ret = ummu_table_clear_node_by_level(data_info, level + 1U,
			cur_node, node_base, node_limit);
		if (cur_node->type == 1) {
			ummu_table_clear_node(cur_node, data_info->mapt_info, pre_node);
			ummu_table_type_switch_plbi(data_info, 0,
				INVALID_ADDR, level);
		}

		return ret;
	}

	if (cur_base == node_base && cur_limit == node_limit) {
		if (cur_node->type == 0) {
			cur_node->base_low = INVALID_ADDR;
			cur_node->limit_low = INVALID_ADDR;
			cur_node->base_high = 0;
			cur_node->limit_high = 0;
			cur_node->permission = 0;
			dma_wmb();
			return 0;
		}

		ummu_table_clear_node(cur_node, data_info->mapt_info, pre_node);
		return 0;
	}

	if (cur_node->type == 1) {
		pr_err("Next level not exist.\n");
		return -EINVAL;
	}

	ret =  ummu_table_clear_node_by_level(data_info, level + 1U, cur_node,
		node_base, node_limit);
	if (cur_node->type == 1) {
		ummu_table_type_switch_plbi(data_info, cur_base,
			cur_limit, level);
	}

	return ret;
}

static int ummu_table_clear_head_node_free_bit(struct ummu_data_info *data_info,
	u32 level, struct ummu_mapt_table_node *pre_node,
	struct ummu_mapt_table_node *cur_node, u64 node_base,
	u64 node_limit)
{
	u32 lvl_idx, lvl_offset;
	u64 cur_base, cur_limit;
	int ret;

	lvl_idx = cur_node->next_lv_index;
	lvl_offset = TABLE_LVL_OFFSET(cur_node->next_lv_offset_low,
					 cur_node->next_lv_offset_high);
	if (cur_node->f_bit) {
		if (cur_node->type == 1) {
			pr_err("next level not exist.\n");
			return -EINVAL;
		}

		ret = ummu_table_clear_node_by_level(data_info, level + 1U,
			cur_node, node_base, node_limit);
		if (cur_node->type == 1) {
			ummu_table_clear_node(cur_node, data_info->mapt_info, pre_node);
			update_ummu_gather(data_info->ummu_gather, CMD_PLBI_OS_N,
					   lvl_idx, lvl_offset);
		}

		return ret;
	}

	cur_base = ADDR_FULL(cur_node->base_low, cur_node->base_high);
	cur_limit = ADDR_FULL(cur_node->limit_low, cur_node->limit_high);
	if (cur_base == node_base && cur_limit == node_limit) {
		if (cur_node->type == 0) {
			cur_node->f_bit = 1;
			return 0;
		}

		ummu_table_clear_node(cur_node, data_info->mapt_info, pre_node);
		return 0;
	}

	if (cur_node->type == 1) {
		pr_err("next level not exist.\n");
		return -EINVAL;
	}

	ret = ummu_table_clear_node_by_level(data_info, level + 1U, cur_node,
					     node_base, node_limit);
	if (cur_node->type == 1)
		ummu_table_type_switch_plbi(data_info, cur_base, cur_limit, level);

	return ret;
}

static int ummu_table_clear_node_by_level(struct ummu_data_info *data_info,
					  u32 level, struct ummu_mapt_table_node *pre_node,
					  u64 lvl_base, u64 lvl_limit)
{
	struct ummu_mapt_table_node *lvl_blk_base, *cur_node;
	u64 node_base, node_limit, lvl_msk;
	struct ummu_mapt_block *mapt_blk;
	u16 base_idx, limit_idx;
	int ret;

	if (level > MAPT_MAX_LVL_INDEX) {
		pr_err("level overflow\n");
		return -EINVAL;
	}

	mapt_blk = xa_load(&data_info->mapt_info->block_base.table_ctx->xa,
			   pre_node->next_lv_index);
	if (mapt_blk == NULL) {
		pr_err("invalid mapt_block\n");
		return -EINVAL;
	}
	lvl_blk_base = (struct ummu_mapt_table_node *)mapt_blk->block_addr +
			TABLE_LVL_OFFSET(pre_node->next_lv_offset_low,
					 pre_node->next_lv_offset_high);

	base_idx = (u16)GET_LEVEL_BLOCK_INDEX(lvl_base, level);
	limit_idx = (u16)GET_LEVEL_BLOCK_INDEX(lvl_limit, level);
	lvl_msk = GET_LEVEL_RANGE_MASK(level);
	if (data_info->lvl >= MAPT_MAX_LVL_INDEX && base_idx != limit_idx)
		data_info->lvl = level;

	for (u16 i = base_idx; i <= limit_idx; i++) {
		cur_node = lvl_blk_base + i;
		if (cur_node->valid == 0) {
			pr_err("unexpected failed, rte suppose to be valid\n");
			return -EINVAL;
		}

		node_base = (i == base_idx) ? (lvl_base & lvl_msk) : 0UL;
		node_limit = (i == limit_idx) ? (lvl_limit & lvl_msk) : lvl_msk;
		/* middle rtes */
		if (base_idx < i && i < limit_idx) {
			ummu_table_clear_node(cur_node, data_info->mapt_info, pre_node);
			continue;
		}

		/* head or tail rte */
		if (data_info->lvl == level)
			data_info->head_flag = (i == base_idx) ? 1 : 0;

		if (data_info->mapt_info->free_bit)
			ret = ummu_table_clear_head_node_free_bit(data_info, level, pre_node,
								  cur_node, node_base, node_limit);
		else
			ret = ummu_table_clear_head_node(data_info, level, pre_node, cur_node,
							 node_base, node_limit);

		if (ret)
			return ret;
	}

	return 0;
}

static int ummu_table_update_token_by_level(struct ummu_data_info *data_info,
	u32 level, struct ummu_mapt_table_node *pre_node,
	u64 lvl_base, u64 lvl_limit);
static int ummu_table_update_node_token_free_bit(struct ummu_data_info *data_info,
	u32 level, struct ummu_mapt_table_node *cur_node,
	u64 node_base, u64 node_limit)
{
	u64 cur_base, cur_limit;

	if (cur_node->f_bit) {
		if (cur_node->type == 1) {
			pr_err("next level not exist.\n");
			return -EINVAL;
		}

		return ummu_table_update_token_by_level(data_info, level + 1U,
			cur_node, node_base, node_limit);
	}

	cur_base = ADDR_FULL(cur_node->base_low, cur_node->base_high);
	cur_limit = ADDR_FULL(cur_node->limit_low, cur_node->limit_high);
	if (cur_base == node_base && cur_limit == node_limit)
		return ummu_update_token((void *)cur_node, data_info);

	if (cur_node->type == 1) {
		pr_err("next level not exist.\n");
		return -EINVAL;
	}

	return ummu_table_update_token_by_level(data_info,
			level + 1U, cur_node, node_base, node_limit);
}

static int ummu_table_update_node_token(struct ummu_data_info *data_info,
	u32 level, struct ummu_mapt_table_node *cur_node,
	u64 node_base, u64 node_limit)
{
	u64 cur_base, cur_limit;
	int ret;

	cur_base = ADDR_FULL(cur_node->base_low, cur_node->base_high);
	cur_limit = ADDR_FULL(cur_node->limit_low, cur_node->limit_high);
	if (cur_base == node_base && cur_limit == node_limit) {
		ret = ummu_update_token((void *)cur_node, data_info);
		if (ret != 0)
			return ret;
	} else if (cur_node->type == 0) {
		return ummu_table_update_token_by_level(data_info,
			level + 1U, cur_node, node_base, node_limit);
	} else {
		pr_err("unexpected failed\n");
		return -EINVAL;
	}

	return 0;
}

static int ummu_table_update_token_by_level(struct ummu_data_info *data_info,
					    u32 level, struct ummu_mapt_table_node *pre_node,
					    u64 lvl_base, u64 lvl_limit)
{
	u64 node_base, node_limit, lvl_msk;
	struct ummu_mapt_table_node *lvl_blk_base, *cur_node;
	struct ummu_mapt_block *mapt_blk;
	u16 base_idx, limit_idx;
	int ret;

	if (level > MAPT_MAX_LVL_INDEX) {
		pr_err("level overflow\n");
		return -EINVAL;
	}

	mapt_blk = xa_load(&data_info->mapt_info->block_base.table_ctx->xa,
			   pre_node->next_lv_index);
	if (mapt_blk == NULL) {
		pr_err("invalid mapt_block\n");
		return -EINVAL;
	}
	lvl_blk_base = (struct ummu_mapt_table_node *)mapt_blk->block_addr +
			TABLE_LVL_OFFSET(pre_node->next_lv_offset_low,
					 pre_node->next_lv_offset_high);

	base_idx = (u16)GET_LEVEL_BLOCK_INDEX(lvl_base, level);
	limit_idx = (u16)GET_LEVEL_BLOCK_INDEX(lvl_limit, level);
	lvl_msk = GET_LEVEL_RANGE_MASK(level);

	for (u16 i = base_idx; i <= limit_idx; i++) {
		cur_node = lvl_blk_base + i;
		if (cur_node->valid == 0) {
			pr_err("unexpected failed, rte suppose to be valid\n");
			return -EINVAL;
		}

		node_base = (i == base_idx) ? (lvl_base & lvl_msk) : 0UL;
		node_limit = (i == limit_idx) ? (lvl_limit & lvl_msk) : lvl_msk;
		/* middle rtes */
		if (base_idx < i && i < limit_idx) {
			ret = ummu_update_token((void *)cur_node, data_info);
			if (ret != 0)
				return ret;
			continue;
		}

		/* head or tail rte */
		if (data_info->mapt_info->free_bit)
			ret = ummu_table_update_node_token_free_bit(data_info, level, cur_node,
								    node_base, node_limit);
		else
			ret = ummu_table_update_node_token(data_info, level, cur_node, node_base,
							   node_limit);

		if (ret)
			return ret;
	}

	return 0;
}

static int ummu_entry_op(struct ummu_mapt_info *mapt_info,
			 struct ummu_data_info *data_info)
{
	struct ummu_mapt_entry_node *node = mapt_info->block_base.entry_block;

	switch (data_info->op) {
	case UMMU_GRANT:
		ummu_entry_fill_node(node, data_info);
		return 0;
	case UMMU_ADD_TOKEN:
	case UMMU_REMOVE_TOKEN:
		return ummu_update_token((void *)node, data_info);
	case UMMU_UNGRANT:
		memset(node, 0, sizeof(*node));
		return 0;
	default:
		pr_err("invalid op code\n");
		return -EINVAL;
	}
}

static int ummu_table_op(struct ummu_mapt_info *mapt_info,
			 struct ummu_data_info *data_info)
{
	struct ummu_mapt_table_node node = {0};
	int ret;

	data_info->mapt_info = mapt_info;

	switch (data_info->op) {
	case UMMU_GRANT:
		ret = ummu_table_fill_node_by_level(data_info, 0,
			&node, data_info->data_base, data_info->data_limit);
		if (ret)
			ummu_table_clear_node_by_level(data_info, 0, &node,
				data_info->data_base, data_info->data_limit);
		return ret;
	case UMMU_ADD_TOKEN:
	case UMMU_REMOVE_TOKEN:
		return ummu_table_update_token_by_level(data_info, 0,
			&node, data_info->data_base, data_info->data_limit);
	case UMMU_UNGRANT:
		return ummu_table_clear_node_by_level(data_info, 0, &node,
			data_info->data_base, data_info->data_limit);
	default:
		pr_err("invalid op code\n");
		return -EINVAL;
	}
}

static int ummu_grant_imp(struct ummu_mapt_info *mapt_info,
			  struct ummu_data_info *data)
{
	if (mapt_info->mode == MAPT_MODE_ENTRY)
		return ummu_entry_op(mapt_info, data);
	else
		return ummu_table_op(mapt_info, data);
}

static int ummu_update_info(enum ummu_grant_op_type opt,
			    struct ummu_mapt_info *mapt_info,
			    struct ummu_data_info *grant_param)
{
	struct maple_tree *granted_addr_mng;

	if (mapt_info->mode != MAPT_MODE_TABLE)
		return 0;

	granted_addr_mng = mapt_info->block_base.table_ctx->granted_addr_mng;

	switch (opt) {
	case UMMU_GRANT:
		return ummu_insert_new_addr(granted_addr_mng, grant_param);
	case UMMU_ADD_TOKEN:
	case UMMU_REMOVE_TOKEN:
		return ummu_token_update(granted_addr_mng, grant_param, opt);
	case UMMU_UNGRANT:
		return ummu_delete_addr(granted_addr_mng, grant_param);
	default:
		return -EINVAL;
	}
}

int ummu_perm_grant(struct iommu_domain *domain, void *va, size_t size,
		    int perm, void *cookie, struct iommu_plb_gather *plb_gather)
{
	struct ummu_domain *ummu_dom = to_ummu_domain(domain);
	u64 ias = core_to_ummu_device(ummu_dom->base_domain.core_dev)->cap.ias;
	struct ummu_seg_attr *seg_attr = NULL;
	struct ummu_mapt_info *mapt_info;
	struct ummu_data_info data_info;
	int ret;

	data_info.ummu_gather = cookie;
	if (data_info.ummu_gather->cookie == NULL) {
		pr_err("cookie is invalid\n");
		return -EINVAL;
	}

	seg_attr = (struct ummu_seg_attr *)data_info.ummu_gather->cookie;
	data_info.data = (void *)((u64)va & GENMASK_ULL((int64_t)ias - 1, 0));
	data_info.data_size = size;
	data_info.perm = (enum ummu_mapt_perm)perm;
	data_info.token = seg_attr->token;
	data_info.e_bit = seg_attr->e_bit;
	data_info.lvl = MAPT_MAX_LVL_INDEX;

	mapt_info = &ummu_dom->cfgs.s1_cfg.io_pt_cfg;
	if (mapt_info == NULL || mapt_info->valid == 0) {
		pr_err("invalid mapt_info\n");
		return -EINVAL;
	}

	if (!ummu_perm_table_mode_is_valid(mapt_info->mode)) {
		pr_err("tid %u get invalid perm table mode[%d].\n",
		       ummu_dom->base_domain.tid, mapt_info->mode);
		return -EINVAL;
	}

	if (ummu_check_data(mapt_info->mode, &data_info) != 0)
		return -EINVAL;

	ummu_perm_data_preproc(&data_info);

	trace_ummu_perm_grant(ummu_dom->base_domain.tid, (u64)va, size, perm,
			      data_info.token != NULL);

	data_info.op = ummu_grant_check(mapt_info, &data_info);
	if (data_info.op == UMMU_OP_END)
		return -EINVAL;

	ret = ummu_grant_imp(mapt_info, &data_info);
	if (ret == 0)
		ret = ummu_update_info(data_info.op, mapt_info, &data_info);

	plb_gather->va = (void *)data_info.data_base;
	/* plb_gather->size = 0 indicates PLB will not be flushed */
	if (mapt_info->positive_plbi || (data_info.op == UMMU_GRANT && !ret))
		plb_gather->size = 0;
	else
		plb_gather->size = data_info.data_size;

	data_info.tokenval = 0;
	return ret;
}

static int ummu_ungrant_imp(struct ummu_mapt_info *mapt_info,
			    struct ummu_data_info *data)
{
	if (mapt_info->mode == MAPT_MODE_ENTRY)
		return ummu_entry_op(mapt_info, data);
	else
		return ummu_table_op(mapt_info, data);
}

int ummu_perm_ungrant(struct iommu_domain *domain, void *va, size_t size,
		      void *cookie, struct iommu_plb_gather *plb_gather)
{
	struct ummu_domain *ummu_dom = to_ummu_domain(domain);
	u64 ias = core_to_ummu_device(ummu_dom->base_domain.core_dev)->cap.ias;
	struct ummu_mapt_info *mapt_info;
	struct ummu_data_info data_info;
	int ret = 0;

	data_info.ummu_gather = cookie;
	data_info.data = (void *)((u64)va & GENMASK_ULL((int64_t)ias - 1, 0));

	mapt_info = &ummu_dom->cfgs.s1_cfg.io_pt_cfg;
	if (mapt_info == NULL || mapt_info->valid == 0) {
		pr_err("tid %u get invalid mapt_info\n", ummu_dom->base_domain.tid);
		return -EINVAL;
	}

	if (!ummu_perm_table_mode_is_valid(mapt_info->mode)) {
		pr_err("tid %u get invalid perm table mode[%d]\n",
			ummu_dom->base_domain.tid, mapt_info->mode);
		return -EINVAL;
	}

	data_info.lvl = MAPT_MAX_LVL_INDEX;
	data_info.data_size = size;
	data_info.bytoken = data_info.ummu_gather->cookie == NULL ? 0 : 1;
	if (data_info.bytoken)
		data_info.tokenval =
			((struct ummu_token_info *)data_info.ummu_gather->cookie)->tokenVal;

	data_info.data_base = (u64)data_info.data;
	data_info.data_limit = (u64)data_info.data + (u64)size - 1;

	if (mapt_info->mode == MAPT_MODE_TABLE &&
	    !IS_ALIGNED((u64)data_info.data, BIT_ULL(MAPT_VPAGE_SHIFT))) {
		pr_err("table mode, data_base must be 4K aligned\n");
		ret = -EINVAL;
		goto clear_info;
	}

	trace_ummu_perm_ungrant(ummu_dom->base_domain.tid, (u64)va, size,
				data_info.ummu_gather->cookie != NULL, ret);

	data_info.op = ummu_ungrant_check(mapt_info, &data_info);
	if (data_info.op == UMMU_OP_END) {
		ret = -EINVAL;
		goto clear_info;
	}

	ret = ummu_ungrant_imp(mapt_info, &data_info);
	if (ret == 0)
		ret = ummu_update_info(data_info.op, mapt_info, &data_info);

	plb_gather->va = (void *)data_info.data_base;
	plb_gather->size = data_info.data_size;

clear_info:
	data_info.tokenval = 0;
	return ret;
}

static int ummu_init_ksva_mapt_for_table(struct ummu_mapt_info *pt_cfg)
{
	struct ummu_mapt_table_ctx *table_ctx;
	struct ummu_mapt_table_node pre_node;
	struct ummu_mapt_table_node *root;
	int ret;

	table_ctx = kzalloc(sizeof(*table_ctx), GFP_KERNEL);
	if (!table_ctx)
		return -ENOMEM;

	xa_init(&table_ctx->xa);

	table_ctx->granted_addr_mng = ummu_create_seg_mng();
	if (!table_ctx->granted_addr_mng) {
		pr_err("init rbtree failed.\n");
		ret = -ENOMEM;
		goto err_create_rbtree;
	}

	table_ctx->expan = ummu_get_mapt_blk_exp();
	table_ctx->blk_exp_size = ummu_get_mapt_base_blk_size();
	if (!IS_ALIGNED((u64)table_ctx->blk_exp_size,
	    BIT_ULL(MAPT_VPAGE_SHIFT))) {
		pr_err("invalid blk exp size.\n");
		ret = -EINVAL;
		goto err_lvl_block_bitmap;
	}

	table_ctx->level_block_bitmap = bitmap_zalloc(MAPT_MAX_LVL_ID_BIT_SIZE, GFP_KERNEL);
	if (!table_ctx->level_block_bitmap) {
		ret = -ENOMEM;
		goto err_lvl_block_bitmap;
	}

	pt_cfg->block_base.table_ctx = table_ctx;
	root = ummu_alloc_level_block(pt_cfg, &pre_node, NULL);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto err_lvl_blk_alloc;
	}
	if (!root) {
		ret = -ENOMEM;
		goto err_lvl_blk_alloc;
	}

	return 0;

err_lvl_blk_alloc:
	bitmap_free(table_ctx->level_block_bitmap);
err_lvl_block_bitmap:
	ummu_destroy_seg_mng(table_ctx->granted_addr_mng);
err_create_rbtree:
	xa_destroy(&table_ctx->xa);
	kfree(table_ctx);
	return ret;
}

static int ummu_init_ksva_mapt_for_entry(struct ummu_domain *domain, size_t size)
{
	struct ummu_mapt_entry_node *node;
	struct block_args blk_para;
	int ret;

	blk_para.block_size_order = get_order(size);
	ret = ummu_alloc_mapt_blk_mem(domain, &blk_para);
	if (ret)
		return ret;

	node = phys_to_virt(blk_para.out_addr);
	node->valid = 0;
	node->nonce = 0;
	domain->cfgs.s1_cfg.io_pt_cfg.block_base.entry_block = node;
	return 0;
}

int ummu_init_ksva_mapt(struct ummu_domain *domain, enum ummu_mapt_mode mode)
{
	struct ummu_domain_cfgs *cfg = &domain->cfgs;
	struct ummu_mapt_info *pt_cfg = &cfg->s1_cfg.io_pt_cfg;
	int ret;

	pt_cfg->mode = mode;

	if (mode == MAPT_MODE_TABLE)
		ret = ummu_init_ksva_mapt_for_table(pt_cfg);
	else
		ret = ummu_init_ksva_mapt_for_entry(domain, PAGE_SIZE);

	if (ret) {
		pr_err("init ksva mapt info failed, ret = %d.\n", ret);
		return ret;
	}

	pt_cfg->valid = 1;
	return 0;
}

void ummu_release_ksva_mapt(struct ummu_domain *domain)
{
	struct ummu_mapt_info *pt_cfg = &domain->cfgs.s1_cfg.io_pt_cfg;
	enum ummu_mapt_mode mode = pt_cfg->mode;
	struct ummu_mapt_block *mapt_blk;
	unsigned long index;

	if (!pt_cfg->valid)
		return;

	if (mode == MAPT_MODE_TABLE) {
		xa_for_each(&pt_cfg->block_base.table_ctx->xa, index, mapt_blk)
			kfree(mapt_blk);

		xa_destroy(&pt_cfg->block_base.table_ctx->xa);
		bitmap_free(pt_cfg->block_base.table_ctx->level_block_bitmap);
		ummu_destroy_seg_mng(pt_cfg->block_base.table_ctx->granted_addr_mng);
		kfree(pt_cfg->block_base.table_ctx);
	}

	ummu_release_domain_mapt_mem(domain);
}
