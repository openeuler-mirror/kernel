// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus hisi decoder: " fmt

#include <linux/dma-mapping.h>
#include <linux/ktime.h>
#include <ub/ubfi/ubfi.h>
#include "../../ubus.h"
#include "hisi-ubus.h"
#include "hisi-decoder.h"

enum entry_type {
	INVALID_ENTRY = 0x0,
	PAGE_TABLE = 0x1,
	PAGE = 0x2,
	RANGE_TABLE = 0x3,
};

struct page_table_entry {
	u64 entry_type : 2;
	u64 reserve1 : 10;
	u64 next_lv_addr : 36;
	u64 reserve2 : 8;
	u64 pgtlb_attr : 8;
};

struct page_entry {
	/* dw0 ~ dw1 */
	u64 entry_type : 2;
	u64 reserve0 : 6;
	u64 token_vld : 1;
	u64 reserve1 : 3;
	u64 ub_addr : 52;
	/* dw2 ~ dw3 */
	u64 reserve2 : 32;
	u64 tpg_num : 20;
	u64 order_type : 2;
	u64 order_id : 8;
	u64 reserve3 : 2;
	/* dw4 ~ dw5 */
	u64 dst_eid_low;
	/* dw6 ~ dw7 */
	u64 dst_eid_high;
	/* dw8 ~ dw9 */
	u64 token_id : 20;
	u64 reserve4 : 12;
	u64 token_value : 32;
	/* dw10 ~ dw11 */
	u64 upi : 16;
	u64 reserve5 : 48;
	/* dw12 ~ dw13 */
	u64 reserve6;
	/* dw14 ~ dw15 */
	u64 reserve7 : 32;
	u64 src_eid : 20;
	u64 reserve8 : 12;
};

struct range_table_entry {
	/* dw0 ~ dw1 */
	u64 entry_type : 2;
	u64 reserve0 : 6;
	u64 token_vld : 1;
	u64 reserve1 : 3;
	u64 next_lv_addr : 36;
	u64 reserve2 : 8;
	u64 page_table_attr : 8;
	/* dw2 ~ dw3 */
	u64 mem_base : 15;
	u64 reserve3 : 1;
	u64 mem_limit : 15;
	u64 reserve4 : 1;
	u64 reserve5 : 32;
	/* dw4 ~ dw5 */
	u64 reserve6 : 12;
	u64 ub_addr : 52;
	/* dw6 ~ dw7 */
	u64 reserve7 : 32;
	u64 tpg_num : 20;
	u64 order_type : 2;
	u64 order_id : 8;
	u64 reserve8 : 2;
	/* dw8 ~ dw9 */
	u64 dst_eid_low;
	/* dw10 ~ dw11 */
	u64 dst_eid_high;
	/* dw12 ~ dw13 */
	u64 token_id : 20;
	u64 reserve9 : 12;
	u64 token_value : 32;
	/* dw14 ~ dw15 */
	u64 upi : 16;
	u64 reserve10 : 16;
	u64 src_eid : 20;
	u64 reserve11 : 12;
};

#define DECODER_PAGE_TABLE_ENTRY_SIZE	8
#define UBA_ADDR_OFFSET			12

#define DECODER_PAGE_INDEX_LOC		20
#define DECODER_PAGE_TABLE_LOC		35
#define DECODER_SUB_PAGE_TABLE_LOC	32
#define DECODER_PAGE_TABLE_MASK		GENMASK_ULL(43, 35)
#define DECODER_SUB_PAGE_TABLE_MASK	GENMASK_ULL(34, 32)
#define DECODER_PGTLB_PAGE_MASK		GENMASK_ULL(31, 20)
#define DECODER_RGTLB_PAGE_MASK		GENMASK_ULL(34, 20)
#define DECODER_RGTLB_ADDRESS_MASK	GENMASK_ULL(34, 20)
#define DECODER_RGTLB_ADDRESS_OFFSET	20
#define TOKEN_VALID_MASK		GENMASK(0, 0)
#define MEM_LMT_MAX			0x7FFF
#define RANGE_UBA_LOW_MASK		GENMASK_ULL(34, 20)
#define RANGE_UBA_HIGH_MASK		GENMASK_ULL(63, 35)
#define UBA_CARRY			0x800000000
#define UBA_NOCARRY			0x0

#define get_pgtlb_idx(decoder, pa) ((((pa) - (decoder)->mmio_base_addr) & \
				    DECODER_PAGE_TABLE_MASK) >> \
				    DECODER_PAGE_TABLE_LOC)

#define get_rgtlb_addr(decoder, pa) ((((pa) - (decoder)->mmio_base_addr) & \
				     DECODER_RGTLB_ADDRESS_MASK) >> \
				     DECODER_RGTLB_ADDRESS_OFFSET)

#define get_rgtlb_page_idx(decoder, pa) ((((pa) - (decoder)->mmio_base_addr) & \
					 DECODER_RGTLB_PAGE_MASK) >> \
					 DECODER_PAGE_INDEX_LOC)

#define get_page_idx(decoder, pa) ((((pa) - (decoder)->mmio_base_addr) & \
				   DECODER_PGTLB_PAGE_MASK) >> \
				   DECODER_PAGE_INDEX_LOC)

#define get_pgtlb_sub_idx(decoder, pa) ((((pa) - (decoder)->mmio_base_addr) & \
					DECODER_SUB_PAGE_TABLE_MASK) >> \
					DECODER_SUB_PAGE_TABLE_LOC)

#define DECODER_QUEUE_TIMEOUT_US 1000000 /* 1s */
#define CMD_ENTRY_SIZE 16
#define EVT_ENTRY_SIZE 16

static void fill_page_entry(struct page_entry *page,
			    struct decoder_map_info *info, u64 offset)
{
	page->entry_type = PAGE;
	page->token_vld = ubc_feature & TOKEN_VALID_MASK;
	page->ub_addr = (info->uba + offset) >> UBA_ADDR_OFFSET;
	page->tpg_num = info->tpg_num;
	page->order_type = info->order_type;
	page->order_id = info->order_id;
	page->dst_eid_low = info->eid_low;
	page->dst_eid_high = info->eid_high;
	page->token_id = info->token_id;
	page->token_value = info->token_value;
	page->upi = info->upi;
	page->src_eid = info->src_eid;
}

static int rgtlb_alloc_page(struct ub_decoder *decoder,
			    struct page_table_desc *desc,
			    struct range_table_entry *entry)
{
	void *page_base;

	page_base = dmam_alloc_coherent(decoder->dev, RANGE_TABLE_PAGE_SIZE,
					&desc->page_dma, GFP_KERNEL);
	if (!page_base)
		return -ENOMEM;

	desc->page_base = page_base;
	desc->count = 0;
	entry->next_lv_addr = (desc->page_dma & DECODER_PGTBL_PGPRT_MASK) >>
			      DECODER_DMA_PAGE_ADDR_OFFSET;
	entry->page_table_attr = PGTLB_ATTR_DEFAULT;
	return 0;
}

static void rgtlb_free_page(struct ub_decoder *decoder,
			    struct page_table_desc *desc,
			    struct range_table_entry *rgtlb_entry)
{
	memset(desc->page_base, 0, RANGE_TABLE_PAGE_SIZE);
	dmam_free_coherent(decoder->dev, RANGE_TABLE_PAGE_SIZE, desc->page_base,
			   desc->page_dma);
	rgtlb_entry->next_lv_addr = decoder->invalid_page_dma;
	desc->page_base = NULL;
	desc->page_dma = 0;
}

static int rgtlb_map(struct ub_decoder *decoder, u32 table_idx,
		     struct decoder_map_info *info, u64 *offset)
{
	struct range_table_entry *rgtlb_entry;
	struct ub_entity *uent = decoder->uent;
	struct page_table_desc *desc;
	struct page_entry *page;
	u32 index;
	u64 addr;

	rgtlb_entry = (struct range_table_entry *)decoder->pgtlb.pgtlb_base +
		      table_idx;
	desc = decoder->pgtlb.desc_base + table_idx * RGTLB_TO_PGTLB;
	addr = get_rgtlb_addr(decoder, info->pa + *offset);
	index = get_rgtlb_page_idx(decoder, info->pa + *offset);
	if (addr >= rgtlb_entry->mem_base && addr <= rgtlb_entry->mem_limit) {
		ub_err(uent, "decoder mapping addr already in range.\n");
		*offset += SZ_1M;
		return -EINVAL;
	}

	if (!desc->page_base)
		if (rgtlb_alloc_page(decoder, desc, rgtlb_entry)) {
			*offset += SZ_1M;
			return -ENOMEM;
		}

	/*
	 * If the page table is applied for the first time,
	 * the error branch is not used.
	 */
	page = (struct page_entry *)desc->page_base + index;
	if (page->entry_type != INVALID_ENTRY) {
		*offset += SZ_1M;
		ub_err(uent, "page entry has been used\n");
		return -EINVAL;
	}

	fill_page_entry(page, info, *offset);
	desc->count++;
	*offset += SZ_1M;
	return 0;
}

static int copy_rg_to_pg(struct ub_decoder *decoder,
			 struct page_table_desc *desc_base,
			 struct range_table_entry *rgtlb_entry,
			 struct page_entry *rg_base, int idx)
{
	struct page_table_entry *pgtlb_entry;
	struct page_entry *rentry, *pentry;
	struct page_table_desc *desc;
	void *page_base;
	int i;

	desc = desc_base + idx;
	pgtlb_entry = (struct page_table_entry *)rgtlb_entry + idx;
	page_base = dmam_alloc_coherent(decoder->dev, PAGE_TABLE_PAGE_SIZE,
					&desc->page_dma, GFP_KERNEL);
	if (!page_base)
		return -ENOMEM;

	desc->page_base = page_base;
	desc->count = 0;
	pgtlb_entry->entry_type = PAGE_TABLE;
	pgtlb_entry->next_lv_addr = (desc->page_dma &
				     DECODER_PGTBL_PGPRT_MASK) >>
				     DECODER_DMA_PAGE_ADDR_OFFSET;
	pgtlb_entry->pgtlb_attr = PGTLB_ATTR_DEFAULT;

	pentry = (struct page_entry *)page_base;
	rentry = (struct page_entry *)rg_base + idx * DECODER_PAGE_SIZE;
	for (i = 0; i < DECODER_PAGE_SIZE; i++) {
		if ((rentry + i)->entry_type == PAGE) {
			desc->count++;
			memcpy(pentry + i, rentry + i, DECODER_PAGE_ENTRY_SIZE);
		}
	}
	return 0;
}

static int rgtlb_unmap_to_range(struct ub_decoder *decoder,
				struct page_table_desc *desc,
				struct range_table_entry *rgtlb_entry)
{
	struct page_table_entry *pgtlb_entry;
	struct page_entry *rg_base;
	struct page_entry *entry;
	dma_addr_t rg_dma;
	int i, j, ret;
	bool flag;

	rgtlb_entry->token_value = 0;
	for (i = 0; i < RGTLB_TO_PGTLB; i++) {
		pgtlb_entry = (struct page_table_entry *)rgtlb_entry + i;
		pgtlb_entry->entry_type = PAGE_TABLE;
		pgtlb_entry->next_lv_addr = decoder->invalid_page_dma;
		pgtlb_entry->pgtlb_attr = PGTLB_ATTR_DEFAULT;
	}

	if (!desc->page_base)
		return 0;
	/*
	 * If l2 table exists,
	 * convert l2 table of range table to l2 table of the page table.
	 */
	rg_base = (struct page_entry *)desc->page_base;
	rg_dma = desc->page_dma;
	memset(desc, 0, sizeof(struct page_table_desc));
	for (i = 0; i < RGTLB_TO_PGTLB; i++) {
		flag = false;
		for (j = 0; j < DECODER_PAGE_SIZE; j++) {
			entry = rg_base + i * DECODER_PAGE_SIZE + j;
			if (entry->entry_type != INVALID_ENTRY) {
				flag = true;
				break;
			}
		}
		if (flag) {
			ret = copy_rg_to_pg(decoder, desc, rgtlb_entry,
					    rg_base, i);
			if (ret)
				return ret;
		}
	}

	memset(rg_base, 0, RANGE_TABLE_PAGE_SIZE);
	dmam_free_coherent(decoder->dev, RANGE_TABLE_PAGE_SIZE, rg_base,
			   rg_dma);
	return 0;
}

static int rgtlb_unmap_to_page(struct ub_decoder *decoder,
			       struct page_table_desc *desc,
			       struct range_table_entry *rgtlb_entry,
			       u32 index)
{
	struct page_entry *page;

	page = (struct page_entry *)desc->page_base + index;

	if (page->entry_type != PAGE) {
		ub_err(decoder->uent, "decoder unmap page from range table error.\n");
		return -EINVAL;
	}
	page->entry_type = INVALID_ENTRY;
	desc->count--;

	if (desc->count == 0)
		rgtlb_free_page(decoder, desc, rgtlb_entry);
	return 0;
}

static int rgtlb_unmap(struct ub_decoder *decoder, u32 table_idx,
		       struct decoder_map_info *info, u64 *offset)
{
	struct range_table_entry *rgtlb_entry;
	struct page_table_desc *desc;
	u32 sub_idx;
	u64 begin;
	u64 size;

	rgtlb_entry = (struct range_table_entry *)decoder->pgtlb.pgtlb_base +
		      table_idx;
	desc = decoder->pgtlb.desc_base + table_idx * RGTLB_TO_PGTLB;

	begin = get_rgtlb_addr(decoder, info->pa + *offset);
	size = (rgtlb_entry->mem_limit - rgtlb_entry->mem_base + 1ULL) * SZ_1M;

	if (begin == rgtlb_entry->mem_base) {
		*offset += size;
		if (info->size >= *offset)
			return rgtlb_unmap_to_range(decoder, desc, rgtlb_entry);
		ub_err(decoder->uent, "can't unmap part of range\n!");
		return -EINVAL;
	}
	sub_idx = get_rgtlb_page_idx(decoder, info->pa + *offset);
	*offset += SZ_1M;
	return rgtlb_unmap_to_page(decoder, desc, rgtlb_entry, sub_idx);
}

static int handle_range_table(struct ub_decoder *decoder, u64 *offset,
			      struct decoder_map_info *info, bool is_map)
{
	u32 table_idx;

	table_idx = get_pgtlb_idx(decoder, info->pa + *offset);

	if (is_map)
		return rgtlb_map(decoder, table_idx, info, offset);
	else
		return rgtlb_unmap(decoder, table_idx, info, offset);
}

static int pgtlb_alloc_page(struct ub_decoder *decoder,
			    struct page_table_desc *desc,
			    struct page_table_entry *pgtlb_entry)
{
	void *page_base;

	page_base = dmam_alloc_coherent(decoder->dev, PAGE_TABLE_PAGE_SIZE,
					&desc->page_dma, GFP_KERNEL);
	if (!page_base)
		return -ENOMEM;

	desc->page_base = page_base;
	desc->count = 0;
	pgtlb_entry->entry_type = PAGE_TABLE;
	pgtlb_entry->next_lv_addr = (desc->page_dma &
				    DECODER_PGTBL_PGPRT_MASK) >>
				    DECODER_DMA_PAGE_ADDR_OFFSET;
	pgtlb_entry->pgtlb_attr = PGTLB_ATTR_DEFAULT;
	return 0;
}

static void pgtlb_free_page(struct ub_decoder *decoder,
			    struct page_table_desc *desc,
			    struct page_table_entry *pgtlb_entry)
{
	memset(desc->page_base, 0, PAGE_TABLE_PAGE_SIZE);
	dmam_free_coherent(decoder->dev, PAGE_TABLE_PAGE_SIZE, desc->page_base,
			   desc->page_dma);
	pgtlb_entry->next_lv_addr = decoder->invalid_page_dma;
	pgtlb_entry->entry_type = PAGE_TABLE;
	desc->page_base = NULL;
	desc->page_dma = 0;
}

static int pgtlb_map_to_page(struct ub_decoder *decoder,
			     struct page_table_desc *desc,
			     struct page_table_entry *pgtlb_entry,
			     struct decoder_map_info *info, u64 offset)
{
	struct page_entry *page;
	u32 index;
	int ret;

	if (!desc->page_base) {
		ret = pgtlb_alloc_page(decoder, desc, pgtlb_entry);
		if (ret)
			return ret;
	}

	index = get_page_idx(decoder, info->pa + offset);

	page = (struct page_entry *)desc->page_base + index;

	/*
	 * If it's the first time to apply for a page table,
	 * the error branch will not be taken.
	 */
	if (page->entry_type != INVALID_ENTRY) {
		ub_err(decoder->uent, "decoder mapping page from page table error.\n");
		return -EINVAL;
	}

	fill_page_entry(page, info, offset);
	desc->count++;
	return 0;
}

static int pgtlb_unmap_to_page(struct ub_decoder *decoder,
			       struct page_table_desc *desc,
			       struct page_table_entry *pgtlb_entry,
			       struct decoder_map_info *info, u64 offset)
{
	struct page_entry *page;
	u32 index;

	index = get_page_idx(decoder, info->pa + offset);
	page = (struct page_entry *)desc->page_base + index;

	if (pgtlb_entry->next_lv_addr == decoder->invalid_page_dma ||
	    page->entry_type != PAGE) {
		ub_err(decoder->uent, "decoder unmap page from page table error.\n");
		return -EINVAL;
	}

	page->entry_type = INVALID_ENTRY;
	desc->count--;

	if (desc->count == 0)
		pgtlb_free_page(decoder, desc, pgtlb_entry);
	return 0;
}

static int handle_page_table(struct ub_decoder *decoder, u64 *offset,
			     struct decoder_map_info *info, bool is_map)
{
	struct page_table_entry *pgtlb_entry;
	struct page_table_desc *desc;
	struct page_table *pgtlb;
	u32 table_idx;
	u32 sub_index;
	int ret;

	pgtlb = &decoder->pgtlb;
	table_idx = get_pgtlb_idx(decoder, info->pa + *offset);
	sub_index = get_pgtlb_sub_idx(decoder, info->pa + *offset);
	desc = pgtlb->desc_base + table_idx * RGTLB_TO_PGTLB + sub_index;
	pgtlb_entry = (struct page_table_entry *)pgtlb->pgtlb_base +
		      table_idx * RGTLB_TO_PGTLB + sub_index;

	if (is_map)
		ret = pgtlb_map_to_page(decoder, desc, pgtlb_entry, info,
					*offset);
	else
		ret = pgtlb_unmap_to_page(decoder, desc, pgtlb_entry, info,
					  *offset);
	*offset += SZ_1M;
	return ret;
}

static void fill_range_table(struct ub_decoder *decoder,
			     struct range_table_entry *rg_entry,
			     struct decoder_map_info *info, u64 *offset)
{
	u64 mem_base, mem_limit;
	u64 uba_high, uba_low;
	u64 size;

	mem_base = get_rgtlb_addr(decoder, info->pa + *offset);
	size = (MEM_LMT_MAX - mem_base + 1ULL) << DECODER_RGTLB_ADDRESS_OFFSET;

	uba_low = (info->uba + *offset) & RANGE_UBA_LOW_MASK;
	uba_high = (info->uba + *offset) & RANGE_UBA_HIGH_MASK;

	if (info->size - *offset >= size) {
		mem_limit = MEM_LMT_MAX;
		*offset += size;
	} else {
		mem_limit = get_rgtlb_addr(decoder, info->pa + info->size);
		mem_limit--;
		*offset += (mem_limit - mem_base + 1) <<
			   DECODER_RGTLB_ADDRESS_OFFSET;
	}

	rg_entry->entry_type = RANGE_TABLE;
	rg_entry->next_lv_addr = decoder->invalid_page_dma;
	rg_entry->page_table_attr = PGTLB_ATTR_DEFAULT;
	rg_entry->token_vld = ubc_feature & TOKEN_VALID_MASK;
	rg_entry->mem_base = mem_base;
	rg_entry->mem_limit = mem_limit;
	rg_entry->ub_addr = (uba_high | uba_low) >> UBA_ADDR_OFFSET;
	rg_entry->tpg_num = info->tpg_num;
	rg_entry->order_id = info->order_id;
	rg_entry->order_type = info->order_type;
	rg_entry->dst_eid_low = info->eid_low;
	rg_entry->dst_eid_high = info->eid_high;
	rg_entry->token_id = info->token_id;
	rg_entry->token_value = info->token_value;
	rg_entry->upi = info->upi;
	rg_entry->src_eid = info->src_eid;
}

static int handle_pgrg_table(struct ub_decoder *decoder, u64 *offset,
			     struct decoder_map_info *info, bool is_map)
{
	struct range_table_entry *rg_entry;
	struct page_table_entry *pg_entry;
	u32 table_idx, sub_index;
	int i;

	if (!is_map)
		return handle_page_table(decoder, offset, info, is_map);

	table_idx = get_pgtlb_idx(decoder, info->pa + *offset);
	sub_index = get_pgtlb_sub_idx(decoder, info->pa + *offset);
	pg_entry = (struct page_table_entry *)decoder->pgtlb.pgtlb_base +
		   table_idx * RGTLB_TO_PGTLB;
	if (sub_index != 0 || info->size - *offset < decoder->rg_size)
		return handle_page_table(decoder, offset, info, is_map);

	for (i = 0; i < RGTLB_TO_PGTLB; i++)
		if ((pg_entry + i)->next_lv_addr != decoder->invalid_page_dma)
			return handle_page_table(decoder, offset, info, is_map);

	ub_dbg(decoder->uent, "create range table\n");
	rg_entry = (struct range_table_entry *)pg_entry;
	fill_range_table(decoder, rg_entry, info, offset);
	return 0;
}

static int handle_table(struct ub_decoder *decoder,
			struct decoder_map_info *info, bool is_map)
{
	struct page_table *pgtlb = &decoder->pgtlb;
	struct range_table_entry *range_tlb_entry;
	u64 offset, rollback_size;
	u32 table_idx;
	int ret = 0;

	for (offset = 0; offset < info->size;) {
		rollback_size = offset;

		mutex_lock(&decoder->table_lock);
		table_idx = get_pgtlb_idx(decoder, info->pa + offset);
		range_tlb_entry = (struct range_table_entry *)
				  pgtlb->pgtlb_base + table_idx;

		if (range_tlb_entry->entry_type == RANGE_TABLE)
			ret = handle_range_table(decoder, &offset, info,
						 is_map);
		else if (range_tlb_entry->next_lv_addr ==
			 decoder->invalid_page_dma)
			ret = handle_pgrg_table(decoder, &offset, info, is_map);
		else
			ret = handle_page_table(decoder, &offset, info, is_map);
		mutex_unlock(&decoder->table_lock);

		if (ret) {
			ub_err(decoder->uent, "decoder table occur fatal error ret=%d\n",
			       ret);
			/* if it is map operation, revert it. unmap operation can't revert */
			if (is_map)
				(void)hi_decoder_unmap(decoder, info->pa,
						       rollback_size);
			break;
		}
	}
	return ret;
}

static void ub_decoder_init_page_table(struct ub_decoder *decoder, void *pgtlb_base)
{
	struct page_table_entry *pgtlb_entry;
	int i;

	for (i = 0; i < DECODER_PAGE_TABLE_SIZE; i++) {
		pgtlb_entry = (struct page_table_entry *)pgtlb_base + i;
		pgtlb_entry->entry_type = PAGE_TABLE;
		pgtlb_entry->next_lv_addr = decoder->invalid_page_dma;
		pgtlb_entry->pgtlb_attr = PGTLB_ATTR_DEFAULT;
	}
}

int hi_init_decoder_queue(struct ub_decoder *decoder)
{
	struct hi_ubc_private_data *data;
	struct ub_bus_controller *ubc;

	if (!decoder)
		return -EINVAL;

	ubc = decoder->uent->ubc;
	data = (struct hi_ubc_private_data *)ubc->data;
	decoder->cmdq.base = data->io_decoder_cmdq;
	decoder->evtq.base = data->io_decoder_evtq;

	decoder->cmdq.qbase = ioremap(decoder->cmdq.base,
				      (1 << decoder->cmdq.qs) * CMD_ENTRY_SIZE);
	if (!decoder->cmdq.qbase)
		return -ENOMEM;

	decoder->evtq.qbase = ioremap(decoder->evtq.base,
				      (1 << decoder->evtq.qs) * EVT_ENTRY_SIZE);
	if (!decoder->evtq.qbase) {
		iounmap(decoder->cmdq.qbase);
		return -ENOMEM;
	}
	return 0;
}

void hi_uninit_decoder_queue(struct ub_decoder *decoder)
{
	iounmap(decoder->cmdq.qbase);
	iounmap(decoder->evtq.qbase);
}

int hi_create_decoder_table(struct ub_decoder *decoder)
{
	struct page_table_desc *invalid_desc = &decoder->invalid_desc;
	struct page_table *pgtlb;
	void *pgtlb_base;
	size_t size;

	size = DECODER_PAGE_TABLE_ENTRY_SIZE * DECODER_PAGE_TABLE_SIZE;
	pgtlb = &decoder->pgtlb;
	pgtlb_base = dmam_alloc_coherent(decoder->dev, size,
					 &pgtlb->pgtlb_dma, GFP_KERNEL);
	if (!pgtlb_base)
		return -ENOMEM;

	pgtlb->pgtlb_base = pgtlb_base;

	size = sizeof(*pgtlb->desc_base) * DECODER_PAGE_TABLE_SIZE;
	pgtlb->desc_base = kzalloc(size, GFP_KERNEL);
	if (!pgtlb->desc_base)
		goto release_pgtlb;

	invalid_desc->page_base = dmam_alloc_coherent(decoder->dev,
						      RANGE_TABLE_PAGE_SIZE,
						      &invalid_desc->page_dma,
						      GFP_KERNEL);
	if (!invalid_desc->page_base)
		goto release_desc;

	decoder->invalid_page_dma = (invalid_desc->page_dma &
				     DECODER_PGTBL_PGPRT_MASK) >>
				     DECODER_DMA_PAGE_ADDR_OFFSET;

	ub_decoder_init_page_table(decoder, pgtlb_base);

	return 0;

release_desc:
	kfree(pgtlb->desc_base);
	pgtlb->desc_base = NULL;
release_pgtlb:
	size = DECODER_PAGE_TABLE_ENTRY_SIZE * DECODER_PAGE_TABLE_SIZE;
	dmam_free_coherent(decoder->dev, size, pgtlb_base, pgtlb->pgtlb_dma);
	return -ENOMEM;
}

void hi_free_decoder_table(struct ub_decoder *decoder)
{
	struct page_table_desc *invalid_desc = &decoder->invalid_desc;
	size_t size;

	dmam_free_coherent(decoder->dev, RANGE_TABLE_PAGE_SIZE,
			   invalid_desc->page_base, invalid_desc->page_dma);
	kfree(decoder->pgtlb.desc_base);

	size = DECODER_PAGE_TABLE_ENTRY_SIZE * DECODER_PAGE_TABLE_SIZE;
	dmam_free_coherent(decoder->dev, size, decoder->pgtlb.pgtlb_base,
			   decoder->pgtlb.pgtlb_dma);
}

int hi_decoder_unmap(struct ub_decoder *decoder, phys_addr_t addr, u64 size)
{
	struct decoder_map_info info = {
		.pa = addr,
		.size = size,
	};
	int ret;

	info.size = ALIGN(info.size, SZ_1M);
	ret = handle_table(decoder, &info, false);
	if (ret)
		return ret;
	return hi_decoder_cmd_request(decoder, info.pa, info.size, TLBI_PARTIAL);
}

int hi_decoder_map(struct ub_decoder *decoder, struct decoder_map_info *info)
{
	info->size = ALIGN(info->size, SZ_1M);

	ub_info(decoder->uent,
		"decoder map, pa=%#llx, uba=%#llx, size=%#llx, cna=%#x, orderid=%#x, ordertype=%#x, eid_l=%#llx, eid_h=%#llx, upi=%#x src_eid=%#x\n",
		info->pa, info->uba, info->size, info->tpg_num, info->order_id,
		info->order_type, info->eid_low, info->eid_high, info->upi,
		info->src_eid);

	if (info->pa < decoder->mmio_base_addr ||
	    info->pa + info->size - 1 > decoder->mmio_end_addr ||
	    info->pa > info->pa + info->size - 1) {
		pr_err("decoder map range check error\n");
		return -EINVAL;
	}

	return handle_table(decoder, info, true);
}

struct sync_entry {
	u64 op : 8;
	u64 reserve0 : 4;
	u64 cm : 2;
	u64 ntf_sh : 2;
	u64 ntf_attr : 4;
	u64 reserve1 : 12;
	u64 notify_data : 32;
	u64 reserve2 : 2;
	u64 notify_addr : 50;
	u64 reserve3 : 12;
};

struct tlbi_all_entry {
	u32 op : 8;
	u32 reserve0 : 24;
	u32 reserve1;
	u32 reserve2;
	u32 reserve3;
};

struct tlbi_partial_entry {
	u32 op : 8;
	u32 reserve0 : 24;
	u32 tlbi_addr_base : 28;
	u32 reserve1 : 4;
	u32 tlbi_addr_limt : 28;
	u32 reserve2 : 4;
	u32 reserve3;
};

#define TLBI_ADDR_MASK GENMASK_ULL(43, 20)
#define TLBI_ADDR_OFFSET 20
#define CMDQ_ENT_DWORDS 2

#define NTF_SH_NSH		0b00
#define NTF_SH_OSH		0b10
#define NTF_SH_ISH		0b11

#define NTF_ATTR_IR_NC		0b00
#define NTF_ATTR_IR_WBRA	0b01
#define NTF_ATTR_IR_WT		0b10
#define NTF_ATTR_IR_WB		0b11
#define NTF_ATTR_OR_NC		0b0000
#define NTF_ATTR_OR_WBRA	0b0100
#define NTF_ATTR_OR_WT		0b1000
#define NTF_ATTR_OR_WB		0b1100

#define Q_IDX(qs, p) ((p) & ((1 << (qs)) - 1))
#define Q_WRP(qs, p) ((p) & (1 << (qs)))
#define Q_OVF(p) ((p) & Q_OVERFLOW_FLAG)

enum NOTIFY_TYPE {
	DISABLE_NOTIFY = 0,
	ENABLE_NOTIFY = 1,
};

static bool queue_has_space(struct ub_decoder_queue *q, u32 n)
{
	u32 space, prod, cons;

	prod = Q_IDX(q->qs, q->prod.cmdq_wr_idx);
	cons = Q_IDX(q->qs, q->cons.cmdq_rd_idx);

	if (Q_WRP(q->qs, q->prod.cmdq_wr_idx) ==
	    Q_WRP(q->qs, q->cons.cmdq_rd_idx))
		space = (1 << q->qs) - (prod - cons);
	else
		space = cons - prod;

	return space >= n;
}

static u32 queue_inc_prod_n(struct ub_decoder_queue *q, u32 n)
{
	u32 prod = (Q_WRP(q->qs, q->prod.cmdq_wr_idx) |
		   Q_IDX(q->qs, q->prod.cmdq_wr_idx)) + n;
	return Q_WRP(q->qs, prod) | Q_IDX(q->qs, prod);
}

#define CMD_0_OP GENMASK_ULL(7, 0)
#define CMD_0_ADDR_BASE GENMASK_ULL(59, 32)
#define CMD_1_ADDR_LIMT GENMASK_ULL(27, 0)

static void decoder_cmdq_issue_cmd(struct ub_decoder *decoder, phys_addr_t addr,
				   u64 size, enum ub_cmd_op_type op)
{
	struct ub_decoder_queue *cmdq = &(decoder->cmdq);
	struct tlbi_partial_entry entry = {};
	u64 cmd[CMDQ_ENT_DWORDS] = {};
	void *pi;
	int i;

	entry.op = op;
	entry.tlbi_addr_base = (addr & TLBI_ADDR_MASK) >> TLBI_ADDR_OFFSET;
	entry.tlbi_addr_limt = ((addr + size - 1U) & TLBI_ADDR_MASK) >>
			       TLBI_ADDR_OFFSET;

	cmd[0] |= FIELD_PREP(CMD_0_OP, entry.op);
	cmd[0] |= FIELD_PREP(CMD_0_ADDR_BASE, entry.tlbi_addr_base);
	cmd[1] |= FIELD_PREP(CMD_1_ADDR_LIMT, entry.tlbi_addr_limt);

	pi = cmdq->qbase + Q_IDX(cmdq->qs, cmdq->prod.cmdq_wr_idx) *
	     sizeof(struct tlbi_partial_entry);

	for (i = 0; i < CMDQ_ENT_DWORDS; i++)
		writeq(cmd[i], pi + i * sizeof(u64));

	cmdq->prod.cmdq_wr_idx = queue_inc_prod_n(cmdq, 1);
}

#define NTF_DMA_ADDR_OFFSERT 2
#define SYNC_0_OP GENMASK_ULL(7, 0)
#define SYNC_0_CM GENMASK_ULL(13, 12)
#define SYNC_0_NTF_ISH GENMASK_ULL(15, 14)
#define SYNC_0_NTF_ATTR GENMASK_ULL(19, 16)
#define SYNC_0_NTF_DATA GENMASK_ULL(63, 32)
#define SYNC_1_NTF_ADDR GENMASK_ULL(51, 2)
#define SYNC_NTF_DATA 0xffffffff

static void decoder_cmdq_issue_sync(struct ub_decoder *decoder)
{
	struct ub_decoder_queue *cmdq = &(decoder->cmdq);
	u64 cmd[CMDQ_ENT_DWORDS] = {};
	struct sync_entry entry = {};
	phys_addr_t sync_dma;
	void __iomem *pi;
	int i;

	entry.op = SYNC;
	entry.cm = ENABLE_NOTIFY;
	sync_dma = cmdq->base + Q_IDX(cmdq->qs, cmdq->prod.cmdq_wr_idx) *
		   sizeof(struct sync_entry);
	entry.ntf_sh = NTF_SH_NSH;
	entry.ntf_attr = NTF_ATTR_IR_NC | NTF_ATTR_OR_NC;
	entry.notify_data = SYNC_NTF_DATA;
	entry.notify_addr = sync_dma >> NTF_DMA_ADDR_OFFSERT;

	cmd[0] |= FIELD_PREP(SYNC_0_OP, entry.op);
	cmd[0] |= FIELD_PREP(SYNC_0_CM, entry.cm);
	cmd[0] |= FIELD_PREP(SYNC_0_NTF_ISH, entry.ntf_sh);
	cmd[0] |= FIELD_PREP(SYNC_0_NTF_ATTR, entry.ntf_attr);
	cmd[0] |= FIELD_PREP(SYNC_0_NTF_DATA, entry.notify_data);
	cmd[1] |= FIELD_PREP(SYNC_1_NTF_ADDR, entry.notify_addr);

	pi = cmdq->qbase + Q_IDX(cmdq->qs, cmdq->prod.cmdq_wr_idx) *
	     sizeof(struct sync_entry);
	for (i = 0; i < CMDQ_ENT_DWORDS; i++)
		writeq(cmd[i], pi + i * sizeof(u64));

	decoder->notify = pi;
	cmdq->prod.cmdq_wr_idx = queue_inc_prod_n(cmdq, 1);
}

static void decoder_cmdq_update_prod(struct ub_decoder *decoder)
{
	struct ub_entity *uent = decoder->uent;
	struct queue_idx q;
	int ret;

	ret = ub_cfg_read_dword(uent, DECODER_CMDQ_PROD, &q.val);
	if (ret)
		ub_err(uent, "update pi, read decoder cmdq prod fail\n");

	decoder->cmdq.prod.cmdq_err_resp = q.cmdq_err_resp;
	ret = ub_cfg_write_dword(uent, DECODER_CMDQ_PROD,
				 decoder->cmdq.prod.val);
	if (ret)
		ub_err(uent, "update pi, write decoder cmdq prod fail\n");
}

static int wait_for_cmdq_free(struct ub_decoder *decoder, u32 n)
{
	ktime_t timeout = ktime_add_us(ktime_get(), DECODER_QUEUE_TIMEOUT_US);
	struct ub_decoder_queue *cmdq = &(decoder->cmdq);
	struct ub_entity *uent = decoder->uent;
	int ret;

	while (true) {
		ret = ub_cfg_read_dword(uent, DECODER_CMDQ_CONS,
					&(cmdq->cons.val));
		if (ret)
			return ret;

		if (queue_has_space(cmdq, n + 1))
			return 0;

		if (ktime_compare(ktime_get(), timeout) > 0) {
			ub_err(uent, "decoder cmdq wait free entry timeout\n");
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
}

static int wait_for_cmdq_notify(struct ub_decoder *decoder)
{
	ktime_t timeout;
	u32 val;

	timeout = ktime_add_us(ktime_get(), DECODER_QUEUE_TIMEOUT_US);
	while (true) {
		val = readl(decoder->notify);
		if (val == SYNC_NTF_DATA)
			return 0;

		if (ktime_compare(ktime_get(), timeout) > 0) {
			ub_err(decoder->uent, "decoder cmdq wait notify timeout\n");
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
}

int hi_decoder_cmd_request(struct ub_decoder *decoder, phys_addr_t addr,
			   u64 size, enum ub_cmd_op_type op)
{
	int ret;

	ret = wait_for_cmdq_free(decoder, 1);
	if (ret)
		return ret;

	decoder_cmdq_issue_cmd(decoder, addr, size, op);
	decoder_cmdq_issue_sync(decoder);
	decoder_cmdq_update_prod(decoder);

	ret = wait_for_cmdq_notify(decoder);
	return ret;
}
#ifdef UBUS_KP_TOOL_STUB
EXPORT_SYMBOL_GPL(hi_decoder_cmd_request);
#endif

static bool queue_empty(struct ub_decoder_queue *q)
{
	return (Q_IDX(q->qs, q->prod.eventq_wr_idx) ==
		Q_IDX(q->qs, q->cons.eventq_rd_idx)) &&
	       (Q_WRP(q->qs, q->prod.eventq_wr_idx) ==
		Q_WRP(q->qs, q->cons.eventq_rd_idx));
}

static void queue_inc_cons(struct ub_decoder_queue *q)
{
	u32 cons = (Q_WRP(q->qs, q->cons.eventq_rd_idx) |
		    Q_IDX(q->qs, q->cons.eventq_rd_idx)) + 1;
	q->cons.eventq_rd_idx = Q_WRP(q->qs, cons) | Q_IDX(q->qs, cons);
}

enum event_op_type {
	RESERVED = 0x0,
	EVENT_ADDR_OUT_OF_RANGE = 0x01,
	EVENT_ILLEGAL_CMD = 0x02,
};

#define EVTQ_0_ID GENMASK_ULL(7, 0)
#define EVTQ_0_ADDR GENMASK_ULL(59, 32)
#define EVTQ_0_CMD_OPCODE GENMASK_ULL(39, 32)
#define EVTQ_ENT_DWORDS 2
#define MAX_REASON_NUM 3

static const char *cmd_err_reason[MAX_REASON_NUM] = {
	"no error",
	"illegal command",
	"abort error(read command with 2bit ecc)"
};

static void fix_err_cmd(struct ub_decoder *decoder)
{
	struct ub_decoder_queue *cmdq = &(decoder->cmdq);
	struct ub_entity *uent = decoder->uent;
	u64 cmd[CMDQ_ENT_DWORDS] = {};
	struct queue_idx prod, cons;
	void *pi;
	int i;

	if (ub_cfg_read_dword(uent, DECODER_CMDQ_CONS, &cons.val)) {
		ub_err(uent, "decoder fix error cmd, read ci failed\n");
		return;
	}
	if (ub_cfg_read_dword(uent, DECODER_CMDQ_PROD, &prod.val)) {
		ub_err(uent, "decoder fix error cmd, read pi failed\n");
		return;
	}

	cmd[0] |= FIELD_PREP(CMD_0_OP, TLBI_ALL);
	pi = cmdq->qbase + Q_IDX(cmdq->qs, cons.cmdq_rd_idx) *
	     sizeof(struct tlbi_partial_entry);

	for (i = 0; i < CMDQ_ENT_DWORDS; i++)
		writeq(cmd[i], pi + i * sizeof(u64));

	if (cons.cmdq_err_reason >= MAX_REASON_NUM)
		ub_err(uent, "cmdq err reason is invalid, reason=%u\n",
			cons.cmdq_err_reason);
	else
		ub_err(uent, "cmdq err reason is %s\n", cmd_err_reason[cons.cmdq_err_reason]);

	prod.cmdq_err_resp = cons.cmdq_err;

	if (ub_cfg_write_dword(uent, DECODER_CMDQ_PROD, prod.val))
		ub_err(uent, "decoder fix error cmd, write pi err resp failed\n");
}

static void handle_evt(struct ub_decoder *decoder, u64 *evt)
{
	struct ub_entity *uent = decoder->uent;

	switch (FIELD_GET(EVTQ_0_ID, evt[0])) {
	case EVENT_ADDR_OUT_OF_RANGE:
		ub_err(uent, "decoder event, input addr out of range, addr=%#.7x00000\n",
		       (u32)FIELD_GET(EVTQ_0_ADDR, evt[0]));
		break;
	case EVENT_ILLEGAL_CMD:
		ub_err(uent, "decoder event, illegal cmd, cmd_opcode=%#x\n",
		       (u32)FIELD_GET(EVTQ_0_CMD_OPCODE, evt[0]));
		fix_err_cmd(decoder);
		break;
	default:
		ub_err(uent, "invalid event opcode, opcode=%#x\n",
		       (u32)FIELD_GET(EVTQ_0_ID, evt[0]));
	}
}

void hi_decoder_event_deal(struct ub_decoder *decoder)
{
	struct ub_decoder_queue *evtq = &decoder->evtq;
	struct ub_entity *uent = decoder->uent;
	u64 evt[EVTQ_ENT_DWORDS];
	void *ci;
	int i;

	if (ub_cfg_read_dword(uent, DECODER_EVENTQ_PROD, &(evtq->prod.val))) {
		ub_err(uent, "decoder handle event, read eventq pi fail\n");
		return;
	}

	while (!queue_empty(evtq)) {
		ci = evtq->qbase + Q_IDX(evtq->qs, evtq->cons.eventq_rd_idx) *
		     EVT_ENTRY_SIZE;

		for (i = 0; i < EVTQ_ENT_DWORDS; i++)
			evt[i] = readq(ci + i * sizeof(u64));

		handle_evt(decoder, evt);
		queue_inc_cons(evtq);

		if (ub_cfg_write_dword(uent, DECODER_EVENTQ_CONS,
				       evtq->cons.val))
			ub_err(uent, "decoder handle event, write eventq ci fail\n");
	}
}
