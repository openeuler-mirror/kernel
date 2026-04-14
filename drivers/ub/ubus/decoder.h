/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __DECODER_H__
#define __DECODER_H__

#include <ub/ubus/ubus.h>

enum ub_cmd_op_type {
	INVALID = 0x0,
	SYNC = 0x1,
	TLBI_ALL = 0x2,
	TLBI_PARTIAL = 0x3,
};

struct queue_idx {
	union {
		u32 val;
		struct {
			u32 cmdq_wr_idx : 11;
			u32 reserved1 : 5;
			u32 cmdq_err_resp : 1;
			u32 reserved2 : 15;
		};
		struct {
			u32 cmdq_rd_idx : 11;
			u32 reserved3 : 5;
			u32 cmdq_err : 1;
			u32 cmdq_err_reason : 3;
			u32 reserved4 : 12;
		};
		struct {
			u32 eventq_wr_idx : 11;
			u32 reserved5 : 21;
		};
		struct {
			u32 eventq_rd_idx : 11;
			u32 reserved6 : 20;
			u32 eventq_ovfl_err_resp : 1;
		};
	};
};

struct ub_decoder_queue {
	phys_addr_t base;
	void __iomem *qbase;
	u32 qs;
	struct queue_idx prod;
	struct queue_idx cons;
};

struct reg_default_val {
	u32 cmdq_cfg_val;
	u32 evtq_cfg_val;
};

struct page_table_desc {
	void *page_base;
	dma_addr_t page_dma;
	u32 count;
};

struct page_table {
	void *pgtlb_base;
	dma_addr_t pgtlb_dma;
	struct page_table_desc *desc_base;
};

struct ub_decoder {
	struct device *dev;
	struct ub_entity *uent;
	phys_addr_t mmio_base_addr;
	phys_addr_t mmio_end_addr;
	u32 mmio_size_sup;
	u64 rg_size;
	struct ub_decoder_queue cmdq;
	struct ub_decoder_queue evtq;
	struct page_table pgtlb;
	struct reg_default_val vals;
	void __iomem *notify;
	int irq_num;

	struct page_table_desc invalid_desc;
	u64 invalid_page_dma;

	struct mutex table_lock;
	bool create_matt;
};

struct decoder_map_info {
	phys_addr_t pa;
	phys_addr_t uba;
	u64 size;
	u32 tpg_num;
	u8 order_id;
	u8 order_type;
	u64 eid_low;
	u64 eid_high;
	u32 token_id;
	u32 token_value;
	u32 upi;
	u32 src_eid;
};

void ub_decoder_init(struct ub_entity *uent);
void ub_decoder_uninit(struct ub_entity *uent);
void ub_init_decoder_usi(struct ub_entity *uent);
void ub_uninit_decoder_usi(struct ub_entity *uent);
int ub_decoder_map(struct ub_decoder *decoder, struct decoder_map_info *info);
int ub_decoder_unmap(struct ub_decoder *decoder, phys_addr_t addr, u64 size);
#endif /* __DECODER_H__ */
