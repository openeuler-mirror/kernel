/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_ALLOC_H_
#define _NSEVF_ALLOC_H_

struct nsevf_hw;

/* Memory allocation types */
enum nsevf_memory_type {
	nsevf_mem_arq_buf = 0, /* ARQ indirect command buffer */
	nsevf_mem_asq_buf = 1,
	nsevf_mem_atq_buf = 2, /* ATQ indirect command buffer */
	nsevf_mem_arq_ring = 3, /* ARQ descriptor ring */
	nsevf_mem_atq_ring = 4, /* ATQ descriptor ring */
	nsevf_mem_pd = 5, /* Page Descriptor */
	nsevf_mem_bp = 6, /* Backing Page - 4KB */
	nsevf_mem_bp_jumbo = 7, /* Backing Page - > 4KB */
	nsevf_mem_reserved
};

/* prototype for functions used for dynamic memory allocation */
enum nsevf_status nsevf_allocate_dma_mem(struct nsevf_hw *hw,
					 struct nsevf_dma_mem *mem,
					 enum nsevf_memory_type type, u64 size,
					 u32 alignment);
enum nsevf_status nsevf_free_dma_mem(struct nsevf_hw *hw,
				     struct nsevf_dma_mem *mem);
enum nsevf_status nsevf_allocate_virt_mem(struct nsevf_hw *hw,
					  struct nsevf_virt_mem *mem, u32 size);
enum nsevf_status nsevf_free_virt_mem(struct nsevf_hw *hw,
				      struct nsevf_virt_mem *mem);

#endif /* _NSEVF_ALLOC_H_ */
