/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_DMA_MAPPING_H
#define _ASM_DMA_MAPPING_H

extern const struct dma_map_ops loongson_dma_ops;
extern bool swiotlb_need_fix;
extern phys_addr_t io_tlb_start;

static inline const struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	if (swiotlb_need_fix)
		return &loongson_dma_ops;
	else
		return NULL;
}

#endif /* _ASM_DMA_MAPPING_H */
