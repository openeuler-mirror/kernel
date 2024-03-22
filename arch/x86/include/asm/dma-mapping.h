/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_DMA_MAPPING_H
#define _ASM_X86_DMA_MAPPING_H

extern const struct dma_map_ops *dma_ops;

static inline const struct dma_map_ops *get_arch_dma_ops(void)
{
	return dma_ops;
}

#ifdef CONFIG_PCI

extern bool is_zhaoxin_kh40000;
extern const struct dma_map_ops kh40000_dma_direct_ops;
extern void kh40000_set_iommu_dma_ops(struct device *dev);

#endif

#endif
