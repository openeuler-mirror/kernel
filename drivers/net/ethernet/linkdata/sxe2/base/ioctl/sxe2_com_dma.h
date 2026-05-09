/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_dma.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_COM_DMA_H__
#define __SXE2_COM_DMA_H__

#include <linux/iommu.h>

struct sxe2_com_context;

#define SXE2_COM_TO_DOMAIN(dma_dev) (iommu_get_domain_for_dev((dma_dev)->dev))
#define SXE2_COM_TO_BUS(dma_dev) (((dma_dev)->dev)->bus)

struct sxe2_com_dma {
	struct list_head list;

	unsigned long vaddr;
	size_t size;
	int prot;
	dma_addr_t iova;
};

struct sxe2_com_dma_dev {
	struct device *dev;
	/* in order to protect the data */
	struct mutex lock;
	struct list_head buffer_list;
};

static inline bool sxe2_com_iommu_supp(struct sxe2_com_dma_dev *dma_dev)
{
	return SXE2_COM_TO_DOMAIN(dma_dev) &&
	    (SXE2_COM_TO_DOMAIN(dma_dev)->type & __IOMMU_DOMAIN_PAGING);
}

s32 sxe2_com_dma_map(struct sxe2_com_context *com_ctxt, unsigned long arg);

s32 sxe2_com_dma_unmap(struct sxe2_com_context *com_ctxt, unsigned long arg);

s32 sxe2_com_dma_clear(struct sxe2_com_context *com_ctxt);

void sxe2_com_dma_print(struct sxe2_com_context *com_ctxt);

#endif
