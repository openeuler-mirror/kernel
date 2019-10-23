/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef __ACC_DATA_H__
#define __ACC_DATA_H__

#include <linux/pci.h>
#include <linux/mm.h>
#include "rde_api.h"

static inline dma_addr_t acc_virt_to_phys(struct pci_dev *pdev, void *va,
	size_t size, u32 smmu_state)
{
	dma_addr_t pa;

	if (!smmu_state)
		pa = (dma_addr_t)virt_to_phys(va);
	else
		pa = pci_map_single(pdev, va, size, DMA_BIDIRECTIONAL);

	return pa;
}

static inline dma_addr_t acc_pfn_to_phys(void *va)
{
	unsigned long pfn;
	unsigned long off;
	unsigned long pa;

	off = (uintptr_t)va % PAGE_SIZE;
	pfn = vmalloc_to_pfn(va);
	pa = (pfn << PAGE_SHIFT) + off;

	return pa;
}

static inline void acc_phys_to_virt(struct pci_dev *pdev, dma_addr_t pa,
	size_t size, u32 smmu_state)
{
	if (smmu_state)
		pci_unmap_single(pdev, pa, size, DMA_BIDIRECTIONAL);
}

int acc_sgl_dump(struct sgl_hw *data);
int acc_sgl_virt_to_phys(struct pci_dev *pdev, struct sgl_hw *data,
	void **sglist_head, u32 smmu_state);
int acc_sgl_phys_to_virt(struct pci_dev *pdev,
	void *sglist_head, u32 smmu_state);

#endif
