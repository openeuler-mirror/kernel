// SPDX-License-Identifier: GPL-2.0
/*
 *	linux/arch/sw_64/kernel/pci_iommu.c
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/scatterlist.h>
#include <linux/log2.h>
#include <linux/dma-mapping.h>
#include <linux/iommu-helper.h>
#include <linux/slab.h>

#include <linux/swiotlb.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <asm/dma.h>

#include <asm/io.h>

const struct dma_map_ops *dma_ops = NULL;
EXPORT_SYMBOL(dma_ops);
