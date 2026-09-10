// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., All rights reserved.
 * Description: common built-in symbols.
 */

#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/dma-map-ops.h>
#include <linux/iommu.h>
#include <linux/ummu_core.h>

#include "../../iommu-priv.h"

void setup_tdev_dma_ops(struct device *dev, bool coherent)
{
	arch_setup_dma_ops(dev, 0, U64_MAX, coherent);
}
EXPORT_SYMBOL_NS_GPL(setup_tdev_dma_ops, UMMU_CORE_INTERNAL);

struct iommu_domain *ummu_core_get_domain_by_tid(struct device *dev,
						 u32 tid)
{
	struct iommu_attach_handle *attach_handle;
	struct iommu_domain *domain;

	attach_handle = iommu_attach_handle_get(dev->iommu_group, tid,
						IOMMU_DOMAIN_SVA);
	if (IS_ERR(attach_handle))
		domain = iommu_get_domain_for_dev(dev);
	else
		domain = attach_handle->domain;

	if (!domain)
		return NULL;

	if (to_ummu_base_domain(domain)->tid != tid)
		return NULL;

	return domain;
}
EXPORT_SYMBOL_GPL(ummu_core_get_domain_by_tid);
