/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UMMU_FLUSH_H__
#define __UMMU_FLUSH_H__

#include "ummu.h"

struct ummu_tlb_range {
	unsigned long iova;
	size_t size;
	size_t granule;
};

void ummu_sync_iommu_domain(struct ummu_base_domain *base_domain,
			    struct iommu_domain *domain);

/* for ummu device reset */
void ummu_init_flush_iotlb(struct ummu_device *ummu);

/* for default_domain_ops */
void ummu_flush_iotlb_all(struct iommu_domain *iommu_domain);
void ummu_flush_iotlb_all_asid(struct iommu_domain *iommu_domain);
void ummu_iotlb_sync(struct iommu_domain *iommu_domain,
		     struct iommu_iotlb_gather *gather);
void ummu_device_tlb_inv_walk(struct iommu_domain *iommu_domain,
			      struct iommu_iotlb_gather *gather);
/* for io_pgtable */
void ummu_tlbi_context(void *cookie);
void ummu_tlbi_walk(unsigned long iova, size_t size, size_t granule,
		    void *cookie);
void ummu_tlbi_page(struct iommu_iotlb_gather *gather, unsigned long iova,
		    size_t granule, void *cookie);

void ummu_device_prefetch_cfg(struct ummu_device *ummu, u32 tecte_tag,
			      u32 tid);
void ummu_sync_tect_range(struct ummu_device *ummu, u32 tecte_tag,
			  u8 range);
void ummu_sync_tect_all(struct ummu_device *ummu);
void ummu_device_sync_tect(struct ummu_device *ummu, u32 tecte_tag);
void ummu_sync_tct(struct ummu_device *ummu, u32 tecte_tag, u32 tid,
		   bool leaf);
void ummu_sync_tct_all(struct ummu_device *ummu, u32 tecte_tag);
int ummu_device_flush_plb(struct ummu_device *ummu, u32 tag, u32 tid,
			  u64 addr, size_t size);
void ummu_device_flush_plb_all(struct iommu_domain *iommu_domain);
void ummu_device_flush_ioplb_all(struct ummu_device *ummu);
int ummu_device_check_pa_continuity(struct ummu_device *ummu, u64 addr,
				    u32 size_order, u32 id);
#endif /*__UMMU_FLUSH_H__*/
