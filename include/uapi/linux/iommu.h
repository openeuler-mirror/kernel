/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * IOMMU user API definitions
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _UAPI_IOMMU_H
#define _UAPI_IOMMU_H

#include <linux/types.h>

/**
 * PASID table data used to bind guest PASID table to the host IOMMU. This will
 * enable guest managed first level page tables.
 * @version: for future extensions and identification of the data format
 * @bytes: size of this structure
 * @base_ptr:	PASID table pointer
 * @pasid_bits:	number of bits supported in the guest PASID table, must be less
 *		or equal than the host supported PASID size.
 */
struct pasid_table_config {
	__u32 version;
#define PASID_TABLE_CFG_VERSION 1
	__u32 bytes;
	__u64 base_ptr;
	__u8 pasid_bits;
};

/**
 * enum iommu_inv_granularity - Generic invalidation granularity
 *
 * When an invalidation request is sent to IOMMU to flush translation caches,
 * it may carry different granularity. These granularity levels are not specific
 * to a type of translation cache. For an example, PASID selective granularity
 * is only applicable to PASID cache invalidation.
 * This enum is a collection of granularities for all types of translation
 * caches. The idea is to make it easy for IOMMU model specific driver do
 * conversion from generic to model specific value.
 */
enum iommu_inv_granularity {
	IOMMU_INV_GRANU_DOMAIN = 1,	/* all TLBs associated with a domain */
	IOMMU_INV_GRANU_DEVICE,		/* caching structure associated with a
					 * device ID
					 */
	IOMMU_INV_GRANU_DOMAIN_PAGE,	/* address range with a domain */
	IOMMU_INV_GRANU_ALL_PASID,	/* cache of a given PASID */
	IOMMU_INV_GRANU_PASID_SEL,	/* only invalidate specified PASID */

	IOMMU_INV_GRANU_NG_ALL_PASID,	/* non-global within all PASIDs */
	IOMMU_INV_GRANU_NG_PASID,	/* non-global within a PASIDs */
	IOMMU_INV_GRANU_PAGE_PASID,	/* page-selective within a PASID */
	IOMMU_INV_NR_GRANU,
};

/** enum iommu_inv_type - Generic translation cache types for invalidation
 *
 * Invalidation requests sent to IOMMU may indicate which translation cache
 * to be operated on.
 * Combined with enum iommu_inv_granularity, model specific driver can do a
 * simple lookup to convert generic type to model specific value.
 */
enum iommu_inv_type {
	IOMMU_INV_TYPE_DTLB,	/* device IOTLB */
	IOMMU_INV_TYPE_TLB,	/* IOMMU paging structure cache */
	IOMMU_INV_TYPE_PASID,	/* PASID cache */
	IOMMU_INV_TYPE_CONTEXT,	/* device context entry cache */
	IOMMU_INV_NR_TYPE
};

/**
 * Translation cache invalidation header that contains mandatory meta data.
 * @version:	info format version, expecting future extesions
 * @type:	type of translation cache to be invalidated
 */
struct tlb_invalidate_hdr {
	__u32 version;
#define TLB_INV_HDR_VERSION_1 1
	enum iommu_inv_type type;
};

/**
 * Translation cache invalidation information, contains generic IOMMU
 * data which can be parsed based on model ID by model specific drivers.
 *
 * @granularity:	requested invalidation granularity, type dependent
 * @size:		2^size of 4K pages, 0 for 4k, 9 for 2MB, etc.
 * @pasid:		processor address space ID value per PCI spec.
 * @addr:		page address to be invalidated
 * @flags	IOMMU_INVALIDATE_PASID_TAGGED: DMA with PASID tagged,
 *						@pasid validity can be
 *						deduced from @granularity
 *		IOMMU_INVALIDATE_ADDR_LEAF: leaf paging entries
 *		IOMMU_INVALIDATE_GLOBAL_PAGE: global pages
 *
 */
struct tlb_invalidate_info {
	struct tlb_invalidate_hdr	hdr;
	enum iommu_inv_granularity	granularity;
	__u32		flags;
#define IOMMU_INVALIDATE_NO_PASID	(1 << 0)
#define IOMMU_INVALIDATE_ADDR_LEAF	(1 << 1)
#define IOMMU_INVALIDATE_GLOBAL_PAGE	(1 << 2)
#define IOMMU_INVALIDATE_PASID_TAGGED	(1 << 3)
	__u8		size;
	__u32		pasid;
	__u64		addr;
};
#endif /* _UAPI_IOMMU_H */
