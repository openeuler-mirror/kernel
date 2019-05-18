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

#endif /* _UAPI_IOMMU_H */
