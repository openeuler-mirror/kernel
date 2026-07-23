/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/**
 * @file hal_smmu.h
 * @brief SMMU hardware abstraction layer definitions
 * @details ARM v8 page table format definitions for MMU600
 */

#ifndef _ZXDH_HAL_SMMU_H_
#define _ZXDH_HAL_SMMU_H_

#include <linux/types.h>

/*
 * Memory attribute definitions for SMMU page table entries
 *
 * Abbreviations:
 * SO: Strongly-ordered memory
 * DE: Device memory
 * NM: Normal memory
 * IWT: Inner cache, write-through
 * OWT: Outer cache, write-through
 * INC: Inner non-cacheable
 * ONC: Outer non-cacheable
 * IWB: Inner cache, write-back
 * OWB: Outer cache, write-back
 */

/* Bit width mask definitions */
#define SMMU_BIT_MASK(bits) ((1ULL << (bits)) - 1)

/* Common bit masks */
#define SMMU_BW1 0x00000001ULL
#define SMMU_BW2 0x00000003ULL
#define SMMU_BW3 0x00000007ULL
#define SMMU_BW4 0x0000000fULL
#define SMMU_BW8 0x000000ffULL
#define SMMU_BW16 0x0000ffffULL
#define SMMU_BW32 0xffffffffULL
#define SMMU_BW48 0x0000ffffffffffffULL
#define SMMU_BW52 0x000fffffffffffffULL

/* Page table entry field positions and masks */
#define SMMU_PTE_WACFG_POS 55
#define SMMU_PTE_WACFG_MASK (SMMU_BW2 << SMMU_PTE_WACFG_POS)
#define SMMU_PTE_RACFG_POS 57
#define SMMU_PTE_RACFG_MASK (SMMU_BW2 << SMMU_PTE_RACFG_POS)

/* L1 descriptor definitions */
#define SMMU_L1_BLOCK_XN_POS 53
#define SMMU_L1_BLOCK_XN_MASK (SMMU_BW1 << SMMU_L1_BLOCK_XN_POS)
#define SMMU_L1_BLOCK_PA_POS 30
#define SMMU_L1_BLOCK_PA_MASK (SMMU_BW18 << SMMU_L1_BLOCK_PA_POS)
#define SMMU_L1_BLOCK_AF_POS 10
#define SMMU_L1_BLOCK_AF_MASK (SMMU_BW1 << SMMU_L1_BLOCK_AF_POS)
#define SMMU_L1_BLOCK_SH_POS 8
#define SMMU_L1_BLOCK_SH_MASK (SMMU_BW2 << SMMU_L1_BLOCK_SH_POS)
#define SMMU_L1_BLOCK_AP_POS 6
#define SMMU_L1_BLOCK_AP_MASK (SMMU_BW2 << SMMU_L1_BLOCK_AP_POS)
#define SMMU_L1_BLOCK_MEMATTR_POS 2
#define SMMU_L1_BLOCK_MEMATTR_MASK (SMMU_BW4 << SMMU_L1_BLOCK_MEMATTR_POS)

#define SMMU_L1_DESC_BLOCK 1
#define SMMU_L1_DESC_TABLE 3

/* L2 descriptor definitions */
#define SMMU_L2_BLOCK_XN_POS 53
#define SMMU_L2_BLOCK_XN_MASK (SMMU_BW1 << SMMU_L2_BLOCK_XN_POS)
#define SMMU_L2_BLOCK_PA_POS 21
#define SMMU_L2_BLOCK_PA_MASK (SMMU_BW27 << SMMU_L2_BLOCK_PA_POS)
#define SMMU_L2_BLOCK_AF_POS 10
#define SMMU_L2_BLOCK_AF_MASK (SMMU_BW1 << SMMU_L2_BLOCK_AF_POS)
#define SMMU_L2_BLOCK_SH_POS 8
#define SMMU_L2_BLOCK_SH_MASK (SMMU_BW2 << SMMU_L2_BLOCK_SH_POS)
#define SMMU_L2_BLOCK_AP_POS 6
#define SMMU_L2_BLOCK_AP_MASK (SMMU_BW2 << SMMU_L2_BLOCK_AP_POS)
#define SMMU_L2_BLOCK_MEMATTR_POS 2
#define SMMU_L2_BLOCK_MEMATTR_MASK (SMMU_BW4 << SMMU_L2_BLOCK_MEMATTR_POS)

#define SMMU_L2_DESC_BLOCK 1
#define SMMU_L2_DESC_TABLE 3

/* L3 descriptor definitions */
#define SMMU_L3_PAGE_XN_POS 53
#define SMMU_L3_PAGE_XN_MASK (SMMU_BW1 << SMMU_L3_PAGE_XN_POS)
#define SMMU_L3_PAGE_PA_POS 12
#define SMMU_L3_PAGE_PA_MASK (SMMU_BW36 << SMMU_L3_PAGE_PA_POS)
#define SMMU_L3_PAGE_AF_POS 10
#define SMMU_L3_PAGE_AF_MASK (SMMU_BW1 << SMMU_L3_PAGE_AF_POS)
#define SMMU_L3_PAGE_SH_POS 8
#define SMMU_L3_PAGE_SH_MASK (SMMU_BW2 << SMMU_L3_PAGE_SH_POS)
#define SMMU_L3_PAGE_AP_POS 6
#define SMMU_L3_PAGE_AP_MASK (SMMU_BW2 << SMMU_L3_PAGE_AP_POS)
#define SMMU_L3_PAGE_MEMATTR_POS 2
#define SMMU_L3_PAGE_MEMATTR_MASK (SMMU_BW4 << SMMU_L3_PAGE_MEMATTR_POS)

#define SMMU_L3_DESC_PAGE 3

/* Memory attribute values */
#define READ_NOALLOCATE 0x100
#define WRITE_NOALLOCATE 0x200

/* Page table validity flags */
#define SMMU_PAGETABLE_INVALID 0
#define SMMU_PAGETABLE_VALID 1
#define SMMU_PAGETABLE_PAGE_TYPE 3
#define SMMU_PAGETABLE_BLOCK_TYPE 1

/* Execute permission */
#define SMMU_PAGETABLE_EXECUTE_NEVER 1 /* XN=1, cannot execute */
#define SMMU_PAGETABLE_EXECUTE 0 /* XN=0, can execute */

/* Page size definitions */
#define SMMU_PAGETABLE_PAGESIZE_4KB 0 /* 4KB small page */
#define SMMU_PAGETABLE_PAGESIZE_64KB 1 /* 64KB large page */
#define SMMU_PAGETABLE_PAGESIZE_1MB 2 /* 1MB section */
#define SMMU_PAGETABLE_PAGESIZE_2MB 3 /* 2MB block */
#define SMMU_PAGETABLE_PAGESIZE_16MB 4 /* 16MB super-section */
#define SMMU_PAGETABLE_PAGESIZE_512MB 5 /* 512MB block */
#define SMMU_PAGETABLE_PAGESIZE_1GB 6 /* 1GB block */

/**
 * struct smmu_pte_cfg - SMMU page table entry configuration
 * @pa_base_addr: Block base physical address
 * @execute_never: Execute never flag (XN bit)
 * @shareable: Shareability attribute (SH field)
 * @access_permission: Access permission (AP field)
 * @memory_attribute: Memory attribute (MemAttr field)
 * @page_type: Page size type
 * @write_allocate_cfg: Write allocate configuration
 * @read_allocate_cfg: Read allocate configuration
 * @endian: Endianness setting
 * @page_format: Page table format version
 */
struct smmu_pte_cfg {
	u64 pa_base_addr;
	u64 execute_never;
	u32 shareable;
	u32 access_permission;
	u32 memory_attribute;
	u32 page_type;
	u64 write_allocate_cfg;
	u64 read_allocate_cfg;
	u32 endian;
	u32 page_format;
};

#endif /* _ZXDH_HAL_SMMU_H_ */
