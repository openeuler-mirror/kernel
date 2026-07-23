/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/**
 * @file        cmdk_mmu600.h
 * @brief       SMMU MMU600 command definitions and structures
 */

#ifndef CMDK_MMU600_H
#define CMDK_MMU600_H

#include <linux/types.h>
#include <linux/device.h>

/* Forward declarations */
struct smmu_pte_address;
struct zxdh_sc_dev;

/* SMMU structures following Linux kernel naming conventions */
struct smmu_pagetable_param {
	u64 pagetable_phy_addr;
	u64 pagetable_vir_addr;
	u32 pagetable_size;
	u64 ex_pagetable_phy_addr;
	u32 ex_pagetable_size;
	u32 l1_pagetable_num;
	u32 l2_pagetable_num;
	u32 l3_pagetable_num;
};

struct smmu_pte_request {
	u32 stream_id;
	u64 phy_addr;
	u64 vir_addr;
	u64 size;
	u32 access_perm;
	u32 mem_attr;
	u32 shareability;
};

/* Function prototypes */
u32 uswap_32(u32 v);
u64 uswap_64(u64 v);
u32 memset_8byte(u64 *p, u64 data, u64 size);
u32 zxdh_smmu_cmd_tlb_sync(void);
u32 zxdh_smmu_set_print_level(u32 print_level);
u8 zxdh_smmu_get_print_level(void);
u32 zxdh_smmu_struct_init(const struct smmu_pagetable_param *pgt_param,
			  struct smmu_pte_address *pte_address, struct device *dmadev);

u32 zxdh_smmu_mmap(struct smmu_pte_request *pte_request, struct zxdh_sc_dev *dev);

#endif /* CMDK_MMU600_H */
