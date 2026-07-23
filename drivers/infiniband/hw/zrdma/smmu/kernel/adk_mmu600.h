/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXDH_SMMU_H_
#define _ZXDH_SMMU_H_

#include <linux/types.h>
#include <linux/device.h>
#include "cmdk_mmu600.h"

/* Forward declarations */
struct smmu_pagetable_param;
struct smmu_pte_request;
struct zxdh_sc_dev;
struct dentry;

/* Maximum stream ID number */
#define ZXDH_SMMU_MAX_STREAM_NUM 64

/* Page Table Entry Access Permission values */
#define SMMU_PTE_AP_EL1_RW 0 /* EL1+ R/W, EL0 none */
#define SMMU_PTE_AP_ALL_RW 1 /* R/W in all EL */
#define SMMU_PTE_AP_EL1_RO 2 /* EL1+ RO, EL0 none */
#define SMMU_PTE_AP_ALL_RO 3 /* RO in all EL */

/* Memory Attribute values */
#define SMMU_PTE_MEMATTR_DEVICE 0
#define SMMU_PTE_MEMATTR_NORMAL_WB_WA 1
#define SMMU_PTE_MEMATTR_NON_CACHEABLE 2

/* Shareability values */
#define SMMU_PAGETABLE_NON_SHAREABLE 0 /* Non-shareable */
#define SMMU_PAGETABLE_OUTER_SHAREABLE 2 /* Outer shareable */
#define SMMU_PAGETABLE_INNER_SHAREABLE 3 /* Inner shareable */

/* SMMU command and message definitions */
#define ZXDH_SMMU_MSG_EVENT_ID 6
#define SMMU_CMDQ_OP_TLBI_NSNH_ALL 0x30
#define ZXDH_SMMU_INVALID_TLB_TIMEOUT_MS 15000

/**
 * struct smmu_tlb_invalidate_cfg - TLB invalidation configuration
 * @cmd: Command type
 * @scale: Scale factor
 * @num: Number of entries
 * @tg: Translation granule
 * @leaf: Leaf level
 * @ttl: Translation table level
 * @vmid: Virtual machine ID
 * @asid: Address space ID
 * @addr: Target address
 */
struct smmu_tlb_invalidate_cfg {
	u32 cmd;
	u32 scale;
	u32 num;
	u32 tg;
	u32 leaf;
	u32 ttl;
	u32 vmid;
	u32 asid;
	u64 addr;
};

/**
 * struct smmu_msg_info - SMMU message information
 * @is_tlb_invalid: TLB invalidation flag
 * @tlb_cfg: TLB invalidation configuration
 */
struct smmu_msg_info {
	u32 is_tlb_invalid;
	struct smmu_tlb_invalidate_cfg tlb_cfg;
};

/**
 * struct smmu_pte_record - Page table entry record
 * @valid: Entry validity
 * @stream_id: Stream ID
 * @virt_addr: Virtual address
 * @phy_addr: Physical address
 * @size: Size
 */
struct smmu_pte_record {
	u32 valid;
	u32 stream_id;
	u64 virt_addr;
	u64 phy_addr;
	u64 size;
};

/* Structure definitions */

/**
 * struct smmu_pte_address - SMMU page table address management
 * @cma_page_mem_base_pa: CMA page memory base physical address
 * @cma_page_mem_base_va: CMA page memory base virtual address
 * @cma_mem_base_va_pte: CMA memory base virtual address for PTE
 * @pagetable_cfg: Page table configuration
 * @pagetable_vir_base_addr: Page table virtual base address
 * @map_manage_addr: Map management address for L2/L3
 * @pte_records: PTE records array
 * @cma_page_addr: CMA page address
 * @pte_temp_vir_addr: Temporary PTE virtual address
 * @pte_temp_phy_addr: Temporary PTE physical address
 * @l1_pagetable_num: L1 page table number
 * @l2_pagetable_num: L2 page table number
 * @l3_pagetable_num: L3 page table number
 * @pte_record_num: PTE record number
 * @pte_fail_record_num: PTE fail record number
 * @l2d_smmu_l2_offset: L2D SMMU L2 offset
 */
struct smmu_pte_address {
	u64 cma_page_mem_base_pa;
	u64 cma_page_mem_base_va;
	u64 cma_mem_base_va_pte;
	struct smmu_pagetable_param pagetable_cfg;
	u64 pagetable_vir_base_addr;
	u64 map_manage_addr;
	struct smmu_pte_record *pte_records;
	struct page *cma_page_addr;
	u64 pte_temp_vir_addr;
	u64 pte_temp_phy_addr;
	u32 l1_pagetable_num;
	u32 l2_pagetable_num;
	u32 l3_pagetable_num;
	u32 pte_record_num;
	u32 pte_fail_record_num;
	struct dentry *dbg_dentry;
	u32 l2d_smmu_l2_offset;
};

/* Function prototypes */
int zxdh_smmu_pagetable_init(struct zxdh_sc_dev *dev);
int zxdh_smmu_pagetable_exit(struct zxdh_sc_dev *dev);
int zxdh_smmu_enable_stream_stage2(u32 stream_id);
int zxdh_smmu_enable_stream_bypass(u32 stream_id);

int zxdh_smmu_set_pte(struct smmu_pte_request *pte_req, struct zxdh_sc_dev *dev);
int zxdh_smmu_delete_pte(u32 stream_id, u64 virt_addr, struct zxdh_sc_dev *dev);

int zxdh_smmu_invalidate_tlb(struct zxdh_sc_dev *dev);

#endif /* _ZXDH_SMMU_H_ */
