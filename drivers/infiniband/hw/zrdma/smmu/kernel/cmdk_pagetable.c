// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "common_define.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/slab.h>
#include "hal_smmu.h"
#include "cmdk_mmu600.h"
#include "cmdk_mmu600_inner.h"
#include "pub_print.h"
#include "adk_mmu600.h"
#include "../../main.h"

/* Define missing macros for backward compatibility */
#define MAX_PTE_RECORDS_NUM (2000)

/* SMMU page table definitions */
#define SMMU_L1_PER_PT_SIZE 0x100
#define SMMU_L1_PT_ALIGN_SIZE 0x100
#define SMMU_L1_PT_NUM 32
#define SMMU_L1_PT_SIZE (SMMU_L1_PT_NUM * SMMU_L1_PER_PT_SIZE)

#define SMMU_L2_PER_PT_SIZE 0x1000
#define SMMU_L2_PT_ALIGN_SIZE 0x1000
#define SMMU_L2_PT_NUM 32
#define SMMU_L2_PT_SIZE (SMMU_L2_PT_NUM * SMMU_L2_PER_PT_SIZE)

#define SMMU_L3_PER_PT_SIZE 0x1000
#define SMMU_L3_PT_ALIGN_SIZE 0x1000
#define SMMU_L3_PT_NUM 0x3DE
#define SMMU_L3_PT_SIZE (SMMU_L3_PT_NUM * SMMU_L3_PER_PT_SIZE)

#define SMMU_PT_TOTAL (SMMU_L1_PT_SIZE + SMMU_L2_PT_SIZE + SMMU_L3_PT_SIZE)

#define PTE_L2D_START_PA 0x6200630000ULL

/* Page table masks */
#define PAGE_MASK_4K 0xfffffffff000ULL
#define PAGE_MASK_2M 0xffffffe00000ULL
#define PAGE_MASK_1G 0xffffc0000000ULL

#define REV_PAGE_MASK_4K 0x0000000fffULL
#define REV_PAGE_MASK_2M 0x00001fffffULL
#define REV_PAGE_MASK_1G 0x003fffffffULL

/* Page size constants */
#define PAGE_SIZE_4K 0x1000
#define PAGE_SIZE_2M 0x200000
#define PAGE_SIZE_1G 0x40000000

/* Page size compatibility */
#define SMMU_PAGETABLE_PAGESIZE_1G SMMU_PAGETABLE_PAGESIZE_1GB

/* Page table descriptor types */
#define L1_LONG_DESCRIPTOR_FOR_BLOCK 0x1
#define L1_LONG_DESCRIPTOR_FOR_TABLE 0x3
#define L2_LONG_DESCRIPTOR_FOR_BLOCK 0x1
#define L2_LONG_DESCRIPTOR_FOR_TABLE 0x3
#define L3_LONG_DESCRIPTOR_FOR_PAGE 0x3

/* Page table descriptor masks and positions */
#define L1_LONG_DESCRIPTOR_BLOCK_PA_MASK 0xFFFFC0000000ULL
#define L1_LONG_DESCRIPTOR_BLOCK_XN_POS 54
#define L1_LONG_DESCRIPTOR_BLOCK_XN_MASK (1ULL << 54)
#define L1_LONG_DESCRIPTOR_BLOCK_S2AP_POS 6
#define L1_LONG_DESCRIPTOR_BLOCK_S2AP_MASK (3ULL << 6)
#define L1_LONG_DESCRIPTOR_BLOCK_AF_POS 10
#define L1_LONG_DESCRIPTOR_BLOCK_AF_MASK (1ULL << 10)
#define L1_LONG_DESCRIPTOR_BLOCK_SH1SH0_POS 8
#define L1_LONG_DESCRIPTOR_BLOCK_SH1SH0_MASK (3ULL << 8)
#define L1_LONG_DESCRIPTOR_BLOCK_MEMATTR_POS 2
#define L1_LONG_DESCRIPTOR_BLOCK_MEMATTR_MASK (0xFULL << 2)
#define L1_LONG_DESCRIPTOR_TABLE_PA_MASK 0xFFFFFFFFF000ULL

#define L2_LONG_DESCRIPTOR_BLOCK_PA_MASK 0xFFFFFFE00000ULL
#define L2_LONG_DESCRIPTOR_BLOCK_XN_POS 54
#define L2_LONG_DESCRIPTOR_BLOCK_XN_MASK (1ULL << 54)
#define L2_LONG_DESCRIPTOR_BLOCK_S2AP_POS 6
#define L2_LONG_DESCRIPTOR_BLOCK_S2AP_MASK (3ULL << 6)
#define L2_LONG_DESCRIPTOR_BLOCK_AF_POS 10
#define L2_LONG_DESCRIPTOR_BLOCK_AF_MASK (1ULL << 10)
#define L2_LONG_DESCRIPTOR_BLOCK_SH1SH0_POS 8
#define L2_LONG_DESCRIPTOR_BLOCK_SH1SH0_MASK (3ULL << 8)
#define L2_LONG_DESCRIPTOR_BLOCK_MEMATTR_POS 2
#define L2_LONG_DESCRIPTOR_BLOCK_MEMATTR_MASK (0xFULL << 2)
#define L2_LONG_DESCRIPTOR_TABLE_PA_MASK 0xFFFFFFFFF000ULL

#define L3_LONG_DESCRIPTOR_BLOCK_PA_MASK 0xFFFFFFFFF000ULL
#define L3_LONG_DESCRIPTOR_BLOCK_XN_POS 54
#define L3_LONG_DESCRIPTOR_BLOCK_XN_MASK (1ULL << 54)
#define L3_LONG_DESCRIPTOR_BLOCK_S2AP_POS 6
#define L3_LONG_DESCRIPTOR_BLOCK_S2AP_MASK (3ULL << 6)
#define L3_LONG_DESCRIPTOR_BLOCK_AF_POS 10
#define L3_LONG_DESCRIPTOR_BLOCK_AF_MASK (1ULL << 10)
#define L3_LONG_DESCRIPTOR_BLOCK_SH1SH0_POS 8
#define L3_LONG_DESCRIPTOR_BLOCK_SH1SH0_MASK (3ULL << 8)
#define L3_LONG_DESCRIPTOR_BLOCK_MEMATTR_POS 2
#define L3_LONG_DESCRIPTOR_BLOCK_MEMATTR_MASK (0xFULL << 2)

/* RACFG and WACFG related macros */
#define LONG_DESCRIPTOR_RACFG_POS 59
#define LONG_DESCRIPTOR_RACFG_MASK (7ULL << 59)
#define LONG_DESCRIPTOR_WACFG_POS 56
#define LONG_DESCRIPTOR_WACFG_MASK (7ULL << 56)

/* Missing macro definitions for compatibility */
#define MEMSET(ptr, size, val, len) memset(ptr, val, len)
#define MEMCPY(dst, size, src, len) memcpy(dst, src, len)

/* Map manage structure sizes using existing definition */
#define SMMU_L2_MAP_MANAGE_SIZE (SMMU_L2_PT_NUM * sizeof(struct t_Map_Manage))
#define SMMU_L3_MAP_MANAGE_SIZE (SMMU_L3_PT_NUM * sizeof(struct t_Map_Manage))

/* TTB management structure */
struct smmu_ttb_manage {
	u32 stream_id;
	u32 valid;
	u64 phy_ttb;
};

/* Forward declarations */
static u64 zxdh_smmu_host_pa_to_l2d_pa(u64 host_pa, struct zxdh_sc_dev *dev);

/* Static variables for page table management */
static u32 s_udV8NumL3Pta __maybe_unused;
static struct smmu_ttb_manage *g_ptTtbMng;

/**
 * zxdh_smmu_get_ttb - Get translation table base address
 * @sid: Stream ID
 * @pte_address: PTE address management structure
 *
 * Return: TTB physical address
 */
static u64 zxdh_smmu_get_ttb(u32 sid, struct smmu_pte_address *pte_address)
{
	return pte_address->cma_page_mem_base_pa + sid * SMMU_L1_PER_PT_SIZE;
}

/**
 * zxdh_smmu_get_pte_size - Get PTE size based on request
 * @request_va: Requested virtual address
 * @request_size: Requested size
 * @ppte_size: Output PTE size
 *
 * Determine the optimal page table entry size (4K, 2M, or 1G blocks).
 *
 * Return: 0 on success, negative error code on failure
 */
static u32 zxdh_smmu_get_pte_size(u64 request_va, u64 request_size, u32 *ppte_size)
{
	/* Check for 1G block alignment and size */
	if (((request_va & REV_PAGE_MASK_1G) == 0) && (request_size >= PAGE_SIZE_1G)) {
		*ppte_size = PAGE_SIZE_1G;
		return 0;
	}

	/* Check for 2M block alignment and size */
	if (((request_va & REV_PAGE_MASK_2M) == 0) && (request_size >= PAGE_SIZE_2M)) {
		*ppte_size = PAGE_SIZE_2M;
		return 0;
	}

	/* Default to 4K pages */
	*ppte_size = PAGE_SIZE_4K;
	return 0;
}

static u32 zxdh_smmu_request_to_pte_cfg(const u32 pte_size,
					const struct smmu_pte_request *pte_request,
					struct smmu_pte_cfg *tlb_entry_cfg)
{
	u64 request_phy_addr = 0;

	/* param check */
	if (!tlb_entry_cfg)
		return -EINVAL;
	if (!pte_request)
		return -EINVAL;

	request_phy_addr = pte_request->phy_addr;

	tlb_entry_cfg->execute_never = SMMU_PAGETABLE_EXECUTE;
	tlb_entry_cfg->shareable = pte_request->shareability;
	tlb_entry_cfg->access_permission = pte_request->access_perm;
	tlb_entry_cfg->memory_attribute = pte_request->mem_attr;

	tlb_entry_cfg->read_allocate_cfg = 0;
	tlb_entry_cfg->write_allocate_cfg = 0;
	if (READ_NOALLOCATE == (READ_NOALLOCATE & tlb_entry_cfg->memory_attribute))
		tlb_entry_cfg->read_allocate_cfg = 3;

	if (WRITE_NOALLOCATE == (WRITE_NOALLOCATE & tlb_entry_cfg->memory_attribute))
		tlb_entry_cfg->write_allocate_cfg = 3;

	switch (pte_size) {
	case PAGE_SIZE_4K: {
		tlb_entry_cfg->pa_base_addr = request_phy_addr & PAGE_MASK_4K;
		tlb_entry_cfg->page_type = SMMU_PAGETABLE_PAGESIZE_4KB; /* */
		break;
	}
	case PAGE_SIZE_2M: {
		tlb_entry_cfg->pa_base_addr = request_phy_addr & PAGE_MASK_2M;
		tlb_entry_cfg->page_type = SMMU_PAGETABLE_PAGESIZE_2MB; /* */
		break;
	}
	case PAGE_SIZE_1G: {
		tlb_entry_cfg->pa_base_addr = request_phy_addr & PAGE_MASK_1G;
		tlb_entry_cfg->page_type = SMMU_PAGETABLE_PAGESIZE_1G; /* */
		break;
	}
	default: {
		tlb_entry_cfg->pa_base_addr = request_phy_addr & PAGE_MASK_4K;
		tlb_entry_cfg->page_type = SMMU_PAGETABLE_PAGESIZE_4KB; /* */
		break;
	}
	}

	return 0;
}

static u64 zxdh_smmu_sram_pagetable_v2p(u64 virt_addr, struct smmu_pte_address *pte_address)
{
	u64 phy_addr = 0;

	if ((pte_address->pagetable_vir_base_addr == 0) ||
	    (pte_address->pagetable_cfg.pagetable_phy_addr == 0)) {
		return -1;
	}

	phy_addr = pte_address->pagetable_cfg.pagetable_phy_addr + virt_addr -
		   pte_address->pagetable_vir_base_addr;

	return phy_addr;
}

static u64 zxdh_smmu_sram_pagetable_p2v(u64 phy_addr, struct smmu_pte_address *pte_address)
{
	u64 virt_addr = 0;

	if ((pte_address->pagetable_vir_base_addr == 0) ||
	    (pte_address->pagetable_cfg.pagetable_phy_addr == 0)) {
		return -1;
	}

	virt_addr = pte_address->pagetable_vir_base_addr + phy_addr -
		    pte_address->pagetable_cfg.pagetable_phy_addr;

	return virt_addr;
}

static u64 zxdh_smmu_get_l1_descriptor_va(u64 udd_l1_ttb_va, u64 request_va)
{
	return (udd_l1_ttb_va + ((request_va & 0xffc0000000ULL) >> 27));
}

static u64 zxdh_smmu_get_l2_descriptor_va(struct zxdh_sc_dev *dev, u32 sid, u64 request_va,
					  struct smmu_pte_address *pte_address)
{
	u32 i = 0;
	u64 level_mask = 0;
	u32 level_offset = 0;
	u64 l2_nth_ttb_va = 0;
	u64 udd_l2_start_ttb_va = 0;
	struct t_Map_Manage *l2_map_manage = NULL;
	u32 *used_l2_ttb_num = NULL;

	/* check param */
	if (!pte_address)
		return -EINVAL;
	if (!pte_address->map_manage_addr)
		return -EINVAL;

	level_mask = 0x3fe00000ull; /* (1G-1)&(~(2M-1)) */
	level_offset = 18; /* div by 2M, mul 8 */

	/* l2 map manage struct */
	l2_map_manage = (struct t_Map_Manage *)(pte_address->map_manage_addr);

	udd_l2_start_ttb_va = pte_address->pagetable_vir_base_addr + SMMU_L1_PT_SIZE +
			      pte_address->l2d_smmu_l2_offset;

	used_l2_ttb_num = &dev->s_udV8NumL2Pta;

	/* if the 1G which this va corresponds to has been allocated, find the existing address */
	for (i = 0; i < *used_l2_ttb_num; i++) {
		if (((request_va & PAGE_MASK_1G) == l2_map_manage[i].uddMaskedVa) &&
		    l2_map_manage[i].udMapValid && (sid == l2_map_manage[i].udSteamIndex)) {
			break;
		}
	}

	/* if not, allocate 4K space used for L2 page table for this 1G */
	if (i == *used_l2_ttb_num) {
		if (*used_l2_ttb_num < SMMU_L2_PT_NUM)
			l2_nth_ttb_va = udd_l2_start_ttb_va + i * SMMU_L2_PER_PT_SIZE;
		else
			return 0;

		l2_map_manage[i].udMapValid = 1;
		l2_map_manage[i].udSteamIndex = sid;
		l2_map_manage[i].uddTTBaseAddr = l2_nth_ttb_va;
		l2_map_manage[i].uddMaskedVa = request_va & PAGE_MASK_1G;

		*used_l2_ttb_num += 1;
		pte_address->l2_pagetable_num = *used_l2_ttb_num;
	}

	return (l2_map_manage[i].uddTTBaseAddr + (u64)((request_va & level_mask) >> level_offset));
}

static u64 zxdh_smmu_get_l3_descriptor(u32 sid, u64 request_va,
				       struct smmu_pte_address *pte_address)
{
	u32 i = 0;
	u64 level_mask = 0;
	u32 level_offset = 0;
	u64 l3_nth_ttb_va = 0;
	u64 udd_l3_start_ttb_va = 0;
	struct t_Map_Manage *l3_manage_map = NULL;
	u32 *used_l3_ttb_num = NULL;

	static u32 s_udV8NumL3Pta;

	/* check param */
	if (!pte_address)
		return -EINVAL;
	if (!pte_address->map_manage_addr)
		return -EINVAL;

	// 2M-1:   1 1111 1111 1111 1111 1111
	// 4K-1:               1111 1111 1111
	//~(4K-1): 1 1111 1111 0000 0000 0000
	level_mask = 0x001ff000ull; /* (2M-1)&(~(4K-1)) */
	level_offset = 9; /* div 4K, mul 8 */

	/* l3 map manage struct */
	l3_manage_map =
		(struct t_Map_Manage *)(pte_address->map_manage_addr + SMMU_L2_MAP_MANAGE_SIZE);

	udd_l3_start_ttb_va =
		pte_address->pagetable_vir_base_addr + SMMU_L1_PT_SIZE + SMMU_L2_PT_SIZE;

	used_l3_ttb_num = &s_udV8NumL3Pta;

	/* the same logic as get L2 */
	for (i = 0; i < *used_l3_ttb_num; i++) {
		if (((request_va & PAGE_MASK_2M) == l3_manage_map[i].uddMaskedVa) &&
		    l3_manage_map[i].udMapValid && (sid == l3_manage_map[i].udSteamIndex))
			break;
	}

	if (i == *used_l3_ttb_num) {
		if (*used_l3_ttb_num < SMMU_L3_PT_NUM)
			l3_nth_ttb_va = udd_l3_start_ttb_va + i * SMMU_L3_PER_PT_SIZE;
		else
			return 0;

		l3_manage_map[i].udMapValid = 1;
		l3_manage_map[i].udSteamIndex = sid;
		l3_manage_map[i].uddTTBaseAddr = l3_nth_ttb_va;
		l3_manage_map[i].uddMaskedVa = request_va & PAGE_MASK_2M;

		*used_l3_ttb_num += 1;
		pte_address->l3_pagetable_num = *used_l3_ttb_num;
	}

	return (l3_manage_map[i].uddTTBaseAddr + (u64)((request_va & level_mask) >> level_offset));
}

u64 zxdh_smmu_host_pa_to_l2d_pa(u64 host_pa, struct zxdh_sc_dev *dev)
{
	u64 udd_offset = 0;
	u64 udd_l2d_pa = 0;

	/* check param */
	if (!dev)
		return -EINVAL;
	if (!dev->pte_address)
		return -EINVAL;
	if (!dev->pte_address->cma_page_mem_base_pa)
		return -EINVAL;

	if (host_pa < dev->pte_address->cma_page_mem_base_pa)
		return -1;

	udd_offset = host_pa - dev->pte_address->cma_page_mem_base_pa;
	udd_l2d_pa = dev->pte_l2d_startpa + udd_offset;
	return udd_l2d_pa;
}

static u32 zxdh_smmu_write_l1_pagetable_entry(const u64 udd_l1_descriptor_va,
					      const struct smmu_pte_cfg *const mmu_pte_cfg,
					      struct zxdh_sc_dev *dev)
{
	u64 udd_l2d_pa = 0;
	u64 physical_address = 0;
	u64 l1_pte_offset = 0;
	u64 *l1_desc_vaddr = NULL;
	u64 *tmp_desc_vaddr = NULL;
	u64 udd_tmp_l1_descriptor_value = 0;
	u64 udd_l2d_tmp_l1_descriptor_value = 0;

	struct zxdh_src_copy_dest copy_dest = {};

	/* check param */
	if (!dev)
		return -EINVAL;
	if (!mmu_pte_cfg)
		return -EINVAL;

	if (mmu_pte_cfg->page_format != PAGE_FORMAT_V8)
		return -1;

	/* pte base address */
	l1_desc_vaddr = (u64 *)udd_l1_descriptor_va;
	*l1_desc_vaddr = 0;

	/* physical block base address or next level page table address */
	physical_address = mmu_pte_cfg->pa_base_addr;

	/* block descriptor */
	if (mmu_pte_cfg->page_type == SMMU_PAGETABLE_PAGESIZE_1G) {
		udd_tmp_l1_descriptor_value =
			((physical_address & L1_LONG_DESCRIPTOR_BLOCK_PA_MASK) |
			 ((mmu_pte_cfg->execute_never << L1_LONG_DESCRIPTOR_BLOCK_XN_POS) &
			  L1_LONG_DESCRIPTOR_BLOCK_XN_MASK) |
			 (((mmu_pte_cfg->access_permission) << L1_LONG_DESCRIPTOR_BLOCK_S2AP_POS) &
			  L1_LONG_DESCRIPTOR_BLOCK_S2AP_MASK) |
			 (((0x1) << L1_LONG_DESCRIPTOR_BLOCK_AF_POS) &
			  L1_LONG_DESCRIPTOR_BLOCK_AF_MASK) |
			 (((mmu_pte_cfg->shareable) << L1_LONG_DESCRIPTOR_BLOCK_SH1SH0_POS) &
			  L1_LONG_DESCRIPTOR_BLOCK_SH1SH0_MASK) |
			 (((mmu_pte_cfg->memory_attribute)
			   << L1_LONG_DESCRIPTOR_BLOCK_MEMATTR_POS) &
			  L1_LONG_DESCRIPTOR_BLOCK_MEMATTR_MASK) |
			 (L1_LONG_DESCRIPTOR_FOR_BLOCK) |
			 (((mmu_pte_cfg->read_allocate_cfg) << LONG_DESCRIPTOR_RACFG_POS) &
			  LONG_DESCRIPTOR_RACFG_MASK) |
			 (((mmu_pte_cfg->write_allocate_cfg) << LONG_DESCRIPTOR_WACFG_POS) &
			  LONG_DESCRIPTOR_WACFG_MASK));

		udd_l2d_tmp_l1_descriptor_value = udd_tmp_l1_descriptor_value;

	}
	/* page table */
	else if (mmu_pte_cfg->page_type == SMMU_PAGETABLE_PAGESIZE_2MB ||
		 mmu_pte_cfg->page_type == SMMU_PAGETABLE_PAGESIZE_4KB) {
		udd_tmp_l1_descriptor_value =
			((physical_address & L1_LONG_DESCRIPTOR_TABLE_PA_MASK) |
			 (L1_LONG_DESCRIPTOR_FOR_TABLE));

		udd_l2d_pa = zxdh_smmu_host_pa_to_l2d_pa(physical_address, dev);
		udd_l2d_tmp_l1_descriptor_value = ((udd_l2d_pa & L1_LONG_DESCRIPTOR_TABLE_PA_MASK) |
						   (L1_LONG_DESCRIPTOR_FOR_TABLE));
	}

	/* default little endian */
	if (mmu_pte_cfg->endian == SMMU_TT_BIGENDIAN) {
		udd_tmp_l1_descriptor_value = uswap_64(udd_tmp_l1_descriptor_value);
		udd_l2d_tmp_l1_descriptor_value = uswap_64(udd_l2d_tmp_l1_descriptor_value);
	}

	*l1_desc_vaddr = udd_tmp_l1_descriptor_value;

	memset((void *)dev->pte_address->pte_temp_vir_addr, 0, 8);
	tmp_desc_vaddr = (u64 *)dev->pte_address->pte_temp_vir_addr;
	*tmp_desc_vaddr = udd_l2d_tmp_l1_descriptor_value;

	l1_pte_offset = udd_l1_descriptor_va - dev->pte_address->cma_page_mem_base_va;

	/* cpy data from host to l2d */
	copy_dest.src = dev->pte_address->pte_temp_phy_addr;
	copy_dest.len = 8;
	copy_dest.dest = dev->pte_l2d_startpa + l1_pte_offset;

	dev->cqp->process_config_pte_table(dev, copy_dest);

	return 0;
}

static u32 zxdh_smmu_write_l2_pagetable_entry(u32 sid, const u64 l2_desc_va,
					      const struct smmu_pte_cfg *const mmu_pte_cfg,
					      struct zxdh_sc_dev *dev)
{
	u64 physical_address = 0;
	u64 l2_desc_value = 0;
	u64 l2d_l2_desc_offset = 0;
	u64 *pull_tmp_l2_descriptor_va = NULL;
	u64 *pull_to_l2d_descriptor_va = NULL;
	u64 udd_l2d_l2_descriptor_value = 0;

	static u64 dma_to_l2d_count;

	struct zxdh_src_copy_dest copy_dest = {};

	/* param check */
	if (!dev)
		return -EINVAL;
	if (!mmu_pte_cfg)
		return -EINVAL;
	if (!dev->pte_address->pte_temp_vir_addr)
		return -EINVAL;

	if (mmu_pte_cfg->page_format != PAGE_FORMAT_V8)
		return -1;

	/* page table base address */
	pull_tmp_l2_descriptor_va = (u64 *)l2_desc_va;
	*pull_tmp_l2_descriptor_va = 0;

	/* block base physical address, or next level page table base address */
	physical_address = mmu_pte_cfg->pa_base_addr;

	/* block descriptor */
	if (mmu_pte_cfg->page_type == SMMU_PAGETABLE_PAGESIZE_2MB) {
		l2_desc_value =
			((physical_address & L2_LONG_DESCRIPTOR_BLOCK_PA_MASK) |
			 ((mmu_pte_cfg->execute_never << L2_LONG_DESCRIPTOR_BLOCK_XN_POS) &
			  L2_LONG_DESCRIPTOR_BLOCK_XN_MASK) |
			 (((mmu_pte_cfg->access_permission) << L2_LONG_DESCRIPTOR_BLOCK_S2AP_POS) &
			  L2_LONG_DESCRIPTOR_BLOCK_S2AP_MASK) |
			 (((0x1) << L2_LONG_DESCRIPTOR_BLOCK_AF_POS) &
			  L2_LONG_DESCRIPTOR_BLOCK_AF_MASK) |
			 (((mmu_pte_cfg->shareable) << L2_LONG_DESCRIPTOR_BLOCK_SH1SH0_POS) &
			  L2_LONG_DESCRIPTOR_BLOCK_SH1SH0_MASK) |
			 (((mmu_pte_cfg->memory_attribute)
			   << L2_LONG_DESCRIPTOR_BLOCK_MEMATTR_POS) &
			  L2_LONG_DESCRIPTOR_BLOCK_MEMATTR_MASK) |
			 (L2_LONG_DESCRIPTOR_FOR_BLOCK) |
			 (((mmu_pte_cfg->read_allocate_cfg) << LONG_DESCRIPTOR_RACFG_POS) &
			  LONG_DESCRIPTOR_RACFG_MASK) |
			 (((mmu_pte_cfg->write_allocate_cfg) << LONG_DESCRIPTOR_WACFG_POS) &
			  LONG_DESCRIPTOR_WACFG_MASK));

		udd_l2d_l2_descriptor_value = l2_desc_value;
	}
	/* page table */
	else if (mmu_pte_cfg->page_type == SMMU_PAGETABLE_PAGESIZE_4KB) {
		l2_desc_value = ((physical_address & L2_LONG_DESCRIPTOR_TABLE_PA_MASK) |
				 (L2_LONG_DESCRIPTOR_FOR_TABLE));

		udd_l2d_l2_descriptor_value = (

			(physical_address & 0x3FFFFFFFFF) // bit[37:0]
			| ((sid & 0xFULL) << 42) // bit[46:42]
			| (1ULL << 47) // bit[51:47]
			| (L2_LONG_DESCRIPTOR_FOR_TABLE));
	}

	/* default little endian */
	if (mmu_pte_cfg->endian == SMMU_TT_BIGENDIAN) {
		l2_desc_value = uswap_64(l2_desc_value);
		udd_l2d_l2_descriptor_value = uswap_64(udd_l2d_l2_descriptor_value);
	}

	*pull_tmp_l2_descriptor_va = l2_desc_value;

	memset((void *)dev->pte_address->pte_temp_vir_addr, 0, 8);
	pull_to_l2d_descriptor_va = (u64 *)dev->pte_address->pte_temp_vir_addr;
	*pull_to_l2d_descriptor_va = udd_l2d_l2_descriptor_value;

	dma_to_l2d_count++;

	// =======================================================================

	// =======================================================================
	l2d_l2_desc_offset = l2_desc_va - dev->pte_address->cma_page_mem_base_va;

	/* cpy data from host to l2d */
	copy_dest.src = dev->pte_address->pte_temp_phy_addr;
	copy_dest.len = 8;
	copy_dest.dest = dev->pte_l2d_startpa + l2d_l2_desc_offset;
	dev->cqp->process_config_pte_table(dev, copy_dest);

	return 0;
}

static u32 zxdh_smmu_write_l3_pagetable_entry(const u64 l3_desc_va,
					      const struct smmu_pte_cfg *const mmu_pte_cfg,
					      struct smmu_pte_address *pte_address)
{
	u64 physical_address = 0;
	u64 *l3_desc_vaddr = NULL;
	u64 udd_tmp_l3_descriptor_value = 0;

	/* param check */
	if (!pte_address)
		return -EINVAL;
	if (!mmu_pte_cfg)
		return -EINVAL;

	if (mmu_pte_cfg->page_format != PAGE_FORMAT_V8)
		return -1;

	/* pte address */
	l3_desc_vaddr = (u64 *)l3_desc_va;
	*l3_desc_vaddr = 0;

	physical_address = mmu_pte_cfg->pa_base_addr;

	if (mmu_pte_cfg->page_type == SMMU_PAGETABLE_PAGESIZE_4KB) {
		udd_tmp_l3_descriptor_value =
			((physical_address & L3_LONG_DESCRIPTOR_BLOCK_PA_MASK) |
			 ((mmu_pte_cfg->execute_never << L3_LONG_DESCRIPTOR_BLOCK_XN_POS) &
			  L3_LONG_DESCRIPTOR_BLOCK_XN_MASK) |
			 (((mmu_pte_cfg->access_permission) << L3_LONG_DESCRIPTOR_BLOCK_S2AP_POS) &
			  L3_LONG_DESCRIPTOR_BLOCK_S2AP_MASK) |
			 (((0x1) << L3_LONG_DESCRIPTOR_BLOCK_AF_POS) &
			  L3_LONG_DESCRIPTOR_BLOCK_AF_MASK) |
			 (((mmu_pte_cfg->shareable) << L3_LONG_DESCRIPTOR_BLOCK_SH1SH0_POS) &
			  L3_LONG_DESCRIPTOR_BLOCK_SH1SH0_MASK) |
			 (((mmu_pte_cfg->memory_attribute)
			   << L3_LONG_DESCRIPTOR_BLOCK_MEMATTR_POS) &
			  L3_LONG_DESCRIPTOR_BLOCK_MEMATTR_MASK) |
			 (L3_LONG_DESCRIPTOR_FOR_PAGE) |
			 (((mmu_pte_cfg->read_allocate_cfg) << LONG_DESCRIPTOR_RACFG_POS) &
			  LONG_DESCRIPTOR_RACFG_MASK) |
			 (((mmu_pte_cfg->write_allocate_cfg) << LONG_DESCRIPTOR_WACFG_POS) &
			  LONG_DESCRIPTOR_WACFG_MASK));
	}

	/* default little endian */
	if (mmu_pte_cfg->endian == SMMU_TT_BIGENDIAN)
		udd_tmp_l3_descriptor_value = uswap_64(udd_tmp_l3_descriptor_value);

	*l3_desc_vaddr = udd_tmp_l3_descriptor_value;

	return 0;
}

static u32 zxdh_smmu_set_l1_pte_entry(u64 udd_l1_descriptor_va, struct smmu_pte_cfg *tlb_entry_cfg,
				      struct zxdh_sc_dev *dev)
{
	if (!dev)
		return -EINVAL;
	if (!tlb_entry_cfg)
		return -EINVAL;

	zxdh_smmu_write_l1_pagetable_entry(udd_l1_descriptor_va, tlb_entry_cfg, dev);

	return 0;
}

static u32 zxdh_smmu_set_l2_pte_entry(u64 udd_l1_descriptor_va, u64 l2_desc_va, u32 sid,
				      struct smmu_pte_cfg *tlb_entry_cfg, struct zxdh_sc_dev *dev)
{
	if (!tlb_entry_cfg)
		return -EINVAL;

	/* write L2 block descriptor */
	zxdh_smmu_write_l2_pagetable_entry(sid, l2_desc_va, tlb_entry_cfg, dev);

	/* create Level1 page table config struct, get L2 pagetable base phyaddr */
	tlb_entry_cfg->pa_base_addr = zxdh_smmu_sram_pagetable_v2p(l2_desc_va, dev->pte_address);
	if (tlb_entry_cfg->pa_base_addr == 0)
		return -1;

	/* write L1 page table entry */
	zxdh_smmu_write_l1_pagetable_entry(udd_l1_descriptor_va, tlb_entry_cfg, dev);

	return 0;
}

static u32 zxdh_smmu_set_l3_pte_entry(u64 udd_l1_descriptor_va, u64 l2_desc_va, u64 l3_desc_va,
				      u64 sid, u64 request_va, struct smmu_pte_cfg *tlb_entry_cfg,
				      struct zxdh_sc_dev *dev)
{
	if (!dev)
		return -EINVAL;
	if (!tlb_entry_cfg)
		return -EINVAL;

	/* write L3 page table descriptor */
	zxdh_smmu_write_l3_pagetable_entry(l3_desc_va, tlb_entry_cfg, dev->pte_address);

	/* structure L2 page table descriptor config */
	tlb_entry_cfg->pa_base_addr = zxdh_smmu_sram_pagetable_v2p(l3_desc_va, dev->pte_address);

	/* write L2 page table descriptor */

	zxdh_smmu_write_l2_pagetable_entry(sid, l2_desc_va, tlb_entry_cfg, dev);

	/* structure L1 page table descriptor config */
	tlb_entry_cfg->pa_base_addr = zxdh_smmu_sram_pagetable_v2p(l2_desc_va, dev->pte_address);

	/* write L1 page table descriptor */
	zxdh_smmu_write_l1_pagetable_entry(udd_l1_descriptor_va, tlb_entry_cfg, dev);

	return 0;
}

static u32 zxdh_smmu_set_pte_entry(u64 udd_l1_ttb_va, u64 request_va, u64 request_pa, u32 sid,
				   struct smmu_pte_cfg *tlb_entry_cfg, struct zxdh_sc_dev *dev)
{
	u64 udd_l1_descriptor_va = 0;
	u64 l2_desc_va = 0;
	u64 l3_desc_va = 0;

	if (!dev)
		return -EINVAL;
	if (!tlb_entry_cfg)
		return -EINVAL;

	if (dev->pte_address->pagetable_vir_base_addr == 0) {
		pr_info("dev->pte_address->pagetable_vir_base_addr == 0\n");
		return -1;
	}

	switch (tlb_entry_cfg->page_type) {
	case SMMU_PAGETABLE_PAGESIZE_4KB: {
		l3_desc_va = zxdh_smmu_get_l3_descriptor(sid, request_va, dev->pte_address);
		l2_desc_va = zxdh_smmu_get_l2_descriptor_va(dev, sid, request_va, dev->pte_address);
		udd_l1_descriptor_va = zxdh_smmu_get_l1_descriptor_va(udd_l1_ttb_va, request_va);

		if (!l3_desc_va || !l2_desc_va || !udd_l1_descriptor_va) {
			pr_info("l3_desc_va|l2_desc_va|udd_l1_descriptor_va == 0\n");
			return -1;
		}

		zxdh_smmu_set_l3_pte_entry(udd_l1_descriptor_va, l2_desc_va, l3_desc_va, sid,
					   request_va, tlb_entry_cfg, dev);
		break;
	}
	case SMMU_PAGETABLE_PAGESIZE_2MB: {
		l3_desc_va = 0;
		l2_desc_va = zxdh_smmu_get_l2_descriptor_va(dev, sid, request_va, dev->pte_address);
		udd_l1_descriptor_va = zxdh_smmu_get_l1_descriptor_va(udd_l1_ttb_va, request_va);

		if (!l2_desc_va || !udd_l1_descriptor_va) {
			pr_info("l2_desc_va|udd_l1_descriptor_va == 0\n");
			return -1;
		}

		zxdh_smmu_set_l2_pte_entry(udd_l1_descriptor_va, l2_desc_va, sid, tlb_entry_cfg,
					   dev);
		break;
	}
	case SMMU_PAGETABLE_PAGESIZE_1G: {
		l3_desc_va = 0;
		l2_desc_va = 0;
		udd_l1_descriptor_va = zxdh_smmu_get_l1_descriptor_va(udd_l1_ttb_va, request_va);

		if (!udd_l1_descriptor_va) {
			pr_info("udd_l1_descriptor_va == 0\n");
			return -1;
		}

		zxdh_smmu_set_l1_pte_entry(udd_l1_descriptor_va, tlb_entry_cfg, dev);
		break;
	}
	default: {
		return -1;
	}
	}

	return 0;
}

u32 zxdh_smmu_show_pagetable_info(struct smmu_pte_address *pte_address)
{
	pr_info("pagetable info: ---------------------\n");
	pr_info("pagetable config.pagetable_phy_addr  = 0x%llx\n",
		pte_address->pagetable_cfg.pagetable_phy_addr);
	pr_info("pagetable config.pagetable_vir_addr  = 0x%llx\n",
		pte_address->pagetable_cfg.pagetable_vir_addr);
	pr_info("pagetable config.pagetable_size  = 0x%x\n",
		pte_address->pagetable_cfg.pagetable_size);
	pr_info("pagetable config.ex_pagetable_phy_addr  = 0x%llx\n",
		pte_address->pagetable_cfg.ex_pagetable_phy_addr);
	pr_info("pagetable config.ex_pagetable_size  = 0x%x\n",
		pte_address->pagetable_cfg.ex_pagetable_size);
	pr_info("max L1 pagetable num = %d, used = %d\n", SMMU_L1_PT_NUM,
		pte_address->l1_pagetable_num);
	pr_info("max L2 pagetable num = %d, used = %d\n", SMMU_L2_PT_NUM,
		pte_address->l2_pagetable_num);
	pr_info("max L3 pagetable num = %d, used = %d\n", SMMU_L3_PT_NUM,
		pte_address->l3_pagetable_num);
	pr_info("pte records num = %d, fail record = %d, max capacity = %d\n",
		pte_address->pte_record_num, pte_address->pte_fail_record_num, MAX_PTE_RECORDS_NUM);

	return 0;
}
EXPORT_SYMBOL(zxdh_smmu_show_pagetable_info);

u32 zxdh_smmu_show_pte_record(u32 stream_id, u64 virt_addr, struct smmu_pte_address *pte_address)
{
	u32 i = 0;
	u64 virt_addr_tmp;
	u64 ttb_addr;

	for (; i < pte_address->pte_record_num; i++) {
		if (pte_address->pte_records[i].valid) {
			// print all records
			if (virt_addr == 0xffffffffffffffff) {
				virt_addr_tmp = pte_address->pte_records[i].virt_addr;
			} else if (virt_addr >= pte_address->pte_records[i].virt_addr &&
				   virt_addr < (pte_address->pte_records[i].virt_addr +
						pte_address->pte_records[i].size)) {
				virt_addr_tmp = virt_addr;
			} else {
				continue;
			}

			ttb_addr = zxdh_smmu_get_ttb(stream_id, pte_address);
			if (ttb_addr == -1 || ttb_addr == 0)
				return -1;

			if (pte_address->pte_records[i].size == PAGE_SIZE_4K)
				zxdh_smmu_get_l3_descriptor(stream_id, virt_addr_tmp, pte_address);
		}
	}
	return 0;
}
EXPORT_SYMBOL(zxdh_smmu_show_pte_record);

struct zxdh_smmu_host_risc_msgs {
	u32 sid;
	u32 va;
};

u32 zxdh_smmu_mmap(struct smmu_pte_request *pte_request, struct zxdh_sc_dev *dev)
{
	u32 ret = 0;
	u32 pte_size = 0;
	u64 l1_ttb_pa = 0;
	u64 request_va = 0;
	u64 request_pa = 0;
	u64 request_size = 0;
	struct smmu_pte_cfg tlb_entry_cfg = { 0 };
	u32 mmap_count = 0;

	if (!dev)
		return -EINVAL;
	if (!pte_request)
		return -EINVAL;

	request_va = pte_request->vir_addr;
	request_pa = pte_request->phy_addr;
	request_size = pte_request->size;

	if ((request_pa & REV_PAGE_MASK_4K) || (request_va & REV_PAGE_MASK_4K) ||
	    (request_size & REV_PAGE_MASK_4K)) {
		return -1;
	}

	tlb_entry_cfg.endian = SMMU_TT_LITTLEENDIAN; /* endian cfg */
	tlb_entry_cfg.page_format = PAGE_FORMAT_V8;

	/* pa */
	l1_ttb_pa = zxdh_smmu_get_ttb(pte_request->stream_id, dev->pte_address);
	if (l1_ttb_pa == -1)
		return -1;

	while (request_size > 0) {
		mmap_count++;

		// if (10 == mmap_count)
		// {
		//     g_ucMmu600PrintModuleId = 8;
		// }

		// 1G 2M 4k
		pte_size = PAGE_SIZE_4K; // Default to 4K
		zxdh_smmu_get_pte_size(request_va, request_size, &pte_size);

		// pte_size = PAGE_SIZE_4K;

		zxdh_smmu_request_to_pte_cfg(pte_size, pte_request, &tlb_entry_cfg);

		ret = zxdh_smmu_set_pte_entry(
			zxdh_smmu_sram_pagetable_p2v(l1_ttb_pa, dev->pte_address), request_va,
			request_pa, pte_request->stream_id, &tlb_entry_cfg, dev);

		if (ret != 0)
			return -1;

		request_va += pte_size;
		request_pa += pte_size;
		pte_request->phy_addr = request_pa;
		if (request_size < pte_size) {
			/* avoid negative value */
			request_size = 0;
		} else {
			request_size -= pte_size;
		}
	}
#ifndef BSP_IS_PC_UT
	/* Write barrier: Ensures all PTE entries are written completely,*/
	wmb();
#endif

	return 0;
}
EXPORT_SYMBOL(zxdh_smmu_mmap);

u32 zxdh_smmu_struct_init(const struct smmu_pagetable_param *pgt_param,
			  struct smmu_pte_address *pte_address, struct device *dma_dev)
{
	void *vaddr = NULL;
	u32 size = 0;
	u32 l1_pt_index = 0;
	u32 page_table_size = 0;

	if (!pgt_param)
		return -EINVAL;
	if (!pte_address)
		return -EINVAL;

	if (pgt_param->pagetable_size == 0 || pgt_param->l1_pagetable_num == 0 ||
	    pgt_param->l2_pagetable_num == 0 || pgt_param->l3_pagetable_num == 0)
		return -1;

	page_table_size = pgt_param->l1_pagetable_num * SMMU_L1_PER_PT_SIZE +
			  pgt_param->l2_pagetable_num * SMMU_L2_PER_PT_SIZE +
			  pgt_param->l3_pagetable_num * SMMU_L3_PER_PT_SIZE;
	if (page_table_size > pgt_param->pagetable_size)
		return -1;

	memcpy(&(pte_address->pagetable_cfg), pgt_param, sizeof(struct smmu_pagetable_param));

	if (pte_address->cma_page_mem_base_va == 0) {
		if (!pgt_param->pagetable_phy_addr)
			return -EINVAL;

		vaddr = (void *)ioremap(pgt_param->pagetable_phy_addr, pgt_param->pagetable_size);

		memset_8byte(vaddr, 0, pgt_param->pagetable_size);

		pte_address->pagetable_vir_base_addr = (u64)vaddr;
	} else {
		if (pgt_param->pagetable_phy_addr & (SMMU_L1_PT_ALIGN_SIZE - 1))
			return -1;

		pte_address->pagetable_vir_base_addr = pte_address->cma_page_mem_base_va;
	}

	size = SMMU_L2_MAP_MANAGE_SIZE + SMMU_L3_MAP_MANAGE_SIZE;
	pte_address->map_manage_addr = (u64)kmalloc(size, GFP_KERNEL);
	if (!pte_address->map_manage_addr)
		return -EINVAL;
	MEMSET((void *)pte_address->map_manage_addr, size, 0, size);

	size = sizeof(struct smmu_pte_record) * MAX_PTE_RECORDS_NUM;
	pte_address->pte_records = kmalloc(size, GFP_KERNEL);
	if (!pte_address->pte_records)
		return -EINVAL;
	MEMSET(pte_address->pte_records, size, 0, size);
	pte_address->pte_temp_vir_addr = (u64)dma_alloc_coherent(
		dma_dev, SMMU_L1_PER_PT_SIZE * 4, &pte_address->pte_temp_phy_addr, GFP_KERNEL);
	if (!pte_address->pte_temp_vir_addr)
		return -EINVAL;
	MEMSET((void *)pte_address->pte_temp_vir_addr, SMMU_L1_PER_PT_SIZE * 4, 0,
	       SMMU_L1_PER_PT_SIZE * 4);

	size = sizeof(struct smmu_ttb_manage) * SMMU_L1_PT_NUM;
	g_ptTtbMng = kmalloc(size, GFP_KERNEL);
	if (!g_ptTtbMng)
		return -EINVAL;
	MEMSET(g_ptTtbMng, size, 0, size);

	for (l1_pt_index = 0; l1_pt_index < SMMU_L1_PT_NUM; l1_pt_index++) {
		g_ptTtbMng[l1_pt_index].phy_ttb = (pte_address->pagetable_cfg.pagetable_phy_addr +
						   l1_pt_index * SMMU_L1_PER_PT_SIZE);
	}

	return 0;
}
