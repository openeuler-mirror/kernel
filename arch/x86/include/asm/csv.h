/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hygon China Secure Virtualization (CSV)
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 *
 * Author: Jiang Xin <jiangxin@hygon.cn>
 */

#ifndef __ASM_X86_CSV_H__
#define __ASM_X86_CSV_H__

#include <linux/numa.h>

#ifndef __ASSEMBLY__

#ifdef CONFIG_HYGON_CSV

struct csv_mem {
	uint64_t start;
	uint64_t size;
};

#define CSV_MR_ALIGN_BITS		(28)

extern struct csv_mem *csv_smr;
extern unsigned int csv_smr_num;
#ifdef CONFIG_SYSFS
extern atomic_long_t csv3_npt_size;
extern atomic_long_t csv3_pri_mem;
extern unsigned long csv3_meta;
extern atomic_long_t csv3_shared_mem[MAX_NUMNODES];
#endif	/* CONFIG_SYSFS */

void __init early_csv_reserve_mem(void);

phys_addr_t csv_alloc_from_contiguous(size_t size, nodemask_t *nodes_allowed,
				      unsigned int align);
void csv_release_to_contiguous(phys_addr_t pa, size_t size);

uint32_t csv_get_smr_entry_shift(void);

void __init early_csv_guest_mem_init(void);
phys_addr_t csv3_alloc_mem_block(void);
void csv3_free_mem_block(phys_addr_t phys_addr);
size_t csv3_get_mem_block_size(void);

#else	/* !CONFIG_HYGON_CSV */

#define csv_smr		NULL
#define csv_smr_num	0U

static inline void __init early_csv_reserve_mem(void) { }

static inline phys_addr_t
csv_alloc_from_contiguous(size_t size, nodemask_t *nodes_allowed,
			  unsigned int align) { return 0; }
static inline void csv_release_to_contiguous(phys_addr_t pa, size_t size) { }

static inline uint32_t csv_get_smr_entry_shift(void) { return 0; }

#endif	/* CONFIG_HYGON_CSV */

#define CPUID_VENDOR_HygonGenuine_ebx	0x6f677948
#define CPUID_VENDOR_HygonGenuine_ecx	0x656e6975
#define CPUID_VENDOR_HygonGenuine_edx	0x6e65476e

#define MSR_CSV3_ENABLED_BIT		30
#define MSR_CSV3_ENABLED		BIT_ULL(MSR_CSV3_ENABLED_BIT)

#ifdef CONFIG_HYGON_CSV

bool csv3_active(void);

void __init csv_early_reset_memory(struct boot_params *bp);
void __init csv_early_update_memory_enc(u64 vaddr, u64 pages);
void __init csv_early_update_memory_dec(u64 vaddr, u64 pages);

void __init csv_early_memory_enc_dec(u64 vaddr, u64 size, bool enc);

void csv_memory_enc_dec(u64 vaddr, u64 pages, bool enc);
int csv3_issue_request_report(phys_addr_t paddr, size_t size);
int csv3_issue_request_rtmr(void *req_buffer, size_t buffer_size);

#else	/* !CONFIG_HYGON_CSV */

static inline bool csv3_active(void) { return false; }

static inline void __init csv_early_reset_memory(struct boot_params *bp) { }
static inline void __init csv_early_update_memory_enc(u64 vaddr, u64 pages) { }
static inline void __init csv_early_update_memory_dec(u64 vaddr, u64 pages) { }

static inline void __init csv_early_memory_enc_dec(u64 vaddr, u64 size,
						   bool enc) { }

static inline void csv_memory_enc_dec(u64 vaddr, u64 pages, bool enc) { }
static inline int csv3_issue_request_report(phys_addr_t paddr, size_t size) { return -EIO; }
static inline int csv3_issue_request_rtmr(void *req_buffer, size_t buffer_size) { return -ENODEV; }

static inline void __init early_csv_guest_mem_init(void) { }
static inline phys_addr_t csv3_alloc_mem_block(void) { return 0; }
static inline void csv3_free_mem_block(phys_addr_t phys_addr) { }
static inline size_t csv3_get_mem_block_size(void) { return 0; }
#endif	/* CONFIG_HYGON_CSV */

#endif	/* __ASSEMBLY__ */

#endif	/* __ASM_X86_CSV_H__ */
