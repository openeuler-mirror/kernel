/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ARM64_MM_INTERNAL_H
#define __ARM64_MM_INTERNAL_H

#include <linux/types.h>

#ifdef CONFIG_ARM64_PMEM_RESERVE
void __init setup_reserve_pmem(u64 start, u64 size);
void __init reserve_pmem(void);
void __init request_pmem_res_resource(void);
#else
static inline void __init setup_reserve_pmem(u64 start, u64 size) {}
static inline void __init reserve_pmem(void) {}
static inline void __init request_pmem_res_resource(void) {}
#endif
#ifdef CONFIG_QUICK_KEXEC
void __init reserve_quick_kexec(void);
void __init request_quick_kexec_res(struct resource *res);
#else
static inline void __init reserve_quick_kexec(void) {}
static inline void __init request_quick_kexec_res(struct resource *res) {}
#endif

#define MAX_RES_REGIONS 32
extern struct memblock_region mbk_memmap_regions[MAX_RES_REGIONS];
extern int mbk_memmap_cnt;

#endif /* ifndef _ARM64_MM_INTERNAL_H */
