// SPDX-License-Identifier: GPL-2.0
/*
* Copyright (C) 2020-2022 Loongson Technology Corporation Limited
*
* Derived from MIPS:
* Copyright (C) 1994 - 2003, 06, 07 by Ralf Baechle (ralf@linux-mips.org)
* Copyright (C) 2007 MIPS Technologies, Inc.
*/
#include <linux/export.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/cacheinfo.h>

#include <asm/cpu.h>
#include <asm/bootinfo.h>
#include <asm/cpu-features.h>
#include <asm/dma.h>
#include <asm/loongarch.h>
#include <asm/processor.h>
#include <asm/setup.h>
extern struct loongson_system_configuration loongson_sysconf;
void cache_error_setup(void)
{
	extern char __weak except_vec_cex;
	set_merr_handler(0x0, &except_vec_cex, 0x80);
}

/* Cache operations. */
void local_flush_icache_range(unsigned long start, unsigned long end)
{
	asm volatile ("\tibar 0\n"::);
}

static inline void __flush_cache_line_hit(int leaf, unsigned long addr)
{
	switch (leaf) {
	case Cache_LEAF0:
		cache_op(Hit_Writeback_Inv_LEAF0, addr);
		break;
	case Cache_LEAF1:
		cache_op(Hit_Writeback_Inv_LEAF1, addr);
		break;
	case Cache_LEAF2:
		cache_op(Hit_Writeback_Inv_LEAF2, addr);
		break;
	case Cache_LEAF3:
		cache_op(Hit_Writeback_Inv_LEAF3, addr);
		break;
	case Cache_LEAF4:
		cache_op(Hit_Writeback_Inv_LEAF4, addr);
		break;
	case Cache_LEAF5:
		cache_op(Hit_Writeback_Inv_LEAF5, addr);
		break;
	default:
		break;
	}
}

static inline void __flush_cache_line_indexed(int leaf, unsigned long addr)
{
	switch (leaf) {
	case Cache_LEAF0:
		cache_op(Index_Writeback_Inv_LEAF0, addr);
		break;
	case Cache_LEAF1:
		cache_op(Index_Writeback_Inv_LEAF1, addr);
		break;
	case Cache_LEAF2:
		cache_op(Index_Writeback_Inv_LEAF2, addr);
		break;
	case Cache_LEAF3:
		cache_op(Index_Writeback_Inv_LEAF3, addr);
		break;
	case Cache_LEAF4:
		cache_op(Index_Writeback_Inv_LEAF4, addr);
		break;
	case Cache_LEAF5:
		cache_op(Index_Writeback_Inv_LEAF5, addr);
		break;
	default:
		break;
	}
}

void flush_cache_line_hit(unsigned long addr)
{
	int leaf;
	struct cache_desc *cdesc = current_cpu_data.cache_leaves;
	unsigned int cache_present = current_cpu_data.cache_leaves_present;

	/* If last level cache is inclusive, no need to flush other caches. */
	leaf = cache_present - 1;
	if (cache_inclusive(cdesc + leaf)) {
		__flush_cache_line_hit(leaf, addr);
		return;
	}

	for (leaf = 0; leaf < cache_present; leaf++)
		__flush_cache_line_hit(leaf, addr);
}

static void flush_cache_leaf(unsigned int leaf)
{
	u64 line;
	int i, j, nr_nodes;
	struct cache_desc *cdesc = current_cpu_data.cache_leaves + leaf;

	nr_nodes = loongson_sysconf.nr_nodes;
	if (cache_private(cdesc))
		nr_nodes = 1;

	line = CSR_DMW0_BASE;
	do {
		for (i = 0; i < cdesc->sets; i++) {
			for (j = 0; j < cdesc->ways; j++) {
				__flush_cache_line_indexed(leaf, line);
				line++;
			}

			line -= cdesc->ways;
			line += cdesc->linesz;
		}
		line += 0x100000000000;
	} while (--nr_nodes > 0);
}

asmlinkage __visible void cpu_flush_caches(void)
{
	int leaf;
	struct cache_desc *cdesc = current_cpu_data.cache_leaves;
	unsigned int cache_present = current_cpu_data.cache_leaves_present;

	/* If last level cache is inclusive, no need to flush other caches. */
	leaf = cache_present - 1;
	if (cache_inclusive(cdesc + leaf)) {
		flush_cache_leaf(leaf);
		return;
	}

	for (leaf = 0; leaf < cache_present; leaf++)
		flush_cache_leaf(leaf);
}

static inline void set_cache_basics(struct cache_desc *cdesc, unsigned int leaf)
{
	unsigned int config;

	config = read_cpucfg(LOONGARCH_CPUCFG17 + leaf);
	cdesc->linesz = 1 << ((config & CACHE_LSIZE_M) >> CACHE_LSIZE);
	cdesc->sets  = 1 << ((config & CACHE_SETS_M) >> CACHE_SETS);
	cdesc->ways  = ((config & CACHE_WAYS_M) >> CACHE_WAYS) + 1;
}

#define populate_cache_properties(conifg, cdesc, level, leaf)	\
{								\
	if (level == 1)	{					\
		cdesc->flags |= CACHE_PRIVATE;			\
	} else {						\
		if (config & IUPRIV)				\
			cdesc->flags |= CACHE_PRIVATE;		\
		if (config & IUINCL)				\
			cdesc->flags |= CACHE_INCLUSIVE;	\
	}							\
	cdesc->flags |= CACHE_PRESENT;				\
	cdesc->level = level;					\
	set_cache_basics(cdesc, leaf);				\
	cdesc++;						\
	leaf++;							\
}

/*
* Each level cache occupies 7bits in order in CPUCFG16
* except level 1 cache with bit0~2.
*
*/
static void probe_cache_hierarchy(void)
{
	struct cache_desc *cdesc = current_cpu_data.cache_leaves;
	unsigned int leaf = 0, level;
	unsigned int config = read_cpucfg(LOONGARCH_CPUCFG16);

#define IUPRE	(1 << 0)
#define IUUNIFY	(1 << 1)
#define IUPRIV	(1 << 2)
#define IUINCL	(1 << 3)
#define DPRE	(1 << 4)
#define DPRIV	(1 << 5)
#define DINCL	(1 << 6)

#define L1DPRE	(1 << 2)

	for (level = 1; level <= CACHE_LEVEL_MAX; level++) {
		if (config & IUPRE) {
			if (config & IUUNIFY)
				cdesc->type = CACHE_TYPE_UNIFIED;
			else
				cdesc->type = CACHE_TYPE_INST;

			populate_cache_properties(config, cdesc, level, leaf);
		}

		if ((level == 1 && (config & L1DPRE)) ||
				(level != 1 && (config & DPRE))) {
			cdesc->type = CACHE_TYPE_DATA;

			populate_cache_properties(config, cdesc, level, leaf);
		}

		if (level == 1)
			config = config >> 3;
		else
			config = config >> 7;

		if (!config)
			break;

	}

	if (leaf > 0)
		current_cpu_data.options |= LOONGARCH_CPU_PREFETCH;

	BUG_ON(leaf > CACHE_LEAVES_MAX);

	current_cpu_data.cache_leaves_present = leaf;
}

void cpu_cache_init(void)
{
	probe_cache_hierarchy();

	shm_align_mask = PAGE_SIZE - 1;
}
