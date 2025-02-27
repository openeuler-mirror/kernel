/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_NUMA_REPLICATION_H
#define _LINUX_NUMA_REPLICATION_H

#ifdef CONFIG_KERNEL_REPLICATION

#include <linux/kabi.h>

/*
 * Why? Because linux is defined to 1 for some reason,
 * and linux/mm.h converted to 1/mm.h. Perhaps compiler?
 * Do not ask me, I have no idea.
 */
#if defined(linux)
#define tmp_linux_value linux
#undef linux
#endif

#include KABI_HIDE_INCLUDE(<linux/mm_types.h>)
#include KABI_HIDE_INCLUDE(<linux/nodemask.h>)
#include KABI_HIDE_INCLUDE(<linux/module.h>)
#include KABI_HIDE_INCLUDE(<linux/mm.h>)
#include KABI_HIDE_INCLUDE(<asm/numa_replication.h>)

#if defined(tmp_linux_value)
#define linux tmp_linux_value
#undef tmp_linux_value
#endif

typedef enum {
	NONE = 0,
	PMD_PROPAGATION = 1,
	PUD_PROPAGATION = 2,
	P4D_PROPAGATION = 3,
	PGD_PROPAGATION = 4
} propagation_level_t;

extern nodemask_t replica_nodes;

#define for_each_memory_node(nid)			\
	for (nid = first_node(replica_nodes);		\
	     nid != MAX_NUMNODES;			\
	     nid = next_node(nid, replica_nodes))

#define this_node_pgd(mm) ((mm)->pgd_numa[numa_node_id()])
#define per_node_pgd(mm, nid) ((mm)->pgd_numa[nid])

static inline bool numa_addr_has_replica(const void *addr)
{
	return ((unsigned long)addr >= PAGE_TABLE_REPLICATION_LEFT) &&
		((unsigned long)addr <= PAGE_TABLE_REPLICATION_RIGHT);
}

void __init numa_replication_init(void);
void __init numa_replicate_kernel_text(void);
void numa_replicate_kernel_rodata(void);
void numa_replication_fini(void);

bool is_text_replicated(void);
propagation_level_t get_propagation_level(void);
void numa_setup_pgd(void);
void __init_or_module *numa_get_replica(void *vaddr, int nid);
int numa_get_memory_node(int nid);
void dump_mm_pgtables(struct mm_struct *mm,
		      unsigned long start, unsigned long end);

/* Macro to walk over mm->pgd_numa and cast it to appropriate level type */
#define for_each_pgtable_replica(table, mm, replica, nid, offset)				\
	for (nid = first_node(replica_nodes), offset = ((unsigned long)table) & (~PAGE_MASK),	\
	     replica = (typeof(table))(((unsigned long)mm->pgd_numa[nid]) + offset);		\
	     nid != MAX_NUMNODES;								\
	     nid = next_node(nid, replica_nodes),						\
	     replica = (typeof(table))(((unsigned long)mm->pgd_numa[nid]) + offset))

static inline void pgd_populate_replicated(struct mm_struct *mm, pgd_t *pgdp, p4d_t *p4dp)
{
	int nid;
	pgd_t *curr_pgd;
	unsigned long offset;

	if (get_propagation_level() == PGD_PROPAGATION) {
		for_each_pgtable_replica(pgdp, mm, curr_pgd, nid, offset) {
			pgd_populate(mm, curr_pgd, p4dp);
		}
	} else {
		pgd_populate(mm, pgdp, p4dp);
	}
}

static inline void p4d_populate_replicated(struct mm_struct *mm, p4d_t *p4dp, pud_t *pudp)
{
	int nid;
	p4d_t *curr_p4d;
	unsigned long offset;

	if (get_propagation_level() == P4D_PROPAGATION) {
		for_each_pgtable_replica(p4dp, mm, curr_p4d, nid, offset) {
			p4d_populate(mm, curr_p4d, pudp);
		}
	} else {
		p4d_populate(mm, p4dp, pudp);
	}
}

static inline void pud_populate_replicated(struct mm_struct *mm, pud_t *pudp, pmd_t *pmdp)
{
	int nid;
	pud_t *curr_pud;
	unsigned long offset;

	if (get_propagation_level() == PUD_PROPAGATION) {
		for_each_pgtable_replica(pudp, mm, curr_pud, nid, offset) {
			pud_populate(mm, curr_pud, pmdp);
		}
	} else {
		pud_populate(mm, pudp, pmdp);
	}
}

static inline void pmd_populate_replicated(struct mm_struct *mm, pmd_t *pmdp, pgtable_t ptep)
{
	int nid;
	pmd_t *curr_pmd;
	unsigned long offset;

	if (get_propagation_level() == PMD_PROPAGATION) {
		for_each_pgtable_replica(pmdp, mm, curr_pmd, nid, offset) {
			pmd_populate(mm, curr_pmd, ptep);
		}
	} else {
		pmd_populate(mm, pmdp, ptep);
	}
}

#else

#if defined(linux)
#define tmp_linux_value linux
#undef linux
#endif

#include KABI_HIDE_INCLUDE(<linux/mm.h>)

#if defined(tmp_linux_value)
#define linux tmp_linux_value
#undef tmp_linux_value
#endif

#define this_node_pgd(mm) ((mm)->pgd)
#define per_node_pgd(mm, nid) ((mm)->pgd)

static inline void numa_setup_pgd(void)
{
}

static inline void __init numa_replication_init(void)
{
}

static inline void __init numa_replicate_kernel_text(void)
{
}

static inline void numa_replicate_kernel_rodata(void)
{
}

static inline void numa_replication_fini(void)
{
}

static inline bool numa_addr_has_replica(const void *addr)
{
	return false;
}

static inline bool is_text_replicated(void)
{
	return false;
}

static inline void *numa_get_replica(void *vaddr, int nid)
{
	return lm_alias(vaddr);
}

static inline void dump_mm_pgtables(struct mm_struct *mm,
				    unsigned long start, unsigned long end)
{
}

#define pgd_populate_replicated pgd_populate
#define p4d_populate_replicated p4d_populate
#define pud_populate_replicated pud_populate
#define pmd_populate_replicated pmd_populate

#endif /*CONFIG_KERNEL_REPLICATION*/
#endif /*_LINUX_NUMA_REPLICATION_H*/
