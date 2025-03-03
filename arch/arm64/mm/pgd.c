// SPDX-License-Identifier: GPL-2.0-only
/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/numa_kernel_replication.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

static struct kmem_cache *pgd_cache __ro_after_init;

static pgd_t *pgd_alloc_orig(struct mm_struct *mm)
{
	gfp_t gfp = GFP_PGTABLE_USER;

	if (PGD_SIZE == PAGE_SIZE)
		return (pgd_t *)__get_free_page(gfp);
	else
		return kmem_cache_alloc(pgd_cache, gfp);
}

static void pgd_free_orig(struct mm_struct *mm, pgd_t *pgd)
{
	if (PGD_SIZE == PAGE_SIZE)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
}

#ifdef CONFIG_KERNEL_REPLICATION
pgd_t *page_pgd_alloc(struct mm_struct *mm)
{
	int nid;
	gfp_t gfp = GFP_PGTABLE_USER | __GFP_THISNODE;
	/*
	 * Kernel replication is not supproted in case of non-page size pgd,
	 * in general we can support it, but maybe later, due to we need to
	 * update page tables allocation significantly, so, let's panic here.
	 */
	for_each_memory_node(nid) {
		struct page *page;

		page = alloc_pages_node(nid, gfp, 0);
		if (!page)
			goto fail;

		WARN_ON_ONCE(page_to_nid(page) != nid);

		*per_node_pgd_ptr(mm, nid) = (pgd_t *)page_address(page);
	}

	for_each_online_node(nid)
		*per_node_pgd_ptr(mm, nid) = per_node_pgd(mm, numa_get_memory_node(nid));

	mm->pgd = per_node_pgd(mm, numa_get_memory_node(0));/*!!!*/

	return mm->pgd;

fail:
	pgd_free(mm, mm->pgd);

	return NULL;
}

static pgd_t *pgd_alloc_replica(struct mm_struct *mm)
{
	pgd_t **pgd_numa = (pgd_t **)kmalloc(sizeof(pgd_t *) * MAX_NUMNODES, GFP_PGTABLE_KERNEL);

	if (!pgd_numa)
		return NULL;

	mm->pgd_numa = pgd_numa;

	return page_pgd_alloc(mm);
}

static void page_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	int nid;
	/*
	 * Kernel replication is not supproted in case of non-page size pgd,
	 * in general we can support it, but maybe later, due to we need to
	 * update page tables allocation significantly, so, let's panic here.
	 */
	for_each_memory_node(nid) {
		if (per_node_pgd(mm, nid) == NULL)
			break;
		WARN_ON_ONCE(page_to_nid(virt_to_page(per_node_pgd(mm, nid))) != nid);
		free_page((unsigned long)per_node_pgd(mm, nid));
	}

	for_each_online_node(nid)
		*per_node_pgd_ptr(mm, nid) = NULL;

}

static void pgd_free_replica(struct mm_struct *mm, pgd_t *pgd)
{
	page_pgd_free(mm, pgd);

	kfree(mm->pgd_numa);
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	mm->pgd_numa = NULL;
	if (is_text_replicated())
		return pgd_alloc_replica(mm);
	else
		return pgd_alloc_orig(mm);

}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (is_text_replicated())
		pgd_free_replica(mm, pgd);
	else
		pgd_free_orig(mm, pgd);
}

#else /* !CONFIG_KERNEL_REPLICATION */
pgd_t *pgd_alloc(struct mm_struct *mm)
{
	return pgd_alloc_orig(mm);
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	pgd_free_orig(mm, pgd);
}
#endif /* CONFIG_KERNEL_REPLICATION */

void __init pgtable_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

#ifdef CONFIG_ARM64_PA_BITS_52
	/*
	 * With 52-bit physical addresses, the architecture requires the
	 * top-level table to be aligned to at least 64 bytes.
	 */
	BUILD_BUG_ON(PGD_SIZE < 64);
#endif

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}
