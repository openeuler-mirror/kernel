// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/mm_inline.h>
#include <linux/sysctl.h>
#include <linux/etmem.h>
#include "internal.h"

static bool enable_kernel_swap __read_mostly = true;

bool kernel_swap_enabled(void)
{
	return READ_ONCE(enable_kernel_swap);
}

static ssize_t kernel_swap_enable_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", enable_kernel_swap ? "true" : "false");
}

static ssize_t kernel_swap_enable_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	if (!strncmp(buf, "true", 4) || !strncmp(buf, "1", 1))
		WRITE_ONCE(enable_kernel_swap, true);
	else if (!strncmp(buf, "false", 5) || !strncmp(buf, "0", 1))
		WRITE_ONCE(enable_kernel_swap, false);
	else
		return -EINVAL;

	return count;
}

struct kobj_attribute kernel_swap_enable_attr =
	__ATTR(kernel_swap_enable, 0644, kernel_swap_enable_show,
		kernel_swap_enable_store);

int add_page_for_swap(struct page *page, struct list_head *pagelist)
{
	int err = -EBUSY;
	struct page *head;

	/* If the page is mapped by more than one process, do not swap it */
	if (page_mapcount(page) > 1)
		return -EACCES;

	if (PageHuge(page))
		return -EACCES;

	head = compound_head(page);
	if (!folio_isolate_lru(page_folio(head))) {
		put_page(page);
		return err;
	}
	put_page(page);
	if (PageUnevictable(page))
		putback_lru_page(page);
	else
		list_add_tail(&head->lru, pagelist);

	err = 0;
	return err;
}
EXPORT_SYMBOL_GPL(add_page_for_swap);

struct page *get_page_from_vaddr(struct mm_struct *mm, unsigned long vaddr)
{
	struct page *page;
	struct vm_area_struct *vma;
	unsigned int follflags;

	mmap_read_lock(mm);

	vma = find_vma(mm, vaddr);
	if (!vma || vaddr < vma->vm_start || vma->vm_flags & VM_LOCKED) {
		mmap_read_unlock(mm);
		return NULL;
	}

	follflags = FOLL_GET | FOLL_DUMP;
	page = follow_page(vma, vaddr, follflags);
	if (IS_ERR(page) || !page) {
		mmap_read_unlock(mm);
		return NULL;
	}

	mmap_read_unlock(mm);
	return page;
}
EXPORT_SYMBOL_GPL(get_page_from_vaddr);

#define SWAP_SCAN_NUM_MAX	32

static unsigned long get_swapcache_reclaim_num(unsigned long *swapcache_watermark)
{
	return total_swapcache_pages() >
		swapcache_watermark[ETMEM_SWAPCACHE_WMARK_LOW] ?
		(total_swapcache_pages() - swapcache_watermark[ETMEM_SWAPCACHE_WMARK_LOW]) : 0;
}

static int move_lru_folios_to_list(struct lruvec *lruvec,
	struct folio *folio, struct list_head *foliolist)
{

	if (!folio_test_large(folio)) {
		/* If another process is also mapping this folio */
		if (folio_mapcount(folio) > 1)
			return -EACCES;
	} else if (folio_test_hugetlb(folio)) {
		/* Do not reclaim hugetlb folios */
		return -EACCES;
	} else {
		/* Try to reclaim THP unless it is mapped by another process */
		if (folio_entire_mapcount(folio) > 1)
			return -EACCES;
	}

	/*
	 * try to a reference to a folio
	 * may fail if, the folio has been freed/frozen
	 */
	if (!(folio_try_get(folio)))
		return -1;

	/* racing with another isolation */
	if (!folio_test_clear_lru(folio)) {
		folio_put(folio);
		return -1;
	}

	list_move(&folio->lru, foliolist);
	update_lru_size(lruvec,
			LRU_INACTIVE_ANON,
			folio_zonenum(folio),
			-folio_nr_pages(folio));
	return 0;
}

/*
 * For each node, scan the inactive anon lru, isolate and move
 * appropriate candidates to swapcache_list[nid]
 */
static void memcg_reclaim_swapcache(struct list_head *swapcache_list,
			unsigned long swapcache_to_reclaim)
{
	struct mem_cgroup *memcg = NULL, *target_memcg = NULL;
	struct lruvec *lruvec;
	int nid;
	pg_data_t *pgdat;
	unsigned int scan_count = 0;
	unsigned long swapcache_total_reclaimable = 0;
	struct list_head *src = NULL;
	struct folio *folio = NULL, *next = NULL, *pos = NULL;

	for_each_node_state(nid, N_MEMORY) {
		INIT_LIST_HEAD(&swapcache_list[nid]);
		cond_resched();
		pgdat = NODE_DATA(nid);

		memcg = mem_cgroup_iter(target_memcg, NULL, NULL);
		do {
			cond_resched();
			lruvec = mem_cgroup_lruvec(memcg, pgdat);
			src = &(lruvec->lists[LRU_INACTIVE_ANON]);

			spin_lock_irq(&lruvec->lru_lock);
			pos = list_last_entry(src, struct folio, lru);
			spin_unlock_irq(&lruvec->lru_lock);
reverse_scan_lru:
			cond_resched();
			scan_count = 0;

			spin_lock_irq(&lruvec->lru_lock);
			if (!pos || list_entry_is_head(pos, src, lru)) {
				spin_unlock_irq(&lruvec->lru_lock);
				continue;
			}

			if (!folio_test_lru(pos) || folio_lru_list(pos) != LRU_INACTIVE_ANON) {
				spin_unlock_irq(&lruvec->lru_lock);
				continue;
			}

			folio = pos;

			list_for_each_entry_safe_reverse_from(folio, next, src, lru) {
				pos = next;
				scan_count++;
				if (scan_count >= SWAP_SCAN_NUM_MAX)
					break;

				if (!folio_test_swapcache(folio) || folio_mapped(folio))
					continue;

				if (move_lru_folios_to_list(lruvec,
							folio,
							&swapcache_list[nid]) != 0)
					continue;

				swapcache_total_reclaimable += folio_nr_pages(folio);
			}
			spin_unlock_irq(&lruvec->lru_lock);

			if (swapcache_total_reclaimable >= swapcache_to_reclaim)
				break;

			if (scan_count >= SWAP_SCAN_NUM_MAX)
				goto reverse_scan_lru;

		} while ((memcg = mem_cgroup_iter(target_memcg, memcg, NULL)));
	}
}

static int lru_gen_reclaim_swapcache(struct list_head *swapcache_list,
			unsigned long swapcache_to_reclaim)
{
	return 0;
}

int do_swapcache_reclaim(unsigned long *swapcache_watermark,
			unsigned int watermark_nr)
{
	int nid;
	unsigned long swapcache_to_reclaim = 0;
	struct list_head *swapcache_list = NULL, *folio_list = NULL;
	struct folio *folio = NULL;

	if (swapcache_watermark == NULL ||
		watermark_nr < ETMEM_SWAPCACHE_NR_WMARK)
		return -EINVAL;

	if (lru_gen_enabled())
		return lru_gen_reclaim_swapcache(swapcache_list, swapcache_to_reclaim);

	swapcache_to_reclaim = get_swapcache_reclaim_num(swapcache_watermark);

	swapcache_list = kcalloc(MAX_NUMNODES, sizeof(struct list_head), GFP_KERNEL);
	if (swapcache_list == NULL)
		return -ENOMEM;

	memcg_reclaim_swapcache(swapcache_list, swapcache_to_reclaim);

	/* Reclaim all the swapcache we have scanned */
	for_each_node_state(nid, N_MEMORY) {
		cond_resched();
		reclaim_folio_list(&swapcache_list[nid], NODE_DATA(nid), false);
	}

	/* Put pack all the pages that are not reclaimed by shrink_folio_list */
	for_each_node_state(nid, N_MEMORY) {
		cond_resched();
		folio_list = &swapcache_list[nid];
		while (!list_empty(folio_list)) {
			folio = lru_to_folio(folio_list);
			list_del(&folio->lru);
			folio_putback_lru(folio);
		}
	}

	kfree(swapcache_list);
	return 0;
}
EXPORT_SYMBOL_GPL(do_swapcache_reclaim);
