// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/mm_inline.h>

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

	follflags = FOLL_GET | FOLL_DUMP | FOLL_FORCE;
	page = follow_page(vma, vaddr, follflags);
	if (IS_ERR(page) || !page) {
		mmap_read_unlock(mm);
		return NULL;
	}

	mmap_read_unlock(mm);
	return page;
}
EXPORT_SYMBOL_GPL(get_page_from_vaddr);

static int add_page_for_reclaim_swapcache(struct page *page,
	struct list_head *pagelist, struct lruvec *lruvec, enum lru_list lru)
{
	struct page *head;

	/* If the page is mapped by more than one process, do not swap it */
	if (page_mapcount(page) > 1)
		return -EINVAL;

	if (PageHuge(page))
		return -EINVAL;

	head = compound_head(page);
	if (!PageLRU(head) || PageUnevictable(head))
		return -EBUSY;

	if (unlikely(!get_page_unless_zero(page)))
		return -EBUSY;

	if (!TestClearPageLRU(page)) {
		/*
		 * This page may in other isolation path,
		 * but we still hold lru_lock.
		 */
		put_page(page);
		return -EBUSY;
	}

	list_move(&head->lru, pagelist);
	update_lru_size(lruvec, lru, page_zonenum(head), -thp_nr_pages(head));

	return 0;
}

static unsigned long reclaim_swapcache_pages_from_list(int nid,
	struct list_head *page_list, unsigned long reclaim_num, bool putback_flag)
{
	unsigned long nr_reclaimed = 0;
	unsigned long nr_moved = 0;
	struct page *page, *next;
	LIST_HEAD(swap_pages);
	struct pglist_data *pgdat = NULL;

	pgdat = NODE_DATA(nid);

	if (putback_flag)
		goto putback_list;

	if (reclaim_num == 0)
		return 0;

	list_for_each_entry_safe(page, next, page_list, lru) {
		if (!page_is_file_lru(page) && !__PageMovable(page)
				&& PageSwapCache(page)) {
			ClearPageActive(page);
			list_move(&page->lru, &swap_pages);
			nr_moved++;
		}

		if (nr_moved >= reclaim_num)
			break;
	}

	/* swap the pages */
	if (pgdat)
		nr_reclaimed = reclaim_pages(&swap_pages);

	return nr_reclaimed;

putback_list:
	while (!list_empty(page_list)) {
		page = lru_to_page(page_list);
		list_del(&page->lru);
		putback_lru_page(page);
	}

	return nr_reclaimed;
}

#define SWAP_SCAN_NUM_MAX       32

static bool swapcache_below_watermark(unsigned long *swapcache_watermark)
{
	return total_swapcache_pages() < swapcache_watermark[ETMEM_SWAPCACHE_WMARK_LOW];
}

static unsigned long get_swapcache_reclaim_num(unsigned long *swapcache_watermark)
{
	return total_swapcache_pages() >
		swapcache_watermark[ETMEM_SWAPCACHE_WMARK_LOW] ?
		(total_swapcache_pages() - swapcache_watermark[ETMEM_SWAPCACHE_WMARK_LOW]) : 0;
}

/*
 * The main function to reclaim swapcache, the whole reclaim process is
 * divided into 3 steps.
 * 1. get the total_swapcache_pages num to reclaim.
 * 2. scan the LRU linked list of each memory node to obtain the
 * swapcache pages that can be reclaimd.
 * 3. reclaim the swapcache page until the requirements are meet.
 */
int do_swapcache_reclaim(unsigned long *swapcache_watermark,
			 unsigned int watermark_nr)
{
	int err = -EINVAL;
	unsigned long swapcache_to_reclaim = 0;
	unsigned long nr_reclaimed = 0;
	unsigned long swapcache_total_reclaimable = 0;
	unsigned long reclaim_page_count = 0;

	unsigned long *nr = NULL;
	unsigned long *nr_to_reclaim = NULL;
	struct list_head *swapcache_list = NULL;

	int nid = 0;
	struct lruvec *lruvec = NULL;
	struct list_head *src = NULL;
	struct page *page = NULL;
	struct page *next = NULL;
	struct page *pos = NULL;

	struct mem_cgroup *memcg = NULL;
	struct mem_cgroup *target_memcg = NULL;

	pg_data_t *pgdat = NULL;
	unsigned int scan_count = 0;
	int nid_num = 0;

	if (swapcache_watermark == NULL ||
	    watermark_nr < ETMEM_SWAPCACHE_NR_WMARK)
		return err;

	/* get the total_swapcache_pages num to reclaim. */
	swapcache_to_reclaim = get_swapcache_reclaim_num(swapcache_watermark);
	if (swapcache_to_reclaim <= 0)
		return err;

	nr = kcalloc(MAX_NUMNODES, sizeof(unsigned long), GFP_KERNEL);
	if (nr == NULL)
		return -ENOMEM;

	nr_to_reclaim = kcalloc(MAX_NUMNODES, sizeof(unsigned long), GFP_KERNEL);
	if (nr_to_reclaim == NULL) {
		kfree(nr);
		return -ENOMEM;
	}

	swapcache_list = kcalloc(MAX_NUMNODES, sizeof(struct list_head), GFP_KERNEL);
	if (swapcache_list == NULL) {
		kfree(nr);
		kfree(nr_to_reclaim);
		return -ENOMEM;
	}

	/*
	 * scan the LRU linked list of each memory node to obtain the
	 * swapcache pages that can be reclaimd.
	 */
	for_each_node_state(nid, N_MEMORY) {
		INIT_LIST_HEAD(&swapcache_list[nid_num]);
		cond_resched();

		pgdat = NODE_DATA(nid);

		memcg = mem_cgroup_iter(target_memcg, NULL, NULL);
		do {
			cond_resched();
			pos = NULL;
			lruvec = mem_cgroup_lruvec(memcg, pgdat);
			src = &(lruvec->lists[LRU_INACTIVE_ANON]);
			spin_lock_irq(&lruvec->lru_lock);
			scan_count = 0;

			/*
			 * Scan the swapcache pages that are not mapped from
			 * the end of the LRU linked list, scan SWAP_SCAN_NUM_MAX
			 * pages each time, and record the scan end point page.
			 */

			pos = list_last_entry(src, struct page, lru);
			spin_unlock_irq(&lruvec->lru_lock);
do_scan:
			cond_resched();
			scan_count = 0;
			spin_lock_irq(&lruvec->lru_lock);

			/*
			 * check if pos page is been released or not in LRU list, if true,
			 * cancel the subsequent page scanning of the current node.
			 */
			if (!pos || list_entry_is_head(pos, src, lru)) {
				spin_unlock_irq(&lruvec->lru_lock);
				continue;
			}

			if (!PageLRU(pos) || folio_lru_list(page_folio(pos)) != LRU_INACTIVE_ANON) {
				spin_unlock_irq(&lruvec->lru_lock);
				continue;
			}

			page = pos;
			pos = NULL;
			/* Continue to scan down from the last scan breakpoint */
			list_for_each_entry_safe_reverse_from(page, next, src, lru) {
				scan_count++;
				pos = next;
				if (scan_count >= SWAP_SCAN_NUM_MAX)
					break;

				if (!PageSwapCache(page))
					continue;

				if (page_mapped(page))
					continue;

				if (add_page_for_reclaim_swapcache(page,
					&swapcache_list[nid_num],
					lruvec, LRU_INACTIVE_ANON) != 0)
					continue;

				nr[nid_num]++;
				swapcache_total_reclaimable++;
			}
			spin_unlock_irq(&lruvec->lru_lock);

			/*
			 * Check whether the scanned pages meet
			 * the reclaim requirements.
			 */
			if (swapcache_total_reclaimable <= swapcache_to_reclaim ||
					scan_count >= SWAP_SCAN_NUM_MAX)
				goto do_scan;

		} while ((memcg = mem_cgroup_iter(target_memcg, memcg, NULL)));

		/* Start reclaiming the next memory node. */
		nid_num++;
	}

	/* reclaim the swapcache page until the requirements are meet. */
	do {
		nid_num = 0;
		reclaim_page_count = 0;

		/* start swapcache page reclaim for each node. */
		for_each_node_state(nid, N_MEMORY) {
			cond_resched();

			nr_to_reclaim[nid_num] = (swapcache_total_reclaimable == 0) ? 0 :
						 ((swapcache_to_reclaim * nr[nid_num]) /
						   swapcache_total_reclaimable);

			reclaim_page_count += reclaim_swapcache_pages_from_list(nid,
						&swapcache_list[nid_num],
						nr_to_reclaim[nid_num], false);
			nid_num++;
		}

		nr_reclaimed += reclaim_page_count;

		/*
		 * Check whether the swapcache page reaches the reclaim requirement or
		 * the number of the swapcache page reclaimd is 0. Stop reclaim.
		 */
		if (nr_reclaimed >= swapcache_to_reclaim || reclaim_page_count == 0)
			goto exit;
	} while (!swapcache_below_watermark(swapcache_watermark) ||
				nr_reclaimed < swapcache_to_reclaim);
exit:
	nid_num = 0;
	/*
	 * Repopulate the swapcache pages that are not reclaimd back
	 * to the LRU linked list.
	 */
	for_each_node_state(nid, N_MEMORY) {
		cond_resched();
		reclaim_swapcache_pages_from_list(nid,
			&swapcache_list[nid_num], 0, true);
		nid_num++;
	}

	kfree(nr);
	kfree(nr_to_reclaim);
	kfree(swapcache_list);

	return 0;
}
EXPORT_SYMBOL_GPL(do_swapcache_reclaim);
