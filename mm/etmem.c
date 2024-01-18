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
