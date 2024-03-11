/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_ETMEM_H_
#define __MM_ETMEM_H_

#include <linux/list.h>
#include <asm/page.h>
#include <linux/mmzone.h>
#include <linux/memcontrol.h>
#include <linux/page-flags.h>

#ifdef CONFIG_ETMEM
/**
 * list_for_each_entry_safe_reverse_from - iterate backwards over list from
 * current point safe against removal
 * @pos:        the type * to use as a loop cursor.
 * @n:          another type * to use as temporary storage
 * @head:       the head for your list.
 * @member:     the name of the list_head within the struct.
 *
 * Iterate backwards over list of given type from current point, safe against
 * removal of list entry.
 */
#define list_for_each_entry_safe_reverse_from(pos, n, head, member)     \
	for (n = list_prev_entry(pos, member);                          \
		!list_entry_is_head(pos, head, member);                \
		pos = n, n = list_prev_entry(n, member))


enum etmem_swapcache_watermark_en {
	ETMEM_SWAPCACHE_WMARK_LOW,
	ETMEM_SWAPCACHE_WMARK_HIGH,
	ETMEM_SWAPCACHE_NR_WMARK
};

#if IS_ENABLED(CONFIG_KVM)
static inline struct kvm *mm_kvm(struct mm_struct *mm)
{
	return mm->kvm;
}
#else
static inline struct kvm *mm_kvm(struct mm_struct *mm)
{
	return NULL;
}
#endif

extern int add_page_for_swap(struct page *page, struct list_head *pagelist);
extern struct page *get_page_from_vaddr(struct mm_struct *mm,
					unsigned long vaddr);
extern struct kobj_attribute kernel_swap_enable_attr;
extern bool kernel_swap_enabled(void);
extern int do_swapcache_reclaim(unsigned long *swapcache_watermark,
				unsigned int watermark_nr);
#else /* !CONFIG_ETMEM */
static inline int add_page_for_swap(struct page *page, struct list_head *pagelist)
{
	return 0;
}

static inline struct page *get_page_from_vaddr(struct mm_struct *mm,
					unsigned long vaddr)
{
	return NULL;
}

static inline bool kernel_swap_enabled(void)
{
	return true;
}
static inline int do_swapcache_reclaim(unsigned long *swapcache_watermark,
					unsigned int watermark_nr)
{
	return 0;
}
#endif /* #ifdef CONFIG_ETMEM */
#endif /* define __MM_ETMEM_H_ */
