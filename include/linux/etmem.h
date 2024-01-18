/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_ETMEM_H_
#define __MM_ETMEM_H_

#include <linux/list.h>
#include <asm/page.h>
#include <linux/mmzone.h>
#include <linux/memcontrol.h>
#include <linux/page-flags.h>

#ifdef CONFIG_ETMEM

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
#endif /* #ifdef CONFIG_ETMEM */
#endif /* define __MM_ETMEM_H_ */
