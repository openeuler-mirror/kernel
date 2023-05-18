/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#ifndef _LINUX_USERSWAP_H
#define _LINUX_USERSWAP_H

#include <linux/mman.h>
#include <linux/userfaultfd.h>

#ifdef CONFIG_USERSWAP

extern int enable_userswap;

/*
 * In uswap situation, we use the bit 0 of the returned address to indicate
 * whether the pages are dirty.
 */
#define USWAP_PAGES_DIRTY	1

int mfill_atomic_pte_nocopy(struct mm_struct *dst_mm,
			    pmd_t *dst_pmd,
			    struct vm_area_struct *dst_vma,
			    unsigned long dst_addr,
			    unsigned long src_addr);

unsigned long uswap_mremap(unsigned long old_addr, unsigned long old_len,
			   unsigned long new_addr, unsigned long new_len);

static inline bool uswap_check_copy_mode(struct vm_area_struct *vma, __u64 mode)
{
	if (!(vma->vm_flags & VM_USWAP) && (mode & UFFDIO_COPY_MODE_DIRECT_MAP))
		return false;
	return true;
}

static inline bool uswap_validate_mremap_flags(unsigned long flags)
{
	if (!enable_userswap && flags & MREMAP_USWAP_SET_PTE)
		return false;
	if (flags & MREMAP_USWAP_SET_PTE && flags & ~MREMAP_USWAP_SET_PTE)
		return false;
	if (flags & ~(MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP |
		      MREMAP_USWAP_SET_PTE))
		return false;
	return true;
}

#endif /* CONFIG_USERSWAP */

#endif /* _LINUX_USERSWAP_H */
