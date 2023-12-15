/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#ifndef _LINUX_USERSWAP_H
#define _LINUX_USERSWAP_H

#include <linux/mman.h>

#ifdef CONFIG_USERSWAP

extern struct static_key_false userswap_enabled;

/*
 * In uswap situation, we use the bit 0 of the returned address to indicate
 * whether the pages are dirty.
 */
#define USWAP_PAGES_DIRTY	1

unsigned long uswap_mremap(unsigned long old_addr, unsigned long old_len,
			   unsigned long new_addr, unsigned long new_len);

bool uswap_register(struct uffdio_register *uffdio_register, bool *uswap_mode);

bool uswap_adjust_uffd_range(struct uffdio_register *uffdio_register,
			     unsigned long *vm_flags, struct mm_struct *mm);

vm_fault_t do_uswap_page(swp_entry_t entry, struct vm_fault *vmf,
			 struct vm_area_struct *vma);

int mfill_atomic_pte_nocopy(struct mm_struct *dst_mm, pmd_t *dst_pmd,
			    struct vm_area_struct *dst_vma,
			    unsigned long dst_addr, unsigned long src_addr);

static inline void uswap_must_wait(unsigned long reason, pte_t pte, bool *ret)
{
	if (!static_branch_unlikely(&userswap_enabled))
		return;
	if ((reason & VM_USWAP) && (!pte_present(pte)))
		*ret = true;
}

static inline bool uswap_check_copy(struct vm_area_struct *vma,
				    uffd_flags_t flags)
{
	if (!!uffd_flags_mode_is(flags, MFILL_ATOMIC_DIRECT_MAP) ^
	    !!(vma->vm_flags & VM_USWAP))
		return false;
	return true;
}

static inline void uswap_get_cpu_id(unsigned long reason, struct uffd_msg *msg)
{
	if (reason & VM_USWAP)
		msg->reserved3 = smp_processor_id();
}

#endif /* CONFIG_USERSWAP */
#endif /* _LINUX_USERSWAP_H */
