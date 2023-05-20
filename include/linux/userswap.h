/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#ifndef _LINUX_USERSWAP_H
#define _LINUX_USERSWAP_H

#include <linux/mman.h>
#include <linux/userfaultfd.h>

#ifdef CONFIG_USERSWAP

extern struct static_key_false userswap_enabled;

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

bool uswap_register(struct uffdio_register *uffdio_register, bool *uswap_mode);

bool uswap_adjust_uffd_range(struct uffdio_register *uffdio_register,
			     unsigned long *vm_flags, struct mm_struct *mm);

bool do_uswap_page(swp_entry_t entry, struct vm_fault *vmf,
		   struct vm_area_struct *vma, vm_fault_t *ret);

static inline bool uswap_check_copy(struct vm_area_struct *vma,
				    unsigned long src_addr,
				    unsigned long len, __u64 mode)
{
	if (vma->vm_flags & VM_USWAP) {
		if (!(mode & UFFDIO_COPY_MODE_DIRECT_MAP))
			return false;
		if (offset_in_page(src_addr))
			return false;
		if (src_addr > TASK_SIZE || src_addr > TASK_SIZE - len)
			return false;
	} else {
		if (mode & UFFDIO_COPY_MODE_DIRECT_MAP)
			return false;
	}

	return true;
}

static inline bool uswap_validate_mremap_flags(unsigned long flags)
{
	if (static_branch_unlikely(&userswap_enabled)) {
		if (flags & MREMAP_USWAP_SET_PTE &&
		    flags & ~MREMAP_USWAP_SET_PTE)
			return false;
		if (flags & ~(MREMAP_FIXED | MREMAP_MAYMOVE |
			      MREMAP_DONTUNMAP | MREMAP_USWAP_SET_PTE))
			return false;
	} else {
		if (flags & ~(MREMAP_FIXED | MREMAP_MAYMOVE |
			      MREMAP_DONTUNMAP))
			return false;
	}
	return true;
}

/* When CONFIG_USERSWAP=y, VM_UFFD_MISSING|VM_USWAP is right;
 * 0 or > 1 flags set is a bug; we expect exactly 1.
 */
static inline bool uswap_vm_flag_bug_on(unsigned long reason)
{
	if (reason & ~(VM_UFFD_MISSING | VM_UFFD_WP | VM_USWAP))
		return true;
	if (reason & VM_USWAP)
		return !(reason & VM_UFFD_MISSING) ||
		       reason & ~(VM_USWAP|VM_UFFD_MISSING);
	return !(reason & VM_UFFD_MISSING) ^ !!(reason & VM_UFFD_WP);
}

static inline bool uswap_missing(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_USWAP && vma->vm_flags & VM_UFFD_MISSING)
		return true;
	return false;
}

static inline void uswap_get_cpu_id(unsigned long reason, struct uffd_msg *msg)
{
	if (reason & VM_USWAP)
		msg->reserved3 = smp_processor_id();
}

static inline void uswap_release(unsigned long *userfault_flags)
{
	if (static_branch_unlikely(&userswap_enabled))
		*userfault_flags |= VM_USWAP;
}

static inline void uswap_must_wait(unsigned long reason, pte_t pte, bool *ret)
{
	if ((reason & VM_USWAP) && (!pte_present(pte)))
		*ret = true;
}

#endif /* CONFIG_USERSWAP */

#endif /* _LINUX_USERSWAP_H */
