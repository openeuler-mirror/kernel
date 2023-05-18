/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#ifndef _LINUX_USERSWAP_H
#define _LINUX_USERSWAP_H

#ifdef CONFIG_USERSWAP

extern int enable_userswap;

int mfill_atomic_pte_nocopy(struct mm_struct *dst_mm,
			    pmd_t *dst_pmd,
			    struct vm_area_struct *dst_vma,
			    unsigned long dst_addr,
			    unsigned long src_addr);

static inline bool uswap_check_copy_mode(struct vm_area_struct *vma, __u64 mode)
{
	if (!(vma->vm_flags & VM_USWAP) && (mode & UFFDIO_COPY_MODE_DIRECT_MAP))
		return false;
	return true;
}

#endif /* CONFIG_USERSWAP */

#endif /* _LINUX_USERSWAP_H */
