/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */
#ifndef __LINUX_PBHA_H
#define __LINUX_PBHA_H

#include <linux/mm.h>
#include <linux/libfdt.h>
#include <linux/pgtable.h>

#define PBHA_VAL_BIT0 1UL
#define PBHA_BITS_SHIFT 59

#define EFI_OEMCONFIG_VARIABLE_GUID                                            \
	EFI_GUID(0x21f3b3c5, 0x946d, 0x41c1, 0x83, 0x8c, 0x19, 0x4e, 0x48,     \
		 0xaa, 0x41, 0xe2)

#define HBM_MODE_MEMORY	0
#define HBM_MODE_CACHE	1

#ifdef CONFIG_ARM64_PBHA
extern bool __ro_after_init pbha_bit0_enabled;
extern bool __ro_after_init pbha_bit0_kernel_enabled;
extern struct mm_walk_ops pbha_bit0_walk_ops;
extern void __init early_pbha_bit0_init(void);
extern int pbha_bit0_update_vma(struct mm_struct *mm, int val);

static inline bool system_support_pbha_bit0(void)
{
	return pbha_bit0_enabled;
}

static inline pgprot_t pgprot_pbha_bit0(pgprot_t prot)
{
	if (!system_support_pbha_bit0() || !pbha_bit0_kernel_enabled)
		return prot;

	return pgprot_pbha(prot, PBHA_VAL_BIT0);
}

static inline pte_t maybe_mk_pbha_bit0(pte_t pte, struct vm_area_struct *vma)
{
	if (!system_support_pbha_bit0())
		return pte;

	/* global init task will update pbha bit0 iff kernel can do this */
	if (unlikely(is_global_init(current)) && pbha_bit0_kernel_enabled &&
	    !(vma->vm_flags & VM_PBHA_BIT0))
		vma->vm_flags |= VM_PBHA_BIT0;

	if (vma->vm_flags & VM_PBHA_BIT0)
		pte = pte_mkpbha(pte, PBHA_VAL_BIT0);

	return pte;
}
#else
static inline bool system_support_pbha_bit0(void) { return false; }
static inline pgprot_t pgprot_pbha_bit0(pgprot_t prot) { return prot; }
static inline pte_t maybe_mk_pbha_bit0(pte_t pte, struct vm_area_struct *vma)
{
	return pte;
}
#endif

#endif
