/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#define pr_fmt(fmt)	"pbha: " fmt

#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/printk.h>
#include <linux/cpufeature.h>
#include <linux/mmu_notifier.h>
#include <linux/pagewalk.h>
#include <linux/pbha.h>

#include <asm/setup.h>

#define HBM_MODE_CACHE	1

bool __ro_after_init pbha_bit0_enabled;
bool __ro_after_init pbha_bit0_kernel_enabled;
static bool pbha_enabled_phase_1;

void __init early_pbha_bit0_init(void)
{
	const u8 *prop;
	void *fdt;
	int node;

	/* Check whether PBHA is enabled or not. */
	if (!system_supports_pbha())
		return;

	fdt = get_early_fdt_ptr();
	if (!fdt)
		return;

	node = fdt_path_offset(fdt, "/chosen");
	if (node < 0)
		return;

	prop = fdt_getprop(fdt, node, "linux,pbha-bit0", NULL);
	if (!prop)
		return;
	if (*prop == HBM_MODE_CACHE)
		pbha_enabled_phase_1 = true;
}

#define pte_pbha_bit0(pte)                                                     \
	(!!(pte_val(pte) & (PBHA_VAL_BIT0 << PBHA_BITS_SHIFT)))

enum {
	CLEAR_PBHA_BIT0_FLAG,
	SET_PBHA_BIT0_FLAG,
};

static inline void pbha_bit0_update_pte_bits(struct vm_area_struct *vma,
		unsigned long addr, pte_t *pte, bool set)
{
	pte_t ptent = *pte;

	if (pte_present(ptent)) {
		pte_t old_pte;

		old_pte = ptep_modify_prot_start(vma, addr, pte);
		if (set)
			ptent = pte_mkpbha(old_pte, PBHA_VAL_BIT0);
		else
			ptent = pte_rmpbha(old_pte, PBHA_VAL_BIT0);
		ptep_modify_prot_commit(vma, addr, pte, old_pte, ptent);
	}
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline void pbha_bit0_update_pmd_bits(struct vm_area_struct *vma,
		unsigned long addr, pmd_t *pmdp, bool set)
{
	pmd_t pmd = *pmdp;

	if (pmd_present(pmd)) {
		if (set)
			pmd = pmd_mkpbha(pmd, PBHA_VAL_BIT0);
		else
			pmd = pmd_rmpbha(pmd, PBHA_VAL_BIT0);

		set_pmd_at(vma->vm_mm, addr, pmdp, pmd);
	}
}
#else
static inline void pbha_bit0_update_pmd_bits(struct vm_area_struct *vma,
					      unsigned long addr, pmd_t *pmdp,
					      bool set)
{
}
#endif

static int pbha_bit0_pte_range(pmd_t *pmd, unsigned long addr,
				unsigned long end, struct mm_walk *walk)
{
	int *op = (int *)walk->private;
	struct vm_area_struct *vma = walk->vma;
	pte_t *pte, ptent;
	spinlock_t *ptl;
	bool set = (*op == SET_PBHA_BIT0_FLAG);

	ptl = pmd_trans_huge_lock(pmd, vma);
	if (ptl) {
		pbha_bit0_update_pmd_bits(vma, addr, pmd, set);

		spin_unlock(ptl);
		return 0;
	}

	if (pmd_trans_unstable(pmd))
		return 0;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE) {
		ptent = *pte;

		pbha_bit0_update_pte_bits(vma, addr, pte, set);
	}
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();
	return 0;
}

static int pbha_bit0_test_walk(unsigned long start, unsigned long end,
				struct mm_walk *walk)
{
	struct vm_area_struct *vma = walk->vma;

	if (vma->vm_flags & VM_PFNMAP)
		return 1;

	return 0;
}

struct mm_walk_ops pbha_bit0_walk_ops = {
	.pmd_entry		= pbha_bit0_pte_range,
	.test_walk		= pbha_bit0_test_walk,
};

int pbha_bit0_update_vma(struct mm_struct *mm, int val)
{
	struct mmu_notifier_range range;
	struct vm_area_struct *vma;
	int old_val;

	if (!system_support_pbha_bit0())
		return -EINVAL;

	old_val = (mm->def_flags & VM_PBHA_BIT0) ? 1 : 0;
	if (val == old_val)
		return 0;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	if (val == SET_PBHA_BIT0_FLAG) {
		mm->def_flags |= VM_PBHA_BIT0;
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (vma->vm_flags & VM_PBHA_BIT0)
				continue;
			vma->vm_flags |= VM_PBHA_BIT0;
			vma_set_page_prot(vma);
		}
	} else {
		mm->def_flags &= ~VM_PBHA_BIT0;
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (!(vma->vm_flags & VM_PBHA_BIT0))
				continue;
			vma->vm_flags &= ~VM_PBHA_BIT0;
			vma_set_page_prot(vma);
		}
	}

	inc_tlb_flush_pending(mm);
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, NULL, mm, 0, -1UL);
	mmu_notifier_invalidate_range_start(&range);
	walk_page_range(mm, 0, mm->highest_vm_end, &pbha_bit0_walk_ops,
		&val);
	mmu_notifier_invalidate_range_end(&range);
	flush_tlb_mm(mm);
	dec_tlb_flush_pending(mm);

	mmap_write_unlock(mm);
	return 0;
}

static int __init setup_pbha(char *str)
{
	if (!pbha_enabled_phase_1)
		return 0;

	if (strcmp(str, "enable") == 0) {
		pbha_bit0_enabled = true;
		pbha_bit0_kernel_enabled = true;
	} else if (strcmp(str, "user") == 0) {
		pbha_bit0_enabled = true;
	}

	pr_info("pbha bit_0 enabled, kernel: %d\n", pbha_bit0_kernel_enabled);

	return 0;
}
early_param("pbha", setup_pbha);
