// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>

#define CVM_PTE_NS_BIT   5
#define CVM_PTE_NS_MASK  (1 << CVM_PTE_NS_BIT)

static bool cvm_guest_enable __read_mostly;

/* please use 'cvm_guest=1' to enable cvm guest feature */
static int __init setup_cvm_guest(char *str)
{
	int ret;
	unsigned int val;

	if (!str)
		return 0;

	ret = kstrtouint(str, 10, &val);
	if (ret) {
		pr_warn("Unable to parse cvm_guest.\n");
	} else {
		if (val)
			cvm_guest_enable = true;
	}
	return ret;
}
early_param("cvm_guest", setup_cvm_guest);

bool is_cvm_world(void)
{
	return cvm_guest_enable;
}

static int change_page_range_cvm(pte_t *ptep, unsigned long addr, void *data)
{
	bool encrypt = (bool)data;
	pte_t pte = READ_ONCE(*ptep);

	if (encrypt) {
		if (!(pte.pte & CVM_PTE_NS_MASK))
			return 0;
		pte.pte = pte.pte & (~CVM_PTE_NS_MASK);
	} else {
		if (pte.pte & CVM_PTE_NS_MASK)
			return 0;
		/* Set NS BIT */
		pte.pte = pte.pte | CVM_PTE_NS_MASK;
	}
	set_pte(ptep, pte);

	return 0;
}

static int __change_memory_common_cvm(unsigned long start, unsigned long size, bool encrypt)
{
	int ret;

	ret = apply_to_page_range(&init_mm, start, size, change_page_range_cvm, (void *)encrypt);
	flush_tlb_kernel_range(start, start + size);
	return ret;
}

static int __set_memory_encrypted(unsigned long addr,
			int numpages,
			bool encrypt)
{
	if (!is_cvm_world())
		return 0;

	WARN_ON(!__is_lm_address(addr));
	return __change_memory_common_cvm(addr, PAGE_SIZE * numpages, encrypt);
}

int set_cvm_memory_encrypted(unsigned long addr, int numpages)
{
	return __set_memory_encrypted(addr, numpages, true);
}

int set_cvm_memory_decrypted(unsigned long addr, int numpages)
{
	return __set_memory_encrypted(addr, numpages, false);
}
