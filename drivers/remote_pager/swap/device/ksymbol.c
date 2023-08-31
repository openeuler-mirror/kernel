// SPDX-License-Identifier: GPL-2.0
/*
 * Generalized Memory Management.
 *
 * Copyright (c) 2023- Huawei, Inc.
 * Author: Jun Chen
 * Co-Author: Cunshu Ni
 */
#include <linux/kprobes.h>

#include "ksymbol.h"

/*
 * Get some symbol which are not exported by kernel
 *   rmap_walk_anon
 *   __anon_vma_prepare
 *   __page_set_anon_rmap
 *   pgtable_trans_huge_deposit
 *   pgtable_trans_huge_withdraw
 */

rmap_walk_anon_symbol_t rmap_walk_anon_symbol;
__anon_vma_prepare_symbol_t __anon_vma_prepare_symbol;
__page_set_anon_rmap_symbol_t __page_set_anon_rmap_symbol;
pgtable_trans_huge_deposit_symbol_t pgtable_trans_huge_deposit_symbol;
pgtable_trans_huge_withdraw_symbol_t pgtable_trans_huge_withdraw_symbol;

static unsigned long (*kallsyms_lookup_name_symbol)(const char *name);

static int init_kallsyms_lookup_name(void)
{
	int ret;

	struct kprobe kprobe = {
		.symbol_name = "kallsyms_lookup_name",
	};

	ret = register_kprobe(&kprobe);
	if (ret)
		return ret;

	kallsyms_lookup_name_symbol = (void *)kprobe.addr;

	unregister_kprobe(&kprobe);

	return 0;
}

static void *__kallsyms_lookup_name(const char *name)
{
	void *symbol;

	symbol = (void *)kallsyms_lookup_name_symbol(name);
	if (!symbol)
		pr_err("Can not find symbol %s\n", name);

	return symbol;
}

int kernel_symbol_init(void)
{
	int ret;

	ret = init_kallsyms_lookup_name();
	if (ret) {
		pr_err("Can not find symbol kallsyms_lookup_name\n");
		return ret;
	}

	rmap_walk_anon_symbol = __kallsyms_lookup_name("rmap_walk_anon");
	__anon_vma_prepare_symbol = __kallsyms_lookup_name("__anon_vma_prepare");
	__page_set_anon_rmap_symbol = __kallsyms_lookup_name("__page_set_anon_rmap");
	pgtable_trans_huge_deposit_symbol = __kallsyms_lookup_name("pgtable_trans_huge_deposit");
	pgtable_trans_huge_withdraw_symbol = __kallsyms_lookup_name("pgtable_trans_huge_withdraw");

	ret =	!rmap_walk_anon_symbol ||
		!__anon_vma_prepare_symbol ||
		!__page_set_anon_rmap_symbol ||
		!pgtable_trans_huge_deposit_symbol ||
		!pgtable_trans_huge_withdraw_symbol;

	return ret;
}
