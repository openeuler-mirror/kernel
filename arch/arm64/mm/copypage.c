// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/copypage.c
 *
 * Copyright (C) 2002 Deep Blue Solutions Ltd, All Rights Reserved.
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/bitops.h>
#include <linux/mm.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/mte.h>

void copy_highpage(struct page *to, struct page *from)
{
	void *kto = page_address(to);
	void *kfrom = page_address(from);

	copy_page(kto, kfrom);

	if (kasan_hw_tags_enabled())
		page_kasan_tag_reset(to);

	if (system_supports_mte() && page_mte_tagged(from)) {
		/* It's a new page, shouldn't have been tagged yet */
		WARN_ON_ONCE(!try_page_mte_tagging(to));
		mte_copy_page_tags(kto, kfrom);
		set_page_mte_tagged(to);
	}
}
EXPORT_SYMBOL(copy_highpage);

void copy_user_highpage(struct page *to, struct page *from,
			unsigned long vaddr, struct vm_area_struct *vma)
{
	copy_highpage(to, from);
	flush_dcache_page(to);
}
EXPORT_SYMBOL_GPL(copy_user_highpage);

#ifdef CONFIG_ARCH_HAS_COPY_MC
/*
 * Return -EFAULT if anything goes wrong while copying page or mte.
 */
int copy_mc_highpage(struct page *to, struct page *from)
{
	void *kto = page_address(to);
	void *kfrom = page_address(from);
	int ret;

	ret = copy_mc_page(kto, kfrom);
	if (ret)
		return -EFAULT;

	if (kasan_hw_tags_enabled())
		page_kasan_tag_reset(to);

	if (system_supports_mte() && page_mte_tagged(from)) {
		/* It's a new page, shouldn't have been tagged yet */
		WARN_ON_ONCE(!try_page_mte_tagging(to));
		ret = mte_copy_mc_page_tags(kto, kfrom);
		if (ret)
			return -EFAULT;

		set_page_mte_tagged(to);
	}

	return 0;
}
EXPORT_SYMBOL(copy_mc_highpage);

int copy_mc_user_highpage(struct page *to, struct page *from,
			unsigned long vaddr, struct vm_area_struct *vma)
{
	int ret;

	ret = copy_mc_highpage(to, from);
	if (!ret)
		flush_dcache_page(to);

	return ret;
}
EXPORT_SYMBOL_GPL(copy_mc_user_highpage);
#endif
