// SPDX-License-Identifier: GPL-2.0
/*
 * accelerate copying page to pmem with non-temproal stroes
 */
#include <linux/sched.h>
#include <linux/mmzone.h>
#include <linux/highmem.h>
#include <linux/sysctl.h>

DEFINE_STATIC_KEY_FALSE(hugepage_nocache_copy);

static void set_hugepage_nocache_copy(bool enabled)
{
	if (enabled)
		static_branch_enable(&hugepage_nocache_copy);
	else
		static_branch_disable(&hugepage_nocache_copy);
}

int sysctl_hugepage_nocache_copy(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = static_branch_unlikely(&hugepage_nocache_copy);

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write)
		set_hugepage_nocache_copy(state);
	return err;
}

static void copy_highpages_nocache(struct page *to, struct page *from, int nr_pages)
{
	char *vfrom, *vto;
	int i;

	for (i = 0; i < nr_pages; i++) {
		cond_resched();
		vfrom = kmap_atomic(from);
		vto = kmap_atomic(to);
		copy_page_nocache(vto, vfrom);
		kunmap_atomic(vto);
		kunmap_atomic(vfrom);
		to++;
		from++;
	}
	copy_page_nocache_barrir();
}

static void copy_highpages_cache(struct page *to, struct page *from, int nr_pages)
{
	int i;

	for (i = 0; i < nr_pages; i++) {
		cond_resched();
		copy_highpage(to + i, from + i);
	}
}

void copy_highpages(struct page *to, struct page *from, int nr_pages)
{
	if (static_branch_unlikely(&hugepage_nocache_copy) && is_node_pmem(page_to_nid(to)))
		return copy_highpages_nocache(to, from, nr_pages);

	return copy_highpages_cache(to, from, nr_pages);
}
