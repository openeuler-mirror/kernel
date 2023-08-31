// SPDX-License-Identifier: GPL-2.0
/*
 * accelerate copying page to pmem with non-temproal stroes
 */
#include <linux/sched.h>
#include <linux/mmzone.h>
#include <linux/highmem.h>
#include <linux/sysctl.h>

DEFINE_STATIC_KEY_FALSE(hugepage_nocache_copy);
#ifdef CONFIG_SYSCTL
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
	int state;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	state = static_branch_unlikely(&hugepage_nocache_copy);
	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write)
		set_hugepage_nocache_copy(state);
	return err;
}

static struct ctl_table copy_highpages_table[] = {
	{
		.procname       = "hugepage_nocache_copy",
		.data           = NULL,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0600,
		.proc_handler   = sysctl_hugepage_nocache_copy,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{}
};

static struct ctl_table copy_highpages_root_table[] = {
	{
		.procname       = "vm",
		.mode           = 0555,
		.child          = copy_highpages_table,
	},
	{}
};

static __init int copy_highpages_init(void)
{
	return register_sysctl_table(copy_highpages_root_table) ? 0 : -ENOMEM;
}
__initcall(copy_highpages_init);
#endif

static void copy_highpages_nocache(struct folio *dst, struct folio *src)
{
	char *vfrom, *vto;
	int i;
	int nr = folio_nr_pages(src);

	for (i = 0; i < nr; i++) {
		cond_resched();
		vfrom = kmap_atomic(folio_page(src, i));
		vto = kmap_atomic(folio_page(dst, i));
		copy_page_nocache(vto, vfrom);
		kunmap_atomic(vto);
		kunmap_atomic(vfrom);
	}
	copy_page_nocache_barrir();
}

static void copy_highpages_cache(struct folio *dst, struct folio *src)
{
	long i = 0;
	long nr = folio_nr_pages(src);

	for (;;) {
		copy_highpage(folio_page(dst, i), folio_page(src, i));
		if (++i == nr)
			break;
		cond_resched();
	}
}

void copy_highpages(struct folio *dst, struct folio *src)
{
	if (static_branch_unlikely(&hugepage_nocache_copy) &&
			get_node_type(page_to_nid(folio_page(dst, 0))) == NODE_TYPE_PMEM)
		return copy_highpages_nocache(dst, src);

	return copy_highpages_cache(dst, src);
}
