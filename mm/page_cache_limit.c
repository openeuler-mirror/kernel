// SPDX-License-Identifier: GPL-2.0
/*
 * Support for periodic memory reclaim and page cache limit
 */

#include <linux/mm.h>
#include <linux/page_cache_limit.h>
#include <linux/swap.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>

static int vm_cache_reclaim_s __read_mostly;
static int vm_cache_reclaim_s_max = 43200;
static int vm_cache_reclaim_weight __read_mostly = 1;
static int vm_cache_reclaim_weight_max = 100;
static int vm_cache_reclaim_enable = 1;

static void shrink_shepherd(struct work_struct *w);
static DECLARE_DEFERRABLE_WORK(shepherd, shrink_shepherd);
static struct work_struct vmscan_works[MAX_NUMNODES];

static bool should_periodical_reclaim(void)
{
	return vm_cache_reclaim_s && vm_cache_reclaim_enable;
}

static unsigned long node_reclaim_num(void)
{
	int nid = numa_node_id();

	return SWAP_CLUSTER_MAX * nr_cpus_node(nid) * vm_cache_reclaim_weight;
}

static int cache_reclaim_enable_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret || !write)
		return ret;

	if (should_periodical_reclaim())
		schedule_delayed_work(&shepherd, round_jiffies_relative(
			(unsigned long)vm_cache_reclaim_s * HZ));

	return 0;
}

static int cache_reclaim_sysctl_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *length, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret || !write)
		return ret;

	if (should_periodical_reclaim())
		mod_delayed_work(system_unbound_wq, &shepherd,
				round_jiffies_relative(
				(unsigned long)vm_cache_reclaim_s * HZ));

	return ret;
}

static struct ctl_table ctl_table[] = {
	{
		.procname       = "cache_reclaim_s",
		.data           = &vm_cache_reclaim_s,
		.maxlen         = sizeof(vm_cache_reclaim_s),
		.mode           = 0644,
		.proc_handler   = cache_reclaim_sysctl_handler,
		.extra1         = SYSCTL_ZERO,
		.extra2         = &vm_cache_reclaim_s_max,
	},
	{
		.procname       = "cache_reclaim_weight",
		.data           = &vm_cache_reclaim_weight,
		.maxlen         = sizeof(vm_cache_reclaim_weight),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ONE,
		.extra2         = &vm_cache_reclaim_weight_max,
	},
	{
		.procname	= "cache_reclaim_enable",
		.data		= &vm_cache_reclaim_enable,
		.maxlen		= sizeof(vm_cache_reclaim_enable),
		.mode		= 0644,
		.proc_handler	= cache_reclaim_enable_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{}
};

static struct ctl_table limit_dir_table[] = {
	{
		.procname = "vm",
		.maxlen = 0,
		.mode = 0555,
		.child = ctl_table,
	},
	{}
};

static void shrink_shepherd(struct work_struct *w)
{
	int node;

	if (!should_periodical_reclaim())
		return;

	for_each_online_node(node) {
		if (!work_pending(&vmscan_works[node]))
			queue_work_node(node, system_unbound_wq, &vmscan_works[node]);
	}

	queue_delayed_work(system_unbound_wq, &shepherd,
		round_jiffies_relative((unsigned long)vm_cache_reclaim_s * HZ));
}

static void shrink_page_work(struct work_struct *w)
{
	page_cache_shrink_memory(node_reclaim_num());
}

static void shrink_shepherd_timer(void)
{
	int i;

	for (i = 0; i < MAX_NUMNODES; i++)
		INIT_WORK(&vmscan_works[i], shrink_page_work);
}

static int __init shrink_page_init(void)
{
	if (!register_sysctl_table(limit_dir_table)) {
		pr_err("register page cache limit sysctl failed.");
		return -ENOMEM;
	}

	shrink_shepherd_timer();

	return 0;
}
late_initcall(shrink_page_init)
