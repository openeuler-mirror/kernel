// SPDX-License-Identifier: GPL-2.0
/*
 * Support for periodic memory reclaim and page cache limit
 */

#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>

#include "internal.h"

static int vm_cache_reclaim_s __read_mostly;
static int vm_cache_reclaim_s_max = 43200;
static int vm_cache_reclaim_weight __read_mostly = 1;
static int vm_cache_reclaim_weight_max = 100;
static int vm_cache_reclaim_enable = 1;
static unsigned long vm_cache_limit_mbytes __read_mostly;

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

static bool page_cache_over_limit(void)
{
	unsigned long lru_file;
	unsigned long limit;

	limit = vm_cache_limit_mbytes << (20 - PAGE_SHIFT);
	lru_file = global_node_page_state(NR_ACTIVE_FILE) +
			global_node_page_state(NR_INACTIVE_FILE);
	if (lru_file > limit)
		return true;

	return false;
}

static bool should_reclaim_page_cache(void)
{
	if (!should_periodical_reclaim())
		return false;

	if (!vm_cache_limit_mbytes)
		return false;

	return true;
}

int cache_reclaim_enable_handler(struct ctl_table *table, int write,
			void *buffer, size_t *length, loff_t *ppos)
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

int cache_reclaim_sysctl_handler(struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
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

int cache_limit_mbytes_sysctl_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *length, loff_t *ppos)
{
	int ret;
	unsigned long vm_cache_limit_mbytes_max;
	unsigned long origin_mbytes = vm_cache_limit_mbytes;
	int nr_retries = MAX_RECLAIM_RETRIES;

	vm_cache_limit_mbytes_max = totalram_pages() >> (20 - PAGE_SHIFT);
	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (ret || !write)
		return ret;

	if (vm_cache_limit_mbytes > vm_cache_limit_mbytes_max) {
		vm_cache_limit_mbytes = origin_mbytes;
		return -EINVAL;
	}

	if (write) {
		while (should_reclaim_page_cache() && page_cache_over_limit() &&
				nr_retries--) {
			if (signal_pending(current))
				return -EINTR;

			shrink_memory(node_reclaim_num(), false);
		}
	}

	return 0;
}

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
	shrink_memory(node_reclaim_num(), true);
}

static void shrink_shepherd_timer(void)
{
	int i;

	for (i = 0; i < MAX_NUMNODES; i++)
		INIT_WORK(&vmscan_works[i], shrink_page_work);
}

static struct ctl_table page_cache_limit_table[] = {
	{
		.procname	= "cache_reclaim_s",
		.data		= &vm_cache_reclaim_s,
		.maxlen		= sizeof(vm_cache_reclaim_s),
		.mode		= 0644,
		.proc_handler	= cache_reclaim_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &vm_cache_reclaim_s_max,
	},
	{
		.procname	= "cache_reclaim_weight",
		.data		= &vm_cache_reclaim_weight,
		.maxlen		= sizeof(vm_cache_reclaim_weight),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= &vm_cache_reclaim_weight_max,
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
	{
		.procname	= "cache_limit_mbytes",
		.data		= &vm_cache_limit_mbytes,
		.maxlen		= sizeof(vm_cache_limit_mbytes),
		.mode		= 0644,
		.proc_handler	= cache_limit_mbytes_sysctl_handler,
	},
};

static int __init shrink_page_init(void)
{
	shrink_shepherd_timer();

	register_sysctl_init("vm", page_cache_limit_table);

	return 0;
}
late_initcall(shrink_page_init)
