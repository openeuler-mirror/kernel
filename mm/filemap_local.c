// SPDX-License-Identifier: GPL-2.0-only
/*
 * PageCache locally allocation policy.
 *
 * Copyright (C) 2026- Huawei, Inc.
 * Author:
 * Cunshu Ni	<nicunshu@huawei.com>
 * Chuan Zheng	<zhengchuan@huawei.com>
 *
 */
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/cpuset.h>
#include <linux/hugetlb.h>
#include <linux/pgalloc.h>
#include <asm/tlbflush.h>
#include "internal.h"

static int sysctl_filemap_alloc_local __read_mostly;

/**
 * numa_is_standard_node - check if the input node has any cpus
 * @nid: NUMA node ID
 *
 * return: if nid is valid and there are cpu associated with this node,
 * return true, else return false.
 */
bool numa_is_standard_node(int nid)
{
	/* check if the nid is valid */
	if (nid < 0 || nid >= nr_node_ids || !node_online(nid))
		return false;

	return !cpumask_empty(cpumask_of_node(nid));
}

/*
 * Get the mask of local nodes (non-cpuless) within current->mems_allowed.
 * This ensures we only allocate pagecache on nodes that are:
 * 1. Allowed by cpuset (mems_allowed)
 * 2. Not marked as cpuless nodes
 */
static nodemask_t filemap_local_nodes_mask(void)
{
	nodemask_t mask = NODE_MASK_NONE;
	int node;

	for_each_node_mask(node, current->mems_allowed) {
		if (numa_is_standard_node(node))
			node_set(node, mask);
	}

	return mask;
}

/*
 * Get the next local node for pagecache allocation using cpuset's rotor.
 * Reuses current->cpuset_mem_spread_rotor but restricts it to local nodes only.
 */
static int filemap_local_rotor_node(nodemask_t *local_nodes)
{
	int n;
	int *rotor = &current->cpuset_mem_spread_rotor;

	/* Initialize rotor if needed */
	if (*rotor == NUMA_NO_NODE)
		*rotor = node_random(local_nodes);

	/*
	 * If rotor points to a cpuless node,
	 * find the next local node in round-robin order.
	 */
	if (!node_isset(*rotor, *local_nodes))
		*rotor = next_node_in(*rotor, *local_nodes);

	n = *rotor;
	*rotor = next_node_in(n, *local_nodes);

	return n;
}

static struct folio *filemap_alloc_folio_local(gfp_t gfp, unsigned int order)
{
	unsigned int mems_cookie;
	struct folio *folio;

	do {
		nodemask_t local_nodes;
		int n;

		mems_cookie = read_mems_allowed_begin();
		local_nodes = filemap_local_nodes_mask();

		/* No non-cpuless nodes available, fallback to current numa */
		if (nodes_empty(local_nodes))
			node_set(numa_node_id(), local_nodes);

		n = filemap_local_rotor_node(&local_nodes);
		folio = __folio_alloc(gfp, order, n, &local_nodes);

	} while (!folio && read_mems_allowed_retry(mems_cookie));

	return folio;
}


/**
 * folio_alloc_local - Allocate a folio on local NUMA nodes only.
 * @gfp: GFP flags.
 * @order: Order of the folio allocation.
 *
 * Allocate a folio according to the current task's NUMA mempolicy, but
 * restrict allocations to standard NUMA nodes only, excluding cpuless NUMA nodes.
 * This is a convenience wrapper around __alloc_pages_mpol_local() that
 * handles the page to folio conversion.
 *
 * Return: The folio on success or NULL if allocation fails.
 */
struct folio *folio_alloc_local(gfp_t gfp, unsigned int order)
{
	struct mempolicy *pol = get_task_policy(current);
	struct page *page;

	page = __alloc_pages_mpol_local(gfp | __GFP_COMP, order, pol,
			NO_INTERLEAVE_INDEX, numa_node_id());
	return page_rmappable_folio(page);
}


bool filemap_alloc_local_enabled(void)
{
	return sysctl_filemap_alloc_local;
}

struct folio *filemap_try_alloc_local(gfp_t gfp, unsigned int order)
{
	if (cpuset_do_page_mem_spread())
		return filemap_alloc_folio_local(gfp, order);

	return folio_alloc_local(gfp, order);
}
EXPORT_SYMBOL(filemap_try_alloc_local);

#ifdef CONFIG_SYSCTL
static struct ctl_table local_filemap_sysctl_table[] = {
	{
		.procname	= "filemap_alloc_local",
		.data		= &sysctl_filemap_alloc_local,
		.maxlen		= sizeof(sysctl_filemap_alloc_local),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
};

int __init local_filemap_sysctl_init(void)
{
	register_sysctl_init("vm", local_filemap_sysctl_table);
	return 0;
}
late_initcall(local_filemap_sysctl_init);
#endif
