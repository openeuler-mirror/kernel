// SPDX-License-Identifier: GPL-2.0
/*
 * CMA based folio allocation
 *
 * Copyright (C) 2026- Huawei, Inc.
 * Author:
 * Cunshu Ni	<nicunshu@huawei.com>
 * Bin Wang	<wangbin224@huawei.com>
 *
 */

#define pr_fmt(fmt) "cma_folio: " fmt

#include <linux/cma.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/nospec.h>
#include <linux/page_owner.h>
#include <linux/vmstat.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/sysctl.h>

#include "internal.h"

static unsigned long folio_cma_size[MAX_NUMNODES] __ro_after_init;
static struct cma *folio_cma_area[MAX_NUMNODES] __ro_after_init;
static int folio_cma_enabled __ro_after_init;

static int __init early_cma_folio(char *p)
{
	int nid, count = 0;
	unsigned long tmp;
	char *s = p;

	if (!p)
		return 0;

	while (*s) {
		if (sscanf(s, "%lu%n", &tmp, &count) != 1)
			break;

		if (s[count] == ':') {
			if (tmp >= MAX_NUMNODES)
				break;
			nid = array_index_nospec(tmp, MAX_NUMNODES);

			s += count + 1;
			tmp = memparse(s, &s);
			folio_cma_size[nid] = tmp;

			if (*s == ',')
				s++;
			else
				break;
		} else {
			/* Plain size: apply to all online nodes */
			tmp = memparse(p, &p);
			for_each_node(nid)
				folio_cma_size[nid] = tmp;
			break;
		}
	}

	return 0;
}
early_param("folio_cma", early_cma_folio);

void __init folio_cma_reserve(void)
{
	int nid, err;
	char name[CMA_MAX_NAME];

	for_each_online_node(nid) {

		if (!folio_cma_size[nid])
			continue;

		snprintf(name, sizeof(name), "folio_cma%d", nid);

		/* order CONT_PTE is the minimum order expected by cma folio */
		err = cma_declare_contiguous_nid(0, folio_cma_size[nid],
				0, PAGE_SIZE << (CONT_PTE_SHIFT - PAGE_SHIFT),
				(CONT_PTE_SHIFT - PAGE_SHIFT), false, name,
				&folio_cma_area[nid], nid);
		if (err)
			pr_warn("reservation failed: err %d, node %d\n", err, nid);
		else {
			pr_info("reserved %lu MiB on node %d\n",
				folio_cma_size[nid] / SZ_1M, nid);

			if (!folio_cma_enabled)
				folio_cma_enabled = 1;
		}
	}

}

bool use_folio_cma(void)
{
	return folio_cma_enabled;
}

struct folio *folio_alloc_cma(gfp_t gfp, unsigned int order,
			   int preferred_nid, nodemask_t *nodemask)
{
	struct page *page;
	struct folio *folio;
	nodemask_t *nodes;
	int node, nid = preferred_nid;

	if (!folio_cma_enabled)
		return NULL;

	if (order == 0)
		return NULL;

	if (nid == NUMA_NO_NODE)
		nid = numa_mem_id();

	if (folio_cma_area[nid]) {
		page = cma_alloc_compound(folio_cma_area[nid], order);
		if (page)
			goto prep;
	}
	if (nodemask)
		nodes = nodemask;
	else
		nodes = &node_states[N_ONLINE];

	if (!(gfp & __GFP_THISNODE) && nodes) {
		for_each_node_mask(node, *nodes) {
			if (node == nid || !folio_cma_area[node])
				continue;
			page = cma_alloc_compound(folio_cma_area[node], order);
			if (page) {
				pr_debug("allocated order %d from node %d, page %p\n",
					order, node, page);
				goto prep;
			} else
				pr_debug("allocation failed: order %d, node %d\n",
					order, node);
		}
	}

	return NULL;

prep:
	folio = page_rmappable_folio(page);
	folio_set_fcma(folio);

	return folio;
}

void folio_put_cma(struct folio *folio)
{
	struct cma *cma = folio_cma_area[folio_nid(folio)];

	if (WARN_ON_ONCE(!cma)) {
		pr_warn("folio %p is not valid cma folio\n", folio);
		return;
	}

	/*
	 * Must clear PG_fcma before cma_release() so that
	 * free_contig_range()->folio_put()->__folio_put() does NOT
	 * recurse back into folio_put_cma().
	 */
	folio_clear_fcma(folio);

	folio_ref_unfreeze(folio, 1);

	if (!cma_release(cma, &folio->page, folio_nr_pages(folio)))
		pr_warn("cma_release failed for page %p\n", folio);
}
