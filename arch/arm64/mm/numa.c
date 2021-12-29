// SPDX-License-Identifier: GPL-2.0-only
/*
 * NUMA support, based on the x86 implementation.
 *
 * Copyright (C) 2015 Cavium Inc.
 * Author: Ganapatrao Kulkarni <gkulkarni@cavium.com>
 */

#define pr_fmt(fmt) "NUMA: " fmt

#include <linux/acpi.h>
#include <linux/memblock.h>
#include <linux/module.h>
#include <linux/of.h>

#include <asm/acpi.h>
#include <asm/sections.h>

struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
EXPORT_SYMBOL(node_data);
nodemask_t numa_nodes_parsed __initdata;
static int cpu_to_node_map[NR_CPUS] = { [0 ... NR_CPUS-1] = NUMA_NO_NODE };

static int numa_distance_cnt;
static u8 *numa_distance;
bool numa_off;

#ifdef CONFIG_COHERENT_DEVICE
nodemask_t __cacheline_aligned cdmmask;

inline int arch_check_node_cdm(int nid)
{
	return node_isset(nid, cdmmask);
}

#ifdef CONFIG_ASCEND_CLEAN_CDM

#define MAX_PARTATION_COUNT 8
#define MAX_CDM_PER_PATRATION 8

/*
 * Here we provide a way to precisely specify the target node to which we want
 * to move the kernel structrue for a cdm node, instead of guessing the hardware
 * topologies. Even the node isn't a cdm node, the movement could be reasonable.
 * Suppose a node is designed to be used only by some certern processes and
 * devices, the kernel structure of that node could be overwritten by a broken
 * process.
 *
 * A possible configure in bootargs:
 *            cdm_move_map=0,2,3,6;1,4,5,7
 * That means to move the kernel structure for node 2,3,6 to node 0 and kernel
 * structure for node 4,5,7 to node 1.
 */
static bool cdm_to_ddr_hardcode = true;
static int cdm_to_ddr_map[MAX_PARTATION_COUNT][MAX_CDM_PER_PATRATION + 1];

static int __init cdm_to_ddr_parse_param(char *str)
{
	int i, j;
	char *p, *n;

	cdm_to_ddr_hardcode = false;
	for (i = 0; i < MAX_PARTATION_COUNT; i++)
		for (j = 0; j < MAX_CDM_PER_PATRATION + 1; j++)
			cdm_to_ddr_map[i][j] = -1;

	for (p = n = str, i = 0; strsep(&p, ";"); i++, n = p) {
		char *s = n;

		for (j = 0; strsep(&n, ","); j++, s = n) {
			int err;
			unsigned long long nid;

			if (j >= MAX_CDM_PER_PATRATION + 1) {
				pr_warn("the cdm nodes in this partation is more than supported\n");
				break;
			}

			err = kstrtoull(s, 0, &nid);
			if (err) {
				pr_err("bootargs for cdm_move_map invalid, %d\n",
					err);
				return err;
			}

			cdm_to_ddr_map[i][j] = (int)nid;
			if (j > 0)
				pr_info("node %d moved to node %d\n",
					cdm_to_ddr_map[i][j],
					cdm_to_ddr_map[i][0]);
		}
	}

	return 0;
}
early_param("cdm_move_map", cdm_to_ddr_parse_param);

static int __init cdm_node_to_ddr_node_mapped(int nid)
{
	int i, j;

	for (i = 0; i < MAX_PARTATION_COUNT; i++) {
		if (cdm_to_ddr_map[i][0] == -1)
			break;
		for (j = 1; j < MAX_CDM_PER_PATRATION + 1; j++) {
			if (cdm_to_ddr_map[i][j] == -1)
				break;
			else if (cdm_to_ddr_map[i][j] == nid)
				return cdm_to_ddr_map[i][0];
		}
	}

	return nid;
}

/**
 * cdm_node_to_ddr_node - Convert the cdm node to the ddr node of the
 *                        same partion.
 * @nid: input node ID
 *
 * Here is a typical memory topology in usage.
 * There are some DDR and HBM in each partion and DDRs present at first, then
 * come all the HBMs of the first partion, then HBMs of the second partion, etc.
 *
 * -------------------------
 * |   P0      |    P1     |
 * ----------- | -----------
 * |node0 DDR| | |node1 DDR|
 * |---------- | ----------|
 * |node2 HBM| | |node4 HBM|
 * |---------- | ----------|
 * |node3 HBM| | |node5 HBM|
 * |---------- | ----------|
 * |   ...   | | |   ...   |
 * |---------- | ----------|
 *
 * Return:
 * This function returns a ddr node which is of the same partion with the input
 * node if the input node is a HBM node.
 * The input nid is returned if it is a DDR node or if the memory topology of
 * the system doesn't apply to the above model.
 */
int __init cdm_node_to_ddr_node(int nid)
{
	nodemask_t ddr_mask;
	int nr_ddr, cdm_per_part, fake_nid;
	int nr_cdm = nodes_weight(cdmmask);
	/*
	 * Specify the count of hbm nodes whoes management structrue would be
	 * moved. Here number 2 is a magic and we should make it configable
	 * for extending
	 */
	int hbm_per_part = 2;

	if (!cdm_to_ddr_hardcode)
		return cdm_node_to_ddr_node_mapped(nid);

	if (!nr_cdm || nodes_empty(numa_nodes_parsed))
		return nid;

	if (!node_isset(nid, cdmmask))
		return nid;

	nodes_xor(ddr_mask, cdmmask, numa_nodes_parsed);
	nr_ddr = nodes_weight(ddr_mask);
	cdm_per_part = nr_cdm / nr_ddr;

	if (cdm_per_part == 0 || nid < nr_ddr ||
			nid >= (hbm_per_part + 1) * nr_ddr)
		/* our assumption has borken, just return the original nid. */
		return nid;

	fake_nid = (nid - nr_ddr) / hbm_per_part;
	fake_nid = !node_isset(fake_nid, cdmmask) ? fake_nid : nid;

	pr_info("nid: %d, fake_nid: %d\n", nid, fake_nid);

	return fake_nid;
}
#endif

static int __init cdm_nodes_setup(char *s)
{
	int nid;
	unsigned long tmpmask;
	int err;

	err = kstrtoul(s, 0, &tmpmask);
	if (err)
		return err;

	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		if ((tmpmask >> nid) & 1)
			node_set(nid, cdmmask);
	}
	return 0;
}
early_param("cdm-nodes", cdm_nodes_setup);
#endif

static __init int numa_parse_early_param(char *opt)
{
	if (!opt)
		return -EINVAL;
	if (str_has_prefix(opt, "off"))
		numa_off = true;

	return 0;
}
early_param("numa", numa_parse_early_param);

cpumask_var_t node_to_cpumask_map[MAX_NUMNODES];
EXPORT_SYMBOL(node_to_cpumask_map);

#ifdef CONFIG_DEBUG_PER_CPU_MAPS

/*
 * Returns a pointer to the bitmask of CPUs on Node 'node'.
 */
const struct cpumask *cpumask_of_node(int node)
{

	if (node == NUMA_NO_NODE)
		return cpu_all_mask;

	if (WARN_ON(node < 0 || node >= nr_node_ids))
		return cpu_none_mask;

	if (WARN_ON(node_to_cpumask_map[node] == NULL))
		return cpu_online_mask;

	return node_to_cpumask_map[node];
}
EXPORT_SYMBOL(cpumask_of_node);

#endif

static void numa_update_cpu(unsigned int cpu, bool remove)
{
	int nid = cpu_to_node(cpu);

	if (nid == NUMA_NO_NODE)
		return;

	if (remove)
		cpumask_clear_cpu(cpu, node_to_cpumask_map[nid]);
	else
		cpumask_set_cpu(cpu, node_to_cpumask_map[nid]);
}

void numa_add_cpu(unsigned int cpu)
{
	numa_update_cpu(cpu, false);
}

void numa_remove_cpu(unsigned int cpu)
{
	numa_update_cpu(cpu, true);
}

void numa_clear_node(unsigned int cpu)
{
	numa_remove_cpu(cpu);
	set_cpu_numa_node(cpu, NUMA_NO_NODE);
}

/*
 * Allocate node_to_cpumask_map based on number of available nodes
 * Requires node_possible_map to be valid.
 *
 * Note: cpumask_of_node() is not valid until after this is done.
 * (Use CONFIG_DEBUG_PER_CPU_MAPS to check this.)
 */
static void __init setup_node_to_cpumask_map(void)
{
	int node;

	/* setup nr_node_ids if not done yet */
	if (nr_node_ids == MAX_NUMNODES)
		setup_nr_node_ids();

	/* allocate and clear the mapping */
	for (node = 0; node < nr_node_ids; node++) {
		alloc_bootmem_cpumask_var(&node_to_cpumask_map[node]);
		cpumask_clear(node_to_cpumask_map[node]);
	}

	/* cpumask_of_node() will now work */
	pr_debug("Node to cpumask map for %u nodes\n", nr_node_ids);
}

/*
 * Set the cpu to node and mem mapping
 */
void numa_store_cpu_info(unsigned int cpu)
{
	set_cpu_numa_node(cpu, cpu_to_node_map[cpu]);
}

void __init early_map_cpu_to_node(unsigned int cpu, int nid)
{
	/* fallback to node 0 */
	if (nid < 0 || nid >= MAX_NUMNODES || numa_off)
		nid = 0;

	cpu_to_node_map[cpu] = nid;

	/*
	 * We should set the numa node of cpu0 as soon as possible, because it
	 * has already been set up online before. cpu_to_node(0) will soon be
	 * called.
	 */
	if (!cpu)
		set_cpu_numa_node(cpu, nid);
}

#ifdef CONFIG_HAVE_SETUP_PER_CPU_AREA
unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(__per_cpu_offset);

static int __init early_cpu_to_node(int cpu)
{
	return cpu_to_node_map[cpu];
}

static int __init pcpu_cpu_distance(unsigned int from, unsigned int to)
{
	return node_distance(early_cpu_to_node(from), early_cpu_to_node(to));
}

static void * __init pcpu_fc_alloc(unsigned int cpu, size_t size,
				       size_t align)
{
	int nid = early_cpu_to_node(cpu);

	return  memblock_alloc_try_nid(size, align,
			__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, nid);
}

static void __init pcpu_fc_free(void *ptr, size_t size)
{
	memblock_free_early(__pa(ptr), size);
}

void __init setup_per_cpu_areas(void)
{
	unsigned long delta;
	unsigned int cpu;
	int rc;

	/*
	 * Always reserve area for module percpu variables.  That's
	 * what the legacy allocator did.
	 */
	rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
				    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
				    pcpu_cpu_distance,
				    pcpu_fc_alloc, pcpu_fc_free);
	if (rc < 0)
		panic("Failed to initialize percpu areas.");

	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu)
		__per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];
}
#endif

/**
 * numa_add_memblk() - Set node id to memblk
 * @nid: NUMA node ID of the new memblk
 * @start: Start address of the new memblk
 * @end:  End address of the new memblk
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int __init numa_add_memblk(int nid, u64 start, u64 end)
{
	int ret;

	ret = memblock_set_node(start, (end - start), &memblock.memory, nid);
	if (ret < 0) {
		pr_err("memblock [0x%llx - 0x%llx] failed to add on node %d\n",
			start, (end - 1), nid);
		return ret;
	}

	node_set(nid, numa_nodes_parsed);
	return ret;
}

/*
 * Initialize NODE_DATA for a node on the local memory
 */
static void __init setup_node_data(int nid, u64 start_pfn, u64 end_pfn)
{
	const size_t nd_size = roundup(sizeof(pg_data_t), SMP_CACHE_BYTES);
	u64 nd_pa;
	void *nd;
	int tnid;
	int fake_nid = cdm_node_to_ddr_node(nid);

	if (start_pfn >= end_pfn)
		pr_info("Initmem setup node %d [<memory-less node>]\n", nid);

	nd_pa = memblock_phys_alloc_try_nid(nd_size, SMP_CACHE_BYTES, fake_nid);
	if (!nd_pa)
		panic("Cannot allocate %zu bytes for node %d data\n",
		      nd_size, nid);

	nd = __va(nd_pa);

	/* report and initialize */
	pr_info("NODE_DATA [mem %#010Lx-%#010Lx]\n",
		nd_pa, nd_pa + nd_size - 1);
	tnid = early_pfn_to_nid(nd_pa >> PAGE_SHIFT);
	if (tnid != nid)
		pr_info("NODE_DATA(%d) on node %d\n", nid, tnid);

	node_data[nid] = nd;
	memset(NODE_DATA(nid), 0, sizeof(pg_data_t));
	NODE_DATA(nid)->node_id = nid;
	NODE_DATA(nid)->node_start_pfn = start_pfn;
	NODE_DATA(nid)->node_spanned_pages = end_pfn - start_pfn;
}

/*
 * numa_free_distance
 *
 * The current table is freed.
 */
void __init numa_free_distance(void)
{
	size_t size;

	if (!numa_distance)
		return;

	size = numa_distance_cnt * numa_distance_cnt *
		sizeof(numa_distance[0]);

	memblock_free(__pa(numa_distance), size);
	numa_distance_cnt = 0;
	numa_distance = NULL;
}

/*
 * Create a new NUMA distance table.
 */
static int __init numa_alloc_distance(void)
{
	size_t size;
	u64 phys;
	int i, j;

	size = nr_node_ids * nr_node_ids * sizeof(numa_distance[0]);
	phys = memblock_find_in_range(0, PFN_PHYS(max_pfn),
				      size, PAGE_SIZE);
	if (WARN_ON(!phys))
		return -ENOMEM;

	memblock_reserve(phys, size);

	numa_distance = __va(phys);
	numa_distance_cnt = nr_node_ids;

	/* fill with the default distances */
	for (i = 0; i < numa_distance_cnt; i++)
		for (j = 0; j < numa_distance_cnt; j++)
			numa_distance[i * numa_distance_cnt + j] = i == j ?
				LOCAL_DISTANCE : REMOTE_DISTANCE;

	pr_debug("Initialized distance table, cnt=%d\n", numa_distance_cnt);

	return 0;
}

/**
 * numa_set_distance() - Set inter node NUMA distance from node to node.
 * @from: the 'from' node to set distance
 * @to: the 'to'  node to set distance
 * @distance: NUMA distance
 *
 * Set the distance from node @from to @to to @distance.
 * If distance table doesn't exist, a warning is printed.
 *
 * If @from or @to is higher than the highest known node or lower than zero
 * or @distance doesn't make sense, the call is ignored.
 */
void __init numa_set_distance(int from, int to, int distance)
{
	if (!numa_distance) {
		pr_warn_once("Warning: distance table not allocated yet\n");
		return;
	}

	if (from >= numa_distance_cnt || to >= numa_distance_cnt ||
			from < 0 || to < 0) {
		pr_warn_once("Warning: node ids are out of bound, from=%d to=%d distance=%d\n",
			    from, to, distance);
		return;
	}

	if ((u8)distance != distance ||
	    (from == to && distance != LOCAL_DISTANCE)) {
		pr_warn_once("Warning: invalid distance parameter, from=%d to=%d distance=%d\n",
			     from, to, distance);
		return;
	}

	numa_distance[from * numa_distance_cnt + to] = distance;
}

/*
 * Return NUMA distance @from to @to
 */
int __node_distance(int from, int to)
{
	if (from >= numa_distance_cnt || to >= numa_distance_cnt)
		return from == to ? LOCAL_DISTANCE : REMOTE_DISTANCE;
	return numa_distance[from * numa_distance_cnt + to];
}
EXPORT_SYMBOL(__node_distance);

static int __init numa_register_nodes(void)
{
	int nid;
	struct memblock_region *mblk;

	/* Check that valid nid is set to memblks */
	for_each_mem_region(mblk) {
		int mblk_nid = memblock_get_region_node(mblk);

		if (mblk_nid == NUMA_NO_NODE || mblk_nid >= MAX_NUMNODES) {
			pr_warn("Warning: invalid memblk node %d [mem %#010Lx-%#010Lx]\n",
				mblk_nid, mblk->base,
				mblk->base + mblk->size - 1);
			return -EINVAL;
		}
	}

	/* Finally register nodes. */
	for_each_node_mask(nid, numa_nodes_parsed) {
		unsigned long start_pfn, end_pfn;

		get_pfn_range_for_nid(nid, &start_pfn, &end_pfn);
		setup_node_data(nid, start_pfn, end_pfn);
		node_set_online(nid);
	}

	/* Setup online nodes to actual nodes*/
	node_possible_map = numa_nodes_parsed;

	return 0;
}

static int __init numa_init(int (*init_func)(void))
{
	int ret;

	nodes_clear(numa_nodes_parsed);
	nodes_clear(node_possible_map);
	nodes_clear(node_online_map);

	ret = numa_alloc_distance();
	if (ret < 0)
		return ret;

	ret = init_func();
	if (ret < 0)
		goto out_free_distance;

	if (nodes_empty(numa_nodes_parsed)) {
		pr_info("No NUMA configuration found\n");
		ret = -EINVAL;
		goto out_free_distance;
	}

	ret = numa_register_nodes();
	if (ret < 0)
		goto out_free_distance;

	setup_node_to_cpumask_map();

	return 0;
out_free_distance:
	numa_free_distance();
	return ret;
}

/**
 * dummy_numa_init() - Fallback dummy NUMA init
 *
 * Used if there's no underlying NUMA architecture, NUMA initialization
 * fails, or NUMA is disabled on the command line.
 *
 * Must online at least one node (node 0) and add memory blocks that cover all
 * allowed memory. It is unlikely that this function fails.
 *
 * Return: 0 on success, -errno on failure.
 */
static int __init dummy_numa_init(void)
{
	phys_addr_t start = memblock_start_of_DRAM();
	phys_addr_t end = memblock_end_of_DRAM();
	int ret;

	if (numa_off)
		pr_info("NUMA disabled\n"); /* Forced off on command line. */
	pr_info("Faking a node at [mem %#018Lx-%#018Lx]\n", start, end - 1);

	ret = numa_add_memblk(0, start, end);
	if (ret) {
		pr_err("NUMA init failed\n");
		return ret;
	}

	numa_off = true;
	return 0;
}

/**
 * arm64_numa_init() - Initialize NUMA
 *
 * Try each configured NUMA initialization method until one succeeds. The
 * last fallback is dummy single node config encompassing whole memory.
 */
void __init arm64_numa_init(void)
{
	if (!numa_off) {
		if (!acpi_disabled && !numa_init(arm64_acpi_numa_init))
			return;
		if (acpi_disabled && !numa_init(of_numa_init))
			return;
	}

	numa_init(dummy_numa_init);
}
