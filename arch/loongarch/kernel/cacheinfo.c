// SPDX-License-Identifier: GPL-2.0-only
/*
 * LoongArch cacheinfo support
 *
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/cacheinfo.h>
#include <linux/of.h>
#include <asm/bootinfo.h>
#include <asm/cpu-info.h>

int init_cache_level(unsigned int cpu)
{
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	unsigned int cache_present = current_cpu_data.cache_leaves_present;
	this_cpu_ci->num_levels =
		current_cpu_data.cache_leaves[cache_present - 1].level;
	this_cpu_ci->num_leaves = cache_present;
	return 0;
}

static inline bool cache_leaves_are_shared(struct cacheinfo *this_leaf,
					struct cacheinfo *sib_leaf)
{
	return (!(*(unsigned char *)(this_leaf->priv) & CACHE_PRIVATE) &&
		!(*(unsigned char *)(sib_leaf->priv) & CACHE_PRIVATE));
}

static void __cache_cpumap_setup(unsigned int cpu)
{
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	struct cacheinfo *this_leaf, *sib_leaf;
	unsigned int index;

	for (index = 0; index < this_cpu_ci->num_leaves; index++) {
		unsigned int i;

		this_leaf = this_cpu_ci->info_list + index;
		/* skip if shared_cpu_map is already populated */
		if (!cpumask_empty(&this_leaf->shared_cpu_map))
			continue;

		cpumask_set_cpu(cpu, &this_leaf->shared_cpu_map);
		for_each_online_cpu(i) {
			struct cpu_cacheinfo *sib_cpu_ci = get_cpu_cacheinfo(i);

			/* skip if itself or no cacheinfo or not in one
			 * physical node. */
			if (i == cpu || !sib_cpu_ci->info_list ||
				(cpu_to_node(i) != cpu_to_node(cpu)))
				continue;
			sib_leaf = sib_cpu_ci->info_list + index;
			if (cache_leaves_are_shared(this_leaf, sib_leaf)) {
				cpumask_set_cpu(cpu, &sib_leaf->shared_cpu_map);
				cpumask_set_cpu(i, &this_leaf->shared_cpu_map);
			}
		}
	}
}

int populate_cache_leaves(unsigned int cpu)
{
	struct cache_desc *cdesc_tmp, *cdesc = current_cpu_data.cache_leaves;
	unsigned int cache_present = current_cpu_data.cache_leaves_present;
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	struct cacheinfo *this_leaf = this_cpu_ci->info_list;
	int i;

	for (i = 0; i < cache_present; i++) {
		cdesc_tmp = cdesc + i;

		this_leaf->type = cdesc_tmp->type;
		this_leaf->level = cdesc_tmp->level;
		this_leaf->coherency_line_size = cdesc_tmp->linesz;
		this_leaf->number_of_sets = cdesc_tmp->sets;
		this_leaf->ways_of_associativity = cdesc_tmp->ways;
		this_leaf->size =
			cdesc_tmp->linesz * cdesc_tmp->sets * cdesc_tmp->ways;
		this_leaf->priv = &cdesc_tmp->flags;
		this_leaf++;
	}

	if (!of_have_populated_dt()) {
		__cache_cpumap_setup(cpu);
		this_cpu_ci->cpu_map_populated = true;
	}

	return 0;
}
