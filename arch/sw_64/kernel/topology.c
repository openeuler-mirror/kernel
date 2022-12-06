// SPDX-License-Identifier: GPL-2.0

#include <linux/acpi.h>
#include <linux/of.h>

#include <asm/topology.h>

static int __init parse_dt_topology(void)
{
	return 0;
}

/*
 * cpu topology table
 */
struct cpu_topology cpu_topology[NR_CPUS];
EXPORT_SYMBOL_GPL(cpu_topology);

const struct cpumask *cpu_coregroup_mask(int cpu)
{
	return topology_llc_cpumask(cpu);
}

static void update_siblings_masks(int cpu)
{
	struct cpu_topology *cpu_topo = &cpu_topology[cpu];
	int sib;

	/* update core and thread sibling masks */
	for_each_online_cpu(sib) {
		struct cpu_topology *sib_topo = &cpu_topology[sib];

		if (cpu_topo->llc_id == sib_topo->llc_id) {
			cpumask_set_cpu(cpu, &sib_topo->llc_sibling);
			cpumask_set_cpu(sib, &cpu_topo->llc_sibling);
		}

		if (cpu_topo->package_id == sib_topo->package_id) {
			cpumask_set_cpu(cpu, &sib_topo->core_sibling);
			cpumask_set_cpu(sib, &cpu_topo->core_sibling);
		}

		if (cpu_topo->core_id == sib_topo->core_id) {
			cpumask_set_cpu(cpu, &sib_topo->thread_sibling);
			cpumask_set_cpu(sib, &cpu_topo->thread_sibling);
		}
	}
}

void store_cpu_topology(int cpu)
{
	struct cpu_topology *cpu_topo = &cpu_topology[cpu];

	if (cpu_topo->package_id != -1)
		goto topology_populated;

	cpu_topo->package_id = rcid_to_package(cpu_to_rcid(cpu));
	cpu_topo->core_id = cpu_to_rcid(cpu) & CORE_ID_MASK;
	cpu_topo->thread_id = (cpu_to_rcid(cpu) >> THREAD_ID_SHIFT) & THREAD_ID_MASK;
	cpu_topo->llc_id = rcid_to_package(cpu_to_rcid(cpu));

	pr_debug("CPU%u: socket %d core %d thread %d llc %d\n",
		 cpu, cpu_topo->package_id, cpu_topo->core_id,
		 cpu_topo->thread_id, cpu_topo->llc_id);

topology_populated:
	update_siblings_masks(cpu);
}

static void clear_cpu_topology(int cpu)
{
	struct cpu_topology *cpu_topo = &cpu_topology[cpu];

	cpumask_clear(&cpu_topo->llc_sibling);
	cpumask_set_cpu(cpu, &cpu_topo->llc_sibling);

	cpumask_clear(&cpu_topo->core_sibling);
	cpumask_set_cpu(cpu, &cpu_topo->core_sibling);
	cpumask_clear(&cpu_topo->thread_sibling);
	cpumask_set_cpu(cpu, &cpu_topo->thread_sibling);
}

static void __init reset_cpu_topology(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct cpu_topology *cpu_topo = &cpu_topology[cpu];

		cpu_topo->thread_id = -1;
		cpu_topo->core_id = 0;
		cpu_topo->package_id = -1;
		cpu_topo->llc_id = -1;

		clear_cpu_topology(cpu);
	}
}

void remove_cpu_topology(int cpu)
{
	int sibling;

	for_each_cpu(sibling, topology_core_cpumask(cpu))
		cpumask_clear_cpu(cpu, topology_core_cpumask(sibling));
	for_each_cpu(sibling, topology_sibling_cpumask(cpu))
		cpumask_clear_cpu(cpu, topology_sibling_cpumask(sibling));
	for_each_cpu(sibling, topology_llc_cpumask(cpu))
		cpumask_clear_cpu(cpu, topology_llc_cpumask(sibling));

	clear_cpu_topology(cpu);
}

#ifdef CONFIG_ACPI
static int __init parse_acpi_topology(void)
{
	return 0;
}
#else
static inline int __init parse_acpi_topology(void)
{
	return -EINVAL;
}
#endif

void __init init_cpu_topology(void)
{
	reset_cpu_topology();

	/*
	 * Discard anything that was parsed if we hit an error so we
	 * don't use partial information.
	 */
	if (!acpi_disabled && parse_acpi_topology())
		reset_cpu_topology();
	else if (of_have_populated_dt() && parse_dt_topology())
		reset_cpu_topology();
}
