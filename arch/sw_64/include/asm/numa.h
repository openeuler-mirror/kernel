/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_SW64_NUMA_H
#define _ASM_SW64_NUMA_H

#include <linux/nodemask.h>
#include <asm/memory.h>

#ifdef CONFIG_NUMA
extern nodemask_t numa_nodes_parsed __initdata;
struct numa_memblk {
	u64			start;
	u64			end;
	int			nid;
};

#define NR_NODE_MEMBLKS		(MAX_NUMNODES*2)
struct numa_meminfo {
	int			nr_blks;
	struct numa_memblk	blk[NR_NODE_MEMBLKS];
};
extern int __init numa_add_memblk(int nodeid, u64 start, u64 end);
extern s16 __cpuid_to_node[CONFIG_NR_CPUS];
static inline void numa_clear_node(int cpu)
{
}

static inline void  set_cpuid_to_node(int cpuid, s16 node)
{
	__cpuid_to_node[cpuid] = node;
}

#endif /* CONFIG_NUMA */

#endif /* _ASM_SW64_NUMA_H */
