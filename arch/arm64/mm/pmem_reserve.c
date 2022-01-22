// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "pmem_reserve: " fmt

#include <linux/memblock.h>
#include <linux/ioport.h>
#include <linux/types.h>

#define MAX_REGIONS 8
static int pmem_res_cnt;
struct resource pmem_res[MAX_REGIONS];

void __init setup_reserve_pmem(u64 start, u64 size)
{
	if (pmem_res_cnt >= MAX_REGIONS) {
		pr_err("protected memory regions above upper limit %d\n", MAX_REGIONS);
		return;
	}

	pmem_res[pmem_res_cnt].start = start;
	pmem_res[pmem_res_cnt].end = start + size - 1;
	pmem_res_cnt++;
}

void __init request_pmem_res_resource(void)
{
	struct resource *res;
	int i;

	for (i = 0; i < pmem_res_cnt; i++) {
		res = &pmem_res[i];
		res->name = "Persistent Memory (legacy)";
		res->flags = IORESOURCE_MEM;
		res->desc = IORES_DESC_PERSISTENT_MEMORY_LEGACY;
		if (res->start && res->end)
			request_resource(&iomem_resource, res);
	}
}

void __init reserve_pmem(void)
{
	struct resource *res;
	phys_addr_t size;
	int i;

	for (i = 0; i < pmem_res_cnt; i++) {
		res = &pmem_res[i];
		size = res->end - res->start;
		if (!memblock_is_region_memory(res->start, size)) {
			pr_warn("region[%pa-%pa] is not in memory\n",
				&res->start, &res->end);
			res->start = res->end = 0;
			continue;
		}

		if (memblock_is_region_reserved(res->start, size)) {
			pr_warn("region[%pa-%pa] overlaps reserved memory\n",
				&res->start, &res->end);
			res->start = res->end = 0;
			continue;
		}

		memblock_remove(res->start, size);
		pr_info("region %d: [%pa-%pa] (%lluMB)\n", i, &res->start, &res->end, size >> 20);
	}
}
