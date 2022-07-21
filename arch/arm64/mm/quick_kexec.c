// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "quick_kexec: " fmt

#include <linux/memblock.h>
#include <linux/ioport.h>
#include <linux/types.h>
#include <linux/kexec.h>

static int __init parse_quick_kexec(char *p)
{
	if (!p)
		return 0;

	quick_kexec_res.end = PAGE_ALIGN(memparse(p, NULL));

	return 0;
}
early_param("quickkexec", parse_quick_kexec);

void __init reserve_quick_kexec(void)
{
	unsigned long long mem_start, mem_len;

	mem_len = quick_kexec_res.end;
	if (mem_len == 0)
		return;

	/* Current arm64 boot protocol requires 2MB alignment */
	mem_start = memblock_find_in_range(0, arm64_dma_phys_limit,
			mem_len, SZ_2M);
	if (mem_start == 0) {
		pr_warn("cannot allocate quick kexec mem (size:0x%llx)\n",
			mem_len);
		quick_kexec_res.end = 0;
		return;
	}

	memblock_reserve(mem_start, mem_len);
	pr_info("quick kexec mem reserved: 0x%016llx - 0x%016llx (%lld MB)\n",
		mem_start, mem_start + mem_len,	mem_len >> 20);

	quick_kexec_res.start = mem_start;
	quick_kexec_res.end = mem_start + mem_len - 1;
}

void __init request_quick_kexec_res(struct resource *res)
{
	if (quick_kexec_res.end &&
	    quick_kexec_res.start >= res->start &&
	    quick_kexec_res.end <= res->end)
		request_resource(res, &quick_kexec_res);
}
