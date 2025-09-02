// SPDX-License-Identifier: GPL-2.0-only
/*
 * HYGON Memory Encryption Support
 *
 * Copyright (C) 2024 Hygon Info Technologies Ltd.
 *
 * Author: Liyang Han <hanliyang@hygon.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define DISABLE_BRANCH_PROFILING

#include <linux/cc_platform.h>
#include <linux/mem_encrypt.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/cma.h>
#include <linux/minmax.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <asm/io.h>
#include <asm/cacheflush.h>
#include <asm/set_memory.h>
#include <asm/csv.h>
#include <asm/processor-hygon.h>

u32 vendor_ebx __section(".data") = 0;
u32 vendor_ecx __section(".data") = 0;
u32 vendor_edx __section(".data") = 0;

void print_hygon_cc_feature_info(void)
{
	/* Secure Memory Encryption */
	if (cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT)) {
		/*
		 * HYGON SME is mutually exclusive with any of the
		 * HYGON CSV features below.
		 */
		pr_info(" HYGON SME");
		return;
	}

	/* Secure Encrypted Virtualization */
	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		pr_info(" HYGON CSV");

	/* Encrypted Register State */
	if (cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		pr_info(" HYGON CSV2");

	if (csv3_active())
		pr_info(" HYGON CSV3");
}

/*
 * Check whether host supports CSV3 in hygon platform.
 * Called in the guest, it always returns false.
 */
static bool __init __maybe_unused csv3_check_cpu_support(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long me_mask;
	u64 msr;
	bool csv3_enabled;

	if (!is_x86_vendor_hygon())
		return false;

	if (sev_status)
		return false;

	/* Check for the SME/CSV support leaf */
	eax = 0x80000000;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (eax < 0x8000001f)
		return false;

#define HYGON_SME_BIT	BIT(0)
#define HYGON_CSV3_BIT	BIT(30)
	/*
	 * Check for the CSV feature:
	 * CPUID Fn8000_001F[EAX]
	 * - Bit 0  - SME support
	 * - Bit 1  - CSV support
	 * - Bit 3  - CSV2 support
	 * - Bit 30 - CSV3 support
	 */
	eax = 0x8000001f;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(eax & HYGON_SME_BIT))
		return false;

	csv3_enabled = !!(eax & HYGON_CSV3_BIT);

	me_mask = 1UL << (ebx & 0x3f);

	/* No SME if Hypervisor bit is set */
	eax = 1;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (ecx & BIT(31))
		return false;

	/* For SME, check the SYSCFG MSR */
	msr = __rdmsr(MSR_AMD64_SYSCFG);
	if (!(msr & MSR_AMD64_SYSCFG_MEM_ENCRYPT))
		return false;

	return !!me_mask && csv3_enabled;
}

/* csv3_active() indicate whether the guest is protected by CSV3 */
bool csv3_active(void)
{
	if (vendor_ebx == 0 || vendor_ecx == 0 || vendor_edx == 0) {
		u32 eax = 0;

		native_cpuid(&eax, &vendor_ebx, &vendor_ecx, &vendor_edx);
	}

	/* HygonGenuine */
	if (vendor_ebx == CPUID_VENDOR_HygonGenuine_ebx &&
	    vendor_ecx == CPUID_VENDOR_HygonGenuine_ecx &&
	    vendor_edx == CPUID_VENDOR_HygonGenuine_edx)
		return !!(sev_status & MSR_CSV3_ENABLED);
	else
		return false;
}
EXPORT_SYMBOL_GPL(csv3_active);

/******************************************************************************/
/**************************** CSV3 CMA interfaces *****************************/
/******************************************************************************/

/* 0 percent of total memory by default*/
static unsigned char csv_mem_percentage;
static unsigned long csv_mem_size;

static int __init cmdline_parse_csv_mem_size(char *str)
{
	unsigned long size;
	char *endp;

	if (str) {
		size  = memparse(str, &endp);
		csv_mem_size = size;
		if (!csv_mem_size)
			csv_mem_percentage = 0;
	}

	return 0;
}
early_param("csv_mem_size", cmdline_parse_csv_mem_size);

static int __init cmdline_parse_csv_mem_percentage(char *str)
{
	unsigned char percentage;
	int ret;

	if (!str)
		return 0;

	ret  = kstrtou8(str, 10, &percentage);
	if (!ret) {
		csv_mem_percentage = min_t(unsigned char, percentage, 80);
		if (csv_mem_percentage != percentage)
			pr_warn("csv_mem_percentage is limited to 80.\n");
	} else {
		/* Disable CSV CMA. */
		csv_mem_percentage = 0;
		pr_err("csv_mem_percentage is invalid. (0 - 80) is expected.\n");
	}

	return ret;
}
early_param("csv_mem_percentage", cmdline_parse_csv_mem_percentage);

#define NUM_SMR_ENTRIES			(8 * 1024)
#define CSV_CMA_SHIFT			PUD_SHIFT
#define CSV_CMA_SIZE			(1 << CSV_CMA_SHIFT)
#define MIN_SMR_ENTRY_SHIFT		23
#define CSV_SMR_INFO_SIZE		(nr_node_ids * sizeof(struct csv_mem))

struct csv_mem *csv_smr;
EXPORT_SYMBOL_GPL(csv_smr);

unsigned int csv_smr_num;
EXPORT_SYMBOL_GPL(csv_smr_num);

#ifdef CONFIG_SYSFS
/**
 * Global counters exposed via /sys/kernel/mm/csv3_cma/mem_info. Updated
 * atomically during VM creation/destruction.
 *
 * csv3_npt_size: total size of NPT tables allocated.
 * csv3_pri_mem: total private memory allocated for CSV guests.
 * csv3_meta: metadata overhead for CSV memory regions.
 * csv3_shared_mem: size of all the CSV3 VMs' shared memory.
 */
atomic_long_t csv3_npt_size = ATOMIC_LONG_INIT(0);
EXPORT_SYMBOL_GPL(csv3_npt_size);

atomic_long_t csv3_pri_mem = ATOMIC_LONG_INIT(0);
EXPORT_SYMBOL_GPL(csv3_pri_mem);

unsigned long csv3_meta;
EXPORT_SYMBOL_GPL(csv3_meta);

atomic_long_t csv3_shared_mem[MAX_NUMNODES];
EXPORT_SYMBOL_GPL(csv3_shared_mem);
#endif

#ifdef CONFIG_CMA
struct csv_cma {
	int nid;
	int fast;
	struct cma *cma;
};

struct cma_array {
	unsigned long count;
	atomic64_t csv_used_size;
	unsigned int index;
	struct csv_cma csv_cma[];
};

static unsigned int smr_entry_shift;
static struct cma_array *csv_contiguous_pernuma_area[MAX_NUMNODES];

static void csv_set_smr_entry_shift(unsigned int shift)
{
	smr_entry_shift = max_t(unsigned int, shift, MIN_SMR_ENTRY_SHIFT);
	pr_info("CSV-CMA: SMR entry size is 0x%x\n", 1 << smr_entry_shift);
}

unsigned int csv_get_smr_entry_shift(void)
{
	return smr_entry_shift;
}
EXPORT_SYMBOL_GPL(csv_get_smr_entry_shift);

static unsigned long __init present_pages_in_node(int nid)
{
	unsigned long range_start_pfn, range_end_pfn;
	unsigned long nr_present = 0;
	int i;

	for_each_mem_pfn_range(i, nid, &range_start_pfn, &range_end_pfn, NULL)
		nr_present += range_end_pfn - range_start_pfn;

	return nr_present;
}

static phys_addr_t __init csv_early_percent_memory_on_node(int nid)
{
	return (present_pages_in_node(nid) * csv_mem_percentage / 100) << PAGE_SHIFT;
}

static void __init csv_cma_reserve_mem(void)
{
	int node, i;
	unsigned long size;
	int idx = 0;
	int count;
	int cma_array_size;
	unsigned long max_spanned_size = 0;

	csv_smr = memblock_alloc_node(CSV_SMR_INFO_SIZE, SMP_CACHE_BYTES, NUMA_NO_NODE);
	if (!csv_smr) {
		pr_err("CSV-CMA: Fail to allocate csv_smr\n");
		return;
	}

	for_each_node_state(node, N_ONLINE) {
		int ret;
		char name[CMA_MAX_NAME];
		struct cma_array *array;
		unsigned long spanned_size;
		unsigned long start = 0, end = 0;
		struct csv_cma *csv_cma;

		size = csv_early_percent_memory_on_node(node);
		count = DIV_ROUND_UP(size, 1 << CSV_CMA_SHIFT);
		if (!count)
			continue;

		cma_array_size = count * sizeof(*csv_cma) + sizeof(*array);
		array = memblock_alloc_node(cma_array_size, SMP_CACHE_BYTES, NUMA_NO_NODE);
		if (!array) {
			pr_err("CSV-CMA: Fail to allocate cma_array\n");
			continue;
		}

		array->count = 0;
		atomic64_set(&array->csv_used_size, 0);
		array->index = 0;
		csv_contiguous_pernuma_area[node] = array;

		for (i = 0; i < count; i++) {
			csv_cma = &array->csv_cma[i];
			csv_cma->fast = 1;
			csv_cma->nid = node;
			snprintf(name, sizeof(name), "csv-n%dc%d", node, i);
			ret = cma_declare_contiguous_nid(0, CSV_CMA_SIZE, 0,
					1 << CSV_MR_ALIGN_BITS, PMD_SHIFT - PAGE_SHIFT,
					false, name, &(csv_cma->cma), node);
			if (ret) {
				pr_warn("CSV-CMA: Fail to reserve memory size 0x%x node %d\n",
					1 << CSV_CMA_SHIFT, node);
				break;
			}

			if (start > cma_get_base(csv_cma->cma) || !start)
				start = cma_get_base(csv_cma->cma);

			if (end < cma_get_base(csv_cma->cma) + cma_get_size(csv_cma->cma))
				end = cma_get_base(csv_cma->cma) + cma_get_size(csv_cma->cma);
		}

		if (!i)
			continue;

		array->count = i;
		spanned_size = end - start;
		if (spanned_size > max_spanned_size)
			max_spanned_size = spanned_size;

		csv_smr[idx].start = start;
		csv_smr[idx].size  = end - start;
		idx++;

		pr_info("CSV-CMA: Node %d - reserve size 0x%016lx, (expected size 0x%016lx)\n",
			node, (unsigned long)i * CSV_CMA_SIZE, size);
	}

	csv_smr_num = idx;
	WARN_ON((max_spanned_size / NUM_SMR_ENTRIES) < 1);
	if (likely((max_spanned_size / NUM_SMR_ENTRIES) >= 1))
		csv_set_smr_entry_shift(ilog2(max_spanned_size / NUM_SMR_ENTRIES - 1) + 1);
}

#define CSV_CMA_AREAS		2458

void __init early_csv_reserve_mem(void)
{
	unsigned long total_pages;

	/* Only reserve memory on the host that enabled CSV3 feature */
	if (!csv3_check_cpu_support())
		return;

	if (cma_alloc_areas(CSV_CMA_AREAS))
		return;

	total_pages = PHYS_PFN(memblock_phys_mem_size());
	if (csv_mem_size) {
		if (csv_mem_size < (total_pages << PAGE_SHIFT)) {
			csv_mem_percentage = csv_mem_size * 100 / (total_pages << PAGE_SHIFT);
			if (csv_mem_percentage > 80)
				csv_mem_percentage = 80; /* Maximum percentage */
		} else
			csv_mem_percentage = 80; /* Maximum percentage */
	}

	if (!csv_mem_percentage) {
		pr_warn("CSV-CMA: Don't reserve any memory\n");
		return;
	}

	csv_cma_reserve_mem();
}

phys_addr_t csv_alloc_from_contiguous(size_t size, nodemask_t *nodes_allowed,
				      unsigned int align)
{
	int nid;
	int nr_nodes;
	struct page *page = NULL;
	struct cma_array *array = NULL;
	phys_addr_t phys_addr;
	int count;
	struct csv_cma *csv_cma;
	int fast = 1;

	if (!nodes_allowed || size > CSV_CMA_SIZE) {
		pr_err("CSV-CMA: Invalid params, size = 0x%lx, nodes_allowed = %p\n",
			size, nodes_allowed);
		return 0;
	}

	align = min_t(unsigned int, align, get_order(CSV_CMA_SIZE));
retry:
	nr_nodes = nodes_weight(*nodes_allowed);

	/* Traverse from current node */
	nid = numa_node_id();
	if (!node_isset(nid, *nodes_allowed))
		nid = next_node_in(nid, *nodes_allowed);

	for (; nr_nodes > 0; nid = next_node_in(nid, *nodes_allowed), nr_nodes--) {
		array = csv_contiguous_pernuma_area[nid];

		if (!array)
			continue;

		count = array->count;
		while (count) {
			array->index = (array->index + 1) % count;
			csv_cma = &array->csv_cma[array->index];

			/*
			 * The value check of csv_cma->fast is lockless, but
			 * that's ok as this don't affect functional correntness
			 * whatever the value of csv_cma->fast.
			 */
			if (fast && !csv_cma->fast) {
				count--;
				continue;
			}
			page = cma_alloc(csv_cma->cma, PAGE_ALIGN(size) >> PAGE_SHIFT,
							align, true);
			if (page) {
				page->private = (unsigned long)csv_cma;
				if (!csv_cma->fast)
					csv_cma->fast = 1;
				goto success;
			} else
				csv_cma->fast = 0;

			count--;
		}
	}

	if (fast) {
		fast = 0;
		goto retry;
	} else {
		pr_err("CSV-CMA: Fail to alloc secure memory(size = 0x%lx)\n", size);
		return 0;
	}

success:
	atomic64_add(PAGE_ALIGN(size), &array->csv_used_size);
	phys_addr = page_to_phys(page);
	clflush_cache_range(__va(phys_addr), size);

	return phys_addr;
}
EXPORT_SYMBOL_GPL(csv_alloc_from_contiguous);

void csv_release_to_contiguous(phys_addr_t pa, size_t size)
{
	struct csv_cma *csv_cma;
	struct cma_array *array = NULL;
	struct page *page = pfn_to_page(pa >> PAGE_SHIFT);

	WARN_ON(!page);
	if (likely(page)) {
		csv_cma = (struct csv_cma *)page->private;
		WARN_ON(!csv_cma);
		if (likely(csv_cma)) {
			page->private = 0;
			csv_cma->fast = 1;
			cma_release(csv_cma->cma, page, PAGE_ALIGN(size) >> PAGE_SHIFT);
			array = csv_contiguous_pernuma_area[csv_cma->nid];
			atomic64_sub(PAGE_ALIGN(size), &array->csv_used_size);
		}
	}
}
EXPORT_SYMBOL_GPL(csv_release_to_contiguous);

#ifdef CONFIG_SYSFS
/*
 * The "free_size" file where the free size of csv cma is read from.
 */
static ssize_t mem_info_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	int node;
	int offset = 0;
	unsigned long csv_used_size, total_used_size = 0;
	unsigned long csv_size, total_csv_size = 0;
	unsigned long shared_mem, total_shared_mem = 0;
	unsigned long npt_size, pri_mem;
	struct cma_array *array = NULL;
	unsigned long bytes_per_mib = 1024 * 1024;

	for_each_node_state(node, N_ONLINE) {
		array = csv_contiguous_pernuma_area[node];
		if (array == NULL) {
			csv_size = 0;
			csv_used_size = 0;
			shared_mem = 0;

			offset += snprintf(buf + offset, PAGE_SIZE - offset, "Node%d:\n", node);
			offset += snprintf(buf + offset, PAGE_SIZE - offset,
						" csv3 shared size:%10lu MiB\n", shared_mem);
			offset += snprintf(buf + offset, PAGE_SIZE - offset,
						" total cma size:%12lu MiB\n", csv_size);
			offset += snprintf(buf + offset, PAGE_SIZE - offset,
						" csv3 cma used:%13lu MiB\n", csv_used_size);
			continue;
		}

		csv_used_size = DIV_ROUND_UP(atomic64_read(&array->csv_used_size), bytes_per_mib);
		shared_mem = DIV_ROUND_UP(atomic_long_read(&csv3_shared_mem[node]), bytes_per_mib);

		csv_size = DIV_ROUND_UP(array->count * CSV_CMA_SIZE, bytes_per_mib);
		offset += snprintf(buf + offset, PAGE_SIZE - offset, "Node%d:\n", node);
		offset += snprintf(buf + offset, PAGE_SIZE - offset,
					" csv3 shared size:%10lu MiB\n", shared_mem);
		offset += snprintf(buf + offset, PAGE_SIZE - offset,
					" total cma size:%12lu MiB\n", csv_size);
		offset += snprintf(buf + offset, PAGE_SIZE - offset,
					" csv3 cma used:%13lu MiB\n",  csv_used_size);
		total_used_size += csv_used_size;
		total_csv_size += csv_size;
		total_shared_mem += shared_mem;
	}

	npt_size = DIV_ROUND_UP(atomic_long_read(&csv3_npt_size), bytes_per_mib);
	pri_mem = DIV_ROUND_UP(atomic_long_read(&csv3_pri_mem), bytes_per_mib);

	offset += snprintf(buf + offset, PAGE_SIZE - offset, "All Nodes:\n");
	offset += snprintf(buf + offset, PAGE_SIZE - offset,
				" csv3 shared size:%10lu MiB\n", total_shared_mem);
	offset += snprintf(buf + offset, PAGE_SIZE - offset,
				" total cma size:%12lu MiB\n", total_csv_size);
	offset += snprintf(buf + offset, PAGE_SIZE - offset,
				" csv3 cma used:%13lu MiB\n", total_used_size);
	offset += snprintf(buf + offset, PAGE_SIZE - offset,
				"  npt table:%16lu MiB\n", npt_size);
	offset += snprintf(buf + offset, PAGE_SIZE - offset,
				"  csv3 private memory:%6lu MiB\n", pri_mem);
	offset += snprintf(buf + offset, PAGE_SIZE - offset,
				"  meta data:%16lu MiB\n", DIV_ROUND_UP(csv3_meta, bytes_per_mib));

	return offset;
}

static struct kobj_attribute csv_cma_attr = __ATTR(mem_info, 0444,	mem_info_show, NULL);

/*
 * Create a group of attributes so that we can create and destroy them all
 * at once.
 */
static struct attribute *csv_cma_attrs[] = {
	&csv_cma_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static const struct attribute_group csv_cma_attr_group = {
	.attrs = csv_cma_attrs,
};

static struct kobject *csv_cma_kobj_root;

static int __init csv_cma_sysfs_init(void)
{
	int err, i;

	if (!is_x86_vendor_hygon() || !boot_cpu_has(X86_FEATURE_CSV3))
		return 0;

	csv_cma_kobj_root = kobject_create_and_add("csv3_cma", mm_kobj);
	if (!csv_cma_kobj_root)
		return -ENOMEM;

	err = sysfs_create_group(csv_cma_kobj_root, &csv_cma_attr_group);
	if (err)
		goto out;

	for (i = 0; i < MAX_NUMNODES; i++)
		atomic_long_set(&csv3_shared_mem[i], 0);

	return 0;

out:
	kobject_put(csv_cma_kobj_root);
	return err;
}

static void __exit csv_cma_sysfs_exit(void)
{
	if (!is_x86_vendor_hygon() || !boot_cpu_has(X86_FEATURE_CSV3))
		return;

	if (csv_cma_kobj_root != NULL)
		kobject_put(csv_cma_kobj_root);
}

module_init(csv_cma_sysfs_init);
module_exit(csv_cma_sysfs_exit);
#endif /* CONFIG_SYSFS */
#else /* !CONFIG_CMA */

unsigned int csv_get_smr_entry_shift(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(csv_get_smr_entry_shift);

void __init early_csv_reserve_mem(void)
{
	/* Only reserve memory on the host that enabled CSV3 feature */
	if (csv3_check_cpu_support())
		pr_warn("CSV-CMA: CONFIG_CMA=n, memory for CSV3 unavailable!\n");
}

phys_addr_t csv_alloc_from_contiguous(size_t size, nodemask_t *nodes_allowed,
				      unsigned int align)
{
	return 0;
}
EXPORT_SYMBOL_GPL(csv_alloc_from_contiguous);

void csv_release_to_contiguous(phys_addr_t pa, size_t size)
{
}
EXPORT_SYMBOL_GPL(csv_release_to_contiguous);

#endif /* CONFIG_CMA */
