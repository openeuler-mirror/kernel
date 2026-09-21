// SPDX-License-Identifier: GPL-2.0-only
/*
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#include <linux/preempt.h>
#include <linux/smp.h>
#include <linux/memblock.h>
#include <asm/mem_encrypt.h>
#include <asm/csv.h>

#include "../mm/mm_internal.h"
#include "csv-shared.c"

struct secure_call_pages {
	struct csv3_secure_call_cmd page_a;
	struct csv3_secure_call_cmd page_b;
};

static u32 csv3_percpu_secure_call_init __initdata;
static u32 early_secure_call_page_idx __initdata;

static DEFINE_PER_CPU(struct secure_call_pages*, secure_call_data);
static DEFINE_PER_CPU(int, secure_call_page_idx);

typedef void (*csv3_secure_call_func)(u64 base_address, u64 num_pages,
				      enum csv3_secure_command_type cmd_type);

bool cc_platform_has_csv3(void)
{
	return csv3_active();
}
EXPORT_SYMBOL_GPL(cc_platform_has_csv3);

void __init csv_early_reset_memory(struct boot_params *bp)
{
	if (!csv3_active())
		return;

	csv3_scan_secure_call_pages(bp);
	csv3_early_secure_call_ident_map(0, 0, CSV3_SECURE_CMD_RESET);
}

void __init csv_early_update_memory_dec(u64 vaddr, u64 pages)
{
	if (!csv3_active())
		return;

	if (pages)
		csv3_early_secure_call_ident_map(__pa(vaddr), pages,
						 CSV3_SECURE_CMD_DEC);
}

void __init csv_early_update_memory_enc(u64 vaddr, u64 pages)
{
	if (!csv3_active())
		return;

	if (pages)
		csv3_early_secure_call_ident_map(__pa(vaddr), pages,
						 CSV3_SECURE_CMD_ENC);
}

static void __init csv3_alloc_secure_call_data(int cpu)
{
	struct secure_call_pages *data;

	data = memblock_alloc(sizeof(*data), PAGE_SIZE);
	if (!data)
		panic("Can't allocate CSV3 secure all data");

	per_cpu(secure_call_data, cpu) = data;
}

static void __init csv3_secure_call_update_table(void)
{
	int cpu;
	struct secure_call_pages *data;
	struct csv3_secure_call_cmd *page_rd;
	struct csv3_secure_call_cmd *page_wr;
	u32 cmd_ack;

	if (!csv3_active())
		return;

	page_rd = (void *)early_memremap_encrypted(csv3_boot_sc_page_a, PAGE_SIZE);
	page_wr = (void *)early_memremap_encrypted(csv3_boot_sc_page_b, PAGE_SIZE);

	while (1) {
		page_wr->cmd_type = CSV3_SECURE_CMD_UPDATE_SECURE_CALL_TABLE;
		page_wr->nums = 0;

		/* initialize per-cpu secure call pages */
		for_each_possible_cpu(cpu) {
			if (cpu >= SECURE_CALL_ENTRY_MAX)
				panic("csv does not support cpus > %d\n",
				      SECURE_CALL_ENTRY_MAX);
			csv3_alloc_secure_call_data(cpu);
			data = per_cpu(secure_call_data, cpu);
			per_cpu(secure_call_page_idx, cpu) = 0;
			page_wr->entry[cpu].base_address = __pa(data);
			page_wr->entry[cpu].size = PAGE_SIZE * 2;
			page_wr->nums++;
		}

		/*
		 * Write command in page_wr must be done before retrieve cmd
		 * ack from page_rd, and it is ensured by the mb below.
		 */
		mb();

		cmd_ack = page_rd->cmd_type;
		if (cmd_ack != CSV3_SECURE_CMD_UPDATE_SECURE_CALL_TABLE)
			break;
	}

	early_memunmap(page_rd, PAGE_SIZE);
	early_memunmap(page_wr, PAGE_SIZE);
}

/**
 * __csv3_early_secure_call - issue secure call command at the stage where new
 *			kernel page table is created and early identity page
 *			table is deprecated .
 * @base_address:	Start address of the specified memory range.
 * @num_pages:		number of the specific pages.
 * @cmd_type:		Secure call cmd type.
 */
static void __init __csv3_early_secure_call(u64 base_address, u64 num_pages,
					    enum csv3_secure_command_type cmd_type)
{
	struct csv3_secure_call_cmd *page_rd;
	struct csv3_secure_call_cmd *page_wr;
	u32 cmd_ack;

	if (csv3_boot_sc_page_a == -1ul || csv3_boot_sc_page_b == -1ul)
		return;

	if (!csv3_percpu_secure_call_init) {
		csv3_secure_call_update_table();
		csv3_percpu_secure_call_init = 1;
	}

	if (early_secure_call_page_idx == 0) {
		page_rd = (void *)early_memremap_encrypted(csv3_boot_sc_page_a,
							   PAGE_SIZE);
		page_wr = (void *)early_memremap_encrypted(csv3_boot_sc_page_b,
							   PAGE_SIZE);
	} else {
		page_wr = (void *)early_memremap_encrypted(csv3_boot_sc_page_a,
							   PAGE_SIZE);
		page_rd = (void *)early_memremap_encrypted(csv3_boot_sc_page_b,
							   PAGE_SIZE);
	}

	while (1) {
		page_wr->cmd_type = (u32)cmd_type;
		page_wr->nums = 1;
		page_wr->entry[0].base_address = base_address;
		page_wr->entry[0].size = num_pages << PAGE_SHIFT;

		/*
		 * Write command in page_wr must be done before retrieve cmd
		 * ack from page_rd, and it is ensured by the mb below.
		 */
		mb();

		cmd_ack = page_rd->cmd_type;
		if (cmd_ack != cmd_type)
			break;
	}

	early_memunmap(page_rd, PAGE_SIZE);
	early_memunmap(page_wr, PAGE_SIZE);

	early_secure_call_page_idx ^= 1;
}

static void csv3_secure_call(u64 base_address, u64 num_pages,
			     enum csv3_secure_command_type cmd_type)
{
	u32 cmd_ack;
	struct secure_call_pages *data;
	struct csv3_secure_call_cmd *page_rd;
	struct csv3_secure_call_cmd *page_wr;
	int page_idx;
	int cpu;

	preempt_disable();

	cpu = smp_processor_id();
	data = per_cpu(secure_call_data, cpu);
	page_idx = per_cpu(secure_call_page_idx, cpu);

	if (page_idx == 0) {
		page_rd = &data->page_a;
		page_wr = &data->page_b;
	} else {
		page_rd = &data->page_b;
		page_wr = &data->page_a;
	}

	while (1) {
		page_wr->cmd_type = (u32)cmd_type;
		page_wr->nums = 1;
		page_wr->entry[0].base_address = base_address;
		page_wr->entry[0].size = num_pages << PAGE_SHIFT;

		/*
		 * Write command in page_wr must be done before retrieve cmd
		 * ack from page_rd, and it is ensured by the smp_mb below.
		 */
		smp_mb();

		cmd_ack = page_rd->cmd_type;
		if (cmd_ack != cmd_type)
			break;
	}

	per_cpu(secure_call_page_idx, cpu) ^= 1;
	preempt_enable();
}

static void __csv3_memory_enc_dec(csv3_secure_call_func secure_call, u64 vaddr,
				  u64 pages, bool enc)
{
	u64 vaddr_end, vaddr_next;
	u64 psize, pmask;
	u64 last_paddr, paddr;
	u64 last_psize = 0;
	pte_t *kpte;
	int level;
	enum csv3_secure_command_type cmd_type;

	cmd_type = enc ? CSV3_SECURE_CMD_ENC : CSV3_SECURE_CMD_DEC;
	vaddr_next = vaddr;
	vaddr_end = vaddr + (pages << PAGE_SHIFT);
	for (; vaddr < vaddr_end; vaddr = vaddr_next) {
		kpte = lookup_address(vaddr, &level);
		if (!kpte || pte_none(*kpte)) {
			panic("invalid pte, vaddr 0x%llx\n", vaddr);
			goto out;
		}

		psize = page_level_size(level);
		pmask = page_level_mask(level);

		vaddr_next = (vaddr & pmask) + psize;
		paddr = ((pte_pfn(*kpte) << PAGE_SHIFT) & pmask) +
			(vaddr & ~pmask);
		psize -= (vaddr & ~pmask);

		if (vaddr_end - vaddr < psize)
			psize = vaddr_end - vaddr;
		if (last_psize == 0 || (last_paddr + last_psize) == paddr) {
			last_paddr = (last_psize == 0 ? paddr : last_paddr);
			last_psize += psize;
		} else {
			secure_call(last_paddr, last_psize >> PAGE_SHIFT,
				    cmd_type);
			last_paddr = paddr;
			last_psize = psize;
		}
	}

	if (last_psize)
		secure_call(last_paddr, last_psize >> PAGE_SHIFT, cmd_type);

out:
	return;
}

void __init csv_early_memory_enc_dec(u64 vaddr, u64 size, bool enc)
{
	u64 npages;

	if (!csv3_active())
		return;

	npages = (size + (vaddr & ~PAGE_MASK) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	__csv3_memory_enc_dec(__csv3_early_secure_call, vaddr & PAGE_MASK,
			      npages, enc);
}

void csv_memory_enc_dec(u64 vaddr, u64 pages, bool enc)
{
	if (!csv3_active())
		return;

	__csv3_memory_enc_dec(csv3_secure_call, vaddr & PAGE_MASK, pages, enc);
}

static void print_secure_call_error(enum csv3_secure_command_type code)
{
	switch (code) {
	case CSV3_SECURE_CMD_ACK:
		pr_debug("secure call: handled\n");
		break;
	case CSV3_SECURE_CMD_ERROR_INTERNAL:
		pr_err("secure call: internal error\n");
		break;
	case CSV3_SECURE_CMD_ERROR_INVALID_COMMAND:
		pr_err("secure call: unsupported cmd\n");
		break;
	case CSV3_SECURE_CMD_ERROR_INVALID_PARAM:
		pr_err("secure call: invalid param\n");
		break;
	case CSV3_SECURE_CMD_ERROR_INVALID_ADDRESS:
		pr_err("secure call: invalid address\n");
		break;
	case CSV3_SECURE_CMD_ERROR_INVALID_LENGTH:
		pr_err("secure call: invalid length\n");
		break;
	default:
		pr_err("secure call: shouldn't reach here\n");
		break;
	}
}

int csv3_issue_request_report(phys_addr_t paddr, size_t size)
{
	struct secure_call_pages *sc_page_info;
	struct csv3_secure_call_cmd *sc_wr, *sc_rd;
	unsigned long flags;
	int sc_page_idx;
	enum csv3_secure_command_type sc_return_code;

	/*
	 * secure call pages needs to access with IRQs disabled because it is
	 * using a per-CPU data.
	 */
	local_irq_save(flags);

	sc_page_info = this_cpu_read(secure_call_data);
	sc_page_idx = this_cpu_read(secure_call_page_idx);

	sc_wr = sc_page_idx ? &sc_page_info->page_a : &sc_page_info->page_b;
	sc_rd = sc_page_idx ? &sc_page_info->page_b : &sc_page_info->page_a;

	sc_wr->cmd_type = CSV3_SECURE_CMD_REQ_REPORT;
	sc_wr->nums = 1;
	sc_wr->unused = 0;
	sc_wr->entry[0].base_address = (u64)paddr;
	sc_wr->entry[0].size = size;

	/*
	 * Write command in sc_wr must be done before retrieve status code
	 * from sc_rd, and it's ensured by the smp_mb below.
	 */
	smp_mb();

	sc_return_code = sc_rd->cmd_type;

	this_cpu_write(secure_call_page_idx, sc_page_idx ^ 1);

	/* Leave per-CPU data access */
	local_irq_restore(flags);

	/* Print return code of the secure call */
	print_secure_call_error(sc_return_code);

	return sc_return_code == CSV3_SECURE_CMD_ACK ? 0 : -EIO;
}
EXPORT_SYMBOL_GPL(csv3_issue_request_report);

int csv3_issue_request_rtmr(void *req_buffer, size_t buffer_size)
{
	struct secure_call_pages *sc_page_info;
	struct csv3_secure_call_cmd *sc_wr, *sc_rd;
	unsigned long flags;
	int sc_page_idx;
	enum csv3_secure_command_type sc_return_code;

	/*
	 * secure call pages needs to access with IRQs disabled because it is
	 * using a per-CPU data.
	 */
	local_irq_save(flags);

	sc_page_info = this_cpu_read(secure_call_data);
	sc_page_idx = this_cpu_read(secure_call_page_idx);

	sc_wr = sc_page_idx ? &sc_page_info->page_a : &sc_page_info->page_b;
	sc_rd = sc_page_idx ? &sc_page_info->page_b : &sc_page_info->page_a;

	sc_wr->cmd_type = CSV3_SECURE_CMD_RTMR;
	sc_wr->nums = 1;
	sc_wr->unused = 0;
	/* The RTMR subcommand buffer lives in the secure call page. */
	unsafe_memcpy((void *)&sc_wr->csv_rtmr_subcmd, req_buffer, buffer_size,
		/* "buffer_size" was calculated by the caller */);

	/*
	 * Write command in sc_wr must be done before retrieve status code
	 * from sc_rd, and it's ensured by the smp_mb below.
	 */
	smp_mb();

	sc_return_code = sc_rd->cmd_type;

	/* If the firmware support RTMR, copy the response data. */
	if (sc_return_code == CSV3_SECURE_CMD_ACK)
		unsafe_memcpy(req_buffer, &sc_rd->csv_rtmr_subcmd, buffer_size,
			/* "buffer_size" was calculated by the caller */);

	this_cpu_write(secure_call_page_idx, sc_page_idx ^ 1);

	/* Leave per-CPU data access */
	local_irq_restore(flags);

	/* Print return code of the secure call */
	print_secure_call_error(sc_return_code);

	/*
	 * If the secure call returns an error, the RTMR is considered
	 * unsupported.
	 */
	return sc_return_code == CSV3_SECURE_CMD_ACK ? 0 : -ENODEV;
}
EXPORT_SYMBOL_GPL(csv3_issue_request_rtmr);
