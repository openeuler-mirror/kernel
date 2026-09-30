// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Huawei Ltd. */

#define pr_fmt(fmt) "tlbid: " fmt

#include <linux/acpi.h>
#include <linux/cpumask.h>

#include <asm/cpu.h>
#include <asm/sysreg.h>
#include <asm/cpufeature.h>
#include <asm/tlbid.h>

struct tlbi_domain {
	cpumask_t cpumask;
	int id;
};

struct tlbid_data {
	struct list_head	target_list[ACPI_TLBI_TYPE_RESERVED];
	unsigned long		*acpi_domain;
	u32			nr_acpi_domain;
	struct tlbi_domain	*cpu_domain[NR_CPUS];
	u8			nis;	/* TLBIDIDR_EL1.NIS */
	u8			nvis;	/* TLBIDIDR_EL1.NVIS */
	u8			nos;	/* TLBIDIDR_EL1.NOS */
	u8			nvos;	/* TLBIDIDR_EL1.NVOS */
};

static struct tlbid_data tlbid_data __read_mostly;

#define TLBI_INV_DOMAIN			(-1)

/*
 * sanitised_ids - Sanitise TLBID domain bit configurations
 *
 * Sanitise that NIS/NVIS and NOS/NVOS configurations follow Arm architecture
 * constraints: if outer domain bits are zero, inner domain bits must also be
 * zero. Outputs error and zeroes out all domain counts if sanitise fails.
 */
static bool sanitised_ids(u8 nvos, u8 nos, u8 nvis, u8 nis)
{
	bool inv = false;

	switch (nos) {
	case 0:
		inv = nvos > 0;
		break;
	case 1 ... 8:
		inv = nvos > 6;
		break;
	case 9 ... 16:
		inv = nvos > 5;
		break;
	}

	if (inv) {
		pr_err("Illegal value of NVOS(%u) for NOS(%u)\n", nvos, nos);
		goto on_error;
	}

	switch (nis) {
	case 0:
		inv = nvis > 0;
		break;
	case 1 ... 8:
		inv = nvis > 6;
		break;
	case 9 ... 16:
		inv = nvis > 5;
		break;
	}

	if (!inv)
		return true;

	pr_err("Illegal value of NVIS(%u) for NIS(%u)\n", nvis, nis);

on_error:
	return false;
}

static int __init tlbid_data_init(void)
{
	u64 tlbididr = read_sanitised_ftr_reg(SYS_TLBIDIDR_EL1);
	u8 nvos, nos, nvis, nis;
	int type, cpu;
	u16 max_id;

	nvos = FIELD_GET(TLBIDIDR_EL1_NVOS, tlbididr);
	nos = FIELD_GET(TLBIDIDR_EL1_NOS, tlbididr);
	nvis = FIELD_GET(TLBIDIDR_EL1_NVIS, tlbididr);
	nis = FIELD_GET(TLBIDIDR_EL1_NIS, tlbididr);

	if (sanitised_ids(nvos, nos, nvis, nis)) {
		tlbid_data.nvos = nvos;
		tlbid_data.nos = nos;
		tlbid_data.nvis = nvis;
		tlbid_data.nis = nis;
	} else {
		tlbid_data.nvos = 0;
		tlbid_data.nos = 0;
		tlbid_data.nvis = 0;
		tlbid_data.nis = 0;
	}

	type = ACPI_TLBI_TYPE_PROCESSOR;
	while (type != ACPI_TLBI_TYPE_RESERVED)
		INIT_LIST_HEAD(&tlbid_data.target_list[type++]);

	tlbid_data.acpi_domain = NULL;
	tlbid_data.nr_acpi_domain = 1;

	for_each_possible_cpu(cpu)
		tlbid_data.cpu_domain[cpu] = NULL;

	if (!system_supports_tlbid())
		return 0;

	max_id = (1 << max(tlbid_data.nos, tlbid_data.nis));
	tlbid_data.acpi_domain = kcalloc(BITS_TO_LONGS(max_id),
					 sizeof(long), GFP_KERNEL);
	if (!tlbid_data.acpi_domain)
		return -ENOMEM;

	return 0;
}

void __init tlbid_data_reset(void)
{
	int cpu, type = ACPI_TLBI_TYPE_PROCESSOR;
	struct tlbi_target *target, *next;

	while (type != ACPI_TLBI_TYPE_RESERVED) {
		struct list_head *head = &tlbid_data.target_list[type++];

		list_for_each_entry_safe(target, next, head, list) {
			list_del(&target->list);
			kfree(target->domains);
			kfree(target);
		}
	}

	for_each_possible_cpu(cpu) {
		kfree(tlbid_data.cpu_domain[cpu]);
		tlbid_data.cpu_domain[cpu] = NULL;
	}

	kfree(tlbid_data.acpi_domain);
	tlbid_data.acpi_domain = NULL;
	tlbid_data.nr_acpi_domain = 1;
	tlbid_data.nis = 0;
	tlbid_data.nos = 0;
	tlbid_data.nvis = 0;
	tlbid_data.nvos = 0;
}

/*
 * find_target - Find TLBI target by type and identifier
 *
 * Looks up the tlbi_target structure associated with the given type and cpu.
 * For PROCESSOR type, converts CPU logical ID to ACPI Processor UID.
 */
static struct tlbi_target *find_target(int type, int cpu)
{
	struct tlbi_target *target = NULL;
	struct list_head *head;
	int uid;

	switch (type) {
	case ACPI_TLBI_TYPE_PROCESSOR:
		uid = get_acpi_id_for_cpu(cpu);
		break;
	default:
		pr_err("Only support Processor as TLBI broadcast target\n");
		return NULL;
	}

	head = &tlbid_data.target_list[type];
	list_for_each_entry(target, head, list) {
		if (target->identifier == uid)
			return target;
	}

	return NULL;
}

int add_target(int type, struct tlbi_target *target)
{
	s32 max_id = 1 << max(tlbid_data.nis, tlbid_data.nos);
	s32 i;

	for (i = 0; i < target->nr_domain; i++) {
		s32 id = target->domains[i];

		if (id >= max_id) {
			pr_err("ACPI table reports invalid domain id %d", id);
			return -EINVAL;
		}
		if ((id > 0) && !test_and_set_bit(id, tlbid_data.acpi_domain))
			tlbid_data.nr_acpi_domain += 1;
	}

	INIT_LIST_HEAD(&target->list);
	list_add_tail(&target->list, &tlbid_data.target_list[type]);
	return 0;
}

/*
 * pick_best_domain - Select optimal TLBI domain for given CPUs
 *
 * Iterates through cpu_domain table to find a domain whose cpumask exactly
 * matches the given active CPUs. This allows targeted TLBI instead of
 * broadcasting to all CPUs, improving TLB invalidation efficiency.
 * Returns domain ID on success, 0 on failure.
 */
int pick_best_domain(const cpumask_t *active_cpus)
{
	struct tlbi_domain *domain;
	cpumask_t tmp;
	int nr_cpu;

	/* Domain 0 is the only supported for Innern Shareable TLBI */
	if (unlikely(tlbid_data.nr_acpi_domain == 1))
		goto domain0;

	nr_cpu = cpumask_weight(active_cpus);
	if (unlikely(nr_cpu == 0))
		goto domain0;

	do {
		domain = &tlbid_data.cpu_domain[nr_cpu - 1][0];
		while (domain->id != TLBI_INV_DOMAIN) {
			if (cpumask_and(&tmp, active_cpus, &domain->cpumask) &&
			    cpumask_equal(&tmp, active_cpus))
				return domain->id;
			domain++;
		}
	} while (++nr_cpu <= num_possible_cpus());

domain0:
	return 0;
}

/*
 * parse_tlbid_topology - Initialize TLBI domain mapping tables
 *
 * Allocates and populates the cpu_domain table:
 * 1. Build CPU-to-domain mapping from ACPI-parsed target data
 * 2. Reorganize data for efficient lookup (domain x CPU matrix)
 *
 * Returns 0 on success, -ENOMEM on allocation failure, -EVINAL on topology
 * parse failure
 */
int __init parse_tlbid_topology(void)
{
	struct tlbi_domain *src, *dst;
	struct tlbi_target *target;
	int cpu, err = 0;
	s32 i;

	if (tlbid_data.nr_acpi_domain == 1)
		return -EINVAL;

	pr_info("ACPI report %d TLBI Domain(s).\n", tlbid_data.nr_acpi_domain);

	/*
	 * Allocate a sparse table to map the CPU count to domain list sharing
	 * the same CPU count.
	 *
	 * NOTICE: Each domain is assumed to contain all system-wide SMMUs,
	 * Any broadcast in a specific domain must wait replies from all SMMUs
	 * before it complete.
	 */
	for_each_possible_cpu(cpu) {
		tlbid_data.cpu_domain[cpu] =
			kcalloc(tlbid_data.nr_acpi_domain,
				sizeof(struct tlbi_domain), GFP_KERNEL);
		if (!tlbid_data.cpu_domain[cpu]) {
			err = -ENOMEM;
			goto on_error;
		}
		for (i = 0; i < tlbid_data.nr_acpi_domain; i++) {
			cpumask_clear(&tlbid_data.cpu_domain[cpu][i].cpumask);
			tlbid_data.cpu_domain[cpu][i].id = cpu ?
							   TLBI_INV_DOMAIN : i;
		}
	}

	/* Initialize the cpumask associated with each tlbi domain */
	for_each_possible_cpu(cpu) {
		target = find_target(ACPI_TLBI_TYPE_PROCESSOR, cpu);
		if (!target) {
			err = -EINVAL;
			goto on_error;
		}
		for (i = 0; i < target->nr_domain; i++) {
			/* Record all CPUs belong to the same domain */
			src = &tlbid_data.cpu_domain[0][target->domains[i]];
			cpumask_set_cpu(cpu, &(src->cpumask));
		}
	}

	/* Move each domain data onto the right position in sparse table */
	for (i = 0; i < tlbid_data.nr_acpi_domain; i++) {
		src = &tlbid_data.cpu_domain[0][i];
		cpu = cpumask_weight(&(src->cpumask));

		if (cpu == 1)
			continue;

		if (cpu == 0) {
			pr_err("TLBI Domain %d has no CPU\n", i);
			err = -EINVAL;
			goto on_error;
		}

		dst = &tlbid_data.cpu_domain[cpu - 1][0];
		while (dst->id != TLBI_INV_DOMAIN) dst++;
		memcpy(dst, src, sizeof(*dst));
		cpumask_clear(&src->cpumask);
		src->id = TLBI_INV_DOMAIN;
	}

	return 0;

on_error:
	tlbid_data_reset();
	return err;
}

static int __init arm64_tlbid_register_cpus(void)
{
	return tlbid_data_init();
}
/* Must occur before acpi_tlbid_init() from acpi_arm_init() */
arch_initcall(arm64_tlbid_register_cpus)
