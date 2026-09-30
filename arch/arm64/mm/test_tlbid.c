// SPDX-License-Identifier: GPL-2.0-only
/* This file is intended to be included into tlbid.c
 * Copyright (C) 2026 Huawei Ltd.
 */

#include <kunit/test.h>

static struct tlbid_data fake_tlbid_data __read_mostly = {
	.nr_acpi_domain = 1,
	.nis = 0,
	.nvis = 0,
	.nos = 0,
	.nvos = 0,
};

static struct acpi_madt_generic_interrupt fake_madt_gicc[NR_CPUS];

static void __init reset_real_tlbid(void)
{
	tlbid_data_reset();
	memcpy(&tlbid_data, &fake_tlbid_data, sizeof(tlbid_data));
}

static int __init setup_fake_tlbid(struct kunit *test)
{
	int ret, cpu, max_domains = 1 << 16;
	struct acpi_madt_generic_interrupt *gicc;
	struct tlbi_target *target;

	if (num_possible_cpus() == 1)
		return 1;

	memcpy(&fake_tlbid_data, &tlbid_data, sizeof(tlbid_data));
	tlbid_data.nis = 8;
	tlbid_data.nvis = 0;
	tlbid_data.nos = 8;
	tlbid_data.nvos = 0;
	for_each_possible_cpu(cpu)
		memcpy(&fake_madt_gicc[cpu], acpi_cpu_get_madt_gicc(cpu),
		       sizeof(struct acpi_madt_generic_interrupt));

	tlbid_data.acpi_domain = kcalloc(BITS_TO_LONGS(max_domains),
					 sizeof(long), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, tlbid_data.acpi_domain);

	INIT_LIST_HEAD(&tlbid_data.target_list[ACPI_TLBI_TYPE_PROCESSOR]);
	INIT_LIST_HEAD(&tlbid_data.target_list[ACPI_TLBI_TYPE_SMMU]);

	/*
	 * Fake TLBI domain topology:
	 *   domain0: [0, num_possible_cpus())
	 *   domain1: [0, (num_possible_cpus() / 2)
	 *   domain2: [num_possible_cpus() / 2, num_possible_cpus())
	 */
	for_each_possible_cpu(cpu) {
		target = kzalloc(sizeof(*target), GFP_KERNEL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target);

		/* The ACPI Processor UID of the corresponding GICC MADT entry */
		gicc = acpi_cpu_get_madt_gicc(cpu);
		gicc->uid = cpu;
		target->nr_domain = 2;
		target->identifier = cpu;
		target->domains = kcalloc(target->nr_domain,
					  sizeof(*target->domains), GFP_KERNEL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, target->domains);
		target->domains[0] = 0;
		target->domains[1] = (cpu < (num_possible_cpus() / 2)) ? 1 : 2;
		ret = add_target(ACPI_TLBI_TYPE_PROCESSOR, target);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	ret = parse_tlbid_topology();
	KUNIT_ASSERT_EQ(test, ret, 0);

	for_each_possible_cpu(cpu)
		memcpy(acpi_cpu_get_madt_gicc(cpu), &fake_madt_gicc[cpu],
		       sizeof(struct acpi_madt_generic_interrupt));

	return 0;
}

static void __init test_parse_tlbid_topology(struct kunit *test)
{
	struct tlbi_domain *actbl[3];
	cpumask_t tmp;
	int cpu;

	if (setup_fake_tlbid(test))
		return;

	actbl[0] = &tlbid_data.cpu_domain[num_possible_cpus() - 1][0];
	actbl[1] = &tlbid_data.cpu_domain[(num_possible_cpus() / 2) - 1][0];
	actbl[2] = &tlbid_data.cpu_domain[(num_possible_cpus() / 2) - 1][1];

	KUNIT_EXPECT_EQ(test, actbl[0]->id, 0);
	KUNIT_EXPECT_TRUE(test, cpumask_equal(cpu_possible_mask,
				&actbl[0]->cpumask));

	KUNIT_EXPECT_EQ(test, actbl[1]->id, 1);
	cpumask_clear(&tmp);
	for_each_possible_cpu(cpu) {
		if (cpu >= (num_possible_cpus() / 2))
			continue;
		cpumask_set_cpu(cpu, &tmp);
	}
	KUNIT_EXPECT_TRUE(test, cpumask_equal(&tmp, &actbl[1]->cpumask));

	KUNIT_EXPECT_EQ(test, actbl[2]->id, 2);
	cpumask_clear(&tmp);
	for_each_possible_cpu(cpu) {
		if (cpu < (num_possible_cpus() / 2))
			continue;
		cpumask_set_cpu(cpu, &tmp);
	}
	KUNIT_EXPECT_TRUE(test, cpumask_equal(&tmp, &actbl[2]->cpumask));

	for_each_possible_cpu(cpu) {
		struct tlbi_domain *domain;
		int i;

		for (i = 0; i < tlbid_data.nr_acpi_domain; i++) {
			domain = &tlbid_data.cpu_domain[cpu][i];
			if (domain != actbl[0] &&
			    domain != actbl[1] &&
			    domain != actbl[2]) {
				KUNIT_EXPECT_EQ(test, domain->id, TLBI_INV_DOMAIN);
			}
		}
	}

	reset_real_tlbid();
}

static void __init test_pick_best_domain(struct kunit *test)
{
	int domain, cpu;
	cpumask_t tmp;

	if (setup_fake_tlbid(test))
		return;

	domain = pick_best_domain(cpu_possible_mask);
	KUNIT_EXPECT_EQ(test, domain, 0);

	cpumask_clear(&tmp);
	for_each_possible_cpu(cpu) {
		if (cpu >= (num_possible_cpus() / 2))
			continue;
		cpumask_set_cpu(cpu, &tmp);
	}
	domain = pick_best_domain(&tmp);
	KUNIT_EXPECT_EQ(test, domain, 1);

	cpumask_clear(&tmp);
	for_each_possible_cpu(cpu) {
		if (cpu < (num_possible_cpus() / 2))
			continue;
		cpumask_set_cpu(cpu, &tmp);
	}
	domain = pick_best_domain(&tmp);
	KUNIT_EXPECT_EQ(test, domain, 2);

	reset_real_tlbid();
}

static struct kunit_case __refdata tlbidomain_test_cases[] = {
	KUNIT_CASE(test_parse_tlbid_topology),
	KUNIT_CASE(test_pick_best_domain),
	{}
};

static struct kunit_suite tlbidomain_test_suite = {
	.name = "tlbidomain_test_suite",
	.test_cases = tlbidomain_test_cases,
};

kunit_test_init_section_suites(&tlbidomain_test_suite);
