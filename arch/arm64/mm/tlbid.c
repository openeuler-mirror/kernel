// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Huawei Ltd. */

#define pr_fmt(fmt) "tlbid: " fmt

#include <linux/cpumask.h>

#include <asm/cpu.h>
#include <asm/sysreg.h>
#include <asm/cpufeature.h>

struct tlbi_domain {
	cpumask_t cpumask;
	int id;
};

struct tlbid_data {
	u8			nis;	/* TLBIDIDR_EL1.NIS */
	u8			nvis;	/* TLBIDIDR_EL1.NVIS */
	u8			nos;	/* TLBIDIDR_EL1.NOS */
	u8			nvos;	/* TLBIDIDR_EL1.NVOS */
};

static struct tlbid_data tlbid_data __read_mostly;

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

	return 0;
}

static int __init arm64_tlbid_register_cpus(void)
{
	return tlbid_data_init();
}
/* Must occur before acpi_tlbid_init() from acpi_arm_init() */
arch_initcall(arm64_tlbid_register_cpus)
