// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file implements handling of
 * Arm Translation Lookaside Buffer Invalidate Domain table (TLBI)
 *
 * Copyright (C) 2026, Huawei Ltd.
 */
#define pr_fmt(fmt)	"ACPI: TLBID: " fmt

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "init.h"

#include <asm/tlbid.h>

static struct acpi_table_header *acpi_tlbid_table;

/*
 * tlbid_parse_subtable - Parse ACPI TLBI subtable entry
 *
 * Called for each entry in the ACPI TLBI table. Allocates a tlbi_target
 * structure and copies domain IDs from the ACPI table. Builds the
 * found_domains bitmap for later domain count calculation.
 */
static int __init tlbid_parse_subtable(union acpi_subtable_headers *header,
				       unsigned long end)
{
	struct acpi_tlbi_subtable *hdr = (struct acpi_tlbi_subtable *)header;
	struct tlbi_target *target;

	if (!hdr)
		return -EINVAL;

	target = kzalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return -ENOMEM;

	/* The ACPI Processor UID of the corresponding GICC MADT entry */
	target->nr_domain = hdr->nr_domain;
	target->identifier = hdr->identifier;
	target->domains = kcalloc(hdr->nr_domain, sizeof(*target->domains),
				  GFP_KERNEL);
	if (!target->domains) {
		kfree(target);
		return -ENOMEM;
	}

	memcpy(target->domains, (void *)acpi_tlbid_table + hdr->offset,
	       hdr->nr_domain * sizeof(*target->domains));

	if (add_target(header->tlbi.type, target)) {
		kfree(target->domains);
		kfree(target);
		return -EINVAL;
	}

	return 0;
}

/*
 * acpi_tlbi_init - Initialize TLBID from ACPI table
 *
 * Main entry point for TLBI table parsing. Gets the ACPI TLBI table,
 * parses Processor and SMMU subtable entries, calculates total domain
 * count, validates against hardware capability, and calls
 * tlbid_chip_data_init() to build domain mapping tables.
 * Outputs appropriate error messages on failure.
 */
void __init acpi_tlbid_init(void)
{
	enum acpi_tlbi_target_type type;
	acpi_status status;
	int ret;

	if (!system_supports_tlbid())
		return;

	status = acpi_get_table(ACPI_SIG_TLBI, 0, &acpi_tlbid_table);
	if (ACPI_FAILURE(status))
		return;

	type = ACPI_TLBI_TYPE_PROCESSOR;
	while (type != ACPI_TLBI_TYPE_RESERVED) {
		ret = acpi_table_parse_entries(ACPI_SIG_TLBI,
					       sizeof(struct acpi_table_tlbi),
					       type, tlbid_parse_subtable, 0);
		if (ret <= 0) {
			pr_err("Failed to get TLBID subtable for %s\n",
			type == ACPI_TLBI_TYPE_PROCESSOR ? "Processor":"SMMU");
			break;
		}
		type++;
	}

	if (type != ACPI_TLBI_TYPE_RESERVED)
		tlbid_data_reset();

	if (parse_tlbid_topology())
		pr_err("Failed to initialize TLBI Domain data\n");

	acpi_put_table(acpi_tlbid_table);
}
