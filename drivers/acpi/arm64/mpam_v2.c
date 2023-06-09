// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM ACPI 2.0
 *
 * Copyright (C) 2019-2022 Huawei Technologies Co., Ltd
 *
 * Author: Yu Liao <liaoyu15@huawei.com>
 *
 * Code was partially borrowed from http://www.linux-arm.org/git?p=
 * linux-jm.git;a=commit;h=10fe7d6363ae96b25f584d4a91f9d0f2fd5faf3b.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

/* Parse the MPAM ACPI table feeding the discovered nodes into the driver */
#define pr_fmt(fmt) "ACPI MPAM: " fmt

#include <linux/acpi.h>
#include <acpi/processor.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cacheinfo.h>
#include <linux/string.h>
#include <linux/nodemask.h>
#include <linux/arm_mpam.h>

extern int
acpi_mpam_label_cache_component_id(struct acpi_table_header *table_hdr,
					struct acpi_pptt_processor *cpu_node,
					u32 *component_id);

static int __init acpi_mpam_parse_cache_v2(struct acpi_mpam_msc_node *msc,
						struct acpi_table_header *pptt)
{
	int ret = 0;
	int level;
	u32 component_id;
	struct mpam_device *dev;
	struct cacheinfo *ci;
	struct acpi_pptt_processor *pptt_cpu_node;
	struct acpi_mpam_resource_node *resources;

	resources = (struct acpi_mpam_resource_node *)(msc + 1);

	pptt_cpu_node = find_acpi_processor_node_from_cache_id(resources->locator.cache_locator.cache_reference);
	if (!pptt_cpu_node) {
		pr_err("Failed to find processor cpu node\n");
		return -EINVAL;
	}

	ret = acpi_mpam_label_cache_component_id(pptt, pptt_cpu_node,
					&component_id);
	if (ret) {
		pr_err("Failed to label cache component id\n");
		return -EINVAL;
	}

	cpus_read_lock();
	ci = cacheinfo_shared_cpu_map_search(pptt_cpu_node);
	if (!ci) {
		pr_err_once("No CPU has cache with PPTT reference %#llx",
				resources->locator.cache_locator.cache_reference);
		pr_err_once("All CPUs must be online to probe mpam.\n");
		cpus_read_unlock();
		return -ENODEV;
	}

	level = ci->level;
	ci = NULL;
	cpus_read_unlock();

	/*
	 * Possible we can get cpu-affinity in next MPAM ACPI version,
	 * now we have to set it to NULL and use default possible_aff-
	 * inity.
	 */
	dev = mpam_device_create_cache(level, component_id, NULL,
				msc->base_address);
	if (IS_ERR(dev)) {
		pr_err("Failed to create cache node\n");
		return -EINVAL;
	}

	return mpam_register_device_irq(dev,
		msc->overflow_interrupt, msc->overflow_interrupt_flags,
		msc->error_interrupt, msc->error_interrupt_flags);
}

static int __init acpi_mpam_parse_memory_v2(struct acpi_mpam_msc_node *msc)
{
	u32 component_id;
	struct mpam_device *dev;
	struct acpi_mpam_resource_node *resources;

	resources = (struct acpi_mpam_resource_node *)(msc + 1);

	component_id = acpi_map_pxm_to_node(resources->locator.memory_locator.proximity_domain);
	if (component_id == NUMA_NO_NODE)
		component_id = 0;

	dev = mpam_device_create_memory(component_id, msc->base_address);
	if (IS_ERR(dev)) {
		pr_err("Failed to create memory node\n");
		return -EINVAL;
	}

	return mpam_register_device_irq(dev,
		msc->overflow_interrupt, msc->overflow_interrupt_flags,
		msc->error_interrupt, msc->error_interrupt_flags);
}

int __init acpi_mpam_parse_table_v2(struct acpi_table_header *table,
					struct acpi_table_header *pptt)
{
	char *table_offset = (char *)(table + 1);
	char *table_end = (char *)table + table->length;
	struct acpi_mpam_msc_node *node_hdr;
	struct acpi_mpam_resource_node *resources;
	int ret = 0;

	ret = mpam_discovery_start();

	if (ret)
		return ret;

	node_hdr = (struct acpi_mpam_msc_node *)table_offset;
	resources = (struct acpi_mpam_resource_node *)(node_hdr + 1);

	while (table_offset < table_end) {
		switch (resources->locator_type) {

		case ACPI_MPAM_LOCATION_TYPE_PROCESSOR_CACHE:
			ret = acpi_mpam_parse_cache_v2(node_hdr, pptt);
			break;
		case ACPI_MPAM_LOCATION_TYPE_MEMORY:
			ret = acpi_mpam_parse_memory_v2(node_hdr);
			break;
		default:
			pr_warn_once("Unknown node type %u offset %ld.",
					(resources->locator_type),
					(table_offset-(char *)table));
			fallthrough;
		case ACPI_MPAM_LOCATION_TYPE_SMMU:
			/* not yet supported */
			fallthrough;
		case ACPI_MPAM_TYPE_UNKNOWN:
			break;
		}
		if (ret)
			break;

		table_offset += node_hdr->length;
		node_hdr = (struct acpi_mpam_msc_node *)table_offset;
		resources = (struct acpi_mpam_resource_node *)(node_hdr + 1);
	}

	if (ret) {
		pr_err("discovery failed: %d\n", ret);
		mpam_discovery_failed();
	} else {
		ret = mpam_discovery_complete();
		if (!ret)
			pr_info("Successfully init mpam by ACPI.\n");
	}

	return ret;
}
