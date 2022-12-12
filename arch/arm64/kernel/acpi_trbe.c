// SPDX-License-Identifier: GPL-2.0-only
/*
 * ACPI probing code for ARM Trace Buffer Extension.
 *
 * Copyright (C) 2022 ARM Ltd.
 */

#include <linux/acpi.h>
#include <linux/coresight.h>
#include <linux/platform_device.h>
#include <linux/init.h>

static struct resource trbe_resources[] = {
	{
		/* irq */
		.flags          = IORESOURCE_IRQ,
	}
};

static struct platform_device trbe_dev = {
	.name = ARMV9_TRBE_PDEV_NAME,
	.id = -1,
	.resource = trbe_resources,
	.num_resources = ARRAY_SIZE(trbe_resources)
};

static void arm_trbe_acpi_register_device(void)
{
	int cpu, hetid, irq, ret;
	bool first = true;
	u16 gsi = 0;

	/*
	 * Sanity check all the GICC tables for the same interrupt number.
	 * For now, we only support homogeneous machines.
	 */
	for_each_possible_cpu(cpu) {
		struct acpi_madt_generic_interrupt *gicc;

		gicc = acpi_cpu_get_madt_gicc(cpu);
		if (gicc->header.length < ACPI_MADT_GICC_TRBE)
			return;

		if (first) {
			gsi = gicc->trbe_interrupt;
			if (!gsi)
				return;
			hetid = find_acpi_cpu_topology_hetero_id(cpu);
			first = false;
		} else if ((gsi != gicc->trbe_interrupt) ||
				(hetid != find_acpi_cpu_topology_hetero_id(cpu))) {
			pr_warn("ACPI: TRBE must be homogeneous\n");
			return;
		}
	}

	irq = acpi_register_gsi(NULL, gsi, ACPI_LEVEL_SENSITIVE,
			ACPI_ACTIVE_HIGH);
	if (irq < 0) {
		pr_warn("ACPI: TRBE Unable to register interrupt: %d\n", gsi);
		return;
	}

	trbe_resources[0].start = irq;
	ret = platform_device_register(&trbe_dev);
	if (ret < 0) {
		pr_warn("ACPI: TRBE: Unable to register device\n");
		acpi_unregister_gsi(gsi);
	}
}

static int arm_acpi_trbe_init(void)
{
	if (acpi_disabled)
		return 0;

	arm_trbe_acpi_register_device();

	return 0;
}
device_initcall(arm_acpi_trbe_init)
