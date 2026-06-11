// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubfi driver: " fmt

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/of.h>

#include "ubrt.h"
#include "ub_fi.h"

#define ACPI_SIG_UBRT "UBRT" /* UB Root Table */
#define UBIOS_INFO_TABLE "linux,ubios-information-table"
#define UBFI_MOD_VERSION "2.0.0"

enum firmware_report_mode firmware_mode = UNKNOWN;

static void ub_firmware_mode_init(void)
{
	if (acpi_disabled)
		firmware_mode = DTS;
	else
		firmware_mode = ACPI;

	pr_info("Starting with mode: %d, version: %s\n", firmware_mode,
		UBFI_MOD_VERSION);
}

static int ubfi_get_acpi_ubrt(void)
{
	struct acpi_table_header *header;
	acpi_status status;

	status = acpi_get_table(ACPI_SIG_UBRT, 0, &header);
	if (ACPI_FAILURE(status)) {
		if (status != AE_NOT_FOUND)
			pr_err("ACPI failed msg: %s\n",
				acpi_format_exception(status));
		return -ENODEV;
	}
	acpi_table = (struct acpi_table_ubrt *)header;
	pr_debug("get ubrt by acpi success\n");
	return 0;
}

static int ubfi_get_dts_ubrt(void)
{
	struct device_node *node;
	u64 phys_addr;

	node = of_find_node_by_path("/chosen");
	if (!node) {
		pr_err("Failed to get device tree chosen node\n");
		return -EINVAL;
	}

	if (of_property_read_u64(node, UBIOS_INFO_TABLE, &phys_addr)) {
		pr_err("Failed to get %s node\n", UBIOS_INFO_TABLE);
		of_node_put(node);
		return -EINVAL;
	}
	of_node_put(node);

	ubios_table = (struct ubios_root_table *)ub_table_get(phys_addr);
	if (!ubios_table)
		return -ENOMEM;

	pr_debug("ubfi get ubrt by device tree success\n");
	return 0;
}

static int ubfi_get_ubrt(void)
{
	if (firmware_mode == ACPI)
		return ubfi_get_acpi_ubrt();
	else
		return ubfi_get_dts_ubrt();
}

static int handle_ubrt(void)
{
	if (firmware_mode == ACPI)
		return handle_acpi_ubrt();
	else
		return handle_dts_ubrt();
}

static void ubfi_put_ubrt(void)
{
	if (firmware_mode == ACPI) {
		acpi_put_table((struct acpi_table_header *)acpi_table);
		acpi_table = NULL;
	} else {
		ub_table_put(ubios_table);
		ubios_table = NULL;
	}
}

static int __init ubfi_init(void)
{
	int ret;

	ub_firmware_mode_init();

	ret = ubfi_get_ubrt();
	if (ret) {
		pr_warn("can't get ub information from firmware, ret=%d\n", ret);
		return 0;
	}

	ret = handle_ubrt();
	if (ret) {
		pr_err("failed to handle ubrt, ret=%d\n", ret);
		ubfi_put_ubrt();
	}

	return ret;
}

static void __exit ubfi_exit(void)
{
	uninit_ub_nodes();
	ubfi_put_ubrt();
}

module_init(ubfi_init);
module_exit(ubfi_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UnifiedBus firmware interface driver");
MODULE_IMPORT_NS(UB_UBFI);
MODULE_VERSION(UBFI_MOD_VERSION);
