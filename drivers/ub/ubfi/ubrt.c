// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubfi ubrt: " fmt

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <ub/ubfi/ubfi.h>

#include "ummu.h"
#include "ubc.h"
#include "ubrt.h"

#define UBIOS_SIG_UBC "ubc"
#define UBIOS_SIG_UMMU "ummu"

struct acpi_table_ubrt *acpi_table;
struct ubios_root_table *ubios_table;

/*
 * ubios max sub table count is 256, max size is 40 + 8 * 256 = 2088
 * ummu max count is 32, max size is 32 + 8 + 32 * 160 = 5160
 * ubc max count is 32, max size is 32 + 24 + 32 * 384 = 12344
 * Choose the largest one as the maximum value for the ubios table.
 */
#define UBIOS_TABLE_TOTAL_SIZE_MAX (sizeof(struct ubrt_ubc_table) + \
				    32 * sizeof(struct ubc_node))

/* remember to use ub_table_put to release memory allocated by ub_table_get */
void *ub_table_get(u64 pa)
{
	void __iomem *va;
	u32 total_size;
	void *ret;

	if (!pa)
		return NULL;

	va = ioremap(pa, sizeof(struct ub_table_header));
	if (!va) {
		pr_err("ioremap ub table header failed\n");
		return NULL;
	}

	total_size = readl(va + UB_TABLE_HEADER_NAME_LEN);
	pr_debug("ub table size is [0x%x]\n", total_size);
	if (total_size == 0 || total_size > UBIOS_TABLE_TOTAL_SIZE_MAX) {
		pr_err("ubios table size is invalid, total_size=0x%x\n",
		       total_size);
		iounmap(va);
		return NULL;
	}
	iounmap(va);

	va = ioremap(pa, total_size);
	if (!va) {
		pr_err("ioremap full ub table failed\n");
		return NULL;
	}

	ret = kzalloc(total_size, GFP_KERNEL);
	if (!ret) {
		iounmap(va);
		return NULL;
	}

	memcpy_fromio(ret, va, total_size);
	iounmap(va);
	return ret;
}

void ub_table_put(void *va)
{
	kfree(va);
}

void uninit_ub_nodes(void)
{
	ubrt_fwnode_del_all();
	destroy_ubc();
}

int handle_acpi_ubrt(void)
{
	bool ubc_done = false, ummu_done = false;
	struct ubrt_sub_table *sub_table;
	int ret = 0;
	u32 i;

	pr_info("acpi ubrt sub table count is %u\n", acpi_table->count);

	for (i = 0; i < acpi_table->count; i++) {
		sub_table = &acpi_table->sub_table[i];
		if (sub_table->type == UB_BUS_CONTROLLER_TABLE && !ubc_done) {
			ret = handle_ubc_table(sub_table->pointer);
			ubc_done = true;
		} else if (sub_table->type == UMMU_TABLE && !ummu_done) {
			ret = handle_ummu_table(sub_table->pointer);
			ummu_done = true;
		} else {
			pr_warn("Ignore sub table: type %u\n", sub_table->type);
		}
		if (ret) {
			pr_err("parse ubrt sub table type %u failed\n",
				sub_table->type);
			goto fail;
		}
	}
	return ret;
fail:
	uninit_ub_nodes();
	return ret;
}

static int get_ubrt_table_name(char *name, u64 sub_table)
{
	void __iomem *va;

	va = ioremap(sub_table, sizeof(struct ub_table_header));
	if (!va) {
		pr_err("ioremap ub table header failed\n");
		return -ENOMEM;
	}

	memcpy_fromio(name, va, UB_TABLE_HEADER_NAME_LEN - 1);
	iounmap(va);
	return 0;
}

int handle_dts_ubrt(void)
{
	bool ubc_done = false, ummu_done = false;
	char name[UB_TABLE_HEADER_NAME_LEN];
	int ret = 0, i;

	if (ubios_table->count == 0) {
		pr_err("ubios root table has no sub tables.\n");
		return 0;
	}
	pr_info("ubios sub table count is %u\n", ubios_table->count);

	for (i = 0; i < ubios_table->count; i++) {
		if (ubios_table->sub_tables[i] == 0)
			continue;
		memset(name, 0, UB_TABLE_HEADER_NAME_LEN);
		ret = get_ubrt_table_name(name, ubios_table->sub_tables[i]);
		if (ret)
			goto out;
		if (name[0] == '\0')
			continue;
		pr_info("ubrt sub table name is %s\n", name);

		if (!strncmp(name, UBIOS_SIG_UMMU, strlen(UBIOS_SIG_UMMU)) &&
		    !ummu_done) {
			ret = handle_ummu_table(ubios_table->sub_tables[i]);
			ummu_done = true;
		} else if (!strncmp(name, UBIOS_SIG_UBC, strlen(UBIOS_SIG_UBC)) &&
			   !ubc_done) {
			ret = handle_ubc_table(ubios_table->sub_tables[i]);
			ubc_done = true;
		} else {
			pr_warn("Ignore sub table: %s\n", name);
		}

		if (ret) {
			pr_err("Create %s failed, ret=%d\n", name, ret);
			goto out;
		}
	}

	return 0;

out:
	uninit_ub_nodes();
	return ret;
}
