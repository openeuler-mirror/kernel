/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#define pr_fmt(fmt)	"pbha: " fmt

#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/printk.h>
#include <linux/cpufeature.h>

#include <asm/setup.h>

#define HBM_MODE_CACHE	1

bool __ro_after_init pbha_bit0_enabled;

void __init early_pbha_bit0_init(void)
{
	const u8 *prop;
	void *fdt;
	int node;

	/* Check whether PBHA is enabled or not. */
	if (!system_supports_pbha())
		return;

	fdt = get_early_fdt_ptr();
	if (!fdt)
		return;

	node = fdt_path_offset(fdt, "/chosen");
	if (node < 0)
		return;

	prop = fdt_getprop(fdt, node, "linux,pbha-bit0", NULL);
	if (!prop)
		return;
	if (*prop == HBM_MODE_CACHE)
		pbha_bit0_enabled = true;
}
