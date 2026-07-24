// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: Support the Platform Erratum Mechanism of UMMU.
 */

#include <linux/acpi.h>
#include <linux/of.h>

#include "plat_erratum.h"

struct ummu_device_option_prop {
	u32 opt;
	const char *prop;
};

#ifdef CONFIG_ACPI
static struct acpi_platform_list ummu_device_plat_info[] = {
	/* HiSilicon Hip12 Platform */
	{"HISI  ", "HIP12   ", 1, "UBRT", greater_than_or_equal,
	 "Erratum UMMU Quirks", UMMU_OPT_IDENTITY_COHERENT},
	{ }
};

void ummu_device_acpi_get_options(struct ummu_device *ummu)
{
	int idx;

	idx = acpi_match_platform_list(ummu_device_plat_info);
	if (idx < 0)
		return;

	ummu->cap.options |= ummu_device_plat_info[idx].data;
}
#endif

/* DT platform erratum options - reserved for future DT-based platforms.
 * Currently no DT platform requires UMMU erratum handling.
 */
static const struct ummu_device_option_prop ummu_device_dt_options[] = {
	{ 0, NULL },
};

void ummu_device_dt_get_options(struct ummu_device *ummu)
{
	int i = 0;

	while (ummu_device_dt_options[i].prop) {
		if (of_property_read_bool(ummu->dev->of_node,
		    ummu_device_dt_options[i].prop))
			ummu->cap.options |= ummu_device_dt_options[i].opt;
		i++;
	}
}
