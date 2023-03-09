// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009 Lemote Inc.
 * Author: Wu Zhangjin, wuzhangjin@gmail.com
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/smp.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/acpi.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <asm/bootinfo.h>
#include <asm/loongson.h>

extern int loongson_acpi_init(void);

static int __init loongson3_acpi_suspend_init(void)
{
#ifdef CONFIG_ACPI
	acpi_status status;
	unsigned long long suspend_addr = 0;

	if (acpi_disabled || acpi_gbl_reduced_hardware)
		return 0;

	acpi_write_bit_register(ACPI_BITREG_SCI_ENABLE, 1);

	status = acpi_evaluate_integer(NULL, "\\SADR", NULL, &suspend_addr);
	if (ACPI_FAILURE(status) || !suspend_addr) {
		pr_err("ACPI S3 is not support!\n");
		return -1;
	}
	loongson_sysconf.suspend_addr = (u64)phys_to_virt(TO_PHYS(suspend_addr));
#endif
	return 0;
}

device_initcall(loongson3_acpi_suspend_init);
