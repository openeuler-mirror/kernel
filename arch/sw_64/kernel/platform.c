// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/sw/kernel/setup.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/platform_device.h>

static struct platform_device sw64_cpufreq_device = {
	.name = "sw64_cpufreq",
	.id = -1,
};

static int __init sw64_cpufreq_init(void)
{
	return platform_device_register(&sw64_cpufreq_device);
}

arch_initcall(sw64_cpufreq_init);
