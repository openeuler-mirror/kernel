// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2013 Linaro Ltd.
 * Copyright (c) 2013 Hisilicon Limited.
 * Based on arch/arm/mach-vexpress/platsmp.c, Copyright (C) 2002 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/io.h>
#include <linux/smp.h>
#include <asm/smp_scu.h>

#include "mach-common.h"

#define HI35XX_BOOT_ADDRESS 0x00000000

void __init hi35xx_smp_prepare_cpus(unsigned int max_cpus)
{
	unsigned long base = 0;
	void __iomem *scu_base = NULL;

	if (scu_a9_has_base()) {
		base = scu_a9_get_base();
		scu_base = ioremap(base, PAGE_SIZE);
		if (!scu_base) {
			pr_err("ioremap(scu_base) failed\n");
			return;
		}

		scu_enable(scu_base);
		iounmap(scu_base);
	}
}

void hi35xx_set_scu_boot_addr(phys_addr_t start_addr, phys_addr_t jump_addr)
{
	void __iomem *virt;

	virt = ioremap(start_addr, PAGE_SIZE);
	if (!virt) {
		pr_err("ioremap(start_addr) failed\n");
		return;
	}

	writel_relaxed(0xe51ff004, virt);   /* ldr pc, [rc, #-4] */
	writel_relaxed(jump_addr, virt + 4);    /* pc jump phy address */
	iounmap(virt);
}

int hi35xx_boot_secondary(unsigned int cpu, struct task_struct *idle)
{
	phys_addr_t jumpaddr;

	jumpaddr = virt_to_phys(secondary_startup);
	hi35xx_set_scu_boot_addr(HI35XX_BOOT_ADDRESS, jumpaddr);
	hi35xx_set_cpu(cpu, true);
	arch_send_wakeup_ipi_mask(cpumask_of(cpu));
	return 0;
}

