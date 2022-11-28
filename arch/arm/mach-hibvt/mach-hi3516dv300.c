// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016-2017 HiSilicon Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
*/

#include <linux/of_address.h>
#include <asm/smp_scu.h>

#include "mach-common.h"

#ifdef CONFIG_SMP

#define REG_CPU_SRST_CRG    0x78
#define CPU1_SRST_REQ       BIT(2)
#define DBG1_SRST_REQ       BIT(4)

void hi35xx_set_cpu(unsigned int cpu, bool enable)
{
	struct device_node *np = NULL;
	unsigned int regval;
	void __iomem *crg_base;

	np = of_find_compatible_node(NULL, NULL, "hisilicon,hi3516dv300-clock");
	if (!np) {
		pr_err("failed to find hisilicon clock node\n");
		return;
	}

	crg_base = of_iomap(np, 0);
	if (!crg_base) {
		pr_err("failed to map address\n");
		return;
	}

	if (enable) {
		/* clear the slave cpu reset */
		regval = readl(crg_base + REG_CPU_SRST_CRG);
		regval &= ~CPU1_SRST_REQ;
		writel(regval, (crg_base + REG_CPU_SRST_CRG));
	} else {
		regval = readl(crg_base + REG_CPU_SRST_CRG);
		regval |= (DBG1_SRST_REQ | CPU1_SRST_REQ);
		writel(regval, (crg_base + REG_CPU_SRST_CRG));
	}
	iounmap(crg_base);
}

static const struct smp_operations hi35xx_smp_ops __initconst = {
	.smp_prepare_cpus       = hi35xx_smp_prepare_cpus,
	.smp_boot_secondary     = hi35xx_boot_secondary,
};

CPU_METHOD_OF_DECLARE(hi3516dv300_smp, "hisilicon,hi3516dv300",
		      &hi35xx_smp_ops);
#endif /* CONFIG_SMP */
