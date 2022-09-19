// SPDX-License-Identifier: GPL-2.0
/*
 * loongson-specific suspend support
 *
 *  Copyright (C) 2020 Loongson Technology Co., Ltd.
 *  Author: Huacai Chen <chenhuacai@loongson.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/acpi.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/suspend.h>

#include <asm/acpi.h>
#include <asm/loongarch.h>
#include <asm/time.h>
#include <asm/tlbflush.h>

#include <asm/loongson.h>
#include <asm/suspend.h>

u64 loongarch_suspend_addr;

extern unsigned long eentry;
extern unsigned long tlbrentry;
struct saved_registers {
	u32 ecfg;
	u64 pgd;
	u64 kpgd;
	u32 pwctl0;
	u32 pwctl1;
	u32 euen;
};
static struct saved_registers saved_regs;

void arch_common_suspend(void)
{
	save_counter();
	saved_regs.pgd = csr_read64(LOONGARCH_CSR_PGDL);
	saved_regs.kpgd = csr_read64(LOONGARCH_CSR_PGDH);
	saved_regs.pwctl0 = csr_read32(LOONGARCH_CSR_PWCTL0);
	saved_regs.pwctl1 = csr_read32(LOONGARCH_CSR_PWCTL1);
	saved_regs.ecfg = csr_read32(LOONGARCH_CSR_ECFG);
	saved_regs.euen = csr_read32(LOONGARCH_CSR_EUEN);

	loongarch_suspend_addr = loongson_sysconf.suspend_addr;
}

void arch_common_resume(void)
{
	sync_counter();
	local_flush_tlb_all();
	csr_write64(per_cpu_offset(0), PERCPU_BASE_KS);

	csr_write64(saved_regs.pgd, LOONGARCH_CSR_PGDL);
	csr_write64(saved_regs.kpgd, LOONGARCH_CSR_PGDH);
	csr_write32(saved_regs.pwctl0, LOONGARCH_CSR_PWCTL0);
	csr_write32(saved_regs.pwctl1, LOONGARCH_CSR_PWCTL1);
	csr_write32(saved_regs.ecfg, LOONGARCH_CSR_ECFG);
	csr_write32(saved_regs.euen, LOONGARCH_CSR_EUEN);
	csr_write64(eentry, LOONGARCH_CSR_EENTRY);
	csr_write64(tlbrentry, LOONGARCH_CSR_TLBRENTRY);
	csr_write64(eentry, LOONGARCH_CSR_MERRENTRY);
}

static void enable_gpe_wakeup(void)
{
	struct list_head *node, *next;
	u32 data = 0;

	data = readl((volatile void *)loongson_sysconf.gpe0_ena_reg);

	list_for_each_safe(node, next, &acpi_wakeup_device_list) {
		struct acpi_device *dev =
			container_of(node, struct acpi_device, wakeup_list);

		if (!dev->wakeup.flags.valid
			|| ACPI_STATE_S3 > (u32) dev->wakeup.sleep_state
			|| !(device_may_wakeup(&dev->dev)
			|| dev->wakeup.prepare_count))
			continue;

		data |= (1 << dev->wakeup.gpe_number);
	}
	writel(data, (volatile void *)loongson_sysconf.gpe0_ena_reg);
}

void enable_pcie_wakeup(void)
{
	u16 value;

	if (loongson_sysconf.is_soc_cpu || acpi_gbl_reduced_hardware)
		return;

	acpi_write_bit_register(ACPI_BITREG_PCIEXP_WAKE_STATUS, 1);

	if (loongson_sysconf.pcie_wake_enabled) {
		acpi_write_bit_register(ACPI_BITREG_PCIEXP_WAKE_DISABLE, 0);
	}
}
EXPORT_SYMBOL_GPL(enable_pcie_wakeup);

int loongarch_acpi_suspend(void)
{
	arch_common_suspend();
	enable_gpe_wakeup();
	enable_pcie_wakeup();
	/* processor specific suspend */
	loongarch_suspend_enter();
	arch_common_resume();

	return 0;
}

static int plat_pm_callback(struct notifier_block *nb, unsigned long action, void *ptr)
{
	int ret = 0;

	switch (action) {
	case PM_POST_SUSPEND:
		enable_gpe_wakeup();
		break;
	default:
		break;
	}

	return notifier_from_errno(ret);
}

static int __init plat_pm_post_init(void)
{
	if (loongson_sysconf.is_soc_cpu || acpi_gbl_reduced_hardware)
		return 0;

	enable_gpe_wakeup();
	pm_notifier(plat_pm_callback, -INT_MAX);
	return 0;
}

late_initcall_sync(plat_pm_post_init);
