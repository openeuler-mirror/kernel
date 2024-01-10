// SPDX-License-Identifier: GPL-2.0-only
/*
 * NMI support for IPIs
 *
 * Copyright (C) 2020 Linaro Limited
 * Author: Sumit Garg <sumit.garg@linaro.org>
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kgdb.h>
#include <linux/nmi.h>
#include <linux/smp.h>

#include <asm/nmi.h>

static struct irq_desc *ipi_nmi_desc __read_mostly;
static int ipi_nmi_id __read_mostly;

bool arm64_supports_nmi(void)
{
	if (ipi_nmi_desc)
		return true;

	return false;
}

void arm64_send_nmi(cpumask_t *mask)
{
	if (WARN_ON_ONCE(!ipi_nmi_desc))
		return;

	__ipi_send_mask(ipi_nmi_desc, mask);
}

#ifdef CONFIG_NON_NMI_IPI_BACKTRACE
static void ipi_cpu_backtrace(void *info)
{
	__printk_safe_enter();
	nmi_cpu_backtrace(get_irq_regs());
	__printk_safe_exit();
}

static DEFINE_PER_CPU(call_single_data_t, cpu_backtrace_csd) =
	CSD_INIT(ipi_cpu_backtrace, NULL);

static void arm64_send_ipi(cpumask_t *mask)
{
	call_single_data_t *csd;
	int this_cpu = raw_smp_processor_id();
	int cpu;
	int ret;

	for_each_online_cpu(cpu) {
		if (cpu == this_cpu)
			continue;
		csd = &per_cpu(cpu_backtrace_csd, cpu);
		ret = smp_call_function_single_async(cpu, csd);
		if (ret)
			pr_info("Sending IPI failed to CPU %d\n", cpu);
	}
}
#endif

bool arch_trigger_cpumask_backtrace(const cpumask_t *mask, int exclude_cpu)
{
	if (ipi_nmi_desc)
		nmi_trigger_cpumask_backtrace(mask, exclude_cpu, arm64_send_nmi);
#ifdef CONFIG_NON_NMI_IPI_BACKTRACE
	else
		nmi_trigger_cpumask_backtrace(mask, exclude_cpu, arm64_send_ipi);
#endif

	return true;
}

static irqreturn_t ipi_nmi_handler(int irq, void *data)
{
	irqreturn_t ret = IRQ_NONE;
	unsigned int cpu = smp_processor_id();

	if (nmi_cpu_backtrace(get_irq_regs()))
		ret = IRQ_HANDLED;

	if (!kgdb_nmicallback(cpu, get_irq_regs()))
		ret = IRQ_HANDLED;

	return ret;
}

void dynamic_ipi_setup(int cpu)
{
	if (!ipi_nmi_desc)
		return;

	if (!prepare_percpu_nmi(ipi_nmi_id))
		enable_percpu_nmi(ipi_nmi_id, IRQ_TYPE_NONE);
}

void dynamic_ipi_teardown(int cpu)
{
	if (!ipi_nmi_desc)
		return;

	disable_percpu_nmi(ipi_nmi_id);
	teardown_percpu_nmi(ipi_nmi_id);
}

void __init set_smp_dynamic_ipi(int ipi)
{
	if (!request_percpu_nmi(ipi, ipi_nmi_handler, "IPI", &cpu_number)) {
		ipi_nmi_desc = irq_to_desc(ipi);
		ipi_nmi_id = ipi;
	}
}
