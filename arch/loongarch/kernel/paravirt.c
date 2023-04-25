// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Loongson Technology Co., Ltd.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * LoongArch paravirtualization support.
 *
 * Author: zhangyanyue <zhangyanyue@loongson.cn>
 */
#include <linux/export.h>
#include <linux/types.h>
#include <linux/cpu.h>
#include <linux/hugetlb.h>
#include <linux/kvm_para.h>
#include <linux/init.h>
#include <linux/reboot.h>
#include <asm/paravirt.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/pgtable.h>

struct static_key paravirt_steal_enabled;
struct static_key paravirt_steal_rq_enabled;

static DEFINE_PER_CPU(struct kvm_steal_time, steal_time) __aligned(64);
static int has_steal_clock;
static unsigned int pv_feature_disabled;

static u64 dummy_steal_clock(int cpu)
{
	return 0;
}

static u64 pv_steal_clock(int cpu)
{
	u64 steal;
	struct kvm_steal_time *src;
	int version;

	src = &per_cpu(steal_time, cpu);
	do {

		version = src->version;
		/* Make sure that the version is read before the steal. */
		virt_rmb();
		steal = src->steal;
		/* Make sure that the steal is read before the next version. */
		virt_rmb();

	} while ((version & 1) || (version != src->version));
	return steal;
}

struct pv_time_ops pv_time_ops = {
	.steal_clock = dummy_steal_clock,
};
EXPORT_SYMBOL_GPL(pv_time_ops);

phys_addr_t slow_virt_to_phys(const void *vaddr)
{
	unsigned long addr = (unsigned long) vaddr;
	unsigned long page_mask = 0;
	pgd_t *pgd = pgd_offset_k(addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	phys_addr_t phys_addr;

	/* See arch/loongarch/kernel/numa.c: setup_per_cpu_areas() */
	if (nr_node_ids < 8)
		return virt_to_phys((void *)vaddr);

	if (pgd_none(*pgd))
		goto out;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		goto out;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto out;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto out;

#ifdef KVM_HUGE_TLB_SUPPORT
	if (pmd_huge(*pmd)) {
		pte = (pte_t *)pmd;
		page_mask = PMD_MASK;
		goto out;
	}
#endif

	pte = pte_offset_kernel(pmd, addr);
	page_mask = PAGE_MASK;

out:
	phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) | (addr & ~page_mask);
	return phys_addr;
}

static void pv_register_steal_time(void)
{
	int cpu = smp_processor_id();
	struct kvm_steal_time *st;

	if (!has_steal_clock)
		return;

	st = &per_cpu(steal_time, cpu);
	pv_notify_host(KVM_FEATURE_STEAL_TIME, slow_virt_to_phys(st));

	pr_info("pv stealtime: cpu %d, st:0x%llx phys:0x%llx\n",
			cpu, (unsigned long long)st, (unsigned long long) slow_virt_to_phys(st));
}

#ifdef CONFIG_SMP
static void pv_disable_steal_time(void)
{
	if (has_steal_clock)
		pv_notify_host(KVM_FEATURE_STEAL_TIME, 0);
}

static int pv_cpu_online(unsigned int cpu)
{
	unsigned long flags;

	local_irq_save(flags);
	pv_register_steal_time();
	local_irq_restore(flags);
	return 0;
}

static int pv_cpu_down_prepare(unsigned int cpu)
{
	unsigned long flags;

	local_irq_save(flags);
	pv_disable_steal_time();
	local_irq_restore(flags);
	return 0;
}
#endif
static void pv_cpu_reboot(void *unused)
{
	pv_disable_steal_time();
}
static int pv_reboot_notify(struct notifier_block *nb, unsigned long code,
		void *unused)
{
	on_each_cpu(pv_cpu_reboot, NULL, 1);
	return NOTIFY_DONE;
}
static struct notifier_block pv_reboot_nb = {
	.notifier_call	= pv_reboot_notify,
};
int __init pv_time_init(void)
{
	if (!cpu_has_hypervisor)
		return 0;
	if (!kvm_para_available())
		return 0;

	if (!(pv_feature_disabled & (1 << KVM_FEATURE_STEAL_TIME)) &&
			pv_feature_support(KVM_FEATURE_STEAL_TIME)) {

		register_reboot_notifier(&pv_reboot_nb);

		has_steal_clock = 1;
		pv_time_ops.steal_clock = pv_steal_clock;
		pv_register_steal_time();
		static_key_slow_inc(&paravirt_steal_enabled);
		static_key_slow_inc(&paravirt_steal_rq_enabled);

#ifdef CONFIG_SMP
		if (cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "loongarch/pv:online",
					pv_cpu_online, pv_cpu_down_prepare) < 0)
			pr_err("failed to install cpu hotplug callbacks\n");
#endif
	}
	return 0;
}

static void pv_send_ipi(const struct cpumask *mask, unsigned int action)
{
	unsigned long flags;
	unsigned int cpu, i, min = 0, max = 0;
	u64 ipi_bitmap = 0;
	long ret;

	if (cpumask_empty(mask))
		return;

	local_irq_save(flags);

	for_each_cpu(i, mask) {
		cpu = cpu_logical_map(i);
		if (!ipi_bitmap) {
			min = max = cpu;
		} else if (cpu < min && (max - cpu) < BITS_PER_LONG) {
			ipi_bitmap <<= min - cpu;
			min = cpu;
		} else if (cpu > min && cpu < min + BITS_PER_LONG) {
			max = cpu < max ? max : cpu;
		} else {
			ret = kvm_hypercall3(KVM_HC_FUNC_IPI, ipi_bitmap, min, action);
			WARN_ONCE(ret < 0, "KVM: failed to send PV IPI: %ld", ret);
			min = max = cpu;
			ipi_bitmap = 0;
		}
		__set_bit(cpu - min, (unsigned long *)&ipi_bitmap);
	}

	if (ipi_bitmap) {
		ret = kvm_hypercall3(KVM_HC_FUNC_IPI, ipi_bitmap, min, action);
		WARN_ONCE(ret < 0, "KVM: failed to send PV IPI: %ld", ret);
	}

	local_irq_restore(flags);
}

extern struct smp_ops smp_ops;
int __init pv_ipi_init(void)
{
	if (!cpu_has_hypervisor)
		return 0;
	if (!IS_ENABLED(CONFIG_SMP))
		return 0;
	if (!kvm_para_available())
		return 0;

	if (!(pv_feature_disabled & (1 << KVM_FEATURE_MULTI_IPI)) &&
			pv_feature_support(KVM_FEATURE_MULTI_IPI)) {
		smp_ops.send_call_func_ipi = pv_send_ipi;
	}
	return 0;
}

static int __init set_pv_ipi(char *str)
{
	pv_feature_disabled |= (1 << KVM_FEATURE_MULTI_IPI);
	return 0;
}
early_param("no_pvipi", set_pv_ipi);

static int __init set_pv_time(char *str)
{
	pv_feature_disabled |= (1 << KVM_FEATURE_STEAL_TIME);
	return 0;
}
early_param("no_pvtime", set_pv_time);
