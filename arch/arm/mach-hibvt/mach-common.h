// SPDX-License-Identifier: GPL-2.0
#ifndef __SMP_COMMON_H
#define __SMP_COMMON_H

#ifdef CONFIG_SMP
void hi35xx_set_cpu(unsigned int cpu, bool enable);
void __init hi35xx_smp_prepare_cpus(unsigned int max_cpus);
int hi35xx_boot_secondary(unsigned int cpu, struct task_struct *idle);
#endif /* CONFIG_SMP */
#endif /* __SMP_COMMON_H */
