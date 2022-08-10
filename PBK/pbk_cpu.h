#ifndef _PBK_CPU_H
#define _PBK_CPU_H

#include <linux/pbk.h>

#define PBK_CPU_ONLINE_STATE  (CPUHP_AP_ACTIVE - 1)
#define PBK_CPU_OFFLINE_STATE CPUHP_OFFLINE

int pbk_cpu_parse_args(const char *str, cpumask_t *pbk_cpus);

int pbk_cpus_up(cpumask_var_t upset);
int pbk_cpus_down(cpumask_var_t downset);

int pbk_alloc_cpus(cpumask_var_t request);
int pbk_alloc_nr_cpu(unsigned int nr_cpu, cpumask_var_t mask);
void pbk_free_cpus(cpumask_var_t release);

#endif /* _PBK_CPU_H */