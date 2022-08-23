#define pr_fmt(fmt) "pbk_cpu: " fmt

#include <linux/cpu.h>

#include "pbk_cpu.h"

cpumask_t __pbk_cpuset;
cpumask_t __pbk_available_cpuset;
DEFINE_SPINLOCK(pbk_acpuset_lock);

/*
 * Reserve and up/down pbk_cpus.
 */

int pbk_cpu_parse_args(const char *str, cpumask_t *pbk_cpus)
{
    int ret;

    cpumask_clear(pbk_cpus);
    ret = cpulist_parse(str, pbk_cpus);
    if (ret < 0 || cpumask_last(pbk_cpus) >= nr_cpu_ids)
        pr_err("Invalid cmdline pbk_cpus\n");
    if (cpumask_test_cpu(0, pbk_cpus)) {
        pr_err("Can not preserve cpu 0\n");
        ret = -EINVAL;
    }

    return ret;
}

static int __init pbk_cpus(char *str)
{
    int ret;

    ret = pbk_cpu_parse_args(str, pbk_cpuset);
    if (ret) {
        cpumask_clear(pbk_cpuset);
        ret = -EINVAL;
    }

    cpumask_copy(pbk_available_cpuset, pbk_cpuset);
    return ret;
}
early_param("pbk_cpus", pbk_cpus);

static int pbk_cpu_up(unsigned int cpu)
{
    int ret;

    ret = do_cpu_up(cpu, PBK_CPU_ONLINE_STATE);
    if (ret)
        pr_err("Failed to online CPU %u\n", cpu);
    else
        sched_domains_numa_masks_set(cpu);

    return ret;
}

static int pbk_cpu_down(unsigned int cpu)
{
    int ret;

    ret = cpu_down(cpu, PBK_CPU_OFFLINE_STATE);
    if (ret)
        pr_err("Failed to offline CPU %u\n", cpu);
    else
        sched_domains_numa_masks_clear(cpu);

    return ret;
}

int pbk_cpus_up(cpumask_var_t upset)
{
    unsigned int cpu;
    int ret;

    for_each_cpu(cpu, upset) {
        ret = pbk_cpu_up(cpu);
        if (ret)
            return ret;
    }
    return 0;
}

int pbk_cpus_down(cpumask_var_t downset)
{
    unsigned int cpu;
    int ret;

    for_each_cpu(cpu, downset) {
        ret = pbk_cpu_down(cpu);
        if (ret)
            return ret;
    }

    return 0;
}

/*
 * Allocate CPUs in @request from pbk_available_cpuset.
 */
int pbk_alloc_cpus(cpumask_var_t request)
{
    unsigned int cpu;
    cpumask_t hold;

    if (cpumask_empty(request)) {
        pr_err("Invalid request cpumask\n");
        return -EINVAL;
    }

    cpumask_clear(&hold);
    spin_lock(&pbk_acpuset_lock);
    for_each_cpu(cpu, request) {
        if (cpumask_test_and_clear_cpu(cpu, pbk_available_cpuset)) {
            cpumask_set_cpu(cpu, &hold);
        } else {
            spin_unlock(&pbk_acpuset_lock);
            pr_err("Request CPU %u is not available\n", cpu);
            /* Invalid request, so revert CPUs. */
            for_each_cpu(cpu, &hold)
                cpumask_set_cpu(cpu, pbk_available_cpuset);
            return -EINVAL;
        }
    }
    spin_unlock(&pbk_acpuset_lock);

    return 0;
}

int pbk_alloc_nr_cpu(unsigned int nr_cpu, cpumask_var_t mask)
{
    unsigned int cpu;

    if (nr_cpu <= 0) {
        pr_err("The value of nr_cpu must be greater than 0\n");
        return -EINVAL;
    }

    spin_lock(&pbk_acpuset_lock);
    if (cpumask_weight(pbk_available_cpuset) < nr_cpu) {
        spin_unlock(&pbk_acpuset_lock);
        pr_err("Available CPU is not enough\n");
        return -EINVAL;
    }

    for_each_cpu(cpu, pbk_available_cpuset) {
        cpumask_clear_cpu(cpu, pbk_available_cpuset);
        cpumask_set_cpu(cpu, mask);
        nr_cpu--;
        if (!nr_cpu)
            break;
    }

    spin_unlock(&pbk_acpuset_lock);

    if (nr_cpu) {
        pr_err("CPU is not enough. May race with others\n");
        BUG();
    }

    return 0;
}

/*
 * Give back CPUs in @release to pbk_available_cpuset.
 */
void pbk_free_cpus(cpumask_var_t release)
{
    unsigned int cpu;

    spin_lock(&pbk_acpuset_lock);
    for_each_cpu(cpu, release)
        cpumask_set_cpu(cpu, pbk_available_cpuset);
    spin_unlock(&pbk_acpuset_lock);
}

/*
 * Add/Delete CPUs @mask to/from domain @pd.
 */
void pbk_set_cpus(struct pbk_domain *pd, cpumask_var_t mask, bool add)
{
    if (add)
        cpumask_or(pbk_domain_cpu(pd), pbk_domain_cpu(pd), mask);
    else
        cpumask_andnot(pbk_domain_cpu(pd), pbk_domain_cpu(pd), mask);
}
