#ifdef CONFIG_PURPOSE_BUILT_KERNEL

#ifndef _LINUX_PBK_H
#define _LINUX_PBK_H

#include <linux/cpu.h>
#include <linux/refcount.h>
#include <linux/spinlock_types.h>
#include <linux/hashtable.h>

typedef pid_t pdid_t;

#define NR_DOMAINS_MAX          16
#define NR_DOMAINS_MAX_BITS     4

extern struct hlist_head pbk_domains[NR_DOMAINS_MAX];
extern spinlock_t pbk_domains_lock;

#define DOMAIN_NAME_LEN         64

struct pbk_domain {
    char name [DOMAIN_NAME_LEN];
    /* Same as pid of the process that creates this domain. */
    pdid_t domain_id;
    refcount_t refcount;
    cpumask_t cpuset;

    /* All processes that join to this domain */
    struct list_head process_list;
    spinlock_t process_list_lock;

    /* Node of hashtable that maps domain_id to domain */
    struct hlist_node ht_node;
};

extern void pbk_create_root_domain(void);
extern struct pbk_domain *pbk_find_get_domain(pdid_t domain_id);
extern struct pbk_domain *pbk_find_get_domain_withcpu(cpumask_var_t mask);
extern struct pbk_domain *pbk_alloc_domain(cpumask_var_t request);
extern void pbk_attach_domain(struct task_struct *p, struct pbk_domain *pd);
extern void destroy_pbk_domain(struct pbk_domain *pd);
extern int pbk_resched_threads(struct task_struct *p, cpumask_var_t new);
extern int pbk_resched_domain_process(struct pbk_domain *pd);
extern void pbk_del_process(struct task_struct *p, struct pbk_domain *pd);

static inline bool is_pbk_process(struct task_struct *p)
{
    return p->pbkd ? true : false;
}

static inline bool is_pbk_view(struct task_struct *p)
{
    return p->pbk_view ? true : false;
}

static inline bool is_pbk_allowed_kthread(struct task_struct *p)
{
    return !strncmp(p->comm, "cpuhp", 5) ||
           !strncmp(p->comm, "ksoftirqd", 9) ||
           !strncmp(p->comm, "migration", 9) ||
           !strncmp(p->comm, "osnoise", 7);
}

static inline cpumask_t *pbk_domain_cpu(struct pbk_domain *pd)
{
    return &pd->cpuset;
}

static inline cpumask_t *current_pbk_cpu(void)
{
    return pbk_domain_cpu(current->pbkd);
}

static inline void get_pbk_domain(struct pbk_domain *pd)
{
    refcount_inc(&pd->refcount);
}

static inline void put_pbk_domain(struct pbk_domain *pd)
{
    if (refcount_dec_and_test(&pd->refcount))
        destroy_pbk_domain(pd);
}

extern cpumask_t __pbk_cpuset;
extern cpumask_t __pbk_available_cpuset;
extern spinlock_t pbk_acpuset_lock;

#define pbk_cpuset (&__pbk_cpuset)
#define pbk_available_cpuset    (&__pbk_available_cpuset)

static inline bool is_pbk_cpu(unsigned int cpu)
{
    return cpumask_test_cpu(cpu, pbk_cpuset);
}

static inline bool is_current_pbk_cpu(unsigned int cpu)
{
    return cpumask_test_cpu(cpu, current_pbk_cpu());
}

static inline bool is_pbk_cpu_state(enum cpuhp_state state)
{
    return (state != CPUHP_AP_IRQ_AFFINITY_ONLINE) &&
           (state != CPUHP_AP_WORKQUEUE_ONLINE) &&
           (state != CPUHP_AP_RCUTREE_ONLINE);
}

extern int do_cpu_up(unsigned int cpu, enum cpuhp_state target);
extern int cpu_down(unsigned int cpu, enum cpuhp_state target);

extern void sched_domains_numa_masks_set(unsigned int cpu);
extern void sched_domains_numa_masks_clear(unsigned int cpu);

#endif /* _LINUX_PBK_H */

#endif /* CONFIG_PURPOSE_BUILT_KERNEL */