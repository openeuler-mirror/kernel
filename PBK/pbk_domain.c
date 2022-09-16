#define pr_fmt(fmt) "pbk_domain: " fmt

#include <linux/pbk.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#include "pbk_cpu.h"

DEFINE_HASHTABLE(pbk_domains, NR_DOMAINS_MAX_BITS);
DEFINE_SPINLOCK(pbk_domains_lock);

/*
 * Create PBK root domain with pbk_cpuset.
 */
void pbk_create_root_domain(void)
{
    cpumask_t workqueue_unbound_mask;
    int ret;

    if (cpumask_empty(pbk_cpuset)) {
        pr_info("No valid pbk_cpuset, skip creating PBK root domain\n");
        return;
    }

    ret = pbk_cpus_up(pbk_cpuset);
    if (ret)
        pr_err("Failed to create PBK root domain\n");

    cpumask_copy(pbk_available_cpuset, pbk_cpuset);
    cpumask_andnot(&workqueue_unbound_mask, cpu_possible_mask, pbk_cpuset);
    ret = workqueue_set_unbound_cpumask(&workqueue_unbound_mask);
    if (!ret)
        pr_info("Set workqueue unbound cpumask to %*pbl\n",
                cpumask_pr_args(&workqueue_unbound_mask));
}

static void pbk_add_domain(struct pbk_domain *pd)
{
    spin_lock(&pbk_domains_lock);
    hash_add(pbk_domains, &pd->ht_node, pd->domain_id);
    spin_unlock(&pbk_domains_lock);
}

struct pbk_domain *pbk_find_get_domain(pdid_t domain_id)
{
    struct pbk_domain *pd;

    spin_lock(&pbk_domains_lock);
    hash_for_each_possible(pbk_domains, pd, ht_node, domain_id) {
        if (pd->domain_id == domain_id) {
            get_pbk_domain(pd);
            spin_unlock(&pbk_domains_lock);
            return pd;
        }
    }
    spin_unlock(&pbk_domains_lock);

    pr_err("PBK domain %d is not found\n", domain_id);
    return NULL;
}

struct pbk_domain *pbk_find_get_domain_withcpu(cpumask_var_t mask)
{
    struct pbk_domain *pd;
    struct hlist_node *tmp;
    unsigned long timeout;
    int bkt;

    timeout = USEC_PER_SEC;
    while (timeout--) {
        hash_for_each_safe(pbk_domains, bkt, tmp, pd, ht_node) {
            if (cpumask_equal(mask, pbk_domain_cpu(pd))) {
                get_pbk_domain(pd);
                return pd;
            }
        }
        udelay(1);
    };

    pr_err("invalid cpulist request %*pbl\n", cpumask_pr_args(mask));
    return NULL;
}

static void pbk_del_domain(struct pbk_domain *pd)
{
    spin_lock(&pbk_domains_lock);
    hash_del(&pd->ht_node);
    spin_unlock(&pbk_domains_lock);
}

static void pbk_add_process(struct task_struct *p, struct pbk_domain *pd)
{
    spin_lock(&pd->process_list_lock);
    list_add(&p->pbk_process, &pd->process_list);
    spin_unlock(&pd->process_list_lock);
}

void pbk_del_process(struct task_struct *p, struct pbk_domain *pd)
{
    spin_lock(&pd->process_list_lock);
    list_del(&p->pbk_process);
    spin_unlock(&pd->process_list_lock);
}

void pbk_attach_domain(struct task_struct *p, struct pbk_domain *pd)
{
    p->pbkd = pd;
    pbk_add_process(p, pd);
    get_pbk_domain(pd);
}

/*
 * Allocate a PBK domain with @request CPU.
 */
struct pbk_domain *pbk_alloc_domain(cpumask_var_t request)
{
    struct pbk_domain *pd;
    pd = kmalloc(sizeof(struct pbk_domain), GFP_KERNEL);
    if (!pd)
        return ERR_PTR(-ENOMEM);

    refcount_set(&pd->refcount, 1);
    spin_lock_init(&pd->process_list_lock);
    INIT_LIST_HEAD(&pd->process_list);
    cpumask_copy(pbk_domain_cpu(pd), request);
    pd->domain_id = current->pid;
    pbk_add_process(current, pd);
    pbk_add_domain(pd);

    return pd;
}

void destroy_pbk_domain(struct pbk_domain *pd)
{
    pbk_free_cpus(pbk_domain_cpu(pd));
    pbk_del_domain(pd);
    kfree(pd);
}

int pbk_resched_threads(struct task_struct *p, cpumask_var_t new)
{
    struct task_struct *tsk;
    int ret = 0;

    for_each_thread(p, tsk) {
        ret = sched_setaffinity(tsk->pid, new);
        if (ret) {
            pr_err("Failed to set affinity for task %d\n", tsk->pid);
            return ret;
        }
    }
    return ret;
}

int pbk_resched_domain_process(struct pbk_domain *pd)
{
    struct task_struct *p;
    int ret = 0;

    spin_lock(&pd->process_list_lock);

    list_for_each_entry(p, &pd->process_list, pbk_process) {
        ret = sched_setaffinity(p->pid, pbk_domain_cpu(pd));
        if (ret)
            goto out;
    }
out:
    spin_unlock(&pd->process_list_lock);
    return ret;
}
