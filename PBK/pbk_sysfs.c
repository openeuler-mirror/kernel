#define pr_fmt(fmt) "pbk_sysfs: " fmt

#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/pbk.h>

#include "pbk_cpu.h"

static struct kobject *pbk_kobj;

static ssize_t pbk_create_domain_store(struct kobject *kobj,
        struct kobj_attribute *attr, const char *buf, size_t count)
{
    cpumask_t request;
    struct pbk_domain *pd;
    int ret;

    ret = cpulist_parse(buf, &request);
    if (ret || !cpumask_subset(&request, pbk_cpuset))
        return -EINVAL;

    ret = pbk_alloc_cpus(&request);
    if (ret)
        goto try_get_pd;

    pd = pbk_alloc_domain(&request);
    if (IS_ERR(pd)) {
        pr_err("Failed to allocate pbk domain\n");
        return PTR_ERR(pd);
    }

    current->pbkd = pd;

    ret = pbk_resched_domain_process(pd);
    if (ret)
        return ret;

    return count;

try_get_pd:
    pd = pbk_find_get_domain_withcpu(&request);
    if (!pd)
        return -EINVAL;

    pbk_attach_domain(current, pd);
    pbk_resched_threads(current, pbk_domain_cpu(pd));
    put_pbk_domain(pd);

    return count;
}

static struct kobj_attribute pbk_create_domain_attr = __ATTR_WO(pbk_create_domain);

static ssize_t pbk_with_nr_cpu_store(struct kobject *kobj,
        struct kobj_attribute *attr, const char *buf, size_t count)
{
    cpumask_t request;
    unsigned int nr_cpu;
    struct pbk_domain *pd;
    int ret;

    ret = kstrtoint(buf, 0, &nr_cpu);
    if (ret)
        return -EINVAL;
    
    cpumask_clear(&request);
    ret = pbk_alloc_nr_cpu(nr_cpu, &request);
    if (ret)
        return ret;
    
    pd = pbk_alloc_domain(&request);
    if (IS_ERR(pd)) {
        pr_err("Failed to allocate pbk domain\n");
        return PTR_ERR(pd);
    }

    current->pbkd = pd;

    ret = pbk_resched_domain_process(pd);
    if (ret)
        return ret;
    
    return count;
}

static struct kobj_attribute pbk_with_nr_cpu_attr = __ATTR_WO(pbk_with_nr_cpu);

static ssize_t pbk_view_store(struct kobject *kobj,
        struct kobj_attribute *attr, const char *buf, size_t count)
{
    int pbk_view = 0;
    int ret;

    ret = kstrtoint(buf, 0, &pbk_view);
    if (ret || pbk_view != 1)
        return -EINVAL;
    
    if (pbk_view)
        current->pbk_view = 1;
    else
        current->pbk_view = 0;

    return count;
}

static struct kobj_attribute pbk_view_attr = __ATTR_WO(pbk_view);

static struct attribute *pbk_attributes[] = {
    &pbk_create_domain_attr.attr,
    &pbk_with_nr_cpu_attr.attr,
    &pbk_view_attr.attr,
    NULL
};

static struct attribute_group pbk_attr_group = {
    .attrs = pbk_attributes,
};

static int __init pbk_sysfs_init(void)
{
    int ret;

    pbk_kobj = kobject_create_and_add("PBK", kernel_kobj);
    if (!pbk_kobj)
        return -ENOMEM;
    
    pbk_create_domain_attr.attr.mode |= S_IWGRP;
    pbk_with_nr_cpu_attr.attr.mode |= S_IWGRP;
    pbk_view_attr.attr.mode |= S_IWGRP;

    ret = sysfs_create_group(pbk_kobj, &pbk_attr_group);
    if (ret) {
        pr_err("Failed to create sysfs entries for PBK\n");
        return ret;
    }

    return 0;
}

subsys_initcall(pbk_sysfs_init);
