// SPDX-License-Identifier: GPL-2.0-only
/*
 * mem_sampling.c: declare the mem_sampling abstract layer and provide
 * unified pmu sampling for NUMA, DAMON, etc.
 *
 * Sample records are converted to mem_sampling_record, and then
 * mem_sampling_record_captured_cb_type invoke the callbacks to
 * pass the record.
 *
 * Copyright (c) 2024-2025, Huawei Technologies Ltd.
 */

#define pr_fmt(fmt) "mem_sampling: " fmt

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mem_sampling.h>
#include <linux/mempolicy.h>
#include <linux/task_work.h>
#include <linux/migrate.h>
#include <linux/sched/numa_balancing.h>
#include <trace/events/kmem.h>

struct mem_sampling_ops_struct mem_sampling_ops;

static int mem_sampling;

#define MEM_SAMPLING_DISABLED		0x0
#define MEM_SAMPLING_NORMAL		0x1
#define NUMA_BALANCING_HW_DISABLED	0x0
#define NUMA_BALANCING_HW_NORMAL	0x1

static int mem_sampling_override __initdata;
struct mem_sampling_record_cb_list_entry {
	struct list_head list;
	mem_sampling_record_cb_type cb;
};
LIST_HEAD(mem_sampling_record_cb_list);

#ifdef CONFIG_NUMABALANCING_MEM_SAMPLING
struct mem_sampling_numa_access_work {
	struct callback_head work;
	u64 vaddr, paddr;
	/* Test for debug : decode buffer cpu not same with handle interrupt cpu*/
	int cpu;
};
#endif /* CONFIG_NUMABALANCING_MEM_SAMPLING */

void mem_sampling_record_cb_register(mem_sampling_record_cb_type cb)
{
	struct mem_sampling_record_cb_list_entry *cb_entry, *tmp;

	list_for_each_entry_safe(cb_entry, tmp, &mem_sampling_record_cb_list, list) {
		if (cb_entry->cb == cb) {
			pr_info("mem_sampling record cb already registered\n");
			return;
		}
	}

	cb_entry = kmalloc(sizeof(struct mem_sampling_record_cb_list_entry), GFP_KERNEL);
	if (!cb_entry) {
		pr_info("mem_sampling record cb entry alloc memory failed\n");
		return;
	}

	cb_entry->cb = cb;
	list_add(&(cb_entry->list), &mem_sampling_record_cb_list);
}

void mem_sampling_record_cb_unregister(mem_sampling_record_cb_type cb)
{
	struct mem_sampling_record_cb_list_entry *cb_entry, *tmp;

	list_for_each_entry_safe(cb_entry, tmp, &mem_sampling_record_cb_list, list) {
		if (cb_entry->cb == cb) {
			list_del(&cb_entry->list);
			kfree(cb_entry);
			return;
		}
	}
}

DEFINE_STATIC_KEY_FALSE(mem_sampling_access_hints);

void mem_sampling_sched_in(struct task_struct *prev, struct task_struct *curr)
{
	if (!static_branch_unlikely(&mem_sampling_access_hints))
		return;
	if (!mem_sampling_ops.sampling_start)
		return;

	if (curr->mm)
		mem_sampling_ops.sampling_start();
	else
		mem_sampling_ops.sampling_stop();
}

bool mem_sampling_enabled(void)
{
	return mem_sampling;
}
EXPORT_SYMBOL_GPL(mem_sampling_enabled);

static void mem_sampling_process(struct mem_sampling_record *record_base, int nr_records)
{
	int i;
	struct mem_sampling_record *record;
	struct mem_sampling_record_cb_list_entry *cb_entry, *tmp;

	if (list_empty(&mem_sampling_record_cb_list))
		goto out;

	for (i = 0; i < nr_records; i++) {
		record = record_base + i;
		list_for_each_entry_safe(cb_entry, tmp, &mem_sampling_record_cb_list, list) {
			cb_entry->cb(record);
		}
	}
out:
	/* if mem_sampling_access_hints is set to false, stop sampling */
	if (static_branch_unlikely(&mem_sampling_access_hints))
		mem_sampling_ops.sampling_continue();
	else
		mem_sampling_ops.sampling_stop();
}

#ifdef CONFIG_NUMABALANCING_MEM_SAMPLING

static int numa_migrate_prep(struct page *page, struct vm_area_struct *vma,
				unsigned long addr, int page_nid,
				int *flags)
{
	get_page(page);

	count_vm_numa_event(NUMA_HINT_FAULTS);
	if (page_nid == numa_node_id()) {
		count_vm_numa_event(NUMA_HINT_FAULTS_LOCAL);
		*flags |= TNF_FAULT_LOCAL;
	}

	return mpol_misplaced(page, vma, addr);
}

/*
 * Called from task_work context to act upon the page access.
 *
 * Physical address (provided by SPE) is used directly instead
 * of walking the page tables to get to the PTE/page. Hence we
 * don't check if PTE is writable for the TNF_NO_GROUP
 * optimization, which means RO pages are considered for grouping.
 */
static void do_numa_access(struct task_struct *p, u64 vaddr, u64 paddr)
{
	struct mm_struct *mm = p->mm;
	struct vm_area_struct *vma;
	struct page *page = NULL;
	int page_nid = NUMA_NO_NODE;
	int last_cpupid;
	int target_nid;
	int flags = 0;

	if (!mm)
		return;

	if (!mmap_read_trylock(mm))
		return;

	vma = find_vma(mm, vaddr);
	if (!vma)
		goto out_unlock;

	if (!vma_migratable(vma) || !vma_policy_mof(vma) ||
		is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_MIXEDMAP))
		goto out_unlock;

	if (!vma->vm_mm ||
	    (vma->vm_file && (vma->vm_flags & (VM_READ|VM_WRITE)) == (VM_READ)))
		goto out_unlock;

	if (!vma_is_accessible(vma))
		goto out_unlock;

	page = pfn_to_online_page(PHYS_PFN(paddr));
	if (!page || is_zone_device_page(page))
		goto out_unlock;

	if (unlikely(!PageLRU(page)))
		goto out_unlock;

	/* TODO: handle PTE-mapped THP or PMD-mapped THP*/
	if (PageCompound(page))
		goto out_unlock;

	/*
	 * Flag if the page is shared between multiple address spaces. This
	 * is later used when determining whether to group tasks together
	 */
	if (page_mapcount(page) > 1 && (vma->vm_flags & VM_SHARED))
		flags |= TNF_SHARED;

	last_cpupid = page_cpupid_last(page);
	page_nid = page_to_nid(page);

	target_nid = numa_migrate_prep(page, vma, vaddr, page_nid, &flags);
	if (target_nid == NUMA_NO_NODE) {
		put_page(page);
		goto out;
	}

	/* Migrate to the requested node */
	if (migrate_misplaced_page(page, vma, target_nid)) {
		page_nid = target_nid;
		flags |= TNF_MIGRATED;
	} else {
		flags |= TNF_MIGRATE_FAIL;
	}

out:
	trace_mm_numa_migrating(vaddr, page_nid, target_nid, flags&TNF_MIGRATED);
	if (page_nid != NUMA_NO_NODE)
		task_numa_fault(last_cpupid, page_nid, 1, flags);

out_unlock:
	mmap_read_unlock(mm);
}

static void task_mem_sampling_access_work(struct callback_head *work)
{
	struct mem_sampling_numa_access_work *iwork =
		container_of(work, struct mem_sampling_numa_access_work, work);

	if (iwork->cpu == smp_processor_id())
		do_numa_access(current, iwork->vaddr, iwork->paddr);
	kfree(iwork);
}

static void numa_create_taskwork(u64 vaddr, u64 paddr, int cpu)
{
	struct mem_sampling_numa_access_work *iwork = NULL;

	iwork = kzalloc(sizeof(*iwork), GFP_ATOMIC);
	if (!iwork)
		return;

	iwork->vaddr = vaddr;
	iwork->paddr = paddr;
	iwork->cpu = smp_processor_id();

	init_task_work(&iwork->work, task_mem_sampling_access_work);
	task_work_add(current, &iwork->work, TWA_RESUME);
}

static void numa_balancing_mem_sampling_cb(struct mem_sampling_record *record)
{
	struct task_struct *p = current;
	u64 vaddr = record->virt_addr;
	u64 paddr = record->phys_addr;

	/* Discard kernel address accesses */
	if (vaddr & (1UL << 63))
		return;

	if (p->pid != record->context_id)
		return;

	trace_mm_mem_sampling_access_record(vaddr, paddr, smp_processor_id(),
					current->pid);
	numa_create_taskwork(vaddr, paddr, smp_processor_id());
}

static void numa_balancing_mem_sampling_cb_register(void)
{
	mem_sampling_record_cb_register(numa_balancing_mem_sampling_cb);
}

static void numa_balancing_mem_sampling_cb_unregister(void)
{
	mem_sampling_record_cb_unregister(numa_balancing_mem_sampling_cb);
}
#endif /* CONFIG_NUMABALANCING_MEM_SAMPLING */

static inline enum mem_sampling_type_enum mem_sampling_get_type(void)
{
#ifdef CONFIG_ARM_SPE_MEM_SAMPLING
	return MEM_SAMPLING_ARM_SPE;
#else
	return MEM_SAMPLING_UNSUPPORTED;
#endif
}

DEFINE_STATIC_KEY_FALSE(sched_numabalancing_mem_sampling);

#ifdef CONFIG_NUMABALANCING_MEM_SAMPLING

static void set_numabalancing_mem_sampling_state(bool enabled)
{
	if (enabled) {
		numa_balancing_mem_sampling_cb_register();
		static_branch_enable(&sched_numabalancing_mem_sampling);
	} else {
		numa_balancing_mem_sampling_cb_unregister();
		static_branch_disable(&sched_numabalancing_mem_sampling);
	}
}

#ifdef CONFIG_PROC_SYSCTL
int sysctl_numabalancing_mem_sampling(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = static_branch_likely(&sched_numabalancing_mem_sampling);

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	if (write && static_branch_likely(&mem_sampling_access_hints))
		set_numabalancing_mem_sampling_state(state);

	return err;
}
#endif
#else
static inline void set_numabalancing_mem_sampling_state(bool enabled)
{

}
#endif

static int sysctl_mem_sampling_mode;

static void __set_mem_sampling_state(bool enabled)
{
	if (enabled)
		static_branch_enable(&mem_sampling_access_hints);
	else
		static_branch_disable(&mem_sampling_access_hints);
}

static void set_mem_sampling_state(bool enabled)
{
	if (!mem_sampling_ops.sampling_start)
		return;
	if (enabled)
		sysctl_mem_sampling_mode = MEM_SAMPLING_NORMAL;
	else
		sysctl_mem_sampling_mode = MEM_SAMPLING_DISABLED;
	__set_mem_sampling_state(enabled);

	if (!enabled)
		set_numabalancing_mem_sampling_state(enabled);
}

#ifdef CONFIG_PROC_SYSCTL
static int sysctl_mem_sampling_enable(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = sysctl_mem_sampling_mode;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write)
		set_mem_sampling_state(state);
	return err;
}
#endif

static struct ctl_table ctl_table[] = {
	{
		.procname       = "mem_sampling_enable",
		.data           = NULL, /* filled in by handler */
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler   = sysctl_mem_sampling_enable,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#ifdef CONFIG_NUMABALANCING_MEM_SAMPLING
	{
		.procname	= "numa_balancing_mem_sampling",
		.data		= NULL, /* filled in by handler */
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_numabalancing_mem_sampling,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif /* CONFIG_NUMABALANCING_MEM_SAMPLING */
	{}
};

static struct ctl_table mem_sampling_dir_table[] = {
	{
		.procname = "kernel",
		.maxlen = 0,
		.mode = 0555,
		.child = ctl_table,
	},
	{}
};

static void __init check_mem_sampling_enable(void)
{
	bool mem_sampling_default = false;

	/* Parsed by setup_mem_sampling. override == 1 enables, -1 disables */
	if (mem_sampling_override)
		set_mem_sampling_state(mem_sampling_override == 1);
	else
		set_mem_sampling_state(mem_sampling_default);
}

static int __init mem_sampling_setup(char *str)
{
	mem_sampling = 1;
	return 1;

}
__setup("mem_sampling_on", mem_sampling_setup);

static int __init mem_sampling_init(void)
{
	enum mem_sampling_type_enum mem_sampling_type = mem_sampling_get_type();

	switch (mem_sampling_type) {
	case MEM_SAMPLING_ARM_SPE:
		if (!arm_spe_enabled()) {
			set_mem_sampling_state(false);
			return -ENODEV;
		}
		mem_sampling_ops.sampling_start		= arm_spe_start;
		mem_sampling_ops.sampling_stop		= arm_spe_stop;
		mem_sampling_ops.sampling_continue	= arm_spe_continue;

		arm_spe_record_capture_callback_register(mem_sampling_process);
		break;

	default:
		pr_info("unsupport hardware pmu type(%d), disable access hint!\n",
			mem_sampling_type);
		set_mem_sampling_state(false);
		return -ENODEV;
	}
	check_mem_sampling_enable();

	if (!register_sysctl_table(mem_sampling_dir_table))
		return -ENOMEM;

	return 0;
}
late_initcall(mem_sampling_init);
