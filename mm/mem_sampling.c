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

struct mem_sampling_ops_struct mem_sampling_ops;

#define MEM_SAMPLING_DISABLED		0x0
#define MEM_SAMPLING_NORMAL		0x1

static int mem_sampling_override __initdata;
struct mem_sampling_record_cb_list_entry {
	struct list_head list;
	mem_sampling_record_cb_type cb;
};
LIST_HEAD(mem_sampling_record_cb_list);

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

static inline enum mem_sampling_type_enum mem_sampling_get_type(void)
{
#ifdef CONFIG_ARM_SPE_MEM_SAMPLING
	return MEM_SAMPLING_ARM_SPE;
#else
	return MEM_SAMPLING_UNSUPPORTED;
#endif
}

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
