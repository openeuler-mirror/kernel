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

void mem_sampling_sched_in(struct task_struct *prev, struct task_struct *curr)
{
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
	mem_sampling_ops.sampling_continue();
}

static inline enum mem_sampling_type_enum mem_sampling_get_type(void)
{
#ifdef CONFIG_ARM_SPE_MEM_SAMPLING
	return MEM_SAMPLING_ARM_SPE;
#else
	return MEM_SAMPLING_UNSUPPORTED;
#endif
}

static int __init mem_sampling_init(void)
{
	enum mem_sampling_type_enum mem_sampling_type = mem_sampling_get_type();

	switch (mem_sampling_type) {
	case MEM_SAMPLING_ARM_SPE:
		if (!arm_spe_enabled())
			return -ENODEV;
		mem_sampling_ops.sampling_start		= arm_spe_start;
		mem_sampling_ops.sampling_stop		= arm_spe_stop;
		mem_sampling_ops.sampling_continue	= arm_spe_continue;

		arm_spe_record_capture_callback_register(mem_sampling_process);
		break;

	default:
		pr_info("unsupport hardware pmu type(%d), disable access hint!\n",
			mem_sampling_type);
		return -ENODEV;
	}

	return 0;
}
late_initcall(mem_sampling_init);
