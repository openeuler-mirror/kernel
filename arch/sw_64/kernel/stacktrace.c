// SPDX-License-Identifier: GPL-2.0
/*
 * Stack trace management functions
 *
 *  Copyright (C) 2018 snyh <xiabin@deepin.com>
 */
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/debug.h>


/*
 * Save stack-backtrace addresses into a stack_trace buffer.
 */
void save_stack_trace(struct stack_trace *trace)
{
	save_stack_trace_tsk(current, trace);
}
EXPORT_SYMBOL_GPL(save_stack_trace);


void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	unsigned long *sp = (unsigned long *)task_thread_info(tsk)->pcb.ksp;
	unsigned long addr;

	WARN_ON(trace->nr_entries || !trace->max_entries);

	while (!kstack_end(sp)) {
		addr = *sp++;
		if (__kernel_text_address(addr) &&
				!in_sched_functions(addr)) {
			if (trace->skip > 0)
				trace->skip--;
			else
				trace->entries[trace->nr_entries++] = addr;
			if (trace->nr_entries >= trace->max_entries)
				break;
		}
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace_tsk);
