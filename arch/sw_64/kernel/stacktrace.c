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
#include <linux/ftrace.h>
#include <linux/perf_event.h>
#include <linux/kallsyms.h>

#include <asm/stacktrace.h>

/*
 * sw_64 PCS assigns the frame pointer to r15.
 *
 * A simple function prologue looks like this:
 *	ldi     sp,-xx(sp)
 *	stl     ra,0(sp)
 *	stl     fp,8(sp)
 *	mov     sp,fp
 *
 * A simple function epilogue looks like this:
 *	mov     fp,sp
 *	ldl     ra,0(sp)
 *	ldl     fp,8(sp)
 *	ldi     sp,+xx(sp)
 */

#ifdef CONFIG_FRAME_POINTER

int unwind_frame(struct task_struct *tsk, struct stackframe *frame)
{
	unsigned long fp = frame->fp;

	if (fp & 0x7)
		return -EINVAL;

	if (!tsk)
		tsk = current;

	if (!on_accessible_stack(tsk, fp, NULL))
		return -EINVAL;

	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));

	/*
	 * Frames created upon entry from user have NULL FP and PC values, so
	 * don't bother reporting these. Frames created by __noreturn functions
	 * might have a valid FP even if PC is bogus, so only terminate where
	 * both are NULL.
	 */
	if (!frame->fp && !frame->pc)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(unwind_frame);

void walk_stackframe(struct task_struct *tsk, struct pt_regs *regs,
		     int (*fn)(unsigned long, void *), void *data)
{
	unsigned long pc, fp;

	struct stackframe frame;

	if (regs) {
		pc = regs->pc;
		fp = regs->r15;
	} else if (tsk == current || tsk == NULL) {
		fp = (unsigned long)__builtin_frame_address(0);
		pc = (unsigned long)walk_stackframe;
	} else {
		fp = tsk->thread.s[6];
		pc = tsk->thread.ra;
	}

	if (!__kernel_text_address(pc) || fn(pc, data))
		return;

	frame.pc = pc;
	frame.fp = fp;
	while (1) {
		int ret;
		ret = unwind_frame(tsk, &frame);
		if (ret < 0)
			break;

		if (fn(frame.pc, data))
			break;
	}
}
EXPORT_SYMBOL_GPL(walk_stackframe);

#else /* !CONFIG_FRAME_POINTER */
void walk_stackframe(struct task_struct *tsk, struct pt_regs *regs,
		     int (*fn)(unsigned long, void *), void *data)
{
	unsigned long *ksp;
	unsigned long sp, pc;

	if (regs) {
		sp = (unsigned long)(regs+1);
		pc = regs->pc;
	} else if (tsk == current || tsk == NULL) {
		register unsigned long current_sp __asm__ ("$30");
		sp = current_sp;
		pc = (unsigned long)walk_stackframe;
	} else {
		sp = tsk->thread.sp;
		pc = tsk->thread.ra;
	}

	ksp = (unsigned long *)sp;

	while (!kstack_end(ksp)) {
		if (__kernel_text_address(pc) && fn(pc, data))
			break;
		pc = (*ksp++) - 0x4;
	}
}
EXPORT_SYMBOL_GPL(walk_stackframe);

#endif/* CONFIG_FRAME_POINTER */

static int print_address_trace(unsigned long pc, void *data)
{
	print_ip_sym((const char *)data, pc);
	return 0;
}

void show_stack(struct task_struct *task, unsigned long *sp, const char *loglvl)
{
	pr_info("Trace:\n");
	walk_stackframe(task, NULL, print_address_trace, (void *)loglvl);
}

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
