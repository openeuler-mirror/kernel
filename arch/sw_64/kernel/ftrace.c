// SPDX-License-Identifier: GPL-2.0
/*
 * Based on arch/arm64/kernel/ftrace.c
 *
 * Copyright (C) 2019 os kernel team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/ftrace.h>

#include <asm/ftrace.h>

#ifdef CONFIG_FUNCTION_TRACER
EXPORT_SYMBOL(_mcount);
#endif

#ifdef CONFIG_DYNAMIC_FTRACE

unsigned long current_tracer = (unsigned long)ftrace_stub;

/*
 * Replace two instruction, which may be a branch or NOP.
 */
static int ftrace_modify_double_code(unsigned long pc, u64 new)
{
	if (sw64_insn_double_write((void *)pc, new))
		return -EPERM;
	return 0;
}

/*
 * Replace a single instruction, which may be a branch or NOP.
 */
static int ftrace_modify_code(unsigned long pc, u32 new)
{
	if (sw64_insn_write((void *)pc, new))
		return -EPERM;
	return 0;
}

/*
 * Replace tracer function in ftrace_caller()
 */
int ftrace_update_ftrace_func(ftrace_func_t func)
{
	unsigned long pc;
	int ret;
	u32 new;

	current_tracer = (unsigned long)func;

	pc = (unsigned long)&ftrace_call;

	new = sw64_insn_call(R26, R27);
	if (ftrace_modify_code(pc, new))
		return ret;
	return 0;
}

/*
 * Turn on the call to ftrace_caller() in instrumented function
 */
int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long pc = rec->ip;
	u32 new;
	int ret;

	/* ldl r28,(ftrace_addr_offset)(r8) */
	new = (0x23U << 26) | (28U << 21) | (8U << 16) | offsetof(struct thread_info, dyn_ftrace_addr);
	if (ftrace_modify_code(pc, new))
		return ret;
	pc = pc + 4;
	new = sw64_insn_call(R28, R28);
	if (ftrace_modify_code(pc, new))
		return ret;
	return 0;
}

/*
 * Turn off the call to ftrace_caller() in instrumented function
 */
int ftrace_make_nop(struct module *mod, struct dyn_ftrace *rec,
		    unsigned long addr)
{
	unsigned long pc = rec->ip;
	unsigned long insn;
	int ret;

	insn = sw64_insn_nop();
	insn = (insn << 32) | insn;
	ret = ftrace_modify_double_code(pc, insn);
	return ret;

}

void arch_ftrace_update_code(int command)
{
	ftrace_modify_all_code(command);
}

/*tracer_addr must be same with syscall_ftrace*/
int __init ftrace_dyn_arch_init(void)
{
	init_thread_info.dyn_ftrace_addr = FTRACE_ADDR;
	return 0;
}
#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
/*
 * function_graph tracer expects ftrace_return_to_handler() to be called
 * on the way back to parent. For this purpose, this function is called
 * in _mcount() or ftrace_caller() to replace return address (*parent) on
 * the call stack to return_to_handler.
 *
 * Note that @frame_pointer is used only for sanity check later.
 */
void prepare_ftrace_return(unsigned long *parent, unsigned long self_addr,
			   unsigned long frame_pointer)
{
	unsigned long return_hooker = (unsigned long)&return_to_handler;
	unsigned long old;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	/*
	 * Note:
	 * No protection against faulting at *parent, which may be seen
	 * on other archs. It's unlikely on AArch64.
	 */
	old = *parent;

	if (!function_graph_enter(old, self_addr, frame_pointer, NULL))
		*parent = return_hooker;
}

#ifdef CONFIG_DYNAMIC_FTRACE
/*
 * Turn on/off the call to ftrace_graph_caller() in ftrace_caller()
 * depending on @enable.
 */
static int ftrace_modify_graph_caller(bool enable)
{
	unsigned long pc = (unsigned long)&ftrace_graph_call;
	u32 branch, nop;

	branch = sw64_insn_br(R31, pc, (unsigned long)ftrace_graph_caller);
	nop = sw64_insn_nop();

	if (enable)
		return ftrace_modify_code(pc, branch);
	else
		return ftrace_modify_code(pc, nop);
}

int ftrace_enable_ftrace_graph_caller(void)
{
	return ftrace_modify_graph_caller(true);
}

int ftrace_disable_ftrace_graph_caller(void)
{
	return ftrace_modify_graph_caller(false);
}
#endif /* CONFIG_DYNAMIC_FTRACE */
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */
