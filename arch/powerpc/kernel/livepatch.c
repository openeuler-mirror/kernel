// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch.c - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2022  Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/livepatch.h>
#include <asm/probes.h>
#include <asm/livepatch.h>
#include <asm/code-patching.h>

int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	struct ppc_inst insn = ppc_inst_read((struct ppc_inst *)old_func);

	arch_data->saved_opcode = ppc_inst_val(insn);
	patch_instruction((struct ppc_inst *)old_func, ppc_inst(BREAKPOINT_INSTRUCTION));
	return 0;
}

void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	patch_instruction((struct ppc_inst *)old_func, ppc_inst(arch_data->saved_opcode));
}

int klp_brk_handler(struct pt_regs *regs)
{
	void *brk_func = NULL;
	unsigned long addr = regs->nip;

	if (user_mode(regs))
		return 0;

	brk_func = klp_get_brk_func((void *)addr);
	if (!brk_func)
		return 0;

#ifdef PPC64_ELF_ABI_v1
	/*
	 * Only static trampoline can be used here to prevent
	 * resource release caused by rollback.
	 */
	regs->gpr[PT_R11] = (unsigned long)brk_func;
	regs->nip = ppc_function_entry((void *)livepatch_brk_trampoline);
#else
	regs->nip = (unsigned long)brk_func;
#endif

	return 1;
}

int klp_unwind_frame(struct task_struct *tsk, struct stackframe *frame)
{
	unsigned long *stack;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	int ftrace_idx = 0;
#endif

	if (!validate_sp(frame->sp, tsk, STACK_FRAME_OVERHEAD))
		return -1;

	if (frame->nip != 0)
		frame->nip = 0;

	stack = (unsigned long *)frame->sp;

	/*
	 * When switching to the exception stack,
	 * we save the NIP in pt_regs
	 *
	 * See if this is an exception frame.
	 * We look for the "regshere" marker in the current frame.
	 */
	if (validate_sp(frame->sp, tsk, STACK_INT_FRAME_SIZE)
	    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
		struct pt_regs *regs = (struct pt_regs *)
			(frame->sp + STACK_FRAME_OVERHEAD);
		frame->nip = regs->nip;
		pr_debug("--- interrupt: task = %d/%s, trap %lx at NIP=x%lx/%pS, LR=0x%lx/%pS\n",
			tsk->pid, tsk->comm, regs->trap,
			regs->nip, (void *)regs->nip,
			regs->link, (void *)regs->link);
	}

	frame->sp = stack[0];
	frame->pc = stack[STACK_FRAME_LR_SAVE];
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/*
	 * IMHO these tests do not belong in
	 * arch-dependent code, they are generic.
	 */
	frame->pc = ftrace_graph_ret_addr(tsk, &ftrace_idx, frame->pc, stack);
#endif

	return 0;
}
