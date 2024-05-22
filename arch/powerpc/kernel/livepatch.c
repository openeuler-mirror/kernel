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
#include <linux/kallsyms.h>
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

static int check_addr_in_same_func(unsigned long addr1, unsigned long addr2)
{
	unsigned long size = 0;
	unsigned long offset = 0;
	unsigned long start;

	if (addr1 == 0 || addr2 == 0)
		return 0;
	if (addr1 == addr2)
		return 1;
	if (!kallsyms_lookup_size_offset(addr1, &size, &offset))
		return 0;
	start = addr1 - offset;
	return (addr2 >= start) && (addr2 - start < size);
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
	if (frame->link != 0)
		frame->link = 0;

	frame->is_top_frame = (frame->sfp == frame->sp);
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
		frame->link = regs->link;
		frame->sfp = regs->gpr[PT_R1];
		frame->nip_link_in_same_func = check_addr_in_same_func(frame->nip, frame->link);
		pr_debug("--- interrupt: task = %d/%s, trap %lx at NIP=0x%lx/%pS, LR=0x%lx/%pS, SFP=0x%lx, nip_link_in_same_func=%u\n",
			tsk->pid, tsk->comm, regs->trap,
			regs->nip, (void *)regs->nip,
			regs->link, (void *)regs->link,
			frame->sfp, frame->nip_link_in_same_func);
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

int klp_patch_text(u32 *dst, const u32 *src, int len)
{
	int i;
	int ret;

	if (len <= 0)
		return -EINVAL;
	/* skip breakpoint at first */
	for (i = 1; i < len; i++) {
		ret = patch_instruction((struct ppc_inst *)(dst + i),
					ppc_inst(src[i]));
		if (ret)
			return ret;
	}
	/*
	 * Avoid compile optimization, make sure that instructions
	 * except first breakpoint has been patched.
	 */
	barrier();
	return patch_instruction((struct ppc_inst *)dst, ppc_inst(src[0]));
}
