// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch.c - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2022  Huawei Technologies Co., Ltd.
 * Copyright (C) 2023  Huawei Technologies Co., Ltd.
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
#include <linux/livepatch.h>
#include <linux/kallsyms.h>
#include <asm/probes.h>
#include <asm/livepatch.h>
#include <asm/code-patching.h>
#include <linux/sched/debug.h>

#define CHECK_JUMP_RANGE LJMP_INSN_SIZE

/*
 * The instruction set on ppc is RISC.
 * The instructions of BL and BLA are 010010xxxxxxxxxxxxxxxxxxxxxxxxx1.
 * The instructions of BCL and BCLA are 010000xxxxxxxxxxxxxxxxxxxxxxxxx1.
 * The instruction of BCCTRL is 010011xxxxxxxxxx0000010000100001.
 * The instruction of BCLRL is 010011xxxxxxxxxx0000000000100001.
 */
static bool is_jump_insn(u32 insn)
{
	u32 tmp1 = (insn & 0xfc000001);
	u32 tmp2 = (insn & 0xfc00ffff);

	if ((tmp1 == 0x48000001) || (tmp1 == 0x40000001) ||
	    (tmp2 == 0x4c000421) || (tmp2 == 0x4c000021))
		return true;
	return false;
}

bool arch_check_jump_insn(unsigned long func_addr)
{
	unsigned long i;
	u32 *insn = (u32 *)func_addr;

	for (i = 0; i < CHECK_JUMP_RANGE; i++) {
		if (is_jump_insn(*insn))
			return true;
		insn++;
	}
	return false;
}

struct stackframe {
	/* stack frame to be unwinded */
	unsigned long sp;
	/* link register saved in last stack frame */
	unsigned long pc;
	/* instruction register saved in pt_regs */
	unsigned long nip;
	/* link register saved in pt_regs */
	unsigned long link;
	/* stack frame pointer (r1 register) saved in pt_regs */
	unsigned long sfp;
	/* check if nip and link are in same function */
	unsigned int nip_link_in_same_func;
	/* check if it is top frame before interrupt */
	unsigned int is_top_frame;
};

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

static int klp_unwind_frame(struct task_struct *tsk, struct stackframe *frame)
{
	unsigned long *stack;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	int ftrace_idx = 0;
#endif

	if (!validate_sp(frame->sp, tsk))
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
	if (validate_sp_size(frame->sp, tsk, STACK_SWITCH_FRAME_SIZE)
	    && stack[STACK_INT_FRAME_MARKER_LONGS] == STACK_FRAME_REGS_MARKER) {
		struct pt_regs *regs = (struct pt_regs *)
			(frame->sp + STACK_INT_FRAME_REGS);
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

static void notrace klp_walk_stackframe(struct stackframe *frame,
		int (*fn)(struct stackframe *, void *),
		struct task_struct *tsk, void *data)
{
	while (1) {
		int ret;

		if (fn(frame, data))
			break;
		ret = klp_unwind_frame(tsk, frame);
		if (ret < 0)
			break;
	}
}

static int check_task_calltrace(struct task_struct *t,
				struct walk_stackframe_args *args,
				int (*fn)(struct stackframe *, void *))
{
	struct stackframe frame = { 0 };
	unsigned long *stack;

	if (t == current) {
		/*
		 * Handle the current carefully on each CPUs, we shouldn't
		 * use saved FP and PC when backtrace current. It's difficult
		 * to backtrack other CPU currents here. But fortunately,
		 * all CPUs will stay in this function, so the current's
		 * backtrace is so similar
		 */
		stack = (unsigned long *)current_stack_pointer;
	} else {
		/*
		 * Skip the first frame since it does not contain lr
		 * at normal position and nip is stored in the lr
		 * position in the second frame.
		 * See arch/powerpc/kernel/entry_${BIT}.S _switch .
		 */
		unsigned long s = *(unsigned long *)t->thread.ksp;

		if (!validate_sp(s, t))
			return 0;
		stack = (unsigned long *)s;
	}

	frame.sp = (unsigned long)stack;
	frame.pc = stack[STACK_FRAME_LR_SAVE];
	klp_walk_stackframe(&frame, fn, t, args);
	if (args->ret) {
		pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
		show_stack(t, NULL, KERN_INFO);
		return args->ret;
	}
	return 0;
}

static int do_check_calltrace(struct walk_stackframe_args *args,
			      int (*fn)(struct stackframe *, void *))
{
	int ret;
	struct task_struct *g, *t;
	unsigned int cpu;

	for_each_process_thread(g, t) {
		if (klp_is_migration_thread(t->comm))
			continue;
		if (klp_is_thread_dead(t))
			continue;
		ret = check_task_calltrace(t, args, fn);
		if (ret)
			return ret;
	}
	for_each_online_cpu(cpu) {
		ret = check_task_calltrace(idle_task(cpu), args, fn);
		if (ret)
			return ret;
	}
	return 0;
}

static int klp_check_jump_func(struct stackframe *frame, void *ws_args)
{
	struct walk_stackframe_args *args = ws_args;

	/* check NIP when the exception stack switching */
	if (frame->nip && !args->check_func(args->data, &args->ret, frame->nip))
		return args->ret;
	if (frame->link && !frame->nip_link_in_same_func &&
	    !args->check_func(args->data, &args->ret, frame->link))
		return args->ret;
	/*
	 * There are two cases that frame->pc is reliable:
	 *   1. frame->pc is not in top frame before interrupt;
	 *   2. nip and link are in same function;
	 */
	if (!frame->is_top_frame || frame->nip_link_in_same_func) {
		if (!args->check_func(args->data, &args->ret, frame->pc))
			return args->ret;
	}
	return 0;
}

int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data)
{
	struct walk_stackframe_args args = {
		.data = data,
		.ret = 0,
		.check_func = check_func,
	};

	return do_check_calltrace(&args, klp_check_jump_func);
}

static int klp_check_module_calltrace(struct stackframe *frame, void *ws_args)
{
	struct walk_stackframe_args *args = ws_args;
	struct module *mod = args->data;

	/* check NIP when the exception stack switching */
	if (frame->nip && within_module_core(frame->nip, mod))
		goto err_out;
	if (frame->link && !frame->nip_link_in_same_func &&
	    within_module_core(frame->link, mod))
		goto err_out;
	if (!frame->is_top_frame || frame->nip_link_in_same_func) {
		if (within_module_core(frame->pc, mod))
			goto err_out;
	}

	return 0;

err_out:
	pr_err("module %s is in use!\n", mod->name);
	return (args->ret = -EBUSY);
}

int arch_klp_module_check_calltrace(void *data)
{
	struct walk_stackframe_args args = {
		.data = data,
		.ret = 0
	};

	return do_check_calltrace(&args, klp_check_module_calltrace);
}

int klp_patch_text(u32 *dst, const u32 *src, int len)
{
	int i;
	int ret;

	if (len <= 0)
		return -EINVAL;
	/* skip breakpoint at first */
	for (i = 1; i < len; i++) {
		ret = patch_instruction(dst + i,
					ppc_inst(src[i]));
		if (ret)
			return ret;
	}
	/*
	 * Avoid compile optimization, make sure that instructions
	 * except first breakpoint has been patched.
	 */
	barrier();
	return patch_instruction(dst, ppc_inst(src[0]));
}

int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	ppc_inst_t insn = ppc_inst_read((const u32 *)old_func);

	arch_data->saved_opcode = ppc_inst_val(insn);
	patch_instruction((u32 *)old_func, ppc_inst(BREAKPOINT_INSTRUCTION));
	return 0;
}

void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	patch_instruction((u32 *)old_func, ppc_inst(arch_data->saved_opcode));
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

#ifdef CONFIG_PPC64
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
