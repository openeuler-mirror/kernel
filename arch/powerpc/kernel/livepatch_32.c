// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch.c - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2018  Huawei Technologies Co., Ltd.
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
#include <linux/uaccess.h>
#include <linux/livepatch.h>
#include <linux/sched/debug.h>
#include <asm/livepatch.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <asm/code-patching.h>

#if defined (CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY) || \
    defined (CONFIG_LIVEPATCH_WO_FTRACE)
#define CHECK_JUMP_RANGE LJMP_INSN_SIZE
#endif

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
/*
 * The instruction set on ppc32 is RISC.
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

struct walk_stackframe_args {
	void *data;
	int ret;
	bool (*check_func)(void *data, int *ret, unsigned long pc);
};

static bool check_jump_insn(unsigned long func_addr)
{
	unsigned long i;
	u32 *insn = (u32*)func_addr;

	for (i = 0; i < CHECK_JUMP_RANGE; i++) {
		if (is_jump_insn(*insn)) {
			return true;
		}
		insn++;
	}
	return false;
}

int arch_klp_check_activeness_func(struct klp_patch *patch, int enable,
				   klp_add_func_t add_func, struct klp_func_list **func_list)
{
	int ret;
	struct klp_object *obj;
	struct klp_func *func;
	unsigned long func_addr = 0;
	unsigned long func_size;
	struct klp_func_node *func_node;
	struct klp_func_list *pcheck = NULL;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			unsigned long old_func = (unsigned long)func->old_func;

			if (enable) {
				bool need_check_old = false;

				if (func->patched || func->force == KLP_ENFORCEMENT)
					continue;
				/*
				 * When enable, checking the currently
				 * active functions.
				 */
				func_node = klp_find_func_node(func->old_func);
				if (!func_node ||
				    list_empty(&func_node->func_stack)) {
					/*
					 * No patched on this function
					 * [ the origin one ]
					 */
					func_addr = old_func;
					func_size = func->old_size;
				} else {
					/*
					 * Previously patched function
					 * [ the active one ]
					 */
					struct klp_func *prev;

					prev = list_first_or_null_rcu(
						&func_node->func_stack,
						struct klp_func, stack_node);
					func_addr = (unsigned long)prev->new_func;
					func_size = prev->new_size;
				}
				/*
				 * When preemtion is disabled and the
				 * replacement area does not contain a jump
				 * instruction, the migration thread is
				 * scheduled to run stop machine only after the
				 * excution of instructions to be replaced is
				 * complete.
				 */
				if (IS_ENABLED(CONFIG_PREEMPTION) ||
				    (func->force == KLP_NORMAL_FORCE) ||
				    check_jump_insn(func_addr)) {
					ret = add_func(func_list, &pcheck,
							func_addr, func_size,
							func->old_name, func->force);
					if (ret)
						return ret;
					need_check_old = (func_addr != old_func);
				}
				if (need_check_old) {
					ret = add_func_to_list(check_funcs, &pcheck, old_func,
						func->old_size, func->old_name, func->force);
					if (ret)
						return ret;
				}
			} else {
				/*
				 * When disable, check for the previously
				 * patched function and the function itself
				 * which to be unpatched.
				 */
				func_node = klp_find_func_node(func->old_func);
				if (!func_node)
					return -EINVAL;
#ifdef CONFIG_PREEMPTION
				/*
				 * No scheduling point in the replacement
				 * instructions. Therefore, when preemption is
				 * not enabled, atomic execution is performed
				 * and these instructions will not appear on
				 * the stack.
				 */
				if (list_is_singular(&func_node->func_stack)) {
					func_addr = old_func;
					func_size = func->old_size;
				} else {
					struct klp_func *prev;

					prev = list_first_or_null_rcu(
						&func_node->func_stack,
						struct klp_func, stack_node);
					func_addr = (unsigned long)prev->new_func;
					func_size = prev->new_size;
				}
				ret = add_func(func_list, &pcheck, func_addr,
						func_size, func->old_name, 0);
				if (ret)
					return ret;
				if (func_addr != old_func) {
					ret = add_func_to_list(check_funcs, &pcheck, old_func,
							func->old_size, func->old_name, 0);
					if (ret)
						return ret;
				}
#endif
				func_addr = (unsigned long)func->new_func;
				func_size = func->new_size;
				ret = add_func(func_list, &pcheck, func_addr,
						func_size, func->old_name, 0);
				if (ret)
					return ret;
			}
		}
	}
	return 0;
}

void notrace klp_walk_stackframe(struct stackframe *frame,
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
		 * See arch/powerpc/kernel/entry_32.S _switch .
		 */
		unsigned long s = *(unsigned long *)t->thread.ksp;

		if (!validate_sp(s, t, STACK_FRAME_OVERHEAD))
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

	for_each_process_thread(g, t) {
		if (klp_is_migration_thread(t->comm))
			continue;
		ret = check_task_calltrace(t, args, fn);
		if (ret)
			return ret;
	}
	return 0;
}

#ifdef CONFIG_LIVEPATCH_BREAKPOINT_NO_STOP_MACHINE
int arch_klp_check_task_calltrace(struct task_struct *t,
				  bool (*check_func)(void *, int *, unsigned long),
				  void *data)
{
	struct walk_stackframe_args args = {
		.data = data,
		.ret = 0,
		.check_func = check_func,
	};

	if (t == NULL)
		return -EINVAL;
	return check_task_calltrace(t, &args, klp_check_jump_func);
}
#endif

int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data)
{
	struct walk_stackframe_args args = {
		.data = data,
		.ret = 0,
		.check_func = check_func,
	};

	return do_check_calltrace(&args, klp_check_jump_func);
}

static int check_module_calltrace(struct stackframe *frame, void *ws_args)
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

	return do_check_calltrace(&args, check_module_calltrace);
}

#endif

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
static inline bool offset_in_range(unsigned long pc, unsigned long addr,
				   long range)
{
	long offset = addr - pc;

	return (offset >= -range && offset < range);
}

long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func)
{
	long ret;
	int i;

	for (i = 0; i < LJMP_INSN_SIZE; i++) {
		ret = copy_from_kernel_nofault(&arch_data->old_insns[i],
			((u32 *)old_func) + i, PPC32_INSN_SIZE);
		if (ret)
			break;
	}
	return ret;
}

static int do_patch(unsigned long pc, unsigned long new_addr)
{
	int ret;
	int i;
	u32 insns[LJMP_INSN_SIZE];

	if (offset_in_range(pc, new_addr, SZ_32M)) {
		struct ppc_inst instr;

		create_branch(&instr, (struct ppc_inst *)pc, new_addr, 0);
		ret = patch_instruction((struct ppc_inst *)pc, instr);
		if (ret) {
			pr_err("patch instruction small range failed, ret=%d\n", ret);
			return -EPERM;
		}
	} else {
		/*
		 * lis r12,sym@ha
		 * addi r12,r12,sym@l
		 * mtctr r12
		 * bctr
		 */
		insns[0] = 0x3d800000 + ((new_addr + 0x8000) >> 16);
		insns[1] = 0x398c0000 + (new_addr & 0xffff);
		insns[2] = 0x7d8903a6;
		insns[3] = 0x4e800420;

		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			ret = patch_instruction((struct ppc_inst *)(((u32 *)pc) + i),
						ppc_inst(insns[i]));
			if (ret) {
				pr_err("patch instruction %d large range failed, ret=%d\n",
				       i, ret);
				return -EPERM;
			}
		}
	}
	return 0;
}

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	int ret;

	func_node = func->func_node;
	list_add_rcu(&func->stack_node, &func_node->func_stack);
	ret = do_patch((unsigned long)func->old_func, (unsigned long)func->new_func);
	if (ret)
		list_del_rcu(&func->stack_node);
	return ret;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long pc;
	int i;
	int ret;

	func_node = func->func_node;
	pc = (unsigned long)func_node->old_func;
	list_del_rcu(&func->stack_node);
	if (list_empty(&func_node->func_stack)) {
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			ret = patch_instruction((struct ppc_inst *)(((u32 *)pc) + i),
						ppc_inst(func_node->arch_data.old_insns[i]));
			if (ret) {
				pr_err("restore instruction %d failed, ret=%d\n", i, ret);
				return;
			}
		}
	} else {
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);
		do_patch(pc, (unsigned long)next_func->new_func);
	}
}
#endif
