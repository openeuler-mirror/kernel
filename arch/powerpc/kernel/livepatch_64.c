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
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/livepatch.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/kallsyms.h>
#include <linux/sched/debug.h>

#include <asm/livepatch.h>
#include <asm/cacheflush.h>
#include <asm/code-patching.h>
#include <asm/elf.h>

#if defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY) || \
    defined(CONFIG_LIVEPATCH_WO_FTRACE)
struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	void *old_func;
	u32	old_insns[LJMP_INSN_SIZE];
#ifdef PPC64_ELF_ABI_v1
	struct ppc64_klp_btramp_entry trampoline;
#else
	unsigned long   trampoline;
#endif
};

static LIST_HEAD(klp_func_list);

static struct klp_func_node *klp_find_func_node(void *old_func)
{
	struct klp_func_node *func_node;

	list_for_each_entry(func_node, &klp_func_list, node) {
		if (func_node->old_func == old_func)
			return func_node;
	}

	return NULL;
}
#endif

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
struct stackframe {
	unsigned long sp;
	unsigned long pc;
	unsigned long nip;
};

struct walk_stackframe_args {
	struct klp_patch *patch;
	int enable;
	int ret;
};

static inline int klp_compare_address(unsigned long pc,
				      unsigned long func_addr,
				      unsigned long func_size,
				      const char *func_name)
{
	if (pc >= func_addr && pc < func_addr + func_size) {
		pr_err("func %s is in use!\n", func_name);
		return -EBUSY;
	}
	return 0;
}

static inline int klp_check_activeness_func_addr(
		struct stackframe *frame,
		unsigned long func_addr,
		unsigned long func_size,
		const char *func_name)
{
	int ret;

	/* Check PC first */
	ret = klp_compare_address(frame->pc, func_addr,
			func_size, func_name);
	if (ret)
		return ret;

	/* Check NIP when the exception stack switching */
	if (frame->nip != 0) {
		ret = klp_compare_address(frame->nip, func_addr,
				func_size, func_name);
		if (ret)
			return ret;
	}

	return ret;
}

static int klp_check_activeness_func(struct stackframe *frame, void *data)
{
	struct walk_stackframe_args *args = data;
	struct klp_patch *patch = args->patch;
	struct klp_object *obj;
	struct klp_func *func;
	unsigned long func_addr, func_size;
	const char *func_name;
	struct klp_func_node *func_node = NULL;

	if (args->ret)
		return args->ret;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			func_node = klp_find_func_node(func->old_func);

			/* Check func address in stack */
			if (args->enable) {
				/*
				 * When enable, checking the currently
				 * active functions.
				 */
				if (!func_node ||
				    list_empty(&func_node->func_stack)) {
					/*
					 * No patched on this function
					 * [ the origin one ]
					 */
					func_addr = (unsigned long)func->old_func;
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
					func_addr = ppc_function_entry(
						(void *)prev->new_func);
					func_size = prev->new_size;
				}
			} else {
				/*
				 * When disable, check for the function itself
				 * which to be unpatched.
				 */
				func_addr = ppc_function_entry(
						(void *)func->new_func);
				func_size = func->new_size;
			}
			func_name = func->old_name;
			args->ret = klp_check_activeness_func_addr(frame,
					func_addr, func_size, func_name);
			if (args->ret)
				return args->ret;

#ifdef PPC64_ELF_ABI_v1
			/*
			 * Check trampoline in stack
			 * new_func callchain:
			 *	old_func
			 *	-=> trampoline
			 *	    -=> new_func
			 * so, we should check all the func in the callchain
			 */
			if (func_addr != (unsigned long)func->old_func) {
				func_addr = (unsigned long)func->old_func;
				func_size = func->old_size;
				args->ret = klp_check_activeness_func_addr(frame,
					func_addr, func_size, "OLD_FUNC");
				if (args->ret)
					return args->ret;

				if (func_node == NULL ||
				    func_node->trampoline.magic != BRANCH_TRAMPOLINE_MAGIC)
					continue;

				func_addr = (unsigned long)&func_node->trampoline;
				func_size = sizeof(struct ppc64_klp_btramp_entry);
				args->ret = klp_check_activeness_func_addr(frame,
						func_addr, func_size, "trampoline");
				if (args->ret)
					return args->ret;
			}
#endif
		}
	}

	return args->ret;
}

static int unwind_frame(struct task_struct *tsk, struct stackframe *frame)
{

	unsigned long *stack;

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
#ifdef CONFIG_FUNCTION_GRAPH_TRACE
	/*
	 * IMHO these tests do not belong in
	 * arch-dependent code, they are generic.
	 */
	frame->pc = ftrace_graph_ret_addr(tsk, &ftrace_idx, frame->ip, stack);
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
		ret = unwind_frame(tsk, frame);
		if (ret < 0)
			break;
	}
}

int klp_check_calltrace(struct klp_patch *patch, int enable)
{
	struct task_struct *g, *t;
	struct stackframe frame;
	unsigned long *stack;
	int ret = 0;

	struct walk_stackframe_args args = {
		.patch = patch,
		.enable = enable,
		.ret = 0
	};

	for_each_process_thread(g, t) {
		if (t == current) {
			/*
			 * Handle the current carefully on each CPUs,
			 * we shouldn't use saved FP and PC when
			 * backtrace current. It's difficult to
			 * backtrack other CPU currents here. But
			 * fortunately,all CPUs will stay in this
			 * function, so the current's backtrace is
			 * so similar
			 */
			stack = (unsigned long *)current_stack_pointer;
		} else if (strncmp(t->comm, "migration/", 10) == 0) {
			/*
			 * current on other CPU
			 * we call this in stop_machine, so the current
			 * of each CPUs is mirgation, just compare the
			 * task_comm here, because we can't get the
			 * cpu_curr(task_cpu(t))). This assumes that no
			 * other thread will pretend to be a stopper via
			 * task_comm.
			 */
			continue;
		} else {
			stack = (unsigned long *)t->thread.ksp;
		}

		frame.sp = (unsigned long)stack;
		frame.pc = stack[STACK_FRAME_LR_SAVE];
		frame.nip = 0;
		klp_walk_stackframe(&frame, klp_check_activeness_func,
				t, &args);
		if (args.ret) {
			ret = args.ret;
			pr_debug("%s FAILED when %s\n", __func__,
				 enable ? "enabling" : "disabling");
			pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
			show_stack(t, NULL, KERN_INFO);

			goto out;
		}
	}

out:
	return ret;
}
#endif

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long pc, new_addr;
	int i;
	int memory_flag = 0;
	long ret;

	func_node = klp_find_func_node(func->old_func);
	if (!func_node) {
		func_node = module_alloc(sizeof(*func_node));
		if (!func_node)
			return -ENOMEM;

		memory_flag = 1;
		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_func = func->old_func;
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			ret = copy_from_kernel_nofault(&func_node->old_insns[i],
				((u32 *)func->old_func) + i, 4);
			if (ret) {
				module_memfree(func_node);
				return -EPERM;
			}
		}
		list_add_rcu(&func_node->node, &klp_func_list);
	}

	list_add_rcu(&func->stack_node, &func_node->func_stack);

	pc = (unsigned long)func->old_func;
	new_addr = (unsigned long)func->new_func;

	ret = livepatch_create_branch(pc, (unsigned long)&func_node->trampoline,
				      new_addr, func->old_mod);
	if (ret)
		goto ERR_OUT;
	flush_icache_range((unsigned long)pc,
			(unsigned long)pc + LJMP_INSN_SIZE * PPC64_INSN_SIZE);

	pr_debug("[%s %d] old = 0x%lx/0x%lx/%pS, new = 0x%lx/0x%lx/%pS\n",
		 __func__, __LINE__,
		 pc, ppc_function_entry((void *)pc), (void *)pc,
		 new_addr, ppc_function_entry((void *)new_addr),
		 (void *)ppc_function_entry((void *)new_addr));

	return 0;

ERR_OUT:
	list_del_rcu(&func->stack_node);
	if (memory_flag) {
		list_del_rcu(&func_node->node);
		module_memfree(func_node);
	}

	return -EPERM;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long pc, new_addr;
	u32 insns[LJMP_INSN_SIZE];
	int i;

	func_node = klp_find_func_node(func->old_func);
	pc = (unsigned long)func_node->old_func;
	if (list_is_singular(&func_node->func_stack)) {
		for (i = 0; i < LJMP_INSN_SIZE; i++)
			insns[i] = func_node->old_insns[i];

		list_del_rcu(&func->stack_node);
		list_del_rcu(&func_node->node);
		module_memfree(func_node);

		for (i = 0; i < LJMP_INSN_SIZE; i++)
			patch_instruction((struct ppc_inst *)((u32 *)pc + i),
					  ppc_inst(insns[i]));

		pr_debug("[%s %d] restore insns at 0x%lx\n", __func__, __LINE__, pc);
	} else {
		list_del_rcu(&func->stack_node);
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);
		new_addr = (unsigned long)next_func->new_func;

		livepatch_create_branch(pc, (unsigned long)&func_node->trampoline,
			new_addr, func->old_mod);

		pr_debug("[%s %d] old = 0x%lx/0x%lx/%pS, new = 0x%lx/0x%lx/%pS\n",
			__func__, __LINE__,
			pc, ppc_function_entry((void *)pc), (void *)pc,
			new_addr, ppc_function_entry((void *)new_addr),
			(void *)ppc_function_entry((void *)new_addr));

	}

	flush_icache_range((unsigned long)pc,
			(unsigned long)pc + LJMP_INSN_SIZE * PPC64_INSN_SIZE);
}

/* return 0 if the func can be patched */
int arch_klp_func_can_patch(struct klp_func *func)
{
	unsigned long old_size = func->old_size;

	if (!old_size)
		return -EINVAL;

	if (old_size < LJMP_INSN_SIZE * sizeof(u32)) {
		pr_err("func %s size less than limit\n", func->old_name);
		return -EPERM;
	}
	return 0;
}

int arch_klp_init_func(struct klp_object *obj, struct klp_func *func)
{
#ifdef PPC64_ELF_ABI_v1
	unsigned long new_addr = (unsigned long)func->new_func;

	/*
	 * ABI v1 address is address of the OPD entry,
	 * which contains address of fn. ABI v2 An address
	 * is simply the address of the function.
	 *
	 * The function descriptor is in the data section. So
	 * If new_addr is in the code segment, we think it is
	 * a function address, if addr isn't in the code segment,
	 * we consider it to be a function descriptor.
	 */
	if (!is_module_text_address(new_addr)) {
		new_addr = (unsigned long)ppc_function_entry((void *)new_addr);
		if (!kallsyms_lookup_size_offset((unsigned long)new_addr,
			&func->new_size, NULL))
			return -ENOENT;
	}

	func->this_mod = __module_text_address(new_addr);
	if (!func->this_mod)
		return -EINVAL;

	func->new_func_descr.entry = new_addr;
	func->new_func_descr.toc = func->this_mod->arch.toc;

	func->new_func = (void *)&func->new_func_descr;
#endif

	if (obj->name)
		func->old_mod = obj->mod;
	else
		func->old_mod = NULL;


	return 0;
}
#endif
