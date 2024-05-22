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
#define CHECK_JUMP_RANGE LJMP_INSN_SIZE
#endif

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
/*
 * The instruction set on ppc64 is RISC.
 * The instructions of BL and BLA are 010010xxxxxxxxxxxxxxxxxxxxxxxxx1.
 * The instructions of BCL and BCLA are 010000xxxxxxxxxxxxxxxxxxxxxxxxx1.
 * The instruction of BCCTRL is 010011xxxxxxxxxx0000010000100001.
 * The instruction of BCLRL is 010011xxxxxxxxxx0000000000100001.
 */
static bool is_jump_insn(u32 insn)
{
	u32 tmp1 = (insn & 0xfc000001);
	u32 tmp2 = (insn & 0xfc00ffff);

	if (tmp1 == 0x48000001 || tmp1 == 0x40000001 ||
		tmp2 == 0x4c000421 || tmp2 == 0x4c000021)
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
		if (is_jump_insn(*insn))
			return true;
		insn++;
	}
	return false;
}

int arch_klp_check_activeness_func(struct klp_func *func, int enable,
				   klp_add_func_t add_func, struct list_head *func_list)
{
	int ret;
	unsigned long func_addr, func_size;
	struct klp_func_node *func_node = NULL;

	func_node = func->func_node;
	/* Check func address in stack */
	if (enable) {
		if (func->patched || func->force == KLP_ENFORCEMENT)
			return 0;
		/*
		 * When enable, checking the currently
		 * active functions.
		 */
		if (list_empty(&func_node->func_stack)) {
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

			prev = list_first_or_null_rcu(&func_node->func_stack,
						      struct klp_func, stack_node);
			func_addr = ppc_function_entry((void *)prev->new_func);
			func_size = prev->new_size;
		}
		/*
		 * When preemption is disabled and the
		 * replacement area does not contain a jump
		 * instruction, the migration thread is
		 * scheduled to run stop machine only after the
		 * excution of instructions to be repalced is
		 * complete.
		 */
		if (IS_ENABLED(CONFIG_PREEMPTION) ||
		    IS_ENABLED(CONFIG_LIVEPATCH_BREAKPOINT_NO_STOP_MACHINE) ||
		    (func->force == KLP_NORMAL_FORCE) ||
		    check_jump_insn(func_addr)) {
			ret = add_func(func_list, func_addr, func_size,
				       func->old_name, func->force);
			if (ret)
				return ret;
		}
	} else {
		/*
		 * When disable, check for the function itself
		 * which to be unpatched.
		 */
		func_addr = ppc_function_entry((void *)func->new_func);
		func_size = func->new_size;
		ret = add_func(func_list, func_addr,
			       func_size, func->old_name, 0);
		if (ret)
			return ret;
	}

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
#ifdef CONFIG_PREEMPTION
		/*
		 * No scheduling point in the replacement
		 * instructions. Therefore, when preemption is
		 * not enabled, atomic execution is performed
		 * and these instructions will not appear on
		 * the stack.
		 */
		func_addr = (unsigned long)func->old_func;
		func_size = func->old_size;
		ret = add_func(func_list, func_addr,
			       func_size, "OLD_FUNC", 0);
		if (ret)
			return ret;
#endif

		if (func_node->arch_data.trampoline.magic != BRANCH_TRAMPOLINE_MAGIC)
			return 0;

		func_addr = (unsigned long)&func_node->arch_data.trampoline;
		func_size = sizeof(struct ppc64_klp_btramp_entry);
		ret = add_func(func_list, func_addr,
				func_size, "trampoline", 0);
		if (ret)
			return ret;
	}
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
		 * Handle the current carefully on each CPUs,
		 * we shouldn't use saved FP and PC when
		 * backtrace current. It's difficult to
		 * backtrack other CPU currents here. But
		 * fortunately,all CPUs will stay in this
		 * function, so the current's backtrace is
		 * so similar
		 */
		stack = (unsigned long *)current_stack_pointer;
	} else {
		/*
		 * Skip the first frame since it does not contain lr
		 * at notmal position and nip is store ind the lr
		 * position in the second frame.
		 * See arch/powerpc/kernel/entry_64.S _switch .
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
	unsigned int cpu;

	for_each_process_thread(g, t) {
		if (klp_is_migration_thread(t->comm))
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

long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func)
{
	long ret;
	int i;

	for (i = 0; i < LJMP_INSN_SIZE; i++) {
		ret = copy_from_kernel_nofault(&arch_data->old_insns[i],
			((u32 *)old_func) + i, PPC64_INSN_SIZE);
		if (ret)
			break;
	}
	return ret;
}

static int do_patch(unsigned long pc, unsigned long new_addr,
		    struct arch_klp_data *arch_data, struct module *old_mod)
{
	int ret;

	ret = livepatch_create_branch(pc, (unsigned long)&arch_data->trampoline,
				      new_addr, old_mod);
	if (ret) {
		pr_err("create branch failed, ret=%d\n", ret);
		return -EPERM;
	}
	flush_icache_range(pc, pc + LJMP_INSN_SIZE * PPC64_INSN_SIZE);
	pr_debug("[%s %d] old = 0x%lx/0x%lx/%pS, new = 0x%lx/0x%lx/%pS\n",
		 __func__, __LINE__,
		 pc, ppc_function_entry((void *)pc), (void *)pc,
		 new_addr, ppc_function_entry((void *)new_addr),
		 (void *)ppc_function_entry((void *)new_addr));
	return 0;
}

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	int ret;

	func_node = func->func_node;
	list_add_rcu(&func->stack_node, &func_node->func_stack);
	ret = do_patch((unsigned long)func->old_func,
		       (unsigned long)func->new_func,
		       &func_node->arch_data, func->old_mod);
	if (ret)
		list_del_rcu(&func->stack_node);
	return ret;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long pc;
	int ret;

	func_node = func->func_node;
	pc = (unsigned long)func_node->old_func;
	list_del_rcu(&func->stack_node);
	if (list_empty(&func_node->func_stack)) {
		ret = klp_patch_text((u32 *)pc, func_node->arch_data.old_insns,
				     LJMP_INSN_SIZE);
		if (ret) {
			pr_err("restore instruction failed, ret=%d\n", ret);
			return;
		}

		pr_debug("[%s %d] restore insns at 0x%lx\n", __func__, __LINE__, pc);
		flush_icache_range(pc, pc + LJMP_INSN_SIZE * PPC64_INSN_SIZE);
	} else {
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);
		do_patch(pc, (unsigned long)next_func->new_func,
			 &func_node->arch_data, func->old_mod);
	}
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

/*
 * Trampoline would be stored in the allocated memory and it need
 * executable permission, so ppc64 use 'module_alloc' but not 'kmalloc'.
 */
void *arch_klp_mem_alloc(size_t size)
{
	void *mem = module_alloc(size);

	if (mem)
		memset(mem, 0, size);  /* initially clear the memory */
	return mem;
}

void arch_klp_mem_free(void *mem)
{
	module_memfree(mem);
}
#endif
