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
#define MAX_SIZE_TO_CHECK (LJMP_INSN_SIZE * sizeof(u32))
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

struct klp_func_list {
	struct klp_func_list *next;
	unsigned long func_addr;
	unsigned long func_size;
	const char *func_name;
	int force;
};

struct stackframe {
	unsigned long sp;
	unsigned long pc;
	unsigned long nip;
};

struct walk_stackframe_args {
	int enable;
	struct klp_func_list *check_funcs;
	int ret;
};

static inline unsigned long klp_size_to_check(unsigned long func_size,
		int force)
{
	unsigned long size = func_size;

	if (force == KLP_STACK_OPTIMIZE && size > MAX_SIZE_TO_CHECK)
		size = MAX_SIZE_TO_CHECK;
	return size;
}

static inline int klp_compare_address(unsigned long pc, unsigned long func_addr,
		const char *func_name, unsigned long check_size)
{
	if (pc >= func_addr && pc < func_addr + check_size) {
		pr_err("func %s is in use!\n", func_name);
		return -EBUSY;
	}
	return 0;
}

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

static int add_func_to_list(struct klp_func_list **funcs, struct klp_func_list **func,
		unsigned long func_addr, unsigned long func_size, const char *func_name,
		int force)
{
	if (*func == NULL) {
		*funcs = (struct klp_func_list*)kzalloc(sizeof(**funcs), GFP_ATOMIC);
		if (!(*funcs))
			return -ENOMEM;
		*func = *funcs;
	} else {
		(*func)->next = (struct klp_func_list*)kzalloc(sizeof(**funcs),
				GFP_ATOMIC);
		if (!(*func)->next)
			return -ENOMEM;
		*func = (*func)->next;
	}
	(*func)->func_addr = func_addr;
	(*func)->func_size = func_size;
	(*func)->func_name = func_name;
	(*func)->force = force;
	(*func)->next = NULL;
	return 0;
}

static int klp_check_activeness_func(struct klp_patch *patch, int enable,
		struct klp_func_list **check_funcs)
{
	int ret;
	struct klp_object *obj;
	struct klp_func *func;
	unsigned long func_addr, func_size;
	struct klp_func_node *func_node = NULL;
	struct klp_func_list *pcheck = NULL;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			func_node = klp_find_func_node(func->old_func);

			/* Check func address in stack */
			if (enable) {
				if (func->force == KLP_ENFORCEMENT)
					continue;
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
				/*
				 * When preemption is disabled and the
				 * replacement area does not contain a jump
				 * instruction, the migration thread is
				 * scheduled to run stop machine only after the
				 * excution of instructions to be repalced is
				 * complete.
				 */
				if (IS_ENABLED(CONFIG_PREEMTION) ||
				    (func->force == KLP_NORMAL_FORCE) ||
				    check_jump_insn(func_addr)) {
					ret = add_func_to_list(check_funcs, &pcheck,
							func_addr, func_size,
							func->old_name, func->force);
					if (ret)
						return ret;
				}
			} else {
				/*
				 * When disable, check for the function itself
				 * which to be unpatched.
				 */
				func_addr = ppc_function_entry(
						(void *)func->new_func);
				func_size = func->new_size;
				ret = add_func_to_list(check_funcs, &pcheck, func_addr,
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
				ret = add_func_to_list(check_funcs, &pcheck, func_addr,
						func_size, "OLD_FUNC", 0);
				if (ret)
					return ret;
#endif

				if (func_node == NULL ||
				    func_node->arch_data.trampoline.magic != BRANCH_TRAMPOLINE_MAGIC)
					continue;

				func_addr = (unsigned long)&func_node->arch_data.trampoline;
				func_size = sizeof(struct ppc64_klp_btramp_entry);
				ret = add_func_to_list(check_funcs, &pcheck, func_addr,
						func_size, "trampoline", 0);
				if (ret)
					return ret;
			}
#endif
		}
	}
	return 0;
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

static bool check_func_list(struct klp_func_list *funcs, int *ret, unsigned long pc)
{
	while (funcs != NULL) {
		*ret = klp_compare_address(pc, funcs->func_addr, funcs->func_name,
				klp_size_to_check(funcs->func_size, funcs->force));
		if (*ret) {
			return false;
		}
		funcs = funcs->next;
	}
	return true;
}

static int klp_check_jump_func(struct stackframe *frame, void *data)
{
	struct walk_stackframe_args *args = data;
	struct klp_func_list *check_funcs = args->check_funcs;

	if (!check_func_list(check_funcs, &args->ret, frame->pc)) {
		return args->ret;
	}
	return 0;
}

static void free_list(struct klp_func_list **funcs)
{
	struct klp_func_list *p;

	while (*funcs != NULL) {
		p = *funcs;
		*funcs = (*funcs)->next;
		kfree(p);
	}
}

int klp_check_calltrace(struct klp_patch *patch, int enable)
{
	struct task_struct *g, *t;
	struct stackframe frame;
	unsigned long *stack;
	int ret = 0;
	struct klp_func_list *check_funcs = NULL;
	struct walk_stackframe_args args;

	ret = klp_check_activeness_func(patch, enable, &check_funcs);
	if (ret)
		goto out;
	args.check_funcs = check_funcs;
	args.ret = 0;

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
			/*
			 * Skip the first frame since it does not contain lr
			 * at notmal position and nip is store ind the lr
			 * position in the second frame.
			 * See arch/powerpc/kernel/entry_64.S _switch .
			 */
			unsigned long s = *(unsigned long *)t->thread.ksp;

			if (!validate_sp(s, t, STACK_FRAME_OVERHEAD))
				continue;
			stack = (unsigned long *)s;
		}

		frame.sp = (unsigned long)stack;
		frame.pc = stack[STACK_FRAME_LR_SAVE];
		frame.nip = 0;
		if (check_funcs != NULL) {
			klp_walk_stackframe(&frame, klp_check_jump_func, t, &args);
			if (args.ret) {
				ret = args.ret;
				pr_debug("%s FAILED when %s\n", __func__,
					 enable ? "enabling" : "disabling");
				pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
				show_stack(t, NULL, KERN_INFO);
				goto out;
			}
		}
	}

out:
	free_list(&check_funcs);
	return ret;
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
	if (ret)
		return -EPERM;
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
	int i;

	func_node = func->func_node;
	pc = (unsigned long)func_node->old_func;
	list_del_rcu(&func->stack_node);
	if (list_empty(&func_node->func_stack)) {
		for (i = 0; i < LJMP_INSN_SIZE; i++)
			patch_instruction((struct ppc_inst *)((u32 *)pc + i),
					  ppc_inst(func_node->arch_data.old_insns[i]));

		pr_debug("[%s %d] restore insns at 0x%lx\n", __func__, __LINE__, pc);
		flush_icache_range(pc, pc + LJMP_INSN_SIZE * PPC64_INSN_SIZE);
	} else {
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);
		do_patch(pc, (unsigned long)next_func->new_func,
			 &func_node->arch_data, func->old_mod);
	}
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
