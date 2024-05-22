// SPDX-License-Identifier: GPL-2.0
/*
 * livepatch.c - arm64-specific Kernel Live Patching Core
 *
 * Copyright (C) 2014 Li Bin <huawei.libin@huawei.com>
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
#include <asm/livepatch.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <asm/insn.h>
#include <asm-generic/sections.h>
#include <asm/ptrace.h>
#include <asm/debug-monitors.h>
#include <linux/ftrace.h>
#include <linux/sched/debug.h>
#include <linux/kallsyms.h>

#define MAX_SIZE_TO_CHECK (LJMP_INSN_SIZE * sizeof(u32))
#define CHECK_JUMP_RANGE LJMP_INSN_SIZE

static inline bool offset_in_range(unsigned long pc, unsigned long addr,
		long range)
{
	long offset = addr - pc;

	return (offset >= -range && offset < range);
}

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
/*
 * The instruction set on arm64 is A64.
 * The instruction of BLR is 1101011000111111000000xxxxx00000.
 * The instruction of BL is 100101xxxxxxxxxxxxxxxxxxxxxxxxxx.
 * The instruction of BLRAX is 1101011x0011111100001xxxxxxxxxxx.
 */
#define is_jump_insn(insn) (((le32_to_cpu(insn) & 0xfffffc1f) == 0xd63f0000) || \
		((le32_to_cpu(insn) & 0xfc000000) == 0x94000000) || \
		((le32_to_cpu(insn) & 0xfefff800) == 0xd63f0800))

struct walk_stackframe_args {
	int enable;
	struct klp_func_list *check_funcs;
	struct module *mod;
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
		*funcs = (struct klp_func_list *)kzalloc(sizeof(**funcs), GFP_ATOMIC);
		if (!(*funcs))
			return -ENOMEM;
		*func = *funcs;
	} else {
		(*func)->next = (struct klp_func_list *)kzalloc(sizeof(**funcs),
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
					func_addr = old_func;
					func_size = func->old_size;
				} else {
					/*
					 * Previously patched function
					 * [the active one]
					 */
					struct klp_func *prev;

					prev = list_first_or_null_rcu(
						&func_node->func_stack,
						struct klp_func, stack_node);
					func_addr = (unsigned long)prev->new_func;
					func_size = prev->new_size;
				}
				/*
				 * When preemption is disabled and the
				 * replacement area does not contain a jump
				 * instruction, the migration thread is
				 * scheduled to run stop machine only after the
				 * excution of instructions to be replaced is
				 * complete.
				 */
				if (IS_ENABLED(CONFIG_PREEMPTION) ||
				    (func->force == KLP_NORMAL_FORCE) ||
				    check_jump_insn(func_addr)) {
					ret = add_func_to_list(check_funcs, &pcheck,
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
				if (!func_node) {
					return -EINVAL;
				}
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
				ret = add_func_to_list(check_funcs, &pcheck,
						func_addr, func_size,
						func->old_name, 0);
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
				ret = add_func_to_list(check_funcs, &pcheck,
						func_addr, func_size,
						func->old_name, 0);
				if (ret)
					return ret;
			}
		}
	}
	return 0;
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

static bool klp_check_jump_func(void *data, unsigned long pc)
{
	struct walk_stackframe_args *args = data;
	struct klp_func_list *check_funcs = args->check_funcs;

	return check_func_list(check_funcs, &args->ret, pc);
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

static int do_check_calltrace(struct walk_stackframe_args *args,
			      bool (*fn)(void *, unsigned long))
{
	struct task_struct *g, *t;
	struct stackframe frame;

	for_each_process_thread(g, t) {
		/*
		 * Handle the current carefully on each CPUs, we shouldn't
		 * use saved FP and PC when backtrace current. It's difficult
		 * to backtrack other CPU currents here. But fortunately,
		 * all CPUs will stay in this function, so the current's
		 * backtrace is so similar
		 */
		if (t == current) {
			/* current on this CPU */
			frame.fp = (unsigned long)__builtin_frame_address(0);
			frame.pc = (unsigned long)do_check_calltrace;
		} else if (klp_is_migration_thread(t->comm)) {
			continue;
		} else {
			frame.fp = thread_saved_fp(t);
			frame.pc = thread_saved_pc(t);
		}
		start_backtrace(&frame, frame.fp, frame.pc);
		walk_stackframe(t, &frame, fn, args);
		if (args->ret) {
			pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
			show_stack(t, NULL, KERN_INFO);
			return args->ret;
		}
	}
	return 0;
}

int klp_check_calltrace(struct klp_patch *patch, int enable)
{
	int ret = 0;
	struct klp_func_list *check_funcs = NULL;
	struct walk_stackframe_args args = {
		.enable = enable,
		.ret = 0
	};

	ret = klp_check_activeness_func(patch, enable, &check_funcs);
	if (ret) {
		pr_err("collect active functions failed, ret=%d\n", ret);
		goto out;
	}
	if (!check_funcs)
		goto out;

	args.check_funcs = check_funcs;
	ret = do_check_calltrace(&args, klp_check_jump_func);
out:
	free_list(&check_funcs);
	return ret;
}

static bool check_module_calltrace(void *data, unsigned long pc)
{
	struct walk_stackframe_args *args = data;

	if (within_module_core(pc, args->mod)) {
		pr_err("module %s is in use!\n", args->mod->name);
		args->ret = -EBUSY;
		return false;
	}
	return true;
}

int arch_klp_module_check_calltrace(void *data)
{
	struct walk_stackframe_args args = {
		.mod = (struct module *)data,
		.ret = 0
	};

	return do_check_calltrace(&args, check_module_calltrace);
}

int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	u32 insn = BRK64_OPCODE_KLP;
	u32 *addr = (u32 *)old_func;

	arch_data->saved_opcode = le32_to_cpu(*addr);
	aarch64_insn_patch_text(&old_func, &insn, 1);
	return 0;
}

void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	aarch64_insn_patch_text(&old_func, &arch_data->saved_opcode, 1);
}

static int klp_breakpoint_handler(struct pt_regs *regs, unsigned int esr)
{
	void *brk_func = NULL;
	unsigned long addr = instruction_pointer(regs);

	brk_func = klp_get_brk_func((void *)addr);
	if (!brk_func) {
		pr_warn("Unrecoverable livepatch detected.\n");
		BUG();
	}

	instruction_pointer_set(regs, (unsigned long)brk_func);
	return 0;
}

static struct break_hook klp_break_hook = {
	.imm = KLP_BRK_IMM,
	.fn = klp_breakpoint_handler,
};

void arch_klp_init(void)
{
	register_kernel_break_hook(&klp_break_hook);
}
#endif

long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func)
{
	long ret;
	int i;

	for (i = 0; i < LJMP_INSN_SIZE; i++) {
		ret = aarch64_insn_read(((u32 *)old_func) + i,
					&arch_data->old_insns[i]);
		if (ret)
			break;
	}
	return ret;
}

static int do_patch(unsigned long pc, unsigned long new_addr)
{
	u32 insns[LJMP_INSN_SIZE];
	int ret;

	if (offset_in_range(pc, new_addr, SZ_128M)) {
		insns[0] = aarch64_insn_gen_branch_imm(pc, new_addr,
						       AARCH64_INSN_BRANCH_NOLINK);
		ret = aarch64_insn_patch_text_nosync((void *)pc, insns[0]);
		if (ret) {
			pr_err("patch instruction small range failed, ret=%d\n", ret);
			return -EPERM;
		}
	} else {
#ifdef CONFIG_ARM64_MODULE_PLTS
		int i;

		insns[0] = 0x92800010 | (((~new_addr) & 0xffff)) << 5;
		insns[1] = 0xf2a00010 | (((new_addr >> 16) & 0xffff)) << 5;
		insns[2] = 0xf2c00010 | (((new_addr >> 32) & 0xffff)) << 5;
		insns[3] = 0xd61f0200;
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			ret = aarch64_insn_patch_text_nosync(((u32 *)pc) + i, insns[i]);
			if (ret) {
				pr_err("patch instruction %d large range failed, ret=%d\n",
				       i, ret);
				return -EPERM;
			}
		}
#else
		/*
		 * When offset from 'new_addr' to 'pc' is out of SZ_128M range but
		 * CONFIG_ARM64_MODULE_PLTS not enabled, we should stop patching.
		 */
		pr_err("new address out of range\n");
		return -EFAULT;
#endif
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
			ret = aarch64_insn_patch_text_nosync(((u32 *)pc) + i,
							     func_node->arch_data.old_insns[i]);
			if (ret) {
				pr_err("restore instruction %d failed, ret=%d\n", i, ret);
				return;
			}
		}
	} else {
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);
		if (WARN_ON(!next_func))
			return;
		do_patch(pc, (unsigned long)next_func->new_func);
	}
}
