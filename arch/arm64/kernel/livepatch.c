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
#include <linux/ftrace.h>
#include <linux/sched/debug.h>
#include <linux/kallsyms.h>

#define LJMP_INSN_SIZE 4

#ifdef CONFIG_ARM64_MODULE_PLTS
#define MAX_SIZE_TO_CHECK (LJMP_INSN_SIZE * sizeof(u32))
#define CHECK_JUMP_RANGE LJMP_INSN_SIZE

static inline bool offset_in_range(unsigned long pc, unsigned long addr,
		long range)
{
	long offset = addr - pc;

	return (offset >= -range && offset < range);
}

#else
#define MAX_SIZE_TO_CHECK sizeof(u32)
#define CHECK_JUMP_RANGE 1
#endif

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	unsigned long old_addr;
#ifdef CONFIG_ARM64_MODULE_PLTS
	u32 old_insns[LJMP_INSN_SIZE];
#else
	u32 old_insn;
#endif
};

static LIST_HEAD(klp_func_list);

static struct klp_func_node *klp_find_func_node(unsigned long old_addr)
{
	struct klp_func_node *func_node;

	list_for_each_entry(func_node, &klp_func_list, node) {
		if (func_node->old_addr == old_addr)
			return func_node;
	}

	return NULL;
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

struct klp_func_list {
	struct klp_func_list *next;
	unsigned long func_addr;
	unsigned long func_size;
	const char *func_name;
	int force;
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
	unsigned long func_addr, func_size;
	struct klp_func_node *func_node;
	struct klp_func_list *pcheck = NULL;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			if (enable) {
				if (func->force == KLP_ENFORCEMENT)
					continue;
				/*
				 * When enable, checking the currently
				 * active functions.
				 */
				func_node = klp_find_func_node((unsigned long)func->old_func);
				if (!func_node ||
				    list_empty(&func_node->func_stack)) {
					func_addr = (unsigned long)func->old_func;
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
				}
			} else {
				/*
				 * When disable, check for the previously
				 * patched function and the function itself
				 * which to be unpatched.
				 */
				func_node = klp_find_func_node((unsigned long)func->old_func);
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
					func_addr = (unsigned long)func->old_func;
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

int klp_check_calltrace(struct klp_patch *patch, int enable)
{
	struct task_struct *g, *t;
	struct stackframe frame;
	int ret = 0;
	struct klp_func_list *check_funcs = NULL;
	struct walk_stackframe_args args = {
		.enable = enable,
		.ret = 0
	};

	ret = klp_check_activeness_func(patch, enable, &check_funcs);
	if (ret)
		goto out;
	args.check_funcs = check_funcs;

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
			frame.pc = (unsigned long)klp_check_calltrace;
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
			frame.fp = thread_saved_fp(t);
			frame.pc = thread_saved_pc(t);
		}
		if (check_funcs != NULL) {
			start_backtrace(&frame, frame.fp, frame.pc);
			walk_stackframe(t, &frame, klp_check_jump_func, &args);
			if (args.ret) {
				ret = args.ret;
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

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long pc, new_addr;
	u32 insn;
	u32 memory_flag = 0;
#ifdef CONFIG_ARM64_MODULE_PLTS
	int i;
	u32 insns[LJMP_INSN_SIZE];
#endif
	int ret = 0;

	func_node = klp_find_func_node((unsigned long)func->old_func);
	if (!func_node) {
		func_node = func->func_node;
		if (!func_node)
			return -ENOMEM;
		memory_flag = 1;

		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_addr = (unsigned long)func->old_func;

#ifdef CONFIG_ARM64_MODULE_PLTS
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			ret = aarch64_insn_read(((u32 *)func->old_func) + i,
					&func_node->old_insns[i]);
			if (ret)
				break;
		}
#else
		ret = aarch64_insn_read((void *)func->old_func,
					&func_node->old_insn);
#endif
		if (ret) {
			return -EPERM;
		}

		list_add_rcu(&func_node->node, &klp_func_list);
	}

	list_add_rcu(&func->stack_node, &func_node->func_stack);

	pc = (unsigned long)func->old_func;
	new_addr = (unsigned long)func->new_func;

#ifdef CONFIG_ARM64_MODULE_PLTS
	if (offset_in_range(pc, new_addr, SZ_128M)) {
		insn = aarch64_insn_gen_branch_imm(pc, new_addr,
				AARCH64_INSN_BRANCH_NOLINK);
		if (aarch64_insn_patch_text_nosync((void *)pc, insn))
			goto ERR_OUT;
	} else {
		insns[0] = cpu_to_le32(0x92800010 | (((~new_addr) & 0xffff)) << 5);
		insns[1] = cpu_to_le32(0xf2a00010 | (((new_addr >> 16) & 0xffff)) << 5);
		insns[2] = cpu_to_le32(0xf2c00010 | (((new_addr >> 32) & 0xffff)) << 5);
		insns[3] = cpu_to_le32(0xd61f0200);
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			if (aarch64_insn_patch_text_nosync(((u32 *)pc) + i, insns[i]))
				goto ERR_OUT;
		}
	}
#else
	insn = aarch64_insn_gen_branch_imm(pc, new_addr,
			AARCH64_INSN_BRANCH_NOLINK);

	if (aarch64_insn_patch_text_nosync((void *)pc, insn))
		goto ERR_OUT;
#endif
	return 0;

ERR_OUT:
	list_del_rcu(&func->stack_node);
	if (memory_flag) {
		list_del_rcu(&func_node->node);
	}

	return -EPERM;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long pc, new_addr;
	u32 insn;
#ifdef CONFIG_ARM64_MODULE_PLTS
	int i;
	u32 insns[LJMP_INSN_SIZE];
#endif
	func_node = klp_find_func_node((unsigned long)func->old_func);
	if (WARN_ON(!func_node))
		return;

	pc = func_node->old_addr;
	if (list_is_singular(&func_node->func_stack)) {
#ifdef CONFIG_ARM64_MODULE_PLTS
		for (i = 0; i < LJMP_INSN_SIZE; i++)
			insns[i] = func_node->old_insns[i];
#else
		insn = func_node->old_insn;
#endif
		list_del_rcu(&func->stack_node);
		list_del_rcu(&func_node->node);

#ifdef CONFIG_ARM64_MODULE_PLTS
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			aarch64_insn_patch_text_nosync(((u32 *)pc) + i,
					insns[i]);
		}
#else
		aarch64_insn_patch_text_nosync((void *)pc, insn);
#endif
	} else {
		list_del_rcu(&func->stack_node);
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);
		if (WARN_ON(!next_func))
			return;

		new_addr = (unsigned long)next_func->new_func;
#ifdef CONFIG_ARM64_MODULE_PLTS
		if (offset_in_range(pc, new_addr, SZ_128M)) {
			insn = aarch64_insn_gen_branch_imm(pc, new_addr,
					AARCH64_INSN_BRANCH_NOLINK);

			aarch64_insn_patch_text_nosync((void *)pc, insn);
		} else {
			insns[0] = cpu_to_le32(0x92800010 | (((~new_addr) & 0xffff)) << 5);
			insns[1] = cpu_to_le32(0xf2a00010 | (((new_addr >> 16) & 0xffff)) << 5);
			insns[2] = cpu_to_le32(0xf2c00010 | (((new_addr >> 32) & 0xffff)) << 5);
			insns[3] = cpu_to_le32(0xd61f0200);
			for (i = 0; i < LJMP_INSN_SIZE; i++)
				aarch64_insn_patch_text_nosync(((u32 *)pc) + i,
						insns[i]);
		}
#else
		insn = aarch64_insn_gen_branch_imm(pc, new_addr,
				AARCH64_INSN_BRANCH_NOLINK);

		aarch64_insn_patch_text_nosync((void *)pc, insn);
#endif
	}
}

#ifdef CONFIG_ARM64_MODULE_PLTS
/* return 0 if the func can be patched */
int arch_klp_func_can_patch(struct klp_func *func)
{
	unsigned long pc = (unsigned long)func->old_func;
	unsigned long new_addr = (unsigned long)func->new_func;
	unsigned long old_size = func->old_size;

	if ((long)old_size <= 0)
		return -EINVAL;

	if (!offset_in_range(pc, new_addr, SZ_128M) &&
	  (old_size < LJMP_INSN_SIZE * sizeof(u32))) {
		pr_err("func %s size less than limit\n", func->old_name);
		return -EPERM;
	}
	return 0;
}
#else
int arch_klp_func_can_patch(struct klp_func *func)
{
	return 0;
}
#endif

void arch_klp_mem_prepare(struct klp_patch *patch)
{
	struct klp_object *obj;
	struct klp_func *func;

	klp_for_each_object(patch, obj) {
		klp_for_each_func(obj, func) {
			func->func_node = kzalloc(sizeof(struct klp_func_node),
					GFP_ATOMIC);
		}
	}
}

void arch_klp_mem_recycle(struct klp_patch *patch)
{
	struct klp_object *obj;
	struct klp_func *func;
	struct klp_func_node *func_node;

	klp_for_each_object(patch, obj) {
		klp_for_each_func(obj, func) {
			func_node = func->func_node;
			if (func_node && list_is_singular(&func_node->func_stack)) {
				kfree(func_node);
				func->func_node = NULL;
			}
		}
	}
}
