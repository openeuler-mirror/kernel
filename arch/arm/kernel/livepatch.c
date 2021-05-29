// SPDX-License-Identifier: GPL-2.0-only
/*
 * livepatch.c - arm-specific Kernel Live Patching Core
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
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <asm/insn.h>
#include <asm/patch.h>

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
struct walk_stackframe_args {
	struct klp_patch *patch;
	int enable;
	int ret;
};

static inline int klp_compare_address(unsigned long pc, unsigned long func_addr,
				unsigned long func_size, const char *func_name)
{
	if (pc >= func_addr && pc < func_addr + func_size) {
		pr_err("func %s is in use!\n", func_name);
		return -EBUSY;
	}
	return 0;
}

static int klp_check_activeness_func(struct stackframe *frame, void *data)
{
	struct walk_stackframe_args *args = data;
	struct klp_patch *patch = args->patch;
	struct klp_object *obj;
	struct klp_func *func;
	unsigned long func_addr, func_size;
	const char *func_name;

	if (args->ret)
		return args->ret;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			if (args->enable) {
				func_addr = (unsigned long)func->old_func;
				func_size = func->old_size;
			} else {
				func_addr = (unsigned long)func->new_func;
				func_size = func->new_size;
			}
			func_name = func->old_name;
			args->ret = klp_compare_address(frame->pc, func_addr,
					func_size, func_name);
			if (args->ret)
				return args->ret;
		}
	}

	return args->ret;
}

int klp_check_calltrace(struct klp_patch *patch, int enable)
{
	struct task_struct *g, *t;
	struct stackframe frame;
	int ret = 0;

	struct walk_stackframe_args args = {
		.patch = patch,
		.enable = enable,
		.ret = 0
	};

	for_each_process_thread(g, t) {
		frame.fp = thread_saved_fp(t);
		frame.sp = thread_saved_sp(t);
		frame.pc = thread_saved_pc(t);
		walk_stackframe(&frame, klp_check_activeness_func, &args);
		if (args.ret) {
			ret = args.ret;
			pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
			show_stack(t, NULL, KERN_INFO);
			goto out;
		}
	}

out:
	return ret;
}
#endif

#define LJMP_INSN_SIZE	4

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	void *old_func;
	u32	old_insn;
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

long arm_insn_read(void *addr, u32 *insnp)
{
	long ret;
	u32 val;

	ret = copy_from_kernel_nofault(&val, addr, LJMP_INSN_SIZE);
	if (!ret)
		*insnp = le32_to_cpu(val);

	return ret;
}

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long pc, new_addr;
	u32 insn;
	long ret;

	func_node = klp_find_func_node(func->old_func);
	if (!func_node) {
		func_node = kzalloc(sizeof(*func_node), GFP_ATOMIC);
		if (!func_node)
			return -ENOMEM;

		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_func = func->old_func;
		ret = arm_insn_read(func->old_func, &func_node->old_insn);
		if (ret) {
			kfree(func_node);
			return -EPERM;
		}
		list_add_rcu(&func_node->node, &klp_func_list);
	}

	list_add_rcu(&func->stack_node, &func_node->func_stack);

	pc = (unsigned long)func->old_func;
	new_addr = (unsigned long)func->new_func;
	insn = arm_gen_branch(pc, new_addr);

	__patch_text((void *)pc, insn);

	return 0;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long pc, new_addr;
	u32 insn;

	func_node = klp_find_func_node(func->old_func);
	pc = (unsigned long)func_node->old_func;
	if (list_is_singular(&func_node->func_stack)) {
		insn = func_node->old_insn;
		list_del_rcu(&func->stack_node);
		list_del_rcu(&func_node->node);
		kfree(func_node);

		__patch_text((void *)pc, insn);
	} else {
		list_del_rcu(&func->stack_node);
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);

		new_addr = (unsigned long)next_func->new_func;
		insn = arm_gen_branch(pc, new_addr);

		__patch_text((void *)pc, insn);
	}
}
