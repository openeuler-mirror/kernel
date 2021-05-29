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
#define LJMP_INSN_SIZE	4

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	void *old_func;
	u32	old_insns[LJMP_INSN_SIZE];
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
};

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

static int unwind_frame(struct task_struct *tsk, struct stackframe *frame)
{

	unsigned long *stack;

	if (!validate_sp(frame->sp, tsk, STACK_FRAME_OVERHEAD))
		return -1;

	stack = (unsigned long *)frame->sp;
	frame->sp = stack[0];
	frame->pc = stack[STACK_FRAME_LR_SAVE];
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
			 * Handle the current carefully on each CPUs, we shouldn't
			 * use saved FP and PC when backtrace current. It's difficult
			 * to backtrack other CPU currents here. But fortunately,
			 * all CPUs will stay in this function, so the current's
			 * backtrace is so similar
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
		klp_walk_stackframe(&frame, klp_check_activeness_func,
				t, &args);
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

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
static inline bool offset_in_range(unsigned long pc, unsigned long addr,
				   long range)
{
	long offset = addr - pc;

	return (offset >= -range && offset < range);
}

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long pc, new_addr;
	long ret;
	int memory_flag = 0;
	int i;
	u32 insns[LJMP_INSN_SIZE];

	func_node = klp_find_func_node(func->old_func);
	if (!func_node) {
		func_node = kzalloc(sizeof(*func_node), GFP_ATOMIC);
		if (!func_node)
			return -ENOMEM;

		memory_flag = 1;
		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_func = func->old_func;
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			ret = copy_from_kernel_nofault(&func_node->old_insns[i],
				((u32 *)func->old_func) + i, LJMP_INSN_SIZE);
			if (ret) {
				kfree(func_node);
				return -EPERM;
			}
		}

		list_add_rcu(&func_node->node, &klp_func_list);
	}

	list_add_rcu(&func->stack_node, &func_node->func_stack);

	pc = (unsigned long)func->old_func;
	new_addr = (unsigned long)func->new_func;
	if (offset_in_range(pc, new_addr, SZ_32M)) {
		struct ppc_inst instr;

		create_branch(&instr, (struct ppc_inst *)pc, new_addr, 0);
		if (patch_instruction((struct ppc_inst *)pc, instr))
			goto ERR_OUT;
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
			if (ret)
				goto ERR_OUT;
		}
	}

	return 0;

ERR_OUT:
	list_del_rcu(&func->stack_node);
	if (memory_flag) {
		list_del_rcu(&func_node->node);
		kfree(func_node);
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
		kfree(func_node);

		for (i = 0; i < LJMP_INSN_SIZE; i++)
			patch_instruction((struct ppc_inst *)(((u32 *)pc) + i),
					  ppc_inst(insns[i]));
	} else {
		list_del_rcu(&func->stack_node);
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);

		new_addr = (unsigned long)next_func->new_func;
		if (offset_in_range(pc, new_addr, SZ_32M)) {
			struct ppc_inst instr;

			create_branch(&instr, (struct ppc_inst *)pc, new_addr, 0);
			patch_instruction((struct ppc_inst *)pc, instr);
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

			for (i = 0; i < LJMP_INSN_SIZE; i++)
				patch_instruction((struct ppc_inst *)(((u32 *)pc) + i),
						  ppc_inst(insns[i]));
		}
	}
}

/* return 0 if the func can be patched */
int arch_klp_func_can_patch(struct klp_func *func)
{
	unsigned long pc = (unsigned long)func->old_func;
	unsigned long new_addr = (unsigned long)func->new_func;
	unsigned long old_size = func->old_size;

	if (!old_size)
		return -EINVAL;

	if (!offset_in_range(pc, new_addr, SZ_32M) &&
	    (old_size < LJMP_INSN_SIZE * sizeof(u32))) {
		pr_err("func %s size less than limit\n", func->old_name);
		return -EPERM;
	}
	return 0;
}
#endif
