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

#ifdef CONFIG_ARM_MODULE_PLTS
#define LJMP_INSN_SIZE	3
#endif

#ifdef ARM_INSN_SIZE
#error "ARM_INSN_SIZE have been redefined, please check"
#else
#define ARM_INSN_SIZE	4
#endif

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	void *old_func;
#ifdef CONFIG_ARM_MODULE_PLTS
	u32	old_insns[LJMP_INSN_SIZE];
#else
	u32	old_insn;
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
	struct klp_func_node *func_node;
	struct klp_func *func;
	unsigned long func_addr, func_size;
	const char *func_name;

	if (args->ret)
		return args->ret;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			if (args->enable) {
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
					func_addr = (unsigned long)prev->new_func;
					func_size = prev->new_size;
				}
			} else {
				/*
				 * When disable, check for the function itself
				 * which to be unpatched.
				 */
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
		if (t == current) {
			frame.fp = (unsigned long)__builtin_frame_address(0);
			frame.sp = current_stack_pointer;
			frame.lr = (unsigned long)__builtin_return_address(0);
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
			frame.sp = thread_saved_sp(t);
			frame.lr = 0;           /* recovered from the stack */
			frame.pc = thread_saved_pc(t);
		}

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

static inline bool offset_in_range(unsigned long pc, unsigned long addr,
				   long range)
{
	long offset = addr - pc;

	return (offset >= -range && offset < range);
}

long arm_insn_read(void *addr, u32 *insnp)
{
	long ret;
	u32 val;

	ret = copy_from_kernel_nofault(&val, addr, ARM_INSN_SIZE);
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
#ifdef CONFIG_ARM_MODULE_PLTS
	int i;
	u32 insns[LJMP_INSN_SIZE];
#endif

	func_node = klp_find_func_node(func->old_func);
	if (!func_node) {
		func_node = kzalloc(sizeof(*func_node), GFP_ATOMIC);
		if (!func_node)
			return -ENOMEM;

		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_func = func->old_func;
#ifdef CONFIG_ARM_MODULE_PLTS
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			ret = arm_insn_read((u32 *)func->old_func + i,
					    &func_node->old_insns[i]);
			if (ret)
				break;
		}
#else
		ret = arm_insn_read(func->old_func, &func_node->old_insn);
#endif
		if (ret) {
			kfree(func_node);
			return -EPERM;
		}
		list_add_rcu(&func_node->node, &klp_func_list);
	}

	list_add_rcu(&func->stack_node, &func_node->func_stack);

	pc = (unsigned long)func->old_func;
	new_addr = (unsigned long)func->new_func;

#ifdef CONFIG_ARM_MODULE_PLTS
	if (!offset_in_range(pc, new_addr, SZ_32M)) {
		/*
		 * [0] LDR PC, [PC+8]
		 * [4] nop
		 * [8] new_addr_to_jump
		 */
		insns[0] = __opcode_to_mem_arm(0xe59ff000);
		insns[1] = __opcode_to_mem_arm(0xe320f000);
		insns[2] = new_addr;

		for (i = 0; i < LJMP_INSN_SIZE; i++)
			__patch_text(((u32 *)pc) + i, insns[i]);

	} else {
		insn = arm_gen_branch(pc, new_addr);
		__patch_text((void *)pc, insn);
	}
#else
	insn = arm_gen_branch(pc, new_addr);
	__patch_text((void *)pc, insn);
#endif

	return 0;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long pc, new_addr;
	u32 insn;
#ifdef CONFIG_ARM_MODULE_PLTS
	int i;
	u32 insns[LJMP_INSN_SIZE];
#endif

	func_node = klp_find_func_node(func->old_func);
	pc = (unsigned long)func_node->old_func;
	if (list_is_singular(&func_node->func_stack)) {
#ifdef CONFIG_ARM_MODULE_PLTS
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			insns[i] = func_node->old_insns[i];
			__patch_text(((u32 *)pc) + i, insns[i]);
		}
#else
		insn = func_node->old_insn;
		__patch_text((void *)pc, insn);
#endif
		list_del_rcu(&func->stack_node);
		list_del_rcu(&func_node->node);
		kfree(func_node);
	} else {
		list_del_rcu(&func->stack_node);
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);

		new_addr = (unsigned long)next_func->new_func;
#ifdef CONFIG_ARM_MODULE_PLTS
		if (!offset_in_range(pc, new_addr, SZ_32M)) {
			/*
			 * [0] LDR PC, [PC+8]
			 * [4] nop
			 * [8] new_addr_to_jump
			 */
			insns[0] = __opcode_to_mem_arm(0xe59ff000);
			insns[1] = __opcode_to_mem_arm(0xe320f000);
			insns[2] = new_addr;

			for (i = 0; i < LJMP_INSN_SIZE; i++)
				__patch_text(((u32 *)pc) + i, insns[i]);

		} else {
			insn = arm_gen_branch(pc, new_addr);
			__patch_text((void *)pc, insn);
		}
#else
		insn = arm_gen_branch(pc, new_addr);
		__patch_text((void *)pc, insn);
#endif
	}
}

#ifdef CONFIG_ARM_MODULE_PLTS
/* return 0 if the func can be patched */
int arch_klp_func_can_patch(struct klp_func *func)
{
	unsigned long pc = (unsigned long)func->old_func;
	unsigned long new_addr = (unsigned long)func->new_func;
	unsigned long old_size = func->old_size;

	if (!old_size)
		return -EINVAL;

	if (!offset_in_range(pc, new_addr, SZ_32M) &&
	    (old_size < LJMP_INSN_SIZE * ARM_INSN_SIZE)) {
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
#endif /* #ifdef CONFIG_ARM_MODULE_PLTS */
