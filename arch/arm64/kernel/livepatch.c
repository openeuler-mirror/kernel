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

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
#include <linux/sched/debug.h>
#include <linux/kallsyms.h>
#endif

#ifdef CONFIG_ARM64_MODULE_PLTS
static inline bool offset_in_range(unsigned long pc, unsigned long addr,
		long range)
{
	long offset = addr - pc;

	return (offset >= -range && offset < range);
}
#endif

#define LJMP_INSN_SIZE 4

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	unsigned long old_addr;
#ifdef CONFIG_ARM64_MODULE_PLTS
	u32	old_insns[LJMP_INSN_SIZE];
#else
	u32	old_insn;
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
	struct klp_func_node *func_node;

	if (args->ret)
		return args->ret;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			if (args->enable) {
				if (func->force)
					continue;

				/*
				 * When enable, checking the currently
				 * active functions.
				 */
				func_node = klp_find_func_node(func->old_addr);
				if (!func_node ||
				    list_empty(&func_node->func_stack)) {
					func_addr = func->old_addr;
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
			} else {
				/*
				 * When disable, check for the function
				 * itself which to be unpatched.
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
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		frame.graph = t->curr_ret_stack;
#endif
		walk_stackframe(t, &frame, klp_check_activeness_func, &args);
		if (args.ret) {
			ret = args.ret;
			pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
			show_stack(t, NULL);
			goto out;
		}
	}

out:
	return ret;
}

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
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

	func_node = klp_find_func_node(func->old_addr);
	if (!func_node) {
		func_node = kzalloc(sizeof(*func_node), GFP_ATOMIC);
		if (!func_node)
			return -ENOMEM;
		memory_flag = 1;

		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_addr = func->old_addr;

#ifdef CONFIG_ARM64_MODULE_PLTS
		for (i = 0; i < LJMP_INSN_SIZE; i++) {
			aarch64_insn_read(((u32 *)func->old_addr) + i,
					&func_node->old_insns[i]);
		}
#else
		aarch64_insn_read((void *)func->old_addr, &func_node->old_insn);
#endif

		list_add_rcu(&func_node->node, &klp_func_list);
	}

	list_add_rcu(&func->stack_node, &func_node->func_stack);

	pc = func->old_addr;
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
	if (memory_flag) {
		list_del_rcu(&func->stack_node);
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
	u32 insn;
#ifdef CONFIG_ARM64_MODULE_PLTS
	int i;
	u32 insns[LJMP_INSN_SIZE];
#endif

	func_node = klp_find_func_node(func->old_addr);
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
		kfree(func_node);

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
	unsigned long pc = func->old_addr;
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
#endif /* #ifdef CONFIG_ARM64_MODULE_PLTS */
#endif


/* Apply per-object alternatives. Based on arm64 module_finalize() */
void arch_klp_init_object_loaded(struct klp_patch *patch,
				 struct klp_object *obj)
{
	int cnt;
	struct klp_modinfo *info;
	Elf_Shdr *s, *alt = NULL;
	void *aseg;
	const char *objname;
	char sec_objname[MODULE_NAME_LEN];
	char secname[KSYM_NAME_LEN];

	info = patch->mod->klp_info;
	objname = obj->name ? obj->name : "vmlinux";

	/* See livepatch core code for BUILD_BUG_ON() explanation */
	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);

	for (s = info->sechdrs; s < info->sechdrs + info->hdr.e_shnum; s++) {
		/* Apply per-object .klp.arch sections */
		cnt = sscanf(info->secstrings + s->sh_name,
			     ".klp.arch.%55[^.].%127s",
			     sec_objname, secname);

		if (cnt != 2)
			continue;
		if (strcmp(sec_objname, objname))
			continue;
		if (!strcmp(".altinstructions", secname))
			alt = s;
	}

	if (alt) {
		aseg = (void *) alt->sh_addr;
		apply_alternatives_module(aseg, alt->sh_size);
	}
}
