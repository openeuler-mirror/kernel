// SPDX-License-Identifier: GPL-2.0
/*
 * livepatch.c - riscv64-specific Kernel Live Patching Core
 *
 * Copyright (C) 2014 Li Bin <huawei.libin@huawei.com>
 * Copyright (C) 2023 Zheng Yejian <zhengyejian1@huawei.com>
 * Copyright (C) 2023 laokz <zhangkai@iscas.ac.cn>
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

/* NOTE, only little-endian machine supported now. */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/uaccess.h>
#include <linux/livepatch.h>
#include <linux/stacktrace.h>
#include <linux/sched/debug.h>
#include <asm/livepatch.h>
#include <asm/patch.h>

#define CHECK_JUMP_RANGE LJMP_INSN_SIZE
#define LJMP_INSN0       0x00000f97
#define LJMP_INSN1       0x010fbf83
#define LJMP_INSN2       0x000f8067
#define NEW_ADDR_INDEX   4
#define EBREAK_INSN      0x00100073

/*
 * Check if any call instructor in the replace area.
 *
 * 31    20   19   15   14 12   11   7   6     0
 *             imm            |   rd   | 1101111    jal  (rd != 0)
 *    imm   |   rs1   |  000  |   rd   | 1100111    jalr (rd != 0)
 *
 * 15 13   12  11    7   6    2   1  0
 *  001  |         imm          |  01       c.jal
 *  100  | 1 |   rs1   | 00000  |  10       c.jalr (rs1 != 0)
 */
bool arch_check_jump_insn(unsigned long func_addr)
{
	unsigned long start = func_addr;
	unsigned long end = func_addr + CHECK_JUMP_RANGE * 4;
	short *i16;
	int *i32;

	while (start < end) {
		if ((*(char *)start & 0x3) == 3) { /* RV32I */
			i32 = (int *)start;      /* jal && rd != 0 */
			if (((*i32 & 0x7f) == 0x6f && (*i32 & 0xf80) != 0) ||
						/* jalr && rd != 0 */
			    ((*i32 & 0x707f) == 0x67 && (*i32 & 0xf80) != 0))
				return true;
			start += 4;
		} else { /* RVC */
			i16 = (short *)start;
			if ((*i16 & 0xe003) == 0x2001 ||                  /* c.jal */
			   ((*i16 & 0xf07f) == 0x9002 && *i16 != 0x9002)) /* c.jalr */
				return true;
			start += 2;
		}
	}
	return false;
}

static bool klp_check_jump_func(void *ws_args, unsigned long pc)
{
	struct walk_stackframe_args *args = ws_args;

	return args->check_func(args->data, &args->ret, pc);
}

static int check_task_calltrace(struct task_struct *t,
				struct walk_stackframe_args *args,
				bool (*fn)(void *, unsigned long))
{
	arch_stack_walk(fn, args, t, NULL);
	if (args->ret) {
		pr_info("PID: %d Comm: %.20s\n", t->pid, t->comm);
		show_stack(t, NULL, KERN_INFO);
		return args->ret;
	}
	return 0;
}

static int do_check_calltrace(struct walk_stackframe_args *args,
			      bool (*fn)(void *, unsigned long))
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

int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data)
{
	struct walk_stackframe_args args = {
		.data = data,
		.ret = 0,
		.check_func = check_func,
	};

	return do_check_calltrace(&args, klp_check_jump_func);
}

long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func)
{
	long ret = copy_from_kernel_nofault(arch_data->old_insns, old_func, KLP_MAX_REPLACE_SIZE);

	if (ret)
		return ret;

	/* assume only we can set breakpoint to this patient */
	if (arch_data->old_insns[0] == EBREAK_INSN)
		arch_data->old_insns[0] = arch_data->saved_opcode;
	return 0;
}

static bool check_module_calltrace(void *ws_args, unsigned long pc)
{
	struct walk_stackframe_args *args = ws_args;
	struct module *mod = args->data;

	if (within_module_core(pc, mod)) {
		pr_err("module %s is in use!\n", mod->name);
		args->ret = -EBUSY;
		return false;
	}
	return true;
}

int arch_klp_module_check_calltrace(void *data)
{
	struct walk_stackframe_args args = {
		.data = data,
		.ret = 0
	};

	return do_check_calltrace(&args, check_module_calltrace);
}

int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	u32 insn = EBREAK_INSN;

	arch_data->saved_opcode = *(u32 *)old_func;
	return patch_text(old_func, &insn, 1);
}

void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	patch_text(old_func, &arch_data->saved_opcode, 1);
}

static int do_patch(unsigned long pc, unsigned long new_addr)
{
	u32 insns[LJMP_INSN_SIZE] = {LJMP_INSN0, LJMP_INSN1, LJMP_INSN2};
	unsigned long *l = (unsigned long *)&insns[NEW_ADDR_INDEX];
	int ret;

	*l = new_addr;

	ret = patch_text_nosync((void *)pc, (void *)insns, KLP_MAX_REPLACE_SIZE);
	if (ret) {
		pr_err("patch instruction failed, ret=%d\n", ret);
		return -EPERM;
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
	int ret;

	func_node = func->func_node;
	pc = (unsigned long)func_node->old_func;
	list_del_rcu(&func->stack_node);
	if (list_empty(&func_node->func_stack)) {
		ret = patch_text_nosync(func_node->old_func,
			(void *)func_node->arch_data.old_insns, KLP_MAX_REPLACE_SIZE);
		if (ret) {
			pr_err("restore instruction failed, ret=%d\n", ret);
			return;
		}
	} else {
		next_func = list_first_or_null_rcu(&func_node->func_stack,
					struct klp_func, stack_node);
		if (WARN_ON(!next_func))
			return;
		do_patch(pc, (unsigned long)next_func->new_func);
	}
}

/*
 * Per the RISC-V psABI:
 *
 *   In the linker relaxation optimization, we introduce a concept
 *   called relocation group; a relocation group consists of 1)
 *   relocations associated with the same target symbol and can be
 *   applied with the same relaxation, or 2) relocations with the
 *   linkage relationship (e.g. `R_RISCV_PCREL_LO12_S` linked with
 *   a `R_RISCV_PCREL_HI20`); all relocations in a single group must
 *   be present in the same section, otherwise will split into another
 *   relocation group.
 *
 * When patches reference external non-exported globals, their
 * R_RISCV_PCREL_HI20/R_RISCV_PCREL_LO12_I relocations target the same
 * symbol and must live in the same section.
 *
 *   R_RISCV_PCREL_HI20 entry should be moved to .klp.rela.xxx section
 *                      when making patch, and when loading livepatch
 *                      core will resolve the target symbol address
 *   R_RISCV_PCREL_LO12_I should also be moved to .klp.rela.xxx section
 *                      when making patch, but when loading livepatch
 *                      core MUST ignore it because R_RISCV_PCREL_LO12_I
 *                      indeed is just a link to the R_RISCV_PCREL_HI20
 */
bool arch_klp_skip_resolve(unsigned int type)
{
	return (type == R_RISCV_PCREL_LO12_I || type == R_RISCV_PCREL_LO12_S);
}
