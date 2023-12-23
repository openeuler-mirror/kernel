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
#include <asm/livepatch.h>
#include <asm/cacheflush.h>
#include <asm/code-patching.h>
#include <asm/elf.h>

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
		    arch_check_jump_insn(func_addr)) {
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
#endif /* CONFIG_PREEMPTION */

		if (func_node->arch_data.trampoline.magic != BRANCH_TRAMPOLINE_MAGIC)
			return 0;

		func_addr = (unsigned long)&func_node->arch_data.trampoline;
		func_size = sizeof(struct ppc64_klp_btramp_entry);
		ret = add_func(func_list, func_addr,
				func_size, "trampoline", 0);
		if (ret)
			return ret;
	}
	return 0;
}

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

	func->new_func_descr.addr = new_addr;
	func->new_func_descr.toc = func->this_mod->arch.toc;
	func->new_func_descr.env = 0;
	func->new_func = (void *)&func->new_func_descr;

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
