/*
 * livepatch.c - x86-specific Kernel Live Patching Core
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
#include <linux/kallsyms.h>
#include <linux/livepatch.h>
#include <linux/stacktrace.h>
#include <linux/memory.h>
#include <asm/text-patching.h>
#include <asm/stacktrace.h>
#include <asm/set_memory.h>
#include <asm/insn.h>

#include <linux/slab.h>
#include <asm/nops.h>
#include <asm/sections.h>

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
/*
 * The instruction set on x86 is CISC.
 * The instructions of call in same segment are 11101000(direct),
 * 11111111(register indirect) and 11111111(memory indirect).
 * The instructions of call in other segment are 10011010(direct),
 * 11111111(indirect).
 */
static bool is_jump_insn(u8 *insn)
{
	if ((insn[0] == 0xE8) || (insn[0] == 0x9a))
		return true;
	else if ((insn[0] == 0xFF) && ((insn[1] & 0x30) == 0x10))
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

static inline unsigned long klp_size_to_check(unsigned long func_size,
		int force)
{
	unsigned long size = func_size;

	if (force == KLP_STACK_OPTIMIZE && size > JMP_E9_INSN_SIZE)
		size = JMP_E9_INSN_SIZE;
	return size;
}

static inline int klp_compare_address(unsigned long stack_addr,
		unsigned long func_addr, const char *func_name,
		unsigned long check_size)
{
	if (stack_addr >= func_addr && stack_addr < func_addr + check_size) {
		pr_err("func %s is in use!\n", func_name);
		return -EBUSY;
	}
	return 0;
}

static bool check_jump_insn(unsigned long func_addr)
{
	int len = JMP_E9_INSN_SIZE;
	struct insn insn;
	u8 *addr = (u8*)func_addr;

	do {
		if (is_jump_insn(addr))
			return true;
		insn_init(&insn, addr, MAX_INSN_SIZE, 1);
		insn_get_length(&insn);
		if (!insn.length || !insn_complete(&insn))
			return true;
		len -= insn.length;
		addr += insn.length;
	} while (len > 0);

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
				 * When preemtion is disabled and the
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
				 * When disable, check for the function
				 * itself which to be unpatched.
				 */
				if (!func_node)
					return -EINVAL;
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
				ret = add_func_to_list(check_funcs, &pcheck, func_addr,
						func_size, func->old_name, 0);
				if (ret)
					return ret;
#endif

				func_addr = (unsigned long)func->new_func;
				func_size = func->new_size;
				ret = add_func_to_list(check_funcs, &pcheck, func_addr,
						func_size, func->old_name, 0);
				if (ret)
					return ret;
			}
		}
	}
	return 0;
}

static void klp_print_stack_trace(void *trace_ptr, int trace_len)
{
	int i;
#ifdef CONFIG_ARCH_STACKWALK
	unsigned long *trace = trace_ptr;
#else
	struct stack_trace *trace = trace_ptr;
#endif

	pr_err("Call Trace:\n");
#ifdef CONFIG_ARCH_STACKWALK
	for (i = 0; i < trace_len; i++) {
		pr_err("[<%pK>] %pS\n",
		(void *)trace[i],
		(void *)trace[i]);
	}
#else
	for (i = 0; i < trace->nr_entries; i++) {
		pr_err("[<%pK>] %pS\n",
		(void *)trace->entries[i],
		(void *)trace->entries[i]);
	}
#endif

}

#ifdef MAX_STACK_ENTRIES
#undef MAX_STACK_ENTRIES
#endif
#define MAX_STACK_ENTRIES  100

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

static int klp_check_stack(void *trace_ptr, int trace_len,
		struct klp_func_list *check_funcs)
{
#ifdef CONFIG_ARCH_STACKWALK
	unsigned long *trace = trace_ptr;
#else
	struct stack_trace *trace = trace_ptr;
#endif
	unsigned long address;
	int i, ret;

#ifdef CONFIG_ARCH_STACKWALK
	for (i = 0; i < trace_len; i++) {
		address = trace[i];
#else
	for (i = 0; i < trace->nr_entries; i++) {
		address = trace->entries[i];
#endif
		if (!check_func_list(check_funcs, &ret, address)) {
#ifdef CONFIG_ARCH_STACKWALK
			klp_print_stack_trace(trace_ptr, trace_len);
#else
			klp_print_stack_trace(trace_ptr, 0);
#endif
			return ret;
		}
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
	int ret = 0;
	struct klp_func_list *check_funcs = NULL;
	static unsigned long trace_entries[MAX_STACK_ENTRIES];
#ifdef CONFIG_ARCH_STACKWALK
	int trace_len;
#else
	struct stack_trace trace;
#endif

	ret = klp_check_activeness_func(patch, enable, &check_funcs);
	if (ret) {
		pr_err("collect active functions failed, ret=%d\n", ret);
		goto out;
	}
	for_each_process_thread(g, t) {
		if (!strncmp(t->comm, "migration/", 10))
			continue;

#ifdef CONFIG_ARCH_STACKWALK
		ret = stack_trace_save_tsk_reliable(t, trace_entries, MAX_STACK_ENTRIES);
		if (ret < 0) {
			pr_err("%s:%d has an unreliable stack, ret=%d\n",
			       t->comm, t->pid, ret);
			goto out;
		}
		trace_len = ret;
		ret = klp_check_stack(trace_entries, trace_len, check_funcs);
#else
		trace.skip = 0;
		trace.nr_entries = 0;
		trace.max_entries = MAX_STACK_ENTRIES;
		trace.entries = trace_entries;
		ret = save_stack_trace_tsk_reliable(t, &trace);
		WARN_ON_ONCE(ret == -ENOSYS);
		if (ret) {
			pr_err("%s: %s:%d has an unreliable stack, ret=%d\n",
			       __func__, t->comm, t->pid, ret);
			goto out;
		}
		ret = klp_check_stack(&trace, 0, check_funcs);
#endif
		if (ret) {
			pr_err("%s:%d check stack failed, ret=%d\n",
			       t->comm, t->pid, ret);
			goto out;
		}
	}

out:
	free_list(&check_funcs);
	return ret;
}
#endif

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
static void *klp_jmp_code(unsigned long ip, unsigned long addr)
{
	return text_gen_insn(JMP32_INSN_OPCODE, (void *)ip, (void *)addr);
}

void arch_klp_code_modify_prepare(void)
	__acquires(&text_mutex)
{
	mutex_lock(&text_mutex);
}

void arch_klp_code_modify_post_process(void)
	__releases(&text_mutex)
{
	text_poke_sync();
	mutex_unlock(&text_mutex);
}

long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func)
{
	return copy_from_kernel_nofault(arch_data->old_code,
					old_func, JMP_E9_INSN_SIZE);
}

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long ip, new_addr;
	void *new;

	func_node = func->func_node;
	ip = (unsigned long)func->old_func;
	list_add_rcu(&func->stack_node, &func_node->func_stack);
	new_addr = (unsigned long)func->new_func;
	/* replace the text with the new text */
	new = klp_jmp_code(ip, new_addr);
	text_poke((void *)ip, new, JMP_E9_INSN_SIZE);

	return 0;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long ip, new_addr;
	void *new;

	func_node = func->func_node;
	ip = (unsigned long)func_node->old_func;
	list_del_rcu(&func->stack_node);
	if (list_empty(&func_node->func_stack)) {
		new = func_node->arch_data.old_code;
	} else {
		next_func = list_first_or_null_rcu(&func_node->func_stack,
						struct klp_func, stack_node);

		new_addr = (unsigned long)next_func->new_func;
		new = klp_jmp_code(ip, new_addr);
	}

	/* replace the text with the new text */
	text_poke((void *)ip, new, JMP_E9_INSN_SIZE);
}
#endif
