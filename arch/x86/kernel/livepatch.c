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

#include <linux/slab.h>
#include <asm/nops.h>
#include <asm/sections.h>

#if defined (CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY) || \
    defined (CONFIG_LIVEPATCH_WO_FTRACE)
#define	JMP_E9_INSN_SIZE	5

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	void *old_func;
	unsigned char old_code[JMP_E9_INSN_SIZE];
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
static inline int klp_compare_address(unsigned long stack_addr,
		unsigned long func_addr, unsigned long func_size,
		const char *func_name)
{
	if (stack_addr >= func_addr && stack_addr < func_addr + func_size) {
		pr_err("func %s is in use!\n", func_name);
		return -EBUSY;
	}
	return 0;
}

static int klp_check_stack_func(struct klp_func *func,
		void *trace_ptr, int trace_len, int enable)
{
#ifdef CONFIG_ARCH_STACKWALK
	unsigned long *trace = trace_ptr;
#else
	struct stack_trace *trace = trace_ptr;
#endif
	unsigned long func_addr, func_size, address;
	const char *func_name;
	struct klp_func_node *func_node;
	int i;

#ifdef CONFIG_ARCH_STACKWALK
	for (i = 0; i < trace_len; i++) {
		address = trace[i];
#else
	for (i = 0; i < trace->nr_entries; i++) {
		address = trace->entries[i];
#endif

		if (enable) {
			if (func->force)
				continue;
			/*
			 * When enable, checking the currently active
			 * functions.
			 */
			func_node = klp_find_func_node(func->old_func);
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
		} else {
			/*
			 * When disable, check for the function itself
			 * which to be unpatched.
			 */
			func_addr = (unsigned long)func->new_func;
			func_size = func->new_size;
		}
		func_name = func->old_name;

		if (klp_compare_address(address, func_addr,
				func_size, func_name))
			return -EAGAIN;
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

/*
 * Determine whether it's safe to transition the task to the target patch state
 * by looking for any to-be-patched or to-be-unpatched functions on its stack.
 */
static int klp_check_stack(struct task_struct *task,
		struct klp_patch *patch, int enable)

{
	static unsigned long trace_entries[MAX_STACK_ENTRIES];
#ifdef CONFIG_ARCH_STACKWALK
	int trace_len;
#else
	struct stack_trace trace;
#endif
	struct klp_object *obj;
	struct klp_func *func;
	int ret;

	if (!strncmp(task->comm, "migration/", 10))
		return 0;

#ifdef CONFIG_ARCH_STACKWALK
	ret = stack_trace_save_tsk_reliable(task, trace_entries, MAX_STACK_ENTRIES);
	if (ret < 0)
		return ret;
	trace_len = ret;
	ret = 0;
#else
	trace.skip = 0;
	trace.nr_entries = 0;
	trace.max_entries = MAX_STACK_ENTRIES;
	trace.entries = trace_entries;
	ret = save_stack_trace_tsk_reliable(task, &trace);
#endif
	WARN_ON_ONCE(ret == -ENOSYS);
	if (ret) {
		pr_info("%s: %s:%d has an unreliable stack\n",
			 __func__, task->comm, task->pid);
		return ret;
	}

	klp_for_each_object(patch, obj) {
		klp_for_each_func(obj, func) {
#ifdef CONFIG_ARCH_STACKWALK
			ret = klp_check_stack_func(func, &trace_entries, MAX_STACK_ENTRIES, enable);
#else
			ret = klp_check_stack_func(func, &trace, 0, enable);
#endif
			if (ret) {
				pr_info("%s: %s:%d is sleeping on function %s\n",
				__func__, task->comm, task->pid,
				func->old_name);

#ifdef CONFIG_ARCH_STACKWALK
				klp_print_stack_trace(&trace_entries, trace_len);
#else
				klp_print_stack_trace(&trace, 0);
#endif

				return ret;

			}
		}
	}

	return 0;
}

int klp_check_calltrace(struct klp_patch *patch, int enable)
{
	struct task_struct *g, *t;
	int ret = 0;

	for_each_process_thread(g, t) {
		ret = klp_check_stack(t, patch, enable);
		if (ret)
			goto out;
	}

out:
	return ret;
}
#endif

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
static void *klp_jmp_code(unsigned long ip, unsigned long addr)
{
	return text_gen_insn(JMP32_INSN_OPCODE, (void *)ip, (void *)addr);
}

static void *klp_old_code(unsigned char *code)
{
	static unsigned char old_code[JMP_E9_INSN_SIZE];

	strncpy(old_code, code, JMP_E9_INSN_SIZE);
	return old_code;
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

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long ip, new_addr;
	void *new;
	long ret;

	func_node = klp_find_func_node(func->old_func);
	ip = (unsigned long)func->old_func;
	if (!func_node) {
		func_node = kzalloc(sizeof(*func_node), GFP_ATOMIC);
		if (!func_node)
			return -ENOMEM;

		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_func = func->old_func;
		ret = copy_from_kernel_nofault(func_node->old_code,
					(void *)ip, JMP_E9_INSN_SIZE);
		if (ret) {
			kfree(func_node);
			return -EPERM;
		}
		list_add_rcu(&func_node->node, &klp_func_list);
	}

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

	func_node = klp_find_func_node(func->old_func);
	ip = (unsigned long)func_node->old_func;
	if (list_is_singular(&func_node->func_stack)) {
		list_del_rcu(&func->stack_node);
		list_del_rcu(&func_node->node);
		new = klp_old_code(func_node->old_code);
		kfree(func_node);
	} else {
		list_del_rcu(&func->stack_node);
		next_func = list_first_or_null_rcu(&func_node->func_stack,
						struct klp_func, stack_node);

		new_addr = (unsigned long)next_func->new_func;
		new = klp_jmp_code(ip, new_addr);
	}

	/* replace the text with the new text */
	text_poke((void *)ip, new, JMP_E9_INSN_SIZE);
}
#endif
