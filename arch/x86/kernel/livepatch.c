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
#include <linux/kprobes.h>
#endif

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

int arch_klp_check_activeness_func(struct klp_patch *patch, int enable,
				   klp_add_func_t add_func, struct klp_func_list **func_list)
{
	int ret;
	struct klp_object *obj;
	struct klp_func *func;
	unsigned long func_addr = 0;
	unsigned long func_size;
	struct klp_func_node *func_node = NULL;
	struct klp_func_list *pcheck = NULL;

	for (obj = patch->objs; obj->funcs; obj++) {
		for (func = obj->funcs; func->old_name; func++) {
			unsigned long old_func = (unsigned long)func->old_func;

			func_node = klp_find_func_node(func->old_func);
			/* Check func address in stack */
			if (enable) {
				bool need_check_old = false;

				if (func->patched || func->force == KLP_ENFORCEMENT)
					continue;
				/*
				 * When enable, checking the currently
				 * active functions.
				 */
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
					ret = add_func(func_list, &pcheck,
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
				ret = add_func(func_list, &pcheck, func_addr,
						func_size, func->old_name, 0);
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
				ret = add_func(func_list, &pcheck, func_addr,
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

static int klp_check_stack(void *trace_ptr, int trace_len,
			   bool (*fn)(void *, int *, unsigned long), void *data)
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
		if (!fn(data, &ret, address)) {
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

static int check_task_calltrace(struct task_struct *t,
				bool (*fn)(void *, int *, unsigned long),
				void *data)
{
	int ret = 0;
	static unsigned long trace_entries[MAX_STACK_ENTRIES];
#ifdef CONFIG_ARCH_STACKWALK
	int trace_len;
#else
	struct stack_trace trace;
#endif

#ifdef CONFIG_ARCH_STACKWALK
	ret = stack_trace_save_tsk_reliable(t, trace_entries, MAX_STACK_ENTRIES);
	if (ret < 0) {
		pr_err("%s:%d has an unreliable stack, ret=%d\n",
		       t->comm, t->pid, ret);
		return ret;
	}
	trace_len = ret;
	ret = klp_check_stack(trace_entries, trace_len, fn, data);
#else
	trace.skip = 0;
	trace.nr_entries = 0;
	trace.max_entries = MAX_STACK_ENTRIES;
	trace.entries = trace_entries;
	ret = save_stack_trace_tsk_reliable(t, &trace);
	if (ret) {
		pr_err("%s: %s:%d has an unreliable stack, ret=%d\n",
		       __func__, t->comm, t->pid, ret);
		return ret;
	}
	ret = klp_check_stack(&trace, 0, fn, data);
#endif
	if (ret) {
		pr_err("%s:%d check stack failed, ret=%d\n",
		       t->comm, t->pid, ret);
		return ret;
	}
	return 0;
}

static int do_check_calltrace(bool (*fn)(void *, int *, unsigned long), void *data)
{
	int ret = 0;
	struct task_struct *g, *t;

	for_each_process_thread(g, t) {
		if (klp_is_migration_thread(t->comm))
			continue;

		ret = check_task_calltrace(t, fn, data);
		if (ret)
			return ret;
	}

	return 0;
}

static bool check_module_calltrace(void *data, int *ret, unsigned long pc)
{
	struct module *mod = (struct module *)data;

	if (within_module_core(pc, mod)) {
		pr_err("module %s is in use!\n", mod->name);
		*ret = -EBUSY;
		return false;
	}
	return true;
}

#ifdef CONFIG_LIVEPATCH_BREAKPOINT_NO_STOP_MACHINE
int arch_klp_check_task_calltrace(struct task_struct *t,
				  bool (*fn)(void *, int *, unsigned long),
				  void *data)
{
	if (t == NULL)
		return -EINVAL;
	return check_task_calltrace(t, fn, data);
}
#endif

int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data)
{
	return do_check_calltrace(check_func, data);
}

int arch_klp_module_check_calltrace(void *data)
{
	return do_check_calltrace(check_module_calltrace, data);
}

int arch_klp_check_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	int ret;
	unsigned char opcode;

	ret = copy_from_kernel_nofault(&opcode, old_func, INT3_INSN_SIZE);
	if (ret)
		return ret;

	/* Another subsystem puts a breakpoint, reject patching at this time */
	if (opcode == INT3_INSN_OPCODE)
		return -EBUSY;

	return 0;
}

int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	unsigned char int3 = INT3_INSN_OPCODE;
	int ret;

	ret = copy_from_kernel_nofault(&arch_data->saved_opcode, old_func,
				       INT3_INSN_SIZE);
	if (ret)
		return ret;

	text_poke(old_func, &int3, INT3_INSN_SIZE);
	/* arch_klp_code_modify_post_process() will do text_poke_sync() */

	return 0;
}

void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func)
{
	unsigned char opcode;
	int ret;

	ret = copy_from_kernel_nofault(&opcode, old_func, INT3_INSN_SIZE);
	if (ret) {
		pr_warn("%s: failed to read opcode, ret=%d\n", __func__, ret);
		return;
	}

	/* instruction have been recovered at arch_klp_unpatch_func() */
	if (opcode != INT3_INSN_OPCODE)
		return;

	text_poke(old_func, &arch_data->saved_opcode, INT3_INSN_SIZE);
	/* arch_klp_code_modify_post_process() will do text_poke_sync() */
}

int klp_int3_handler(struct pt_regs *regs)
{
	unsigned long addr = regs->ip - INT3_INSN_SIZE;
	void *brk_func;

	if (user_mode(regs))
		return 0;

	brk_func = klp_get_brk_func((void *)addr);
	if (!brk_func)
		return 0;

	int3_emulate_jmp(regs, (unsigned long)brk_func);
	return 1;
}
NOKPROBE_SYMBOL(klp_int3_handler);
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
	long ret;

	/* Prevent text modification */
	mutex_lock(&text_mutex);
	ret = copy_from_kernel_nofault(arch_data->old_insns,
			old_func, JMP_E9_INSN_SIZE);
	mutex_unlock(&text_mutex);

	return ret;
}

static void klp_patch_text(void *dst, const void *src, int len)
{
	if (len <= 1)
		return;
	/* skip breakpoint at first */
	text_poke(dst + 1, src + 1, len - 1);
	/*
	 * Avoid compile optimization, make sure that instructions
	 * except first breakpoint has been patched.
	 */
	barrier();
	/* update jmp opcode */
	text_poke(dst, src, 1);
}

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long ip, new_addr;
	unsigned char *new;

	func_node = func->func_node;
	ip = (unsigned long)func->old_func;
	list_add_rcu(&func->stack_node, &func_node->func_stack);
	new_addr = (unsigned long)func->new_func;
	/* replace the text with the new text */
	new = (unsigned char *)klp_jmp_code(ip, new_addr);
	klp_patch_text((void *)ip, (const void *)new, JMP_E9_INSN_SIZE);
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
		new = func_node->arch_data.old_insns;
	} else {
		next_func = list_first_or_null_rcu(&func_node->func_stack,
						struct klp_func, stack_node);

		new_addr = (unsigned long)next_func->new_func;
		new = klp_jmp_code(ip, new_addr);
	}

	/* replace the text with the new text */
	klp_patch_text((void *)ip, (const void *)new, JMP_E9_INSN_SIZE);
}
#endif
