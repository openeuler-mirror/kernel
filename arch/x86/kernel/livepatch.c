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
#include <asm/text-patching.h>
#include <asm/stacktrace.h>
#include <asm/set_memory.h>

/* Apply per-object alternatives. Based on x86 module_finalize() */
void arch_klp_init_object_loaded(struct klp_patch *patch,
				 struct klp_object *obj)
{
	int cnt;
	struct klp_modinfo *info;
	Elf_Shdr *s, *alt = NULL, *para = NULL;
	void *aseg, *pseg;
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
		if (!strcmp(".parainstructions", secname))
			para = s;
	}

	if (alt) {
		aseg = (void *) alt->sh_addr;
		apply_alternatives(aseg, aseg + alt->sh_size);
	}

	if (para) {
		pseg = (void *) para->sh_addr;
		apply_paravirt(pseg, pseg + para->sh_size);
	}
}


#ifdef	CONFIG_LIVEPATCH_WO_FTRACE
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
		struct stack_trace *trace, int enable)
{
	unsigned long func_addr, func_size, address;
	const char *func_name;
	int i;

	for (i = 0; i < trace->nr_entries; i++) {
		address = trace->entries[i];

		if (enable) {
			if (func->force)
				continue;
			func_addr = func->old_addr;
			func_size = func->old_size;
		} else {
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

static void klp_print_stack_trace(struct stack_trace *trace)
{
	int i;

	pr_err("Call Trace:\n");
	for (i = 0; i < trace->nr_entries; i++) {
		pr_err("[<%pK>] %pS\n",
		(void *)trace->entries[i],
		(void *)trace->entries[i]);
	}

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
	static unsigned long entries[MAX_STACK_ENTRIES];
	struct stack_trace trace;
	struct klp_object *obj;
	struct klp_func *func;
	int ret;

	trace.skip = 0;
	trace.nr_entries = 0;
	trace.max_entries = MAX_STACK_ENTRIES;
	trace.entries = entries;
	ret = save_stack_trace_tsk_reliable(task, &trace);
	WARN_ON_ONCE(ret == -ENOSYS);
	if (ret) {
		pr_info("%s: %s:%d has an unreliable stack\n",
			 __func__, task->comm, task->pid);
		return ret;
	}

	klp_for_each_object(patch, obj) {
		klp_for_each_func(obj, func) {
			ret = klp_check_stack_func(func, &trace, enable);
			if (ret) {
				pr_info("%s: %s:%d is sleeping on function %s\n",
				__func__, task->comm, task->pid,
				func->old_name);

				klp_print_stack_trace(&trace);

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

#include <linux/slab.h>
#include <asm/nops.h>
#include <asm/sections.h>

#define	JMP_E9_INSN_SIZE	5
union klp_code_union {
	char code[JMP_E9_INSN_SIZE];
	struct {
		unsigned char e9;
		int offset;
	} __packed;
};

struct klp_func_node {
	struct list_head node;
	struct list_head func_stack;
	unsigned long old_addr;
	unsigned char old_code[JMP_E9_INSN_SIZE];
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

int arch_klp_init_func(struct klp_object *obj, struct klp_func *func)
{
	return 0;
}

void arch_klp_free_func(struct klp_object *obj, struct klp_func *limit)
{

}

static int klp_calc_offset(long pc, long addr)
{
	return (int)(addr - pc);
}

static unsigned char *klp_jmp_code(unsigned long ip, unsigned long addr)
{
	static union klp_code_union calc;

	calc.e9 = 0xe9;
	calc.offset = klp_calc_offset(ip + JMP_E9_INSN_SIZE, addr);

	return calc.code;
}

static unsigned char *klp_old_code(unsigned char *code)
{
	static union klp_code_union old_code;

	strncpy(old_code.code, code, JMP_E9_INSN_SIZE);
	return old_code.code;
}

void arch_klp_code_modify_prepare(void)
{
	set_kernel_text_rw();
	set_all_modules_text_rw();
}

void arch_klp_code_modify_post_process(void)
{
	set_all_modules_text_ro();
	set_kernel_text_ro();
}

static inline int within(unsigned long addr, unsigned long start,
		unsigned long end)
{
	return addr >= start && addr < end;
}

static unsigned long text_ip_addr(unsigned long ip)
{
	if (within(ip, (unsigned long)_text, (unsigned long)_etext))
		ip = (unsigned long)__va(__pa_symbol(ip));

	return ip;
}

int arch_klp_patch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	unsigned long ip, new_addr;
	const unsigned char *new;

	func_node = klp_find_func_node(func->old_addr);
	ip = func->old_addr;
	if (!func_node) {
		func_node = kzalloc(sizeof(*func_node), GFP_ATOMIC);
		if (!func_node)
			return -ENOMEM;

		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_addr = func->old_addr;
		probe_kernel_read(func_node->old_code,
				(void *)ip, JMP_E9_INSN_SIZE);
		list_add_rcu(&func_node->node, &klp_func_list);
	}

	list_add_rcu(&func->stack_node, &func_node->func_stack);

	new_addr = (unsigned long)func->new_func;
	new = klp_jmp_code(ip, new_addr);

	ip = text_ip_addr(ip);
	if (probe_kernel_write((void *)ip, new, JMP_E9_INSN_SIZE))
		return -EPERM;

	sync_core();

	return 0;
}

void arch_klp_unpatch_func(struct klp_func *func)
{
	struct klp_func_node *func_node;
	struct klp_func *next_func;
	unsigned long ip, new_addr;
	const unsigned char *new;

	func_node = klp_find_func_node(func->old_addr);
	ip = func_node->old_addr;
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

	ip = text_ip_addr(ip);
	probe_kernel_write((void *)ip, new, JMP_E9_INSN_SIZE);
	sync_core();
}
#endif
