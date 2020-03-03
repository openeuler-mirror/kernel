/*
 * core.c - Kernel Live Patching Core
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2014 SUSE
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
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kallsyms.h>
#include <linux/livepatch.h>
#include <linux/elf.h>
#include <linux/moduleloader.h>
#include <linux/completion.h>
#include <linux/memory.h>
#include <asm/cacheflush.h>
#include "core.h"
#include "patch.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#ifdef CONFIG_LIVEPATCH_RESTRICT_KPROBE
#include <linux/kprobes.h>
#endif

#if defined(CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY)
#include "transition.h"
#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)
#include <linux/stop_machine.h>
#endif

/*
 * klp_mutex is a coarse lock which serializes access to klp data.  All
 * accesses to klp-related variables and structures must have mutex protection,
 * except within the following functions which carefully avoid the need for it:
 *
 * - klp_ftrace_handler()
 * - klp_update_patch_state()
 */
DEFINE_MUTEX(klp_mutex);

static LIST_HEAD(klp_patches);

static struct kobject *klp_root_kobj;

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
struct patch_data {
	struct klp_patch        *patch;
	atomic_t                cpu_count;
};
#endif

#ifdef CONFIG_LIVEPATCH_RESTRICT_KPROBE
/*
 * Check whether a function has been registered with kprobes before patched.
 * We can't patched this function util we unregisted the kprobes.
 */
struct kprobe *klp_check_patch_kprobed(struct klp_patch *patch)
{
	struct klp_object *obj;
	struct klp_func *func;
	struct kprobe *kp;
	int i;

	klp_for_each_object(patch, obj) {
		klp_for_each_func(obj, func) {
			for (i = 0; i < func->old_size; i++) {
				kp = get_kprobe((void *)func->old_addr + i);
				if (kp) {
					pr_err("func %s has been probed, (un)patch failed\n",
						func->old_name);
					return kp;
				}
			}
		}
	}

	return NULL;
}
#else
static inline struct kprobe *klp_check_patch_kprobed(struct klp_patch *patch)
{
	return NULL;
}
#endif /* CONFIG_LIVEPATCH_RESTRICT_KPROBE */

static bool klp_is_module(struct klp_object *obj)
{
	return obj->name;
}

/* sets obj->mod if object is not vmlinux and module is found */
static int klp_find_object_module(struct klp_object *obj)
{
	struct module *mod;

	if (!klp_is_module(obj))
		return 0;

	mutex_lock(&module_mutex);
	/*
	 * We do not want to block removal of patched modules and therefore
	 * we do not take a reference here. The patches are removed by
	 * klp_module_going() instead.
	 */
	mod = find_module(obj->name);
	/*
	 * Do not mess work of klp_module_coming() and klp_module_going().
	 * Note that the patch might still be needed before klp_module_going()
	 * is called. Module functions can be called even in the GOING state
	 * until mod->exit() finishes. This is especially important for
	 * patches that modify semantic of the functions.
	 */
#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
	if (mod && mod->klp_alive)
		obj->mod = mod;
#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)
	if (!mod) {
		pr_err("module '%s' not loaded\n", obj->name);
		mutex_unlock(&module_mutex);
		return -ENOPKG; /* the deponds module is not loaded */
	} else if (mod->state == MODULE_STATE_COMING || !try_module_get(mod)) {
		mutex_unlock(&module_mutex);
		return -EINVAL;
	} else {
		obj->mod = mod;
	}
#endif /* ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */

	mutex_unlock(&module_mutex);
	return 0;
}

static bool klp_is_patch_registered(struct klp_patch *patch)
{
	struct klp_patch *mypatch;

	list_for_each_entry(mypatch, &klp_patches, list)
		if (mypatch == patch)
			return true;

	return false;
}

static bool klp_initialized(void)
{
	return !!klp_root_kobj;
}

struct klp_find_arg {
	const char *objname;
	const char *name;
	unsigned long addr;
	unsigned long count;
	unsigned long pos;
};

static int klp_find_callback(void *data, const char *name,
			     struct module *mod, unsigned long addr)
{
	struct klp_find_arg *args = data;

	if ((mod && !args->objname) || (!mod && args->objname))
		return 0;

	if (strcmp(args->name, name))
		return 0;

	if (args->objname && strcmp(args->objname, mod->name))
		return 0;

	args->addr = addr;
	args->count++;

	/*
	 * Finish the search when the symbol is found for the desired position
	 * or the position is not defined for a non-unique symbol.
	 */
	if ((args->pos && (args->count == args->pos)) ||
	    (!args->pos && (args->count > 1)))
		return 1;

	return 0;
}

static int klp_find_object_symbol(const char *objname, const char *name,
				  unsigned long sympos, unsigned long *addr)
{
	struct klp_find_arg args = {
		.objname = objname,
		.name = name,
		.addr = 0,
		.count = 0,
		.pos = sympos,
	};

	mutex_lock(&module_mutex);
	if (objname)
		module_kallsyms_on_each_symbol(klp_find_callback, &args);
	else
		kallsyms_on_each_symbol(klp_find_callback, &args);
	mutex_unlock(&module_mutex);

	cond_resched();

	/*
	 * Ensure an address was found. If sympos is 0, ensure symbol is unique;
	 * otherwise ensure the symbol position count matches sympos.
	 */
	if (args.addr == 0)
		pr_err("symbol '%s' not found in symbol table\n", name);
	else if (args.count > 1 && sympos == 0) {
		pr_err("unresolvable ambiguity for symbol '%s' in object '%s'\n",
		       name, objname);
	} else if (sympos != args.count && sympos > 0) {
		pr_err("symbol position %lu for symbol '%s' in object '%s' not found\n",
		       sympos, name, objname ? objname : "vmlinux");
	} else {
		*addr = args.addr;
		return 0;
	}

	*addr = 0;
	return -EINVAL;
}

static int klp_resolve_symbols(Elf_Shdr *relasec, struct module *pmod)
{
	int i, cnt, vmlinux, ret;
	char objname[MODULE_NAME_LEN];
	char symname[KSYM_NAME_LEN];
	char *strtab = pmod->core_kallsyms.strtab;
	Elf_Rela *relas;
	Elf_Sym *sym;
	unsigned long sympos, addr;

	/*
	 * Since the field widths for objname and symname in the sscanf()
	 * call are hard-coded and correspond to MODULE_NAME_LEN and
	 * KSYM_NAME_LEN respectively, we must make sure that MODULE_NAME_LEN
	 * and KSYM_NAME_LEN have the values we expect them to have.
	 *
	 * Because the value of MODULE_NAME_LEN can differ among architectures,
	 * we use the smallest/strictest upper bound possible (56, based on
	 * the current definition of MODULE_NAME_LEN) to prevent overflows.
	 */
	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);

	relas = (Elf_Rela *) relasec->sh_addr;
	/* For each rela in this klp relocation section */
	for (i = 0; i < relasec->sh_size / sizeof(Elf_Rela); i++) {
		sym = pmod->core_kallsyms.symtab + ELF_R_SYM(relas[i].r_info);
		if (sym->st_shndx != SHN_LIVEPATCH) {
			pr_err("symbol %s is not marked as a livepatch symbol\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		/* Format: .klp.sym.objname.symname,sympos */
		cnt = sscanf(strtab + sym->st_name,
			     ".klp.sym.%55[^.].%127[^,],%lu",
			     objname, symname, &sympos);
		if (cnt != 3) {
			pr_err("symbol %s has an incorrectly formatted name\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		/* klp_find_object_symbol() treats a NULL objname as vmlinux */
		vmlinux = !strcmp(objname, "vmlinux");
		ret = klp_find_object_symbol(vmlinux ? NULL : objname,
					     symname, sympos, &addr);
		if (ret)
			return ret;

		sym->st_value = addr;
	}

	return 0;
}

static int klp_write_object_relocations(struct module *pmod,
					struct klp_object *obj)
{
	int i, cnt, ret = 0;
	const char *objname, *secname;
	char sec_objname[MODULE_NAME_LEN];
	Elf_Shdr *sec;

	if (WARN_ON(!klp_is_object_loaded(obj)))
		return -EINVAL;

	objname = klp_is_module(obj) ? obj->name : "vmlinux";

	/* For each klp relocation section */
	for (i = 1; i < pmod->klp_info->hdr.e_shnum; i++) {
		sec = pmod->klp_info->sechdrs + i;
		secname = pmod->klp_info->secstrings + sec->sh_name;
		if (!(sec->sh_flags & SHF_RELA_LIVEPATCH))
			continue;

		/*
		 * Format: .klp.rela.sec_objname.section_name
		 * See comment in klp_resolve_symbols() for an explanation
		 * of the selected field width value.
		 */
		cnt = sscanf(secname, ".klp.rela.%55[^.]", sec_objname);
		if (cnt != 1) {
			pr_err("section %s has an incorrectly formatted name\n",
			       secname);
			ret = -EINVAL;
			break;
		}

		if (strcmp(objname, sec_objname))
			continue;

		ret = klp_resolve_symbols(sec, pmod);
		if (ret)
			break;

		ret = apply_relocate_add(pmod->klp_info->sechdrs,
					 pmod->core_kallsyms.strtab,
					 pmod->klp_info->symndx, i, pmod);
		if (ret)
			break;
	}

	return ret;
}

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
static int __klp_disable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;

	if (WARN_ON(!patch->enabled))
		return -EINVAL;

	if (klp_transition_patch)
		return -EBUSY;

#ifdef CONFIG_LIVEPATCH_STACK
	/* enforce stacking: only the last enabled patch can be disabled */
	if (!list_is_last(&patch->list, &klp_patches) &&
	    list_next_entry(patch, list)->enabled)
		return -EBUSY;
#endif

	klp_init_transition(patch, KLP_UNPATCHED);

	klp_for_each_object(patch, obj)
		if (obj->patched)
			klp_pre_unpatch_callback(obj);

	/*
	 * Enforce the order of the func->transition writes in
	 * klp_init_transition() and the TIF_PATCH_PENDING writes in
	 * klp_start_transition().  In the rare case where klp_ftrace_handler()
	 * is called shortly after klp_update_patch_state() switches the task,
	 * this ensures the handler sees that func->transition is set.
	 */
	smp_wmb();

	klp_start_transition();
	klp_try_complete_transition();
	patch->enabled = false;

	return 0;
}
#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)
/*
 * This function is called from stop_machine() context.
 */
static int disable_patch(struct klp_patch *patch)
{
	pr_notice("disabling patch '%s'\n", patch->mod->name);

	klp_unpatch_objects(patch);
	patch->enabled = false;
	module_put(patch->mod);
	return 0;
}

int klp_try_disable_patch(void *data)
{
	int ret = 0;
	int flag = 0;
	struct patch_data *pd = (struct patch_data *)data;

	if (atomic_inc_return(&pd->cpu_count) == 1) {
		struct klp_patch *patch = pd->patch;

		if (klp_check_patch_kprobed(patch)) {
			flag = 1;
			atomic_inc(&pd->cpu_count);
			return -EINVAL;
		}

		ret = klp_check_calltrace(patch, 0);
		if (ret) {
			flag = 1;
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		ret = disable_patch(patch);
		if (ret) {
			flag = 1;
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		atomic_inc(&pd->cpu_count);
	} else {
		while (atomic_read(&pd->cpu_count) <= num_online_cpus())
			cpu_relax();

		if (!flag)
			klp_smp_isb();
	}

	return ret;
}

void __weak arch_klp_code_modify_prepare(void)
{
}

void __weak arch_klp_code_modify_post_process(void)
{
}


static int __klp_disable_patch(struct klp_patch *patch)
{
	int ret;
	struct patch_data patch_data = {
		.patch = patch,
		.cpu_count = ATOMIC_INIT(0),
	};

	if (WARN_ON(!patch->enabled))
		return -EINVAL;

#ifdef CONFIG_LIVEPATCH_STACK
	/* enforce stacking: only the last enabled patch can be disabled */
	if (!list_is_last(&patch->list, &klp_patches) &&
	    list_next_entry(patch, list)->enabled) {
		pr_err("only the last enabled patch can be disabled\n");
		return -EBUSY;
	}
#endif

	arch_klp_code_modify_prepare();
	ret = stop_machine(klp_try_disable_patch, &patch_data, cpu_online_mask);
	arch_klp_code_modify_post_process();

	return ret;
}
#endif /* if defined(CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY) */


/**
 * klp_disable_patch() - disables a registered patch
 * @patch:	The registered, enabled patch to be disabled
 *
 * Unregisters the patched functions from ftrace.
 *
 * Return: 0 on success, otherwise error
 */
int klp_disable_patch(struct klp_patch *patch)
{
	int ret;

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		ret = -EINVAL;
		goto err;
	}

	if (!patch->enabled) {
		ret = -EINVAL;
		goto err;
	}

	ret = __klp_disable_patch(patch);

err:
	mutex_unlock(&klp_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(klp_disable_patch);

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
static int __klp_enable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	if (klp_transition_patch)
		return -EBUSY;

	if (WARN_ON(patch->enabled))
		return -EINVAL;

#ifdef CONFIG_LIVEPATCH_STACK
	/* enforce stacking: only the first disabled patch can be enabled */
	if (patch->list.prev != &klp_patches &&
	    !list_prev_entry(patch, list)->enabled)
		return -EBUSY;
#endif

	/*
	 * A reference is taken on the patch module to prevent it from being
	 * unloaded.
	 */
	if (!try_module_get(patch->mod))
		return -ENODEV;

	pr_notice("enabling patch '%s'\n", patch->mod->name);

	klp_init_transition(patch, KLP_PATCHED);

	/*
	 * Enforce the order of the func->transition writes in
	 * klp_init_transition() and the ops->func_stack writes in
	 * klp_patch_object(), so that klp_ftrace_handler() will see the
	 * func->transition updates before the handler is registered and the
	 * new funcs become visible to the handler.
	 */
	smp_wmb();

	klp_for_each_object(patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;

		ret = klp_pre_patch_callback(obj);
		if (ret) {
			pr_warn("pre-patch callback failed for object '%s'\n",
				klp_is_module(obj) ? obj->name : "vmlinux");
			goto err;
		}

		ret = klp_patch_object(obj);
		if (ret) {
			pr_warn("failed to patch object '%s'\n",
				klp_is_module(obj) ? obj->name : "vmlinux");
			goto err;
		}
	}

	klp_start_transition();
	klp_try_complete_transition();
	patch->enabled = true;

	return 0;
err:
	pr_warn("failed to enable patch '%s'\n", patch->mod->name);

	klp_cancel_transition();
	return ret;
}
#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)
/*
 * This function is called from stop_machine() context.
 */
static int enable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	pr_notice_once("tainting kernel with TAINT_LIVEPATCH\n");
	add_taint(TAINT_LIVEPATCH, LOCKDEP_STILL_OK);

	if (!try_module_get(patch->mod))
		return -ENODEV;
	patch->enabled = true;

	pr_notice("enabling patch '%s'\n", patch->mod->name);

	klp_for_each_object(patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;

		ret = klp_patch_object(obj);
		if (ret) {
			pr_warn("failed to patch object '%s'\n",
				klp_is_module(obj) ? obj->name : "vmlinux");
			goto disable;
		}
	}

	return 0;

disable:
	disable_patch(patch);
	return ret;
}

int klp_try_enable_patch(void *data)
{
	int ret = 0;
	int flag = 0;
	struct patch_data *pd = (struct patch_data *)data;

	if (atomic_inc_return(&pd->cpu_count) == 1) {
		struct klp_patch *patch = pd->patch;

		if (klp_check_patch_kprobed(patch)) {
			flag = 1;
			atomic_inc(&pd->cpu_count);
			return -EINVAL;
		}

		ret = klp_check_calltrace(patch, 1);
		if (ret) {
			flag = 1;
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		ret = enable_patch(patch);
		if (ret) {
			flag = 1;
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		atomic_inc(&pd->cpu_count);
	} else {
		while (atomic_read(&pd->cpu_count) <= num_online_cpus())
			cpu_relax();

		if (!flag)
			klp_smp_isb();
	}

	return ret;
}

static int __klp_enable_patch(struct klp_patch *patch)
{
	int ret;
	struct patch_data patch_data = {
		.patch = patch,
		.cpu_count = ATOMIC_INIT(0),
	};

	if (WARN_ON(patch->enabled))
		return -EINVAL;

#ifdef CONFIG_LIVEPATCH_STACK
	/* enforce stacking: only the first disabled patch can be enabled */
	if (patch->list.prev != &klp_patches &&
	    !list_prev_entry(patch, list)->enabled) {
		pr_err("only the first disabled patch can be enabled\n");
		return -EBUSY;
	}
#endif

	arch_klp_code_modify_prepare();
	ret = stop_machine(klp_try_enable_patch, &patch_data, cpu_online_mask);
	arch_klp_code_modify_prepare();
	if (ret)
		return ret;

#ifndef CONFIG_LIVEPATCH_STACK
	/* move the enabled patch to the list tail */
	list_del(&patch->list);
	list_add_tail(&patch->list, &klp_patches);
#endif

	return 0;
}
#endif /* #ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY */

/**
 * klp_enable_patch() - enables a registered patch
 * @patch:	The registered, disabled patch to be enabled
 *
 * Performs the needed symbol lookups and code relocations,
 * then registers the patched functions with ftrace.
 *
 * Return: 0 on success, otherwise error
 */
int klp_enable_patch(struct klp_patch *patch)
{
	int ret;

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		ret = -EINVAL;
		goto err;
	}

	ret = __klp_enable_patch(patch);

err:
	mutex_unlock(&klp_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(klp_enable_patch);

/*
 * Sysfs Interface
 *
 * /sys/kernel/livepatch
 * /sys/kernel/livepatch/<patch>
 * /sys/kernel/livepatch/<patch>/enabled
 * /sys/kernel/livepatch/<patch>/transition
 * /sys/kernel/livepatch/<patch>/signal
 * /sys/kernel/livepatch/<patch>/force
 * /sys/kernel/livepatch/<patch>/<object>
 * /sys/kernel/livepatch/<patch>/<object>/<function,sympos>
 */

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool enabled;

	ret = kstrtobool(buf, &enabled);
	if (ret)
		return ret;

	patch = container_of(kobj, struct klp_patch, kobj);

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		/*
		 * Module with the patch could either disappear meanwhile or is
		 * not properly initialized yet.
		 */
		ret = -EINVAL;
		goto err;
	}

	if (patch->enabled == enabled) {
		/* already in requested state */
		ret = -EINVAL;
		goto err;
	}

#if defined(CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY)
	if (patch == klp_transition_patch) {
		klp_reverse_transition();
	} else if (enabled) {
		ret = __klp_enable_patch(patch);
		if (ret)
			goto err;
	} else {
		ret = __klp_disable_patch(patch);
		if (ret)
			goto err;
	}
#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)
	if (enabled) {
		ret = __klp_enable_patch(patch);
		if (ret)
			goto err;
	} else {
		ret = __klp_disable_patch(patch);
		if (ret)
			goto err;
	}
#endif

	mutex_unlock(&klp_mutex);

	return count;

err:
	mutex_unlock(&klp_mutex);
	return ret;
}

static ssize_t enabled_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	return snprintf(buf, PAGE_SIZE-1, "%d\n", patch->enabled);
}

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
static ssize_t transition_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	return snprintf(buf, PAGE_SIZE-1, "%d\n",
			patch == klp_transition_patch);
}

static ssize_t signal_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool val;

	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	if (!val)
		return count;

	mutex_lock(&klp_mutex);

	patch = container_of(kobj, struct klp_patch, kobj);
	if (patch != klp_transition_patch) {
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	klp_send_signals();

	mutex_unlock(&klp_mutex);

	return count;
}

static ssize_t force_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool val;

	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	if (!val)
		return count;

	mutex_lock(&klp_mutex);

	patch = container_of(kobj, struct klp_patch, kobj);
	if (patch != klp_transition_patch) {
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	klp_force_transition();

	mutex_unlock(&klp_mutex);

	return count;
}
#endif /* #ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */

static struct kobj_attribute enabled_kobj_attr = __ATTR_RW(enabled);
#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
static struct kobj_attribute transition_kobj_attr = __ATTR_RO(transition);
static struct kobj_attribute signal_kobj_attr = __ATTR_WO(signal);
static struct kobj_attribute force_kobj_attr = __ATTR_WO(force);
#endif /* #ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */

static struct attribute *klp_patch_attrs[] = {
	&enabled_kobj_attr.attr,
#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
	&transition_kobj_attr.attr,
	&signal_kobj_attr.attr,
	&force_kobj_attr.attr,
#endif /* #ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */
	NULL
};

static int state_show(struct seq_file *m, void *v)
{
	struct klp_patch *patch;
	char *state;
	int index = 0;

	seq_printf(m, "%-5s\t%-26s\t%-8s\n", "Index", "Patch", "State");
	seq_puts(m, "-----------------------------------------------\n");
	mutex_lock(&klp_mutex);
	list_for_each_entry(patch, &klp_patches, list) {
		if (patch->enabled)
			state = "enabled";
		else
			state = "disabled";

		seq_printf(m, "%-5d\t%-26s\t%-8s\n", ++index,
				patch->mod->name, state);
	}
	mutex_unlock(&klp_mutex);
	seq_puts(m, "-----------------------------------------------\n");

	return 0;
}

static int klp_state_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, state_show, NULL);
}

static const struct file_operations proc_klpstate_operations = {
	.open		= klp_state_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void klp_kobj_release_patch(struct kobject *kobj)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	complete(&patch->finish);
}

static struct kobj_type klp_ktype_patch = {
	.release = klp_kobj_release_patch,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_attrs = klp_patch_attrs,
};

static void klp_kobj_release_object(struct kobject *kobj)
{
}

static struct kobj_type klp_ktype_object = {
	.release = klp_kobj_release_object,
	.sysfs_ops = &kobj_sysfs_ops,
};

static void klp_kobj_release_func(struct kobject *kobj)
{
}

static struct kobj_type klp_ktype_func = {
	.release = klp_kobj_release_func,
	.sysfs_ops = &kobj_sysfs_ops,
};

/*
 * Free all functions' kobjects in the array up to some limit. When limit is
 * NULL, all kobjects are freed.
 */
static void klp_free_funcs_limited(struct klp_object *obj,
				   struct klp_func *limit)
{
	struct klp_func *func;

	for (func = obj->funcs; func->old_name && func != limit; func++)
		kobject_put(&func->kobj);
}

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
/* Clean up when a patched object is unloaded */
static void klp_free_object_loaded(struct klp_object *obj)
{
	struct klp_func *func;

	obj->mod = NULL;

	klp_for_each_func(obj, func)
		func->old_addr = 0;
}
#endif /* #ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */

/*
 * Free all objects' kobjects in the array up to some limit. When limit is
 * NULL, all kobjects are freed.
 */
static void klp_free_objects_limited(struct klp_patch *patch,
				     struct klp_object *limit)
{
	struct klp_object *obj;

	for (obj = patch->objs; obj->funcs && obj != limit; obj++) {
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
		if (klp_is_module(obj))
			module_put(obj->mod);
#endif
		klp_free_funcs_limited(obj, NULL);
		kobject_put(&obj->kobj);
	}
}

static void klp_free_patch(struct klp_patch *patch)
{
	klp_free_objects_limited(patch, NULL);
	if (!list_empty(&patch->list))
		list_del(&patch->list);
}

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
int __weak arch_klp_func_can_patch(struct klp_func *func)
{
	return 0;
}
#endif

static int klp_init_func(struct klp_object *obj, struct klp_func *func)
{
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	int ret;
#endif

	if (!func->old_name || !func->new_func)
		return -EINVAL;

	if (strlen(func->old_name) >= KSYM_NAME_LEN)
		return -EINVAL;

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	ret = arch_klp_func_can_patch(func);
	if (ret)
		return ret;
#endif

	INIT_LIST_HEAD(&func->stack_node);
	func->patched = false;
#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
	func->transition = false;
#endif

	/* The format for the sysfs directory is <function,sympos> where sympos
	 * is the nth occurrence of this symbol in kallsyms for the patched
	 * object. If the user selects 0 for old_sympos, then 1 will be used
	 * since a unique symbol will be the first occurrence.
	 */
	return kobject_init_and_add(&func->kobj, &klp_ktype_func,
				    &obj->kobj, "%s,%lu", func->old_name,
				    func->old_sympos ? func->old_sympos : 1);
}

/* Arches may override this to finish any remaining arch-specific tasks */
void __weak arch_klp_init_object_loaded(struct klp_patch *patch,
					struct klp_object *obj)
{
}

/* parts of the initialization that is done only when the object is loaded */
static int klp_init_object_loaded(struct klp_patch *patch,
				  struct klp_object *obj)
{
	struct klp_func *func;
	int ret;

	mutex_lock(&text_mutex);

	module_disable_ro(patch->mod);
	ret = klp_write_object_relocations(patch->mod, obj);
	if (ret) {
		module_enable_ro(patch->mod, true);
		mutex_unlock(&text_mutex);
		return ret;
	}

	arch_klp_init_object_loaded(patch, obj);
	module_enable_ro(patch->mod, true);

	mutex_unlock(&text_mutex);

	klp_for_each_func(obj, func) {
		ret = klp_find_object_symbol(obj->name, func->old_name,
					     func->old_sympos,
					     &func->old_addr);
		if (ret)
			return ret;

		ret = kallsyms_lookup_size_offset(func->old_addr,
						  &func->old_size, NULL);
		if (!ret) {
			pr_err("kallsyms size lookup failed for '%s'\n",
			       func->old_name);
			return -ENOENT;
		}

		ret = kallsyms_lookup_size_offset((unsigned long)func->new_func,
						  &func->new_size, NULL);
		if (!ret) {
			pr_err("kallsyms size lookup failed for '%s' replacement\n",
			       func->old_name);
			return -ENOENT;
		}
	}

	return 0;
}

static int klp_init_object(struct klp_patch *patch, struct klp_object *obj)
{
	struct klp_func *func;
	int ret;
	const char *name;

	if (!obj->funcs)
		return -EINVAL;

	if (klp_is_module(obj) && strlen(obj->name) >= MODULE_NAME_LEN)
		return -EINVAL;

	obj->patched = false;
	obj->mod = NULL;

	ret = klp_find_object_module(obj);
	if (ret)
		return ret;

	name = klp_is_module(obj) ? obj->name : "vmlinux";
	ret = kobject_init_and_add(&obj->kobj, &klp_ktype_object,
				   &patch->kobj, "%s", name);
	if (ret)
		goto put;

	if (klp_is_object_loaded(obj)) {
		ret = klp_init_object_loaded(patch, obj);
		if (ret)
			goto out;
	}

	klp_for_each_func(obj, func) {
		ret = klp_init_func(obj, func);
		if (ret)
			goto free;
	}


	return 0;

free:
	klp_free_funcs_limited(obj, func);
out:
	kobject_put(&obj->kobj);
put:
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
	module_put(obj->mod);
#endif
	return ret;
}

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
static inline int klp_load_hook(struct klp_object *obj)
{
	struct klp_hook *hook;

	if (!obj->hooks_load)
		return 0;

	for (hook = obj->hooks_load; hook->hook; hook++)
		(*hook->hook)();

	return 0;
}

static inline int klp_unload_hook(struct klp_object *obj)
{
	struct klp_hook *hook;

	if (!obj->hooks_unload)
		return 0;

	for (hook = obj->hooks_unload; hook->hook; hook++)
		(*hook->hook)();

	return 0;
}
#endif

static int klp_init_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	if (!patch->objs)
		return -EINVAL;

	mutex_lock(&klp_mutex);

	if (klp_is_patch_registered(patch)) {
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	patch->enabled = false;
	init_completion(&patch->finish);

	ret = kobject_init_and_add(&patch->kobj, &klp_ktype_patch,
				   klp_root_kobj, "%s", patch->mod->name);
	if (ret) {
		mutex_unlock(&klp_mutex);
		return ret;
	}

	klp_for_each_object(patch, obj) {
		ret = klp_init_object(patch, obj);
		if (ret)
			goto free;
	}

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	klp_for_each_object(patch, obj)
		klp_load_hook(obj);
#endif

	list_add_tail(&patch->list, &klp_patches);

	mutex_unlock(&klp_mutex);

	return 0;

free:
	klp_free_objects_limited(patch, obj);

	mutex_unlock(&klp_mutex);

	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	return ret;
}

/**
 * klp_unregister_patch() - unregisters a patch
 * @patch:	Disabled patch to be unregistered
 *
 * Frees the data structures and removes the sysfs interface.
 *
 * Return: 0 on success, otherwise error
 */
int klp_unregister_patch(struct klp_patch *patch)
{
	int ret;
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	struct klp_object *obj;
#endif

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		ret = -EINVAL;
		goto err;
	}

	if (patch->enabled) {
		ret = -EBUSY;
		goto err;
	}

	klp_free_patch(patch);

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	klp_for_each_object(patch, obj)
		klp_unload_hook(obj);
#endif

	mutex_unlock(&klp_mutex);

	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	return 0;
err:
	mutex_unlock(&klp_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(klp_unregister_patch);

/**
 * klp_register_patch() - registers a patch
 * @patch:	Patch to be registered
 *
 * Initializes the data structure associated with the patch and
 * creates the sysfs interface.
 *
 * There is no need to take the reference on the patch module here. It is done
 * later when the patch is enabled.
 *
 * Return: 0 on success, otherwise error
 */
int klp_register_patch(struct klp_patch *patch)
{
	if (!patch || !patch->mod)
		return -EINVAL;

	if (!is_livepatch_module(patch->mod)) {
		pr_err("module %s is not marked as a livepatch module\n",
		       patch->mod->name);
		return -EINVAL;
	}

	if (!klp_initialized())
		return -ENODEV;

	if (!klp_have_reliable_stack()) {
		pr_err("This architecture doesn't have support for the livepatch consistency model.\n");
		return -ENOSYS;
	}

	return klp_init_patch(patch);
}
EXPORT_SYMBOL_GPL(klp_register_patch);

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
/*
 * Remove parts of patches that touch a given kernel module. The list of
 * patches processed might be limited. When limit is NULL, all patches
 * will be handled.
 */
static void klp_cleanup_module_patches_limited(struct module *mod,
					       struct klp_patch *limit)
{
	struct klp_patch *patch;
	struct klp_object *obj;

	list_for_each_entry(patch, &klp_patches, list) {
		if (patch == limit)
			break;

		klp_for_each_object(patch, obj) {
			if (!klp_is_module(obj) || strcmp(obj->name, mod->name))
				continue;

			/*
			 * Only unpatch the module if the patch is enabled or
			 * is in transition.
			 */
			if (patch->enabled || patch == klp_transition_patch) {

				if (patch != klp_transition_patch)
					klp_pre_unpatch_callback(obj);

				pr_notice("reverting patch '%s' on unloading module '%s'\n",
					  patch->mod->name, obj->mod->name);
				klp_unpatch_object(obj);

				klp_post_unpatch_callback(obj);
			}

			klp_free_object_loaded(obj);
			break;
		}
	}
}

int klp_module_coming(struct module *mod)
{
	int ret;
	struct klp_patch *patch;
	struct klp_object *obj;

	if (WARN_ON(mod->state != MODULE_STATE_COMING))
		return -EINVAL;

	mutex_lock(&klp_mutex);
	/*
	 * Each module has to know that klp_module_coming()
	 * has been called. We never know what module will
	 * get patched by a new patch.
	 */
	mod->klp_alive = true;

	list_for_each_entry(patch, &klp_patches, list) {
		klp_for_each_object(patch, obj) {
			if (!klp_is_module(obj) || strcmp(obj->name, mod->name))
				continue;

			obj->mod = mod;

			ret = klp_init_object_loaded(patch, obj);
			if (ret) {
				pr_warn("failed to initialize patch '%s' for module '%s' (%d)\n",
					patch->mod->name, obj->mod->name, ret);
				goto err;
			}

			/*
			 * Only patch the module if the patch is enabled or is
			 * in transition.
			 */
			if (!patch->enabled && patch != klp_transition_patch)
				break;

			pr_notice("applying patch '%s' to loading module '%s'\n",
				  patch->mod->name, obj->mod->name);

			ret = klp_pre_patch_callback(obj);
			if (ret) {
				pr_warn("pre-patch callback failed for object '%s'\n",
					obj->name);
				goto err;
			}

			ret = klp_patch_object(obj);
			if (ret) {
				pr_warn("failed to apply patch '%s' to module '%s' (%d)\n",
					patch->mod->name, obj->mod->name, ret);

				klp_post_unpatch_callback(obj);
				goto err;
			}

			if (patch != klp_transition_patch)
				klp_post_patch_callback(obj);

			break;
		}
	}

	mutex_unlock(&klp_mutex);

	return 0;

err:
	/*
	 * If a patch is unsuccessfully applied, return
	 * error to the module loader.
	 */
	pr_warn("patch '%s' failed for module '%s', refusing to load module '%s'\n",
		patch->mod->name, obj->mod->name, obj->mod->name);
	mod->klp_alive = false;
	obj->mod = NULL;
	klp_cleanup_module_patches_limited(mod, patch);
	mutex_unlock(&klp_mutex);

	return ret;
}

void klp_module_going(struct module *mod)
{
	if (WARN_ON(mod->state != MODULE_STATE_GOING &&
		    mod->state != MODULE_STATE_COMING))
		return;

	mutex_lock(&klp_mutex);
	/*
	 * Each module has to know that klp_module_going()
	 * has been called. We never know what module will
	 * get patched by a new patch.
	 */
	mod->klp_alive = false;

	klp_cleanup_module_patches_limited(mod, NULL);

	mutex_unlock(&klp_mutex);
}
#endif /* ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */

static int __init klp_init(void)
{
	int ret;
	struct proc_dir_entry *root_klp_dir, *res;

	ret = klp_check_compiler_support();
	if (ret) {
		pr_info("Your compiler is too old; turning off.\n");
		return -EINVAL;
	}

	root_klp_dir = proc_mkdir("livepatch", NULL);
	if (!root_klp_dir)
		goto error_out;

	res = proc_create("livepatch/state", 0, NULL,
			&proc_klpstate_operations);
	if (!res)
		goto error_remove;

	klp_root_kobj = kobject_create_and_add("livepatch", kernel_kobj);
	if (!klp_root_kobj)
		goto error_remove;

	return 0;

error_remove:
	remove_proc_entry("livepatch", NULL);
error_out:
	return -ENOMEM;
}

module_init(klp_init);
