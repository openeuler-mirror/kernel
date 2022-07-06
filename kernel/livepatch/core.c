// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * core.c - Kernel Live Patching Core
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2014 SUSE
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
#include "state.h"
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

/*
 * Actively used patches: enabled or in transition. Note that replaced
 * or disabled patches are not listed even though the related kernel
 * module still can be loaded.
 */
LIST_HEAD(klp_patches);

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
 * We can't patched this function util we unregistered the kprobes.
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
				kp = get_kprobe(func->old_func + i);
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
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
	if (!mod) {
		pr_err("module '%s' not loaded\n", obj->name);
		mutex_unlock(&module_mutex);
		return -ENOPKG; /* the deponds module is not loaded */
	}

	if (mod->state == MODULE_STATE_COMING || !try_module_get(mod)) {
		mutex_unlock(&module_mutex);
		return -EINVAL;
	}

	obj->mod = mod;
#else
	if (mod && mod->klp_alive)
		obj->mod = mod;
#endif

	mutex_unlock(&module_mutex);
	return 0;
}

static bool klp_initialized(void)
{
	return !!klp_root_kobj;
}

static struct klp_func *klp_find_func(struct klp_object *obj,
				      struct klp_func *old_func)
{
	struct klp_func *func;

	klp_for_each_func(obj, func) {
		if ((strcmp(old_func->old_name, func->old_name) == 0) &&
		    (old_func->old_sympos == func->old_sympos)) {
			return func;
		}
	}

	return NULL;
}

static struct klp_object *klp_find_object(struct klp_patch *patch,
					  struct klp_object *old_obj)
{
	struct klp_object *obj;

	klp_for_each_object(patch, obj) {
		if (klp_is_module(old_obj)) {
			if (klp_is_module(obj) &&
			    strcmp(old_obj->name, obj->name) == 0) {
				return obj;
			}
		} else if (!klp_is_module(obj)) {
			return obj;
		}
	}

	return NULL;
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

static int klp_resolve_symbols(Elf_Shdr *sechdrs, const char *strtab,
			       unsigned int symndx, Elf_Shdr *relasec,
			       const char *sec_objname)
{
	int i, cnt, ret;
	char sym_objname[MODULE_NAME_LEN];
	char sym_name[KSYM_NAME_LEN];
#ifdef CONFIG_MODULES_USE_ELF_RELA
	Elf_Rela *relas;
#else
	Elf_Rel *relas;
#endif
	Elf_Sym *sym;
	unsigned long sympos, addr;
	bool sym_vmlinux;
	bool sec_vmlinux = !strcmp(sec_objname, "vmlinux");

	/*
	 * Since the field widths for sym_objname and sym_name in the sscanf()
	 * call are hard-coded and correspond to MODULE_NAME_LEN and
	 * KSYM_NAME_LEN respectively, we must make sure that MODULE_NAME_LEN
	 * and KSYM_NAME_LEN have the values we expect them to have.
	 *
	 * Because the value of MODULE_NAME_LEN can differ among architectures,
	 * we use the smallest/strictest upper bound possible (56, based on
	 * the current definition of MODULE_NAME_LEN) to prevent overflows.
	 */
	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);

#ifdef CONFIG_MODULES_USE_ELF_RELA
	relas = (Elf_Rela *) relasec->sh_addr;
#else
	relas = (Elf_Rel *) relasec->sh_addr;
#endif
	/* For each rela in this klp relocation section */
	for (i = 0; i < relasec->sh_size / sizeof(*relas); i++) {
		sym = (Elf_Sym *)sechdrs[symndx].sh_addr + ELF_R_SYM(relas[i].r_info);
		if (sym->st_shndx != SHN_LIVEPATCH) {
			pr_err("symbol %s is not marked as a livepatch symbol\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		/* Format: .klp.sym.sym_objname.sym_name,sympos */
		cnt = sscanf(strtab + sym->st_name,
			     ".klp.sym.%55[^.].%127[^,],%lu",
			     sym_objname, sym_name, &sympos);
		if (cnt != 3) {
			pr_err("symbol %s has an incorrectly formatted name\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		sym_vmlinux = !strcmp(sym_objname, "vmlinux");

		/*
		 * Prevent module-specific KLP rela sections from referencing
		 * vmlinux symbols.  This helps prevent ordering issues with
		 * module special section initializations.  Presumably such
		 * symbols are exported and normal relas can be used instead.
		 */
		if (!sec_vmlinux && sym_vmlinux) {
			pr_err("invalid access to vmlinux symbol '%s' from module-specific livepatch relocation section",
			       sym_name);
			return -EINVAL;
		}

		/* klp_find_object_symbol() treats a NULL objname as vmlinux */
		ret = klp_find_object_symbol(sym_vmlinux ? NULL : sym_objname,
					     sym_name, sympos, &addr);
		if (ret)
			return ret;

		sym->st_value = addr;
	}

	return 0;
}

/*
 * At a high-level, there are two types of klp relocation sections: those which
 * reference symbols which live in vmlinux; and those which reference symbols
 * which live in other modules.  This function is called for both types:
 *
 * 1) When a klp module itself loads, the module code calls this function to
 *    write vmlinux-specific klp relocations (.klp.rela.vmlinux.* sections).
 *    These relocations are written to the klp module text to allow the patched
 *    code/data to reference unexported vmlinux symbols.  They're written as
 *    early as possible to ensure that other module init code (.e.g.,
 *    jump_label_apply_nops) can access any unexported vmlinux symbols which
 *    might be referenced by the klp module's special sections.
 *
 * 2) When a to-be-patched module loads -- or is already loaded when a
 *    corresponding klp module loads -- klp code calls this function to write
 *    module-specific klp relocations (.klp.rela.{module}.* sections).  These
 *    are written to the klp module text to allow the patched code/data to
 *    reference symbols which live in the to-be-patched module or one of its
 *    module dependencies.  Exported symbols are supported, in addition to
 *    unexported symbols, in order to enable late module patching, which allows
 *    the to-be-patched module to be loaded and patched sometime *after* the
 *    klp module is loaded.
 */
int klp_apply_section_relocs(struct module *pmod, Elf_Shdr *sechdrs,
			     const char *shstrtab, const char *strtab,
			     unsigned int symndx, unsigned int secndx,
			     const char *objname)
{
	int cnt, ret;
	char sec_objname[MODULE_NAME_LEN];
	Elf_Shdr *sec = sechdrs + secndx;

	/*
	 * Format: .klp.rela.sec_objname.section_name
	 * See comment in klp_resolve_symbols() for an explanation
	 * of the selected field width value.
	 */
	cnt = sscanf(shstrtab + sec->sh_name, ".klp.rela.%55[^.]",
		     sec_objname);
	if (cnt != 1) {
		pr_err("section %s has an incorrectly formatted name\n",
		       shstrtab + sec->sh_name);
		return -EINVAL;
	}

	if (strcmp(objname ? objname : "vmlinux", sec_objname))
		return 0;

	ret = klp_resolve_symbols(sechdrs, strtab, symndx, sec, sec_objname);
	if (ret)
		return ret;

#ifdef CONFIG_MODULES_USE_ELF_RELA
	return apply_relocate_add(sechdrs, strtab, symndx, secndx, pmod);
#else
	return apply_relocate(sechdrs, strtab, symndx, secndx, pmod);
#endif
}

/*
 * Sysfs Interface
 *
 * /sys/kernel/livepatch
 * /sys/kernel/livepatch/<patch>
 * /sys/kernel/livepatch/<patch>/enabled
 * /sys/kernel/livepatch/<patch>/transition
 * /sys/kernel/livepatch/<patch>/force
 * /sys/kernel/livepatch/<patch>/<object>
 * /sys/kernel/livepatch/<patch>/<object>/<function,sympos>
 */
static int __klp_disable_patch(struct klp_patch *patch);

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
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

	if (patch->enabled == enabled) {
		/* already in requested state */
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Allow to reverse a pending transition in both ways. It might be
	 * necessary to complete the transition without forcing and breaking
	 * the system integrity.
	 *
	 * Do not allow to re-enable a disabled patch.
	 */
	if (patch == klp_transition_patch)
		klp_reverse_transition();
	else if (!enabled)
		ret = __klp_disable_patch(patch);
	else
		ret = -EINVAL;

out:
	mutex_unlock(&klp_mutex);

	if (ret)
		return ret;
	return count;
}

#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)

static bool klp_is_patch_registered(struct klp_patch *patch)
{
	struct klp_patch *mypatch;

	list_for_each_entry(mypatch, &klp_patches, list)
		if (mypatch == patch)
			return true;

	return false;
}

static int __klp_enable_patch(struct klp_patch *patch);
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
		goto out;
	}

	if (patch->enabled == enabled) {
		/* already in requested state */
		ret = -EINVAL;
		goto out;
	}

	if (enabled)
		ret = __klp_enable_patch(patch);
	else
		ret = __klp_disable_patch(patch);

out:
	mutex_unlock(&klp_mutex);

	if (ret)
		return ret;
	return count;
}
#endif

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
static struct kobj_attribute force_kobj_attr = __ATTR_WO(force);
#endif /* #ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */

static struct attribute *klp_patch_attrs[] = {
	&enabled_kobj_attr.attr,
#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
	&transition_kobj_attr.attr,
	&force_kobj_attr.attr,
#endif /* #ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */
	NULL
};
ATTRIBUTE_GROUPS(klp_patch);

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

static const struct proc_ops proc_klpstate_operations = {
	.proc_open		= klp_state_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
};

static void klp_free_object_dynamic(struct klp_object *obj)
{
	kfree(obj->name);
	kfree(obj);
}

static void klp_init_func_early(struct klp_object *obj,
				struct klp_func *func);
static void klp_init_object_early(struct klp_patch *patch,
				  struct klp_object *obj);

static struct klp_object *klp_alloc_object_dynamic(const char *name,
						   struct klp_patch *patch)
{
	struct klp_object *obj;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return NULL;

	if (name) {
		obj->name = kstrdup(name, GFP_KERNEL);
		if (!obj->name) {
			kfree(obj);
			return NULL;
		}
	}

	klp_init_object_early(patch, obj);
	obj->dynamic = true;

	return obj;
}

static void klp_free_func_nop(struct klp_func *func)
{
	kfree(func->old_name);
	kfree(func);
}

static struct klp_func *klp_alloc_func_nop(struct klp_func *old_func,
					   struct klp_object *obj)
{
	struct klp_func *func;

	func = kzalloc(sizeof(*func), GFP_KERNEL);
	if (!func)
		return NULL;

	if (old_func->old_name) {
		func->old_name = kstrdup(old_func->old_name, GFP_KERNEL);
		if (!func->old_name) {
			kfree(func);
			return NULL;
		}
	}

	klp_init_func_early(obj, func);
	/*
	 * func->new_func is same as func->old_func. These addresses are
	 * set when the object is loaded, see klp_init_object_loaded().
	 */
	func->old_sympos = old_func->old_sympos;
	func->nop = true;

	return func;
}

static int klp_add_object_nops(struct klp_patch *patch,
			       struct klp_object *old_obj)
{
	struct klp_object *obj;
	struct klp_func *func, *old_func;

	obj = klp_find_object(patch, old_obj);

	if (!obj) {
		obj = klp_alloc_object_dynamic(old_obj->name, patch);
		if (!obj)
			return -ENOMEM;
	}

	klp_for_each_func(old_obj, old_func) {
		func = klp_find_func(obj, old_func);
		if (func)
			continue;

		func = klp_alloc_func_nop(old_func, obj);
		if (!func)
			return -ENOMEM;
	}

	return 0;
}

/*
 * Add 'nop' functions which simply return to the caller to run
 * the original function. The 'nop' functions are added to a
 * patch to facilitate a 'replace' mode.
 */
static int klp_add_nops(struct klp_patch *patch)
{
	struct klp_patch *old_patch;
	struct klp_object *old_obj;

	klp_for_each_patch(old_patch) {
		klp_for_each_object(old_patch, old_obj) {
			int err;

			err = klp_add_object_nops(patch, old_obj);
			if (err)
				return err;
		}
	}

	return 0;
}

static void klp_kobj_release_patch(struct kobject *kobj)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	complete(&patch->finish);
}

static struct kobj_type klp_ktype_patch = {
	.release = klp_kobj_release_patch,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = klp_patch_groups,
};

static void klp_kobj_release_object(struct kobject *kobj)
{
	struct klp_object *obj;

	obj = container_of(kobj, struct klp_object, kobj);

	if (obj->dynamic)
		klp_free_object_dynamic(obj);
}

static struct kobj_type klp_ktype_object = {
	.release = klp_kobj_release_object,
	.sysfs_ops = &kobj_sysfs_ops,
};

static void klp_kobj_release_func(struct kobject *kobj)
{
	struct klp_func *func;

	func = container_of(kobj, struct klp_func, kobj);

	if (func->nop)
		klp_free_func_nop(func);
}

static struct kobj_type klp_ktype_func = {
	.release = klp_kobj_release_func,
	.sysfs_ops = &kobj_sysfs_ops,
};

static void __klp_free_funcs(struct klp_object *obj, bool nops_only)
{
	struct klp_func *func, *tmp_func;

	klp_for_each_func_safe(obj, func, tmp_func) {
		if (nops_only && !func->nop)
			continue;

		list_del(&func->node);
		kobject_put(&func->kobj);
	}
}

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
/* Clean up when a patched object is unloaded */
static void klp_free_object_loaded(struct klp_object *obj)
{
	struct klp_func *func;

	obj->mod = NULL;

	klp_for_each_func(obj, func) {
		func->old_func = NULL;

		if (func->nop)
			func->new_func = NULL;
	}
}
#endif /* #ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY */

static void __klp_free_objects(struct klp_patch *patch, bool nops_only)
{
	struct klp_object *obj, *tmp_obj;

	klp_for_each_object_safe(patch, obj, tmp_obj) {
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
		if (klp_is_module(obj) && obj->mod) {
			module_put(obj->mod);
			obj->mod = NULL;
		}
#endif
		__klp_free_funcs(obj, nops_only);

		if (nops_only && !obj->dynamic)
			continue;

		list_del(&obj->node);
		kobject_put(&obj->kobj);
	}
}

static void klp_free_objects(struct klp_patch *patch)
{
	__klp_free_objects(patch, false);
}

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
static void klp_free_objects_dynamic(struct klp_patch *patch)
{
	__klp_free_objects(patch, true);
}
#endif

/*
 * This function implements the free operations that can be called safely
 * under klp_mutex.
 *
 * The operation must be completed by calling klp_free_patch_finish()
 * outside klp_mutex.
 */
static void klp_free_patch_start(struct klp_patch *patch)
{
	if (!list_empty(&patch->list))
		list_del(&patch->list);

	klp_free_objects(patch);
}

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
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

/*
 * This function implements the free part that must be called outside
 * klp_mutex.
 *
 * It must be called after klp_free_patch_start(). And it has to be
 * the last function accessing the livepatch structures when the patch
 * gets disabled.
 */
static void klp_free_patch_finish(struct klp_patch *patch)
{
	/*
	 * Avoid deadlock with enabled_store() sysfs callback by
	 * calling this outside klp_mutex. It is safe because
	 * this is called when the patch gets disabled and it
	 * cannot get enabled again.
	 */
	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	/* Put the module after the last access to struct klp_patch. */
	if (!patch->forced)
		module_put(patch->mod);
}

/*
 * The livepatch might be freed from sysfs interface created by the patch.
 * This work allows to wait until the interface is destroyed in a separate
 * context.
 */
static void klp_free_patch_work_fn(struct work_struct *work)
{
	struct klp_patch *patch =
		container_of(work, struct klp_patch, free_work);

	klp_free_patch_finish(patch);
}

void klp_free_patch_async(struct klp_patch *patch)
{
	klp_free_patch_start(patch);
	schedule_work(&patch->free_work);
}

void klp_free_replaced_patches_async(struct klp_patch *new_patch)
{
	struct klp_patch *old_patch, *tmp_patch;

	klp_for_each_patch_safe(old_patch, tmp_patch) {
		if (old_patch == new_patch)
			return;
		klp_free_patch_async(old_patch);
	}
}

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
int __weak arch_klp_func_can_patch(struct klp_func *func)
{
	return 0;
}

int __weak arch_klp_init_func(struct klp_object *obj, struct klp_func *func)
{
	return 0;
}
#endif

static int klp_init_func(struct klp_object *obj, struct klp_func *func)
{
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	int ret;
#endif

	INIT_LIST_HEAD(&func->stack_node);
	func->patched = false;

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
#ifdef CONFIG_PPC64
	if (klp_is_module(obj))
		func->old_mod = obj->mod;
	else
		func->old_mod = NULL;
#endif
	ret = arch_klp_func_can_patch(func);
	if (ret)
		return ret;

	ret = arch_klp_init_func(obj, func);
	if (ret)
		return ret;
#endif
#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
	func->transition = false;
#endif

	/* The format for the sysfs directory is <function,sympos> where sympos
	 * is the nth occurrence of this symbol in kallsyms for the patched
	 * object. If the user selects 0 for old_sympos, then 1 will be used
	 * since a unique symbol will be the first occurrence.
	 */
	return kobject_add(&func->kobj, &obj->kobj, "%s,%lu",
			   func->old_name,
			   func->old_sympos ? func->old_sympos : 1);
}

static int klp_apply_object_relocs(struct klp_patch *patch,
				   struct klp_object *obj)
{
	int i, ret;
	struct klp_modinfo *info = patch->mod->klp_info;

	for (i = 1; i < info->hdr.e_shnum; i++) {
		Elf_Shdr *sec = info->sechdrs + i;

		if (!(sec->sh_flags & SHF_RELA_LIVEPATCH))
			continue;

		ret = klp_apply_section_relocs(patch->mod, info->sechdrs,
					       info->secstrings,
					       patch->mod->core_kallsyms.strtab,
					       info->symndx, i, obj->name);
		if (ret)
			return ret;
	}

	return 0;
}

/* parts of the initialization that is done only when the object is loaded */
static int klp_init_object_loaded(struct klp_patch *patch,
				  struct klp_object *obj)
{
	struct klp_func *func;
	int ret;

	module_disable_ro(patch->mod);
	if (klp_is_module(obj)) {
		/*
		 * Only write module-specific relocations here
		 * (.klp.rela.{module}.*).  vmlinux-specific relocations were
		 * written earlier during the initialization of the klp module
		 * itself.
		 */
		ret = klp_apply_object_relocs(patch, obj);
		if (ret) {
			module_enable_ro(patch->mod, true);
			pr_err("apply object relocations failed, ret=%d\n", ret);
			return ret;
		}
	}
	module_enable_ro(patch->mod, true);

	klp_for_each_func(obj, func) {
		ret = klp_find_object_symbol(obj->name, func->old_name,
					     func->old_sympos,
					     (unsigned long *)&func->old_func);
		if (ret)
			return ret;

		ret = kallsyms_lookup_size_offset((unsigned long)func->old_func,
						  &func->old_size, NULL);
		if (!ret) {
			pr_err("kallsyms size lookup failed for '%s'\n",
			       func->old_name);
			return -ENOENT;
		}

#ifdef PPC64_ELF_ABI_v1
		/*
		 * PPC64 big endian binary format is 'elfv1' defaultly, actual
		 * symbol name of old function need a prefix '.' (related
		 * feature 'function descriptor'), otherwise size found by
		 * 'kallsyms_lookup_size_offset' may be abnormal.
		 */
		if (func->old_name[0] !=  '.') {
			pr_warn("old_name '%s' may miss the prefix '.', old_size=%lu\n",
				func->old_name, func->old_size);
		}
#endif

		if (func->nop)
			func->new_func = func->old_func;

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

	if (klp_is_module(obj) && strnlen(obj->name, MODULE_NAME_LEN) >= MODULE_NAME_LEN) {
		pr_err("obj name is too long\n");
		return -EINVAL;
	}
	klp_for_each_func(obj, func) {
		if (!func->old_name) {
			pr_err("old name is invalid\n");
			return -EINVAL;
		}
		/*
		 * NOPs get the address later. The patched module must be loaded,
		 * see klp_init_object_loaded().
		 */
		if (!func->new_func && !func->nop) {
			pr_err("new_func is invalid\n");
			return -EINVAL;
		}
		if (strlen(func->old_name) >= KSYM_NAME_LEN) {
			pr_err("function old name is too long\n");
			return -EINVAL;
		}
	}

	obj->patched = false;
	obj->mod = NULL;

	ret = klp_find_object_module(obj);
	if (ret)
		return ret;

	name = klp_is_module(obj) ? obj->name : "vmlinux";
	ret = kobject_add(&obj->kobj, &patch->kobj, "%s", name);
	if (ret)
		goto out;

	/*
	 * For livepatch without ftrace, we need to modify the first N
	 * instructions of the to-be-patched func. So should check if the
	 * func length enough to allow this modification.
	 *
	 * We add check hook in klp_init_func and will using the old_size
	 * internally, so the klp_init_object_loaded should called first
	 * to fill the klp_func struct.
	 */
	if (klp_is_object_loaded(obj)) {
		ret = klp_init_object_loaded(patch, obj);
		if (ret)
			goto out;
	}

	klp_for_each_func(obj, func) {
		ret = klp_init_func(obj, func);
		if (ret)
			goto out;
	}

	return 0;

out:
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
	if (klp_is_module(obj)) {
		module_put(obj->mod);
		obj->mod = NULL;
	}
#endif
	return ret;
}

static void klp_init_func_early(struct klp_object *obj,
				struct klp_func *func)
{
	kobject_init(&func->kobj, &klp_ktype_func);
	list_add_tail(&func->node, &obj->func_list);
	func->func_node = NULL;
}

static void klp_init_object_early(struct klp_patch *patch,
				  struct klp_object *obj)
{
	INIT_LIST_HEAD(&obj->func_list);
	kobject_init(&obj->kobj, &klp_ktype_object);
	list_add_tail(&obj->node, &patch->obj_list);
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
	obj->mod = NULL;
#endif
}

static void klp_init_patch_early(struct klp_patch *patch)
{
	struct klp_object *obj;
	struct klp_func *func;

	INIT_LIST_HEAD(&patch->list);
	INIT_LIST_HEAD(&patch->obj_list);
	kobject_init(&patch->kobj, &klp_ktype_patch);
	patch->enabled = false;
	patch->forced = false;
	INIT_WORK(&patch->free_work, klp_free_patch_work_fn);
	init_completion(&patch->finish);

	klp_for_each_object_static(patch, obj) {
		klp_init_object_early(patch, obj);

		klp_for_each_func_static(obj, func) {
			klp_init_func_early(obj, func);
		}
	}
}

static int klp_init_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	ret = kobject_add(&patch->kobj, klp_root_kobj, "%s", patch->mod->name);
	if (ret)
		return ret;

	if (patch->replace) {
		ret = klp_add_nops(patch);
		if (ret)
			return ret;
	}

	klp_for_each_object(patch, obj) {
		ret = klp_init_object(patch, obj);
		if (ret)
			return ret;
	}

	flush_module_icache(patch->mod);
	set_mod_klp_rel_state(patch->mod, MODULE_KLP_REL_DONE);
	module_disable_ro(patch->mod);
	jump_label_apply_nops(patch->mod);
	ret = jump_label_register(patch->mod);
	if (ret) {
		module_enable_ro(patch->mod, true);
		pr_err("register jump label failed, ret=%d\n", ret);
		return ret;
	}
	module_enable_ro(patch->mod, true);

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
	klp_for_each_object(patch, obj)
		klp_load_hook(obj);
#endif

	list_add_tail(&patch->list, &klp_patches);

	return 0;
}

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
static int __klp_disable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;

	if (WARN_ON(!patch->enabled))
		return -EINVAL;

	if (klp_transition_patch)
		return -EBUSY;

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
	patch->enabled = false;
	klp_try_complete_transition();

	return 0;
}
#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)
int __weak klp_check_calltrace(struct klp_patch *patch, int enable)
{
	return 0;
}

static LIST_HEAD(klp_func_list);

struct klp_func_node *klp_find_func_node(const void *old_func)
{
	struct klp_func_node *func_node;

	list_for_each_entry(func_node, &klp_func_list, node) {
		if (func_node->old_func == old_func)
			return func_node;
	}

	return NULL;
}

void klp_add_func_node(struct klp_func_node *func_node)
{
	list_add_rcu(&func_node->node, &klp_func_list);
}

void klp_del_func_node(struct klp_func_node *func_node)
{
	list_del_rcu(&func_node->node);
}

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
	struct patch_data *pd = (struct patch_data *)data;

	if (atomic_inc_return(&pd->cpu_count) == 1) {
		struct klp_patch *patch = pd->patch;

		if (klp_check_patch_kprobed(patch)) {
			atomic_inc(&pd->cpu_count);
			return -EINVAL;
		}

		ret = klp_check_calltrace(patch, 0);
		if (ret) {
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		ret = disable_patch(patch);
		if (ret) {
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		atomic_inc(&pd->cpu_count);
	} else {
		while (atomic_read(&pd->cpu_count) <= num_online_cpus())
			cpu_relax();

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

void __weak *arch_klp_mem_alloc(size_t size)
{
	return kzalloc(size, GFP_ATOMIC);
}

void __weak arch_klp_mem_free(void *mem)
{
	kfree(mem);
}

long __weak arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func)
{
	return -ENOSYS;
}

static struct klp_func_node *func_node_alloc(struct klp_func *func)
{
	long ret;
	struct klp_func_node *func_node = NULL;

	func_node = klp_find_func_node(func->old_func);
	if (func_node) /* The old_func has ever been patched */
		return func_node;
	func_node = arch_klp_mem_alloc(sizeof(struct klp_func_node));
	if (func_node) {
		INIT_LIST_HEAD(&func_node->func_stack);
		func_node->old_func = func->old_func;
		/*
		 * Module which contains 'old_func' would not be removed because
		 * it's reference count has been held during registration.
		 * But it's not in stop_machine context here, 'old_func' should
		 * not be modified as saving old code.
		 */
		ret = arch_klp_save_old_code(&func_node->arch_data, func->old_func);
		if (ret) {
			arch_klp_mem_free(func_node);
			pr_err("save old code failed, ret=%ld\n", ret);
			return NULL;
		}
		klp_add_func_node(func_node);
	}
	return func_node;
}

static void func_node_free(struct klp_func *func)
{
	struct klp_func_node *func_node;

	func_node = func->func_node;
	if (func_node) {
		func->func_node = NULL;
		if (list_empty(&func_node->func_stack)) {
			klp_del_func_node(func_node);
			arch_klp_mem_free(func_node);
		}
	}
}

static void klp_mem_recycle(struct klp_patch *patch)
{
	struct klp_object *obj;
	struct klp_func *func;

	klp_for_each_object(patch, obj) {
		klp_for_each_func(obj, func) {
			func_node_free(func);
		}
	}
}

static int klp_mem_prepare(struct klp_patch *patch)
{
	struct klp_object *obj;
	struct klp_func *func;

	klp_for_each_object(patch, obj) {
		klp_for_each_func(obj, func) {
			func->func_node = func_node_alloc(func);
			if (func->func_node == NULL) {
				klp_mem_recycle(patch);
				pr_err("alloc func_node failed\n");
				return -ENOMEM;
			}
		}
	}
	return 0;
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
	if (ret)
		return ret;

	klp_mem_recycle(patch);
	return 0;
}
#endif /* if defined(CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY) */

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
static int __klp_enable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	if (klp_transition_patch)
		return -EBUSY;

	if (WARN_ON(patch->enabled))
		return -EINVAL;

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
	patch->enabled = true;
	klp_try_complete_transition();

	return 0;
err:
	pr_warn("failed to enable patch '%s'\n", patch->mod->name);

	klp_cancel_transition();
	return ret;
}

/**
 * klp_enable_patch() - enable the livepatch
 * @patch:	patch to be enabled
 *
 * Initializes the data structure associated with the patch, creates the sysfs
 * interface, performs the needed symbol lookups and code relocations,
 * registers the patched functions with ftrace.
 *
 * This function is supposed to be called from the livepatch module_init()
 * callback.
 *
 * Return: 0 on success, otherwise error
 */
int klp_enable_patch(struct klp_patch *patch)
{
	int ret;
	struct klp_object *obj;

	if (!patch || !patch->mod || !patch->objs)
		return -EINVAL;

	klp_for_each_object_static(patch, obj) {
		if (!obj->funcs)
			return -EINVAL;
	}

	if (!is_livepatch_module(patch->mod)) {
		pr_err("module %s is not marked as a livepatch module\n",
		       patch->mod->name);
		return -EINVAL;
	}

	if (!klp_initialized())
		return -ENODEV;

	if (!klp_have_reliable_stack()) {
		pr_warn("This architecture doesn't have support for the livepatch consistency model.\n");
		pr_warn("The livepatch transition may never complete.\n");
	}

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_compatible(patch)) {
		pr_err("Livepatch patch (%s) is not compatible with the already installed livepatches.\n",
			patch->mod->name);
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	if (!try_module_get(patch->mod)) {
		mutex_unlock(&klp_mutex);
		return -ENODEV;
	}

	klp_init_patch_early(patch);

	ret = klp_init_patch(patch);
	if (ret)
		goto err;

	ret = __klp_enable_patch(patch);
	if (ret)
		goto err;

	mutex_unlock(&klp_mutex);

	return 0;

err:
	klp_free_patch_start(patch);

	mutex_unlock(&klp_mutex);

	klp_free_patch_finish(patch);

	return ret;
}
EXPORT_SYMBOL_GPL(klp_enable_patch);

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
	struct patch_data *pd = (struct patch_data *)data;

	if (atomic_inc_return(&pd->cpu_count) == 1) {
		struct klp_patch *patch = pd->patch;

		if (klp_check_patch_kprobed(patch)) {
			atomic_inc(&pd->cpu_count);
			return -EINVAL;
		}

		ret = klp_check_calltrace(patch, 1);
		if (ret) {
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		ret = enable_patch(patch);
		if (ret) {
			atomic_inc(&pd->cpu_count);
			return ret;
		}
		atomic_inc(&pd->cpu_count);
	} else {
		while (atomic_read(&pd->cpu_count) <= num_online_cpus())
			cpu_relax();

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

	ret = klp_mem_prepare(patch);
	if (ret)
		return ret;
	arch_klp_code_modify_prepare();
	ret = stop_machine(klp_try_enable_patch, &patch_data, cpu_online_mask);
	arch_klp_code_modify_post_process();
	if (ret) {
		klp_mem_recycle(patch);
		return ret;
	}

#ifndef CONFIG_LIVEPATCH_STACK
	/* move the enabled patch to the list tail */
	list_del(&patch->list);
	list_add_tail(&patch->list, &klp_patches);
#endif

	return 0;
}

/**
 * klp_register_patch() - registers a patch
 * @patch:      Patch to be registered
 *
 * Initializes the data structure associated with the patch and
 * creates the sysfs interface.
 *
 * Return: 0 on success, otherwise error
 */
int klp_register_patch(struct klp_patch *patch)
{
	int ret;
	struct klp_object *obj;

	if (!patch) {
		pr_err("patch invalid\n");
		return -EINVAL;
	}
	if (!patch->mod) {
		pr_err("patch->mod invalid\n");
		return -EINVAL;
	}
	if (!patch->objs) {
		pr_err("patch->objs invalid\n");
		return -EINVAL;
	}

	klp_for_each_object_static(patch, obj) {
		if (!obj->funcs) {
			pr_err("obj->funcs invalid\n");
			return -EINVAL;
		}
	}

	if (!is_livepatch_module(patch->mod)) {
		pr_err("module %s is not marked as a livepatch module\n",
			patch->mod->name);
		return -EINVAL;
	}

	if (!klp_initialized()) {
		pr_err("kernel live patch not available\n");
		return -ENODEV;
	}

	mutex_lock(&klp_mutex);

	if (klp_is_patch_registered(patch)) {
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	klp_init_patch_early(patch);

	ret = klp_init_patch(patch);
	if (ret)
		goto err;

	mutex_unlock(&klp_mutex);

	return 0;

err:
	klp_free_patch_start(patch);

	mutex_unlock(&klp_mutex);

	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	return ret;
}
EXPORT_SYMBOL_GPL(klp_register_patch);

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
	int ret = 0;
	struct klp_object *obj;

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		ret = -EINVAL;
		goto out;
	}

	if (patch->enabled) {
		ret = -EBUSY;
		goto out;
	}

	klp_for_each_object(patch, obj)
		klp_unload_hook(obj);

	klp_free_patch_start(patch);

	mutex_unlock(&klp_mutex);

	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	return 0;
out:
	mutex_unlock(&klp_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(klp_unregister_patch);

#endif /* #ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY */
/*
 * This function unpatches objects from the replaced livepatches.
 *
 * We could be pretty aggressive here. It is called in the situation where
 * these structures are no longer accessed from the ftrace handler.
 * All functions are redirected by the klp_transition_patch. They
 * use either a new code or they are in the original code because
 * of the special nop function patches.
 *
 * The only exception is when the transition was forced. In this case,
 * klp_ftrace_handler() might still see the replaced patch on the stack.
 * Fortunately, it is carefully designed to work with removed functions
 * thanks to RCU. We only have to keep the patches on the system. Also
 * this is handled transparently by patch->module_put.
 */
void klp_unpatch_replaced_patches(struct klp_patch *new_patch)
{
	struct klp_patch *old_patch;

	klp_for_each_patch(old_patch) {
		if (old_patch == new_patch)
			return;

		old_patch->enabled = false;
		klp_unpatch_objects(old_patch);
	}
}

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
/*
 * This function removes the dynamically allocated 'nop' functions.
 *
 * We could be pretty aggressive. NOPs do not change the existing
 * behavior except for adding unnecessary delay by the ftrace handler.
 *
 * It is safe even when the transition was forced. The ftrace handler
 * will see a valid ops->func_stack entry thanks to RCU.
 *
 * We could even free the NOPs structures. They must be the last entry
 * in ops->func_stack. Therefore unregister_ftrace_function() is called.
 * It does the same as klp_synchronize_transition() to make sure that
 * nobody is inside the ftrace handler once the operation finishes.
 *
 * IMPORTANT: It must be called right after removing the replaced patches!
 */
void klp_discard_nops(struct klp_patch *new_patch)
{
	klp_unpatch_objects_dynamic(klp_transition_patch);
	klp_free_objects_dynamic(klp_transition_patch);
}

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

	klp_for_each_patch(patch) {
		if (patch == limit)
			break;

		klp_for_each_object(patch, obj) {
			if (!klp_is_module(obj) || strcmp(obj->name, mod->name))
				continue;

			if (patch != klp_transition_patch)
				klp_pre_unpatch_callback(obj);

			pr_notice("reverting patch '%s' on unloading module '%s'\n",
				  patch->mod->name, obj->mod->name);
			klp_unpatch_object(obj);

			klp_post_unpatch_callback(obj);

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

	if (!strcmp(mod->name, "vmlinux")) {
		pr_err("vmlinux.ko: invalid module name");
		return -EINVAL;
	}

	mutex_lock(&klp_mutex);
	/*
	 * Each module has to know that klp_module_coming()
	 * has been called. We never know what module will
	 * get patched by a new patch.
	 */
	mod->klp_alive = true;

	klp_for_each_patch(patch) {
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
	struct proc_dir_entry *root_klp_dir, *res;

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
