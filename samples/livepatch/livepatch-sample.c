// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * livepatch-sample.c - Kernel Live Patching Sample Module
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#ifdef CONFIG_PPC64
#include <asm/code-patching.h>
#endif

/*
 * This (dumb) live patch overrides the function that prints the
 * kernel boot cmdline when /proc/cmdline is read.
 *
 * Example:
 *
 * $ cat /proc/cmdline
 * <your cmdline>
 *
 * $ insmod livepatch-sample.ko
 * $ cat /proc/cmdline
 * this has been live patched
 *
 * $ echo 0 > /sys/kernel/livepatch/livepatch_sample/enabled
 * $ cat /proc/cmdline
 * <your cmdline>
 */

#include <linux/seq_file.h>

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
void load_hook(void)
{
	pr_info("load_hook\n");
}

void unload_hook(void)
{
	pr_info("unload_hook\n");
}

static struct klp_hook hooks_load[] = {
	{
		.hook = load_hook
	}, { }
};

static struct klp_hook hooks_unload[] = {
	{
		.hook = unload_hook
	}, { }
};
#endif

static int livepatch_cmdline_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", "this has been live patched");
	return 0;
}

static struct klp_func funcs[] = {
	{
#ifdef CONFIG_PPC64
		.old_name = ".cmdline_proc_show",
#else
		.old_name = "cmdline_proc_show",
#endif
		.new_func = livepatch_cmdline_proc_show,
	}, { }
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
		.hooks_load = hooks_load,
		.hooks_unload = hooks_unload,
#endif
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int livepatch_init(void)
{
#ifdef CONFIG_PPC64
	patch.objs[0].funcs[0].new_func =
		(void *)ppc_function_entry((void *)livepatch_cmdline_proc_show);
#endif

#ifdef CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
	return klp_enable_patch(&patch);
#elif defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY)
	return klp_register_patch(&patch);
#endif
}

static void livepatch_exit(void)
{
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
	WARN_ON(klp_unregister_patch(&patch));
#endif
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
