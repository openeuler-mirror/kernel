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

#ifdef CONFIG_LIVEPATCH_WO_FTRACE
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
#endif /* CONFIG_LIVEPATCH_WO_FTRACE */

static int livepatch_cmdline_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", "this has been live patched");
	return 0;
}

static struct klp_func funcs[] = {
	{
		.old_name = "cmdline_proc_show",
		.new_func = livepatch_cmdline_proc_show,
	}, { }
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
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
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	return klp_register_patch(&patch);
#else
	return klp_enable_patch(&patch);
#endif
}

static void livepatch_exit(void)
{
#ifdef CONFIG_LIVEPATCH_WO_FTRACE
	WARN_ON(klp_unregister_patch(&patch));
#endif
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
