// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Wang Yuanheng
 * Author: Wang Yuanheng
 *
 */

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <asm/debug.h>

__read_mostly bool bind_vcpu_enabled;
EXPORT_SYMBOL(bind_vcpu_enabled);

static int __init bind_vcpu_init(void)
{
	struct dentry *bindvcpu;

	if (!sw64_debugfs_dir)
		return -ENODEV;

	bindvcpu = debugfs_create_bool("bind_vcpu", 0644,
			sw64_debugfs_dir, &bind_vcpu_enabled);
	if (!bindvcpu)
		return -ENOMEM;
	return 0;
}
late_initcall(bind_vcpu_init);
