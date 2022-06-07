// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Mao Minkai
 * Author: Mao Minkai
 *
 * This code is taken from arch/mips/kernel/segment.c
 *	Copyright (C) 2013 Imagination Technologies Ltd.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <asm/unaligned.h>
#include <asm/debug.h>

static int show_unaligned(struct seq_file *sf, void *v)
{
	extern struct unaligned_stat {
		unsigned long count, va, pc;
	} unaligned[2];

	seq_printf(sf, "kernel unaligned acc\t: %ld (pc=%lx, va=%lx)\n", unaligned[0].count, unaligned[0].pc, unaligned[0].va);
	seq_printf(sf, "user unaligned acc\t: %ld (pc=%lx, va=%lx)\n", unaligned[1].count, unaligned[1].pc, unaligned[1].va);

	return 0;
}

static int unaligned_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_unaligned, NULL);
}

static const struct file_operations unaligned_fops = {
	.open		= unaligned_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init unaligned_info(void)
{
	struct dentry *unaligned;

	if (!sw64_debugfs_dir)
		return -ENODEV;

	unaligned = debugfs_create_file("unaligned", S_IRUGO,
				       sw64_debugfs_dir, NULL,
				       &unaligned_fops);
	if (!unaligned)
		return -ENOMEM;
	return 0;
}
device_initcall(unaligned_info);
