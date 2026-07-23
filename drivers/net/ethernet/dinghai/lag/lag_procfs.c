// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/printk.h>

#include "dh_procfs.h"
#include "lag.h"

void *lag_info_seq_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;

	return NULL;
}

void *lag_info_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

void lag_info_seq_stop(struct seq_file *seq, void *v)
{
}

int lag_info_seq_show(struct seq_file *seq, void *v)
{
	return 0;
}

const struct seq_operations lag_info_seq_ops = {
	.start = lag_info_seq_start,
	.next = lag_info_seq_next,
	.stop = lag_info_seq_stop,
	.show = lag_info_seq_show,
};
