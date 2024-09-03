// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/debugfs.h>
#include <linux/blkdev.h>

#include "../blk-mq-debugfs.h"
#include "stats.h"
#include "iodump.h"

static const char *stage_name[NR_STAGE_GROUPS] = {
#ifdef CONFIG_HIERARCHY_THROTTLE
	[STAGE_THROTTLE]	= "throtl",
#endif
#ifdef CONFIG_HIERARCHY_WBT
	[STAGE_WBT]		= "wbt",
#endif
#ifdef CONFIG_HIERARCHY_GETTAG
	[STAGE_GETTAG]		= "gettag",
#endif
#ifdef CONFIG_HIERARCHY_PLUG
	[STAGE_PLUG]		= "plug",
#endif
#ifdef CONFIG_HIERARCHY_DEADLINE
	[STAGE_DEADLINE]        = "deadline",
#endif
#ifdef CONFIG_HIERARCHY_BFQ
	[STAGE_BFQ]	        = "bfq",
#endif
#ifdef CONFIG_HIERARCHY_KYBER
	[STAGE_KYBER]		= "kyber",
#endif
#ifdef CONFIG_HIERARCHY_HCTX
	[STAGE_HCTX]		= "hctx",
#endif
#ifdef CONFIG_HIERARCHY_REQUEUE
	[STAGE_REQUEUE]		= "requeue",
#endif
#ifdef CONFIG_HIERARCHY_RQ_DRIVER
	[STAGE_RQ_DRIVER]	= "rq_driver",
#endif
#ifdef CONFIG_HIERARCHY_BIO
	[STAGE_BIO]		= "bio",
#endif
};

const char *hierarchy_stage_name(enum stage_group stage)
{
	return stage_name[stage];
}

static int __hierarchy_stats_show(struct hierarchy_stats_data *hstats_data,
				  struct seq_file *m, enum stage_group stage)
{
	u64 dispatched[NR_NEW_STAT_GROUPS] = {0};
	u64 completed[NR_NEW_STAT_GROUPS] = {0};
	u64 latency[NR_NEW_STAT_GROUPS] = {0};
	int cpu;
	int i;

	for_each_possible_cpu(cpu) {
		struct hierarchy_stats *stat =
			per_cpu_ptr(hstats_data->hstats, cpu);

		for (i = 0; i < NR_NEW_STAT_GROUPS; ++i) {
			dispatched[i] += stat->dispatched[i];
			completed[i] += stat->completed[i];
			latency[i] += stage_is_rq(stage) ?
				      stat->jiffies[i] : stat->nsecs[i];
		}
	}

	if (stage_is_rq(stage))
		for (i = 0; i < NR_NEW_STAT_GROUPS; ++i)
			latency[i] =
				jiffies_to_msecs(latency[i]) * NSEC_PER_MSEC;

	seq_printf(m, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
		   dispatched[STAT_READ], completed[STAT_READ],
		   latency[STAT_READ], dispatched[STAT_WRITE],
		   completed[STAT_WRITE], latency[STAT_WRITE],
		   dispatched[STAT_DISCARD], completed[STAT_DISCARD],
		   latency[STAT_DISCARD], dispatched[STAT_FLUSH],
		   completed[STAT_FLUSH], latency[STAT_FLUSH]);

	hierarchy_show_slow_io(hstats_data, m);
	seq_putc(m, '\n');
	return 0;
}

static void *hierarchy_stats_start(struct seq_file *m, loff_t *pos)
{
	enum stage_group stage = *pos;

	if (stage < 0 || stage >= NR_STAGE_GROUPS)
		return NULL;

	return pos;
}

static void *hierarchy_stats_next(struct seq_file *m, void *v, loff_t *pos)
{
	enum stage_group stage = ++(*pos);

	if (stage >= 0 && stage < NR_STAGE_GROUPS)
		return pos;

	return NULL;
}

static void hierarchy_stats_stop(struct seq_file *m, void *v)
{
}

static int hierarchy_stats_show(struct seq_file *m, void *v)
{
	enum stage_group stage = (*(loff_t *)v);
	struct blk_io_hierarchy_stats *stats = m->private;
	struct hierarchy_stats_data *hstats_data =
				get_hstats_data(stats, stage);

	if (!hstats_data)
		return 0;

	seq_printf(m, "%s ", hierarchy_stage_name(stage));
	__hierarchy_stats_show(hstats_data, m, stage);
	put_hstats_data(stats, hstats_data);
	return 0;
}

static const struct seq_operations hierarchy_stats_ops = {
	.start	= hierarchy_stats_start,
	.next	= hierarchy_stats_next,
	.stop	= hierarchy_stats_stop,
	.show	= hierarchy_stats_show,
};

static int hierarchy_stats_show_single(void *v, struct seq_file *m)
{
	struct hierarchy_stage *hstage = v;

	return __hierarchy_stats_show(hstage->hstats_data, m, hstage->stage);
}

static const struct blk_mq_debugfs_attr hierarchy_debugfs_attrs[] = {
	{"stats", 0400, hierarchy_stats_show_single},
	{},
};

static const struct blk_mq_debugfs_attr hierarchy_stats_attr[] = {
	{"stats", 0400, .seq_ops = &hierarchy_stats_ops},
	{},
};

static void hierarchy_register_stage(struct blk_io_hierarchy_stats *stats,
				     enum stage_group stage)
{
	struct hierarchy_stage *hstage = stats->hstage[stage];
	struct dentry *dir;

	if (!stage_name[stage] || hstage->debugfs_dir)
		return;

	dir = debugfs_create_dir(stage_name[stage], stats->debugfs_dir);
	if (IS_ERR(dir))
		return;

	hstage->debugfs_dir = dir;
	debugfs_create_files(dir, hstage, hierarchy_debugfs_attrs);
	io_hierarchy_register_iodump(hstage);
}

static void hierarchy_unregister_stage(struct blk_io_hierarchy_stats *stats,
				       enum stage_group stage)
{
	struct hierarchy_stage *hstage = stats->hstage[stage];

	if (!stage_name[stage] || !hstage->debugfs_dir)
		return;

	debugfs_remove_recursive(hstage->debugfs_dir);
	hstage->debugfs_dir = NULL;
}

void blk_mq_debugfs_register_hierarchy(struct request_queue *q,
				       enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats =
		queue_to_wrapper(q)->io_hierarchy_stats;

	if (!blk_mq_hierarchy_registered(q, stage) ||
	    !blk_mq_debugfs_enabled(q))
		return;

	hierarchy_register_stage(stats, stage);
}

void blk_mq_debugfs_unregister_hierarchy(struct request_queue *q,
					 enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats =
		queue_to_wrapper(q)->io_hierarchy_stats;

	if (!blk_mq_hierarchy_registered(q, stage) ||
	    !blk_mq_debugfs_enabled(q))
		return;

	hierarchy_unregister_stage(stats, stage);
}

void blk_mq_debugfs_create_default_hierarchy_attr(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats =
		queue_to_wrapper(q)->io_hierarchy_stats;

	if (!blk_mq_debugfs_enabled(q))
		return;

	debugfs_create_files(stats->debugfs_dir, stats, hierarchy_stats_attr);
}
