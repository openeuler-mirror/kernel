/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef BLK_IO_HIERARCHY_IODUMP_H
#define BLK_IO_HIERARCHY_IODUMP_H

#ifdef CONFIG_HIERARCHY_IO_DUMP

#include "stats.h"

#define ns_to_ms(time) div_u64(time, NSEC_PER_MSEC)

int blk_io_hierarchy_iodump_init(struct request_queue *q,
				 struct hierarchy_stage *hstage);
void blk_io_hierarchy_iodump_exit(struct request_queue *q,
				  enum stage_group stage);
void hierarchy_add_bio(struct hierarchy_stage *hstage, struct bio *bio);
void hierarchy_remove_bio(struct hierarchy_stage *hstage, struct bio *bio);
void bio_hierarchy_data_init(struct bio *bio, struct bio_hierarchy_data *hdata);
void io_hierarchy_register_iodump(struct hierarchy_stage *hstage);

void hierarchy_account_slow_io(struct hierarchy_stage *hstage,
			       enum stat_group op, unsigned long duration);
void hierarchy_show_slow_io(struct hierarchy_stats_data *hstats_data,
			    struct seq_file *m);

static inline void
hierarchy_account_slow_io_ns(struct hierarchy_stage *hstage,
			     enum stat_group op, u64 duration)
{
	hierarchy_account_slow_io(hstage, op, ns_to_ms(duration));
}

static inline void
hierarchy_account_slow_io_jiffies(struct hierarchy_stage *hstage,
				  enum stat_group op, unsigned long duration)
{
	hierarchy_account_slow_io(hstage, op, jiffies_to_msecs(duration));
}

#else
static inline int
blk_io_hierarchy_iodump_init(struct request_queue *q,
			     struct hierarchy_stage *hstage)
{
	return 0;
}

static inline void
blk_io_hierarchy_iodump_exit(struct request_queue *q, enum stage_group stage)
{
}

static inline void
hierarchy_add_bio(struct hierarchy_stage *hstage, struct bio *bio)
{
}

static inline void
hierarchy_remove_bio(struct hierarchy_stage *hstage, struct bio *bio)
{
}

static inline void
bio_hierarchy_data_init(struct bio *bio, struct bio_hierarchy_data *hdata)
{
}

static inline void
io_hierarchy_register_iodump(struct hierarchy_stage *hstage)
{
}

static inline void
hierarchy_account_slow_io(struct hierarchy_stage *hstage,
			  enum stat_group op, unsigned long duration)
{
}

static inline void
hierarchy_account_slow_io_ns(struct hierarchy_stage *hstage,
			     enum stat_group op, u64 duration)
{
}

static inline void
hierarchy_account_slow_io_jiffies(struct hierarchy_stage *hstage,
				  enum stat_group op, unsigned long duration)
{
}

#endif
#endif
