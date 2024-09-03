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

#ifndef BLK_IO_HIERARCHY_STATS_H
#define BLK_IO_HIERARCHY_STATS_H

#ifdef CONFIG_BLK_IO_HIERARCHY_STATS

#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include "../blk.h"

struct bio_hierarchy_data {
	u64 time;
#ifdef CONFIG_HIERARCHY_IO_DUMP
	struct bio *bio;
	struct list_head hierarchy_list;
#endif
};

struct hierarchy_stats {
	union {
		/* for bio based stages. */
		u64 nsecs[NR_NEW_STAT_GROUPS];
		/* for request based stages. */
		unsigned long jiffies[NR_NEW_STAT_GROUPS];
	};
	unsigned long dispatched[NR_NEW_STAT_GROUPS];
	unsigned long completed[NR_NEW_STAT_GROUPS];
#ifdef CONFIG_HIERARCHY_IO_DUMP
	unsigned long slow[NR_NEW_STAT_GROUPS];
#endif
};

struct hierarchy_stats_data {
	int ref;
	struct hierarchy_stats __percpu *hstats;
};

struct hierarchy_stage {
	enum stage_group stage;
	bool unbalanced_warned;
	struct dentry *debugfs_dir;
	struct hierarchy_stats_data *hstats_data;
#ifdef CONFIG_HIERARCHY_IO_DUMP
	unsigned long threshold;
	void *dump_data;
#endif
};

struct blk_io_hierarchy_stats {
	struct request_queue *q;
	struct dentry *debugfs_dir;
	spinlock_t hstage_lock;
	struct hierarchy_stage *hstage[NR_STAGE_GROUPS];
};

static inline bool stage_is_bio(enum stage_group stage)
{
	return stage >= 0 && stage < NR_BIO_STAGE_GROUPS;
}

static inline bool stage_is_rq(enum stage_group stage)
{
	return stage >= NR_BIO_STAGE_GROUPS && stage < NR_RQ_STAGE_GROUPS;
}

const char *hierarchy_stage_name(enum stage_group stage);
int blk_io_hierarchy_stats_alloc(struct request_queue *q);
void blk_io_hierarchy_stats_free(struct request_queue *q);

/* APIs for stage registration */
bool blk_mq_hierarchy_registered(struct request_queue *q,
				 enum stage_group stage);
void blk_mq_register_hierarchy(struct request_queue *q, enum stage_group stage);
void blk_mq_unregister_hierarchy(struct request_queue *q,
				 enum stage_group stage);

/* APIs for disk level debugfs */
void blk_mq_debugfs_register_hierarchy_stats(struct request_queue *q);
void blk_mq_debugfs_create_default_hierarchy_attr(struct request_queue *q);

/* APIs for stage level debugfs */
void blk_mq_debugfs_register_hierarchy(struct request_queue *q,
				       enum stage_group stage);
void blk_mq_debugfs_unregister_hierarchy(struct request_queue *q,
					 enum stage_group stage);
struct hierarchy_stats_data *get_hstats_data(
		struct blk_io_hierarchy_stats *stats,
		enum stage_group stage);
void put_hstats_data(struct blk_io_hierarchy_stats *stats,
		     struct hierarchy_stats_data *hstats_data);

/* APIs for bio based stage io accounting */
void bio_hierarchy_start_io_acct(struct bio *bio, enum stage_group stage);
void __bio_hierarchy_end_io_acct(struct bio *bio, enum stage_group stage,
				 u64 time);
void bio_free_hierarchy_data(struct bio *bio);

static inline void bio_hierarchy_end_io_acct(struct bio *bio,
					     enum stage_group stage)
{
	__bio_hierarchy_end_io_acct(bio, stage, blk_time_get_ns());
}

static inline void bio_list_hierarchy_end_io_acct(struct bio_list *list,
						  enum stage_group stage)
{
	u64 time = blk_time_get_ns();
	struct bio *bio;

	bio_list_for_each(bio, list)
		__bio_hierarchy_end_io_acct(bio, stage, time);
}

/* APIs for request based stage io accounting */
void blk_rq_hierarchy_stats_complete(struct request *rq);
void __rq_hierarchy_start_io_acct(struct request *rq,
				  struct hierarchy_stage *hstage);
void __rq_hierarchy_end_io_acct(struct request *rq,
				struct hierarchy_stage *hstage);

static inline void rq_hierarchy_start_io_acct(struct request *rq,
					      enum stage_group stage)
{
	if (!blk_mq_hierarchy_registered(rq->q, stage))
		return;

	__rq_hierarchy_start_io_acct(rq,
		queue_to_wrapper(rq->q)->io_hierarchy_stats->hstage[stage]);
}

static inline void rq_hierarchy_end_io_acct(struct request *rq,
					    enum stage_group stage)
{
	if (!blk_mq_hierarchy_registered(rq->q, stage))
		return;

	__rq_hierarchy_end_io_acct(rq,
		queue_to_wrapper(rq->q)->io_hierarchy_stats->hstage[stage]);
}

static inline void rq_list_hierarchy_start_io_acct(struct list_head *head,
						   enum stage_group stage)
{
	struct request *rq;
	struct hierarchy_stage *hstage;

	if (list_empty(head))
		return;

	rq = list_first_entry(head, struct request, queuelist);
	if (!blk_mq_hierarchy_registered(rq->q, stage))
		return;

	hstage = queue_to_wrapper(rq->q)->io_hierarchy_stats->hstage[stage];
	list_for_each_entry(rq, head, queuelist)
		__rq_hierarchy_start_io_acct(rq, hstage);
}

static inline void rq_list_hierarchy_end_io_acct(struct list_head *head,
						 enum stage_group stage)
{
	struct request *rq;
	struct hierarchy_stage *hstage;

	if (list_empty(head))
		return;

	rq = list_first_entry(head, struct request, queuelist);
	if (!blk_mq_hierarchy_registered(rq->q, stage))
		return;

	hstage = queue_to_wrapper(rq->q)->io_hierarchy_stats->hstage[stage];
	list_for_each_entry(rq, head, queuelist)
		__rq_hierarchy_end_io_acct(rq, hstage);
}

static inline void blk_rq_hierarchy_stats_init(struct request *rq)
{
	request_to_wrapper(rq)->stage = NR_RQ_STAGE_GROUPS;
	request_to_wrapper(rq)->flush_done = false;
}

static inline void blk_rq_hierarchy_set_flush_done(struct request *rq)
{
	request_to_wrapper(rq)->flush_done = true;
}

static inline bool blk_rq_hierarchy_is_flush_done(struct request *rq)
{
	return request_to_wrapper(rq)->flush_done;
}

#ifdef CONFIG_HIERARCHY_BIO
void bio_hierarchy_start(struct bio *bio);
void __bio_hierarchy_end(struct bio *bio, u64 now);

static inline void bio_hierarchy_end(struct bio *bio)
{
	if (!bio_flagged(bio, BIO_HIERARCHY_ACCT))
		return;

	if (!blk_mq_hierarchy_registered(bio->bi_disk->queue, STAGE_BIO))
		return;

	__bio_hierarchy_end(bio, blk_time_get_ns());
}

static inline void req_bio_hierarchy_end(struct request *rq, struct bio *bio)
{
	u64 now;

	if (!bio_flagged(bio, BIO_HIERARCHY_ACCT))
		return;

	if (!blk_mq_hierarchy_registered(bio->bi_disk->queue, STAGE_BIO))
		return;

	now = request_to_wrapper(rq)->io_end_time_ns;
	if (!now) {
		now = blk_time_get_ns();
		request_to_wrapper(rq)->io_end_time_ns = now;
	}

	__bio_hierarchy_end(bio, now);
}
#endif

#else /* CONFIG_BLK_IO_HIERARCHY_STATS */

static inline int
blk_io_hierarchy_stats_alloc(struct request_queue *q)
{
	return 0;
}

static inline void
blk_io_hierarchy_stats_free(struct request_queue *q)
{
}

static inline bool
blk_mq_hierarchy_registered(struct request_queue *q, enum stage_group stage)
{
	return false;
}

static inline void
blk_mq_register_hierarchy(struct request_queue *q, enum stage_group stage)
{
}

static inline void
blk_mq_unregister_hierarchy(struct request_queue *q, enum stage_group stage)
{
}

static inline void
blk_mq_debugfs_register_hierarchy_stats(struct request_queue *q)
{
}

static inline void
blk_mq_debugfs_register_hierarchy(struct request_queue *q,
				  enum stage_group stage)
{
}

static inline void
blk_mq_debugfs_unregister_hierarchy(struct request_queue *q,
				    enum stage_group stage)
{
}

static inline void
bio_hierarchy_start_io_acct(struct bio *bio, enum stage_group stage)
{
}

static inline void
bio_hierarchy_end_io_acct(struct bio *bio, enum stage_group stage)
{
}

static inline void
bio_list_hierarchy_end_io_acct(struct bio_list *list, enum stage_group stage)
{
}

static inline void
bio_free_hierarchy_data(struct bio *bio)
{
}

static inline void
blk_rq_hierarchy_set_flush_done(struct request *rq)
{
}

static inline bool
blk_rq_hierarchy_is_flush_done(struct request *rq)
{
	return false;
}

static inline void
blk_rq_hierarchy_stats_complete(struct request *rq)
{
}

static inline void
rq_hierarchy_start_io_acct(struct request *rq, enum stage_group stage)
{
}

static inline void
rq_hierarchy_end_io_acct(struct request *rq, enum stage_group stage)
{
}

static inline void
rq_list_hierarchy_start_io_acct(struct list_head *head, enum stage_group stage)
{
}

static inline void
rq_list_hierarchy_end_io_acct(struct list_head *head, enum stage_group stage)
{
}

static inline void
blk_rq_hierarchy_stats_init(struct request *rq)
{
}

#endif /* CONFIG_BLK_IO_HIERARCHY_STATS */

#if !defined(CONFIG_BLK_IO_HIERARCHY_STATS) || !defined(CONFIG_HIERARCHY_BIO)
static inline void
bio_hierarchy_start(struct bio *bio)
{
}

static inline void
bio_hierarchy_end(struct bio *bio)
{
}

static inline void
req_bio_hierarchy_end(struct request *rq, struct bio *bio)
{
}
#endif

#endif /* BLK_IO_HIERARCHY_STATS_H */
