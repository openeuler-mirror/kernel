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

#include <linux/module.h>
#include <linux/debugfs.h>

#include "stats.h"
#include "iodump.h"
#include "../blk.h"
#include "../blk-mq-debugfs.h"

#define io_hierarchy_add(statsp, field, group, nr) \
	this_cpu_add((statsp)->hstats->field[group], nr)
#define io_hierarchy_inc(statsp, field, group) \
	io_hierarchy_add(statsp, field, group, 1)

#define PRE_ALLOC_BIO_CNT 8

static mempool_t *hdata_pool;

void blk_mq_debugfs_register_hierarchy_stats(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats;
	enum stage_group stage;

	lockdep_assert_held(&q->debugfs_mutex);

	stats = queue_to_wrapper(q)->io_hierarchy_stats;
	if (!stats || !blk_mq_debugfs_enabled(q))
		return;

	stats->debugfs_dir = debugfs_create_dir("blk_io_hierarchy",
						q->debugfs_dir);
	blk_mq_debugfs_create_default_hierarchy_attr(q);

	for (stage = 0; stage < NR_STAGE_GROUPS; ++stage)
		blk_mq_debugfs_register_hierarchy(q, stage);
}

static void bio_alloc_hierarchy_data(struct bio *bio)
{
	if (!bio->hdata) {
		struct bio_hierarchy_data *hdata =
					mempool_alloc(hdata_pool, GFP_NOIO);

		bio_hierarchy_data_init(bio, hdata);
		bio->hdata = hdata;
	}
}

void bio_free_hierarchy_data(struct bio *bio)
{
	if (!bio->hdata)
		return;

	mempool_free(bio->hdata, hdata_pool);
	bio->hdata = NULL;
}

int blk_io_hierarchy_stats_alloc(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats;

	if (!q->mq_ops)
		return 0;

	stats = kzalloc(sizeof(struct blk_io_hierarchy_stats), GFP_KERNEL);
	if (!stats)
		return -ENOMEM;

	spin_lock_init(&stats->hstage_lock);
	stats->q = q;
	queue_to_wrapper(q)->io_hierarchy_stats = stats;

	return 0;
}

void blk_io_hierarchy_stats_free(struct request_queue *q)
{
	struct blk_io_hierarchy_stats *stats =
		queue_to_wrapper(q)->io_hierarchy_stats;

	if (!stats)
		return;

	queue_to_wrapper(q)->io_hierarchy_stats = NULL;
	kfree(stats);
}

bool blk_mq_hierarchy_registered(struct request_queue *q,
				 enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats =
		queue_to_wrapper(q)->io_hierarchy_stats;

	if (!stats)
		return false;

	return stats->hstage[stage] != NULL;
}
EXPORT_SYMBOL_GPL(blk_mq_hierarchy_registered);

static struct hierarchy_stats_data *alloc_hstats_data(void)
{
	struct hierarchy_stats_data *hstats_data;

	hstats_data = kmalloc(sizeof(*hstats_data), GFP_KERNEL);
	if (!hstats_data)
		return NULL;

	hstats_data->hstats = alloc_percpu(struct hierarchy_stats);
	if (!hstats_data->hstats) {
		kfree(hstats_data);
		return NULL;
	}

	hstats_data->ref = 1;
	return hstats_data;
}

struct hierarchy_stats_data *get_hstats_data(
		struct blk_io_hierarchy_stats *stats,
		enum stage_group stage)
{
	struct hierarchy_stage *hstage;
	struct hierarchy_stats_data *hstats_data = NULL;

	spin_lock(&stats->hstage_lock);
	hstage = stats->hstage[stage];
	if (hstage) {
		hstats_data = hstage->hstats_data;
		if (hstats_data)
			hstats_data->ref++;
	}
	spin_unlock(&stats->hstage_lock);

	return hstats_data;
}

static void __put_hstats_data(struct blk_io_hierarchy_stats *stats,
			      struct hierarchy_stats_data *hstats_data)
{
	if (--hstats_data->ref == 0) {
		free_percpu(hstats_data->hstats);
		kfree(hstats_data);
	}
}

void put_hstats_data(struct blk_io_hierarchy_stats *stats,
		     struct hierarchy_stats_data *hstats_data)
{
	spin_lock(&stats->hstage_lock);
	__put_hstats_data(stats, hstats_data);
	spin_unlock(&stats->hstage_lock);
}

void blk_mq_register_hierarchy(struct request_queue *q, enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats =
		queue_to_wrapper(q)->io_hierarchy_stats;
	struct hierarchy_stage *hstage;

	if (!stats || !hierarchy_stage_name(stage))
		return;

	if (blk_mq_hierarchy_registered(q, stage)) {
		pr_warn("blk-io-hierarchy: disk %s is registering stage %s again.",
			kobject_name(q->kobj.parent),
			hierarchy_stage_name(stage));
		return;
	}

	/*
	 * Alloc memory before freeze queue, prevent deadlock if new IO is
	 * issued by memory reclaim.
	 */
	hstage = kmalloc(sizeof(*hstage), GFP_KERNEL);
	if (!hstage)
		return;

	hstage->hstats_data = alloc_hstats_data();
	if (!hstage->hstats_data) {
		kfree(hstage);
		return;
	}

	hstage->stage = stage;
	hstage->unbalanced_warned = false;
	hstage->debugfs_dir = NULL;
	if (blk_io_hierarchy_iodump_init(q, hstage) < 0) {
		put_hstats_data(stats, hstage->hstats_data);
		kfree(hstage);
		return;
	}

	blk_mq_freeze_queue(q);

	mutex_lock(&q->debugfs_mutex);
	WRITE_ONCE(stats->hstage[stage], hstage);
	blk_mq_debugfs_register_hierarchy(q, stage);
	mutex_unlock(&q->debugfs_mutex);

	blk_mq_unfreeze_queue(q);
}
EXPORT_SYMBOL_GPL(blk_mq_register_hierarchy);

void blk_mq_unregister_hierarchy(struct request_queue *q,
				 enum stage_group stage)
{
	struct blk_io_hierarchy_stats *stats =
		queue_to_wrapper(q)->io_hierarchy_stats;
	struct hierarchy_stage *hstage;

	if (!blk_mq_hierarchy_registered(q, stage))
		return;

	mutex_lock(&q->debugfs_mutex);

	blk_mq_debugfs_unregister_hierarchy(q, stage);
	blk_io_hierarchy_iodump_exit(q, stage);

	spin_lock(&stats->hstage_lock);
	hstage = stats->hstage[stage];
	stats->hstage[stage] = NULL;
	__put_hstats_data(stats, hstage->hstats_data);
	spin_unlock(&stats->hstage_lock);

	kfree(hstage);

	mutex_unlock(&q->debugfs_mutex);
}
EXPORT_SYMBOL_GPL(blk_mq_unregister_hierarchy);

static enum stat_group bio_hierarchy_op(struct bio *bio)
{
	if (op_is_discard(bio->bi_opf))
		return STAT_DISCARD;

	if (op_is_flush(bio->bi_opf) &&
	    !(bio_sectors(bio) || (bio->bi_opf & REQ_HAS_DATA)))
		return STAT_FLUSH;

	if (op_is_write(bio->bi_opf))
		return STAT_WRITE;

	return STAT_READ;
}


void bio_hierarchy_start_io_acct(struct bio *bio, enum stage_group stage)
{
	struct request_queue *q = bio->bi_disk->queue;
	struct hierarchy_stage *hstage;

	if (!blk_mq_hierarchy_registered(q, stage))
		return;

	hstage = queue_to_wrapper(q)->io_hierarchy_stats->hstage[stage];
	bio_alloc_hierarchy_data(bio);
	io_hierarchy_inc(hstage->hstats_data, dispatched,
			 bio_hierarchy_op(bio));
	bio->hdata->time = blk_time_get_ns();
	hierarchy_add_bio(hstage, bio);
}

void __bio_hierarchy_end_io_acct(struct bio *bio, enum stage_group stage,
				 u64 time)
{
	struct request_queue *q = bio->bi_disk->queue;
	struct hierarchy_stage *hstage;
	u64 duration;
	enum stat_group op;

	if (!blk_mq_hierarchy_registered(q, stage))
		return;

	op = bio_hierarchy_op(bio);
	duration = time - bio->hdata->time;
	hstage = queue_to_wrapper(q)->io_hierarchy_stats->hstage[stage];

	hierarchy_remove_bio(hstage, bio);
	io_hierarchy_inc(hstage->hstats_data, completed, op);
	io_hierarchy_add(hstage->hstats_data, nsecs, op, duration);
	hierarchy_account_slow_io_ns(hstage, op, duration);
}

static enum stat_group rq_hierarchy_op(struct request *rq)
{
	if (op_is_discard(rq->cmd_flags))
		return STAT_DISCARD;

	if (is_flush_rq(rq))
		return STAT_FLUSH;

	if (op_is_write(rq->cmd_flags))
		return STAT_WRITE;

	return STAT_READ;
}

static void rq_hierarchy_warn_unbalanced(struct request *rq,
					 struct hierarchy_stage *hstage,
					 enum stage_group old_stage,
					 enum stage_group new_stage)
{
	if (hstage->unbalanced_warned)
		return;

	pr_warn("blk-io-hierarchy: disk %s stage %d(%s) -> %d(%s) unbalanced accounting.",
		kobject_name(rq->q->kobj.parent),
		old_stage, hierarchy_stage_name(old_stage),
		new_stage, hierarchy_stage_name(new_stage));
	hstage->unbalanced_warned = true;
}

void blk_rq_hierarchy_stats_complete(struct request *rq)
{
	struct hierarchy_stage *hstage;
	enum stage_group stage;

	stage = request_to_wrapper(rq)->stage;
	if (stage == NR_RQ_STAGE_GROUPS)
		return;

	if (!blk_mq_hierarchy_registered(rq->q, stage))
		return;

	hstage = queue_to_wrapper(rq->q)->io_hierarchy_stats->hstage[stage];
	rq_hierarchy_warn_unbalanced(rq, hstage, stage, NR_RQ_STAGE_GROUPS);
	__rq_hierarchy_end_io_acct(rq, hstage);
}

void __rq_hierarchy_start_io_acct(struct request *rq,
				  struct hierarchy_stage *hstage)
{
	struct request_wrapper *rq_wrapper = request_to_wrapper(rq);

	blk_rq_hierarchy_stats_complete(rq);
	io_hierarchy_inc(hstage->hstats_data, dispatched, rq_hierarchy_op(rq));
	WRITE_ONCE(rq_wrapper->hierarchy_time, jiffies);

	/*
	 * Paired with barrier in hierarchy_show_rq_fn(), make sure
	 * hierarchy_time is set before stage.
	 */
	smp_store_release(&rq_wrapper->stage, hstage->stage);
}
EXPORT_SYMBOL_GPL(__rq_hierarchy_start_io_acct);

void __rq_hierarchy_end_io_acct(struct request *rq,
				struct hierarchy_stage *hstage)
{
	enum stat_group op;
	unsigned long duration;
	struct request_wrapper *rq_wrapper;

	rq_wrapper = request_to_wrapper(rq);
	if (rq_wrapper->stage != hstage->stage) {
		rq_hierarchy_warn_unbalanced(rq, hstage, rq_wrapper->stage,
					     hstage->stage);
		return;
	}

	op = rq_hierarchy_op(rq);
	duration = jiffies - rq_wrapper->hierarchy_time;

	io_hierarchy_inc(hstage->hstats_data, completed, op);
	io_hierarchy_add(hstage->hstats_data, jiffies, op, duration);
	hierarchy_account_slow_io_jiffies(hstage, op, duration);
	WRITE_ONCE(rq_wrapper->stage, NR_RQ_STAGE_GROUPS);
}
EXPORT_SYMBOL_GPL(__rq_hierarchy_end_io_acct);

#ifdef CONFIG_HIERARCHY_BIO
void bio_hierarchy_start(struct bio *bio)
{
	struct request_queue_wrapper *q_wrapper;
	struct gendisk *disk = bio->bi_disk;
	struct hierarchy_stage *hstage;

	if (bio_flagged(bio, BIO_HIERARCHY_ACCT))
		return;

	if (!blk_mq_hierarchy_registered(disk->queue, STAGE_BIO))
		return;

	bio_set_flag(bio, BIO_HIERARCHY_ACCT);
	if (bio_has_data(bio))
		bio->bi_opf |= REQ_HAS_DATA;
	q_wrapper = queue_to_wrapper(disk->queue);
	hstage = q_wrapper->io_hierarchy_stats->hstage[STAGE_BIO];
	io_hierarchy_inc(hstage->hstats_data, dispatched,
			 bio_hierarchy_op(bio));
}

void __bio_hierarchy_end(struct bio *bio, u64 now)
{
	struct request_queue_wrapper *q_wrapper;
	struct gendisk *disk = bio->bi_disk;
	struct hierarchy_stage *hstage;
	enum stat_group op;
	u64 duration;

	op = bio_hierarchy_op(bio);
	duration = now - bio->bi_alloc_time_ns;
	q_wrapper = queue_to_wrapper(disk->queue);
	hstage = q_wrapper->io_hierarchy_stats->hstage[STAGE_BIO];

	io_hierarchy_inc(hstage->hstats_data, completed, op);
	io_hierarchy_add(hstage->hstats_data, nsecs, op, duration);
	hierarchy_account_slow_io_ns(hstage, op, duration);

	bio_clear_flag(bio, BIO_HIERARCHY_ACCT);
	bio->bi_opf &= ~REQ_HAS_DATA;
}
#endif

static int __init hierarchy_stats_init(void)
{
	hdata_pool = mempool_create_kmalloc_pool(PRE_ALLOC_BIO_CNT,
			sizeof(struct bio_hierarchy_data));
	if (!hdata_pool)
		panic("Failed to create hdata_pool\n");

	return 0;
}
module_init(hierarchy_stats_init);
