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

#include <linux/seq_file.h>
#include <linux/blktrace_api.h>
#include <linux/blk-cgroup.h>
#include <linux/sched/task.h>

#include "iodump.h"
#include "../blk.h"
#include "../blk-mq-debugfs.h"

#define RWB_LEN 6
#define PATH_LEN 64
#define ms_to_ns(time) (time * NSEC_PER_MSEC)
#define DEFAULT_THRESHOLD 1000

static DEFINE_MUTEX(dump_mutex);

struct bio_dump_data {
	u64 stat_time;
	struct list_head head;
	spinlock_t lock;
};

struct rq_dump_data {
	struct request_queue *q;
	enum stage_group stage;
	unsigned int tag;
	unsigned int total_tags;
	bool has_elevator;
	bool enter_queue;
};

int blk_io_hierarchy_iodump_init(struct request_queue *q,
				 struct hierarchy_stage *hstage)
{
	hstage->threshold = DEFAULT_THRESHOLD;

	if (stage_is_bio(hstage->stage)) {
		struct bio_dump_data *bio_ddata =
			kmalloc(sizeof(*bio_ddata), GFP_KERNEL);

		if (!bio_ddata)
			return -ENOMEM;

		INIT_LIST_HEAD(&bio_ddata->head);
		spin_lock_init(&bio_ddata->lock);
		hstage->dump_data = bio_ddata;
		return 0;
	}

	if (stage_is_rq(hstage->stage)) {
		struct rq_dump_data *rq_ddata =
			kzalloc(sizeof(*rq_ddata), GFP_KERNEL);

		if (!rq_ddata)
			return -ENOMEM;

		rq_ddata->q = q;
		rq_ddata->stage = hstage->stage;
		hstage->dump_data = rq_ddata;
		return 0;
	}

	return -EINVAL;
}

void blk_io_hierarchy_iodump_exit(struct request_queue *q,
				  enum stage_group stage)
{
	struct hierarchy_stage *hstage =
		queue_to_wrapper(q)->io_hierarchy_stats->hstage[stage];

	if (stage_is_bio(hstage->stage)) {
		struct bio_dump_data *bio_ddata = hstage->dump_data;

		WARN(!list_empty(&bio_ddata->head),
		     "blk-io-hierarchy: disk %s stage %s unregistered whih throttled IO.\n",
		     kobject_name(q->kobj.parent), hierarchy_stage_name(stage));
	}

	kfree(hstage->dump_data);
	hstage->dump_data = NULL;
}

void hierarchy_add_bio(struct hierarchy_stage *hstage, struct bio *bio)
{
	unsigned long flags;
	struct bio_hierarchy_data *data = bio->hdata;
	struct bio_dump_data *bio_ddata = hstage->dump_data;

	spin_lock_irqsave(&bio_ddata->lock, flags);
	list_add_tail(&data->hierarchy_list, &bio_ddata->head);
	spin_unlock_irqrestore(&bio_ddata->lock, flags);
}

void hierarchy_remove_bio(struct hierarchy_stage *hstage, struct bio *bio)
{
	unsigned long flags;
	struct bio_hierarchy_data *data = bio->hdata;
	struct bio_dump_data *bio_ddata = hstage->dump_data;

	spin_lock_irqsave(&bio_ddata->lock, flags);
	list_del_init(&data->hierarchy_list);
	spin_unlock_irqrestore(&bio_ddata->lock, flags);
}

void bio_hierarchy_data_init(struct bio *bio, struct bio_hierarchy_data *hdata)
{
	hdata->bio = bio;
	INIT_LIST_HEAD(&hdata->hierarchy_list);
}

static void *bio_hierarchy_list_start(struct seq_file *m, loff_t *pos)
	 __acquires(&bio_ddata->lock)
{
	struct hierarchy_stage *hstage = m->private;
	struct bio_dump_data *bio_ddata = hstage->dump_data;

	spin_lock_irq(&bio_ddata->lock);
	bio_ddata->stat_time = blk_time_get_ns();

	return seq_list_start(&bio_ddata->head, *pos);
}

static void *bio_hierarchy_list_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct hierarchy_stage *hstage = m->private;
	struct bio_dump_data *bio_ddata = hstage->dump_data;

	return seq_list_next(v, &bio_ddata->head, pos);
}

static void bio_hierarchy_list_stop(struct seq_file *m, void *v)
	__releases(&hstage->lock)
{
	struct hierarchy_stage *hstage = m->private;
	struct bio_dump_data *bio_ddata = hstage->dump_data;

	spin_unlock_irq(&bio_ddata->lock);
}

static void __hierarchy_show_bio(struct seq_file *m,
				 struct bio_hierarchy_data *data,
				 enum stage_group stage, u64 duration)
{
	char rwbs[RWB_LEN];
	char path[PATH_LEN] = {0};
	struct bio *bio = data->bio;
	struct task_struct *task = get_pid_task(bio->pid, PIDTYPE_PID);

	blk_fill_rwbs(rwbs, bio->bi_opf, bio->bi_iter.bi_size);
#ifdef CONFIG_BLK_CGROUP
	cgroup_path(bio->bi_css->cgroup, path, PATH_LEN);
#endif

	seq_printf(m, "%s-%d %s stage %s bio %s %lu + %u cgroup %s started %llu ns ago\n",
		   task ? task->comm : "null", task ? task->pid : 0,
		   bio->bi_disk->disk_name, hierarchy_stage_name(stage),
		   rwbs, bio->bi_iter.bi_sector, bio_sectors(bio), path,
		   duration);

	if (task)
		put_task_struct(task);
}

static u64 get_duration(u64 a, u64 b)
{
	return a > b ? a - b : 0;
}

static void hierarchy_show_bio(struct seq_file *m,
			       struct bio_hierarchy_data *data)
{
	u64 duration;
	struct hierarchy_stage *hstage = m->private;
	struct bio_dump_data *bio_ddata = hstage->dump_data;

	duration = get_duration(bio_ddata->stat_time, data->time);
	if (hstage->threshold > ns_to_ms(duration))
		return;

	__hierarchy_show_bio(m, data, hstage->stage, duration);
}

static int bio_hierarchy_list_show(struct seq_file *m, void *v)
{
	struct bio_hierarchy_data *data =
		list_entry(v, struct bio_hierarchy_data, hierarchy_list);

	hierarchy_show_bio(m, data);
	return 0;
}

static const struct seq_operations hierarchy_bio_dump_ops = {
	.start	= bio_hierarchy_list_start,
	.next	= bio_hierarchy_list_next,
	.stop	= bio_hierarchy_list_stop,
	.show	= bio_hierarchy_list_show,
};

static int threshold_show(void *data, struct seq_file *m)
{
	struct hierarchy_stage *hstage = data;

	seq_printf(m, "%lu\n", hstage->threshold);
	return 0;
}

/*
 * max size needed by different bases to express U64
 * HEX: "0xFFFFFFFFFFFFFFFF" --> 18
 * DEC: "18446744073709551615" --> 20
 * OCT: "01777777777777777777777" --> 23
 * pick the max one to define NUMBER_BUF_LEN
 */
#define MAX_BUF_LEN 24
static ssize_t threshold_store(void *data, const char __user *buf, size_t count,
			       loff_t *ppos)
{
	int err;
	unsigned long val;
	char b[MAX_BUF_LEN + 1];
	struct hierarchy_stage *hstage = data;

	if (count > MAX_BUF_LEN)
		return -EINVAL;

	if (copy_from_user(b, buf, count))
		return -EFAULT;

	b[count] = 0;
	err = kstrtoul(b, 0, &val);
	if (!err)
		hstage->threshold = val;

	return err ? err : count;
}

static void rq_hierarchy_init_dump_data(struct rq_dump_data *rq_ddata)
{
	struct request_queue *q = rq_ddata->q;

	rq_ddata->has_elevator = !!q->elevator;

	if (rq_ddata->has_elevator)
		rq_ddata->total_tags = q->nr_hw_queues * q->nr_requests;
	else
		rq_ddata->total_tags = q->nr_hw_queues *
				       q->tag_set->queue_depth;
}

static bool __rq_hierarchy_start(struct rq_dump_data *rq_ddata,
				 unsigned int tag)
{
	/*
	 * Grab .q_usage_counter so request pool won't go away, then no
	 * request use-after-free is possible during iteration. If queue is
	 * frozen, there won't be any inflight requests.
	 */
	if (!percpu_ref_tryget(&rq_ddata->q->q_usage_counter)) {
		rq_ddata->enter_queue = false;
		return false;
	}

	rq_ddata->enter_queue = true;
	rq_hierarchy_init_dump_data(rq_ddata);
	rq_ddata->tag = tag;

	return tag < rq_ddata->total_tags + rq_ddata->q->nr_hw_queues;
}

static bool __rq_hierarchy_next(struct rq_dump_data *rq_ddata)
{
	rq_ddata->tag++;

	return rq_ddata->tag < rq_ddata->total_tags + rq_ddata->q->nr_hw_queues;
}

static void __rq_hierarchy_stop(struct rq_dump_data *rq_ddata)
{
	if (rq_ddata->enter_queue) {
		percpu_ref_put(&rq_ddata->q->q_usage_counter);
		rq_ddata->enter_queue = false;
	}
}

static void *rq_hierarchy_start(struct seq_file *m, loff_t *pos)
	 __acquires(&dump_mutex)
{
	struct hierarchy_stage *hstage = m->private;
	struct rq_dump_data *rq_ddata = hstage->dump_data;

	mutex_lock(&dump_mutex);

	if (__rq_hierarchy_start(rq_ddata, *pos))
		return rq_ddata;

	return NULL;
}

static void *rq_hierarchy_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct rq_dump_data *rq_ddata = v;

	if (__rq_hierarchy_next(rq_ddata)) {
		*pos = rq_ddata->tag;
		return rq_ddata;
	}

	(*pos)++;
	return NULL;
}

static void rq_hierarchy_stop(struct seq_file *m, void *v)
	__releases(&dump_mutex)
{
	struct hierarchy_stage *hstage = m->private;
	struct rq_dump_data *rq_ddata = hstage->dump_data;

	__rq_hierarchy_stop(rq_ddata);
	mutex_unlock(&dump_mutex);
}

static struct request *hierarchy_find_and_get_rq(struct rq_dump_data *rq_ddata)
{
	struct request *rq;
	struct request_wrapper *rq_wrapper;
	struct blk_mq_hw_ctx *hctx;
	struct request_queue *q = rq_ddata->q;
	unsigned int nr_tag = rq_ddata->tag;
	unsigned int hctx_id;

	if (nr_tag >= rq_ddata->total_tags) {
		hctx_id = nr_tag - rq_ddata->total_tags;
		if (hctx_id >= q->nr_hw_queues)
			return NULL;

		hctx = q->queue_hw_ctx[hctx_id];
		rq = hctx->fq->flush_rq;
	} else if (rq_ddata->has_elevator) {
		hctx_id = nr_tag / q->nr_requests;
		if (hctx_id >= q->nr_hw_queues)
			return NULL;

		hctx = q->queue_hw_ctx[hctx_id];
		rq = hctx->sched_tags->static_rqs[nr_tag % q->nr_requests];
	} else {
		hctx_id = nr_tag / q->tag_set->queue_depth;
		if (hctx_id >= q->nr_hw_queues)
			return NULL;

		hctx = q->queue_hw_ctx[hctx_id];
		if (!hctx->tags)
			return NULL;

		rq = hctx->tags->static_rqs[nr_tag % q->tag_set->queue_depth];
	}

	rq_wrapper = request_to_wrapper(rq);
	/*
	 * fast path to avoid refcount cas operations for the request that
	 * is from other shared request_queue or other stages.
	 */
	if (rq->q != q || READ_ONCE(rq_wrapper->stage) != rq_ddata->stage)
		return NULL;

	if (!refcount_inc_not_zero(&rq->ref))
		return NULL;

	/* Check again after request is pinned, in case request is resued. */
	if (rq->q != q) {
		blk_mq_put_rq_ref(rq);
		return NULL;
	}

	/*
	 * Barrier is paired with the smp_store_release() in
	 * rq_hierarchy_start_io_acct(), so that if stage is read, uninitialized
	 * hierarchy_time won't be read.
	 */
	if (smp_load_acquire(&rq_wrapper->stage) != rq_ddata->stage) {
		blk_mq_put_rq_ref(rq);
		return NULL;
	}

	return rq;
}

static void hierarchy_show_rq(struct seq_file *m, struct request *rq,
			      u64 duration)
{
	struct request_wrapper *rq_wrapper = request_to_wrapper(rq);
	struct task_struct *task = get_pid_task(rq_wrapper->pid, PIDTYPE_PID);
	const char *name = hierarchy_stage_name(rq_wrapper->stage);

	seq_printf(m, "%s-%d %s stage %s ", task ? task->comm : "null",
		   task ? task->pid : 0,
		   rq->rq_disk ? rq->rq_disk->disk_name : "?",
		   name ? name : "?");
	debugfs_rq_show(m, rq);
	seq_printf(m, " started %llu ns ago}\n", duration);

	if (task)
		put_task_struct(task);
}

static int rq_hierarchy_show(struct seq_file *m, void *v)
{
	u64 duration;
	unsigned long htime;
	struct hierarchy_stage *hstage = m->private;
	struct request_wrapper *rq_wrapper;
	struct request *rq = hierarchy_find_and_get_rq(v);

	if (!rq)
		return 0;

	rq_wrapper = request_to_wrapper(rq);
	htime = READ_ONCE(rq_wrapper->hierarchy_time);
	htime = time_after(jiffies, htime) ? jiffies - htime : 0;
	duration = jiffies_to_msecs(htime);
	if (hstage->threshold <= duration)
		hierarchy_show_rq(m, rq, ms_to_ns(duration));

	blk_mq_put_rq_ref(rq);
	return 0;
}

static const struct seq_operations hierarchy_rq_dump_ops = {
	.start	= rq_hierarchy_start,
	.next	= rq_hierarchy_next,
	.stop	= rq_hierarchy_stop,
	.show	= rq_hierarchy_show,
};

static const struct blk_mq_debugfs_attr hierarchy_threshold_attr[] = {
	{
		"threshold",
		0600,
		threshold_show,
		threshold_store,
	},
	{},
};

static const struct blk_mq_debugfs_attr hierarchy_bio_dump_attr[] = {
	{
		"io_dump",
		0400,
		.seq_ops = &hierarchy_bio_dump_ops,
	},
	{},
};

static const struct blk_mq_debugfs_attr hierarchy_rq_dump_attr[] = {
	{
		"io_dump",
		0400,
		.seq_ops = &hierarchy_rq_dump_ops,
	},
	{},
};

void io_hierarchy_register_iodump(struct hierarchy_stage *hstage)
{
	const struct blk_mq_debugfs_attr *attr;

	if (stage_is_bio(hstage->stage))
		attr = hierarchy_bio_dump_attr;
	else if (stage_is_rq(hstage->stage))
		attr = hierarchy_rq_dump_attr;
	else
		attr = NULL;

	debugfs_create_files(hstage->debugfs_dir, hstage,
			     hierarchy_threshold_attr);
	if (attr)
		debugfs_create_files(hstage->debugfs_dir, hstage, attr);
}

void hierarchy_account_slow_io(struct hierarchy_stage *hstage,
			       enum stat_group op, unsigned long duration)
{
	if (hstage->threshold <= duration)
		this_cpu_inc(hstage->hstats_data->hstats->slow[op]);
}

void hierarchy_show_slow_io(struct hierarchy_stats_data *hstats_data,
			    struct seq_file *m)
{
	u64 slow[NR_NEW_STAT_GROUPS] = {0};
	int cpu;
	int i;

	for_each_possible_cpu(cpu) {
		struct hierarchy_stats *stat =
			per_cpu_ptr(hstats_data->hstats, cpu);

		for (i = 0; i < NR_NEW_STAT_GROUPS; ++i)
			slow[i] += stat->slow[i];
	}

	seq_printf(m, " %llu %llu %llu %llu", slow[STAT_READ], slow[STAT_WRITE],
		   slow[STAT_DISCARD], slow[STAT_FLUSH]);
}
