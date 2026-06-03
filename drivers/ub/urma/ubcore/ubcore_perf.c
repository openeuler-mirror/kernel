// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: uburma global latency tracer – per-type, per-CPU, low overhead
 * Author: Perf module
 * Create: 2026-05-12
 * Note: No per-process tracking, global aggregation only.
 * History: 2026-05-12 Create file
 */

#include <linux/log2.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "ub/urma/ubcore_perf.h"

// Control sampling range（1ns ~ 4s）
#define UBCORE_PERF_BUCKET_SHIFT        32
// Control sampling precision（1/2^6）
#define UBCORE_PERF_SUB_BUCKET_SHIFT        6
#define UBCORE_PERF_SUB_BUCKETS  (1 << UBCORE_PERF_SUB_BUCKET_SHIFT)
#define UBCORE_PERF_BUCKETS          (UBCORE_PERF_BUCKET_SHIFT * UBCORE_PERF_SUB_BUCKETS)

struct ub_perf_latency_record {
	u64 count;
	u64 sum_ns;
	u64 min_ns;
	u64 max_ns;
	u64 buckets[UBCORE_PERF_BUCKETS];
	u32 version;
};
struct ub_perf_latency_cpu_ctx {
	struct ub_perf_latency_record perf_table[PERF_RECORD_TYPE_MAX];
} ____cacheline_aligned;
static bool ub_perf_status;
static u32 global_version = 1;
static DEFINE_SPINLOCK(version_lock);
static DEFINE_PER_CPU(struct ub_perf_latency_cpu_ctx *, perf_cpu_ctx_ptr);

/**
 * latence_idx = log2(delta_ns) * UBCORE_PERF_SUB_BUCKETS +
 * (latency_offset / (log2(delta_ns) * UBCORE_PERF_SUB_BUCKETS) *
 * UBCORE_PERF_SUB_BUCKETS)
 */
static u32 perf_get_bucket(u64 delta_ns)
{
	u32 latency_idx, sub_bucket_idx, bucket_base_idx, bucket_shift;
	u64 latency_offset;

	if (delta_ns == 0)
		return 0;
	bucket_shift = ilog2(delta_ns);
	bucket_base_idx = (u32)bucket_shift * UBCORE_PERF_SUB_BUCKETS;
	latency_offset = delta_ns - (1ULL << bucket_shift);
	// represents latency_offset divided by 64
	if (unlikely(bucket_base_idx >= UBCORE_PERF_BUCKETS))
		return UBCORE_PERF_BUCKETS - 1;
	if (bucket_shift >= UBCORE_PERF_SUB_BUCKET_SHIFT)
		sub_bucket_idx = (u32)(latency_offset >>
				       (bucket_shift - UBCORE_PERF_SUB_BUCKET_SHIFT));
	else
		sub_bucket_idx = (u32)(latency_offset <<
				       (UBCORE_PERF_SUB_BUCKET_SHIFT - bucket_shift));
	sub_bucket_idx &= (UBCORE_PERF_SUB_BUCKETS - 1);
	latency_idx = bucket_base_idx + sub_bucket_idx;

	if (latency_idx >= UBCORE_PERF_BUCKETS)
		return UBCORE_PERF_BUCKETS - 1;
	return latency_idx;
}
/**
 *   exp = bucket / 64, sub = bucket % 64，
 *   low = 2^exp + (2^exp * sub) / 64
 *   The return value represents the nanoseconds corresponding to the bucket index.
 */
static inline u64 bucket_low_bound(u32 bucket)
{
	u32 exp;
	u32 sub;
	u64 base;

	if (bucket == 0)
		return 0;

	exp = bucket >> UBCORE_PERF_SUB_BUCKET_SHIFT;
	sub = bucket & (UBCORE_PERF_SUB_BUCKETS - 1);
	base = 1ULL << exp;

	return base + ((base * sub) >> UBCORE_PERF_SUB_BUCKET_SHIFT);
}

static void record_reset(struct ub_perf_latency_record *record, u32 version)
{
	record->count = 0;
	record->sum_ns = 0;
	record->min_ns = U64_MAX;
	record->max_ns = 0;
	memset(record->buckets, 0, sizeof(record->buckets));
	record->version = version;
}

static void record_update(struct ub_perf_latency_record *record, u64 delta_ns)
{
	u32 record_idx = perf_get_bucket(delta_ns);

	record->count++;
	record->sum_ns += delta_ns;
	if (delta_ns < record->min_ns)
		record->min_ns = delta_ns;
	if (delta_ns > record->max_ns)
		record->max_ns = delta_ns;
	record->buckets[record_idx]++;
}

void ubcore_perf_start(void)
{

	WRITE_ONCE(ub_perf_status, true);

	spin_lock(&version_lock);
	global_version++;
	spin_unlock(&version_lock);
}
EXPORT_SYMBOL(ubcore_perf_start);
void ubcore_perf_stop(void)
{
	WRITE_ONCE(ub_perf_status, false);
}
EXPORT_SYMBOL(ubcore_perf_stop);

void ubcore_perf_record(u32 record_type, u64 delta_ns)
{
	struct ub_perf_latency_cpu_ctx *context;
	struct ub_perf_latency_record *record;
	u32 version;

	if (!READ_ONCE(ub_perf_status))
		return;
	if (unlikely(record_type >= PERF_RECORD_TYPE_MAX))
		return;

	context = this_cpu_read(perf_cpu_ctx_ptr);
	if (unlikely(!context))
		return;

	record = &context->perf_table[record_type];
	version = READ_ONCE(global_version);

	if (record->version != version)
		record_reset(record, version);

	record_update(record, delta_ns);
}
EXPORT_SYMBOL(ubcore_perf_record);

static void ubcore_perf_aggregate_all_cpus(struct ub_perf_latency_record agg[],
			       u32 version)
{
	int online_cpu;
	u32 record_type_idx;

	memset(agg, 0, sizeof(*agg) * PERF_RECORD_TYPE_MAX);
	for (record_type_idx = 0;
	     record_type_idx < PERF_RECORD_TYPE_MAX;
	     record_type_idx++) {
		agg[record_type_idx].min_ns = U64_MAX;
		agg[record_type_idx].version = version;
	}

	for_each_online_cpu(online_cpu) {
		struct ub_perf_latency_cpu_ctx *ctx = per_cpu(perf_cpu_ctx_ptr, online_cpu);

		if (!ctx)
			continue;
		for (record_type_idx = 0;
		     record_type_idx < PERF_RECORD_TYPE_MAX;
		     record_type_idx++) {
			const struct ub_perf_latency_record *rec =
				&ctx->perf_table[record_type_idx];
			if (rec->version != version)
				continue;

			agg[record_type_idx].count  += rec->count;
			agg[record_type_idx].sum_ns += rec->sum_ns;
			if (rec->min_ns < agg[record_type_idx].min_ns)
				agg[record_type_idx].min_ns = rec->min_ns;
			if (rec->max_ns > agg[record_type_idx].max_ns)
				agg[record_type_idx].max_ns = rec->max_ns;
			for (int i = 0; i < UBCORE_PERF_BUCKETS; i++)
				agg[record_type_idx].buckets[i] += rec->buckets[i];
		}
	}
}

static u64 ubcore_perf_cal_bucket_latency(u32 bucket_idx,
					   u64 bucket_base_sample,
					   u64 bucket_sample_offset)
{
	u64 low = bucket_low_bound(bucket_idx);
	u64 high;

	high = bucket_low_bound(bucket_idx + 1);
	if (bucket_base_sample == 0)
		return low;
	/* uniform difference within a bucket */
	return low + bucket_sample_offset * (high - low) / bucket_base_sample;
}
static void ubcore_compute_stat_for_type(const struct ub_perf_latency_record *cur_record,
				  struct ubcore_latency_record_stat *stat,
				  u32 record_type)
{
	u64 count = cur_record->count;
	u64 p90_idx = (count * 90  + 99) / 100;
	u64 p99_idx = (count * 99  + 99) / 100;
	u64 p9999_idx = (count * 9999 + 9999) / 10000;
	u64 last_bucket_sample, cur_bucket_sample;
	u64 p90_ns, p99_ns, p9999_ns;
	bool p90_ns_found = false, p99_ns_found = false, p9999_ns_found = false;
	int bucket_idx;

	if (count == 0) {
		memset(stat, 0, sizeof(*stat));
		return;
	}
	cur_bucket_sample = 0;
	for (bucket_idx = 0; bucket_idx < UBCORE_PERF_BUCKETS; bucket_idx++) {
		last_bucket_sample = cur_bucket_sample;
		cur_bucket_sample += cur_record->buckets[bucket_idx];

		if (!p90_ns_found && cur_bucket_sample >= p90_idx) {
			p90_ns = ubcore_perf_cal_bucket_latency(bucket_idx,
				cur_record->buckets[bucket_idx], p90_idx - last_bucket_sample);
			p90_ns_found = true;
		}
		if (!p99_ns_found && cur_bucket_sample >= p99_idx) {
			p99_ns = ubcore_perf_cal_bucket_latency(bucket_idx,
				cur_record->buckets[bucket_idx], p99_idx - last_bucket_sample);
			p99_ns_found = true;
		}
		if (!p9999_ns_found && cur_bucket_sample >= p9999_idx) {
			p9999_ns = ubcore_perf_cal_bucket_latency(bucket_idx,
				cur_record->buckets[bucket_idx], p9999_idx - last_bucket_sample);
			p9999_ns_found = true;
		}
	}

	stat->record_type = record_type;
	stat->count = count;
	stat->min_ns = cur_record->min_ns;
	stat->max_ns = cur_record->max_ns;
	stat->avg_ns = cur_record->sum_ns / count;
	stat->p90_ns = p90_ns_found ? p90_ns : 0U;
	stat->p99_ns = p99_ns_found ? p99_ns : 0U;
	stat->p9999_ns = p9999_ns_found ? p9999_ns : 0U;
}

void ubcore_perf_dump_info(struct ubcore_latency_stat *stat)
{
	struct ub_perf_latency_record *agg_record;
	u32 version;
	u32 record_type;

	if (!stat)
		return;

	agg_record = vzalloc((uint32_t)PERF_RECORD_TYPE_MAX *
			    sizeof(struct ub_perf_latency_record));
	if (!agg_record)
		return;

	version = READ_ONCE(global_version);
	ubcore_perf_aggregate_all_cpus(agg_record, version);

	stat->version = version;
	memset(stat->perf_stat_table, 0, sizeof(stat->perf_stat_table));

	for (record_type = 0; record_type < PERF_RECORD_TYPE_MAX; record_type++) {
		if (agg_record[record_type].count == 0)
			continue;
		ubcore_compute_stat_for_type(&agg_record[record_type],
			&stat->perf_stat_table[record_type], (u32)record_type);
	}

	vfree(agg_record);
}
EXPORT_SYMBOL(ubcore_perf_dump_info);

static void ubcore_perf_free_cpu_ctx(void)
{
	int cpu;

	WRITE_ONCE(ub_perf_status, false);

	for_each_possible_cpu(cpu) {
		struct ub_perf_latency_cpu_ctx *ctx;

		ctx = per_cpu(perf_cpu_ctx_ptr, cpu);
		if (ctx) {
			per_cpu(perf_cpu_ctx_ptr, cpu) = NULL;
			vfree(ctx);
		}
	}
}

int ubcore_perf_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct ub_perf_latency_cpu_ctx *ctx;

		ctx = vzalloc(sizeof(struct ub_perf_latency_cpu_ctx));
		if (!ctx) {
			ubcore_perf_free_cpu_ctx();
			return -ENOMEM;
		}
		memset(ctx->perf_table, 0, sizeof(ctx->perf_table));
		per_cpu(perf_cpu_ctx_ptr, cpu) = ctx;
	}
	return 0;
}

void ubcore_perf_uninit(void)
{
	WRITE_ONCE(ub_perf_status, false);
	ubcore_perf_free_cpu_ctx();
}
