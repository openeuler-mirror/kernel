// SPDX-License-Identifier: GPL-2.0

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include "gcov.h"

/*
 * __gcov_init is called by gcc-generated constructor code for each object
 * file compiled with -fprofile-arcs.
 */
void __gcov_init(struct gcov_info *info)
{
	static unsigned int gcov_version;

	mutex_lock(&gcov_lock);
	if (gcov_version == 0) {
		gcov_version = gcov_info_version(info);
		/*
		 * Printing gcc's version magic may prove useful for debugging
		 * incompatibility reports.
		 */
		pr_info("version magic: 0x%x\n", gcov_version);
	}
	/*
	 * Add new profiling data structure to list and inform event
	 * listener.
	 */
	gcov_info_link(info);
	if (gcov_events_enabled)
		gcov_event(GCOV_ADD, info);
	mutex_unlock(&gcov_lock);
}
EXPORT_SYMBOL(__gcov_init);

/*
 * These functions may be referenced by gcc-generated profiling code but serve
 * no function for kernel profiling.
 */
void __gcov_flush(void)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_flush);

void __gcov_merge_add(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_add);

void __gcov_merge_single(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_single);

void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_delta);

void __gcov_merge_ior(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_ior);

void __gcov_merge_time_profile(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_time_profile);

void __gcov_merge_icall_topn(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_icall_topn);

void __gcov_exit(void)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_exit);

#ifdef CONFIG_PGO_KERNEL
/* Number of top N value histogram. */
#define GCOV_TOPN_VALUES 4

void __gcov_merge_topn(gcov_type *counters, unsigned int n_counters)
{
	/* Unused. */
}
EXPORT_SYMBOL(__gcov_merge_topn);

struct indirect_call_tuple {
	void *callee;

	gcov_type *counters;
};

/* Kernel does not support __thread keyword. */
struct indirect_call_tuple __gcov_indirect_call;
EXPORT_SYMBOL(__gcov_indirect_call);

gcov_type __gcov_time_profiler_counter;
EXPORT_SYMBOL(__gcov_time_profiler_counter);

/*
 * Tries to determine N most commons value among its inputs.
 */
static inline void __gcov_topn_values_profiler_body(gcov_type *counters,
		gcov_type value)
{
	int empty_counter = -1;
	unsigned int i;

	counters[0]++;
	++counters;

	/* First try to find an existing value. */
	for (i = 0; i < GCOV_TOPN_VALUES; i++)
		if (value == counters[2 * i]) {
			counters[2 * i + 1] += GCOV_TOPN_VALUES;
			return;
		} else if (counters[2 * i + 1] <= 0)
			empty_counter = i;

	/* Find an empty slot for a new value. */
	if (empty_counter != -1) {
		counters[2 * empty_counter] = value;
		counters[2 * empty_counter + 1] = GCOV_TOPN_VALUES;
		return;
	}

	/*
	 * We haven't found an empty slot, then decrement all
	 * counter values by one.
	 */
	for (i = 0; i < GCOV_TOPN_VALUES; i++)
		counters[2 * i + 1]--;
}

void __gcov_topn_values_profiler(gcov_type *counters, gcov_type value)
{
	__gcov_topn_values_profiler_body(counters, value);
}
EXPORT_SYMBOL(__gcov_topn_values_profiler);

/*
 * Tries to determine the most common value among its inputs.
 */
static inline void __gcov_indirect_call_profiler_body(gcov_type value,
		void *cur_func)
{
	/* Removed the C++ virtual tables contents as kernel is written in C. */
	if (cur_func == __gcov_indirect_call.callee)
		__gcov_topn_values_profiler_body(__gcov_indirect_call.counters, value);

	__gcov_indirect_call.callee = NULL;
}

void __gcov_indirect_call_profiler_v4(gcov_type value, void *cur_func)
{
	__gcov_indirect_call_profiler_body(value, cur_func);
}
EXPORT_SYMBOL(__gcov_indirect_call_profiler_v4);

/*
 * Increase corresponding COUNTER by VALUE.
 */
void __gcov_average_profiler(gcov_type *counters, gcov_type value)
{
	counters[0] += value;
	counters[1]++;
}
EXPORT_SYMBOL(__gcov_average_profiler);

void __gcov_ior_profiler(gcov_type *counters, gcov_type value)
{
	*counters |= value;
}
EXPORT_SYMBOL(__gcov_ior_profiler);

/*
 * If VALUE is a power of two, COUNTERS[1] is incremented.	Otherwise
 * COUNTERS[0] is incremented.
 */
void __gcov_pow2_profiler(gcov_type *counters, gcov_type value)
{
	if (value == 0 || (value & (value - 1)))
		counters[0]++;
	else
		counters[1]++;
}
EXPORT_SYMBOL(__gcov_pow2_profiler);

/*
 * If VALUE is in interval <START, START + STEPS - 1>, then increases the
 * corresponding counter in COUNTERS.	If the VALUE is above or below
 * the interval, COUNTERS[STEPS] or COUNTERS[STEPS + 1] is increased
 * instead.
 */
void __gcov_interval_profiler(gcov_type *counters, gcov_type value,
		int start, unsigned int steps)
{
	gcov_type delta = value - start;

	if (delta < 0)
		counters[steps + 1]++;
	else if (delta >= steps)
		counters[steps]++;
	else
		counters[delta]++;
}
EXPORT_SYMBOL(__gcov_interval_profiler);
#endif
