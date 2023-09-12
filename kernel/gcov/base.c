// SPDX-License-Identifier: GPL-2.0
/*
 *  This code maintains a list of active profiling data structures.
 *
 *    Copyright IBM Corp. 2009
 *    Author(s): Peter Oberparleiter <oberpar@linux.vnet.ibm.com>
 *
 *    Uses gcc-internal data definitions.
 *    Based on the gcov-kernel patch by:
 *		 Hubertus Franke <frankeh@us.ibm.com>
 *		 Nigel Hinds <nhinds@us.ibm.com>
 *		 Rajan Ravindran <rajancr@us.ibm.com>
 *		 Peter Oberparleiter <oberpar@linux.vnet.ibm.com>
 *		 Paul Larson
 */

#define pr_fmt(fmt)	"gcov: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include "gcov.h"

static int gcov_events_enabled;
static DEFINE_MUTEX(gcov_lock);

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

/**
 * gcov_enable_events - enable event reporting through gcov_event()
 *
 * Turn on reporting of profiling data load/unload-events through the
 * gcov_event() callback. Also replay all previous events once. This function
 * is needed because some events are potentially generated too early for the
 * callback implementation to handle them initially.
 */
void gcov_enable_events(void)
{
	struct gcov_info *info = NULL;

	mutex_lock(&gcov_lock);
	gcov_events_enabled = 1;

	/* Perform event callback for previously registered entries. */
	while ((info = gcov_info_next(info))) {
		gcov_event(GCOV_ADD, info);
		cond_resched();
	}

	mutex_unlock(&gcov_lock);
}

#ifdef CONFIG_MODULES
/* Update list and generate events when modules are unloaded. */
static int gcov_module_notifier(struct notifier_block *nb, unsigned long event,
				void *data)
{
	struct module *mod = data;
	struct gcov_info *info = NULL;
	struct gcov_info *prev = NULL;

	if (event != MODULE_STATE_GOING)
		return NOTIFY_OK;
	mutex_lock(&gcov_lock);

	/* Remove entries located in module from linked list. */
	while ((info = gcov_info_next(info))) {
		if (within_module((unsigned long)info, mod)) {
			gcov_info_unlink(prev, info);
			if (gcov_events_enabled)
				gcov_event(GCOV_REMOVE, info);
		} else
			prev = info;
	}

	mutex_unlock(&gcov_lock);

	return NOTIFY_OK;
}

static struct notifier_block gcov_nb = {
	.notifier_call	= gcov_module_notifier,
};

static int __init gcov_init(void)
{
	return register_module_notifier(&gcov_nb);
}
device_initcall(gcov_init);
#endif /* CONFIG_MODULES */

#ifdef CONFIG_PGO_KERNEL
/*
 * If VALUE is in interval <START, START + STEPS - 1>, then increases the
 * corresponding counter in COUNTERS. If the VALUE is above or below
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

/*
 * If VALUE is a power of two, COUNTERS[1] is incremented. Otherwise
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
 * Tries to determine the most common value among its inputs. Checks if the
 * value stored in COUNTERS[0] matches VALUE. If this is the case, COUNTERS[1]
 * is incremented. If this is not the case and COUNTERS[1] is not zero,
 * COUNTERS[1] is decremented. Otherwise COUNTERS[1] is set to one and
 * VALUE is stored to COUNTERS[0]. This algorithm guarantees that if this
 * function is called more than 50% of the time with one value, this value
 * will be in COUNTERS[0] in the end.
 *
 * In any case, COUNTERS[2] is incremented.
 */
static inline void __gcov_one_value_profiler_body(gcov_type *counters,
						  gcov_type value)
{
	if (value == counters[0])
		counters[1]++;
	else if (counters[1] == 0) {
		counters[1] = 1;
		counters[0] = value;
	} else
		counters[1]--;

	counters[2]++;
}

void __gcov_one_value_profiler(gcov_type *counters, gcov_type value)
{
	__gcov_one_value_profiler_body(counters, value);
}
EXPORT_SYMBOL(__gcov_one_value_profiler);

/*
 * These two variables are used to actually track caller and callee.
 * Discarded __thread keyword as kernel does not support TLS.
 * The variables are set directly by GCC instrumented code, so declaration
 * here must match one in tree-profile.c.
 */
void *__gcov_indirect_call_callee;
EXPORT_SYMBOL(__gcov_indirect_call_callee);
gcov_type *__gcov_indirect_call_counters;
EXPORT_SYMBOL(__gcov_indirect_call_counters);

/*
 * Tries to determine the most common value among its inputs.
 */
void __gcov_indirect_call_profiler_v2(gcov_type value, void *cur_func)
{
	/* Removed the C++ virtual tables contents as kernel is written in C. */
	if (cur_func == __gcov_indirect_call_callee)
		__gcov_one_value_profiler_body(__gcov_indirect_call_counters,
					       value);
}
EXPORT_SYMBOL(__gcov_indirect_call_profiler_v2);

/* Counter for first visit of each function. */
gcov_type __gcov_time_profiler_counter;
EXPORT_SYMBOL(__gcov_time_profiler_counter);

/* Increase corresponding COUNTER by VALUE. */
void __gcov_average_profiler(gcov_type *counters, gcov_type value)
{
	counters[0] += value;
	counters[1]++;
}
EXPORT_SYMBOL(__gcov_average_profiler);

/* Bitwise-OR VALUE into COUNTER. */
void __gcov_ior_profiler(gcov_type *counters, gcov_type value)
{
	*counters |= value;
}
EXPORT_SYMBOL(__gcov_ior_profiler);
#endif
