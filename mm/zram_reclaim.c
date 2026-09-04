// SPDX-License-Identifier: GPL-2.0
#include <linux/bits.h>
#include <linux/cgroup.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mutex.h>
#include <linux/kstrtox.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/swap.h>
#ifdef CONFIG_ARM64
#include <asm/cputype.h>
#endif

#include "zram_reclaim.h"

#define ZRAM_PRIORITY_DELTA		10
#define ZRAM_PRIORITY_FLOOR		(DEF_PRIORITY - ZRAM_PRIORITY_DELTA)
#define ZRAM_LIMIT_RATIO_DEFAULT	30
#define ZRAM_LIMIT_RATIO_MAX		60
/* Ignore small anon costs when checking for overload. */
#define ZRAM_ABS_COST_MIN		5000UL

/* Scale the overload threshold with the amount of anonymous memory. */
#define ZRAM_ABS_COST_SHIFT		10
/* Use a higher swappiness when compressed-swap reclaim is overloaded. */
#define ZRAM_OVERLOAD_SWAPPINESS	150

/* Publish the reset counter bank with release/acquire semantics. */
#define ZRAM_RECLAIM_STATE_ENABLED	BIT(0)
#define ZRAM_RECLAIM_STATE_BANK		BIT(1)

struct memcg_reclaim_state {
	u32 state;
	unsigned int limit_ratio;
	struct mutex lock;
	atomic_long_t anon_cost[2];
	atomic_long_t file_cost[2];
};

static unsigned int zram_file_weight_default;

static inline bool zram_reclaim_state_enabled(u32 state)
{
	return state & ZRAM_RECLAIM_STATE_ENABLED;
}

static inline unsigned int zram_reclaim_state_bank(u32 state)
{
	return !!(state & ZRAM_RECLAIM_STATE_BANK);
}

static unsigned long zram_reclaim_swap_usage(struct mem_cgroup *memcg)
{
	unsigned long nr_memsw, nr_mem;

	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return page_counter_read(&memcg->swap);

	nr_memsw = page_counter_read(&memcg->memsw);
	nr_mem = page_counter_read(&memcg->memory);

	if (nr_memsw <= nr_mem)
		return 0;

	return nr_memsw - nr_mem;
}

static struct memcg_reclaim_state *zram_reclaim_get_state(struct mem_cgroup *memcg)
{
	return READ_ONCE(memcg->memcg_reclaim_state);
}

static struct memcg_reclaim_state *zram_reclaim_get_or_alloc_state(struct mem_cgroup *memcg)
{
	struct memcg_reclaim_state *state, *new_state;

	state = zram_reclaim_get_state(memcg);
	if (state)
		return state;

	new_state = kzalloc(sizeof(*new_state), GFP_KERNEL);
	if (!new_state)
		return NULL;
	mutex_init(&new_state->lock);

	/* Only one concurrently allocated state may be installed. */
	state = cmpxchg(&memcg->memcg_reclaim_state, NULL, new_state);
	if (state) {
		mutex_destroy(&new_state->lock);
		kfree(new_state);
		return state;
	}

	return new_state;
}

void zram_reclaim_memcg_free(struct mem_cgroup *memcg)
{
	struct memcg_reclaim_state *state = zram_reclaim_get_state(memcg);

	if (!state)
		return;

	mutex_destroy(&state->lock);
	kfree(state);
}

static unsigned long zram_reclaim_read_counter(atomic_long_t *counter)
{
	long val = atomic_long_read(counter);

	return val > 0 ? val : 0;
}

static void zram_reclaim_decay_counter(atomic_long_t *counter,
				       unsigned long decay)
{
	long old, new;

	if (!decay)
		return;

	do {
		old = atomic_long_read(counter);
		if (old <= 0)
			return;

		new = old > decay ? old - decay : 0;
	} while (atomic_long_cmpxchg(counter, old, new) != old);
}

static bool zram_reclaim_anon_overloaded(unsigned long a_cost,
					 unsigned long f_cost,
					 unsigned long abs_threshold,
					 unsigned int weight)
{
	u64 weighted_file;
	u64 threshold;

	if (a_cost <= abs_threshold ||
	    check_mul_overflow((u64)f_cost, (u64)weight, &weighted_file) ||
	    check_add_overflow(weighted_file, 1ULL, &threshold))
		return false;

	return (u64)a_cost > threshold;
}

static void zram_reclaim_note_cost(struct mem_cgroup *memcg, struct lruvec *lruvec,
				   bool file, unsigned long nr_pages)
{
	struct memcg_reclaim_state *state;
	unsigned long a, f, a_decay, f_decay, total, sum, threshold;
	unsigned int bank;
	u32 snapshot;

	if (!memcg)
		return;

	state = zram_reclaim_get_state(memcg);
	if (!state)
		return;

	/* Observe enabled flag + reset bank; pairs with smp_store_release() writer. */
	snapshot = smp_load_acquire(&state->state);
	if (!zram_reclaim_state_enabled(snapshot))
		return;

	bank = zram_reclaim_state_bank(snapshot);
	if (file)
		atomic_long_add(nr_pages, &state->file_cost[bank]);
	else
		atomic_long_add(nr_pages, &state->anon_cost[bank]);

	a = zram_reclaim_read_counter(&state->anon_cost[bank]);
	f = zram_reclaim_read_counter(&state->file_cost[bank]);

	total = lruvec_page_state(lruvec, NR_INACTIVE_ANON) +
		lruvec_page_state(lruvec, NR_ACTIVE_ANON) +
		lruvec_page_state(lruvec, NR_INACTIVE_FILE) +
		lruvec_page_state(lruvec, NR_ACTIVE_FILE);
	threshold = total >> 2;

	if (check_add_overflow(a, f, &sum))
		sum = ULONG_MAX;
	if (sum > threshold) {
		a_decay = a >> 1;
		f_decay = f >> 1;
		zram_reclaim_decay_counter(&state->anon_cost[bank], a_decay);
		zram_reclaim_decay_counter(&state->file_cost[bank], f_decay);
	}
}

void zram_reclaim_note_cost_folio(struct folio *folio, bool file)
{
	/* Skip shmem folios faulting in through do_swap_page(). */
	if (!file && !folio_test_anon(folio))
		return;

	zram_reclaim_note_cost(folio_memcg(folio), folio_lruvec(folio), file,
			       folio_nr_pages(folio));
}

bool zram_reclaim_should_use_policy(struct lruvec *lruvec, struct mem_cgroup *memcg,
				    char priority, int *swappiness)
{
	struct memcg_reclaim_state *state;
	unsigned long abs_threshold, total_anon, total_file, a_cost, f_cost;
	unsigned long nr_swap, total;
	unsigned int limit, weight = zram_file_weight_default;
	bool zram_overloaded;
	unsigned int bank;
	u32 snapshot;

	if (!memcg || !weight)
		return false;

	if (lru_gen_enabled())
		return false;

	state = zram_reclaim_get_state(memcg);
	if (!state)
		return false;

	/* Observe enabled flag + reset bank; pairs with smp_store_release() writer. */
	snapshot = smp_load_acquire(&state->state);
	if (!zram_reclaim_state_enabled(snapshot))
		return false;

	bank = zram_reclaim_state_bank(snapshot);

	/* Near-OOM direct reclaim (priority near DEF_PRIORITY floor): let VM decide. */
	if (!current_is_kswapd() && priority < ZRAM_PRIORITY_FLOOR)
		return false;

	a_cost = zram_reclaim_read_counter(&state->anon_cost[bank]);
	f_cost = zram_reclaim_read_counter(&state->file_cost[bank]);

	total_anon = lruvec_page_state(lruvec, NR_ACTIVE_ANON) +
		     lruvec_page_state(lruvec, NR_INACTIVE_ANON);
	total_file = lruvec_page_state(lruvec, NR_ACTIVE_FILE) +
		     lruvec_page_state(lruvec, NR_INACTIVE_FILE);

	abs_threshold = max(ZRAM_ABS_COST_MIN,
			    total_anon >> ZRAM_ABS_COST_SHIFT);

	if (total_anon < total_file / 2)
		return false;

	limit = READ_ONCE(state->limit_ratio);
	if (limit) {
		nr_swap = zram_reclaim_swap_usage(memcg);
		if (!nr_swap)
			return false;

		total = nr_swap + total_anon;
		if (total && (u64)nr_swap * 100 > (u64)limit * total)
			return false;
	}

	zram_overloaded = zram_reclaim_anon_overloaded(a_cost, f_cost,
						       abs_threshold, weight);
	if (!zram_overloaded)
		return true;

	*swappiness = ZRAM_OVERLOAD_SWAPPINESS;
	return false;
}

static int memory_zram_reclaim_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	struct memcg_reclaim_state *state = zram_reclaim_get_state(memcg);
	u32 snapshot = 0;
	unsigned int ratio = 0;

	if (state) {
		/* Serialize with writers to read a consistent state and ratio. */
		mutex_lock(&state->lock);
		snapshot = state->state;
		ratio = state->limit_ratio;
		mutex_unlock(&state->lock);
	}

	seq_printf(m, "%u %u\n",
		   zram_reclaim_state_enabled(snapshot) ? 1 : 0, ratio);

	return 0;
}

static ssize_t memory_zram_reclaim_write(struct kernfs_open_file *of,
					 char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	struct memcg_reclaim_state *state = zram_reclaim_get_state(memcg);
	char *token;
	bool ratio_specified = false;
	bool enable = false;
	unsigned long ratio = 0;
	u32 snapshot, new_state;
	unsigned int bank;
	int ret;

	token = strsep(&buf, " \t");
	if (!token)
		return -EINVAL;

	ret = kstrtobool(token, &enable);
	if (ret)
		return ret;

	if (buf) {
		token = strstrip(buf);
		if (token && *token) {
			ratio_specified = true;
			ret = kstrtoul(token, 0, &ratio);
			if (ret)
				return ret;
			if (ratio > ZRAM_LIMIT_RATIO_MAX)
				return -EINVAL;
		}
	}

	if (!enable) {
		if (!ratio_specified || ratio)
			return -EINVAL;
	}

	if (!state && enable) {
		state = zram_reclaim_get_or_alloc_state(memcg);
		if (!state)
			return -ENOMEM;
	}

	if (!state)
		return nbytes;

	mutex_lock(&state->lock);
	snapshot = READ_ONCE(state->state);
	bank = zram_reclaim_state_bank(snapshot);

	if (!enable) {
		WRITE_ONCE(state->limit_ratio, 0);
		/* Disable policy; pairs with smp_load_acquire() readers. */
		smp_store_release(&state->state,
				  bank ? ZRAM_RECLAIM_STATE_BANK : 0);
		ret = nbytes;
		goto out_unlock;
	}

	if (!ratio_specified) {
		ratio = ZRAM_LIMIT_RATIO_DEFAULT;
	} else if (!ratio) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (zram_reclaim_state_enabled(snapshot) &&
	    ratio != READ_ONCE(state->limit_ratio)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	if (!zram_reclaim_state_enabled(snapshot)) {
		bank ^= 1;
		atomic_long_set(&state->anon_cost[bank], 0);
		atomic_long_set(&state->file_cost[bank], 0);
	}

	WRITE_ONCE(state->limit_ratio, ratio);
	new_state = ZRAM_RECLAIM_STATE_ENABLED;
	if (bank)
		new_state |= ZRAM_RECLAIM_STATE_BANK;
	/* Publish enabled flag + reset bank; pairs with smp_load_acquire() readers. */
	smp_store_release(&state->state, new_state);

	ret = nbytes;
out_unlock:
	mutex_unlock(&state->lock);
	return ret;
}

static struct cftype zram_files_dfl[] = {
	{
		.name = "zram_reclaim",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = memory_zram_reclaim_show,
		.write = memory_zram_reclaim_write,
	},
	{ }
};

static struct cftype zram_files_legacy[] = {
	{
		.name = "zram_reclaim",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = memory_zram_reclaim_show,
		.write = memory_zram_reclaim_write,
	},
	{ }
};

static int __init zram_reclaim_init(void)
{
#ifdef CONFIG_ARM64
	u32 midr = read_cpuid_id();

	if (MIDR_IMPLEMENTOR(midr) == ARM_CPU_IMP_HISI) {
		switch (MIDR_PARTNUM(midr)) {
		case HISI_CPU_PART_TSV110:
			zram_file_weight_default = 64;
			break;
		case HISI_CPU_PART_LINXICORE9100:
		case HISI_CPU_PART_HIP11:
		case HISI_CPU_PART_HIP12:
			zram_file_weight_default = 100;
			break;
		}
	}
#endif
	if (!zram_file_weight_default)
		return 0;

	WARN_ON(cgroup_add_dfl_cftypes(&memory_cgrp_subsys, zram_files_dfl));
	WARN_ON(cgroup_add_legacy_cftypes(&memory_cgrp_subsys,
					  zram_files_legacy));
	return 0;
}
subsys_initcall(zram_reclaim_init);
