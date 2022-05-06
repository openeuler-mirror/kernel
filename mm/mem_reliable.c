// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"mem reliable: " fmt


#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/seq_file.h>
#include <linux/mmzone.h>
#include <linux/oom.h>
#include <linux/crash_dump.h>

enum mem_reliable_types {
	MEM_RELIABLE_ALL,
	MEM_RELIABLE_FALLBACK,
	MEM_RELIABLE_SHM,
	MEM_RELIABLE_PAGECACHE,
	MEM_RELIABLE_MAX
};

DEFINE_STATIC_KEY_FALSE(mem_reliable);

bool reliable_enabled;
static atomic_long_t total_reliable_mem;
/* reliable user limit for user tasks with reliable flag */
unsigned long task_reliable_limit = ULONG_MAX;
bool reliable_allow_fallback __read_mostly = true;
bool shmem_reliable __read_mostly = true;
struct percpu_counter reliable_shmem_used_nr_page __read_mostly;
DEFINE_PER_CPU(long, nr_reliable_buddy_pages);
long shmem_reliable_nr_page = LONG_MAX;

bool pagecache_use_reliable_mem __read_mostly = true;
struct percpu_counter pagecache_reliable_pages;
struct percpu_counter anon_reliable_pages;

static unsigned long zero;
static unsigned long reliable_pagecache_max_bytes = ULONG_MAX;

bool mem_reliable_counter_initialized(void)
{
	return likely(percpu_counter_initialized(&pagecache_reliable_pages)) &&
		likely((percpu_counter_initialized(&anon_reliable_pages)));
}

bool mem_reliable_status(void)
{
	return mem_reliable_is_enabled();
}
EXPORT_SYMBOL_GPL(mem_reliable_status);

void add_reliable_mem_size(long sz)
{
	atomic_long_add(sz, &total_reliable_mem);
}

bool page_reliable(struct page *page)
{
	if (!mem_reliable_is_enabled() || !page)
		return false;

	return page_zonenum(page) < ZONE_MOVABLE;
}

void reliable_lru_add_batch(int zid, enum lru_list lru, int val)
{
	if (!mem_reliable_is_enabled())
		return;

	if (zid < ZONE_MOVABLE && zid >= 0) {
		if (is_file_lru(lru))
			percpu_counter_add(&pagecache_reliable_pages, val);
		else if (is_anon_lru(lru))
			percpu_counter_add(&anon_reliable_pages, val);
	}
}

void reliable_lru_add(enum lru_list lru, struct page *page, int val)
{
	if (!page_reliable(page))
		return;

	if (is_file_lru(lru))
		percpu_counter_add(&pagecache_reliable_pages, val);
	else if (is_anon_lru(lru))
		percpu_counter_add(&anon_reliable_pages, val);
	else if (lru == LRU_UNEVICTABLE) {
		if (PageAnon(page))
			percpu_counter_add(&anon_reliable_pages, val);
		else
			percpu_counter_add(&pagecache_reliable_pages, val);
	}
}

static int reliable_mem_notifier(struct notifier_block *nb,
				 unsigned long action, void *arg)
{
	struct memory_notify *m_arg = arg;
	struct zone *zone;

	switch (action) {
	case MEM_ONLINE:
		zone = page_zone(pfn_to_page(m_arg->start_pfn));
		if (zone_reliable(zone))
			add_reliable_mem_size(m_arg->nr_pages * PAGE_SIZE);
		break;
	case MEM_OFFLINE:
		zone = page_zone(pfn_to_page(m_arg->start_pfn));
		if (zone_reliable(zone))
			add_reliable_mem_size(-m_arg->nr_pages * PAGE_SIZE);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block reliable_notifier_block = {
	.notifier_call = reliable_mem_notifier,
};

void mem_reliable_init(bool has_unmirrored_mem, unsigned long *zone_movable_pfn)
{
	if (!reliable_enabled)
		return;

	if (is_kdump_kernel()) {
		pr_err("init failed, the kdump is in progress\n");
		return;
	}

	if (atomic_long_read(&total_reliable_mem) == 0) {
		memset(zone_movable_pfn, 0,
		       sizeof(unsigned long) * MAX_NUMNODES);

		pr_err("init failed, mirrored memory size is zero.");

		return;
	}

	if (!has_unmirrored_mem) {
		pr_err("init failed, unmirrored memory size is zero.");

		return;
	}

	if (register_hotmemory_notifier(&reliable_notifier_block)) {
		pr_err("init failed, register memory notifier failed.");
		return;
	}

	static_branch_enable(&mem_reliable);

	pr_info("init succeed, mirrored memory size(%lu)",
		atomic_long_read(&total_reliable_mem));
}

void shmem_reliable_init(void)
{
	if (!shmem_reliable_is_enabled())
		return;

	if (!mem_reliable_is_enabled()) {
		shmem_reliable = false;
		pr_info("shmem reliable disabled.\n");
		return;
	}

	percpu_counter_init(&reliable_shmem_used_nr_page, 0, GFP_KERNEL);
}

static unsigned long total_reliable_mem_sz(void)
{
	return atomic_long_read(&total_reliable_mem);
}

static unsigned long used_reliable_mem_sz(void)
{
	unsigned long nr_page = 0;
	struct zone *z;

	for_each_populated_zone(z)
		if (zone_idx(z) < ZONE_MOVABLE)
			nr_page += zone_page_state(z, NR_FREE_PAGES);

	return total_reliable_mem_sz() - nr_page * PAGE_SIZE;
}

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num << (PAGE_SHIFT - 10), 8);
	seq_write(m, " kB\n", 4);
}

void reliable_report_meminfo(struct seq_file *m)
{
	s64 nr_pagecache_pages = 0;
	s64 nr_anon_pages = 0;
	long nr_buddy_pages = 0;
	int cpu;

	if (!mem_reliable_is_enabled())
		return;

	for_each_possible_cpu(cpu)
		nr_buddy_pages += per_cpu(nr_reliable_buddy_pages, cpu);

	nr_anon_pages = percpu_counter_sum_positive(&anon_reliable_pages);
	nr_pagecache_pages = percpu_counter_sum_positive(&pagecache_reliable_pages);

	show_val_kb(m, "ReliableTotal:    ",
			total_reliable_mem_sz() >> PAGE_SHIFT);
	show_val_kb(m, "ReliableUsed:     ",
			used_reliable_mem_sz() >> PAGE_SHIFT);
	show_val_kb(m, "ReliableTaskUsed: ", nr_anon_pages + nr_pagecache_pages);
	show_val_kb(m, "ReliableBuddyMem: ", nr_buddy_pages);

	if (shmem_reliable_is_enabled()) {
		show_val_kb(m, "ReliableShmem:    ",
			    percpu_counter_sum(&reliable_shmem_used_nr_page));
	}

	if (pagecache_reliable_is_enabled()) {
		unsigned long num = 0;

		num += global_node_page_state(NR_LRU_BASE + LRU_ACTIVE_FILE);
		num += global_node_page_state(NR_LRU_BASE + LRU_INACTIVE_FILE);
		show_val_kb(m, "FileCache:        ", num);
		seq_printf(m, "ReliableFileCache: %8llu kB\n",
			   nr_pagecache_pages << (PAGE_SHIFT - 10));
	}
}

void reliable_report_usage(struct seq_file *m, struct mm_struct *mm)
{
	if (!mem_reliable_is_enabled())
		return;

	seq_printf(m, "Reliable:\t%8lu kB\n",
		atomic_long_read(&mm->reliable_nr_page) << (PAGE_SHIFT - 10));
}

#ifdef CONFIG_SYSCTL
int reliable_limit_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	unsigned long old = task_reliable_limit;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (ret == 0 && write) {
		if (task_reliable_limit > total_reliable_mem_sz()) {
			task_reliable_limit = old;
			return -EINVAL;
		}
	}

	return ret;
}

static void mem_reliable_feature_disable(int idx);

#define CTRL_BITS_SHIFT MEM_RELIABLE_MAX
#define CTRL_BITS_MASK ((1 << CTRL_BITS_SHIFT) - 1)

static unsigned long mem_reliable_ctrl_bits = CTRL_BITS_MASK;

static void mem_reliable_ctrl_bit_disabled(int idx)
{
	clear_bit(idx, &mem_reliable_ctrl_bits);
}

static bool mem_reliable_ctrl_bit_is_enabled(int idx)
{
	return !!test_bit(idx, &mem_reliable_ctrl_bits);
}

static void mem_reliable_parse_ctrl_bits(unsigned long ctrl_bits)
{
	bool status;
	int i;

	for (i = MEM_RELIABLE_FALLBACK; i < MEM_RELIABLE_MAX; i++) {
		status = !!test_bit(i, &ctrl_bits);

		if (mem_reliable_ctrl_bit_is_enabled(i) && !status)
			mem_reliable_feature_disable(i);
	}
}

static void mem_reliable_disable_all(void)
{
	mem_reliable_ctrl_bits = 0;

	reliable_allow_fallback = false;
	shmem_reliable = false;
	pagecache_use_reliable_mem = false;
	static_branch_disable(&mem_reliable);

	pr_info("memory reliable feature disabled.\n");
}

int reliable_debug_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	unsigned long old_ctrl_bits, new_ctrl_bits;
	static DEFINE_MUTEX(reliable_debug_mutex);
	int ret;

	mutex_lock(&reliable_debug_mutex);
	old_ctrl_bits = mem_reliable_ctrl_bits;
	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (ret == 0 && write) {
		if (!mem_reliable_is_enabled() ||
		    (mem_reliable_ctrl_bits > (1 << CTRL_BITS_SHIFT) - 1)) {
			mem_reliable_ctrl_bits = old_ctrl_bits;
			mutex_unlock(&reliable_debug_mutex);

			return -EINVAL;
		}

		new_ctrl_bits = mem_reliable_ctrl_bits;
		mem_reliable_ctrl_bits = old_ctrl_bits;
		if (!!test_bit(MEM_RELIABLE_ALL, &new_ctrl_bits))
			mem_reliable_parse_ctrl_bits(new_ctrl_bits);
		else
			mem_reliable_disable_all();
	}

	mutex_unlock(&reliable_debug_mutex);

	return ret;
}

#ifdef CONFIG_SHMEM
static unsigned long sysctl_shmem_reliable_bytes_limit = ULONG_MAX;

int reliable_shmem_bytes_limit_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	unsigned long *data_ptr = (unsigned long *)(table->data);
	unsigned long old = *data_ptr;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (ret == 0 && write) {
		if (*data_ptr > total_reliable_mem_sz()) {
			*data_ptr = old;
			return -EINVAL;
		}

		shmem_reliable_nr_page = *data_ptr >> PAGE_SHIFT;
	}

	return ret;
}
#endif

int reliable_pagecache_max_bytes_write(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	unsigned long old_value = reliable_pagecache_max_bytes;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (!ret && write) {
		if (reliable_pagecache_max_bytes > total_reliable_mem_sz()) {
			reliable_pagecache_max_bytes = old_value;
			return -EINVAL;
		}
	}

	return ret;
}

static struct ctl_table reliable_ctl_table[] = {
	{
		.procname = "task_reliable_limit",
		.data = &task_reliable_limit,
		.maxlen = sizeof(task_reliable_limit),
		.mode = 0644,
		.proc_handler = reliable_limit_handler,
	},
	{
		.procname = "reliable_debug",
		.data = &mem_reliable_ctrl_bits,
		.maxlen = sizeof(mem_reliable_ctrl_bits),
		.mode = 0600,
		.proc_handler = reliable_debug_handler,
	},
#ifdef CONFIG_SHMEM
	{
		.procname = "shmem_reliable_bytes_limit",
		.data = &sysctl_shmem_reliable_bytes_limit,
		.maxlen = sizeof(sysctl_shmem_reliable_bytes_limit),
		.mode = 0644,
		.proc_handler = reliable_shmem_bytes_limit_handler,
	},
#endif
	{
		.procname = "reliable_pagecache_max_bytes",
		.data = &reliable_pagecache_max_bytes,
		.maxlen = sizeof(reliable_pagecache_max_bytes),
		.mode = 0644,
		.proc_handler = reliable_pagecache_max_bytes_write,
		.extra1 = &zero,
	},
	{}
};

static struct ctl_table reliable_dir_table[] = {
	{
		.procname = "vm",
		.maxlen = 0,
		.mode = 0555,
		.child = reliable_ctl_table,
	},
	{}
};

void page_cache_prepare_alloc(gfp_t *gfp)
{
	s64 nr_reliable = 0;

	if (!mem_reliable_is_enabled())
		return;

	if (!pagecache_reliable_is_enabled())
		goto no_reliable;

	nr_reliable = percpu_counter_read_positive(&pagecache_reliable_pages);

	if (nr_reliable > reliable_pagecache_max_bytes >> PAGE_SHIFT)
		goto no_reliable;

	*gfp |= ___GFP_RELIABILITY;
	return;

no_reliable:
	*gfp &= ~___GFP_RELIABILITY;
}

static int __init reliable_sysctl_init(void)
{
	if (!mem_reliable_is_enabled())
		return 0;

	if (!register_sysctl_table(reliable_dir_table)) {
		pr_err("register sysctl failed.");
		return -1;
	}

	percpu_counter_init(&pagecache_reliable_pages, 0, GFP_KERNEL);
	percpu_counter_init(&anon_reliable_pages, 0, GFP_KERNEL);

	return 0;
}
arch_initcall(reliable_sysctl_init);
#else
static void mem_reliable_ctrl_bit_disabled(int idx) {}
#endif

static void mem_reliable_feature_disable(int idx)
{
	char *str = NULL;

	switch (idx) {
	case MEM_RELIABLE_FALLBACK:
		reliable_allow_fallback = false;
		str = "fallback";
		break;
	case MEM_RELIABLE_SHM:
		shmem_reliable = false;
		str = "shmem";
		break;
	case MEM_RELIABLE_PAGECACHE:
		pagecache_use_reliable_mem = false;
		str = "pagecache";
		break;
	default:
		pr_err("unknown index: %d", idx);
		return;
	}

	mem_reliable_ctrl_bit_disabled(idx);
	pr_info("%s is disabled\n", str);
}

void reliable_show_mem_info(void)
{
	s64 nr_pagecache_pages = 0;
	s64 nr_anon_pages = 0;

	if (!mem_reliable_is_enabled())
		return;

	nr_anon_pages = percpu_counter_sum_positive(&anon_reliable_pages);
	nr_pagecache_pages = percpu_counter_sum_positive(&pagecache_reliable_pages);

	pr_info("ReliableTotal: %lu kB\n", total_reliable_mem_sz() >> 10);
	pr_info("ReliableUsed: %lu kB\n", used_reliable_mem_sz() >> 10);
	pr_info("ReliableTaskLimit: %lu kB\n", task_reliable_limit >> 10);
	pr_info("ReliableTaskUsed: %lld kB\n",
		(nr_anon_pages + nr_pagecache_pages) << (PAGE_SHIFT - 10));

	if (shmem_reliable_is_enabled()) {
		pr_info("ReliableShmemPagesLimit: %ld\n",
			shmem_reliable_nr_page);
		pr_info("ReliableShmem: %llu kB\n",
			percpu_counter_sum(&reliable_shmem_used_nr_page)
				<< (PAGE_SHIFT - 10));
	}

	if (pagecache_reliable_is_enabled()) {
		unsigned long num = 0;

		num += global_node_page_state(NR_LRU_BASE + LRU_ACTIVE_FILE);
		num += global_node_page_state(NR_LRU_BASE + LRU_INACTIVE_FILE);
		pr_info("ReliableFileCacheLimit: %lu kB\n",
			reliable_pagecache_max_bytes >> 10);
		pr_info("FileCache: %lu kB\n", num << (PAGE_SHIFT - 10));
		pr_info("ReliableFileCache: %llu kB\n",
			nr_pagecache_pages << (PAGE_SHIFT - 10));
	}
}

void mem_reliable_out_of_memory(gfp_t gfp_mask, unsigned int order,
				int preferred_nid, nodemask_t *nodemask)
{
	struct oom_control oc = {
		.zonelist = node_zonelist(preferred_nid, gfp_mask),
		.nodemask = nodemask,
		.memcg = NULL,
		.gfp_mask = gfp_mask,
		.order = order,
	};

	if (!mutex_trylock(&oom_lock))
		return;
	out_of_memory(&oc);
	mutex_unlock(&oom_lock);
}

static int __init setup_reliable_debug(char *str)
{
	if (*str++ != '=' || !*str)
		/*
		 * No options specified.
		 */
		goto out;

	/*
	 * Determine which debug features should be switched on
	 */
	for (; *str && *str != ','; str++) {
		switch (*str) {
		case 'F':
			mem_reliable_feature_disable(MEM_RELIABLE_FALLBACK);
			break;
		case 'S':
			mem_reliable_feature_disable(MEM_RELIABLE_SHM);
			break;
		case 'P':
			mem_reliable_feature_disable(MEM_RELIABLE_PAGECACHE);
			break;
		default:
			pr_err("reliable_debug option '%c' unknown. skipped\n",
			       *str);
		}
	}

out:
	return 1;
}
__setup("reliable_debug", setup_reliable_debug);
