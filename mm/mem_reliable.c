// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"mem reliable: " fmt

#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/crash_dump.h>
#include <linux/seq_file.h>
#include <linux/mmzone.h>

#define PAGES_TO_B(n_pages)	((n_pages) << PAGE_SHIFT)

DEFINE_STATIC_KEY_FALSE(mem_reliable);
EXPORT_SYMBOL_GPL(mem_reliable);

bool reliable_enabled;
bool shmem_reliable __read_mostly = true;
bool pagecache_reliable __read_mostly = true;
struct percpu_counter pagecache_reliable_pages;
struct percpu_counter anon_reliable_pages;
struct percpu_counter shmem_reliable_pages;
unsigned long pagecache_reliable_limit = ULONG_MAX;
/* reliable user limit for user tasks with reliable flag */
unsigned long task_reliable_limit = ULONG_MAX;
unsigned long shmem_reliable_limit = ULONG_MAX;
bool reliable_allow_fallback __read_mostly = true;

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

static unsigned long total_reliable_pages(void)
{
	unsigned long total_reliable_pages = 0;
	struct zone *z;

	for_each_populated_zone(z)
		if (zone_idx(z) < ZONE_MOVABLE)
			total_reliable_pages += zone_managed_pages(z);

	return total_reliable_pages;
}

static unsigned long free_reliable_pages(void)
{
	struct zone *zone;
	unsigned long cnt = 0;

	for_each_populated_zone(zone)
		if (zone_idx(zone) < ZONE_MOVABLE)
			cnt += zone_page_state(zone, NR_FREE_PAGES);

	return cnt;
}

static unsigned long used_reliable_pages(void)
{
	return total_reliable_pages() - free_reliable_pages();
}

void mem_reliable_init(bool has_unmirrored_mem, unsigned long mirrored_sz)
{
	if (!reliable_enabled)
		return;

	if (!has_unmirrored_mem) {
		pr_err("init failed, unmirrored memory size is zero.\n");
		return;
	}

	static_branch_enable(&mem_reliable);

	pr_info("init succeed, mirrored memory size(%lu)\n", mirrored_sz);
}

void shmem_reliable_init(void)
{
	if (!mem_reliable_is_enabled() || !shmem_reliable_is_enabled()) {
		shmem_reliable = false;
		return;
	}

	percpu_counter_init(&shmem_reliable_pages, 0, GFP_KERNEL);
}

void reliable_lru_add_batch(int zid, enum lru_list lru, int val)
{
	if (!mem_reliable_is_enabled())
		return;

	if (zid < ZONE_MOVABLE) {
		if (is_file_lru(lru))
			percpu_counter_add(&pagecache_reliable_pages, val);
		else if (is_anon_lru(lru))
			percpu_counter_add(&anon_reliable_pages, val);
	}
}

void reliable_lru_add(enum lru_list lru, struct folio *folio, int val)
{
	if (!folio_reliable(folio))
		return;

	if (is_file_lru(lru))
		percpu_counter_add(&pagecache_reliable_pages, val);
	else if (is_anon_lru(lru))
		percpu_counter_add(&anon_reliable_pages, val);
	else if (lru == LRU_UNEVICTABLE) {
		if (folio_test_anon(folio))
			percpu_counter_add(&anon_reliable_pages, val);
		else
			percpu_counter_add(&pagecache_reliable_pages, val);
	}
}

static int reliable_pagecache_max_bytes_write(struct ctl_table *table,
					      int write, void __user *buffer,
					      size_t *length, loff_t *ppos)
{
	unsigned long old_value = pagecache_reliable_limit;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (!ret && write) {
		if (pagecache_reliable_limit >
		    PAGES_TO_B(total_reliable_pages())) {
			pagecache_reliable_limit = old_value;
			return -EINVAL;
		}
	}

	return ret;
}

static int reliable_limit_handler(struct ctl_table *table, int write,
				  void __user *buffer, size_t *length,
				  loff_t *ppos)
{
	unsigned long old = task_reliable_limit;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (!ret && write) {
		if (task_reliable_limit > PAGES_TO_B(total_reliable_pages()) ||
		    task_reliable_limit <
			    (task_reliable_used_pages() << PAGE_SHIFT)) {
			task_reliable_limit = old;
			return -EINVAL;
		}
	}

	return ret;
}

#ifdef CONFIG_SHMEM
static int reliable_shmem_bytes_limit_handler(struct ctl_table *table,
					      int write, void __user *buffer,
					      size_t *length, loff_t *ppos)
{
	unsigned long *data_ptr = (unsigned long *)(table->data);
	unsigned long old = *data_ptr;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (!ret && write) {
		if (*data_ptr > PAGES_TO_B(total_reliable_pages())) {
			*data_ptr = old;
			return -EINVAL;
		}
	}

	return ret;
}
#endif

static struct ctl_table reliable_ctl_table[] = {
	{
		.procname = "reliable_pagecache_max_bytes",
		.data = &pagecache_reliable_limit,
		.maxlen = sizeof(pagecache_reliable_limit),
		.mode = 0644,
		.proc_handler = reliable_pagecache_max_bytes_write,
	},
	{
		.procname = "task_reliable_limit",
		.data = &task_reliable_limit,
		.maxlen = sizeof(task_reliable_limit),
		.mode = 0644,
		.proc_handler = reliable_limit_handler,
	},
#ifdef CONFIG_SHMEM
	{
		.procname = "shmem_reliable_bytes_limit",
		.data = &shmem_reliable_limit,
		.maxlen = sizeof(shmem_reliable_limit),
		.mode = 0644,
		.proc_handler = reliable_shmem_bytes_limit_handler,
	},
#endif
	{}
};

static int __init reliable_sysctl_init(void)
{
	if (!mem_reliable_is_enabled())
		return 0;

	if (!register_sysctl("vm", reliable_ctl_table)) {
		pr_err("register sysctl failed.");
		return -ENOMEM;
	}

	percpu_counter_init(&pagecache_reliable_pages, 0, GFP_KERNEL);
	percpu_counter_init(&anon_reliable_pages, 0, GFP_KERNEL);

	return 0;
}
arch_initcall(reliable_sysctl_init);

#define PAGES_TO_KB(n_pages)	((n_pages) << (PAGE_SHIFT - 10))

void reliable_report_meminfo(struct seq_file *m)
{
	if (!mem_reliable_is_enabled())
		return;

	seq_printf(m, "ReliableTotal:    %8lu kB\n",
		   PAGES_TO_KB(total_reliable_pages()));
	seq_printf(m, "ReliableUsed:     %8lu kB\n",
		   PAGES_TO_KB(used_reliable_pages()));
	seq_printf(m, "ReliableTaskUsed: %8lu kB\n",
		   PAGES_TO_KB(task_reliable_used_pages()));
	seq_printf(m, "ReliableBuddyMem: %8lu kB\n",
		   PAGES_TO_KB(free_reliable_pages()));

	if (shmem_reliable_is_enabled()) {
		unsigned long shmem_pages = (unsigned long)percpu_counter_sum(
			&shmem_reliable_pages);
		seq_printf(m, "ReliableShmem:    %8lu kB\n",
			   PAGES_TO_KB(shmem_pages));
	}

	if (filemap_reliable_is_enabled()) {
		unsigned long nr_reliable_pages = 0;
		unsigned long num = 0;

		num += global_node_page_state(NR_LRU_BASE + LRU_ACTIVE_FILE);
		num += global_node_page_state(NR_LRU_BASE + LRU_INACTIVE_FILE);
		seq_printf(m, "FileCache:        %8lu kB\n", PAGES_TO_KB(num));

		nr_reliable_pages =
			percpu_counter_sum_positive(&pagecache_reliable_pages);
		seq_printf(m, "ReliableFileCache: %8lu kB\n",
			   PAGES_TO_KB(nr_reliable_pages));
	}
}

void mem_reliable_out_of_memory(gfp_t gfp, unsigned int order,
				int preferred_nid, nodemask_t *nodemask)
{
	struct oom_control oc = {
		.zonelist = node_zonelist(preferred_nid, gfp),
		.nodemask = nodemask,
		.memcg = NULL,
		.gfp_mask = gfp,
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
		case 'P':
			pagecache_reliable = false;
			pr_info("disable page cache use reliable memory\n");
			break;
		case 'S':
			shmem_reliable = false;
			pr_info("disable shmem use reliable memory\n");
			break;
		case 'F':
			reliable_allow_fallback = false;
			pr_info("disable memory reliable fallback\n");
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
