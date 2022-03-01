// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"mem reliable: " fmt


#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/seq_file.h>
#include <linux/mmzone.h>
#include <linux/oom.h>

#define MEM_RELIABLE_RESERVE_MIN (256UL << 20)

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
atomic_long_t reliable_user_used_nr_page;
/* reliable user limit for user tasks with reliable flag */
unsigned long task_reliable_limit = ULONG_MAX;
bool reliable_allow_fallback __read_mostly = true;
bool shmem_reliable __read_mostly = true;
struct percpu_counter reliable_shmem_used_nr_page __read_mostly;
DEFINE_PER_CPU(long, nr_reliable_buddy_pages);
unsigned long nr_reliable_reserve_pages = MEM_RELIABLE_RESERVE_MIN / PAGE_SIZE;
long shmem_reliable_nr_page = LONG_MAX;

bool pagecache_use_reliable_mem __read_mostly = true;
atomic_long_t page_cache_fallback = ATOMIC_LONG_INIT(0);
DEFINE_PER_CPU(long, pagecache_reliable_pages);
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
	return mem_reliable_is_enabled() && page_zonenum(page) < ZONE_MOVABLE;
}

static bool is_fallback_page(gfp_t gfp, struct page *page)
{
	bool ret = false;

	if (!page)
		return ret;

	if ((gfp & ___GFP_RELIABILITY) && !page_reliable(page))
		ret = true;

	return ret;
}

static bool reliable_and_lru_check(enum lru_list lru, struct page *page)
{
	if (!page || !page_reliable(page))
		return false;

	if (lru != LRU_ACTIVE_FILE && lru != LRU_INACTIVE_FILE)
		return false;

	return true;
}

void page_cache_reliable_lru_add(enum lru_list lru, struct page *page, int val)
{
	if (!reliable_and_lru_check(lru, page))
		return;

	this_cpu_add(pagecache_reliable_pages, val);
}

void page_cache_fallback_inc(gfp_t gfp, struct page *page)
{
	long num;

	if (!pagecache_reliable_is_enabled())
		return;

	if (!is_fallback_page(gfp, page))
		return;

	num = atomic_long_inc_return(&page_cache_fallback);
	if (num < 0)
		atomic_long_set(&page_cache_fallback, 0);
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

void reliable_report_meminfo(struct seq_file *m)
{
	long buddy_pages_sum = 0;
	int cpu;

	if (mem_reliable_is_enabled()) {
		for_each_possible_cpu(cpu)
			buddy_pages_sum +=
				per_cpu(nr_reliable_buddy_pages, cpu);

		seq_printf(m, "ReliableTotal:    %8lu kB\n",
			   total_reliable_mem_sz() >> 10);
		seq_printf(m, "ReliableUsed:     %8lu kB\n",
			   used_reliable_mem_sz() >> 10);
		seq_printf(m, "ReliableBuddyMem: %8lu kB\n",
			   buddy_pages_sum << (PAGE_SHIFT - 10));

		if (shmem_reliable_is_enabled()) {
			unsigned long shmem = (unsigned long)percpu_counter_sum(
				&reliable_shmem_used_nr_page) << (PAGE_SHIFT - 10);
			seq_printf(m, "ReliableShmem:    %8lu kB\n", shmem);
		}

		if (pagecache_reliable_is_enabled()) {
			unsigned long num = 0;
			int cpu;

			num += global_node_page_state(NR_LRU_BASE +
						      LRU_ACTIVE_FILE);
			num += global_node_page_state(NR_LRU_BASE +
						      LRU_INACTIVE_FILE);
			seq_printf(m, "FileCache:        %8lu kB\n",
					num << (PAGE_SHIFT - 10));

			num = 0;
			for_each_possible_cpu(cpu)
				num += per_cpu(pagecache_reliable_pages, cpu);

			seq_printf(m, "ReliableFileCache:%8lu kB\n",
					num << (PAGE_SHIFT - 10));
		}
	}
}

void reliable_report_usage(struct seq_file *m, struct mm_struct *mm)
{
	if (mem_reliable_is_enabled()) {
		seq_printf(m, "Reliable:\t%8lu kB\n",
			   atomic_long_read(&mm->reliable_nr_page));
	}
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

static void mem_reliable_feature_set(int idx, bool enable);

#define CTRL_BITS_SHIFT MEM_RELIABLE_MAX
#define CTRL_BITS_MASK ((1 << CTRL_BITS_SHIFT) - 1)

static unsigned long mem_reliable_ctrl_bits = CTRL_BITS_MASK;

static void mem_reliable_ctrl_bit_set(int idx, bool enable)
{
	if (enable)
		set_bit(idx, &mem_reliable_ctrl_bits);
	else
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

	if (!mem_reliable_is_enabled()) {
		static_branch_enable(&mem_reliable);
		mem_reliable_ctrl_bit_set(MEM_RELIABLE_ALL, 1);
		pr_info("memory reliable feature enabled.\n");
	}

	for (i = MEM_RELIABLE_FALLBACK; i < MEM_RELIABLE_MAX; i++) {
		status = !!test_bit(i, &ctrl_bits);

		if (mem_reliable_ctrl_bit_is_enabled(i) ^ status) {
			mem_reliable_ctrl_bit_set(i, status);
			mem_reliable_feature_set(i, status);
		}
	}
}

static void mem_reliable_disable_all(void)
{
	if (!mem_reliable_is_enabled())
		return;

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
		if (mem_reliable_ctrl_bits > (1 << CTRL_BITS_SHIFT) - 1) {
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

static unsigned long sysctl_reliable_reserve_size = MEM_RELIABLE_RESERVE_MIN;

int reliable_reserve_size_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	unsigned long *data_ptr = (unsigned long *)(table->data);
	unsigned long old = *data_ptr;
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, length, ppos);
	if (ret == 0 && write) {
		if (*data_ptr > total_reliable_mem_sz() ||
		    *data_ptr < MEM_RELIABLE_RESERVE_MIN) {
			*data_ptr = old;
			return -EINVAL;
		}

		nr_reliable_reserve_pages = *data_ptr / PAGE_SIZE;
	}

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
	{
		.procname = "reliable_reserve_size",
		.data = &sysctl_reliable_reserve_size,
		.maxlen = sizeof(sysctl_reliable_reserve_size),
		.mode = 0644,
		.proc_handler = reliable_reserve_size_handler,
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

static int __init reliable_sysctl_init(void)
{
	if (!mem_reliable_is_enabled())
		return 0;

	if (!register_sysctl_table(reliable_dir_table)) {
		pr_err("register sysctl failed.");
		return -1;
	}

	return 0;
}
late_initcall(reliable_sysctl_init);
#endif

static void mem_reliable_feature_set(int idx, bool enable)
{
	char *str = NULL;

	switch (idx) {
	case MEM_RELIABLE_FALLBACK:
		reliable_allow_fallback = enable;
		str = "fallback";
		break;
	case MEM_RELIABLE_SHM:
		shmem_reliable = enable;
		str = "shmem";
		break;
	case MEM_RELIABLE_PAGECACHE:
		pagecache_use_reliable_mem = enable;
		str = "pagecache";
		break;
	default:
		pr_err("unknown index: %d", idx);
		return;
	}

	pr_info("%s is %s\n", str, enable ? "enabled" : "disabled");
}

void reliable_show_mem_info(void)
{
	if (mem_reliable_is_enabled()) {
		pr_info("ReliableTotal: %lu kB", total_reliable_mem_sz() >> 10);
		pr_info("ReliableUsed: %lu kB", used_reliable_mem_sz() >> 10);
		pr_info("task_reliable_limit: %lu kB",
			task_reliable_limit >> 10);
		pr_info("reliable_user_used: %ld kB",
			atomic_long_read(&reliable_user_used_nr_page) * 4);
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
			mem_reliable_feature_set(MEM_RELIABLE_FALLBACK, false);
			break;
		case 'S':
			mem_reliable_feature_set(MEM_RELIABLE_SHM, false);
			break;
		case 'P':
			mem_reliable_feature_set(MEM_RELIABLE_PAGECACHE, false);
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
