// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"mem reliable: " fmt


#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/seq_file.h>
#include <linux/mmzone.h>
#include <linux/oom.h>

DEFINE_STATIC_KEY_FALSE(mem_reliable);

bool reliable_enabled;
static atomic_long_t total_reliable_mem;
atomic_long_t reliable_user_used_nr_page;
/* reliable user limit for user tasks with reliable flag */
unsigned long task_reliable_limit = ULONG_MAX;
bool reliable_allow_fallback __read_mostly = true;
bool shmem_reliable __read_mostly = true;
struct percpu_counter reliable_shmem_used_nr_page __read_mostly;

bool pagecache_use_reliable_mem __read_mostly = true;
void add_reliable_mem_size(long sz)
{
	atomic_long_add(sz, &total_reliable_mem);
}

bool page_reliable(struct page *page)
{
	return mem_reliable_is_enabled() && page_zonenum(page) < ZONE_MOVABLE;
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
	if (mem_reliable_is_enabled()) {
		seq_printf(m, "ReliableTotal:    %8lu kB\n",
			   total_reliable_mem_sz() >> 10);
		seq_printf(m, "ReliableUsed:     %8lu kB\n",
			   used_reliable_mem_sz() >> 10);

		if (shmem_reliable_is_enabled()) {
			unsigned long shmem = (unsigned long)percpu_counter_sum(
				&reliable_shmem_used_nr_page) << (PAGE_SHIFT - 10);
			seq_printf(m, "ReliableShmem:    %8lu kB\n", shmem);
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

static struct ctl_table reliable_ctl_table[] = {
	{
		.procname = "task_reliable_limit",
		.data = &task_reliable_limit,
		.maxlen = sizeof(task_reliable_limit),
		.mode = 0644,
		.proc_handler = reliable_limit_handler,
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
			reliable_allow_fallback = false;
			pr_info("fallback disabled.");
			break;
		case 'S':
			shmem_reliable = false;
			pr_info("shmem reliable disabled.");
			break;
		case 'P':
			pagecache_use_reliable_mem = false;
			pr_info("disable page cache use reliable memory\n");
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
