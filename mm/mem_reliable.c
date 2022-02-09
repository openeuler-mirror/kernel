// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"mem reliable: " fmt


#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/seq_file.h>
#include <linux/mmzone.h>

DEFINE_STATIC_KEY_FALSE(mem_reliable);

bool reliable_enabled;
static atomic_long_t total_reliable_mem;
atomic_long_t reliable_user_used_nr_page;

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
	}
}

void reliable_report_usage(struct seq_file *m, struct mm_struct *mm)
{
	if (mem_reliable_is_enabled()) {
		seq_printf(m, "Reliable:\t%8lu kB\n",
			   atomic_long_read(&mm->reliable_nr_page));
	}
}
