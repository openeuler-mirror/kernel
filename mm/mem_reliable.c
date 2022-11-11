// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"mem reliable: " fmt

#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/seq_file.h>
#include <linux/mmzone.h>

DEFINE_STATIC_KEY_FALSE(mem_reliable);
EXPORT_SYMBOL_GPL(mem_reliable);

bool reliable_enabled;

static atomic_long_t total_reliable_mem;
bool shmem_reliable __read_mostly = true;

bool mem_reliable_status(void)
{
	return mem_reliable_is_enabled();
}
EXPORT_SYMBOL_GPL(mem_reliable_status);

void page_cache_prepare_alloc(gfp_t *gfp)
{
	if (mem_reliable_is_enabled())
		*gfp |= GFP_RELIABLE;
}

void add_reliable_mem_size(long sz)
{
	atomic_long_add(sz, &total_reliable_mem);
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
		pr_err("init failed, mirrored memory size is zero.\n");
		return;
	}

	if (!has_unmirrored_mem) {
		pr_err("init failed, unmirrored memory size is zero.\n");
		return;
	}

	if (register_hotmemory_notifier(&reliable_notifier_block)) {
		pr_err("init failed, register memory notifier failed.\n");
		return;
	}

	static_branch_enable(&mem_reliable);

	pr_info("init succeed, mirrored memory size(%lu)\n",
		total_reliable_mem_sz());
}

void shmem_reliable_init(void)
{
	if (!mem_reliable_is_enabled() || !shmem_reliable_is_enabled())
		shmem_reliable = false;
}

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num << (PAGE_SHIFT - 10), 8);
	seq_write(m, " kB\n", 4);
}

void reliable_report_meminfo(struct seq_file *m)
{
	if (!mem_reliable_is_enabled())
		return;

	show_val_kb(m, "ReliableTotal:    ",
			total_reliable_mem_sz() >> PAGE_SHIFT);
	show_val_kb(m, "ReliableUsed:     ",
			used_reliable_mem_sz() >> PAGE_SHIFT);
}
