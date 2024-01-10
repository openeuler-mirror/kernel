// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"mem reliable: " fmt

#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/crash_dump.h>

#define PAGES_TO_B(n_pages)	((n_pages) << PAGE_SHIFT)

DEFINE_STATIC_KEY_FALSE(mem_reliable);
EXPORT_SYMBOL_GPL(mem_reliable);

bool reliable_enabled;
bool shmem_reliable __read_mostly = true;
bool pagecache_reliable __read_mostly = true;

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
	if (!mem_reliable_is_enabled() || !shmem_reliable_is_enabled())
		shmem_reliable = false;
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
		default:
			pr_err("reliable_debug option '%c' unknown. skipped\n",
			       *str);
		}
	}

out:
	return 1;
}
__setup("reliable_debug", setup_reliable_debug);
