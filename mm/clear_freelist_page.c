// SPDX-License-Identifier: GPL-2.0
/*
 * Support for clear free list pages.
 */

#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/nmi.h>
#include <linux/sched/clock.h>
#include <linux/module.h>

#define CFP_DEFAULT_TIMEOUT 2000
#define for_each_populated_zone_pgdat(pgdat, zone) \
	for (zone = pgdat->node_zones;      \
		zone;                  \
		zone = next_pgdat_zone(zone))      \
		if (!populated_zone(zone))      \
			; /* do nothing */      \
		else

struct pgdat_entry {
	struct pglist_data *pgdat;
	struct work_struct work;
};

static DECLARE_WAIT_QUEUE_HEAD(clear_freelist_wait);
static DEFINE_MUTEX(clear_freelist_lock);
static atomic_t clear_freelist_workers;
static atomic_t clear_pages_num;
static ulong cfp_timeout_ms = CFP_DEFAULT_TIMEOUT;

/*
 * next_pgdat_zone - helper magic for for_each_populated_zone_pgdat()
 */
static struct zone *next_pgdat_zone(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
		zone++;
	else
		zone = NULL;
	return zone;
}

static void clear_pgdat_freelist_pages(struct work_struct *work)
{
	struct pgdat_entry *entry = container_of(work, struct pgdat_entry, work);
	u64 cfp_timeout_ns = cfp_timeout_ms * NSEC_PER_MSEC;
	struct pglist_data *pgdat = entry->pgdat;
	unsigned long flags, order, t;
	struct page *page;
	struct zone *zone;
	u64 start, now;

	start = sched_clock();

	for_each_populated_zone_pgdat(pgdat, zone) {
		spin_lock_irqsave(&zone->lock, flags);
		for_each_migratetype_order(order, t) {
			list_for_each_entry(page, &zone->free_area[order].free_list[t], lru) {
				now = sched_clock();
				if (unlikely(now - start > cfp_timeout_ns)) {
					spin_unlock_irqrestore(&zone->lock, flags);
					goto out;
				}

#ifdef CONFIG_KMAP_LOCAL
				int i;

				/* Clear highmem by clear_highpage() */
				for (i = 0; i < (1 << order); i++)
					clear_highpage(page + i);
#else
				memset(page_address(page), 0, (1 << order) * PAGE_SIZE);
#endif
				touch_nmi_watchdog();
				atomic_add(1 << order, &clear_pages_num);
			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);

		cond_resched();
	}

out:
	kfree(entry);

	if (atomic_dec_and_test(&clear_freelist_workers))
		wake_up(&clear_freelist_wait);
}

static void init_clear_freelist_work(struct pglist_data *pgdat)
{
	struct pgdat_entry *entry;

	entry = kzalloc(sizeof(struct pgdat_entry), GFP_KERNEL);
	if (!entry)
		return;

	entry->pgdat = pgdat;
	INIT_WORK(&entry->work, clear_pgdat_freelist_pages);
	queue_work_node(pgdat->node_id, system_unbound_wq, &entry->work);
}

static void clear_freelist_pages(void)
{
	struct pglist_data *pgdat;

	mutex_lock(&clear_freelist_lock);
	drain_all_pages(NULL);

	for_each_online_pgdat(pgdat) {
		atomic_inc(&clear_freelist_workers);
		init_clear_freelist_work(pgdat);
	}

	wait_event(clear_freelist_wait, atomic_read(&clear_freelist_workers) == 0);

	pr_debug("Cleared pages %d\nFree pages %lu\n", atomic_read(&clear_pages_num),
		global_zone_page_state(NR_FREE_PAGES));
	atomic_set(&clear_pages_num, 0);

	mutex_unlock(&clear_freelist_lock);
}

static int sysctl_clear_freelist_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	int val;

	table->data = &val;
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (!ret && write)
		clear_freelist_pages();

	return ret;
}

static struct ctl_table clear_freelist_table[] = {
	{
		.procname   = "clear_freelist_pages",
		.data       = NULL,
		.maxlen     = sizeof(int),
		.mode       = 0200,
		.proc_handler   = &sysctl_clear_freelist_handler,
		.extra1     = SYSCTL_ONE,
		.extra2     = SYSCTL_ONE,
	},
	{ }
};

static struct ctl_table sys_ctl_table[] = {
	{
		.procname   = "vm",
		.mode       = 0555,
		.child      = clear_freelist_table,
	},
	{ }
};

static bool clear_freelist_enabled;
static int __init setup_clear_freelist(char *str)
{
	clear_freelist_enabled = true;
	return 1;
}
__setup("clear_freelist", setup_clear_freelist);

static int __init clear_freelist_init(void)
{
	if (clear_freelist_enabled)
		register_sysctl_table(sys_ctl_table);

	return 0;
}
module_init(clear_freelist_init);
module_param(cfp_timeout_ms, ulong, 0644);
