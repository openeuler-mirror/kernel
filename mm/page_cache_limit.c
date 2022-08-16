#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/swap.h>
#include <linux/page_cache_limit.h>

int pagecache_reclaim_enable;
int pagecache_limit_ratio;
int pagecache_reclaim_ratio;

static unsigned long pagecache_limit_pages;
static unsigned long node_pagecache_limit_pages[MAX_NUMNODES];
static wait_queue_head_t *pagecache_limitd_wait_queue[MAX_NUMNODES];
static struct task_struct *pagecache_limitd_tasks[MAX_NUMNODES];

static unsigned long get_node_total_pages(int nid)
{
	int zone_type;
	unsigned long managed_pages = 0;
	pg_data_t *pgdat = NODE_DATA(nid);

	if (!pgdat)
		return 0;

	for (zone_type = 0; zone_type < MAX_NR_ZONES; zone_type++)
		managed_pages += zone_managed_pages(&pgdat->node_zones[zone_type]);

	return managed_pages;
}

static void setup_pagecache_limit(void)
{
	int i;
	unsigned long node_total_pages;

	pagecache_limit_pages = pagecache_limit_ratio * totalram_pages() / 100;

	for (i = 0; i < MAX_NUMNODES; i++) {
		node_total_pages = get_node_total_pages(i);
		node_pagecache_limit_pages[i] = node_total_pages *
						pagecache_limit_ratio / 100;
	}
}

int proc_page_cache_limit(struct ctl_table *table, int write,
		   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && !ret)
		setup_pagecache_limit();

	return ret;
}

void kpagecache_limitd_stop(int nid)
{
	if (nid < 0 || nid >= MAX_NUMNODES)
		return;

	if (pagecache_limitd_tasks[nid]) {
		kthread_stop(pagecache_limitd_tasks[nid]);
		pagecache_limitd_tasks[nid] = NULL;
	}

	if (pagecache_limitd_wait_queue[nid]) {
		kvfree(pagecache_limitd_wait_queue[nid]);
		pagecache_limitd_wait_queue[nid] = NULL;
	}
}

static void wakeup_kpagecache_limitd(int nid)
{
	if (!pagecache_limitd_wait_queue[nid])
		return;

	if (!waitqueue_active(pagecache_limitd_wait_queue[nid]))
		return;

	wake_up_interruptible(pagecache_limitd_wait_queue[nid]);
}

static bool pagecache_overlimit(void)
{
	unsigned long total_pagecache;

	total_pagecache = global_node_page_state(NR_FILE_PAGES);
	total_pagecache -= global_node_page_state(NR_SHMEM);

	return total_pagecache > pagecache_limit_pages;
}

void wakeup_all_kpagecache_limitd(void)
{
	int nid;

	if (!pagecache_reclaim_enable || !pagecache_overlimit())
		return;

	for_each_node_state(nid, N_MEMORY)
		wakeup_kpagecache_limitd(nid);
}

static unsigned long node_nr_page_cache(int nid)
{
	struct pglist_data *pgdat;
	unsigned long num = 0;

	pgdat = NODE_DATA(nid);
	if (!pgdat)
		return 0;

	num = node_page_state(pgdat, NR_FILE_PAGES);
	num -= node_page_state(pgdat, NR_SHMEM);

	return num;
}

static unsigned long node_nr_page_reclaim(int nid)
{
	unsigned long nr_page_cache;
	unsigned long nr_to_reclaim;
	unsigned long total_pages;

	if (!node_pagecache_limit_pages[nid])
		return 0;

	nr_page_cache = node_nr_page_cache(nid);
	if (!nr_page_cache)
		return 0;

	if (nr_page_cache < node_pagecache_limit_pages[nid])
		return 0;

	total_pages = get_node_total_pages(nid);
	nr_to_reclaim = nr_page_cache - node_pagecache_limit_pages[nid];
	nr_to_reclaim += total_pages * pagecache_reclaim_ratio / 100;

	return nr_to_reclaim;
}

static void shrink_node_page_cache(int nid, gfp_t mask)
{
	int i;
	unsigned long nr_to_reclaim;
	unsigned long nr_reclaimed;
	enum page_cache_reclaim_flag flag;

	nr_to_reclaim = node_nr_page_reclaim(nid);
	if (nr_to_reclaim <= 0)
		return;

	flag = 0;
	for (i = PAGE_CACHE_RECLAIM_NO_UNMAP;
			i < PAGE_CACHE_RECLAIM_NR_FLAGS; i++) {
		nr_reclaimed = __shrink_node_page_cache(nid, mask, nr_to_reclaim, flag);
		nr_to_reclaim -= nr_reclaimed;

		if (nr_to_reclaim <= 0)
			break;

		flag |= i;
	}
}

static void shrink_page_cache(gfp_t mask)
{
	int nid;

	if (!pagecache_reclaim_enable || !pagecache_overlimit())
		return;

	for_each_node_state(nid, N_MEMORY)
		shrink_node_page_cache(nid, mask);
}

static DECLARE_COMPLETION(setup_done);
static int pagecache_limitd(void *arg)
{
	DEFINE_WAIT(wait);
	int nid = *(int *)arg;

	if (nid < 0 || nid >= MAX_NUMNODES)
		nid = numa_node_id();

	complete(&setup_done);
	set_freezable();
	for (;;) {
		try_to_freeze();
		shrink_page_cache(GFP_KERNEL | __GFP_HIGHMEM);

		prepare_to_wait(pagecache_limitd_wait_queue[nid], &wait,
				TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		schedule();
		finish_wait(pagecache_limitd_wait_queue[nid], &wait);
	}

	finish_wait(pagecache_limitd_wait_queue[nid], &wait);

	return 0;
}

int kpagecache_limitd_run(int nid)
{
	int ret = 0;
	wait_queue_head_t *queue_head = NULL;

	if (pagecache_limitd_tasks[nid] && pagecache_limitd_wait_queue[nid])
		return 0;

	queue_head = kvmalloc(sizeof(wait_queue_head_t), GFP_KERNEL);
	if (!queue_head)
		return -ENOMEM;

	init_waitqueue_head(queue_head);
	pagecache_limitd_wait_queue[nid] = queue_head;
	pagecache_limitd_tasks[nid] = kthread_run(pagecache_limitd,
			(void *)&nid, "kpagecache_limitd%d", nid);

	if (IS_ERR(pagecache_limitd_tasks[nid])) {
		BUG_ON(system_state < SYSTEM_RUNNING);
		ret = PTR_ERR(pagecache_limitd_tasks[nid]);
		pr_err("Failed to start pagecache_limitd on node %d\n", nid);
		pagecache_limitd_tasks[nid] = NULL;
		kvfree(queue_head);
	} else
		wait_for_completion(&setup_done);

	return ret;
}

static int __init kpagecache_limitd_init(void)
{
	int nid;
	int ret;

	for_each_node_state(nid, N_MEMORY) {
		ret = kpagecache_limitd_run(nid);
		if (ret == -ENOMEM)
			break;
	}

	return 0;
}

module_init(kpagecache_limitd_init);
