#include <linux/mm.h>
#include <linux/sysctl.h>

int pagecache_reclaim_enable;
int pagecache_limit_ratio;
int pagecache_reclaim_ratio;

static unsigned long pagecache_limit_pages;
static unsigned long node_pagecache_limit_pages[MAX_NUMNODES];

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
