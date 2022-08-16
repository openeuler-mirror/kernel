#ifndef _PAGECACHE_H
#define _PAGECACHE_H

#ifdef CONFIG_SHRINK_PAGECACHE
extern int pagecache_reclaim_enable;
extern int pagecache_limit_ratio;
extern int pagecache_reclaim_ratio;

int proc_page_cache_limit(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);
#else
#endif

#endif
