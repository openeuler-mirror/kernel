#ifndef _PAGECACHE_H
#define _PAGECACHE_H

#ifdef CONFIG_SHRINK_PAGECACHE
enum page_cache_reclaim_flag {
	PAGE_CACHE_RECLAIM_NO_UNMAP,
	PAGE_CACHE_RECLAIM_UNMAP,
	PAGE_CACHE_RECLAIM_WRITEPAGE,
	PAGE_CACHE_RECLAIM_NR_FLAGS,
};

extern int pagecache_reclaim_enable;
extern int pagecache_limit_ratio;
extern int pagecache_reclaim_ratio;

int proc_page_cache_limit(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);
unsigned long __shrink_node_page_cache(int nid, gfp_t mask,
		unsigned long nr_to_reclaim, enum page_cache_reclaim_flag flag);
void kpagecache_limitd_stop(int nid);
int kpagecache_limitd_run(int nid);
void wakeup_all_kpagecache_limitd(void);
#else
static inline void kpagecache_limitd_stop(int nid) {}
static inline int kpagecache_limitd_run(int nid) { return 0; }
static inline void wakeup_all_kpagecache_limitd(void) {}
#endif

#endif
