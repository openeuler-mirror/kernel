/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __LINUX_DYNAMIC_HUGETLB_H
#define __LINUX_DYNAMIC_HUGETLB_H

#include <linux/page_counter.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/memcontrol.h>

#ifdef CONFIG_DYNAMIC_HUGETLB

extern bool enable_dhugetlb;
extern struct static_key_false dhugetlb_enabled_key;
#define dhugetlb_enabled (static_branch_unlikely(&dhugetlb_enabled_key))

#define NR_PERCPU_POOL		num_possible_cpus()
#define PERCPU_POOL_PAGE_MAX	1024
#define PERCPU_POOL_PAGE_BATCH	(PERCPU_POOL_PAGE_MAX >> 2)

struct split_hugepage {
	struct list_head head_pages;
	unsigned long start_pfn;
};

struct percpu_pages_pool {
	spinlock_t lock;
	unsigned long free_pages;
	long used_pages;
	struct list_head head_page;
};

struct huge_pages_pool {
	/*
	 * This four counts is used for huge page allocation.
	 */
	unsigned long nr_huge_pages;
	unsigned long free_huge_pages;
	unsigned long resv_huge_pages;
	unsigned long used_huge_pages;
	/*
	 * free_normal_pages means how many huge pages can be split to
	 * smaller pages or reserved for huge page allocation.
	 */
	unsigned long free_normal_pages;
	/*
	 * split_normal_pages means how many huge pages have already been
	 * split.
	 */
	unsigned long split_normal_pages;
	struct list_head hugepage_freelists;
	/* Used to record which hugepages have been split */
	struct list_head hugepage_splitlists;
};

enum huge_pages_pool_type {
	HUGE_PAGES_POOL_1G,
	HUGE_PAGES_POOL_2M,
	HUGE_PAGES_POOL_4K,
	HUGE_PAGES_POOL_MAX,
};
/*
 * Dynamic hugetlb pool data structure. Each Dynamic hugetlb pool is
 * associated with one memory cgroup and controls the allocation of memory
 * resources for both processes and files which belongs to the memory cgroup.
 */
struct dhugetlb_pool {
	int nid;
	spinlock_t lock;
	spinlock_t reserved_lock;
	atomic_t refcnt;
	unsigned long normal_pages_disabled;

	struct mem_cgroup *attach_memcg;

	unsigned long total_huge_pages;
	struct huge_pages_pool hpages_pool[HUGE_PAGES_POOL_MAX];
	struct percpu_pages_pool percpu_pool[0];
};

bool dhugetlb_hide_files(struct cftype *cft);
ssize_t write_2M_reserved_pages(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);
ssize_t write_1G_reserved_pages(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);
int normal_pages_disabled_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val);
u64 normal_pages_disabled_read(struct cgroup_subsys_state *css, struct cftype *cft);
ssize_t write_hugepage_to_hpool(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);
int hugetlb_pool_info_show(struct seq_file *m, void *v);
void hugetlb_pool_inherit(struct mem_cgroup *memcg, struct mem_cgroup *parent);
int hugetlb_pool_destroy(struct cgroup *cgrp);
void __init dynamic_hugetlb_init(void);

struct page *alloc_page_from_dhugetlb_pool(gfp_t gfp, unsigned int order,
					   unsigned int flags);
bool free_page_to_dhugetlb_pool(struct page *page);
void free_page_list_to_dhugetlb_pool(struct list_head *list);
int task_has_mem_in_hpool(struct task_struct *tsk);

void link_hpool(struct hugetlbfs_inode_info *p);
void unlink_hpool(struct hugetlbfs_inode_info *p);
bool file_has_mem_in_hpool(struct hugetlbfs_inode_info *p);
int dhugetlb_acct_memory(struct hstate *h, long delta, struct hugetlbfs_inode_info *p);
struct page *alloc_huge_page_from_dhugetlb_pool(struct hstate *h, struct dhugetlb_pool *hpool,
						bool need_unreserved);
void free_huge_page_to_dhugetlb_pool(struct page *page, bool restore_reserve);

#else

#define enable_dhugetlb		0
#define dhugetlb_enabled	0

struct dhugetlb_pool {};

#ifdef CONFIG_CGROUPS
static inline bool dhugetlb_hide_files(struct cftype *cft)
{
	return false;
}
#endif
static inline void hugetlb_pool_inherit(struct mem_cgroup *memcg, struct mem_cgroup *parent)
{
}
static inline int hugetlb_pool_destroy(struct cgroup *cgrp)
{
	return 0;
}
static inline void __init dynamic_hugetlb_init(void)
{
}

static inline struct page *alloc_page_from_dhugetlb_pool(gfp_t gfp, unsigned int order,
							 unsigned int flags)
{
	return NULL;
}
static inline bool free_page_to_dhugetlb_pool(struct page *page)
{
	return false;
}
static inline void free_page_list_to_dhugetlb_pool(struct list_head *list)
{
}
static inline int task_has_mem_in_hpool(struct task_struct *tsk)
{
	return 0;
}

#ifdef CONFIG_HUGETLBFS
static inline void link_hpool(struct hugetlbfs_inode_info *p)
{
}
static inline void unlink_hpool(struct hugetlbfs_inode_info *p)
{
}
static inline bool file_has_mem_in_hpool(struct hugetlbfs_inode_info *p)
{
	return false;
}
static inline int dhugetlb_acct_memory(struct hstate *h, long delta, struct hugetlbfs_inode_info *p)
{
	return 0;
}
static inline
struct page *alloc_huge_page_from_dhugetlb_pool(struct hstate *h, struct dhugetlb_pool *hpool,
						bool need_unreserved)
{
	return NULL;
}
static inline
void free_huge_page_to_dhugetlb_pool(struct page *page, bool restore_reserve)
{
}
#endif

#endif /* CONFIG_DYNAMIC_HUGETLB */
#endif /* __LINUX_DYNAMIC_HUGETLB_H */
