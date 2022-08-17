/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_CACHE_LIMIT_H
#define _LINUX_PAGE_CACHE_LIMIT_H
#ifdef CONFIG_PAGE_CACHE_LIMIT
extern unsigned long page_cache_shrink_memory(unsigned long nr_to_reclaim,
						bool may_swap);
#endif /* CONFIG_PAGE_CACHE_LIMIT */
#endif /* _LINUX_PAGE_CACHE_LIMIT_H */
