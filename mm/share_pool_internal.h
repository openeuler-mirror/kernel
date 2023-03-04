/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SHARE_POOL_INTERNAL_H
#define SHARE_POOL_INTERNAL_H

#include <linux/hugetlb.h>
#include <linux/memcontrol.h>

#ifdef CONFIG_ASCEND_SHARE_POOL
static inline void sp_memcg_uncharge_hpage(struct page *page)
{
	if (!sp_is_enabled())
		return;

	mem_cgroup_uncharge(page);
}
#else
static inline void sp_memcg_uncharge_hpage(struct page *page)
{
}
#endif

#endif
