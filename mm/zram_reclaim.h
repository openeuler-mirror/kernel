/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_ZRAM_RECLAIM_H
#define _MM_ZRAM_RECLAIM_H

#include <linux/memcontrol.h>

#ifdef CONFIG_ZRAM_RECLAIM
void zram_reclaim_memcg_free(struct mem_cgroup *memcg);

void zram_reclaim_note_cost_folio(struct folio *folio, bool file);

bool zram_reclaim_should_use_policy(struct lruvec *lruvec,
				    struct mem_cgroup *memcg, char priority, int *swappiness);
#else
static inline void zram_reclaim_memcg_free(struct mem_cgroup *memcg) { }

static inline void zram_reclaim_note_cost_folio(struct folio *folio, bool file) { }

static inline bool zram_reclaim_should_use_policy(struct lruvec *lruvec,
					 struct mem_cgroup *memcg, char priority, int *swappiness)
{
	return false;
}
#endif

#endif /* _MM_ZRAM_RECLAIM_H */
