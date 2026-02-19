/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM kmem

#if !defined(_TRACE_KMEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KMEM_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <trace/events/mmflags.h>
#ifdef CONFIG_MEM_SAMPLING
#include <linux/mem_sampling.h>
#endif

TRACE_EVENT(kmem_cache_alloc,

	TP_PROTO(unsigned long call_site,
		 const void *ptr,
		 struct kmem_cache *s,
		 gfp_t gfp_flags,
		 int node),

	TP_ARGS(call_site, ptr, s, gfp_flags, node),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
		__field(	size_t,		bytes_req	)
		__field(	size_t,		bytes_alloc	)
		__field(	unsigned long,	gfp_flags	)
		__field(	int,		node		)
		__field(	bool,		accounted	)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
		__entry->bytes_req	= s->object_size;
		__entry->bytes_alloc	= s->size;
		__entry->gfp_flags	= (__force unsigned long)gfp_flags;
		__entry->node		= node;
		__entry->accounted	= IS_ENABLED(CONFIG_MEMCG_KMEM) ?
					  ((gfp_flags & __GFP_ACCOUNT) ||
					  (s->flags & SLAB_ACCOUNT)) : false;
	),

	TP_printk("call_site=%pS ptr=%p bytes_req=%zu bytes_alloc=%zu gfp_flags=%s node=%d accounted=%s",
		(void *)__entry->call_site,
		__entry->ptr,
		__entry->bytes_req,
		__entry->bytes_alloc,
		show_gfp_flags(__entry->gfp_flags),
		__entry->node,
		__entry->accounted ? "true" : "false")
);

TRACE_EVENT(kmalloc,

	TP_PROTO(unsigned long call_site,
		 const void *ptr,
		 size_t bytes_req,
		 size_t bytes_alloc,
		 gfp_t gfp_flags,
		 int node),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
		__field(	size_t,		bytes_req	)
		__field(	size_t,		bytes_alloc	)
		__field(	unsigned long,	gfp_flags	)
		__field(	int,		node		)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
		__entry->bytes_req	= bytes_req;
		__entry->bytes_alloc	= bytes_alloc;
		__entry->gfp_flags	= (__force unsigned long)gfp_flags;
		__entry->node		= node;
	),

	TP_printk("call_site=%pS ptr=%p bytes_req=%zu bytes_alloc=%zu gfp_flags=%s node=%d accounted=%s",
		(void *)__entry->call_site,
		__entry->ptr,
		__entry->bytes_req,
		__entry->bytes_alloc,
		show_gfp_flags(__entry->gfp_flags),
		__entry->node,
		(IS_ENABLED(CONFIG_MEMCG_KMEM) &&
		 (__entry->gfp_flags & (__force unsigned long)__GFP_ACCOUNT)) ? "true" : "false")
);

TRACE_EVENT(kfree,

	TP_PROTO(unsigned long call_site, const void *ptr),

	TP_ARGS(call_site, ptr),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
	),

	TP_printk("call_site=%pS ptr=%p",
		  (void *)__entry->call_site, __entry->ptr)
);

TRACE_EVENT(kmem_cache_free,

	TP_PROTO(unsigned long call_site, const void *ptr, const struct kmem_cache *s),

	TP_ARGS(call_site, ptr, s),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
		__string(	name,		s->name		)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
		__assign_str(name, s->name);
	),

	TP_printk("call_site=%pS ptr=%p name=%s",
		  (void *)__entry->call_site, __entry->ptr, __get_str(name))
);

TRACE_EVENT(mm_page_free,

	TP_PROTO(struct page *page, unsigned int order),

	TP_ARGS(page, order),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
	),

	TP_fast_assign(
		__entry->pfn		= page_to_pfn(page);
		__entry->order		= order;
	),

	TP_printk("page=%p pfn=0x%lx order=%d",
			pfn_to_page(__entry->pfn),
			__entry->pfn,
			__entry->order)
);

TRACE_EVENT(mm_page_free_batched,

	TP_PROTO(struct page *page),

	TP_ARGS(page),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
	),

	TP_fast_assign(
		__entry->pfn		= page_to_pfn(page);
	),

	TP_printk("page=%p pfn=0x%lx order=0",
			pfn_to_page(__entry->pfn),
			__entry->pfn)
);

TRACE_EVENT(mm_page_alloc,

	TP_PROTO(struct page *page, unsigned int order,
			gfp_t gfp_flags, int migratetype),

	TP_ARGS(page, order, gfp_flags, migratetype),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
		__field(	unsigned long,	gfp_flags	)
		__field(	int,		migratetype	)
	),

	TP_fast_assign(
		__entry->pfn		= page ? page_to_pfn(page) : -1UL;
		__entry->order		= order;
		__entry->gfp_flags	= (__force unsigned long)gfp_flags;
		__entry->migratetype	= migratetype;
	),

	TP_printk("page=%p pfn=0x%lx order=%d migratetype=%d gfp_flags=%s",
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn != -1UL ? __entry->pfn : 0,
		__entry->order,
		__entry->migratetype,
		show_gfp_flags(__entry->gfp_flags))
);

DECLARE_EVENT_CLASS(mm_page,

	TP_PROTO(struct page *page, unsigned int order, int migratetype,
		 int percpu_refill),

	TP_ARGS(page, order, migratetype, percpu_refill),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
		__field(	int,		migratetype	)
		__field(	int,		percpu_refill	)
	),

	TP_fast_assign(
		__entry->pfn		= page ? page_to_pfn(page) : -1UL;
		__entry->order		= order;
		__entry->migratetype	= migratetype;
		__entry->percpu_refill	= percpu_refill;
	),

	TP_printk("page=%p pfn=0x%lx order=%u migratetype=%d percpu_refill=%d",
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn != -1UL ? __entry->pfn : 0,
		__entry->order,
		__entry->migratetype,
		__entry->percpu_refill)
);

DEFINE_EVENT(mm_page, mm_page_alloc_zone_locked,

	TP_PROTO(struct page *page, unsigned int order, int migratetype,
		 int percpu_refill),

	TP_ARGS(page, order, migratetype, percpu_refill)
);

TRACE_EVENT(mm_page_pcpu_drain,

	TP_PROTO(struct page *page, unsigned int order, int migratetype),

	TP_ARGS(page, order, migratetype),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
		__field(	int,		migratetype	)
	),

	TP_fast_assign(
		__entry->pfn		= page ? page_to_pfn(page) : -1UL;
		__entry->order		= order;
		__entry->migratetype	= migratetype;
	),

	TP_printk("page=%p pfn=0x%lx order=%d migratetype=%d",
		pfn_to_page(__entry->pfn), __entry->pfn,
		__entry->order, __entry->migratetype)
);

TRACE_EVENT(mm_page_alloc_extfrag,

	TP_PROTO(struct page *page,
		int alloc_order, int fallback_order,
		int alloc_migratetype, int fallback_migratetype),

	TP_ARGS(page,
		alloc_order, fallback_order,
		alloc_migratetype, fallback_migratetype),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn			)
		__field(	int,		alloc_order		)
		__field(	int,		fallback_order		)
		__field(	int,		alloc_migratetype	)
		__field(	int,		fallback_migratetype	)
		__field(	int,		change_ownership	)
	),

	TP_fast_assign(
		__entry->pfn			= page_to_pfn(page);
		__entry->alloc_order		= alloc_order;
		__entry->fallback_order		= fallback_order;
		__entry->alloc_migratetype	= alloc_migratetype;
		__entry->fallback_migratetype	= fallback_migratetype;
		__entry->change_ownership	= (alloc_migratetype ==
					get_pageblock_migratetype(page));
	),

	TP_printk("page=%p pfn=0x%lx alloc_order=%d fallback_order=%d pageblock_order=%d alloc_migratetype=%d fallback_migratetype=%d fragmenting=%d change_ownership=%d",
		pfn_to_page(__entry->pfn),
		__entry->pfn,
		__entry->alloc_order,
		__entry->fallback_order,
		pageblock_order,
		__entry->alloc_migratetype,
		__entry->fallback_migratetype,
		__entry->fallback_order < pageblock_order,
		__entry->change_ownership)
);

TRACE_EVENT(mm_alloc_contig_migrate_range_info,

	TP_PROTO(unsigned long start,
		 unsigned long end,
		 unsigned long nr_migrated,
		 unsigned long nr_reclaimed,
		 unsigned long nr_mapped,
		 int migratetype),

	TP_ARGS(start, end, nr_migrated, nr_reclaimed, nr_mapped, migratetype),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned long, nr_migrated)
		__field(unsigned long, nr_reclaimed)
		__field(unsigned long, nr_mapped)
		__field(int, migratetype)
	),

	TP_fast_assign(
		__entry->start = start;
		__entry->end = end;
		__entry->nr_migrated = nr_migrated;
		__entry->nr_reclaimed = nr_reclaimed;
		__entry->nr_mapped = nr_mapped;
		__entry->migratetype = migratetype;
	),

	TP_printk("start=0x%lx end=0x%lx migratetype=%d nr_migrated=%lu nr_reclaimed=%lu nr_mapped=%lu",
		  __entry->start,
		  __entry->end,
		  __entry->migratetype,
		  __entry->nr_migrated,
		  __entry->nr_reclaimed,
		  __entry->nr_mapped)
);

/*
 * Required for uniquely and securely identifying mm in rss_stat tracepoint.
 */
#ifndef __PTR_TO_HASHVAL
static unsigned int __maybe_unused mm_ptr_to_hash(const void *ptr)
{
	int ret;
	unsigned long hashval;

	ret = ptr_to_hashval(ptr, &hashval);
	if (ret)
		return 0;

	/* The hashed value is only 32-bit */
	return (unsigned int)hashval;
}
#define __PTR_TO_HASHVAL
#endif

#define TRACE_MM_PAGES		\
	EM(MM_FILEPAGES)	\
	EM(MM_ANONPAGES)	\
	EM(MM_SWAPENTS)		\
	EMe(MM_SHMEMPAGES)

#undef EM
#undef EMe

#define EM(a)	TRACE_DEFINE_ENUM(a);
#define EMe(a)	TRACE_DEFINE_ENUM(a);

TRACE_MM_PAGES

#undef EM
#undef EMe

#define EM(a)	{ a, #a },
#define EMe(a)	{ a, #a }

TRACE_EVENT(rss_stat,

	TP_PROTO(struct mm_struct *mm,
		int member),

	TP_ARGS(mm, member),

	TP_STRUCT__entry(
		__field(unsigned int, mm_id)
		__field(unsigned int, curr)
		__field(int, member)
		__field(long, size)
	),

	TP_fast_assign(
		__entry->mm_id = mm_ptr_to_hash(mm);
		/*
		 * curr is true if the mm matches the current task's mm_struct.
		 * Since kthreads (PF_KTHREAD) have no mm_struct of their own
		 * but can borrow one via kthread_use_mm(), we must filter them
		 * out to avoid incorrectly attributing the RSS update to them.
		 */
		__entry->curr = current->mm == mm && !(current->flags & PF_KTHREAD);
		__entry->member = member;
		__entry->size = (get_mm_counter_sum(mm, member)
							<< PAGE_SHIFT);
	),

	TP_printk("mm_id=%u curr=%d type=%s size=%ldB",
		__entry->mm_id,
		__entry->curr,
		__print_symbolic(__entry->member, TRACE_MM_PAGES),
		__entry->size)
	);
#ifdef CONFIG_ARM_SPE_MEM_SAMPLING
TRACE_EVENT(mm_spe_record,
	TP_PROTO(struct mem_sampling_record *record),

	TP_ARGS(record),

	TP_STRUCT__entry(
		__field(u64, vaddr)
		__field(u64, paddr)
		__field(int, pid)
	),

	TP_fast_assign(
		__entry->vaddr = record->virt_addr;
		__entry->paddr = record->phys_addr;
		__entry->pid = record->context_id;

	),

	TP_printk("vaddr=%llu paddr=%llu pid=%d",
		__entry->vaddr, __entry->paddr, __entry->pid)
);

TRACE_EVENT(spe_boost_spe_record,
	TP_PROTO(struct mem_sampling_record *record),

	TP_ARGS(record),

	TP_STRUCT__entry(
		__field(u64, boost_spe_pa1)
		__field(u64, boost_spe_pa2)
		__field(u64, boost_spe_pa3)
		__field(u64, boost_spe_pa4)
		__field(u64, boost_spe_pa5)
		__field(u64, boost_spe_pa6)
		__field(u64, boost_spe_pa7)
		__field(u64, boost_spe_pa8)
	),

	TP_fast_assign(
		__entry->boost_spe_pa1 = record->boost_spe_addr[0];
		__entry->boost_spe_pa2 = record->boost_spe_addr[1];
		__entry->boost_spe_pa3 = record->boost_spe_addr[2];
		__entry->boost_spe_pa4 = record->boost_spe_addr[3];
		__entry->boost_spe_pa5 = record->boost_spe_addr[4];
		__entry->boost_spe_pa6 = record->boost_spe_addr[5];
		__entry->boost_spe_pa7 = record->boost_spe_addr[6];
		__entry->boost_spe_pa8 = record->boost_spe_addr[7];
	),

	TP_printk("boost_spe_addr[0]=0x%llx boost_spe_addr[1]=0x%llx tlb_addr[2]=0x%llx tlb_addr[3]=0x%llx tlb_addr[4]=0x%llx tlb_addr[5]=0x%llx tlb_addr[6]=0x%llx tlb_addr[7]=0x%llx",
		__entry->boost_spe_pa1, __entry->boost_spe_pa2,
		__entry->boost_spe_pa3, __entry->boost_spe_pa4,
		__entry->boost_spe_pa5, __entry->boost_spe_pa6,
		__entry->boost_spe_pa7, __entry->boost_spe_pa8)
);
#endif /* CONFIG_ARM_SPE_MEM_SAMPLING */


#ifdef CONFIG_NUMABALANCING_MEM_SAMPLING
TRACE_EVENT(mm_numa_migrating,

	TP_PROTO(u64 vaddr, int page_nid, int target_nid,
		int migrate_success),

	TP_ARGS(vaddr, page_nid, target_nid, migrate_success),

	TP_STRUCT__entry(
		__field(u64, vaddr)
		__field(int, page_nid)
		__field(int, target_nid)
		__field(int, migrate_success)
	),

	TP_fast_assign(
		__entry->vaddr = vaddr;
		__entry->page_nid = page_nid;
		__entry->target_nid = target_nid;
		__entry->migrate_success = !!(migrate_success);
	),

	TP_printk("vaddr=%llu page_nid=%d target_nid=%d migrate_success=%d",
		__entry->vaddr, __entry->page_nid,
		__entry->target_nid, __entry->migrate_success)
);

TRACE_EVENT(mm_mem_sampling_access_record,

	TP_PROTO(u64 vaddr, u64 paddr, int cpuid, int pid),

	TP_ARGS(vaddr, paddr, cpuid, pid),

	TP_STRUCT__entry(
		__field(u64, vaddr)
		__field(u64, paddr)
		__field(int, cpuid)
		__field(int, pid)
	),

	TP_fast_assign(
		__entry->vaddr = vaddr;
		__entry->paddr = paddr;
		__entry->cpuid = cpuid;
		__entry->pid = pid;
	),

	TP_printk("vaddr=%llu paddr=%llu cpuid=%d pid=%d",
		__entry->vaddr, __entry->paddr,
		__entry->cpuid, __entry->pid)
);
#endif /* CONFIG_NUMABALANCING_MEM_SAMPLING */

#ifdef CONFIG_DAMON_MEM_SAMPLING
TRACE_EVENT(mm_mem_sampling_damon_record,

	TP_PROTO(u64 vaddr, int pid),

	TP_ARGS(vaddr, pid),

	TP_STRUCT__entry(
		__field(u64, vaddr)
		__field(int, pid)
	),

	TP_fast_assign(
		__entry->vaddr = vaddr;
		__entry->pid = pid;
	),

	TP_printk("vaddr=%llx pid=%d", __entry->vaddr, __entry->pid)
);
#endif /* CONFIG_DAMON_MEM_SAMPLING */

#ifdef CONFIG_PFN_RANGE_ALLOC
TRACE_EVENT(pfn_range_alloc,

	TP_PROTO(struct folio *folio, unsigned int nr_pages,
			int nid),

	TP_ARGS(folio, nr_pages, nid),

	TP_STRUCT__entry(
		__field(struct folio*, folio)
		__field(unsigned int, nr_pages)
		__field(int, nid)
	),

	TP_fast_assign(
		__entry->folio = folio;
		__entry->nr_pages = nr_pages;
		__entry->nid = nid;
	),

	TP_printk("folio=%p pfn=0x%lx err=%ld nr_pages=%u nid=%d",
		!IS_ERR(__entry->folio) ? __entry->folio : NULL,
		!IS_ERR(__entry->folio) ? folio_pfn(__entry->folio) : 0,
		!IS_ERR(__entry->folio) ? 0 : PTR_ERR(__entry->folio),
		__entry->nr_pages,
		__entry->nid)
);

TRACE_EVENT(pfn_range_free,

	TP_PROTO(struct folio *folio, int ret),

	TP_ARGS(folio, ret),

	TP_STRUCT__entry(
		__field(struct folio*, folio)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->folio = folio;
		__entry->ret = ret;
	),

	TP_printk("folio=%p pfn=0x%lx ret=%d",
		__entry->folio, folio_pfn(__entry->folio), __entry->ret)
);

TRACE_EVENT(hugetlb_pool_alloc,

	TP_PROTO(struct folio *folio, int nid),

	TP_ARGS(folio, nid),

	TP_STRUCT__entry(
		__field(struct folio*, folio)
		__field(int, nid)
	),

	TP_fast_assign(
		__entry->folio = folio;
		__entry->nid = nid;
	),

	TP_printk("folio=%p pfn=0x%lx err=%ld nid=%d",
		!IS_ERR(__entry->folio) ? __entry->folio : NULL,
		!IS_ERR(__entry->folio) ? folio_pfn(__entry->folio) : 0,
		!IS_ERR(__entry->folio) ? 0 : PTR_ERR(__entry->folio),
		__entry->nid)
);

TRACE_EVENT(hugetlb_pool_free,

	TP_PROTO(struct folio *folio, int ret),

	TP_ARGS(folio, ret),

	TP_STRUCT__entry(
		__field(struct folio*, folio)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->folio = folio;
		__entry->ret = ret;
	),

	TP_printk("folio=%p pfn=0x%lx ret=%d",
		__entry->folio, folio_pfn(__entry->folio), __entry->ret)
);

TRACE_EVENT(hugetlb_pool_alloc_size,

	TP_PROTO(struct folio *folio, int nid, unsigned long size),

	TP_ARGS(folio, nid, size),

	TP_STRUCT__entry(
		__field(struct folio*, folio)
		__field(int, nid)
		__field(unsigned long, size)
	),

	TP_fast_assign(
		__entry->folio = folio;
		__entry->nid = nid;
		__entry->size = size;
	),

	TP_printk("folio=%p pfn=0x%lx err=%ld nid=%d size=0x%lx",
		!IS_ERR(__entry->folio) ? __entry->folio : NULL,
		!IS_ERR(__entry->folio) ? folio_pfn(__entry->folio) : 0,
		!IS_ERR(__entry->folio) ? 0 : PTR_ERR(__entry->folio),
		__entry->nid, __entry->size)
);

#endif
#endif /* _TRACE_KMEM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
