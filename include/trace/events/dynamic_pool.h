/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM dynamic_pool

#if !defined(_TRACE_DPOOL_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DPOOL_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <trace/events/mmflags.h>

#define show_size(type)				\
	__print_symbolic(type,			\
		{ PAGES_POOL_1G, "1G" },	\
		{ PAGES_POOL_2M, "2M" },	\
		{ PAGES_POOL_4K, "4K" })

TRACE_EVENT(dpool_demote,

	TP_PROTO(struct dynamic_pool *dpool, int type, struct page *page,
		 int ret),

	TP_ARGS(dpool, type, page, ret),

	TP_STRUCT__entry(
			__field(struct dynamic_pool *, dpool)
			__field(int, type)
			__field(unsigned long, pfn)
			__field(int, ret)
	),

	TP_fast_assign(
			__entry->dpool	= dpool;
			__entry->type	= type;
			__entry->pfn	= page ? page_to_pfn(page) : -1UL;
			__entry->ret	= ret;
	),

	TP_printk("dpool=%p size=%s page=%p pfn=%lx ret=%d",
		  __entry->dpool,
		  show_size(__entry->type),
		  __entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		  __entry->pfn,
		  __entry->ret)
);

TRACE_EVENT(dpool_promote,

	TP_PROTO(struct dynamic_pool *dpool, int type, struct page *page,
		 int ret),

	TP_ARGS(dpool, type, page, ret),

	TP_STRUCT__entry(
			__field(struct dynamic_pool *, dpool)
			__field(int, type)
			__field(unsigned long, pfn)
			__field(int, ret)
	),

	TP_fast_assign(
			__entry->dpool	= dpool;
			__entry->type	= type;
			__entry->pfn	= page ? page_to_pfn(page) : -1UL;
			__entry->ret	= ret;
	),

	TP_printk("dpool=%p size=%s page=%p pfn=%lx ret=%d",
		  __entry->dpool,
		  show_size(__entry->type),
		  __entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		  __entry->pfn,
		  __entry->ret)
);

TRACE_EVENT(dpool_acct_memory,

	TP_PROTO(struct dynamic_pool *dpool, int type, long delta,
		 unsigned long resv, int ret),

	TP_ARGS(dpool, type, delta, resv, ret),

	TP_STRUCT__entry(
			__field(struct dynamic_pool *, dpool)
			__field(int, type)
			__field(long, delta)
			__field(unsigned long, resv)
			__field(int, ret)
	),

	TP_fast_assign(
			__entry->dpool	= dpool;
			__entry->type	= type;
			__entry->delta	= delta;
			__entry->resv	= resv;
			__entry->ret	= ret;
	),

	TP_printk("dpool=%p size=%s delta=%ld resv=%lu ret=%d",
		  __entry->dpool,
		  show_size(__entry->type),
		  __entry->delta,
		  __entry->resv,
		  __entry->ret)
);

TRACE_EVENT(dpool_alloc_hugepage,

	TP_PROTO(struct dynamic_pool *dpool, int type, struct folio *folio,
		 unsigned long free, unsigned long resv),

	TP_ARGS(dpool, type, folio, free, resv),

	TP_STRUCT__entry(
			__field(struct dynamic_pool *, dpool)
			__field(int, type)
			__field(unsigned long, pfn)
			__field(unsigned long, free)
			__field(unsigned long, resv)
	),

	TP_fast_assign(
			__entry->dpool	= dpool;
			__entry->type	= type;
			__entry->pfn	= folio ? folio_pfn(folio) : -1UL;
			__entry->free	= free;
			__entry->resv	= resv;
	),

	TP_printk("dpool=%p size=%s page=%p pfn=%lx free=%lu resv=%lu",
		  __entry->dpool,
		  show_size(__entry->type),
		  __entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		  __entry->pfn,
		  __entry->free,
		  __entry->resv)
);

TRACE_EVENT(dpool_free_hugepage,

	TP_PROTO(struct dynamic_pool *dpool, int type, struct folio *folio,
		 unsigned long free, unsigned long resv),

	TP_ARGS(dpool, type, folio, free, resv),

	TP_STRUCT__entry(
			__field(struct dynamic_pool *, dpool)
			__field(int, type)
			__field(unsigned long, pfn)
			__field(unsigned long, free)
			__field(unsigned long, resv)
	),

	TP_fast_assign(
			__entry->dpool	= dpool;
			__entry->type	= type;
			__entry->pfn	= folio ? folio_pfn(folio) : -1UL;
			__entry->free	= free;
			__entry->resv	= resv;
	),

	TP_printk("dpool=%p size=%s page=%p pfn=%lx free=%lu resv=%lu",
		  __entry->dpool,
		  show_size(__entry->type),
		  __entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		  __entry->pfn,
		  __entry->free,
		  __entry->resv)
);

#endif /* _TRACE_DPOOL_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
