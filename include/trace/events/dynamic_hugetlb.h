#undef TRACE_SYSTEM
#define TRACE_SYSTEM dynamic_hugetlb

#if !defined(_TRACE_DHUGETLB_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DHUGETLB_H

#include <linux/tracepoint.h>
#include <trace/events/mmflags.h>

#define	DHUGETLB_SPLIT		0x01u
#define	DHUGETLB_MERGE		0x02u
#define	DHUGETLB_MIGRATE	0x04u
#define	DHUGETLB_RESV		0x08u
#define	DHUGETLB_UNRESV		0x10u
#define	DHUGETLB_ALLOC		0x20u
#define	DHUGETLB_FREE		0x40u

#define __def_action_names						\
	{(unsigned long)DHUGETLB_SPLIT,		"split page"},	\
	{(unsigned long)DHUGETLB_MERGE,		"merge page"},	\
	{(unsigned long)DHUGETLB_MIGRATE,	"migrate page"},	\
	{(unsigned long)DHUGETLB_RESV,		"resv page"},	\
	{(unsigned long)DHUGETLB_UNRESV,	"unresv page"},	\
	{(unsigned long)DHUGETLB_ALLOC,		"alloc page"},	\
	{(unsigned long)DHUGETLB_FREE,		"free page"}

#define show_action(action)						\
	(action) ? __print_flags(action, "",				\
	__def_action_names						\
	) : "none"

TRACE_EVENT(dynamic_hugetlb_split_merge,

	TP_PROTO(const void *hpool, struct page *page, unsigned long action, unsigned long size),

	TP_ARGS(hpool, page, action, size),

	TP_STRUCT__entry(
		__field(	const void *,	hpool	)
		__field(	unsigned long,	pfn	)
		__field(	unsigned long,	action	)
		__field(	unsigned long,	size	)
	),

	TP_fast_assign(
		__entry->hpool	= hpool;
		__entry->pfn	= page ? page_to_pfn(page) : -1UL;
		__entry->action	= action;
		__entry->size	= size;
	),

	TP_printk("hpool=%p page=%p pfn=%lu action=%s size=%lu",
		__entry->hpool,
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn,
		show_action(__entry->action),
		__entry->size)
);

TRACE_EVENT(dynamic_hugetlb_acct_memory,

	TP_PROTO(const void *hpool, unsigned long count, unsigned long action, unsigned long size),

	TP_ARGS(hpool, count, action, size),

	TP_STRUCT__entry(
		__field(	const void *,	hpool	)
		__field(	unsigned long,	count	)
		__field(	unsigned long,	action	)
		__field(	unsigned long,	size	)
	),

	TP_fast_assign(
		__entry->hpool	= hpool;
		__entry->size	= size;
		__entry->count	= count;
		__entry->action	= action;
	),

	TP_printk("hpool=%p action=%s size = %lu mmap_count=%lu",
		__entry->hpool,
		show_action(__entry->action),
		__entry->size,
		__entry->count)
);

TRACE_EVENT(dynamic_hugetlb_alloc_free,

	TP_PROTO(const void *hpool, struct page *page, unsigned long count, unsigned long action, unsigned long size),

	TP_ARGS(hpool, page, count, action, size),

	TP_STRUCT__entry(
		__field(	const void *,	hpool	)
		__field(	unsigned long,	pfn	)
		__field(	unsigned long,	count	)
		__field(	unsigned long,	action	)
		__field(	unsigned long,	size	)
	),

	TP_fast_assign(
		__entry->hpool	= hpool;
		__entry->pfn	= page ? page_to_pfn(page) : -1UL;
		__entry->count	= count;
		__entry->action	= action;
		__entry->size	= size;
	),

	TP_printk("hpool=%p page=%p pfn=%lu action=%s size = %lu free_count=%lu",
		__entry->hpool,
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn,
		show_action(__entry->action),
		__entry->size,
		__entry->count)
);

#endif /* _TRACE_DHUGETLB_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
