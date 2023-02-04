#undef TRACE_SYSTEM
#define TRACE_SYSTEM dhugetlb

#if !defined(_TRACE_DHUGETLB_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DHUGETLB_H

#include <linux/tracepoint.h>
#include <trace/events/mmflags.h>

#define	DHUGETLB_SPLIT_1G       0x01u
#define	DHUGETLB_SPLIT_2M       0x02u
#define	DHUGETLB_MERGE_4K       0x04u
#define	DHUGETLB_MIGRATE_4K     0x08u
#define	DHUGETLB_RESV_1G	0x10u
#define	DHUGETLB_UNRESV_1G	0x20u
#define	DHUGETLB_RESV_2M	0x40u
#define	DHUGETLB_UNRESV_2M	0x80u
#define	DHUGETLB_ALLOC_1G	0x100u
#define	DHUGETLB_FREE_1G	0x200u
#define	DHUGETLB_ALLOC_2M	0x400u
#define	DHUGETLB_FREE_2M	0x800u

#define __def_action_names						\
	{(unsigned long)DHUGETLB_SPLIT_1G,	"split_1G_to_2M"},	\
	{(unsigned long)DHUGETLB_SPLIT_2M,	"split_2M_to_4K"},	\
	{(unsigned long)DHUGETLB_MERGE_4K,	"merge_4K_to_2M"},	\
	{(unsigned long)DHUGETLB_MIGRATE_4K,	"migrate_4K_to_2M"},	\
	{(unsigned long)DHUGETLB_RESV_1G,	"resv_1G_page"},	\
	{(unsigned long)DHUGETLB_UNRESV_1G,	"unresv_1G_page"},	\
	{(unsigned long)DHUGETLB_RESV_2M,	"resv_2M_page"},	\
	{(unsigned long)DHUGETLB_UNRESV_2M,	"unresv_2M_page"},	\
	{(unsigned long)DHUGETLB_ALLOC_1G,	"alloc_1G_page"},	\
	{(unsigned long)DHUGETLB_FREE_1G,	"free_1G_page"},	\
	{(unsigned long)DHUGETLB_ALLOC_2M,	"alloc_2M_page"},	\
	{(unsigned long)DHUGETLB_FREE_2M,	"free_2M_page"}

#define show_action(action)						\
	(action) ? __print_flags(action, "",				\
	__def_action_names						\
	) : "none"

TRACE_EVENT(dhugetlb_split_merge,

	TP_PROTO(const void *hpool, struct page *page, unsigned long action),

	TP_ARGS(hpool, page, action),

	TP_STRUCT__entry(
		__field(	const void *,	hpool	)
		__field(	unsigned long,	pfn	)
		__field(	unsigned long,	action	)
	),

	TP_fast_assign(
		__entry->hpool	= hpool;
		__entry->pfn	= page ? page_to_pfn(page) : -1UL;
		__entry->action	= action;
	),

	TP_printk("hpool=%p page=%p pfn=%lu action=%s",
		__entry->hpool,
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn != -1UL ? __entry->pfn : 0,
		show_action(__entry->action))
);

TRACE_EVENT(dhugetlb_acct_memory,

	TP_PROTO(const void *hpool, unsigned long count, unsigned long action),

	TP_ARGS(hpool, count, action),

	TP_STRUCT__entry(
		__field(	const void *,	hpool	)
		__field(	unsigned long,	count	)
		__field(	unsigned long,	action	)
	),

	TP_fast_assign(
		__entry->hpool	= hpool;
		__entry->count	= count;
		__entry->action	= action;
	),

	TP_printk("hpool=%p action=%s, mmap_count=%lu",
		__entry->hpool,
		show_action(__entry->action),
		__entry->count)
);

TRACE_EVENT(dhugetlb_alloc_free,

	TP_PROTO(const void *hpool, struct page *page, unsigned long count,
		 unsigned long action),

	TP_ARGS(hpool, page, count, action),

	TP_STRUCT__entry(
		__field(	const void *,	hpool	)
		__field(	unsigned long,	pfn	)
		__field(	unsigned long,	count	)
		__field(	unsigned long,	action	)
	),

	TP_fast_assign(
		__entry->hpool	= hpool;
		__entry->pfn	= page ? page_to_pfn(page) : -1UL;
		__entry->count	= count;
		__entry->action	= action;
	),

	TP_printk("hpool=%p page=%p pfn=%lu action=%s free_count=%lu",
		__entry->hpool,
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn != -1UL ? __entry->pfn : 0,
		show_action(__entry->action),
		__entry->count)
);

#endif /* _TRACE_DHUGETLB_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
