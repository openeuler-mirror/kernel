/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM attach

#if !defined(_TRACE_ATTACH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ATTACH_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/mm_types.h>

TRACE_EVENT(attach_page_range_start,

	TP_PROTO(struct mm_struct *dst_mm,
		struct mm_struct *src_mm,
		unsigned long dst_addr,
		unsigned long src_addr,
		unsigned long size),

	TP_ARGS(dst_mm, src_mm, dst_addr, src_addr, size),

	TP_STRUCT__entry(
		__field(struct mm_struct *,	dst_mm)
		__field(struct mm_struct *,	src_mm)
		__field(unsigned long,	dst_addr)
		__field(unsigned long,	src_addr)
		__field(unsigned long,	size)
	),

	TP_fast_assign(
		__entry->dst_mm = dst_mm;
		__entry->src_mm = src_mm;
		__entry->dst_addr = dst_addr;
		__entry->src_addr = src_addr;
		__entry->size = size;
	),

	TP_printk("dst_mm=%p src_mm=%p dst_addr=0x%lx src_addr=0x%lx size=%ld",
		__entry->dst_mm, __entry->src_mm,
		__entry->dst_addr, __entry->src_addr,
		__entry->size)
);

TRACE_EVENT(attach_page_range_end,

	TP_PROTO(struct mm_struct *dst_mm,
		struct mm_struct *src_mm,
		unsigned long dst_addr,
		unsigned long src_addr,
		int ret),

	TP_ARGS(dst_mm, src_mm, dst_addr, src_addr, ret),

	TP_STRUCT__entry(
		__field(struct mm_struct *,	dst_mm)
		__field(struct mm_struct *,	src_mm)
		__field(unsigned long,	dst_addr)
		__field(unsigned long,	src_addr)
		__field(int,	ret)
	),

	TP_fast_assign(
		__entry->dst_mm = dst_mm;
		__entry->src_mm = src_mm;
		__entry->dst_addr = dst_addr;
		__entry->src_addr = src_addr;
		__entry->ret = ret;
	),

	TP_printk("dst_mm=%p src_mm=%p dst_addr=0x%lx src_addr=0x%lx ret=%d",
		__entry->dst_mm, __entry->src_mm,
		__entry->dst_addr, __entry->src_addr,
		__entry->ret)
);

TRACE_EVENT(attach_extent_start,

	TP_PROTO(struct mm_struct *dst_mm,
		struct mm_struct *src_mm,
		unsigned long dst_addr,
		unsigned long src_addr,
		pmd_t *new_pmd,
		pmd_t *old_pmd,
		unsigned long extent),

	TP_ARGS(dst_mm, src_mm, dst_addr, src_addr, new_pmd, old_pmd, extent),

	TP_STRUCT__entry(
		__field(struct mm_struct *,	dst_mm)
		__field(struct mm_struct *,	src_mm)
		__field(unsigned long,	dst_addr)
		__field(unsigned long,	src_addr)
		__field(pmd_t *,	new_pmd)
		__field(pmd_t *,	old_pmd)
		__field(unsigned long,	extent)
	),

	TP_fast_assign(
		__entry->dst_mm = dst_mm;
		__entry->src_mm = src_mm;
		__entry->dst_addr = dst_addr;
		__entry->src_addr = src_addr;
		__entry->new_pmd = new_pmd;
		__entry->old_pmd = old_pmd;
		__entry->extent = extent;
	),

	TP_printk("dst_mm=%p src_mm=%p dst_addr=0x%lx src_addr=0x%lx new_pmd=%016llx old_pmd=%016llx extent=%ld",
		__entry->dst_mm, __entry->src_mm,
		__entry->dst_addr, __entry->src_addr,
		pmd_val(*__entry->new_pmd), pmd_val(*__entry->old_pmd),
		__entry->extent)
);

TRACE_EVENT(attach_extent_end,

	TP_PROTO(struct mm_struct *dst_mm,
		struct mm_struct *src_mm,
		unsigned long dst_addr,
		unsigned long src_addr,
		pmd_t *new_pmd,
		pmd_t *old_pmd,
		int ret),

	TP_ARGS(dst_mm, src_mm, dst_addr, src_addr, new_pmd, old_pmd, ret),

	TP_STRUCT__entry(
		__field(struct mm_struct *,	dst_mm)
		__field(struct mm_struct *,	src_mm)
		__field(unsigned long,	dst_addr)
		__field(unsigned long,	src_addr)
		__field(pmd_t *,	new_pmd)
		__field(pmd_t *,	old_pmd)
		__field(int,	ret)
	),

	TP_fast_assign(
		__entry->dst_mm = dst_mm;
		__entry->src_mm = src_mm;
		__entry->dst_addr = dst_addr;
		__entry->src_addr = src_addr;
		__entry->new_pmd = new_pmd;
		__entry->old_pmd = old_pmd;
		__entry->ret = ret;
	),

	TP_printk("dst_mm=%p src_mm=%p dst_addr=0x%lx src_addr=0x%lx new_pmd=%016llx old_pmd=%016llx ret=%d",
		__entry->dst_mm, __entry->src_mm,
		__entry->dst_addr, __entry->src_addr,
		pmd_val(*__entry->new_pmd), pmd_val(*__entry->old_pmd),
		__entry->ret)
);

#endif /* _TRACE_ATTACH_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
