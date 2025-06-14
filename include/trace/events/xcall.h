/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM xcall

#if !defined(_TRACE_XCALL_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XCALL_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/fs.h>

TRACE_EVENT(epoll_rc_queue,

	TP_PROTO(struct file *file, int cpu),

	TP_ARGS(file, cpu),

	TP_STRUCT__entry(
		__field(struct file *, file)
		__field(int, cpu)
	),

	TP_fast_assign(
		__entry->file = file;
		__entry->cpu = cpu;
	),

	TP_printk("0x%pK on cpu %d", __entry->file, __entry->cpu)
);

TRACE_EVENT(epoll_rc_prefetch,

	TP_PROTO(struct file *file),

	TP_ARGS(file),

	TP_STRUCT__entry(
		__field(struct file *, file)
	),

	TP_fast_assign(
		__entry->file = file;
	),

	TP_printk("0x%pK", __entry->file)
);

TRACE_EVENT(epoll_rc_ready,

	TP_PROTO(struct file *file, int len),

	TP_ARGS(file, len),

	TP_STRUCT__entry(
		__field(struct file *, file)
		__field(int, len)
	),

	TP_fast_assign(
		__entry->file = file;
		__entry->len = len;
	),

	TP_printk("0x%pK, len %d", __entry->file, __entry->len)
);

TRACE_EVENT(epoll_rc_hit,

	TP_PROTO(struct file *file, int len),

	TP_ARGS(file, len),

	TP_STRUCT__entry(
		__field(struct file *, file)
		__field(int, len)
	),

	TP_fast_assign(
		__entry->file = file;
		__entry->len = len;
	),

	TP_printk("0x%pK, len: %d", __entry->file, __entry->len)
);

TRACE_EVENT(epoll_rc_miss,

	TP_PROTO(struct file *file),

	TP_ARGS(file),

	TP_STRUCT__entry(
		__field(struct file *, file)
	),

	TP_fast_assign(
		__entry->file = file;
	),

	TP_printk("0x%pK", __entry->file)
);

#endif /* _TRACE_XCALL_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
