/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

/* This must be outside ifdef __HISI_MEMORY_TRACE_H__ */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ub_memory

#if !defined(__HISI_MEMORY_TRACE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __HISI_MEMORY_TRACE_H__

#include <linux/tracepoint.h>

TRACE_EVENT(mem_ras_event,
	TP_PROTO(struct ub_mem_device *device, struct ub_mem_ras_err_info *info),
	TP_ARGS(device, info),

	TP_STRUCT__entry(
		__field(u32, eid)
		__field(u32, cna)
		__field(u8, type)
		__field(u64, val0)
		__field(u64, val1)
	),

	TP_fast_assign(
		__entry->eid = device->uent->eid;
		__entry->cna = device->uent->cna;
		__entry->type = (u8)info->type;
		__entry->val0 = info->val0;
		__entry->val1 = info->val1;
	),

	TP_printk(
		"%u-%u-%u-%llu-%llu", __entry->eid, __entry->cna,
		__entry->type, __entry->val0, __entry->val1
	)
);

#endif /* __HISI_MEMORY_TRACE_H__ */

/* This must be outside ifdef __HISI_MEMORY_TRACE_H__ */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE memory_trace
#include <trace/define_trace.h>
