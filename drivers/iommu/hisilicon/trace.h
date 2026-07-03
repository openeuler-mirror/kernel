/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright(c) 2025 HiSilicon Technologies Co., All rights reserved.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ummu_driver

#if !defined(__TRACE_UMMU_DRIVER_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __TRACE_UMMU_DRIVER_H__

#include <linux/tracepoint.h>

TRACE_EVENT(ummu_flush_iotlb_all,
	    TP_PROTO(u32 tid, const char *name),
	    TP_ARGS(tid, name),
	    TP_STRUCT__entry(
		__field(u32, tid)
		__string(name, name)
	),
	    TP_fast_assign(
		__entry->tid = tid;
		__assign_str(name, name);
	),
	    TP_printk("%s: TID = %u", __get_str(name), __entry->tid)
);

TRACE_EVENT(ummu_iotlb_sync,
	    TP_PROTO(u32 tid, unsigned long iova, unsigned long size,
		     const char *name),
	    TP_ARGS(tid, iova, size, name),
	    TP_STRUCT__entry(
		__field(u32, tid)
		__field(unsigned long, iova)
		__field(unsigned long, size)
		__string(name, name)
	),
	    TP_fast_assign(
		__entry->tid = tid;
		__entry->iova = iova;
		__entry->size = size;
		__assign_str(name, name);
	),
	    TP_printk("%s: TID = %u, IOVA = 0x%016lx, SIZE = 0x%016lx",
		      __get_str(name), __entry->tid, __entry->iova,
		      __entry->size
	)
);

TRACE_EVENT(ummu_perm_grant,
	    TP_PROTO(u32 tid, u64 iova, u64 size, int perm, bool tkv_en),
	    TP_ARGS(tid, iova, size, perm, tkv_en),
	    TP_STRUCT__entry(
		__field(u32, tid)
		__field(u64, iova)
		__field(u64, size)
		__field(int, perm)
		__field(bool, tkv_en)
	),
	    TP_fast_assign(
		__entry->tid = tid;
		__entry->iova = iova;
		__entry->size = size;
		__entry->perm = perm;
		__entry->tkv_en = tkv_en;
	),
	    TP_printk("map: TID = %u, IOVA = 0x%llx, SIZE = 0x%llx, PERMISSION = %d, TKV_EN = %d",
		      __entry->tid, __entry->iova, __entry->size, __entry->perm, __entry->tkv_en
	)
);

TRACE_EVENT(ummu_perm_ungrant,
	    TP_PROTO(u32 tid, u64 iova, u64 size, bool tkv_en, int ret),
	    TP_ARGS(tid, iova, size, tkv_en, ret),
	    TP_STRUCT__entry(
		__field(u32, tid)
		__field(u64, iova)
		__field(u64, size)
		__field(bool, tkv_en)
		__field(int, ret)
	),
	    TP_fast_assign(
		__entry->tid = tid;
		__entry->iova = iova;
		__entry->size = size;
		__entry->tkv_en = tkv_en;
		__entry->ret = ret;
	),
	    TP_printk("map: TID = %u, IOVA = 0x%llx, SIZE = 0x%llx, TKV_EN = %d, RET = %d",
		      __entry->tid, __entry->iova, __entry->size, __entry->tkv_en, __entry->ret
	)
);

TRACE_EVENT(ummu_sync_tect,
	    TP_PROTO(const char *name, u32 tecte_tag),
	    TP_ARGS(name, tecte_tag),
	    TP_STRUCT__entry(
		__string(name, name)
		__field(u32, tecte_tag)
	),
	    TP_fast_assign(
		__assign_str(name, name);
		__entry->tecte_tag = tecte_tag;
	),
	    TP_printk("%s, tecte_tag = %u", __get_str(name), __entry->tecte_tag)
);

TRACE_EVENT(ummu_sync_tect_range,
	    TP_PROTO(const char *name, u32 tecte_tag, u8 range),
	    TP_ARGS(name, tecte_tag, range),
	    TP_STRUCT__entry(
		__string(name, name)
		__field(u32, tecte_tag)
		__field(u8, range)
	),
	    TP_fast_assign(
		__assign_str(name, name);
		__entry->tecte_tag = tecte_tag;
		__entry->range = range;
	),
	    TP_printk("%s, tecte_tag = %u, range = %u",
		      __get_str(name), __entry->tecte_tag, __entry->range)
);

TRACE_EVENT(ummu_sync_tct,
	    TP_PROTO(const char *name, u32 tecte_tag, u32 tid, bool leaf),
	    TP_ARGS(name, tecte_tag, tid, leaf),
	    TP_STRUCT__entry(
		__string(name, name)
		__field(u32, tecte_tag)
		__field(u32, tid)
		__field(bool, leaf)
	),
	    TP_fast_assign(
		__assign_str(name, name);
		__entry->tecte_tag = tecte_tag;
		__entry->tid = tid;
		__entry->leaf = leaf;
	),
	    TP_printk("%s, tecte_tag = %u, tid = %u, leaf = %d",
		      __get_str(name), __entry->tecte_tag, __entry->tid, __entry->leaf)
);

TRACE_EVENT(ummu_sync_tct_all,
	    TP_PROTO(const char *name, u32 tecte_tag),
	    TP_ARGS(name, tecte_tag),
	    TP_STRUCT__entry(
		__string(name, name)
		__field(u32, tecte_tag)
	),
	    TP_fast_assign(
		__assign_str(name, name);
		__entry->tecte_tag = tecte_tag;
	),
	    TP_printk("%s, tecte_tag = %u", __get_str(name), __entry->tecte_tag)
);

TRACE_EVENT(ummu_event,
	    TP_PROTO(const char *name, u8 code, u64 *evt, u8 length),
	    TP_ARGS(name, code, evt, length),
	    TP_STRUCT__entry(
		__string(name, name)
		__field(u8, code)
		__field(u8, length)
		__dynamic_array(u64, arr, length)
	),
	    TP_fast_assign(
		__assign_str(name, name);
		__entry->code = code;
		__entry->length = length;
		memcpy(__get_dynamic_array(arr), evt, length*sizeof(u64));
	),
	    TP_printk("%s, receive 0x%02x event, content=%s", __get_str(name),
		      __entry->code, __print_array(__get_dynamic_array(arr),
		      __entry->length, sizeof(u64)))
);

#endif /* _TRACE_UMMU_DRIVER_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
