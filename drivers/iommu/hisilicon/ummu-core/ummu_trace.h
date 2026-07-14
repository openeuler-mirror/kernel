/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Core trace.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ummu_core

#if !defined(__TRACE_UMMU_CORE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __TRACE_UMMU_CORE_H__

#include <linux/tracepoint.h>

TRACE_EVENT(ummu_core_alloc_tid,
	    TP_PROTO(const char *iommu_name, const char *dev_name, u32 tid),
	    TP_ARGS(iommu_name, dev_name, tid),
	    TP_STRUCT__entry(
		__string(iommu_name, iommu_name)
		__string(dev_name, dev_name)
		__field(u32, tid)
	),
	    TP_fast_assign(
		__assign_str(iommu_name, iommu_name);
		__assign_str(dev_name, dev_name);
		__entry->tid = tid;
	),
	    TP_printk("iommu: %s, device = %s, TID = %u", __get_str(iommu_name),
		       __get_str(dev_name), __entry->tid)
);

TRACE_EVENT(ummu_core_free_tid,
	    TP_PROTO(const char *iommu_name, u32 tid),
	    TP_ARGS(iommu_name, tid),
	    TP_STRUCT__entry(
		__string(iommu_name, iommu_name)
		__field(u32, tid)
	),
	    TP_fast_assign(
		__assign_str(iommu_name, iommu_name);
		__entry->tid = tid;
	),
	    TP_printk("iommu: %s, TID = %u", __get_str(iommu_name),
		       __entry->tid)
);

#endif /* __TRACE_UMMU_CORE_H__ */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE ummu_trace
#include <trace/define_trace.h>
