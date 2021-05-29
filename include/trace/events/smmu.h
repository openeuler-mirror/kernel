/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Arm SMMUv3 trace points
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM smmu

#if !defined(_TRACE_SMMU_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SMMU_H

#include <linux/tracepoint.h>

struct device;

DECLARE_EVENT_CLASS(smmu_bond,
		    TP_PROTO(struct device *dev, unsigned int pasid),
		    TP_ARGS(dev, pasid),
		    TP_STRUCT__entry(
			__string(dev, dev_name(dev))
			__field(int, pasid)
		    ),
		    TP_fast_assign(
			__assign_str(dev, dev_name(dev));
			__entry->pasid = pasid;
		    ),
		    TP_printk("dev=%s pasid=%d", __get_str(dev), __entry->pasid)
);

DEFINE_EVENT(smmu_bond, smmu_bind_alloc,
	     TP_PROTO(struct device *dev, unsigned int pasid),
	     TP_ARGS(dev, pasid));

DEFINE_EVENT(smmu_bond, smmu_bind_get,
	     TP_PROTO(struct device *dev, unsigned int pasid),
	     TP_ARGS(dev, pasid));

DEFINE_EVENT(smmu_bond, smmu_unbind_put,
	     TP_PROTO(struct device *dev, unsigned int pasid),
	     TP_ARGS(dev, pasid));

DEFINE_EVENT(smmu_bond, smmu_unbind_free,
	     TP_PROTO(struct device *dev, unsigned int pasid),
	     TP_ARGS(dev, pasid));

TRACE_EVENT(smmu_mm_release,
	    TP_PROTO(unsigned int pasid),
	    TP_ARGS(pasid),
	    TP_STRUCT__entry(__field(int, pasid)),
	    TP_fast_assign(__entry->pasid = pasid;),
	    TP_printk("pasid=%d", __entry->pasid)
);

TRACE_EVENT(smmu_mm_invalidate,
	    TP_PROTO(unsigned int pasid,
		     unsigned long start, unsigned long end),
	    TP_ARGS(pasid, start, end),
	    TP_STRUCT__entry(
			__field(int, pasid)
			__field(unsigned long, start)
			__field(unsigned long, end)
		    ),
	    TP_fast_assign(
			   __entry->pasid = pasid;
			   __entry->start = start;
			   __entry->end = end;
			  ),
	    TP_printk("pasid=%d start=0x%lx end=0x%lx",
		      __entry->pasid, __entry->start,
		      __entry->end)
)

DECLARE_EVENT_CLASS(smmu_mn,
		    TP_PROTO(unsigned int pasid),
		    TP_ARGS(pasid),
		    TP_STRUCT__entry(__field(int, pasid)),
		    TP_fast_assign(__entry->pasid = pasid;),
		    TP_printk("pasid=%d", __entry->pasid)
);

DEFINE_EVENT(smmu_mn, smmu_mn_alloc, TP_PROTO(unsigned int pasid), TP_ARGS(pasid));
DEFINE_EVENT(smmu_mn, smmu_mn_free, TP_PROTO(unsigned int pasid), TP_ARGS(pasid));
DEFINE_EVENT(smmu_mn, smmu_mn_get, TP_PROTO(unsigned int pasid), TP_ARGS(pasid));
DEFINE_EVENT(smmu_mn, smmu_mn_put, TP_PROTO(unsigned int pasid), TP_ARGS(pasid));


#endif /* _TRACE_SMMU_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
