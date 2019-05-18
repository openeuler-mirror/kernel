/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iommu trace points
 *
 * Copyright (C) 2013 Shuah Khan <shuah.kh@samsung.com>
 *
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM iommu

#if !defined(_TRACE_IOMMU_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IOMMU_H

#include <linux/tracepoint.h>
#include <linux/iommu.h>
#include <uapi/linux/iommu.h>

struct device;

DECLARE_EVENT_CLASS(iommu_group_event,

	TP_PROTO(int group_id, struct device *dev),

	TP_ARGS(group_id, dev),

	TP_STRUCT__entry(
		__field(int, gid)
		__string(device, dev_name(dev))
	),

	TP_fast_assign(
		__entry->gid = group_id;
		__assign_str(device, dev_name(dev));
	),

	TP_printk("IOMMU: groupID=%d device=%s",
			__entry->gid, __get_str(device)
	)
);

DEFINE_EVENT(iommu_group_event, add_device_to_group,

	TP_PROTO(int group_id, struct device *dev),

	TP_ARGS(group_id, dev)

);

DEFINE_EVENT(iommu_group_event, remove_device_from_group,

	TP_PROTO(int group_id, struct device *dev),

	TP_ARGS(group_id, dev)
);

DECLARE_EVENT_CLASS(iommu_device_event,

	TP_PROTO(struct device *dev),

	TP_ARGS(dev),

	TP_STRUCT__entry(
		__string(device, dev_name(dev))
	),

	TP_fast_assign(
		__assign_str(device, dev_name(dev));
	),

	TP_printk("IOMMU: device=%s", __get_str(device)
	)
);

DEFINE_EVENT(iommu_device_event, attach_device_to_domain,

	TP_PROTO(struct device *dev),

	TP_ARGS(dev)
);

DEFINE_EVENT(iommu_device_event, detach_device_from_domain,

	TP_PROTO(struct device *dev),

	TP_ARGS(dev)
);

TRACE_EVENT(map,

	TP_PROTO(unsigned long iova, phys_addr_t paddr, size_t size),

	TP_ARGS(iova, paddr, size),

	TP_STRUCT__entry(
		__field(u64, iova)
		__field(u64, paddr)
		__field(size_t, size)
	),

	TP_fast_assign(
		__entry->iova = iova;
		__entry->paddr = paddr;
		__entry->size = size;
	),

	TP_printk("IOMMU: iova=0x%016llx paddr=0x%016llx size=%zu",
			__entry->iova, __entry->paddr, __entry->size
	)
);

TRACE_EVENT(unmap,

	TP_PROTO(unsigned long iova, size_t size, size_t unmapped_size),

	TP_ARGS(iova, size, unmapped_size),

	TP_STRUCT__entry(
		__field(u64, iova)
		__field(size_t, size)
		__field(size_t, unmapped_size)
	),

	TP_fast_assign(
		__entry->iova = iova;
		__entry->size = size;
		__entry->unmapped_size = unmapped_size;
	),

	TP_printk("IOMMU: iova=0x%016llx size=%zu unmapped_size=%zu",
			__entry->iova, __entry->size, __entry->unmapped_size
	)
);

DECLARE_EVENT_CLASS(iommu_error,

	TP_PROTO(struct device *dev, unsigned long iova, int flags),

	TP_ARGS(dev, iova, flags),

	TP_STRUCT__entry(
		__string(device, dev_name(dev))
		__string(driver, dev_driver_string(dev))
		__field(u64, iova)
		__field(int, flags)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(dev));
		__assign_str(driver, dev_driver_string(dev));
		__entry->iova = iova;
		__entry->flags = flags;
	),

	TP_printk("IOMMU:%s %s iova=0x%016llx flags=0x%04x",
			__get_str(driver), __get_str(device),
			__entry->iova, __entry->flags
	)
);

DEFINE_EVENT(iommu_error, io_page_fault,

	TP_PROTO(struct device *dev, unsigned long iova, int flags),

	TP_ARGS(dev, iova, flags)
);

TRACE_EVENT(dev_fault,

	TP_PROTO(struct device *dev,  struct iommu_fault_event *evt),

	TP_ARGS(dev, evt),

	TP_STRUCT__entry(
		__string(device, dev_name(dev))
		__field(int, type)
		__field(int, reason)
		__field(u64, addr)
		__field(u32, pasid)
		__field(u32, pgid)
		__field(u32, last_req)
		__field(u32, prot)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(dev));
		__entry->type = evt->type;
		__entry->reason = evt->reason;
		__entry->addr = evt->addr;
		__entry->pasid = evt->pasid;
		__entry->pgid = evt->page_req_group_id;
		__entry->last_req = evt->last_req;
		__entry->prot = evt->prot;
	),

	TP_printk("IOMMU:%s type=%d reason=%d addr=0x%016llx pasid=%d group=%d last=%d prot=%d",
		__get_str(device),
		__entry->type,
		__entry->reason,
		__entry->addr,
		__entry->pasid,
		__entry->pgid,
		__entry->last_req,
		__entry->prot
	)
);

TRACE_EVENT(dev_page_response,

	TP_PROTO(struct device *dev,  struct page_response_msg *msg),

	TP_ARGS(dev, msg),

	TP_STRUCT__entry(
		__string(device, dev_name(dev))
		__field(int, code)
		__field(u64, addr)
		__field(u32, pasid)
		__field(u32, pgid)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(dev));
		__entry->code = msg->resp_code;
		__entry->addr = msg->addr;
		__entry->pasid = msg->pasid;
		__entry->pgid = msg->page_req_group_id;
	),

	TP_printk("IOMMU:%s code=%d addr=0x%016llx pasid=%d group=%d",
		__get_str(device),
		__entry->code,
		__entry->addr,
		__entry->pasid,
		__entry->pgid
	)
);

TRACE_EVENT(sva_invalidate,

	TP_PROTO(struct device *dev,  struct tlb_invalidate_info *ti),

	TP_ARGS(dev, ti),

	TP_STRUCT__entry(
		__string(device, dev_name(dev))
		__field(int, type)
		__field(u32, granu)
		__field(u32, flags)
		__field(u8, size)
		__field(u32, pasid)
		__field(u64, addr)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(dev));
		__entry->type = ti->hdr.type;
		__entry->flags = ti->flags;
		__entry->granu = ti->granularity;
		__entry->size = ti->size;
		__entry->pasid = ti->pasid;
		__entry->addr = ti->addr;
	),

	TP_printk("IOMMU:%s type=%d flags=0x%08x granu=%d size=%d pasid=%d addr=0x%016llx",
		__get_str(device),
		__entry->type,
		__entry->flags,
		__entry->granu,
		__entry->size,
		__entry->pasid,
		__entry->addr
	)
);


#endif /* _TRACE_IOMMU_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
