// SPDX-License-Identifier: GPL-2.0
/*
 * iommu trace points
 *
 * Copyright (C) 2013 Shuah Khan <shuah.kh@samsung.com>
 *
 */

#include <linux/string.h>
#include <linux/types.h>

#define CREATE_TRACE_POINTS
#include <trace/events/iommu.h>
#include <trace/events/smmu.h>

/* iommu_group_event */
EXPORT_TRACEPOINT_SYMBOL_GPL(add_device_to_group);
EXPORT_TRACEPOINT_SYMBOL_GPL(remove_device_from_group);

/* iommu_device_event */
EXPORT_TRACEPOINT_SYMBOL_GPL(attach_device_to_domain);
EXPORT_TRACEPOINT_SYMBOL_GPL(detach_device_from_domain);

/* iommu_map_unmap */
EXPORT_TRACEPOINT_SYMBOL_GPL(map);
EXPORT_TRACEPOINT_SYMBOL_GPL(unmap);

/* iommu_error */
EXPORT_TRACEPOINT_SYMBOL_GPL(io_page_fault);

/* Arm SMMUv3 traces */
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_bind_alloc);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_bind_get);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_unbind_put);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_unbind_free);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_mm_release);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_mm_invalidate);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_mn_alloc);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_mn_free);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_mn_get);
EXPORT_TRACEPOINT_SYMBOL_GPL(smmu_mn_put);
