/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: nested mode interface
 */

#ifndef __UMMU_NESTED_H__
#define __UMMU_NESTED_H__

#include "ummu.h"

struct ummu_nested_domain {
	struct ummu_base_domain base_domain;
	struct ummu_domain *s2_parent;
	__le64 tecte[2];
	/* belongs IOMMU framework, using for multi-instance traversal */
	struct iommu_domain *domain;
};

static inline struct ummu_nested_domain *to_nested_domain(struct iommu_domain *dom)
{
	struct ummu_base_domain *base_dom =
			container_of(dom, struct ummu_base_domain, domain);

	return container_of(base_dom, struct ummu_nested_domain, base_domain);
}

struct iommu_domain *ummu_viommu_alloc_domain_nested(struct iommu_domain *parent,
				u32 flags,
				const struct iommu_user_data *user_data);

int ummu_viommu_cache_invalidate_user(struct iommu_domain *domain,
				      struct iommu_user_data_array *array);

struct iommufd_viommu *ummu_viommu_alloc(struct device *dev,
					 struct iommu_domain *parent,
					 struct iommufd_ctx *ictx,
					 unsigned int viommu_type);

#endif /* __UMMU_NESTED_H__ */
