/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Framework's implementations.
 */

#ifndef __LOGIC_UMMU_H__
#define __LOGIC_UMMU_H__
#include <linux/ummu_core.h>
#include "../ummu.h"

#define __GEN_OPS(ops_name, src, dst) \
	do { \
		if (!IS_ERR_OR_NULL((const void *)(src)->ops_name)) \
			(dst)->ops_name = logic_ummu_##ops_name; \
		else \
			(dst)->ops_name = NULL; \
	} while (0)

#define GEN_IOMMU_DIRTY_OPS(src, dst) \
	do { \
		__GEN_OPS(set_dirty_tracking, src, dst); \
		__GEN_OPS(read_and_clear_dirty, src, dst); \
	} while (0)

#define GEN_IOMMU_PERM_OPS(src, dst) \
	do { \
		__GEN_OPS(grant, src, dst); \
		__GEN_OPS(ungrant, src, dst); \
		__GEN_OPS(plb_sync, src, dst); \
		__GEN_OPS(plb_sync_all, src, dst); \
	} while (0)

struct iommu_domain *iommu_to_agent_domain(struct iommu_domain *dom);
int logic_add_ummu_device(struct ummu_device *ummu,
			  const struct iommu_ops *iommu_ops,
			  const struct ummu_core_ops *core_ops);
void logic_remove_ummu_device(struct ummu_device *ummu);
int logic_ummu_device_init(void);
void logic_ummu_device_exit(void);

#endif  /* __LOGIC_UMMU_H__ */
