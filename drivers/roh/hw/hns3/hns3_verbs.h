/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2020-2022 Hisilicon Limited.
#ifndef __HNS3_ROH_VERBS_H__
#define __HNS3_ROH_VERBS_H__

#include "core.h"
#include "hns3_common.h"

int hns3_roh_set_eid(struct roh_device *rohdev, struct roh_eid_attr *eid_attr);
struct roh_mib_stats *hns3_roh_alloc_hw_stats(struct roh_device *rohdev,
					      enum roh_mib_type mib_type);
int hns3_roh_get_hw_stats(struct roh_device *rohdev, struct roh_mib_stats *stats,
			  enum roh_mib_type mib_type);

#endif /* __HNS3_ROH_VERBS_H__ */
