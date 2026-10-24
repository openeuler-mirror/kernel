/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ummu mpam internal interface.
 */

#ifndef __UMMU_QOS_H__
#define __UMMU_QOS_H__

#include <linux/device.h>
#include "ummu.h"

enum ummu_mpam_type {
	/* Memory traffic monitoring of the UB device when ummu is bypassed. */
	UMMU_BYPASS_MPAM,
	/*
	 * Memory traffic monitoring of ummu-originated transactions
	 * relating to the Non-secure programming interface.
	 */
	UMMU_UOTR_MPAM,
	UMMU_MPAM_TYPE_NUM,
};

int ummu_device_set_group_mpam(struct ummu_core_device *core_dev, u32 tid,
				u16 partid, u8 pmg);
int ummu_group_qos_set_mpam(struct iommu_group *group, u16 partid, u8 pmg);
int ummu_group_qos_get_mpam(struct iommu_group *group, u16 *partid, u8 *pmg);
int ummu_set_bypass_mpam(struct ummu_device *ummu, int partid, int pmg);
int ummu_get_bypass_mpam(struct ummu_device *ummu, int *partid, int *pmg);
int ummu_set_uotr_mpam(struct ummu_device *ummu, int partid, int pmg);
int ummu_get_uotr_mpam(struct ummu_device *ummu, int *partid, int *pmg);
int ummu_device_set_config(struct ummu_core_device *core_dev, struct device *dev,
			   int type, void *data);
int ummu_device_dev_config(struct device *dev, int type, int command, void *data);
void ummu_release_partid_map(void);

#endif  /* __UMMU_QOS_H__ */
