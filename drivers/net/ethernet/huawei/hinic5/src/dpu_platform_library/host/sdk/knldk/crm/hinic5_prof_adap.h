/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_prof_adap.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_PROF_ADAP_H
#define HINIC5_PROF_ADAP_H

#include <linux/workqueue.h>

#include "hinic5_profile.h"
#include "hinic5_hwdev.h"

enum cpu_affinity_work_type {
	WORK_TYPE_AEQ,
	WORK_TYPE_MBOX,
	WORK_TYPE_MGMT_MSG,
	WORK_TYPE_COMM,
	WORK_TYPE_FAST_MSG,
};

enum hisdk5_sw_features {
	HISDK5_SW_F_CHANNEL_LOCK = BIT(0),
};

#define GET_PROF_ATTR_OPS(hwdev)	\
		((hwdev)->prof_attr ? (hwdev)->prof_attr->ops : NULL)

static inline int hisdk5_get_work_cpu_affinity(struct hinic5_hwdev *hwdev,
					       enum cpu_affinity_work_type type)
{
	struct hinic5_prof_ops *ops = GET_PROF_ATTR_OPS(hwdev);

	if (ops && ops->get_work_cpu_affinity)
		return ops->get_work_cpu_affinity(hwdev->prof_attr->priv_data, type);

	return WORK_CPU_UNBOUND;
}

static inline void hisdk5_fault_post_process(struct hinic5_hwdev *hwdev,
					     u16 src, u16 level)
{
	struct hinic5_prof_ops *ops = GET_PROF_ATTR_OPS(hwdev);

	if (ops && ops->fault_recover)
		ops->fault_recover(hwdev->prof_attr->priv_data, src, level);
}

static inline void hisdk5_probe_success(struct hinic5_hwdev *hwdev)
{
	struct hinic5_prof_ops *ops = GET_PROF_ATTR_OPS(hwdev);

	if (ops && ops->probe_success)
		ops->probe_success(hwdev->prof_attr->priv_data);
}

static inline bool hisdk5_sw_feature_en(const struct hinic5_hwdev *hwdev,
					u64 feature_bit)
{
	if (!hwdev->prof_attr)
		return false;

	return ((hwdev->prof_attr->sw_feature_cap & feature_bit) != 0) &&
		((hwdev->prof_attr->dft_sw_feature & feature_bit) != 0);
}

#ifdef CONFIG_MODULE_PROF
static inline void hisdk5_remove_pre_process(struct hinic5_hwdev *hwdev)
{
	struct hinic5_prof_ops *ops = NULL;

	if (!hwdev)
		return;

	ops = GET_PROF_ATTR_OPS(hwdev);

	if (ops && ops->remove_pre_handle)
		ops->remove_pre_handle(hwdev);
}
#else
static inline void hisdk5_remove_pre_process(struct hinic5_hwdev *hwdev) {};
#endif

#define SW_FEATURE_EN(hwdev, f_bit)	\
		hisdk5_sw_feature_en(hwdev, HISDK5_SW_F_##f_bit)
#define HISDK5_F_CHANNEL_LOCK_EN(hwdev)	SW_FEATURE_EN(hwdev, CHANNEL_LOCK)

int  hisdk5_init_profile_adapter(struct hinic5_hwdev *hwdev);
void hisdk5_deinit_profile_adapter(struct hinic5_hwdev *hwdev);

#endif
