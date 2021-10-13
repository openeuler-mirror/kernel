/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_PROF_ADAP_H
#define SPHW_PROF_ADAP_H

#include <linux/workqueue.h>

#include "sphw_profile.h"

#define GET_PROF_ATTR_OPS(hwdev)	\
		((hwdev)->prof_attr ? (hwdev)->prof_attr->ops : NULL)

static inline int sphw_get_work_cpu_affinity(struct sphw_hwdev *hwdev,
					     enum cpu_affinity_work_type type)
{
	struct sphw_prof_ops *ops = GET_PROF_ATTR_OPS(hwdev);

	if (ops && ops->get_work_cpu_affinity)
		return ops->get_work_cpu_affinity(hwdev->prof_attr->priv_data, type);

	return WORK_CPU_UNBOUND;
}

static inline void sphw_fault_post_process(struct sphw_hwdev *hwdev, u16 src, u16 level)
{
	struct sphw_prof_ops *ops = GET_PROF_ATTR_OPS(hwdev);

	if (ops && ops->fault_recover)
		ops->fault_recover(hwdev->prof_attr->priv_data, src, level);
}

static inline bool sphw_sw_feature_en(struct sphw_hwdev *hwdev, u64 feature_bit)
{
	if (!hwdev->prof_attr)
		return false;

	return (hwdev->prof_attr->sw_feature_cap & feature_bit) &&
		(hwdev->prof_attr->dft_sw_feature & feature_bit);
}

#define SW_FEATURE_EN(hwdev, f_bit)	\
		sphw_sw_feature_en(hwdev, SPHW_SW_F_##f_bit)
#define SPHW_F_CHANNEL_LOCK_EN(hwdev)	SW_FEATURE_EN(hwdev, CHANNEL_LOCK)

void sphw_init_profile_adapter(struct sphw_hwdev *hwdev);
void sphw_deinit_profile_adapter(struct sphw_hwdev *hwdev);

#endif
