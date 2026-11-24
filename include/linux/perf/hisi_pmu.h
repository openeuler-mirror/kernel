/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HiSilicon SoC uncore PMU interface for in-kernel users
 *
 * Copyright (c) 2026 HiSilicon Limited.
 */

#ifndef __LINUX_PERF_HISI_PMU_H
#define __LINUX_PERF_HISI_PMU_H

#include <linux/errno.h>

struct device;

#if IS_ENABLED(CONFIG_HISI_PMU)
int hisi_uncore_pmu_get_type(struct device *dev);
#else
static inline int hisi_uncore_pmu_get_type(struct device *dev)
{
	return -ENODEV;
}
#endif

#endif /* __LINUX_PERF_HISI_PMU_H */
