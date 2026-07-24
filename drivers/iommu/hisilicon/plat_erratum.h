/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: the header file of the Platform Erratum Mechanism
 */

#ifndef __UMMU_PLAT_ERRATUM_H__
#define __UMMU_PLAT_ERRATUM_H__

#include "ummu.h"

#ifdef CONFIG_ACPI
void ummu_device_acpi_get_options(struct ummu_device *ummu);
#else
static inline void ummu_device_acpi_get_options(struct ummu_device *ummu)
{
}
#endif

void ummu_device_dt_get_options(struct ummu_device *ummu);
#endif
