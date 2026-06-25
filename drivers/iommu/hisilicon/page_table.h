/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU MATT interface
 */

#ifndef __UMMU_PAGE_TABLE_H__
#define __UMMU_PAGE_TABLE_H__

#include "ummu.h"

int ummu_domain_collect_pgtable(struct ummu_domain *u_domain);
int ummu_global_identity_pgtbl_init(struct ummu_device *ummu);
void ummu_global_identity_pgtbl_free(void);
struct ummu_domain *ummu_get_global_identity_domain(void);

#endif /* __UMMU_PAGE_TABLE_H__ */
