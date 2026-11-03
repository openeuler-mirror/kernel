/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu internal interfaces — cross-file bridge.
 */

#ifndef __UMMU_DTU_INTERNAL_H__
#define __UMMU_DTU_INTERNAL_H__

#include "dtu.h"
#include "dtu_cmd.h"

#include <linux/iommu.h>
#include <linux/types.h>

extern const struct iommu_domain_ops ub_dtu_domain_ops;

/* Two-step container_of: iommu_domain * → ub_dtu_logic_domain * */
static inline struct ub_dtu_logic_domain *to_ub_dtu_domain(struct iommu_domain *dom)
{
	struct ummu_base_domain *base_domain;

	base_domain = container_of(dom, struct ummu_base_domain, domain);
	return container_of(base_domain, struct ub_dtu_logic_domain, base_domain);
}

void ub_dtu_logic_init(void);
int  ub_dtu_logic_add_device(struct ub_dtu_device *dtu);
void ub_dtu_logic_remove_device(struct ub_dtu_device *dtu);

int ub_dtu_config_all_dev(struct ub_dtu_logic_domain *dtu_dom,
			  const struct dtu_addr_window *win, u8 win_num,
			  int prot, bool enable, u8 *out_imp_win_num);

#endif /* __UMMU_DTU_INTERNAL_H__ */
