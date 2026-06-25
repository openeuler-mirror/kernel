/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg device helper header file
 */

#ifndef UBAGG_DEVICE_H
#define UBAGG_DEVICE_H

#include <ub/urma/ubcore_types.h>

struct ubcore_ucontext *
ubagg_alloc_ucontext(struct ubcore_device *dev, uint32_t eid_index,
		     struct ubcore_udrv_priv *udrv_data);
int ubagg_free_ucontext(struct ubcore_ucontext *uctx);
uint32_t ubagg_get_ucontext_count(void);

struct ubcore_device *ubagg_find_bonding_device(const union ubcore_eid *eid);

#endif /* UBAGG_DEVICE_H */
