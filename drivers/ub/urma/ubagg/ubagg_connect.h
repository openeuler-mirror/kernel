/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg connect header file
 * Author: Chen Chongyu
 * Create: 2026-05-13
 * Note:
 * History: 2026-05-13: create file
 */

#ifndef UBAGG_CONNECT_H
#define UBAGG_CONNECT_H

#include <linux/types.h>
#include <ub/urma/ubcore_types.h>

#include "ubagg_types.h"

int ubagg_connect_init(void);
void ubagg_connect_uninit(void);

int ubagg_connect_xchg_seg(struct ubcore_seg *seg, uint32_t ue_idx,
			   struct ubcore_device *dev,
			   struct ubagg_seg_exchange_info *seg_info);

int ubagg_connect_xchg_jetty(struct ubcore_tjetty_cfg *cfg, uint32_t ue_idx,
			     bool is_jfr, struct ubcore_device *dev,
			     struct ubagg_jetty_exchange_info *jetty_info);

#endif /* UBAGG_CONNECT_H */
