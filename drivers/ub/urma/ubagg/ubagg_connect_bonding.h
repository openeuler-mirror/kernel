/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg connect bonding header file
 * Author: Chen Chongyu
 * Create: 2026-05-13
 * Note:
 * History: 2026-05-13: create file
 */

#ifndef UBAGG_CONNECT_BONDING_H
#define UBAGG_CONNECT_BONDING_H

#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>

#define UBAGG_NS_TO_MS            1000000
#define UBAGG_EXC_THRESHOLD_MS    20

int ubagg_connect_exchange_udata_when_import_seg(struct ubcore_seg *seg,
				struct ubcore_udata *udata, struct ubcore_device *dev);

int ubagg_connect_exchange_udata_when_import_jetty(
	struct ubcore_tjetty_cfg *cfg, struct ubcore_udata *udata, bool is_jfr,
	struct ubcore_device *dev);

void handle_bonding_msg(struct ubcore_device *dev,
	struct ubcore_comm_msg *msg, void *conn);

#endif
