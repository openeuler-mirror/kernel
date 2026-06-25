/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg failback header file
 */

#ifndef UBAGG_FAILBACK_H
#define UBAGG_FAILBACK_H

#include <linux/skbuff.h>
#include <net/genetlink.h>

#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubagg_types.h"

int ubagg_fb_nl_start(struct sk_buff *skb, struct genl_info *info);
int ubagg_fb_nl_result(struct sk_buff *skb, struct genl_info *info);

int ubagg_fb_init(void);
void ubagg_fb_exit(void);

#endif /* UBAGG_FAILBACK_H */
