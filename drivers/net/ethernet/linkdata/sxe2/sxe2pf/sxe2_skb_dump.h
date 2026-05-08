/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_skb_dump.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_SKB_DUMP_H__
#define __SXE2_SKB_DUMP_H__

#include <linux/skbuff.h>
#include "sxe2_log.h"

void sxe2_dump_skb(struct sk_buff *skb);

#ifndef SXE2_CFG_RELEASE
#define SKB_DUMP(skb) sxe2_dump_skb(skb)
#else
#define SKB_DUMP(skb)
#endif

#endif
