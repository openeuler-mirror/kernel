// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_skb_dump.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "sxe2_skb_dump.h"

#define SKB_DESCRIPTION_LEN 256
static DEFINE_PER_CPU(u64, pkg_cnt);

void sxe2_dump_skb(struct sk_buff *skb)
{
	u32 len = skb->len;
	u32 data_len = skb->data_len;
	u64 *pkt = this_cpu_ptr(&pkg_cnt);

	s8 desc[SKB_DESCRIPTION_LEN] = {};

	(void)snprintf(desc, SKB_DESCRIPTION_LEN, "pkg_cnt=%llu, skb addr:0x%llx %s",
		       (++*pkt), (u64)skb, "linear region");
#ifndef SXE2_CFG_RELEASE
	sxe2_log_binary(__FILE__, __func__, __LINE__, (u8 *)skb->data, (u64)skb,
			min_t(u32, (len - data_len), 256), desc);
#endif
	(void)data_len;
	(void)len;
}
