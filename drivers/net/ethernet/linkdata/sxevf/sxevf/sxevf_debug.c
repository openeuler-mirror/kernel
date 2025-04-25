// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxevf_debug.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/highmem.h>

#include "sxevf_debug.h"

#define SKB_DESCRIPTION_LEN 256
void sxevf_dump_skb(struct sk_buff *skb)
{
#ifndef SXE_DRIVER_RELEASE
	u32 len = skb->len;
	u32 data_len = skb->data_len;
#endif

	s8 desc[SKB_DESCRIPTION_LEN] = {};

	snprintf(desc, SKB_DESCRIPTION_LEN, "skb addr:%p %s", skb,
		 "linear region");
#ifndef SXE_DRIVER_RELEASE
	sxe_log_binary(__FILE__, __func__, __LINE__, (u8 *)skb->data,
		       (u64)skb, min_t(u32, len - data_len, 256), desc);
#endif
}
