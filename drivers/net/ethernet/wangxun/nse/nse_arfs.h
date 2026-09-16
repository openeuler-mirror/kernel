/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_ARFS_H_
#define _NSE_ARFS_H_

#ifdef CONFIG_RFS_ACCEL
int
nse_rx_flow_steer(struct net_device *netdev, const struct sk_buff *skb,
		  u16 rxq_idx, u32 flow_id);
#else

static inline int
nse_rx_flow_steer(struct net_device __always_unused *netdev,
		  const struct sk_buff __always_unused *skb,
		  u16 __always_unused rxq_idx, u32 __always_unused flow_id)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_RFS_ACCEL */

#endif
