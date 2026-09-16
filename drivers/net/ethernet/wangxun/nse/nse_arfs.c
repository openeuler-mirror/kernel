// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_irq.h"

int
nse_rx_flow_steer(struct net_device *netdev, const struct sk_buff *skb,
		  u16 rxq_idx, u32 flow_id)
{
	return -EOPNOTSUPP;
}

