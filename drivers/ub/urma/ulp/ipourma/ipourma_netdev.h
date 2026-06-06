/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: Functions definition of ipourma_netdev
 */

#ifndef _IPOURMA_NETDEV_H
#define _IPOURMA_NETDEV_H

#include "ipourma_types.h"

extern int ipourma_min_eid_cnt;

struct ipourma_set_ip_work {
	struct list_head list;
	struct delayed_work d_work;
	struct ipourma_dev_priv *priv;
	int eid_idx;
};

int ipourma_unalloc_netdev(struct net_device *dev);
struct net_device *ipourma_alloc_netdev(struct ubcore_device *urma_dev);
int ipourma_create_new_eid(struct ipourma_dev_priv *priv, u32 eid_idx);

#endif
