/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: Functions definition of ipourma_netdev
 */

#ifndef _IPOURMA_NETDEV_H
#define _IPOURMA_NETDEV_H

#include "ipourma_types.h"

struct ipourma_set_ip_work {
	struct list_head list;
	struct delayed_work d_work;
	struct ipourma_dev_priv *priv;
	int eid_idx;
};

/* Deferred old-ns cleanup queued from ndo_stop; carries the pre-move
 * net/ifindex (they switch after ndo_stop). */
struct ipourma_netns_cleanup {
	struct work_struct work;
	struct ipourma_dev_priv *priv;
	struct net *net;	/* maybe_get_net() reference on the old namespace */
	int ifindex;		/* ifindex in the old namespace */
};

int ipourma_unalloc_netdev(struct net_device *dev);
struct net_device *ipourma_alloc_netdev(struct ubcore_device *urma_dev);
int ipourma_create_new_eid(struct ipourma_dev_priv *priv, u32 eid_idx);

#endif
