/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: Functions definition of ipourma_netlink
 */

#ifndef _IPOURMA_NETLINK_H
#define _IPOURMA_NETLINK_H

#include "ipourma_types.h"

int  ipourma_netlink_init(void);
void ipourma_netlink_uninit(void);
void ipourma_set_rtnl_link_ops(struct net_device *dev);
struct rtnl_link_ops *ipourma_get_rtnl_link_ops(void);

#endif
