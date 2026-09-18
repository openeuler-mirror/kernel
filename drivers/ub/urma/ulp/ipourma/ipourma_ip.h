/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: Functions definition of ipourma_ip
 */

#ifndef _IPOURMA_IP_H
#define _IPOURMA_IP_H

#include "ipourma_types.h"

int ipourma_send_ipv6_netlink(struct net_device *dev, union ubcore_eid *eid, int msg_type);
void ipourma_init_ipv6_addr(struct work_struct *work);
void ipourma_unset_ipv6_addr(struct work_struct *work);

#endif
