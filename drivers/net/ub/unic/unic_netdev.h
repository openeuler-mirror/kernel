/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_NETDEV_H__
#define __UNIC_NETDEV_H__

#include <linux/netdevice.h>

#include "unic_dev.h"

int unic_net_open(struct net_device *netdev);
int unic_net_open_no_link_change(struct net_device *netdev);
int unic_net_stop(struct net_device *netdev);
void unic_net_stop_no_link_change(struct net_device *netdev);
void unic_set_netdev_ops(struct net_device *netdev);
void unic_link_status_update(struct unic_dev *unic_dev);
int unic_register_ipaddr_notifier(void);
void unic_unregister_ipaddr_notifier(void);
void unic_link_status_change(struct net_device *netdev, bool linkup);
void unic_enable_channels(struct unic_dev *unic_dev);
void unic_disable_channels(struct unic_dev *unic_dev);
int unic_query_link_status(struct unic_dev *unic_dev, u8 *link_status,
			   u8 *all_port_link_down);
int unic_register_netdevice_notifier(void);
void unic_unregister_netdevice_notifier(void);

#endif /* __UNIC_NETDEV_H__ */
