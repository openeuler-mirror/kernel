// SPDX-License-Identifier: GPL-2.0+
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <linux/skbuff.h>

#include "ubl.h"
#include "hnae3.h"
#include "hns3_enet.h"
#include "hns3_unic.h"

void hns3_unic_init(struct net_device *netdev)
{
	netdev->features &= ~(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_CSUM |
		NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
		NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX);
	netdev->features |= NETIF_F_VLAN_CHALLENGED;
	netdev->hw_features &= ~(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_CSUM |
		NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
		NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX);

	netdev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
}
