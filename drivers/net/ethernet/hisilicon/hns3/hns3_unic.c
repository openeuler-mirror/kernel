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

void hns3_unic_set_default_cc(struct sk_buff *skb)
{
	struct ublhdr *ubl = (struct ublhdr *)skb->data;

	if (skb->protocol == htons(ETH_P_IP) ||
	    skb->protocol == htons(ETH_P_IPV6))
		ubl->h_cc = htons(UNIC_CC_DEFAULT_FECN_MODE);
}

void hns3_unic_init(struct net_device *netdev)
{
	struct hnae3_handle *h = hns3_get_handle(netdev);
	struct pci_dev *pdev = h->pdev;
	struct hnae3_ae_dev *ae_dev = pci_get_drvdata(pdev);

	netdev->features &= ~(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_CSUM |
		NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
		NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX);
	netdev->features |= NETIF_F_VLAN_CHALLENGED;
	netdev->hw_features &= ~(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_CSUM |
		NETIF_F_RXCSUM | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
		NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX);

	netdev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
	netdev->max_mtu = ae_dev->dev_specs.max_frm_size;
}

/**
 * L3T is an element of the TX BD interface for software and hardware
 * interaction, used to identify the message type. As the message data
 * given by software to the chip cannot be self-decoded, the driver needs
 * to actively inform the chip of the message type, which is unrelated
 * to checksum offloading.
 */
void hns3_unic_set_l3_type(struct sk_buff *skb, u32 *type_cs_vlan_tso)
{
	if (skb->protocol == htons(ETH_P_IP))
		hnae3_set_field(*type_cs_vlan_tso, HNS3_TXD_L3T_M,
				HNS3_TXD_L3T_S, HNS3_L3T_IPV4);
	else if (skb->protocol == htons(ETH_P_IPV6))
		hnae3_set_field(*type_cs_vlan_tso, HNS3_TXD_L3T_M,
				HNS3_TXD_L3T_S, HNS3_L3T_IPV6);
}

u8 hns3_unic_get_l3_type(struct net_device *netdev, u32 ol_info, u32 l234info)
{
	struct hns3_nic_priv *priv = netdev_priv(netdev);
	u32 l3_type;

	l3_type = hns3_get_l3_type(priv, l234info, ol_info);

	if (l3_type == HNS3_L3_TYPE_IPV4)
		return UB_IPV4_CFG_TYPE;
	else if (l3_type == HNS3_L3_TYPE_IPV6)
		return UB_IPV6_CFG_TYPE;
	else if (l3_type != HNS3_L3_TYPE_PARSE_FAIL)
		return UB_NOIP_CFG_TYPE;

	return UB_UNKNOWN_CFG_TYPE;
}
