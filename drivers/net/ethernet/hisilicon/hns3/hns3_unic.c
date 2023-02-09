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

#define HNS3_UNIC_LB_TEST_PACKET_SIZE	128

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

#define UNIC_DHCPV4_PROTO 0x0100
void hns3_unic_lp_setup_skb(struct sk_buff *skb)
{
	unsigned int nip_ctrl_len = sizeof(struct ub_nip_ctrl_fld);
	struct net_device *ndev = skb->dev;
	struct ub_nip_ctrl_fld *ctrl_fld;
	unsigned char *sw_ptype;
	unsigned char *packet;
	unsigned int i;

	skb_reserve(skb, NET_IP_ALIGN);

	sw_ptype = (unsigned char *)skb_put(skb, sizeof(unsigned char));
	*sw_ptype = UB_NOIP_CFG_TYPE;
	ctrl_fld = (struct ub_nip_ctrl_fld *)skb_put(skb, nip_ctrl_len);
	packet = (unsigned char *)skb_put(skb, HNS3_UNIC_LB_TEST_PACKET_SIZE -
					  nip_ctrl_len);
	ctrl_fld->proto = htons(UNIC_DHCPV4_PROTO);
	memcpy(ctrl_fld->d_guid, ndev->dev_addr, UBL_ALEN);
	memcpy(ctrl_fld->s_guid, ndev->dev_addr, UBL_ALEN);

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	for (i = 0; i < HNS3_UNIC_LB_TEST_PACKET_SIZE - nip_ctrl_len; i++)
		packet[i] = (unsigned char)(i & 0xff);
}

void hns3_unic_lb_check_skb_data(struct hns3_enet_ring *ring,
				 struct sk_buff *skb)
{
	unsigned int nip_ctrl_len = sizeof(struct ub_nip_ctrl_fld);
	struct hns3_enet_tqp_vector *tqp_vector = ring->tqp_vector;
	struct net_device *ndev = skb->dev;
	struct ub_nip_ctrl_fld *ctrl_fld;
	u32 len = skb_headlen(skb);
	bool is_success = false;
	unsigned char *packet;
	u32 i;

	if (len != HNS3_UNIC_LB_TEST_PACKET_SIZE + 1)
		goto out;

	ctrl_fld = (struct ub_nip_ctrl_fld *)(skb->data + 1);
	if (memcmp(ctrl_fld->d_guid, ndev->dev_addr, UBL_ALEN) ||
	    memcmp(ctrl_fld->s_guid, ndev->dev_addr, UBL_ALEN) ||
	    ctrl_fld->proto != htons(UNIC_DHCPV4_PROTO))
		goto out;

	packet = (unsigned char *)ctrl_fld + nip_ctrl_len;
	for (i = 0; i < HNS3_UNIC_LB_TEST_PACKET_SIZE - nip_ctrl_len; i++)
		if (packet[i] != (unsigned char)(i & 0xff))
			goto out;

	is_success = true;

out:
	if (is_success)
		tqp_vector->rx_group.total_packets++;
	else
		print_hex_dump(KERN_ERR, "ubn selftest:", DUMP_PREFIX_OFFSET,
			       16, 1, skb->data, len, true);

	dev_kfree_skb_any(skb);
}
