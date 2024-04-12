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
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>

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

int hns3_unic_init(struct net_device *netdev)
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

	return hns3_unic_init_guid(netdev);
}

/**
 * L3T is an element of the TX BD interface for software and hardware
 * interaction, used to identify the message type. As the message data
 * given by software to the chip cannot be self-decoded, the driver needs
 * to actively inform the chip of the message type, which is unrelated
 * to checksum offloading.
 */
static void hns3_unic_set_l3_type(struct sk_buff *skb, u32 *type_cs_vlan_tso)
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

static int addr_event(struct notifier_block *nb, unsigned long event,
		      struct sockaddr *sa, struct net_device *ndev)
{
	struct hnae3_handle *handle;
	int ret;

	if (ndev->type != ARPHRD_UB)
		return NOTIFY_DONE;

	if (!hns3_unic_port_dev_check(ndev))
		return NOTIFY_DONE;

	handle = hns3_get_handle(ndev);

	switch (event) {
	case NETDEV_UP:
		if (handle->ae_algo->ops->add_addr) {
			ret = handle->ae_algo->ops->add_addr(handle,
				(const unsigned char *)sa, HNAE3_UNIC_IP_ADDR);
			if (ret)
				return NOTIFY_BAD;
		} else {
			return NOTIFY_DONE;
		}
		break;
	case NETDEV_DOWN:
		if (handle->ae_algo->ops->rm_addr) {
			ret = handle->ae_algo->ops->rm_addr(handle,
				(const unsigned char *)sa, HNAE3_UNIC_IP_ADDR);
			if (ret)
				return NOTIFY_BAD;
		} else {
			return NOTIFY_DONE;
		}
		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static int unic_inetaddr_event(struct notifier_block *this, unsigned long event,
			       void *ptr)
{
	struct in_ifaddr *ifa4 = (struct in_ifaddr *)ptr;
	struct net_device *ndev = (struct net_device *)ifa4->ifa_dev->dev;
	struct sockaddr_in in;

	in.sin_family = AF_INET;
	in.sin_addr.s_addr = ifa4->ifa_address;

	return addr_event(this, event, (struct sockaddr *)&in, ndev);
}

static int unic_inet6addr_event(struct notifier_block *this, unsigned long event,
				void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net_device *ndev = (struct net_device *)ifa6->idev->dev;
	struct sockaddr_in6 in6;

	in6.sin6_family = AF_INET6;
	in6.sin6_addr = ifa6->addr;

	return addr_event(this, event, (struct sockaddr *)&in6, ndev);
}

static struct notifier_block unic_inetaddr_notifier = {
	.notifier_call = unic_inetaddr_event
};

static struct notifier_block unic_inet6addr_notifier = {
	.notifier_call = unic_inet6addr_event
};

void register_ipaddr_notifier(void)
{
	register_inetaddr_notifier(&unic_inetaddr_notifier);
	register_inet6addr_notifier(&unic_inet6addr_notifier);
}

void unregister_ipaddr_notifier(void)
{
	unregister_inetaddr_notifier(&unic_inetaddr_notifier);
	unregister_inet6addr_notifier(&unic_inet6addr_notifier);
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
#define HNS3_UNIC_DUMP_ROW_SIZE 16

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
		print_hex_dump(KERN_ERR, "ubl selftest:", DUMP_PREFIX_OFFSET,
			       HNS3_UNIC_DUMP_ROW_SIZE, 1, skb->data, len, true);

	dev_kfree_skb_any(skb);
}

static void hns3_unic_extern_mc_guid(u8 *mguid, const unsigned char *addr)
{
	int proto_size = sizeof(u16);
	int addr_proto_oft = HNS3_SIMPLE_GUID_LEN - proto_size;
	int proto_oft = UBL_ALEN - proto_size;

	memset(mguid, 0xFF, proto_oft);
	memcpy(&mguid[proto_oft], &addr[addr_proto_oft], proto_size);
}

static int hns3_unic_add_mc_guid(struct net_device *netdev,
				 const unsigned char *addr)
{
	u8 format_simple_guid_addr[HNS3_SIMPLE_FORMAT_GUID_ADDR_LEN] = {0};
	struct hnae3_handle *h = hns3_get_handle(netdev);
	u8 mguid[UBL_ALEN] = {0};

	if (!hns3_unic_mguid_valid_check(addr)) {
		hns3_unic_format_sim_guid_addr(format_simple_guid_addr, addr);
		netdev_err(netdev, "Add mc guid err! invalid guid: %s\n",
			   format_simple_guid_addr);
		return -EINVAL;
	}

	hns3_unic_extern_mc_guid(mguid, addr);
	if (h->ae_algo->ops->add_addr)
		return h->ae_algo->ops->add_addr(h, (const u8 *)mguid,
						 HNAE3_UNIC_MCGUID_ADDR);

	return 0;
}

static int hns3_unic_del_mc_guid(struct net_device *netdev,
				 const unsigned char *addr)
{
	u8 format_simple_guid_addr[HNS3_SIMPLE_FORMAT_GUID_ADDR_LEN] = {0};
	struct hnae3_handle *h = hns3_get_handle(netdev);
	u8 mguid[UBL_ALEN] = {0};

	if (!hns3_unic_mguid_valid_check(addr)) {
		hns3_unic_format_sim_guid_addr(format_simple_guid_addr, addr);
		netdev_err(netdev, "Del mc guid err! invalid guid: %s\n",
			   format_simple_guid_addr);
		return -EINVAL;
	}

	hns3_unic_extern_mc_guid(mguid, addr);
	if (h->ae_algo->ops->rm_addr)
		return h->ae_algo->ops->rm_addr(h, (const u8 *)mguid,
						HNAE3_UNIC_MCGUID_ADDR);

	return 0;
}

static u8 hns3_unic_get_netdev_flags(struct net_device *netdev)
{
	u8 flags = 0;

	/* GUID promiscuous multiplexing unicast promiscuous, IP promiscuous
	 * multiplexing multicast promiscuous
	 */
	if (netdev->flags & IFF_PROMISC)
		flags = HNAE3_USER_UPE | HNAE3_USER_MPE;

	return flags;
}

void hns3_unic_set_rx_mode(struct net_device *netdev)
{
	struct hnae3_handle *h = hns3_get_handle(netdev);
	u8 new_flags;

	new_flags = hns3_unic_get_netdev_flags(netdev);

	__dev_mc_sync(netdev, hns3_unic_add_mc_guid, hns3_unic_del_mc_guid);

	h->netdev_flags = new_flags;
	hns3_request_update_promisc_mode(h);
}

int hns3_unic_init_guid(struct net_device *netdev)
{
	const u8 bc_guid[HNS3_SIMPLE_GUID_LEN] = {0xff, 0xff, 0xff, 0xff,
						  0xff, 0xff};
	struct hns3_nic_priv *priv = netdev_priv(netdev);
	struct hnae3_handle *h = priv->ae_handle;
	u8 temp_guid_addr[UBL_ALEN];
	int ret;

	if (!h->ae_algo->ops->get_func_guid ||
	    !h->ae_algo->ops->set_func_guid) {
		netdev_err(netdev, "the guid handlers may not exist\n");
		return -EOPNOTSUPP;
	}

	ret = h->ae_algo->ops->get_func_guid(h, temp_guid_addr);
	if (ret) {
		netdev_err(netdev, "get function guid fail, ret = %d!\n", ret);
		return ret;
	}

	ret = hns3_unic_add_mc_guid(netdev, bc_guid);
	if (ret) {
		netdev_err(netdev, "add mc guid fail, ret = %d!\n", ret);
		return ret;
	}

	memcpy(netdev->dev_addr, temp_guid_addr, netdev->addr_len);
	memcpy(netdev->perm_addr, temp_guid_addr, netdev->addr_len);

	h->ae_algo->ops->set_func_guid(h, netdev->dev_addr);

	return 0;
}

int hns3_unic_fill_skb_desc(struct hns3_nic_priv *priv,
			    struct hns3_enet_ring *ring,
			    struct sk_buff *skb, struct hns3_desc *desc,
			    struct hns3_desc_cb *desc_cb)
{
	struct hns3_desc_param param;

	desc_cb->send_bytes = skb->len;

	hns3_init_desc_data(skb, &param);
	hns3_unic_set_l3_type(skb, &param.type_cs_vlan_tso);
	desc->tx.type_cs_vlan_tso_len = cpu_to_le32(param.type_cs_vlan_tso);

	return 0;
}
