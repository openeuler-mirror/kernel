/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ACCEL_H
#define XSC_ACCEL_H

#include <linux/netdev_features.h>
#include <linux/udp.h>
#include "common/xsc_core.h"
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>

static inline void xsc_udp_gso_handle_tx_skb(struct sk_buff *skb)
{
	int payload_len = skb_shinfo(skb)->gso_size + sizeof(struct udphdr);

	udp_hdr(skb)->len = htons(payload_len);
}

static inline bool xsc_inet_ifa_equal(__be32 addr, const struct in_ifaddr *ifa)
{
	return (addr == ifa->ifa_address);
}

static inline int xsc_inet_addr_onlink(struct in_device *in_dev, __be32 a)
{
	struct in_ifaddr *ifa;

	rcu_read_lock();
	for (ifa = rcu_dereference((in_dev)->ifa_list); ifa;
	     ifa = rcu_dereference(ifa->ifa_next)) {
		if (xsc_inet_ifa_equal(a, ifa)) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();

	return 0;
}

static inline bool xsc_arp_filter_tx(struct xsc_sq *sq, struct sk_buff *skb)
{
	struct xsc_core_device *xdev = sq->cq.xdev;
	struct xsc_adapter *adapter = xdev->eth_priv;
	struct net_device *dev = xdev->netdev;
	struct in_device *in_dev = NULL;
	struct xsc_sq_stats *stats = sq->stats;
	struct xsc_core_device *peer_xdev;
	struct in_device *peer_indev = NULL;
	struct arphdr *arp;
	unsigned char *arp_ptr;
	__be32 sip;
	unsigned char *smac;

	if (skb->protocol  != htons(ETH_P_ARP))
		return false;

	arp = arp_hdr(skb);
	if (arp->ar_op != htons(ARPOP_REPLY) && arp->ar_op != htons(ARPOP_REQUEST))
		return false;

	arp_ptr = (unsigned char *)(arp + 1);
	smac = arp_ptr;
	arp_ptr += dev->addr_len;
	memcpy(&sip, arp_ptr, 4);

	if (arp->ar_op == htons(ARPOP_REQUEST) && is_zero_ether_addr(smac))
		stats->arp_request_smac_0++;

	if (arp->ar_op == htons(ARPOP_REPLY) && is_zero_ether_addr(smac))
		stats->arp_reply_smac_0++;

	if (arp->ar_op != htons(ARPOP_REPLY) || !xsc_core_is_pf(xdev) ||
	    !xsc_host_is_multi_pcie(xdev))
		return false;

	if (!xsc_support_hw_feature(xdev, XSC_HW_ARP_FILTER_SUPPORT) ||
	    !XSC_GET_PFLAG(&adapter->nic_param, XSC_PFLAG_ARP_FILTER))
		return false;

	in_dev = __in_dev_get_rcu(skb->dev);
	if (!in_dev || IN_DEV_ARP_IGNORE(in_dev) > 0)
		return false;

	if (!xsc_inet_addr_onlink(in_dev, sip)) {
		peer_xdev = xsc_get_peer_pf(xdev);
		peer_indev = __in_dev_get_rcu(peer_xdev->netdev);

		if (peer_indev && xsc_inet_addr_onlink(peer_indev, sip)) {
			dev_kfree_skb_any(skb);
			stats->arp_reply_err_drop++;
			return true;
		}
	}

	return false;
}

static inline bool xsc_accel_handle_tx(struct xsc_sq *sq, struct sk_buff *skb)
{
	/*no not consider tls and ipsec*/
	if (skb_is_gso(skb) && skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
		xsc_udp_gso_handle_tx_skb(skb);

	if (xsc_arp_filter_tx(sq, skb))
		return false;

	return true;
}

static inline bool xsc_arp_filter_rx(struct xsc_rq *rq, struct sk_buff *skb)
{
	struct xsc_core_device *xdev = rq->cq.xdev;
	struct net_device *dev = xdev->netdev;
	struct xsc_rq_stats *stats = rq->stats;
	struct arphdr *arp;
	unsigned char *arp_ptr;
	unsigned char *smac;

	if (skb->protocol != htons(ETH_P_ARP))
		return false;

	arp = (struct arphdr *)(skb->data);
	if (arp->ar_op != htons(ARPOP_REPLY) && arp->ar_op != htons(ARPOP_REQUEST))
		return false;

	arp_ptr = (unsigned char *)(arp + 1);
	smac = arp_ptr;
	arp_ptr += dev->addr_len;

	if (arp->ar_op == htons(ARPOP_REQUEST) && is_zero_ether_addr(smac))
		stats->arp_request_smac_0++;

	if (arp->ar_op == htons(ARPOP_REPLY) && is_zero_ether_addr(smac))
		stats->arp_reply_smac_0++;

	return false;
}

static inline bool xsc_accel_handle_rx(struct xsc_rq *rq, struct sk_buff *skb)
{
	if (xsc_arp_filter_rx(rq, skb))
		return false;

	return true;
}

static inline bool xsc_vxlan_allowed(struct xsc_core_device *dev)
{
	return true;
}

static inline bool xsc_geneve_tx_allowed(struct xsc_core_device *dev)
{
	return false;
}

static inline bool xsc_any_tunnel_proto_supported(struct xsc_core_device *dev)
{
	return false;
}

#endif /* XSC_ACCEL_H */
