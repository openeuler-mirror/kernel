/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2023 Hisilicon Limited. */

#ifndef __HNS3_ROH_H
#define __HNS3_ROH_H

#include "hns3_enet.h"

#define ARP_IP_LEN	4
#define HNS3_ROH_MAC_ADDR_MASK	0x00ffffff

#define hns3_roh_update_mac_by_ip(ip_addr, mac) \
	u64_to_ether_addr((ip_addr) & HNS3_ROH_MAC_ADDR_MASK, mac)
#define hns3_roh_arp_hlen_max(skb) \
	(ETH_HLEN + arp_hdr_len((skb)->dev) + VLAN_HLEN)

static inline int hns3_roh_arp_reply_idx_move_fd(int idx)
{
	return (idx + 1) % HNS3_APR_REPLY_LTH;
}

void hns3_handle_roh_arp_reply(struct hns3_enet_tqp_vector *tqp_vector,
			       struct hns3_nic_priv *priv);
int hns3_handle_roh_arp_req(struct sk_buff *skb, struct hns3_nic_priv *priv);
bool hns3_need_to_handle_roh_arp_req(struct sk_buff *skb);
#endif
