// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/inetdevice.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_net.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hns3_enet.h"
#include "hns3_cae_pkt.h"

#define DEFAULT_PAGE_SIZE	4096
#define DEFAULT_TCP_MSS	1460
#define DEFAULT_MIN_PKT_LEN	60
#define NEXTHDR_HOP		0

u8 pkt_head_table[HNS3_CAE_PKT_TYPE_MAX][128] = {
	/* ARP */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0xee, 0x08, 0x06, 0x00, 0x01,
	 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x01, 0x01, 0x01,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
	 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* TCP */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0xee, 0x08, 0x00, 0x45, 0x00,
	 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x40, 0xfd,
	 0xe4, 0x33, 0xc0, 0xa8, 0x0a, 0x0a, 0xc0, 0xa8,
	 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* TCP_DSCP */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0xee, 0x08, 0x00, 0x45, 0x00,
	 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x40, 0xfd,
	 0xe4, 0x33, 0xc0, 0xa8, 0x0a, 0x0a, 0xc0, 0xa8,
	 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* PAUSE */
	{
	 0x01, 0x80, 0xc2, 0x00, 0x00, 0x01, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x06, 0x88, 0x08, 0x00, 0x01,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* PAUSE_ERR */
	{
	 0x01, 0x80, 0xc2, 0x00, 0x00, 0x01, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x06, 0x88, 0x08, 0x00, 0x01,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* PFC */
	{
	 0x01, 0x80, 0xc2, 0x00, 0x00, 0x01, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x06, 0x88, 0x08, 0x01, 0x01,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* PFC_ERR */
	{
	 0x01, 0x80, 0xc2, 0x00, 0x00, 0x01, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x06, 0x88, 0x08, 0x01, 0x01,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* IPV4 */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x02, 0x08, 0x00, 0x45, 0x00,
	 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x40, 0xfd,
	 0x75, 0x8b, 0xc0, 0xa8, 0x0a, 0x0a, 0xc0, 0xa8,
	 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	/* IPV4_LOOSE_OPTION */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x03, 0x08, 0x00,
	 0x46, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00,
	 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x0a, 0x0b,
	 0xc0, 0xa8, 0x0a, 0x0a,
	 0x83, 0x00, 0x04, 0x00,
	 0x00, 0x64, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
	 0x19, 0x09, 0x00, 0x00
	},
	/* IPV4_TRACEROUTE_OPTION */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x03, 0x08, 0x00,
	 0x48, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00,
	 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x0a, 0x0b,
	 0xc0, 0xa8, 0x0a, 0x0a,
	 0x52, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0xc0, 0x00, 0x00, 0x01,
	 0x00, 0x64, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
	 0x19, 0x09, 0x00, 0x00
	},
	/* IPV6 */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x02, 0x86, 0xdd, 0x60, 0x00,
	 0x00, 0x00, 0x05, 0xdc, 0x3b, 0xff, 0xfe, 0xc0,
	 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00,
	 0x00, 0x00, 0xc0, 0xa8, 0x0a, 0x0b, 0xfe, 0xc0,
	 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00,
	 0x00, 0x00, 0xc0, 0x55, 0x01, 0x01, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00,
	},
	/* ipv6_extension_routing */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x03, 0x86, 0xdd,
	 0x60, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x2b, 0xff,
	 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
	 0x02, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x0a, 0x0b,
	 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
	 0x02, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x0a, 0x0a,
	 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x16, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x21,
	 0x16, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x22,
	 0x00, 0x64, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
	 0x15, 0x99, 0x00, 0x00
	},
	/* IPV4+SCTP */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x02, 0x08, 0x00,
	 0x45, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00,
	 0x40, 0x84, 0x00, 0x00, 0x80, 0x05, 0x7a, 0xb5,
	 0x80, 0x05, 0x7a, 0xab,
	 0x00, 0x64, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x04,
	},
	/* IPV6+SCTP */
	{
	 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xaa,
	 0xbb, 0xcc, 0xdd, 0x02, 0x86, 0xdd,
	 0x60, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x84, 0xff,
	 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
	 0x02, 0x00, 0x00, 0x00, 0x80, 0x05, 0x7a, 0xb5,
	 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
	 0x02, 0x00, 0x00, 0x00, 0x80, 0x05, 0x7a, 0xab,
	 0x00, 0x64, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x04,
	},
};

#define MAX_KTHREAD_NUM 16
struct kthread_info {
	int tid;
	struct task_struct *task;
	int stop;
	struct hns3_nic_priv *net_priv;
	struct hns3_cae_pkt_cfg_info *in_info;
	struct hns3_cae_pkt_result_info *out_info;
};

struct kthread_info *kthread_table[MAX_KTHREAD_NUM] = {0};

/* This mutexes are created for packets send */
struct mutex pkt_mutex[MAX_KTHREAD_NUM];

int is_send_thread(int tid)
{
	return (tid % 2 == 0);
}

int __get_tid(int queue_id, int is_send)
{
	if (is_send)
		return (queue_id * 2) % MAX_KTHREAD_NUM;
	else
		return (queue_id * 2 + 1) % MAX_KTHREAD_NUM;
}

void fill_skb_head(struct sk_buff *skb, int mss)
{
	struct ipv6hdr *ip6_hdr;
	int protocol;

	skb->network_header = ETH_HLEN;
	if (skb->protocol == htons(ETH_P_8021Q)) {
		skb->network_header += VLAN_HLEN;
		protocol = vlan_get_protocol(skb);
	} else {
		protocol = skb->protocol;
	}
	if (protocol == htons(ETH_P_IP))
		skb->transport_header = skb->network_header +
					ip_hdr(skb)->ihl * 4;
	if (protocol == htons(ETH_P_IPV6)) {
		ip6_hdr = (struct ipv6hdr *)skb_network_header(skb);
		skb->transport_header = skb->network_header +
					sizeof(struct ipv6hdr);
		if (ip6_hdr->nexthdr == NEXTHDR_HOP)
			skb->transport_header += (skb_transport_header(skb)[1] +
						  1) << 3;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
	}

	skb_shinfo(skb)->gso_size = mss;
}

static struct sk_buff *__hns_assemble_skb(struct net_device *ndev,
					  const void *data, int length,
					  int queue_id, int mss)
{
	const struct ethhdr *ethhead = (const struct ethhdr *)data;
	const char *head_data = (const char *)data;
	struct sk_buff *skb;
	int proc_length;
	struct page *p;
	int bnum = 0;
	void *buff;

	/* allocate test skb */
	skb = alloc_skb(256, GFP_KERNEL);
	if (!skb)
		return NULL;

	skb->protocol = ethhead->h_proto;
	skb->queue_mapping = queue_id;
	skb->dev = ndev;
	skb_reset_mac_header(skb);

	if (length <= 256) {
		skb_put(skb, length);
		memcpy(&skb->data[0], head_data, length);
	} else {
		skb_put(skb, 256);
		memcpy(&skb->data[0], head_data, 256);
		proc_length = length - 256;
		while (proc_length > DEFAULT_PAGE_SIZE) {
			p = dev_alloc_pages(get_order(DEFAULT_PAGE_SIZE));
			if (!p) {
				dev_kfree_skb_any(skb);
				return NULL;
			}

			buff = page_address(p);
			memcpy(buff, head_data + length - proc_length,
			       DEFAULT_PAGE_SIZE);
			skb_add_rx_frag(skb, bnum, p, 0, DEFAULT_PAGE_SIZE,
					DEFAULT_PAGE_SIZE);
			proc_length -= DEFAULT_PAGE_SIZE;
			bnum++;
		}
		p = dev_alloc_pages(get_order(DEFAULT_PAGE_SIZE));
		if (!p) {
			dev_kfree_skb_any(skb);
			return NULL;
		}

		buff = page_address(p);
		memcpy(buff, head_data + length - proc_length, proc_length);
		skb_add_rx_frag(skb, bnum, p, 0, proc_length,
				DEFAULT_PAGE_SIZE);
	}

	fill_skb_head(skb, mss);

	return skb;
}

void hns3_cae_pkt_type_deal(u8 *payload, struct hns3_cae_pkt_cfg_info *in_info,
			    struct in_ifaddr *ifa_list,
			    u8 *pkt_payload, u32 head_len)
{
	u8 payload_data;
	int i;

	/* DST_MAC */
	memcpy(payload, in_info->dst_mac, ETH_ALEN);
	payload[16] = in_info->pkt_len / 256;
	payload[17] = in_info->pkt_len % 256;

	/* checksum */
	memcpy(payload + 24, &in_info->pkt_checksum, 2);

	/* SRC_IP */
	if (ifa_list)
		memcpy(payload + 26, &ifa_list->ifa_address, 4);

	/* DST_IP */
	memcpy(payload + 30, in_info->dst_ip, 4);

	/* payload */
	payload_data = in_info->pkt_payload_flag == 1 ? 0xFF : 0;
	for (i = 0; i < in_info->pkt_len; i++)
		pkt_payload[i] = payload_data;
	memcpy(payload + head_len, pkt_payload, in_info->pkt_len - head_len);
}

void __fill_the_pkt_head(struct net_device *netdev, u8 *payload,
			 struct hns3_cae_pkt_cfg_info *in_info)
{
	struct in_ifaddr *ifa_list;
	u8 *pkt_payload;
	u32 vlan_tag;
	size_t count;
	int i;

	pkt_payload = kzalloc((in_info->pkt_len) * sizeof(u8), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(pkt_payload))
		return;

	count = in_info->pkt_len > 128 ? 128 : in_info->pkt_len;
	memcpy(payload, pkt_head_table[in_info->type], count);
	memcpy(payload + 6, netdev->dev_addr, ETH_ALEN);
	ifa_list = (struct in_ifaddr *)netdev->ip_ptr->ifa_list;

	switch (in_info->type) {
	case HNS3_CAE_PKT_TYPE_ARP:
		memcpy(payload + 22, netdev->dev_addr, ETH_ALEN);

		if (ifa_list)
			memcpy(payload + 28, &ifa_list->ifa_address, 4);

		memcpy(payload + 32, in_info->dst_mac, ETH_ALEN);
		memcpy(payload + 38, in_info->dst_ip, 4);
		break;
	case HNS3_CAE_PKT_TYPE_TCP:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);
		payload[16] = in_info->pkt_len / 256;
		payload[17] = in_info->pkt_len % 256;

		if (ifa_list)
			memcpy(payload + 26, &ifa_list->ifa_address, 4);

		memcpy(payload + 30, in_info->dst_ip, 4);
		break;
	case HNS3_CAE_PKT_TYPE_TCP_DSCP:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);
		payload[15] = (in_info->dscp << 2);
		payload[16] = in_info->pkt_len / 256;
		payload[17] = in_info->pkt_len % 256;

		if (ifa_list)
			memcpy(payload + 26, &ifa_list->ifa_address, 4);

		memcpy(payload + 30, in_info->dst_ip, 4);
		break;
	case HNS3_CAE_PKT_TYPE_PAUSE:
		memcpy(payload + 16, &in_info->pause_time, 2);
		break;
	case HNS3_CAE_PKT_TYPE_PAUSE_ERR:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);
		memcpy(payload + 12, &in_info->eth_type, 2);
		memcpy(payload + 14, &in_info->pause_code, 2);
		memcpy(payload + 16, &in_info->pause_time, 2);
		break;
	case HNS3_CAE_PKT_TYPE_PFC:
		payload[17] = in_info->priority;
		for (i = 0; i < 8; i++) {
			if ((in_info->priority >> i) & 0x01)
				memcpy(payload + 18 + i * 2,
				       &in_info->pause_time, 2);
		}
		break;
	case HNS3_CAE_PKT_TYPE_PFC_ERR:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);
		memcpy(payload + 12, &in_info->eth_type, 2);
		memcpy(payload + 14, &in_info->pause_code, 2);
		payload[17] = in_info->priority;
		for (i = 0; i < 8; i++) {
			if ((in_info->priority >> i) & 0x01)
				memcpy(payload + 18 + i * 2,
				       &in_info->pause_time, 2);
		}
		break;
	case HNS3_CAE_PKT_TYPE_IPV4:
		hns3_cae_pkt_type_deal(payload, in_info, ifa_list, pkt_payload,
				       34);
		break;
	case HNS3_CAE_PKT_TYPE_IPV4_LOOSESRCROUTE_OPTION:
		hns3_cae_pkt_type_deal(payload, in_info, ifa_list, pkt_payload,
				       58);
		break;
	case HNS3_CAE_PKT_TYPE_IPV4_TRACEROUTE_OPTION:
		hns3_cae_pkt_type_deal(payload, in_info, ifa_list, pkt_payload,
				       66);
		break;
	case HNS3_CAE_PKT_TYPE_IPV6:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);
		memcpy(payload + 22, in_info->pkt_inet6_addr, 16);

		hns3_cae_pkt_type_deal(payload, in_info, ifa_list, pkt_payload,
				       54);
		break;
	case HNS3_CAE_PKT_TYPE_IPV6_EXTENSION_ROUTING:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);
		memcpy(payload + 22, in_info->pkt_inet6_addr, 16);

		hns3_cae_pkt_type_deal(payload, in_info, ifa_list, pkt_payload,
				       114);
		break;
	case HNS3_CAE_PKT_TYPE_SCTP4:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);

		/* SRC_IP */
		if (ifa_list)
			memcpy(payload + 26, &ifa_list->ifa_address, 4);

		memcpy(payload + 30, in_info->dst_ip, 4);
		/* checksum */
		memcpy(payload + 42, &in_info->pkt_checksum_sctp, 4);
		break;
	case HNS3_CAE_PKT_TYPE_SCTP6:
		memcpy(payload, in_info->dst_mac, ETH_ALEN);
		memcpy(payload + 22, in_info->pkt_inet6_addr, 16);
		/* checksum */
		memcpy(payload + 62, &in_info->pkt_checksum_sctp, 4);
		break;
	default:
		break;
	}

	if (in_info->vlan_tag) {
		memmove(payload + 16, payload + 12, 48);
		vlan_tag = htonl(in_info->vlan_tag);
		memcpy(payload + 12, &vlan_tag, sizeof(vlan_tag));
	}

	kfree(pkt_payload);
}

#define MAX_PKTS_NUM_ONCE 50

static int __hns3_cae_change_send_queue(int cur_queue,
					struct hns3_cae_pkt_cfg_info *in_info,
					u8 *payload)
{
	int queue_id = cur_queue;

	queue_id++;
	if (queue_id >= in_info->queue_id + in_info->multi_queue)
		queue_id = in_info->queue_id;

	/* use last ip for different queue */
	if (in_info->multi_queue > 1)
		payload[33] = queue_id % 255;

	return queue_id;
}

int __hns3_cae_send_pkt(struct hns3_nic_priv *net_priv,
			struct hns3_cae_pkt_cfg_info *in_info,
			struct hns3_cae_pkt_result_info *out_info)
{
	struct hnae3_handle *handle;
	struct sk_buff *skb;
	int pkt_len;
	u8 *payload;
	int ret = 0;
	int i;
	int change_flag;
	int total_len;
	int tid;
	int queue_id = in_info->queue_id;
	struct net_device *netdev = net_priv->netdev;

	handle = net_priv->ae_handle;
	if (queue_id > handle->kinfo.num_tqps ||
	    queue_id + in_info->multi_queue - 1 > handle->kinfo.num_tqps) {
		pr_err("%s,%d:queue(%d) or multi_queue(%d) is invalid\n",
		       __func__, __LINE__,
		       in_info->queue_id, in_info->multi_queue);
		return -EINVAL;
	}

	pkt_len = in_info->pkt_len;

	payload = kzalloc(pkt_len, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(payload))
		return -ENOMEM;

	__fill_the_pkt_head(netdev, payload, in_info);
	tid = __get_tid(queue_id, 1);
	total_len = 0;
	change_flag = MAX_PKTS_NUM_ONCE;
	for (i = 0; i < in_info->num; i++) {
skb_again:
		if (in_info->multi_queue > 1) {
			change_flag--;
			if (change_flag <= 0) {
				change_flag = MAX_PKTS_NUM_ONCE;
				queue_id =
				    __hns3_cae_change_send_queue(queue_id,
								 in_info,
								 payload);
			}
		}

		skb = __hns_assemble_skb(netdev, payload, pkt_len,
					 queue_id, in_info->mss);
		if (!skb) {
			ret = -1;
			goto out;
		}

send_again:
		if (in_info->new_thread && kthread_table[tid]) {
			if (kthread_table[tid]->stop) {
				dev_kfree_skb_any(skb);
				break;
			}
		}

		ret = netdev->netdev_ops->ndo_start_xmit(skb, netdev);
		if (ret == NETDEV_TX_BUSY) {
			if (in_info->multi_queue > 1) {
				dev_kfree_skb_any(skb);
				change_flag = 0;
				goto skb_again;
			}

			if (in_info->wait_all_finish) {
				schedule();
				goto send_again;
			}

			dev_kfree_skb_any(skb);
			break;
		}
		total_len += pkt_len;
	}

	out_info->num = i;
	out_info->total_len = total_len;
out:
	kfree(payload);
	return ret;
}

void hns3_cae_pkt_init(void)
{
	int i;

	for (i = 0; i < MAX_KTHREAD_NUM; i++)
		mutex_init(&pkt_mutex[i]);
}

void hns3_cae_pkt_destroy(void)
{
	int i;

	for (i = 0; i < MAX_KTHREAD_NUM; i++)
		mutex_destroy(&pkt_mutex[i]);
}

int __hns3_cae_new_task(void *arg)
{
	struct kthread_info *info = (struct kthread_info *)arg;
	int tid = info->tid;

	if (is_send_thread(tid)) {
		__hns3_cae_send_pkt(info->net_priv,
				    info->in_info, info->out_info);
		pr_err("send pkt %d, the total len = %d\n",
		       info->out_info->num, info->out_info->total_len);
	}

	mutex_lock(&pkt_mutex[tid]);
	kfree(info->in_info);
	kfree(info->out_info);
	kfree(info);
	kthread_table[tid] = NULL;
	mutex_unlock(&pkt_mutex[tid]);

	return 0;
}

int hns3_cae_create_new_thread(int tid,
			       struct hns3_nic_priv *net_priv,
			       struct hns3_cae_pkt_cfg_info *in_info,
			       struct hns3_cae_pkt_result_info *out_info)
{
	char name[] = "hns3_cae_pkt00";
	int ret;

	if (kthread_table[tid]) {
		pr_err("%s,%d:the thread[%d] is busy!\n", __func__, __LINE__,
		       tid);
		return -EINVAL;
	}

	kthread_table[tid] = kzalloc(sizeof(*kthread_table[0]), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(kthread_table[tid])) {
		pr_err("%s,%d:thread[%d] mem alloc failed\n", __func__,
		       __LINE__, tid);
		return -ENOMEM;
	}

	kthread_table[tid]->tid = tid;
	kthread_table[tid]->net_priv = net_priv;
	kthread_table[tid]->in_info = kzalloc(sizeof(*in_info), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(kthread_table[tid]->in_info)) {
		pr_err("%s,%d:thread[%d] in info alloc failed\n", __func__,
		       __LINE__, tid);
		ret = -ENOMEM;
		goto err_in_info_alloc;
	}

	kthread_table[tid]->out_info = kzalloc(sizeof(*out_info), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(kthread_table[tid]->out_info)) {
		pr_err("%s,%d:thread[%d] out info alloc failed\n", __func__,
		       __LINE__, tid);
		ret = -ENOMEM;
		goto err_out_info_alloc;
	}

	memcpy(kthread_table[tid]->in_info, in_info, sizeof(*in_info));

	name[13] = tid / 10 + '0';
	name[14] = tid % 10 + '0';
	kthread_table[tid]->task =
	    kthread_run(__hns3_cae_new_task, kthread_table[tid], "%s", name);
	if (IS_ERR(kthread_table[tid]->task)) {
		pr_err("%s,%d:thread[%d] alloc failed\n", __func__, __LINE__,
		       tid);
		ret = -EAGAIN;
		goto err_kthread_alloc;
	}

	return 0;

err_kthread_alloc:
	kfree(kthread_table[tid]->out_info);

err_out_info_alloc:
	kfree(kthread_table[tid]->in_info);

err_in_info_alloc:
	kfree(kthread_table[tid]);
	kthread_table[tid] = NULL;

	return ret;
}

void hns3_cae_stop_new_thread(int tid)
{
	mutex_lock(&pkt_mutex[tid]);
	if (kthread_table[tid])
		kthread_table[tid]->stop = 1;
	mutex_unlock(&pkt_mutex[tid]);
}

int hns3_cae_send_pkt(struct hns3_nic_priv *net_priv,
		      void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
	struct hns3_cae_pkt_result_info *out_info;
	struct hns3_cae_pkt_cfg_info *in_info;
	struct hnae3_handle *handle;
	int queue_id;
	int tid;

	in_info = (struct hns3_cae_pkt_cfg_info *)buf_in;
	out_info = (struct hns3_cae_pkt_result_info *)buf_out;

	if (!in_info || in_size < sizeof(struct hns3_cae_pkt_cfg_info) ||
	    !out_info || out_size < sizeof(struct hns3_cae_pkt_result_info)) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	handle = net_priv->ae_handle;
	queue_id = in_info->queue_id;
	if (queue_id > handle->kinfo.num_tqps) {
		pr_err("%s,%d:queue(%d) is invalid\n", __func__, __LINE__,
		       in_info->queue_id);
		return -EINVAL;
	}

	memset(out_info, 0, sizeof(*out_info));
	tid = __get_tid(in_info->queue_id, 1);
	if (in_info->stop_thread) {
		hns3_cae_stop_new_thread(tid);
		return 0;
	}

	if (in_info->new_thread)
		return hns3_cae_create_new_thread(tid, net_priv, in_info,
						  out_info);

	return __hns3_cae_send_pkt(net_priv, in_info, out_info);
}
