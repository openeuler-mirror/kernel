/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_PKT_H__
#define __HNS3_CAE_PKT_H__

#include <linux/types.h>

#define IP_ADDR_LEN	4
#define IP6_ADDR_LEN	10
#define MIN_PKT_LEN	64
#define IPV4_TRACEROUTE_PKT_LEN	66
#define IPV6_EXTENSION_PKT_LEN	114

enum PKT_TYPE {
	HNS3_CAE_PKT_TYPE_ARP = 0,
	HNS3_CAE_PKT_TYPE_TCP,
	HNS3_CAE_PKT_TYPE_TCP_DSCP,
	HNS3_CAE_PKT_TYPE_PAUSE,
	HNS3_CAE_PKT_TYPE_PAUSE_ERR,
	HNS3_CAE_PKT_TYPE_PFC,
	HNS3_CAE_PKT_TYPE_PFC_ERR,
	HNS3_CAE_PKT_TYPE_IPV4,
	HNS3_CAE_PKT_TYPE_IPV4_LOOSESRCROUTE_OPTION,
	HNS3_CAE_PKT_TYPE_IPV4_TRACEROUTE_OPTION,
	HNS3_CAE_PKT_TYPE_IPV6,
	HNS3_CAE_PKT_TYPE_IPV6_EXTENSION_ROUTING,
	HNS3_CAE_PKT_TYPE_SCTP4,
	HNS3_CAE_PKT_TYPE_SCTP6,
	HNS3_CAE_PKT_TYPE_MAX,
};

struct hns3_cae_pkt_cfg_info {
	int queue_id;
	int type;
	int pkt_len;
	int num;
	int mss;
	int new_thread;
	int stop_thread;
	int wait_all_finish;
	u32 vlan_tag;
	u16 pause_time;
	u16 eth_type;
	u16 pause_code;
	u8 priority;
	u8 dscp;
	u8 dst_mac[ETH_ALEN];
	u8 dst_ip[IP_ADDR_LEN];
	int multi_queue;
	int pkt_payload_flag;
	u16 pkt_checksum;
	u32 pkt_checksum_sctp;
	u16 pkt_inet6_addr[IP6_ADDR_LEN];
};

struct hns3_cae_pkt_result_info {
	int total_len;
	int num;
};

int hns3_cae_send_pkt(const struct hns3_nic_priv *net_priv, void *buf_in,
		      u32 in_size, void *buf_out, u32 out_size);
void hns3_cae_pkt_init(void);
void hns3_cae_pkt_destroy(void);

#endif
