/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_PKT_H__
#define __HNS3_CAE_PKT_H__

enum PKT_TYPE {
	NICTOOL_PKT_TYPE_ARP = 0,
	NICTOOL_PKT_TYPE_TCP,
	NICTOOL_PKT_TYPE_TCP_DSCP,
	NICTOOL_PKT_TYPE_PAUSE,
	NICTOOL_PKT_TYPE_PAUSE_ERR,
	NICTOOL_PKT_TYPE_PFC,
	NICTOOL_PKT_TYPE_PFC_ERR,
	NICTOOL_PKT_TYPE_IPV4,
	NICTOOL_PKT_TYPE_IPV4_LOOSESRCROUTE_OPTION,
	NICTOOL_PKT_TYPE_IPV4_TRACEROUTE_OPTION,
	NICTOOL_PKT_TYPE_IPV6,
	NICTOOL_PKT_TYPE_IPV6_EXTENSION_ROUTING,
	NICTOOL_PKT_TYPE_SCTP4,
	NICTOOL_PKT_TYPE_SCTP6,
	NICTOOL_PKT_TYPE_MAX,
};

struct nictool_pkt_cfg_info {
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
	u8 dst_mac[6];
	u8 dst_ip[4];
	int multi_queue;
	int pkt_payload_flag;
	u16 pkt_checksum;
	u32 pkt_checksum_sctp;
	u16 pkt_inet6_addr[10];
};

struct nictool_pkt_result_info {
	int total_len;
	int num;
};

int hns3_test_send_pkt(struct hns3_nic_priv *net_priv, void *buf_in,
		       u32 in_size, void *buf_out, u32 out_size);
void hns3_test_pkt_init(void);
void hns3_test_pkt_destroy(void);

#endif
