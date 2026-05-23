/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_tc_rule_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef NIC_TC_RULE_DEFS_H
#define NIC_TC_RULE_DEFS_H

#if defined(__LINUX__) || defined(VMWARE)
#include <linux/types.h>
#endif

enum hinic5_tc_rule_profile_id_e {
	/* vlan, tunnel */
	HINIC5_TC_PROFILE_TUN_ETH = 0,       /* eth */
	HINIC5_TC_PROFILE_TUN_ETH_VLAN = 1,       /* eth/vlan */
	HINIC5_TC_PROFILE_TUN_ETH_QINQ = 2,       /* eth/svlan/cvlan */

	/* vlan, non-tunnel */
	HINIC5_TC_PROFILE_ETH = 3,       /* eth */
	HINIC5_TC_PROFILE_ETH_VLAN = 4,       /* eth/vlan */
	HINIC5_TC_PROFILE_ETH_QINQ = 5,       /* eth/svlan/cvlan */

	/* ipv4, tunnel */
	HINIC5_TC_PROFILE_TUN_ETH_IP4 = 6,       /* eth/ipv4 */
	HINIC5_TC_PROFILE_TUN_ETH_IP4_TCPORUDP = 7,       /* eth/ipv4/udp_or_tcp */

	/* ipv4, non-tunnel */
	HINIC5_TC_PROFILE_ETH_IP4 = 8,       /* eth/ipv4 */
	HINIC5_TC_PROFILE_ETH_IP4_TCPORUDP = 9,       /* eth/ipv4/udp_or_tcp */

	/* ipv6, tunnel */
	HINIC5_TC_PROFILE_TUN_ETH_IP6 = 10,       /* eth/ipv6 */
	HINIC5_TC_PROFILE_TUN_ETH_IP6_TCPORUDP = 11,       /* eth/ipv6/udp_or_tcp */

	/* ipv6, non-tunnel */
	HINIC5_TC_PROFILE_ETH_IP6 = 12,       /* eth/ipv6 */
	HINIC5_TC_PROFILE_ETH_IP6_TCPORUDP = 13,       /* eth/ipv6/udp_or_tcp */

	/* Tunnel packets that fail vtep dip check */
	HINIC5_TC_PROFILE_OUTER_IP_INNER_IP = 14,        /* eth/ipv4(6)/udp/vxlan/eth/ipv4 */
	HINIC5_TC_PROFILE_OUTER_IP_INNER_IP_TCPORUDP = 15,     /* eth/ipv4(6)/udp/vxlan/eth/ipv4/udp_or_tcp */

	HINIC5_TC_PROFILE_MAX = 16
};

#define HINIC5_TC_PROFILE_ADM_MAX 14

struct hinic5_tc_rule_tun_eth {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 smac_2 : 8;
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 vni_l : 8;

	u32 dmac_0 : 8;
	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;

	u32 dmac_4 : 8;
	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;

	u32 rsvd : 8;
	u32 ether_type : 16;
	u32 dmac_5 : 8;
};

struct hinic5_tc_rule_tun_eth_vlan {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 smac_2 : 8;
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 vni_l : 8;

	u32 dmac_0 : 8;
	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;

	u32 dmac_4 : 8;
	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;

	u32 vlan_tag_h : 8;
	u32 ether_type : 16;
	u32 dmac_5 : 8;

	u32 rsvd : 24;
	u32 vlan_tag_l : 8;
};

struct hinic5_tc_rule_tun_eth_qinq {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 smac_2 : 8;
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 vni_l : 8;

	u32 dmac_0 : 8;
	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;

	u32 dmac_4 : 8;
	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;

	u32 vlan_tag_h : 8;
	u32 ether_type : 16;
	u32 dmac_5 : 8;

	u32 rsvd : 8;
	u32 cvlan_tag : 16;
	u32 vlan_tag_l : 8;
};

struct hinic5_tc_rule_eth {
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 padding : 16;

	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;
	u32 smac_2 : 8;

	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;

	u32 ether_type : 16;
	u32 dmac_5 : 8;
	u32 dmac_4 : 8;
};

struct hinic5_tc_rule_eth_vlan {
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 padding : 16;

	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;
	u32 smac_2 : 8;

	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;

	u32 ether_type : 16;
	u32 dmac_5 : 8;
	u32 dmac_4 : 8;

	u32 rsvd : 16;
	u32 vlan_tag : 16;
};

struct hinic5_tc_rule_eth_qinq {
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 padding : 16;

	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;
	u32 smac_2 : 8;

	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;

	u32 ether_type : 16;
	u32 dmac_5 : 8;
	u32 dmac_4 : 8;

	u32 cvlan_tag : 16;
	u32 vlan_tag : 16;
};

struct hinic5_tc_rule_tun_eth_ip4 {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 dmac_2 : 8;
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;
	u32 vni_l : 8;

	u32 ether_type_h : 8;
	u32 dmac_5 : 8;
	u32 dmac_4 : 8;
	u32 dmac_3 : 8;

	u32 sip_2 : 8;
	u32 sip_1 : 8;
	u32 sip_0 : 8;
	u32 ether_type_l : 8;

	u32 dip_2 : 8;
	u32 dip_1 : 8;
	u32 dip_0 : 8;
	u32 sip_3 : 8;

	u32 rsvd : 16;
	u32 proto : 8;
	u32 dip_3 : 8;
};

struct hinic5_tc_rule_tun_eth_ip4_tcporudp {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 dmac_2 : 8;
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;
	u32 vni_l : 8;

	u32 ether_type_h : 8;
	u32 dmac_5 : 8;
	u32 dmac_4 : 8;
	u32 dmac_3 : 8;

	u32 sip_2 : 8;
	u32 sip_1 : 8;
	u32 sip_0 : 8;
	u32 ether_type_l : 8;

	u32 dip_2 : 8;
	u32 dip_1 : 8;
	u32 dip_0 : 8;
	u32 sip_3 : 8;

	u32 sport : 16;
	u32 proto : 8;
	u32 dip_3 : 8;

	u32 rsvd : 16;
	u32 dport : 16;
};

struct hinic5_tc_rule_eth_ip4 {
	u32 vlan_tag : 16;
	u32 padding : 16;

	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;

	u32 sip_1 : 8;
	u32 sip_0 : 8;
	u32 dmac_5 : 8;
	u32 dmac_4 : 8;

	u32 dip_1 : 8;
	u32 dip_0 : 8;
	u32 sip_3 : 8;
	u32 sip_2 : 8;

	u32 rsvd : 8;
	u32 proto : 8;
	u32 dip_3 : 8;
	u32 dip_2 : 8;
};

struct hinic5_tc_rule_eth_ip4_tcporudp {
	u32 vlan_tag : 16;
	u32 padding : 16;

	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;

	u32 sip_1 : 8;
	u32 sip_0 : 8;
	u32 dmac_5 : 8;
	u32 dmac_4 : 8;

	u32 dip_1 : 8;
	u32 dip_0 : 8;
	u32 sip_3 : 8;
	u32 sip_2 : 8;

	u32 sport_h : 8;
	u32 proto : 8;
	u32 dip_3 : 8;
	u32 dip_2 : 8;

	u32 rsvd : 8;
	u32 dport : 16;
	u32 sport_l : 8;
};

struct hinic5_tc_rule_tun_eth_ip6_off {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 sip6_1_h : 8;
	u32 sip6_0 : 16;
	u32 vni_l : 8;

	u32 sip6_3_h : 8;
	u32 sip6_2 : 16;
	u32 sip6_1_l : 8;

	u32 sip6_5_h : 8;
	u32 sip6_4 : 16;
	u32 sip6_3_l : 8;

	u32 sip6_7_h : 8;
	u32 sip6_6 : 16;
	u32 sip6_5_l : 8;

	u32 dip6_1_h : 8;
	u32 dip6_0 : 16;
	u32 sip6_7_l : 8;

	u32 dip6_3_h : 8;
	u32 dip6_2 : 16;
	u32 dip6_1_l : 8;

	u32 dip6_5_h : 8;
	u32 dip6_4 : 16;
	u32 dip6_3_l : 8;

	u32 dip6_7_h : 8;
	u32 dip6_6 : 16;
	u32 dip6_5_l : 8;

	u32 rsvd : 16;
	u32 proto : 8;
	u32 dip6_7_l : 8;
};

struct hinic5_tc_rule_tun_eth_ip6_tcporudp_off {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 sip6_1_h : 8;
	u32 sip6_0 : 16;
	u32 vni_l : 8;

	u32 sip6_3_h : 8;
	u32 sip6_2 : 16;
	u32 sip6_1_l : 8;

	u32 sip6_5_h : 8;
	u32 sip6_4 : 16;
	u32 sip6_3_l : 8;

	u32 sip6_7_h : 8;
	u32 sip6_6 : 16;
	u32 sip6_5_l : 8;

	u32 dip6_1_h : 8;
	u32 dip6_0 : 16;
	u32 sip6_7_l : 8;

	u32 dip6_3_h : 8;
	u32 dip6_2 : 16;
	u32 dip6_1_l : 8;

	u32 dip6_5_h : 8;
	u32 dip6_4 : 16;
	u32 dip6_3_l : 8;

	u32 dip6_7_h : 8;
	u32 dip6_6 : 16;
	u32 dip6_5_l : 8;

	u32 sport : 16;
	u32 proto : 8;
	u32 dip6_7_l : 8;

	u32 rsvd : 16;
	u32 dport : 16;
};

struct hinic5_tc_rule_tun_eth_ip6_on {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 smac_2 : 8;
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 vni_l : 8;

	u32 dmac_0 : 8;
	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;

	u32 dmac_4 : 8;
	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;

	u32 sip6_0_h : 8;
	u32 ether_type : 16;
	u32 dmac_5 : 8;

	u32 sip6_2_h : 8;
	u32 sip6_1 : 16;
	u32 sip6_0_l : 8;

	u32 sip6_4_h : 8;
	u32 sip6_3 : 16;
	u32 sip6_2_l : 8;

	u32 dip6_1 : 16;
	u32 dip6_0 : 16;

	u32 dip6_3 : 16;
	u32 dip6_2 : 16;

	u32 rsvd : 16;
	u32 proto : 8;
	u32 dip6_4_h : 8;
};

struct hinic5_tc_rule_tun_eth_ip6_tcporudp_on {
	u32 vni_h : 16;
	u32 padding : 16;

	u32 smac_2 : 8;
	u32 smac_1 : 8;
	u32 smac_0 : 8;
	u32 vni_l : 8;

	u32 dmac_0 : 8;
	u32 smac_5 : 8;
	u32 smac_4 : 8;
	u32 smac_3 : 8;

	u32 dmac_4 : 8;
	u32 dmac_3 : 8;
	u32 dmac_2 : 8;
	u32 dmac_1 : 8;

	u32 sip6_0_h : 8;
	u32 ether_type : 16;
	u32 dmac_5 : 8;

	u32 sip6_2_h : 8;
	u32 sip6_1 : 16;
	u32 sip6_0_l : 8;

	u32 sip6_4_h : 8;
	u32 sip6_3 : 16;
	u32 sip6_2_l : 8;

	u32 dip6_1 : 16;
	u32 dip6_0 : 16;

	u32 dip6_3 : 16;
	u32 dip6_2 : 16;

	u32 sport : 16;
	u32 proto : 8;
	u32 dip6_4_h : 8;

	u32 rsvd : 16;
	u32 dport : 16;
};

struct hinic5_tc_rule_eth_ip6 {
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;
	u32 padding : 16;

	u32 dmac_5 : 8;
	u32 dmac_4 : 8;
	u32 dmac_3 : 8;
	u32 dmac_2 : 8;

	u32 sip6_1 : 16;
	u32 sip6_0 : 16;

	u32 sip6_3 : 16;
	u32 sip6_2 : 16;

	u32 sip6_5 : 16;
	u32 sip6_4 : 16;

	u32 sip6_7 : 16;
	u32 sip6_6 : 16;

	u32 dip6_1 : 16;
	u32 dip6_0 : 16;

	u32 dip6_3 : 16;
	u32 dip6_2 : 16;

	u32 dip6_5 : 16;
	u32 dip6_4 : 16;

	u32 dip6_7 : 16;
	u32 dip6_6 : 16;

	u32 rsvd : 24;
	u32 proto : 8;
};

struct hinic5_tc_rule_eth_ip6_tcporudp {
	u32 dmac_1 : 8;
	u32 dmac_0 : 8;
	u32 padding : 16;

	u32 dmac_5 : 8;
	u32 dmac_4 : 8;
	u32 dmac_3 : 8;
	u32 dmac_2 : 8;

	u32 sip6_1 : 16;
	u32 sip6_0 : 16;

	u32 sip6_3 : 16;
	u32 sip6_2 : 16;

	u32 sip6_5 : 16;
	u32 sip6_4 : 16;

	u32 dip6_1 : 16;
	u32 dip6_0 : 16;

	u32 dip6_3 : 16;
	u32 dip6_2 : 16;

	u32 dip6_5 : 16;
	u32 dip6_4 : 16;

	u32 dip6_7 : 16;
	u32 dip6_6 : 16;

	u32 dport_h : 8;
	u32 sport : 16;
	u32 proto : 8;

	u32 rsvd : 24;
	u32 dport_l : 8;
};

struct hinic5_tc_rule_outer_ip_inner_ip {
	u32 outer_dip_0 : 16;
	u32 padding : 16;

	u32 outer_dip_2 : 16;
	u32 outer_dip_1 : 16;

	u32 outer_dip_4 : 16;
	u32 outer_dip_3 : 16;

	u32 outer_dip_6 : 16; /* ipv4_0 */
	u32 outer_dip_5 : 16;

	u32 vni_h : 16;
	u32 outer_dip_7 : 16; /* ipv4_1 */

	u32 sip_2 : 8;
	u32 sip_1 : 8;
	u32 sip_0 : 8;
	u32 vni_l : 8;

	u32 dip_2 : 8;
	u32 dip_1 : 8;
	u32 dip_0 : 8;
	u32 sip_3 : 8;

	u32 rsvd : 24;
	u32 dip_3 : 8;
};

struct hinic5_tc_rule_outer_ip_inner_ip_tcporudp {
	u32 outer_dip_0 : 16;
	u32 padding : 16;

	u32 outer_dip_2 : 16;
	u32 outer_dip_1 : 16;

	u32 outer_dip_4 : 16;
	u32 outer_dip_3 : 16;

	u32 outer_dip_6 : 16; /* ipv4_0 */
	u32 outer_dip_5 : 16;

	u32 vni_h : 16;
	u32 outer_dip_7 : 16; /* ipv4_1 */

	u32 sip_2 : 8;
	u32 sip_1 : 8;
	u32 sip_0 : 8;
	u32 vni_l : 8;

	u32 dip_2 : 8;
	u32 dip_1 : 8;
	u32 dip_0 : 8;
	u32 sip_3 : 8;

	u32 dport_h : 8;
	u32 sport : 16;
	u32 dip_3 : 8;

	u32 rsvd : 24;
	u32 dport_l : 8;
};

#endif