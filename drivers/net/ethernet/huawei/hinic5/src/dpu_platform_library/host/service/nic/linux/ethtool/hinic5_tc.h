/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_tc.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_TC_H
#define HINIC5_TC_H

#include <linux/rhashtable.h>

#include "ossl_knl.h"
#include "hinic5_nic_dev.h"
#include "nic_mpu_tc_cmd_defs.h"
#include "nic_tc_rule_defs.h"

#ifdef static
#undef static
#define LLT_STATIC_DEF_SAVED
#endif

enum hinic5_tc_key_flag {
	HINIC5_TC_KEY_ETH_TYPE = 0,
	HINIC5_TC_KEY_VNI,
	HINIC5_TC_KEY_VLAN_TAG,
	HINIC5_TC_KEY_CVLAN,
	HINIC5_TC_KEY_SRC_MAC,
	HINIC5_TC_KEY_DST_MAC,
	HINIC5_TC_KEY_IPV4,
	HINIC5_TC_KEY_IPV6,
	HINIC5_TC_KEY_ENC_IP,
	HINIC5_TC_KEY_PORTS,
	HINIC5_TC_KEY_PROTOCOL,
	HINIC5_TC_KEY_TYPE_MAX
};

enum hinic5_tc_field_type {
	HINIC5_TC_FIELD_ETH_TYPE,
	HINIC5_TC_FIELD_VNI,
	HINIC5_TC_FIELD_VLAN_TAG,
	HINIC5_TC_FIELD_CVLAN_TAG,
	HINIC5_TC_FIELD_SRC_MAC,
	HINIC5_TC_FIELD_DST_MAC,
	HINIC5_TC_FIELD_SRC_IP,
	HINIC5_TC_FIELD_DST_IP,
	HINIC5_TC_FIELD_SRC_IPV6,
	HINIC5_TC_FIELD_DST_IPV6,
	HINIC5_TC_FIELD_ENC_DST_IP,
	HINIC5_TC_FIELD_ENC_DST_IPV6,
	HINIC5_TC_FIELD_SRC_PORT,
	HINIC5_TC_FIELD_DST_PORT,
	HINIC5_TC_FIELD_PROTOCOL,
	HINIC5_TC_FIELD_TYPE_MAX
};

struct hinic5_tc_l2_key {
	u8		dmac[ETH_ALEN];
	u8		smac[ETH_ALEN];
	__be16		vlan_tag;
	__be16		cvlan_tag;
	__be16		ether_type;
	u32 vni;
};

struct hinic5_tc_l3_key {
	union {
		struct {
			struct in_addr daddr;
			struct in_addr saddr;
		} ipv4;
		struct {
			struct in6_addr daddr;
			struct in6_addr saddr;
		} ipv6;
	};
	union {
		struct {
			struct in_addr daddr;
			struct in_addr saddr;
		} enc_ipv4;
		struct {
			struct in6_addr daddr;
			struct in6_addr saddr;
		} enc_ipv6;
	};
};

struct hinic5_tc_l4_key {
	u8  ip_proto;
	struct {
		__be16 sport;
		__be16 dport;
	} ports;
};

struct hinic5_tc_flow {
	u16 key_flags;
	struct hinic5_tc_l2_key		l2_key;
	struct hinic5_tc_l2_key		l2_mask;
	struct hinic5_tc_l3_key		l3_key;
	struct hinic5_tc_l3_key		l3_mask;
	struct hinic5_tc_l4_key		l4_key;
	struct hinic5_tc_l4_key		l4_mask;
	struct hinic5_tc_action_info    actions;
};

#define SHIFT_8BITS 8
#define SHIFT_16BITS 16
#define SHIFT_24BITS 24

#define FIELD_BYTE_0 0
#define FIELD_BYTE_1 1
#define FIELD_BYTE_2 2
#define FIELD_BYTE_3 3
#define FIELD_BYTE_4 4
#define FIELD_BYTE_5 5
#define FIELD_BYTE_6 6
#define FIELD_BYTE_7 7
#define FIELD_BYTE_8 8
#define FIELD_BYTE_9 9
#define FIELD_BYTE_10 10
#define FIELD_BYTE_11 11
#define FIELD_BYTE_12 12
#define FIELD_BYTE_13 13
#define FIELD_BYTE_14 14
#define FIELD_BYTE_15 15

#define FIELD_U16(data, hi, lo) \
	(((data)[hi] << SHIFT_8BITS) | (data)[lo])

#define WRITE_MAC(rule_st, field, data) do {		\
	(rule_st)->field##_0 = (data)[FIELD_BYTE_0];	\
	(rule_st)->field##_1 = (data)[FIELD_BYTE_1];	\
	(rule_st)->field##_2 = (data)[FIELD_BYTE_2];	\
	(rule_st)->field##_3 = (data)[FIELD_BYTE_3];	\
	(rule_st)->field##_4 = (data)[FIELD_BYTE_4];	\
	(rule_st)->field##_5 = (data)[FIELD_BYTE_5];	\
} while (0)

#define WRITE_VNI(rule_st, data) do {						\
	(rule_st)->vni_h = FIELD_U16(data, FIELD_BYTE_2, FIELD_BYTE_1);		\
	(rule_st)->vni_l = (data)[FIELD_BYTE_0];				\
} while (0)

#define WRITE_FIELD_U8(rule_st, field, data)	\
	((rule_st)->field = (data)[FIELD_BYTE_0])

#define WRITE_FIELD_U16(rule_st, field, data) \
	((rule_st)->field = FIELD_U16(data, FIELD_BYTE_0, FIELD_BYTE_1))

#define WRITE_FIELD_SPLIT_U16(rule_st, field, data) do {	\
	(rule_st)->field##_l = (data)[FIELD_BYTE_1];			\
	(rule_st)->field##_h = (data)[FIELD_BYTE_0];			\
} while (0)

#define WRITE_IP4(rule_st, field, data) do {		\
	(rule_st)->field##_0 = (data)[FIELD_BYTE_0];	\
	(rule_st)->field##_1 = (data)[FIELD_BYTE_1];	\
	(rule_st)->field##_2 = (data)[FIELD_BYTE_2];	\
	(rule_st)->field##_3 = (data)[FIELD_BYTE_3];	\
} while (0)

#define WRITE_IP6_128BITS(rule_st, field, data) do {				\
	(rule_st)->field##_0 = FIELD_U16(data, FIELD_BYTE_0, FIELD_BYTE_1);	\
	(rule_st)->field##_1 = FIELD_U16(data, FIELD_BYTE_2, FIELD_BYTE_3);	\
	(rule_st)->field##_2 = FIELD_U16(data, FIELD_BYTE_4, FIELD_BYTE_5);	\
	(rule_st)->field##_3 = FIELD_U16(data, FIELD_BYTE_6, FIELD_BYTE_7);	\
	(rule_st)->field##_4 = FIELD_U16(data, FIELD_BYTE_8, FIELD_BYTE_9);	\
	(rule_st)->field##_5 = FIELD_U16(data, FIELD_BYTE_10, FIELD_BYTE_11);	\
	(rule_st)->field##_6 = FIELD_U16(data, FIELD_BYTE_12, FIELD_BYTE_13);	\
	(rule_st)->field##_7 = FIELD_U16(data, FIELD_BYTE_14, FIELD_BYTE_15);	\
} while (0)

#define WRITE_IP6_96BITS(rule_st, field, data) do {				\
	(rule_st)->field##_0 = FIELD_U16(data, FIELD_BYTE_0, FIELD_BYTE_1);	\
	(rule_st)->field##_1 = FIELD_U16(data, FIELD_BYTE_2, FIELD_BYTE_3);	\
	(rule_st)->field##_2 = FIELD_U16(data, FIELD_BYTE_4, FIELD_BYTE_5);	\
	(rule_st)->field##_3 = FIELD_U16(data, FIELD_BYTE_6, FIELD_BYTE_7);	\
	(rule_st)->field##_4 = FIELD_U16(data, FIELD_BYTE_8, FIELD_BYTE_9);	\
	(rule_st)->field##_5 = FIELD_U16(data, FIELD_BYTE_10, FIELD_BYTE_11);	\
} while (0)

#define WRITE_IP6_128BITS_OPT_OFF(rule_st, field, data) do {			\
	(rule_st)->field##_0 = FIELD_U16(data, FIELD_BYTE_0, FIELD_BYTE_1);	\
	(rule_st)->field##_1_h = (data)[FIELD_BYTE_2];				\
	(rule_st)->field##_1_l = (data)[FIELD_BYTE_3];				\
	(rule_st)->field##_2 = FIELD_U16(data, FIELD_BYTE_4, FIELD_BYTE_5);	\
	(rule_st)->field##_3_h = (data)[FIELD_BYTE_6];				\
	(rule_st)->field##_3_l = (data)[FIELD_BYTE_7];				\
	(rule_st)->field##_4 = FIELD_U16(data, FIELD_BYTE_8, FIELD_BYTE_9);	\
	(rule_st)->field##_5_h = (data)[FIELD_BYTE_10];				\
	(rule_st)->field##_5_l = (data)[FIELD_BYTE_11];				\
	(rule_st)->field##_6 = FIELD_U16(data, FIELD_BYTE_12, FIELD_BYTE_13);	\
	(rule_st)->field##_7_h = (data)[FIELD_BYTE_14];				\
	(rule_st)->field##_7_l = (data)[FIELD_BYTE_15];				\
} while (0)

#define WRITE_SIP6_72BITS_OPT_ON(rule_st, data) do {				\
	(rule_st)->sip6_0_h = (data)[FIELD_BYTE_0];				\
	(rule_st)->sip6_0_l = (data)[FIELD_BYTE_1];				\
	(rule_st)->sip6_1 = FIELD_U16(data, FIELD_BYTE_2, FIELD_BYTE_3);	\
	(rule_st)->sip6_2_h = (data)[FIELD_BYTE_4];				\
	(rule_st)->sip6_2_l = (data)[FIELD_BYTE_5];				\
	(rule_st)->sip6_3 = FIELD_U16(data, FIELD_BYTE_6, FIELD_BYTE_7);	\
	(rule_st)->sip6_4_h = (data)[FIELD_BYTE_8];				\
} while (0)

#define WRITE_DIP6_72BITS_OPT_ON(rule_st, data) do {				\
	(rule_st)->dip6_0 = FIELD_U16(data, FIELD_BYTE_0, FIELD_BYTE_1);	\
	(rule_st)->dip6_1 = FIELD_U16(data, FIELD_BYTE_2, FIELD_BYTE_3);	\
	(rule_st)->dip6_2 = FIELD_U16(data, FIELD_BYTE_4, FIELD_BYTE_5);	\
	(rule_st)->dip6_3 = FIELD_U16(data, FIELD_BYTE_6, FIELD_BYTE_7);	\
	(rule_st)->dip6_4_h = (data)[FIELD_BYTE_8];				\
} while (0)

#define BYTE8_SIZE 8
#define IP6_ADDR_TRUNC_72BITS 72
#define IP6_ADDR_TRUNC_96BITS 96
#define IP6_ADDR_128BITS 128

struct hinic5_tc_ip6_trunc {
	u8 sip6[IP6_ADDR_TRUNC_96BITS / BYTE8_SIZE];
	u8 dip6[IP6_ADDR_TRUNC_72BITS / BYTE8_SIZE];
};

struct hinic5_tc_flow_node {
	unsigned long cookie; /* hash key: provided by TC */
	struct hinic5_tc_flow flow; /* hash value: saved flow */
	u16 rule_id; /* index of pfe key: assigned in firmware */

	struct rhash_head node;
};

#define HINIC5_TC_TCAM_BITMAP_LEN 64

/* PFE tc info */
struct hinic5_tc_info {
	u16 profile_id;
	/* PFE group key template 3-1 used: 1'b0: use template 3-1-1, 1'b1: use template 3-1-2 */
	u16 tunnel_opt;
	/* PFE group key template 3-2 IPV6 sip truncation offset value N,
	 * truncate [N+len:N], maximum value is 32
	 */
	u16 ipv6_shift_value;
	/* PFE group key template 3-1 IPV6 sip and dip truncation offset value N,
	 * truncate [N+len:N], maximum value is 56
	 */
	u16 ipv6_shift_value2;
	u16 enc_ip_type; /* Tunnel packet outer IP type: 0-ipv4, 1-ipv6 */
	ulong tcam_bitmap[HINIC5_TC_TCAM_BITMAP_LEN];
	struct rhashtable flow_table;
	struct rhashtable_params flow_ht_params;
	struct mutex tc_lock; /* Mutex to protect this structure from concurrent access */
};

int hinic5_setup_tc(struct net_device *netdev, enum tc_setup_type type, void *type_data);
int hinic5_init_tc(struct hinic5_nic_dev *nic_dev);
void hinic5_deinit_tc(struct hinic5_nic_dev *nic_dev);
int hinic5_tc_set_profile_id(struct hinic5_nic_dev *nic_dev, u16 profile_id);

#endif
