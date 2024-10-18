/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#ifndef _NBL_FLOW_LEONIS_H_
#define _NBL_FLOW_LEONIS_H_

#include "nbl_core.h"
#include "nbl_hw.h"
#include "nbl_resource.h"

#define NBL_EM_PHY_KT_OFFSET				(0x1F000)

#define NBL_TOTAL_MACVLAN_NUM				2048
#define NBL_MAX_ACTION_NUM				16

#define NBL_SPORT_ETH_OFFSET				8
#define NBL_MCC_NUM_PER_SWITCH                          256

#define NBL_FLOW_MCC_INDEX_SIZE				1024
#define NBL_FLOW_MCC_INDEX_START			(7 * 1024)

#define NBL_MACVLAN_TBL_BUCKET_SIZE			64
#define NBL_MACVLAN_X_AXIS_BUCKET_SIZE			64
#define NBL_MACVLAN_Y_AXIS_BUCKET_SIZE			16

enum nbl_flow_mcc_index_type {
	NBL_MCC_INDEX_ETH,
	NBL_MCC_INDEX_VSI,
	NBL_MCC_INDEX_BOND,
};

struct nbl_flow_mcc_index_key {
	enum nbl_flow_mcc_index_type type;
	union {
		u8 eth_id;
		u16 vsi_id;
		u32 data;
	};
};

#define NBL_FLOW_MCC_INDEX_KEY_INIT(key, key_type_arg, value_arg)				\
do {												\
	typeof(key)	__key   = key;								\
	typeof(key_type_arg)	__type = key_type_arg;						\
	typeof(value_arg) __value = value_arg;							\
	__key->type		= __type;							\
	if (__type == NBL_MCC_INDEX_ETH)							\
		__key->eth_id	= __value;							\
	else if (__type == NBL_MCC_INDEX_VSI || __type == NBL_MCC_INDEX_BOND)			\
		__key->vsi_id	= __value;							\
} while (0)

#pragma pack(1)

#define NBL_DUPPKT_PTYPE_NA				135
#define NBL_DUPPKT_PTYPE_NS				136

struct nbl_flow_macvlan_node_data {
	struct nbl_flow_fem_entry entry[NBL_FLOW_MACVLAN_MAX];
	u16 vsi;
};

union nbl_l2_phy_up_data_u {
	struct nbl_l2_phy_up_data {
		u32 act0:22;
		u64 rsv1:62;
		u32 padding:4;
		u32 sport:4;
		u32 svlan_id:16;
		u64 dst_mac:48;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L2_PHY_UP_DATA_TAB_WIDTH (sizeof(struct nbl_l2_phy_up_data) \
		/ sizeof(u32))
	u32 data[NBL_L2_PHY_UP_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l2_phy_up_data)];
};

union nbl_l2_phy_lldp_lacp_data_u {
	struct nbl_l2_phy_lldp_lacp_data {
		u32 act0:22;
		u32 rsv1:2;
		u8 padding[14];
		u32 sport:4;
		u32 ether_type:16;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L2_PHY_LLDP_LACP_DATA_TAB_WIDTH (sizeof(struct nbl_l2_phy_lldp_lacp_data) \
		/ sizeof(u32))
	u32 data[NBL_L2_PHY_LLDP_LACP_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l2_phy_lldp_lacp_data)];
};

union nbl_l2_phy_down_data_u {
	struct nbl_l2_phy_down_data {
		u32 act0:22;
		u32 rsv2:10;
		u64 rsv1:52;
		u32 padding:6;
		u32 sport:2;
		u32 svlan_id:16;
		u64 dst_mac:48;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L2_PHY_DOWN_DATA_TAB_WIDTH (sizeof(struct nbl_l2_phy_down_data) \
		/ sizeof(u32))
	u32 data[NBL_L2_PHY_DOWN_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l2_phy_down_data)];
};

union nbl_l2_phy_up_multi_data_u {
	struct nbl_l2_phy_up_multi_data {
		u32 act0:22;
		u32 act1:22;
		u32 rsv2:20;
		u64 rsv1:36;
		u32 padding:4;
		u32 sport:4;
		u64 dst_mac:48;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L2_PHY_UP_MULTI_DATA_TAB_WIDTH (sizeof(struct nbl_l2_phy_up_multi_data) \
		/ sizeof(u32))
	u32 data[NBL_L2_PHY_UP_MULTI_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l2_phy_up_multi_data)];
};

union nbl_l2_phy_down_multi_data_u {
	struct nbl_l2_phy_down_multi_data {
		u32 act0:22;
		u32 act1:22;
		u32 rsv2:20;
		u64 rsv1:36;
		u32 padding:6;
		u32 sport:2;
		u64 dst_mac:48;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L2_PHY_DOWN_MULTI_DATA_TAB_WIDTH (sizeof(struct nbl_l2_phy_down_multi_data) \
		/ sizeof(u32))
	u32 data[NBL_L2_PHY_DOWN_MULTI_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l2_phy_down_multi_data)];
};

union nbl_l3_phy_up_multi_data_u {
	struct nbl_l3_phy_up_multi_data {
		u32 act0:22;
		u32 act1:22;
		u32 rsv2:20;
		u64 rsv1:60;
		u32 padding:12;
		u32 sport:4;
		u64 dst_mac:16;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L3_PHY_UP_MULTI_DATA_TAB_WIDTH (sizeof(struct nbl_l3_phy_up_multi_data) \
		/ sizeof(u32))
	u32 data[NBL_L3_PHY_UP_MULTI_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l3_phy_up_multi_data)];
};

union nbl_l3_phy_down_multi_data_u {
	struct nbl_l3_phy_down_multi_data {
		u32 act0:22;
		u32 act1:22;
		u32 rsv3:20;
		u64 rsv2;
		u64 rsv1:4;
		u32 padding:6;
		u32 sport:2;
		u64 dst_mac:16;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L3_PHY_DOWN_MULTI_DATA_TAB_WIDTH (sizeof(struct nbl_l3_phy_down_multi_data) \
		/ sizeof(u32))
	u32 data[NBL_L3_PHY_DOWN_MULTI_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l3_phy_down_multi_data)];
};

union nbl_common_data_u {
	struct nbl_common_data {
		u32 rsv[10];
	} __packed info;
#define NBL_COMMON_DATA_TAB_WIDTH (sizeof(struct nbl_common_data) \
		/ sizeof(u32))
	u32 data[NBL_COMMON_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_common_data)];
};

#pragma pack()

struct nbl_flow_param {
	u8 *mac;
	u8 type;
	u8 eth;
	u16 ether_type;
	u16 vid;
	u16 vsi;
	u16 mcc_id;
	u32 index;
	u32 *data;
	u32 priv_data;
	bool for_pmd;
};

struct nbl_mt_input {
	u8 key[NBL_KT_BYTE_LEN];
	u8 at_num;
	u8 kt_left_num;
	u32 tbl_id;
	u16 depth;
	u16 power;
};

struct nbl_ht_item {
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_bucket;
	u32 key_index;
	u8 ht_table;
};

struct nbl_kt_item {
	union nbl_common_data_u kt_data;
};

struct nbl_tcam_item {
	struct nbl_ht_item ht_item;
	struct nbl_kt_item kt_item;
	u32 tcam_action[NBL_MAX_ACTION_NUM];
	bool tcam_flag;
	u8 key_mode;
	u8 pp_type;
	u32 *pp_tcam_count;
	u16 tcam_index;
};

struct nbl_tcam_ad_item {
	u32 action[NBL_MAX_ACTION_NUM];
};

struct nbl_flow_rule_cfg_ops {
	int (*cfg_action)(struct nbl_flow_param param, u32 *action0, u32 *action1);
	int (*cfg_key)(union nbl_common_data_u *data,
		       struct nbl_flow_param param, u8 eth_mode);
	void (*cfg_kt_action)(union nbl_common_data_u *data, u32 action0, u32 action1);
};

#endif
