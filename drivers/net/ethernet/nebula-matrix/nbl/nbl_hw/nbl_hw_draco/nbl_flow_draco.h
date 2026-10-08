/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#ifndef _NBL_FLOW_DRACO_H_
#define _NBL_FLOW_DRACO_H_

#include "nbl_core.h"
#include "nbl_hw.h"
#include "nbl_resource.h"

#define NBL_KT_NUM_PER_KT_BLOCK		(1024)
#define NBL_KT_BLOCK_ALLOC_NUM		(1)
#define NBL_MAX_MACVLAN_NUM		(NBL_KT_BLOCK_ALLOC_NUM * NBL_KT_NUM_PER_KT_BLOCK)
#define NBL_EM_PHY_KT_OFFSET		(0)
#define NBL_FLOW_MCC_INDEX_START	(0)
/* ensure mcc_index_size greater than NBL_INDEX_HASH_DIVISOR,
 * otherwise when call nbl_common_get_index() kennel will panic
 * bacause devide error:000 .
 */
#define NBL_FLOW_MCC_INDEX_SIZE		(16)
#define NBL_TABLE_KEY_LEN		10
#define NBL_DRACO_FULL_TCAM_NUM		64
#define NBL_DRACO_KT_MAX_BLOCK		128
#define NBL_DRACO_GET_KT_BLOCK_IDX(idx) ((idx) / NBL_KT_NUM_PER_KT_BLOCK)

#define NBL_DRACO_FLOW_MCC_BMC_DPORT	(276)
#define NBL_DRACO_FLOW_MCC_EMP_DPORT	(277)
#define NBL_DRACO_MAX_MCC_NUM			(512)
#define NBL_DRACO_ETH_MAX_MCC_NUM(eth_num)	(NBL_DRACO_MAX_MCC_NUM / (eth_num))
#define NBL_DRACO_ETH_MAX_MCC_NUM_4PF		(NBL_DRACO_MAX_MCC_NUM / NBL_MAX_ETHERNET)
#define NBL_DRACO_ETH_MCC_ID_BASE(eth_id)	(NBL_DRACO_ETH_MAX_MCC_NUM_4PF * (eth_id))

#define NBL_FEM_CMD_ERRCODE_NOT_HIT			(2)

enum nbl_flow_mcc_index_type {
	NBL_MCC_INDEX_MULTICAST,
	NBL_MCC_INDEX_ECMP,
};

struct nbl_flow_mcc_index_key {
	enum nbl_flow_mcc_index_type type;
	u8 eth_id;
	u16 vsi_id;
};

#define NBL_FLOW_MCC_INDEX_KEY_INIT(key, key_type_arg, eth_id_arg, vsi_id_arg)	\
do {										\
	typeof(key)		__key = key;					\
	typeof(key_type_arg)	__type = key_type_arg;				\
	typeof(eth_id_arg)	__eth_id_value = eth_id_arg;			\
	typeof(vsi_id_arg)	__vsi_id_value = vsi_id_arg;			\
	__key->type	= __type;						\
	__key->eth_id	= __eth_id_value;					\
	__key->vsi_id	= __vsi_id_value;					\
} while (0)

struct nbl_flow_l2_data {
	struct nbl_flow_fem_entry entry;
	union {
		struct nbl_flow_mcc_group *mcc_group;
		u16 vsi;
	};
	u8 mac[ETH_ALEN];
	u16 vlan;
	bool multi;
	bool mcast_flow;
};

struct nbl_flow_change_data {
	void *priv;
	u16 vsi;
};

/* EM0 Profile Table */
#define NBL_EM0_PT_PHY_L2_MULTICAST			0
#define NBL_EM0_PT_PHY_L2_UNICAST			1

#define NBL_EM0_PT_PHY_DIPSEC_IPV4			4
#define NBL_EM0_PT_PHY_DIPSEC_IPV6			5
#define NBL_EM0_PT_PHY_UTLS_IPV4			4
#define NBL_EM0_PT_PHY_UTLS_IPV6			5

#define NBL_MACVLAN_TBL_BUCKET_SIZE			64
#define NBL_MACVLAN_X_AXIS_BUCKET_SIZE			64
#define NBL_MACVLAN_Y_AXIS_BUCKET_SIZE			16

#define GET_LKP_ID(is_mc_mac) \
	((is_mc_mac) ? NBL_EM0_PT_PHY_L2_MULTICAST : NBL_EM0_PT_PHY_L2_UNICAST)

enum nbl_draco_tbl_to_write {
	NBL_DRACO_PROFILE_TBL = 0,
	NBL_DRACO_HT_TBL,
	NBL_DRACO_KTAT_TBL,
	NBL_DRACO_OFTAD_TBL,
	NBL_DRACO_DFT_TBL,
};

struct nbl_draco_tbl_ab_ad {
	u8 action_data[8];
	u8 action_bits;
};

struct nbl_flow_param {
	u8 *mac;
	u8 eth_id;
	u16 ether_type;
	u16 vid;
	u16 vsi_id;
	u16 mcc_id;
	u16 sec_idx;
	u32 index;
	u32 *data;
	u32 priv_data;
	bool for_pmd;

	/* NBL_KT_HALF_MODE or NBL_KT_FULL_MODE */
	u8 kt_type;
	u16 pf_id;
	u8 alloc_oft;
	u8 kt_mode;
	u32 kt_idx;
	u8 *key;
	u16 key_len;
	u8 template;
	u8 del_on_hit;
	u8 lkp_mode;
	u8 ht_id;
	u8 ht_slot_id;
	u8 hmc;

	/* KT alloc & free param */
	u32 start_kt_index;
	bool free_all;

	/* Table read */
	u8 tbl_to_read;
	u32 read_addr;

	/* Table write */
	enum nbl_draco_tbl_to_write tbl_to_write;
	u8 dft_addr;
#define NBL_DRACO_DFT_BASEADDR (5)
	u8 pt_addr;
	u8 *tbl;
};

#pragma pack(1)

union nbl_common_data_u {
	struct nbl_common_data {
		u32 rsv[10];
	} __packed info;
#define NBL_COMMON_DATA_TAB_WIDTH (sizeof(struct nbl_common_data) \
		/ sizeof(u32))
	u32 data[NBL_COMMON_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_common_data)];
};

union nbl_phy_l2_data_u {
	struct nbl_phy_l2_data {
		u64 rsv0:48;
		u64 base_ad:16;
		u32 base_ab:8;
		u32 sport_id:11;
		u32 sport_dir:1;
		u32 rsv1:1;
		/* sport's 16 bit, we only set sw_id and phy */
		u32 sport_sw_id:2;
		u32 sport_phy:1;
		u32 svlan_id:16;
		u64 dst_mac:48;
		u32 rsv2:4;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_PHY_L2_DATA_TAB_WIDTH (sizeof(struct nbl_phy_l2_data) \
		/ sizeof(u32))
	u32 data[NBL_PHY_L2_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_phy_l2_data)];
};

union nbl_phy_accel_data_u {
	struct nbl_phy_accel_ipv4 {
		u32 rsv3:16;
		u32 base_ad:16;
		u32 base_ab:8;
		u32 sport_id:11;
		u32 sport_dir:1;
		u32 rsv2:1;
		/* sport's 16 bit, we only set sw_id and phy */
		u32 sport_sw_id:2;
		u32 sport_phy:1;
		u32 l4_dportl:8;
		u32 l4_dporth:8;
		u32 l4_sport:16;
		u32 dip_low:8;
		u32 dip_high:24;
		u32 sip_low:8;
		u32 sip_high:24;
		u32 rsv1:4;
		u32 template:4;
		u32 rsv[5];
	} __packed ipv4_info;
	struct nbl_phy_accel_ipv6 {
		// u64 rsv3:48;
		// u64 base_ad:16;
		u64 base_ab:8;
		u64 sport_id:11;
		u64 sport_dir:1;
		u64 rsv2:1;
		/* sport's 16 bit, we only set sw_id and phy */
		u64 sport_sw_id:2;
		u64 sport_phy:1;
		u64 l4_dport:16;
		u64 l4_sport:16;
		u64 dip3:8;
		u64 dip2;
		u64 dip1:56;
		u64 sip3:8;
		u64 sip2;
		u64 sip1:56;
		u64 rsv1:4;
		u64 template:4;
	} __packed ipv6_info;
	u32 data[NBL_KT_BYTE_LEN / 4];
	u8 hash_key[NBL_KT_BYTE_LEN];
};

#pragma pack()

struct nbl_kt_item {
	union nbl_common_data_u kt_data;
};

struct nbl_flow_rule_cfg_ops {
	int (*cfg_action)(struct nbl_flow_param param, u8 *ab, u16 *ad);
	int (*cfg_key)(union nbl_common_data_u *data,
		       struct nbl_flow_param param, u8 eth_id);
	int (*cfg_kt_action)(union nbl_common_data_u *data, u8 ab, u16 ad);
};

#pragma pack(1)

/* req_head and resp_head for all cmd */
union nbl_fem_cmd_head_u {
	struct nbl_fem_cmd_head {
		u32 cmd_status:2;
		u32 cmd_type:2;
		u32 rsv0:12;
		u32 module:4;
#define NBL_FEM_CMD_HEAD_MODULE_FEM		(1)
#define NBL_FEM_CMD_HEAD_MODULE_ACL		(2)
		u32 table:4;
#define NBL_FEM_CMD_HEAD_TABLE_PT		(0)
#define NBL_FEM_CMD_HEAD_TABLE_HT		(1)
#define NBL_FEM_CMD_HEAD_TABLE_KT_AT		(2)
#define NBL_FEM_CMD_HEAD_TABLE_OFT_AT		(3)
#define NBL_FEM_CMD_HEAD_TABLE_DEFAULT		(4)
#define NBL_FEM_CMD_HEAD_TABLE_KT_BIND_PF	(5)
#define NBL_FEM_CMD_HEAD_TABLE_KT_BLK_MNG	(6)
		u32 opcode:4;
#define NBL_FEM_CMD_HEAD_OPCODE_TBLADD		(0)
#define NBL_FEM_CMD_HEAD_OPCODE_TBLREAD		(1)
#define NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE	(2)
#define NBL_FEM_CMD_HEAD_OPCODE_KTALLOC		(3)
#define NBL_FEM_CMD_HEAD_OPCODE_KTFREE		(4)
#define NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP	(5)
		u32 rsv1:4;
		u32 errcode:8;
		u32 status:2;
#define NBL_FEM_CMD_HEAD_STATUS_SUCCESS		(0)
#define NBL_FEM_CMD_HEAD_STATUS_FAIL		(1)
#define NBL_FEM_CMD_HEAD_STATUS_ERR		(2)
#define NBL_FEM_CMD_HEAD_STATUS_NO_MODULE_MATCH	(3)
		u32 rsv2:6;
#define NBL_FEM_CMD_HEAD_READ_CMD_LEN		(20)
#define NBL_FEM_CMD_HEAD_WRITE_CMD_LEN		(76)
		u32 cmd_len:8;
		u32 qid:4;
		u32 seq:4;
	} __packed info;
#define NBL_FEM_CMD_HEAD_TAB_WIDTH (sizeof(struct nbl_fem_cmd_head) \
		/ sizeof(u32))
	u32 data[NBL_FEM_CMD_HEAD_TAB_WIDTH];
	u8 head_data[sizeof(struct nbl_fem_cmd_head)];
};

/* req_data and resp_data for all cmd */
union nbl_fem_cmd_data_u {
	struct nbl_fem_cmd_data {
		u32 rsv[18];
	} __packed info;
#define NBL_FEM_CMD_DATA_TAB_WIDTH (sizeof(struct nbl_fem_cmd_data) \
		/ sizeof(u32))
	u32 data[NBL_FEM_CMD_DATA_TAB_WIDTH];
	u8 cmd_data[sizeof(struct nbl_fem_cmd_data)];
};

/* requeset param for KTAlloc */
union nbl_fem_req_param_ktalloc_u {
	struct nbl_fem_req_param_ktalloc {
		u32 rsv0:28;
		u32 pf_id:2;
		u32 rsv1:2;
		u32 rsv3[17];
	} __packed info;
#define NBL_FEM_REQ_PARAM_KTALLOC_TAB_WIDTH (sizeof(struct nbl_fem_req_param_ktalloc) \
		/ sizeof(u32))
	u32 data[NBL_FEM_REQ_PARAM_KTALLOC_TAB_WIDTH];
	u8 param_data[sizeof(struct nbl_fem_req_param_ktalloc)];
};

/* response data for KTAlloc */
union nbl_fem_resp_data_ktalloc_u {
	struct  nbl_fem_resp_data_ktalloc {
		u32 kt_idx:17;
		u32 rsv0:15;
		u32 rsv1[17];
	} __packed info;
#define NBL_FEM_RESP_DATA_KTALLOC_TAB_WIDTH (sizeof(struct  nbl_fem_resp_data_ktalloc) \
		/ sizeof(u32))
	u32 data[NBL_FEM_RESP_DATA_KTALLOC_TAB_WIDTH];
	u8 resp_data[sizeof(struct nbl_fem_resp_data_ktalloc)];
};

/* requeset param for KTFree */
union nbl_fem_req_param_ktfree_u {
	struct nbl_fem_req_param_ktfree {
		u32 mode:1;
#define NBL_FEM_CMD_PARAM_KTFREE_MODE_KT_IDX	(0)
#define NBL_FEM_CMD_PARAM_KTFREE_MODE_PF	(1)
		u32 rsv0:7;
		u32 kt_idx:17;
		u32 rsv1:3;
		u32 pf_id:2;
		u32 rsv2:1;
		u32 hmc:1;
#define NBL_FEM_CMD_PARAM_HMC_ONC		(0)
#define NBL_FEM_CMD_PARAM_HMC_HMC		(1)
		u32 rsv3[17];
	} __packed info;
#define NBL_FEM_REQ_PARAM_KTFREE_TAB_WIDTH (sizeof(struct nbl_fem_req_param_ktfree) \
		/ sizeof(u32))
	u32 data[NBL_FEM_REQ_PARAM_KTFREE_TAB_WIDTH];
	u8 param_data[sizeof(struct nbl_fem_req_param_ktfree)];
};

/* response data for KTFree */
union nbl_fem_resp_data_ktfree_u {
	struct  nbl_fem_resp_data_ktfree {
		u32 rsv[18];
	} __packed info;
#define NBL_FEM_RESP_DATA_KTFREE_TAB_WIDTH (sizeof(struct  nbl_fem_resp_data_ktfree) \
		/ sizeof(u32))
	u32 data[NBL_FEM_RESP_DATA_KTFREE_TAB_WIDTH];
	u8 resp_data[sizeof(struct nbl_fem_resp_data_ktfree)];
};

/* requeset param for TblAdd */
union nbl_fem_req_param_tbladd_u {
	struct nbl_fem_req_param_tbladd {
		u32 oft:1;
#define NBL_FEM_CMD_PARAM_OFT_DISABLE		(0)
#define NBL_FEM_CMD_PARAM_OFT_ENABLE		(1)
		u32 rsv0:3;
		u32 kt_mode:2;
#define NBL_FEM_CMD_PARAM_KT_MODE_160		(0)
#define NBL_FEM_CMD_PARAM_KT_MODE_160_88	(1)
#define NBL_FEM_CMD_PARAM_KT_MODE_160_176	(2)
		u32 rsv1:2;
		u32 kt_idx:17;
		u32 rsv2:3;
		u32 pf_id:2;
		u32 rsv3:1;
		u32 hmc:1;
#define NBL_FEM_CMD_PARAM_HMC_ONC		(0)
#define NBL_FEM_CMD_PARAM_HMC_HMC		(1)
		u8 key[64];
		u32 rsv4;
	} __packed info;
#define NBL_FEM_REQ_PARAM_TBLADD_TAB_WIDTH (sizeof(struct nbl_fem_req_param_tbladd) \
		/ sizeof(u32))
	u32 data[NBL_FEM_REQ_PARAM_TBLADD_TAB_WIDTH];
	u8 param_data[sizeof(struct nbl_fem_req_param_tbladd)];
};

/* response data for TblAdd */
union nbl_fem_resp_data_tbladd_u {
	struct  nbl_fem_resp_data_tbladd {
		u32 slot_id:3;
		u32 rsv0:1;
		u32 tbl_idx:15;
		u32 rsv1:5;
		u32 tbl_type:1;
#define NBL_FEM_CMD_PARAM_TBL_TYPE_HT		(0)
#define NBL_FEM_CMD_PARAM_TBL_TYPE_OFT		(1)
		u32 rsv2:7;
		u32 hash_data1:14;
		u32 rsv3:2;
		u32 hash_data0:14;
		u32 rsv4:2;
		u32 rsv5[16];
	} __packed info;
#define NBL_FEM_RESP_DATA_TBLADD_TAB_WIDTH (sizeof(struct  nbl_fem_resp_data_tbladd) \
		/ sizeof(u32))
	u32 data[NBL_FEM_RESP_DATA_TBLADD_TAB_WIDTH];
	u8 resp_data[sizeof(struct nbl_fem_resp_data_tbladd)];
};

/* requeset param for TblLoolUp */
union nbl_fem_req_param_tbllookup_u {
	struct nbl_fem_req_param_tbllookup {
		u32 sport_flag:3;
		u32 rsv0:1;
		u32 del_on_hit:1;
		u32 rsv1:3;
		u32 mode:1;
#define NBL_FEM_CMD_PARAM_MODE_NORMAL	(0)
#define NBL_FEM_CMD_PARAM_MODE_FAST	(1)
		u32 rsv2:19;
		u32 pf_id:2;
		u32 rsv3:1;
		u32 hmc:1;
#define NBL_FEM_CMD_PARAM_HMC_ONC		(0)
#define NBL_FEM_CMD_PARAM_HMC_HMC		(1)
		u8 lkp_key[40];
		u32 ht_id:1;
#define NBL_FEM_CMD_PARAM_TBL_HT0		(0)
#define NBL_FEM_CMD_PARAM_TBL_HT1		(1)
		u32 ht_slot_id:3;
		u32 kt_idx:17;
		u32 rsv4:11;
		u32 rsv5[6];
	} __packed info;
#define NBL_FEM_REQ_PARAM_TBLLOOKUP_TAB_WIDTH (sizeof(struct nbl_fem_req_param_tbllookup) \
		/ sizeof(u32))
	u32 data[NBL_FEM_REQ_PARAM_TBLLOOKUP_TAB_WIDTH];
	u8 param_data[sizeof(struct nbl_fem_req_param_tbllookup)];
};

/* response data for TblLoolUp */
union nbl_fem_resp_data_tbllookup_u {
	struct  nbl_fem_resp_data_tbllookup {
		u32 hit_pos:1;
#define NBL_FEM_CMD_PARAM_HIT_POS_HT_KT		(0)
#define NBL_FEM_CMD_PARAM_HIT_POS_OFT		(1)
		u32 rsv0:3;
		u32 slot_id:3;
		u32 rsv1:1;
		u32 ht_addr:15;
		u32 rsv2:9;
		u32 kt_idx:17;
		u32 rsv3:15;
		u32 hash1_idx:16;
		u32 hash0_idx:16;
		u32 ab:18;
		u32 rsv4:14;
		u32 ad_l[11];
		u32 ad_h:16;
		u32 rsv5:16;
		u32 rsv6[2];
	} __packed info;
#define NBL_FEM_RESP_DATA_TBLLOOKUP_TAB_WIDTH (sizeof(struct  nbl_fem_resp_data_tbllookup) \
		/ sizeof(u32))
	u32 data[NBL_FEM_RESP_DATA_TBLLOOKUP_TAB_WIDTH];
	u8 resp_data[sizeof(struct  nbl_fem_resp_data_tbllookup)];
};

union nbl_fem_req_param_tblread_u {
	struct nbl_fem_req_param_tblread {
		u32 rsv1:28;
		u32 pf_id:2;
		u32 rsv2:2;
		u64 tbl_addr:40;
		u64 rsv3:24;
		u32 rsv4[15];
	} __packed info;

	struct nbl_fem_req_param_tblread_kt_bind_pf {
		u32 rsv1:28;
		u32 pf_id:2;
		u32 rsv2:2;
		u32 rsv3[17];
	} __packed kt_bind_pf;

	struct nbl_fem_req_param_tblread_oftad {
		u32 rsv1:28;
		u32 pf_id:2;
		u32 rsv2:2;
		u32 tbl_addr_rsv:1;
		u32 tbl_addr:6;
		u32 read_mask:1;
		u32 rsv4:24;
		u32 rsv5[16];
	} __packed oftad;

#define NBL_FEM_REQ_PARAM_TBLREAD_TAB_WIDTH (sizeof(struct nbl_fem_req_param_tblread) \
		/ sizeof(u32))
	u32 data[NBL_FEM_REQ_PARAM_TBLREAD_TAB_WIDTH];
	u8 param_data[sizeof(struct nbl_fem_req_param_tblread)];
};

union nbl_fem_resp_data_tblread_u {
	struct nbl_fem_resp_data_tblread {
		u32 tbl_rdat[18];
	} __packed info;
	struct nbl_fem_resp_data_tblread_oft {
		u32 oft0_key[5];
		u32 oft1_key[5];
		u32 oft0_ktidx:17;
		u32 rsv0:15;
		u32 oft1_ktidx:17;
		u32 rsv1:15;
		u32 oft0_valid:1;
		u32 oft1_valid:1;
		u32 oft0_size:1;
		u32 oft1_size:1;
		u32 rsv2:28;
		u32 rsv3[5];
	} __packed oft_info;
	struct nbl_fem_resp_data_tblread_kt_bind_pf {
		u32 kt_bind[4];
		u32 rsv[14];
	} __packed kt_bind_pf_info;
#define NBL_FEM_RESP_DATA_TBLREAD_TAB_WIDTH (sizeof(struct nbl_fem_resp_data_tblread) \
		/ sizeof(u32))
	u32 data[NBL_FEM_RESP_DATA_TBLREAD_TAB_WIDTH];
	u8 resp_data[sizeof(struct  nbl_fem_resp_data_tblread)];
};

#define NBL_DRACO_CMD_TBLWRITE_DFT_DATALEN (9)
union nbl_fem_req_param_tblwrite_u {
	struct nbl_fem_req_data_tblwrite {
		u32 tbl_addr:20;
		u32 rsv2:8;
		u32 pf_id:2;
		u32 rsv1:2;
		u8 data[64];
	} __packed info;

	struct nbl_fem_req_data_tblwrite_pt {
		u32 tbl_addr:4;
		u32 rsv2:24;
		u32 pf_id:2;
		u32 rsv1:2;
		u8 data[64];
	} __packed pt_tbl;

	struct nbl_fem_req_data_tblwrite_dft {
		u32 tbl_addr:4;
		u32 rsv2:24;
		u32 pf_id:2;
		u32 rsv1:2;
		u8 data[64];
	} __packed dft_tbl;

	struct nbl_fem_req_data_tblwrite_ht {
		u32 slot_id:3;
		u32 ht_addr:14;
		u32 slot_mode:1;
		u32 ht_id:1;
		u32 rsv2:9;
		u32 pf_id:2;
		u32 rsv1:2;
		u8 data[64];
	} __packed ht_tbl;

	struct nbl_fem_req_data_tblwrite_ktat {
		u32 kt_addr:17;
		u32 at_half:1; /* 0 for low half, 1 for high half */
		u32 at_type:1; /* 0 for half & 1 for full */
		u32 kt_type:1; /* 0 for half & 1 for full */
		u32 rsv2:8;
		u32 pf_id:2;
		u32 rsv1:2;
		u8 data[64];
	} __packed ktat_tbl;

	struct nbl_fem_req_data_tblwrite_oftad {
		u32 oft_addr:7;
		u32 kt_type:1;
		u32 opcode:1; /* 0 for delete and 1 for add */
		u32 rsv2:19;
		u32 pf_id:2;
		u32 rsv1:2;
		u8 data[64];
	} __packed oftad_tbl;

#define NBL_FEM_REQ_DATA_TBLWRITE_TAB_WIDTH (sizeof(struct nbl_fem_req_data_tblwrite) \
		/ sizeof(u32))
	u32 data[NBL_FEM_REQ_DATA_TBLWRITE_TAB_WIDTH];
	u8 param_data[sizeof(struct nbl_fem_req_data_tblwrite)];
};

union nbl_fem_resp_data_tblwrite_u {
	struct nbl_fem_resp_data_tblwrite {
		u32 rsv[18];
	} __packed info;

#define NBL_FEM_RESP_DATA_TBLWRITE_TAB_WIDTH (sizeof(struct nbl_fem_resp_data_tblwrite) \
		/ sizeof(u64))
	u64 data[NBL_FEM_RESP_DATA_TBLWRITE_TAB_WIDTH];
	u8 resp_data[sizeof(struct  nbl_fem_resp_data_tblwrite)];
};

#pragma pack()

struct nbl_fem_cmd_cfg_ops {
	int (*cfg_req_head)(union nbl_fem_cmd_head_u *data, struct nbl_flow_param *param);
	int (*cfg_req_param)(union nbl_fem_cmd_data_u *data, struct nbl_flow_param *param);
};

void nbl_flow_restore_flow(void *priv, bool restore_all);
int nbl_phy_cfg_flow_default_action(struct nbl_resource_mgt *res_mgt, u16 vsi_id,
				    u16 eth_id, bool status);

#endif
