/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#ifndef _NBL_TC_FLOW_LEONIS_H_
#define _NBL_TC_FLOW_LEONIS_H_

#include "nbl_core.h"
#include "nbl_hw.h"
#include "nbl_resource.h"
#include "nbl_tc_mcc_leonis.h"

#define NBL_FLOW_INGRESS				0
#define NBL_FLOW_EGRESS					1

#define NBL_FLOW_INNER_PATTERN				0
#define NBL_FLOW_OUTER_PATTERN				1

#define NBL_MAX_ETHPORTS				516
#define NBL_FLOW_ETH_REP_0				2048
#define NBL_FLOW_ETH_REP_1				2049
#define NBL_FLOW_ETH_REP_2				2050
#define NBL_FLOW_ETH_REP_3				2051
#define NBL_FLOW_BOND_REP_PORT_ID			2052
#define NBL_ETHER_TYPE_IPV4				4
#define NBL_ETHER_TYPE_IPV6				6
#define NBL_FLOW_MAX_REP_ID				0xFFFF

#define NBL_FLOW_ICMP_REQ_TYPE				8
#define NBL_FLOW_ICMP_REQ_CODE				0
#define NBL_FLOW_ICMP_REP_TYPE				0
#define NBL_FLOW_ICMP_REP_CODE				0

#define NBL_FLOW_ICMP6_REQ_TYPE				128
#define NBL_FLOW_ICMP6_REQ_CODE				0
#define NBL_FLOW_ICMP6_REP_TYPE				129
#define NBL_FLOW_ICMP6_REP_CODE				0

#define NBL_HASH_CFT_MAX				4
#define NBL_HASH_CFT_AVL				2
#define NBL_HASH0					1
#define NBL_HASH1					2

#define NBL_KEY_TYPE_160				0
#define NBL_KEY_TYPE_320				1

#define NBL_FEM_AT_LEN					32
#define NBL_FEM_AT_HALF_LEN				16
#define NBL_AT_WIDTH					22

	#define NBL_PP1_AT2_OFFSET				(92 * 1024)
	#define NBL_PP1_AT_OFFSET				(80 * 1024)
	#define NBL_PP2_AT2_OFFSET				(64 * 1024)

#define NBL_PP1_POWER					13
#define NBL_PP2_POWER					14

#define NBL_FEM_AT_NO_ENTRY				(0)
#define NBL_FEM_AT_ONE_ENTRY				(1)
#define NBL_FEM_AT_TWO_ENTRY				(2)

#define NBL_HT0_HASH					1
#define NBL_HT1_HASH					2

#define NBL_MASK_16	0xffff

#define NBL_PP_STAGE_PROFILE_NUM			(48)
#define NBL_PP_PROFILE_STAGE_NUM			(8)

#define NBL_FLOW_TABLE_LEN				(8 * 1024)
#define NBL_TABLE_KEY_VALUE_LEN				(40)
#define NBL_TABLE_KEY_DATA_LEN				(10)

#define NBL_FLOW_PROFILE_START				16
#define NBL_FLOW_LEN_INVALID				(0xffffffff)

#define NBL_FLOW_TABLE_L4_PORT_DEFAULT_MASK		0xFFFF
#define NBL_FLOW_TABLE_FULL_MASK_AS_U32			0xFFFFFFFF
#define NBL_FLOW_TABLE_FULL_MASK_AS_U16			0xFFFF
#define NBL_FLOW_TABLE_FULL_MASK_AS_U8			0xFF

#define NBL_GET_ARG_LEN(sz) ((sz) / sizeof(u32))
#define NBL_GET_ARG_COPY_LEN(sz) ((sz) * sizeof(u32))

#define NBL_FLOW_TC_PEDIT_MAC	1024
#define NBL_FLOW_TC_PEDIT_IP	1024
#define NBL_FLOW_TC_PEDIT_IP6	512

#define NBL_FLOW_TC_PEDIT_MAC_BASE 0
#define NBL_FLOW_TC_PEDIT_IP_BASE NBL_FLOW_TC_PEDIT_MAC

/* at node's idx has two continuous idx, and the begin idx need to be even number */
#define NBL_FLOW_AT_IDX_NUM				2
#define NBL_FLOW_AT_IDX_MULTIPLE			2

struct nbl_tcam_item {
	union nbl_tc_common_data_u kt_data;
	u32 tcam_action[NBL_MAX_ACTION_NUM];
	bool tcam_flag;
	u8 key_mode;
	u8 pp_type;
	u32 *pp_tcam_count;
	u16 tcam_index;
	u32 sw_hash_id;
	u8 profile_id;
};

#define NBL_ACT_INGRESS				1
#define NBL_ACT_ENGRESS				0

#define NBL_TC_KT_HALF_MODE			1
#define NBL_TC_KT_FULL_MODE			2

struct nbl_edit_item {
	struct list_head tc_mcc_list;
	u32 encap_idx;
	u16 smac_idx;
	u16 dmac_idx;
	u16 sip_idx;
	u16 dip_idx;
	u16 mcc_idx;
	bool is_mir;
	u8 direct;
};

struct nbl_select_input {
	struct nbl_flow_pp_ht_mng *pp_ht0_mng;
	struct nbl_flow_pp_ht_mng *pp_ht1_mng;
	struct nbl_flow_tcam_key_mng *tcam_pp_key_mng;
	struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng;
	unsigned long *pp_kt_bmp;
	u32 kt_idx_offset;
	u32 *pp_tcam_count;
	u32 act_offset;
	u32 act2_offset;
	u32 pp_kt_num;
	u8 pp_type;
};

/* flow tab hash-list struct  */
struct nbl_flow_tab_conf {
	union {
		u32 key_value[NBL_TABLE_KEY_DATA_LEN];
		u8 key_data[NBL_TABLE_KEY_VALUE_LEN];
	};
};

struct nbl_flow_tab_filter {
	struct nbl_flow_tab_conf key;
	struct nbl_tc_ht_item ht_item;
	struct nbl_edit_item edit_item;
	struct nbl_act_collect act_collect;
	u64 act_flags;
	u32 assoc_tbl_id;
	u32 tbl_id;
	u32 sw_hash_id;
	u32 ref_cnt;
	u16 tcam_index;
	u8 pp_type;
	bool tcam_flag;
};

struct nbl_flow_idx_info {
	u64 key_flag;
	u32 flow_idx;
	u16 tnl_mac_idx;
	u16 pp_flag;
	u8  outer_pattern_flag;
	u8  profile_id;
	bool     last_stage;
	bool	pt_cmd;
};

struct nbl_mt_input {
	u32 tbl_id;
	u16 depth;
	u16 power;
	u8 key[NBL_KT_BYTE_LEN];
	u8 key_full;
	u8 at_num;
	u8 kt_left_num;
	u8 pp_type;
};

struct nbl_flow_info_init {
	int (*init_func)(struct nbl_resource_mgt *res_mgt);
};

struct nbl_flow_info_uninit {
	void (*uninit_func)(struct nbl_resource_mgt *res_mgt);
};

int nbl_tc_flow_alloc_bmp_id(unsigned long *bitmap_mng, u32 size,
			     u8 type, u32 *bitmap_id);
void nbl_tc_flow_free_bmp_id(unsigned long *bitmap_mng, u32 id, u8 type);
int nbl_flow_flush(struct nbl_resource_mgt *res_mgt);
void nbl_flow_info_uninit_list(struct nbl_resource_mgt *res_mgt);
void nbl_flow_resource_unavailable(struct nbl_tc_flow_mgt *tc_flow_mgt);
bool nbl_flow_is_available(struct nbl_tc_flow_mgt *tc_flow_mgt);
void nbl_flow_ref_inc(void);
void nbl_flow_ref_dec(void);

struct nbl_flow_pp_ht_tbl *
nbl_pp_ht_lookup(struct nbl_flow_pp_ht_mng *pp_ht_mng, u16 hash_value,
		 struct nbl_flow_pp_ht_key *pp_ht_key);
int nbl_insert_pp_ht(struct nbl_resource_mgt *res_mgt,
		     struct nbl_flow_pp_ht_mng *pp_ht_mng,
		     u16 hash_value0, u16 hash_value1, u32 key_index);
int nbl_delete_pp_ht(struct nbl_resource_mgt *res_mgt,
		     struct nbl_flow_pp_ht_mng *pp_ht_mng,
		     struct nbl_flow_pp_ht_tbl *node, u16 hash_value0,
		     u16 hash_value1, u32 key_index);

bool nbl_pp_ht0_ht1_search(struct nbl_flow_pp_ht_mng *pp_ht0_mng, u16 ht0_hash,
			   struct nbl_flow_pp_ht_mng *pp_ht1_mng, u16 ht1_hash);
int nbl_pp_at_lookup(struct nbl_resource_mgt *res_mgt, u8 pp_type, u8 at_type,
		     struct nbl_flow_pp_at_key *act_key, struct nbl_flow_at_tbl **act_node);

int nbl_insert_pp_at(struct nbl_resource_mgt *res_mgt, u8 pp_type, u8 at_type,
		     struct nbl_flow_pp_at_key *act_key, struct nbl_flow_at_tbl **act_node);

struct nbl_tc_flow *
nbl_tc_flow_index_lookup(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key);
int nbl_tc_flow_delete_index(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key);

int nbl_tcam_key_lookup(struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
			struct nbl_tcam_item *tcam_item, u16 *index);
int nbl_insert_tcam_key_ad(struct nbl_common_info *common,
			   struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
			   struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng,
			   struct nbl_tcam_item *tcam_item,
			   struct nbl_flow_tcam_ad_item *ad_item,
			   u16 *index);
int nbl_delete_tcam_key_ad(struct nbl_common_info *common,
			   struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
			   struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng,
			   u16 index, u8 key_mode, u8 pp_type);

int nbl_cmdq_flow_ht_clear_2hw(struct nbl_tc_ht_item *ht_item,
			       u8 pp_type, struct nbl_resource_mgt *res_mgt);

void nbl_flow_remove_ops(struct nbl_resource_ops *res_ops);
int nbl_flow_setup_ops(struct nbl_resource_ops *res_ops);
void nbl_flow_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_flow_mgt_start(struct nbl_resource_mgt *res_mgt);

#endif
