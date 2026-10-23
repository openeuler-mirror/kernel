/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#ifndef _NBL_TC_FLOW_DRACO_H_
#define _NBL_TC_FLOW_DRACO_H_

#include "nbl_tc_flow.h"
#include "nbl_flow_draco.h"
#include "nbl_tc_pedit.h"

#define NBL_BIT_TO_BYTE(bits) (((bits) + 7) / 8)
#define NBL_BYTES_TO_BITS(bytes) ((bytes) * 8)

#define NBL_DRACO_FLOW_GET_LEN(idx) 64

#define NBL_DRACO_CMD_PED_TNL_LEN 56
#define NBL_DRACO_CMD_PED_REP_LEN 32
#define NBL_DRACO_CMD_PED_READ_RESP_LEN 40
#define NBL_DRACO_CMD_PED_READ_LEN 16

#define NBL_DRACO_ASSOC_TBL_ID_MASK (0x3fff)
#define NBL_DRACO_ASSOC_PF_ID_SHIFT (14)

#define NBL_DRACO_MAX_ACT_LEN (6)
// #define NBL_TABLE_KEY_LEN		(10)

#define NBL_DRACO_KT_HALF_MODE 0
#define NBL_DRACO_KT_FULL_MODE 1
#define NBL_DRACO_AT_TYPE_0 0
#define NBL_DRACO_AT_TYPE_1 1
#define NBL_DRACO_AT_TYPE_2 2
#define NBL_DRACO_AT0_LENGTH 0
#define NBL_DRACO_AT1_LENGTH 11
#define NBL_DRACO_AT2_LENGTH 22
#define NBL_DRACO_AT_BYTES 11

#define NBL_DRACO_KT_AB_EXT 18
#define NBL_DRACO_KT_AB_BASE 8
#define NBL_DRACO_ACL_SPEC_ID_WIDTH 12
#define NBL_DRACO_FULL_KEY 320
#define NBL_DRACO_HALF_KEY 160
#define NBL_DRACO_FULL_KEY_BYTES 40
#define NBL_DRACO_HALF_KEY_BYTES 20
#define NBL_DRACO_FULL_KT_AT 62
#define NBL_DRACO_FULL_AT 176
#define NBL_DRACO_HALF_AT 88
#define NBL_DRACO_FLOW_MAX_LEN (496 + 16)

#define NBL_DRACO_MAX_PROFILE_NUM (24)

#define NBL_DRACO_MAX_TBL_ID (16 * 1024)
#define NBL_DRACO_MAX_HALF_FLOW_KT_NUM (128 * 1024)
#define NBL_DRACO_MAX_FULL_FLOW_KT_NUM (64 * 1024)
#define NBL_DRACO_MAX_HALF_FLOW_KT_NUM_HASH	\
	(NBL_DRACO_MAX_HALF_FLOW_KT_NUM + NBL_DRACO_HASH_BUCK_RSV2048)
#define NBL_DRACO_MAX_FULL_FLOW_KT_NUM_HASH	\
	(NBL_DRACO_MAX_FULL_FLOW_KT_NUM + NBL_DRACO_HASH_BUCK_RSV1024)

#define NBL_DRACO_KT_IS_ENTRY_HEAD(kt_idx) ((kt_idx) % 2 == 0)

#define NBL_DRACO_GET_HALF_KT_IDX(blk_idx, kt_idx)	\
	((blk_idx) * NBL_DRACO_HALF_KT_PER_BLOCK_CNT + (kt_idx))
#define NBL_DRACO_GET_FULL_KT_IDX(blk_idx, kt_idx)	\
	((blk_idx) * NBL_DRACO_HALF_KT_PER_BLOCK_CNT + (kt_idx) * 2)

#define NBL_DRACO_GET_HALF_KT_NODE_IDX(idx) ((idx) % NBL_DRACO_HALF_KT_PER_BLOCK_CNT)
#define NBL_DRACO_GET_FULL_KT_NODE_IDX(idx) (NBL_DRACO_GET_HALF_KT_NODE_IDX(idx) / 2)

#define NBL_DRACO_HALF_KT_BLOCK_IS_FREE(kt_free) ((kt_free) == NBL_DRACO_HALF_KT_PER_BLOCK_CNT)
#define NBL_DRACO_FULL_KT_BLOCK_IS_FREE(kt_free) ((kt_free) == NBL_DRACO_FULL_KT_PER_BLOCK_CNT)
#define NBL_DRACO_GET_AT_BYTES(at_type) ((at_type) * 11)

#define NBL_DRACO_VAILD_BLOCK_IDX(kt_node, aside_idx) (((kt_node)->kt_block_id + (aside_idx)))

#define NBL_DRACO_MAX_HW_IDX_NUM	\
	((NBL_DRACO_MAC_PED_NUM) / (NBL_DRACO_MAC_PED_SLICE) + \
	(NBL_DRACO_IP_PED_NUM) / (NBL_DRACO_IP_PED_SLICE) + \
	(NBL_DRACO_TNL_ENCAP_NUM) / (NBL_DRACO_TNL_ENCAP_SLICE) + \
	(NBL_DRACO_TNL_VTEP_NUM) / (NBL_DRACO_TNL_VTEP_SLICE) + \
	(NBL_DRACO_MIRROR_MAX_NUM) / (NBL_DRACO_MIRROR_MAX_SLICE) + \
	(NBL_DRACO_MCC_NUM) / (NBL_DRACO_MCC_MAX_SLICE) + 6)

#define NBL_DRACO_LOOKUP_ID_NUM 16
#define NBL_DRACO_TCAM_SPEC 128
#define NBL_DRACO_TCAM_SPEC_HALF (128)
#define NBL_DRACO_TCAM_SPEC_FULL (64)
#define NBL_DRACO_TCAM_EVICTION_TM (10 * 1000 * 1000) /* 60s */

#define NBL_DRACO_MAX_ACT_LEN (6)
#define NBL_DRACO_VLD_KAT_OFFSET (2)

#define NBL_DRACO_ACTION_LEN_TNL (40)
#define NBL_DRACO_ACTION_LEN_IP4NAT (32)
#define NBL_DRACO_ACTION_LEN_IP6NAT (12)
#define NBL_DRACO_ACTION_LEN_MACNAT (12)

#define NBL_DRACO_HALF_KT_PER_BLOCK_CNT (1024)
#define NBL_DRACO_FULL_KT_PER_BLOCK_CNT (512)

#define NBL_DRACO_SPORT_DIR_TX (0)
#define NBL_DRACO_SPORT_DIR_RX (1)

/* udf */
#define NBL_DRACO_UDF_WIDTH (160)
#define NBL_DRACO_UDF_UNIT (4)
#define NBL_DRACO_UDF_SIZE_8B (0)
#define NBL_DRACO_UDF_SIZE_8B_MASK (1)
#define NBL_DRACO_UDF_SIZE_16B (2)
#define NBL_DRACO_UDF_SIZE_32B (3)
#define NBL_DRACO_UDF_FLAG_OFT (0)
#define NBL_DRACO_UDF_LOC_VTEP_OFT (4)
#define NBL_DRACO_UDF_MCC_PRUNE_OFT (4)
#define NBL_DRACO_UDF_SEC_ID_OFT (16)
#define NBL_DRACO_UDF_FLOW_STAT_ID_OFT (28)
#define NBL_DRACO_UDF_PP0_IDX_OFT (32)
#define NBL_DRACO_UDF_CAP_INFO_OFT (40)
#define NBL_DRACO_UDF_FLOW_CAR_OFT (48)
#define NBL_DRACO_UDF_MIRR_ID_OFT (60)
#define NBL_DRACO_UDF_T_OVN_DATA_OFT (68)
#define NBL_DRACO_UDF_UDP_SP_OFT (68)
#define NBL_DRACO_UDF_NVGRE_FLOW_ID_OFT (84)
#define NBL_DRACO_UDF_ACL_TAG_OFT (92)
#define NBL_DRACO_UDF_ECN_OFT (100)
#define NBL_DRACO_UDF_QPN_OFT (104)
#define NBL_DRACO_UDF_DP_HASH_OFT (128)

/* PP UDI ID */
#define NBL_DRACO_UDF_ID_SET_PP0_IDX (1)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR (2)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR_FLAG (3)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR (4)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR_FLOW_ID (5)

/* ACL UDI ID */
#define NBL_DRACO_ACL_UDF_ID_SET_ACL0_IDX (1)
#define NBL_DRACO_ACL_UDF_ID_CAR (2)
#define NBL_DRACO_ACL_UDF_ID_CAR_MIRR (3)
#define NBL_DRACO_ACL_UDF_ID_CAR_MIRR_FLOW_ID (4)
#define NBL_DRACO_ACL_UDF_ID_CAR_MIRR_FLAG (5)
#define NBL_DRACO_ACL_UDF_ID_CAR_MIRROR_FLOW_ID_FLAG (6)
#define NBL_DRACO_ACL_UDL_ID_STAT_CAR_MIRR (7)

/* EPRO UDI ID */
#define NBL_DRACO_EPRO_UDF_ID_SET_CAR (1)

/* UDF length */
#define NBL_DRACO_UDF_ID_SET_PP0_IDX_LEN (16)
#define NBL_DRACO_UDF_ID_SET_STAT_CAR_LEN (32)
#define NBL_DRACO_UDF_ID_SET_MIRR_ID_LEN (8)
#define NBL_DRACO_UDF_ID_FLOW_STAT_ID_LEN (20)
#define NBL_DRACO_UDF_ID_FLOW_CAR_LEN (12)
#define NBL_DRACO_UDF_LOC_VTEP_LEN (4)
#define NBL_DRACO_UDF_NVGRE_FLOW_ID_LEN (8)
#define NBL_DRACO_UDF_T_OVN_DATA_LEN (32)

/* ACL related UDF length */
#define NBL_DRACO_UDF_SET_ACL0_IDX_LEN (16)

/* acl */
#define NBL_ACL_TCAM_IDX0 0
#define NBL_ACL_TCAM_IDX1 1
#define NBL_ACL_TCAM_IDX2 2
#define NBL_ACL_TCAM_IDX3 3
#define NBL_ACL_TCAM_IDX4 4
#define NBL_ACL_TCAM_IDX5 5
#define NBL_ACL_TCAM_IDX6 6
#define NBL_ACL_TCAM_IDX7 7
#define NBL_ACL_TCAM_IDX8 8
#define NBL_ACL_TCAM_IDX9 9
#define NBL_ACL_TCAM_IDX10 10
#define NBL_ACL_TCAM_IDX11 11
#define NBL_ACL_TCAM_IDX12 12
#define NBL_ACL_TCAM_IDX13 13
#define NBL_ACL_TCAM_IDX14 14
#define NBL_ACL_TCAM_IDX15 15
#define NBL_ACL_PROFILE_CNT (16)
#define NBL_ACL_STAGE_NUM (2)
#define NBL_ACL_TCAM_CNT (16)
#define NBL_ACL_TCAM_DEPTH (512)
#define NBL_ACL_TCAM_BITS (40)
#define NBL_ACL_TCAM_BYTES (5)
#define NBL_ACL_KEY_MAX_BYTES (80)
#define NBL_ACL_ACT_RAM_NUM (16)
#define NBL_ACL_PROFILE_NUM (16)
#define NBL_ACL_GRAPH_NUM (16)

#define NBL_DRACO_ACL_ASSOC_CAPA (4096)
#define NBL_DRACO_ACL_ASSOC_MASK (0x3FF)
#define NBL_DRACO_ACL_ASSOC_PFID_OFT (10)
#define NBL_DRACO_ACL_SPEC_CAPA (2048 / 4)
#define NBL_DRACO_ACL_SPEC_MASK (0x1FF)
#define NBL_DRACO_ACL_SPEC_PFID_OFT (9)
#define NBL_DRACO_ACL_ENTRY_MASK (0x7F)
#define NBL_DRACO_ACL_ENTRY_PFID_OFT (7)
#define NBL_DRACO_ACL_KEY_LEN_MAX (80)
#define NBL_DRACO_ACL_ACT_LEN_MAX (164)
#define NBL_DRACO_ACL_ACT_RAM_BITS (82)

#define NBL_DRACO_ACL_ACT_AB_OFT (12)
#define NBL_DRACO_ACL_ACT_AD_OFT (30)

/* reserve entry ID for ICMPv6 NS & NA */
#define NBL_DRACO_ACL_RSV_ENTRY_CNT (2)
#define NBL_DRACO_ACL_ENTRY_FOR_NS (126)
#define NBL_DRACO_ACL_ENTRY_FOR_NA (127)

struct nbl_bitmap_mng {
	struct device *dev;
	bool safe_lock;
	bool skip_zero;
	struct mutex bmp_lock;	/* for bitmap */
	u32 bmp_size;	/* full size */
	unsigned long *id_bmp;
};

struct nbl_flow_node_param {
	u32 key_len;
	u32 entries;
};

#pragma pack(1)

union nbl_draco_sport_u {
	struct {
		u16 eth_id : 2;
		u16 lag_id : 1;
		u16 lag : 1;
		u16 rsv1 : 7;
		u16 dir : 1;
		u16 rsv0 : 1;
		u16 sw_id : 2;
		u16 phy_flow : 1;
	} rx;

	struct {
		u16 vsi_id : 9;
		u16 cpu : 1;
		u16 rdma : 1;
		u16 dir : 1;
		u16 rsv0 : 1;
		u16 sw_id : 2;
		u16 phy_flow : 1;
	} tx;

	u16 data;
};

union nbl_flow_udfs {
	struct {
		u32 pad : 16;
		u32 flag : 8;
		u32 mirr_id : 8;
		u32 flow_car : 11;
		u32 flow_car_vld : 1;
		u32 flow_stat_id : 19;
		u32 flow_stat_vld : 1;
	} info;

	u32 data[2];
};

union nbl_action_bits_ext {
	struct {
		u8 TNL_OP : 1;
		u8 SET_DMAC : 1;
		u8 SET_SMAC : 1;
		u8 SET_DIP : 1;
		u8 SET_SIP : 1;
		u8 SET_DP : 1;
		u8 SET_SP : 1;
		u8 SET_TTL : 1;
		u8 SET_TOS : 2;
		u8 VLAN_OP : 4;
		u8 SET_UDF : 3;
		u8 SET_DEST : 1;
		u16 RESV : 14;
	} extab;

	u32 data;
};

struct nbl_draco_flow_tab_conf {
	union {
		struct {
			u32 act_value[NBL_DRACO_MAX_ACT_LEN];
			u32 key_value[NBL_TABLE_KEY_LEN];
		};
		u8 buf[NBL_TABLE_KEY_LEN * 4 + NBL_DRACO_MAX_ACT_LEN * 4];
	};
};

struct nbl_draco_kt_idx_info {
	u32 kt_type : 1;
	u32 at_type : 2;
	u32 kt_in_use : 1;
	u32 kt_profile_id : 4;
	u32 kt_block_id : 8;
	u32 kt_rsv : 16;
};

struct nbl_draco_hw_res_key {
	u16 hw_res_block_id;
	enum nbl_draco_ped_type res_type;
};

struct nbl_flow_ped_ip6_node {
	u8 data[NBL_IPV6_ADDR_LEN_AS_U8];
	struct nbl_draco_hw_res_key hw_res_key;
};

struct nbl_flow_ped_mac_node {
	u8 data[ETH_ALEN];
	struct nbl_draco_hw_res_key hw_res_key;
};

struct nbl_flow_mirror_key {
	u8 mirror_type;
	u16 dport;
};

struct nbl_flow_mirror_node {
	struct nbl_flow_mirror_key key;
	struct nbl_draco_hw_res_key hw_res_key;
};

struct nbl_flow_tnl_vtep_node {
	u8 sip[NBL_IPV6_ADDR_LEN_AS_U8];
	u8 smac[NBL_MAC_ADDR_LEN_AS_U8];
#define NBL_FLOW_TNL_VTEP_PAD_LEN  (NBL_IPV6_ADDR_LEN_AS_U8 - NBL_MAC_ADDR_LEN_AS_U8)
	u8 pad[NBL_FLOW_TNL_VTEP_PAD_LEN];
};

struct nbl_flow_tnl_vtep_hnode {
	struct nbl_flow_tnl_vtep_node vtep_key;
	u8 vtep_id;
	u32 ref_cnt;
};

struct nbl_flow_tnl_prof_node {
	union {
		u64 vx_data;
		u64 nvg_data;
		u64 gnv_data;
		u64 gnv_ovn_data;

		struct {
			u16 DB7;
			u16 DB6;
			u16 DB5;
			u16 DB0;
		};

		struct {
			u8 gnv_opt_data[NBL_FLOW_ENCAP_GENEVE_OVN_OPT_LEN];
		};

		struct {
#define NBL_DRACO_NVGRE_VNI_LEN 3
			u8 gre_d_l[NBL_DRACO_NVGRE_VNI_LEN];
			u32 gre_d_h;
			u8 gre_rsv : 5;
			u8 flow_put : 1;
			u8 vni_put : 1;
			u8 gre_hlen : 1;
		};
	};

	union {
		struct {
			u16 frg_oft : 13;
			u16 flg : 3;
			u8 id : 8;
		};
#define NBL_TNL_L3_DATA_BYTES_LEN 3
		u8 l3_data[NBL_TNL_L3_DATA_BYTES_LEN];
	};

	u8 dip[NBL_IPV6_ADDR_LEN_AS_U8];
	u8 ttl;
	union {
		u16 iv_info;
		struct {
			u16 ivid : 12;
			u16 ipri : 3;
			u16 itpid_sel : 1;
		};
	};

	union {
		u16 ov_info;
		struct {
			u16 ovid : 12;
			u16 opri : 3;
			u16 otpid_sel : 1;
		};
	};

	u8 dmac[NBL_MAC_ADDR_LEN_AS_U8];
	u16 loc_vtep_id : 4;
	u16 dscp : 6;
	u16 dscp_inherit : 1;
	u16 tnl_type : 2;
	u16 tnl_l3 : 1;
	u16 vlan_num : 2;
};

struct nbl_flow_tnl_prof_hnode {
	struct nbl_flow_tnl_prof_node prof_key;
	u32 tnl_idx;
	u32 ref_cnt;
};

struct nbl_flow_tnl_decap_assd_node {
	u32 loc_vtep_id : 4;
	u32 vlan_lmt : 2;
	u32 t_lx_sel : 1;
	u32 rsv : 25;
};

struct nbl_flow_tnl_decap_tcam_hnode {
	struct nbl_flow_tnl_decap_tcam_node decap_tcam_key;
	struct nbl_flow_tnl_decap_assd_node decap_assd_node;
	u32 ref_cnt;
};

enum nbl_tnl_templt_type {
	NBL_TNL_VXLAN_TYPE,
	NBL_TNL_NVGRE_TYPE,
	NBL_TNL_GENEVE_TYPE,
	NBL_TNL_GENEVE_OVN_TYPE,
	NBL_TNL_RAW_TYPE,
};

#define NBL_TNL_NOT_UDP_HDR(tnl_type) ((tnl_type) == NBL_TNL_NVGRE_TYPE)

struct nbl_draco_vlan_info {
	u16 vid : 12;
	u16 pri : 3;
	u16 tpid_sel : 1;
};

union nbl_udf_profile_u {
	struct {
		u8 oft : 5;
		u8 sz : 2;
		u8 en : 1;
	} info;
};

union nbl_udf_instruction_u {
	struct {
		union nbl_udf_profile_u p0;
		union nbl_udf_profile_u p1;
		union nbl_udf_profile_u p2;
		union nbl_udf_profile_u p3;
	} prfs;

	u32 value;
};

struct nbl_draco_flow_mcc_tbl {
	union {
		u32 mcc_tbl[16];
		struct {
			u64 vld:1;
			u64 leaf_dport_eth:4;
			u64 leaf_dport_lag:2;
			u64 leaf_dport_vsi_0_56:57;
			u64 leaf_dport_vsi_57_120:64;
			u64 leaf_dport_vsi_121_184:64;
			u64 leaf_dport_vsi_185_248:64;
			u64 leaf_dport_vsi_249_277:29;
			u64 clr_udf_btm0:1;
			u64 clr_udf_btm1:1;
			u64 clr_udf_btm2:1;
			u64 clr_udf_btm3:1;
			u64 mcc_pri:1;
			u64 udf_prune_en:1;
			u64 rsv0:29;
			u64 rsv1[3];
		};
	};
};

#pragma pack()

#define NBL_DRACO_GET_MCC_ETH_IDX(idx) ((idx) + 1)
#define NBL_DRACO_GET_MCC_LAG_IDX(idx) ((idx) + 5)
#define NBL_DRACO_GET_MCC_VSI_IDX(idx) ((idx) + 7)

enum nbl_draco_mirror_mode {
	NBL_DRACO_MIRROR_SPAN_MODE = 0,
	NBL_DRACO_MIRROR_RDMA_RAW_MODE,
	NBL_DRACO_MIRROR_RSPAN_MODE,
	NBL_DRACO_MIRROR_ERSPAN_MODE,
};

struct nbl_draco_flow_node {
	/* fixed */
	struct nbl_draco_flow_tab_conf key;
	struct nbl_draco_kt_idx_info kt_info;
	struct nbl_draco_ped_info ped_info;
	struct nbl_draco_hw_res_key hw_res_key[NBL_DRACO_NEED_PED_RECORD_TYPE_END];
	u64 act_flags;

	u32 kt_index;
	u32 ht0_hash;
	u32 ht1_hash;
	u32 hash_table_id;
	u32 ht_index;
	u32 slot_id;
	u32 tcam_index;
	u32 tcam_table_id;

	u16 assoc_tbl_id;
	u16 graph_index;
	u16 profile_index;
	u16 profile_stage;

	struct nbl_draco_vtep_info vtep_info;
	bool tcam_flag;
	bool offloaded;

	u8 ref_cnt;
};

struct nbl_draco_hw_res_node {
	struct list_head res_node;
	struct nbl_draco_hw_res_key hw_res_key;

	u16 avail_hw_res_num;
	u16 hw_res_base_id;

	/* user could only write the following members */
	u16 used_hw_res_num;
	struct nbl_bitmap_mng hw_res_bmp_mng;
};

struct nbl_draco_flow_hw_res_mgt {
	struct list_head hw_res_list[NBL_DRACO_NEED_PED_RECORD_TYPE_END];
	struct nbl_draco_hw_res_node *cur_res_node[NBL_DRACO_NEED_PED_RECORD_TYPE_END];
	void *hw_res_hash;
	/* for hw ped res */
	spinlock_t hw_res_lock[NBL_DRACO_NEED_PED_RECORD_TYPE_END];
};

struct nbl_draco_kt_node {
	/* kt block index */
	u8 kt_block_id;
	struct list_head kt_node;
	u8 alloc_at0_cnt;
	/* kt index left by current kt block */
	u16 avail_kt_num;
	u16 avail_half_at1_num;
	u16 avail_half_at2_num;
	/* kt index pool */
	struct nbl_bitmap_mng kt_bmp_mng; /* for at0 & full kt */
	struct nbl_bitmap_mng kt_bmp_mng_at1;
	struct nbl_bitmap_mng kt_bmp_mng_at2;

	/* kt index info */
	struct nbl_draco_kt_idx_info kt_idx_info[NBL_DRACO_HALF_KT_PER_BLOCK_CNT];
};

struct nbl_draco_kt_mgt {
	struct list_head kt_half_list;
	struct list_head kt_full_list;
	struct nbl_flow_tab_hash_info kt_hash;

	struct nbl_draco_kt_node *cur_node[NBL_DRACO_MAX_PROFILE_NUM];
	/* [0, NBL_DRACO_MAX_PROFILE_NUM) for per profile, the last postion for all profiles */
	u8 kt_block_alloc_stat[NBL_DRACO_MAX_PROFILE_NUM + 1];

	struct mutex kt_lock; /* for global use */
	struct mutex full_kt_lock; /* for full kt use */
	struct mutex half_kt_lock; /* for half kt use */
};

struct nbl_draco_flow_hw_stats {
	/* used PP entries */
	u32 pp_flow_rule_count;
	u32 pp_tcam_entry;
	u32 used_pp0_entry;
	u32 used_pp1_entry;
	u32 pid_entries[NBL_DRACO_MAX_PROFILE_NUM];
	u32 lid_entries[NBL_DRACO_LOOKUP_ID_NUM];

	/* acl related */
	u32 acl_flow_rule_count;
	u32 used_acl0_entry;
	u32 used_acl1_entry;

	/* extra hardware related stats */
	u32 kt_count;
	u32 mcc_count;
	u32 mirror_count;
	u32 ped_ipv6_count;
	u32 ped_mac_count;
	u32 encap_count;
	u32 decap_count;
};

struct nbl_flow_acl_mgt {
	struct nbl_profile_msg profile_msg[NBL_ACL_PROFILE_NUM];
	struct nbl_profile_assoc_graph profile_graph[NBL_ACL_GRAPH_NUM];
	u32 profile_graph_count;

	/* acl accosciate index */
	struct nbl_bitmap_mng *assoc_mng;
	/* acl spec stat index */
	struct nbl_bitmap_mng *spec_mng;
	/* acl entry index */
	struct nbl_bitmap_mng *entry_mng[NBL_ACL_PROFILE_CNT];
	/* acl hash */
	struct nbl_hash_mng *acl_hash[NBL_ACL_PROFILE_CNT];
	/* acl parameters, for hardware configure */
	struct nbl_acl_cfg_param_full acl_cfg[NBL_ACL_PROFILE_CNT];
	void *flow_mgt;
};

struct nbl_draco_flow_mgt {
	struct nbl_resource_mgt *res_mgt;
	struct nbl_draco_kt_mgt kt_mgt;
	/* hw related resource */
	struct nbl_draco_flow_hw_res_mgt hw_mgt;

	/* draco hw related stats */
	spinlock_t stats_lock;
	struct nbl_draco_flow_hw_stats stats;

	/* tcam flow list */
	spinlock_t tcam_lock;
	bool tcam_eviction_enabled;
	struct nbl_profile_offload_msg tcam_data_info[NBL_DRACO_TCAM_SPEC];

	/* for ACL */
	struct nbl_flow_acl_mgt *acl_mgt;

	/* for assoc_table */
	struct nbl_bitmap_mng assoc_table_mng;

	/* for ped */
	struct nbl_tc_pedit_res_info pedit_res[NBL_DRACO_PED_MAX];
	struct nbl_flow_tab_hash_info ped_hash[NBL_DRACO_NEED_RESOURCE_TYPE_END];
	struct mutex ped_lock[NBL_DRACO_PED_MAX]; /* for ped */
};

enum last_vlan_type {
	VLAN_NULL,
	VLAN_POP_INNER,
	VLAN_POP_OUTER,
	VLAN_PUSH_INNER,
	VLAN_PUSH_OUTER,
	VLAN_REPLACE_INNER,
	VLAN_REPLACE_OUTER,
};

enum nbl_flow_vlan_type {
	NBL_FLOW_VLAN_TYPE_VLAN = 0,
	NBL_FLOW_VLAN_TYPE_QINQ,
	NBL_FLOW_VLAN_TYPE_QINQ1,
	NBL_FLOW_VLAN_TYPE_QINQ2,
};

enum nbl_draco_vlan_op {
	NBL_FLOW_VLAN_NULL = 0,
	/* POP */
	NBL_FLOW_VLAN_POP = 1,
	/* POP->POP */
	NBL_FLOW_VLAN_POP2 = 3,
	/* POP->POP->PUSH */
	NBL_FLOW_VLAN_REP_IVLAN_POP = 5,
	/* POP->PUSH */
	NBL_FLOW_VLAN_REP_OVLAN = 7,
	/* PUSH */
	NBL_FLOW_VLAN_PUSH = 9,
	/* POP->POP->PUSH->PUSH */
	NBL_FLOW_VLAN_REP_BOTH = 12,
	/* PUSH->PUSH */
	NBL_FLOW_VLAN_PUSH2 = 13,
	/* POP->PUSH->PUSH */
	NBL_FLOW_VLAN_PUSH_REP = 14,
	/* rsv use */
	NBL_FLOW_VLAN_RSV,
};

enum nbl_cmdq_fem_opcode {
	NBL_CMDQ_FEM_OPCODE_TBLADD,
	NBL_CMDQ_FEM_OPCODE_TBLREAD,
	NBL_CMDQ_FEM_OPCODE_TBLWRITE,
	NBL_CMDQ_FEM_OPCODE_KTALLOC,
	NBL_CMDQ_FEM_OPCODE_KTFREE,
	NBL_CMDQ_FEM_OPCODE_TBLLKP,
};

enum nbl_cmdq_fem_table {
	NBL_CMDQ_FEM_TBL = 0,
	NBL_CMDQ_FEM_TBL_PT = 0,
	NBL_CMDQ_FEM_TBL_HT,
	NBL_CMDQ_FEM_TBL_KTAT,
	NBL_CMDQ_FEM_TBL_OFTAD,
	NBL_CMDQ_FEM_TBL_DFT,
	NBL_CMDQ_FEM_TBL_KTBLK_PF,
	NBL_CMDQ_FEM_TBL_KTBLK,
};

enum nbl_cmdq_ped_opcode {
	NBL_CMDQ_PED_OPCODE_READ = 1,
	NBL_CMDQ_PED_OPCODE_WRITE,
};

enum nbl_cmdq_ped_table {
	NBL_CMDQ_PED_TBL_ENCAP,
	NBL_CMDQ_PED_TBL_ENCAP_VTEP,
	NBL_CMDQ_PED_TBL_MAC_REP,
	NBL_CMDQ_PED_TBL_IP_REP,
	NBL_CMDQ_PED_TBL_MIRR,
};

enum nbl_draco_tbl_to_read {
	NBL_DRACO_PROFILE_TBL_TO_READ = 0,
	NBL_DRACO_HT_TBL_TO_READ,
	NBL_DRACO_KTAT_TBL_TO_READ,
	NBL_DRACO_OFTAD_TBL_TO_READ,
	NBL_DRACO_DFT_TBL_TO_READ,
	NBL_DRACO_KT_BIND_PF_TBL_TO_READ,
	NBL_DRACO_KT_BLK_MNG_TBL_TO_READ,
};

#define NBL_KT_BLOCK_SIZE (1024)
#define NBL_KT_BLOCK_ID_MAX (64)

#define NBL_DRACO_CMD_TBLWRITE_DFT_DATALEN (9)
#define NBL_DRACO_CMD_TBLADD_LEN (76)
#define NBL_DRACO_CMD_TBLLKP_LEN (56)
#define NBL_DRACO_CMD_TBLWRITE_LEN (76)
#define NBL_DRACO_CMD_TBLWRITE_DATALEN (64)
#define NBL_DRACO_CMD_TBLREAD_LEN (20)
#define NBL_DRACO_CMD_KTBLOCK_LEN (16)
#define NBL_DRACO_CMDQ_PARAM_LEN (8)

typedef int (*__draco_action_2hw)(struct nbl_tc_flow_mgt *mgt, u32 *key,
				  struct nbl_rule_action *action,
				  union nbl_action_bits_ext *act_bits,
				  s16 *offsets);

struct nbl_draco_flow_action_2hw {
	u64 draco_action_type;
	__draco_action_2hw act_2hw;
};

#define NBL_DRACO_GET_PROF_NODE_DATA(data) ((struct nbl_flow_tnl_prof_node *)(data))
#define NBL_DRACO_GET_VTEP_NODE_DATA(data)	\
	((struct nbl_flow_tnl_vtep_node *)(((u8 *)(data)) + sizeof(struct nbl_flow_tnl_prof_node)))

int nbl_tc_flow_mgt_start_draco(struct nbl_resource_mgt *res_mgt);
int nbl_tc_flow_mgt_stop_draco(struct nbl_resource_mgt *res_mgt);

int nbl_tc_flow_flush_flow_draco(struct nbl_resource_mgt *res_mgt);

int nbl_bitmap_mng_init(struct nbl_bitmap_mng *bmp_mng, u16 size, bool use_lock,
			bool skip_zero);
void nbl_bitmap_mng_release(struct nbl_bitmap_mng *bmp_mng);
int nbl_bitmap_mng_alloc_id(struct nbl_bitmap_mng *bmp_mng, u32 *id);
void nbl_bitmap_mng_release_id(struct nbl_bitmap_mng *bmp_mng, u32 id);
void nbl_bitmap_mng_reset(struct nbl_bitmap_mng *bmp_mng);

#endif
