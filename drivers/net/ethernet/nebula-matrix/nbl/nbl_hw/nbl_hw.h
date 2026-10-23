/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_HW_H_
#define _NBL_HW_H_

#include "nbl_include.h"

#define NBL_MAX_ETHERNET				(4)

#define NBL_PT_PP0					0
#define NBL_PT_PP1					1
#define NBL_PT_LEN					3
#define NBL_MAX_TCAM_ID					(63)
#define NBL_TCAM_TABLE_LEN				(64)
#define NBL_MCC_ID_INVALID				U16_MAX
#define NBL_KT_BYTE_LEN					40
#define NBL_KT_BYTE_HALF_LEN				20

#define NBL_EM0_PT_PHY_UP_TUNNEL_L2			0
#define NBL_EM0_PT_PHY_UP_L2				1
#define NBL_EM0_PT_PHY_DOWN_L2				2
#define NBL_EM0_PT_PHY_UP_LLDP_LACP			3
#define NBL_EM0_PT_PMD_ND_UPCALL			4
#define NBL_EM0_PT_PHY_L2_UP_MULTI_MCAST		5
#define NBL_EM0_PT_PHY_L3_UP_MULTI_MCAST		6
#define NBL_EM0_PT_PHY_L2_DOWN_MULTI_MCAST		7
#define NBL_EM0_PT_PHY_L3_DOWN_MULTI_MCAST		8
#define NBL_EM0_PT_PHY_DPRBAC_IPV4			9
#define NBL_EM0_PT_PHY_DPRBAC_IPV6			10
#define nbl_em0_pt_phy_ul4s_ipv4			11
#define nbl_em0_pt_phy_ul4s_ipv6			12
#define NBL_EM1_PT_PHY_ECN_COUNT			5
#define NBL_EM1_PT_PHY_ECN				3

#define NBL_PP0_PROFILE_ID_MIN				(0)
#define NBL_PP0_PROFILE_ID_MAX				(15)
#define NBL_PP1_PROFILE_ID_MIN				(16)
#define NBL_PP1_PROFILE_ID_MAX				(31)
#define NBL_PP2_PROFILE_ID_MIN				(32)
#define NBL_PP2_PROFILE_ID_MAX				(47)
#define NBL_PP_PROFILE_NUM				(16)

#define NBL_QID_MAP_TABLE_ENTRIES			(4096)
#define NBL_EPRO_PF_RSS_RET_TBL_DEPTH			(4096)
#define NBL_EPRO_RSS_RET_TBL_DEPTH			(8192 * 2)
#define NBL_EPRO_RSS_ENTRY_SIZE_UNIT			(16)
#define NBL_EPRO_RSS_ENTRY_SIZE_UNIT_DRACO		(32)

#define NBL_EPRO_PF_RSS_RET_TBL_COUNT			(512)
#define NBL_EPRO_PF_RSS_ENTRY_SIZE			(5)

#define NBL_EPRO_RSS_ENTRY_MAX_COUNT			(512)
#define NBL_EPRO_RSS_ENTRY_MAX_SIZE			(4)

#define NBL_EPRO_RSS_SK_SIZE 40
#define NBL_EPRO_RSS_PER_KEY_SIZE 8
#define NBL_EPRO_RSS_KEY_NUM (NBL_EPRO_RSS_SK_SIZE / NBL_EPRO_RSS_PER_KEY_SIZE)

enum {
	NBL_HT0,
	NBL_HT1,
	NBL_HT_MAX,
};

enum {
	NBL_OFT0,
	NBL_OFT1,
	NBL_OFT_MAX,
};

enum {
	NBL_KT_HALF_MODE,
	NBL_KT_FULL_MODE,
};

enum nbl_next_stg_id {
	NBL_NEXT_STAGE_INIT	= 0,
	NBL_NEXT_STAGE_PP0	= 1,
	NBL_NEXT_STAGE_PP1	= 2,
	NBL_NEXT_STAGE_ACL0	= 3,
	NBL_NEXT_STAGE_ACL1	= 4,
	NBL_NEXT_STAGE_RSV	= 5,
	NBL_NEXT_STAGE_EPRO	= 6,
	NBL_NEXT_STAGE_PED	= 7,
};

enum nbl_pp_type {
	NBL_PP_TYPE_0,
	NBL_PP_TYPE_1,
	NBL_PP_TYPE_2,
	NBL_PP_TYPE_MAX,
};

enum nbl_pp_at_type {
	NBL_AT_TYPE_0,
	NBL_AT_TYPE_1,
	NBL_AT_TYPE_2,
	NBL_AT_TYPE_MAX,
};

enum nbl_pp_fc_type {
	NBL_FC_COMMON_TYPE,
	NBL_FC_SPEC_TYPE,
	NBL_FC_TYPE_MAX,
};

enum nbl_counter_type {
	NBL_FLOW_WIDTH_72_COUNTER = 0,
	NBL_FLOW_WIDTH_144_COUNTER,
	NBL_FLOW_SPEC_COUNTER,
	NBL_FLOW_CAR_DROP_COUNTER,
};

#define NBL_FC_TYPE_CNT 2

#pragma pack(1)
union nbl_base_action_bits {
	struct {
		u8 VLAN_OP:4;
	#define BASE_ACTION_SET_ACL_UDF_CAR_MIRR        (3)
	#define BASE_ACTION_SET_IEPRO_UDF_MIRROR        (7)
		u8 SET_UDF:3;
		u8 SET_DEST:1;
	} baseab;

	u8 data;
};

union sport_action {
	struct {
		u16 eth_id:2;
		u16 lag_id:1;
		u16 lag_vld:1;
		u16 rsv:7;
	#define SPORT_DIR_TX			(0)
	#define SPORT_DIR_RX			(1)
		u16 dir:1;
		u16 rsv1:1;
		u16 sw_id:2;
		u16 phy_flag:1;
	} up;

	struct {
		u16 vsi_id:9;
	#define SPORT_CPU_FWD_NO		(0)
	#define SPORT_CPU_FWD_YES		(1)
		u16 cpu_fwd:1;
	#define SPORT_RDMA_NO			(0)
	#define SPORT_RDMA_YES			(1)
		u16 rdma:1;
	#define SPORT_DIR_TX			(0)
	#define SPORT_DIR_RX			(1)
		u16 dir:1;
		u16 rsv1:1;
		u16 sw_id:2;
	#define SPORT_PHY_FLAG_NO		(0)
	#define SPORT_PHY_FLAG_YES		(1)
		u16 phy_flag:1;
	} down;

	u16 data;
};

union dport_action {
	struct {
		u16 eth_id:2;
		u16 lag_id:1;
		u16 lag_vld:1;
		u16 rsv:5;
	#define DPORT_OTHER_TYPE_ETH		(0)
	#define DPORT_OTHER_TYPE_MC		(1)
	#define DPORT_OTHER_TYPE_DROP		(2)
	#define DPORT_OTHER_TYPE_INVALID	(3)
		u16 other_type:2;
	#define DPORT_DIR_RX			(0)
	#define DPORT_DIR_OTHER			(1)
		u16 dir:1;
		u16 strip_act:1;
		u16 next_stg:3;
	} down;

	struct {
		u16 vsi_id:9;
		u16 DQ_V:1;
		u16 rsv:1;
	#define DPORT_DIR_RX			(0)
	#define DPORT_DIR_OTHER			(1)
		u16 dir:1;
		u16 strip_act:1;
		u16 next_stg:3;
	} up;

	struct {
		u16 mgid:9;
	#define DPORT_OTHER_TYPE_ETH		(0)
	#define DPORT_OTHER_TYPE_MC		(1)
	#define DPORT_OTHER_TYPE_DROP		(2)
	#define DPORT_OTHER_TYPE_INVALID	(3)
		u16 other_type:2;
	#define DPORT_DIR_RX			(0)
	#define DPORT_DIR_OTHER			(1)
		u16 dir:1;
		u16 strip_act:1;
		u16 next_stg:3;
	} mcc;

	struct {
		u16 drop_code:9;
	#define DPORT_OTHER_TYPE_ETH		(0)
	#define DPORT_OTHER_TYPE_MC		(1)
	#define DPORT_OTHER_TYPE_DROP		(2)
	#define DPORT_OTHER_TYPE_INVALID	(3)
		u16 other_type:2;
	#define DPORT_DIR_RX			(0)
	#define DPORT_DIR_OTHER			(1)
		u16 dir:1;
		u16 strip_act:1;
		u16 next_stg:3;
	} drop;

	u16 data;
};

union dq_info_action {
	struct {
		u16 loc_qid:7;
		u16 mode:2;
	#define DQ_INFO_MODE_PORT_QUEUE_GROUP_RSS	(0)
	#define DQ_INFO_MODE_LOCAL_QUEUE_ID		(1)
	#define DQ_INFO_MODE_SUB_QUEUE_GROUP_0		(2)
	#define DQ_INFO_MODE_SUB_QUEUE_GROUP_1		(3)
		u16 rsv:7;
	} dq_info;

	u16 data;
};

union nbl_base_action_datas {
	struct {
		u16 resreved0;
		u16 resreved1;
		union dq_info_action dq;
		union dport_action dport;
	};

	u64 data;

	u32 u32_arr[2];
};

#pragma pack()

#pragma pack(1)
union nbl_action_data {
	struct clear_flag_act {
		u16 clear_flag:8;
		u16 start_offset:5;
		u16 rsv:1;
		u16 identify:2;
	#define NBL_CLEAR_FLAGS_IDENTIFY	(0)
	} clear_flag;

	struct set_flag_act {
		u16 set_flag:8;
		u16 start_offset:5;
		u16 rsv:1;
		u16 identify:2;
	#define NBL_SET_FLAGS_IDENTIFY	(1)
	} set_flag;

	struct set_fwd_type_act {
		u16 next_stg:4;
		u16 next_stg_vld:1;
		u16 fwd_type:3;
		u16 fwd_type_vld:1;
		u16 cos:3;
		u16 set_cos_vld:1;
		u16 rsv:1;
		u16 identify:2;
	#define NBL_SET_FWD_TYPE_IDENTIFY	(2)
	} set_fwd_type;

	/* FLOW ACTION */
	struct flow_id_act {
	#define NBL_FLOW_IDX_MAX_FLOW_ID	(65535)
		u16 flow_id;
	} flow_idx;

	struct rss_id_act {
		u16 rss_id:10;
		u16 rss_tc_en:1;
		u16 rsv:5;
	} rss_idx;

	struct port_car_act {
		u16 car_id:10;
		u16 rsv:6;
	} port_car;

	struct flow_car_act {
		u16 car_id:12;
		u16 rsv:4;
	} flow_car;

	struct cascade_act_act {
		u16 table_id;
	} cascade_act;

	struct mirror_id_act {
		u16 mirror_id:4;
		u16 mirror_mode:2;
	#define NBL_MIRROR_MODE_IN		(0)
	#define NBL_MIRROR_MODE_FLOW		(1)
	#define NBL_MIRROR_MODE_OUT		(2)
		uint32_t rsv:10;
	} mirror_idx;

	union dport_act {
		struct {
			/* port_type = SET_DPORT_TYPE_ETH_LAG, set the eth and lag field. */
			u16 dport_info:10;
			u16 dport_type:2;
		#define FWD_DPORT_TYPE_ETH		(0)
		#define FWD_DPORT_TYPE_LAG		(1)
		#define FWD_DPORT_TYPE_VSI		(2)
			u16 dport_id:4;
		#define FWD_DPORT_ID_HOST_TLS		(0)
		#define FWD_DPORT_ID_ECPU_TLS		(1)
		#define FWD_DPORT_ID_HOST_RDMA		(2)
		#define FWD_DPORT_ID_ECPU_RDMA		(3)
		#define FWD_DPORT_ID_EMP		(4)
		#define FWD_DPORT_ID_BMC		(5)
		#define FWD_DPORT_ID_LOOP_BACK		(7)
		#define FWD_DPORT_ID_ETH0		(8)
		#define FWD_DPORT_ID_ETH1		(9)
		#define FWD_DPORT_ID_ETH2		(10)
		#define FWD_DPORT_ID_ETH3		(11)
		} fwd_dport;

		struct {
			/* port_type = SET_DPORT_TYPE_ETH_LAG, set the eth and lag field. */
			u16 eth_id:2;
			u16 lag_id:2;
			u16 eth_vld:1;
			u16 lag_vld:1;
			u16 rsv:4;
			u16 port_type:2;
			u16 next_stg_sel:2;
			u16 upcall_flag:2;
		} down;

		struct {
			/* port_type = SET_DPORT_TYPE_VSI_HOST and SET_DPORT_TYPE_VSI_ECPU,
			 * set the port_id field as the vsi_id.
			 * port_type = SET_DPORT_TYPE_SP_PORT, set the port_id as the defined
			 * PORT_TYPE_SP_*.
			 */
			u16 port_id:10;
		#define PORT_TYPE_SP_DROP		(0x3FF)
		#define PORT_TYPE_SP_GLB_LB		(0x3FE)
		#define PORT_TYPE_SP_BMC		(0x3FD)
		#define PORT_TYPE_SP_EMP		(0x3FC)
			u16 port_type:2;
		#define SET_DPORT_TYPE_VSI_HOST		(0)
		#define SET_DPORT_TYPE_VSI_ECPU		(1)
		#define SET_DPORT_TYPE_ETH_LAG		(2)
		#define SET_DPORT_TYPE_SP_PORT		(3)
			u16 next_stg_sel:2;
		#define NEXT_STG_SEL_NONE		(0)
		#define NEXT_STG_SEL_ACL_S0		(1)
		#define NEXT_STG_SEL_EPRO		(2)
		#define NEXT_STG_SEL_BYPASS		(3)
			u16 upcall_flag:2;
		#define AUX_KEEP_FWD_TYPE		(0)
		#define AUX_FWD_TYPE_NML_FWD		(1)
		#define AUX_FWD_TYPE_UPCALL		(2)
		} up;
	} dport;

	struct dqueue_act {
		u16 que_id:11;
		u16 rsv:5;
	} dqueue;

	struct mcc_id_act {
		u16 mcc_id:13;
		u16 pri:1;
	#define NBL_MCC_PRI_HIGH		(0)
	#define NBL_MCC_PRI_LOW			(1)
		uint32_t rsv:2;
	} mcc_idx;

	struct vni_id_act {
		u16 vni_id;
	} vni_idx;

	struct stat_flow_id_act {
		u16 stat_flow_id:11;
		u16 rsv:5;
	} stat_flow_idx;

	struct prbac_id_act {
		u16 prbac_id;
	} prbac_idx;

	struct sec_id_act {
		u16 rsv:4;
		u16 sec_id:11;
		u16 vld:1;
	} sec_idx;

	struct dp_hash_act {
		u16 dp_hash;
	} dp_hash_idx;

	struct pri_mdf_dscp_act {
		u16 dscp:6;
		u16 i_ip_flag:1;
		u16 o_ip_flag:1;
		u16 off_sel:1;
	#define NBL_DSCP_MDF_OFF_SEL_IPV4		(0)
	#define NBL_DSCP_MDF_OFF_SEL_IPV6		(1)
		u16 rsv:1;
		u16 dscp_flag:1;
		u16 rsv1:5;
	} pri_mdf_dscp;

	struct pri_mdf_vlan_act {
		u16 pri:3;
		u16 rsv0:3;
		u16 i_cvlan_flag:1;
		u16 i_svlan_flag:1;
		u16 o_cvlan_flag:1;
		u16 o_svlan_flag:1;
		u16 rsv1:6;
	} pri_mdf_vlan;

	struct ttl_mdf_act {
		u16 ttl_value:8;
		u16 ttl_sub1_flag:1;
		u16 rsv:7;
	} ttl_mdf;

	struct vlan_mdf_act {
		u16 vlan_value;
	} vlan_mdf;

	struct dscp_mdf_act {
		u16 ecn_value:2;
		u16 dscp_value:6;
		u16 ecn_en:1;
		u16 dscp_en:1;
		u16 rsv:6;
	} dscp_mdf;

	struct index_value_act {
		u16 index;
	} index_value;

	struct set_aux_act {
		u16 nstg_val:4;
		u16 nstg_vld:1;
		u16 ftype_val:3;
		u16 ftype_vld:1;
		u16 pkt_cos_val:3;
		u16 pcos_vld:1;
		u16 rsv:1;
	#define NBL_SET_AUX_CLR_FLG			(0)
	#define NBL_SET_AUX_SET_FLG			(1)
	#define NBL_SET_AUX_SET_AUX			(2)
		u16 sub_id:2;
	} set_aux;

	u16 data;
};

struct nbl_tnl_encap_data {
	u8 vni[3];
	union {
		struct {
			u16 encap_id:12;
			u16 rsv:2;
			u16 udp_enc:1;
			u16 untag_enc:1;
		};
		u16 u16_encap_data;
	};
};

#pragma pack()

enum nbl_chan_flow_rule_type {
	NBL_FLOW_EPRO_ECPVPT_REG = 0,
	NBL_FLOW_EPRO_ECPIPT_REG,
	NBL_FLOW_DPED_TAB_TNL_REG,
	NBL_FLOW_DPED_REPLACE,
	NBL_FLOW_UPED_REPLACE,
	NBL_FLOW_DPED_MIRROR_TABLE,
	NBL_FLOW_DPED_MIR_CMD_0_TABLE,
	NBL_FLOW_EPRO_MT_REG,
	NBL_FLOW_EM0_TCAM_TABLE_REG,
	NBL_FLOW_EM1_TCAM_TABLE_REG,
	NBL_FLOW_EM2_TCAM_TABLE_REG,
	NBL_FLOW_EM0_AD_TABLE_REG,
	NBL_FLOW_EM1_AD_TABLE_REG,
	NBL_FLOW_EM2_AD_TABLE_REG,
	NBL_FLOW_IPRO_UDL_PKT_FLT_DMAC_REG,
	NBL_FLOW_IPRO_UDL_PKT_FLT_CTRL_REG,
	NBL_FLOW_ACTION_RAM_TBL,
	NBL_FLOW_MCC_TBL_REG,
	NBL_FLOW_EPRO_EPT_REG,
	NBL_FLOW_IPRO_UP_SRC_PORT_TBL_REG,
	NBL_FLOW_UCAR_FLOW_REG,
	NBL_FLOW_EPRO_VPT_REG,
	NBL_FLOW_UCAR_FLOW_TIMMING_ADD_ADDR,
	NBL_FLOW_SHAPING_GRP_TIMMING_ADD_ADDR,
	NBL_FLOW_SHAPING_GRP_REG,
	NBL_FLOW_DSCH_VN_SHA2GRP_MAP_TBL_REG,
	NBL_FLOW_DSCH_VN_GRP2SHA_MAP_TBL_REG,
	NBL_FLOW_SHAPING_DPORT_TIMMING_ADD_ADDR,
	NBL_FLOW_SHAPING_DPORT_REG,
	NBL_FLOW_DSCH_PSHA_EN_ADDR,
	NBL_FLOW_UCAR_FLOW_4K_REG,
	NBL_FLOW_UCAR_FLOW_4K_TIMMING_ADD_ADDR,
	NBL_FLOW_SHAPING_NET_TIMMING_ADD_ADDR,
	NBL_FLOW_SHAPING_NET_REG,
	NBL_FLOW_DSCH_VN_NET2SHA_MAP_TBL_REG,
	NBL_FLOW_DSCH_VN_SHA2NET_MAP_TBL_REG,
	NBL_FLOW_UCAR_CAR_CTRL_ADDR,
	NBL_FLOW_UCAR_GREEN_CELL_ADDR,
	NBL_FLOW_UCAR_GREEN_PKT_ADDR,
	NBL_FLOW_UPED_VSI_TYPE_REG,
	NBL_FLOW_DPED_VSI_TYPE_REG,
};

enum nbl_chan_flow_mode {
	NBL_FLOW_READ_MODE = 0,
	NBL_FLOW_WRITE_MODE,
	NBL_FLOW_READ_OR_WRITE_MODE,
	NBL_FLOW_READ_AND_WRITE_MODE,
	NBL_FLOW_READ_OR_AND_WRITE_MODE,
};

struct nbl_macvlan_param {
	u8 mac[ETH_ALEN];
	u16 vlan_id;
	u16 flow_id;
	u8 eth_id;
};

enum nbl_macvlan_modify_type {
	NBL_MACVLAN_MODIFY_RDMABYPASS = 1,
};

struct nbl_macvlan_modify_param {
	enum nbl_macvlan_modify_type type;
	u32 value;
};

enum nbl_board_type_enum {
	NBL_BOOTIS_BOARD_TYPE_DF200_COMMON	= 0x00020605,
	NBL_BOOTIS_BOARD_TYPE_DF200_VM		= 0x00020606,
	NBL_BOOTIS_BOARD_TYPE_RNIC400_SINGLE	= 0x00020801,
	NBL_BOOTIS_BOARD_TYPE_RNIC400_DUAL	= 0x00020802,
	NBL_BOOTIS_BOARD_TYPE_RNIC2X100		= 0x00020803,
	NBL_BOOTIS_BOARD_TYPE_RNIC400_QUAD	= 0x00020804,
	NBL_BOOTIS_BOARD_TYPE_RNIC400_DUAL_MP	= 0x00020805,
};

enum nbl_get_eth_statistics_type {
	NBL_GET_ETH_STATIS_LEN		= 1,
	NBL_GET_ETH_STATIS_STRING,
	NBL_GET_ETH_STATIS_VALUE,
};

struct nbl_eth_statistics_info {
	const char *descp;
	const u64 *base_addr;
	const u32 offset;
	const u8 is_64bit;
};

//mac len 14, ip len 20, l4 len, ipv4,tcp
#define NBL_TX_DEFAULT_HDR_LEN	(0x14A7)
#define NBL_TSO_OFFSET		(14)
struct nbl_tx_extend_head_leonis {
	/* DW0 */
	u32 mac_len :5;
	u32 ip_len :5;
	u32 l4_len :4;
	u32 l4_type :2;
	u32 inner_ip_type :2;
	u32 external_ip_type :2;
	u32 external_ip_len :5;
	u32 l4_tunnel_type :2;
	u32 l4_tunnel_len :5;
	/* DW1 */
#define NBL_TX_LEONIS_MSS_OFFSET	17
#define NBL_TX_LEONIS_TLS_ID_OFFSET	0
#define NBL_TX_LEONIS_TLS_FLAG_OFFSET	10
	u32 l4s_sid :10;
	u32 l4s_sync_ind :1;
	u32 l4s_redun_ind :1;
	u32 l4s_redun_head_ind :1;
	u32 l4s_hdl_ind :1;
	u32 l4s_pbrac_mode :1;
	u32 rsv0 :2;
	u32 mss :14;
	u32 tso :1;
	/* DW2 */
#define NBL_TX_LEONIS_FWD_OFFSET	24
#define NBL_TX_LEONIS_DPORT_OFFSET	21
#define NBL_TX_LEONIS_DPORT_ID_OFFSET	11
#define NBL_TX_LEONIS_CSUM_OFFSET	27
	/* if dport = NBL_TX_DPORT_ETH; dport_info = 0
	 * if dport = NBL_TX_DPORT_HOST; dport_info = host queue id
	 * if dport = NBL_TX_DPORT_ECPU; dport_info = ecpu queue_id
	 */
	u32 dport_info :11;
	/* if dport = NBL_TX_DPORT_ETH; dport_id[3:0] = eth port id, dport_id[9:4] = lag id
	 * if dport = NBL_TX_DPORT_HOST; dport_id[9:0] = host vsi_id
	 * if dport = NBL_TX_DPORT_ECPU; dport_id[9:0] = ecpu vsi_id
	 */
	u32 dport_id :10;
#define NBL_TX_DPORT_ID_LAG_OFFSET	(4)
	u32 dport :3;
#define NBL_TX_DPORT_ETH		(0)
#define NBL_TX_DPORT_HOST		(1)
#define NBL_TX_DPORT_ECPU		(2)
#define NBL_TX_DPORT_EMP		(3)
#define NBL_TX_DPORT_BMC		(4)
#define NBL_TX_DPORT_EMP_DRACO		(2)
#define NBL_TX_DPORT_BMC_DRACO		(3)
	u32 fwd :2;
#define NBL_TX_FWD_TYPE_DROP		(0)
#define NBL_TX_FWD_TYPE_NORMAL		(1)
#define NBL_TX_FWD_TYPE_RSV		(2)
#define NBL_TX_FWD_TYPE_CPU_ASSIGNED	(3)
#define NBL_TX_FWD_TYPE_CPU_ASSIGNED_RSS_LAG (7)
	u32 rss_lag_en :1;
	u32 l4_csum_en :1;
	u32 l3_csum_en :1;
	u32 rsv1 :3;
} __packed;

struct nbl_tx_extend_head_df200 {
	/* DW0 */
	u32 mac_len :5;
	u32 ip_len :5;
	u32 l4_len :4;
	u32 l4_type :2;
	u32 inner_ip_type :2;
	u32 external_ip_type :2;
	u32 external_ip_len :5;
	u32 l4_tunnel_type :2;
	u32 l4_tunnel_len :5;
	/* DW1 */
#define NBL_TX_DF200_DPORT_OFFSET	12
#define NBL_TX_DF200_MSS_OFFSET		17
	u32 l4s_sid :10;
	u32 inner_l3_cs :1;
	u32 inner_l4_cs :1;
	u32 dport :3;
	u32 tag_idx :2;
	u32 mss :14;
	u32 tso :1;
	/* DW2 */
#define NBL_TX_DF200_FWD_OFFSET		24
#define NBL_TX_DF200_DPORT_ID_OFFSET	11
#define NBL_TX_DF200_CSUM_OFFSET	27
	u32 dport_info :11;
	u32 dport_id :12;
	u32 tag_en :1;
	u32 fwd :2;
	u32 rss_lag_en :1;
	u32 l4_csum_en :1;
	u32 l3_csum_en :1;
	u32 rsv1 :3;
} __packed;

struct nbl_tx_extend_head_vm_8k {
	/* DW0 */
	u32 mac_len :5;
	u32 ip_len :5;
	u32 l4_len :4;
	u32 l4_type :2;
	u32 inner_ip_type :2;
	u32 external_ip_type :2;
	u32 external_ip_len :5;
	u32 l4_tunnel_type :2;
	u32 l4_tunnel_len :5;
	/* DW1 */
#define NBL_TX_DF200_VM_DPORT_ID_OFFSET	0
#define NBL_TX_DF200_VM_MSS_OFFSET	17
	u32 dport_id :12;
	u32 rsv0:1;
	u32 inner_l3_cs :1;
	u32 inner_l4_cs :1;
	u32 tag_idx :2;
	u32 mss :14;
	u32 tso :1;
	/* DW2 */
#define NBL_TX_DF200_VM_FWD_OFFSET	24
#define NBL_TX_DF200_VM_DPORT_OFFSET	16
#define NBL_TX_DF200_VM_CSUM_OFFSET	27
	u32 dport_info :16;
	u32 dport :3;
	u32 rsv1:4;
	u32 tag_en :1;
	u32 fwd :2;
	u32 rss_lag_en :1;
	u32 l4_csum_en :1;
	u32 l3_csum_en :1;
	u32 tag_idx_hi :3;
} __packed;

struct nbl_tx_extend_head_draco {
	/* DW0 */
#define NBL_TX_DRACO_L3_LEN_OFFSET		5
#define NBL_TX_DRACO_L4_LEN_OFFSET		10
#define NBL_TX_DRACO_L4_TYPE_OFFSET		14
#define NBL_TX_DRACO_L3_TYPE_OFFSET		16
#define NBL_TX_DRACO_OUTER_L3_TYPE_OFFSET	18
#define NBL_TX_DRACO_OUTER_L3_LEN_OFFSET	20
#define NBL_TX_DRACO_TNL_LEN_OFFSET		25
	u32 mac_len :5;
	u32 ip_len :5;
	u32 l4_len :4;
	u32 l4_type :2;
	u32 inner_ip_type :2;
	u32 external_ip_type :2;
	u32 external_ip_len :5;
	u32 l4_tunnel_len :7;
	/* DW1 */
#define NBL_TX_DRACO_TLS_OFFSET		2
#define NBL_TX_DRACO_TLS_FLAG_OFFSET	17
	u32 l4_tunnel_type :2;
	u32 l4s_sid :15;
	u32 l4s_sync_ind :1;
	u32 l4s_redun_ind :1;
	u32 l4s_redun_head_ind :1;
	u32 l4s_hdl_ind :1;
	u32 l4s_pbrac_mode :1;
	u32 rsv0 :2;
	u32 acl_tag :8;
	/* DW2 */
#define NBL_TX_DRACO_FWD_OFFSET		20
#define NBL_TX_DRACO_DPORT_OFFSET	18
#define NBL_TX_DRACO_DPORT_ID_OFFSET	9
#define NBL_TX_DRACO_INNER_CSUM_OFFSET	23
#define NBL_TX_DRACO_CSUM_OFFSET	25
	u32 dport_info :9;
	u32 dport_id :9;
	u32 dport :2;
	u32 fwd :2;
	u32 rss_lag_en :1;
	u32 inner_l4_csum_en :1;
	u32 inner_l3_csum_en :1;
	u32 outer_l4_csum_en :1;
	u32 outer_l3_csum_en :1;
	u32 sc_idx :3;
	u32 sc_vld :1;
	u32 mc_en :1;
	/* DW3 */
#define NBL_TX_VLAN_TYPE_OFFSET		16
#define NBL_TX_VLAN_VID_OFFSET		17
	u32 vlan_tag :16;
	u32 vlan_etype :1;
#define NBL_TX_VLAN_ETYPE_0X8100	(0)
#define NBL_TX_VLAN_ETYPE_0X88A8	(1)
	u32 vlan_vld :1;
	u32 rsv1 :14;
} __packed;

struct nbl_rx_extend_head_leonis {
	/* DW0 */
	/* 0x0:eth, 0x1:host, 0x2:ecpu, 0x3:emp, 0x4:bcm */
	u32 sport :3;
	u32 dport_info :11;
	/* sport = 0, sport_id[3:0] = eth id,
	 * sport = 1, sport_id[9:0] = host vsi_id,
	 * sport = 2, sport_id[9:0] = ecpu vsi_id,
	 */
	u32 sport_id :10;
	/* 0x0:drop, 0x1:normal, 0x2:cpu upcall */
	u32 fwd :2;
	u32 rsv0 :6;
	/* DW1 */
	u32 error_code :6;
	u32 ptype :10;
	u32 profile_id :4;
	u32 checksum_status :1;
	u32 rsv1 :1;
	u32 l4s_sid :10;
	/* DW2 */
	u32 rsv3 :2;
	u32 l4s_hdl_ind :1;
	u32 l4s_tcp_offset :14;
	u32 l4s_resync_ind :1;
	u32 l4s_check_ind :1;
	u32 l4s_dec_ind :1;
	u32 rsv2 :4;
	u32 num_buffers :8;
} __packed;

struct nbl_rx_extend_head_draco {
	/* DW0 */
	/* 0x0:eth, 0x1:host, 0x2:emp, 0x3:bmc */
	u32 sport :2;
	u32 dport_info :9;
	/* sport = 0, sport_id[3:0] = eth id,
	 * sport = 1, sport_id[9:0] = host vsi_id,
	 */
	u32 sport_id :9;
	u32 ptype :8;
	#define NBL_CHECKSUM_REPORT_L4_CHECKSUM		(0x5)
	#define NBL_CHECKSUM_CHECKED			(0x10)
	/* bit0:indicate tnl-inner or un-tnl l4 csum result, 0 is success, 1 is failed
	 * bit1:indicate tnl-inner or un-tnl l3 csum result, 0 is success, 1 is failed
	 * bit2:indicate tnl-outer l4 csum result, 0 is success, 1 is failed
	 * bit3:indicate tnl-outer l3 csum result, 0 is success, 1 is failed
	 */
	u32 checksum_report :4;
	/* DW1 */
	u32 checksum_status :1;
	u32 rsv0 :2;
	u32 l4s_sid :11;
	u32 l4s_hdl_ind :1;
	u32 l4s_tcp_offset :14;
	u32 l4s_resync_ind :1;
	u32 l4s_check_ind :1;
	u32 l4s_dec_ind :1;
	/* DW2 */
	u32 error_code :4;
	u32 sc_idx:3;
	u32 sc_vld:1;
	u32 outer_vlan_vid:12;
	u32 outer_vlan_tpid_enc:1;
	u32 outer_vlan_pri:3;
	u32 num_buffers :8;
	/* DW3 */
	u32 rss_hash;
} __packed;

struct nbl_rx_extend_head_df200 {
	/* DW0 */
	/* 0x0:eth, 0x1:host, 0x2:ecpu, 0x3:emp, 0x4:bcm */
	u32 sport :3;
	/* sport = 1, host uvn received queue_id,
	 * sport = 2, ecpu uvn received queue_id,
	 */
	u32 sport_info :12;
	/* sport = 0, indicate eth id,
	 * sport = 1, indicate host vsi id,
	 * sport = 2, indicate ecpu vsi id,
	 */
	u32 sport_id :11;
	/* 0x0:drop, 0x1:normal, 0x2:cpu upcall */
	u32 fwd :2;
	/* bit0:indicate tnl-inner or un-tnl l4 csum result, 0 is success, 1 is failed
	 * bit1:indicate tnl-inner or un-tnl l3 csum result, 0 is success, 1 is failed
	 * bit2:indicate tnl-outer l4 csum result, 0 is success, 1 is failed
	 * bit3:indicate tnl-outer l3 csum result, 0 is success, 1 is failed
	 */
	u32 checksum_report:4;
	/* DW1 */
	u32 rsv0 :6;
	u32 ptype :10;
	u32 profile_id :4;
	u32 checksum_status :1;
	u32 rsv1 :11;
	/* DW2 */
	u32 rsv3 :2;
	u32 l4s_hdl_ind :1;
	u32 rsv2 :21;
	u32 num_buffers :8;
} __packed;

struct nbl_rx_extend_head_vm_8k {
	/* DW0 */
	/* 0x0:eth, 0x1:host, 0x2:ecpu, 0x3:emp, 0x4:bcm */
	u64 sport :3;
	/* sport = 1, host uvn received queue_id,
	 * sport = 2, ecpu uvn received queue_id,
	 */
	u64 sport_info :14;
	/* sport = 0, indicate eth id,
	 * sport = 1, indicate host vsi id,
	 * sport = 2, indicate ecpu vsi id,
	 */
	u64 sport_id :11;
	/* 0x0:drop, 0x1:normal, 0x2:cpu upcall */
	u64 fwd :2;
	/* bit0:indicate tnl-inner or un-tnl l4 csum result, 0 is success, 1 is failed
	 * bit1:indicate tnl-inner or un-tnl l3 csum result, 0 is success, 1 is failed
	 * bit2:indicate tnl-outer l4 csum result, 0 is success, 1 is failed
	 * bit3:indicate tnl-outer l3 csum result, 0 is success, 1 is failed
	 */
	u64 checksum_report:4;
	/* DW1 */
	u64 rsv0 :4;
	u64 ptype :10;
	u64 profile_id :4;
	u64 checksum_status :1;
	u64 rsv1 :11;
	/* DW2 */
	u32 rsv3 :2;
	u32 l4s_hdl_ind :1;
	u32 rsv2 :21;
	u32 num_buffers :8;
} __packed;

#define NBL_RX_EXT_HDR_NUM_BUFFERS_OFFSET	(11)

struct nbl_ktls_init_payload_leonis {
	/* DW0 */
	u16 initial:1;
	u16 rsv1:7;
	u16 sync:1;
	u16 rsv2:7;
	u16 sid:10;
	u16 rsv3:6;
	/* DW1 */
	u16 rsv4;
	u16 rsv5;
	/* DWX */
	u8 rec_num[NBL_KTLS_REC_LEN];
	u8 iv[NBL_KTLS_IV_LEN];
};

struct nbl_ktls_sync_payload_leonis {
	/* DW0 */
	u16 initial:1;
	u16 rsv1:7;
	u16 sync:1;
	u16 rsv2:7;
	u16 sid:10;
	u16 rsv3:6;
	/* DW1 */
	u16 rsv4;
	u16 rsv5;
	/* DWX */
	u8 rec_num[NBL_KTLS_REC_LEN];
	__be16 redlen;
};

struct nbl_ktls_init_payload_draco {
	/* DW0 */
	u32 type:2;
	u32 rsv3:2;
	u32 sync:1;
	u32 rsv2:1;
	u32 initial:1;
	u32 rsv1:1;

	u32 hlen1:3;
	u32 rs:1;
	u32 rsv4:4;

	u32 plen1:7;
	u32 hlen2:1;

	u32 plen2:8;
	/* DWX */
	u8 rec_num[NBL_KTLS_REC_LEN];
	u8 iv[NBL_KTLS_IV_LEN];
	u8 salt[NBL_KTLS_SALT_LEN];
	u8 key[NBL_KTLS_KEY_LEN];
	u8 pad[NBL_KTLS_PAD_LEN];
};

struct nbl_ktls_sync_payload_draco {
	/* DW0 */
	u32 type:2;
	u32 rsv3:2;
	u32 sync:1;
	u32 rsv2:1;
	u32 initial:1;
	u32 rsv1:1;

	u32 rsv4:24;
	/* DWX */
	u8 rec_num[NBL_KTLS_REC_LEN];
	u8 iv[NBL_KTLS_IV_LEN];
	u8 salt[NBL_KTLS_SALT_LEN];
	u8 key[NBL_KTLS_KEY_LEN];
	__be16 redlen;
};

/* TX inner IP header type */
enum nbl_tx_iipt {
	NBL_TX_IIPT_NONE = 0x0,
	NBL_TX_IIPT_IPV6 = 0x1,
	NBL_TX_IIPT_IPV4 = 0x2,
	NBL_TX_IIPT_RSV  = 0x3
};

/* TX L4 packet type */
enum nbl_tx_l4t {
	NBL_TX_L4T_NONE = 0x0,
	NBL_TX_L4T_TCP  = 0x1,
	NBL_TX_L4T_UDP  = 0x2,
	NBL_TX_L4T_RSV  = 0x3
};

enum nbl_sff8636_device_tech_type {
	SFF8636_TRANSMIT_FIBER_850nm_VCSEL		= 0x0,
	SFF8636_TRANSMIT_FIBER_1310nm_VCSEL		= 0x1,
	SFF8636_TRANSMIT_FIBER_1550nm_VCSEL		= 0x2,
	SFF8636_TRANSMIT_FIBER_1310nm_FP		= 0x3,
	SFF8636_TRANSMIT_FIBER_1310nm_DFB		= 0x4,
	SFF8636_TRANSMIT_FIBER_1550nm_DFB		= 0x5,
	SFF8636_TRANSMIT_FIBER_1310nm_EML		= 0x6,
	SFF8636_TRANSMIT_FIBER_1550nm_EML		= 0x7,
	SFF8636_TRANSMIT_FIBER_OTHER			= 0x8,
	SFF8636_TRANSMIT_FIBER_1490nm_DFB		= 0x9,
	SFF8636_TRANSMIT_COPPER_UNEQUA			= 0xa,
	SFF8636_TRANSMIT_COPPER_PASSIVE_EQUALIZED	= 0xb,
	SFF8636_TRANSMIT_COPPER_NEAR_FAR_END		= 0xc,
	SFF8636_TRANSMIT_COPPER_FAR_END			= 0xd,
	SFF8636_TRANSMIT_COPPER_NEAR_END		= 0xe,
	SFF8636_TRANSMIT_COPPER_LINEAR_ACTIVE		= 0xf,
};

enum nbl_sfp_type {
	SFF8024_IDENTIFIER_VALUE_QSFP28	 = 0x11,
	SFF8024_IDENTIFIER_VALUE_QSFP56	 = 0x1e,
};

enum {
	NBL_ETH_SERDES_TYPE_NRZ,
	NBL_ETH_SERDES_TYPE_PAM4,
};

union nbl_mcc_lag_param {
	struct nbl_mcc_lag_info {
		u8 id;
		u8 enable;
	} __packed info;
	u16 data;
} __packed;

#define NBL_SPORT_ETH_OFFSET				8

enum {
	NBL_FD_PROFILE_IPV4 = 2,
	NBL_FD_PROFILE_L2_IPV6 = 4,
	NBL_FD_PROFILE_DEFAULT = 6,
	NBL_FD_PROFILE_MAX,
	NBL_RDMA_BOND_PROFILE_TX = 9,
	NBL_RDMA_PROFILE_RX = 10,
};

#define NBL_RDMA_RX_TCAM_ID				(15)
#define NBL_RDMA_TX_TCAM_ID				(15)
#define NBL_RDMA_MIRROR_DEPTH_BASE			(8)

struct nbl_event_link_status_update_data {
	u8 num;
	u8 eth_id[NBL_MAX_ETHERNET];
};

#endif
