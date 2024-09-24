/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_HW_H_
#define _NBL_HW_H_

#include "nbl_include.h"

#define NBL_MAX_ETHERNET				(4)

#define NBL_PT_PP0					0
#define NBL_PT_LEN					3
#define NBL_TCAM_TABLE_LEN				(64)
#define NBL_MCC_ID_INVALID				U16_MAX
#define NBL_KT_BYTE_LEN					40
#define NBL_KT_BYTE_HALF_LEN				20

#define NBL_EM0_PT_PHY_UP_TUNNEL_UNICAST_L2		0
#define NBL_EM0_PT_PHY_UP_LLDP_LACP			1
#define NBL_EM0_PT_PHY_UP_UNICAST_L2			2
#define NBL_EM0_PT_PHY_DOWN_UNICAST_L2			3
#define NBL_EM0_PT_PHY_UP_MULTICAST_L2			4
#define NBL_EM0_PT_PHY_DOWN_MULTICAST_L2		5
#define NBL_EM0_PT_PHY_UP_MULTICAST_L3			6
#define NBL_EM0_PT_PHY_DOWN_MULTICAST_L3		7
#define NBL_EM0_PT_PHY_DPRBAC_IPV4			8
#define NBL_EM0_PT_PHY_DPRBAC_IPV6			9
#define NBL_EM0_PT_PHY_UL4S_IPV4			10
#define NBL_EM0_PT_PHY_UL4S_IPV6			11
#define NBL_EM0_PT_PMD_ND_UPCALL			12

#define NBL_PP0_PROFILE_ID_MIN				(0)
#define NBL_PP0_PROFILE_ID_MAX				(15)
#define NBL_PP1_PROFILE_ID_MIN				(16)
#define NBL_PP1_PROFILE_ID_MAX				(31)
#define NBL_PP2_PROFILE_ID_MIN				(32)
#define NBL_PP2_PROFILE_ID_MAX				(47)
#define NBL_PP_PROFILE_NUM				(16)

#define NBL_QID_MAP_TABLE_ENTRIES			(4096)
#define NBL_EPRO_RSS_RET_TBL_DEPTH			(8192 * 2)
#define NBL_EPRO_RSS_ENTRY_SIZE_UNIT			(16)

#define NBL_EPRO_RSS_SK_SIZE 40
#define NBL_EPRO_RSS_PER_KEY_SIZE 8
#define NBL_EPRO_RSS_KEY_NUM (NBL_EPRO_RSS_SK_SIZE / NBL_EPRO_RSS_PER_KEY_SIZE)

enum {
	NBL_HT0,
	NBL_HT1,
	NBL_HT_MAX,
};

enum {
	NBL_KT_HALF_MODE,
	NBL_KT_FULL_MODE,
};

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
};

enum nbl_chan_flow_mode {
	NBL_FLOW_READ_MODE = 0,
	NBL_FLOW_WRITE_MODE,
	NBL_FLOW_READ_OR_WRITE_MODE,
	NBL_FLOW_READ_AND_WRITE_MODE,
	NBL_FLOW_READ_OR_AND_WRITE_MODE,
};

#define SFF8636_TRANSMIT_FIBER_850nm_VCSEL	(0x0)
#define SFF8636_TRANSMIT_FIBER_1310nm_VCSEL	(0x1)
#define SFF8636_TRANSMIT_FIBER_1550nm_VCSEL	(0x2)
#define SFF8636_TRANSMIT_FIBER_1310nm_FP	(0x3)
#define SFF8636_TRANSMIT_FIBER_1310nm_DFB	(0x4)
#define SFF8636_TRANSMIT_FIBER_1550nm_DFB	(0x5)
#define SFF8636_TRANSMIT_FIBER_1310nm_EML	(0x6)
#define SFF8636_TRANSMIT_FIBER_1550nm_EML	(0x7)
#define SFF8636_TRANSMIT_FIBER_OTHER		(0x8)
#define SFF8636_TRANSMIT_FIBER_1490nm_DFB	(0x9)
#define SFF8636_TRANSMIT_COPPER_UNEQUA		(0xa)
#define SFF8636_TRANSMIT_COPPER_PASSIVE_EQUALIZED	(0xb)
#define SFF8636_TRANSMIT_COPPER_NEAR_FAR_END		(0xc)
#define SFF8636_TRANSMIT_COPPER_FAR_END			(0xd)
#define SFF8636_TRANSMIT_COPPER_NEAR_END		(0xe)
#define SFF8636_TRANSMIT_COPPER_LINEAR_ACTIVE		(0xf)

#endif
