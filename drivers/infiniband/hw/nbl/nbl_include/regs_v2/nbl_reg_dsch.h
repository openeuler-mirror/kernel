/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_DSCH_LAYOUT_H
#define NBL_DSCH_LAYOUT_H

#include <linux/types.h>

#define NBL_DSCH_CSCH_QLEN_TH_OFF_V2		0x0124
#define NBL_DSCH_POLL_WGT_OFF_V2		0x0128
#define NBL_DSCH_DB_TO_CSCH_EN_OFF_V2		0x0144
#define NBL_DSCH_SQ_PRI_MAP_CFG_OFF_V2		0x0160
#define NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V2		0x0164
#define NBL_DSCH_PRI03_MAP_CFG_OFF_V2		0x0168
#define NBL_DSCH_PRI47_MAP_CFG_OFF_V2		0x016c
#define NBL_DSCH_IMAP_CFG_OFF_V2		0x0170
#define NBL_DSCH_SW_DB_IN_CSCH_TH_OFF_V2	0x0188
#define NBL_DSCH_PRI03_P2S_MAP_OFF_V2(dport_id) \
	(0x0190 + 0x8 * (dport_id))
#define NBL_DSCH_PRI47_P2S_MAP_OFF_V2(dport_id) \
	(0x0194 + 0x8 * (dport_id))

#define NBL_DSCH_SW_DB_IN_CSCH_TH_OFF_V3	0x01b8
#define NBL_DSCH_CSCH_QLEN_TH_OFF_V3		0x0214
#define NBL_DSCH_POLL_WGT_OFF_V3		0x0218
#define NBL_DSCH_SQ_PRI_MAP_CFG_OFF_V3		0x0230
#define NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V3		0x0234
#define NBL_DSCH_PRI03_MAP_CFG_OFF_V3		0x0238
#define NBL_DSCH_PRI47_MAP_CFG_OFF_V3		0x023c
#define NBL_DSCH_IMAP_CFG_OFF_V3		0x0240
#define NBL_DSCH_BP_RESP_OFF			0x0244
#define NBL_DSCH_DB_TO_CSCH_EN_OFF_V3		0x024c
#define NBL_DSCH_PRI03_P2S_MAP_OFF_V3		0x0250
#define NBL_DSCH_PRI47_P2S_MAP_OFF_V3		0x0254
#define NBL_DSCH_DWRR_EN_OFF_V3			0x02e0
#define NBL_DSCH_TC_GHOST_BITMAP_OFF_V3		0x02ec
#define NBL_DSCH_STORE_UP_FC_MODE_OFF_V2	0x075c
/* multi plane en for 4pf bond, 1 enable, 0 disable */
#define NBL_DSCH_MP_EN_OFF			0x0660

#define NBL_DSCH_PSHA_EN_OFF			0x028c
#define NBL_DSCH_NET_EN_OFF_V2			0x0300
#define NBL_DSCH_NET_EN_OFF_V3			0x02a0
#define NBL_DSCH_NET_EN_REG_BITS		32

#define NBL_DSCH_N2G_CFG_TBL_OFF		0x00080000
#define NBL_DSCH_G2P_CFG_TBL_OFF		0x00084000
#define NBL_DSCH_TC_WGT_CFG_TBL_OFF		0x00088000
#define NBL_DSCH_TC_SPWRR_CFG_TBL_OFF		0x0008c000
#define NBL_DSCH_NET2SHA_MAP_TBL_OFF		0x00090000
#define NBL_DSCH_GRP2SHA_MAP_TBL_OFF		0x00094000
#define NBL_DSCH_SHA2NET_MAP_TBL_OFF		0x00098000
#define NBL_DSCH_SHA2GRP_MAP_TBL_OFF		0x0009c000
#define NBL_DSCH_DBQ_ATTR_TBL_OFF		0x000c4000
#define NBL_DSCH_TC_Q_LIST_ATTR_TBL_OFF		0x000c8000
#define NBL_DSCH_SPT_GRP_LIST_TBL_OFF		0x000d8000
#define NBL_DSCH_GRP_NET_LIST_TBL_OFF		0x000e0000
#define NBL_DSCH_VF2VSI_CFG_TBL_OFF		0x000f4000

#define NBL_DSCH_DWORD_STRIDE			0x4
#define NBL_DSCH_TC_NUM				8
#define NBL_DSCH_TC_WGT_CFG_TBL_STRIDE		0x8
#define NBL_DSCH_DBQ_ATTR_TBL_STRIDE		0x40
#define NBL_DSCH_DBQ_ATTR_TC_STRIDE		0x8
#define NBL_DSCH_TC_Q_LIST_ATTR_TBL_STRIDE	0x20
#define NBL_DSCH_TC_Q_LIST_ATTR_TC_STRIDE	0x4
#define NBL_DSCH_DBQ_ATTR_TBL_NEMPTY		0x80000000U

#define NBL_DSCH_NET_NODE_NUM			256
#define NBL_DSCH_GRP_NODE_NUM			64
#define NBL_DSCH_RNIC_TBL_MAX_DEPTH		2

#define NBL_DSCH_BP_RESP_ALL_ENABLE		0x7fff
#define NBL_DSCH_BP_RESP_DPT_DISABLE		0x7fe7
/* dscp respond to dqm bp for 4pf bond, 0xFFFFFFFF enable, 0xFFFFF0FF disable */
#define NBL_DSCH_BP_RESP_DQM_ENABLE		0xFFFFFFFF
#define NBL_DSCH_BP_RESP_DQM_DISABLE		0xFFFFF0FF

#define NBL_DSCH_REG_ADDR(base, off)		((base) + (off))
#define NBL_DSCH_TBL_ADDR(base, off, stride, id) \
	(NBL_DSCH_REG_ADDR((base), (off)) + (stride) * (id))

#define NBL_DSCH_N2G_CFG_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_N2G_CFG_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_G2P_CFG_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_G2P_CFG_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_TC_WGT_CFG_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_TC_WGT_CFG_TBL_OFF, \
			  NBL_DSCH_TC_WGT_CFG_TBL_STRIDE, (id))
#define NBL_DSCH_TC_WGT_CFG_ADDR(base, id, tc) \
	(NBL_DSCH_TC_WGT_CFG_TBL_ADDR((base), (id)) + \
	 NBL_DSCH_DWORD_STRIDE * ((tc) / 4))
#define NBL_DSCH_TC_SPWRR_CFG_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_TC_SPWRR_CFG_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_NET2SHA_MAP_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_NET2SHA_MAP_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_GRP2SHA_MAP_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_GRP2SHA_MAP_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_SHA2NET_MAP_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_SHA2NET_MAP_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_SHA2GRP_MAP_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_SHA2GRP_MAP_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_DBQ_ATTR_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_DBQ_ATTR_TBL_OFF, \
			  NBL_DSCH_DBQ_ATTR_TBL_STRIDE, (id))
#define NBL_DSCH_TC_Q_LIST_ATTR_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_TC_Q_LIST_ATTR_TBL_OFF, \
			  NBL_DSCH_TC_Q_LIST_ATTR_TBL_STRIDE, (id))
#define NBL_DSCH_SPT_GRP_LIST_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_SPT_GRP_LIST_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_GRP_NET_LIST_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_GRP_NET_LIST_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))
#define NBL_DSCH_VF2VSI_CFG_TBL_ADDR(base, id) \
	NBL_DSCH_TBL_ADDR((base), NBL_DSCH_VF2VSI_CFG_TBL_OFF, \
			  NBL_DSCH_DWORD_STRIDE, (id))

union rdma_n2g_cfg_tbl {
	u32 data[1];
	struct {
		u32 grp_id : 6;
		u32 rsv : 25;
		u32 vld : 1;
	};
};

union rdma_g2p_cfg_tbl {
	u32 data[1];
	struct {
		u32 cpu_type : 1;
		u32 port : 1;
		u32 rsv : 29;
		u32 vld : 1;
	};
};

union rdma_g2p_cfg_tbl_v2 {
	u32 data[1];
	struct {
		u32 port : 2;
		u32 rsv : 29;
		u32 vld : 1;
	};
};

union rdma_tc_wgt_cfg_tbl {
	u32 data[2];
	struct {
		u32 tc0_wgt : 8;
		u32 tc1_wgt : 8;
		u32 tc2_wgt : 8;
		u32 tc3_wgt : 8;
		u32 tc4_wgt : 8;
		u32 tc5_wgt : 8;
		u32 tc6_wgt : 8;
		u32 tc7_wgt : 8;
	};
};

union rdma_tc_spwrr_cfg_tbl {
	u32 data[1];
	struct {
		u32 tc_spwrr : 8;
		u32 rsv : 24;
	};
};

union rdma_net2sha_map_tbl {
	u32 data[1];
	struct {
		u32 net_shaping_id : 11;
		u32 rsv : 20;
		u32 vld : 1;
	};
};

union rdma_net2sha_map_tbl_v2 {
	u32 data[1];
	struct {
		u32 net_shaping_id : 9;
		u32 rsv : 22;
		u32 vld : 1;
	};
};

union rdma_grp2sha_map_tbl {
	u32 data[1];
	struct {
		u32 grp_shaping_id : 8;
		u32 rsv : 23;
		u32 vld : 1;
	};
};

union rdma_grp2sha_map_tbl_v2 {
	u32 data[1];
	struct {
		u32 grp_shaping_id : 6;
		u32 rsv : 25;
		u32 vld : 1;
	};
};

union rdma_sha2net_map_tbl {
	u32 data[1];
	struct {
		u32 rdma_vf_id : 6;
		u32 rsv : 25;
		u32 vld : 1;
	};
};

union rdma_sha2grp_map_tbl {
	u32 data[1];
	struct {
		u32 rdma_grp_id : 6;
		u32 rsv : 25;
		u32 vld : 1;
	};
};

union rdma_tc_q_list_attr_tbl {
	u32 data[1];
	struct {
		u32 rptr : 6;
		u32 rsv1 : 2;
		u32 rlen : 7;
		u32 rsv : 1;
		u32 wptr : 3;
		u32 rsv2 : 5;
		u32 wlen : 4;
		u32 fly : 4;
	};
};

union rdma_grp_net_list_tbl {
	u32 data[1];
	struct {
		u32 next_net_id : 8;
		u32 rsv3 : 4;
		u32 pre_net_id : 8;
		u32 rsv2 : 4;
		u32 shaping_state : 2;
		u32 pfc : 1;
		u32 valid : 1;
		u32 rsv1 : 4;
	};
};

union rdma_grp_net_list_tbl_v2 {
	u32 data[1];
	struct {
		u32 next : 6;
		u32 rsv3 : 6;
		u32 pre : 6;
		u32 rsv2 : 6;
		u32 sst : 2;
		u32 pfc : 1;
		u32 valid : 1;
		u32 rsv1 : 4;
	};
};

union rdma_spt_grp_list_tbl {
	u32 data[1];
	struct {
		u32 next_grp_id : 6;
		u32 rsv3 : 6;
		u32 pre_grp_id : 6;
		u32 rsv2 : 6;
		u32 shaping_state : 2;
		u32 valid : 1;
		u32 rsv1 : 5;
	};
};

union rdma_spt_grp_list_tbl_v2 {
	u32 data[1];
	struct {
		u32 next : 6;
		u32 rsv3 : 6;
		u32 pre : 6;
		u32 rsv2 : 6;
		u32 sst : 2;
		u32 valid : 1;
		u32 rsv1 : 5;
	};
};

union rdma_vf2vsi_cfg_tbl {
	struct {
		u32 vsi_id : 11;
		u32 resv : 20;
		u32 valid : 1;
	};
	u32 data;
};

union rdma_poll_wgt_cfg {
	u32 data[1];
	struct {
		u32 csch : 8;
		u32 sch : 8;
		u32 rnr : 8;
		u32 rto : 8;
	};
};

_Static_assert(sizeof(union rdma_poll_wgt_cfg) == 4,
	      "rdma_poll_wgt_cfg size must be 4 bytes");

#define NBL_DSCH_NET_TC_MAX 3

/* rdma_pri03_map_cfg and rdma_pri47_map_cfg common struct*/
union rdma_pfc_imap_cfg {
	u32 data[2];
	struct {
		u32 pri0_map : 8;
		u32 pri1_map : 8;
		u32 pri2_map : 8;
		u32 pri3_map : 8;
		u32 pri4_map : 8;
		u32 pri5_map : 8;
		u32 pri6_map : 8;
		u32 pri7_map : 8;
	};
};

_Static_assert(sizeof(union rdma_pfc_imap_cfg) == 8,
	      "rdma_pfc_imap_cfg size must be 8 bytes");

/* dsch rdma pri03 p2s map and pri47 p2s map */
union rdma_p2s_map_cfg {
	u32 data[2];
	struct {
		u32 pri0 : 8;
		u32 pri1 : 8;
		u32 pri2 : 8;
		u32 pri3 : 8;
		u32 pri4 : 8;
		u32 pri5 : 8;
		u32 pri6 : 8;
		u32 pri7 : 8;
	};
};

_Static_assert(sizeof(union rdma_p2s_map_cfg) == 8,
	      "rdma_p2s_map_cfg size must be 8 bytes");

/* rdma_sq_pri_map_cfg
 * rdma_raq_pri_map_cfg
 * rdma_pri_imap_cfg
 * common struct
 */
union rdma_sq_raq_pri_map_cfg {
	u32 data[1];
	struct {
		u32 pri0 : 3;
		u32 pri1 : 3;
		u32 pri2 : 3;
		u32 pri3 : 3;
		u32 pri4 : 3;
		u32 pri5 : 3;
		u32 pri6 : 3;
		u32 pri7 : 3;
		u32 rsv : 8;
	};
};

_Static_assert(sizeof(union rdma_sq_raq_pri_map_cfg) == 4,
	      "rdma_sq_raq_pri_map_cfg size must be 4 bytes");

enum nbl_tm_algorithm {
	nbl_tm_algorithm_dwrr,
	nbl_tm_algorithm_sp,
	nbl_tm_algorithm_max
};

#endif /* NBL_DSCH_LAYOUT_H */
