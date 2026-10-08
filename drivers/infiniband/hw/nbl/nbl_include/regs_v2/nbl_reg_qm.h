/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_QM_LAYOUT_H
#define NBL_QM_LAYOUT_H

#include <linux/types.h>

/* DQM registers */
#define NBL_DQM_RXMAC_TX_COS_BP_EN_OFF		0x0664

#define NBL_DQM_REG_ADDR(base, off)		((base) + (off))

/* Attention: QM is Draco Reg Name, UQM is RNIC Reg Name */
#define NBL_QM_TX_RXMAC_COS_BP_EN_OFF		0x0160
#define NBL_QM_DN_COS_MAPPING_0_OFF		0x0514
#define NBL_QM_DN_COS_MAPPING_1_OFF		0x0524
#define NBL_QM_DN_COS_MAPPING_2_OFF		0x0534
#define NBL_QM_DN_COS_MAPPING_DPORT_STRIDE	0x4
#define NBL_QM_VSI_MAPPING_TBL_OFF		0x0000b500
#define NBL_QM_TABLE_STRIDE			0x4

#define NBL_UQM_TABLE_STRIDE			0x4
#define NBL_UQM_CFG_QM_BP_EN_OFF		0x1004
#define NBL_UQM_CFG_PORT_TSH_OFF		0x1058
#define NBL_UQM_CFG_COS_TSH_OFF_V3		0x1360
#define NBL_UQM_CFG_COS_TSH_OFF_V4		0x1320
#define NBL_UQM_CFG_COS_TSH_STRIDE		0x4
#define NBL_UQM_VSI2VF_MAP_TBL_OFF		0x00008000
#define NBL_UQM_DUMP_TBL_OFF			0x0000c000

#define NBL_QM_REG_ADDR(base, off)		((base) + (off))
#define NBL_UQM_REG_ADDR(base, off)		((base) + (off))

/* Draco Use */
#define NBL_QM_DN_COS_MAPPING_ADDR(base, off, dport_id) \
	(NBL_QM_REG_ADDR((base), (off)) + \
	 NBL_QM_DN_COS_MAPPING_DPORT_STRIDE * (dport_id))
#define NBL_QM_DN_COS_MAPPING_0_ADDR(base, dport_id) \
	NBL_QM_DN_COS_MAPPING_ADDR((base), NBL_QM_DN_COS_MAPPING_0_OFF, \
				   (dport_id))
#define NBL_QM_DN_COS_MAPPING_1_ADDR(base, dport_id) \
	NBL_QM_DN_COS_MAPPING_ADDR((base), NBL_QM_DN_COS_MAPPING_1_OFF, \
				   (dport_id))
#define NBL_QM_DN_COS_MAPPING_2_ADDR(base, dport_id) \
	NBL_QM_DN_COS_MAPPING_ADDR((base), NBL_QM_DN_COS_MAPPING_2_OFF, \
				   (dport_id))
#define NBL_QM_VSI_MAPPING_TBL_ADDR(base, vsi_id) \
	(NBL_QM_REG_ADDR((base), NBL_QM_VSI_MAPPING_TBL_OFF) + \
	 NBL_QM_TABLE_STRIDE * (vsi_id))

/* RNIC DF200 Use */
#define NBL_UQM_VSI2VF_MAP_TBL_ADDR(base, vsi_id) \
	(NBL_UQM_REG_ADDR((base), NBL_UQM_VSI2VF_MAP_TBL_OFF) + \
	 NBL_UQM_TABLE_STRIDE * (vsi_id))
#define NBL_UQM_CFG_COS_TSH_ADDR(base, off, pri) \
	(NBL_UQM_REG_ADDR((base), (off)) + NBL_UQM_CFG_COS_TSH_STRIDE * (pri))
#define NBL_UQM_DUMP_TBL_ADDR(base, mirror_id) \
	(NBL_UQM_REG_ADDR((base), NBL_UQM_DUMP_TBL_OFF) + \
	 NBL_UQM_TABLE_STRIDE * (mirror_id))

union dqm_rxmac_tx_cos_bp_en_table {
	u32 data[1];
	struct {
		u32 eth0 : 8;
		u32 eth1 : 8;
		u32 eth2 : 8;
		u32 eth3 : 8;
	};
};

union qm_dn_cos_mapping_0 {
	u32 data[1];
	struct {
		u32 cos0 : 9;
		u32 cos1 : 9;
		u32 cos2 : 9;
		u32 rsv : 5;
	};
};

union qm_dn_cos_mapping_1 {
	u32 data[1];
	struct {
		u32 cos3 : 9;
		u32 cos4 : 9;
		u32 cos5 : 9;
		u32 rsv : 5;
	};
};

union qm_dn_cos_mapping_2 {
	u32 data[1];
	struct {
		u32 cos6 : 9;
		u32 cos7 : 9;
		u32 rsv : 14;
	};
};

union cfg_qm_bp_en_table {
	u32 data[1];
	struct {
		u32 port_pause_en : 4;
		u32 rsv1 : 12;
		u32 cos_pause_en : 8;
		u32 rsv2 : 8;
	};
};

union cfg_pfc_tsh_table {
	u32 data[1];
	struct {
		u32 xoff : 12;
		u32 rsv1 : 4;
		u32 xon : 12;
		u32 rsv2 : 4;
	};
};

union qm_vsi_mapping_tbl {
	u32 data[1];
	struct {
		u32 vf_id : 6;
		u32 valid : 1;
		u32 rsv : 25;
	};
};

union uqm_vsi2vf_map_tbl {
	u32 data[1];
	struct {
		u32 vf_id : 2;
		u32 rsv : 28;
		u32 rdma_offload : 1;
		u32 valid : 1;
	};
};

union uqm_dump_tbl {
	u32 data[1];
	struct {
		u32 vfid : 1;
		u32 rsv : 7;
		u32 qpn : 18;
		u32 rsv1 : 5;
		u32 vld : 1;
	};
};

#endif /* NBL_QM_LAYOUT_H */
