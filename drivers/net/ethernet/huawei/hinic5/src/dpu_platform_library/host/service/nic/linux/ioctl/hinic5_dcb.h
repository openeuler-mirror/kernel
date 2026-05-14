/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_dcb.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_DCB_H
#define HINIC5_DCB_H

#include "ossl_knl.h"

struct hinic5_cos_cfg {
	u8	up;
	u8	bw_pct;
	u8	tc_id;
	u8	prio_sp; /* 0 - DWRR, 1 - SP */
};

struct hinic5_tc_cfg {
	u8	bw_pct;
	u8	prio_sp; /* 0 - DWRR, 1 - SP */
	u16	rsvd;
};

enum HINIC5_DCB_TRUST {
	DCB_PCP,
	DCB_DSCP,
};

#define PCP_MAX_UP 8
#define DSCP_MAC_UP 64
#define DBG_DFLT_DSCP_VAL  0xFF

struct hinic5_dcb_config {
	u8	trust; /* pcp, dscp */
	u8	default_cos;
	u8	pcp_user_cos_num;
	u8	pcp_valid_cos_map;
	u8	dscp_user_cos_num;
	u8	dscp_valid_cos_map;
	u8	pcp2cos[PCP_MAX_UP];
	u8	dscp2cos[DSCP_MAC_UP];

	u8	cos_qp_offset[NIC_DCB_COS_MAX];
	u8	cos_qp_num[NIC_DCB_COS_MAX];
};

struct hinic5_nic_dev;

u8 hinic5_get_dev_user_cos_num(struct hinic5_nic_dev *nic_dev);
u8 hinic5_get_dev_valid_cos_map(struct hinic5_nic_dev *nic_dev);
int hinic5_dcb_init(struct hinic5_nic_dev *nic_dev);
void hinic5_dcb_reset_hw_config(struct hinic5_nic_dev *nic_dev);
int hinic5_configure_dcb(struct net_device *netdev);
int hinic5_setup_cos(struct net_device *netdev, u8 cos, u8 netif_run);
void hinic5_dcbcfg_set_pfc_state(struct hinic5_nic_dev *nic_dev, u8 pfc_state);
u8 hinic5_dcbcfg_get_pfc_state(struct hinic5_nic_dev *nic_dev);
void hinic5_dcbcfg_set_pfc_pri_en(struct hinic5_nic_dev *nic_dev,
				  u8 pfc_en_bitmap);
u8 hinic5_dcbcfg_get_pfc_pri_en(struct hinic5_nic_dev *nic_dev);
int hinic5_dcbcfg_set_ets_up_tc_map(struct hinic5_nic_dev *nic_dev,
				    const u8 *up_tc_map);
void hinic5_dcbcfg_get_ets_up_tc_map(struct hinic5_nic_dev *nic_dev,
				     u8 *up_tc_map);
int hinic5_dcbcfg_set_ets_tc_bw(struct hinic5_nic_dev *nic_dev,
				const u8 *tc_bw);
void hinic5_dcbcfg_get_ets_tc_bw(struct hinic5_nic_dev *nic_dev, u8 *tc_bw);
void hinic5_dcbcfg_set_ets_tc_prio_type(struct hinic5_nic_dev *nic_dev,
					u8 tc_prio_bitmap);
void hinic5_dcbcfg_get_ets_tc_prio_type(struct hinic5_nic_dev *nic_dev,
					u8 *tc_prio_bitmap);
int hinic5_dcbcfg_set_up_bitmap(struct hinic5_nic_dev *nic_dev,
				struct hinic5_dcb_config *wanted_dcb_cfg);
void hinic5_update_tx_db_cos(struct hinic5_nic_dev *nic_dev, u8 dcb_en);

void hinic5_update_qp_cos_cfg(struct hinic5_nic_dev *nic_dev);
void hinic5_vport_down(struct hinic5_nic_dev *nic_dev);
int hinic5_vport_up(struct hinic5_nic_dev *nic_dev);
int hinic5_configure_dcb_hw(struct hinic5_nic_dev *nic_dev, u8 dcb_en);
#endif
