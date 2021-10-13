/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_DCB_H
#define SPNIC_DCB_H

enum SPNIC_DCB_FLAGS {
	SPNIC_DCB_UP_COS_SETTING,
	SPNIC_DCB_TRAFFIC_STOPPED,
};

struct spnic_cos_cfg {
	u8	up;
	u8	bw_pct;
	u8	tc_id;
	u8	prio_sp;	/* 0 - DWRR, 1 - SP */
};

struct spnic_tc_cfg {
	u8	bw_pct;
	u8	prio_sp;	/* 0 - DWRR, 1 - SP */
	u16	rsvd;
};

struct spnic_dcb_config {
	/* The num_tc of the protocol stack is also the same */
	u8	max_cos;
	u8	default_cos;
	u8	valid_cos_bitmap;
	u8	rsvd1;
	struct spnic_cos_cfg cos_cfg[SPNIC_DCB_COS_MAX];
	struct spnic_tc_cfg tc_cfg[SPNIC_DCB_TC_MAX];

	u8	pfc_state;
	u8	pfc_en_bitmap;
	u16	rsvd2;
};

int spnic_dcb_init(struct spnic_nic_dev *nic_dev);
int spnic_dcb_reset_hw_config(struct spnic_nic_dev *nic_dev);
int spnic_configure_dcb(struct net_device *netdev);
int spnic_setup_tc(struct net_device *netdev, u8 tc);
u8 spnic_get_valid_up_bitmap(struct spnic_dcb_config *dcb_cfg);
void spnic_dcbcfg_set_pfc_state(struct spnic_nic_dev *nic_dev, u8 pfc_state);
u8 spnic_dcbcfg_get_pfc_state(struct spnic_nic_dev *nic_dev);
void spnic_dcbcfg_set_pfc_pri_en(struct spnic_nic_dev *nic_dev, u8 pfc_en_bitmap);
u8 spnic_dcbcfg_get_pfc_pri_en(struct spnic_nic_dev *nic_dev);
int spnic_dcbcfg_set_ets_up_tc_map(struct spnic_nic_dev *nic_dev, const u8 *up_tc_map);
void spnic_dcbcfg_get_ets_up_tc_map(struct spnic_nic_dev *nic_dev, u8 *up_tc_map);
int spnic_dcbcfg_set_ets_tc_bw(struct spnic_nic_dev *nic_dev, const u8 *tc_bw);
void spnic_dcbcfg_get_ets_tc_bw(struct spnic_nic_dev *nic_dev, u8 *tc_bw);
void spnic_dcbcfg_set_ets_tc_prio_type(struct spnic_nic_dev *nic_dev, u8 tc_prio_bitmap);
void spnic_dcbcfg_get_ets_tc_prio_type(struct spnic_nic_dev *nic_dev, u8 *tc_prio_bitmap);
int spnic_dcbcfg_set_up_bitmap(struct spnic_nic_dev *nic_dev, u8 valid_up_bitmap);
void spnic_update_tx_db_cos(struct spnic_nic_dev *nic_dev);
#endif
