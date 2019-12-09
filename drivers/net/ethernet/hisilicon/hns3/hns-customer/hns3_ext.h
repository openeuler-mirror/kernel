/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HNS3_EXT_H
#define __HNS3_EXT_H
#include <linux/types.h>
#include "hns3_enet.h"
#include "hnae3.h"
#include "hclge_main_it.h"

enum hns3_ext_op_code {
	HNS3_EXT_OPC_CLEAN_STATS64 = 0,
	HNS3_EXT_OPC_GET_CHIPID,
	HNS3_EXT_OPC_GET_SFPINFO,
	HNS3_EXT_OPC_SET_SFP_STATE,
	HNS3_EXT_OPC_GET_CHIP_NUM,
	HNS3_EXT_OPC_GET_PORT_NUM,
	HNS3_EXT_OPC_SET_LED,
	HNS3_EXT_OPC_GET_PRESENT,
	HNS3_EXT_OPC_DISABLE_LANE,
	HNS3_EXT_OPC_GET_LANE_STATUS,
	HNS3_EXT_OPC_GET_LED_SIGNAL,
	HNS3_EXT_OPC_SET_MAC_STATE,
	HNS3_EXT_OPC_CONFIG_CLOCK,
	HNS3_EXT_OPC_GET_PFC_STORM_PARA,
	HNS3_EXT_OPC_SET_PFC_STORM_PARA,
	HNS3_EXT_OPC_GET_PHY_REG,
	HNS3_EXT_OPC_SET_PHY_REG,
	HNS3_EXT_OPC_GET_MAC_ID,
	HNS3_EXT_OPC_OPT_MAC_TABLE,
	HNS3_EXT_OPC_RESET,
	HNS3_EXT_OPC_GET_HILINK_REF_LOS,
	HNS3_EXT_OPC_GET_8211_PHY_REG,
	HNS3_EXT_OPC_SET_8211_PHY_REG,
	HNS3_EXT_OPC_GET_PORT_TYPE,
};

struct hns3_sfp_info_para {
	u8 *buff;
	u16 offset;
	u16 size;
	u16 *outlen;
};

struct hns3_led_state_para {
	u32 type;
	u32 status;
};

struct hns3_pfc_storm_para {
	u32 dir;
	u32 enable;
	u32 period_ms;
	u32 times;
	u32 recovery_period_ms;
};

struct hns3_phy_para {
	u32 page_select_addr;
	u32 reg_addr;
	u16 page;
	u16 data;
};

struct hns3_lamp_signal {
	u8 error;
	u8 locate;
	u8 activity;
};

int nic_get_chipid(struct net_device *ndev, u32 *chip_id);
int nic_netdev_match_check(struct net_device *netdev);
int nic_get_sfpinfo(struct net_device *ndev, u8 *buff, u16 size, u16 *outlen);
int nic_get_sfp_present(struct net_device *ndev, int *present);
int nic_set_sfp_state(struct net_device *ndev, bool en);
int nic_clean_stats64(struct net_device *netdev,
		      struct rtnl_link_stats64 *stats);
int nic_get_chip_num(struct net_device *ndev, u32 *chip_num);
int nic_get_port_num_per_chip(struct net_device *ndev, u32 *port_num);
int nic_set_led(struct net_device *ndev, int type, int status);
int nic_disable_net_lane(struct net_device *ndev);
int nic_get_net_lane_status(struct net_device *ndev, u32 *status);
int nic_set_cpu_affinity(struct net_device *netdev, cpumask_t *affinity_mask);
int nic_set_mac_state(struct net_device *ndev, int enable);
int nic_disable_clock(struct net_device *ndev);
int nic_set_pfc_storm_para(struct net_device *ndev, int dir, int enable,
			   int period_ms, int times, int recovery_period_ms);
int nic_get_pfc_storm_para(struct net_device *ndev, int dir, int *enable,
			   int *period_ms, int *times, int *recovery_period_ms);
int nic_get_phy_reg(struct net_device *ndev, u32 page_select_addr,
		    u16 page, u32 reg_addr, u16 *data);
int nic_set_phy_reg(struct net_device *ndev, u32 page_select_addr,
		    u16 page, u32 reg_addr, u16 data);
int nic_get_mac_id(struct net_device *ndev, u32 *mac_id);
int nic_get_hilink_ref_los(struct net_device *ndev, u32 *status);
int nic_get_8211_phy_reg(struct net_device *ndev, u32 page_select_addr,
			 u16 page, u32 reg_addr, u16 *data);
int nic_set_8211_phy_reg(struct net_device *ndev, u32 page_select_addr,
			 u16 page, u32 reg_addr, u16 data);
int nic_get_port_wire_type(struct net_device *ndev, u32 *wire_type);

#endif
