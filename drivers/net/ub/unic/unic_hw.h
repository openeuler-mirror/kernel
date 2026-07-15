/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_HW_H__
#define __UNIC_HW_H__

#include <linux/ethtool.h>
#include <ub/ubase/ubase_comm_cmd.h>

#include "unic_dev.h"
#include "unic_qos_hw.h"

#define UNIC_DL_CONFIG_MODE_TX_EN_B	0
#define UNIC_DL_CONFIG_MODE_RX_EN_B	1
#define UNIC_DL_CONFIG_MODE_APP_LP_EN_B	2

#define UNIC_LINK_STATUS_UP_B	0
#define UNIC_LINK_STATUS_UP_M	BIT(UNIC_LINK_STATUS_UP_B)

#define UNIC_LINK_STATUS_DOWN	0
#define UNIC_LINK_STATUS_UP	1

enum unic_rss_tc_mode {
	UNIC_RSS_TC_MODE0,
	UNIC_RSS_TC_MODE1
};

enum unic_rss_tc_valid {
	UNIC_RSS_TC_INVALID,
	UNIC_RSS_TC_VALID
};

struct unic_caps_item {
	void		*p;
	u32		default_val;
	u8		size;
	const char	*name;
};

struct unic_speed_bit_map {
	u32 speed;
	u32 lanes;
	u32 speed_bit;
};

struct unic_link_mode_bit_map {
	u32 speed_bit;
	enum ethtool_link_mode_bit_indices link_mode;
};

struct unic_promisc_en {
	u8 en_uc_ip;
	u8 en_uc_guid;
	u8 en_mc;
	u8 en_uc_mac;
	u8 en_mc_mac;
	u8 en_bc;
};

#define UNIC_RSS_MAX_CNT	10U
struct unic_cfg_rss_cmd {
	u8 tc_mode;
	u8 tc_valid;
	u8 jfr_reg_num;
	u8 rsvd;
	__le16 jfr_idx[UNIC_RSS_MAX_CNT];
};

static inline bool unic_is_port_down(struct unic_dev *unic_dev)
{
	return unic_dev->hw.mac.link_status == UNIC_LINK_STATUS_DOWN;
}

int unic_get_speed_bit(u32 speed, u32 lanes, u32 *speed_bit);

int unic_update_port_info(struct unic_dev *unic_dev);

int unic_set_mac_speed_duplex(struct unic_dev *unic_dev, u32 speed, u8 duplex,
			      u8 lanes);
int unic_set_mac_autoneg(struct unic_dev *unic_dev, u8 autoneg);
int unic_set_mac_link_ksettings(struct unic_dev *unic_dev,
				const struct ethtool_link_ksettings *cmd);

int unic_query_dev_res(struct unic_dev *unic_dev);

int unic_check_validate_dump_mtu(struct unic_dev *unic_dev, int new_mtu,
				 u16 *max_frame_size);
int unic_config_mtu(struct unic_dev *unic_dev, int new_mtu);

int unic_mac_cfg(struct unic_dev *unic_dev, bool enable);
int unic_mac_mode_cfg(struct net_device *netdev, bool enable);

int unic_sync_promisc_mode(struct unic_dev *unic_dev);
int unic_activate_promisc_mode(struct unic_dev *unic_dev, bool activate);
void unic_fill_promisc_en(struct unic_promisc_en *promisc_en, u8 flags);
int unic_get_promisc_mode(struct unic_dev *unic_dev,
			  struct unic_promisc_cfg_cmd *resp);
int unic_set_promisc_mode(struct unic_dev *unic_dev,
			  struct unic_promisc_en *promisc_en);

int unic_cfg_vport_buf(struct unic_dev *unic_dev, bool init);
int unic_query_vport_ctx(struct unic_dev *unic_dev, u16 offset,
			 struct unic_vport_ctx_cmd *resp);
int unic_set_fec_mode(struct unic_dev *unic_dev, u32 fec_mode);
int unic_update_fec_stats(struct unic_dev *unic_dev);
int unic_set_vlan_filter_hw(struct unic_dev *unic_dev, bool filter_en);
int unic_set_port_vlan_hw(struct unic_dev *unic_dev, u16 vlan_id, bool is_kill);
int unic_set_rss_tc_mode(struct unic_dev *unic_dev, u8 tc_valid);
int unic_query_rss_cfg(struct unic_dev *unic_dev,
		       struct unic_cfg_rss_cmd *resp);

#endif /* __UNIC_HW_H__ */
