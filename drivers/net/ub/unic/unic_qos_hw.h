/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_QOS_HW_H__
#define __UNIC_QOS_HW_H__

#include <linux/ethtool.h>

#include "unic_dev.h"

int unic_set_prio_tc(struct unic_dev *unic_dev, u8 *prio_vl);
int unic_query_vl_map(struct unic_dev *unic_dev,
		      struct unic_config_vl_map_cmd *resp);
int unic_config_vl_rate_limit(struct unic_dev *unic_dev, u64 *vl_maxrate,
			      u16 vl_bitmap);
int unic_mac_pause_en_cfg(struct unic_dev *unic_dev, u32 tx_pause,
			  u32 rx_pause);
int unic_pfc_pause_cfg(struct unic_dev *unic_dev, u8 pfc_en);
int unic_set_vl_map(struct unic_dev *unic_dev, u8 *dscp_prio, u8 *prio_vl,
		    u8 map_type);

#endif /* __UNIC_QOS_HW_H__ */
