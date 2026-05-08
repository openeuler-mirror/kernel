/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_netdev.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_NETDEV_H__
#define __SXE2VF_NETDEV_H__

#include <linux/if_vlan.h>
#include "sxe2vf.h"

struct sxe2vf_adapter;

#define SXE2VF_FRAME_SIZE_MAX 9728
#define SXE2VF_PACKET_HDR_PAD (ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))

#define SXE2VF_NETDEV_WATCHDOG_TIMEOUT (5 * HZ)
#define NETIF_VLAN_FILTERING_FEATURES                                          \
	(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER)

void sxe2vf_netdev_init(struct sxe2vf_adapter *adapter);

s32 sxe2vf_netdev_register(struct sxe2vf_adapter *adapter);

void sxe2vf_netdev_unregister(struct sxe2vf_adapter *adapter);

#endif
