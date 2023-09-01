/* SPDX-License-Identifier: GPL-2.0+ */
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef __HNS3_UNIC_H
#define __HNS3_UNIC_H

#include "ubl.h"

#define UNIC_CC_DEFAULT_FECN_MODE 0x4000

struct ub_nip_ctrl_fld {
	__be16 proto;
	unsigned char d_guid[UBL_ALEN];
	unsigned char s_guid[UBL_ALEN];
};

void hns3_unic_set_default_cc(struct sk_buff *skb);
void hns3_unic_init(struct net_device *netdev);
void hns3_unic_set_l3_type(struct sk_buff *skb, u32 *type_cs_vlan_tso);
u8 hns3_unic_get_l3_type(struct net_device *netdev, u32 ol_info, u32 l234info);
void hns3_unic_init_guid(struct net_device *netdev);
void hns3_unic_lp_setup_skb(struct sk_buff *skb);
void hns3_unic_lb_check_skb_data(struct hns3_enet_ring *ring,
				 struct sk_buff *skb);
void register_ipaddr_notifier(void);
void unregister_ipaddr_notifier(void);
void hns3_unic_init_guid(struct net_device *netdev);

#endif
