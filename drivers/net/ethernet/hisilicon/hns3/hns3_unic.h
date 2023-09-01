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

void hns3_unic_set_default_cc(struct sk_buff *skb);
void hns3_unic_init(struct net_device *netdev);
void hns3_unic_set_l3_type(struct sk_buff *skb, u32 *type_cs_vlan_tso);
u8 hns3_unic_get_l3_type(struct net_device *netdev, u32 ol_info, u32 l234info);

#endif
