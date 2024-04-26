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
#define HNS3_UNIC_RX_HEAD_SIZE 128

struct ub_nip_ctrl_fld {
	__be16 proto;
	unsigned char d_guid[UBL_ALEN];
	unsigned char s_guid[UBL_ALEN];
};

static inline bool hns3_unic_mguid_valid_check(const u8 *addr)
{
#define HNS3_UNIC_MCGUID_VALID_PREFIX 0xffffffffu
	u32 *upper = (u32 *)addr;

	/* The guid from the user is used as the lower 48 bits of the actual
	 * guid. Therefore, this interface is used to check only the lower
	 * 48 bits of the guid.
	 */
	return *upper == HNS3_UNIC_MCGUID_VALID_PREFIX;
}

#define HNS3_SIMPLE_FORMAT_GUID_ADDR_LEN 18
#define HNS3_SIMPLE_GUID_LEN 6

static inline void hns3_unic_format_sim_guid_addr(char *format_simple_guid_addr,
						  const u8 *guid_addr)
{
	snprintf(format_simple_guid_addr, HNS3_SIMPLE_FORMAT_GUID_ADDR_LEN,
		 "%02x:%02x:%02x:%02x:%02x:%02x",
		 guid_addr[0], guid_addr[1], guid_addr[2],
		 guid_addr[3], guid_addr[4], guid_addr[5]);
}

void hns3_unic_set_default_cc(struct sk_buff *skb);
int hns3_unic_init(struct net_device *netdev);
u8 hns3_unic_get_l3_type(struct net_device *netdev, u32 ol_info, u32 l234info);
void hns3_unic_lp_setup_skb(struct sk_buff *skb);
void hns3_unic_lb_check_skb_data(struct hns3_enet_ring *ring,
				 struct sk_buff *skb);
void register_ipaddr_notifier(void);
void unregister_ipaddr_notifier(void);
void hns3_unic_set_rx_mode(struct net_device *netdev);
int hns3_unic_init_guid(struct net_device *netdev);
int hns3_unic_fill_skb_desc(struct hns3_nic_priv *priv,
			    struct hns3_enet_ring *ring,
			    struct sk_buff *skb, struct hns3_desc *desc,
			    struct hns3_desc_cb *desc_cb);

#endif
