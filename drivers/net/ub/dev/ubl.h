/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2023-2023 Hisilicon Limited.
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

#ifndef __LINUX_UBL_H
#define __LINUX_UBL_H

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/skbuff.h>

#define UBL_MOD_VERSION "1.0.0"

#define UBL_HARD_HLEN		4
#define UBL_HLEN		6
#define UBL_ALEN		16

#define UBL_LCRC_LEN		2
#define UBL_BCRC_LEN		4
#define UBL_LINK_LEN		2

#define UB_DEFAULT_NPI		1

#define UB_MAX_BLOCK_NUM	16
#define UB_FLIT_NUM_OF_BLOCK	32
#define UB_BYTE_OF_FLIT		20
#define UB_BYTE_OF_BLK		(UB_BYTE_OF_FLIT * UB_FLIT_NUM_OF_BLOCK)

#define UB_BLOCK_CRC_LEN	(UBL_BCRC_LEN + UBL_LCRC_LEN)
#define UB_MAX_MTU_PER_BLK	(UB_BYTE_OF_BLK - UBL_LINK_LEN - UB_BLOCK_CRC_LEN)
#define UB_DATA_LEN		1500
#define UB_MAX_MTU		((UB_MAX_BLOCK_NUM * UB_MAX_MTU_PER_BLK) - \
				UBL_HLEN - UBL_HARD_HLEN + UBL_LINK_LEN)
#define UB_MIN_MTU		68

#define UB_IPV4_CFG_TYPE	3
#define UB_IPV6_CFG_TYPE	4
#define UB_NOIP_CFG_TYPE	5
#define UB_UNKNOWN_CFG_TYPE	255

/**
 *	struct ublhdr - ub link header
 *	@h_cc: cc
 *	@h_npi: npi
 */
struct ublhdr {
	__be16 h_cc;
	__be32 h_npi;
} __packed;

/**
 * ubl_rmv_sw_ctype - delete software packet type for skb->data
 * @skb: buffer to alter
 *
 * Before the packet is sent to the hardware, remove sw_ctype field
 * and restore the original packet.
 */
static inline void *ubl_rmv_sw_ctype(struct sk_buff *skb)
{
	return pskb_pull(skb, sizeof(u8));
}

int ubl_create_header(struct sk_buff *skb, struct net_device *dev,
		      unsigned short type, const void *daddr,
		      const void *saddr, unsigned int len);
void ubl_setup(struct net_device *dev);
__be16 ubl_type_trans(struct sk_buff *skb, struct net_device *dev, u8 type);
struct net_device *alloc_ubldev_mqs(int sizeof_priv, unsigned int txqs,
				    unsigned int rxqs);
int ubl_add_sw_ctype(struct sk_buff *skb, u8 ctype);
#define alloc_ubldev_mq(sizeof_priv, count) \
	alloc_ubldev_mqs((sizeof_priv), (count), (count))

#endif
