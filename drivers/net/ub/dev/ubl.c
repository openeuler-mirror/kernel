// SPDX-License-Identifier: GPL-2.0+
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
 * UBL      An implementation of the UB protocol suite for the LINUX
 *      operating system.
 *
 * UB link device handling.
 *
 * Version:	@(#)ubl.c	1.0.1	23/02/14
 *
 */

#include <linux/netdevice.h>
#include <net/pkt_sched.h>

#include "ubl.h"

static __be16 ubl_type_to_proto(u8 type)
{
	__be16 proto;

	switch (type) {
	case UB_IPV4_CFG_TYPE:
		proto = htons(ETH_P_IP);
		break;
	case UB_IPV6_CFG_TYPE:
		proto = htons(ETH_P_IPV6);
		break;
	case UB_NOIP_CFG_TYPE:
	default:
		proto = htons(ETH_P_UB);
		break;
	}

	return proto;
}

/**
 * ubl_add_sw_ctype - add software packet type for skb->data
 * @skb: buffer to alter
 * @ctype: indicates the packet type
 *
 * The packet type cannot be known by parsing packe from user,
 * which leads to restrictions on the use of socket.
 * Add cs_type field to indicate the packet type. And sw_ctype
 * exists only during software prcessing.
 * +----------+----+-----+-----------+
 * | sw_ctype | CC | NPI | L3 Packet |
 * +----------+----+-----+-----------+
 */
int ubl_add_sw_ctype(struct sk_buff *skb, u8 ctype)
{
	u8 *pkt_cfg;

	if (skb_cow_head(skb, sizeof(u8)))
		return -ENOMEM;

	pkt_cfg = (u8 *)skb_push(skb, sizeof(u8));
	*pkt_cfg = ctype;

	return 0;
}

/**
 * ubl_create_header - create the ubl header
 * @skb:	buffer to alter
 * @dev:	source device
 * @type:	ubl type field
 * @daddr:	not used in ubl
 * @saddr:	not used in ubl
 * @len:   packet length (<= skb->len)
 *
 */
int ubl_create_header(struct sk_buff *skb, struct net_device *dev,
		      unsigned short type, const void *daddr,
		      const void *saddr, unsigned int len)
{
	u8 ctype = UB_NOIP_CFG_TYPE;
	int ret = -UBL_HLEN;
	struct ublhdr *ubl;

	if (type == ETH_P_IP || type == ETH_P_IPV6) {
		ubl = (struct ublhdr *)skb_push(skb, UBL_HLEN);
		memset(ubl, 0, sizeof(struct ublhdr));
		ubl->h_npi = htonl(UB_DEFAULT_NPI);
		ctype = (type == ETH_P_IP) ? UB_IPV4_CFG_TYPE : UB_IPV6_CFG_TYPE;
		ret = UBL_HLEN;
	} else if (type == ETH_P_UB) {
		/* if type is ETH_P_UB, then do nothing. */
		ret = 0;
	}

	if (ubl_add_sw_ctype(skb, ctype))
		ret = -ENOMEM;

	return ret;
}
EXPORT_SYMBOL(ubl_create_header);

/**
 * ubl_header_parse_protocol - parse packets protocol before send it to driver.
 * @skb: buffer to alter
 *
 * parse packets based on packet data if skb->protocol is ETH_P_ALL or 0.
 */
static __be16 ubl_header_parse_protocol(const struct sk_buff *skb)
{
	return ubl_type_to_proto(skb->data[0]);
}

const static struct header_ops ubl_header_ops ____cacheline_aligned = {
	.create		= ubl_create_header,
	.parse_protocol	= ubl_header_parse_protocol,
};

/**
 * ubl_setup - setup ub link network device
 * @dev: network device
 *
 * Fill in the fields of the device structure with ubl-generic values.
 */
void ubl_setup(struct net_device *dev)
{
	dev->header_ops         = &ubl_header_ops;
	dev->type               = ARPHRD_UB;
	dev->hard_header_len    = UBL_HLEN;
	dev->min_header_len     = UBL_HLEN;
	dev->mtu                = UB_DATA_LEN;
	dev->min_mtu            = UB_MIN_MTU;
	dev->max_mtu            = UB_DATA_LEN;
	dev->addr_len           = UBL_ALEN;
	dev->tx_queue_len       = DEFAULT_TX_QUEUE_LEN;
	dev->flags              = (IFF_NOARP | IFF_POINTOPOINT);
	dev->priv_flags         |= IFF_TX_SKB_SHARING;
}
EXPORT_SYMBOL(ubl_setup);

/**
 * alloc_ubldev_mqs - Allocates and sets up an ub-n device
 * @sizeof_priv: Size of additional driver-private structure to be allocated
 *	for this ubl device
 * @txqs: The number of TX queues this device has.
 * @rxqs: The number of RX queues this device has.
 *
 * Fill in the fields of the device structure with ubl-generic
 * values. Basically does everything except registering the device.
 *
 * Constructs a new net device, complete with a private data area of
 * size (sizeof_priv).  A 32-byte (not bit) alignment is enforced for
 * this private data area.
 */

struct net_device *alloc_ubldev_mqs(int sizeof_priv, unsigned int txqs,
				    unsigned int rxqs)
{
	return alloc_netdev_mqs(sizeof_priv, "ubl%d", NET_NAME_UNKNOWN,
				ubl_setup, txqs, rxqs);
}
EXPORT_SYMBOL(alloc_ubldev_mqs);

/**
 * ubl_type_trans - obtains skb->protocol and adds sw_ptype to the packet
 * @skb: buffer to alter
 * @dev: source device
 * @type: packet type
 *
 * Obtains the packet type and translates it to skb->protocol and adds sw_ptype
 * to the packet data.
 */
__be16 ubl_type_trans(struct sk_buff *skb, struct net_device *dev, u8 type)
{
	skb->dev = dev;
	ubl_add_sw_ctype(skb, type);
	skb_reset_mac_header(skb);
	if (type == UB_IPV4_CFG_TYPE || type == UB_IPV6_CFG_TYPE)
		skb_pull_inline(skb, UBL_HLEN + 1);
	else if (type != UB_NOIP_CFG_TYPE)
		net_warn_ratelimited("An unknown packet is received by %s, type is %u\n",
				     dev->name, type);

	return ubl_type_to_proto(type);
}
EXPORT_SYMBOL(ubl_type_trans);

MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UB link level");
MODULE_VERSION(UBL_MOD_VERSION);
