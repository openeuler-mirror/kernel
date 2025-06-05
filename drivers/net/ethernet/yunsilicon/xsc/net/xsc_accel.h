/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ACCEL_H
#define XSC_ACCEL_H

#include <linux/netdev_features.h>
#include <linux/udp.h>
#include "common/xsc_core.h"

static inline void xsc_udp_gso_handle_tx_skb(struct sk_buff *skb)
{
	int payload_len = skb_shinfo(skb)->gso_size + sizeof(struct udphdr);

	udp_hdr(skb)->len = htons(payload_len);
}

static inline struct sk_buff *xsc_accel_handle_tx(struct sk_buff *skb)
{
	/*no not consider tls and ipsec*/
	if (skb_is_gso(skb) && skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
		xsc_udp_gso_handle_tx_skb(skb);
	return skb;
}

static inline bool xsc_vxlan_allowed(struct xsc_core_device *dev)
{
	return false;
}

static inline bool xsc_geneve_tx_allowed(struct xsc_core_device *dev)
{
	return false;
}

static inline bool xsc_any_tunnel_proto_supported(struct xsc_core_device *dev)
{
	return false;
}

#endif /* XSC_ACCEL_H */
