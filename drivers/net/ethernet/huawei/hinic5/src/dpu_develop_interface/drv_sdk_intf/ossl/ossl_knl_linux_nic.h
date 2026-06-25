/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : ossl_knl_linux_nic.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Kernel compatibility layer for the NIC module across different OS kernels.
 */


#ifndef OSSL_KNL_LINUX_NIC_H
#define OSSL_KNL_LINUX_NIC_H

#include <net/xdp.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#include "base_type.h"
#include "nic_kcompat.h"

#define ETH_ALEN        6       /* Octets in one ethernet addr   */

#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif

#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

#ifndef NETIF_F_SCTP_CSUM
#define NETIF_F_SCTP_CSUM 0
#endif

#ifndef NETIF_F_SCTP_CRC
#define NETIF_F_SCTP_CRC NETIF_F_SCTP_CSUM
#endif /* NETIF_F_SCTP_CRC */

#ifndef ETHTOOL_GLINKSETTINGS
/* adapt to SUPPORTED_** and ADVERTISED_**, only 32 bits */
enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT	= 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT		= 6,
	ETHTOOL_LINK_MODE_TP_BIT		= 7,
	ETHTOOL_LINK_MODE_FIBRE_BIT		= 10,
	ETHTOOL_LINK_MODE_Pause_BIT		= 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT	= 14,
	ETHTOOL_LINK_MODE_Backplane_BIT		= 16,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT	= 12,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT	= 17,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT	= 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT	= 20,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT	= 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT	= 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT	= 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT	= 26,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT	= 31,
};

#ifndef __ETHTOOL_LINK_MODE_MASK_NBITS
#define __ETHTOOL_LINK_MODE_MASK_NBITS 32
#endif
#endif

#ifndef __ETHTOOL_DECLARE_LINK_MODE_MASK
#define __ETHTOOL_DECLARE_LINK_MODE_MASK(name)	\
	DECLARE_BITMAP(name, __ETHTOOL_LINK_MODE_MASK_NBITS)
#endif

#ifndef ETHTOOL_LINK_MODE_1000baseX_Full_BIT
#define ETHTOOL_LINK_MODE_1000baseX_Full_BIT 41
#endif

#ifndef ETHTOOL_LINK_MODE_10000baseCR_Full_BIT
#define ETHTOOL_LINK_MODE_10000baseCR_Full_BIT 42
#define ETHTOOL_LINK_MODE_10000baseSR_Full_BIT 43
#define ETHTOOL_LINK_MODE_10000baseLR_Full_BIT 44
#define ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT 45
#endif

#ifndef ETHTOOL_LINK_MODE_25000baseKR_Full_BIT
#define ETHTOOL_LINK_MODE_25000baseCR_Full_BIT 31
#define ETHTOOL_LINK_MODE_25000baseKR_Full_BIT 32
#define ETHTOOL_LINK_MODE_25000baseSR_Full_BIT 33
#endif

#ifndef ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT
#define ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT 34
#define ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT 35
#define ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT 40
#endif

#ifndef ETHTOOL_LINK_MODE_50000baseKR_Full_BIT
#define ETHTOOL_LINK_MODE_50000baseKR_Full_BIT 52
#define ETHTOOL_LINK_MODE_50000baseCR_Full_BIT 54
#define ETHTOOL_LINK_MODE_50000baseSR_Full_BIT 53
#endif

#ifndef ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT
#define ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT 36
#define ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT 37
#define ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT 38
#define ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT 39
#endif

#ifndef ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT
#define ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT 57
#define ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT 59
#define ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT 58
#endif

#ifndef ETHTOOL_LINK_MODE_100000baseKR_Full_BIT
#define ETHTOOL_LINK_MODE_100000baseKR_Full_BIT 75
#define ETHTOOL_LINK_MODE_100000baseCR_Full_BIT 78
#define ETHTOOL_LINK_MODE_100000baseSR_Full_BIT 76
#endif

#ifndef ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT
#define ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT 62
#define ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT 63
#define ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT 66
#endif

#ifndef ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT
#define ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT 80
#define ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT 81
#define ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT 84
#endif

#ifndef ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT
#define ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT 85
#define ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT 86
#define ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT 89
#endif

#ifndef ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT
#define ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT 94
#define ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT 97
#define ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT 93
#endif

#ifndef SPEED_50000
#define SPEED_50000	50000
#endif

#ifndef SPEED_200000
#define SPEED_200000	200000
#endif

#ifndef SPEED_400000
#define SPEED_400000 400000
#endif

#ifndef SPEED_800000
#define SPEED_800000 800000
#endif

#ifdef NEED_DEFINE_SPEED_20000
#define SPEED_20000 20000
#endif /* NEED_DEFINE_SPEED_20000 */

#ifdef NEED_DEFINE_SPEED_25000
#define SPEED_25000 25000
#endif /* NEED_DEFINE_SPEED_25000 */

#ifdef NEED_DEFINE_SPEED_40000
#define SPEED_40000 40000
#endif /* NEED_DEFINE_SPEED_40000 */

#ifdef NEED_DEFINE_SPEED_100000
#define SPEED_100000 100000
#endif /* NEED_DEFINE_SPEED_100000 */

#ifdef ETHTOOL_GMODULEEEPROM
#ifndef ETH_MODULE_SFF_8472
#define ETH_MODULE_SFF_8472 0x2
#endif
#ifndef ETH_MODULE_SFF_8636
#define ETH_MODULE_SFF_8636 0x3
#endif
#ifndef ETH_MODULE_SFF_8436
#define ETH_MODULE_SFF_8436 0x4
#endif
#ifndef ETH_MODULE_SFF_8472_LEN
#define ETH_MODULE_SFF_8472_LEN 512
#endif
#ifndef ETH_MODULE_SFF_8636_MAX_LEN
#define ETH_MODULE_SFF_8636_MAX_LEN 640
#endif
#ifndef ETH_MODULE_SFF_8436_MAX_LEN
#define ETH_MODULE_SFF_8436_MAX_LEN 640
#endif
#endif

#ifdef NEED_DEFINE_U16_MAX
#define U16_MAX ((u16)~0U)
#endif /* NEED_DEFINE_U16_MAX */

#ifdef NEED_DEFINE_U32_MAX
#define U32_MAX ((u32)~0U)
#endif /* NEED_DEFINE_U32_MAX */

#ifdef NEED_DEFINE_DMA_RMB
/* It is used for tx hw_ci and sw_ci. */
#define dma_rmb() rmb()
#endif /* NEED_DEFINE_DMA_RMB */

#ifdef NEED_ETH_P_8021AD
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN	*/
#endif /* NEED_ETH_P_8021AD */

#ifdef NEED___vlan_get_protocol
__be16 __vlan_get_protocol(struct sk_buff *skb, __be16 type, int *next_depth);
#endif /* NEED___vlan_get_protocol */

#ifdef NEED_NETDEV_PHYS_ITEM_ID
#define netdev_phys_item_id netdev_phys_port_id
#endif /* NEED_NETDEV_PHYS_ITEM_ID */

#ifdef NEED_DEFINE_NETDEV_RSS_KEY_LEN
#define NETDEV_RSS_KEY_LEN (13 * 4)
#endif /* NEED_DEFINE_NETDEV_RSS_KEY_LEN */


#ifdef NEED_NAPI_SCHEDULE_IRQOFF
#define napi_schedule_irqoff napi_schedule
#endif /* NEED_NAPI_SCHEDULE_IRQOFF */

#ifdef NEED_DEFINE_ETH_MODULE_SFF_8636
#define ETH_MODULE_SFF_8636 0x3
#endif /* NEED_DEFINE_ETH_MODULE_SFF_8636 */
#ifndef NEED_DEFINE_ETH_MODULE_SFF_8636_LEN
#define ETH_MODULE_SFF_8636_LEN 256
#endif /* NEED_DEFINE_ETH_MODULE_SFF_8636_LEN */
#ifndef NEED_DEFINE_ETH_MODULE_SFF_8436
#define ETH_MODULE_SFF_8436 0x4
#endif /* NEED_DEFINE_ETH_MODULE_SFF_8436 */
#ifndef NEED_DEFINE_ETH_MODULE_SFF_8436_LEN
#define ETH_MODULE_SFF_8436_LEN 256
#endif /* NEED_DEFINE_ETH_MODULE_SFF_8436_LEN */

#ifdef NEED_DEFINE_NETIF_F_GSO_UDP_TUNNEL_CSUM
/*
 * if someone backports this, hopefully they backport as a #define.
 * declare it as zero on older kernels so that if it get's or'd in
 * it won't effect anything, therefore preventing core driver changes.
 */
#define NETIF_F_GSO_UDP_TUNNEL_CSUM 0
#define SKB_GSO_UDP_TUNNEL_CSUM 0
#endif /* NEED_DEFINE_NETIF_F_GSO_UDP_TUNNEL_CSUM */

#ifdef NEED_DEFINE_FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif /* NEED_DEFINE_FIELD_SIZEOF */

#ifdef NEED_DEFINE_SKB_VLAN_TAG_PRESENT
#define skb_vlan_tag_present(__skb) vlan_tx_tag_present(__skb)
#define skb_vlan_tag_get(__skb) vlan_tx_tag_get(__skb)
#define skb_vlan_tag_get_id(__skb) vlan_tx_tag_get_id(__skb)
#endif /* NEED_DEFINE_SKB_VLAN_TAG_PRESENT */

#ifdef HAVE_ETHTOOL_GLINKSETTINGS
#ifdef NEED_ENUM_ETHTOOL_LINK_MODE_25000baseCR_Full_BIT
#define ETHTOOL_LINK_MODE_25000baseCR_Full_BIT 31
#endif /* NEED_ENUM_ETHTOOL_LINK_MODE_25000baseCR_Full_BIT */
#ifdef NEED_ETHTOOL_LINK_MODE_25000baseKR_Full_BIT
#define ETHTOOL_LINK_MODE_25000baseKR_Full_BIT 32
#endif /* NEED_ETHTOOL_LINK_MODE_25000baseKR_Full_BIT */
#ifdef NEED_ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT
#define ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT 36
#endif /* NEED_ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT */
#ifdef NEED_ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT
#define ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT 38
#endif /* NEED_ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT */
#endif /* HAVE_ETHTOOL_GLINKSETTINGS */

#if defined(HAVE_XDP_XDP_QUERY_PROG) || defined(HAVE_BPF_XDP_QUERY_PROG)
#define HAVE_XDP_QUERY_PROG
#endif /* HAVE_XDP_QUERY_PROG */

#if defined(HAVE_NDO_SELECT_QUEUE_SB_DEV) && !defined(HAVE_NDO_SELECT_QUEUE_FALLBACK)
#define HAVE_NDO_SELECT_QUEUE_SB_DEV_ONLY
#elif defined(HAVE_NDO_SELECT_QUEUE_FALLBACK) && \
	(defined(HAVE_NDO_SELECT_QUEUE_SB_DEV) || \
	defined(HAVE_NDO_SELECT_QUEUE_ACCEL))
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
#endif /* HAVE_NDO_SELECT_QUEUE_ACCEL */

/* netif_napi_add_weight style in new kernel version */
#ifdef HAVE_NETIF_NAPI_ADD_WEIGHT
#define netif_napi_add(dev, napi, napi_struct, weight) \
	netif_napi_add_weight(dev, napi, napi_struct, weight)
#elif defined(HAVE_NETIF_NAPI_NO_WEIGHT)
#define netif_napi_add(dev, napi, napi_struct, weight)  netif_napi_add(dev, napi, napi_struct)
#endif

/* skb_recv_datagram absent noblock param int new kernel version */
#ifndef HAVE_SKB_RECV_DATAGRAM_NOBLOCK
#define skb_recv_datagram(sk, flags, noblock, err) \
	skb_recv_datagram(sk, (flags) | ((noblock) != 0 ? MSG_DONTWAIT : 0), err)
#endif

/* bpf_warn_invalid_xdp_action absent net_dev and prog param in old kernel version */
#ifndef HAVE_NETDEV_PROG_XDP_WARN_ACTION
#define	bpf_warn_invalid_xdp_action(net_dev, prog, act) \
	bpf_warn_invalid_xdp_action(act)
#endif

#ifndef netdev_hw_addr_list_for_each
#define netdev_hw_addr_list_for_each(ha, l) \
	list_for_each_entry(ha, &(l)->list, list)
#endif /* NEED_DEFINE_NETDEV_HW_ADDR_LIST_FOR_EACH */

#ifdef NEED_SKB_FRAG_OFF_ADD
#define skb_frag_off_add(frag, delta) kc_skb_frag_off_add(frag, delta)
static inline void kc_skb_frag_off_add(skb_frag_t *frag, int delta)
{
#ifdef HAVE_TYPEDEF_SKB_FRAG_T_BIOVEC
	frag->bv_offset += (unsigned short)delta;
#else
	frag->page_offset += (unsigned short)delta;
#endif
}
#endif /* NEED_SKB_FRAG_OFF_ADD */

/* ether_addr_copy did not exist prior to kernel version 3.10 */
#ifdef NEED_ETHER_ADDR_COPY
#define ether_addr_copy __kc_ether_addr_copy
static inline void __kc_ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	for (u16 i = 0; i < ETH_ALEN / sizeof(u16); ++i) {
		a[i] = b[i];
	}
#endif
}
#endif

/* eth_hw_addr_set was introduced in kernel version 5.15 */
static inline void hinic5_eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
#if defined(HAVE_ETH_HW_ADDR_SET)
	eth_hw_addr_set(dev, addr);
#else
	ether_addr_copy(dev->dev_addr, addr);
#endif
}

#ifdef HAVE_PAGE_POOL_SUPPORT
#if defined(HAVE_PAGE_POOL_NEW)
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>
#elif defined(HAVE_PAGE_POOL_OLD)
#include <net/page_pool.h>
#endif
#endif /* HAVE_PAGE_POOL_SUPPORT */


#if (KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE)
#define HAVE_ENCAPSULATION_TSO
#endif

#if (KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE)
#define HAVE_ENCAPSULATION_CSUM
#endif

#endif /* OSSL_KNL_LINUX_NIC_H */