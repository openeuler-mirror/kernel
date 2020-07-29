/* SPDX-License-Identifier: GPL-2.0*/
/* Huawei HiNIC PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
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

#ifndef OSSL_KNL_LINUX_H_
#define OSSL_KNL_LINUX_H_

#include <linux/string.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/udp.h>
#include <linux/highmem.h>

#ifndef SUPPORTED_100000baseKR4_Full
#define SUPPORTED_100000baseKR4_Full	0
#define ADVERTISED_100000baseKR4_Full	0
#endif
#ifndef SUPPORTED_100000baseCR4_Full
#define SUPPORTED_100000baseCR4_Full	0
#define ADVERTISED_100000baseCR4_Full	0
#endif

#ifndef SUPPORTED_40000baseKR4_Full
#define SUPPORTED_40000baseKR4_Full	0
#define ADVERTISED_40000baseKR4_Full	0
#endif
#ifndef SUPPORTED_40000baseCR4_Full
#define SUPPORTED_40000baseCR4_Full	0
#define ADVERTISED_40000baseCR4_Full	0
#endif

#ifndef SUPPORTED_25000baseKR_Full
#define	SUPPORTED_25000baseKR_Full	0
#define ADVERTISED_25000baseKR_Full	0
#endif
#ifndef SUPPORTED_25000baseCR_Full
#define SUPPORTED_25000baseCR_Full	0
#define	ADVERTISED_25000baseCR_Full	0
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

#ifndef RHEL_RELEASE_CODE
/* NOTE: RHEL_RELEASE_* introduced in RHEL4.5. */
#define RHEL_RELEASE_CODE 0
#endif

/* SuSE version macros are the same as Linux kernel version macro. */
#ifndef SLE_VERSION
#define SLE_VERSION(a, b, c)	KERNEL_VERSION(a, b, c)
#endif
#define SLE_LOCALVERSION(a, b, c)	KERNEL_VERSION(a, b, c)
#ifdef CONFIG_SUSE_KERNEL
#if    (KERNEL_VERSION(92, 0, 0) <= SLE_LOCALVERSION_CODE && \
	KERNEL_VERSION(93, 0, 0) > SLE_LOCALVERSION_CODE)
/* SLES12 SP2 GA is 4.4.21-69.
 * SLES12 SP2 updates before SLES12 SP3 are: 4.4.{21,38,49,59}
 * SLES12 SP2 updates after SLES12 SP3 are: 4.4.{74,90,103,114,120}
 * but they all use a SLE_LOCALVERSION_CODE matching 92.nn.y
 */
#define SLE_VERSION_CODE SLE_VERSION(12, 2, 0)
#else
/* SLES15 Beta1 is 4.12.14-2.
 * SLES12 SP4 will also use 4.12.14-nn.xx.y
 */
#define SLE_VERSION_CODE SLE_VERSION(15, 0, 0)
/* new SLES kernels must be added here with >= based on kernel
 * the idea is to order from newest to oldest and just catch all
 * of them using the >=
 */
#endif /* LINUX_VERSION_CODE == KERNEL VERSION(x,y,z) */
#endif /* CONFIG_SUSE_KERNEL */
#ifndef SLE_VERSION_CODE
#define SLE_VERSION_CODE 0
#endif /* SLE_VERSION_CODE */
#ifndef SLE_LOCALVERSION_CODE
#define SLE_LOCALVERSION_CODE 0
#endif /* SLE_LOCALVERSION_CODE */

/*****************************************************************************/
#define ETH_TYPE_TRANS_SETS_DEV
#define HAVE_NETDEV_STATS_IN_NETDEV

/*****************************************************************************/

#if (RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(6, 2) <= RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 0) > RHEL_RELEASE_CODE))
#define HAVE_RHEL6_NET_DEVICE_EXTENDED
#endif /* RHEL >= 6.2 && RHEL < 7.0 */
#if (RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(6, 6) <= RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 0) > RHEL_RELEASE_CODE))
#define HAVE_RHEL6_NET_DEVICE_OPS_EXT
#define HAVE_NDO_SET_FEATURES
#endif /* RHEL >= 6.6 && RHEL < 7.0 */

#define HAVE_NDO_GET_STATS64

/*****************************************************************************/
#ifndef HAVE_SETUP_TC
#define HAVE_SETUP_TC
#endif

#ifndef HAVE_NDO_SET_FEATURES
#define HAVE_NDO_SET_FEATURES
#endif

/*****************************************************************************/
#define HAVE_ETHTOOL_SET_PHYS_ID

/*****************************************************************************/
#define HAVE_VF_SPOOFCHK_CONFIGURE

#define HAVE_NDO_SET_VF_TRUST

/*****************************************************************************/
#define HAVE_NAPI_GRO_FLUSH_OLD

/*****************************************************************************/
#ifndef HAVE_SRIOV_CONFIGURE
#define HAVE_SRIOV_CONFIGURE
#endif

/*****************************************************************************/
#define HAVE_NDO_SET_VF_LINK_STATE

/*****************************************************************************/
#define HAVE_NDO_SELECT_QUEUE_ACCEL

#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK

/*****************************************************************************/
#define HAVE_NDO_SET_VF_MIN_MAX_TX_RATE

/*****************************************************************************/
#define HAVE_SKBUFF_CSUM_LEVEL
#define HAVE_MULTI_VLAN_OFFLOAD_EN

/*****************************************************************************/
#define HAVE_RXFH_HASHFUNC

/*****************************************************************************/
#define HAVE_NETDEVICE_MIN_MAX_MTU

/*****************************************************************************/
#define HAVE_VOID_NDO_GET_STATS64

/*****************************************************************************/
#define HAVE_NDO_SETUP_TC_CHAIN_INDEX

/*****************************************************************************/
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
/*****************************************************************************/

/*****************************************************************************/
#define HAVE_TIMER_SETUP
/*****************************************************************************/

/*****************************************************************************/
#define HAVE_NDO_SELECT_QUEUE_SB_DEV
/*****************************************************************************/

/* vxlan outer udp checksum will offload and skb->inner_transport_header
 * is wrong
 */
#if (SLE_VERSION_CODE && ((SLE_VERSION(12, 1, 0) == SLE_VERSION_CODE) || \
	(SLE_VERSION(12, 0, 0) == SLE_VERSION_CODE))) || \
	(RHEL_RELEASE_CODE && (RHEL_RELEASE_VERSION(7, 0) == RHEL_RELEASE_CODE))
#define HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
#endif

#define HAVE_ENCAPSULATION_TSO

#define HAVE_ENCAPSULATION_CSUM

int local_atoi(const char *name);

#define nicif_err(priv, type, dev, fmt, args...)		\
	netif_level(err, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_warn(priv, type, dev, fmt, args...)		\
	netif_level(warn, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_notice(priv, type, dev, fmt, args...)		\
	netif_level(notice, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_info(priv, type, dev, fmt, args...)		\
	netif_level(info, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_dbg(priv, type, dev, fmt, args...)		\
	netif_level(dbg, priv, type, dev, "[NIC]"fmt, ##args)

#define tasklet_state(tasklet) ((tasklet)->state)

#endif
