/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 3snic Technologies Co., Ltd */

#ifndef SSS_LINUX_KERNEL_H_
#define SSS_LINUX_KERNEL_H_

#include <net/checksum.h>
#include <net/ipv6.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/if_vlan.h>
#include <linux/udp.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/bitmap.h>
#include <linux/slab.h>

/* UTS_RELEASE is in a different header starting in kernel 2.6.18 */
#ifndef UTS_RELEASE
#include <generated/utsrelease.h>
#endif

#ifndef NETIF_F_SCTP_CSUM
#define NETIF_F_SCTP_CSUM 0
#endif

#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif

#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

/* ************************************************************************ */
#define ETH_TYPE_TRANS_SETS_DEV
#define HAVE_NETDEV_STATS_IN_NETDEV

/* ************************************************************************ */
#ifndef HAVE_SET_RX_MODE
#define HAVE_SET_RX_MODE
#endif
#define HAVE_INET6_IFADDR_LIST

/* ************************************************************************ */
#define HAVE_NDO_GET_STATS64

/* ************************************************************************ */
#ifndef HAVE_MQPRIO
#define HAVE_MQPRIO
#endif
#ifndef HAVE_SETUP_TC
#define HAVE_SETUP_TC
#endif

#ifndef HAVE_NDO_SET_FEATURES
#define HAVE_NDO_SET_FEATURES
#endif
#define HAVE_IRQ_AFFINITY_NOTIFY

/* ************************************************************************ */
#define HAVE_ETHTOOL_SET_PHYS_ID

/* ************************************************************************ */
#define HAVE_NETDEV_WANTED_FEAUTES

/* ************************************************************************ */
#ifndef HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_VF_SPOOFCHK_CONFIGURE
#endif
#ifndef HAVE_SKB_L4_RXHASH
#define HAVE_SKB_L4_RXHASH
#endif

/* ************************************************************************ */
#define HAVE_ETHTOOL_GRXFHINDIR_SIZE
#define HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef ETHTOOL_SRXNTUPLE
#undef ETHTOOL_SRXNTUPLE
#endif

/* ************************************************************************ */
#define _kc_kmap_atomic(page) kmap_atomic(page)
#define _kc_kunmap_atomic(addr) kunmap_atomic(addr)

/* ************************************************************************ */
#include <linux/of_net.h>
#define HAVE_FDB_OPS
#define HAVE_ETHTOOL_GET_TS_INFO

/* ************************************************************************ */
#define HAVE_NAPI_GRO_FLUSH_OLD

/* ************************************************************************ */
#ifndef HAVE_SRIOV_CONFIGURE
#define HAVE_SRIOV_CONFIGURE
#endif

/* ************************************************************************ */
#define HAVE_ENCAP_TSO_OFFLOAD
#define HAVE_SKB_INNER_NETWORK_HEADER

/* ************************************************************************ */
#define HAVE_NDO_SET_VF_LINK_STATE
#define HAVE_SKB_INNER_PROTOCOL
#define HAVE_MPLS_FEATURES

/* ************************************************************************ */
#define HAVE_VXLAN_CHECKS
#define HAVE_NDO_SELECT_QUEUE_ACCEL

#define HAVE_NET_GET_RANDOM_ONCE
#define HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS

/* ************************************************************************ */
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK

/* ************************************************************************ */
#define HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
#define HAVE_VLAN_FIND_DEV_DEEP_RCU

/* ************************************************************************ */
#define HAVE_SKBUFF_CSUM_LEVEL
#define HAVE_MULTI_VLAN_OFFLOAD_EN
#define HAVE_ETH_GET_HEADLEN_FUNC

/* ************************************************************************ */
#define HAVE_RXFH_HASHFUNC

/****************************************************************/
#define HAVE_NDO_SET_VF_TRUST

/* ************************************************************** */
#include <net/devlink.h>

/* ************************************************************** */
#define HAVE_IO_MAP_WC_SIZE

/* ************************************************************************ */
#define HAVE_NETDEVICE_MIN_MAX_MTU

/* ************************************************************************ */
#define HAVE_VOID_NDO_GET_STATS64
#define HAVE_VM_OPS_FAULT_NO_VMA

/* ************************************************************************ */
#define HAVE_HWTSTAMP_FILTER_NTP_ALL
#define HAVE_NDO_SETUP_TC_ADM_INDEX
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
#define HAVE_PTP_CLOCK_DO_AUX_WORK

/* ************************************************************************ */
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#define HAVE_XDP_SUPPORT

/* ************************************************************************ */
#define HAVE_NDO_BPF_NETDEV_BPF
#define HAVE_TIMER_SETUP
#define HAVE_XDP_DATA_META

/* ************************************************************************ */
#define HAVE_NDO_SELECT_QUEUE_SB_DEV

/*****************************************************************************/
#define dev_open(x) dev_open(x, NULL)
#define HAVE_NEW_ETHTOOL_LINK_SETTINGS_ONLY

#ifndef get_ds
#define get_ds()	(KERNEL_DS)
#endif

#ifndef dma_zalloc_coherent
#define dma_zalloc_coherent(d, s, h, f) _sss_nic_dma_zalloc_coherent(d, s, h, f)
static inline void *_sss_nic_dma_zalloc_coherent(struct device *dev,
						 size_t size, dma_addr_t *dma_handle, gfp_t gfp)
{
	/* Above kernel 5.0, fixed up all remaining architectures
	 * to zero the memory in dma_alloc_coherent, and made
	 * dma_zalloc_coherent a no-op wrapper around dma_alloc_coherent,
	 * which fixes all of the above issues.
	 */
	return dma_alloc_coherent(dev, size, dma_handle, gfp);
}
#endif

#ifndef do_gettimeofday
#define do_gettimeofday(time) _kc_do_gettimeofday(time)
static inline void _kc_do_gettimeofday(struct timeval *tv)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / NSEC_PER_USEC;
}
#endif

/*****************************************************************************/
#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#endif

/*****************************************************************************/
#ifndef rtc_time_to_tm
#define rtc_time_to_tm rtc_time64_to_tm
#endif
#define HAVE_NDO_TX_TIMEOUT_TXQ

/* ************************************************************************ */

#define HAVE_ENCAPSULATION_TSO
#define HAVE_ENCAPSULATION_CSUM

#ifndef eth_zero_addr
static inline void __kc_eth_zero_addr(u8 *addr)
{
	memset(addr, 0x00, ETH_ALEN);
}

#define eth_zero_addr(_addr) __kc_eth_zero_addr(_addr)
#endif

#ifndef netdev_hw_addr_list_for_each
#define netdev_hw_addr_list_for_each(ha, l) \
	list_for_each_entry(ha, &(l)->list, list)
#endif

#define spin_lock_deinit(lock)

#define destroy_work(work)

#ifndef HAVE_TIMER_SETUP
void initialize_timer(const void *adapter_hdl, struct timer_list *timer);
#endif

#define nicif_err(priv, type, dev, fmt, args...) \
	netif_level(err, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_warn(priv, type, dev, fmt, args...) \
	netif_level(warn, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_notice(priv, type, dev, fmt, args...) \
	netif_level(notice, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_info(priv, type, dev, fmt, args...) \
	netif_level(info, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_dbg(priv, type, dev, fmt, args...) \
	netif_level(dbg, priv, type, dev, "[NIC]" fmt, ##args)

#define destroy_completion(completion)
#define sema_deinit(lock)
#define mutex_deinit(lock)
#define rwlock_deinit(lock)

#define tasklet_state(tasklet) ((tasklet)->state)

#ifndef hash_init
#define HASH_SIZE(name) (ARRAY_SIZE(name))

static inline void __hash_init(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);
}

#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF sizeof_field
#endif

#ifndef skb_frag_off_add
#define skb_frag_off_add(frag, delta) \
	((frag)->page_offset += (unsigned short)(delta))
#endif

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

#ifndef ETHTOOL_LINK_MODE_50000baseKR_Full_BIT
#define ETHTOOL_LINK_MODE_50000baseKR_Full_BIT 52
#define ETHTOOL_LINK_MODE_50000baseCR_Full_BIT 54
#define ETHTOOL_LINK_MODE_50000baseSR_Full_BIT 53
#endif

#ifndef ETHTOOL_LINK_MODE_100000baseKR_Full_BIT
#define ETHTOOL_LINK_MODE_100000baseKR_Full_BIT 75
#define ETHTOOL_LINK_MODE_100000baseCR_Full_BIT 78
#define ETHTOOL_LINK_MODE_100000baseSR_Full_BIT 76
#endif

#ifndef ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT
#define ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT 57
#define ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT 59
#define ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT 58
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

#ifndef SPEED_200000
#define SPEED_200000	200000
#endif

#define HAVE_XDP_QUERY_PROG

#endif
/* ************************************************************************ */
