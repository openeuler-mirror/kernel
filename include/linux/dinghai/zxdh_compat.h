/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/io.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/if_link.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/vxlan.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/mii.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>

#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif /* GCC_VERSION */

/* Backport macros for controlling GCC diagnostics */

#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC 1000000L
#endif
#include <net/ipv6.h>
/* UTS_RELEASE is in a different header starting in kernel 2.6.18 */
#ifndef UTS_RELEASE
/* utsrelease.h changed locations in 2.6.33 */
#include <generated/utsrelease.h>
#endif

/* NAPI enable/disable flags here */
#define NAPI

#ifdef DISABLE_NET_POLL_CONTROLLER
#undef CONFIG_NET_POLL_CONTROLLER
#endif

/* generic boolean compatibility */
#undef TRUE
#undef FALSE
#define TRUE true
#define FALSE false
#ifdef GCC_VERSION
#if (GCC_VERSION < 3000)
#define _Bool char
#endif
#else
#define _Bool char
#endif

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#ifndef module_param
#define module_param(v, t, p) MODULE_PARM(v, "i")
#endif

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK 0xffffffffffffffffULL
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK 0x00000000ffffffffULL
#endif

#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP 0x10
#endif

#ifndef uninitialized_var
#define uninitialized_var(x) ((x) = (x))
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net, pdev)
#endif

#ifdef HAVE_POLL_CONTROLLER
#define CONFIG_NET_POLL_CONTROLLER
#endif

#ifndef SKB_DATAREF_SHIFT
#define skb_header_cloned(x) 0
#endif

#ifndef NETIF_F_GSO
#define gso_size tso_size
#define gso_segs tso_segs
#endif

#ifndef NETIF_F_GRO
#define vlan_gro_receive(_napi, _vlgrp, _vlan, _skb) vlan_hwaccel_receive_skb(_skb, _vlgrp, _vlan)
#define napi_gro_receive(_napi, _skb) netif_receive_skb(_skb)
#endif

#ifndef NETIF_F_LRO
#define NETIF_F_LRO BIT(15)
#endif

#ifndef NETIF_F_NTUPLE
#define NETIF_F_NTUPLE BIT(27)
#endif

#ifndef NETIF_F_ALL_FCOE
#define NETIF_F_ALL_FCOE (NETIF_F_FCOE_CRC | NETIF_F_FCOE_MTU | NETIF_F_FSO)
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend, dev) .vendor = (vend), .device = (dev),
.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

#ifndef node_online
#define node_online(node) ((node) == 0)
#endif

// #ifndef cpu_online
// #define cpu_online(cpuid) test_bit((cpuid), &cpu_online_map)
// #endif

#ifndef _LINUX_RANDOM_H
#include <linux/random.h>
#endif

#ifndef BITS_PER_TYPE
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#endif

#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(bits) (((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#endif

#ifndef DECLARE_BITMAP
#define DECLARE_BITMAP(name, bits) long name[BITS_TO_LONGS(bits)]
#endif

#ifndef VLAN_HLEN
#define VLAN_HLEN 4
#endif

#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#if defined(__i386__) || defined(__x86_64__)
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#endif
#endif

/* taken from 2.6.24 definition in linux/kernel.h */
#ifndef IS_ALIGNED
#define IS_ALIGNED(x, a) (((x) % ((typeof(x))(a))) == 0)
#endif

#if !defined(NETIF_F_HW_VLAN_TX) && !defined(NETIF_F_HW_VLAN_CTAG_TX)
			 struct _kc_vlan_ethhdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};
#define vlan_ethhdr _kc_vlan_ethhdr
struct _kc_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};
#define vlan_hdr _kc_vlan_hdr
#define vlan_tx_tag_present(_skb) 0
#define vlan_tx_tag_get(_skb) 0
#endif /* NETIF_F_HW_VLAN_TX && NETIF_F_HW_VLAN_CTAG_TX */

#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT 13
#endif

#ifndef PCI_EXP_LNKSTA_CLS_2_5GB
#define PCI_EXP_LNKSTA_CLS_2_5GB 0x0001
#endif

#ifndef PCI_EXP_LNKSTA_CLS_5_0GB
#define PCI_EXP_LNKSTA_CLS_5_0GB 0x0002
#endif

#ifndef PCI_EXP_LNKSTA_CLS_8_0GB
#define PCI_EXP_LNKSTA_CLS_8_0GB 0x0003
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X1
#define PCI_EXP_LNKSTA_NLW_X1 0x0010
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X2
#define PCI_EXP_LNKSTA_NLW_X2 0x0020
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X4
#define PCI_EXP_LNKSTA_NLW_X4 0x0040
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X8
#define PCI_EXP_LNKSTA_NLW_X8 0x0080
#endif

#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif

#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part */
#endif

#ifndef ETH_GSTRING_LEN
#define ETH_GSTRING_LEN 32
#endif

#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS 0x1d
#undef ethtool_drvinfo
#define ethtool_drvinfo k_ethtool_drvinfo
struct k_ethtool_drvinfo {
	u32 cmd;
	char driver[32];
	char version[32];
	char fw_version[32];
	char bus_info[32];
	char reserved1[32];
	char reserved2[16];
	u32 n_stats;
	u32 testinfo_len;
	u32 eedump_len;
	u32 regdump_len;
};

struct ethtool_stats {
	u32 cmd;
	u32 n_stats;
	u64 data[];
};
#endif /* ETHTOOL_GSTATS */

#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS 0x1b
enum ethtool_stringset {
	ETH_SS_TEST = 0,
	ETH_SS_STATS,
};
struct ethtool_gstrings {
	u32 cmd; /* ETHTOOL_GSTRINGS */
	u32 string_set; /* string set id e.c. ETH_SS_TEST, etc*/
	u32 len; /* number of strings in the string set */
	u8 data[];
};
#endif /* ETHTOOL_GSTRINGS */

#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST 0x1a
enum ethtool_test_flags {
	ETH_TEST_FL_OFFLINE = BIT(0),
	ETH_TEST_FL_FAILED = BIT(1),
};
struct ethtool_test {
	u32 cmd;
	u32 flags;
	u32 reserved;
	u32 len;
	u64 data[];
};
#endif /* ETHTOOL_TEST */

#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM 0xb
#undef ETHTOOL_GREGS
struct ethtool_eeprom {
	u32 cmd;
	u32 magic;
	u32 offset;
	u32 len;
	u8 data[];
};

struct ethtool_value {
	u32 cmd;
	u32 data;
};
#endif /* ETHTOOL_GEEPROM */

#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK 0xa
#endif /* ETHTOOL_GLINK */

#ifndef ETHTOOL_GWOL
#define ETHTOOL_GWOL 0x5
#define ETHTOOL_SWOL 0x6
#define SOPASS_MAX 6
struct ethtool_wolinfo {
	u32 cmd;
	u32 supported;
	u32 wolopts;
	u8 sopass[SOPASS_MAX]; /* SecureOn(tm) password */
};
#endif /* ETHTOOL_GWOL */

#ifndef ETHTOOL_GREGS
#define ETHTOOL_GREGS 0x00000004 /* Get NIC registers */
#define ethtool_regs _kc_ethtool_regs
/* for passing big chunks of data */
struct _kc_ethtool_regs {
	u32 cmd;
	u32 version; /* driver-specific, indicates different chips/revs */
	u32 len; /* bytes */
	u8 data[];
};
#endif /* ETHTOOL_GREGS */

#ifndef ETHTOOL_GMSGLVL
#define ETHTOOL_GMSGLVL 0x00000007 /* Get driver message level */
#endif
#ifndef ETHTOOL_SMSGLVL
#define ETHTOOL_SMSGLVL 0x00000008 /* Set driver msg level, priv. */
#endif
#ifndef ETHTOOL_NWAY_RST
#define ETHTOOL_NWAY_RST 0x00000009 /* Restart autonegotiation, priv */
#endif
#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK 0x0000000a /* Get link status */
#endif
#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM 0x0000000b /* Get EEPROM data */
#endif
#ifndef ETHTOOL_SEEPROM
#define ETHTOOL_SEEPROM 0x0000000c /* Set EEPROM data */
#endif
#ifndef ETHTOOL_GCOALESCE
#define ETHTOOL_GCOALESCE 0x0000000e /* Get coalesce config */

#define ethtool_coalesce _kc_ethtool_coalesce
struct _kc_ethtool_coalesce {
	u32 cmd;

	u32 rx_coalesce_usecs;

	u32 rx_max_coalesced_frames;

	u32 rx_coalesce_usecs_irq;
	u32 rx_max_coalesced_frames_irq;

	u32 tx_coalesce_usecs;

	u32 tx_max_coalesced_frames;

	u32 tx_coalesce_usecs_irq;
	u32 tx_max_coalesced_frames_irq;

	u32 stats_block_coalesce_usecs;

	u32 use_adaptive_rx_coalesce;
	u32 use_adaptive_tx_coalesce;

	u32 pkt_rate_low;
	u32 rx_coalesce_usecs_low;
	u32 rx_max_coalesced_frames_low;
	u32 tx_coalesce_usecs_low;
	u32 tx_max_coalesced_frames_low;

	u32 pkt_rate_high;
	u32 rx_coalesce_usecs_high;
	u32 rx_max_coalesced_frames_high;
	u32 tx_coalesce_usecs_high;
	u32 tx_max_coalesced_frames_high;

	u32 rate_sample_interval;
};
#endif /* ETHTOOL_GCOALESCE */

#ifndef ETHTOOL_SCOALESCE
#define ETHTOOL_SCOALESCE 0x0000000f /* Set coalesce config. */
#endif
#ifndef ETHTOOL_GRINGPARAM
#define ETHTOOL_GRINGPARAM 0x00000010 /* Get ring parameters */

#define ethtool_ringparam _kc_ethtool_ringparam
struct _kc_ethtool_ringparam {
	u32 cmd;

	u32 rx_max_pending;
	u32 rx_mini_max_pending;
	u32 rx_jumbo_max_pending;
	u32 tx_max_pending;

	u32 rx_pending;
	u32 rx_mini_pending;
	u32 rx_jumbo_pending;
	u32 tx_pending;
};
#endif /* ETHTOOL_GRINGPARAM */

#ifndef ETHTOOL_SRINGPARAM
#define ETHTOOL_SRINGPARAM 0x00000011 /* Set ring parameters, priv. */
#endif
#ifndef ETHTOOL_GPAUSEPARAM
#define ETHTOOL_GPAUSEPARAM 0x00000012 /* Get pause parameters */

#define ethtool_pauseparam _kc_ethtool_pauseparam
struct _kc_ethtool_pauseparam {
	u32 cmd;
	u32 autoneg;
	u32 rx_pause;
	u32 tx_pause;
};
#endif /* ETHTOOL_GPAUSEPARAM */

#ifndef ETHTOOL_SPAUSEPARAM
#define ETHTOOL_SPAUSEPARAM 0x00000013 /* Set pause parameters. */
#endif
#ifndef ETHTOOL_GRXCSUM
#define ETHTOOL_GRXCSUM 0x00000014 /* Get RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_SRXCSUM
#define ETHTOOL_SRXCSUM 0x00000015 /* Set RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GTXCSUM
#define ETHTOOL_GTXCSUM 0x00000016 /* Get TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STXCSUM
#define ETHTOOL_STXCSUM 0x00000017 /* Set TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GSG
#define ETHTOOL_GSG 0x00000018
#endif
#ifndef ETHTOOL_SSG
#define ETHTOOL_SSG 0x00000019
#endif
#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST 0x0000001a /* execute NIC self-test, priv. */
#endif
#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS 0x0000001b /* get specified string set */
#endif
#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS 0x0000001d /* get NIC-specific statistics */
#endif
#ifndef ETHTOOL_GTSO
#define ETHTOOL_GTSO 0x0000001e /* Get TSO enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STSO
#define ETHTOOL_STSO 0x0000001f /* Set TSO enable (ethtool_value) */
#endif

#ifndef ETHTOOL_BUSINFO_LEN
#define ETHTOOL_BUSINFO_LEN 32
#endif

#ifndef WAKE_FILTER
#define WAKE_FILTER BIT(7)
#endif

#ifndef SPEED_2500
#define SPEED_2500 2500
#endif
#ifndef SPEED_5000
#define SPEED_5000 5000
#endif
#ifndef SPEED_14000
#define SPEED_14000 14000
#endif
#ifndef SPEED_25000
#define SPEED_25000 25000
#endif
#ifndef SPEED_50000
#define SPEED_50000 50000
#endif
#ifndef SPEED_56000
#define SPEED_56000 56000
#endif
#ifndef SPEED_100000
#define SPEED_100000 100000
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif
#ifndef AX_RELEASE_VERSION
#define AX_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

#ifndef AX_RELEASE_CODE
#define AX_RELEASE_CODE 0
#endif

#ifdef __KLOCWORK__
/* The following are not compiled into the binary driver; they are here
 * only to tune Klocwork scans to workaround false-positive issues.
 */
#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define memcpy(dest, src, len) memcpy_s(dest, len, src, len)
#define memset(dest, ch, len) memset_s(dest, len, ch, len)

static inline int _kc_test_and_clear_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags = 0;

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old & ~mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}
#define test_and_clear_bit(nr, addr) _kc_test_and_clear_bit(nr, addr)

static inline int _kc_test_and_set_bit(int nr, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags = 0;

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old | mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}
#define test_and_set_bit(nr, addr) _kc_test_and_set_bit(nr, addr)

#ifdef uninitialized_var
#undef uninitialized_var
#define uninitialized_var(x) ((x) = (*(&(x))))
#endif

#ifdef WRITE_ONCE
#undef WRITE_ONCE
#define WRITE_ONCE(x, val) ((x) = (val))
#endif /* WRITE_ONCE */
#endif /* __KLOCWORK__ */

#include "vfd.h"
struct vfd_objects *create_vfd_sysfs(struct pci_dev *pdev, int num_alloc_vfs);
void destroy_vfd_sysfs(struct pci_dev *pdev, struct vfd_objects *vfd_obj);

/* Older versions of GCC will trigger -Wformat-nonliteral warnings for const
 * char * strings. Unfortunately, the implementation of do_trace_printk does
 * this, in order to add a storage attribute to the memory. This was fixed in
 * GCC 5.1, but we still use older distributions built with GCC 4.x.
 *
 * The string pointer is only passed as a const char * to the __trace_bprintk
 * function. Since that function has the __printf attribute, it will trigger
 * the warnings. We can't remove the attribute, so instead we'll use the
 * __diag macro to disable -Wformat-nonliteral around the call to
 * __trace_bprintk.
 */
#if GCC_VERSION < 50100
#define __trace_bprintk(ip, fmt, args...)               \
	({                                              \
		int err;                                \
		__diag_push();                          \
		__diag(ignored "-Wformat-nonliteral");  \
		err = __trace_bprintk(ip, fmt, ##args); \
		__diag_pop();                           \
		err;                                    \
	})
#endif /* GCC_VERSION < 5.1.0 */

#define HAVE_SCTP

static inline struct device *pci_dev_to_dev(struct pci_dev *pdev)
{
	return &pdev->dev;
}

#undef HAVE_PCI_ERS
#define HAVE_PCI_ERS

#include <linux/aer.h>
#include <linux/pci_hotplug.h>

#define NEW_SKB_CSUM_HELP

#define HAVE_DEVICE_NUMA_NODE

static inline struct device *netdev_to_dev(struct net_device *netdev)
{
	return &netdev->dev;
}

#define ETH_TYPE_TRANS_SETS_DEV
#define HAVE_NETDEV_STATS_IN_NETDEV

#define HAVE_ETHTOOL_GET_SSET_COUNT
#define HAVE_NETDEV_NAPI_LIST

#define NETDEV_CAN_SET_GSO_MAX_SIZE
#ifdef HAVE_PCI_ASPM_H
#include <linux/pci-aspm.h>
#endif
#define HAVE_NETDEV_VLAN_FEATURES
#ifndef PCI_EXP_LNKCAP_ASPMS
#define PCI_EXP_LNKCAP_ASPMS 0x00000c00 /* ASPM Support */
#endif /* PCI_EXP_LNKCAP_ASPMS */

#include <net/sch_generic.h>
#define ethtool_cmd_speed_set _kc_ethtool_cmd_speed_set
static inline void _kc_ethtool_cmd_speed_set(struct ethtool_cmd *ep, __u32 speed)
{
	ep->speed = (__u16)(speed & 0xFFFF);
	ep->speed_hi = (__u16)(speed >> 16);
}
#define HAVE_TX_MQ
#define HAVE_NETDEV_SELECT_QUEUE
#ifdef CONFIG_DEBUG_FS
#define HAVE_IXGBE_DEBUG_FS
#define HAVE_IGB_DEBUG_FS
#endif /* CONFIG_DEBUG_FS */

#ifndef HAVE_NET_DEVICE_OPS
#define HAVE_NET_DEVICE_OPS
#endif
#ifdef CONFIG_DCB
#define HAVE_PFC_MODE_ENABLE
#endif /* CONFIG_DCB */

#define HAVE_ASPM_QUIRKS
#define HAVE_PCI_DEV_IS_VIRTFN_BIT

#ifndef HAVE_NETDEV_STORAGE_ADDRESS
#define HAVE_NETDEV_STORAGE_ADDRESS
#endif
#ifndef HAVE_NETDEV_HW_ADDR
#define HAVE_NETDEV_HW_ADDR
#endif
#ifndef HAVE_TRANS_START_IN_QUEUE
#define HAVE_TRANS_START_IN_QUEUE
#endif
#ifndef HAVE_INCLUDE_LINUX_MDIO_H
#define HAVE_INCLUDE_LINUX_MDIO_H
#endif
#include <linux/mdio.h>

#ifdef CONFIG_DCB
#ifndef HAVE_DCBNL_OPS_GETAPP
#define HAVE_DCBNL_OPS_GETAPP
#endif
#endif /* CONFIG_DCB */
#include <linux/pm_runtime.h>
/* IOV bad DMA target work arounds require at least this kernel rev support */
#define HAVE_PCIE_TYPE

#define HAVE_SYSTEM_SLEEP_PM_OPS
#ifndef HAVE_SET_RX_MODE
#define HAVE_SET_RX_MODE
#endif

#define HAVE_STRUCT_DEVICE_OF_NODE
#define HAVE_PM_QOS_REQUEST_LIST
#define HAVE_IRQ_AFFINITY_HINT
#include <linux/of.h>

#define HAVE_PM_QOS_REQUEST_ACTIVE
#define HAVE_8021P_SUPPORT
#define HAVE_NDO_GET_STATS64

#ifndef HAVE_MQPRIO
#define HAVE_MQPRIO
#endif
#ifndef HAVE_SETUP_TC
#define HAVE_SETUP_TC
#endif
#ifdef CONFIG_DCB
#ifndef HAVE_DCBNL_IEEE
#define HAVE_DCBNL_IEEE
#endif
#endif /* CONFIG_DCB */
#ifndef HAVE_NDO_SET_FEATURES
#define HAVE_NDO_SET_FEATURES
#endif
#define HAVE_IRQ_AFFINITY_NOTIFY

/* use < 2.6.40 because of a Fedora 15 kernel update where they
 * updated the kernel version to 2.6.40.x and they back-ported 3.0 features
 * like set_phys_id for ethtool.
 */
#define HAVE_ETHTOOL_SET_PHYS_ID

#ifndef HAVE_DCBNL_IEEE_DELAPP
#define HAVE_DCBNL_IEEE_DELAPP
#endif

#ifndef HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_VF_SPOOFCHK_CONFIGURE
#endif
#ifndef HAVE_SKB_L4_RXHASH
#define HAVE_SKB_L4_RXHASH
#endif
#define HAVE_IOMMU_PRESENT
#define HAVE_PM_QOS_REQUEST_LIST_NEW

#define HAVE_ETHTOOL_GRXFHINDIR_SIZE
#define HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef ETHTOOL_SRXNTUPLE
#undef ETHTOOL_SRXNTUPLE
#endif

#include <linux/kconfig.h>

#if !defined(NO_PTP_SUPPORT) && IS_ENABLED(CONFIG_PTP_1588_CLOCK)
#define HAVE_PTP_1588_CLOCK
#endif /* !NO_PTP_SUPPORT && IS_ENABLED(CONFIG_PTP_1588_CLOCK) */

#include <linux/of_net.h>
#define HAVE_FDB_OPS
#define HAVE_ETHTOOL_GET_TS_INFO

#define HAVE_STRUCT_PAGE_PFMEMALLOC

/******************************************************************************/
#include <linux/hashtable.h>
#define HAVE_CONST_STRUCT_PCI_ERROR_HANDLERS
#define USE_CONST_DEV_UC_CHAR
#define HAVE_NDO_FDB_ADD_NLATTR

#ifndef HAVE_ENCAP_CSUM_OFFLOAD
#define HAVE_ENCAP_CSUM_OFFLOAD
#endif

#ifndef HAVE_GRE_ENCAP_OFFLOAD
#define HAVE_GRE_ENCAP_OFFLOAD
#endif

#ifndef HAVE_SRIOV_CONFIGURE
#define HAVE_SRIOV_CONFIGURE
#endif

#define HAVE_BRIDGE_ATTRIBS
#ifndef BRIDGE_MODE_VEB
#define BRIDGE_MODE_VEB 0 /* Default loopback mode */
#endif /* BRIDGE_MODE_VEB */
#ifndef BRIDGE_MODE_VEPA
#define BRIDGE_MODE_VEPA 1 /* 802.1Qbg defined VEPA mode */
#endif /* BRIDGE_MODE_VEPA */

#define HAVE_BRIDGE_FILTER
#define HAVE_FDB_DEL_NLATTR

#define HAVE_NDO_SET_VF_LINK_STATE

#define HAVE_NDO_GET_PHYS_PORT_ID
#define HAVE_NETIF_SET_XPS_QUEUE_CONST_MASK

#define HAVE_VXLAN_CHECKS

/* for ndo_dfwd_ ops add_station, del_station and _start_xmit */
#ifndef HAVE_NDO_DFWD_OPS
#define HAVE_NDO_DFWD_OPS
#endif

#define HAVE_NET_GET_RANDOM_ONCE
#define HAVE_PTP_1588_CLOCK_PINS
#define HAVE_NETDEV_PORT

#define HAVE_NDO_SET_VF_MIN_MAX_TX_RATE

#define HAVE_DCBNL_OPS_SETAPP_RETURN_INT
#include <linux/time64.h>
#define HAVE_RHASHTABLE

#define HAVE_SKBUFF_CSUM_LEVEL
#ifndef HAVE_UOS_RELEASE_CODE
#define HAVE_SKB_XMIT_MORE
#endif
#define HAVE_SKB_INNER_PROTOCOL_TYPE

#define HAVE_NDO_FEATURES_CHECK

#define HAVE_NDO_FDB_ADD_VID
#define HAVE_NDO_FDB_DEL_VID
#define HAVE_RXFH_HASHFUNC
#define NDO_DFLT_BRIDGE_GETLINK_HAS_BRFLAGS

#define HAVE_INCLUDE_LINUX_TIMECOUNTER_H
#define HAVE_NDO_BRIDGE_SET_DEL_LINK_FLAGS

#define HAVE_DDP_PROFILE_UPLOAD_SUPPORT

#define HAVE_NDO_GET_PHYS_PORT_NAME
#define HAVE_PTP_CLOCK_INFO_GETTIME64
#define HAVE_NDO_BRIDGE_GETLINK_NLFLAGS
#define HAVE_PASSTHRU_FEATURES_CHECK
#define HAVE_NDO_SET_VF_RSS_QUERY_EN
#define HAVE_NDO_SET_TX_MAXRATE

#undef HAVE_STRUCT_PAGE_PFMEMALLOC

#define HAVE_NDO_DFLT_BRIDGE_GETLINK_VLAN_SUPPORT
#define HAVE_VF_STATS

#include <net/dst_metadata.h>

#define HAVE_NDO_SET_VF_TRUST

#ifndef CONFIG_64BIT
#include <linux/io-64-nonatomic-lo-hi.h> /* 32-bit readq/writeq */
#endif /* !CONFIG_64BIT */

#define HAVE_NETIF_NAPI_ADD_CALLS_NAPI_HASH_ADD
#define HAVE_NETDEV_UPPER_INFO

#define HAVE_PAGE_COUNT_BULK_UPDATE
#define HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
#define HAVE_PTP_CROSSTIMESTAMP
#define HAVE_TC_SETUP_CLSU32

#define HAVE_NETIF_TRANS_UPDATE
#define HAVE_ETHTOOL_CONVERT_U32_AND_LINK_MODE
#define HAVE_ETHTOOL_25G_BITS
#define HAVE_ETHTOOL_50G_BITS
#define HAVE_ETHTOOL_100G_BITS
#define HAVE_TCF_MIRRED_REDIRECT

#define HAVE_UDP_ENC_RX_OFFLOAD

#define HAVE_FLOW_DISSECTOR_KEY_VLAN_PRIO
#define HAVE_ETHTOOL_NEW_1G_BITS
#define HAVE_ETHTOOL_NEW_10G_BITS

#define HAVE_TC_FLOWER_ENC
#define HAVE_NETDEVICE_MIN_MAX_MTU
#define HAVE_SWIOTLB_SKIP_CPU_SYNC
#define HAVE_NETDEV_TC_RESETS_XPS
#define HAVE_XPS_QOS_SUPPORT
#define HAVE_DEV_WALK_API
#define HAVE_ETHTOOL_NEW_2500MB_BITS
#define HAVE_ETHTOOL_5G_BITS
/* kernel 4.10 onwards, as part of busy_poll rewrite, new state were added
 * which is part of NAPI:state. If NAPI:state=NAPI_STATE_IN_BUSY_POLL,
 * it means napi_poll is invoked in busy_poll context
 */
#define HAVE_NAPI_STATE_IN_BUSY_POLL
#define HAVE_TCF_MIRRED_EGRESS_REDIRECT

#define HAVE_VOID_NDO_GET_STATS64
#define HAVE_VM_OPS_FAULT_NO_VMA

#define HAVE_METADATA_PORT_INFO
#define HAVE_HWTSTAMP_FILTER_NTP_ALL
#define HAVE_NDO_SETUP_TC_CHAIN_INDEX
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
#define HAVE_PTP_CLOCK_DO_AUX_WORK

#define HAVE_XDP_SUPPORT
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#define HAVE_TCF_EXTS_HAS_ACTION

#include <linux/phy.h>

#define HAVE_NDO_BPF
#define HAVE_XDP_BUFF_DATA_META
#define HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
#define HAVE_TCF_BLOCK

#include <linux/nospec.h>
#define HAVE_XDP_BUFF_RXQ
#define HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
#define HAVE_TCF_MIRRED_DEV
#define HAVE_VF_STATS_DROPPED

#define HAVE_XDP_BUFF_IN_XDP_H

#include <linux/overflow.h>
#include <net/xdp_sock.h>
#define HAVE_AF_XDP_SUPPORT

#define HAVE_DEVLINK_ESWITCH_OPS_EXTACK
#define HAVE_AF_XDP_ZC_SUPPORT
#define HAVE_VXLAN_TYPE
#define HAVE_ETF_SUPPORT /* Earliest TxTime First */

#define HAVE_PTP_SYS_OFFSET_EXTENDED_IOCTL
#define HAVE_NDO_BRIDGE_SETLINK_EXTACK
#define HAVE_DMA_ALLOC_COHERENT_ZEROES_MEM
#define HAVE_GENEVE_TYPE
#define HAVE_TC_INDIR_BLOCK

#define HAVE_NDO_FDB_ADD_EXTACK
#define NO_XDP_QUERY_XSK_UMEM
#define HAVE_AF_XDP_NETDEV_UMEM
#define HAVE_TC_FLOW_RULE_INFRASTRUCTURE
#define HAVE_TC_FLOWER_ENC_IP
#define HAVE_DEVLINK_INFO_GET
#define HAVE_DEVLINK_FLASH_UPDATE
#define HAVE_DEVLINK_PORT_PARAMS

#define HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED
#define SPIN_UNLOCK_IMPLIES_MMIOWB
#define HAVE_NDO_GET_DEVLINK_PORT

#define XSK_UMEM_RETURNS_XDP_DESC
#define HAVE_FLOW_BLOCK_API
#define HAVE_DEVLINK_PORT_ATTR_PCI_VF
#if IS_ENABLED(CONFIG_DIMLIB)
#define HAVE_CONFIG_DIMLIB
#endif

#define HAVE_NDO_XSK_WAKEUP

#define HAVE_TX_TIMEOUT_TXQUEUE

#define HAVE_DEVLINK_REGION_OPS_SNAPSHOT
#define HAVE_ETHTOOL_COALESCE_PARAMS_SUPPORT

#define HAVE_TC_FLOW_INDIR_DEV
#define HAVE_TC_FLOW_INDIR_BLOCK_CLEANUP
#define HAVE_XDP_BUFF_FRAME_SZ
#define HAVE_MEM_TYPE_XSK_BUFF_POOL

#define HAVE_FLOW_INDIR_BLOCK_QDISC
#define HAVE_UDP_TUNNEL_NIC_INFO

#define HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS
#define HAVE_DEVLINK_FLASH_UPDATE_PARAMS
#define HAVE_NETDEV_BPF_XSK_POOL

#define HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FW

	static inline int pci_enable_pcie_error_reporting(struct pci_dev __always_unused *dev)
	{
		return 0;
	}
#define pci_disable_pcie_error_reporting(dev) \
	do {                                  \
	} while (0)

#endif /* _KCOMPAT_H_ */
