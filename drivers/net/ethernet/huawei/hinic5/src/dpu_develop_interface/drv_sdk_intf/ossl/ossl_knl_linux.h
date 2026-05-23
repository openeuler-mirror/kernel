/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : ossl_knl_linux.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef OSSL_KNL_LINUX_H_
#define OSSL_KNL_LINUX_H_

#include <net/ipv6.h>
#include <net/checksum.h>
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
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "sdk_kcompat.h"
#include "ossl_knl_linux_nic.h"
#ifdef HAVE_XDP_SUPPORT
#include <net/xdp.h>
#endif /* HAVE_XDP_SUPPORT */

/* UTS_RELEASE is in a different header starting in kernel 2.6.18 */
#ifndef UTS_RELEASE
/* utsrelease.h changed locations in 2.6.33 */
#if (KERNEL_VERSION(2, 6, 33) > LINUX_VERSION_CODE)
#include <linux/utsrelease.h>
#else
#include <generated/utsrelease.h>
#endif
#endif

#undef __always_unused
#define __always_unused __attribute__((__unused__))

#define ossl_get_free_pages __get_free_pages

#ifndef high_16_bits
#define low_16_bits(x) ((x) & 0xFFFF)
#define high_16_bits(x) (((x) & 0xFFFF0000) >> 16)
#endif

#ifndef U8_MAX
#define U8_MAX 0xFF
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

#if (defined(AX_RELEASE_CODE) && AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3, 0))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5, 0)
#elif (defined(AX_RELEASE_CODE) && AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3, 1))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5, 1)
#elif (defined(AX_RELEASE_CODE) && AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3, 2))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5, 3)
#endif

#ifndef RHEL_RELEASE_CODE
/* NOTE: RHEL_RELEASE_* introduced in RHEL4.5. */
#define RHEL_RELEASE_CODE 0
#endif

/* RHEL 7 didn't backport the parameter change in
 * create_singlethread_workqueue.
 * If/when RH corrects this we will want to tighten up the version check.
 */
#if (defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0))
#undef create_singlethread_workqueue
#define create_singlethread_workqueue(name) \
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)
#endif

/* Ubuntu Release ABI is the 4th digit of their kernel version. You can find
 * it in /usr/src/linux/$(uname -r)/include/generated/utsrelease.h for new
 * enough versions of Ubuntu. Otherwise you can simply see it in the output of
 * uname as the 4th digit of the kernel. The UTS_UBUNTU_RELEASE_ABI is not in
 * the linux-source package, but in the linux-headers package. It begins to
 * appear in later releases of 14.04 and 14.10.
 *
 * Ex:
 * <Ubuntu 14.04.1>
 * $uname -r
 * 3.13.0-45-generic
 * ABI is 45
 *
 * <Ubuntu 14.10>
 * $uname -r
 * 3.16.0-23-generic
 * ABI is 23.
 */
#ifndef UTS_UBUNTU_RELEASE_ABI
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#else

#ifndef __HULK_3_10__
/* Ubuntu does not provide actual release version macro, so we use the kernel
 * version plus the ABI to generate a unique version code specific to Ubuntu.
 * In addition, we mask the lower 8 bits of LINUX_VERSION_CODE in order to
 * ignore differences in sublevel which are not important since we have the
 * ABI value. Otherwise, it becomes impossible to correlate ABI to version for
 * ordering checks.
 */
#define UBUNTU_VERSION_CODE \
	(((~0xFF & LINUX_VERSION_CODE) << 8) + UTS_UBUNTU_RELEASE_ABI)
#endif
#if UTS_UBUNTU_RELEASE_ABI > 255
#error UTS_UBUNTU_RELEASE_ABI is too large...
#endif /* UTS_UBUNTU_RELEASE_ABI > 255 */

#if (KERNEL_VERSION(3, 0, 0) >= LINUX_VERSION_CODE)
/* Our version code scheme does not make sense for non 3.x or newer kernels,
 * and we have no support in kcompat for this scenario. Thus, treat this as a
 * non-Ubuntu kernel. Possibly might be better to error here.
 */
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#endif
#endif

/* Note that the 3rd digit is always zero, and will be ignored. This is
 * because Ubuntu kernels are based on x.y.0-ABI values, and while their linux
 * version codes are 3 digit, this 3rd digit is superseded by the ABI value.
 */
#define UBUNTU_VERSION(a, b, c, d) ((KERNEL_VERSION(a, b, 0) << 8) + (d))

#ifndef DEEPIN_PRODUCT_VERSION
#define DEEPIN_PRODUCT_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifdef CONFIG_DEEPIN_KERNEL
#if (KERNEL_VERSION(4, 4, 102) == LINUX_VERSION_CODE)
#define DEEPIN_VERSION_CODE DEEPIN_PRODUCT_VERSION(15, 2, 0)
#endif
#endif

#ifndef DEEPIN_VERSION_CODE
#define DEEPIN_VERSION_CODE 0
#endif

/* SuSE version macros are the same as Linux kernel version macro. */
#ifndef SLE_VERSION
#define SLE_VERSION(a, b, c) KERNEL_VERSION(a, b, c)
#endif
#define SLE_LOCALVERSION(a, b, c) KERNEL_VERSION(a, b, c)
#ifdef CONFIG_SUSE_KERNEL
#if (KERNEL_VERSION(2, 6, 27) == LINUX_VERSION_CODE)
/* SLES11 GA is 2.6.27 based. */
#define SLE_VERSION_CODE SLE_VERSION(11, 0, 0)
#elif (KERNEL_VERSION(2, 6, 32) == LINUX_VERSION_CODE)
/* SLES11 SP1 is 2.6.32 based. */
#define SLE_VERSION_CODE SLE_VERSION(11, 1, 0)
#elif (KERNEL_VERSION(3, 0, 13) == LINUX_VERSION_CODE)
/* SLES11 SP2 GA is 3.0.13-0.27. */
#define SLE_VERSION_CODE SLE_VERSION(11, 2, 0)
#elif (KERNEL_VERSION(3, 0, 76) == LINUX_VERSION_CODE)
/* SLES11 SP3 GA is 3.0.76-0.11. */
#define SLE_VERSION_CODE SLE_VERSION(11, 3, 0)
#elif (KERNEL_VERSION(3, 0, 101) == LINUX_VERSION_CODE)
/* SLES11 SP4 GA (3.0.101-63) and update kernels 3.0.101-63+ */
#define SLE_VERSION_CODE SLE_VERSION(11, 4, 0)
#elif (KERNEL_VERSION(3, 12, 28) == LINUX_VERSION_CODE)
/*
 * SLES12 GA is 3.12.28-4
 * kernel updates 3.12.xx-<33 through 52>[.yy].
 */
#define SLE_VERSION_CODE SLE_VERSION(12, 0, 0)
#elif (KERNEL_VERSION(3, 12, 49) == LINUX_VERSION_CODE)
/*
 * SLES12 SP1 GA is 3.12.49-11
 * updates 3.12.xx-60.yy where xx={51..}
 */
#define SLE_VERSION_CODE SLE_VERSION(12, 1, 0)
#elif ((KERNEL_VERSION(4, 4, 21) <= LINUX_VERSION_CODE && \
	(KERNEL_VERSION(4, 4, 59) >= LINUX_VERSION_CODE)) || \
	(KERNEL_VERSION(4, 4, 74) <= LINUX_VERSION_CODE && \
	KERNEL_VERSION(4, 5, 0) > LINUX_VERSION_CODE &&     \
	KERNEL_VERSION(92, 0, 0) <= SLE_LOCALVERSION_CODE && \
	KERNEL_VERSION(93, 0, 0) > SLE_LOCALVERSION_CODE))
/*
 * SLES12 SP2 GA is 4.4.21-69.
 * SLES12 SP2 updates before SLES12 SP3 are: 4.4.{21,38,49,59}
 * SLES12 SP2 updates after SLES12 SP3 are: 4.4.{74,90,103,114,120}
 * but they all use a SLE_LOCALVERSION_CODE matching 92.nn.y
 */
#define SLE_VERSION_CODE SLE_VERSION(12, 2, 0)
#elif ((KERNEL_VERSION(4, 4, 73) == LINUX_VERSION_CODE || \
	KERNEL_VERSION(4, 4, 82) == LINUX_VERSION_CODE ||      \
	KERNEL_VERSION(4, 4, 92)) == LINUX_VERSION_CODE ||     \
	(KERNEL_VERSION(4, 4, 103) == LINUX_VERSION_CODE &&    \
	(KERNEL_VERSION(6, 33, 0) == LINUX_VERSION_CODE ||  \
	KERNEL_VERSION(6, 38, 0) == SLE_LOCALVERSION_CODE)) || \
	(KERNEL_VERSION(4, 4, 114) <= LINUX_VERSION_CODE && \
	KERNEL_VERSION(4, 5, 0) > LINUX_VERSION_CODE &&          \
	KERNEL_VERSION(94, 0, 0) <= SLE_LOCALVERSION_CODE && \
	KERNEL_VERSION(95, 0, 0) > SLE_LOCALVERSION_CODE))
/* SLES12 SP3 GM is 4.4.73-5 and update kernels are 4.4.82-6.3.
 * SLES12 SP3 updates not conflicting with SP2 are: 4.4.{82,92}
 * SLES12 SP3 updates conflicting with SP2 are:
 * - 4.4.103-6.33.1, 4.4.103-6.38.1
 * - 4.4.{114,120}-94.nn.y
 */
#define SLE_VERSION_CODE SLE_VERSION(12, 3, 0)
#elif (KERNEL_VERSION(4, 12, 14) <= LINUX_VERSION_CODE)
/* SLES15 Beta1 is 4.12.14-2.
 * SLES12 SP4 will also use 4.12.14-nn.xx.y
 */
#define SLE_VERSION_CODE SLE_VERSION(15, 0, 0)

#include <linux/suse_version.h>

/*
 * new SLES kernels must be added here with >= based on kernel
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
#ifndef SUSE_PRODUCT_CODE
#define SUSE_PRODUCT_CODE 0
#endif /* SUSE_PRODUCT_CODE */
#ifndef SUSE_PRODUCT
#define SUSE_PRODUCT(product, version, patchlevel, auxrelease) \
	(((product) << 24) + ((version) << 16) + \
	((patchlevel) << 8) + (auxrelease))
#endif /* SUSE_PRODUCT */

#ifndef ALIGN_DOWN
#ifndef __ALIGN_KERNEL
#define __ALIGN_KERNEL(x, a) __ALIGN_MASK(x, (typeof(x))(a) - 1)
#endif
#define ALIGN_DOWN(x, a) __ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif
/* ************************************************************************ */
/* mm buddy */
#ifndef MAX_ORDER
#ifdef MAX_PAGE_ORDER
#define MAX_ORDER MAX_PAGE_ORDER
#endif /* MAX_PAGE_ORDER */
#endif /* !MAX_ORDER */

/* ************************************************************************ */
#if (KERNEL_VERSION(2, 6, 22) > LINUX_VERSION_CODE)
#define tcp_hdr(skb) ((skb)->h.th)
#define tcp_hdrlen(skb) ((skb)->h.th->doff << 2)
#define skb_transport_offset(skb) ((skb)->h.raw - (skb)->data)
#define skb_transport_header(skb) ((skb)->h.raw)
#define ipv6_hdr(skb) ((skb)->nh.ipv6h)
#define ip_hdr(skb) ((skb)->nh.iph)
#define skb_network_header(skb) ((skb)->nh.raw)
#define skb_tail_pointer(skb) ((skb)->tail)
#define skb_reset_tail_pointer(skb) ((skb)->tail = (skb)->data)
#define skb_set_tail_pointer(skb, offset) \
	((skb)->tail = (skb)->data + (offset))
#define skb_copy_to_linear_data(skb, from, len) memcpy(skb->data, from, len)
#define pci_register_driver pci_module_init

#ifdef NETIF_F_MULTI_QUEUE
#ifndef alloc_etherdev_mq
#define alloc_etherdev_mq(_a, _b) alloc_etherdev(_a)
#endif
#endif /* NETIF_F_MULTI_QUEUE */

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN 4
#endif
#define cancel_work_sync(x) flush_scheduled_work()
#ifndef udp_hdr
#define udp_hdr _udp_hdr
static inline struct udphdr *_udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}
#endif

#ifdef cpu_to_be16
#undef cpu_to_be16
#endif
#define cpu_to_be16(x) __constant_htons(x)
#endif /* < 2.6.22 */

/* ************************************************************************ */
#if (KERNEL_VERSION(2, 6, 32) > LINUX_VERSION_CODE)
#undef netdev_tx_t
#define netdev_tx_t int
#endif /* < 2.6.32 */

/* ************************************************************************ */
#if (KERNEL_VERSION(2, 6, 33) > LINUX_VERSION_CODE)
#ifndef IPV4_FLOW
#define IPV4_FLOW 0x10
#endif /* IPV4_FLOW */
#ifndef IPV6_FLOW
#define IPV6_FLOW 0x11
#endif /* IPV6_FLOW */

#ifndef __percpu
#define __percpu
#endif /* __percpu */

#ifndef PORT_DA
#define PORT_DA PORT_OTHER
#endif /* PORT_DA */
#ifndef PORT_NONE
#define PORT_NONE PORT_OTHER
#endif

#if ((RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(6, 3) <= RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 0) > RHEL_RELEASE_CODE)))
#if !defined(CONFIG_X86_32) && !defined(CONFIG_NEED_DMA_MAP_STATE)
#undef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME) dma_addr_t ADDR_NAME
#undef DEFINE_DMA_UNMAP_LEN
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME) __u32 LEN_NAME
#undef dma_unmap_addr
#define dma_unmap_addr(PTR, ADDR_NAME) ((PTR)->ADDR_NAME)
#undef dma_unmap_addr_set
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL) (((PTR)->ADDR_NAME) = (VAL))
#undef dma_unmap_len
#define dma_unmap_len(PTR, LEN_NAME) ((PTR)->LEN_NAME)
#undef dma_unmap_len_set
#define dma_unmap_len_set(PTR, LEN_NAME, VAL) (((PTR)->LEN_NAME) = (VAL))
#endif /* CONFIG_X86_64 && !CONFIG_NEED_DMA_MAP_STATE */
#endif /* RHEL_RELEASE_CODE */

#if (!(RHEL_RELEASE_CODE && (RHEL_RELEASE_VERSION(6, 2) <= RHEL_RELEASE_CODE)))
#define sk_tx_queue_get(_sk) (-1)
#define sk_tx_queue_set(_sk, _tx_queue) \
	do {                                \
	} while (0)
#endif /* !(RHEL >= 6.2) */
#endif /* < 2.6.33 */

/* ************************************************************************ */
#if (KERNEL_VERSION(2, 6, 34) > LINUX_VERSION_CODE)
#if (RHEL_RELEASE_VERSION(6, 0) > RHEL_RELEASE_CODE)
#ifndef pci_num_vf
#define pci_num_vf(pdev) _kc_pci_num_vf(pdev)
int _kc_pci_num_vf(struct pci_dev *dev);
#endif
#endif /* RHEL_RELEASE_CODE */

#ifndef ETH_FLAG_NTUPLE
#define ETH_FLAG_NTUPLE NETIF_F_NTUPLE
#endif

#ifndef netdev_mc_count
#define netdev_mc_count(dev) ((dev)->mc_count)
#endif
#ifndef netdev_mc_empty
#define netdev_mc_empty(dev) (netdev_mc_count(dev) == 0)
#endif
#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = dev->mc_list; mclist; mclist = mclist->next)
#endif
#ifndef netdev_uc_count
#define netdev_uc_count(dev) ((dev)->uc.count)
#endif
#ifndef netdev_uc_empty
#define netdev_uc_empty(dev) (netdev_uc_count(dev) == 0)
#endif
#ifndef netdev_for_each_uc_addr
#define netdev_for_each_uc_addr(ha, dev) \
	list_for_each_entry(ha, &dev->uc.list, list)
#endif
#ifndef dma_set_coherent_mask
#define dma_set_coherent_mask(dev, mask) \
	pci_set_consistent_dma_mask(to_pci_dev(dev), (mask))
#endif

/* netdev logging taken from include/linux/netdevice.h */
#ifndef netdev_name
static inline const char *_kc_netdev_name(const struct net_device *dev)
{
	if (dev->reg_state != NETREG_REGISTERED)
		return "(unregistered net_device)";
	return dev->name;
}

#define netdev_name(netdev) _kc_netdev_name(netdev)
#endif /* netdev_name */

#undef netdev_emerg
#define netdev_emerg(dev, format, args...) \
	netdev_printk(KERN_EMERG, dev, format, ##args)
#undef netdev_alert
#define netdev_alert(dev, format, args...) \
	netdev_printk(KERN_ALERT, dev, format, ##args)
#undef netdev_crit
#define netdev_crit(dev, format, args...) \
	netdev_printk(KERN_CRIT, dev, format, ##args)
#undef netdev_err
#define netdev_err(dev, format, args...) \
	netdev_printk(KERN_ERR, dev, format, ##args)
#undef netdev_warn
#define netdev_warn(dev, format, args...) \
	netdev_printk(KERN_WARNING, dev, format, ##args)
#undef netdev_notice
#define netdev_notice(dev, format, args...) \
	netdev_printk(KERN_NOTICE, dev, format, ##args)
#undef netdev_info
#define netdev_info(dev, format, args...) \
	netdev_printk(KERN_INFO, dev, format, ##args)
#undef netdev_dbg
#if defined(DEBUG)
#define netdev_dbg(__dev, format, args...) \
	netdev_printk(KERN_DEBUG, __dev, format, ##args)
#elif defined(CONFIG_DYNAMIC_DEBUG)
#define netdev_dbg(__dev, format, args...)                  \
	dynamic_dev_dbg((__dev)->dev.parent, "%s: " format, \
			netdev_name(__dev), ##args)
#else /* DEBUG */
#define netdev_dbg(__dev, format, args...)                    \
	({                                                        \
		if (0)                                                \
			netdev_printk(KERN_DEBUG, __dev, format, ##args); \
		0;                                                    \
	})
#endif /* DEBUG */

#undef netif_printk
#define netif_printk(priv, type, level, dev, fmt, args...) \
	do {                                                   \
		if (netif_msg_##type(priv) != 0)                        \
			netdev_printk(level, (dev), fmt, ##args);      \
	} while (0)

#undef netif_emerg
#define netif_emerg(priv, type, dev, fmt, args...) \
	netif_level(emerg, priv, type, dev, fmt, ##args)
#undef netif_alert
#define netif_alert(priv, type, dev, fmt, args...) \
	netif_level(alert, priv, type, dev, fmt, ##args)
#undef netif_crit
#define netif_crit(priv, type, dev, fmt, args...) \
	netif_level(crit, priv, type, dev, fmt, ##args)
#undef netif_err
#define netif_err(priv, type, dev, fmt, args...) \
	netif_level(err, priv, type, dev, fmt, ##args)
#undef netif_warn
#define netif_warn(priv, type, dev, fmt, args...) \
	netif_level(warn, priv, type, dev, fmt, ##args)
#undef netif_notice
#define netif_notice(priv, type, dev, fmt, args...) \
	netif_level(notice, priv, type, dev, fmt, ##args)
#undef netif_info
#define netif_info(priv, type, dev, fmt, args...) \
	netif_level(info, priv, type, dev, fmt, ##args)
#undef netif_dbg
#define netif_dbg(priv, type, dev, fmt, args...) \
	netif_level(dbg, priv, type, dev, fmt, ##args)

#ifndef for_each_set_bit
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	(bit) < (size); (bit) = find_next_bit((addr), (size), (bit) + 1))
#endif /* for_each_set_bit */

#ifndef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR DECLARE_PCI_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_LEN DECLARE_PCI_UNMAP_LEN
#define dma_unmap_addr pci_unmap_addr
#define dma_unmap_addr_set pci_unmap_addr_set
#define dma_unmap_len pci_unmap_len
#define dma_unmap_len_set pci_unmap_len_set
#endif /* DEFINE_DMA_UNMAP_ADDR */

#ifndef pci_bus_speed
/* override pci_bus_speed introduced in 2.6.19 with an expanded enum type */
enum _kc_pci_bus_speed {
	_KC_PCIE_SPEED_2_5GT = 0x14,
	_KC_PCIE_SPEED_5_0GT = 0x15,
	_KC_PCIE_SPEED_8_0GT = 0x16,
	_KC_PCI_SPEED_UNKNOWN = 0xff,
};

#define pci_bus_speed _kc_pci_bus_speed
#define PCIE_SPEED_2_5GT _KC_PCIE_SPEED_2_5GT
#define PCIE_SPEED_5_0GT _KC_PCIE_SPEED_5_0GT
#define PCIE_SPEED_8_0GT _KC_PCIE_SPEED_8_0GT
#define PCI_SPEED_UNKNOWN _KC_PCI_SPEED_UNKNOWN
#endif /* pci_bus_speed */

#else /* < 2.6.34 */
#ifndef HAVE_SET_RX_MODE
#define HAVE_SET_RX_MODE
#endif
#define HAVE_INET6_IFADDR_LIST
#endif /* < 2.6.34 */

/* ************************************************************************ */
#if (KERNEL_VERSION(2, 6, 36) > LINUX_VERSION_CODE)
#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#ifdef NET_IP_ALIGN
#undef NET_IP_ALIGN
#endif
#define NET_IP_ALIGN 0
#endif /* CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS */

#ifdef __LINX_6_0_60__
enum work_busy_status {
	/* bit mask for work_busy() return values */
	WORK_BUSY_PENDING = 1 << 0,
	WORK_BUSY_RUNNING = 1 << 1,
};

#define work_busy(work) _work_busy(work)
unsigned int _work_busy(struct work_struct *work);

#endif

#ifdef NET_SKB_PAD
#undef NET_SKB_PAD
#endif

#if (L1_CACHE_BYTES > 32)
#define NET_SKB_PAD L1_CACHE_BYTES
#else
#define NET_SKB_PAD 32
#endif

static inline struct sk_buff *_kc_netdev_alloc_skb_ip_align(struct net_device *dev,
							    unsigned int length)
{
	struct sk_buff *skb;

	skb = alloc_skb(length + NET_SKB_PAD + NET_IP_ALIGN, GFP_ATOMIC);
	if (skb) {
#if (NET_IP_ALIGN + NET_SKB_PAD)
		skb_reserve(skb, NET_IP_ALIGN + NET_SKB_PAD);
#endif
		skb->dev = dev;
	}

	return skb;
}

#ifdef netdev_alloc_skb_ip_align
#undef netdev_alloc_skb_ip_align
#endif
#define netdev_alloc_skb_ip_align(n, l) _kc_netdev_alloc_skb_ip_align(n, l)

#undef netif_level
#define netif_level(level, priv, type, dev, fmt, args...) \
	do {                                                  \
		if (netif_msg_##type(priv) != 0)                       \
			netdev_##level(dev, fmt, ##args);             \
	} while (0)

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 3)))
#undef usleep_range
#define usleep_range(min, max) msleep(DIV_ROUND_UP(min, 1000))
#endif

#define u64_stats_update_begin(a) \
	do {                          \
	} while (0)
#define u64_stats_update_end(a) \
	do {                        \
	} while (0)
#define u64_stats_fetch_retry(a, b) (0)
#define u64_stats_fetch_begin(a) (0)
#define u64_stats_fetch_retry_bh(a, b) (0)
#define u64_stats_fetch_begin_bh(a) (0)
struct u64_stats_sync_empty {
	int:0;
};

#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 1))
#define HAVE_8021P_SUPPORT
#endif

/* RHEL6.4 and SLES11sp2 backported skb_tx_timestamp */
/* RHEL6.4 and SLES11sp2 backported skb_tx_timestamp */
#if (!(RHEL_RELEASE_VERSION(6, 4) <= RHEL_RELEASE_CODE) && \
	!(SLE_VERSION(11, 2, 0) <= SLE_VERSION_CODE))
static inline void skb_tx_timestamp(struct sk_buff __always_unused *skb) {}
#endif

#else /* < 2.6.36 */


#endif /* < 2.6.36 */

/* ************************************************************************ */
#if (KERNEL_VERSION(2, 6, 37) > LINUX_VERSION_CODE)
#ifndef VLAN_N_VID
#define VLAN_N_VID VLAN_GROUP_ARRAY_LEN
#endif /* VLAN_N_VID */

static inline void *_kc_vzalloc(unsigned long size)
{
	void *pr = vmalloc(size);

	if (pr)
		memset(pr, 0, size);
	return pr;
}

#define vzalloc(_size) _kc_vzalloc(_size)
#endif

/* ************************************************************************ */
#if (KERNEL_VERSION(2, 6, 39) > LINUX_VERSION_CODE)

#ifndef TC_BITMASK
#define TC_BITMASK 15
#endif

#ifndef NETIF_F_RXCSUM
#define NETIF_F_RXCSUM BIT(29)
#endif

#ifndef skb_queue_reverse_walk_safe
#define skb_queue_reverse_walk_safe(queue, skb, tmp) \
	for (skb = (queue)->prev, tmp = skb->prev; \
	skb != (struct sk_buff *)(queue); skb = tmp, tmp = skb->prev)
#endif

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6, 0)))
u8 _kc_netdev_get_num_tc(struct net_device *dev);
#define netdev_get_num_tc(dev) _kc_netdev_get_num_tc(dev)
int _kc_netdev_set_num_tc(struct net_device *dev, u8 num_tc);
#define netdev_set_num_tc(dev, tc) _kc_netdev_set_num_tc((dev), (tc))
#define netdev_reset_tc(dev) _kc_netdev_set_num_tc((dev), 0)
#define netdev_set_tc_queue(dev, tc, cnt, off) \
	do {                                       \
	} while (0)
#define netdev_set_prio_tc_map(dev, up, tc) \
	do {                                    \
	} while (0)
#else /* RHEL6.1 or greater */
#ifndef HAVE_MQPRIO
#define HAVE_MQPRIO
#endif /* HAVE_MQPRIO */

#endif /* !(RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,0)) */

#ifndef udp_csum
#define udp_csum __kc_udp_csum
static inline __wsum __kc_udp_csum(struct sk_buff *skb)
{
	__wsum csum = csum_partial(skb_transport_header(skb),
				   sizeof(struct udphdr), skb->csum);

	for (skb = skb_shinfo(skb)->frag_list; skb; skb = skb->next)
		csum = csum_add(csum, skb->csum);

	return csum;
}
#endif /* udp_csum */
#else /* < 2.6.39 */

#ifndef HAVE_MQPRIO
#define HAVE_MQPRIO
#endif
#ifndef HAVE_SETUP_TC
#define HAVE_SETUP_TC
#endif

#define HAVE_IRQ_AFFINITY_NOTIFY
#endif /* < 2.6.39 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 0, 0) > LINUX_VERSION_CODE)

#ifndef kfree_rcu
#define kfree_rcu(_ptr, _rcu_head) kfree(_ptr)
#endif /* kfree_rcu */

#else
#define HAVE_NETDEV_WANTED_FEAUTES
#endif

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 2, 0) > LINUX_VERSION_CODE)
#ifndef dma_zalloc_coherent
#define dma_zalloc_coherent(d, s, h, f) _kc_dma_zalloc_coherent(d, s, h, f)
static inline void *_kc_dma_zalloc_coherent(struct device *dev, size_t size,
					    dma_addr_t *dma_handle, gfp_t flag)
{
	void *ret = dma_alloc_coherent(dev, size, dma_handle, flag);

	if (ret)
		memset(ret, 0, size);

	return ret;
}
#endif

#ifndef skb_frag_size
#define skb_frag_size(frag)	kc_skb_frag_size(frag)
static inline unsigned int kc_skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}
#endif /* skb_frag_size */

#ifndef skb_frag_size_sub
#define skb_frag_size_sub(frag, delta)	kc_skb_frag_size_sub(frag, delta)
static inline void kc_skb_frag_size_sub(skb_frag_t *frag, int delta)
{
	frag->size -= delta;
}
#endif /* skb_frag_size_sub */

#ifndef skb_frag_page
#define skb_frag_page(frag) _kc_skb_frag_page(frag)
static inline struct page *_kc_skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}
#endif /* skb_frag_page */

#ifndef skb_frag_address
#define skb_frag_address(frag)	kc_skb_frag_address(frag)
static inline void *kc_skb_frag_address(const skb_frag_t *frag)
{
	return page_address(skb_frag_page(frag)) + frag->page_offset;
}
#endif /* skb_frag_address */

#ifndef skb_frag_dma_map
#if (KERNEL_VERSION(2, 6, 0) <= LINUX_VERSION_CODE)
#include <linux/dma-mapping.h>
#endif
#define skb_frag_dma_map(dev, frag, offset, size, dir) \
	_kc_skb_frag_dma_map(dev, frag, offset, size, dir)

static inline dma_addr_t _kc_skb_frag_dma_map(struct device *dev, const skb_frag_t *frag,
					      size_t offset, size_t size,
					      enum dma_data_direction dir)
{
	return dma_map_page(dev, skb_frag_page(frag),
			    frag->page_offset + offset, size, dir);
}
#endif /* skb_frag_dma_map */

#ifndef __skb_frag_unref
#define __skb_frag_unref(frag) __kc_skb_frag_unref(frag)
static inline void __kc_skb_frag_unref(skb_frag_t *frag)
{
	put_page(skb_frag_page(frag));
}
#endif /* __skb_frag_unref */

#ifndef SPEED_UNKNOWN
#define SPEED_UNKNOWN -1
#endif
#ifndef DUPLEX_UNKNOWN
#define DUPLEX_UNKNOWN 0xff
#endif
#if ((RHEL_RELEASE_VERSION(6, 3) <= RHEL_RELEASE_CODE) || \
	(SLE_VERSION_CODE && SLE_VERSION(11, 3, 0) <= SLE_VERSION_CODE))
#ifndef HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_PCI_DEV_FLAGS_ASSIGNED
#endif
#endif
#else /* < 3.2.0 */
#ifndef HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_PCI_DEV_FLAGS_ASSIGNED

#endif

#endif /* < 3.2.0 */

#if (KERNEL_VERSION(3, 3, 0) > LINUX_VERSION_CODE)
/*
 * NOTE: the order of parameters to _kc_alloc_workqueue() is different than
 * alloc_workqueue() to avoid compiler warning from -Wvarargs.
 */
#define STR_IDX 3
#define FIRST_TO_CHECK 4
static inline struct workqueue_struct *__printf(STR_IDX, FIRST_TO_CHECK)
_kc_alloc_workqueue(__maybe_unused int flags, __maybe_unused int max_active,
		    const char *fmt, ...)
{
	struct workqueue_struct *wq;
	va_list args, temp;
	unsigned int len;
	char *p;

	va_start(args, fmt);
	va_copy(temp, args);
	len = vsnprintf(NULL, 0, fmt, temp);
	va_end(temp);

	p = kmalloc(len + 1, GFP_KERNEL);
	if (!p) {
		va_end(args);
		return NULL;
	}

	vsnprintf(p, len + 1, fmt, args);
	va_end(args);

#if (KERNEL_VERSION(2, 6, 36) > LINUX_VERSION_CODE)
	wq = create_workqueue(p);
#else
	wq = alloc_workqueue(p, flags, max_active);
#endif
	kfree(p);

	return wq;
}

#ifdef alloc_workqueue
#undef alloc_workqueue
#endif
#define alloc_workqueue(fmt, flags, max_active, args...) \
	_kc_alloc_workqueue(flags, max_active, fmt, ##args)

#if !(RHEL_RELEASE_VERSION(6, 5) <= RHEL_RELEASE_CODE)
typedef u32 netdev_features_t;
#endif
#undef PCI_EXP_TYPE_RC_EC
#define PCI_EXP_TYPE_RC_EC 0xa /* Root Complex Event Collector */
#ifndef CONFIG_BQL
#define netdev_tx_completed_queue(_q, _p, _b) \
	do {                                      \
	} while (0)
#define netdev_completed_queue(_n, _p, _b) \
	do {                                   \
	} while (0)
#define netdev_tx_sent_queue(_q, _b) \
	do {                             \
	} while (0)
#define netdev_sent_queue(_n, _b) \
	do {                          \
	} while (0)
#define netdev_tx_reset_queue(_q) \
	do {                          \
	} while (0)
#define netdev_reset_queue(_n) \
	do {                       \
	} while (0)
#endif
#if (SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(11, 3, 0))
#endif /* SLE_VERSION(11,3,0) */
#define netif_xmit_stopped(_q) netif_tx_queue_stopped(_q)
#if !(SLE_VERSION_CODE && SLE_VERSION(11, 4, 0) <= SLE_VERSION_CODE)
static inline int kc_ipv6_skip_exthdr(const struct sk_buff *skb, int start,
				      u8 *nexthdrp,
				      __be16 __always_unused *frag_offp)
{
	return ipv6_skip_exthdr(skb, start, nexthdrp);
}

#undef ipv6_skip_exthdr
#define ipv6_skip_exthdr(a, b, c, d) kc_ipv6_skip_exthdr((a), (b), (c), (d))
#endif /* !SLES11sp4 or greater */

#else /* ! < 3.3.0 */
#define HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef ETHTOOL_SRXNTUPLE
#undef ETHTOOL_SRXNTUPLE
#endif
#endif /* < 3.3.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 4, 0) > LINUX_VERSION_CODE)
#ifndef NETIF_F_RXFCS
#define NETIF_F_RXFCS 0
#endif /* NETIF_F_RXFCS */
#ifndef NETIF_F_RXALL
#define NETIF_F_RXALL 0
#endif /* NETIF_F_RXALL */

#if !(SLE_VERSION_CODE && SLE_VERSION(11, 3, 0) <= SLE_VERSION_CODE)
#define NUMTCS_RETURNS_U8
#endif /* !(SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(11,3,0)) */

#ifndef skb_add_rx_frag
#define skb_add_rx_frag _kc_skb_add_rx_frag
void _kc_skb_add_rx_frag(struct sk_buff *param0, int param1,
			struct page *param2, int param3, int param4, unsigned int param5);
#endif
#ifdef NET_ADDR_RANDOM
#define eth_hw_addr_random(N)                   \
	do {                                        \
		eth_random_addr(N->dev_addr);           \
		N->addr_assign_type |= NET_ADDR_RANDOM; \
	} while (0)
#else /* NET_ADDR_RANDOM */
#define eth_hw_addr_random(N) eth_random_addr(N->dev_addr)
#endif /* NET_ADDR_RANDOM */

#ifndef for_each_set_bit_from
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit)); \
	(bit) < (size); (bit) = find_next_bit((addr), (size), (bit) + 1))
#endif /* for_each_set_bit_from */

#if (RHEL_RELEASE_VERSION(7, 0) > RHEL_RELEASE_CODE)
#define _kc_kmap_atomic(page) kmap_atomic(page, KM_SKB_DATA_SOFTIRQ)
#define _kc_kunmap_atomic(addr) kunmap_atomic(addr, KM_SKB_DATA_SOFTIRQ)
#else
#define _kc_kmap_atomic(page) __kmap_atomic(page)
#define _kc_kunmap_atomic(addr) __kunmap_atomic(addr)
#endif

#else /* < 3.4.0 */

#define _kc_kmap_atomic(page) kmap_atomic(page)
#define _kc_kunmap_atomic(addr) kunmap_atomic(addr)
#endif /* >= 3.4.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 5, 0) > LINUX_VERSION_CODE)

#ifndef BITS_PER_LONG_LONG
#define BITS_PER_LONG_LONG 64
#endif

#ifndef ether_addr_equal
static inline bool __kc_ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
	return !compare_ether_addr(addr1, addr2);
}

#define ether_addr_equal(_addr1, _addr2) \
	__kc_ether_addr_equal((_addr1), (_addr2))
#endif

/* Definitions for !CONFIG_OF_NET are introduced in 3.10 */
#ifdef CONFIG_OF_NET
static inline int of_get_phy_mode(struct device_node __always_unused *np)
{
	return -ENODEV;
}

static inline const void *of_get_mac_address(struct device_node __always_unused *np)
{
	return NULL;
}
#endif
#else
#include <linux/of_net.h>
#define HAVE_FDB_OPS

#endif /* < 3.5.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 6, 0) > LINUX_VERSION_CODE)
#ifndef eth_random_addr
#define eth_random_addr _kc_eth_random_addr
static inline void _kc_eth_random_addr(u8 *addr)
{
	get_random_bytes(addr, ETH_ALEN);
	addr[0] &= 0xfe; /* clear multicast */
	addr[0] |= 0x02; /* set local assignment */
}
#endif /* eth_random_addr */
#endif /* < 3.6.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 8, 0) > LINUX_VERSION_CODE)
#else /* >= 3.8.0 */
#ifndef HAVE_SRIOV_CONFIGURE
#define HAVE_SRIOV_CONFIGURE
#endif
#endif /* < 3.8.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 10, 0) > LINUX_VERSION_CODE)
#ifndef NAPI_POLL_WEIGHT
#define NAPI_POLL_WEIGHT 64
#endif
#ifdef CONFIG_PCI_IOV
int kc_pci_vfs_assigned(struct pci_dev *dev);
#else
static inline int kc_pci_vfs_assigned(struct pci_dev __always_unused *dev)
{
	return 0;
}
#endif
#define pci_vfs_assigned(dev) kc_pci_vfs_assigned(dev)

#ifndef NEED_DEFINE_LIST_FIRST_ENTRY_OR_NULL
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#endif /* NEED_DEFINE_LIST_FIRST_ENTRY_OR_NULL */
#ifndef VLAN_TX_COOKIE_MAGIC
static inline struct sk_buff *kc_vlan_hwaccel_put_tag(struct sk_buff *skb,
			u16 vlan_tci)
{
#ifdef VLAN_TAG_PRESENT
	vlan_tci |= VLAN_TAG_PRESENT;
#endif
	skb->vlan_tci = vlan_tci;

	return skb;
}

#define __vlan_hwaccel_put_tag(skb, vlan_proto, vlan_tci) \
	kc_vlan_hwaccel_put_tag(skb, vlan_tci)
#endif
#ifndef PCI_DEVID
#define PCI_DEVID(bus, devfn) ((((u16)(bus)) << 8) | (devfn))
#endif
#else /* >= 3.10.0 */
#endif /* >= 3.10.0 */

/* ************************************************************************ */
#ifdef NEED_PDE_DATA
#ifdef HAVE_PDE_DATA_LOWERCASE
#define PDE_DATA pde_data
#else
#warning PDE_DATA not defined
#endif
#endif

#if (KERNEL_VERSION(6, 3, 0) > LINUX_VERSION_CODE)
static inline void vm_flags_set(struct vm_area_struct *vma, vm_flags_t flags)
{
	vma->vm_flags |= flags;
}

static inline void vm_flags_clear(struct vm_area_struct *vma, vm_flags_t flags)
{
	vma->vm_flags &= ~flags;
}
#endif /* < 6.3.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 13, 0) > LINUX_VERSION_CODE)
#define dma_set_mask_and_coherent(_p, _m) kc_dma_set_mask_and_coherent(_p, _m)
int kc_dma_set_mask_and_coherent(struct device *dev, u64 mask);
#ifndef u64_stats_init
#define u64_stats_init(a) \
	do {                  \
	} while (0)
#endif
#ifndef BIT_ULL
#define BIT_ULL(n) (1ULL << (n))
#endif

#if (SLE_VERSION_CODE && SLE_VERSION(12, 1, 0) <= SLE_VERSION_CODE)
#undef HAVE_STRUCT_PAGE_PFMEMALLOC
#define HAVE_DCBNL_OPS_SETAPP_RETURN_INT
#endif

#ifndef NEED_DEFINE_LIST_NEXT_ENTRY
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#endif /* NEED_DEFINE_LIST_NEXT_ENTRY */

#ifndef NEED_DEFINE_LIST_PREV_ENTRY
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)
#endif /* NEED_DEFINE_LIST_PREV_ENTRY */

#else /* >= 3.13.0 */
#define HAVE_VXLAN_CHECKS
#if (defined(UBUNTU_VERSION_CODE) && UBUNTU_VERSION_CODE && \
	UBUNTU_VERSION(3, 13, 0, 24) <= UBUNTU_VERSION_CODE)
#else
#define HAVE_NDO_SELECT_QUEUE_ACCEL
#endif
#define HAVE_NET_GET_RANDOM_ONCE
#define HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
#endif

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 14, 0) > LINUX_VERSION_CODE)
#if (!(RHEL_RELEASE_CODE && \
	RHEL_RELEASE_VERSION(7, 0) <= RHEL_RELEASE_CODE) && \
	!(SLE_VERSION_CODE && SLE_VERSION(12, 0, 0) <= SLE_VERSION_CODE))

/* it isn't expected that this would be a #define unless we made it so */
#ifndef NEED_SKB_SET_HASH

#define PKT_HASH_TYPE_NONE 0
#define PKT_HASH_TYPE_L2 1
#define PKT_HASH_TYPE_L3 2
#define PKT_HASH_TYPE_L4 3

enum _kc_pkt_hash_types {
	_KC_PKT_HASH_TYPE_NONE = PKT_HASH_TYPE_NONE,
	_KC_PKT_HASH_TYPE_L2 = PKT_HASH_TYPE_L2,
	_KC_PKT_HASH_TYPE_L3 = PKT_HASH_TYPE_L3,
	_KC_PKT_HASH_TYPE_L4 = PKT_HASH_TYPE_L4,
};

#define pkt_hash_types _kc_pkt_hash_types
#define skb_set_hash __kc_skb_set_hash
static inline void
__kc_skb_set_hash(struct sk_buff __maybe_unused *skb,
		  u32 __maybe_unused hash, int __maybe_unused type)
{
#ifdef HAVE_SKB_L4_RXHASH
	skb->l4_rxhash = (type == PKT_HASH_TYPE_L4);
#endif
#ifdef NETIF_F_RXHASH
	skb->rxhash = hash;
#endif
}
#endif /* NEED_SKB_SET_HASH */
#else /* RHEL_RELEASE_CODE >= 7.0 || SLE_VERSION_CODE >= 12.0 */
#ifndef HAVE_VXLAN_CHECKS
#define HAVE_VXLAN_CHECKS
#endif /* HAVE_VXLAN_CHECKS */
#endif /* !(RHEL_RELEASE_CODE >= 7.0 && SLE_VERSION_CODE >= 12.0) */
#ifndef pci_enable_msix_range
int kc_pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries,
			     int min_vec, int max_vec);
#define pci_enable_msix_range kc_pci_enable_msix_range
#endif
#else /* >= 3.14.0 */
#endif /* 3.14.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 16, 0) > LINUX_VERSION_CODE)

#ifndef NETIF_F_GSO_IPXIP4
#define NETIF_F_GSO_IPXIP4 0
#endif

#ifndef NETIF_F_GSO_IPXIP6
#define NETIF_F_GSO_IPXIP6 0
#endif

#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 4))
#define HAVE_VLAN_FIND_DEV_DEEP_RCU
#endif

#else
#define HAVE_VLAN_FIND_DEV_DEEP_RCU

#endif /* 3.16.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(3, 18, 0) > LINUX_VERSION_CODE)
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_VERSION(7, 1) < RHEL_RELEASE_CODE)
#define HAVE_MULTI_VLAN_OFFLOAD_EN
#endif
#else
#define HAVE_MULTI_VLAN_OFFLOAD_EN
#endif /* 3.18.0 */

#if (KERNEL_VERSION(4, 6, 0) > LINUX_VERSION_CODE)
#if !(RHEL_RELEASE_CODE && RHEL_RELEASE_VERSION(7, 5) <= RHEL_RELEASE_CODE)
#define UNSUPPORT_NTUPLE_IPV6
#endif
#endif /* 4.6.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(4, 11, 0) > LINUX_VERSION_CODE)
#define HAVE_STRUCT_CURRENT
#if (SLE_VERSION_CODE && (SLE_VERSION(12, 3, 0) <= SLE_VERSION_CODE)) ||   \
	(RHEL_RELEASE_CODE && \
	RHEL_RELEASE_VERSION(7, 5) <= RHEL_RELEASE_CODE) || \
	(DEEPIN_VERSION_CODE && \
	(DEEPIN_PRODUCT_VERSION(15, 2, 0) == DEEPIN_VERSION_CODE))

#endif
#ifdef CONFIG_NET_RX_BUSY_POLL
#define HAVE_NDO_BUSY_POLL
#endif
#else /* > 4.11 */

#define HAVE_VM_OPS_FAULT_NO_VMA
#endif /* 4.11.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(4, 13, 0) > LINUX_VERSION_CODE)
#else /* > 4.13 */
#if !defined(HAVE_HWTSTAMP_FILTER_NTP_ALL)
#define HAVE_HWTSTAMP_FILTER_NTP_ALL
#endif
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
#define HAVE_PTP_CLOCK_DO_AUX_WORK
#endif /* 4.13.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(4, 15, 0) > LINUX_VERSION_CODE)
#if ((KERNEL_VERSION(3, 10, 0) == LINUX_VERSION_CODE) && RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(7, 6) == RHEL_RELEASE_CODE))
#else
#define TC_SETUP_QDISC_MQPRIO TC_SETUP_MQPRIO
#endif
#if (KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE)
#if (SLE_VERSION_CODE && (SLE_VERSION(15, 0, 0) <= SLE_VERSION_CODE)) || \
	(RHEL_RELEASE_CODE && RHEL_RELEASE_VERSION(7, 5) <= RHEL_RELEASE_CODE)
#else /* 4.12-4.15 */
#define HAVE_IP6_FRAG_ID_ENABLE_UFO
#endif
#else /* < 4.12.0 */
#define HAVE_IP6_FRAG_ID_ENABLE_UFO
#endif
#endif /* 4.15.0 */
/* ************************************************************************ */
#if (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE)
#if KERNEL_VERSION(3, 1, 0) <= LINUX_VERSION_CODE || \
	KERNEL_VERSION(2, 6, 32) == LINUX_VERSION_CODE
#define NEED_VLAN_RESTORE
#endif
#else
#define HAVE_MACRO_VM_FAULT_T
#endif /* 4.17.0 */

#if (KERNEL_VERSION(4, 18, 0) > LINUX_VERSION_CODE)
#else /* >= 4.18 */
#if RHEL_RELEASE_CODE && RHEL_RELEASE_VERSION(8, 2) <= RHEL_RELEASE_CODE
#define ETH_GET_HEADLEN_NEED_DEV
#endif
#endif

/* ************************************************************************ */
#if (KERNEL_VERSION(4, 19, 0) > LINUX_VERSION_CODE)

#ifndef bitmap_zalloc
#if (SLE_VERSION_CODE && (SLE_VERSION(15, 0, 0) > SLE_VERSION_CODE))
#ifndef kmalloc_array

#define SIZE_MAX	(~(size_t)0)

static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	if (size != 0 && n > SIZE_MAX / size)
		return NULL;
	return __kmalloc(n * size, flags);
}
#endif
#endif

#define bitmap_zalloc(nbits, flags) _hinic5_bitmap_zalloc(nbits, flags)
static inline unsigned long *_hinic5_bitmap_zalloc(unsigned int nbits, gfp_t flags)
{
	return kmalloc_array(BITS_TO_LONGS(nbits),
			     sizeof(unsigned long), flags | __GFP_ZERO);
}

#define bitmap_free(bitmap)  _hinic5_bitmap_free(bitmap)
static inline void _hinic5_bitmap_free(unsigned long *bitmap)
{
	kfree(bitmap);
}

#endif

#endif

/*****************************************************************************/
#if (KERNEL_VERSION(5, 0, 0) > LINUX_VERSION_CODE)
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 0))
#define dev_open(x) dev_open(x, NULL)
#endif
#else /* >= 5.0.0 */
#define dev_open(x) dev_open(x, NULL)


#ifndef get_ds
#define get_ds()	(KERNEL_DS)
#endif

#ifndef dma_zalloc_coherent
#define dma_zalloc_coherent(d, s, h, f) _hinic5_dma_zalloc_coherent(d, s, h, f)
static inline void *_hinic5_dma_zalloc_coherent(struct device *dev,
						size_t size, dma_addr_t *dma_handle,
						gfp_t gfp)
{
	/* Above kernel 5.0, fixed up all remaining architectures
	 * to zero the memory in dma_alloc_coherent, and made
	 * dma_zalloc_coherent a no-op wrapper around dma_alloc_coherent,
	 * which fixes all of the above issues.
	 */
	return dma_alloc_coherent(dev, size, dma_handle, gfp);
}
#endif

#if (KERNEL_VERSION(5, 6, 0) <= LINUX_VERSION_CODE)
#ifndef DT_KNL_EMU
struct timeval {
	__kernel_old_time_t     tv_sec;         /* seconds */
	__kernel_suseconds_t    tv_usec;        /* microseconds */
};
#endif
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

#endif /* 5.0.0 */

/*****************************************************************************/
#if (KERNEL_VERSION(5, 2, 0) > LINUX_VERSION_CODE)
#else /* >= 5.2.0 */
#define ETH_GET_HEADLEN_NEED_DEV
#define HAVE_GENL_OPS_FIELD_VALIDATE
#endif /* 5.2.0 */

/*****************************************************************************/
#if (KERNEL_VERSION(5, 4, 0) > LINUX_VERSION_CODE)
#if (SUSE_PRODUCT(1, 15, 2, 0) <= SUSE_PRODUCT_CODE)
#ifndef pci_cleanup_aer_uncorrect_error_status
#define pci_cleanup_aer_uncorrect_error_status pci_aer_clear_nonfatal_status
#endif
#else /* < SLES15sp2 */
#endif /* >= SLES15sp2 */
#else /* >= 5.4.0 */
#endif /* 5.4.0 */

/*****************************************************************************/
#if (KERNEL_VERSION(5, 6, 0) > LINUX_VERSION_CODE)
#else /* >= 5.6.0 */
#ifndef rtc_time_to_tm
#define rtc_time_to_tm rtc_time64_to_tm
#endif

#define HAVE_PROC_OPS
#endif /* 5.6.0 */

/*****************************************************************************/
#if (KERNEL_VERSION(5, 7, 0) > LINUX_VERSION_CODE)
#else /* >= 5.7.0 */

#ifndef pci_cleanup_aer_uncorrect_error_status
#define pci_cleanup_aer_uncorrect_error_status pci_aer_clear_nonfatal_status
#endif
#endif /* 5.7.0 */

/* ************************************************************************ */
#if (KERNEL_VERSION(5, 9, 0) > LINUX_VERSION_CODE)

#else /* >= 5.9.0 */
#define HAVE_XDP_FRAME_SZ
#endif /* 5.9.0 */


#ifdef NEED_DEFINE_PCI_DMA_COMPAT
#include <linux/dma-mapping.h>

/* This defines the direction arg to the DMA mapping routines. */
#define PCI_DMA_BIDIRECTIONAL	DMA_BIDIRECTIONAL
#define PCI_DMA_TODEVICE	DMA_TO_DEVICE
#define PCI_DMA_FROMDEVICE	DMA_FROM_DEVICE
#define PCI_DMA_NONE		DMA_NONE

static inline void *pci_alloc_consistent(struct pci_dev *pdev, size_t size,
					 dma_addr_t *dma_handle)
{
	return dma_alloc_coherent(&pdev->dev, size, dma_handle, GFP_ATOMIC);
}

static inline void *pci_zalloc_consistent(struct pci_dev *pdev, size_t size,
					  dma_addr_t *dma_handle)
{
	return dma_alloc_coherent(&pdev->dev, size, dma_handle, GFP_ATOMIC);
}

static inline void pci_free_consistent(struct pci_dev *pdev, size_t size,
				       void *vaddr, dma_addr_t dma_handle)
{
	dma_free_coherent(&pdev->dev, size, vaddr, dma_handle);
}

static inline dma_addr_t pci_map_single(struct pci_dev *pdev, void *ptr,
					size_t size, int direction)
{
	return dma_map_single(&pdev->dev, ptr, size,
			      (enum dma_data_direction)direction);
}

static inline void pci_unmap_single(struct pci_dev *pdev, dma_addr_t dma_addr,
				    size_t size, int direction)
{
	dma_unmap_single(&pdev->dev, dma_addr, size,
			 (enum dma_data_direction)direction);
}

static inline dma_addr_t pci_map_page(struct pci_dev *pdev, struct page *page,
				      unsigned long offset, size_t size,
				      int direction)
{
	return dma_map_page(&pdev->dev, page, offset, size,
			    (enum dma_data_direction)direction);
}

static inline void pci_unmap_page(struct pci_dev *pdev, dma_addr_t dma_address,
				  size_t size, int direction)
{
	dma_unmap_page(&pdev->dev, dma_address, size,
		       (enum dma_data_direction)direction);
}

static inline int pci_map_sg(struct pci_dev *pdev, struct scatterlist *sg,
			     int nents, int direction)
{
	return dma_map_sg(&pdev->dev, sg, nents,
			  (enum dma_data_direction)direction);
}

static inline void pci_unmap_sg(struct pci_dev *pdev, struct scatterlist *sg,
				int nents, int direction)
{
	dma_unmap_sg(&pdev->dev, sg, nents, (enum dma_data_direction)direction);
}

static inline void pci_dma_sync_single_for_cpu(struct pci_dev *pdev,
					       dma_addr_t dma_handle,
					       size_t size, int direction)
{
	dma_sync_single_for_cpu(&pdev->dev, dma_handle, size,
				(enum dma_data_direction)direction);
}

static inline void pci_dma_sync_single_for_device(struct pci_dev *pdev,
						  dma_addr_t dma_handle,
						  size_t size, int direction)
{
	dma_sync_single_for_device(&pdev->dev, dma_handle, size,
				   (enum dma_data_direction)direction);
}

static inline void pci_dma_sync_sg_for_cpu(struct pci_dev *pdev,
					   struct scatterlist *sg,
					   int nelems, int direction)
{
	dma_sync_sg_for_cpu(&pdev->dev, sg, nelems,
			    (enum dma_data_direction)direction);
}

static inline void pci_dma_sync_sg_for_device(struct pci_dev *pdev,
					      struct scatterlist *sg,
					      int nelems, int direction)
{
	dma_sync_sg_for_device(&pdev->dev, sg, nelems,
			       (enum dma_data_direction)direction);
}

static inline int pci_dma_mapping_error(struct pci_dev *pdev,
					dma_addr_t dma_addr)
{
	return dma_mapping_error(&pdev->dev, dma_addr);
}

#ifdef CONFIG_PCI
static inline int pci_set_dma_mask(struct pci_dev *dev, u64 mask)
{
	return dma_set_mask(&dev->dev, mask);
}

static inline int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask)
{
	return dma_set_coherent_mask(&dev->dev, mask);
}
#else
static inline int pci_set_dma_mask(struct pci_dev *dev, u64 mask)
{ return -EIO; }
static inline int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask)
{ return -EIO; }
#endif
#endif /* > NEED_DEFINE_PCI_DMA_COMPAT */

/* ************************************************************************ */
/* pci_pool */
#if (KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE)

#include <linux/dmapool.h>

#define	pci_pool dma_pool
#define pci_pool_create(name, pdev, size, align, allocation) \
		dma_pool_create(name, &pdev->dev, size, align, allocation)
#define	pci_pool_destroy(pool) dma_pool_destroy(pool)
#define	pci_pool_alloc(pool, flags, handle) dma_pool_alloc(pool, flags, handle)
#define	pci_pool_zalloc(pool, flags, handle) \
		dma_pool_zalloc(pool, flags, handle)
#define	pci_pool_free(pool, vaddr, addr) dma_pool_free(pool, vaddr, addr)
#endif /* > 5.15.0 */

/* PCI AER */
#ifdef NEED_PCI_DISABLE_PCIE_ERROR_REPORTING
#define	pci_disable_pcie_error_reporting(pdev)	((void)pdev)
#endif

#ifdef NEED_PCI_ENABLE_PCIE_ERROR_REPORTING
#define pci_enable_pcie_error_reporting(pdev)	((void)pdev)
#endif

/* ************************************************************************ */
/* device class */
#ifndef HAVE_CLASS_CREATE_OWNER
#define	class_create(owner, dev_class) class_create(dev_class)
#endif

#ifdef NEED_GET_FS
#define get_fs()			0
#endif

#ifdef NEED_SET_FS
#define set_fs(fs)			((void)fs)
#endif

#ifdef NEED_FORCE_UACCESS_BEGIN
#define force_uaccess_begin()		0
#endif

#ifdef NEED_FORCE_UACCESS_END
#define force_uaccess_end(oldfs)	((void)oldfs)
#endif

/* ************************************************************************ */
/* kallsyms */

#ifndef kallsyms_lookup_name
#define	kallsyms_lookup_name(name)	__symbol_get(name)
#endif

#ifndef kallsyms_lookup_name_wrap
#define	kallsyms_lookup_name_wrap(name)	__symbol_get(name)
#endif

/* ********************* net/devlink.h start ************ */
#ifdef HAVE_DEVLINK_H
#include <net/devlink.h>
#endif

/*****************************************************************************/
#if (KERNEL_VERSION(5, 5, 0) > LINUX_VERSION_CODE)
#else /* >= 5.5.0 */
#define HAVE_DEVLINK_FLASH_UPDATE_PARAMS // TODO, legacy, devlink feature macro switch
#endif /* 5.5.0 */

/* devlink_alloc */
#if (defined(HAVE_DEVLINK_ALLOC) && defined(HAVE_DEVLINK_ALLOC_SET_DEV))
#define ossl_devlink_alloc(ops, priv_size, dev) devlink_alloc(ops, priv_size, dev)
#else
#define ossl_devlink_alloc(ops, priv_size, dev) devlink_alloc(ops, priv_size)
#endif

/* devlink_register */
#ifdef HAVE_DEVLINK_REGISTER
#ifndef HAVE_DEVLINK_REGISTER_HAVE_RET
#define ossl_devlink_register(devlink, dev) ({ devlink_register(devlink); 0; })
#else
#ifndef HAVE_DEVLINK_REGISTER_SET_DEV
#define ossl_devlink_register(devlink, dev) devlink_register(devlink)
#else
#define ossl_devlink_register(devlink, dev) devlink_register(devlink, dev)
#endif
#endif
#endif

/* devlink_params_* */
#ifndef HAVE_DEVLINK_PARAMS_PUBLISH
#define	devlink_params_publish(devlink)		((void)(devlink))
#endif

#ifndef HAVE_DEVLINK_PARAMS_UNPUBLISH
#define	devlink_params_unpublish(devlink)	((void)(devlink))
#endif
/* ********************* net/devlink.h end ************ */

/* vxlan outer udp checksum will offload and
 * skb->inner_transport_header is wrong
 */
#if (defined(SLE_VERSION_CODE) && defined(SLE_VERSION) && SLE_VERSION_CODE && \
	((SLE_VERSION(12, 1, 0) == SLE_VERSION_CODE) || \
	(SLE_VERSION(12, 0, 0) == SLE_VERSION_CODE))) || \
	(RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(7, 0) == RHEL_RELEASE_CODE))
#define HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
#endif

#ifdef NEED_ETH_ZERO_ADDR
static inline void hinic5_eth_zero_addr(u8 *addr)
{
	(void)memset_s(addr, ETH_ALEN, 0x00, ETH_ALEN);
}

#define eth_zero_addr(_addr) hinic5_eth_zero_addr(_addr)
#endif

#ifdef NEED_PCI_SRIOV_GET_TOTALVFS
int pci_sriov_get_totalvfs(struct pci_dev *dev);
#endif

#ifdef NEED_CPUMASK_LOCAL_SPREAD
unsigned int cpumask_local_spread(unsigned int i, int node);
#endif

#define spin_lock_deinit(lock)	((void)(lock))

struct file *hinic5_file_creat(const char *file_name);

struct file *hinic5_file_open(const char *file_name);

void hinic5_file_close(struct file *file_handle);

u32 hinic5_get_file_size(struct file *file_handle);

void hinic5_set_file_position(struct file *file_handle, u32 position);

int hinic5_file_read(struct file *file_handle, char *log_buffer, u32 rd_length,
	      u32 *file_pos);

u32 hinic5_file_write(struct file *file_handle, const char *log_buffer, u32 wr_length);

struct sdk_thread_info {
	struct task_struct *thread_obj;
	char *name;
	void (*thread_fn)(void *x);
	void *thread_event;
	void *data;
};

int hinic5_creat_thread(struct sdk_thread_info *thread_info);

void hinic5_stop_thread(struct sdk_thread_info *thread_info);

#define destroy_work(work)
void hinic5_utctime_to_localtime(u64 utctime, u64 *localtime);

#ifndef HAVE_TIMER_SETUP
void initialize_timer(const void *adapter_hdl, struct timer_list *timer);
#endif

void hinic5_add_to_timer(struct timer_list *timer, u64 period);
void hinic5_stop_timer(struct timer_list *timer);
void hinic5_delete_timer(struct timer_list *timer);
u64 hinic5_ossl_get_real_time(void);

/* Does not exist in linux kernel, defined as empty */
#define destroy_completion(completion)
#define sema_deinit(lock)
#define mutex_deinit(lock)
#define rwlock_deinit(lock)

#define tasklet_state(tasklet) ((tasklet)->state)

#ifdef NEED_MATH64_MUL_U64_U64_DIV_U64
u64 mul_u64_u64_div_u64(u64 a, u64 b, u64 c);
#else
#define HAVE_PTP_INFO_GETTIMEX64
#endif

#ifdef NEED_PTP_ADJUST_BY_SCALED_PPM
static inline bool diff_by_scaled_ppm(u64 base, long scaled_ppm, u64 *diff)
{
	bool negative = false;
	long scaled_ppm_val = scaled_ppm;

	if (scaled_ppm < 0) {
		negative = true;
		scaled_ppm_val = -scaled_ppm;
	}
	/* scaled_ppm(x.y) low 16bit -> y, high 16bit -> x */
	*diff = mul_u64_u64_div_u64(base, (u64)scaled_ppm_val, 1000000ULL << 16);

	return negative;
}
static inline u64 adjust_by_scaled_ppm(u64 base, long scaled_ppm)
{
	u64 diff;

	if (diff_by_scaled_ppm(base, scaled_ppm, &diff))
		return base - diff;

	return base + diff;
}
#endif

#ifdef NEED_SYSFS_EMIT
int sysfs_emit(char *buf, const char *fmt, ...);
#endif

#ifdef NEED_PCI_DOMAIN_NR
static inline int pci_domain_nr(struct pci_bus *bus)
{
	return bus->domain_nr;
}
#endif

#ifdef NEED_STRLCPY
#define strlcpy strscpy
#endif

#endif /* OSSL_KNL_LINUX_H_ */
