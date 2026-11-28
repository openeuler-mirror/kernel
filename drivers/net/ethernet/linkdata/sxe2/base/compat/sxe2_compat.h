/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_compat.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COMPAT_H__
#define __SXE2_COMPAT_H__

#include <net/devlink.h>
#include <linux/netdevice.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/skbuff.h>
#include <linux/filter.h>
#include <linux/version.h>
#include "sxe2_compat_gcc.h"

#ifndef NEED_COMPAT_DIM
#include <linux/dim.h>
#endif

#include "sxe2_compat_flow_offload.h"

#include "sxe2_compat_overflow.h"

#define HAVE_DEVLINK_FLASH_UPDATE_BEGIN_END_NOTIFY 1
#define HAVE_DEVLINK_FLASH_UPDATE_PARAMS 1
#define HAVE_DEVLINK_FLASH_UPDATE_PARAMS_OVERWRITE_MASK 1
#define HAVE_DEVLINK_HEALTH 1
#define HAVE_DEVLINK_HEALTH_OPS_EXTACK 1
#define HAVE_DEVLINK_INFO_DRIVER_NAME_PUT 1
#define HAVE_DEVLINK_PARAMS 1
#define HAVE_DEVLINK_PARAMS_PUBLISH 1
#define HAVE_DEVLINK_PORT_REGISTERED 1
#define HAVE_DEVLINK_PORT_SPLIT 1
#define HAVE_DEVLINK_PORT_SPLIT_EXTACK 1
#define HAVE_DEVLINK_PORT_SPLIT_IN_OPS 1
#define HAVE_DEVLINK_PORT_TYPE_ETH_HAS_NETDEV 1
#define HAVE_DEVLINK_REGIONS 1
#define HAVE_DEVLINK_REGION_OPS_SNAPSHOT 1
#define HAVE_DEVLINK_REGION_OPS_SNAPSHOT_OPS 1
#define DEVLINK_REGISTER_NEED_2_PARAMS 1
#define HAVE_DEVLINK_RELOAD_ENABLE_DISABLE 1
#define NEED_DEVLINK_FMSG_DUMP_SKB 1
#define NEED_DEVLINK_FMSG_PUT 1
#define NEED_DEVLINK_RESOURCES_UNREGISTER_NO_RESOURCE 1
#define NEED_DEVLINK_TO_DEV 1
#define NEED_DEVLINK_UNLOCKED_RESOURCE 1
#define NEED_DEVL_HEALTH_REPORTER_CREATE 1
#define NEED_DEVL_LOCK 1
#define NEED_DEVL_PARAMS_REGISTER 1
#define NEED_DEVL_PORT_REGISTER 1
#define NEED_DEVL_REGION_CREATE 1
#define NEED_DEVL_REGISTER 1
#define NEED_DEVL_RESOURCE_REGISTER 1
#define DEVLINK_ALLOC_NEED_2_PARAMS 1
#define HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT 1
#define HAVE_NETDEV_SB_DEV 1
#define HAVE_NDO_BRIDGE_SETLINK_EXTACK 1
#define HAVE_NDO_OFFLOAD_STATS 1
#define HAVE_NDO_FDB_ADD_EXTACK 1
#define HAVE_NDO_FDB_ADD_VID 1
#define NDO_FDB_DEL_API_NEED_5_PARAMS 1
#define HAVE_NDO_GET_DEVLINK_PORT 1
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV 1
#define HAVE_NDO_UDP_TUNNEL_CALLBACK 1
#define HAVE_NETDEV_MIN_MAX_MTU 1
#define NETIF_NAPI_ADD_API_NEED_4_PARAMS 1
#define NEED_XDP_FEATURES 1
#define HAVE_AF_XDP_ZC_SUPPORT 1
#define HAVE_NDO_SELECT_QUEUE_SB_DEV 1
#define HAVE_XDP_SUPPORT 1
#define NEED_DEFINE_XDP_PREPARE_BUFF 1
#define HAVE_TX_TIMEOUT_TXQUEUE 1
#define HAVE_INCLUDE_BITFIELD 1
#define NEED_DPLL_NETDEV_PIN_SET 1
#define HAVE_NDO_XSK_WAKEUP 1
#define HAVE_ETHTOOL_SUPPORTED_RING_PARAMS 1
#define NEED_DEFINE_ETHTOOL_SPRINTF 1
#define HAVE_ETHTOOL_FLOW_RSS 1
#define HAVE_ETHTOOL_LINK_MODE_FEC_NONE_BIT 1
#define SUPPORTED_COALESCE_PARAMS 1
#define HAVE_EXPORTED_IRQ_SET_AFFINITY 1
#define BPF_WARN_INVALID_XDP_ACTION_NEED_1_PARAM 1
#define XDP_DO_FLUSH_MAP_DROP 1
#define HAVE_FLOW_BLOCK_API 1
#define HAVE_FLOW_INDR_BLOCK_API 1
#define NEED_FLOW_INDR_BLOCK_CB_REGISTER 1
#define HAVE_FLOW_INDIR_BLOCK_QDISC 1
#define HAVE_FLOW_DISSECTOR_KEY_CVLAN 1
#define HAVE_FLOW_MATCH_ICMP 1
#define HAVE_TC_FLOWER_TCP 1
#define HAVE_TC_FLOWER_ICMP 1
#define HAVE_TC_FLOW_INDIR_BLOCK_CLEANUP 1
#define HAVE_TC_FLOW_INDIR_DEV 1
#define HAVE_TC_FLOW_RULE_INFRASTRUCTURE 1
#define HAVE_FLOW_DISSECTOR_KEY_ENC_IP 1
#define HAVE_TC_FLOWER_ENC 1
#define HAVE_TC_FLOWER_VLAN_IN_TAGS 1
#define HAVE_TCF_EXTS_FOR_EACH_ACTION 1
#define HAVE_TCF_EXTS_HAS_ACTION 1
#define HAVE_TCF_BLOCK 1
#define HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO 1
#define HAVE_TC_INDIR_BLOCK 1
#define HAVE_TC_SETUP_CLSFLOWER 1
#define HAVE_TCF_MIRRED_DEV 1
#define HAVE_TCF_MIRRED_EGRESS_REDIRECT 1
#define HAVE_TCF_MIRRED_REDIRECT 1
#define HAVE_CDEV_DEVICE 1
#define HAVE_NO_LLSEEK 1
#define HAVE_STREAM_OPEN 1
#define CLASS_CREATE_API_NEED_2_PARAMS 1
#define HAVE_GNSS_MODULE 1
#define HAVE_POLL_T 1
#define HAVE_DEV_IN_MDEV_API 1
#define HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE 1
#define NEED_DEFINE_KREALLOC_ARRAY 1
#define NEED_KMEM_CACHE_ALLOC_LRU 1
#define NOT_SUPP_GET_USER_PAGES_LONGTERM 1
#define NOT_SUPP_KMAP_LOCAL_PAGE 1
#define HAVE_GENEVE_TYPE 1
#define HAVE_GRETAP_TYPE 1
#define HAVE_VXLAN_TYPE 1
#define HAVE_STRUCT_PCI_DEV_PTM_ENABLED 1
#define NEED_PCIE_PTM_ENABLED 1
#define NEED_PCI_DISABLE_PTM 1
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE 1
#define HAVE_PTP_CANCEL_WORKER_SYNC 1
#define HAVE_PTP_CLOCK_DO_AUX_WORK 1
#define HAVE_PTP_CLOCK_INFO_ADJFINE 1
#define HAVE_PTP_CLOCK_INFO_GETTIME64 1
#define HAVE_PTP_CLOCK_INFO_GETTIMEX64 1
#define HAVE_PTP_FIND_PIN_UNLOCKED 1
#define NEED_DIFF_BY_SCALED_PPM 1
#define HAVE_PTP_TX_ONESTEP_P2P 1
#define HAVE_PTP_SYS_OFFSET_EXTENDED_IOCTL 1
#define HAVE_PTP_CROSSTIMESTAMP 1
#define HAVE_STDDEF_OFFSETTOEND 1
#define HAVE_PASID_SUPPORT 1
#define HAVE_LMV1_SUPPORT 1
#define HAVE_PAGE_COUNT_BULK_UPDATE 1
#define HAVE_X86_STEPPING 1
#define HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING 1
#define NEED_CLEANUP_API 1
#define NEED___STRUCT_SIZE 1
#define HAVE_COMPLETION_RAW_SPINLOCK 1
#define NEED_FIND_NEXT_BIT_WRAP 1
#define HAVE_HWMON_DEVICE_REGISTER_WITH_INFO 1
#define HAVE_IOMMU_DEV_FEAT_AUX 1
#define HAVE_STRUCT_STATIC_KEY_FALSE 1
#define NEED_LOWER_16_BITS 1
#define NEED_UPPER_16_BITS 1
#define HAVE_LINKMODE 1
#define NEED_LIST_COUNT_NODES 1
#define NEED_DIV_U64_ROUND_CLOSEST 1
#define NEED_DIV_U64_ROUND_UP 1
#define NEED_ROUNDUP_U64 1
#define HAVE_MDEV_GET_DRVDATA 1
#define HAVE_LINUX_REFCOUNT_HEADER 1
#define NEED_SCHED_PARAM 1
#define HAVE_SKB_CSUM_IS_SCTP 1
#define NEED_NAPI_BUILD_SKB 1
#define NEED_STR_ENABLED_DISABLED 1
#define HAVE_STRING_HELPERS_H 1
#define NEED_TIMER_CONTAINER_OF 1
#define HAVE_TRACE_ENABLED_SUPPORT 1
#define HAVE_U64_STATS_FETCH_BEGIN_IRQ 1
#define HAVE_U64_STATS_FETCH_RETRY_IRQ 1
#define NEED_U64_STATS_SET 1
#define HAVE_XARRAY_API 1
#define HAVE_UDP_TUNNEL_NIC_INFO_MAY_SLEEP 1
#define HAVE_UDP_TUNNEL_NIC_SHARED 1
#define HAVE_UDP_TUNNEL_NIC_INFO 1
#define HAVE_ASSIGN_STR_2_PARAMS 1
#define HAVE_STRSCPY 1
#define XSK_UMEM_RETURNS_XDP_DESC 1
#define HAVE_METADATA_PORT_INFO 1
#define HAVE_SCTP 1
#define HAVE_LINUX_BITS_HEADER 1
#define IPSEC_HAVE_REAL_DEV 1
#define IPSEC_STATE_ADD_API_NEED_1_PARAMS 1
#define XDP_RXQ_INFO_REG_NEED_3_PARAMS 1
#define NEED_DEFINE_XDP_PREPARE_BUFF 1
#define HAVE_XDP_BUFF_IN_XDP_H 1
#define HAVE_XDP_BUFF_DATA_META 1
#define HAVE_XDP_BUFF_RXQ 1
#define HAVE_MEM_TYPE_XSK_BUFF_POOL 1
#define HAVE_AF_XDP_NETDEV_UMEM 1
#define HAVE_NETDEV_BPF_XSK_POOL 1
#define HAVE_XDP_BUFF_FRAME_SZ 1
#define HAVE_XSK_IS_EOP_DESC 1
#define HAVE_SKB_FILL_PAGE_DESC_NOACC 1

#ifndef ETH_GSTRING_LEN
#define ETH_GSTRING_LEN 32
#endif

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
struct _kc_xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
};

#define xdp_buff _kc_xdp_buff

#define TIMER_DATA_TYPE		unsigned long
#define TIMER_FUNC_TYPE		void (*)(TIMER_DATA_TYPE)

#define timer_setup(timer, callback, flags)				\
	__setup_timer((timer), (TIMER_FUNC_TYPE)(callback),		\
		      (TIMER_DATA_TYPE)(timer), (flags))

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

#ifndef xdp_do_flush_map
#define xdp_do_flush_map() do {} while (0)
#endif
#endif

#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
static inline bool _kc_napi_complete_done2(struct napi_struct *napi,
					   int __always_unused work_done)
{
	(void)napi_complete(napi);

	return true;
}

#ifdef napi_complete_done
#undef napi_complete_done
#endif
#define napi_complete_done _kc_napi_complete_done2
#endif

#if ((KERNEL_VERSION(4, 19, 0) > LINUX_VERSION_CODE) || defined(NEED_BITMAP_ALLOC))
#define bitmap_alloc(nbits, flags) \
	kmalloc_array(BITS_TO_LONGS(nbits), sizeof(unsigned long), flags)
#define bitmap_zalloc(nbits, flags) bitmap_alloc(nbits, ((flags) | __GFP_ZERO))
#define bitmap_free(bitmap) kfree(bitmap)
#endif

#if (KERNEL_VERSION(4, 18, 0) > LINUX_VERSION_CODE)
#define KERNEL_WRITE_POS_LOFF
#endif

#ifdef RANDOM_ETHER_ADDR_RENAME
#define random_ether_addr eth_random_addr
#endif

#ifdef NEED_XDP_FEATURES
enum netdev_xdp_act {
	NETDEV_XDP_ACT_BASIC = 1,
	NETDEV_XDP_ACT_REDIRECT = 2,
	NETDEV_XDP_ACT_NDO_XMIT = 4,
	NETDEV_XDP_ACT_XSK_ZEROCOPY = 8,
	NETDEV_XDP_ACT_HW_OFFLOAD = 16,
	NETDEV_XDP_ACT_RX_SG = 32,
	NETDEV_XDP_ACT_NDO_XMIT_SG = 64,

	NETDEV_XDP_ACT_MASK = 127,
};

typedef u32 xdp_features_t;

static inline void
xdp_set_features_flag(struct net_device *dev, xdp_features_t val)
{
}

static inline void xdp_clear_features_flag(struct net_device *dev)
{
}

static inline void
xdp_features_set_redirect_target(struct net_device *dev, bool support_sg)
{
}

static inline void xdp_features_clear_redirect_target(struct net_device *dev)
{
}
#endif

#ifdef NEED_XSK_BUFF_POOL_RENAME
#define XDP_SETUP_XSK_POOL XDP_SETUP_XSK_UMEM
#define xsk_get_pool_from_qid xdp_get_umem_from_qid
#define xsk_pool_get_rx_frame_size xsk_umem_get_rx_frame_size
#define xsk_pool_set_rxq_info xsk_buff_set_rxq_info
#define xsk_pool_dma_unmap xsk_buff_dma_unmap
#define xsk_pool_dma_map xsk_buff_dma_map
#define xsk_tx_peek_desc xsk_umem_consume_tx
#define xsk_tx_release xsk_umem_consume_tx_done
#define xsk_tx_completed xsk_umem_complete_tx
#define xsk_uses_need_wakeup xsk_umem_uses_need_wakeup
#endif

#ifdef XDP_BUFF_TO_FRAME_RENAME
#define xdp_convert_buff_to_frame convert_to_xdp_frame
#endif

#ifdef NEED_XSK_UMEM_RELEASE_RENAME
#define xsk_umem_release_addr		xsk_umem_discard_addr
#define xsk_umem_release_addr_rq	xsk_umem_discard_addr_rq
#endif

#if defined(HAVE_MEM_TYPE_XSK_BUFF_POOL) && \
!defined(HAVE_NETDEV_BPF_XSK_POOL) && \
defined(HAVE_AF_XDP_MULTI_BUF_SUPPORT)
#define NEED_XSK_POOL_FROM_UMEM
#endif

#ifdef NEED_DEFINE_PCI_AER_CLEAR_NONFATAL_STATUS
#define pci_aer_clear_nonfatal_status pci_cleanup_aer_uncorrect_error_status
#endif

#ifdef NEED_FLOW_CLS_OFFLOAD
struct tc_cls_flower_offload;
#define flow_cls_offload tc_cls_flower_offload
struct tc_block_offload;
#define flow_block_offload tc_block_offload
#define flow_cls_offload_flow_rule tc_cls_flower_offload_flow_rule
#endif

#ifdef NEED_FLOW_BLOCK_CB_SETUP_SIMPLE
#define FLOW_CLS_REPLACE TC_CLSFLOWER_REPLACE
#define FLOW_CLS_DESTROY TC_CLSFLOWER_DESTROY
#define FLOW_CLS_STATS TC_CLSFLOWER_STATS
#define FLOW_CLS_TMPLT_CREATE TC_CLSFLOWER_TMPLT_CREATE
#define FLOW_CLS_TMPLT_DESTROY TC_CLSFLOWER_TMPLT_DESTROY
#endif

#ifdef NEED_PCI_AER_CLEAR_NONFATAL_STATUS
#define pci_aer_clear_nonfatal_status	pci_cleanup_aer_uncorrect_error_status
#endif

#ifdef NEED_FLOW_BLOCK_BINDER_TYPE
#define FLOW_BLOCK_BINDER_TYPE_UNSPEC TCF_BLOCK_BINDER_TYPE_UNSPEC
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS \
	TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS \
	TCF_BLOCK_BINDER_TYPE_CLSACT_EGRESS
#endif

#ifdef NEED_FLOW_BLOCK_BIND
#define FLOW_BLOCK_BIND TC_BLOCK_BIND
#define FLOW_BLOCK_UNBIND TC_BLOCK_UNBIND
#endif

#ifdef NEED_FLOW_INDR_BLOCK_CB_REGISTER
#include <net/pkt_cls.h>
#define __flow_indr_block_cb_register __tc_indr_block_cb_register
#define __flow_indr_block_cb_unregister __tc_indr_block_cb_unregister
#endif

#ifdef NEED_XDP_CONVERT_BUFF_TO_FRAME
#define xdp_convert_buff_to_frame convert_to_xdp_frame
#endif

#ifndef NETIF_NAPI_ADD_API_NEED_4_PARAMS
static inline void
netif_napi_add_compat(struct net_device *dev, struct napi_struct *napi,
		      int (*poll)(struct napi_struct *, int), int weight)
{
	netif_napi_add(dev, napi, poll);
}

#ifdef netif_napi_add
#undef netif_napi_add
#endif
#define netif_napi_add(dev, napi, poll, weight) netif_napi_add_compat(dev, napi, poll, weight)
#endif

#ifdef BPF_WARN_INVALID_XDP_ACTION_NEED_1_PARAM
static inline void
bpf_warn_invalid_xdp_action_compat(struct net_device *dev, struct bpf_prog *prog, u32 act)
{
	bpf_warn_invalid_xdp_action(act);
}

#ifdef bpf_warn_invalid_xdp_action
#undef bpf_warn_invalid_xdp_action
#endif
#define bpf_warn_invalid_xdp_action(dev, prog, act) bpf_warn_invalid_xdp_action_compat(dev, prog, act)
#endif

#ifndef CLASS_CREATE_API_NEED_2_PARAMS
static inline struct class *class_create_compat(struct module *owner, const char *devname)
{
	return class_create(devname);
}

#ifdef class_create
#undef class_create
#endif
#define class_create(owner, devname) class_create_compat(owner, devname)
#endif

#ifdef XDP_RXQ_INFO_REG_NEED_3_PARAMS
static inline int
xdp_rxq_info_reg_compat(struct xdp_rxq_info *xdp_rxq, struct net_device *dev,
			u32 queue_index, unsigned int __always_unused napi_id)
{
	return xdp_rxq_info_reg(xdp_rxq, dev, queue_index);
}

#define xdp_rxq_info_reg(xdp_rxq, dev, queue_index, napi_id) \
		xdp_rxq_info_reg_compat(xdp_rxq, dev, queue_index, napi_id)
#endif

#if !defined(PCLINT)
#if defined(HAVE_AF_XDP_MULTI_BUF_SUPPORT) && \
	!defined(HAVE_SKB_FILL_PAGE_DESC_NOACC)
static inline void
__skb_fill_page_desc_noacc(struct skb_shared_info *shinfo, int i,
			   struct page *page, int off, int size)
{
	skb_frag_t *frag = &shinfo->frags[i];

	__skb_frag_set_page(frag, page);
	skb_frag_off_set(frag, off);
	skb_frag_size_set(frag, size);
}
#endif

#if defined(HAVE_AF_XDP_MULTI_BUF_SUPPORT) && !defined(HAVE_XDP_FRAME_BULK)
struct xdp_frame_bulk {
	int count;
};

static inline void xdp_frame_bulk_init(struct xdp_frame_bulk *bq)
{
	bq->count = 0;
}

static inline void
xdp_return_frame_bulk(struct xdp_frame *xdpf, struct xdp_frame_bulk *bq)
{
	(void)bq;
	xdp_return_frame(xdpf);
}

static inline void xdp_flush_frame_bulk(struct xdp_frame_bulk *bq)
{
	(void)bq;
}
#endif
#endif

#ifdef DEVLINK_ALLOC_NEED_2_PARAMS
static inline struct devlink *
devlink_alloc_compat(const struct devlink_ops *ops, size_t priv_size,
		     struct device * __always_unused dev)
{
	return devlink_alloc(ops, priv_size);
}

#define devlink_alloc(ops, priv_size, dev) devlink_alloc_compat(ops, priv_size, dev)
#endif

#ifdef DEVLINK_REGISTER_NEED_2_PARAMS
static inline int
devlink_register_compat(struct devlink *devlink, struct device *dev)
{
	return devlink_register(devlink, dev);
}

#define devlink_register(devlink, dev) devlink_register_compat(devlink, dev)
#endif

#ifdef XDP_DO_FLUSH_MAP_DROP
#define xdp_do_flush_map xdp_do_flush
#endif

#ifdef HAVE_STRSCPY
#define SXE2_STRCPY strscpy
#else
#define SXE2_STRCPY strlcpy
#endif

#ifdef NEED_NAPI_ALLOC_SKB
#define __napi_alloc_skb(napi, len, gfp_mask) \
	({ \
		typeof(gfp_mask) __unused_mask __attribute__((unused)) = (gfp_mask); \
		napi_alloc_skb(napi, len); \
	})

#endif

#ifdef NEED_NAPI_BUILD_SKB
#define napi_build_skb(data, frag_size) build_skb(data, frag_size)
#endif

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) (sizeof((((TYPE *)0)->MEMBER)))
#endif

#ifndef BITS_PER_TYPE
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#endif

#ifdef NEED_DEFINE_BITS_TO_U32
#define BITS_TO_U32(nr) __KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#endif

#ifdef NEED_XSK_UMEM_GET_RX_FRAME_SIZE
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifndef xsk_umem_get_rx_frame_size
static inline u32
xsk_umem_get_rx_frame_size_compat(struct xdp_umem *umem)
{
	return umem->chunk_size_nohr - XDP_PACKET_HEADROOM;
}

#define xsk_umem_get_rx_frame_size xsk_umem_get_rx_frame_size_compat
#endif
#endif
#endif

#ifdef NEED_DEFINE_ETHTOOL_SPRINTF
#ifndef ethtool_sprintf
void ethtool_sprintf_compat(u8 **data, const char *fmt, ...);
#define ethtool_sprintf ethtool_sprintf_compat
#endif
#endif

#ifdef NEED_DEFINE_KREALLOC_ARRAY
static inline void *__must_check krealloc_array(void *p,
						size_t new_n,
						size_t new_size,
						gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(new_n, new_size, &bytes)))
		return NULL;

	return krealloc(p, bytes, flags);
}
#endif

#ifdef NEED_DEFINE_DEV_PAGE_IS_REUSABLE
static inline bool dev_page_is_reusable(struct page *page)
{
	return likely(page_to_nid(page) == numa_mem_id() &&
		      !page_is_pfmemalloc(page));
}
#endif

#ifdef NEED_DEFINE_NET_PREFETCH
static inline void net_prefetch(void *p)
{
	prefetch(p);
#if L1_CACHE_BYTES < 128
	prefetch((u8 *)p + L1_CACHE_BYTES);
#endif
}
#endif

#ifdef NEED_DEFINE_XDP_PREPARE_BUFF
static __always_inline void
xdp_prepare_buff(struct xdp_buff *xdp, unsigned char *hard_start,
		 int headroom, int data_len, const bool meta_valid)
{
	unsigned char *data = hard_start + headroom;

	xdp->data_hard_start = hard_start;
	xdp->data = data;
	xdp->data_end = data + data_len;
	xdp->data_meta = meta_valid ? data : data + 1;
}
#endif

#ifdef NEED_DEFINE_ETH_HW_ADDR_SET
static inline void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
	ether_addr_copy(dev->dev_addr, addr);
}
#endif

#ifdef NEED_DEFINE_MUL_U64_U64_DIV_U64
static inline u64 mul_u64_u64_div_u64(u64 a, u64 b, u64 c)
{
	u64 res = 0, div, rem;
	int shift;

	if (ilog2(a) + ilog2(b) > 62) {
		div = div64_u64_rem(b, c, &rem);
		res = div * a;
		b = rem;

		shift = ilog2(a) + ilog2(b) - 62;
		if (shift > 0) {
			b >>= shift;
			c >>= shift;
			if (!c)
				return res;
		}
	}

	return res + div64_u64(a * b, c);
}
#endif

#ifdef NEED_DEFINE_FLEX_ARRAY_SIZE
#ifndef array_size
#ifndef SXE2_NEED_DEFINE_SIZE_MUL
static inline size_t size_mul(size_t factor1, size_t factor2)
{
	size_t bytes;

	if (check_mul_overflow(factor1, factor2, &bytes))
		return SIZE_MAX;

	return bytes;
}
#endif

#define array_size(a, b)  size_mul(a, b)
#endif

#undef flex_array_size
#define flex_array_size(p, member, count)				\
		array_size(count,						\
			    sizeof(*(p)->member) + __must_be_array((p)->member))
#endif

#ifdef NEED_FLOW_BLOCK_CB_SETUP_SIMPLE
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
#include <net/pkt_cls.h>
static inline int flow_block_cb_setup_simple(struct flow_block_offload *f,
					     struct list_head __always_unused *driver_list,
				   tc_setup_cb_t *cb,
				   void *cb_ident, void *cb_priv,
				   bool ingress_only)
{
	if (ingress_only &&
	    f->binder_type != TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	switch (f->command) {
	case TC_BLOCK_BIND:
#ifdef HAVE_TCF_BLOCK_CB_REGISTER_EXTACK
		return tcf_block_cb_register(f->block, cb, cb_ident, cb_priv,
					     f->extack);
#else
		return tcf_block_cb_register(f->block, cb, cb_ident, cb_priv);
#endif
	case TC_BLOCK_UNBIND:
		tcf_block_cb_unregister(f->block, cb, cb_ident);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}
#endif
#endif

#ifdef NEED_DEFINE_KFREE_SENSITIVE
static inline void kfree_sensitive(const void *p)
{
	size_t ks;
	void *mem = (void *)p;

	ks = ksize(mem);
	if (ks)
		memzero_explicit(mem, ks);
	kfree(mem);
}
#endif

#ifdef NEED_DEFINE_NETIF_IS_GENEVE
static inline bool netif_is_geneve(const struct net_device *dev)
{
	return dev->rtnl_link_ops &&
	       !strcmp(dev->rtnl_link_ops->kind, "geneve");
}
#endif

#ifdef NEED_DEFINE_SKB_FRAG_OFF
#define skb_frag_off(frag)	frag->page_offset
#endif

#ifndef DIV_ROUND_DOWN_ULL
#define DIV_ROUND_DOWN_ULL(ll, d) \
	({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })
#endif

#ifndef ETH_P_LLDP
#define ETH_P_LLDP	0x88CC
#endif

#ifdef NEED_PTP_SYSTEM_TIMESTAMP
struct ptp_system_timestamp {
	struct timespec64 pre_ts;
	struct timespec64 post_ts;
};

static inline void
ptp_read_system_prets(struct ptp_system_timestamp *sts) { }

static inline void
ptp_read_system_postts(struct ptp_system_timestamp *sts) { }
#endif

#ifdef NEED_PTP_SYSTEM_TIMESTAMP_INTERFACE
#include <linux/ptp_clock_kernel.h>
static inline void
ptp_read_system_prets(struct ptp_system_timestamp *sts) { }

static inline void
ptp_read_system_postts(struct ptp_system_timestamp *sts) { }
#endif

#ifdef HAVE_SKB_XMIT_MORE
#define netdev_xmit_more()	(first_buf->skb->xmit_more)
#endif

#ifdef NEED_NETDEV_TX_SENT_QUEUE
static inline bool __netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					  unsigned int bytes,
					  bool xmit_more)
{
	if (xmit_more) {
#ifdef CONFIG_BQL
		dql_queued(&dev_queue->dql, bytes);
#endif
		return netif_tx_queue_stopped(dev_queue);
	}
	netdev_tx_sent_queue(dev_queue, bytes);
	return true;
}
#endif

#ifdef ETH_GET_HEADLEN_NEED_2_PRAMS
static inline u32 eth_get_headlen_compat(const struct net_device __always_unused *dev,
					 void *data, unsigned int len)
{
	return eth_get_headlen(data, len);
}

#define eth_get_headlen(dev, data, len) eth_get_headlen_compat(dev, data, len)
#endif

#ifdef NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
static inline int ida_alloc(struct ida *ida, gfp_t gfp)
{
	return ida_simple_get(ida, 0, 0, gfp);
}

static inline int ida_alloc_min(struct ida *ida, unsigned int min, gfp_t gfp)
{
	return ida_simple_get(ida, min, 0, gfp);
}

static inline int ida_alloc_max(struct ida *ida, unsigned int max, gfp_t gfp)
{
	return ida_simple_get(ida, 0, max, gfp);
}

static inline int
ida_alloc_range(struct ida *ida, unsigned int min, unsigned int max, gfp_t gfp)
{
	return ida_simple_get(ida, min, max, gfp);
}

static inline void ida_free(struct ida *ida, unsigned int id)
{
	ida_simple_remove(ida, id);
}
#endif

#ifndef struct_size
#define struct_size(p, member, count) \
	({ \
		typeof(p) __p = (p); \
		(sizeof(*__p) + sizeof(*__p->member) * (count)); \
	})
#endif

#ifdef NEED_BITMAP_FROM_ARR32
#if BITS_PER_LONG == 64
static inline void bitmap_from_arr32(unsigned long *bitmap, const u32 *buf,
				     unsigned int nbits)
{
	unsigned int i, halfwords;

	halfwords = DIV_ROUND_UP(nbits, 32);
	for (i = 0; i < halfwords; i++) {
		bitmap[i / 2] = (unsigned long)buf[i];
		if (++i < halfwords)
			bitmap[i / 2] |= ((unsigned long)buf[i]) << 32;
	}

	if (nbits % BITS_PER_LONG)
		bitmap[(halfwords - 1) / 2] &= BITMAP_LAST_WORD_MASK(nbits);
}
#else
#define bitmap_from_arr32(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *)(bitmap),	\
			       (const unsigned long *)(buf), (nbits))
#endif
#endif

#ifdef NEED_BITMAP_TO_ARR32
#if BITS_PER_LONG == 64
static inline void bitmap_to_arr32(u32 *buf, const unsigned long *bitmap,
				   unsigned int nbits)
{
	unsigned int i, halfwords;

	halfwords = DIV_ROUND_UP(nbits, 32);
	for (i = 0; i < halfwords; i++) {
		buf[i] = (u32)(bitmap[i / 2] & UINT_MAX);
		if (++i < halfwords)
			buf[i] = (u32)(bitmap[i / 2] >> 32);
	}

	if (nbits % BITS_PER_LONG)
		buf[halfwords - 1] &= (u32)(UINT_MAX >> ((-nbits) & 31));
}
#else
#define bitmap_to_arr32(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *)(buf),		\
			       (const unsigned long *)(bitmap), (nbits))
#endif
#endif

#ifndef IEEE_8021QAZ_APP_SEL_DSCP
#define IEEE_8021QAZ_APP_SEL_DSCP	5
#endif

#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU 68
#endif

#ifdef NEED_DEFINE_PAGE_FRAG_FREE
#define page_frag_free __free_page_frag
#endif

#ifdef NEED_ASSIGN_BIT
static inline void assign_bit(long nr, unsigned long *addr, bool value)
{
	if (value)
		set_bit(nr, addr);
	else
		clear_bit(nr, addr);
}
#endif

#ifdef NEED_DMA_ATTRS
#include <linux/page_ref.h>
static inline
dma_addr_t __kc_dma_map_page_attrs(struct device *dev, struct page *page,
				   size_t offset, size_t size,
				   enum dma_data_direction dir,
				   unsigned long __always_unused attrs)
{
	return dma_map_page(dev, page, offset, size, dir);
}

#define dma_map_page_attrs __kc_dma_map_page_attrs

static inline
void __kc_dma_unmap_page_attrs(struct device *dev,
			       dma_addr_t addr, size_t size,
			       enum dma_data_direction dir,
			       unsigned long __always_unused attrs)
{
	dma_unmap_page(dev, addr, size, dir);
}

#define dma_unmap_page_attrs __kc_dma_unmap_page_attrs

static inline void __page_frag_cache_drain(struct page *page,
					   unsigned int count)
{
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (!page_ref_sub_and_test(page, count))
		return;

	init_page_count(page);
#else
	WARN_ON(count > 1);
	if (!count)
		return;
#endif
	__free_pages(page, compound_order(page));
}
#endif

#ifdef FIXUP_USER_FAULT_5_PARAMS
static inline int
fixup_user_fault_compat(struct mm_struct *mm,
			unsigned long address, unsigned int fault_flags,
		     bool *unlocked)
{
	return fixup_user_fault(NULL, mm, address, fault_flags, unlocked);
}

#ifdef fixup_user_fault
#undef fixup_user_fault
#endif
#define fixup_user_fault(mm, address, fault_flags, unlocked) \
	fixup_user_fault_compat((mm), (address), (fault_flags), (unlocked))
#endif

#ifdef NOT_SUPP_MMAP_READ_LOCK
static inline void mmap_read_lock(struct mm_struct *mm)
{
	down_read(&mm->mmap_sem);
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
	up_read(&mm->mmap_sem);
}
#endif

#ifdef NOT_SUPP_UNTAGGED_ADDR
#include <linux/uaccess.h>
#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif
#endif

#ifdef NOT_SUPP_VMA_LOOKUP
static inline
struct vm_area_struct *vma_lookup(struct mm_struct *mm, unsigned long addr)
{
	return find_vma_intersection(mm, addr, addr + 1);
}
#endif

#ifdef PIN_USER_PAGE_8_PARAMS
static inline long pin_user_pages_remote_compat(struct mm_struct *mm,
						unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   struct vm_area_struct **vmas, int *locked)
{
	return pin_user_pages_remote(NULL, mm, start, nr_pages, gup_flags, pages, vmas, locked);
}

#ifdef pin_user_pages_remote
#undef pin_user_pages_remote
#endif
#define pin_user_pages_remote(mm, start, nr_pages, gup_flags, pages, vmas, locked) \
	pin_user_pages_remote_compat(mm, start, nr_pages, gup_flags, pages, vmas, locked)
#elif defined(PIN_USER_PAGE_6_PARAMS)
static inline long pin_user_pages_remote_compat(struct mm_struct *mm,
						unsigned long start, unsigned long nr_pages,
			   unsigned int gup_flags, struct page **pages,
			   struct vm_area_struct **vmas, int *locked)
{
	(void)vmas;
	return pin_user_pages_remote(mm, start, nr_pages, gup_flags, pages, locked);
}

#ifdef pin_user_pages_remote
#undef pin_user_pages_remote
#endif
#define pin_user_pages_remote(mm, start, nr_pages, gup_flags, pages, vmas, locked) \
	pin_user_pages_remote_compat(mm, start, nr_pages, gup_flags, pages, vmas, locked)
#endif

#ifdef EVENTFD_SIGNAL_1PARAM
static inline int eventfd_signal_compat(struct eventfd_ctx *ctx, int n)
{
	(void)eventfd_signal(ctx);

	return n;
}

#ifdef eventfd_signal
#undef eventfd_signal
#endif
#define eventfd_signal(ctx, n) \
	eventfd_signal_compat(ctx, n)
#endif

#ifndef VM_FLAGS_ONLY_READ
static inline void vm_flags_set(struct vm_area_struct *vma,
				vm_flags_t flags)
{
	vma->vm_flags |= flags;
}
#endif

#ifdef IOMMU_MAP_6_PARAMS
static inline int iommu_map_compat(struct iommu_domain *domain, unsigned long iova,
				   phys_addr_t paddr, size_t size, int prot)
{
	return iommu_map(domain, iova, paddr, size, prot, GFP_KERNEL_ACCOUNT);
}

#ifdef iommu_map
#undef iommu_map
#endif
#define iommu_map(domain, iova, paddr, size, prot) \
	iommu_map_compat(domain, iova, paddr, size, prot)
#endif

#ifdef NOT_SUPP_KMAP_LOCAL_PAGE
static inline void *kmap_local_page(struct page *page)
{
	return kmap(page);
}

static inline void kunmap_local(void *vaddr)
{
	kunmap(virt_to_page(vaddr));
}

#endif

#ifndef CONFIG_DCB
#define IEEE_8021QAZ_MAX_TCS    8
#define IEEE_8021Q_MAX_PRIORITIES 8
#endif

#ifndef NEED_COMPAT_DIM
#ifndef NEED_DIM_END_SAMPLE_POINTER
static inline void net_dim_compat(struct dim *dim,
				  const struct dim_sample *end_sample)
{
	if (end_sample)
		net_dim(dim, *end_sample);
}

#define net_dim(_dim, _p_dim_sample) net_dim_compat(_dim, _p_dim_sample)
#endif
#endif

#endif
