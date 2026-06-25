/* SPDX-License-Identifier: GPL-2.0 */

/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_compat.h
 * @author: Linkdata
 * @date: 2026.04.18
 * @brief:
 * @note:
 */
#ifndef __SXE2_COMPAT_H__
#define __SXE2_COMPAT_H__

#include "sxe2_compat_gcc.h"
#include <linux/filter.h>
#include <linux/version.h>
#include <net/devlink.h>
#include <linux/netdevice.h>
#include <linux/iommu.h>
#include <linux/mm.h>

#include "sxe2_compat_flow_offload.h"

#define HAVE_MACSEC_SUPPORT
#define SUPPORT_ETHTOOL_GET_RMON_STATS
#define HAVE_NDO_XSK_WAKEUP
#define HAVE_NETDEV_BPF_XSK_POOL
#define HAVE_MEM_TYPE_XSK_BUFF_POOL
#define HAVE_XDP_BUFF_RXQ
#define HAVE_AF_XDP_ZC_SUPPORT
#define XSK_UMEM_RETURNS_XDP_DESC
#define HAVE_XDP_BUFF_FRAME_SZ
#define HAVE_AF_XDP_NETDEV_UMEM
#define SUPPORTED_COALESCE_PARAMS
#define IPSEC_HAVE_REAL_DEV
#define SUPPORTED_FLASH_UPDATE_PARAMS
#define HAVE_NDO_ETH_IOCTL
#define HAVE_FLOW_BLOCK_API
#define HAVE_FLOW_INDR_BLOCK_API
#define HAVE_TC_FLOW_INDIR_DEV
#define HAVE_FLOW_OFFLOAD_H
#define HAVE_TC_FLOW_RULE_INFRASTRUCTURE
#define HAVE_TC_INDIR_BLOCK
#define HAVE_TC_FLOWER_ENC
#define HAVE_VXLAN_TYPE
#define HAVE_GENEVE_TYPE
#define HAVE_GRETAP_TYPE
#define HAVE_TC_FLOWER_VLAN_IN_TAGS
#define HAVE_FLOW_DISSECTOR_KEY_CVLAN
#define HAVE_PTP_CLOCK_INFO_GETTIMEX64
#define HAVE_XDP_BUFF_IN_XDP_H
#define HAVE_SCTP
#define HAVE_METADATA_PORT_INFO
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#define HAVE_NDO_OFFLOAD_STATS
#define HAVE_XDP_SUPPORT
#define HAVE_NETDEV_MIN_MAX_MTU
#define HAVE_NDO_SELECT_QUEUE_SB_DEV
#define HAVE_XDP_BUFF_DATA_META
#define HAVE_PTP_CLOCK_INFO_ADJFINE
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
#define HAVE_NETDEV_SB_DEV
#define HAVE_ETHTOOL_FLOW_RSS
#define HAVE_UDP_TUNNEL_NIC_INFO
#define HAVE_UDP_TUNNEL_NIC_SHARED
#define HAVE_UDP_TUNNEL_NIC_INFO_MAY_SLEEP

#ifdef PCLINT
#undef SUPPORT_ETHTOOL_GET_RMON_STATS
#endif

#define NEED_INCLUDE_NETDEV_RX_QUEUE_H
#define NEED_NAPI_ALLOC_SKB
#define RANDOM_ETHER_ADDR_RENAME
#define SUPPORT_MACSEC_INFO_STRUCT
#define SUPPORTED_ETHTOOL_EEPROM_BY_PAGE
#define SXE2_KERNEL_MATCHED
#define IPSEC_HAVE_XS_XSO_DIR
#define VM_FLAGS_ONLY_READ
#define IOMMU_MAP_6_PARAMS
#define PIN_USER_PAGE_6_PARAMS
#define NOT_SUPP_IOMMU_CAPABLE

#ifdef RANDOM_ETHER_ADDR_RENAME
#define random_ether_addr eth_random_addr
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
#define bpf_warn_invalid_xdp_action(dev, prog, act) \
	bpf_warn_invalid_xdp_action_compat(dev, prog, act)
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

#ifdef DEVLINK_ALLOC_NEED_2_PARAMS
static inline struct devlink *
devlink_alloc_compat(const struct devlink_ops *ops, size_t priv_size,
		     struct device * __always_unused dev)
{
	return devlink_alloc(ops, priv_size);
}

#define devlink_alloc(ops, priv_size, dev) devlink_alloc_compat(ops, priv_size, dev)
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
#define __napi_alloc_skb(napi, len, gfp_mask) napi_alloc_skb(napi, len)
#endif

#ifdef NEED_NAPI_BUILD_SKB
#define napi_build_skb(data, frag_size) build_skb(data, frag_size)
#endif

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) (sizeof((((TYPE *)0)->(MEMBER))))
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
static inline size_t size_mul(size_t factor1, size_t factor2)
{
	size_t bytes;

	if (check_mul_overflow(factor1, factor2, &bytes))
		return SIZE_MAX;

	return bytes;
}

#define array_size(a, b)  size_mul(a, b)
#endif

#undef flex_array_size
#define flex_array_size(p, member, count)				\
		((count) * sizeof(p->(member)[0]))
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
		return tcf_block_cb_register(f->block, cb, cb_ident, cb_priv,
					f->extack);
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
#define skb_frag_off(frag)	((frag)->page_offset)
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
ptp_read_system_prets(struct ptp_system_timestamp *sts)
{
}

static inline void
ptp_read_system_postts(struct ptp_system_timestamp *sts)
{
}
#endif

#ifdef NEED_PTP_SYSTEM_TIMESTAMP_INTERFACE
#include <linux/ptp_clock_kernel.h>
static inline void
ptp_read_system_prets(struct ptp_system_timestamp *sts)
{
}

static inline void
ptp_read_system_postts(struct ptp_system_timestamp *sts)
{
}
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
		(sizeof(*__p) + sizeof(*__p->(member)) * (count)); \
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

#endif

