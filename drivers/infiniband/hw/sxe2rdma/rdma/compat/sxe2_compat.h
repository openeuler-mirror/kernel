/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SXE2_COMPAT_H__
#define __SXE2_COMPAT_H__

#include <net/xdp.h>
#include <net/devlink.h>

#include "sxe2_compat_gcc.h"

#include <rdma/ib_umem.h>
#include <linux/scatterlist.h>
#include <rdma/ib_user_verbs.h>

#ifdef NEED_KERNEL_AUX_DEFINE
#include "auxiliary_bus.h"
#include "rdma/uverbs_ioctl.h"
#endif
#ifdef CTYUNOS_25_03
#include <linux/auxiliary_bus.h>
#endif

#ifndef IB_QP_ATTR_STANDARD_BITS
#define IB_QP_ATTR_STANDARD_BITS GENMASK(20, 0)
#endif
#include <rdma/ib_verbs.h>

#ifndef from_tasklet
#define from_tasklet(var, callback_tasklet, tasklet_fieldname) \
	container_of(callback_tasklet, typeof(*var), tasklet_fieldname)
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

#ifdef DEVLINK_ALLOC_NEED_2_PARAMS
static inline struct devlink *
devlink_alloc_compat(const struct devlink_ops *ops, size_t priv_size,
		  struct device * __always_unused dev)
{
	return devlink_alloc(ops, priv_size);
}

#define devlink_alloc(ops, priv_size, dev) devlink_alloc_compat(ops, priv_size, dev)
#endif

#define SXE2_STRCPY strlcpy

#ifdef NEED_NAPI_BUILD_SKB
#define napi_build_skb(data, frag_size) build_skb(data, frag_size)
#endif

#ifdef NEED_DEFINE_BITS_TO_U32
#define BITS_TO_U32(nr) __KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#endif

#ifdef NEED_DEFINE_ETHTOOL_SPRINTF
#ifndef ethtool_sprintf
static inline void ethtool_sprintf_compat(u8 **data, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(*data, ETH_GSTRING_LEN, fmt, args);
	va_end(args);

	*data += ETH_GSTRING_LEN;
}
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

#ifdef RDMA_IRQ_UPDATE_AFFINITY
static inline int irq_update_affinity_hint(unsigned int irq, const struct cpumask *m)
{
	return irq_set_affinity_hint(irq, m);
}
#endif
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS_NOT_SUPPORT
static inline size_t sxe2_ib_umem_num_dma_blocks(struct ib_umem *umem, unsigned long pgsz, u64 iova)
{
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif

	return (size_t)((ALIGN(iova + umem->length, pgsz) -
			 ALIGN_DOWN(iova, pgsz))) / pgsz;
}
#endif
#ifdef NEED_RDMA_UMEM_BLOCK_ITER_NEXT
struct kc_ib_block_iter {
	struct scatterlist *__sg;
	dma_addr_t __dma_addr;
	size_t __sg_numblocks;
	unsigned int __sg_nents;
	unsigned int __sg_advance;
	unsigned int __pg_bit;
};

void kc__rdma_block_iter_start(struct kc_ib_block_iter *biter,
					struct scatterlist *sglist,
					unsigned int nents,
					unsigned long pgsz);
bool kc__rdma_block_iter_next(struct kc_ib_block_iter *biter);

static inline dma_addr_t
kc_rdma_block_iter_dma_address(struct kc_ib_block_iter *biter)
{
	return biter->__dma_addr & ~(BIT_ULL(biter->__pg_bit) - 1);
}

static inline void
kc__rdma_umem_block_iter_start(struct kc_ib_block_iter *biter,
							struct ib_umem *umem,
							unsigned long pgsz)
{
	kc__rdma_block_iter_start(biter, umem->sg_head.sgl, umem->nmap,
							  pgsz);
	biter->__sg_advance = ib_umem_offset(umem) & ~(pgsz - 1);
	biter->__sg_numblocks =
		sxe2_ib_umem_num_dma_blocks(umem, pgsz, umem->address);
}

static inline bool
kc__rdma_umem_block_iter_next(struct kc_ib_block_iter *biter)
{
	return kc__rdma_block_iter_next(biter) && biter->__sg_numblocks--;
}

#define kc_rdma_umem_for_each_dma_block(umem, biter, pgsz)                        \
	for (kc__rdma_umem_block_iter_start(biter, umem, pgsz);                  \
		kc__rdma_umem_block_iter_next(biter);)

#undef rdma_umem_for_each_dma_block
#define rdma_umem_for_each_dma_block kc_rdma_umem_for_each_dma_block
#define ib_block_iter kc_ib_block_iter
#define rdma_block_iter_dma_address kc_rdma_block_iter_dma_address
#define __rdma_umem_block_iter_start kc__rdma_umem_block_iter_start
#define __rdma_block_iter_next kc__rdma_block_iter_next
#endif
#ifdef UVERBS_CMD_MASK
static inline void kc_set_rdma_uverbs_cmd_mask(struct ib_device *dev)
{
	 dev->uverbs_cmd_mask =
		BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT) |
		BIT_ULL(IB_USER_VERBS_CMD_ALLOC_PD) |
		BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_PD) |
		BIT_ULL(IB_USER_VERBS_CMD_REG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_REREG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_DEREG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_RESIZE_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_MODIFY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_POLL_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_POST_RECV) |
		BIT_ULL(IB_USER_VERBS_CMD_POST_SEND) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_MODIFY_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_SRQ) |
		BIT_ULL(IB_USER_VERBS_CMD_POST_SRQ_RECV) |
		BIT_ULL(IB_USER_VERBS_CMD_ATTACH_MCAST) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_AH) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_AH) |
		BIT_ULL(IB_USER_VERBS_CMD_DETACH_MCAST);
	dev->uverbs_ex_cmd_mask = BIT_ULL(IB_USER_VERBS_EX_CMD_MODIFY_QP) |
		BIT_ULL(IB_USER_VERBS_EX_CMD_QUERY_DEVICE) |
		BIT_ULL(IB_USER_VERBS_EX_CMD_CREATE_CQ);

}
#endif

#ifdef IRQ_UPDATE_AFFINITY
/**
 * irq_update_affinity_hint - Update the affinity hint
 * @irq:	Interrupt to update
 * @m:		cpumask pointer (NULL to clear the hint)
 *
 * Updates the affinity hint, but does not change the affinity of the interrupt.
 */
static inline int
irq_update_affinity_hint(unsigned int irq, const struct cpumask *m)
{
	return irq_set_affinity_hint(irq, m);
}
#endif

#ifdef NEED_IB_RATE
enum ib_rate_compat {
	IB_RATE_28_GBPS		 = 19,
	IB_RATE_50_GBPS		 = 20,
	IB_RATE_400_GBPS	 = 21,
	IB_RATE_600_GBPS	 = 22,
};
#endif

#ifdef NEED_UVERBS_ATTR_CONST_IN
#define UVERBS_ATTR_CONST_IN(_attr_id, _enum_type, ...)                        \
	UVERBS_ATTR_PTR_IN(                                                    \
		_attr_id,                                                      \
		UVERBS_ATTR_SIZE(                                              \
			sizeof(u64) + BUILD_BUG_ON_ZERO(!sizeof(_enum_type)),  \
			sizeof(u64)),                                          \
		__VA_ARGS__)
#endif

#ifdef NEED_AUXILIARY_SET
static inline void auxiliary_set_drvdata(struct auxiliary_device *auxdev,
					 void *data)
{
	auxdev->dev.driver_data = data;
}

static inline void *auxiliary_get_drvdata(struct auxiliary_device *auxdev)
{
	return auxdev->dev.driver_data;
}
#endif

#ifdef NEED_UAPI_CHAIN_OBJ_TREE_NAME
enum uapi_definition_kind {
	UAPI_DEF_END = 0,
	UAPI_DEF_OBJECT_START,
	UAPI_DEF_WRITE,
	UAPI_DEF_CHAIN_OBJ_TREE,
	UAPI_DEF_CHAIN,
	UAPI_DEF_IS_SUPPORTED_FUNC,
	UAPI_DEF_IS_SUPPORTED_DEV_FN,
};

#define PTR_IF(cond, ptr)	((cond) ? (ptr) : NULL)

#define UAPI_DEF_CHAIN_OBJ_TREE(_object_enum, _object_ptr, ...)	\
		({										\
			{									\
				.kind = UAPI_DEF_CHAIN_OBJ_TREE,\
				.object_start = { .object_id = _object_enum },\
				.chain_obj_tree = _object_ptr,	\
			},									\
			##__VA_ARGS__						\
		})

#define UAPI_DEF_CHAIN_OBJ_TREE_NAMED(_object_enum, ...)                       \
	UAPI_DEF_CHAIN_OBJ_TREE(_object_enum,				       \
		PTR_IF(IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS),	       \
		&UVERBS_OBJECT(_object_enum)),			       \
		##__VA_ARGS__)
#endif

#ifdef IB_UMEM_GET_V3
static inline struct ib_ucontext *rdma_device_to_drv_context(struct ib_device *device)
{
	void *__ptr = (void *)(device);

	return (struct ib_ucontext *)((char *)__ptr - offsetof(struct ib_ucontext, device));
}
#endif

#ifdef NEDD_ONE_PARAM_ALLOC
#define sxe2_ib_alloc_device(drv_struct, member)                                    \
	container_of(ib_alloc_device(sizeof(struct drv_struct) +              \
				BUILD_BUG_ON_ZERO(offsetof(              \
				struct drv_struct, member))),    \
	struct drv_struct, member)
#endif

#ifdef NEED_CREATE_AH_FLAGS
enum rdma_create_ah_flags {
	RDMA_CREATE_AH_SLEEPABLE = BIT(0),
};
#endif

#ifdef HAVE_NO_IB_DEVICE_OPS
void sxe2_set_device_ops(struct ib_device *dev_ops);
#endif

#ifdef NEED_RDMA_MMAP_IO
struct sxe2_vma_data {
	struct list_head list;
	struct vm_area_struct *vma;
	struct mutex *vma_list_mutex;
};

int rdma_user_mmap_io(struct ib_ucontext *ucontext, struct vm_area_struct *vma,
	unsigned long pfn, unsigned long size, pgprot_t prot);
#endif

#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
u64 sxe2_set_best_pagesz(u64 addr, struct ib_umem *region, u64 page_size_cap);
#endif

#ifdef HAVE_NO_GET_CONST
int _uverbs_get_const(s64 *to, const struct uverbs_attr_bundle *attrs_bundle,
				  size_t idx, s64 lower_bound, u64 upper_bound,
				  s64  *def_val);

#define uverbs_get_const(_to, _attrs_bundle, _idx)                             \
	({                                                                     \
		s64 _val;                                                      \
		int _ret = _uverbs_get_const(&_val, _attrs_bundle, _idx,       \
		type_min(typeof(*_to)),           \
		type_max(typeof(*_to)), NULL);    \
		(*_to) = _val;                                                 \
		_ret;                                                          \
	})
#endif
#endif
