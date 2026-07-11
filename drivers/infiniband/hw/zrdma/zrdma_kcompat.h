/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef ZRDMA_KCOMPAT_H
#define ZRDMA_KCOMPAT_H

#include <linux/version.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/mii.h>
#include <linux/vmalloc.h>
#include <linux/irq.h>
#include <linux/hugetlb.h>
#include <linux/io.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_umem.h>
#include <rdma/uverbs_ioctl.h>
#include <linux/kconfig.h>
#include <net/secure_seq.h>
#include <linux/io-64-nonatomic-lo-hi.h>

#ifndef RDMA_DRIVER_ZXDH
#define RDMA_DRIVER_ZXDH 50
#endif

#ifndef IB_QP_ATTR_STANDARD_BITS
#define IB_QP_ATTR_STANDARD_BITS GENMASK(20, 0)
#endif

#ifdef USE_KMAP
#define kmap_local_page kmap
#endif

#define ZXDH_MTU_HEADER_RSV 102

#define set_max_sge(props, rf)                                                            \
	do {                                                                              \
		((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
		((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_deref_sgid_attr(sgid_attr) ((sgid_attr)->ndev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)

struct zxdh_mr;
struct zxdh_cq;
struct zxdh_cq_buf;
struct zxdh_ucontext;
u32 zxdh_create_stag(struct zxdh_device *iwdev);
void zxdh_free_stag(struct zxdh_device *iwdev, u32 stag);
int zxdh_hw_alloc_mw(struct zxdh_device *iwdev, struct zxdh_mr *iwmr);
void zxdh_cq_free_rsrc(struct zxdh_pci_f *rf, struct zxdh_cq *iwcq);
int zxdh_process_resize_list(struct zxdh_cq *iwcq, struct zxdh_device *iwdev,
			     struct zxdh_cq_buf *lcqe_buf);
int zxdh_get_eth_speed(struct ib_device *dev, struct net_device *netdev, u32 port_num, u16 *speed,
		       u8 *width);

#ifndef ether_addr_copy
#define ether_addr_copy(mac_addr, new_mac_addr) memcpy(mac_addr, new_mac_addr, ETH_ALEN)
#endif

#ifndef ether_addr_cmp
#define ether_addr_cmp(mac_addr, new_mac_addr) memcmp(mac_addr, new_mac_addr, ETH_ALEN)
#endif

#ifndef eth_zero_addr
#define eth_zero_addr(mac_addr) memset(mac_addr, 0x00, ETH_ALEN)
#endif

#define zxdh_for_each_ipv6_addr(ifp, tmp, idev) \
	list_for_each_entry_safe(ifp, tmp, &idev->addr_list, if_list)

void zxdh_get_dev_fw_str(struct ib_device *dev, char *str);

int zxdh_create_ah_v2(struct ib_ah *ib_ah, struct rdma_ah_attr *attr, u32 flags,
		      struct ib_udata *udata);
int zxdh_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *attr, struct ib_udata *udata);

int zxdh_destroy_ah(struct ib_ah *ibah, u32 ah_flags);

int zxdh_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr, struct ib_udata *udata);

/* functions called by zxdh_create_qp and zxdh_free_qp_rsrc */
int zxdh_validate_qp_attrs(struct ib_qp_init_attr *init_attr, struct zxdh_device *iwdev);

void zxdh_setup_virt_qp(struct zxdh_device *iwdev, struct zxdh_qp *iwqp,
			struct zxdh_qp_init_info *init_info);

int zxdh_setup_kmode_qp(struct zxdh_device *iwdev, struct zxdh_qp *iwqp,
			struct zxdh_qp_init_info *info, struct ib_qp_init_attr *init_attr);

void zxdh_roce_fill_and_set_qpctx_info(struct zxdh_qp *iwqp,
				       struct zxdh_qp_host_ctx_info *ctx_info);

int zxdh_cqp_create_qp_cmd(struct zxdh_qp *iwqp);

void zxdh_free_qp_rsrc(struct zxdh_qp *iwqp);

int zxdh_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata);

int zxdh_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr, struct ib_udata *udata);

int zxdh_hw_alloc_stag(struct zxdh_device *iwdev, struct zxdh_mr *iwmr);

struct ib_mr *zxdh_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type, u32 max_num_sg);

int zxdh_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);

void zxdh_dealloc_ucontext(struct ib_ucontext *context);

int zxdh_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);

int zxdh_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);

int zxdh_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata);

int zxdh_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);

int zxdh_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata);

int zxdh_hwdereg_mr(struct ib_mr *ib_mr);

struct ib_mr *zxdh_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 len, u64 virt,
				 int new_access, struct ib_pd *new_pd, struct ib_udata *udata);

int zxdh_hwreg_mr(struct zxdh_device *iwdev, struct zxdh_mr *iwmr, u16 access);

struct ib_mr *zxdh_rereg_mr_trans(struct zxdh_mr *iwmr, u64 start, u64 len, u64 virt,
				  struct ib_udata *udata);

struct zxdh_pbl *zxdh_get_pbl(unsigned long va, struct list_head *pbl_list);

void zxdh_copy_user_pgaddrs(struct zxdh_mr *iwmr, u64 *pblpar, struct zxdh_pble_info **pbleinfo,
			    enum zxdh_pble_level level, bool use_pbles, bool pble_type);

void zxdh_del_memlist(struct zxdh_mr *iwmr, struct zxdh_ucontext *ucontext);

void zxdh_unregister_rdma_device(struct ib_device *ibdev);
void zxdh_disassociate_ucontext(struct ib_ucontext *context);
int kc_zxdh_set_roce_cm_info(struct zxdh_qp *iwqp, struct ib_qp_attr *attr, u16 *vlan_id);
int kc_zxdh_create_sysfs_file(struct ib_device *ibdev);
struct zxdh_device *kc_zxdh_get_device(struct net_device *netdev);
void kc_zxdh_put_device(struct zxdh_device *iwdev);

int zxdh_query_gid_roce(struct ib_device *ibdev, u32 port, int index, union ib_gid *gid);

int zxdh_modify_port(struct ib_device *ibdev, u32 port, int mask, struct ib_port_modify *props);

int zxdh_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey);

int zxdh_roce_port_immutable(struct ib_device *ibdev, u32 port_num,
			     struct ib_port_immutable *immutable);

int zxdh_iw_port_immutable(struct ib_device *ibdev, u32 port_num,
			   struct ib_port_immutable *immutable);

struct rdma_hw_stats *zxdh_alloc_hw_port_stats(struct ib_device *ibdev, u32 port_num);

int zxdh_get_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats, u32 port_num,
		      int index);

int zxdh_process_mad(struct ib_device *ibdev, int mad_flags, u32 port_num,
		     const struct ib_wc *in_wc, const struct ib_grh *in_grh,
		     const struct ib_mad *in_mad, struct ib_mad *out_mad, size_t *out_mad_size,
		     u16 *out_mad_pkey_index);

int zxdh_query_gid(struct ib_device *ibdev, u32 port, int index, union ib_gid *gid);

int zxdh_query_qpc(struct zxdh_sc_qp *qp, struct zxdh_dma_mem *qpc_buf);
void zxdh_print_hw_qpc(__le64 *qp_ctx);

enum rdma_link_layer zxdh_get_link_layer(struct ib_device *ibdev, u32 port_num);

int zxdh_query_port(struct ib_device *ibdev, u32 port, struct ib_port_attr *props);

void zxdh_clean_cqes(struct zxdh_qp *iwqp, struct zxdh_cq *iwcq);
struct zxdh_device *zxdh_device_get_by_source_netdev(struct net_device *netdev);
#define kc_free_lsmm_dereg_mr(iwdev, iwqp) ((iwdev)->ibdev.ops.dereg_mr((iwqp)->lsmm_mr, NULL))

static inline int cq_validate_flags(u32 flags, u8 hw_rev)
{
	/* GEN1 does not support CQ create flags */
	if (hw_rev == ZXDH_GEN_1)
		return flags ? -EOPNOTSUPP : 0;

	return flags & ~IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION ? -EOPNOTSUPP : 0;
}

static inline u64 *zxdh_next_pbl_addr(u64 *pbl, struct zxdh_pble_info **pinfo, u32 *idx,
				      u32 *l2_pinfo_cnt)
{
	*idx += 1;
	if (!(*pinfo) || *idx != (*pinfo)->cnt)
		return ++pbl;
	*idx = 0;
	(*pinfo)++;
	*l2_pinfo_cnt += 1;
	return (*pinfo)->addr;
}

static inline size_t zxdh_ib_umem_num_dma_blocks(struct ib_umem *umem, unsigned long pgsz, u64 iova)
{
	return (size_t)((ALIGN(iova + umem->length, pgsz) - ALIGN_DOWN(iova, pgsz))) / pgsz;
}

int zxdh_fill_qpc(struct zxdh_sc_dev *dev, u32 qpn, struct zxdh_dma_mem *qpc_buf);
int zxdh_fill_cqc(struct zxdh_sc_dev *dev, u32 cqn, struct zxdh_dma_mem *cqc_buf);
int zxdh_fill_ceqc(struct zxdh_sc_dev *dev, u32 ceqn, struct zxdh_dma_mem *ceqc_buf);
int zxdh_fill_aeqc(struct zxdh_sc_dev *dev, struct zxdh_dma_mem *aeqc_buf);
int zxdh_fill_srqc(struct zxdh_sc_dev *dev, u32 srqn, struct zxdh_dma_mem *srqc_buf);

enum ib_mtu zxdh_mtu_int_to_enum(int mtu);

#define ZXDH_UAPI_DEF

#endif /* ZRDMA_KCOMPAT_H_ */
