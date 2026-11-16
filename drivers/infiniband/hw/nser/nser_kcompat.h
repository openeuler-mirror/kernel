/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2021 WangXun Corporation */
#ifndef NSER_KCOMPAT_H
#define NSER_KCOMPAT_H

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
#include <rdma/nser-abi.h>

/* Mapping nser driver ID to 100 till we are in k.org */
#define RDMA_DRIVER_NSER 100

/*******************************************************************************/

struct dst_entry *nser_get_fl6_dst(struct sockaddr_in6 *src_addr, struct sockaddr_in6 *dst_addr);
struct neighbour *nser_get_neigh_ipv6(struct dst_entry *dst, struct sockaddr_in6 *dst_ipaddr);
struct neighbour *nser_get_neigh_ipv4(struct rtable *rt, __be32 *dst_ipaddr);

struct nser_mr;
struct nser_cq;
struct nser_cq_buf;
struct nser_ucontext;

struct nser_device;
struct nser_pci_f;
struct nser_qp;

u32 nser_create_stag(struct nser_device *iwdev);
void nser_free_stag(struct nser_device *iwdev, u32 stag);
int nser_hw_alloc_mw(struct nser_device *iwdev, struct nser_mr *iwmr);
void nser_cq_free_rsrc(struct nser_pci_f *rf, struct nser_cq *iwcq);
int nser_process_resize_list(struct nser_cq *iwcq,
							 struct nser_device *iwdev,
							 struct nser_cq_buf *lcqe_buf);

#define kc_set_driver_id(x)

#define nser_for_each_ipv6_addr(ifp, tmp, idev) \
		list_for_each_entry_safe(ifp, tmp, &idev->addr_list, if_list)

void nser_get_dev_fw_str(struct ib_device *dev, char *str);

struct dst_entry *nser_get_fl6_dst(struct sockaddr_in6 *src_addr,
				    struct sockaddr_in6 *dst_addr);
struct neighbour *nser_get_neigh_ipv6(struct dst_entry *dst,
				       struct sockaddr_in6 *dst_ipaddr);
struct neighbour *nser_get_neigh_ipv4(struct rtable *rt, __be32 *dst_ipaddr);

int nser_create_ah_v2(struct ib_ah *ib_ah,
		       struct rdma_ah_attr *attr, u32 flags,
		       struct ib_udata *udata);
int nser_create_ah(struct ib_ah *ibah,
		    struct rdma_ah_init_attr *attr,
		    struct ib_udata *udata);
int nser_destroy_ah(struct ib_ah *ibah, u32 ah_flags);

int nser_create_cq(struct ib_cq *ibcq,
		    const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata);

/* functions called by nser_create_qp and nser_free_qp_rsrc */
int nser_validate_qp_attrs(struct ib_qp_init_attr *init_attr,
			    struct nser_device *iwdev);

void nser_setup_virt_qp(struct nser_device *iwdev,
			 struct nser_qp *iwqp,
			 struct nser_qp_init_info *init_info);

int nser_setup_kmode_qp(struct nser_device *iwdev,
			 struct nser_qp *iwqp,
			 struct nser_qp_init_info *info,
			 struct ib_qp_init_attr *init_attr);
int nser_setup_umode_qp(struct ib_udata *udata,
			 struct nser_device *iwdev,
			 struct nser_qp *iwqp,
			 struct nser_qp_init_info *info);

void nser_roce_fill_and_set_qpctx_info(struct nser_qp *iwqp,
					struct nser_qp_host_ctx_info *ctx_info);

int nser_cqp_create_qp_cmd(struct nser_qp *iwqp);

void nser_free_qp_rsrc(struct nser_qp *iwqp);

int nser_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata);

int nser_create_qp(struct ib_qp *ibqp,
		    struct ib_qp_init_attr *init_attr,
		    struct ib_udata *udata);

int nser_hw_alloc_stag(struct nser_device *iwdev,
			struct nser_mr *iwmr);

struct ib_mr *nser_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type, u32 max_num_sg);

int nser_add_gid(struct ib_device *device,
		  u8 port_num,
		  unsigned int index,
		  const union ib_gid *gid,
		  const struct ib_gid_attr *attr,
		  void **context);

int nser_del_gid(struct ib_device *device,
		  u8 port_num,
		  unsigned int index,
		  void **context);

int nser_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata);

int nser_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);
#define kc_nser_destroy_qp(ibqp, udata) nser_destroy_qp(ibqp, udata)

int nser_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata);

int nser_hwdereg_mr(struct ib_mr *ib_mr);

struct ib_mr *nser_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				  u64 len, u64 virt, int new_access,
				  struct ib_pd *new_pd,
				  struct ib_udata *udata);

struct ib_mr *nser_reg_user_mr_dmabuf(struct ib_pd *pd, u64 start, u64 len,
				       u64 virt, int fd, int access,
				       struct ib_udata *udata);

int nser_hwreg_mr(struct nser_device *iwdev, struct nser_mr *iwmr,
		   u16 access);

struct ib_mr *nser_rereg_mr_trans(struct nser_mr *iwmr, u64 start, u64 len,
				   u64 virt, struct ib_udata *udata);

struct nser_pbl *nser_get_pbl(unsigned long va,
				struct list_head *pbl_list);

void nser_del_memlist(struct nser_mr *iwmr,
		       struct nser_ucontext *ucontext);

void nser_unregister_rdma_device(struct ib_device *ibdev);
void nser_release_ib_devname(struct nser_device *iwdev);
char *nser_set_ib_devname(struct nser_device *iwdev);
void nser_disassociate_ucontext(struct ib_ucontext *context);
int kc_nser_set_roce_cm_info(struct nser_qp *iwqp,
			      struct ib_qp_attr *attr,
			      u16 *vlan_id);
int kc_nser_create_sysfs_file(struct ib_device *ibdev);
struct nser_device *kc_nser_get_device(struct net_device *netdev);
void kc_nser_put_device(struct nser_device *iwdev);
void kc_set_roce_uverbs_cmd_mask(struct nser_device *iwdev);
void kc_set_rdma_uverbs_cmd_mask(struct nser_device *iwdev);

int nser_query_gid_roce(struct ib_device *ibdev, u32 port, int index,
			 union ib_gid *gid);
int nser_modify_port(struct ib_device *ibdev, u32 port, int mask,
		      struct ib_port_modify *props);
int nser_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
		     u16 *pkey);
int nser_roce_port_immutable(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_immutable *immutable);
struct rdma_hw_stats *nser_alloc_hw_port_stats(struct ib_device *ibdev,
						u32 port_num);
int nser_get_hw_stats(struct ib_device *ibdev,
		       struct rdma_hw_stats *stats, u32 port_num,
		       int index);
int nser_query_gid(struct ib_device *ibdev, u32 port, int index,
		    union ib_gid *gid);
enum rdma_link_layer nser_get_link_layer(struct ib_device *ibdev,
					  u32 port_num);
int nser_query_port(struct ib_device *ibdev, u32 port,
		     struct ib_port_attr *props);
void nser_get_eth_speed_and_width(u32 link_speed, u16 *active_speed,
				   u8 *active_width);

u16 kc_rdma_get_udp_sport(u32 fl, u32 lqpn, u32 rqpn);
void nser_clean_cqes(struct nser_qp *iwqp, struct nser_cq *iwcq);

int nser_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);
void nser_dealloc_ucontext(struct ib_ucontext *context);
int nser_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
int nser_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);

#define kc_free_lsmm_dereg_mr(iwdev, iwqp) \
	((iwdev)->ibdev.ops.dereg_mr((iwqp)->lsmm_mr, NULL))

static inline int cq_validate_flags(u32 flags)
{
	/* GEN1/2 does not support CQ create flags */
	return flags ? -EOPNOTSUPP : 0;
}

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)
#define kc_set_props_ip_gid_caps(props)	((props)->ip_gids = true)
#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#define kc_rdma_udata_to_drv_context(ibpd, udata) \
		rdma_udata_to_drv_context(udata, struct nser_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct nser_ucontext, ibucontext)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)

#endif /* NSER_KCOMPAT_H_ */
