/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_device_port.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_DEVICE_H
#define SXE2_DRV_DEVICE_H

#include <rdma/ib_pack.h>
#include "sxe2_drv_rdma_common.h"

#define SXE2_OK			      0
#define SXE2_MAX_USER_SPACE_VER	      1
#define SXE2_MIN_USER_SPACE_VER	      1
#define SXE2_FEATURE_FW_INFO	      0
#define SXE2_MAX_PAGES_PER_FMR	      262144
#define SXE2_MAX_QPS_PER_MGN	      16
#define SXE2_MAX_MCGS		      256
#define SXE2_PKEY_TBL_SZ	      1
#define SXE2_GID_TABLE_LEN	      32
#define SXE2_RDMA_ABI_VER	      1
#define SXE2_UCTX_IS_PF		      1
#define SXE2_UCTX_IS_VF		      0
#define SXE2_MAX_CQ_MODERATION_COUNT  0xFFFF
#define SXE2_MAX_CQ_MODERATION_PERIOD 0xFFF
#define SXE2_RDMA_FW_VER_MAJOR	      GENMASK_ULL(31, 16)
#define SXE2_RDMA_FW_VER_MINOR	      GENMASK_ULL(15, 0)
#define SXE2_CQ_USED_NUM          0
#define SXE2_MR_USED_NUM          1
#define SXE2_PD_USED_NUM          1
#define SXE2_AH_USED_NUM          1
#define SXE2_QP_USED_NUM          1

#define set_max_sge(props, rdma_func)                                          \
	do {                                                                   \
		((props)->max_send_sge =                                       \
			 (s32)(rdma_func)                                      \
				 ->ctx_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
		((props)->max_recv_sge =                                       \
			 (s32)(rdma_func)                                      \
				 ->ctx_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define ether_addr_copy(mac_addr, new_mac_addr)                                \
	memcpy(mac_addr, new_mac_addr, ETH_ALEN)

enum { SXE2_ALLOC_UCTX_MIN_HW_WQ_SIZE = 1 << 0,
};

enum sxe2_port_phys_state {
	SXE2_PORT_PHYS_STATE_SLEEP			 = 1,
	SXE2_PORT_PHYS_STATE_POLLING			 = 2,
	SXE2_PORT_PHYS_STATE_DISABLED			 = 3,
	SXE2_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	SXE2_PORT_PHYS_STATE_LINK_UP			 = 5,
	SXE2_PORT_PHYS_STATE_LINK_ERROR_RECOVERY	 = 6,
	SXE2_PORT_PHYS_STATE_PHY_TEST			 = 7,
};

struct sxe2_alloc_ucontext_req {
	__u32 rsvd32;
	__u8 userspace_ver;
	__u8 rsvd8[3];
	__aligned_u64 comp_mask;
};

struct sxe2_alloc_ucontext_resp {
	__u32 max_pds;
	__u32 max_qps;
	__u32 wq_size;
	__u8 kernel_ver;
	__u8 rsvd[3];
	__aligned_u64 feature_flags;
	__aligned_u64 db_mmap_key;
	__u32 max_hw_wq_frags;
	__u32 max_hw_read_sges;
	__u32 max_hw_inline;
	__u32 max_hw_rq_quanta;
	__u32 max_hw_wq_quanta;
	__u32 min_hw_cq_size;
	__u32 max_hw_cq_size;
	__u16 max_hw_sq_chunk;
	__u8 hw_rev;
	__u8 is_pf;
	__aligned_u64 comp_mask;
	__u16 min_hw_wq_size;
	__u32 max_db;
	__u8 rsvd3[2];
	__u8 bdf[16];
	__u32 max_hw_srq_quanta;
	__u32 max_hw_srq_wr;
};

#define offsetofend(TYPE, MEMBER)                                              \
	(offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))

#define SXE2_ALLOC_UCTX_MIN_REQ_LEN                                            \
	offsetofend(struct sxe2_alloc_ucontext_req, rsvd8)
#define SXE2_ALLOC_UCTX_MIN_RESP_LEN                                           \
	offsetofend(struct sxe2_alloc_ucontext_resp, rsvd)

 #ifdef NEED_KALLOC_UCONTEXT_V1
struct ib_ucontext *sxe2_rdma_kalloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata);
 #else
int sxe2_rdma_kalloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);
#endif
#ifdef DEVICE_OPS_V1
int sxe2_rdma_kdealloc_ucontext(struct ib_ucontext *context);
#else
void sxe2_rdma_kdealloc_ucontext(struct ib_ucontext *context);
#endif
int sxe2_rdma_kquery_device(struct ib_device *ibdev,
			    struct ib_device_attr *props,
			    struct ib_udata *udata);
#ifdef QUERY_PORT_V1
int sxe2_rdma_kquery_port(struct ib_device *ibdev, u8 port,
			  struct ib_port_attr *props);
#else
int sxe2_rdma_kquery_port(struct ib_device *ibdev, u32 port,
			  struct ib_port_attr *props);
#endif
void sxe2_rdma_kget_dev_fw_str(struct ib_device *ibdev, char *str);

#ifdef QUERY_GID_ROCE_V1
int sxe2_rdma_kquery_gid(struct ib_device *ibdev, u8 port, int index,
			 union ib_gid *gid);
#else
int sxe2_rdma_kquery_gid(struct ib_device *ibdev, u32 port, int index,
			 union ib_gid *gid);
#endif
#ifdef GET_LINK_LAYER_V1
enum rdma_link_layer sxe2_rdma_kget_link_layer(struct ib_device *ibdev,
					       u8 port_num);
#else
enum rdma_link_layer sxe2_rdma_kget_link_layer(struct ib_device *ibdev,
					       u32 port_num);
#endif
#ifdef GET_NETDEV_OP_V1
struct net_device *sxe2_rdma_kget_net_dev(struct ib_device *ibdev, u8 port_num);
#else
struct net_device *sxe2_rdma_kget_net_dev(struct ib_device *ibdev,
					  u32 port_num);
#endif
#ifdef MODIFY_PORT_V1
int sxe2_rdma_kmodify_port(struct ib_device *ibdev, u8 port, int mask,
			   struct ib_port_modify *props);
#else
int sxe2_rdma_kmodify_port(struct ib_device *ibdev, u32 port, int mask,
			   struct ib_port_modify *props);
#endif

static inline enum ib_mtu sxe2_mtu_int_to_enum(int mtu)
{
	enum ib_mtu ib_mtu;

	if (mtu >= 4096)
		ib_mtu = IB_MTU_4096;
	else if (mtu >= 2048)
		ib_mtu = IB_MTU_2048;
	else if (mtu >= 1024)
		ib_mtu = IB_MTU_1024;
	else if (mtu >= 512)
		ib_mtu = IB_MTU_512;
	else
		ib_mtu = IB_MTU_256;

	return ib_mtu;
}

static inline int sxe2_ib_mtu_enmu_to_int(enum ib_mtu mtu)
{
	switch (mtu) {
	case IB_MTU_256:
		return 256;
	case IB_MTU_512:
		return 512;
	case IB_MTU_1024:
		return 1024;
	case IB_MTU_2048:
		return 2048;
	case IB_MTU_4096:
		return 4096;
	default:
		return -1;
	}
}

static inline enum ib_mtu sxe2_iboe_get_mtu(int mtu)
{
	mtu = mtu - (IB_GRH_BYTES + IB_UDP_BYTES + IB_BTH_BYTES +
		     IB_EXT_XRC_BYTES + IB_EXT_ATOMICETH_BYTES + IB_ICRC_BYTES);

	if (mtu >= sxe2_ib_mtu_enmu_to_int(IB_MTU_4096))
		return IB_MTU_4096;
	else if (mtu >= sxe2_ib_mtu_enmu_to_int(IB_MTU_2048))
		return IB_MTU_2048;
	else if (mtu >= sxe2_ib_mtu_enmu_to_int(IB_MTU_1024))
		return IB_MTU_1024;
	else if (mtu >= sxe2_ib_mtu_enmu_to_int(IB_MTU_512))
		return IB_MTU_512;
	else
		return IB_MTU_256;
}
#ifdef ROCE_PORT_IMMUTABLE_V1
int sxe2_kget_port_immutable(struct ib_device *ibdev, u8 port_num,
			     struct ib_port_immutable *immutable);
#else
int sxe2_kget_port_immutable(struct ib_device *ibdev, u32 port_num,
				    struct ib_port_immutable *immutable);
#endif
#endif
