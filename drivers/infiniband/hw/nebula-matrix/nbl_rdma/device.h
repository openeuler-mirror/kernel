/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * device information module
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: Peter.Pan <peter.pan@nebula-matrix.com>
 */

#ifndef DEVICE_H
#define DEVICE_H

#include <rdma/ib_verbs.h>
#include <rdma/ib_mad.h>
#include "nbl_adapt.h"

#define EMP_FW_VERSION_NAME_MAX 7

#define NBL_RDMA_FW_MAJOR_VER 1
#define NBL_RDMA_FW_MINOR_VER 0

#define NBL_PKEY_TBL_SZ 1
#define NBL_DEFAULT_PKEY 0xFFFF

#define NBL_MAX_PAGES_PER_FMR 4096

#define NBL_PORT_BASE_LID 0 /* IB spec, the base LID of the port */
#define NBL_DEF_LID_MASK_CNT 0 /* IB spec, LID mask count for multipath support */
#define NBL_DEF_SM_LID 0 /* the LID of the SM managing this port */
#define NBL_DEF_SM_SL 0 /* the administrative SL of the SM managing this port */

#define NBL_GID_TABLE_LEN 32 /* gid table length */

#define NBL_SHADOW_HASH_SHIFT 8 /* 32 max, increase this to reduce the probability of confict */
#define NBL_SHADOW_HASH_SIZE  (1 << NBL_SHADOW_HASH_SHIFT)
#define NBL_SHADOW_HASH_MASK  0xffffffff /* width of the hash value */
#define RDMA_CORE_PORT_IBA_NBL                                                 \
	(RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP | RDMA_CORE_CAP_IB_MAD |  \
	 RDMA_CORE_CAP_IB_CM | RDMA_CORE_CAP_AF_IB | \
	 RDMA_CORE_CAP_ETH_AH)
#define NBL_MMAP_HASH_RETRY_CNT 10
#define NBL_MMAP_HASH_TBL_SIZE 6

enum {
	NBL_ROCE_VERSION_2 = 2,
	NBL_ROCE_VERSION_NONE,
};

enum {
	NBL_ROCE_L3_TYPE_IPV4 = 0,
	NBL_ROCE_L3_TYPE_IPV6 = 1,
	NBL_ROCE_L3_TYPE_NONE,
};

struct shadow_list {
	struct hlist_head head[NBL_SHADOW_HASH_SIZE];
};

struct shadow_node {
	u64 p_addr;
	void *va;
	unsigned long len;
	struct hlist_node node;
};

struct nbl_ucontext {
	struct ib_ucontext ibucontext;
	struct nbl_device *nbl_dev;
	struct rdma_user_mmap_entry *db_mmap_entry;
	struct rdma_user_mmap_entry *dwqe_mmap_entry;
	struct shadow_list shadow_head;
	struct mutex shadow_list_lock;
	struct list_head vma_list;
	struct mutex vma_list_mutex;
	bool is_lat_process;
};

int nbl_add_shadow_mmap(struct nbl_ucontext *uctx, void *va, u64 phy_addr, unsigned long len);
struct shadow_node *nbl_find_shadow_mmap(struct nbl_ucontext *uctx,
					 u64 phy_addr, unsigned long len);
int nbl_ib_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);

void nbl_ib_dealloc_ucontext(struct ib_ucontext *ibcontext);

void nbl_ib_disassociate_ucontext(struct ib_ucontext *ibctx);

void nbl_ib_get_dev_fw_str(struct ib_device *dev, char *str);
int nbl_ib_query_pkey(struct ib_device *dev, u32 port, u16 index, u16 *pkey);

int nbl_ib_get_port_immutable(struct ib_device *dev, u32 port_num,
			      struct ib_port_immutable *immutable);
enum rdma_link_layer nbl_ib_get_link_layer(struct ib_device *dev, u32 port_num);


int nbl_ib_modify_port(struct ib_device *dev, u32 port, int mask,
			struct ib_port_modify *props);

int nbl_ib_query_device(struct ib_device *dev, struct ib_device_attr *props,
			struct ib_udata *udata);
int nbl_ib_query_port(struct ib_device *dev, u32 port,
		      struct ib_port_attr *props);
struct net_device *nbl_ib_get_netdev(struct ib_device *ibdev, u32 port_num);

#endif
