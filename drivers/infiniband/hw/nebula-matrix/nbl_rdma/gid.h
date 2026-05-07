/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: lewis.liu <lewis.liu@nebula-matrix.com>
 */

#ifndef NBL_IB_GID_H
#define NBL_IB_GID_H

#include <rdma/ib_verbs.h>
#include "type.h"
#include "main.h"

/* software circumvention scheme control macro of source ip modification */
/* #define NBL_SRC_IP_MODIFY 1 */

struct nbl_src_addr_tbl {
	u16 src_addr_index;
	u16 sgid_index;
	u8 sgid[NBL_SRC_IP_SIZE];
};

struct nbl_src_addr_node {
	struct list_head list;
	struct nbl_src_addr_tbl info;
};

struct nbl_grc_add_src_addr_info_req {
	u16 function_id;
	u16 sgid_index;
	u8 sgid[16];
};

struct nbl_grc_del_src_addr_info_req {
	u16 src_addr_index;
	u16 sgid_index;
	u16 function_id;
	u8 rsv[2];
};

struct nbl_grc_get_src_addr_info_req {
	u16 function_id;
	u16 sgid_index;
};

struct nbl_grc_get_src_addr_info_resp {
	u16 src_addr_index;
	u8 rsv[2];
	u8 sgid[16];
};

struct nbl_grc_send_src_addr_info_req {
	u16 src_addr_index;
	u8 smac[6];
	u8 sip[16];
	u8 insert_vlan_ipv4_valid;
	u8 rsv[3];
};

int nbl_ib_add_gid(const struct ib_gid_attr *attr, void **context);
int nbl_ib_del_gid(const struct ib_gid_attr *attr, void **context);
int nbl_ib_query_gid(struct ib_device *ibdev, u32 port, int index,
		  union ib_gid *gid);

int nbl_get_src_addr_info(const struct nbl_device *dev, u16 gid_idx,
			  u16 *src_addr_index, u8 *src_ip);

void nbl_init_src_addr_list(struct nbl_pci_f *rf);
void nbl_del_all_src_addr_node(struct nbl_pci_f *rf);
#endif /* NBL_IB_GID_H */
