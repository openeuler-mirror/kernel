/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: lewis.liu <lewis.liu@nebula-matrix.com>
 */

#ifndef NBL_IB_GID_H
#define NBL_IB_GID_H

#include <rdma/ib_verbs.h>
#include "type.h"
#include "nbl_adapt.h"

/* used by nbl_ib_query_port for ib_core to get gid_tbl_len */
#define NBL_GID_FUNC_TABLE_LEN_V4 256 /* per func gid table len rnic400 */
#define NBL_GID_FUNC_TABLE_LEN 16 /* per func gid table len */

/*
 * the total size of SRC ADDR table for DF200 EPCU,
 * each function(pf/vf) divide equally 16 src addr tbl entry,
 * and df200 ecpu has 2 PF, the total size is 32
 */
struct nbl_src_addr_tbl_lbuf {
	u16 src_addr_index;
	u16 sgid_index;
	u8 sgid[NBL_SRC_IP_SIZE];
	struct net_device *netdev;
};

struct nbl_src_addr_node {
	struct list_head list;
	struct nbl_src_addr_tbl_lbuf info;
};

int nbl_ib_add_gid(const struct ib_gid_attr *attr, void **context);
int nbl_ib_del_gid(const struct ib_gid_attr *attr, void **context);
int nbl_ib_query_gid(struct ib_device *ibdev, u32 port, int index,
		  union ib_gid *gid);

bool nbl_gid_in_src_addr_table(const struct nbl_device *dev,
	const union ib_gid *ib_gid);
int nbl_get_src_addr_info(const struct nbl_device *dev,
	u16 gid_idx, u16 *src_addr_index, u8 *src_ip, u8 *seq_num);

#endif /* NBL_IB_GID_H */
