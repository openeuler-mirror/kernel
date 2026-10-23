/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright(c) 2021-2030 nbl, Inc.
 */
#ifndef _NBL_TC_MCC_LEONIS_H_
#define _NBL_TC_MCC_LEONIS_H_

#include "nbl_core.h"
#include "nbl_hw.h"
#include "nbl_resource.h"

#define NBL_TC_MCC_MAX_OFFLOAD_CNT (8)

struct nbl_tc_mcc_info {
	struct list_head node;
	u16 dport_id;
	u16 mcc_id;
	u8 port_type;
};

void nbl_tc_mcc_init(struct nbl_tc_mcc_mgt *tc_mcc_mgt, struct nbl_common_info *common);
int nbl_tc_mcc_add_leaf_node(struct nbl_tc_mcc_mgt *tc_mcc_mgt, u16 dport_id, u8 port_type);
void nbl_tc_mcc_get_list(struct nbl_tc_mcc_mgt *tc_mcc_mgt, struct list_head *tc_mcc_list);
void nbl_tc_mcc_add_hw_tbl(struct nbl_resource_mgt *res_mgt, struct nbl_tc_mcc_mgt *tc_mcc_mgt);
void nbl_tc_mcc_free_hw_tbl(struct nbl_resource_mgt *res_mgt, struct nbl_tc_mcc_mgt *tc_mcc_mgt,
			    struct list_head *tc_mcc_list);
void nbl_tc_mcc_free_list(struct nbl_tc_mcc_mgt *tc_mcc_mgt);

#endif
