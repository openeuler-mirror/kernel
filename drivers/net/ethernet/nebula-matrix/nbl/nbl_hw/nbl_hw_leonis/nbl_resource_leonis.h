/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_RESOURCE_LEONIS_H_
#define _NBL_RESOURCE_LEONIS_H_

#include "nbl_resource.h"

#define NBL_MAX_PF_LEONIS			8
/* product NO(ASIC SNIC as 3)-V NO.R NO.B NO.SP NO */
#define NBL_LEONIS_DRIVER_VERSION	"3-3.1.120"

int nbl_flow_mgt_start_leonis(struct nbl_resource_mgt *res_mgt);
void nbl_flow_mgt_stop_leonis(struct nbl_resource_mgt *res_mgt);
int nbl_flow_setup_ops_leonis(struct nbl_resource_ops *resource_ops);
void nbl_flow_remove_ops_leonis(struct nbl_resource_ops *resource_ops);
int nbl_queue_setup_ops_leonis(struct nbl_resource_ops *resource_ops);
void nbl_queue_remove_ops_leonis(struct nbl_resource_ops *resource_ops);

void nbl_queue_mgt_init_leonis(struct nbl_queue_mgt *queue_mgt);
int nbl_res_queue_setup_qid_map_table_leonis(struct nbl_resource_mgt *res_mgt, u16 func_id,
					     u64 notify_addr);
void nbl_res_queue_remove_qid_map_table_leonis(struct nbl_resource_mgt *res_mgt, u16 func_id);
int nbl_res_queue_init_qid_map_table(struct nbl_resource_mgt *res_mgt,
				     struct nbl_queue_mgt *queue_mgt, struct nbl_phy_ops *phy_ops);

void nbl_intr_mgt_init_leonis(struct nbl_resource_mgt *res_mgt);

#endif
