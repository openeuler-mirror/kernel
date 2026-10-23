/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_RESOURCE_LEONIS_H_
#define _NBL_RESOURCE_LEONIS_H_

#include "nbl_resource.h"

#define NBL_MAX_PF_LEONIS			8
/* product NO(ASIC SNIC as 3)-V NO.R NO.B NO.SP NO */
#define NBL_LEONIS_DRIVER_VERSION	"3-3.1.510.1"

int nbl_flow_mgt_start_leonis(struct nbl_resource_mgt *res_mgt);
void nbl_flow_mgt_stop_leonis(struct nbl_resource_mgt *res_mgt);
int nbl_flow_setup_ops_leonis(struct nbl_resource_ops *resource_ops);
void nbl_flow_remove_ops_leonis(struct nbl_resource_ops *resource_ops);
int nbl_tc_flow_mgt_start_leonis(struct nbl_resource_mgt *res_mgt);
void nbl_tc_flow_mgt_stop_leonis(struct nbl_resource_mgt *res_mgt);
int nbl_tc_flow_setup_ops_leonis(struct nbl_resource_ops *resource_ops);
void nbl_tc_flow_remove_ops_leonis(struct nbl_resource_ops *resource_ops);
int nbl_tc_flow_flush_flow(struct nbl_resource_mgt *res_mgt);
int nbl_flow_set_decap_set(void *priv, struct nbl_ch_prm_set_decap_set *param);
int nbl_queue_mgt_init_leonis(struct nbl_resource_mgt *res_mgt);
int nbl_res_queue_setup_qid_map_table_leonis(struct nbl_resource_mgt *res_mgt, u16 func_id,
					     u64 notify_addr);
void nbl_res_queue_remove_qid_map_table_leonis(struct nbl_resource_mgt *res_mgt, u16 func_id);
int nbl_res_queue_init_qid_map_table(struct nbl_resource_mgt *res_mgt,
				     struct nbl_queue_mgt *queue_mgt, struct nbl_phy_ops *phy_ops);
void nbl_res_queue_get_rxfh_indir_leonis(void *priv, u16 vsi_id, u32 *indir);
int nbl_res_queue_get_hash_fields_leonis(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields);
int nbl_res_queue_set_hash_fields_leonis(void *priv, u16 vsi_id, int flow_type, u64 hash_fields);
void nbl_intr_mgt_init_leonis(struct nbl_resource_mgt *res_mgt);
int nbl_res_queue_get_rss_ret_base_and_size_leonis(struct nbl_resource_mgt *res_mgt,
						   u16 vsi_id, u16 queue_num,
						   struct nbl_queue_vsi_info *vsi_info);
#endif
