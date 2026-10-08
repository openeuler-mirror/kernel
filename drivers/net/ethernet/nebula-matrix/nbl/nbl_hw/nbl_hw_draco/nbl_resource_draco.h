/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_RESOURCE_DRACO_H_
#define _NBL_RESOURCE_DRACO_H_

#include "nbl_resource.h"

/* product NO(ASIC SNIC v2 as 4)-V NO.R NO.B NO.SP NO */
#define NBL_DRACO_DRIVER_VERSION		"4-3.1.105.1"

#define NBL_PF_NUM_DRACO			(4)
#define NBL_MAX_PF_DRACO			(8)
#define NBL_TWO_ETHERNET_VSI_ID_GAP_DRACO	(128)
#define NBL_FOUR_ETHERNET_VSI_ID_GAP_DRACO	(64)
#define NBL_RES_RDMA_PF_INTR_NUM		(16)
#define NBL_RES_RDMA_VF_INTR_NUM		(3)
/* PF data/user/xdp vsi support 128 rss member */
#define NBL_PF_RSS_BIG_SIZE_VSI_NUM		(3)
/* VSI 12-275 only support 32 rss member */
#define NBL_VSI_RSS_SIZE_COMMON_BASE_ID		(12)
/* PF_CTRL_VSI_NUM + PF_EXTRA_VSI_NUM = 8 */
#define NBL_VSI_VF_BASE_ID			(NBL_VSI_RSS_SIZE_COMMON_BASE_ID + 8)

int nbl_flow_mgt_start_draco(struct nbl_resource_mgt *res_mgt);
void nbl_flow_mgt_stop_draco(struct nbl_resource_mgt *res_mgt);
int nbl_flow_setup_ops_draco(struct nbl_resource_ops *resource_ops);
void nbl_flow_remove_ops_draco(struct nbl_resource_ops *resource_ops);

int nbl_queue_mgt_init_draco(struct nbl_resource_mgt *res_mgt);
int nbl_res_queue_init_epro_vpt_extra(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
int nbl_res_queue_setup_qid_map_table_draco(struct nbl_resource_mgt *res_mgt, u16 func_id,
					    u64 notify_addr);
int nbl_res_queue_get_rss_ret_base_and_size_draco(struct nbl_resource_mgt *res_mgt,
						  u16 vsi_id, u16 queue_num,
						  struct nbl_queue_vsi_info *vsi_info);
void nbl_res_queue_get_rxfh_indir_draco(void *priv, u16 vsi_id, u32 *indir);
int nbl_res_queue_get_hash_fields_draco(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields);
int nbl_res_queue_set_hash_fields_draco(void *priv, u16 vsi_id, int flow_type, u64 hash_fields);

void nbl_intr_mgt_init_draco(struct nbl_resource_mgt *res_mgt);

int nbl_tc_flow_setup_ops_draco(struct nbl_resource_ops *res_ops);
void nbl_tc_flow_remove_ops_draco(struct nbl_resource_ops *res_ops);

#endif
