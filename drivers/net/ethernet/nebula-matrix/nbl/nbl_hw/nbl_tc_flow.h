/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_TC_FLOW_H_
#define _NBL_TC_FLOW_H_

#include "nbl_resource.h"

#define NBL_FLOW_IN_PORT_TYPE_ETH			0x0
#define NBL_FLOW_IN_PORT_TYPE_LAG			0x400
#define NBL_FLOW_IN_PORT_TYPE_VSI			0x800

#define NBL_FLOW_OUT_PORT_TYPE_VSI			0x0
#define NBL_FLOW_OUT_PORT_TYPE_ETH			0x10
#define NBL_FLOW_OUT_PORT_TYPE_LAG			0x20

#define NBL_FLOW_ENCAP_VXLAN_FLAGS			(0x08000000)
#define NBL_FLOW_ENCAP_VXLAN_UDP_PORT			(4789)
#define NBL_FLOW_ENCAP_GENEVE_UDP_PORT			(6081)
#define NBL_FLOW_ENCAP_GENEVE_OVN_OPT_LEN		(8)
#define NBL_FLOW_ENCAP_GENEVE_DB_OFT			(5)

#define NBL_SAFE_THREADS_WAIT_TIME			(200)

struct nbl_profile_offload_msg {
	u16 act_assoc_tbl_id; /* for action assignment */
	u16 assoc_tbl_id; /* for key assignment */
	u16 graph_index;
	u8 profile_id;
	u8 profile_stage;
	u32 kt_index;
	u8 at_type;
	bool	pp_or_acl; /* 0 for pp and 1 for acl */
	bool	pt_cmd;
	bool	last_stage;
	bool	full_key;
	bool	avoid_tcam;
};

bool nbl_flow_is_available(struct nbl_tc_flow_mgt *tc_flow_mgt);
void nbl_flow_clean_create_destroy_cnt(struct nbl_tc_flow_mgt *tc_flow_mgt);
bool nbl_flow_is_resource_ready(struct nbl_tc_flow_mgt *tc_flow_mgt);
void nbl_flow_set_resource_init_status(struct nbl_tc_flow_mgt *tc_flow_mgt, bool status);
void nbl_flow_resource_available(struct nbl_tc_flow_mgt *tc_flow_mgt);
void nbl_flow_resource_unavailable(struct nbl_tc_flow_mgt *tc_flow_mgt);
void nbl_flow_wait_flows_free_done(struct nbl_tc_flow_mgt *tc_flow_mgt);

struct nbl_tc_flow *
nbl_tc_flow_index_lookup(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key);
int nbl_tc_flow_idx_lookup(void *priv, struct nbl_flow_index_key key);
struct nbl_tc_flow *
nbl_tc_flow_insert_index(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key);
int nbl_tc_flow_delete_index(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key);

void nbl_assign_key(u32 *kt_data, bool full, u32 offset, u16 length, u32 value);
void nbl_assign_hash_key_key(u32 *kt_data,
			     struct nbl_flow_key_info *key,
			     struct nbl_profile_msg *prf_msg,
			     struct nbl_fdir_fltr *input,
			     u32 value,
			     u16 tab_index);
int nbl_insert_flow_tab_filter(struct nbl_resource_mgt *res_mgt,
			       void *key,
			       void *node,
			       void **new_node,
			       u8 profile_id);
#endif
