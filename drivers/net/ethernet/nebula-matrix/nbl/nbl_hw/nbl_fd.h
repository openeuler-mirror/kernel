/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_FD_H_
#define _NBL_FD_H_

#include "nbl_resource.h"

#define NBL_FD_RULE_MAX_512				(512)
#define NBL_FD_RULE_MAX_1024				(1024)
#define NBL_FD_RULE_MAX_1536				(1536)
#define NBL_FD_RULE_MAX_DEFAULT				(NBL_FD_RULE_MAX_512)
#define NBL_FD_RULE_MAX					(NBL_FD_RULE_MAX_1536)

#define NBL_FD_TCAM_DEPTH				(512)

#define NBL_FD_IPV4_TCAM_WIDTH				(5)
#define NBL_FD_L2_IPV6_TCAM_WIDTH			(10)
#define NBL_FD_DEFAULT_MODE_DEPTH			(1)
#define NBL_FD_LITE_MODE_DEPTH				(4)
#define NBL_FD_FULL_MODE_DEPTH				(1)

#define NBL_FD_UDF_FLEX_WORD_M				GENMASK_ULL(31, 0)
#define NBL_FD_UDF_FLEX_OFFS_S				32
#define NBL_FD_UDF_FLEX_OFFS_M				GENMASK_ULL(63, NBL_FD_UDF_FLEX_OFFS_S)
#define NBL_FD_UDF_FLEX_FLTR_M				GENMASK_ULL(63, 0)

#define NBL_MIRROR_ID_ENABLE				(0x80)

union nbl_rdma_tcam_default_data_u {
	struct nbl_rdma_tcam_default_data {
		u64 dport_ad:16;
		u64 dport_ab:16;
		u64 rsv0:4;
		u64 pid:4;
	} __packed info;
	struct nbl_rdma_tcam_default_data_sport {
		u64 rsv0:16;
		u64 sport_ad:16;
		u64 rsv1:4;
		u64 pid:4;
	} __packed sport;

	u8 hash_key[5];
};

union nbl_fd_tcam_default_data_u {
	struct nbl_fd_tcam_default_data {
		u64 rsv1:36;
		u64 dport:16;
		u64 padding:8;
		u64 l4_proto:8;
		u64 l4_dport:16;
		u64 l4_sport:16;
		u64 svlan:16;
		u64 ethertype:16;
		u64 src_mac:48;
		u64 dst_mac:48;
		u64 udf:32;
		u64 dip_l:64;
		u64 dip_h:64;
		u64 sip_l:64;
		u64 sip_h:64;
		u64 pid:4;
	} __packed info;
	struct nbl_fd_tcam_default_data_draco {
		u64 rsv1:24;
		u64 dport_ad:16;
		u64 dport_ab:16;
		u64 udf:32;
		u64 dip_l:64;
		u64 dip_h:64;
		u64 sip_l:64;
		u64 sip_h:64;
		u64 l4_dport:16;
		u64 l4_sport:16;
		u64 svlan:16;
		u64 dst_mac:48;
		u64 src_mac:48;
		u64 ethertype:16;
		u64 l4_proto:8;
		u64 rsv0:4;
		u64 pid:4;
	} __packed draco;
#define NBL_FD_TCAM_DEFAULT_DATA_TAB_WIDTH (sizeof(struct nbl_fd_tcam_default_data) / sizeof(u32))
	u32 data[NBL_FD_TCAM_DEFAULT_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_fd_tcam_default_data)];
};

union nbl_fd_tcam_ipv4_data_u {
	struct nbl_fd_tcam_ipv4_data {
		u64 rsv1:12;
		u64 dport:16;
		u64 padding:8;
		u64 l4_proto:8;
		u64 l4_dport:16;
		u64 l4_sport:16;
		u64 svlan:16;
		u64 udf:32;
		u64 dip:32;
		u64 sip:32;
		u64 pid:4;
	} __packed info;
#define NBL_FD_TCAM_IPV4_DATA_TAB_WIDTH (sizeof(struct nbl_fd_tcam_ipv4_data) / sizeof(u32))
	u32 data[NBL_FD_TCAM_IPV4_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_fd_tcam_ipv4_data)];
};

union nbl_fd_tcam_l2_ipv6_data_u {
	struct nbl_fd_tcam_l2_ipv6_data {
		u64 rsv:12;
		u64 dport:16;
		u64 padding:8;
		u64 l4_proto:8;
		u64 l4_dport:16;
		u64 l4_sport:16;
		u64 svlan:16;
		u64 ehtertype:16;
		u64 udf:32;
		u32 dip[NBL_IPV6_U32LEN];
		u32 sip[NBL_IPV6_U32LEN];
		u64 pid:4;
	} __packed info;
#define NBL_FD_TCAM_L2_IPV6_DATA_TAB_WIDTH (sizeof(struct nbl_fd_tcam_l2_ipv6_data) / sizeof(u32))
	u32 data[NBL_FD_TCAM_L2_IPV6_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_fd_tcam_l2_ipv6_data)];
};

struct nbl_fd_tcam_index {
	u16 depth_index;
	u16 start_depth_index;
	u16 depth_index_max_spec;
};

struct nbl_fd_tcam_index_info {
	struct nbl_fd_tcam_index default_index[NBL_FD_DEFAULT_MODE_DEPTH];
	struct nbl_fd_tcam_index v4[NBL_FD_LITE_MODE_DEPTH];
	struct nbl_fd_tcam_index v6[NBL_FD_FULL_MODE_DEPTH];
	u8 default_cnt;
	u8 v4_cnt;
	u8 v6_cnt;
};

int nbl_fd_config_key_leonis(struct nbl_resource_mgt *res_mgt, struct nbl_flow_direct_entry *entry,
			     struct nbl_acl_tcam_param *data, struct nbl_acl_tcam_param *mask,
			     u32 *action, u16 vsi_id);
int nbl_fd_config_key_draco(struct nbl_resource_mgt *res_mgt, struct nbl_flow_direct_entry *entry,
			    struct nbl_acl_tcam_param *data, struct nbl_acl_tcam_param *mask,
			    u32 *action, u16 vsi_id);
int nbl_fd_handle_queue_update_leonis(u16 type, void *event_data, void *callback_data);
int nbl_fd_handle_queue_update_draco(u16 type, void *event_data, void *callback_data);
int nbl_fd_configure_tx_mirror_to_rdma(struct nbl_resource_mgt *res_mgt, u8 mt_id);
void nbl_fd_remove_tx_mirror_to_rdma(struct nbl_resource_mgt *res_mgt);

#endif
