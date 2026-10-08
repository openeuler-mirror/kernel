/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_FC_LEONIS_H_
#define _NBL_FC_LEONIS_H_
#include "nbl_resource.h"
#include "nbl_core.h"
#include "nbl_hw.h"

#define NBL_FLOW_STAT_HIT_SIZE 5
#define NBL_FLOW_STAT_BYTES_SIZE 6
#define NBL_SPEC_STAT_HIT_SIZE 8
#define NBL_SPEC_STAT_BYTES_SIZE 8

#define NBL_FLOW_STATS_BYTES_WIDE (0xffffffffffff)
#define NBL_FLOW_STATS_HITS_WIDE (0xffffffffff)
#define NBL_GET_FLOW_STAT_BYTES(_cur_v, _pre_v, _v) do		\
{								\
	typeof(_v) v = _v;					\
	typeof(_cur_v) cur_v = _cur_v;				\
	typeof(_pre_v) pre_v = _pre_v;				\
	if (cur_v >= pre_v)					\
		*v = cur_v - pre_v;				\
	else							\
		*v = NBL_FLOW_STATS_BYTES_WIDE - pre_v + cur_v;	\
} while (0)

#define NBL_GET_FLOW_STAT_HITS(_cur_v, _pre_v, _v) do		\
{								\
	typeof(_v) v = _v;					\
	typeof(_cur_v) cur_v = _cur_v;				\
	typeof(_pre_v) pre_v = _pre_v;				\
	if (cur_v >= pre_v)					\
		*v = cur_v - pre_v;				\
	else							\
		*v = NBL_FLOW_STATS_HITS_WIDE - pre_v + cur_v;	\
} while (0)

#define NBL_SPEC_STATS_BYTES_WIDE (0xffffffffffffffff)
#define NBL_SPEC_STATS_HITS_WIDE (0xffffffffffffffff)
#define NBL_GET_SPEC_STAT_BYTES(_cur_v, _pre_v, _v) do		\
{								\
	typeof(_v) v = _v;					\
	typeof(_cur_v) cur_v = _cur_v;				\
	typeof(_pre_v) pre_v = _pre_v;				\
	if (cur_v >= pre_v)					\
		*v = cur_v - pre_v;				\
	else							\
		*v = NBL_SPEC_STATS_BYTES_WIDE - pre_v + cur_v;	\
} while (0)

#define NBL_GET_SPEC_STAT_HITS(_cur_v, _pre_v, _v) do		\
{								\
	typeof(_v) v = _v;					\
	typeof(_cur_v) cur_v = _cur_v;				\
	typeof(_pre_v) pre_v = _pre_v;				\
	if (cur_v >= pre_v)					\
		*v = cur_v - pre_v;				\
	else							\
		*v = NBL_SPEC_STATS_HITS_WIDE - pre_v + cur_v;	\
} while (0)

#pragma pack(1)
/* CMDQ data content for ACL-FLOW ID */
struct nbl_cmd_acl_stat_flowid_addr {
	u32 addr:17;
	u32 rsv:15;
} __packed;

struct nbl_cmd_acl_stat_flowid_data {
	u8 bytes[NBL_FLOW_STAT_BYTES_SIZE];
	u8 hits[NBL_FLOW_STAT_HIT_SIZE];
	u8 rsv;

} __packed;

union nbl_cmd_acl_flowid_u {
	struct nbl_cmd_acl_flowid {
		struct nbl_cmd_acl_stat_flowid_addr all_addr[NBL_FLOW_COUNT_NUM];
		struct nbl_cmd_acl_stat_flowid_data all_data[NBL_FLOW_COUNT_NUM];
	} __packed info;
#define NBL_CMD_ACL_FLOWID_TAB_WIDTH (sizeof(struct nbl_cmd_acl_flowid) \
		/ sizeof(u32))
	u32 data[NBL_CMD_ACL_FLOWID_TAB_WIDTH];
};

/* CMDQ data content for ACL-STAT ID */
struct nbl_cmd_acl_stat_statid_addr {
	u32 addr:11;
	u32 rsv:21;
} __packed;

struct nbl_cmd_acl_stat_statid_data {
	u8 bytes[NBL_SPEC_STAT_BYTES_SIZE];
	u8 hits[NBL_SPEC_STAT_HIT_SIZE];
} __packed;

union nbl_cmd_acl_statid_u {
	struct nbl_cmd_acl_statid {
		struct nbl_cmd_acl_stat_statid_addr all_addr[NBL_FLOW_COUNT_NUM];
		struct nbl_cmd_acl_stat_statid_data all_data[NBL_FLOW_COUNT_NUM];
	} __packed info;
#define NBL_CMD_ACL_STATID_TAB_WIDTH (sizeof(struct nbl_cmd_acl_statid) \
		/ sizeof(u32))
	u32 data[NBL_CMD_ACL_STATID_TAB_WIDTH];
};

#pragma pack()

int nbl_fc_add_stats_leonis(void *priv, enum nbl_pp_fc_type fc_type, unsigned long cookie);
int nbl_fc_del_stats_leonis(void *priv, unsigned long cookie);
int nbl_fc_setup_ops_leonis(struct nbl_resource_ops *res_ops);
void nbl_fc_remove_ops_leonis(struct nbl_resource_ops *res_ops);
int nbl_fc_mgt_start_leonis(struct nbl_resource_mgt *res_mgt);
void nbl_fc_mgt_stop_leonis(struct nbl_resource_mgt *res_mgt);
#endif
