/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_FC_DRACO_H_
#define _NBL_FC_DRACO_H_

#include "nbl_resource.h"
#include "nbl_core.h"
#include "nbl_hw.h"
#include "nbl_fc.h"

#define NBL_DRACO_UDF_STAT_ID_VLD_BITS 0x1ffff

#define NBL_DRACO_FLOW_STAT_WIDTH_72_HIT_SIZE 4
#define NBL_DRACO_FLOW_STAT_WIDTH_72_BYTES_SIZE 5
#define NBL_DRACO_FLOW_STAT_WIDTH_144_HIT_SIZE 9
#define NBL_DRACO_FLOW_STAT_WIDTH_144_BYTES_SIZE 9
#define NBL_DRACO_SPEC_STAT_HIT_SIZE 8
#define NBL_DRACO_SPEC_STAT_BYTES_SIZE 8

#define NBL_GET_DELTA_VALUE(_cur_v, _pre_v, _v, _max_v) do	\
{								\
	typeof(_v) v = _v;					\
	typeof(_cur_v) cur_v = _cur_v;				\
	typeof(_pre_v) pre_v = _pre_v;				\
	if (cur_v >= pre_v)					\
		*v = cur_v - pre_v;				\
	else							\
		*v = (_max_v) - pre_v + cur_v;			\
} while (0)

#define NBL_DRACO_FLOW_STATS_WIDTH_72_BYTES_WIDE (0xffffffffff)
#define NBL_DRACO_FLOW_STATS_WIDTH_72_HITS_WIDE (0xffffffff)
#define NBL_DRACO_GET_FLOW_WIDTH_72_STAT_BYTES(_cur_v, _pre_v, _v) \
	NBL_GET_DELTA_VALUE(_cur_v, _pre_v, _v, NBL_DRACO_FLOW_STATS_WIDTH_72_BYTES_WIDE)
#define NBL_DRACO_GET_FLOW_WIDTH_72_STAT_HITS(_cur_v, _pre_v, _v) \
	NBL_GET_DELTA_VALUE(_cur_v, _pre_v, _v, NBL_DRACO_FLOW_STATS_WIDTH_72_HITS_WIDE)

#define NBL_DRACO_FLOW_STATS_WIDTH_144_BYTES_WIDE (0xffffffffffffffff)
#define NBL_DRACO_FLOW_STATS_WIDTH_144_HITS_WIDE (0xffffffffffffffff)
#define NBL_DRACO_GET_FLOW_WIDTH_144_STAT_BYTES(_cur_v, _pre_v, _v) \
	NBL_GET_DELTA_VALUE(_cur_v, _pre_v, _v, NBL_DRACO_FLOW_STATS_WIDTH_144_BYTES_WIDE)
#define NBL_DRACO_GET_FLOW_WIDTH_144_STAT_HITS(_cur_v, _pre_v, _v) \
	NBL_GET_DELTA_VALUE(_cur_v, _pre_v, _v, NBL_DRACO_FLOW_STATS_WIDTH_144_HITS_WIDE)

#define NBL_DRACO_SPEC_STATS_BYTES_WIDE (0xffffffffffffffff)
#define NBL_DRACO_SPEC_STATS_HITS_WIDE (0xffffffffffffffff)
#define NBL_DRACO_GET_SPEC_STAT_BYTES(_cur_v, _pre_v, _v) \
	NBL_GET_DELTA_VALUE(_cur_v, _pre_v, _v, NBL_DRACO_SPEC_STATS_BYTES_WIDE)
#define NBL_DRACO_GET_SPEC_STAT_HITS(_cur_v, _pre_v, _v) \
	NBL_GET_DELTA_VALUE(_cur_v, _pre_v, _v, NBL_DRACO_SPEC_STATS_HITS_WIDE)

#define NBL_DRACO_CMDQ_ACL_STAT_BASE_LEN 44

enum nbl_cmdq_acl_table {
	NBL_CMDQ_ACL_TBL_TCAM = 0,
	NBL_CMDQ_ACL_TBL_FLOW_STAT,
	NBL_CMDQ_ACL_TBL_SPEC_STAT,
	NBL_CMDQ_ACL_TBL_AT
};

enum nbl_cmdq_acl_opcode {
	NBL_CMDQ_ACL_OPCODE_SEARCH = 1,
	NBL_CMDQ_ACL_OPCODE_READ,
	NBL_CMDQ_ACL_OPCODE_WRITE,
};

enum nbl_draco_fc_cmdq_op {
	NBL_CMDQ_READ_FLOW_STAT = 0,
	NBL_CMDQ_READ_SPEC_STAT,
	NBL_CMDQ_CLEAR_FLOW_STAT,
	NBL_CMDQ_CLEAR_SPEC_STAT,
};

#pragma pack(1)

struct nbl_draco_cmd_flow_stat_addr {
	u32 addr:17;
	u32 rsv:15;
} __packed;

struct nbl_draco_cmd_flow_stat_req {
	u32 stat_num:3;
	u32 rsv:29;
	struct nbl_draco_cmd_flow_stat_addr addrs[8];
	u8 rsv1[16];
} __packed;

struct nbl_draco_cmd_flow_stat_width_72_data {
	u8 bytes[NBL_DRACO_FLOW_STAT_WIDTH_72_BYTES_SIZE];
	u8 hits[NBL_DRACO_FLOW_STAT_WIDTH_72_HIT_SIZE];
#define NBL_DRACO_FLOW_STAT_WIDTH_72_RSV_SIZE 9
	u8 rsv[NBL_DRACO_FLOW_STAT_WIDTH_72_RSV_SIZE];
} __packed;

struct nbl_draco_flow_stat_width_72_cmd_resp {
	u8 rsv[8];
	struct nbl_draco_cmd_flow_stat_width_72_data all_data[NBL_FLOW_COUNT_NUM];
} __packed;

struct nbl_draco_cmd_spec_stat_width_144_data {
	u8 bytes[NBL_DRACO_FLOW_STAT_WIDTH_144_BYTES_SIZE];
	u8 hits[NBL_DRACO_FLOW_STAT_WIDTH_144_HIT_SIZE];
} __packed;

struct nbl_draco_flow_stat_width_144_cmd_resp {
	u8 rsv[8];
	struct nbl_draco_cmd_spec_stat_width_144_data all_data[NBL_FLOW_COUNT_NUM];
} __packed;

struct nbl_draco_cmd_spec_stat_data {
	u8 bytes[NBL_DRACO_SPEC_STAT_BYTES_SIZE];
	u8 hits[NBL_DRACO_SPEC_STAT_HIT_SIZE];
} __packed;

struct nbl_draco_spec_stat_cmd_resp {
	u8 rsv[8];
	struct nbl_draco_cmd_spec_stat_data all_data[NBL_FLOW_COUNT_NUM];
} __packed;

#pragma pack()

int nbl_fc_add_stats_draco(void *priv, bool is_spec, u64 cookie,
			   u32 flow_id, u16 bind_car_id);
int nbl_fc_del_stats_draco(void *priv, bool is_spec, u64 cookie);
int nbl_fc_setup_ops_draco(struct nbl_resource_ops *res_ops);
void nbl_fc_remove_ops_draco(struct nbl_resource_ops *res_ops);
int nbl_fc_mgt_start_draco(struct nbl_resource_mgt *res_mgt);
void nbl_fc_mgt_stop_draco(struct nbl_resource_mgt *res_mgt);

#endif
