/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_ULP_FORMAT_H
#define ROCE_VERBS_ULP_FORMAT_H
#include "roce_verbs_cmd.h"
#include "roce_ccf_format.h"

/*******************AA*******************/
struct tag_roce_aa_master_modify_qpc {
	struct tag_roce_verbs_cmd_com com;
	u32 opt;
	u32 qid;
	u32 local_comm_id;
	u32 remote_comm_id;

	struct roce_qp_context qpc;
};

struct tag_roce_aa_slave_modify_qpc {
	struct tag_roce_verbs_cmd_com com;
	u32 gid_index;
	u32 qid;
	u32 local_comm_id;
	u32 remote_comm_id;

	struct roce_qp_context qpc;
};

struct roce_aa_set_conn_stat_inbuf {
	struct tag_roce_verbs_cmd_com com;
	u32 qid;
	u32 io_qpn[9];
};

struct roce_aa_get_master_qpn_inbuf {
	struct tag_roce_verbs_cmd_com com;
};

struct roce_aa_disconnect_inbuf {
	struct tag_roce_verbs_cmd_com com;
	u32 tid_h;
	u32 tid_l;
	u32 rsvd4;
	u32 rsvd5;
	u32 local_cmid;
	u32 remote_cmid;
	u32 remote_qpn;
};

struct roce_shard_map_entry {
	u32 volume_id;
	u32 hash_low_cnt : 8;
	u32 dd_id : 8;
	u32 lun_id : 16;

	u32 rsvd : 8;
	u32 hash_high_offset : 8;
	u32 hash_low_offset : 8;
	u32 hash_high_cnt : 8;
	u32 admin_qpn;
};

struct roce_aa_set_shard_cfg_inbuf {
	struct tag_roce_verbs_cmd_com com;
	u32 op;
	u32 entry_num;
	struct roce_shard_map_entry shard_info[64];
};

struct roce_master_qp_modify2rst_inbuf {
	struct tag_roce_verbs_cmd_com com;
};

struct tag_roce_aa_query_master_qp_bitmap {
	struct tag_roce_verbs_cmd_com com;
};

/*******************VBS*******************/
struct tag_roce_vbs_master_modify_qpc {
	struct tag_roce_verbs_cmd_com com;

	u32 opt;
	u32 sqpc_ci_record_addr_h;
	u32 sqpc_ci_record_addr_l;
	u32 rsvd;

	struct roce_qp_context qpc;
};

#endif /* ROCE_VERBS_ULP_FORMAT_H */
