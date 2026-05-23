/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : 187x_cmdq_ops.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef _187X_CMDQ_PRIVATE_H_
#define _187X_CMDQ_PRIVATE_H_

#include "ossl_knl.h"
#include "hinic5_nic_cmdq.h"

struct hinic5_qp_ctxt_header {
	u32 rsvd[2];
	u16 num_queues;
	u16 queue_type;
	u16 start_qid;
	u16 dest_func_id;
};

struct hinic5_clean_queue_ctxt {
	struct hinic5_qp_ctxt_header cmdq_hdr;
};

struct hinic5_qp_ctxt_block {
	struct hinic5_qp_ctxt_header	cmdq_hdr;
	union {
		struct hinic5_sq_ctxt	sq_ctxt[HINIC5_Q_CTXT_MAX];
		struct hinic5_rq_ctxt	rq_ctxt[HINIC5_Q_CTXT_MAX];
	};
};

struct hinic5_rss_cmd_header {
	u32 rsv[3];
	u16 rsv1;
	u16 dest_func_id;
};

/* NIC HTN CMD */
enum hinic5_htn_cmd {
	HINIC5_HTN_CMD_SQ_RQ_CONTEXT_MULTI_ST = 0x20,
	HINIC5_HTN_CMD_SQ_RQ_CONTEXT_MULTI_LD,
	HINIC5_HTN_CMD_TSO_LRO_SPACE_CLEAN,
	HINIC5_HTN_CMD_SVLAN_MODIFY,
	HINIC5_HTN_CMD_SET_RSS_INDIR_TABLE,
	HINIC5_HTN_CMD_GET_RSS_INDIR_TABLE,
};

struct hinic5_vlan_ctx {
	u32 rsv[2];
	u16 vlan_tag;
	u8 vlan_sel;
	u8 vlan_mode;
	u16 start_qid;
	u16 dest_func_id;
};

struct hinic5_car_cmd_header {
	u32 rsv[2];
	u32 op_num; /* Number of configured car_ids, minimum 1, maximum 32 */
	u16 rsv1;
	u16 index; /* Starting index of configuration, 16B unit, index must be 32B aligned */
};

struct hinic5_car_cmd_payload {
	u32 context[4]; /* Written by hardware, read by driver */
	u32 profile[4]; /* Written by driver, read by hardware */
};

#endif
