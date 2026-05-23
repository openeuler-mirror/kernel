/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : 182x_cmdq_ops.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef _182X_CMDQ_PRIVATE_H_
#define _182X_CMDQ_PRIVATE_H_

#include "ossl_knl.h"
#include "hinic5_nic_cmdq.h"

struct hinic5_qp_ctxt_header {
	u16	num_queues;
	u16	queue_type;
	u16	start_qid;
	u16	rsvd;
};

struct hinic5_clean_queue_ctxt {
	struct hinic5_qp_ctxt_header cmdq_hdr;
	u32 rsvd;
};

struct hinic5_qp_ctxt_block {
	struct hinic5_qp_ctxt_header	cmdq_hdr;
	union {
		struct hinic5_sq_ctxt	sq_ctxt[HINIC5_Q_CTXT_MAX];
		struct hinic5_rq_ctxt	rq_ctxt[HINIC5_Q_CTXT_MAX];
	};
};

struct hinic5_vlan_ctx {
	u32 func_id;
	u32 qid; /* if qid = 0xFFFF, config current function all queue */
	u32 vlan_id;
	u32 vlan_mode;
	u32 vlan_sel;
};

#endif
