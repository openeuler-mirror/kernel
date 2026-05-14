/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : qos_base_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : qos data structure
 */

#ifndef QOS_BASE_CMD_H
#define QOS_BASE_CMD_H

#include "mpu_cmd_base_defs.h"

/**
 * @brief enum qos_cc_l2d parm command
 */
typedef enum tag_qos_cc_l2d_parm {
	QOS_CC_L2D_PARM_INVALID = 0,         /**< parm command invalid */
	QOS_CC_L2D_PARM_NIC_OQ_THRD,         /**< parm command nic_oq_thrd */
	QOS_CC_L2D_PARM_ROCE_OQ_THRD,        /**< parm command roce_oq_thrd */
	QOS_CC_L2D_PARM_UBOE_OQ_THRD,        /**< parm command uboe_oq_thrd */
	QOS_CC_L2D_PARM_HCT_EN,              /**< parm command hct_en */
} qos_cc_l2d_parm_e;

/**
 * @brief struct qos_cc_l2d tbl command
 */
typedef struct tag_qos_cc_l2d_tbl {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 nic_oq_thrd : 10;
			u32 nic_oq_thrd_mark : 1;
			u32 rsvd : 21;
#else
			u32 rsvd : 21;
			u32 nic_oq_thrd_mark : 1;
			u32 nic_oq_thrd : 10;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 roce_oq_thrd : 10;
			u32 roce_oq_thrd_mark : 1;
			u32 rsvd : 21;
#else
			u32 rsvd : 21;
			u32 roce_oq_thrd_mark : 1;
			u32 roce_oq_thrd : 10;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 uboe_oq_thrd : 10;
			u32 uboe_oq_thrd_mark : 1;
			u32 rsvd : 21;
#else
			u32 rsvd : 21;
			u32 uboe_oq_thrd_mark : 1;
			u32 uboe_oq_thrd : 10;
#endif
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 host_cg_tran_en : 1;
			u32 host_cg_tran_mark : 1;
			u32 rsvd : 30;
#else
			u32 rsvd : 30;
			u32 host_cg_tran_mark : 1;
			u32 host_cg_tran_en : 1;
#endif
		} bs;
		u32 value;
	} dw3;

	u32 dw_rsvd[4];
} qos_cc_l2d_tbl_s;

/* For scalability, actual pass-through size is 32B, union occupies 64B */
#define CFM_QOS_CC_L2D_DATA_LEN 64

/* L2DMEM write request */
typedef struct tag_cfm_l2dmem_req {
	struct mgmt_msg_head head;
	/* For scalability */
	union {
		u32 padding[CFM_QOS_CC_L2D_DATA_LEN];
		qos_cc_l2d_tbl_s l2d_tbl;
	} cfg;
} qos_cc_l2d_req_s;

/* L2DMEM read response */
typedef struct tag_cfm_l2dmem_rsp {
	struct mgmt_msg_head head;
	union {
		u32 padding[CFM_QOS_CC_L2D_DATA_LEN];
		qos_cc_l2d_tbl_s l2d_tbl;
	} cfg;
} qos_cc_l2d_rsp_s;

#endif /* QOS_BASE_CMD_H */
