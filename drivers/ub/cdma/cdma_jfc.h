/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_JFC_H__
#define __CDMA_JFC_H__

#include "cdma_types.h"
#include "cdma_db.h"

#define CDMA_JFC_DEPTH_MIN 64
#define CDMA_JFC_DEPTH_SHIFT_BASE 6
#define CDMA_JFC_DEFAULT_CQE_SHIFT 7
#define CDMA_JFC_OTHER_CQE_SHIFT 6

#define CDMA_DB_L_OFFSET 6
#define CDMA_DB_H_OFFSET 38

#define CQE_VA_L_OFFSET 12
#define CQE_VA_H_OFFSET 32

#define CDMA_IMM_DATA_SHIFT 32

enum cdma_record_db {
	CDMA_NO_RECORD_EN,
	CDMA_RECORD_EN
};

enum cdma_jfc_state {
	CDMA_JFC_STATE_INVALID,
	CDMA_JFC_STATE_VALID,
	CDMA_JFC_STATE_ERROR
};

enum cdma_armed_jfc {
	CDMA_CTX_NO_ARMED,
	CDMA_CTX_ALWAYS_ARMED,
	CDMA_CTX_REG_NEXT_CEQE,
	CDMA_CTX_REG_NEXT_SOLICITED_CEQE
};

enum cdma_jfc_type {
	CDMA_NORMAL_JFC_TYPE,
	CDMA_RAW_JFC_TYPE
};

enum cdma_cq_cnt_mode {
	CDMA_CQE_CNT_MODE_BY_COUNT,
	CDMA_CQE_CNT_MODE_BY_CI_PI_GAP
};

struct cdma_jfc {
	struct cdma_base_jfc base;
	u32 jfcn;
	u32 ceqn;
	u32 tid;
	struct cdma_buf buf;
	struct cdma_sw_db db;
	u32 ci;
	u32 arm_sn;
	spinlock_t lock;
	refcount_t event_refcount;
	struct completion event_comp;
	u32 mode;
};

struct cdma_jfc_ctx {
	/* DW0 */
	u32 state : 2;
	u32 arm_st : 2;
	u32 shift : 4;
	u32 cqe_size : 1;
	u32 record_db_en : 1;
	u32 jfc_type : 1;
	u32 inline_en : 1;
	u32 cqe_va_l : 20;
	/* DW1 */
	u32 cqe_va_h;
	/* DW2 */
	union {
		struct {
			u32 cqe_token_id : 20;
			u32 cq_cnt_mode : 1;
			u32 rsv0 : 2;
			u32 ceqn : 9;
		} hw_ver_1;
		struct {
			u32 cqe_token_id : 20;
			u32 cq_cnt_mode : 1;
			u32 rsv0 : 3;
			u32 ceqn : 8;
		} hw_ver_0;
	};
	/* DW3 */
	u32 cqe_token_value : 24;
	u32 rsv1 : 8;
	/* DW4 */
	u32 pi : 22;
	u32 cqe_coalesce_cnt : 10;
	/* DW5 */
	u32 ci : 22;
	u32 cqe_coalesce_period : 3;
	u32 rsv2 : 7;
	/* DW6 */
	u32 record_db_addr_l;
	/* DW7 */
	u32 record_db_addr_h : 26;
	u32 rsv3 : 6;
	/* DW8 */
	u32 push_usi_en : 1;
	u32 push_cqe_en : 1;
	u32 token_en : 1;
	u32 rsv4 : 9;
	u32 tpn : 20;
	/* DW9 ~ DW12 */
	u32 rmt_eid[4];
	/* DW13 */
	u32 seid_idx : 10;
	u32 rmt_token_id : 20;
	u32 rsv5 : 2;
	/* DW14 */
	u32 remote_token_value;
	/* DW15 */
	u32 int_vector : 16;
	u32 stars_en : 1;
	u32 rsv6 : 15;
	/* DW16 */
	u32 poll : 1;
	u32 cqe_report_timer : 24;
	u32 se : 1;
	u32 arm_sn : 2;
	u32 rsv7 : 4;
	/* DW17 */
	u32 se_cqe_idx : 24;
	u32 rsv8 : 8;
	/* DW18 */
	u32 wr_cqe_idx : 22;
	u32 rsv9 : 10;
	/* DW19 */
	u32 cqe_cnt : 24;
	u32 rsv10 : 8;
	/* DW20 ~ DW31 */
	u32 rsv11[12];
};

struct cdma_jfc_cqe {
	/* DW0 */
	u32 s_r : 1;
	u32 is_jetty : 1;
	u32 owner : 1;
	u32 inline_en : 1;
	u32 opcode : 3;
	u32 fd : 1;
	u32 rsv : 8;
	u32 substatus : 8;
	u32 status : 8;
	/* DW1 */
	u32 entry_idx : 16;
	u32 local_num_l : 16;
	/* DW2 */
	u32 local_num_h : 4;
	u32 rmt_idx : 20;
	u32 rsv1 : 8;
	/* DW3 */
	u32 tpn : 24;
	u32 rsv2 : 8;
	/* DW4 */
	u32 byte_cnt;
	/* DW5 ~ DW6 */
	u32 user_data_l;
	u32 user_data_h;
	/* DW7 ~ DW10 */
	u32 rmt_eid[4];
	/* DW11 ~ DW12 */
	u32 data_l;
	u32 data_h;
	/* DW13 ~ DW15 */
	u32 inline_data[3];
};

static inline struct cdma_jfc *to_cdma_jfc(struct cdma_base_jfc *base_jfc)
{
	return container_of(base_jfc, struct cdma_jfc, base);
}

struct cdma_base_jfc *cdma_create_jfc(struct cdma_dev *cdev,
				      struct cdma_jfc_cfg *cfg,
				      struct cdma_udata *udata);

int cdma_delete_jfc(struct cdma_dev *cdev, u32 jfcn,
		    struct cdma_cmd_delete_jfc_args *arg);

int cdma_jfc_completion(struct notifier_block *nb, unsigned long jfcn,
			void *data);

int cdma_poll_jfc(struct cdma_base_jfc *base_jfc, int cr_cnt,
		  struct dma_cr *cr);

#endif /* __CDMA_JFC_H__ */
