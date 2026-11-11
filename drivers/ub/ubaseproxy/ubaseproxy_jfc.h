/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_JFC_H__
#define __UBASEPROXY_JFC_H__

#include "ubaseproxy_dev.h"

enum ubaseproxy_jfc_state {
	UBASEPROXY_JFC_STATE_INVALID,
	UBASEPROXY_JFC_STATE_VALID,
	UBASEPROXY_JFC_STATE_ERROR,
	UBASEPROXY_JFC_STATE_RESERVE,
};

struct ubaseproxy_jfc_key_words {
	u64				cnt;
	u8				ceqn;
	u8				shift;
	u32				inline_en;
	u32				cqe_size;
};

struct ubaseproxy_jfc_ctx {
	/* DW0 */
	u32 state : 2;
	u32 arm_st : 2;
	u32 shift : 4;
	u32 cqe_size : 1;
	u32 record_db_en : 1;
	u32 jfc_type : 1;
	u32 inline_en : 1;
	u32 cqe_base_addr_l : 20;
	/* DW1 */
	u32 cqe_base_addr_h;
	/* DW2 */
	u32 queue_token_id : 20;
	u32 cq_cnt_mode : 1;
	u32 rsv0 : 2;
	u32 ceqn : 9;
	/* DW3 */
	u32 ad : 24;
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
	u32 queue_position : 1;
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
	u32 ccu_en : 1;
	u32 ccucqe_other_die : 1;
	u32 rsv6 : 13;
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

struct ubaseproxy_jfc_default {
	struct ubaseproxy_jfc_ctx	create_mask;
	struct ubaseproxy_jfc_ctx	modify_mask;
	struct ubaseproxy_jfc_ctx	default_value;
};

int ubaseproxy_jfc_ref_dec(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
			   u16 index, u32 jfcn, u16 mbx_ue_id);
int ubaseproxy_jfc_ref_inc(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
			   u16 index, u32 jfcn, u16 mbx_ue_id);
int ubaseproxy_init_ue_jfc_ctx_default(struct ubaseproxy_dev *udev);
void ubaseproxy_uninit_ue_jfc_ctx_default(struct ubaseproxy_dev *udev);
int ubaseproxy_handle_create_jfc_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_destroy_jfc_ctx_req(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_modify_jfc_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_query_jfc_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req);

#endif /* __UBASEPROXY_JFC_H__ */
