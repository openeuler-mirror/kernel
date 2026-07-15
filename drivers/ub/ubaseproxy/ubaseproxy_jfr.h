/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_JFR_H__
#define __UBASEPROXY_JFR_H__

#include "ubaseproxy_dev.h"

enum ubaseproxy_jfr_state {
	UBASEPROXY_JFR_STATE_RESET,
	UBASEPROXY_JFR_STATE_READY,
	UBASEPROXY_JFR_STATE_ERROR,
	UBASEPROXY_JFR_STATE_RESERVE,
};

enum ubaseproxy_jfr_type {
	UBASEPROXY_JFR_TYPE_RAW_OR_NIC,
	UBASEPROXY_JFR_TYPE_UM,
	UBASEPROXY_JFR_TYPE_RC,
	UBASEPROXY_JFR_TYPE_RM,
	UBASEPROXY_JFR_TYPE_RESERVED,
};

struct ubaseproxy_jfr_key_words {
	enum ubaseproxy_jfr_state	state;
	enum ubaseproxy_jfr_type	type;
	u32				jfcn;
};

struct ubaseproxy_jfr_ctx {
	/* DW0 */
	u32 state : 2;
	u32 limit_wl : 2;
	u32 rqe_size_shift : 3;
	u32 token_en : 1;
	u32 rqe_shift : 4;
	u32 rnr_timer : 5;
	u32 record_db_en : 1;
	u32 rqe_token_id_l : 14;
	/* DW1 */
	u32 rqe_token_id_h : 6;
	u32 type : 3;
	u32 rsv : 2;
	u32 jfr_type : 1;
	u32 rqe_base_addr_l : 20;
	/* DW2 */
	u32 rqe_base_addr_h;
	/* DW3 */
	u32 rqe_position : 1;
	u32 pld_position : 1;
	u32 pld_token_id : 20;
	u32 rsv1 : 10;
	/* DW4 */
	u32 token_value;
	/* DW5 */
	u32 user_data_l;
	/* DW6 */
	u32 user_data_h;
	/* DW7 */
	u32 pi : 16;
	u32 ci : 16;
	/* DW8 */
	u32 idx_que_addr_l;
	/* DW9 */
	u32 idx_que_addr_h : 20;
	u32 jfcn_l : 12;
	/* DW10 */
	u32 jfcn_h : 8;
	u32 record_db_addr_l : 24;
	/* DW11 */
	u32 record_db_addr_m;
	/* DW12 */
	u32 record_db_addr_h : 2;
	u32 cqeie : 1;
	u32 cqesz : 1;
	u32 rqe_cnt : 16;
	u32 rsv2 : 12;
	/* padding */
	u32 reserved[3];
};

struct ubaseproxy_jfr_default {
	struct ubaseproxy_jfr_ctx	create_mask;
	struct ubaseproxy_jfr_ctx	modify_mask;
	struct ubaseproxy_jfr_ctx	default_value;
};

int ubaseproxy_init_ue_jfr_ctx_default(struct ubaseproxy_dev *udev);
void ubaseproxy_uninit_ue_jfr_ctx_default(struct ubaseproxy_dev *udev);
int ubaseproxy_handle_create_jfr_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_destroy_jfr_ctx_req(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_modify_jfr_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_query_jfr_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req);

#endif /* __UBASEPROXY_JFR_H__ */
