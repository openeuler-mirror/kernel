/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_EQ_H__
#define __UBASEPROXY_EQ_H__

#include "ubaseproxy_dev.h"

#define UBASEPROXY_EQ_STAT_VALID	1
#define UBASEPROXY_EQ_ALWAYS_ARMED	2
#define UBASEPROXY_EQ_MAX_SHIFT		14
#define UBASEPROXY_EQ_MIN_PERIOD	4
#define UBASEPROXY_EQ_MAX_PERIOD	7

struct ubaseproxy_eq_ctx {
	/* DW0 */
	u32 state : 2;
	u32 arm_st : 2;
	u32 eqe_size : 1;
	u32 rsv0 : 3;
	u32 pi : 24;

	/* DW1 */
	u32 shift : 5;
	u32 eqe_coalesce_period : 3;
	u32 ci : 24;

	/* DW2 */
	u32 eqe_coalesce_cnt : 10;
	u32 rsv1 : 2;
	u32 eqe_base_addr_l : 20;

	/* DW3 */
	u32 eqe_base_addr_h;

	/* DW4 */
	u32 eqe_token_id : 20;
	u32 rsv2 : 12;

	/* DW5 */
	u32 eqe_token_value;

	/* DW6 */
	u32 irq_num : 16;
	u32 rsv3_1 : 16;

	/* DW7 */
	u32 rsv3_2;

	/* DW8 */
	u32 eqn : 8;
	u32 eqe_cnt : 10;
	u32 rsv4 : 12;
	u32 eqe_report_timer_l : 2;

	/* DW9 */
	u32 eqe_report_timer_h;

	/* DW10 */
	u32 funid : 8;
	u32 pi_bypass : 24;

	/* DW11 */
	u32 state2 : 2;
	u32 eqe_position : 1;
	u32 rsv5_1 : 29;

	/* DW12~DW15 */
	u32 rsv5_2[4];
};

struct ubaseproxy_eq_default {
	struct ubaseproxy_eq_ctx create_mask;
	struct ubaseproxy_eq_ctx default_value;
};

struct ubaseproxy_eq_key_words {
	u16 cnt;
	u32 rsv0 : 16;
};

int ubaseproxy_handle_create_eq_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_destroy_eq_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_query_eq_ctx_req(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req);

int ubaseproxy_init_ue_eq_ctx_default(struct ubaseproxy_dev *udev);
void ubaseproxy_uninit_ue_eq_ctx_default(struct ubaseproxy_dev *udev);

int ubaseproxy_ceq_ref_inc(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa, u16 eqn,
			   u16 mbx_ue_id);
int ubaseproxy_ceq_ref_dec(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa, u16 eqn,
			   u16 mbx_ue_id);

#endif
