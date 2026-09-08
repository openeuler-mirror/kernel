/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_RC_H__
#define __UBASEPROXY_RC_H__

#include <linux/dma-mapping.h>

#include "ubaseproxy_dev.h"

#define UBASEPROXY_RC_TYPE 2U

#define UBASEPROXY_RC_ADDR_L_OFFSET 12U
#define UBASEPROXY_RC_ADDR_L_MASK GENMASK(19, 0)
#define UBASEPROXY_RC_ADDR_H_OFFSET 32U
#define UBASEPROXY_RC_TOKEN_ID_L_MASK GENMASK(11, 0)
#define UBASEPROXY_RC_TOKEN_ID_H_OFFSET 12U

enum ubaseproxy_rc_state {
	UBASEPROXY_RC_STATE_RESET,
	UBASEPROXY_RC_STATE_READY,
	UBASEPROXY_RC_STATE_ERROR,
	UBASEPROXY_RC_STATE_SUSPEND
};

struct ubaseproxy_rc_key_words {
	enum ubaseproxy_rc_state state;
	u32 rce_size;
	void *rce_addr;
	dma_addr_t rce_dma_base_addr;
};

struct ubaseproxy_rc_ctx {
	/* DW0 */
	u32 rsv0 : 5;
	u32 type : 3;
	u32 rce_shift : 4;
	u32 rsv1 : 4;
	u32 state : 3;
	u32 rsv2 : 1;
	u32 rce_token_id_l : 12;
	/* DW1 */
	u32 rce_token_id_h : 8;
	u32 rsv3 : 4;
	u32 rce_base_addr_l : 20;
	/* DW2 */
	u32 rce_base_addr_h;
	/* DW3~DW31 */
	u32 rsv4[28];
	u32 avail_sgmt_ost : 10;
	u32 rsv5 : 22;
	/* DW32~DW63 */
	u32 rsv6[32];
};

struct ubaseproxy_rc_default {
	struct ubaseproxy_rc_ctx create_mask;
	struct ubaseproxy_rc_ctx default_value;
};

int ubaseproxy_init_ue_rc_ctx_default(struct ubaseproxy_dev *udev);

void ubaseproxy_uninit_ue_rc_ctx_default(struct ubaseproxy_dev *udev);

int ubaseproxy_handle_create_rc_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_query_rc_ctx_req(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req);
int ubaseproxy_handle_destroy_rc_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req);
void ubaseproxy_erase_rc_ctx_resources(struct ubaseproxy_dev *udev,
					 struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa);

#endif /* __UBASEPROXY_RC_H__ */
