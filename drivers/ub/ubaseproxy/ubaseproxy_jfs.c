// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_mbx.h"
#include "ubaseproxy_jfs.h"

#define UBASEPROXY_STATE_ARRAY_LEN 2

#define UBASEPROXY_JFS_MASK_OFFSET 128
#define UBASEPROXY_JETTY_CTX_BYTES sizeof(struct ubaseproxy_jetty_ctx)
#define UBASEPROXY_JETTY_CTX_SIZE (UBASEPROXY_JETTY_CTX_BYTES / sizeof(u32))

static void ubaseproxy_fill_safety_seg(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req,
				       struct ubaseproxy_jetty_key_words *jetty)
{
	struct ubaseproxy_jetty_ctx *ctx;
	u32 sqe_token_id;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	ctx->safety_sqe_base_addr_l = (jetty->safety_sqe_dma_addr >> UBASEPROXY_SQE_VA0_OFFSET) &
				       UBASEPROXY_SQE_VA0_VALID_BIT;
	ctx->safety_sqe_base_addr_h = (jetty->safety_sqe_dma_addr >> UBASEPROXY_SQE_VA1_OFFSET) &
				       UBASEPROXY_SQE_VA1_VALID_BIT;
	sqe_token_id = udev->tid;
	ctx->safety_sqe_tokenid_l = sqe_token_id & (u32)UBASEPROXY_SQE_TOKEN_ID_L_MASK;
	ctx->safety_sqe_tokenid_h = (sqe_token_id >> UBASEPROXY_SQE_TOKEN_ID_H_OFFSET) &
				     (u32)UBASEPROXY_SQE_TOKEN_ID_H_MASK;
}

int ubaseproxy_handle_create_jfs_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_key_words *jetty;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jettyn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JETTY_CTX_BYTES)
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jetty = (struct ubaseproxy_jetty_key_words *)xa_load(&ue_ctx_xa->jetty,
							     jettyn);
	if (jetty) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jfs_create_jetty_already_exists,
				   "created jetty(%u) already exists.\n",
				   jettyn);
		return -EINVAL;
	}

	ubaseproxy_fill_safety_seg(udev, req, jetty);

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create jetty(%u) mbx, ret = %d.\n",
			       jettyn, ret);
	}

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send create jetty(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}
