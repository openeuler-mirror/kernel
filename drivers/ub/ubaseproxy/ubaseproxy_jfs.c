// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_jfc.h"
#include "ubaseproxy_mbx.h"
#include "ubaseproxy_jfs.h"

#define UBASEPROXY_STATE_ARRAY_LEN 2

#define UBASEPROXY_JFS_MASK_OFFSET 128
#define UBASEPROXY_JETTY_CTX_BYTES sizeof(struct ubaseproxy_jetty_ctx)
#define UBASEPROXY_JETTY_CTX_SIZE (UBASEPROXY_JETTY_CTX_BYTES / sizeof(u32))

static int ubaseproxy_store_jetty_res(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req,
				      struct ubaseproxy_jetty_ctx *jetty_ctx,
				      struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				      struct ubaseproxy_jetty_key_words *jetty)
{
	u16 jettyn = req->tag;
	int ret;

	jetty->state = jetty_ctx->state;
	jetty->tx_jfcn = jetty_ctx->tx_jfcn;
	jetty->rx_jfcn = jetty_ctx->rx_jfcn;
	jetty->mode = jetty_ctx->jfs_mode;

	ret = xa_err(xa_store(&ue_ctx_xa->jetty, jettyn, jetty, GFP_KERNEL));
	if (ret)
		ubaseproxy_err(udev,
			       "failed to create jetty(%u) ctx res, ret=%d.\n",
			       jettyn, ret);

	return ret;
}

static int ubaseproxy_jfc_inc_jetty_cnt(struct ubaseproxy_dev *udev,
					struct ubaseproxy_jetty_ctx *jetty_ctx,
					struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
					u16 jettyn, u16 mbx_ue_id)
{
	u32 tx_jfcn = jetty_ctx->tx_jfcn;
	u32 rx_jfcn = jetty_ctx->rx_jfcn;
	int ret;

	ret = ubaseproxy_jfc_ref_inc(udev, ue_ctx_xa, jettyn, tx_jfcn,
				     mbx_ue_id);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_tx_jfc_ref_inc,
				   "failed to increase tx jfc(%u) cnt by jetty(%u) res, ret=%d.\n",
				   tx_jfcn, jettyn, ret);
		return ret;
	}

	if (jetty_ctx->jfs_mode == UBASEPROXY_JFS_MODE)
		return 0;

	ret = ubaseproxy_jfc_ref_inc(udev, ue_ctx_xa, jettyn, rx_jfcn,
				     mbx_ue_id);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_rx_jfc_ref_inc,
				   "failed to increase rx jfc(%u) cnt by jetty(%u) res, ret=%d.\n",
				   rx_jfcn, jettyn, ret);
		ubaseproxy_jfc_ref_dec(udev, ue_ctx_xa, jettyn, tx_jfcn,
					     mbx_ue_id);
	}

	return ret;
}

static void ubaseproxy_del_jetty_res(struct ubaseproxy_dev *udev,
				     struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				     struct ubaseproxy_jetty_key_words *jetty,
				     u16 jettyn)
{
	xa_erase(&ue_ctx_xa->jetty, jettyn);
	kfree(jetty);
}

static struct ubaseproxy_jetty_key_words*
ubaseproxy_create_jetty_res(struct ubaseproxy_dev *udev,
			    struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_key_words *jetty;
	struct ubaseproxy_jetty_ctx *jetty_ctx;
	u16 jettyn = req->tag;
	int ret;

	jetty = kzalloc(sizeof(struct ubaseproxy_jetty_key_words), GFP_KERNEL);
	if (!jetty)
		return NULL;

	jetty_ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	ret = ubaseproxy_store_jetty_res(udev, req, jetty_ctx, ue_ctx_xa,
					 jetty);
	if (ret) {
		kfree(jetty);
		return NULL;
	}

	ret = ubaseproxy_jfc_inc_jetty_cnt(udev, jetty_ctx, ue_ctx_xa, jettyn,
					   mbx_ue_id);
	if (ret) {
		ubaseproxy_del_jetty_res(udev, ue_ctx_xa, jetty, jettyn);
		return NULL;
	}

	return jetty;
}

static void
ubaseproxy_update_jetty_ctx_res(struct ubase_proxy_req_msg *req,
				struct ubaseproxy_jetty_key_words *jetty)
{
	struct ubaseproxy_jetty_ctx *jetty_ctx, *ctx_mask;
	u32 ctx_len = req->data_len;

	jetty_ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	if (ctx_len == (UBASEPROXY_JETTY_CTX_BYTES + UBASEPROXY_JFS_MASK_OFFSET))
		ctx_mask = (struct ubaseproxy_jetty_ctx *)(
			   (char *)jetty_ctx + UBASEPROXY_JFS_MASK_OFFSET);
	else
		ctx_mask = jetty_ctx + 1;

	if (ctx_mask->state == 0)
		jetty->state = jetty_ctx->state;
}

static int ubaseproxy_jfc_reduce_jetty_cnt(struct ubaseproxy_dev *udev,
					   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
					   struct ubaseproxy_jetty_key_words *jetty,
					   u16 jettyn, u16 mbx_ue_id)
{
	u32 tx_jfcn = jetty->tx_jfcn;
	u32 rx_jfcn = jetty->rx_jfcn;
	int ret;

	ret = ubaseproxy_jfc_ref_dec(udev, ue_ctx_xa, jettyn, tx_jfcn,
				     mbx_ue_id);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_reduce_tx_jfc_dec,
				   "failed to decrease tx jfc(%u) cnt by jetty(%u) res, ret=%d.\n",
				   tx_jfcn, jettyn, ret);
		return ret;
	}

	if (jetty->mode == UBASEPROXY_JFS_MODE)
		return 0;

	ret = ubaseproxy_jfc_ref_dec(udev, ue_ctx_xa, jettyn, rx_jfcn,
				     mbx_ue_id);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_reduce_rx_jfc_dec,
				   "failed to decrease rx jfc(%u) cnt by jetty(%u) res, ret=%d.\n",
				   rx_jfcn, jettyn, ret);
		ubaseproxy_jfc_ref_inc(udev, ue_ctx_xa, jettyn, tx_jfcn,
					     mbx_ue_id);
	}

	return ret;
}

static void ubaseproxy_destroy_jetty_res(struct ubaseproxy_dev *udev,
					 struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
					 struct ubaseproxy_jetty_key_words *jetty,
					 u16 jettyn, u16 mbx_ue_id)
{
	int ret;

	ret = ubaseproxy_jfc_reduce_jetty_cnt(udev, ue_ctx_xa, jetty, jettyn,
					      mbx_ue_id);
	if (ret)
		return;

	ubaseproxy_del_jetty_res(udev, ue_ctx_xa, jetty, jettyn);
}

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

	jetty = ubaseproxy_create_jetty_res(udev, req);
	if (!jetty) {
		ret = -ENOMEM;
		goto out;
	}

	ubaseproxy_fill_safety_seg(udev, req, jetty);

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create jetty(%u) mbx, ret = %d.\n",
			       jettyn, ret);
		ubaseproxy_destroy_jetty_res(udev, ue_ctx_xa, jetty, jettyn,
					     mbx_ue_id);
	}

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send create jetty(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_destroy_jfs_ctx_req(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_key_words *jetty;
	struct ubase_ctx_result ctx_res;
	u16 jettyn = req->tag;
	int ret;

	if (req->data_len)
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jetty = (struct ubaseproxy_jetty_key_words *)xa_load(&ue_ctx_xa->jetty,
							     jettyn);
	if (!jetty) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_destroy_jetty_not_exists,
				   "destroyed jetty(%u) not exists.\n",
				   jettyn);
		return -EINVAL;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy jetty(%u) mbx, ret = %d.\n",
			       jettyn, ret);
	else
		ubaseproxy_destroy_jetty_res(udev, ue_ctx_xa, jetty, jettyn,
					     mbx_ue_id);

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy jetty(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_modify_jfs_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_key_words *jetty;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jettyn = req->tag;
	int ret;

	if (ctx_len != (UBASEPROXY_JETTY_CTX_BYTES + UBASEPROXY_JFS_MASK_OFFSET) &&
	    ctx_len != (UBASEPROXY_JETTY_CTX_BYTES * UBASEPROXY_CTXLEN_AND_MASK))
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jetty = (struct ubaseproxy_jetty_key_words *)xa_load(&ue_ctx_xa->jetty,
							     jettyn);
	if (!jetty) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_modify_jetty_not_exists,
				   "modified jetty(%u) not exists.\n",
				   jettyn);
		return -EINVAL;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send modify jetty(%u) mbx, ret = %d.\n",
			       jettyn, ret);
	else
		ubaseproxy_update_jetty_ctx_res(req, jetty);

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send modify jetty(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_query_jfs_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_key_words *jetty;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_ctx_result ctx_res;
	u16 jettyn = req->tag;
	int ret;

	if (req->data_len)
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jetty = (struct ubaseproxy_jetty_key_words *)xa_load(&ue_ctx_xa->jetty,
							     jettyn);
	if (!jetty) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_query_jetty_not_exists,
				   "queried jetty(%u) not exists.\n",
				   jettyn);
		return -EINVAL;
	}

	mailbox = ubase_alloc_cmd_mailbox(udev->comdev.adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		ret = -ENOMEM;
		goto out;
	}

	ret = ubaseproxy_post_mbox(udev, req, mailbox);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send query jetty(%u) mbx, ret = %d.\n",
			       jettyn, ret);

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA,
				   ret ? 0 : UBASEPROXY_JETTY_CTX_BYTES,
				   ret);
	ret =  ubaseproxy_send_resp_to_ue(udev, req, mailbox, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send query jetty(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	if (!IS_ERR_OR_NULL(mailbox))
		ubase_free_cmd_mailbox(udev->comdev.adev, mailbox);

	return ret;
}
