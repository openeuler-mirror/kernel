// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include "ubaseproxy_mbx.h"
#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_jfs.h"
#include "ubaseproxy_rc.h"

#define UBASEPROXY_RC_CTX_BYTES sizeof(struct ubaseproxy_rc_ctx)
#define UBASEPROXY_RC_CTX_SIZE (UBASEPROXY_RC_CTX_BYTES / sizeof(u32))

static int ubaseproxy_check_rc_range_values(struct ubaseproxy_dev *udev,
					    struct ubaseproxy_rc_ctx *rc_ctx,
					    u16 mbx_ue_id)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;
	u32 rc_depth;

	rc_depth = ilog2(roundup_pow_of_two(ue_caps->rc_depth));
	if (!rc_ctx->rce_shift || rc_ctx->rce_shift > rc_depth) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, rc_field_rce_shift,
				   "failed to check rc ctx, rce_shift = %u.\n",
				   rc_ctx->rce_shift);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_rc_fixed_values(struct ubaseproxy_dev *udev,
					    struct ubaseproxy_rc_ctx *rc_ctx,
					    u16 rcn, u16 mbx_ue_id)
{
	struct ubaseproxy_rc_default *rc_default;
	int ret;

	rc_default = udev->caps.ue_default.rc_default;
	ret = ubaseproxy_check_ctx_mask_value(udev, rc_ctx,
					      &rc_default->create_mask,
					      &rc_default->default_value,
					      UBASEPROXY_RC_CTX_SIZE);
	if (ret)
		ubaseproxy_risk_rl(udev, mbx_ue_id, rc_ctx_fixed,
				   "failed to check rc(%u) ctx fixed value.\n",
				   rcn);

	return ret;
}

static int ubaseproxy_check_rc_mbx_header(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_buf *ctx_buf;

	ctx_buf = ubaseproxy_get_ue_ctx_buf(udev, mbx_ue_id);
	if (req->tag >= ctx_buf->rc.entry_cnt) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, rc_req_tag,
				   "failed to check rc mbx header, rcn = %u.\n",
				   req->tag);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_create_rc_ctx(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_rc_ctx *rc_ctx;
	int ret;

	ret = ubaseproxy_check_rc_mbx_header(udev, req);
	if (ret)
		return ret;

	rc_ctx = (struct ubaseproxy_rc_ctx *)req->data;
	ret = ubaseproxy_check_rc_range_values(udev, rc_ctx,
					       le16_to_cpu(req->mbx_ue_id));
	if (ret)
		return ret;

	return ubaseproxy_check_rc_fixed_values(udev, rc_ctx, req->tag,
						le16_to_cpu(req->mbx_ue_id));
}

static void ubaseproxy_fill_rc_ctx(struct ubaseproxy_dev *udev,
				   struct ubase_proxy_req_msg *req,
				   struct ubaseproxy_rc_key_words *rc)
{
	struct ubaseproxy_rc_ctx *ctx = (struct ubaseproxy_rc_ctx *)req->data;
	u32 token_id = udev->tid;

	ctx->rce_token_id_l = token_id & (u32)UBASEPROXY_RC_TOKEN_ID_L_MASK;
	ctx->rce_token_id_h = token_id >> UBASEPROXY_RC_TOKEN_ID_H_OFFSET;
	ctx->rce_base_addr_l = (rc->rce_dma_base_addr >> UBASEPROXY_RC_ADDR_L_OFFSET) &
			       (u32)UBASEPROXY_RC_ADDR_L_MASK;
	ctx->rce_base_addr_h = rc->rce_dma_base_addr >> UBASEPROXY_RC_ADDR_H_OFFSET;
}

static struct ubaseproxy_rc_key_words *
ubaseproxy_create_rc_res(struct ubaseproxy_dev *udev,
			 struct ubase_proxy_req_msg *req,
			 struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa, u16 rcn)
{
#define RC_QUEUE_ENTRY_SIZE 64

	struct ubaseproxy_rc_ctx *ctx = (struct ubaseproxy_rc_ctx *)req->data;
	u32 iova_size = RC_QUEUE_ENTRY_SIZE * (1 << ctx->rce_shift);
	struct auxiliary_device *adev = udev->comdev.adev;
	struct ubaseproxy_rc_key_words *rc;
	int ret;

	rc = kzalloc(sizeof(struct ubaseproxy_rc_key_words), GFP_KERNEL);
	if (!rc)
		return NULL;

	rc->state = ctx->state;
	rc->rce_size = iova_size;
	rc->rce_addr = dma_alloc_coherent(adev->dev.parent, rc->rce_size,
					  &rc->rce_dma_base_addr, GFP_KERNEL);
	if (!rc->rce_addr) {
		kfree(rc);
		return NULL;
	}

	ret = xa_err(xa_store(&ue_ctx_xa->rc, rcn, rc, GFP_KERNEL));
	if (ret) {
		ubaseproxy_err(udev, "failed to create rc(%u), ret=%d.\n",
			       rcn, ret);
		dma_free_coherent(adev->dev.parent, rc->rce_size,
				  rc->rce_addr, rc->rce_dma_base_addr);
		kfree(rc);
		return NULL;
	}

	return rc;
}

static void ubaseproxy_del_rc_res(struct ubaseproxy_dev *udev,
				  struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				  struct ubaseproxy_rc_key_words *rc,
				  u16 rcn)
{
	struct auxiliary_device *adev = udev->comdev.adev;

	xa_erase(&ue_ctx_xa->rc, rcn);
	dma_free_coherent(adev->dev.parent, rc->rce_size,
			  rc->rce_addr, rc->rce_dma_base_addr);
	kfree(rc);
}

int ubaseproxy_handle_create_rc_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_rc_key_words *rc;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 rcn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_RC_CTX_BYTES)
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, le16_to_cpu(req->mbx_ue_id));
	rc = (struct ubaseproxy_rc_key_words *)xa_load(&ue_ctx_xa->rc, rcn);
	if (rc) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   rc_create_rc_already_exists,
				   "created rc(%u) already exists.\n", rcn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_create_rc_ctx(udev, req);
	if (ret)
		return ret;

	rc = ubaseproxy_create_rc_res(udev, req, ue_ctx_xa, rcn);
	if (!rc) {
		ret = -ENOMEM;
		goto out;
	}

	ubaseproxy_fill_rc_ctx(udev, req, rc);

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create rc(%u) mbx, ret = %d.\n",
			       rcn, ret);
		ubaseproxy_del_rc_res(udev, ue_ctx_xa, rc, rcn);
	}

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UBASE, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send create rc(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_destroy_rc_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_rc_key_words *rc;
	struct ubase_ctx_result ctx_res;
	u16 rcn = req->tag;
	int ret;

	if (req->data_len)
		return -EINVAL;

	ret = ubaseproxy_check_rc_mbx_header(udev, req);
	if (ret)
		return ret;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, le16_to_cpu(req->mbx_ue_id));
	rc = (struct ubaseproxy_rc_key_words *)xa_load(&ue_ctx_xa->rc, rcn);
	if (!rc) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   rc_destroy_rc_not_exists,
				   "destroyed rc(%u) not exists.\n", rcn);
		return -EINVAL;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy rc(%u) mbx, ret = %d.\n",
			       rcn, ret);
	else
		ubaseproxy_del_rc_res(udev, ue_ctx_xa, rc, rcn);

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UBASE, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy rc(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_query_rc_ctx_req(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_rc_key_words *rc;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_ctx_result ctx_res;
	u16 rcn = req->tag;
	int ret;

	if (req->data_len)
		return -EINVAL;

	ret = ubaseproxy_check_rc_mbx_header(udev, req);
	if (ret)
		return ret;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, le16_to_cpu(req->mbx_ue_id));
	rc = (struct ubaseproxy_rc_key_words *)xa_load(&ue_ctx_xa->rc, rcn);
	if (!rc) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   rc_query_rc_not_exists,
				   "queried rc(%u) not exists.\n", rcn);
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
			       "failed to send query rc(%u) mbx, ret = %d.\n",
			       rcn, ret);

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UBASE,
				   ret ? 0 : UBASEPROXY_RC_CTX_BYTES,
				   ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, mailbox, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send query rc(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	if (!IS_ERR_OR_NULL(mailbox))
		ubase_free_cmd_mailbox(udev->comdev.adev, mailbox);

	return ret;
}

static void
ubaseproxy_init_rc_create_mask(struct ubaseproxy_rc_default *rc_default)
{
	const u32 rc_ctx_mask[] = {
		/* DW0-DW15 */
		GENMASK(7, 0) | GENMASK(19, 12), GENMASK(11, 8), 0,
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0),
		/* DW16-DW31 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW32-DW63 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
	};

	memcpy(&rc_default->create_mask, rc_ctx_mask, UBASEPROXY_RC_CTX_BYTES);
}

static void
ubaseproxy_init_rc_default_value(struct ubaseproxy_rc_default *rc_default)
{
	rc_default->default_value.state = UBASEPROXY_RC_STATE_READY;
	rc_default->default_value.type = UBASEPROXY_RC_TYPE;
	rc_default->default_value.avail_sgmt_ost = DEFAULT_AVAIL_SGMT_OST_VAL;
}

int ubaseproxy_init_ue_rc_ctx_default(struct ubaseproxy_dev *udev)
{
	struct ubaseproxy_rc_default *rc_default;

	rc_default = kzalloc(sizeof(struct ubaseproxy_rc_default), GFP_KERNEL);
	if (!rc_default)
		return -ENOMEM;

	ubaseproxy_init_rc_create_mask(rc_default);
	ubaseproxy_init_rc_default_value(rc_default);

	udev->caps.ue_default.rc_default = rc_default;

	return 0;
}

void ubaseproxy_uninit_ue_rc_ctx_default(struct ubaseproxy_dev *udev)
{
	kfree(udev->caps.ue_default.rc_default);
	udev->caps.ue_default.rc_default = NULL;
}

void ubaseproxy_erase_rc_ctx_resources(struct ubaseproxy_dev *udev,
					 struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa)
{
	struct ubaseproxy_rc_key_words *rc = NULL;
	unsigned long index = 0;

	if (!xa_empty(&ue_ctx_xa->rc)) {
		xa_for_each(&ue_ctx_xa->rc, index, rc)
			ubaseproxy_del_rc_res(udev, ue_ctx_xa, rc, index);
	}
}
