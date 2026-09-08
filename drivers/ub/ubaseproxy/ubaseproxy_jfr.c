// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_jfc.h"
#include "ubaseproxy_mbx.h"
#include "ubaseproxy_jfr.h"

#define UBASEPROXY_JFR_JFCN_L_BIT 12
#define UBASEPROXY_JFR_CTX_BYTES sizeof(struct ubaseproxy_jfr_ctx)
#define UBASEPROXY_JFR_CTX_SIZE (UBASEPROXY_JFR_CTX_BYTES / sizeof(u32))

#define UBASEPROXY_JFR_LIMIT_WL_0 0
#define UBASEPROXY_JFR_LIMIT_WL_64 64
#define UBASEPROXY_JFR_LIMIT_WL_512 512
#define UBASEPROXY_JFR_LIMIT_WL_4096 4096
#define UBASEPROXY_JFR_LIMIT_WL_MASK 0x03

static u16 ubaseproxy_get_jfr_limit_wl_value(u8 limit_wl)
{
	const u16 limit_wl_map[] = {
		UBASEPROXY_JFR_LIMIT_WL_0,
		UBASEPROXY_JFR_LIMIT_WL_64,
		UBASEPROXY_JFR_LIMIT_WL_512,
		UBASEPROXY_JFR_LIMIT_WL_4096};

	return limit_wl_map[limit_wl & UBASEPROXY_JFR_LIMIT_WL_MASK];
}

static void ubaseproxy_update_jfr_ctx_res(struct ubase_proxy_req_msg *req,
					  struct ubaseproxy_jfr_key_words *jfr)
{
	struct ubaseproxy_jfr_ctx *jfr_ctx, *ctx_mask;

	jfr_ctx = (struct ubaseproxy_jfr_ctx *)req->data;
	ctx_mask = jfr_ctx + 1;
	if (ctx_mask->state == 0)
		jfr->state = jfr_ctx->state;
}

static int ubaseproxy_check_jfr_flush_done(struct ubaseproxy_dev *udev,
					   struct ubase_proxy_req_msg *req)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	struct ubaseproxy_jfr_ctx *ctx;
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox))
		return -ENOMEM;

	ubase_fill_mbx_attr(&attr, req->tag, UBASE_MB_QUERY_JFR_CONTEXT,
			    mbx_ue_id);

	ret = ubase_hw_upgrade_ctx_for_proxy(adev, &attr, mailbox);
	if (ret)
		goto out;

	ctx = (struct ubaseproxy_jfr_ctx *)mailbox->buf;
	if (ctx->ci == ctx->rqe_cnt)
		goto out;

	ret = -EBUSY;
out:
	ubase_free_cmd_mailbox(adev, mailbox);
	return ret;
}

static int ubaseproxy_check_destroy_jfr(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req,
					struct ubaseproxy_jfr_key_words *jfr)
{
	u16 jfrn = req->tag;
	int ret;

	if (jfr->state != UBASEPROXY_JFR_STATE_ERROR) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   jfr_field_state,
				   "failed to check destroy jfr(%u) ctx state value:%u.\n",
				   jfrn, jfr->state);
		return -EINVAL;
	}

	ret = ubaseproxy_check_jfr_flush_done(udev, req);
	if (ret) {
		ubaseproxy_err(udev, "failed to check jfr(%u) flush done.\n",
			       jfrn);
		return ret;
	}

	return 0;
}

static void ubaseproxy_del_jfr_res(struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				   struct ubaseproxy_jfr_key_words *jfr,
				   u16 jfrn)
{
	xa_erase(&ue_ctx_xa->jfr, jfrn);
	kfree(jfr);
}

static void ubaseproxy_destroy_jfr_res(struct ubaseproxy_dev *udev,
				       struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				       struct ubaseproxy_jfr_key_words *jfr,
				       u16 jfrn, u16 mbx_ue_id)
{
	int ret;

	ret = ubaseproxy_jfc_ref_dec(udev, ue_ctx_xa, jfrn, jfr->jfcn,
				     mbx_ue_id);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_destroy_jfc_dec,
				   "failed to decrease jfc(%u) cnt by jfr(%u) res, ret=%d.\n",
				   jfr->jfcn, jfrn, ret);
		return;
	}

	ubaseproxy_del_jfr_res(ue_ctx_xa, jfr, jfrn);
}

static int ubaseproxy_store_jfr_res(struct ubaseproxy_dev *udev,
				    struct ubase_proxy_req_msg *req,
				    struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				    struct ubaseproxy_jfr_key_words *jfr)
{
	struct ubaseproxy_jfr_ctx *jfr_ctx;
	u16 jfrn = req->tag;
	u32 jfcn;
	int ret;

	jfr_ctx = (struct ubaseproxy_jfr_ctx *)req->data;
	jfcn = jfr_ctx->jfcn_l + (jfr_ctx->jfcn_h << UBASEPROXY_JFR_JFCN_L_BIT);
	jfr->state = jfr_ctx->state;
	jfr->jfcn = jfcn;
	jfr->type = jfr_ctx->type;
	jfr->rqe_shift = jfr_ctx->rqe_shift;

	ret = xa_err(xa_store(&ue_ctx_xa->jfr, jfrn, jfr, GFP_KERNEL));
	if (ret)
		ubaseproxy_err(udev, "failed to create jfr(%u) ctx res, ret=%d.\n",
			       jfrn, ret);

	return ret;
}

static struct ubaseproxy_jfr_key_words*
ubaseproxy_create_jfr_res(struct ubaseproxy_dev *udev,
			  struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfr_key_words *jfr;
	struct ubaseproxy_jfr_ctx *jfr_ctx;
	u16 jfrn = req->tag;
	u32 jfcn;
	int ret;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfr = kzalloc(sizeof(struct ubaseproxy_jfr_key_words), GFP_KERNEL);
	if (!jfr)
		return NULL;

	ret = ubaseproxy_store_jfr_res(udev, req, ue_ctx_xa, jfr);
	if (ret) {
		kfree(jfr);
		return NULL;
	}

	jfr_ctx = (struct ubaseproxy_jfr_ctx *)req->data;
	jfcn = jfr_ctx->jfcn_l + (jfr_ctx->jfcn_h << UBASEPROXY_JFR_JFCN_L_BIT);
	ret = ubaseproxy_jfc_ref_inc(udev, ue_ctx_xa, jfrn, jfcn, mbx_ue_id);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_create_jfc_inc,
				   "failed to increase jfc(%u) cnt by jfr(%u) res, ret=%d.\n",
				   jfcn, jfrn, ret);
		ubaseproxy_del_jfr_res(ue_ctx_xa, jfr, jfrn);
		return NULL;
	}

	return jfr;
}

static void
ubaseproxy_init_jfr_create_mask(struct ubaseproxy_jfr_default *jfr_default)
{
	const u32 jfr_create_mask[] = {
		/* DW0-DW3 */
		GENMASK(1, 0), GENMASK(10, 9), 0, GENMASK(31, 22),
		/* DW4-DW7 */
		0, 0, 0, GENMASK(31, 0),
		/* DW8-DW11 */
		0, 0, 0, 0,
		/* DW12-DW15 */
		GENMASK(31, 3), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0)
	};
	struct ubaseproxy_jfr_ctx *create_mask = &jfr_default->create_mask;

	memcpy(create_mask, jfr_create_mask, UBASEPROXY_JFR_CTX_BYTES);
}

static void
ubaseproxy_init_jfr_modify_mask(struct ubaseproxy_jfr_default *jfr_default)
{
	const u32 jfr_modify_mask[] = {
		/* DW0-DW3 */
		GENMASK(31, 4), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW4-DW7 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW8-DW11 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW12-DW15 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0)
	};
	struct ubaseproxy_jfr_ctx *modify_mask = &jfr_default->modify_mask;

	memcpy(modify_mask, jfr_modify_mask, UBASEPROXY_JFR_CTX_BYTES);
}

static void
ubaseproxy_init_jfr_default_value(struct ubaseproxy_jfr_default *jfr_default)
{
	jfr_default->default_value.state = UBASEPROXY_JFR_STATE_READY;
}

int ubaseproxy_init_ue_jfr_ctx_default(struct ubaseproxy_dev *udev)
{
	struct ubaseproxy_jfr_default *jfr_default;

	jfr_default = kzalloc(sizeof(struct ubaseproxy_jfr_default),
			      GFP_KERNEL);
	if (!jfr_default)
		return -ENOMEM;

	ubaseproxy_init_jfr_create_mask(jfr_default);
	ubaseproxy_init_jfr_modify_mask(jfr_default);
	ubaseproxy_init_jfr_default_value(jfr_default);

	udev->caps.ue_default.jfr_default = jfr_default;

	return 0;
}

void ubaseproxy_uninit_ue_jfr_ctx_default(struct ubaseproxy_dev *udev)
{
	kfree(udev->caps.ue_default.jfr_default);
	udev->caps.ue_default.jfr_default = NULL;
}

static int
ubaseproxy_check_jfr_ctx_fixed_values(struct ubaseproxy_dev *udev,
				      struct ubaseproxy_jfr_ctx *ctx,
				      u16 jfrn, u16 mbx_ue_id)
{
	struct ubaseproxy_jfr_default *jfr_default;
	int ret;

	jfr_default = udev->caps.ue_default.jfr_default;
	ret = ubaseproxy_check_ctx_mask_value(udev, ctx,
					      &jfr_default->create_mask,
					      &jfr_default->default_value,
					      UBASEPROXY_JFR_CTX_SIZE);
	if (ret)
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_ctx_fixed,
				   "failed to check jfr(%u) ctx fixed values.\n",
				   jfrn);

	return ret;
}

static int
ubaseproxy_check_jfr_ctx_range_values(struct ubaseproxy_dev *udev,
				      struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				      struct ubaseproxy_jfr_ctx *ctx,
				      u16 jfrn, u16 mbx_ue_id)
{
#define UBASEPROXY_JFR_MIN_RQE_SHIFT 6
#define UBASEPROXY_JFR_MAX_RNR_TIMER 19
#define UBASEPROXY_JFR_MAX_RQE_SIZE_SHIFT 4

	u32 jfcn = ctx->jfcn_l + (ctx->jfcn_h << UBASEPROXY_JFR_JFCN_L_BIT);
	struct ubaseproxy_jfc_key_words *jfc;
	u32 rqe_depth = 1 << ctx->rqe_shift;
	u16 limit_wl_value;

	if (ctx->rqe_shift < UBASEPROXY_JFR_MIN_RQE_SHIFT ||
	    rqe_depth > udev->caps.ue_caps.jfr_depth) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_field_rqe_shift,
				   "failed to check jfr(%u) rqe shift(%u).\n",
				   jfrn, ctx->rqe_shift);
		return -EINVAL;
	}

	limit_wl_value = ubaseproxy_get_jfr_limit_wl_value(ctx->limit_wl);
	if (limit_wl_value >= rqe_depth) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_rqe_depth_limit,
				   "failed to check jfr(%u) limit wl.\n", jfrn);
		return -EINVAL;
	}

	if (ctx->rqe_size_shift > UBASEPROXY_JFR_MAX_RQE_SIZE_SHIFT) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_field_rqe_size_shift,
				   "failed to check jfr(%u) rqe size shift.\n",
				   jfrn);
		return -EINVAL;
	}

	if (ctx->rnr_timer > UBASEPROXY_JFR_MAX_RNR_TIMER) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_field_rnr_timer,
				   "failed to check jfr(%u) rnr timer.\n",
				   jfrn);
		return -EINVAL;
	}

	if (ctx->type == UBASEPROXY_JFR_TYPE_RAW_OR_NIC ||
	    ctx->type >= UBASEPROXY_JFR_TYPE_RESERVED) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_field_type,
				   "failed to check jfr(%u) type.\n", jfrn);
		return -EINVAL;
	}

	jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, jfcn);
	if (!jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_create_jfc_not_exists,
				   "failed to check jfr(%u) jfcn, jfc(%u) not exists.\n",
				   jfrn, jfcn);
		return -EINVAL;
	}

	if (ctx->cqeie != jfc->inline_en) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_field_cqeie,
				   "jfr(%u) cqeie(%u) is not equal to jfc(%u) inline_en(%u).\n",
				   jfrn, ctx->cqeie, jfcn, jfc->inline_en);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_jfr_mbx_header(struct ubaseproxy_dev *udev, u16 jfrn,
					   u16 mbx_ue_id)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;

	if (jfrn >= ue_caps->jfr_max_cnt) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_req_tag,
				   "failed to check jfr mbx header, tag = %u\n",
				   jfrn);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_create_jfr_ctx(struct ubaseproxy_dev *udev,
					   struct ubase_proxy_req_msg *req,
					   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa)
{
	struct ubaseproxy_jfr_ctx *ctx;
	u16 jfrn = req->tag;
	int ret;

	ret = ubaseproxy_check_jfr_mbx_header(udev, jfrn,
					      le16_to_cpu(req->mbx_ue_id));
	if (ret)
		return ret;

	ctx = (struct ubaseproxy_jfr_ctx *)req->data;
	ret = ubaseproxy_check_jfr_ctx_fixed_values(udev, ctx, jfrn,
						    le16_to_cpu(req->mbx_ue_id));
	if (ret)
		return ret;

	return ubaseproxy_check_jfr_ctx_range_values(udev, ue_ctx_xa, ctx, jfrn,
						     le16_to_cpu(req->mbx_ue_id));
}

static int ubaseproxy_check_jfr_ctx_mask(struct ubaseproxy_dev *udev,
					 struct ubaseproxy_jfr_ctx *ctx,
					 u16 jfrn, u16 mbx_ue_id)
{
	struct ubaseproxy_jfr_ctx *ctx_mask, *modify_mask;
	int ret;

	ctx_mask = ctx + 1;
	modify_mask = &udev->caps.ue_default.jfr_default->modify_mask;
	ret = ubaseproxy_check_ctx_mask_value(udev, ctx_mask,
					      modify_mask, modify_mask,
					      UBASEPROXY_JFR_CTX_SIZE);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_ctx_fixed,
				   "failed to check modify jfr(%u) ctx mask value.\n",
				   jfrn);
		return ret;
	}

	return 0;
}

static int ubaseproxy_check_modify_jfr_state(struct ubaseproxy_dev *udev,
					     struct ubaseproxy_jfr_ctx *ctx,
					     struct ubaseproxy_jfr_key_words *jfr,
					     u16 jfrn, u16 mbx_ue_id)
{
#define UBASEPROXY_JFR_STATE_FIELD_WIDTH 2

	struct ubaseproxy_jfr_ctx *ctx_mask;

	ctx_mask = ctx + 1;
	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->state,
					     UBASEPROXY_JFR_STATE_FIELD_WIDTH)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jfr_modify_state_ctx_mask,
				   "failed to check jfr(%u) state ctx mask.\n",
				   jfrn);
		return -EINVAL;
	}

	if (ctx_mask->state == 0 &&
	    (jfr->state != UBASEPROXY_JFR_STATE_READY ||
	     ctx->state != UBASEPROXY_JFR_STATE_ERROR)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jfr_modify_state_check,
				   "invalid jfr(%u) state modify, from %u to %u.\n",
				   jfrn, jfr->state, ctx->state);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_modify_jfr_limit_wl(struct ubaseproxy_dev *udev,
						struct ubaseproxy_jfr_ctx *ctx,
						struct ubaseproxy_jfr_key_words *jfr,
						u16 jfrn, u16 mbx_ue_id)
{
#define UBASEPROXY_JFR_LIMIT_WL_FIELD_WIDTH 2

	struct ubaseproxy_jfr_ctx *ctx_mask;
	u16 limit_wl_value;

	ctx_mask = ctx + 1;
	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->limit_wl,
					     UBASEPROXY_JFR_LIMIT_WL_FIELD_WIDTH)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jfr_modify_limit_wl_ctx_mask,
				   "failed to check jfr(%u) limit_wl ctx mask.\n",
				   jfrn);
		return -EINVAL;
	}

	limit_wl_value = ubaseproxy_get_jfr_limit_wl_value(ctx->limit_wl);
	if (ctx_mask->limit_wl == 0 && limit_wl_value >= BIT(jfr->rqe_shift)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jfr_modify_limit_wl_check,
				   "failed to check modify jfr(%u) limit wl.\n",
				   jfrn);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_modify_jfr_ctx(struct ubaseproxy_dev *udev,
					   struct ubase_proxy_req_msg *req,
					   struct ubaseproxy_jfr_key_words *jfr)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_jfr_ctx *ctx;
	u16 jfrn = req->tag;
	int ret;

	ctx = (struct ubaseproxy_jfr_ctx *)req->data;

	ret = ubaseproxy_check_jfr_ctx_mask(udev, ctx, jfrn, mbx_ue_id);
	if (ret)
		return ret;

	ret = ubaseproxy_check_modify_jfr_state(udev, ctx, jfr, jfrn,
						mbx_ue_id);
	if (ret)
		return ret;

	return ubaseproxy_check_modify_jfr_limit_wl(udev, ctx, jfr,
						    jfrn, mbx_ue_id);
}

int ubaseproxy_handle_create_jfr_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfr_key_words *jfr;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jfrn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JFR_CTX_BYTES) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_req_len,
				   "create jfr(%u) ctx_len(%u) error.\n",
				   jfrn, ctx_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfr = (struct ubaseproxy_jfr_key_words *)xa_load(&ue_ctx_xa->jfr, jfrn);
	if (jfr) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jfr_create_jfr_already_exists,
				   "created jfr(%u) already exists.\n",
				   jfrn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_create_jfr_ctx(udev, req, ue_ctx_xa);
	if (ret)
		return ret;

	jfr = ubaseproxy_create_jfr_res(udev, req);
	if (!jfr) {
		ret = -ENOMEM;
		goto out;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create jfr(%u) mbx, ret = %d.\n",
			       jfrn, ret);
		ubaseproxy_destroy_jfr_res(udev, ue_ctx_xa, jfr, jfrn,
					   mbx_ue_id);
	}

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send create jfr(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_destroy_jfr_ctx_req(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfr_key_words *jfr;
	struct ubase_ctx_result ctx_res;
	u16 jfrn = req->tag;
	int ret;

	if (req->data_len) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_req_len,
				   "destroy jfr(%u) data_len(%u) error.\n",
				   jfrn, req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfr = (struct ubaseproxy_jfr_key_words *)xa_load(&ue_ctx_xa->jfr, jfrn);
	if (!jfr) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_destroy_jfr_not_exists,
				   "destroyed jfr(%u) not exists.\n",
				   jfrn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_destroy_jfr(udev, req, jfr);
	if (ret)
		return ret;

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy jfr(%u) mbx, ret = %d.\n",
			       jfrn, ret);
	else
		ubaseproxy_destroy_jfr_res(udev, ue_ctx_xa, jfr, jfrn,
					   mbx_ue_id);

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy jfr(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_modify_jfr_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfr_key_words *jfr;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jfrn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JFR_CTX_BYTES * UBASEPROXY_CTXLEN_AND_MASK) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_req_len,
				   "modify jfr(%u) ctx_len(%u) error.\n",
				   jfrn, ctx_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfr = (struct ubaseproxy_jfr_key_words *)xa_load(&ue_ctx_xa->jfr, jfrn);
	if (!jfr) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_modify_jfr_not_exists,
				   "modified jfr(%u) not exists.\n", jfrn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_modify_jfr_ctx(udev, req, jfr);
	if (ret)
		return ret;

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send modify jfr(%u) mbx, ret = %d.\n",
			       jfrn, ret);
	else
		ubaseproxy_update_jfr_ctx_res(req, jfr);

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send modify jfr(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_query_jfr_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfr_key_words *jfr;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_ctx_result ctx_res;
	u16 jfrn = req->tag;
	int ret;

	if (req->data_len) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_req_len,
				   "query jfr(%u) data_len(%u) error.\n",
				   jfrn, req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfr = (struct ubaseproxy_jfr_key_words *)xa_load(&ue_ctx_xa->jfr, jfrn);
	if (!jfr) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfr_query_jfr_not_exists,
				   "queried jfr(%u) not exists.\n", jfrn);
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
			       "failed to send query jfr(%u) mbx, ret = %d.\n",
			       jfrn, ret);

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA,
				   ret ? 0 : UBASEPROXY_JFR_CTX_BYTES,
				   ret);
	ret =  ubaseproxy_send_resp_to_ue(udev, req, mailbox, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send query jfr(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	if (!IS_ERR_OR_NULL(mailbox))
		ubase_free_cmd_mailbox(udev->comdev.adev, mailbox);

	return ret;
}
