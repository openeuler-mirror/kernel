// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_eq.h"
#include "ubaseproxy_mbx.h"
#include "ubaseproxy_jfc.h"

#define UBASEPROXY_JFC_CTX_BYTES (sizeof(struct ubaseproxy_jfc_ctx))
#define UBASEPROXY_JFC_CTX_SIZE (UBASEPROXY_JFC_CTX_BYTES / sizeof(u32))
#define UBASEPROXY_JFC_DEPTH_SHIFT_BASE 6

int ubaseproxy_jfc_ref_dec(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
			   u16 index, u32 jfcn, u16 mbx_ue_id)
{
	struct ubaseproxy_jfc_key_words *jfc;

	jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, jfcn);
	if (!jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_ref_dec,
				   "failed to reduce jetty/jfs/jfr(%u) cnt, jfc(%u) not exists.\n",
				   index, jfcn);
		return -EINVAL;
	}
	jfc->cnt--;

	return 0;
}

int ubaseproxy_jfc_ref_inc(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
			   u16 index, u32 jfcn, u16 mbx_ue_id)
{
	struct ubaseproxy_jfc_key_words *jfc;

	jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, jfcn);
	if (!jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_ref_inc,
				   "failed to increase jetty/jfs/jfr(%u) cnt, jfc(%u) not exists.\n",
				   index, jfcn);
		return -EINVAL;
	}
	jfc->cnt++;

	return 0;
}

static void
ubaseproxy_init_jfc_create_mask(struct ubaseproxy_jfc_default *jfc_default)
{
	const u32 jfc_create_mask[] = {
		/* DW0-DW1 */
		GENMASK(1, 0) | GENMASK(8, 8) | GENMASK(10, 10), 0,
		/* DW2-DW4 */
		GENMASK(31, 21), GENMASK(31, 24), GENMASK(21, 0),
		/* DW5-DW7 */
		GENMASK(21, 0) | GENMASK(31, 25), 0, GENMASK(31, 26),
		/* DW8-DW11 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW12-DW15 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW16-DW18 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW19-DW31 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0)
	};
	struct ubaseproxy_jfc_ctx *create_mask = &jfc_default->create_mask;

	memcpy(create_mask, jfc_create_mask, UBASEPROXY_JFC_CTX_BYTES);
}

static void
ubaseproxy_init_jfc_modify_mask(struct ubaseproxy_jfc_default *jfc_default)
{
	const u32 jfc_modify_mask[] = {
		/* DW0-DW2 */
		GENMASK(1, 0) | GENMASK(31, 4), GENMASK(31, 0), GENMASK(31, 0),
		/* DW3-DW5 */
		GENMASK(31, 0), GENMASK(21, 0), GENMASK(21, 0) || GENMASK(31, 25),
		/* DW6-DW31 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0)
	};
	struct ubaseproxy_jfc_ctx *modify_mask;

	modify_mask = &jfc_default->modify_mask;
	memcpy(modify_mask, jfc_modify_mask, UBASEPROXY_JFC_CTX_BYTES);
}

static void
ubaseproxy_init_jfc_default_value(struct ubaseproxy_jfc_default *jfc_default)
{
	jfc_default->default_value.state = UBASEPROXY_JFC_STATE_VALID;
}

int ubaseproxy_init_ue_jfc_ctx_default(struct ubaseproxy_dev *udev)
{
	struct ubaseproxy_jfc_default *jfc_default;

	jfc_default = kzalloc(sizeof(struct ubaseproxy_jfc_default),
			      GFP_KERNEL);
	if (!jfc_default)
		return -ENOMEM;

	ubaseproxy_init_jfc_create_mask(jfc_default);
	ubaseproxy_init_jfc_modify_mask(jfc_default);
	ubaseproxy_init_jfc_default_value(jfc_default);

	udev->caps.ue_default.jfc_default = jfc_default;

	return 0;
}

void ubaseproxy_uninit_ue_jfc_ctx_default(struct ubaseproxy_dev *udev)
{
	kfree(udev->caps.ue_default.jfc_default);
	udev->caps.ue_default.jfc_default = NULL;
}

static int ubaseproxy_check_jfc_ctx_fixed_values(struct ubaseproxy_dev *udev,
						 struct ubaseproxy_jfc_ctx *jfc_ctx,
						 u16 jfcn, u16 mbx_ue_id)
{
	struct ubaseproxy_jfc_default *jfc_default;
	int ret;

	jfc_default = udev->caps.ue_default.jfc_default;
	ret = ubaseproxy_check_ctx_mask_value(udev, jfc_ctx,
					      &jfc_default->create_mask,
					      &jfc_default->default_value,
					      UBASEPROXY_JFC_CTX_SIZE);
	if (ret)
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_ctx_fixed,
				   "failed to check jfc(%u) ctx fixed value.\n",
				   jfcn);

	return ret;
}

static int ubaseproxy_check_jfc_ctx_range_values(struct ubaseproxy_dev *udev,
						 struct ubaseproxy_jfc_ctx *jfc_ctx,
						 u16 jfcn, u16 mbx_ue_id)
{
	u8 max;

	max = ilog2(udev->caps.ue_caps.jfc_depth) - UBASEPROXY_JFC_DEPTH_SHIFT_BASE;
	if (jfc_ctx->shift > max) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_field_shift,
				   "check jfc(%u) shift(%u) bigger than max shift(%u).\n",
				   jfcn, jfc_ctx->shift, max);
		return -ERANGE;
	}

	if (jfc_ctx->cqe_coalesce_cnt >
	    BIT(jfc_ctx->shift + UBASEPROXY_JFC_DEPTH_SHIFT_BASE)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_field_cqe_coalesce_cnt,
				   "check jfc(%u) cqe_coalesce_cnt(%u) bigger than max depth(2^%u).\n",
				   jfcn, jfc_ctx->cqe_coalesce_cnt,
				   jfc_ctx->shift);
		return -ERANGE;
	}

	return 0;
}

static int ubaseproxy_check_create_jfc_ctx(struct ubaseproxy_dev *udev,
					   struct ubase_proxy_req_msg *req,
					   u16 jfcn)
{
	struct ubaseproxy_jfc_ctx *jfc_ctx;
	int ret;

	if (jfcn >= udev->caps.ue_caps.jfc_max_cnt) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id), jfc_req_tag,
				   "check jfcn(%u) error, jfcn exceeds max count.\n",
				   jfcn);
		return -EINVAL;
	}

	jfc_ctx = (struct ubaseproxy_jfc_ctx *)req->data;
	ret = ubaseproxy_check_jfc_ctx_fixed_values(udev, jfc_ctx, jfcn,
						    le16_to_cpu(req->mbx_ue_id));
	if (ret)
		return ret;

	return ubaseproxy_check_jfc_ctx_range_values(udev, jfc_ctx, jfcn,
						     le16_to_cpu(req->mbx_ue_id));
}

static struct ubaseproxy_jfc_key_words*
ubaseproxy_create_jfc_res(struct ubaseproxy_dev *udev,
			  struct ubase_proxy_req_msg *req,
			  struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa, u16 jfcn)
{
	struct ubaseproxy_jfc_key_words *jfc;
	struct ubaseproxy_jfc_ctx *jfc_ctx;
	int ret;

	jfc = kzalloc(sizeof(struct ubaseproxy_jfc_key_words), GFP_KERNEL);
	if (!jfc)
		return NULL;

	jfc_ctx = (struct ubaseproxy_jfc_ctx *)req->data;
	jfc->inline_en = jfc_ctx->inline_en;
	jfc->shift = jfc_ctx->shift;
	jfc->cqe_size = jfc_ctx->cqe_size;
	jfc->ceqn = jfc_ctx->ceqn;

	ret = ubaseproxy_ceq_ref_inc(udev, ue_ctx_xa, jfc->ceqn,
				     le16_to_cpu(req->mbx_ue_id));
	if (ret) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   jfc_create_eq_inc,
				   "create jfc(%u) failed, eq inc err, ret = %d.\n",
				   jfcn, ret);
		kfree(jfc);
		return NULL;
	}

	ret = xa_err(xa_store(&ue_ctx_xa->jfc, jfcn, jfc, GFP_KERNEL));
	if (ret) {
		ubaseproxy_err(udev, "create jfc(%u) failed, ret=%d.\n", jfcn,
			       ret);
		kfree(jfc);
		return NULL;
	}

	return jfc;
}

static void ubaseproxy_destroy_jfc_res(struct ubaseproxy_dev *udev,
				       struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				       struct ubaseproxy_jfc_key_words *jfc,
				       u16 jfcn, u16 mbx_ue_id)
{
	int ret;

	ret = ubaseproxy_ceq_ref_dec(udev, ue_ctx_xa, jfc->ceqn, mbx_ue_id);
	if (ret)
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_destroy_eq_dec,
				   "failed dec eq cnt, jfc(%u), ret = %d.\n",
				   jfcn, ret);

	xa_erase(&ue_ctx_xa->jfc, jfcn);
	kfree(jfc);
}

static int ubaseproxy_check_modify_jfc_mask(struct ubaseproxy_dev *udev,
					    struct ubaseproxy_jfc_ctx *ctx_mask,
					    u16 jfcn, u16 mbx_ue_id)
{
#define UBASEPROXY_JFC_ARM_ST_FIELD_WIDTH 2
#define UBASEPROXY_JFC_CQE_COALESCE_CNT_FIELD_WIDTH 10
#define UBASEPROXY_JFC_CQE_COALESCE_PERIOD_FIELD_WIDTH 3

	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->arm_st,
					     UBASEPROXY_JFC_ARM_ST_FIELD_WIDTH)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_mask_arm_st,
				   "failed to check jfc(%u) arm_st ctx mask.\n",
				   jfcn);
		return -EINVAL;
	}

	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->cqe_coalesce_cnt,
					     UBASEPROXY_JFC_CQE_COALESCE_CNT_FIELD_WIDTH)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_mask_cqe_coalesce_cn,
				   "failed to check jfc(%u) cqe_coalesce_cnt ctx mask.\n",
				   jfcn);
		return -EINVAL;
	}

	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->cqe_coalesce_period,
					     UBASEPROXY_JFC_CQE_COALESCE_PERIOD_FIELD_WIDTH)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_mask_cqe_coalesce_period,
				   "failed to check jfc(%u) cqe_coalesce_period ctx mask.\n",
				   jfcn);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_modify_jfc_ctx(struct ubaseproxy_dev *udev,
					   struct ubaseproxy_jfc_ctx *jfc_ctx,
					   struct ubaseproxy_jfc_key_words *jfc,
					   u16 jfcn, u16 mbx_ue_id)
{
	struct ubaseproxy_jfc_ctx *jfc_modify_mask, *jfc_ctx_mask;
	int ret;

	jfc_modify_mask = &udev->caps.ue_default.jfc_default->modify_mask;
	jfc_ctx_mask = (struct ubaseproxy_jfc_ctx *)(jfc_ctx + 1);
	ret = ubaseproxy_check_ctx_mask_value(udev, jfc_ctx_mask,
					      jfc_modify_mask, jfc_modify_mask,
					      UBASEPROXY_JFC_CTX_SIZE);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_ctx_fixed,
				   "failed to check modify jfc(%u) ctx value.\n",
				   jfcn);
		return ret;
	}

	if (jfc_ctx_mask->cqe_coalesce_cnt == 0 &&
	    jfc_ctx->cqe_coalesce_cnt >
	    BIT(jfc->shift + UBASEPROXY_JFC_DEPTH_SHIFT_BASE)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_modify_cqe_coalesce_cnt,
				   "modify jfc(%u) cqe_coalesce_cnt(%u) more than max depth(2^%u).\n",
				   jfcn, jfc_ctx->cqe_coalesce_cnt, jfc->shift);
		return -ERANGE;
	}

	return ubaseproxy_check_modify_jfc_mask(udev, jfc_ctx_mask, jfcn,
						mbx_ue_id);
}

static int ubaseproxy_check_destroy_jfc_ctx(struct ubaseproxy_dev *udev,
					    struct ubaseproxy_jfc_key_words *jfc,
					    u16 jfcn, u16 mbx_ue_id)
{
	if (jfc->cnt) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_field_cnt,
				   "destroyed jfc(%u) has unbound jfs/jfr, unbound cnt %llu.\n",
				   jfcn, jfc->cnt);
		return -EINVAL;
	}

	return 0;
}

int ubaseproxy_handle_create_jfc_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfc_key_words *jfc;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jfcn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JFC_CTX_BYTES) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_req_len,
				   "create jfc(%u) ctx_len(%u) error.\n",
				   jfcn, ctx_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, jfcn);
	if (jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_create_jfc_already_exists,
				   "created jfc(%u) already exists.\n",
				   jfcn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_create_jfc_ctx(udev, req, jfcn);
	if (ret)
		return ret;

	jfc = ubaseproxy_create_jfc_res(udev, req, ue_ctx_xa, jfcn);
	if (!jfc) {
		ret = -ENOMEM;
		goto out;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create jfc(%u) mbx, ret = %d.\n",
			       jfcn, ret);
		ubaseproxy_destroy_jfc_res(udev, ue_ctx_xa, jfc, jfcn,
					   mbx_ue_id);
	}

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send create jfc(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_destroy_jfc_ctx_req(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfc_key_words *jfc;
	struct ubase_ctx_result ctx_res;
	u16 jfcn = req->tag;
	int ret;

	if (req->data_len) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_req_len,
				   "destroy jfc(%u) data_len(%u) error.\n",
				   jfcn, req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, jfcn);
	if (!jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_destroy_jfc_not_exists,
				   "destroyed jfc(%u) not exists.\n", jfcn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_destroy_jfc_ctx(udev, jfc, jfcn, mbx_ue_id);
	if (ret)
		return ret;

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy jfc(%u) mbx, ret = %d.\n",
			       jfcn, ret);
	else
		ubaseproxy_destroy_jfc_res(udev, ue_ctx_xa, jfc, jfcn,
					   mbx_ue_id);

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy jfc(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_modify_jfc_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfc_key_words *jfc;
	struct ubaseproxy_jfc_ctx *jfc_ctx;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jfcn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JFC_CTX_BYTES * UBASEPROXY_CTXLEN_AND_MASK) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_req_len,
				   "modify jfc(%u) ctx_len(%u) error.\n",
				   jfcn, ctx_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, jfcn);
	if (!jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_modify_jfc_not_exists,
				   "modified jfc(%u) not exists.\n", jfcn);
		return -EINVAL;
	}

	jfc_ctx = (struct ubaseproxy_jfc_ctx *)req->data;
	ret = ubaseproxy_check_modify_jfc_ctx(udev, jfc_ctx, jfc, jfcn, mbx_ue_id);
	if (ret)
		return ret;

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send modify jfc(%u) mbx, ret = %d.\n",
			       jfcn, ret);
		goto out;
	}

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send modify jfc(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_query_jfc_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfc_key_words *jfc;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_ctx_result ctx_res;
	u16 jfcn = req->tag;
	int ret;

	if (req->data_len) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_req_len,
				   "query jfc(%u) data_len(%u) error.\n",
				   jfcn, req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, jfcn);
	if (!jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfc_query_jfc_not_exists,
				   "queried jfc(%u) not exists.\n", jfcn);
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
			       "failed to send query jfc(%u) mbx, ret = %d.\n",
			       jfcn, ret);

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA,
				   ret ? 0 : UBASEPROXY_JFC_CTX_BYTES,
				   ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, mailbox, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send query jfc(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	if (!IS_ERR_OR_NULL(mailbox))
		ubase_free_cmd_mailbox(udev->comdev.adev, mailbox);

	return ret;
}
