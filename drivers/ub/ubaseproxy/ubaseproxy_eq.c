// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_jfc.h"
#include "ubaseproxy_mbx.h"
#include "ubaseproxy_eq.h"

#define UBASEPROXY_EQ_CTX_BYTES (sizeof(struct ubaseproxy_eq_ctx))
#define UBASEPROXY_EQ_CTX_SIZE (UBASEPROXY_EQ_CTX_BYTES / sizeof(u32))

static int ubaseproxy_check_eq_mbx_header(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;
	u8 eq_vector_num;

	eq_vector_num = req->opcode == UBASE_MB_CREATE_AEQ_CONTEXT ?
				       ue_caps->aeq_vector_num :
				       ue_caps->ceq_vector_num;
	if (req->tag >= eq_vector_num) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   eq_req_tag,
				   "failed to check eq mbx header, tag = %u.\n",
				   req->tag);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_eq_ctx_range_values(struct ubaseproxy_dev *udev,
						struct ubase_proxy_req_msg *req)
{
#define UBASEPROXY_EQ_DEPTH_SHIFT_BASE	6

	struct ubaseproxy_eq_ctx *ctx = (struct ubaseproxy_eq_ctx *)req->data;
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;
	u8 eq_vector_num;
	u32 eqe_depth;

	if (ctx->shift > UBASEPROXY_EQ_MAX_SHIFT) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   eq_field_shift,
				   "Invalid shift: %u (max: %u).\n",
				   ctx->shift, UBASEPROXY_EQ_MAX_SHIFT);
		return -EINVAL;
	}

	if (ctx->eqe_coalesce_period < UBASEPROXY_EQ_MIN_PERIOD ||
	    ctx->eqe_coalesce_period > UBASEPROXY_EQ_MAX_PERIOD) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   eq_field_eqe_coalesce_period,
				   "Invalid coalesce period: %u (range: %u-%u).\n",
				   ctx->eqe_coalesce_period, UBASEPROXY_EQ_MIN_PERIOD,
				   UBASEPROXY_EQ_MAX_PERIOD);
		return -EINVAL;
	}

	eqe_depth = BIT(ctx->shift + UBASEPROXY_EQ_DEPTH_SHIFT_BASE);
	if (ctx->eqe_coalesce_cnt > eqe_depth) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   eq_field_eqe_coalesce_cnt,
				   "check eqn(%u) eqe_coalesce_cnt(%u) bigger than eqe_depth(%u).\n",
				   ctx->eqn, ctx->eqe_coalesce_cnt, eqe_depth);
		return -EINVAL;
	}

	eq_vector_num = req->opcode == UBASE_MB_CREATE_AEQ_CONTEXT ?
				       ue_caps->aeq_vector_num :
				       ue_caps->ceq_vector_num;
	if (ctx->eqn >= eq_vector_num) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   eq_field_eqn,
				   "Invalid eqn: %u (max: %u).\n", ctx->eqn,
				   eq_vector_num - 1);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_eq_ctx_fixed_values(struct ubaseproxy_dev *udev,
						struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_eq_default *eq_default;
	struct ubaseproxy_eq_ctx *eq_ctx;
	int ret;

	eq_ctx = (struct ubaseproxy_eq_ctx *)req->data;
	eq_default = udev->caps.ue_default.eq_default;
	ret = ubaseproxy_check_ctx_mask_value(udev, eq_ctx,
					      &eq_default->create_mask,
					      &eq_default->default_value,
					      UBASEPROXY_EQ_CTX_SIZE);
	if (ret)
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   eq_ctx_fixed,
				   "failed to check eq(%u) ctx fixed value, ret = %d.\n",
				   req->tag, ret);

	return ret;
}

static int ubaseproxy_check_create_eq_ctx(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req)
{
	int ret;

	ret = ubaseproxy_check_eq_mbx_header(udev, req);
	if (ret)
		return ret;

	ret = ubaseproxy_check_eq_ctx_range_values(udev, req);
	if (ret)
		return ret;

	return ubaseproxy_check_eq_ctx_fixed_values(udev, req);
}

static struct ubaseproxy_eq_key_words*
ubaseproxy_create_eq_res(struct ubaseproxy_dev *udev,
			 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_eq_key_words *eq_info;
	struct xarray *eq_xa;
	int ret;

	eq_info = kzalloc(sizeof(struct ubaseproxy_eq_key_words), GFP_KERNEL);
	if (!eq_info)
		return NULL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	eq_xa = req->opcode == UBASE_MB_CREATE_AEQ_CONTEXT ?
		&ue_ctx_xa->aeq : &ue_ctx_xa->ceq;
	ret = xa_err(xa_store(eq_xa, req->tag, eq_info, GFP_KERNEL));
	if (ret) {
		kfree(eq_info);
		return NULL;
	}

	return eq_info;
}

static void ubaseproxy_del_eq_res(struct xarray *arr,
				  struct ubaseproxy_eq_key_words *eq_info,
				  u8 eqn)
{
	xa_erase(arr, eqn);
	kfree(eq_info);
}

int ubaseproxy_handle_create_eq_ctx_req(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_eq_key_words *eq_info;
	struct ubase_ctx_result ctx_res;
	u8 eqn = (u8)req->tag;
	struct xarray *eq_xa;
	int ret;

	if (req->data_len != UBASEPROXY_EQ_CTX_BYTES)
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	eq_xa = req->opcode == UBASE_MB_CREATE_AEQ_CONTEXT ?
		&ue_ctx_xa->aeq : &ue_ctx_xa->ceq;
	eq_info = (struct ubaseproxy_eq_key_words *)xa_load(eq_xa, eqn);
	if (eq_info) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   eq_create_eq_already_exists,
				   "created eq(%u) already exists.\n",
				   eqn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_create_eq_ctx(udev, req);
	if (ret)
		return ret;

	eq_info = ubaseproxy_create_eq_res(udev, req);
	if (!eq_info) {
		ubaseproxy_err(udev, "failed to create eq res.\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create eq(%u) mbx, ret = %d.\n",
			       req->tag, ret);
		ubaseproxy_del_eq_res(eq_xa, eq_info, eqn);
	}

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UBASE, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send create eq(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_destroy_eq_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_eq_key_words *eq_info;
	struct ubase_ctx_result ctx_res;
	u8 eqn = (u8)req->tag;
	struct xarray *eq_xa;
	int ret;

	if (req->data_len)
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	eq_xa = req->opcode == UBASE_MB_DESTROY_AEQ_CONTEXT ?
		&ue_ctx_xa->aeq : &ue_ctx_xa->ceq;
	eq_info = (struct ubaseproxy_eq_key_words *)xa_load(eq_xa, eqn);
	if (!eq_info) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, eq_destroy_eq_not_exists,
				   "destroy eq(%u) not exists.\n",
				   req->tag);
		return -EINVAL;
	}

	if (req->opcode == UBASE_MB_DESTROY_CEQ_CONTEXT && eq_info->cnt) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, eq_destroy_jfc_not_empty,
				   "failed to destroy ceq, jfc not empty.\n");
		return -EINVAL;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy eq(%u) mbx, ret = %d.\n",
			       eqn, ret);
	else
		ubaseproxy_del_eq_res(eq_xa, eq_info, eqn);

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UBASE, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy eq(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_query_eq_ctx_req(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_eq_key_words *eq_info;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_ctx_result ctx_res;
	u8 eqn = (u8)req->tag;
	struct xarray *eq_xa;
	int ret;

	if (req->data_len)
		return -EINVAL;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	eq_xa = req->opcode == UBASE_MB_QUERY_AEQ_CONTEXT ?
		&ue_ctx_xa->aeq : &ue_ctx_xa->ceq;
	eq_info = (struct ubaseproxy_eq_key_words *)xa_load(eq_xa, eqn);
	if (!eq_info) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, eq_query_eq_not_exists,
				   "query eq(%u) not exists.\n", eqn);
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
			       "failed to send query eq(%u) mbx, ret = %d.\n",
			       eqn, ret);

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UBASE,
				   ret ? 0 : UBASEPROXY_EQ_CTX_BYTES,
				   ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, mailbox, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send query eq(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	if (!IS_ERR_OR_NULL(mailbox))
		ubase_free_cmd_mailbox(udev->comdev.adev, mailbox);

	return ret;
}

static void
ubaseproxy_init_eq_create_mask(struct ubaseproxy_eq_default *eq_default)
{
	const u32 eq_ctx_mask[] = {
		/* DW0-DW3 */
		GENMASK(31, 0), GENMASK(31, 8), GENMASK(11, 10), 0,
		/* DW4-DW7*/
		GENMASK(31, 20), 0, GENMASK(31, 16), GENMASK(31, 0),
		/* DW8-DW11*/
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 3) | GENMASK(1, 0),
		/* DW12-DW15 */
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
	};

	memcpy(&eq_default->create_mask, eq_ctx_mask, UBASEPROXY_EQ_CTX_BYTES);
}

static void
ubaseproxy_init_eq_default_value(struct ubaseproxy_eq_default *eq_default)
{
	eq_default->default_value.state = UBASEPROXY_EQ_STAT_VALID;
	eq_default->default_value.state2 = UBASEPROXY_EQ_STAT_VALID;
	eq_default->default_value.arm_st = UBASEPROXY_EQ_ALWAYS_ARMED;
	eq_default->default_value.eqe_size = 1;
}

int ubaseproxy_init_ue_eq_ctx_default(struct ubaseproxy_dev *udev)
{
	struct ubaseproxy_eq_default *eq_default;

	eq_default = kzalloc(sizeof(struct ubaseproxy_eq_default), GFP_KERNEL);
	if (!eq_default)
		return -ENOMEM;

	ubaseproxy_init_eq_create_mask(eq_default);
	ubaseproxy_init_eq_default_value(eq_default);

	udev->caps.ue_default.eq_default = eq_default;

	return 0;
}

void ubaseproxy_uninit_ue_eq_ctx_default(struct ubaseproxy_dev *udev)
{
	kfree(udev->caps.ue_default.eq_default);
	udev->caps.ue_default.eq_default = NULL;
}

int ubaseproxy_ceq_ref_inc(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa, u16 eqn,
			   u16 mbx_ue_id)
{
	struct ubaseproxy_eq_key_words *eq_info;

	eq_info = (struct ubaseproxy_eq_key_words *)xa_load(&ue_ctx_xa->ceq, eqn);
	if (!eq_info) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, eq_ceq_ref_inc,
				   "failed to inc cnt, eq(%u) not exists.\n",
				   eqn);
		return -EINVAL;
	}
	eq_info->cnt++;

	return 0;
}

int ubaseproxy_ceq_ref_dec(struct ubaseproxy_dev *udev,
			   struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa, u16 eqn,
			   u16 mbx_ue_id)
{
	struct ubaseproxy_eq_key_words *eq_info;

	eq_info = (struct ubaseproxy_eq_key_words *)xa_load(&ue_ctx_xa->ceq, eqn);
	if (!eq_info) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, eq_ceq_ref_dec,
				   "failed to reduce cnt, eq(%u) not exists.\n",
				   eqn);
		return -EINVAL;
	}

	eq_info->cnt--;

	return 0;
}
