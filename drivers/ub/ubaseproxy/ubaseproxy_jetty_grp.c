// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_jfs.h"
#include "ubaseproxy_mbx.h"
#include "ubaseproxy_jetty_grp.h"

#define UBASEPROXY_JTG_CTX_BYTES (sizeof(struct ubaseproxy_jetty_grp_ctx))
#define UBASEPROXY_JTG_CTX_SIZE (UBASEPROXY_JTG_CTX_BYTES / sizeof(u32))

static int
ubaseproxy_check_jetty_grp_mbx_header(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;

	if (req->tag >= ue_caps->jtg_max_cnt) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   jtg_req_tag,
				   "failed to check jetty group mbx header, tag = %u\n",
				   req->tag);
		return -EINVAL;
	}

	return 0;
}

static int
ubaseproxy_add_jetty_grp_bound_jettys(struct ubaseproxy_dev *udev,
				      struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				      struct ubaseproxy_jetty_grp_ctx *ctx,
				      u16 jtgn, u16 mbx_ue_id)
{
	unsigned long valid = (unsigned long)ctx->valid;
	int jetty_num = (int)ctx->jetty_number;
	u16 jetty_id;
	int ret, i;

	for (i = 0; i <= jetty_num; i++) {
		if (!test_bit(i, &valid))
			continue;

		jetty_id = ctx->start_jetty_id + i;
		ret = ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						      mbx_ue_id);
		if (ret) {
			ubaseproxy_risk_rl(udev, mbx_ue_id,
					   jtg_add_jetty_bound,
					   "jetty group(%u) failed to bind jetty(%u).\n",
					   jtgn, jetty_id);
			goto err_bind;
		}

	}

	return 0;

err_bind:
	for (i -= 1; i >= 0; i--) {
		if (!test_bit(i, &valid))
			continue;

		jetty_id = ctx->start_jetty_id + i;
		(void)ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa, jetty_id,
							mbx_ue_id);
	}

	return ret;
}

static int ubaseproxy_check_jetty_grp_ctx_values(struct ubaseproxy_dev *udev,
						 struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_grp_ctx *ctx;
	u16 jtgn = req->tag;
	int ret;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	if (ctx->start_jetty_id >= ue_caps->jfs_max_cnt) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_field_start_jetty_id,
				   "failed to check jetty group(%u) start jetty id, start jetty id = %u.\n",
				   jtgn, ctx->start_jetty_id);
		return -EINVAL;
	}

	if (ctx->rsv) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_field_rsv,
				   "failed to check jetty group(%u) rsv, rsv = %u.\n",
				   jtgn, ctx->rsv);
		return -EINVAL;
	}

	if (ctx->jetty_number >= ue_caps->jfs_max_cnt) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_field_jetty_number,
				   "failed to check jetty group(%u) jetty number, jetty number = %u.\n",
				   jtgn, ctx->jetty_number);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	ret = ubaseproxy_add_jetty_grp_bound_jettys(udev, ue_ctx_xa, ctx, jtgn,
						    le16_to_cpu(req->mbx_ue_id));
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_check_jetty_group_valid,
				   "failed to check jetty group(%u) valid, valid = 0x%x, ret = %d.\n",
				   jtgn, ctx->valid, ret);
		return ret;
	}

	return 0;
}

static int ubaseproxy_check_create_jetty_grp_ctx(struct ubaseproxy_dev *udev,
						 struct ubase_proxy_req_msg *req)
{
	int ret;

	ret = ubaseproxy_check_jetty_grp_mbx_header(udev, req);
	if (ret)
		return ret;

	return ubaseproxy_check_jetty_grp_ctx_values(udev, req);
}

static int ubaseproxy_store_jetty_grp_res(struct ubaseproxy_dev *udev,
					  struct ubase_proxy_req_msg *req,
					  struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
					  struct ubaseproxy_jtg_key_words *jtg)
{
	struct ubaseproxy_jetty_grp_ctx *ctx;
	u16 jtgn = req->tag;
	int ret;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	jtg->start_jetty_id = ctx->start_jetty_id;
	jtg->jetty_number = ctx->jetty_number;
	jtg->valid = ctx->valid;

	ret = xa_err(xa_store(&ue_ctx_xa->jetty_grp, jtgn, jtg, GFP_KERNEL));
	if (ret)
		ubaseproxy_err(udev,
			       "failed to store jetty group(%u) res to xa, ret = %d.\n",
			       jtgn, ret);

	return ret;
}

static struct ubaseproxy_jtg_key_words*
ubaseproxy_create_jetty_grp_res(struct ubaseproxy_dev *udev,
				struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jtg_key_words *jtg;
	int ret;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = kzalloc(sizeof(struct ubaseproxy_jtg_key_words), GFP_KERNEL);
	if (!jtg)
		return NULL;

	ret = ubaseproxy_store_jetty_grp_res(udev, req, ue_ctx_xa, jtg);
	if (ret) {
		kfree(jtg);
		return NULL;
	}

	return jtg;
}

static void
ubaseproxy_del_jetty_grp_bound_jettys(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req,
				      u16 start_jetty_id,
				      u8 jetty_num, u32 valid)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	u16 jetty_id, i;
	int ret;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	for (i = 0; i <= jetty_num; i++) {
		if (!test_bit(i, (unsigned long *)&valid))
			continue;

		jetty_id = start_jetty_id + i;
		ret = ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa, jetty_id,
							mbx_ue_id);
		if (ret)
			ubaseproxy_risk_rl(udev, mbx_ue_id,
					   jtg_del_jetty_bound,
					   "jetty group(%u) failed to del bound jetty(%u).\n",
					   req->tag, jetty_id);
	}
}

static void
ubaseproxy_del_jetty_grp_res(struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
			     struct ubaseproxy_jtg_key_words *jtg,
			     u16 jtgn)
{
	xa_erase(&ue_ctx_xa->jetty_grp, jtgn);
	kfree(jtg);
	jtg = NULL;
}

static void
ubaseproxy_destroy_jetty_grp_res(struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				 struct ubaseproxy_jtg_key_words *jtg,
				 u16 jtgn)
{
	ubaseproxy_del_jetty_grp_res(ue_ctx_xa, jtg, jtgn);
}

int ubaseproxy_handle_create_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
					       struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_grp_ctx *ctx;
	struct ubaseproxy_jtg_key_words *jtg;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jtgn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JTG_CTX_BYTES) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_req_len,
				   "failed to check create jetty group ctx len, len = %u.\n",
				   ctx_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = (struct ubaseproxy_jtg_key_words *)xa_load(&ue_ctx_xa->jetty_grp,
							 jtgn);
	if (jtg) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jtg_create_jtg_already_exists,
				   "created jetty group(%u) already exists.\n",
				   jtgn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_create_jetty_grp_ctx(udev, req);
	if (ret)
		return ret;

	jtg = ubaseproxy_create_jetty_grp_res(udev, req);
	if (!jtg) {
		ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
		ubaseproxy_del_jetty_grp_bound_jettys(udev, req,
						      ctx->start_jetty_id,
						      ctx->jetty_number,
						      ctx->valid);
		ret = -ENOMEM;
		goto out;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create jetty group(%u) mbx, ret = %d.\n",
			       jtgn, ret);
		ubaseproxy_del_jetty_grp_bound_jettys(udev, req,
						      jtg->start_jetty_id,
						      jtg->jetty_number,
						      jtg->valid);
		ubaseproxy_destroy_jetty_grp_res(ue_ctx_xa, jtg, jtgn);
	}

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send create jetty group(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_destroy_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
						struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jtg_key_words *jtg;
	struct ubase_ctx_result ctx_res;
	u16 jtgn = req->tag;
	int ret;

	if (req->data_len) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_req_len,
				   "failed to check destroy jetty group ctx len, len = %u.\n",
				   req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = (struct ubaseproxy_jtg_key_words *)xa_load(&ue_ctx_xa->jetty_grp, jtgn);
	if (!jtg) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jtg_destroy_jtg_not_exists,
				   "destroyed jetty group(%u) not exists.\n",
				   jtgn);
		return -EINVAL;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send destroy jetty group(%u) mbx, ret = %d.\n",
			       jtgn, ret);
	} else {
		ubaseproxy_del_jetty_grp_bound_jettys(udev, req,
						      jtg->start_jetty_id,
						      jtg->jetty_number,
						      jtg->valid);
		ubaseproxy_destroy_jetty_grp_res(ue_ctx_xa, jtg, jtgn);
	}

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send destroy jetty group(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}

int ubaseproxy_handle_query_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
					      struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jtg_key_words *jtg;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_ctx_result ctx_res;
	u16 jtgn = req->tag;
	int ret;

	if (req->data_len) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_req_len,
				   "failed to check query jetty group ctx len, len = %u.\n",
				   req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = (struct ubaseproxy_jtg_key_words *)xa_load(&ue_ctx_xa->jetty_grp, jtgn);
	if (!jtg) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_query_jtg_not_exists,
				   "queried jetty group(%u) not exists.\n",
				   jtgn);
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
			       "failed to send query jetty group(%u) mbx, ret = %d.\n",
			       jtgn, ret);

out:
	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA,
				   ret ? 0 : UBASEPROXY_JTG_CTX_BYTES,
				   ret);
	ret =  ubaseproxy_send_resp_to_ue(udev, req, mailbox, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send query jetty group(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	if (!IS_ERR_OR_NULL(mailbox))
		ubase_free_cmd_mailbox(udev->comdev.adev, mailbox);

	return ret;
}

static int ubaseproxy_check_jetty_grp_ctx_mask(struct ubaseproxy_dev *udev,
					       struct ubase_proxy_req_msg *req)
{
	const u32 jtg_modify_mask[] = {GENMASK(26, 0), 0};
	struct ubaseproxy_jetty_grp_ctx *ctx, *ctx_mask;
	int ret;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	ctx_mask = ctx + 1;
	ret = ubaseproxy_check_ctx_mask_value(udev, ctx_mask,
					      (void *)jtg_modify_mask,
					      (void *)jtg_modify_mask,
					      UBASEPROXY_JTG_CTX_SIZE);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to check jetty group(%u) ctx mask value.\n",
			       req->tag);
		return ret;
	}

	return 0;
}

static int
ubaseproxy_check_modify_jetty_grp_jetty_number(struct ubaseproxy_dev *udev,
					       struct ubase_proxy_req_msg *req)
{
#define UBASEPROXY_JTG_JETTY_NUMBER_FEILD_WIDTH 5

	struct ubaseproxy_jetty_grp_ctx *ctx, *ctx_mask;
	u16 jtgn = req->tag;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	ctx_mask = ctx + 1;
	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->jetty_number,
					     UBASEPROXY_JTG_JETTY_NUMBER_FEILD_WIDTH)) {
		ubaseproxy_err(udev,
			       "failed to check jetty group(%u) jetty number mask.\n",
			       jtgn);
		return -EINVAL;
	}

	if (ctx_mask->jetty_number == 0 &&
	    ctx->jetty_number >= udev->caps.ue_caps.jfs_max_cnt) {
		ubaseproxy_err(udev,
			       "failed to modify jetty group(%u) jetty number, jetty number = %u.\n",
			       jtgn, ctx->jetty_number);
		return -EINVAL;
	}

	return 0;
}

static void
ubaseproxy_update_jetty_grp_changed_jettys(struct ubaseproxy_dev *udev,
					   struct ubase_proxy_req_msg *req,
					   struct ubaseproxy_jtg_key_words *jtg,
					   struct ubaseproxy_jtg_bound_jetty *bound_jetty)
{
	unsigned long changed_bitmap, add_bitmap, del_bitmap;
	u8 add_jetty_cnt = 0, del_jetty_cnt = 0;
	struct ubaseproxy_jetty_grp_ctx *ctx;
	unsigned long valid, last_valid;
	u8 i;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	valid = ctx->valid;
	last_valid = jtg->valid;
	changed_bitmap = valid ^ last_valid;
	add_bitmap = changed_bitmap & valid;
	del_bitmap = changed_bitmap & last_valid;
	for (i = 0; i <= jtg->jetty_number; i++) {
		if (test_bit(i, &add_bitmap))
			bound_jetty->add_jetty[add_jetty_cnt++] = i;
		if (test_bit(i, &del_bitmap))
			bound_jetty->del_jetty[del_jetty_cnt++] = i;
	}

	bound_jetty->add_jetty_num = add_jetty_cnt;
	bound_jetty->del_jetty_num = del_jetty_cnt;
}

static int
ubaseproxy_modify_jetty_grp_bound_jettys(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req,
					 struct ubaseproxy_jtg_key_words *jtg,
					 struct ubaseproxy_jtg_bound_jetty *bound_jetty)
{
	int add_jetty_num, del_jetty_num, ret, i, j;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	u16 jtgn = req->tag, jetty_id;

	ubaseproxy_update_jetty_grp_changed_jettys(udev, req, jtg, bound_jetty);

	add_jetty_num = (int)bound_jetty->add_jetty_num;
	del_jetty_num = (int)bound_jetty->del_jetty_num;
	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	for (i = 0; i < add_jetty_num; i++) {
		jetty_id = jtg->start_jetty_id + bound_jetty->add_jetty[i];
		ret = ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						      mbx_ue_id);
		if (ret) {
			ubaseproxy_err(udev,
				       "jetty group(%u) failed to add bound jetty(%u).\n",
				       jtgn, jetty_id);
			goto err_bind;
		}
	}

	for (j = 0; j < del_jetty_num; j++) {
		jetty_id = jtg->start_jetty_id + bound_jetty->del_jetty[j];
		ret = ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa,
							jetty_id, mbx_ue_id);
		if (ret) {
			ubaseproxy_err(udev,
				       "jetty group(%u) failed to del bound jetty(%u).\n",
				       jtgn, jetty_id);
			goto err_unbind;
		}
	}

	return 0;

err_unbind:
	for (j -= 1; j >= 0; j--) {
		jetty_id = jtg->start_jetty_id + bound_jetty->del_jetty[j];
		(void)ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						      mbx_ue_id);
	}

err_bind:
	for (i -= 1; i >= 0; i--) {
		jetty_id = jtg->start_jetty_id + bound_jetty->add_jetty[i];
		(void)ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa,
							jetty_id, mbx_ue_id);
	}

	return ret;
}

static int
ubaseproxy_check_modify_jetty_grp_valid(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req,
					struct ubaseproxy_jtg_key_words *jtg,
					struct ubaseproxy_jtg_bound_jetty *bound_jetty)
{
#define UBASEPROXY_JTG_VALID_FEILD_WIDTH 32

	struct ubaseproxy_jetty_grp_ctx *ctx, *ctx_mask;
	u16 jtgn = req->tag;
	int ret;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	ctx_mask = ctx + 1;
	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->valid,
					     UBASEPROXY_JTG_VALID_FEILD_WIDTH)) {
		ubaseproxy_err(udev,
			       "failed to check jetty group(%u) valid mask.\n",
			       jtgn);
		return -EINVAL;
	}

	if (ctx_mask->valid == 0) {
		ret = ubaseproxy_modify_jetty_grp_bound_jettys(udev, req,
							       jtg, bound_jetty);
		if (ret) {
			ubaseproxy_err(udev,
				       "failed to modify jetty group(%u) valid, valid = 0x%x, ret = %d.\n",
				       jtgn, ctx->valid, ret);
			return ret;
		}
	}

	return 0;
}

static int
ubaseproxy_check_modify_jetty_grp_ctx(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req,
				      struct ubaseproxy_jtg_key_words *jtg,
				      struct ubaseproxy_jtg_bound_jetty *bound_jetty)
{
	int ret;

	ret = ubaseproxy_check_jetty_grp_ctx_mask(udev, req);
	if (ret)
		return ret;

	ret = ubaseproxy_check_modify_jetty_grp_jetty_number(udev, req);
	if (ret)
		return ret;

	return ubaseproxy_check_modify_jetty_grp_valid(udev, req, jtg, bound_jetty);
}

static void
ubaseproxy_revert_jetty_grp_bound_jettys(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req,
					 struct ubaseproxy_jtg_key_words *jtg,
					 struct ubaseproxy_jtg_bound_jetty *bound_jetty)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	u16 jtgn = req->tag;
	u16 jetty_id, i;
	int ret;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	for (i = 0; i < bound_jetty->add_jetty_num; i++) {
		jetty_id = jtg->start_jetty_id + bound_jetty->add_jetty[i];
		ret = ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa,
							jetty_id, mbx_ue_id);
		if (ret)
			ubaseproxy_err(udev,
				       "jetty group(%u) failed to unbound added jetty(%u).\n",
				       jtgn, jetty_id);
	}

	for (i = 0; i < bound_jetty->del_jetty_num; i++) {
		jetty_id = jtg->start_jetty_id + bound_jetty->del_jetty[i];
		ret = ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						      mbx_ue_id);
		if (ret)
			ubaseproxy_err(udev,
				       "jetty group(%u) failed to bind del jetty(%u).\n",
				       jtgn, jetty_id);
	}
}

static void
ubaseproxy_update_jetty_grp_ctx_res(struct ubase_proxy_req_msg *req,
				    struct ubaseproxy_jtg_key_words *jtg)
{
	struct ubaseproxy_jetty_grp_ctx *ctx, *ctx_mask;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	ctx_mask = ctx + 1;
	if (ctx_mask->jetty_number == 0)
		jtg->jetty_number = ctx->jetty_number;
	if (ctx_mask->valid == 0)
		jtg->valid = ctx->valid;
}

int ubaseproxy_handle_modify_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
					       struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_jtg_bound_jetty bound_jetty = {0};
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jtg_key_words *jtg;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jtgn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JTG_CTX_BYTES * UBASEPROXY_CTXLEN_AND_MASK) {
		ubaseproxy_err(udev,
			       "failed to check modify jetty group ctx len, len = %u.\n",
			       ctx_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = (struct ubaseproxy_jtg_key_words *)xa_load(&ue_ctx_xa->jetty_grp, jtgn);
	if (!jtg) {
		ubaseproxy_err(udev,
			       "modified jetty group(%u) not exists.\n",
			       jtgn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_modify_jetty_grp_ctx(udev, req, jtg,
						    &bound_jetty);
	if (ret)
		return ret;

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send modify jetty group(%u) mbx, ret = %d.\n",
			       jtgn, ret);
		ubaseproxy_revert_jetty_grp_bound_jettys(udev, req, jtg,
							 &bound_jetty);
	} else {
		ubaseproxy_update_jetty_grp_ctx_res(req, jtg);
	}

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send modify jetty group(%u) resp to ue, ret = %d.\n",
			       jtgn, ret);

	return ret;
}
