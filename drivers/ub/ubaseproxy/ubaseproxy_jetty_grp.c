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
ubaseproxy_bind_jettys_to_jetty_grp(struct ubaseproxy_dev *udev,
				    struct ubase_proxy_req_msg *req,
				    u16 start_jetty_id, u32 valid)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	u16 jtgn = req->tag;
	u32 jetty_id;
	int ret, i;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);

	for (i = 0; i < fls(valid); i++) {
		if (!test_bit(i, (unsigned long *)&valid))
			continue;

		jetty_id = start_jetty_id + i;
		ret = ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						      mbx_ue_id, jtgn);
		if (ret)
			goto err_bind;
	}

	return 0;

err_bind:
	for (i -= 1; i >= 0; i--) {
		if (!test_bit(i, (unsigned long *)&valid))
			continue;

		jetty_id = start_jetty_id + i;
		ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						  mbx_ue_id, jtgn);
	}

	return ret;
}

static void
ubaseproxy_unbind_jettys_from_jetty_grp(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req,
					u16 start_jetty_id, u32 valid)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	u16 jtgn = req->tag;
	u32 jetty_id;
	int i;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);

	for (i = 0; i < fls(valid); i++) {
		if (!test_bit(i, (unsigned long *)&valid))
			continue;

		jetty_id = start_jetty_id + i;
		ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						  mbx_ue_id, jtgn);
	}
}

static bool ubaseproxy_check_jetty_grp_valid(u16 start_jetty_id, u32 valid,
					     u32 jfs_max_cnt)
{
	return !valid || (start_jetty_id + fls(valid) - 1 < jfs_max_cnt);
}

static int
ubaseproxy_check_jetty_grp_ctx_values(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req)
{
	u32 jfs_max_cnt = udev->caps.ue_caps.jfs_max_cnt;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_jetty_grp_ctx *ctx;
	u16 jtgn = req->tag;
	int ret;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	if (ctx->start_jetty_id >= jfs_max_cnt) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_field_start_jetty_id,
				   "failed to check jetty group(%u) start_jetty_id(%u).\n",
				   jtgn, ctx->start_jetty_id);
		return -EINVAL;
	}

	if (ctx->rsv) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_field_rsv,
				   "failed to check jetty group(%u) rsv(%u).\n",
				   jtgn, ctx->rsv);
		return -EINVAL;
	}

	if (ctx->valid & ~GENMASK(ctx->jetty_number, 0)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_valid_exceeds_range,
				   "create jetty group(%u) valid(0x%x) exceeds jetty_number(%u) range.\n",
				   jtgn, ctx->valid, ctx->jetty_number);
		return -EINVAL;
	}

	if (!ubaseproxy_check_jetty_grp_valid(ctx->start_jetty_id, ctx->valid,
					      jfs_max_cnt)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_field_valid,
				   "failed to check jetty group(%u) valid(%u), start_jetty_id = %u.\n",
				   jtgn, ctx->valid, ctx->start_jetty_id);
		return -EINVAL;
	}

	ret = ubaseproxy_bind_jettys_to_jetty_grp(udev, req, ctx->start_jetty_id,
						  ctx->valid);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_create_bindings,
				   "failed to create jetty group(%u) bindings, valid = 0x%x.\n",
				   jtgn, ctx->valid);
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
ubaseproxy_del_jetty_grp_res(struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
			     struct ubaseproxy_jtg_key_words *jtg,
			     u16 jtgn)
{
	xa_erase(&ue_ctx_xa->jetty_grp, jtgn);
	kfree(jtg);
}

static void
ubaseproxy_destroy_jetty_grp_res(struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				 struct ubaseproxy_jtg_key_words *jtg,
				 u16 jtgn)
{
	ubaseproxy_del_jetty_grp_res(ue_ctx_xa, jtg, jtgn);
}

static int
ubaseproxy_check_modify_jetty_grp_mask(struct ubaseproxy_dev *udev,
				       struct ubaseproxy_jetty_grp_ctx *ctx_mask,
				       u16 jtgn, u16 mbx_ue_id)
{
#define UBASEPROXY_JTG_JETTY_NUMBER_BITS	5
#define UBASEPROXY_JTG_VALID_BITS		32

	u32 modify_mask[] = {GENMASK(26, 0), 0};
	int ret;

	ret = ubaseproxy_check_ctx_mask_value(udev, ctx_mask,
					      modify_mask, modify_mask,
					      UBASEPROXY_JTG_CTX_SIZE);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_modify_mask,
				   "failed to check jetty group(%u) ctx mask value.\n",
				   jtgn);
		return ret;
	}

	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->jetty_number,
					     UBASEPROXY_JTG_JETTY_NUMBER_BITS)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_modify_jetty_num_mask,
				   "failed to check jetty group(%u) jetty_number mask(%u).\n",
				   jtgn, ctx_mask->jetty_number);
		return -EINVAL;
	}

	if (!ubaseproxy_check_ctx_mask_field(ctx_mask->valid,
					     UBASEPROXY_JTG_VALID_BITS)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_modify_valid_mask,
				   "failed to check jetty group(%u) valid mask(0x%x).\n",
				   jtgn, ctx_mask->valid);
		return -EINVAL;
	}

	return 0;
}

static void
ubaseproxy_get_jetty_grp_modify_info(struct ubaseproxy_jtg_key_words *jtg,
				     struct ubaseproxy_jetty_grp_ctx *ctx,
				     struct ubaseproxy_jetty_grp_ctx *ctx_mask,
				     struct ubaseproxy_jtg_modify_info *info)
{
	info->old_valid = jtg->valid;
	info->old_jetty_num = jtg->jetty_number;
	info->new_valid = (ctx_mask->valid == 0) ?
			  ctx->valid : info->old_valid;
	info->new_jetty_num = (ctx_mask->jetty_number == 0) ?
			      ctx->jetty_number : info->old_jetty_num;

	info->to_bind = info->new_valid & ~info->old_valid;
	info->to_unbind = info->old_valid & ~info->new_valid;
}

static int
ubaseproxy_update_jetty_grp_bindings(struct ubaseproxy_dev *udev,
				     struct ubase_proxy_req_msg *req,
				     struct ubaseproxy_jtg_key_words *jtg,
				     struct ubaseproxy_jtg_modify_info *info)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id), jtgn = req->tag;
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	int ret, i, j;
	u32 jetty_id;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);

	for (i = 0; i < fls(info->to_bind); i++) {
		if (!test_bit(i, (unsigned long *)&info->to_bind))
			continue;

		jetty_id = jtg->start_jetty_id + i;
		ret = ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						      mbx_ue_id, jtgn);
		if (ret)
			goto err_bind;
	}

	for (j = 0; j < fls(info->to_unbind); j++) {
		if (!test_bit(j, (unsigned long *)&info->to_unbind))
			continue;

		jetty_id = jtg->start_jetty_id + j;
		ret = ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa, jetty_id,
							mbx_ue_id, jtgn);
		if (ret)
			goto err_unbind;
	}

	jtg->jetty_number = info->new_jetty_num;
	jtg->valid = info->new_valid;

	return 0;

err_unbind:
	for (j -= 1; j >= 0; j--) {
		if (!test_bit(j, (unsigned long *)&info->to_unbind))
			continue;

		jetty_id = jtg->start_jetty_id + j;
		ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						mbx_ue_id, jtgn);
	}

err_bind:
	for (i -= 1; i >= 0; i--) {
		if (!test_bit(i, (unsigned long *)&info->to_bind))
			continue;

		jetty_id = jtg->start_jetty_id + i;
		ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						  mbx_ue_id, jtgn);
	}

	return ret;
}

static int
ubaseproxy_check_modify_jetty_grp_values(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req,
					 struct ubaseproxy_jtg_key_words *jtg,
					 struct ubaseproxy_jtg_modify_info *info)
{
	u32 jfs_max_cnt = udev->caps.ue_caps.jfs_max_cnt;
	struct ubaseproxy_jetty_grp_ctx *ctx, *ctx_mask;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	u16 jtgn = req->tag;
	int ret;

	if (info->new_valid & ~GENMASK(info->new_jetty_num, 0)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
				   jtg_modify_valid_exceeds_range,
				   "modify jetty group(%u) valid(0x%x) exceeds jetty_number(%u) range.\n",
				   jtgn, info->new_valid, info->new_jetty_num);
		return -EINVAL;
	}

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	ctx_mask = ctx + 1;
	if (ctx_mask->valid == 0 &&
	    !ubaseproxy_check_jetty_grp_valid(jtg->start_jetty_id, ctx->valid,
					      jfs_max_cnt)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_modify_valid,
				   "failed to modify jetty group(%u) valid(0x%x).\n",
				   jtgn, ctx->valid);
		return -EINVAL;
	}

	ret = ubaseproxy_update_jetty_grp_bindings(udev, req, jtg, info);
	if (ret)
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_modify_bindings,
				   "failed to update jetty group(%u) bindings, ret = %d.\n",
				   jtgn, ret);

	return ret;
}

static int
ubaseproxy_check_modify_jetty_grp_ctx(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req,
				      struct ubaseproxy_jtg_key_words *jtg,
				      struct ubaseproxy_jtg_modify_info *info)
{
	struct ubaseproxy_jetty_grp_ctx *ctx, *ctx_mask;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	u16 jtgn = req->tag;
	int ret;

	ctx = (struct ubaseproxy_jetty_grp_ctx *)req->data;
	ctx_mask = ctx + 1;

	ret = ubaseproxy_check_modify_jetty_grp_mask(udev, ctx_mask, jtgn,
						     mbx_ue_id);
	if (ret)
		return ret;

	ubaseproxy_get_jetty_grp_modify_info(jtg, ctx, ctx_mask, info);

	return ubaseproxy_check_modify_jetty_grp_values(udev, req, jtg, info);
}

static void
ubaseproxy_restore_jetty_grp_bindings(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req,
				      struct ubaseproxy_jtg_key_words *jtg,
				      struct ubaseproxy_jtg_modify_info *info)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id), jtgn = req->tag;
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	u32 jetty_id;
	int i;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);

	for (i = 0; i < fls(info->to_bind); i++) {
		if (!test_bit(i, (unsigned long *)&info->to_bind))
			continue;

		jetty_id = jtg->start_jetty_id + i;
		ubaseproxy_jetty_unbind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						  mbx_ue_id, jtgn);
	}

	for (i = 0; i < fls(info->to_unbind); i++) {
		if (!test_bit(i, (unsigned long *)&info->to_unbind))
			continue;

		jetty_id = jtg->start_jetty_id + i;
		ubaseproxy_jetty_bind_jetty_grp(udev, ue_ctx_xa, jetty_id,
						mbx_ue_id, jtgn);
	}

	jtg->jetty_number = info->old_jetty_num;
	jtg->valid = info->old_valid;
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
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_create_req_len,
				   "create jetty group(%u) ctx_len(%u) error.\n",
				   jtgn, ctx_len);
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
		ubaseproxy_unbind_jettys_from_jetty_grp(udev, req,
							ctx->start_jetty_id,
							ctx->valid);
		ret = -ENOMEM;
		goto out;
	}

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send create jetty group(%u) mbx, ret = %d.\n",
			       jtgn, ret);
		ubaseproxy_unbind_jettys_from_jetty_grp(udev, req,
							jtg->start_jetty_id,
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
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_destroy_req_len,
				   "destroy jetty group(%u) data_len(%u) error.\n",
				   jtgn, req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = (struct ubaseproxy_jtg_key_words *)xa_load(&ue_ctx_xa->jetty_grp,
							 jtgn);
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
		ubaseproxy_unbind_jettys_from_jetty_grp(udev, req,
							jtg->start_jetty_id,
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
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_query_req_len,
				   "query jetty group(%u) data_len(%u) error.\n",
				   jtgn, req->data_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = (struct ubaseproxy_jtg_key_words *)xa_load(&ue_ctx_xa->jetty_grp,
							 jtgn);
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

int ubaseproxy_handle_modify_jetty_grp_ctx_req(struct ubaseproxy_dev *udev,
					       struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jtg_modify_info info;
	struct ubaseproxy_jtg_key_words *jtg;
	struct ubase_ctx_result ctx_res;
	u32 ctx_len = req->data_len;
	u16 jtgn = req->tag;
	int ret;

	if (ctx_len != UBASEPROXY_JTG_CTX_BYTES * UBASEPROXY_CTXLEN_AND_MASK) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_modify_req_len,
				   "modify jetty group(%u) ctx_len(%u) error.\n",
				   jtgn, ctx_len);
		return -EINVAL;
	}

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jtg = (struct ubaseproxy_jtg_key_words *)xa_load(&ue_ctx_xa->jetty_grp,
							 jtgn);
	if (!jtg) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jtg_modify_jtg_not_exists,
				   "modified jetty group(%u) not exists.\n",
				   jtgn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_modify_jetty_grp_ctx(udev, req, jtg, &info);
	if (ret)
		return ret;

	ret = ubaseproxy_send_mbx_based_ue_req(udev, req);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to send modify jetty group(%u) mbx, ret = %d.\n",
			       jtgn, ret);
		ubaseproxy_restore_jetty_grp_bindings(udev, req, jtg, &info);
	}

	ubaseproxy_fill_ctx_result(&ctx_res, UBASE_OPC_PROXY_TO_UDMA, 0, ret);
	ret = ubaseproxy_send_resp_to_ue(udev, req, NULL, &ctx_res);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send modify jetty group(%u) resp to ue, ret = %d.\n",
			       req->tag, ret);

	return ret;
}
