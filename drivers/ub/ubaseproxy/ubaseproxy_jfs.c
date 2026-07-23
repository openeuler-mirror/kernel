// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_jfc.h"
#include "ubaseproxy_mbx.h"
#include "ubaseproxy_jfr.h"
#include "ubaseproxy_jfs.h"

#define UBASEPROXY_STATE_ARRAY_LEN 2

#define UBASEPROXY_JFS_MASK_OFFSET 128
#define UBASEPROXY_JETTY_CTX_BYTES sizeof(struct ubaseproxy_jetty_ctx)
#define UBASEPROXY_JETTY_CTX_SIZE (UBASEPROXY_JETTY_CTX_BYTES / sizeof(u32))

int ubaseproxy_jetty_bind_jetty_grp(struct ubaseproxy_dev *udev,
				    struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				    u16 jettyn, u16 mbx_ue_id)
{
	struct ubaseproxy_jetty_key_words *jetty;

	jetty = (struct ubaseproxy_jetty_key_words *)xa_load(&ue_ctx_xa->jetty,
							     jettyn);
	if (!jetty) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_bind_jetty_not_exists,
				   "failed to bind jetty group, jetty(%u) not exist.\n",
				   jettyn);
		return -EINVAL;
	}

	if (jetty->mode != UBASEPROXY_JETTY_MODE) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_bind_not_in_jetty_mode,
				   "failed to bind jetty group, jetty(%u) is not in jetty mode.\n",
				   jettyn);
		return -EINVAL;
	}

	if (jetty->jtg_bind_state) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_bind_already_bound_group,
				   "failed to bind jetty group, jetty(%u) has already bound a jetty group.\n",
				   jettyn);
		return -EINVAL;
	}

	jetty->jtg_bind_state = UBASEPROXY_JETTY_GRP_BIND;

	return 0;
}

int ubaseproxy_jetty_unbind_jetty_grp(struct ubaseproxy_dev *udev,
				      struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				      u16 jettyn, u16 mbx_ue_id)
{
	struct ubaseproxy_jetty_key_words *jetty;

	jetty = (struct ubaseproxy_jetty_key_words *)xa_load(&ue_ctx_xa->jetty,
							     jettyn);
	if (!jetty) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_unbind_jetty_not_exists,
				   "failed to unbind jetty group, jetty(%u) not exist.\n",
				   jettyn);
		return -EINVAL;
	}

	jetty->jtg_bind_state = UBASEPROXY_JETTY_GRP_UNBIND;

	return 0;
}

static int ubaseproxy_dynamic_init_default(struct ubaseproxy_dev *udev,
					   struct ubaseproxy_jetty_ctx *ctx,
					   struct ubaseproxy_jetty_default *jetty_default,
					   u16 mbx_ue_id)
{
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfc_key_words *rx_jfc;

	if (ctx->jfs_mode == UBASEPROXY_JFS_MODE)
		return 0;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	rx_jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc,
							    ctx->rx_jfcn);
	if (!rx_jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_init_load_rx_jfc,
				   "failed to load rx jfc, rx_jfcn = %u.\n",
				   ctx->rx_jfcn);
		return -EINVAL;
	}

	jetty_default->default_value.cqe_ie = rx_jfc->inline_en;
	jetty_default->default_value.cqe_sz = rx_jfc->cqe_size;

	return 0;
}

static void ubaseproxy_dynamic_uninit_default(struct ubaseproxy_jetty_ctx *ctx,
					      struct ubaseproxy_jetty_default *jetty_default)
{
	if (ctx->jfs_mode == UBASEPROXY_JFS_MODE)
		return;

	jetty_default->default_value.cqe_ie = 0;
	jetty_default->default_value.cqe_sz = 0;
}

static int
ubaseproxy_check_jetty_ctx_fixed_values(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_jetty_default *jetty_default;
	struct ubaseproxy_jetty_ctx *ctx;
	int ret;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	jetty_default = udev->caps.ue_default.jetty_default;
	ret = ubaseproxy_dynamic_init_default(udev, ctx, jetty_default,
					      le16_to_cpu(req->mbx_ue_id));
	if (ret)
		return ret;

	ret = ubaseproxy_check_ctx_mask_value(udev, ctx,
					      &jetty_default->create_mask,
					      &jetty_default->default_value,
					      UBASEPROXY_JETTY_CTX_SIZE);
	if (ret)
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   jfs_ctx_fixed,
				   "failed to check jetty(%u) ctx fixed value.\n",
				   req->tag);

	ubaseproxy_dynamic_uninit_default(ctx, jetty_default);

	return ret;
}

static int ubaseproxy_check_jetty_type_match(struct ubaseproxy_dev *udev,
					     struct ubase_proxy_req_msg *req,
					     u16 jfrn)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfr_key_words *jfr;
	struct ubaseproxy_jetty_ctx *ctx;
	u16 jettyn = req->tag;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	if (ctx->jfs_mode != UBASEPROXY_JETTY_MODE)
		return 0;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfr = (struct ubaseproxy_jfr_key_words *)xa_load(&ue_ctx_xa->jfr, jfrn);
	if (!jfr) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_check_jfr_not_exists,
				   "failed to check jetty(%u) type, jfr(%u) not exists.\n",
				   jettyn, jfrn);
		return -EINVAL;
	}

	if (jfr->type != ctx->type) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_check_jfr_type_not_match,
				   "failed to match jetty(%u) type(%u) and jfr(%u) type(%u).\n",
				   jettyn, ctx->type, jfrn, jfr->type);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_jfr_exists(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jfr_key_words *jfr;
	struct ubaseproxy_jetty_ctx *ctx;
	u32 jfrn;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	if (ctx->jfs_mode == UBASEPROXY_JFS_MODE)
		return 0;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	jfrn = (ctx->jfrn_h << UBASEPROXY_JETTY_CTX_JFRN_H_OFFSET)
		+ ctx->jfrn_l;
	jfr = (struct ubaseproxy_jfr_key_words *)xa_load(&ue_ctx_xa->jfr, jfrn);
	if (!jfr) {
		ubaseproxy_err(udev,
				"failed to check jetty(%u), jfr(%u) not exists.\n",
				req->tag, jfrn);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_jfc_exists(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_jfc_key_words *tx_jfc, *rx_jfc;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_jetty_ctx *ctx;
	u16 jettyn = req->tag;
	u32 tx_jfcn, rx_jfcn;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	tx_jfcn = ctx->tx_jfcn;
	rx_jfcn = ctx->rx_jfcn;

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	tx_jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, tx_jfcn);
	if (!tx_jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_check_tx_jfc_not_exists,
				   "failed to check jetty(%u), tx jfc(%u) not exists.\n",
				   jettyn, tx_jfcn);
		return -EINVAL;
	}

	if (ctx->jfs_mode == UBASEPROXY_JFS_MODE)
		return 0;

	rx_jfc = (struct ubaseproxy_jfc_key_words *)xa_load(&ue_ctx_xa->jfc, rx_jfcn);
	if (!rx_jfc) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_check_rx_jfc_not_exists,
				   "failed to check jetty(%u), rx jfc(%u) not exists.\n",
				   jettyn, rx_jfcn);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_jetty_sl_value(struct ubaseproxy_dev *udev,
					   struct ubase_proxy_req_msg *req)
{
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_ue_ctx_qos *ue_ctx_qos;
	struct ubaseproxy_jetty_ctx *ctx;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	ue_ctx_qos = ubaseproxy_get_ue_ctx_qos(udev, mbx_ue_id);
	if (!test_bit(ctx->sl, &ue_ctx_qos->total_sl_bitmap)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_check_sl_not_valid,
				   "failed to check jetty ctx sl, ue_id = %hu, sl(%u) is not in valid sl_bitmap(0x%lx).\n",
				   mbx_ue_id, ctx->sl, ue_ctx_qos->total_sl_bitmap);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_jfs_seid_idx(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_seid_table *ue_seid_table;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	struct ubaseproxy_jetty_ctx *ctx;
	int ret = 0;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	ue_seid_table = ubaseproxy_get_ue_seid_table(udev, mbx_ue_id);

	spin_lock_bh(&ue_seid_table->seid_lock);
	if (!test_bit(ctx->seid_idx, ue_seid_table->seid_bmap)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_check_jfs_seid,
				   "failed to check jfs ctx seid idx, seid_idx = %u.\n",
				   ctx->seid_idx);
		ret = -EINVAL;
	}
	spin_unlock_bh(&ue_seid_table->seid_lock);

	return ret;
}

static int
ubaseproxy_check_jetty_ctx_range_values(struct ubaseproxy_dev *udev,
					struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;
	struct ubaseproxy_jetty_ctx *ctx;
	u32 jettyn = req->tag;
	u32 jfs_depth, jfrn;
	int ret;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	if (ctx->type < UBASEPROXY_JETTY_TYPE_UM ||
	    ctx->type > UBASEPROXY_JETTY_TYPE_RM) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   jfs_field_type,
				   "failed to check jetty ctx, jettyn = %u, type = %u.\n",
				   jettyn, ctx->type);
		return -EINVAL;
	}

	jfs_depth = ilog2(roundup_pow_of_two(ue_caps->jfs_depth));
	if (!ctx->sqe_bb_shift || ctx->sqe_bb_shift > jfs_depth) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   jfs_field_sqe_bb_shift,
				   "failed to check jetty ctx, jettyn = %u, sqe_bb_shift = %u, jfs_depth = %u.\n",
				   jettyn, ctx->sqe_bb_shift, jfs_depth);
		return -EINVAL;
	}

	if (ctx->next_send_ssn != ctx->next_rcv_ssn) {
		ubaseproxy_err(udev,
			       "failed to check jetty ctx, jettyn = %u, next_send_ssn = %u, next_rcv_ssn = %u.\n",
			       jettyn, ctx->next_send_ssn, ctx->next_rcv_ssn);
		return -EINVAL;
	}

	ret = ubaseproxy_check_jetty_sl_value(udev, req);
	if (ret)
		return ret;

	ret = ubaseproxy_check_jfs_seid_idx(udev, req);
	if (ret)
		return ret;

	jfrn = (ctx->jfrn_h << UBASEPROXY_JETTY_CTX_JFRN_H_OFFSET) + ctx->jfrn_l;
	return ubaseproxy_check_jetty_type_match(udev, req, jfrn);
}

static int ubaseproxy_check_jetty_mbx_header(struct ubaseproxy_dev *udev,
					     struct ubase_proxy_req_msg *req)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;

	if (req->tag >= ue_caps->jfs_max_cnt) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   jfs_req_tag,
				   "failed to check jetty mbx header, tag = %u.\n",
				   req->tag);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_check_create_jetty_ctx(struct ubaseproxy_dev *udev,
					     struct ubase_proxy_req_msg *req)
{
	int ret;

	ret = ubaseproxy_check_jetty_mbx_header(udev, req);
	if (ret)
		return ret;

	ret = ubaseproxy_check_jfc_exists(udev, req);
	if (ret)
		return ret;

	ret = ubaseproxy_check_jfr_exists(udev, req);
	if (ret)
		return ret;

	ret = ubaseproxy_check_jetty_ctx_range_values(udev, req);
	if (ret)
		return ret;

	return ubaseproxy_check_jetty_ctx_fixed_values(udev, req);
}

static int ubaseproxy_check_state_mask(struct ubaseproxy_jetty_ctx *ctx_mask,
				       struct ubaseproxy_jetty_ctx *modify_mask)
{
	return ctx_mask->state != modify_mask->state ? -EINVAL : 0;
}

static int ubaseproxy_check_modify_jetty_mask(struct ubaseproxy_dev *udev,
					      struct ubaseproxy_jetty_ctx *ctx,
					      u32 ctx_len, u16 jettyn,
					      u16 mbx_ue_id)
{
#define UBASEPROXY_SOFT_JETTY_CTX_SIZE	(UBASEPROXY_JETTY_CTX_SIZE / 2)

	struct ubaseproxy_jetty_ctx *modify_mask;
	struct ubaseproxy_jetty_ctx *ctx_mask;
	int ret;

	modify_mask = &udev->caps.ue_default.jetty_default->modify_mask;
	if (ctx_len == (UBASEPROXY_JETTY_CTX_BYTES + UBASEPROXY_JFS_MASK_OFFSET))
		ctx_mask = (struct ubaseproxy_jetty_ctx *)(
			   (char *)ctx + UBASEPROXY_JFS_MASK_OFFSET);
	else
		ctx_mask = ctx + 1;

	ret = ubaseproxy_check_ctx_mask_value(udev, ctx_mask, modify_mask,
					      modify_mask,
					      UBASEPROXY_SOFT_JETTY_CTX_SIZE);
	if (ret) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_ctx_fixed,
				   "failed to check modify jetty(%u) ctx value.\n",
				   jettyn);
		return ret;
	}

	ret = ubaseproxy_check_state_mask(ctx_mask, modify_mask);
	if (ret)
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_mask_state,
				   "failed to check jetty(%u) state mask.\n",
				   jettyn);

	return ret;
}

static struct ubaseproxy_jetty_state_item {
	u8 cur_state;
	s16 assoc_state[UBASEPROXY_STATE_ARRAY_LEN];
} state_item[] = {
	{
		UBASEPROXY_JETTY_STATE_READY,
		{
			UBASEPROXY_JETTY_STATE_SUSPEND,
			UBASEPROXY_JETTY_STATE_ERROR
		}
	},
	{
		UBASEPROXY_JETTY_STATE_SUSPEND,
		{
			UBASEPROXY_JETTY_STATE_READY,
			UBASEPROXY_JETTY_STATE_ERROR
		}
	},
};

static int ubaseproxy_check_modify_jetty_ctx(struct ubaseproxy_dev *udev,
					     struct ubase_proxy_req_msg *req,
					     struct ubaseproxy_jetty_key_words *jetty)
{
	struct ubaseproxy_jetty_ctx *ctx;
	u32 i, j;
	int ret;

	ctx = (struct ubaseproxy_jetty_ctx *)req->data;
	ret = ubaseproxy_check_modify_jetty_mask(udev, ctx, req->data_len,
						 req->tag,
						 le16_to_cpu(req->mbx_ue_id));
	if (ret)
		return ret;

	for (i = 0 ; i < ARRAY_SIZE(state_item); i++) {
		if (state_item[i].cur_state != jetty->state)
			continue;

		for (j = 0; j < ARRAY_SIZE(state_item[i].assoc_state); j++) {
			if (state_item[i].assoc_state[j] == ctx->state)
				return 0;
		}
	}

	ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
			   jfs_modify_check_state,
			   "failed to check jetty(%u) ctx, jetty->state = %u, ctx->state = %u.\n",
			   req->tag, jetty->state, ctx->state);

	return -EINVAL;
}

static inline bool ubaseproxy_jfs_flush_ssn_vld(struct ubaseproxy_jetty_ctx *ctx)
{
#define UBASEPROXY_RCV_SEND_MAX_DIFF_VAL	512U
	u16 rcv_send_diff = le16_to_cpu(ctx->next_rcv_ssn) -
			    le16_to_cpu(ctx->next_send_ssn);

	return ctx->flush_ssn_vld &&
	       (rcv_send_diff < UBASEPROXY_RCV_SEND_MAX_DIFF_VAL);
}

static int ubaseproxy_check_jetty_flush_done(struct auxiliary_device *adev,
					     u16 mbx_ue_id, u32 idx)
{
	struct ubase_cmd_mailbox *mailbox;
	struct ubaseproxy_jetty_ctx *ctx;
	struct ubase_mbx_attr attr = {0};
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox))
		return -ENOMEM;

	ubase_fill_mbx_attr(&attr, idx, UBASE_MB_QUERY_JFS_CONTEXT, mbx_ue_id);
	ret = ubase_hw_upgrade_ctx_for_proxy(adev, &attr, mailbox);
	if (ret)
		goto out;

	ctx = (struct ubaseproxy_jetty_ctx *)mailbox->buf;
	if (!ctx->flush_cqe_done && !ubaseproxy_jfs_flush_ssn_vld(ctx))
		ret = -EBUSY;

out:
	ubase_free_cmd_mailbox(adev, mailbox);
	return ret;
}

int ubaseproxy_check_destroy_jetty_ctx(struct ubaseproxy_dev *udev,
				       struct ubase_proxy_req_msg *req,
				       struct ubaseproxy_jetty_key_words *jetty)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	u16 jettyn = req->tag;

	if (jetty->state != UBASEPROXY_JETTY_STATE_ERROR) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_field_state,
				   "failed to check destroy jetty(%u) state = %u.\n",
				   jettyn, jetty->state);
		return -EINVAL;
	}

	if (jetty->mode == UBASEPROXY_JETTY_MODE &&
	    jetty->jtg_bind_state == UBASEPROXY_JETTY_GRP_BIND) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, jfs_field_mode,
				   "failed to check destroy jetty: jetty(%u) bind jetty group.\n",
				   jettyn);
		return -EINVAL;
	}

	if (ubaseproxy_check_jetty_flush_done(adev, mbx_ue_id, jettyn)) {
		ubaseproxy_err(udev,
			       "failed to check jetty(%u) flush done.\n",
			       jettyn);
		return -EINVAL;
	}

	return 0;
}

static int ubaseproxy_store_jetty_res(struct ubaseproxy_dev *udev,
				      struct ubase_proxy_req_msg *req,
				      struct ubaseproxy_jetty_ctx *jetty_ctx,
				      struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa,
				      struct ubaseproxy_jetty_key_words *jetty)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	u16 jettyn = req->tag;
	int ret;

	jetty->state = jetty_ctx->state;
	jetty->tx_jfcn = jetty_ctx->tx_jfcn;
	jetty->rx_jfcn = jetty_ctx->rx_jfcn;
	jetty->mode = jetty_ctx->jfs_mode;
	jetty->sqebb_depth = 1 << jetty_ctx->sqe_bb_shift;

	jetty->safety_sqe_addr = dma_alloc_coherent(adev->dev.parent,
						    jetty->sqebb_depth * UBASEPROXY_SQEBB_SIZE,
						    &jetty->safety_sqe_dma_addr, GFP_KERNEL);
	if (!jetty->safety_sqe_addr)
		return -ENOMEM;

	ret = xa_err(xa_store(&ue_ctx_xa->jetty, jettyn, jetty, GFP_KERNEL));
	if (ret) {
		dma_free_coherent(adev->dev.parent, jetty->sqebb_depth * UBASEPROXY_SQEBB_SIZE,
				  jetty->safety_sqe_addr, jetty->safety_sqe_dma_addr);
		ubaseproxy_err(udev,
			       "failed to create jetty(%u) ctx res, ret=%d.\n",
			       jettyn, ret);
	}

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
	struct auxiliary_device *adev = udev->comdev.adev;

	dma_free_coherent(adev->dev.parent, jetty->sqebb_depth * UBASEPROXY_SQEBB_SIZE,
			  jetty->safety_sqe_addr, jetty->safety_sqe_dma_addr);
	xa_erase(&ue_ctx_xa->jetty, jettyn);
	kfree(jetty);
}

void ubaseproxy_erase_jetty_ctx_resources(struct ubaseproxy_dev *udev,
					  struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa)
{
	struct ubaseproxy_jetty_key_words *jetty = NULL;
	unsigned long index = 0;

	if (!xa_empty(&ue_ctx_xa->jetty)) {
		xa_for_each(&ue_ctx_xa->jetty, index, jetty)
			ubaseproxy_del_jetty_res(udev, ue_ctx_xa, jetty, index);
	}
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

	ret = ubaseproxy_check_create_jetty_ctx(udev, req);
	if (ret)
		return ret;

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

	ret = ubaseproxy_check_destroy_jetty_ctx(udev, req, jetty);
	if (ret)
		return ret;

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

	ret = ubaseproxy_check_modify_jetty_ctx(udev, req, jetty);
	if (ret)
		return ret;

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

static void
ubaseproxy_init_jetty_create_mask(struct ubaseproxy_jetty_default *jetty_default)
{
	const u32 jetty_ctx_mask[] = {
		/* DW0-DW15 */
		GENMASK(18, 16), GENMASK(11, 9), 0, GENMASK(31, 0), 0,
		GENMASK(11, 8), GENMASK(31, 10), 0, 0,
		GENMASK(31, 22) | GENMASK(1, 1), GENMASK(31, 24),
		GENMASK(31, 20), GENMASK(23, 20), 0, 0, GENMASK(31, 0),
		/* DW16-DW21 */
		GENMASK(31, 16), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0),
		/* DW22*/
		GENMASK(3, 2),
		/* DW23-DW30 */
		GENMASK(31, 0), GENMASK(31, 16), GENMASK(31, 0), GENMASK(31, 0),
		GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0), GENMASK(31, 0),
		/* DW31*/
		GENMASK(9, 0),
		/* DW32-DW63 */
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};

	memcpy(&jetty_default->create_mask, jetty_ctx_mask,
	       UBASEPROXY_JETTY_CTX_BYTES);
}

static void
ubaseproxy_init_jetty_default_value(struct ubaseproxy_jetty_default *jetty_default)
{
	jetty_default->default_value.state = UBASEPROXY_JETTY_STATE_READY;
	jetty_default->default_value.avail_sgmt_ost = DEFAULT_AVAIL_SGMT_OST_VAL;
}

static void
ubaseproxy_init_jetty_modify_mask(struct ubaseproxy_jetty_default *jetty_default)
{
#define REVTMASK(h, l) (~GENMASK(h, l) & 0xFFFFFFFF)
#define JETTY_STATE_MASK REVTMASK(18, 16)
#define JETTY_STATE_OFSET_IDX 0
#define JETTY_INVALID_MASK 0xFF

	u32 *modify_mask;

	modify_mask = (u32 *)&jetty_default->modify_mask;
	memset(modify_mask, JETTY_INVALID_MASK, UBASEPROXY_JETTY_CTX_BYTES);
	modify_mask[JETTY_STATE_OFSET_IDX] = JETTY_STATE_MASK;
}

int ubaseproxy_init_ue_jetty_ctx_default(struct ubaseproxy_dev *udev)
{
	struct ubaseproxy_jetty_default *jetty_default;

	jetty_default = kzalloc(sizeof(struct ubaseproxy_jetty_default),
				GFP_KERNEL);
	if (!jetty_default)
		return -ENOMEM;

	ubaseproxy_init_jetty_create_mask(jetty_default);
	ubaseproxy_init_jetty_modify_mask(jetty_default);
	ubaseproxy_init_jetty_default_value(jetty_default);

	udev->caps.ue_default.jetty_default = jetty_default;

	return 0;
}

void ubaseproxy_uninit_ue_jetty_ctx_default(struct ubaseproxy_dev *udev)
{
	kfree(udev->caps.ue_default.jetty_default);
	udev->caps.ue_default.jetty_default = NULL;
}
