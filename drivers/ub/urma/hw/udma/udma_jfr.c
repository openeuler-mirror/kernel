// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <uapi/ub/urma/udma/udma_abi.h>
#include "udma_cmd.h"
#include "udma_jetty.h"
#include "udma_common.h"
#include "udma_db.h"
#include "udma_jfc.h"
#include "udma_jfr.h"

const char *state_str[] = {
	"RESET",
	"READY",
	"ERROR",
	"INVALID"
};

static const char *to_state_str(enum ubcore_jfr_state state)
{
	if ((int)state >= (int)JFR_STATE_NUM)
		return state_str[JFR_STATE_NUM];

	return state_str[state];
}

static int udma_verify_jfr_param(struct udma_dev *dev,
				 struct ubcore_jfr_cfg *cfg)
{
	if (!cfg->max_sge || !cfg->depth ||
	    roundup_pow_of_two(cfg->depth) > dev->caps.jfr.depth ||
	    roundup_pow_of_two(cfg->max_sge) > dev->caps.jfr_sge) {
		dev_err(dev->dev, "Invalid jfr param, depth = %u, max_sge = %u.\n",
			cfg->depth, cfg->max_sge);
		return -EINVAL;
	}

	if (cfg->flag.bs.token_policy > UBCORE_TOKEN_PLAIN_TEXT) {
		dev_err(dev->dev, "jfr key policy = %d is not supported now.\n",
			cfg->flag.bs.token_policy);
		return -EINVAL;
	}

	return 0;
}

static int udma_get_k_jfr_buf(struct udma_dev *dev, struct udma_jfr *jfr)
{
	uint32_t idx_buf_size;
	int ret;

	jfr->rq.buf.entry_size = UDMA_SGE_SIZE * min(jfr->max_sge, dev->caps.jfr_sge);
	jfr->rq.buf.entry_cnt = jfr->wqe_cnt;

	if (!jfr->rq.cstm) {
		ret = udma_k_alloc_buf(dev, &jfr->rq.buf);
		if (ret) {
			dev_err(dev->dev, "failed to alloc rq buffer, id=%u.\n", jfr->rq.id);
			return ret;
		}
	}
	jfr->idx_que.buf.entry_size = UDMA_IDX_QUE_ENTRY_SZ;
	jfr->idx_que.buf.entry_cnt = jfr->wqe_cnt;
	idx_buf_size = jfr->idx_que.buf.entry_size * jfr->idx_que.buf.entry_cnt;
	ret = udma_alloc_normal_buf(dev, idx_buf_size, &jfr->idx_que.buf);
	if (ret) {
		dev_err(dev->dev,
			"failed to alloc idx que buffer for jfr when buffer size = %u.\n",
			idx_buf_size);
		goto err_idx_que;
	}

	jfr->rq.wrid = kcalloc(1, jfr->rq.buf.entry_cnt * sizeof(uint64_t), GFP_KERNEL);
	if (!jfr->rq.wrid)
		goto err_wrid;

	jfr->jetty_addr = (uintptr_t)&jfr->rq;

	if (udma_alloc_sw_db(dev, &jfr->sw_db, UDMA_JFR_TYPE_DB)) {
		dev_err(dev->dev, "failed to alloc sw db for jfr(%u).\n", jfr->rq.id);
		goto err_alloc_db;
	}

	udma_init_udma_table(&jfr->idx_que.jfr_idx_table, jfr->idx_que.buf.entry_cnt - 1, 0, false);

	jfr->rq.tid = dev->tid;

	return 0;

err_alloc_db:
	kfree(jfr->rq.wrid);
err_wrid:
	udma_free_normal_buf(dev, idx_buf_size, &jfr->idx_que.buf);
err_idx_que:
	if (!jfr->rq.cstm)
		udma_k_free_buf(dev, &jfr->rq.buf);

	return -ENOMEM;
}

static int udma_jfr_get_u_cmd(struct udma_dev *dev, struct ubcore_udata *udata,
			      struct udma_create_jetty_ucmd *ucmd)
{
	unsigned long byte;

	if (!udata->udrv_data) {
		dev_err(dev->dev, "jfr udata udrv_data is null.\n");
		return -EINVAL;
	}

	if (!udata->udrv_data->in_addr || udata->udrv_data->in_len != sizeof(*ucmd)) {
		dev_err(dev->dev, "jfr in_len %u or addr is invalid.\n",
			udata->udrv_data->in_len);
		return -EINVAL;
	}

	byte = copy_from_user(ucmd, (void *)(uintptr_t)udata->udrv_data->in_addr,
			      sizeof(*ucmd));
	if (byte) {
		dev_err(dev->dev,
			"failed to copy jfr udata, byte = %lu.\n", byte);
		return -EFAULT;
	}

	return 0;
}

static int udma_u_alloc_jfr_buf(struct udma_dev *dev, struct udma_jfr *jfr,
				struct udma_create_jetty_ucmd *ucmd)
{
	int ret = 0;

	if (ucmd->is_hugepage) {
		if (!udma_alloc_u_hugepage(jfr->udma_ctx, jfr->rq.buf.addr, jfr->rq.buf.len)) {
			dev_err(dev->dev, "failed to create rq.\n");
			return -ENOMEM;

		}
		jfr->rq.buf.is_hugepage = true;
	} else {
		jfr->rq.buf.page_priv =
			udma_get_map_page_priv(jfr->udma_ctx, jfr->rq.buf.addr, ucmd->buf_len);
		if (jfr->rq.buf.page_priv == NULL) {
			dev_err(dev->dev, "failed to get rq page.\n");
			return -EINVAL;
		}
	}

	jfr->idx_que.buf.page_priv =
		udma_get_map_page_priv(jfr->udma_ctx, jfr->idx_que.buf.addr, ucmd->idx_len);
	if (jfr->idx_que.buf.page_priv == NULL) {
		dev_err(dev->dev, "failed to get idx que page.\n");
		ret = -EINVAL;
		goto err_get_idx_buf;
	}

	jfr->sw_db.page_priv = udma_get_sw_db(jfr->udma_ctx, jfr->sw_db.db_addr);
	if (jfr->sw_db.page_priv == NULL) {
		dev_err(dev->dev, "failed to get sw db page.\n");
		ret = -EINVAL;
		goto err_get_sw_db;
	}

	return ret;
err_get_sw_db:
	udma_put_map_page_priv(jfr->udma_ctx, jfr->idx_que.buf.page_priv);
err_get_idx_buf:
	if (ucmd->is_hugepage)
		udma_free_u_hugepage(jfr->udma_ctx, jfr->rq.buf.addr);
	else
		udma_put_map_page_priv(jfr->udma_ctx, jfr->rq.buf.page_priv);

	return ret;
}

static int udma_get_u_jfr_buf(struct udma_dev *dev, struct udma_jfr *jfr,
			      struct ubcore_udata *udata,
			      struct udma_create_jetty_ucmd *ucmd)
{
	int ret;

	ret = udma_jfr_get_u_cmd(dev, udata, ucmd);
	if (ret)
		return ret;

	jfr->udma_ctx = to_udma_context(udata->uctx);
	jfr->idx_que.buf.addr = ucmd->idx_addr;
	jfr->sw_db.db_addr = ucmd->db_addr;
	jfr->jfr_sleep_buf.db_addr = ucmd->jfr_sleep_buf;
	jfr->jetty_addr = ucmd->jetty_addr;
	jfr->rq.buf.addr = ucmd->buf_addr;
	jfr->rq.buf.len = ucmd->buf_len;
	jfr->rq.tid = jfr->udma_ctx->tid;

	if (ucmd->non_pin && dev->caps.sva_sep_mode_en) {
		dev_err(dev->dev, "sep mode not support non_pin.\n");
		return -EINVAL;
	}

	if (likely(jfr->jfr_sleep_buf.db_addr)) {
		ret = udma_pin_sw_db(jfr->udma_ctx, &jfr->jfr_sleep_buf);
		if (ret) {
			dev_err(dev->dev, "failed to pin jfr sleep time buf, ret = %d.\n", ret);
			return ret;
		}
	}

	if (ucmd->non_pin) {
		jfr->buff_non_pin = true;
		return 0;
	}

	ret = udma_u_alloc_jfr_buf(dev, jfr, ucmd);
	if (ret) {
		dev_err(dev->dev, "failed to alloc jfr buf, ret = %d.\n", ret);
		goto err_alloc_jfr_buf;
	}

	return ret;

err_alloc_jfr_buf:
	if (likely(jfr->jfr_sleep_buf.db_addr))
		udma_unpin_sw_db(jfr->udma_ctx, &jfr->jfr_sleep_buf, false);
	return ret;
}

static int udma_get_jfr_buf(struct udma_dev *dev, struct udma_jfr *jfr,
			    struct ubcore_udata *udata)
{
	struct udma_create_jetty_ucmd ucmd = {};

	if (udata == NULL)
		return udma_get_k_jfr_buf(dev, jfr);
	else
		return udma_get_u_jfr_buf(dev, jfr, udata, &ucmd);
}

static void udma_put_jfr_buf(struct udma_dev *dev, struct udma_jfr *jfr, bool dirty)
{
	uint32_t size;

	if (jfr->udma_ctx == NULL) {
		if (!jfr->rq.cstm)
			udma_k_free_buf(dev, &jfr->rq.buf);

		udma_free_sw_db(dev, &jfr->sw_db);

		size = jfr->idx_que.buf.entry_cnt * jfr->idx_que.buf.entry_size;
		udma_free_normal_buf(dev, size, &jfr->idx_que.buf);
		udma_destroy_udma_table(dev, &jfr->idx_que.jfr_idx_table, "JFR_IDX");

		kfree(jfr->rq.wrid);
		return;
	}

	if (likely(jfr->jfr_sleep_buf.db_addr))
		udma_unpin_sw_db(jfr->udma_ctx, &jfr->jfr_sleep_buf, dirty);

	if (jfr->buff_non_pin)
		return;

	udma_put_sw_db(jfr->udma_ctx, jfr->sw_db.db_addr);
	udma_put_map_page_priv(jfr->udma_ctx, jfr->idx_que.buf.page_priv);
	if (jfr->rq.buf.is_hugepage)
		udma_free_u_hugepage(jfr->udma_ctx, jfr->rq.buf.addr);
	else
		udma_put_map_page_priv(jfr->udma_ctx, jfr->rq.buf.page_priv);
}

static enum udma_rx_limit_wl to_udma_limit_wl(uint32_t rx_threshold)
{
	if (rx_threshold >= LIMIT_WL_4096_V)
		return UDMA_RX_LIMIT_WL_4096;
	if (rx_threshold >= LIMIT_WL_512_V)
		return UDMA_RX_LIMIT_WL_512;
	if (rx_threshold >= LIMIT_WL_64_V)
		return UDMA_RX_LIMIT_WL_64;

	return UDMA_RX_LIMIT_WL_0;
}

static void udma_init_jfrc(struct udma_dev *dev, struct ubcore_jfr_cfg *cfg,
			   struct udma_jfr *jfr, void *mb_buf,
			   uint32_t rx_threshold)
{
	struct udma_jfr_ctx *ctx = (struct udma_jfr_ctx *)mb_buf;
	struct udma_jfc *jfc = to_udma_jfc(cfg->jfc);
	uint32_t tid = jfr->rq.tid;
	uint64_t db_addr;

	db_addr = jfr->sw_db.db_addr;

	memset(ctx, 0, sizeof(struct udma_jfr_ctx) * UDMA_CTX_NUM);
	ctx->state = UDMA_JFR_STATE_READY;
	ctx->record_db_en = 1;
	ctx->rqe_base_addr_l = (jfr->rq.buf.addr >> RQE_VA_L_PAGE_4K_OFFSET) &
			       (uint32_t)RQE_VA_L_VALID_BIT;
	ctx->rqe_base_addr_h = (jfr->rq.buf.addr >> (uint32_t)RQE_VA_H_PAGE_4K_OFFSET) &
			       (uint32_t)RQE_VA_H_VALID_BIT;
	ctx->idx_que_addr_l = (jfr->idx_que.buf.addr >> JFR_IDX_VA_L_PAGE_4K_OFFSET) &
			      (uint32_t)JFR_IDX_VA_L_VALID_BIT;
	ctx->idx_que_addr_h = (jfr->idx_que.buf.addr >> (uint32_t)JFR_IDX_VA_H_PAGE_4K_OFFSET) &
			      (uint32_t)JFR_IDX_VA_H_VALID_BIT;
	ctx->record_db_addr_l = (db_addr >> JFR_DB_VA_L_PAGE_64_OFFSET) &
				 (uint32_t)JFR_DB_VA_L_VALID_BIT;
	ctx->record_db_addr_m = (db_addr >> (uint32_t)JFR_DB_VA_M_PAGE_64_OFFSET) &
				 (uint32_t)JFR_DB_VA_M_VALID_BIT;
	ctx->record_db_addr_h = (db_addr >> (uint32_t)JFR_DB_VA_H_PAGE_64_OFFSET) &
				 (uint32_t)JFR_DB_VA_H_VALID_BIT;
	ctx->rqe_token_id_l = tid & (uint32_t)RQE_TOKEN_ID_L_MASK;
	ctx->rqe_token_id_h = (tid >> RQE_TOKEN_ID_H_OFFSET) & (uint32_t)RQE_TOKEN_ID_H_MASK;
	ctx->jfcn_l = cfg->jfc->id & (uint32_t)JFR_JFCN_L_VALID_BIT;
	ctx->jfcn_h = (cfg->jfc->id >> JFR_JFCN_H_OFFSET) & (uint32_t)JFR_JFCN_H_VALID_BIT;
	if (cfg->min_rnr_timer > UDMA_RNR_MAX) {
		dev_warn(dev->dev,
			 "min_rnr_timer is out of range, max_value(%d) is applied.\n",
			 UDMA_RNR_MAX);
		ctx->rnr_timer = UDMA_RNR_MAX;
	} else {
		ctx->rnr_timer = cfg->min_rnr_timer;
	}
	if (cfg->flag.bs.token_policy != UBCORE_TOKEN_NONE)
		ctx->token_en = 1;
	ctx->type = to_udma_type(cfg->trans_mode);
	ctx->token_value = cfg->token_value.token;
	ctx->user_data_l = jfr->jetty_addr;
	ctx->user_data_h = jfr->jetty_addr >> UDMA_USER_DATA_H_OFFSET;
	ctx->rqe_size_shift = ilog2(jfr->max_sge);
	ctx->rqe_shift = ilog2(jfr->wqe_cnt);
	if (!!(dev->caps.feature & UDMA_CAP_FEATURE_JFC_INLINE))
		ctx->cqeie = jfc->inline_en;

	ctx->limit_wl = (uint32_t)to_udma_limit_wl(rx_threshold);
	ctx->pld_token_id = tid & (uint32_t)JFR_PLD_TOKEN_ID_MASK;
}

static void udma_reset_sw_k_jfr_queue(struct udma_jfr *jfr)
{
	ida_destroy(&jfr->idx_que.jfr_idx_table.ida_table.ida);
	ida_init(&jfr->idx_que.jfr_idx_table.ida_table.ida);
	jfr->rq.pi = 0;
	jfr->rq.ci = 0;
	*jfr->sw_db.db_record = 0;
}

static int udma_hw_init_jfrc(struct udma_dev *dev, struct ubcore_jfr_cfg *cfg,
			     struct udma_jfr *jfr, uint32_t rx_threshold)
{
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;
	struct udma_jfr_ctx *ctx = NULL;
	int ret;

	mailbox = udma_alloc_cmd_mailbox(dev);
	if (!mailbox) {
		dev_err(dev->dev, "failed to alloc mailbox for JFRC.\n");
		return -ENOMEM;
	}

	udma_init_jfrc(dev, cfg, jfr, mailbox->buf, rx_threshold);

	mbox_attr.tag = jfr->rq.id;
	mbox_attr.op = UDMA_CMD_CREATE_JFR_CONTEXT;
	ret = udma_post_mbox(dev, mailbox, &mbox_attr);
	if (ret)
		dev_err(dev->dev,
			"failed to post mbox cmd of create JFRC, ret = %d.\n",
			ret);

	if (jfr->rq.buf.kva)
		udma_reset_sw_k_jfr_queue(jfr);

	ctx = (struct udma_jfr_ctx *)mailbox->buf;
	ctx->token_value = 0;
	udma_free_cmd_mailbox(dev, mailbox);

	return ret;
}

static void set_jfr_param(struct udma_jfr *jfr, struct ubcore_jfr_cfg *cfg)
{
	if (cfg->depth < UDMA_MIN_JFR_DEPTH)
		jfr->wqe_cnt = UDMA_MIN_JFR_DEPTH;
	else
		jfr->wqe_cnt = roundup_pow_of_two(cfg->depth);

	jfr->ubcore_jfr.jfr_id.id = jfr->rq.id;
	jfr->ubcore_jfr.jfr_cfg = *cfg;
	jfr->max_sge = roundup_pow_of_two(cfg->max_sge);
	jfr->ubcore_jfr.jfr_cfg.max_sge = jfr->max_sge;
	jfr->ubcore_jfr.jfr_cfg.depth = jfr->wqe_cnt;
	jfr->state = UBCORE_JFR_STATE_READY;

	if (!cfg->flag.bs.lock_free)
		spin_lock_init(&jfr->lock);

	jfr->rq.pi = 0;
	jfr->rq.ci = 0;
}

static int udma_alloc_jfr_id(struct udma_dev *udma_dev, uint32_t cfg_id, uint32_t *idx)
{
	struct udma_ida *ida_table = &udma_dev->jfr_table.ida_table;
	uint32_t min;
	uint32_t max;
	int id;

	if (cfg_id && (cfg_id < ida_table->min || cfg_id > ida_table->max)) {
		dev_err(udma_dev->dev,
			"user specify id %u error, min %u max %u.\n",
			cfg_id, ida_table->min, ida_table->max);
		return -EINVAL;
	}

	spin_lock(&ida_table->lock);
	min = cfg_id ? cfg_id : ida_table->next;
	max = cfg_id ? cfg_id : ida_table->max;
	id = ida_alloc_range(&ida_table->ida, min, max, GFP_ATOMIC);
	if (id < 0) {
		if (!cfg_id)
			id = ida_alloc_range(&ida_table->ida, min = ida_table->min,
					     max, GFP_ATOMIC);
		if (id < 0) {
			spin_unlock(&ida_table->lock);
			dev_err(udma_dev->dev,
				"alloc jfr id range (%u - %u) failed, ret = %d.\n",
				min, max, id);
			return id == -ENOSPC ? -ENOSR : id;
		}
	}

	*idx = (uint32_t)id;

	if (!cfg_id)
		ida_table->next = (uint32_t)id + 1 > ida_table->max ?
				  ida_table->min : (uint32_t)id + 1;
	spin_unlock(&ida_table->lock);

	return 0;
}

struct ubcore_jfr *udma_create_jfr(struct ubcore_device *dev,
				   struct ubcore_jfr_cfg *cfg,
				   struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_jfr *udma_jfr;
	int ret;

	ret = udma_verify_jfr_param(udma_dev, cfg);
	if (ret) {
		dev_err(udma_dev->dev, "verify jfr param failed.\n");
		return ERR_PTR(-EINVAL);
	}

	udma_jfr = kzalloc(sizeof(*udma_jfr), GFP_KERNEL);
	if (!udma_jfr)
		return ERR_PTR(-ENOMEM);

	ret = udma_alloc_jfr_id(udma_dev, cfg->id, &udma_jfr->rq.id);
	if (ret)
		goto err_alloc_jfr_id;

	set_jfr_param(udma_jfr, cfg);

	ret = udma_get_jfr_buf(udma_dev, udma_jfr, udata);
	if (ret)
		goto err_get_jfr_buf;

	ret = xa_err(xa_store(&udma_dev->jfr_table.xa, udma_jfr->rq.id,
			      udma_jfr, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "store jfr to jfr_table failed.\n");
		goto err_xa_store;
	}

	ret = udma_hw_init_jfrc(udma_dev, cfg, udma_jfr, 0);
	if (ret) {
		dev_err(udma_dev->dev, "failed to init JFRC, ret = %d.\n", ret);
		goto err_hw_init_jfrc;
	}

	udma_jfr->rq.activated = true;
	refcount_set(&udma_jfr->ae_refcount, 1);
	init_completion(&udma_jfr->ae_comp);

	if (dfx_switch)
		udma_dfx_store_id(udma_dev, &udma_dev->dfx_info->jfr, udma_jfr->rq.id, "jfr");

	return &udma_jfr->ubcore_jfr;

err_hw_init_jfrc:
	xa_erase(&udma_dev->jfr_table.xa, udma_jfr->rq.id);
err_xa_store:
	udma_put_jfr_buf(udma_dev, udma_jfr, false);
err_get_jfr_buf:
	udma_id_free(&udma_dev->jfr_table.ida_table, udma_jfr->rq.id);
err_alloc_jfr_id:
	kfree(udma_jfr);
	return ERR_PTR(ret);
}

static int modify_jfr_context(struct udma_dev *dev, uint32_t jfrn,
			      bool state_flag, bool rx_threshold_flag,
			      struct ubcore_jfr_attr *attr)
{
	struct ubase_mbx_attr mbox_attr = {};
	struct udma_jfr_ctx *ctx, *ctx_mask;
	struct ubase_cmd_mailbox *mailbox;
	int ret;

	mailbox = udma_alloc_cmd_mailbox(dev);
	if (!mailbox) {
		dev_err(dev->dev, "failed to alloc mailbox for JFRC.\n");
		return -EINVAL;
	}

	ctx = (struct udma_jfr_ctx *)mailbox->buf;
	ctx_mask = ctx + 1;
	memset(ctx_mask, 0xff, sizeof(struct udma_jfr_ctx));
	if (state_flag) {
		ctx->state = attr->state;
		ctx_mask->state = 0;
	}

	if (rx_threshold_flag) {
		ctx->limit_wl = (uint32_t)to_udma_limit_wl(attr->rx_threshold);
		ctx_mask->limit_wl = 0;
	}

	mbox_attr.tag = jfrn;
	mbox_attr.op = UDMA_CMD_MODIFY_JFR_CONTEXT;

	ret = udma_post_mbox(dev, mailbox, &mbox_attr);
	if (ret)
		dev_err(dev->dev,
			"failed to post mbox cmd of modify JFRC, ret = %d.\n", ret);

	udma_free_cmd_mailbox(dev, mailbox);

	return ret;
}

static int udma_modify_jfr_to_error(struct ubcore_jfr *jfr, bool *need_sleep)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);
	struct ubcore_jfr_attr attr;
	int ret = 0;

	if (udma_jfr->state == UBCORE_JFR_STATE_READY) {
		attr.state = UBCORE_JFR_STATE_ERROR;
		attr.mask = UBCORE_JFR_STATE;
		ret = modify_jfr_context(udma_dev, udma_jfr->rq.id, true, false, &attr);
		if (ret) {
			dev_err(udma_dev->dev, "failed to modify jfr state to error, id: %u.\n",
				udma_jfr->rq.id);
			return ret;
		}

		udma_jfr->state = UBCORE_JFR_STATE_ERROR;

		*need_sleep = true;
	}

	return ret;
}

static int udma_modify_jfr_to_reset(struct ubcore_jfr *jfr)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);
	struct ubase_mbx_attr mbox_attr = {};
	int ret = 0;

	if (udma_jfr->state != UBCORE_JFR_STATE_RESET) {
		mbox_attr.tag = udma_jfr->rq.id;
		mbox_attr.op = UDMA_CMD_DESTROY_JFR_CONTEXT;
		ret = post_mailbox_update_ctx(udma_dev, NULL, 0, &mbox_attr);
		if (ret) {
			dev_err(udma_dev->dev, "failed to post jfr destroy cmd, id: %u.\n",
				udma_jfr->rq.id);
			return ret;
		}

		udma_jfr->state = UBCORE_JFR_STATE_RESET;
	}

	return ret;
}

static int udma_modify_and_del_jfr(struct udma_dev *udma_dev, struct udma_jfr *udma_jfr)
{
	bool large_payload = false;
	bool need_sleep = false;
	uint32_t sleep_time = 0;
	int ret = 0;

	ret = udma_modify_jfr_to_error(&udma_jfr->ubcore_jfr, &need_sleep);
	if (ret)
		return ret;
	if (!udma_jfr->rq.buf.kva && udma_jfr->jfr_sleep_buf.page)
		large_payload = !!(*(bool *)udma_jfr->jfr_sleep_buf.virt_addr);
	if (need_sleep) {
		sleep_time = large_payload ? jfr_sleep_time : UDMA_DEF_JFR_SLEEP_TIME;
		dev_info_ratelimited(udma_dev->dev, "jfr sleep time = %u us.\n", sleep_time);
		usleep_range(sleep_time, sleep_time + UDMA_SLEEP_DELAY_TIME);
	}

	return udma_modify_jfr_to_reset(&udma_jfr->ubcore_jfr);
}

static void udma_free_jfr_prepare(struct ubcore_jfr *jfr)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);

	if (udma_jfr->rq.buf.kva && jfr->jfr_cfg.jfc)
		udma_clean_jfc(jfr->jfr_cfg.jfc, udma_jfr->rq.id, udma_dev);

	if (dfx_switch)
		udma_dfx_delete_id(udma_dev, &udma_dev->dfx_info->jfr, udma_jfr->rq.id);

	xa_erase(&udma_dev->jfr_table.xa, udma_jfr->rq.id);

	if (refcount_dec_and_test(&udma_jfr->ae_refcount))
		complete(&udma_jfr->ae_comp);
	wait_for_completion(&udma_jfr->ae_comp);
	udma_put_jfr_buf(udma_dev, udma_jfr, true);
	udma_id_free(&udma_dev->jfr_table.ida_table, udma_jfr->rq.id);
	jfr->jfr_cfg.token_value.token = 0;
}

int udma_destroy_jfr(struct ubcore_jfr *jfr)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);
	int ret;

	ret = udma_modify_and_del_jfr(udma_dev, udma_jfr);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to modify and delete jfr, id: %u, ret = %d.\n",
			udma_jfr->rq.id, ret);
		return ret;
	}

	udma_free_jfr_prepare(jfr);
	kfree(jfr);

	return 0;
}

int udma_destroy_jfr_batch(struct ubcore_jfr **jfr, int jfr_cnt, int *bad_jfr_index)
{
	struct udma_jetty_queue **rq_list;
	struct udma_jetty_queue *rq;
	uint32_t active_jfr_cnt = 0;
	bool large_payload = false;
	struct udma_dev *udma_dev;
	struct udma_jfr *udma_jfr;
	bool need_sleep = false;
	uint32_t sleep_time = 0;
	uint32_t i;
	int ret;

	if (!jfr) {
		pr_info("jfr array is null.\n");
		return -EINVAL;
	}

	if (!jfr_cnt) {
		pr_info("jfr cnt is 0.\n");
		return -EINVAL;
	}

	udma_dev = to_udma_dev(jfr[0]->ub_dev);

	rq_list = kcalloc(jfr_cnt, sizeof(*rq_list), GFP_KERNEL);
	if (!rq_list)
		return -ENOMEM;

	for (i = 0; i < jfr_cnt; i++) {
		rq = &(to_udma_jfr(jfr[i])->rq);
		if (rq->activated)
			rq_list[active_jfr_cnt++] = rq;
	}

	for (i = 0; i < active_jfr_cnt; i++) {
		ret = udma_modify_jfr_to_error(&(to_udma_jfr_from_queue(rq_list[i])->ubcore_jfr),
					       &need_sleep);
		if (ret) {
			*bad_jfr_index = 0;
			kfree(rq_list);
			return ret;
		}

		if (unlikely(large_payload))
			continue;
		udma_jfr = to_udma_jfr(&(to_udma_jfr_from_queue(rq_list[i])->ubcore_jfr));
		if (!udma_jfr->rq.buf.kva && udma_jfr->jfr_sleep_buf.page)
			large_payload = !!(*(bool *)udma_jfr->jfr_sleep_buf.virt_addr);
	}

	if (need_sleep) {
		sleep_time = large_payload ? jfr_sleep_time : UDMA_DEF_JFR_SLEEP_TIME;
		dev_info_ratelimited(udma_dev->dev, "jfr sleep time = %u us.\n", sleep_time);
		usleep_range(sleep_time, sleep_time + UDMA_SLEEP_DELAY_TIME);
	}

	for (i = 0; i < active_jfr_cnt; i++) {
		ret = udma_modify_jfr_to_reset(&(to_udma_jfr_from_queue(rq_list[i])->ubcore_jfr));
		if (ret) {
			*bad_jfr_index = 0;
			kfree(rq_list);
			return ret;
		}
	}

	for (i = 0; i < active_jfr_cnt; i++)
		udma_free_jfr_prepare(&(to_udma_jfr_from_queue(rq_list[i])->ubcore_jfr));

	for (i = 0; i < jfr_cnt; i++)
		kfree(jfr[i]);

	kfree(rq_list);

	return 0;
}

static bool verify_modify_jfr_state(enum ubcore_jfr_state jfr_state,
				    enum ubcore_jfr_state attr_state)
{
	switch (jfr_state) {
	case UBCORE_JFR_STATE_RESET:
		return attr_state == UBCORE_JFR_STATE_READY;
	case UBCORE_JFR_STATE_READY:
		return attr_state == UBCORE_JFR_STATE_ERROR;
	case UBCORE_JFR_STATE_ERROR:
		return attr_state == UBCORE_JFR_STATE_RESET;
	default:
		break;
	}

	return false;
}

static int verify_modify_jfr(struct udma_dev *udma_dev, struct udma_jfr *udma_jfr,
			     struct ubcore_jfr_attr *attr, bool *state_flag,
			     bool *rx_threshold_flag)
{
	*rx_threshold_flag = false;
	*state_flag = false;

	if (!(attr->mask & (UBCORE_JFR_RX_THRESHOLD | UBCORE_JFR_STATE))) {
		dev_err(udma_dev->dev,
			"modify jfr mask is error or not set, jfrn = %u.\n",
			udma_jfr->rq.id);
		return -EINVAL;
	}

	if (attr->mask & UBCORE_JFR_RX_THRESHOLD) {
		if (attr->rx_threshold >= udma_jfr->wqe_cnt) {
			dev_err(udma_dev->dev,
				"JFR rx_threshold(%u) must less than wqe num(%u).\n",
				attr->rx_threshold, udma_jfr->wqe_cnt);
			return -EINVAL;
		}
		*rx_threshold_flag = true;
	}

	if (attr->mask & UBCORE_JFR_STATE) {
		if (udma_jfr->state == attr->state) {
			dev_info_ratelimited(udma_dev->dev,
				"jfr(%u) state has been %s, keep it unchanged.\n",
				udma_jfr->rq.id, to_state_str(attr->state));
			return 0;
		} else if (!verify_modify_jfr_state(udma_jfr->state,
						    attr->state)) {
			dev_err(udma_dev->dev,
				"jfr(%u) not support modify jfr state from %s to %s.\n",
				udma_jfr->rq.id, to_state_str(udma_jfr->state),
				to_state_str(attr->state));
			return -EINVAL;
		} else if ((attr->state == UBCORE_JFR_STATE_RESET ||
			    attr->state == UBCORE_JFR_STATE_ERROR) &&
			    *rx_threshold_flag) {
			dev_err(udma_dev->dev,
				"jfr(%u) not support set rx threshold when change state to %s.\n",
				udma_jfr->rq.id, to_state_str(attr->state));
			return -EINVAL;
		}
		*state_flag = true;
	}

	return 0;
}

static int udma_destroy_hw_jfr_ctx(struct udma_dev *dev, uint32_t jfr_id)
{
	struct ubase_mbx_attr attr = {};
	int ret;

	attr.tag = jfr_id;
	attr.op = UDMA_CMD_DESTROY_JFR_CONTEXT;
	ret = post_mailbox_update_ctx(dev, NULL, 0, &attr);
	if (ret)
		dev_err(dev->dev,
			"post mailbox destroy jfr ctx failed, ret = %d.\n", ret);

	return ret;
}

int udma_modify_jfr(struct ubcore_jfr *jfr, struct ubcore_jfr_attr *attr,
		    struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);
	bool rx_threshold_flag = false;
	bool state_flag = false;
	int ret = 0;

	ret = verify_modify_jfr(udma_dev, udma_jfr, attr, &state_flag,
				&rx_threshold_flag);
	if (ret)
		return ret;

	if (!(rx_threshold_flag || state_flag))
		return 0;

	if (rx_threshold_flag && !state_flag) {
		ret = modify_jfr_context(udma_dev, udma_jfr->rq.id, state_flag,
					 rx_threshold_flag, attr);
	} else {
		switch (attr->state) {
		case UBCORE_JFR_STATE_RESET:
			ret = udma_destroy_hw_jfr_ctx(udma_dev, udma_jfr->rq.id);
			break;
		case UBCORE_JFR_STATE_READY:
			ret = udma_hw_init_jfrc(udma_dev, &jfr->jfr_cfg, udma_jfr,
						rx_threshold_flag ?
						attr->rx_threshold : udma_jfr->rx_threshold);
			break;
		default:
			ret = modify_jfr_context(udma_dev, udma_jfr->rq.id, state_flag,
						rx_threshold_flag, attr);
			break;
		}
	}

	if (ret)
		return ret;

	if (state_flag)
		udma_jfr->state = attr->state;

	if (rx_threshold_flag)
		udma_jfr->rx_threshold = attr->rx_threshold;

	return 0;
}

int udma_unimport_jfr(struct ubcore_tjetty *tjfr)
{
	struct udma_target_jetty *udma_tjfr = to_udma_tjetty(tjfr);

	udma_tjfr->token_value = 0;
	tjfr->cfg.token_value.token = 0;

	kfree(udma_tjfr);

	return 0;
}

static void fill_wqe_idx(struct udma_jfr *jfr, uint32_t wqe_idx)
{
	uint32_t *idx_buf;

	idx_buf = (uint32_t *)get_buf_entry(&jfr->idx_que.buf, jfr->rq.pi);
	*idx_buf = cpu_to_le32(wqe_idx);

	jfr->rq.pi++;
}

static void fill_recv_sge_to_wqe(struct ubcore_jfr_wr *wr, void *wqe,
				 uint32_t max_sge)
{
	struct udma_wqe_sge *sge = (struct udma_wqe_sge *)wqe;
	uint32_t i, cnt;

	for (i = 0, cnt = 0; i < wr->src.num_sge; i++) {
		if (!wr->src.sge[i].len)
			continue;
		set_data_of_sge(sge + cnt, wr->src.sge + i);
		++cnt;
	}

	if (cnt < max_sge)
		memset(sge + cnt, 0, (max_sge - cnt) * UDMA_SGE_SIZE);
}

static int post_recv_one(struct udma_dev *dev, struct udma_jfr *jfr,
			 struct ubcore_jfr_wr *wr)
{
	uint32_t wqe_idx;
	int ret = 0;
	void *wqe;

	if (unlikely(wr->src.num_sge > jfr->max_sge)) {
		dev_err(dev->dev,
			"failed to check sge, wr_num_sge = %u, max_sge = %u, jfrn = %u.\n",
			wr->src.num_sge, jfr->max_sge, jfr->rq.id);
		return -EINVAL;
	}

	if (udma_jfrwq_overflow(jfr)) {
		dev_err(dev->dev, "failed to check jfrwq, jfrwq is full, jfrn = %u.\n",
			jfr->rq.id);
		return -ENOMEM;
	}

	ret = udma_id_alloc(dev, &jfr->idx_que.jfr_idx_table.ida_table,
			    &wqe_idx);
	if (ret) {
		dev_err(dev->dev, "failed to get jfr wqe idx.\n");
		return ret;
	}
	wqe = get_buf_entry(&jfr->rq.buf, wqe_idx);

	fill_recv_sge_to_wqe(wr, wqe, jfr->max_sge);

	fill_wqe_idx(jfr, wqe_idx);

	jfr->rq.wrid[wqe_idx] = wr->user_ctx;

	return ret;
}

/* thanks to drivers/infiniband/hw/bnxt_re/ib_verbs.c */
int udma_post_jfr_wr(struct ubcore_jfr *ubcore_jfr, struct ubcore_jfr_wr *wr,
		     struct ubcore_jfr_wr **bad_wr)
{
	struct udma_dev *dev = to_udma_dev(ubcore_jfr->ub_dev);
	struct udma_jfr *jfr = to_udma_jfr(ubcore_jfr);
	unsigned long flags;
	uint32_t nreq;
	int ret = 0;

	if (!ubcore_jfr->jfr_cfg.flag.bs.lock_free)
		spin_lock_irqsave(&jfr->lock, flags);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		ret = post_recv_one(dev, jfr, wr);
		if (ret) {
			*bad_wr = wr;
			break;
		}
	}

	if (likely(nreq)) {
		/*
		 * Ensure that the pipeline fills all RQEs into the RQ queue,
		 * then updating the PI pointer.
		 */
		wmb();
		*jfr->sw_db.db_record = jfr->rq.pi &
					(uint32_t)UDMA_JFR_DB_PI_M;
	}

	if (!ubcore_jfr->jfr_cfg.flag.bs.lock_free)
		spin_unlock_irqrestore(&jfr->lock, flags);

	return ret;
}

struct ubcore_tjetty *udma_import_jfr_ex(struct ubcore_device *dev,
					 struct ubcore_tjetty_cfg *cfg,
					 struct ubcore_active_tp_cfg *active_tp_cfg,
					 struct ubcore_udata *udata)
{
	struct udma_target_jetty *udma_tjfr;

	udma_tjfr = kzalloc(sizeof(*udma_tjfr), GFP_KERNEL);
	if (!udma_tjfr)
		return NULL;

	if (!udata) {
		if (cfg->flag.bs.token_policy != UBCORE_TOKEN_NONE) {
			udma_tjfr->token_value = cfg->token_value.token;
			udma_tjfr->token_value_valid = true;
		}
	}

	udma_swap_endian(cfg->id.eid.raw, udma_tjfr->le_eid.raw, UBCORE_EID_SIZE);

	return &udma_tjfr->ubcore_tjetty;
}

int udma_free_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata)
{
	kfree(jfr);

	return 0;
}

static struct udma_jfr_opt_info opt_k_jfr_table[] = {
	{UBCORE_JFR_DEPTH, sizeof(uint32_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_FLAG, sizeof(uint32_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_TRANS_MODE, sizeof(uint32_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_MAX_SGE, sizeof(uint8_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_MIN_RNR_TIMER, sizeof(uint8_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_BIND_JFC, sizeof(uint64_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_TOKEN_VALUE, sizeof(uint32_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_USER_CTX, sizeof(uint64_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_RQE_BASE_ADDR, sizeof(uint64_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_ID, sizeof(uint32_t), PERM_READ | PERM_WRITE, 0},
	{UBCORE_JFR_DB_ADDR, sizeof(uint64_t), PERM_READ, USER_IGNORE},
	{UBCORE_JFR_DB_STATUS, sizeof(uint8_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_PI, sizeof(uint16_t), PERM_READ, 0},
	{UBCORE_JFR_PI_TYPE, sizeof(uint16_t), PERM_READ | PERM_WRITE, USER_IGNORE},
	{UBCORE_JFR_CI, sizeof(uint16_t), PERM_READ, 0},
};

static int udma_query_jfr_ctx(struct udma_dev *dev, struct udma_jfr_ctx *ctx,
			      uint32_t jfr_id)
{
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;

	mbox_attr.tag = jfr_id;
	mbox_attr.op = UDMA_CMD_QUERY_JFR_CONTEXT;
	mailbox = udma_mailbox_query_ctx(dev, &mbox_attr);
	if (!mailbox) {
		dev_err(dev->dev, "failed to alloc mailbox for JFRC.\n");
		return -ENOMEM;
	}
	memcpy((void *)ctx, mailbox->buf, sizeof(*ctx));

	udma_free_cmd_mailbox(dev, mailbox);

	return 0;
}

static int udma_k_get_jfr_param(struct udma_dev *dev, struct ubcore_jfr *ubcore_jfr,
				uint64_t opt, void *buf)
{
	struct udma_jfr *udma_jfr = to_udma_jfr(ubcore_jfr);
	struct udma_jfr_ctx jfr_ctx = {};
	int ret;

	switch (opt) {
	case UBCORE_JFR_DEPTH:
		*(uint32_t *)buf = ubcore_jfr->jfr_cfg.depth;
		break;
	case UBCORE_JFR_FLAG:
		*(uint32_t *)buf = ubcore_jfr->jfr_cfg.flag.value;
		break;
	case UBCORE_JFR_TRANS_MODE:
		*(uint32_t *)buf = ubcore_jfr->jfr_cfg.trans_mode;
		break;
	case UBCORE_JFR_MAX_SGE:
		*(uint32_t *)buf = ubcore_jfr->jfr_cfg.max_sge;
		break;
	case UBCORE_JFR_MIN_RNR_TIMER:
		*(uint8_t *)buf = ubcore_jfr->jfr_cfg.min_rnr_timer;
		break;
	case UBCORE_JFR_BIND_JFC:
		*(uint64_t *)buf = (uintptr_t)ubcore_jfr->jfr_cfg.jfc;
		break;
	case UBCORE_JFR_TOKEN_VALUE:
		*(uint32_t *)buf = ubcore_jfr->jfr_cfg.token_value.token;
		break;
	case UBCORE_JFR_USER_CTX:
		*(uint32_t *)buf = 0;
		break;
	case UBCORE_JFR_RQE_BASE_ADDR:
		*(uint64_t *)buf = udma_jfr->rq.buf.addr;
		break;
	case UBCORE_JFR_ID:
		*(uint32_t *)buf = udma_jfr->rq.id;
		break;
	case UBCORE_JFR_DB_ADDR:
		*(uint64_t *)buf = (uintptr_t)udma_jfr->rq.db_addr;
		break;
	case UBCORE_JFR_DB_STATUS:
		/* TO DO*/
		break;
	case UBCORE_JFR_PI:
		ret = udma_query_jfr_ctx(dev, &jfr_ctx, udma_jfr->rq.id);
		if (ret) {
			dev_err(dev->dev,
				"failed to query jfr ctx, rq_id = %u, ret = %d.\n",
				udma_jfr->rq.id, ret);
			return ret;
		}
		*(uint16_t *)buf = jfr_ctx.pi;
		break;
	case UBCORE_JFR_PI_TYPE:
		/* TO DO*/
		break;
	case UBCORE_JFR_CI:
		ret = udma_query_jfr_ctx(dev, &jfr_ctx, udma_jfr->rq.id);
		if (ret) {
			dev_err(dev->dev,
				"failed to query jfr ctx, id = %u, ret = %d.\n",
				udma_jfr->rq.id, ret);
			return ret;
		}
		*(uint16_t *)buf = jfr_ctx.ci;
		break;
	default:
		dev_err(dev->dev, "invalid param, opt=%llu.\n", opt);
		return -EINVAL;
	}

	return 0;
}

static int udma_k_set_jfr_param(struct udma_dev *dev, struct ubcore_jfr *ubcore_jfr,
				uint64_t opt, void *buf)
{
	struct udma_jfr *udma_jfr = to_udma_jfr(ubcore_jfr);
	uint64_t addr;

	switch (opt) {
	case UBCORE_JFR_DEPTH:
	case UBCORE_JFR_FLAG:
	case UBCORE_JFR_TRANS_MODE:
	case UBCORE_JFR_MAX_SGE:
	case UBCORE_JFR_MIN_RNR_TIMER:
	case UBCORE_JFR_BIND_JFC:
	case UBCORE_JFR_TOKEN_VALUE:
		break;
	case UBCORE_JFR_RQE_BASE_ADDR:
		addr = *(uint64_t *)buf;
		if (!addr) {
			dev_err(dev->dev, "jfr rqe base addr is null.\n");
			return -EINVAL;
		}
		udma_jfr->rq.buf.addr = addr;
		udma_jfr->rq.buf.kva = (void *)(uintptr_t)udma_jfr->rq.buf.addr;
		udma_jfr->rq.cstm = true;
		break;
	case UBCORE_JFR_ID:
		udma_jfr->rq.id = *(uint32_t *)buf;
		break;
	case UBCORE_JFR_DB_ADDR:
	case UBCORE_JFR_DB_STATUS:
	case UBCORE_JFR_PI_TYPE:
		/* TO DO */
		break;
	default:
		dev_err(dev->dev, "invalid param, opt=%llu.\n", opt);
		return -EINVAL;
	}

	return 0;
}

static int udma_k_check_set_get_jfr_param(uint64_t opt, void *buf, uint32_t len,
					  struct ubcore_udata *udata,
					  enum udma_k_set_get_jfr_opt_perm perm)
{
#define UDMA_K_JFR_GET_JFR_OPT_CNT 15

	if (!buf)
		return -ENOMEM;

	for (size_t i = 0; i < UDMA_K_JFR_GET_JFR_OPT_CNT; i++) {
		if ((opt_k_jfr_table[i].opt == opt) &&
		    (opt_k_jfr_table[i].buf_len == len) &&
		    (opt_k_jfr_table[i].perm & perm))
			return ((opt_k_jfr_table[i].attr & USER_IGNORE) && (udata != NULL)) ?
				-EEXIST : 0;
	}

	return -EINVAL;
}

int udma_alloc_jfr(struct ubcore_device *dev, struct ubcore_jfr_cfg *cfg, struct ubcore_jfr **jfr,
		   struct ubcore_udata *udata)
{
	struct udma_jfr *udma_jfr;

	udma_jfr = kzalloc(sizeof(*udma_jfr), GFP_KERNEL);
	if (!udma_jfr)
		return -EINVAL;

	udma_jfr->ubcore_jfr.jfr_cfg = *cfg;
	*jfr = &udma_jfr->ubcore_jfr;

	return 0;
}

int udma_active_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct ubcore_jfr_opt *jfr_opt = &jfr->jfr_opt;
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);
	struct ubcore_jfr_cfg *cfg = &jfr->jfr_cfg;
	int ret;

	if (udma_verify_jfr_param(udma_dev, cfg))
		return -EINVAL;

	if (udma_alloc_jfr_id(udma_dev, jfr_opt->urma_jfr_id, &udma_jfr->rq.id))
		return -EINVAL;

	set_jfr_param(udma_jfr, cfg);

	ret = udma_get_jfr_buf(udma_dev, udma_jfr, udata);
	if (ret)
		goto err_get_jfr_buf;

#ifdef CONFIG_V121
	if (udma_bind_jfc(udma_dev, cfg->jfc->id, UDMA_RECV_JFC))
		goto err_xa_store;
#endif

	ret = xa_err(xa_store(&udma_dev->jfr_table.xa, udma_jfr->rq.id, udma_jfr, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "failed to store jfr table.\n");
		goto err_xa_store;
	}

	ret = udma_hw_init_jfrc(udma_dev, cfg, udma_jfr, 0);
	if (ret) {
		dev_err(udma_dev->dev, "failed to init jfrc, ret = %d.\n", ret);
		goto err_hw_init_jfrc;
	}

	refcount_set(&udma_jfr->ae_refcount, 1);
	init_completion(&udma_jfr->ae_comp);

	if (dfx_switch)
		udma_dfx_store_id(udma_dev, &udma_dev->dfx_info->jfr, udma_jfr->rq.id, "jfr");
	udma_jfr->rq.activated = true;

	return 0;

err_hw_init_jfrc:
#ifdef CONFIG_V121
	udma_unbind_jfc(udma_dev, cfg->jfc->id, UDMA_RECV_JFC);
#endif
	xa_erase(&udma_dev->jfr_table.xa, udma_jfr->rq.id);
err_xa_store:
	udma_put_jfr_buf(udma_dev, udma_jfr, false);
err_get_jfr_buf:
	udma_id_free(&udma_dev->jfr_table.ida_table, udma_jfr->rq.id);

	return ret;
}

int udma_set_jfr_opt(struct ubcore_jfr *jfr, uint64_t opt, void *buf, uint32_t len,
		     struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	int ret;

	ret = udma_k_check_set_get_jfr_param(opt, buf, len, udata, PERM_WRITE);
	if (ret == -EEXIST)
		return 0;

	if (ret) {
		dev_err(udma_dev->dev, "failed to check opt, len = %u, opt = %llu.\n", len, opt);
		return ret;
	}

	ret = udma_k_set_jfr_param(udma_dev, jfr, opt, buf);
	if (ret)
		dev_err(udma_dev->dev, "failed to get jfr param.\n");

	return ret;
}

int udma_get_jfr_opt(struct ubcore_jfr *jfr, uint64_t opt, void *buf, uint32_t len,
		     struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	int ret;

	ret = udma_k_check_set_get_jfr_param(opt, buf, len, udata, PERM_READ);
	if (ret == -EEXIST)
		return 0;
	if (ret)
		return ret;

	ret = udma_k_get_jfr_param(udma_dev, jfr, opt, buf);
	if (ret)
		dev_err(udma_dev->dev, "failed to get jfr param.\n");

	return ret;
}

int udma_deactive_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);
	int ret;

	if (!udma_jfr->rq.activated) {
		dev_info_ratelimited(udma_dev->dev, "jfr no need deactivate.\n");
		return 0;
	}

	ret = udma_modify_and_del_jfr(udma_dev, udma_jfr);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to deactivate jfr, rq_id = %u, ret = %d.\n",
			udma_jfr->rq.id, ret);
		return ret;
	}

	udma_free_jfr_prepare(jfr);
	udma_jfr->rq.activated = false;

	return 0;
}
