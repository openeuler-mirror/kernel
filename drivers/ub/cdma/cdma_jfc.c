// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/delay.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "cdma_cmd.h"
#include "cdma_context.h"
#include "cdma_mbox.h"
#include "cdma_common.h"
#include "cdma_event.h"
#include "cdma_db.h"
#include "cdma_jfs.h"
#include "cdma_jfc.h"

static int cdma_get_cmd_from_user(struct cdma_create_jfc_ucmd *ucmd,
				  struct cdma_dev *cdev,
				  struct cdma_udata *udata,
				  struct cdma_jfc *jfc,
				  struct cdma_jfc_cfg *cfg)
{
	struct cdma_context *ctx;
	u32 depth = cfg->depth;
	int ret;

	if (!udata) {
		jfc->arm_sn = 1;
		jfc->buf.entry_cnt = depth ? roundup_pow_of_two(depth) : depth;
		return 0;
	}

	if (!udata->udrv_data || !udata->udrv_data->in_addr ||
		udata->udrv_data->in_len != (u32)sizeof(*ucmd)) {
		dev_err(cdev->dev, "invalid parameter\n");
		return -EINVAL;
	}

	ret = (int)copy_from_user(ucmd, (void *)udata->udrv_data->in_addr,
				  (u32)sizeof(*ucmd));
	if (ret) {
		dev_err(cdev->dev,
			"copy udata from user failed, ret = %d\n", ret);
		return -EFAULT;
	}

	jfc->mode = ucmd->mode;
	jfc->db.db_addr = ucmd->db_addr;

	ctx = udata->uctx;
	jfc->base.ctx = ctx;
	jfc->base.jfae = udata->jfae;
	jfc->tid = ctx->tid;

	if (cdev->caps.cqe_size == CDMA_DEFAULT_CQE_SIZE)
		jfc->buf.entry_cnt = ucmd->buf_len >> CDMA_JFC_DEFAULT_CQE_SHIFT;
	else
		jfc->buf.entry_cnt = ucmd->buf_len >> CDMA_JFC_OTHER_CQE_SHIFT;

	return ret;
}

static int cdma_check_jfc_cfg(struct cdma_dev *cdev, struct cdma_jfc *jfc,
			      struct cdma_jfc_cfg *cfg)
{
	if (!jfc->buf.entry_cnt || jfc->buf.entry_cnt > cdev->caps.jfc.depth) {
		dev_err(cdev->dev, "invalid jfc depth = %u, cap depth = %u\n",
			jfc->buf.entry_cnt, cdev->caps.jfc.depth);
		return -EINVAL;
	}

	if (jfc->buf.entry_cnt < CDMA_JFC_DEPTH_MIN)
		jfc->buf.entry_cnt = CDMA_JFC_DEPTH_MIN;

	if (cfg->ceqn >= cdev->caps.comp_vector_cnt) {
		dev_err(cdev->dev, "invalid ceqn = %u, cap ceq cnt = %u\n",
			cfg->ceqn, cdev->caps.comp_vector_cnt);
		return -EINVAL;
	}

	return 0;
}

static void cdma_init_jfc_param(struct cdma_jfc_cfg *cfg, struct cdma_jfc *jfc)
{
	jfc->base.id = jfc->jfcn;
	jfc->base.jfc_cfg = *cfg;
	jfc->base.jfc_event.jfce = NULL;
	jfc->ceqn = cfg->ceqn;
}

static int cdma_jfc_id_alloc(struct cdma_dev *cdev, struct cdma_jfc *jfc)
{
	struct cdma_table *jfc_tbl = &cdev->jfc_table;
	u32 min = jfc_tbl->idr_tbl.min;
	u32 max = jfc_tbl->idr_tbl.max;
	unsigned long flags;
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&jfc_tbl->lock, flags);
	id = idr_alloc(&jfc_tbl->idr_tbl.idr, jfc, jfc_tbl->idr_tbl.next, max,
		       GFP_NOWAIT);
	if (id < 0) {
		id = idr_alloc(&jfc_tbl->idr_tbl.idr, jfc, min, max,
			       GFP_NOWAIT);
		if (id < 0)
			dev_err(cdev->dev, "alloc jfc id failed\n");
	}

	jfc_tbl->idr_tbl.next = (id >= 0 && id + 1 <= max) ? id + 1 : min;
	spin_unlock_irqrestore(&jfc_tbl->lock, flags);
	idr_preload_end();

	jfc->jfcn = id;

	return id;
}

static void cdma_jfc_id_free(struct cdma_dev *cdev, u32 jfcn)
{
	struct cdma_table *jfc_tbl = &cdev->jfc_table;
	unsigned long flags;

	spin_lock_irqsave(&jfc_tbl->lock, flags);
	idr_remove(&jfc_tbl->idr_tbl.idr, jfcn);
	spin_unlock_irqrestore(&jfc_tbl->lock, flags);
}

static int cdma_get_jfc_buf(struct cdma_dev *cdev,
			    struct cdma_create_jfc_ucmd *ucmd,
			    struct cdma_udata *udata, struct cdma_jfc *jfc)
{
	u32 size;
	int ret;

	if (udata) {
		jfc->buf.umem = cdma_umem_get(cdev, ucmd->buf_addr,
					      ucmd->buf_len, false,
					      jfc->base.ctx);
		if (IS_ERR(jfc->buf.umem)) {
			ret = PTR_ERR(jfc->buf.umem);
			dev_err(cdev->dev, "get umem failed, ret = %d\n",
				ret);
			return ret;
		}
		jfc->buf.addr = ucmd->buf_addr;
		ret = cdma_pin_sw_db(jfc->base.ctx, &jfc->db);
		if (ret)
			cdma_put_umem(jfc->buf.umem, false);

		return ret;
	}

	spin_lock_init(&jfc->lock);
	jfc->buf.entry_size = cdev->caps.cqe_size;
	jfc->tid = cdev->tid;
	size = jfc->buf.entry_size * jfc->buf.entry_cnt;
	ret = cdma_k_alloc_buf(cdev, size, &jfc->buf);
	if (ret) {
		dev_err(cdev->dev, "alloc buffer for jfc failed\n");
		return ret;
	}

	ret = cdma_alloc_sw_db(cdev, &jfc->db);
	if (ret) {
		dev_err(cdev->dev, "alloc sw db for jfc failed: %u\n",
			jfc->jfcn);
		cdma_k_free_buf(cdev, &jfc->buf);
	}

	return ret;
}

static void cdma_free_jfc_buf(struct cdma_dev *cdev, struct cdma_jfc *jfc)
{
	if (!jfc->buf.kva) {
		cdma_unpin_sw_db(jfc->base.ctx, &jfc->db);
		cdma_put_umem(jfc->buf.umem, false);
	} else {
		cdma_k_free_buf(cdev, &jfc->buf);
		cdma_free_sw_db(cdev, &jfc->db);
	}
}

static void cdma_construct_jfc_ctx(struct cdma_dev *cdev,
				   struct cdma_jfc *jfc,
				   struct cdma_jfc_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->state = CDMA_JFC_STATE_VALID;
	ctx->arm_st = jfc_arm_mode ? CDMA_CTX_NO_ARMED : CDMA_CTX_ALWAYS_ARMED;
	ctx->shift = ilog2(jfc->buf.entry_cnt) - CDMA_JFC_DEPTH_SHIFT_BASE;

	if (cdev->caps.cqe_size == CDMA_DEFAULT_CQE_SIZE)
		ctx->cqe_size = CDMA_128_CQE_SIZE;
	else
		ctx->cqe_size = CDMA_64_CQE_SIZE;

	ctx->record_db_en = CDMA_RECORD_EN;
	ctx->jfc_type = CDMA_NORMAL_JFC_TYPE;
	ctx->cqe_va_l = jfc->buf.addr >> CQE_VA_L_OFFSET;
	ctx->cqe_va_h = jfc->buf.addr >> CQE_VA_H_OFFSET;
	ctx->hw_ver_0.cqe_token_id = jfc->tid;

	if (cqe_mode)
		ctx->hw_ver_0.cq_cnt_mode = CDMA_CQE_CNT_MODE_BY_CI_PI_GAP;
	else
		ctx->hw_ver_0.cq_cnt_mode = CDMA_CQE_CNT_MODE_BY_COUNT;

	if (cdev->hw_ver == UBASE_HW_VER_K_1 || cdev->hw_ver == UBASE_HW_VER_A_1)
		ctx->hw_ver_1.ceqn = jfc->ceqn;
	else
		ctx->hw_ver_0.ceqn = jfc->ceqn;

	ctx->record_db_addr_l = jfc->db.db_addr >> CDMA_DB_L_OFFSET;
	ctx->record_db_addr_h = jfc->db.db_addr >> CDMA_DB_H_OFFSET;
}

static int cdma_query_jfc_destroy_done(struct cdma_dev *cdev, uint32_t jfcn)
{
	struct ubase_mbx_attr attr = { 0 };
	struct ubase_cmd_mailbox *mailbox;
	struct cdma_jfc_ctx *jfc_ctx;
	int ret;

	cdma_fill_mbx_attr(&attr, jfcn, CDMA_CMD_QUERY_JFC_CONTEXT, 0);
	mailbox = cdma_mailbox_query_ctx(cdev, &attr);
	if (!mailbox)
		return -ENOMEM;

	jfc_ctx = mailbox->buf;
	ret = jfc_ctx->pi == jfc_ctx->wr_cqe_idx ? 0 : -EAGAIN;

	cdma_free_cmd_mailbox(cdev, mailbox);

	return ret;
}

static int cdma_post_destroy_jfc_mbox(struct cdma_dev *cdev, u32 jfcn,
				      enum cdma_jfc_state state)
{
	struct ubase_mbx_attr attr = { 0 };
	struct cdma_jfc_ctx ctx = { 0 };

	ctx.state = state;
	cdma_fill_mbx_attr(&attr, jfcn, CDMA_CMD_DESTROY_JFC_CONTEXT, 0);

	return cdma_post_mailbox_ctx(cdev, (void *)&ctx, sizeof(ctx), &attr);
}

static int cdma_destroy_and_flush_jfc(struct cdma_dev *cdev,
				      struct cdma_jfc *jfc)
{
#define QUERY_MAX_TIMES 5
	struct cdma_context *ctx = jfc->base.ctx;
	u32 jfcn = jfc->jfcn;
	u32 wait_times = 0;
	int ret;

	if (cdev->status == CDMA_INVALID || (ctx && ctx->invalid)) {
		dev_info(cdev->dev,
			 "resetting ignore jfc ctx, jfcn = %u\n", jfcn);
		return 0;
	}

	ret = cdma_post_destroy_jfc_mbox(cdev, jfcn, CDMA_JFC_STATE_INVALID);
	if (ret) {
		dev_err(cdev->dev, "post mbox to destroy jfc failed, id: %u\n",
			jfcn);
		return ret;
	}

	while (true) {
		if (!cdma_query_jfc_destroy_done(cdev, jfcn))
			return 0;
		if (wait_times > QUERY_MAX_TIMES)
			break;
		msleep(1 << wait_times);
		wait_times++;
	}
	dev_err(cdev->dev, "jfc flush time out, id = %u\n", jfcn);

	return -ETIMEDOUT;
}

static inline void *cdma_get_buf_entry(struct cdma_buf *buf, u32 n)
{
	uint32_t entry_index = n & buf->entry_cnt_mask;

	return (char *)buf->kva + (entry_index * buf->entry_size);
}

static struct cdma_jfc_cqe *cdma_get_next_cqe(struct cdma_jfc *jfc, u32 n)
{
	struct cdma_jfc_cqe *cqe;
	u32 valid_owner;

	cqe = (struct cdma_jfc_cqe *)cdma_get_buf_entry(&jfc->buf, n);
	valid_owner = (jfc->ci >> jfc->buf.entry_cnt_mask_ilog2) &
		      CDMA_JFC_DB_VALID_OWNER_M;
	if (!(cqe->owner ^ valid_owner))
		return NULL;

	return cqe;
}

static struct cdma_jetty_queue *cdma_update_jetty_idx(struct cdma_jfc_cqe *cqe)
{
	struct cdma_jetty_queue *queue;
	u32 entry_idx;

	entry_idx = cqe->entry_idx;
	queue = (struct cdma_jetty_queue *)((u64)cqe->user_data_h <<
		CDMA_ADDR_SHIFT | cqe->user_data_l);
	if (!queue)
		return NULL;

	if (!!cqe->fd)
		return queue;

	queue->ci += (entry_idx - queue->ci) & (queue->buf.entry_cnt - 1);

	return queue;
}

static enum jfc_poll_state cdma_get_cr_status(u8 src_status,
					      u8 substatus,
					      enum dma_cr_status *dst_status)
{
struct cdma_cqe_status {
	bool is_valid;
	enum dma_cr_status cr_status;
};

	static struct cdma_cqe_status map[CDMA_CQE_STATUS_NUM][CDMA_CQE_SUB_STATUS_NUM] = {
		{{true, DMA_CR_SUCCESS}, {false, DMA_CR_SUCCESS}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}, {false, DMA_CR_SUCCESS}},
		{{true, DMA_CR_UNSUPPORTED_OPCODE_ERR}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}},
		{{false, DMA_CR_SUCCESS}, {true, DMA_CR_LOC_LEN_ERR},
		 {true, DMA_CR_LOC_ACCESS_ERR}, {true, DMA_CR_REM_RESP_LEN_ERR},
		 {true, DMA_CR_LOC_DATA_POISON}},
		{{false, DMA_CR_SUCCESS}, {true, DMA_CR_REM_UNSUPPORTED_REQ_ERR},
		 {true, DMA_CR_REM_ACCESS_ABORT_ERR}, {false, DMA_CR_SUCCESS},
		 {true, DMA_CR_REM_DATA_POISON}},
		{{true, DMA_CR_RNR_RETRY_CNT_EXC_ERR}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}},
		{{true, DMA_CR_ACK_TIMEOUT_ERR}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}},
		{{true, DMA_CR_WR_FLUSH_ERR}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}, {false, DMA_CR_SUCCESS},
		 {false, DMA_CR_SUCCESS}}
	};

	if ((src_status < CDMA_CQE_STATUS_NUM) && (substatus < CDMA_CQE_SUB_STATUS_NUM) &&
		map[src_status][substatus].is_valid) {
		*dst_status = map[src_status][substatus].cr_status;
		return JFC_OK;
	}

	return JFC_POLL_ERR;
}

static enum jfc_poll_state cdma_update_flush_cr(struct cdma_jetty_queue *queue,
						struct cdma_jfc_cqe *cqe,
						struct dma_cr *cr)
{
	if (cdma_get_cr_status(cqe->status, cqe->substatus, &cr->status))
		return JFC_POLL_ERR;

	if (cqe->fd) {
		cr->status = DMA_CR_WR_FLUSH_ERR_DONE;
		queue->flush_flag = true;
	} else {
		queue->ci++;
	}

	return JFC_OK;
}

static enum jfc_poll_state cdma_parse_cqe_for_jfc(struct cdma_dev *cdev,
						  struct cdma_jfc_cqe *cqe,
						  struct dma_cr *cr)
{
	struct cdma_jetty_queue *queue;
	struct cdma_jfs *jfs;

	queue = cdma_update_jetty_idx(cqe);
	if (!queue) {
		dev_err(cdev->dev, "update jetty idx failed\n");
		return JFC_POLL_ERR;
	}

	jfs = container_of(queue, struct cdma_jfs, sq);
	cr->flag.bs.s_r = cqe->s_r;
	cr->flag.bs.jetty = cqe->is_jetty;
	cr->completion_len = cqe->byte_cnt;
	cr->tpn = cqe->tpn;
	cr->local_id = cqe->local_num_h << CDMA_SRC_IDX_SHIFT | cqe->local_num_l;
	cr->remote_id = cqe->rmt_idx;

	if (cqe->status)
		dev_warn(cdev->dev,
			 "get sq %u cqe status abnormal, ci = %u, pi = %u, status = %u, substatus = %u\n",
			 queue->id, queue->ci, queue->pi, cqe->status, cqe->substatus);

	if (cdma_update_flush_cr(queue, cqe, cr)) {
		dev_err(cdev->dev,
			"update cr failed, status = %u, substatus = %u\n",
			cqe->status, cqe->substatus);
		return JFC_POLL_ERR;
	}

	return JFC_OK;
}

static enum jfc_poll_state cdma_poll_one(struct cdma_dev *cdev,
					 struct cdma_jfc *jfc,
					 struct dma_cr *cr)
{
	enum dma_cr_status status;
	struct cdma_jfc_cqe *cqe;

	cqe = cdma_get_next_cqe(jfc, jfc->ci);
	if (!cqe)
		return JFC_EMPTY;

	++jfc->ci;
	/* Ensure that the reading of the event is completed before parsing. */
	rmb();

	if (cdma_parse_cqe_for_jfc(cdev, cqe, cr))
		return JFC_POLL_ERR;

	status = cr->status;
	if (status == DMA_CR_WR_FLUSH_ERR_DONE || status == DMA_CR_WR_SUSPEND_DONE) {
		dev_info(cdev->dev, "poll cr flush/suspend done, jfc id = %u, status = %u\n",
			 jfc->jfcn, status);
		return JFC_EMPTY;
	}

	return JFC_OK;
}

static void cdma_release_jfc_event(struct cdma_jfc *jfc)
{
	cdma_release_comp_event(jfc->base.jfc_event.jfce,
			&jfc->base.jfc_event.comp_event_list);
	cdma_release_async_event(jfc->base.jfae,
		&jfc->base.jfc_event.async_event_list);
}

static int cdma_post_create_jfc_mbox(struct cdma_dev *cdev, struct cdma_jfc *jfc)
{
	struct ubase_mbx_attr attr = { 0 };
	struct cdma_jfc_ctx ctx = { 0 };

	cdma_construct_jfc_ctx(cdev, jfc, &ctx);
	cdma_fill_mbx_attr(&attr, jfc->jfcn, CDMA_CMD_CREATE_JFC_CONTEXT, 0);

	return cdma_post_mailbox_ctx(cdev, (void *)&ctx, sizeof(ctx), &attr);
}

struct cdma_base_jfc *cdma_create_jfc(struct cdma_dev *cdev,
				      struct cdma_jfc_cfg *cfg,
				      struct cdma_udata *udata)
{
	struct cdma_create_jfc_ucmd ucmd = { 0 };
	struct cdma_jfc *jfc;
	int ret;

	jfc = kzalloc(sizeof(*jfc), GFP_KERNEL);
	if (!jfc)
		return NULL;

	ret = cdma_get_cmd_from_user(&ucmd, cdev, udata, jfc, cfg);
	if (ret)
		goto err_get_cmd;

	ret = cdma_check_jfc_cfg(cdev, jfc, cfg);
	if (ret)
		goto err_check_cfg;

	ret = cdma_jfc_id_alloc(cdev, jfc);
	if (ret < 0)
		goto err_alloc_jfc_id;

	cdma_init_jfc_param(cfg, jfc);
	ret = cdma_get_jfc_buf(cdev, &ucmd, udata, jfc);
	if (ret)
		goto err_get_jfc_buf;

	if (udata) {
		ret = cdma_get_jfae_ref(jfc->base.jfae);
		if (ret)
			goto err_get_jfae;
	}

	ret = cdma_post_create_jfc_mbox(cdev, jfc);
	if (ret)
		goto err_alloc_cqc;

	refcount_set(&jfc->event_refcount, 1);
	init_completion(&jfc->event_comp);
	jfc->base.jfae_handler = cdma_jfc_async_event_cb;
	jfc->base.jfce_handler = cdma_jfc_comp_event_cb;
	jfc->base.dev = cdev;

	dev_info(cdev->dev, "create jfc, id = %u, queue id = %u\n",
		 jfc->jfcn, cfg->queue_id);

	return &jfc->base;

err_alloc_cqc:
	if (udata)
		cdma_put_jfae_ref(jfc->base.jfae);
err_get_jfae:
	cdma_free_jfc_buf(cdev, jfc);
err_get_jfc_buf:
	cdma_jfc_id_free(cdev, jfc->jfcn);
err_alloc_jfc_id:
err_check_cfg:
err_get_cmd:
	kfree(jfc);
	return NULL;
}

int cdma_delete_jfc(struct cdma_dev *cdev, u32 jfcn,
		    struct cdma_cmd_delete_jfc_args *arg)
{
	struct cdma_jfc_event *jfc_event;
	struct cdma_table *jfc_tbl;
	struct cdma_jfc *jfc;
	unsigned long flags;
	int ret;

	if (!cdev)
		return -EINVAL;

	if (jfcn >= cdev->caps.jfc.max_cnt + cdev->caps.jfc.start_idx ||
		jfcn < cdev->caps.jfc.start_idx) {
		dev_err(cdev->dev,
			"jfc id invalid, jfcn = %u, start_idx = %u, max_cnt = %u\n",
			jfcn, cdev->caps.jfc.start_idx, cdev->caps.jfc.max_cnt);
		return -EINVAL;
	}

	jfc_tbl = &cdev->jfc_table;
	spin_lock_irqsave(&jfc_tbl->lock, flags);
	jfc = idr_find(&jfc_tbl->idr_tbl.idr, jfcn);
	if (jfc)
		idr_remove(&jfc_tbl->idr_tbl.idr, jfcn);
	spin_unlock_irqrestore(&jfc_tbl->lock, flags);
	if (!jfc) {
		dev_err(cdev->dev, "find jfc failed, jfcn = %u\n", jfcn);
		return -EINVAL;
	}

	ret = cdma_destroy_and_flush_jfc(cdev, jfc);
	if (ret)
		dev_err(cdev->dev, "jfc delete failed, jfcn = %u, ret = %d\n",
			jfcn, ret);

	if (refcount_dec_and_test(&jfc->event_refcount))
		complete(&jfc->event_comp);
	wait_for_completion(&jfc->event_comp);

	cdma_free_jfc_buf(cdev, jfc);
	if (arg) {
		jfc_event = &jfc->base.jfc_event;
		arg->out.comp_events_reported = jfc_event->comp_events_reported;
		arg->out.async_events_reported = jfc_event->async_events_reported;
	}

	dev_info(cdev->dev, "delete jfc, id = %u\n", jfc->jfcn);

	cdma_release_jfc_event(jfc);
	kfree(jfc);

	return 0;
}

int cdma_jfc_completion(struct notifier_block *nb, unsigned long jfcn,
			void *data)
{
	struct auxiliary_device *adev = (struct auxiliary_device *)data;
	struct cdma_base_jfc *base_jfc;
	struct cdma_table *jfc_tbl;
	struct cdma_dev *cdev;
	struct cdma_jfc *jfc;
	unsigned long flags;

	if (!adev)
		return -EINVAL;

	cdev = get_cdma_dev(adev);
	jfc_tbl = &cdev->jfc_table;
	spin_lock_irqsave(&jfc_tbl->lock, flags);
	jfc = idr_find(&jfc_tbl->idr_tbl.idr, jfcn);
	if (!jfc) {
		dev_warn(cdev->dev, "can not find jfc, jfcn = %lu\n", jfcn);
		spin_unlock_irqrestore(&jfc_tbl->lock, flags);
		return -EINVAL;
	}

	++jfc->arm_sn;
	base_jfc = &jfc->base;
	if (base_jfc->jfce_handler) {
		refcount_inc(&jfc->event_refcount);
		spin_unlock_irqrestore(&jfc_tbl->lock, flags);
		base_jfc->jfce_handler(base_jfc);
		if (refcount_dec_and_test(&jfc->event_refcount))
			complete(&jfc->event_comp);
	} else {
		spin_unlock_irqrestore(&jfc_tbl->lock, flags);
	}

	return 0;
}

/* thanks to drivers/infiniband/hw/bnxt_re/ib_verbs.c */
int cdma_poll_jfc(struct cdma_base_jfc *base_jfc, int cr_cnt,
		  struct dma_cr *cr)
{
	struct cdma_jfc *jfc = to_cdma_jfc(base_jfc);
	enum jfc_poll_state err = JFC_OK;
	int npolled = 0;

	jfc->buf.entry_cnt_mask = jfc->buf.entry_cnt - 1;
	jfc->buf.entry_cnt_mask_ilog2 = ilog2(jfc->buf.entry_cnt);

	spin_lock(&jfc->lock);

	for (npolled = 0; npolled < cr_cnt; ++npolled) {
		err = cdma_poll_one(base_jfc->dev, jfc, cr + npolled);
		if (err != JFC_OK)
			break;
	}

	if (npolled)
		*jfc->db.db_record = jfc->ci & (u32)CDMA_JFC_DB_CI_IDX_M;

	spin_unlock(&jfc->lock);

	return err == JFC_POLL_ERR ? -CDMA_INTER_ERR : npolled;
}
