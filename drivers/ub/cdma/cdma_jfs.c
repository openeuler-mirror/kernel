// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define pr_fmt(fmt) "CDMA: " fmt
#define dev_fmt pr_fmt

#include <linux/io.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <uapi/ub/cdma/cdma_abi.h>
#include "cdma_cmd.h"
#include "cdma_common.h"
#include "cdma_mbox.h"
#include "cdma_event.h"
#include "cdma_context.h"
#include "cdma_jfs.h"

static int cdma_get_user_jfs_cmd(struct cdma_dev *cdev, struct cdma_jfs *jfs,
				 struct cdma_udata *udata,
				 struct cdma_create_jfs_ucmd *ucmd)
{
	struct cdma_context *ctx;
	int ret;

	if (!udata) {
		jfs->jfs_addr = (uintptr_t)&jfs->sq;
		jfs->is_kernel = true;
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
			"copy jfs udata failed, ret = %d\n", ret);
		return -EFAULT;
	}

	if (!ucmd->jetty_addr || !ucmd->buf_len || !ucmd->buf_addr) {
		dev_err(cdev->dev, "user cmd param is invalid\n");
		return -EINVAL;
	}

	ctx = udata->uctx;
	jfs->base_jfs.ctx = ctx;
	jfs->base_jfs.jfae = udata->jfae;
	jfs->sq.tid = ctx->tid;
	jfs->jfs_addr = ucmd->jetty_addr;
	jfs->sq.id = ucmd->jfs_id;
	jfs->queue_id = ucmd->queue_id;
	jfs->sq.non_pin = ucmd->non_pin;

	return 0;
}

static int cdma_alloc_jfs_id(struct cdma_dev *cdev, struct cdma_jfs *jfs)
{
	struct cdma_idr *idr_tbl = &cdev->jfs_table.idr_tbl;
	u32 max = idr_tbl->max;
	u32 min = idr_tbl->min;
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&cdev->jfs_table.lock);
	id = idr_alloc(&idr_tbl->idr, jfs, idr_tbl->next, max, GFP_NOWAIT);
	if (id < 0) {
		id = idr_alloc(&idr_tbl->idr, jfs, min, max, GFP_NOWAIT);
		if (id < 0)
			dev_err(cdev->dev, "alloc cdma jfs id failed\n");
	}

	idr_tbl->next = (id >= 0 && id + 1 <= max) ? id + 1 : min;
	spin_unlock(&cdev->jfs_table.lock);
	idr_preload_end();

	return id;
}

static inline u32 cdma_sq_cal_wqebb_num(u32 sqe_ctl_len, u32 sge_num)
{
	return (sqe_ctl_len + (sge_num - 1) * CDMA_JFS_SGE_SIZE) / CDMA_JFS_WQEBB_SIZE + 1;
}

static inline void cdma_set_kernel_db(struct cdma_dev *cdev,
				      struct cdma_jetty_queue *queue)
{
	queue->dwqe_addr =
		cdev->k_db_base + JETTY_DSQE_OFFSET + CDMA_HW_PAGE_SIZE * queue->id;
	queue->db_addr = queue->dwqe_addr + CDMA_DOORBELL_OFFSET;
}

static int cdma_get_sq_buf(struct cdma_dev *cdev, struct cdma_jfs *jfs,
			   struct cdma_jfs_cfg *jfs_cfg,
			   struct cdma_create_jfs_ucmd *ucmd)
{
	struct cdma_jetty_queue *sq = &jfs->sq;
	u32 wqe_bb_depth;
	u32 sqe_bb_cnt;
	int ret = 0;
	u32 size;

	if (!jfs->is_kernel) {
		sq->buf.umem = cdma_umem_get(cdev, ucmd->buf_addr,
					     ucmd->buf_len, false,
					     jfs->base_jfs.ctx);
		if (IS_ERR(sq->buf.umem)) {
			ret = PTR_ERR(sq->buf.umem);
			dev_err(cdev->dev, "get jfs umem failed, ret = %d\n",
				ret);
			return ret;
		}

		sq->buf.addr = ucmd->buf_addr;
		sq->buf.entry_cnt = ucmd->buf_len >> WQE_BB_SIZE_SHIFT;
		sq->sqe_bb_cnt = ucmd->sqe_bb_cnt;
		if (sq->sqe_bb_cnt > MAX_WQEBB_NUM)
			sq->sqe_bb_cnt = MAX_WQEBB_NUM;
	} else {
		spin_lock_init(&sq->lock);
		sq->tid = cdev->tid;
		sq->max_sge_num = jfs_cfg->max_sge;
		sqe_bb_cnt =
			cdma_sq_cal_wqebb_num(SQE_WRITE_NOTIFY_CTL_LEN,
					      jfs_cfg->max_sge);
		if (sqe_bb_cnt > MAX_WQEBB_NUM)
			sqe_bb_cnt = MAX_WQEBB_NUM;
		sq->sqe_bb_cnt = sqe_bb_cnt;

		wqe_bb_depth = roundup_pow_of_two(sqe_bb_cnt * jfs_cfg->depth);
		sq->buf.entry_size = CDMA_JFS_WQEBB_SIZE;
		size = ALIGN(wqe_bb_depth * sq->buf.entry_size, CDMA_HW_PAGE_SIZE);
		sq->buf.entry_cnt = size >> WQE_BB_SIZE_SHIFT;

		ret = cdma_k_alloc_buf(cdev, size, &sq->buf);
		if (ret) {
			dev_err(cdev->dev,
				"alloc jfs (%u) sq buf failed, size = %u, ret = %d\n",
				sq->id, size, ret);
			return ret;
		}

		cdma_set_kernel_db(cdev, sq);
		sq->kva_curr = sq->buf.kva;
	}

	return ret;
}

static void cdma_init_jfsc(struct cdma_dev *cdev, struct cdma_jfs_cfg *cfg,
			   struct cdma_jfs *jfs, void *mb_buf)
{
	struct cdma_jfs_ctx *ctx = mb_buf;

	ctx->state = CDMA_JETTY_READY;
	ctx->sl = cdev->sl[cfg->priority % cdev->sl_num];
	ctx->jfs_mode = CDMA_JFS_MODE;
	ctx->type = (cfg->trans_mode == CDMA_JETTY_ROL) ? CDMA_JETTY_ROL : CDMA_JETTY_ROI;
	ctx->sqe_base_addr_l = (jfs->sq.buf.addr >> SQE_VA_L_OFFSET) &
				   (u32)SQE_VA_L_VALID_BIT;
	ctx->sqe_base_addr_h = (jfs->sq.buf.addr >> SQE_VA_H_OFFSET) &
				   (u32)SQE_VA_H_VALID_BIT;
	ctx->sqe_token_id_l = jfs->sq.tid & (u32)SQE_TOKEN_ID_L_MASK;
	ctx->sqe_token_id_h = (jfs->sq.tid >> SQE_TOKEN_ID_H_OFFSET) &
				  (u32)SQE_TOKEN_ID_H_MASK;
	ctx->sqe_bb_shift = ilog2(roundup_pow_of_two(jfs->sq.buf.entry_cnt));
	ctx->tx_jfcn = cfg->jfc_id;
	ctx->ta_timeout = cfg->err_timeout;
	ctx->rnr_retry_num = cfg->rnr_retry;
	ctx->user_data_l = jfs->jfs_addr;
	ctx->user_data_h = jfs->jfs_addr >> CDMA_USER_DATA_H_OFFSET;
	ctx->seid_idx = cfg->eid_index;
	ctx->err_mode = cfg->flag.bs.error_suspend;
	ctx->cmp_odr = cfg->flag.bs.outorder_comp;
	ctx->avail_sgmt_ost = AVAIL_SGMT_OST_INIT;
	ctx->sqe_pld_tokenid = jfs->sq.tid & (u32)SQE_PLD_TOKEN_ID_MASK;
	ctx->next_send_ssn = get_random_u16();
	ctx->next_rcv_ssn = ctx->next_send_ssn;

	ctx->sqe_pos = cfg->sqe_pos;
	ctx->sqe_pld_pos = cfg->pld_pos;
	ctx->rmt_eid = cfg->rmt_eid;
	ctx->rmt_tokenid = cfg->pld_token_id;
	ctx->tpn = cfg->tpn;
}

static inline void cdma_reset_jfs_queue(struct cdma_jetty_queue *sq)
{
	sq->kva_curr = sq->buf.kva;
	sq->pi = 0;
	sq->ci = 0;
	sq->flush_flag = false;
}

static int cdma_create_hw_jfs_ctx(struct cdma_dev *cdev, struct cdma_jfs *jfs,
				  struct cdma_jfs_cfg *cfg)
{
	struct ubase_mbx_attr attr = { 0 };
	struct cdma_jfs_ctx ctx = { 0 };
	int ret;

	cdma_init_jfsc(cdev, cfg, jfs, &ctx);
	cdma_fill_mbx_attr(&attr, jfs->sq.id, CDMA_CMD_CREATE_JFS_CONTEXT, 0);
	ret = cdma_post_mailbox_ctx(cdev, &ctx, sizeof(ctx), &attr);
	if (ret) {
		dev_err(cdev->dev, "upgrade jfs ctx failed, ret = %d\n", ret);
		return ret;
	}

	cdma_reset_jfs_queue(&jfs->sq);

	return 0;
}

static void cdma_free_sq_buf(struct cdma_dev *cdev, struct cdma_jetty_queue *sq)
{
	u32 size;

	if (sq->buf.kva) {
		size = sq->buf.entry_cnt * sq->buf.entry_size;
		cdma_k_free_buf(cdev, size, &sq->buf);
	} else {
		cdma_put_umem(sq->buf.umem, false);
		sq->buf.umem = NULL;
	}
}

static void cdma_set_query_flush_time(struct cdma_jetty_queue *sq,
				      u8 err_timeout)
{
	static u32 time[] = {
		CDMA_TA_TIMEOUT_128MS,
		CDMA_TA_TIMEOUT_1000MS,
		CDMA_TA_TIMEOUT_8000MS,
		CDMA_TA_TIMEOUT_64000MS,
	};
	static u8 time_index_max = ARRAY_SIZE(time) - 1;

	if (err_timeout > time_index_max)
		err_timeout = time_index_max;

	sq->ta_tmo = time[err_timeout];
}

static inline void cdma_free_jfs_id(struct cdma_dev *cdev, u32 id)
{
	spin_lock(&cdev->jfs_table.lock);
	idr_remove(&cdev->jfs_table.idr_tbl.idr, id);
	spin_unlock(&cdev->jfs_table.lock);
}

static int cdma_verify_jfs_cfg(struct cdma_dev *cdev, struct cdma_jfs_cfg *cfg)
{
	if (!cfg->depth || cfg->depth > cdev->caps.jfs.depth) {
		dev_err(cdev->dev,
			"jfs param is invalid, depth = %u, max_depth = %u\n",
			cfg->depth, cdev->caps.jfs.depth);
		return -EINVAL;
	}

	return 0;
}

struct cdma_base_jfs *cdma_create_jfs(struct cdma_dev *cdev,
				      struct cdma_jfs_cfg *cfg,
				      struct cdma_udata *udata)
{
	struct cdma_create_jfs_ucmd ucmd = { 0 };
	struct cdma_jfs *jfs;
	int ret;

	if (cdma_verify_jfs_cfg(cdev, cfg))
		return NULL;

	jfs = kzalloc(sizeof(*jfs), GFP_KERNEL);
	if (!jfs)
		return NULL;

	ret = cdma_get_user_jfs_cmd(cdev, jfs, udata, &ucmd);
	if (ret)
		goto err_alloc_jfsn;

	ret = cdma_alloc_jfs_id(cdev, jfs);
	if (ret < 0)
		goto err_alloc_jfsn;

	jfs->id = ret;
	jfs->sq.id = ret;
	jfs->base_jfs.id = jfs->sq.id;
	jfs->base_jfs.cfg = *cfg;
	jfs->dev = cdev;
	jfs->queue_id = cfg->queue_id;

	ret = cdma_get_sq_buf(cdev, jfs, cfg, &ucmd);
	if (ret)
		goto err_get_jfs_buf;

	if (udata) {
		ret = cdma_get_jfae_ref(jfs->base_jfs.jfae);
		if (ret)
			goto err_get_jfae;
	}

	ret = cdma_create_hw_jfs_ctx(cdev, jfs, cfg);
	if (ret)
		goto err_create_hw_jfsc;

	cdma_set_query_flush_time(&jfs->sq, cfg->err_timeout);
	refcount_set(&jfs->ae_ref_cnt, 1);
	init_completion(&jfs->ae_comp);
	jfs->sq.state = CDMA_JETTY_READY;
	jfs->base_jfs.jfae_handler = cdma_jfs_async_event_cb;
	jfs->base_jfs.dev = cdev;

	dev_info(
		cdev->dev,
		"create jfs, id = %u, queue id = %u, depth = %u, priority = %u, jfc id = %u\n",
		jfs->id, jfs->queue_id, cfg->depth, cfg->priority, cfg->jfc_id);

	return &jfs->base_jfs;

err_create_hw_jfsc:
	if (udata)
		cdma_put_jfae_ref(jfs->base_jfs.jfae);
err_get_jfae:
	cdma_free_sq_buf(cdev, &jfs->sq);
err_get_jfs_buf:
	cdma_free_jfs_id(cdev, jfs->sq.id);
err_alloc_jfsn:
	kfree(jfs);

	return NULL;
}

static int cdma_set_jfs_state(struct cdma_dev *cdev, u32 jfs_id,
			      enum cdma_jetty_state state)
{
	struct cdma_jfs_ctx ctx[SZ_2] = { 0 };
	struct ubase_mbx_attr attr = { 0 };
	struct cdma_jfs_ctx *ctx_mask;

	ctx_mask = (struct cdma_jfs_ctx *)((char *)ctx + SZ_128);
	memset(ctx_mask, 0xff, sizeof(*ctx_mask));
	ctx->state = state;
	ctx_mask->state = 0;

	cdma_fill_mbx_attr(&attr, jfs_id, CDMA_CMD_MODIFY_JFS_CONTEXT, 0);

	return cdma_post_mailbox_ctx(cdev, (void *)ctx, sizeof(ctx), &attr);
}

static int cdma_query_jfs_ctx(struct cdma_dev *cdev,
			      struct cdma_jfs_ctx *jfs_ctx, u32 jfs_id)
{
	struct ubase_mbx_attr attr = { 0 };
	struct ubase_cmd_mailbox *mailbox;

	cdma_fill_mbx_attr(&attr, jfs_id, CDMA_CMD_QUERY_JFS_CONTEXT, 0);
	mailbox = cdma_mailbox_query_ctx(cdev, &attr);
	if (!mailbox)
		return -ENOMEM;
	memcpy((void *)jfs_ctx, mailbox->buf, sizeof(*jfs_ctx));

	cdma_free_cmd_mailbox(cdev, mailbox);

	return 0;
}

static int cdma_destroy_hw_jfs_ctx(struct cdma_dev *cdev, u32 jfs_id)
{
	struct ubase_mbx_attr attr = { 0 };
	int ret;

	cdma_fill_mbx_attr(&attr, jfs_id, CDMA_CMD_DESTROY_JFS_CONTEXT, 0);
	ret = cdma_post_mailbox_ctx(cdev, NULL, 0, &attr);
	if (ret)
		dev_err(cdev->dev,
			"post mailbox destroy jfs ctx failed, ret = %d\n", ret);

	return ret;
}

static bool cdma_wait_timeout(u32 *sum_times, u32 times, u32 ta_timeout)
{
	u32 wait_time;

	if (*sum_times > ta_timeout)
		return true;

	wait_time = 1 << times;
	msleep(wait_time);
	*sum_times += wait_time;

	return false;
}

static bool cdma_query_jfs_fd(struct cdma_dev *cdev,
			      struct cdma_jetty_queue *sq)
{
	struct cdma_jfs_ctx ctx = { 0 };
	u16 rcv_send_diff = 0;
	u32 sum_times = 0;
	u32 times = 0;

	while (true) {
		if (cdma_query_jfs_ctx(cdev, &ctx, sq->id))
			return false;

		if (ctx.flush_cqe_done)
			return true;

		if (cdma_wait_timeout(&sum_times, times, CDMA_TA_TIMEOUT_64000MS)) {
			dev_warn(cdev->dev,
				 "flush cqe timeout, id = %u. PI = %u, CI = %u, next_send_ssn = %u next_rcv_ssn = %u state = %u\n",
				 sq->id, ctx.pi, ctx.ci, ctx.next_send_ssn,
				 ctx.next_rcv_ssn, ctx.state);
			break;
		}

		times++;
	}

	/* In the flip scenario, ctx.next_rcv_ssn - ctx.next_send_ssn value is less than 512. */
	rcv_send_diff = ctx.next_rcv_ssn - ctx.next_send_ssn;
	if (ctx.flush_ssn_vld && rcv_send_diff < CDMA_RCV_SEND_MAX_DIFF)
		return true;

	dev_err(cdev->dev, "query jfs flush ssn error, id = %u", sq->id);

	return false;
}

static int cdma_modify_jfs_precondition(struct cdma_dev *cdev,
					struct cdma_jetty_queue *sq)
{
	struct cdma_jfs_ctx ctx = { 0 };
	u16 rcv_send_diff = 0;
	u32 sum_times = 0;
	u32 times = 0;

	while (true) {
		if (cdma_query_jfs_ctx(cdev, &ctx, sq->id)) {
			dev_err(cdev->dev, "query jfs ctx failed, id = %u\n",
				sq->id);
			return -ENOMEM;
		}

		rcv_send_diff = ctx.next_rcv_ssn - ctx.next_send_ssn;
		if ((ctx.pi == ctx.ci) && (rcv_send_diff < CDMA_RCV_SEND_MAX_DIFF) &&
		    (ctx.state == CDMA_JETTY_READY))
			break;

		if ((rcv_send_diff < CDMA_RCV_SEND_MAX_DIFF) &&
		    (ctx.state == CDMA_JETTY_ERROR))
			break;

		if (cdma_wait_timeout(&sum_times, times, sq->ta_tmo)) {
			dev_warn(cdev->dev,
				 "modify jfs precondition timeout, id = %u. PI = %u, CI = %u, next_send_ssn = %u next_rcv_ssn = %u state = %u\n",
				 sq->id, ctx.pi, ctx.ci, ctx.next_send_ssn,
				 ctx.next_rcv_ssn, ctx.state);
			break;
		}
		times++;
	}

	return 0;
}

static bool cdma_destroy_jfs_precondition(struct cdma_dev *cdev,
					  struct cdma_jetty_queue *sq)
{
#define CDMA_DESTROY_JETTY_DELAY_TIME 100U

	if ((sq->state == CDMA_JETTY_READY) ||
	    (sq->state == CDMA_JETTY_SUSPENDED)) {
		if (cdma_modify_jfs_precondition(cdev, sq))
			return false;

		if (cdma_set_jfs_state(cdev, sq->id, CDMA_JETTY_ERROR)) {
			dev_err(cdev->dev, "modify jfs state to error failed, id = %u\n",
				sq->id);
			return false;
		}

		sq->state = CDMA_JETTY_ERROR;
		dev_dbg(cdev->dev, "set jfs %u status finished\n", sq->id);
	}

	if (!cdma_query_jfs_fd(cdev, sq))
		return false;

	udelay(CDMA_DESTROY_JETTY_DELAY_TIME);

	return true;
}

static int cdma_modify_and_destroy_jfs(struct cdma_dev *cdev,
				       struct cdma_jfs *jfs)
{
	struct cdma_context *ctx = jfs->base_jfs.ctx;
	struct cdma_jetty_queue *sq = &jfs->sq;
	int ret = 0;

	if (cdev->status == CDMA_INVALID || (ctx && ctx->invalid)) {
		dev_info(cdev->dev,
			 "resetting ignore jfs ctx, id = %u\n", sq->id);
		return 0;
	}

	if (!cdma_destroy_jfs_precondition(cdev, sq))
		return -EINVAL;

	if (sq->state != CDMA_JETTY_RESET)
		ret = cdma_destroy_hw_jfs_ctx(cdev, sq->id);

	return ret;
}

static inline void cdma_release_jfs_event(struct cdma_jfs *jfs)
{
	cdma_release_async_event(jfs->base_jfs.jfae,
		&jfs->base_jfs.jfs_event.async_event_list);
}

int cdma_delete_jfs(struct cdma_dev *cdev, u32 jfs_id)
{
	struct cdma_jfs *jfs;
	int ret;

	if (jfs_id >= cdev->caps.jfs.start_idx + cdev->caps.jfs.max_cnt) {
		dev_info(
			cdev->dev,
			"jfs id invalid, jfs_id = %u, start_idx = %u, max_cnt = %u\n",
			jfs_id, cdev->caps.jfs.start_idx,
			cdev->caps.jfs.max_cnt);
		return -EINVAL;
	}

	spin_lock(&cdev->jfs_table.lock);
	jfs = idr_find(&cdev->jfs_table.idr_tbl.idr, jfs_id);
	spin_unlock(&cdev->jfs_table.lock);
	if (!jfs) {
		dev_err(cdev->dev, "get jfs from table failed, id = %u\n", jfs_id);
		return -EINVAL;
	}

	ret = cdma_modify_and_destroy_jfs(cdev, jfs);
	if (ret)
		dev_err(cdev->dev, "jfs delete failed, id = %u, ret = %d\n",
			jfs->id, ret);

	if (refcount_dec_and_test(&jfs->ae_ref_cnt))
		complete(&jfs->ae_comp);
	wait_for_completion(&jfs->ae_comp);

	cdma_free_sq_buf(cdev, &jfs->sq);

	cdma_free_jfs_id(cdev, jfs_id);

	dev_info(cdev->dev, "delete jfs, id = %u\n", jfs_id);

	cdma_release_jfs_event(jfs);

	kfree(jfs);

	return 0;
}

static u8 cdma_get_jfs_opcode(enum cdma_wr_opcode opcode)
{
	switch (opcode) {
	case CDMA_WR_OPC_WRITE:
		return CDMA_OPC_WRITE;
	case CDMA_WR_OPC_WRITE_NOTIFY:
		return CDMA_OPC_WRITE_WITH_NOTIFY;
	case CDMA_WR_OPC_READ:
		return CDMA_OPC_READ;
	case CDMA_WR_OPC_CAS:
		return CDMA_OPC_CAS;
	case CDMA_WR_OPC_FADD:
		return CDMA_OPC_FAA;
	default:
		return CDMA_OPC_INVALID;
	}
}

static inline u32 cdma_get_normal_sge_num(u8 opcode, struct cdma_sqe_ctl *tmp_sq)
{
	switch (opcode) {
	case CDMA_OPC_CAS:
	case CDMA_OPC_FAA:
		return CDMA_ATOMIC_SGE_NUM_ATOMIC;
	default:
		return tmp_sq->sge_num;
	}
}

static bool cdma_k_check_sge_num(u8 opcode, struct cdma_jetty_queue *sq,
				 struct cdma_jfs_wr *wr)
{
	switch (opcode) {
	case CDMA_OPC_CAS:
	case CDMA_OPC_FAA:
		return sq->max_sge_num == 0;
	case CDMA_OPC_READ:
		return wr->rw.dst.num_sge > sq->max_sge_num;
	case CDMA_OPC_WRITE_WITH_NOTIFY:
		return wr->rw.src.num_sge > CDMA_JFS_MAX_SGE_NOTIFY ||
		       wr->rw.src.num_sge > sq->max_sge_num;
	default:
		return wr->rw.src.num_sge > sq->max_sge_num;
	}
}

static int cdma_fill_sw_sge(struct cdma_sqe_ctl *sqe_ctl,
			    struct cdma_jfs_wr *wr,
			    struct cdma_normal_sge *sge)
{
	struct cdma_sge_info *sge_info;
	u32 sge_num = 0;
	u32 num_sge;
	u32 i;

	switch (wr->opcode) {
	case CDMA_WR_OPC_WRITE:
	case CDMA_WR_OPC_WRITE_NOTIFY:
		sge_info = wr->rw.src.sge;
		num_sge = wr->rw.src.num_sge;
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < num_sge; i++) {
		if (sge_info[i].len == 0)
			continue;
		sge->va = sge_info[i].addr;
		sge->length = sge_info[i].len;
		sge->token_id = sge_info[i].seg->tid;
		sge++;
		sge_num++;
	}
	sqe_ctl->sge_num = sge_num;

	return 0;
}

static inline u32 cdma_get_ctl_len(u8 opcode)
{
	if (opcode == CDMA_OPC_WRITE_WITH_NOTIFY)
		return SQE_WRITE_NOTIFY_CTL_LEN;

	return SQE_NORMAL_CTL_LEN;
}

static int cdma_k_fill_write_sqe(struct cdma_dev *cdev,
				 struct cdma_sqe_ctl *sqe_ctl,
				 struct cdma_jfs_wr *wr)
{
	struct cdma_token_info *token_info;
	struct cdma_sge_info *sge_info;
	struct cdma_normal_sge *sge;
	u32 ctrl_len;

	ctrl_len = cdma_get_ctl_len(sqe_ctl->opcode);
	sge = (struct cdma_normal_sge *)((void *)sqe_ctl + ctrl_len);

	if (cdma_fill_sw_sge(sqe_ctl, wr, sge))
		return -EINVAL;

	sge_info = wr->rw.dst.sge;

	sqe_ctl->toid = sge_info[0].seg->tid;
	sqe_ctl->token_en = sge_info[0].seg->token_value_valid;
	sqe_ctl->rmt_token_value = sge_info[0].seg->token_value;
	sqe_ctl->target_hint = wr->rw.target_hint;
	sqe_ctl->rmt_addr_l_or_token_id =
		sge_info[0].addr & (u32)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value =
		(sge_info[0].addr >> (u32)SQE_CTL_RMA_ADDR_OFFSET) &
			(u32)SQE_CTL_RMA_ADDR_BIT;

	if (sqe_ctl->opcode == CDMA_OPC_WRITE_WITH_NOTIFY) {
		token_info = (struct cdma_token_info *)
				((void *)sqe_ctl + SQE_NOTIFY_TOKEN_ID_FIELD);
		token_info->token_id = wr->rw.notify_tokenid;
		token_info->token_value = wr->rw.notify_tokenvalue;

		memcpy((void *)sqe_ctl + SQE_NOTIFY_ADDR_FIELD,
			&wr->rw.notify_addr, sizeof(u64));
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
			&wr->rw.notify_data, sizeof(u64));
	}

	return 0;
}

static int cdma_k_fill_read_sqe(struct cdma_dev *cdev,
				struct cdma_sqe_ctl *sqe_ctl,
				struct cdma_jfs_wr *wr)
{
	struct cdma_sge_info *sge_info;
	struct cdma_normal_sge *sge;
	u32 sge_num = 0;
	u32 num;

	sge = (struct cdma_normal_sge *)(sqe_ctl + 1);
	sge_info = wr->rw.dst.sge;

	for (num = 0; num < wr->rw.dst.num_sge; num++) {
		if (!sge_info[num].len)
			continue;
		sge->va = sge_info[num].addr;
		sge->length = sge_info[num].len;
		sge->token_id = sge_info[num].seg->tid;
		sge++;
		sge_num++;
	}

	sge_info = wr->rw.src.sge;
	sqe_ctl->sge_num = sge_num;
	sqe_ctl->toid = sge_info[0].seg->tid;
	sqe_ctl->token_en = sge_info[0].seg->token_value_valid;
	sqe_ctl->rmt_token_value = sge_info[0].seg->token_value;
	sqe_ctl->rmt_addr_l_or_token_id =
		sge_info[0].addr & (u32)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value =
		(sge_info[0].addr >> (u32)SQE_CTL_RMA_ADDR_OFFSET) &
		(u32)SQE_CTL_RMA_ADDR_BIT;

	return 0;
}

static bool cdma_check_atomic_len(u32 len, u8 opcode)
{
	switch (len) {
	case CDMA_ATOMIC_LEN_4:
	case CDMA_ATOMIC_LEN_8:
		return true;
	case CDMA_ATOMIC_LEN_16:
		if (opcode == CDMA_WR_OPC_CAS)
			return true;
		return false;
	default:
		return false;
	}
}

static int cdma_k_fill_cas_sqe(struct cdma_dev *cdev,
			       struct cdma_sqe_ctl *sqe_ctl,
			       struct cdma_jfs_wr *wr)
{
	struct cdma_sge_info *sge_info;
	struct cdma_normal_sge *sge;

	sge_info = wr->cas.src;
	if (!cdma_check_atomic_len(sge_info->len, wr->opcode)) {
		dev_err(cdev->dev, "cdma cas sge len invalid, len = %u\n",
			sge_info->len);
		return -EINVAL;
	}

	sge = (struct cdma_normal_sge *)(sqe_ctl + 1);
	sge->va = sge_info->addr;
	sge->length = sge_info->len;
	sge->token_id = sge_info->seg->tid;

	sge_info = wr->cas.dst;
	sqe_ctl->sge_num = CDMA_ATOMIC_SGE_NUM;
	sqe_ctl->toid = sge_info->seg->tid;
	sqe_ctl->token_en = sge_info->seg->token_value_valid;
	sqe_ctl->rmt_token_value = sge_info->seg->token_value;
	sqe_ctl->rmt_addr_l_or_token_id = sge_info->addr &
					  (u32)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value =
		(sge_info->addr >> (u32)SQE_CTL_RMA_ADDR_OFFSET) &
		(u32)SQE_CTL_RMA_ADDR_BIT;

	if (sge->length <= CDMA_ATOMIC_LEN_8) {
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
		       &wr->cas.swap_data, sge->length);
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD + sge->length,
		       &wr->cas.cmp_data, sge->length);
	} else {
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
		       (char *)wr->cas.swap_addr, sge->length);
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD + sge->length,
		       (char *)wr->cas.cmp_addr, sge->length);
	}

	return 0;
}

static int cdma_k_fill_faa_sqe(struct cdma_dev *cdev,
			       struct cdma_sqe_ctl *sqe_ctl,
			       struct cdma_jfs_wr *wr)
{
	struct cdma_sge_info *sge_info;
	struct cdma_normal_sge *sge;

	sge_info = wr->faa.src;
	if (!cdma_check_atomic_len(sge_info->len, wr->opcode)) {
		dev_err(cdev->dev, "cdma faa sge len invalid, len = %u\n",
			sge_info->len);
		return -EINVAL;
	}

	sge = (struct cdma_normal_sge *)(sqe_ctl + 1);
	sge->va = sge_info->addr;
	sge->length = sge_info->len;
	sge->token_id = sge_info->seg->tid;

	sge_info = wr->faa.dst;
	sqe_ctl->sge_num = CDMA_ATOMIC_SGE_NUM;
	sqe_ctl->toid = sge_info->seg->tid;
	sqe_ctl->token_en = sge_info->seg->token_value_valid;
	sqe_ctl->rmt_token_value = sge_info->seg->token_value;
	sqe_ctl->rmt_addr_l_or_token_id = sge_info->addr &
					  (u32)SQE_CTL_RMA_ADDR_BIT;
	sqe_ctl->rmt_addr_h_or_token_value =
		(sge_info->addr >> (u32)SQE_CTL_RMA_ADDR_OFFSET) &
		(u32)SQE_CTL_RMA_ADDR_BIT;

	if (sge->length <= CDMA_ATOMIC_LEN_8)
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
		       &wr->faa.operand, sge->length);
	else
		memcpy((void *)sqe_ctl + SQE_ATOMIC_DATA_FIELD,
		       (void *)wr->faa.operand_addr, sge->length);

	return 0;
}

static int cdma_fill_normal_sge(struct cdma_dev *cdev,
				struct cdma_sqe_ctl *sqe_ctl,
				struct cdma_jfs_wr *wr)
{
	switch (wr->opcode) {
	case CDMA_WR_OPC_WRITE:
	case CDMA_WR_OPC_WRITE_NOTIFY:
		return cdma_k_fill_write_sqe(cdev, sqe_ctl, wr);
	case CDMA_WR_OPC_READ:
		return cdma_k_fill_read_sqe(cdev, sqe_ctl, wr);
	case CDMA_WR_OPC_CAS:
		return cdma_k_fill_cas_sqe(cdev, sqe_ctl, wr);
	case CDMA_WR_OPC_FADD:
		return cdma_k_fill_faa_sqe(cdev, sqe_ctl, wr);
	default:
		dev_err(cdev->dev, "cdma wr opcode invalid, opcode = %u\n",
			(u8)wr->opcode);
		return -EINVAL;
	}
}

static int cdma_set_sqe(struct cdma_dev *cdev, struct cdma_sqe_ctl *sqe_ctl,
			struct cdma_jfs_wr *wr, struct cdma_jetty_queue *sq,
			u8 opcode)
{
	int ret;

	sqe_ctl->cqe = wr->flag.bs.complete_enable;
	sqe_ctl->owner = (sq->pi & sq->buf.entry_cnt) == 0 ? 1 : 0;
	sqe_ctl->opcode = opcode;
	sqe_ctl->tpn = wr->tpn;
	sqe_ctl->place_odr = wr->flag.bs.place_order;
	sqe_ctl->fence = wr->flag.bs.fence;
	sqe_ctl->comp_order = wr->flag.bs.comp_order;
	sqe_ctl->se = wr->flag.bs.solicited_enable;
	sqe_ctl->inline_en = 0;
	memcpy(sqe_ctl->rmt_eid, &wr->rmt_eid, sizeof(wr->rmt_eid));

	ret = cdma_fill_normal_sge(cdev, sqe_ctl, wr);
	if (ret)
		dev_err(cdev->dev,
			"cdma fill normal sge failed, wr opcode = %u, ret = %d\n",
			(u8)wr->opcode, ret);

	return ret;
}

static u32 cdma_cal_wqebb_num(struct cdma_jfs_wr *wr, u8 opcode,
			      struct cdma_sqe_ctl *tmp_sq)
{
	u32 normal_sge_num;
	u32 sqe_ctl_len;
	u32 wqebb_cnt;

	sqe_ctl_len = cdma_get_ctl_len(opcode);

	normal_sge_num = cdma_get_normal_sge_num(opcode, tmp_sq);
	wqebb_cnt = cdma_sq_cal_wqebb_num(sqe_ctl_len, normal_sge_num);

	return wqebb_cnt;
}

static inline bool to_check_sq_overflow(struct cdma_jetty_queue *sq,
					u32 wqebb_cnt)
{
	return (sq->pi - sq->ci + wqebb_cnt) > sq->buf.entry_cnt;
}

static int cdma_copy_to_sq(struct cdma_jetty_queue *sq, u32 wqebb_cnt,
			   struct cdma_jfs_wqebb *tmp_sq)
{
	u32 remain = sq->buf.entry_cnt - (sq->pi & (sq->buf.entry_cnt - 1));
	u32 tail_cnt;
	u32 head_cnt;

	if (to_check_sq_overflow(sq, wqebb_cnt))
		return -ENOMEM;

	tail_cnt = remain > wqebb_cnt ? wqebb_cnt : remain;
	head_cnt = wqebb_cnt - tail_cnt;

	memcpy(sq->kva_curr, tmp_sq, tail_cnt * sizeof(*tmp_sq));
	if (head_cnt)
		memcpy(sq->buf.kva, tmp_sq + tail_cnt,
		       head_cnt * sizeof(*tmp_sq));

	return 0;
}

static void *cdma_k_update_ptr(u32 total_size, u32 wqebb_size, u8 *base_addr,
			       u8 *curr_addr)
{
	u8 *end_addr;

	end_addr = base_addr + total_size;
	curr_addr = ((curr_addr + wqebb_size) < end_addr) ?
			    (curr_addr + wqebb_size) :
			    base_addr + (curr_addr + wqebb_size - end_addr);

	return curr_addr;
}

static int cdma_post_one_wr(struct cdma_jetty_queue *sq, struct cdma_jfs_wr *wr,
			    struct cdma_dev *cdev,
			    struct cdma_sqe_ctl **dwqe_addr, u8 *dwqe_enable)
{
	struct cdma_jfs_wqebb tmp_sq[MAX_WQEBB_NUM] = { 0 };
	u32 wqebb_cnt;
	u8 opcode;
	int ret;

	opcode = cdma_get_jfs_opcode(wr->opcode);
	if (opcode == CDMA_OPC_INVALID) {
		dev_err(cdev->dev, "cdma invalid opcode = %u\n", wr->opcode);
		return -EINVAL;
	}

	if (cdma_k_check_sge_num(opcode, sq, wr)) {
		dev_err(cdev->dev, "cdma sge num invalid, opcode = %u\n",
			opcode);
		return -EINVAL;
	}

	ret = cdma_set_sqe(cdev, (struct cdma_sqe_ctl *)tmp_sq, wr, sq, opcode);
	if (ret)
		return ret;

	wqebb_cnt =
		cdma_cal_wqebb_num(wr, opcode, (struct cdma_sqe_ctl *)tmp_sq);
	if (wqebb_cnt == 1 &&
	    !!(cdev->caps.feature & CDMA_CAP_FEATURE_DIRECT_WQE))
		*dwqe_enable = 1;

	ret = cdma_copy_to_sq(sq, wqebb_cnt, tmp_sq);
	if (ret) {
		dev_err(cdev->dev,
			"cdma jfs overflow, wqebb_cnt = %u, ret = %d\n",
			wqebb_cnt, ret);
		return ret;
	}

	*dwqe_addr = sq->kva_curr;

	sq->kva_curr = cdma_k_update_ptr(sq->buf.entry_cnt * sq->buf.entry_size,
					 wqebb_cnt * sq->buf.entry_size,
					 (u8 *)sq->buf.kva, (u8 *)sq->kva_curr);

	sq->pi += wqebb_cnt;

	return 0;
}

static void cdma_write_dsqe(struct cdma_jetty_queue *sq,
			    struct cdma_sqe_ctl *ctrl)
{
#define DWQE_SIZE 8
	int i;

	ctrl->sqe_bb_idx = sq->pi;
	for (i = 0; i < DWQE_SIZE; i++)
		writeq_relaxed(*((u64 *)ctrl + i), (u64 *)sq->dwqe_addr + i);
}

static inline void cdma_k_update_sq_db(struct cdma_jetty_queue *sq)
{
	u32 *db_addr = (u32 *)sq->db_addr;
	*db_addr = sq->pi;
}

/* thanks to drivers/infiniband/hw/bnxt_re/ib_verbs.c */
static int cdma_post_sq_wr(struct cdma_dev *cdev, struct cdma_jetty_queue *sq,
			   struct cdma_jfs_wr *wr, struct cdma_jfs_wr **bad_wr)
{
	struct cdma_sqe_ctl *dwqe_addr;
	struct cdma_jfs_wr *it;
	u8 dwqe_enable = 0;
	int wr_cnt = 0;
	int ret = 0;

	spin_lock(&sq->lock);

	for (it = wr; it != NULL; it = it->next) {
		ret = cdma_post_one_wr(sq, it, cdev, &dwqe_addr, &dwqe_enable);
		if (ret) {
			dev_err(cdev->dev,
				"cdma post one wr failed, ret = %d\n", ret);
			*bad_wr = it;
			goto post_wr;
		}
		wr_cnt++;
	}

post_wr:
	if (wr_cnt) {
		if (cdev->status == CDMA_NORMAL) {
			/* Ensure the order of write memory operations */
			wmb();
			if (wr_cnt == 1 && dwqe_enable && (sq->pi - sq->ci == 1))
				cdma_write_dsqe(sq, dwqe_addr);
			else
				cdma_k_update_sq_db(sq);
		}
	}

	spin_unlock(&sq->lock);

	return ret;
}

int cdma_post_jfs_wr(struct cdma_jfs *jfs, struct cdma_jfs_wr *wr,
		     struct cdma_jfs_wr **bad_wr)
{
	struct cdma_dev *cdev = jfs->dev;
	int ret;

	ret = cdma_post_sq_wr(cdev, &jfs->sq, wr, bad_wr);
	if (ret)
		dev_err(cdev->dev,
			"cdma post jfs wr failed, sq_id = %u, ret = %d\n",
			jfs->sq.id, ret);

	return ret;
}
