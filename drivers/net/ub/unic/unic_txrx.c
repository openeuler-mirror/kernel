// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "unic_dev.h"
#include "unic_txrx.h"

static u16 unic_get_cqe_period(u16 cqe_period)
{
	u16 period[] = {
		UNIC_CQE_PERIOD_0,
		UNIC_CQE_PERIOD_4,
		UNIC_CQE_PERIOD_16,
		UNIC_CQE_PERIOD_64,
		UNIC_CQE_PERIOD_256,
		UNIC_CQE_PERIOD_1024,
		UNIC_CQE_PERIOD_4096,
		UNIC_CQE_PERIOD_16384
	};
	u16 i;

	for (i = 0; i < ARRAY_SIZE(period); ++i) {
		if (cqe_period == period[i])
			return i;
	}

	return 0;
}

bool unic_jfc_support_ceqn9(struct unic_dev *unic_dev)

{
	return unic_dev->hw_ver != UBASE_HW_VER_A_0 &&
	       unic_dev->hw_ver != UBASE_HW_VER_K_0;
}

static void unic_init_jfc_ctx(struct unic_cq *cq, u8 jfc_shift,
			      struct unic_dev *unic_dev, u16 cqe_coal_cnt,
			      u16 cqe_coal_period)
{
	struct unic_jfc_ctx *ctx = &cq->jfc_ctx;

	ctx->state = UNIC_JFC_STATE_VALID;
	ctx->arm_st = UNIC_CTX_ALWAY_ARMED;
	ctx->shift = jfc_shift - UNIC_CTX_SHIFT_BASE;
	ctx->record_db_en = 0;
	ctx->jfc_type = UNIC_RAW_JFC_TYPE;
	ctx->inline_en = UNIC_NO_INLINE_DATA;
	ctx->cqe_base_addr_l = (cq->cqe_dma_addr >> UNIC_CQE_VA_L_OFFSET) &
			UNIC_CQE_VA_L_VALID_BIT;
	ctx->cqe_base_addr_h = (cq->cqe_dma_addr >> UNIC_CQE_VA_H_OFFSET) &
			UNIC_CQE_VA_H_VALID_BIT;

	if (unic_jfc_support_ceqn9(unic_dev)) {
		ctx->dw2_ceqn9.queue_token_id = unic_dev->tid;
		ctx->dw2_ceqn9.ceqn = 0;
		ctx->dw2_ceqn9.cq_cnt_mode = UNIC_CQE_CNT_MODE_BY_COUNT;

	} else {
		ctx->dw2_ceqn8.queue_token_id = unic_dev->tid;
		ctx->dw2_ceqn8.ceqn = 0;
		ctx->dw2_ceqn8.cq_cnt_mode = UNIC_CQE_CNT_MODE_BY_COUNT;
	}
	ctx->cqe_coalesce_cnt = cqe_coal_cnt;
	ctx->cqe_coalesce_period = unic_get_cqe_period(cqe_coal_period);
}

static int unic_cq_alloc_resource(struct auxiliary_device *adev,
				  struct unic_cq *cq, u32 cqe_depth)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	u32 size = cqe_depth * unic_get_cqe_size();

	cq->cqe = dma_alloc_coherent(adev->dev.parent, size, &cq->cqe_dma_addr,
				     unic_dev->gfp);
	if (!cq->cqe) {
		dev_err(adev->dev.parent, "failed to dma alloc unic cqe.\n");
		return -ENOMEM;
	}

	return 0;
}

static void unic_cq_free_resource(struct auxiliary_device *adev,
				  struct unic_cq *cq, u32 cqe_depth)
{
	u32 size = cqe_depth * unic_get_cqe_size();
	union unic_cqe *cqe = cq->cqe;

	dma_free_coherent(adev->dev.parent, size, cqe, cq->cqe_dma_addr);
}

static int unic_mbx_create_jfc_context(struct auxiliary_device *adev,
				       struct unic_cq *cq, u32 jfcn)
{
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		dev_err(adev->dev.parent,
			"failed to alloc mailbox for create jfc context, jfcn = %u.\n",
			jfcn);
		return -ENOMEM;
	}

	memcpy(mailbox->buf, &cq->jfc_ctx, sizeof(struct unic_jfc_ctx));
	ubase_fill_mbx_attr(&attr, jfcn, UBASE_MB_CREATE_JFC_CONTEXT, 0);
	ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
	if (ret)
		dev_err(adev->dev.parent,
			"failed to post create jfc ctx mbx, jfcn = %u, ret = %d\n",
			jfcn, ret);

	ubase_free_cmd_mailbox(adev, mailbox);
	return ret;
}

static int unic_post_destroy_jfc_ctx(struct auxiliary_device *adev, u32 jfcn)
{
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		dev_err(adev->dev.parent,
			"failed to alloc mbx for post destroy jfcn(%u) ctx.\n",
			jfcn);
		return -ENOMEM;
	}

	ubase_fill_mbx_attr(&attr, jfcn, UBASE_MB_DESTROY_JFC_CONTEXT, 0);

	ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
	if (ret)
		dev_err(adev->dev.parent,
			"failed to post destroy jfcn(%u) ctx mbx, ret=%d.\n",
			jfcn, ret);

	ubase_free_cmd_mailbox(adev, mailbox);
	return ret;
}

static void unic_jfc_wait_flush_done(struct unic_dev *unic_dev, u32 jfcn)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	struct unic_jfc_ctx *ctx;
	int ret;

	if (test_bit(UNIC_STATE_RESETTING, &unic_dev->state))
		return;

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		dev_err(adev->dev.parent,
			"failed to alloc mbx for jfc(%u) flush.\n", jfcn);
		return;
	}

	ubase_fill_mbx_attr(&attr, jfcn, UBASE_MB_QUERY_JFC_CONTEXT, 0);

	ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
	if (ret) {
		dev_err(adev->dev.parent,
			"failed to wait jfcn(%u) flush, ret=%d\n", jfcn, ret);
		goto out;
	}

	ctx = (struct unic_jfc_ctx *)mailbox->buf;
	if (ctx->wr_cqe_idx == ctx->pi)
		goto out;

	dev_err(adev->dev.parent, "wait jfcn(%u) flush done timeout.\n", jfcn);
out:
	ubase_free_cmd_mailbox(adev, mailbox);
}

static void unic_jfc_wait_flush(struct unic_dev *unic_dev,
				enum unic_cq_type type, u32 num,
				unsigned long des_bitmap)
{
#define UNIC_WAIT_FLUSH_JFC_TIME	10

	struct unic_channel *c;
	struct unic_cq **cq;
	u32 i;

	/* Wait for the chip to complete the flush process through sleep */
	msleep(UNIC_WAIT_FLUSH_JFC_TIME);

	for (i = 0; i < num; i++) {
		if (!test_bit(i, &des_bitmap))
			continue;

		c = &unic_dev->channels.c[i];
		cq = type == UNIC_CQ_RQ ? &c->rq_cq : &c->sq_cq;
		unic_jfc_wait_flush_done(unic_dev, (*cq)->jfcn);
	}
}

static void unic_destroy_multi_jfc_context(struct unic_dev *unic_dev,
					   enum unic_cq_type type, u32 num)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	unsigned long des_bitmap = 0;
	struct unic_channel *c;
	struct unic_cq **cq;
	int ret;
	u32 i;

	/* Since jfc wait flush is a post-condition,
	 * there is no need to query if jfc destroy fails here.
	 * Other jfs/jfr query after set error, and query is a precondition.
	 */
	for (i = 0; i < num; i++) {
		c = &unic_dev->channels.c[i];
		cq = type == UNIC_CQ_RQ ? &c->rq_cq : &c->sq_cq;
		ret = unic_post_destroy_jfc_ctx(adev, (*cq)->jfcn);
		if (!ret)
			set_bit(i, &des_bitmap);
	}

	unic_jfc_wait_flush(unic_dev, type, num, des_bitmap);
}

int unic_create_cq(struct unic_dev *unic_dev, u32 idx, enum unic_cq_type type)
{
	struct unic_channel *channel = &unic_dev->channels.c[idx];
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_resource_space *mem_base = ubase_get_mem_base(adev);
	u16 channels_num = unic_dev->channels.num;
	struct unic_coalesce *coal;
	struct unic_cq *cq;
	u32 cqe_depth;
	u8 jfc_shift;
	int ret;

	if (!mem_base)
		return -ENODATA;

	cq = devm_kzalloc(&adev->dev, sizeof(*cq), GFP_KERNEL);
	if (!cq)
		return -ENOMEM;

	if (type == UNIC_CQ_RQ) {
		cqe_depth = unic_dev->channels.rq_cqe_depth;
		cq->jfcn = idx + channels_num;
		coal = &unic_dev->channels.unic_coal.rx_coal;
	} else {
		cqe_depth = unic_dev->channels.sq_cqe_depth;
		cq->jfcn = idx;
		coal = &unic_dev->channels.unic_coal.tx_coal;
	}

	ret = unic_cq_alloc_resource(adev, cq, cqe_depth);
	if (ret)
		goto err_alloc_res;

	channels_num = unic_dev->channels.num;
	jfc_shift = ilog2(roundup_pow_of_two(cqe_depth));
	unic_init_jfc_ctx(cq, jfc_shift, unic_dev, coal->int_ql, coal->int_gl);

	cq->db_addr = mem_base->addr + UNIC_JFC_DB_OFFSET;

	ret = unic_mbx_create_jfc_context(adev, cq, cq->jfcn);
	if (ret)
		goto err_fill_send_cq_mbx;

	if (type)
		channel->rq_cq = cq;
	else
		channel->sq_cq = cq;

	return 0;

err_fill_send_cq_mbx:
	unic_cq_free_resource(adev, cq, cqe_depth);
err_alloc_res:
	devm_kfree(&adev->dev, cq);
	return ret;
}

static void unic_multi_cq_res_destroy(struct unic_dev *unic_dev,
				      enum unic_cq_type type, u32 num)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channel *c;
	struct unic_cq **cq;
	u32 cqe_depth, i;

	cqe_depth = type == UNIC_CQ_RQ ? unic_dev->channels.rq_cqe_depth :
					 unic_dev->channels.sq_cqe_depth;

	for (i = 0; i < num; i++) {
		c = &unic_dev->channels.c[i];
		cq = type == UNIC_CQ_RQ ? &c->rq_cq : &c->sq_cq;
		unic_cq_free_resource(adev, *cq, cqe_depth);
		devm_kfree(&adev->dev, *cq);
		*cq = NULL;
	}
}

void unic_destroy_cq(struct unic_dev *unic_dev, u32 num, enum unic_cq_type type)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	enum ubase_reset_stage reset_stage;

	if (!num)
		return;

	/* The hardware does not access the configured memory after the reset,
	 * directly destroy the cq.
	 */
	reset_stage = ubase_get_reset_stage(adev);
	if (reset_stage == UBASE_RESET_STAGE_UNINIT)
		goto cq_res_destroy;

	unic_destroy_multi_jfc_context(unic_dev, type, num);

cq_res_destroy:
	unic_multi_cq_res_destroy(unic_dev, type, num);
}

int unic_napi_poll(struct napi_struct *napi, int budget)
{
	struct unic_channel *c = container_of(napi, struct unic_channel, napi);
	struct net_device *netdev = c->sq->netdev;
	struct unic_dev *unic_dev = netdev_priv(netdev);
	int work_done;

	if (unlikely(test_bit(UNIC_STATE_DOWN, &unic_dev->state))) {
		napi_complete(napi);
		return 0;
	}

	unic_poll_tx(c->sq, budget);

	work_done = unic_poll_rx(c, budget, unic_send_skb_to_stack);
	if (work_done >= budget)
		return budget;

	napi_complete_done(napi, work_done);

	return work_done;
}

void unic_cq_doorbell(struct unic_cq *cq, u32 last_ci)
{
	struct unic_jfc_db jfc_db = {0};

	if (unlikely(cq->ci == last_ci))
		return;

	jfc_db.ci = cq->ci;
	jfc_db.jfc_num = cq->jfcn;

	writeq(*(u64 *)&jfc_db, cq->db_addr);
}

void unic_clear_all_queue(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_channel *c;
	u32 i;

	mutex_lock(&unic_dev->channels.mutex);

	if (!unic_dev->channels.c)
		goto out;

	for (i = 0; i < unic_dev->channels.num; i++) {
		c = &unic_dev->channels.c[i];
		unic_clear_sq(c->sq);
		unic_clear_rq(c->rq);
	}
out:
	mutex_unlock(&unic_dev->channels.mutex);
}
