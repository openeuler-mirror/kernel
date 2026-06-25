// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/debugfs.h>
#include <ub/ubase/ubase_comm_debugfs.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "unic_debugfs.h"
#include "unic_dev.h"
#include "unic_event.h"
#include "unic_txrx.h"
#include "unic_ctx_debugfs.h"

static inline void unic_jfs_ctx_titles_print(struct seq_file *s)
{
	seq_puts(s, "SQ_ID  SQE_BB_SHIFT  STATE  JFS_MODE  TX_JFCN\n");
}

static void unic_dump_jfs_ctx_info_sw(struct unic_sq *sq, struct seq_file *s,
				      u32 index)
{
	struct unic_jfs_ctx *ctx = &sq->jfs_ctx;

	seq_printf(s, "%-7u", index);
	seq_printf(s, "%-14u", ctx->sqe_bb_shift);
	seq_printf(s, "%-7u", ctx->state);
	seq_printf(s, "%-10u", ctx->jfs_mode);
	seq_printf(s, "%-9u\n", ctx->tx_jfcn);
}

static inline void unic_jfr_ctx_titles_print(struct seq_file *s)
{
	seq_puts(s, "RQ_ID  STATE  RQE_SHIFT  RX_JFCN  PI     CI     ");
	seq_puts(s, "RECORD_DB_EN\n");
}

static void unic_dump_jfr_ctx_info_sw(struct unic_rq *rq, struct seq_file *s,
				      u32 index)
{
	struct unic_jfr_ctx *ctx = &rq->jfr_ctx;
	u32 jfcn;

	jfcn = ctx->jfcn_l | (ctx->jfcn_h << UNIC_JFR_JFCN_H_OFFSET);

	seq_printf(s, "%-7u", index);
	seq_printf(s, "%-7u", ctx->state);
	seq_printf(s, "%-11u", ctx->rqe_shift);
	seq_printf(s, "%-9u", jfcn);
	seq_printf(s, "%-7u", ctx->pi);
	seq_printf(s, "%-7u", ctx->ci);
	seq_printf(s, "%-14u\n", ctx->record_db_en);
}

static inline void unic_jfc_ctx_titles_print(struct seq_file *s)
{
	seq_puts(s, "CQ_ID  ARM_ST  STATE  INLINE_EN  SHIFT  CQE_COAL_CNT  ");
	seq_puts(s, "CEQN  RECORD_DB_EN  CQE_COAL_PEIRIOD\n");
}

static void unic_dump_jfc_ctx_info_sw(struct unic_cq *cq, struct seq_file *s,
				      u32 index)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_jfc_ctx *ctx = &cq->jfc_ctx;

	seq_printf(s, "%-7u", index);
	seq_printf(s, "%-8u", ctx->arm_st);
	seq_printf(s, "%-7u", ctx->state);
	seq_printf(s, "%-11u", ctx->inline_en);
	seq_printf(s, "%-7u", ctx->shift);
	seq_printf(s, "%-14u", ctx->cqe_coalesce_cnt);

	if (unic_jfc_support_ceqn9(unic_dev))
		seq_printf(s, "%-6u", ctx->dw2_ceqn9.ceqn);

	else
		seq_printf(s, "%-6u", ctx->dw2_ceqn8.ceqn);
	seq_printf(s, "%-14u", ctx->record_db_en);
	seq_printf(s, "%-18u\n", ctx->cqe_coalesce_period);
}

static inline void unic_jfs_sq_info_print(struct seq_file *s)
{
	seq_puts(s, "SQ_ID  PI  CI  LAST_PI  START_CI  ");
	seq_puts(s, "CHECK_CI_LATE  QUEUE_INDEX  QUEUE_STATE  ");
	seq_puts(s, "TX_BUFF_NUM  TX_BUFF_PI  TX_BUFF_CI\n");
}

static inline void unic_jfr_rq_info_print(struct seq_file *s)
{
	seq_puts(s, "RQ_ID  PI  CI  QUEUE_INDEX  PENDING_BUF\n");
}

static inline void unic_jfc_sq_cq_info_print(struct seq_file *s)
{
	seq_puts(s, "SQ_CQ_ID  JFCN  CI\n");
}

static inline void unic_jfc_rq_cq_info_print(struct seq_file *s)
{
	seq_puts(s, "RQ_CQ_ID  JFCN  CI\n");
}

static void unic_get_jfs_sq_info(struct unic_dev *unic_dev,
				 struct seq_file *s, u32 index)
{
	struct unic_sq *sq = unic_dev->channels.c[index].sq;
	struct net_device *netdev = unic_dev->comdev.netdev;
	struct netdev_queue *queue;

	queue = netdev_get_tx_queue(netdev, sq->queue_index);

	seq_printf(s, "%-7u", index);
	seq_printf(s, "%-4u", sq->pi);
	seq_printf(s, "%-4u", sq->ci);
	seq_printf(s, "%-9u", sq->last_pi);
	seq_printf(s, "%-10u", sq->start_pi);
	seq_printf(s, "%-15d", sq->check_ci_late);
	seq_printf(s, "%-13u", sq->queue_index);
	seq_printf(s, "%-13lu", queue->state);
	seq_printf(s, "%-13u", sq->tx_buff->num);
	seq_printf(s, "%-12u", sq->tx_buff->pi);
	seq_printf(s, "%-10u\n", sq->tx_buff->ci);
}

static void unic_get_jfr_rq_info(struct unic_dev *unic_dev,
				 struct seq_file *s, u32 index)
{
	struct unic_rq *rq = unic_dev->channels.c[index].rq;

	seq_printf(s, "%-7u", index);
	seq_printf(s, "%-4u", rq->pi);
	seq_printf(s, "%-4u", rq->ci);
	seq_printf(s, "%-13u", rq->queue_index);
	seq_printf(s, "%-11u\n", rq->pending_buf);
}

static void unic_get_jfc_sq_cq_info(struct unic_dev *unic_dev,
				    struct seq_file *s, u32 index)
{
	struct unic_cq *sq_cq = unic_dev->channels.c[index].sq_cq;

	seq_printf(s, "%-10u", index);
	seq_printf(s, "%-6u", sq_cq->jfcn);
	seq_printf(s, "%-2u\n", sq_cq->ci);
}

static void unic_get_jfc_rq_cq_info(struct unic_dev *unic_dev,
				    struct seq_file *s, u32 index)
{
	struct unic_cq *rq_cq = unic_dev->channels.c[index].rq_cq;

	seq_printf(s, "%-10u", index);
	seq_printf(s, "%-6u", rq_cq->jfcn);
	seq_printf(s, "%-2u\n", rq_cq->ci);
}

static void unic_get_jfs_ctx_sw(struct unic_channels *channels,
				struct seq_file *s, u32 index)
{
	struct unic_channel *channel = &channels->c[index];

	unic_dump_jfs_ctx_info_sw(channel->sq, s, index);
}

static void unic_get_jfr_ctx_sw(struct unic_channels *channels,
				struct seq_file *s, u32 index)
{
	struct unic_channel *channel = &channels->c[index];

	unic_dump_jfr_ctx_info_sw(channel->rq, s, index);
}

static void unic_get_sq_jfc_ctx_sw(struct unic_channels *channels,
				   struct seq_file *s, u32 index)
{
	struct unic_channel *channel = &channels->c[index];

	unic_dump_jfc_ctx_info_sw(channel->sq->cq, s, index);
}

static void unic_get_rq_jfc_ctx_sw(struct unic_channels *channels,
				   struct seq_file *s, u32 index)
{
	struct unic_channel *channel = &channels->c[index];

	unic_dump_jfc_ctx_info_sw(channel->rq->cq, s, index);
}

static int unic_dbg_dump_ctx_sw(struct seq_file *s, void *data,
				enum unic_dbg_ctx_type ctx_type)
{
	struct unic_dbg_context {
		void (*print_ctx_titles)(struct seq_file *s);
		void (*get_ctx)(struct unic_channels *channels,
				struct seq_file *s, u32 index);
	} dbg_ctx[] = {
		{
			.print_ctx_titles = unic_jfs_ctx_titles_print,
			.get_ctx = unic_get_jfs_ctx_sw,
		},
		{
			.print_ctx_titles = unic_jfr_ctx_titles_print,
			.get_ctx = unic_get_jfr_ctx_sw,
		},
		{
			.print_ctx_titles = unic_jfc_ctx_titles_print,
			.get_ctx = unic_get_sq_jfc_ctx_sw,
		},
		{
			.print_ctx_titles = unic_jfc_ctx_titles_print,
			.get_ctx = unic_get_rq_jfc_ctx_sw,
		},
	};
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	int ret = 0;
	u32 i;

	dbg_ctx[ctx_type].print_ctx_titles(s);

	if (!mutex_trylock(&unic_dev->channels.mutex))
		return -EBUSY;

	if (__unic_resetting(unic_dev) || !unic_dev->channels.c) {
		ret = -EBUSY;
		goto out;
	}

	for (i = 0; i < unic_dev->channels.num; i++)
		dbg_ctx[ctx_type].get_ctx(&unic_dev->channels, s, i);

out:
	mutex_unlock(&unic_dev->channels.mutex);

	return ret;
}

int unic_dbg_dump_jfs_ctx_sw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_ctx_sw(s, data, UNIC_DBG_JFS_CTX);
}

int unic_dbg_dump_jfr_ctx_sw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_ctx_sw(s, data, UNIC_DBG_JFR_CTX);
}

int unic_dbg_dump_rq_jfc_ctx_sw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_ctx_sw(s, data, UNIC_DBG_RQ_JFC_CTX);
}

int unic_dbg_dump_sq_jfc_ctx_sw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_ctx_sw(s, data, UNIC_DBG_SQ_JFC_CTX);
}

int unic_dbg_dump_sq_rq_cq_info(struct seq_file *s, void *data)
{
	struct unic_dbg_context {
		void (*print_titles)(struct seq_file *s);
		void (*get_info)(struct unic_dev *unic_dev, struct seq_file *s,
				 u32 index);
	} dbg_ctx[] = {
		{
			.print_titles = unic_jfs_sq_info_print,
			.get_info = unic_get_jfs_sq_info,
		},
		{
			.print_titles = unic_jfr_rq_info_print,
			.get_info = unic_get_jfr_rq_info,
		},
		{
			.print_titles = unic_jfc_sq_cq_info_print,
			.get_info = unic_get_jfc_sq_cq_info,
		},
		{
			.print_titles = unic_jfc_rq_cq_info_print,
			.get_info = unic_get_jfc_rq_cq_info,
		},
	};
	struct unic_dev *priv = dev_get_drvdata(s->private);
	u32 ctx_num = ARRAY_SIZE(dbg_ctx);
	int ret = 0;
	u32 i, j;

	if (!mutex_trylock(&priv->channels.mutex))
		return -EBUSY;

	if (__unic_resetting(priv) || !priv->channels.c) {
		ret = -EBUSY;
		goto out;
	}

	for (i = 0; i < ctx_num; i++) {
		dbg_ctx[i].print_titles(s);
		for (j = 0; j < priv->channels.num; j++)
			dbg_ctx[i].get_info(priv, s, j);

		seq_puts(s, "\n");
	}

out:
	mutex_unlock(&priv->channels.mutex);
	return ret;
}

static int unic_dbg_dump_context_hw(struct seq_file *s, void *data,
				    enum unic_dbg_ctx_type ctx_type)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_ctx_info ctx_info = {0};
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret = 0;
	u32 i;

	if (!mutex_trylock(&unic_dev->channels.mutex))
		return -EBUSY;

	if (__unic_resetting(unic_dev) ||
	    !unic_dev->channels.c) {
		ret = -EBUSY;
		goto channel_ready_err;
	}

	mailbox = ubase_alloc_cmd_mailbox(adev);
	if (IS_ERR_OR_NULL(mailbox)) {
		unic_err(unic_dev, "failed to alloc mailbox for dump context.\n");
		ret = -ENOMEM;
		goto channel_ready_err;
	}

	ret = unic_get_ctx_info(unic_dev, ctx_type, &ctx_info);
	if (ret)
		goto upgrade_ctx_err;

	for (i = 0; i < unic_dev->channels.num; i++) {
		ubase_fill_mbx_attr(&attr, i + ctx_info.start_idx, ctx_info.op,
				    0);
		ret = ubase_hw_upgrade_ctx_ex(adev, &attr, mailbox);
		if (ret) {
			unic_err(unic_dev,
				 "failed to post query %s ctx mbx, ret = %d.\n",
				 ctx_info.ctx_name, ret);
			goto upgrade_ctx_err;
		}

		seq_printf(s, "offset\t%s", ctx_info.ctx_name);
		seq_printf(s, "%u\n", i);
		unic_mask_ctx_key_words(mailbox->buf, ctx_type);
		ubase_print_context_hw(s, mailbox->buf, ctx_info.ctx_size);
		seq_puts(s, "\n");
	}

upgrade_ctx_err:
	ubase_free_cmd_mailbox(adev, mailbox);
channel_ready_err:
	mutex_unlock(&unic_dev->channels.mutex);

	return ret;
}

int unic_dbg_dump_jfs_context_hw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_context_hw(s, data, UNIC_DBG_JFS_CTX);
}

int unic_dbg_dump_jfr_context_hw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_context_hw(s, data, UNIC_DBG_JFR_CTX);
}

int unic_dbg_dump_sq_jfc_context_hw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_context_hw(s, data, UNIC_DBG_SQ_JFC_CTX);
}

int unic_dbg_dump_rq_jfc_context_hw(struct seq_file *s, void *data)
{
	return unic_dbg_dump_context_hw(s, data, UNIC_DBG_RQ_JFC_CTX);
}
