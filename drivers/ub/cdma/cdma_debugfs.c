// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <ub/ubase/ubase_comm_debugfs.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "cdma.h"
#include "cdma_queue.h"
#include "cdma_jfc.h"
#include "cdma_jfs.h"
#include "cdma_mbox.h"
#include "cdma_cmd.h"
#include "cdma_debugfs.h"

#define BUF_10_BASE 10
#define BUF_SIZE 8
#define CDMA_S_IRUSR 0400

/* ctx debugfs start */
static void cdma_get_ctx_info(struct cdma_dev *cdev,
			      struct cdma_queue *queue,
			      enum cdma_dbg_ctx_type ctx_type,
			      struct cdma_ctx_info *ctx_info)
{
#define CDMA_DBG_CTX_SIZE_256 256
#define UBASE_CTX_SIZE_128 128
	switch (ctx_type) {
	case CDMA_DBG_JFS_CTX:
		ctx_info->start_idx = queue->jfs_id;
		ctx_info->ctx_size = CDMA_DBG_CTX_SIZE_256;
		ctx_info->op = UBASE_MB_QUERY_JFS_CONTEXT;
		ctx_info->ctx_name = "jfs";
		break;
	case CDMA_DBG_SQ_JFC_CTX:
		ctx_info->start_idx = queue->jfc_id;
		ctx_info->ctx_size = UBASE_CTX_SIZE_128;
		ctx_info->op = UBASE_MB_QUERY_JFC_CONTEXT;
		ctx_info->ctx_name = "sq_jfc";
		break;
	default:
		break;
	}
}

static void cdma_print_ctx_hw_bytype(struct seq_file *s,
				     enum cdma_dbg_ctx_type ctx_type,
				     struct cdma_ctx_info *ctx_info,
				     struct ubase_cmd_mailbox *mailbox)
{
	struct cdma_jfs_ctx *jfs_ctx;
	struct cdma_jfc_ctx *jfc_ctx;

	seq_printf(s, "offset\t%s%u\n", ctx_info->ctx_name, ctx_info->start_idx);

	if (ctx_type == CDMA_DBG_JFS_CTX) {
		jfs_ctx = (struct cdma_jfs_ctx *)mailbox->buf;
		jfs_ctx->sqe_base_addr_l = 0;
		jfs_ctx->sqe_base_addr_h = 0;
		jfs_ctx->user_data_l = 0;
		jfs_ctx->user_data_h = 0;
		ubase_print_context_hw(s, jfs_ctx, ctx_info->ctx_size);
	} else if (ctx_type == CDMA_DBG_SQ_JFC_CTX) {
		jfc_ctx = (struct cdma_jfc_ctx *)mailbox->buf;
		jfc_ctx->cqe_va_l = 0;
		jfc_ctx->cqe_va_h = 0;
		jfc_ctx->cqe_token_value = 0;
		jfc_ctx->record_db_addr_l = 0;
		jfc_ctx->record_db_addr_h = 0;
		jfc_ctx->remote_token_value = 0;
		ubase_print_context_hw(s, jfc_ctx, ctx_info->ctx_size);
	}

	seq_puts(s, "\n");
}

static int cdma_dbg_dump_ctx_hw(struct seq_file *s, enum cdma_dbg_ctx_type ctx_type)
{
	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	struct auxiliary_device *adev = cdev->adev;
	u32 queue_id = cdev->cdbgfs.cfg.queue_id;
	struct cdma_ctx_info ctx_info = { 0 };
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr;
	struct cdma_queue *queue;

	spin_lock(&cdev->queue_table.lock);
	queue = idr_find(&cdev->queue_table.idr_tbl.idr, queue_id);
	if (!queue) {
		spin_unlock(&cdev->queue_table.lock);
		dev_err(&adev->dev, "find queue[%u] for dump context hw failed.\n", queue_id);
		return -EINVAL;
	}

	if (!queue->jfs_id) {
		spin_unlock(&cdev->queue_table.lock);
		dev_warn(&adev->dev, "queue resource is not initialized.\n");
		return -EINVAL;
	}

	cdma_get_ctx_info(cdev, queue, ctx_type, &ctx_info);
	spin_unlock(&cdev->queue_table.lock);

	cdma_fill_mbx_attr(&attr, ctx_info.start_idx, ctx_info.op, 0);
	mailbox = cdma_mailbox_query_ctx(cdev, &attr);
	if (!mailbox) {
		dev_err(&adev->dev, "cdma dbg post query %s ctx mbx failed.\n",
			ctx_info.ctx_name);
		return -ENOMEM;
	}

	cdma_print_ctx_hw_bytype(s, ctx_type, &ctx_info, mailbox);

	cdma_free_cmd_mailbox(cdev, mailbox);

	return 0;
}

static int cdma_dbg_dump_jfs_ctx_hw(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	return cdma_dbg_dump_ctx_hw(s, CDMA_DBG_JFS_CTX);
}

static int cdma_dbg_dump_sq_jfc_ctx_hw(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	return cdma_dbg_dump_ctx_hw(s, CDMA_DBG_SQ_JFC_CTX);
}

static void cdma_get_jfs_cfg(struct cdma_queue *queue, struct seq_file *s)
{
	struct cdma_jfs_cfg *cfg;

	if (!queue->jfs)
		return;

	cfg = &queue->jfs->cfg;
	seq_printf(s, "%-13u", cfg->depth);
	seq_printf(s, "%-12u", cfg->flag.value);
	seq_printf(s, "%-17u", cfg->eid_index);
	seq_printf(s, "%-10u", cfg->priority);
	seq_printf(s, "%-9u", cfg->max_sge);
	seq_printf(s, "%-10u", cfg->max_rsge);
	seq_printf(s, "%-11u", cfg->rnr_retry);
	seq_printf(s, "%-13u", cfg->err_timeout);
	seq_printf(s, "%-14u", cfg->jfc_id);
	seq_printf(s, "%-15u", cfg->sqe_pos);
	seq_printf(s, "%-11u", cfg->tpn);
	seq_printf(s, "%-15u", cfg->pld_pos);
	seq_printf(s, "%-16u", cfg->queue_id);
}

static void cdma_get_jfc_cfg(struct cdma_queue *queue, struct seq_file *s)
{
	struct cdma_jfc_cfg *cfg;

	if (!queue->jfc)
		return;

	cfg = &queue->jfc->jfc_cfg;
	seq_printf(s, "%-13u", cfg->depth);
	seq_printf(s, "%-12u", cfg->ceqn);
	seq_printf(s, "%-16u", cfg->queue_id);
}

static void cdma_get_jfs_title(struct seq_file *s)
{
	seq_puts(s, "depth        ");
	seq_puts(s, "flag        ");
	seq_puts(s, "eid_index        ");
	seq_puts(s, "priority  ");
	seq_puts(s, "max_sge  ");
	seq_puts(s, "max_rsge  ");
	seq_puts(s, "rnr_retry  ");
	seq_puts(s, "err_timeout  ");
	seq_puts(s, "jfc_id        ");
	seq_puts(s, "sqe_pos        ");
	seq_puts(s, "tpn        ");
	seq_puts(s, "pld_pos        ");
	seq_puts(s, "queue_id        ");
	seq_puts(s, "\n");
}

static void cdma_get_jfc_title(struct seq_file *s)
{
	seq_puts(s, "depth        ");
	seq_puts(s, "flag        ");
	seq_puts(s, "ceqn        ");
	seq_puts(s, "queue_id        ");
	seq_puts(s, "\n");
}

static int cdma_dbg_dump_ctx(struct seq_file *s, enum cdma_dbg_ctx_type ctx_type)
{
	struct cdma_dbg_context {
		void (*get_title)(struct seq_file *s);
		void (*get_cfg)(struct cdma_queue *queue, struct seq_file *s);
	} dbg_ctx[] = {
		{
			.get_title = cdma_get_jfs_title,
			.get_cfg = cdma_get_jfs_cfg,
		},
		{
			.get_title = cdma_get_jfc_title,
			.get_cfg = cdma_get_jfc_cfg,
		},
	};
	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	u32 queue_id = cdev->cdbgfs.cfg.queue_id;
	struct cdma_queue *queue;

	dbg_ctx[ctx_type].get_title(s);

	spin_lock(&cdev->queue_table.lock);
	queue = idr_find(&cdev->queue_table.idr_tbl.idr, queue_id);
	if (!queue) {
		spin_unlock(&cdev->queue_table.lock);
		dev_err(&cdev->adev->dev, "find queue[%u] for dump context failed.\n", queue_id);
		return -EINVAL;
	}

	dbg_ctx[ctx_type].get_cfg(queue, s);

	spin_unlock(&cdev->queue_table.lock);

	return 0;
}

static int cdma_dbg_dump_jfs_ctx(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	return cdma_dbg_dump_ctx(s, CDMA_DBG_JFS_CTX);
}

static int cdma_dbg_dump_sq_jfc_ctx(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	return cdma_dbg_dump_ctx(s, CDMA_DBG_SQ_JFC_CTX);
}
/* ctx debugfs end */

/* resource debugfs start */
static int cdma_dbg_dump_dev_info(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	u32 seid_idx, seid, upi, i;
	u8 eu_num;

	mutex_lock(&cdev->eu_mutex);
	eu_num = cdev->base.attr.eu_num;
	seq_printf(s, "EU_ENTRY_NUM: %u\n", eu_num);
	for (i = 0; i < eu_num; i++) {
		seid_idx = cdev->base.attr.eus[i].eid_idx;
		seid = cdev->base.attr.eus[i].eid.dw0;
		upi = cdev->base.attr.eus[i].upi;
		seq_printf(s, "SEID_IDX: %u, SEID: %u, UPI: %u\n", seid_idx, seid, upi);
	}
	mutex_unlock(&cdev->eu_mutex);

	return 0;
}

static int cdma_dbg_dump_cap_info(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	struct cdma_caps *caps = &cdev->caps;

	seq_printf(s, "MAX_JFC: %u\n", caps->jfc.max_cnt);
	seq_printf(s, "MAX_JFS: %u\n", caps->jfs.max_cnt);
	seq_printf(s, "MAX_JFC_DEPTH: %u\n", caps->jfc.depth);
	seq_printf(s, "MAX_JFS_DEPTH: %u\n", caps->jfs.depth);
	seq_printf(s, "MAX_JFS_SGE: %u\n", caps->jfs_sge);
	seq_printf(s, "MAX_JFS_RSGE: %u\n", caps->jfs_rsge);
	seq_printf(s, "MAX_MSG_SIZE: %u\n", caps->max_msg_len);
	seq_printf(s, "TRANS_MODE: %u\n", caps->trans_mode);
	seq_printf(s, "CEQ_CNT: %u\n", caps->comp_vector_cnt);

	return 0;
}

static int cdma_dbg_dump_queue_info(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	u32 queue_id = cdev->cdbgfs.cfg.queue_id;
	struct cdma_queue *queue;

	spin_lock(&cdev->queue_table.lock);
	queue = idr_find(&cdev->queue_table.idr_tbl.idr, queue_id);
	if (!queue) {
		spin_unlock(&cdev->queue_table.lock);
		dev_err(&cdev->adev->dev, "find queue[%u] for dump queue info failed.\n", queue_id);
		return -EINVAL;
	}

	seq_printf(s, "QUEUE_DEPTH: %u\n", queue->cfg.queue_depth);
	seq_printf(s, "DST CNA: 0x%x\n", queue->cfg.dcna);
	seq_printf(s, "RMT EID: 0x%x\n", queue->cfg.rmt_eid.dw0);
	seq_printf(s, "PRIORITY: %u\n", queue->cfg.priority);

	spin_unlock(&cdev->queue_table.lock);

	return 0;
}
/* resource debugfs end */

/* entry info start */
static void cdma_dbg_dump_sqe_info(struct cdma_sqe_ctl *sqe_ctl, struct seq_file *s)
{
	seq_printf(s, "sqe bb idx: %u\n", sqe_ctl->sqe_bb_idx);
	seq_printf(s, "place odr: %u\n", sqe_ctl->place_odr);
	seq_printf(s, "comp order: %u\n", sqe_ctl->comp_order);
	seq_printf(s, "fence: %u\n", sqe_ctl->fence);
	seq_printf(s, "se: %u\n", sqe_ctl->se);
	seq_printf(s, "cqe: %u\n", sqe_ctl->cqe);
	seq_printf(s, "owner: %u\n", sqe_ctl->owner);
	seq_printf(s, "opcode: %u\n", sqe_ctl->opcode);
	seq_printf(s, "tpn: %u\n", sqe_ctl->tpn);
	seq_printf(s, "sge num: %u\n", sqe_ctl->sge_num);
	seq_printf(s, "rmt eid: %u\n", sqe_ctl->rmt_eid[0]);
}

static void cdma_dbg_dump_cqe_info(struct cdma_jfc_cqe *cqe, struct seq_file *s)
{
	seq_printf(s, "sr: %u\n", cqe->s_r);
	seq_printf(s, "owner: %u\n", cqe->owner);
	seq_printf(s, "opcode: %u\n", cqe->opcode);
	seq_printf(s, "fd: %u\n", cqe->fd);
	seq_printf(s, "substatus: %u\n", cqe->substatus);
	seq_printf(s, "status: %u\n", cqe->status);
	seq_printf(s, "entry idx: %u\n", cqe->entry_idx);
	seq_printf(s, "tpn: %u\n", cqe->tpn);
	seq_printf(s, "rmt eid: %u\n", cqe->rmt_eid[0]);
	seq_printf(s, "byte cnt: %u\n", cqe->byte_cnt);
}

static void cdma_dbg_dum_eu(struct cdma_dev *cdev, int i, struct seq_file *s)
{
	struct eu_info *eu = &cdev->base.attr.eus[i];

	seq_printf(s, "%d: ", i);
	seq_printf(s, "idx[0x%x] ", eu->eid_idx);
	seq_printf(s, "eid[0x%x] ", eu->eid.dw0);
	seq_printf(s, "upi[0x%x]\n", eu->upi);
}

static int cdma_dbg_dump_sqe(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	u32 queue_id = cdev->cdbgfs.cfg.queue_id;
	u32 entry_pi = cdev->cdbgfs.cfg.entry_pi;
	struct cdma_sqe_ctl *sqe_ctl;
	struct cdma_queue *queue;
	struct cdma_jfs *jfs;

	spin_lock(&cdev->queue_table.lock);
	queue = idr_find(&cdev->queue_table.idr_tbl.idr, queue_id);
	if (!queue) {
		spin_unlock(&cdev->queue_table.lock);
		dev_err(&cdev->adev->dev, "find queue[%u] for dump sqe failed.\n", queue_id);
		return -EINVAL;
	}

	if (queue->jfs && queue->is_kernel) {
		jfs = to_cdma_jfs(queue->jfs);
		if (entry_pi >= jfs->base_jfs.cfg.depth) {
			spin_unlock(&cdev->queue_table.lock);
			dev_err(&cdev->adev->dev, "pi [%u] overflow for dump sqe.\n", entry_pi);
			return -EINVAL;
		}

		spin_lock(&jfs->sq.lock);
		sqe_ctl = (struct cdma_sqe_ctl *)(jfs->sq.buf.kva +
			   (entry_pi & (jfs->sq.buf.entry_cnt - 1)) *
			    jfs->sq.buf.entry_size);
		cdma_dbg_dump_sqe_info(sqe_ctl, s);
		spin_unlock(&jfs->sq.lock);
	} else {
		dev_warn(&cdev->adev->dev, "not support queue[%u] for dump sqe.\n", queue_id);
	}

	spin_unlock(&cdev->queue_table.lock);

	return 0;
}

static int cdma_dbg_dump_cqe(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	u32 queue_id = cdev->cdbgfs.cfg.queue_id;
	u32 entry_ci = cdev->cdbgfs.cfg.entry_ci;
	struct cdma_queue *queue;
	struct cdma_jfc_cqe *cqe;
	struct cdma_jfc *jfc;

	spin_lock(&cdev->queue_table.lock);
	queue = idr_find(&cdev->queue_table.idr_tbl.idr, queue_id);
	if (!queue) {
		spin_unlock(&cdev->queue_table.lock);
		dev_err(&cdev->adev->dev, "find queue[%u] for dump cqe failed.\n", queue_id);
		return -EINVAL;
	}

	if (queue->jfc && queue->is_kernel) {
		jfc = to_cdma_jfc(queue->jfc);
		if (entry_ci >= jfc->base.jfc_cfg.depth) {
			spin_unlock(&cdev->queue_table.lock);
			dev_err(&cdev->adev->dev, "ci [%u] overflow for dump cqe.\n", entry_ci);
			return -EINVAL;
		}

		spin_lock(&jfc->lock);
		cqe = (struct cdma_jfc_cqe *)(jfc->buf.kva +
		      (entry_ci & (jfc->buf.entry_cnt - 1)) *
		      jfc->buf.entry_size);
		cdma_dbg_dump_cqe_info(cqe, s);
		spin_unlock(&jfc->lock);
	} else {
		dev_warn(&cdev->adev->dev, "not support queue[%u] for dump cqe.\n", queue_id);
	}

	spin_unlock(&cdev->queue_table.lock);

	return 0;
}

/* Dump eu info */
static int cdma_dbg_dump_eu(struct seq_file *s, void *data)
{
	if (!s || !s->private)
		return -EINVAL;

	struct cdma_dev *cdev = dev_get_drvdata(s->private);
	int ret, i;

	ret = cdma_ctrlq_query_eu(cdev);
	if (ret)
		return ret;

	mutex_lock(&cdev->eu_mutex);
	for (i = 0; i < cdev->base.attr.eu_num; i++)
		cdma_dbg_dum_eu(cdev, i, s);
	mutex_unlock(&cdev->eu_mutex);

	return 0;
}
/* entry info end */

static bool cdma_dbg_dentry_support(struct device *dev, u32 property)
{
	struct cdma_dev *cdev = dev_get_drvdata(dev);

	return ubase_dbg_dentry_support(cdev->adev, property);
}

static struct ubase_dbg_dentry_info cdma_dbg_dentry[] = {
	{
		.name = "context",
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
	}, {
		.name = "resource_info",
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
	}, {
		.name = "entry_info",
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
	},
	/* keep "cdma" at the bottom and add new directory above */
	{
		.name = "cdma",
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
	},
};

static struct ubase_dbg_cmd_info cdma_dbg_cmd[] = {
	{
		.name = "jfs_context",
		.dentry_index = CDMA_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_jfs_ctx,
	}, {
		.name = "sq_jfc_context",
		.dentry_index = CDMA_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_sq_jfc_ctx,
	}, {
		.name = "jfs_context_hw",
		.dentry_index = CDMA_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_jfs_ctx_hw,
	}, {
		.name = "sq_jfc_context_hw",
		.dentry_index = CDMA_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_sq_jfc_ctx_hw,
	}, {
		.name = "dev_info",
		.dentry_index = CDMA_DBG_DENTRY_RES_INFO,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_dev_info,
	}, {
		.name = "cap_info",
		.dentry_index = CDMA_DBG_DENTRY_RES_INFO,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_cap_info,
	}, {
		.name = "queue_info",
		.dentry_index = CDMA_DBG_DENTRY_RES_INFO,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_queue_info,
	}, {
		.name = "sqe",
		.dentry_index = CDMA_DBG_DENTRY_ENTRY_INFO,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_sqe,
	}, {
		.name = "cqe",
		.dentry_index = CDMA_DBG_DENTRY_ENTRY_INFO,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_cqe,
	}, {
		.name = "eu",
		.dentry_index = CDMA_DBG_DENTRY_ENTRY_INFO,
		.property = UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = cdma_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = cdma_dbg_dump_eu,
	},
};

static ssize_t cdma_dbgfs_cfg_write_val(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos,
					enum cdma_dbgfs_cfg_type type)
{
	struct cdma_dbgfs_cfg *cfg = (struct cdma_dbgfs_cfg *)filp->private_data;
	char buf[BUF_SIZE] = { 0 };
	ssize_t len, ret;
	u32 value;

	len = simple_write_to_buffer(buf, BUF_SIZE - 1, ppos, buffer, count);
	if (len < 0)
		return len;

	ret = kstrtouint(buf, BUF_10_BASE, &value);
	if (ret)
		return ret;

	switch (type) {
	case CDMA_QUEUE_ID:
		cfg->queue_id = value;
		break;
	case CDMA_ENTRY_PI:
		cfg->entry_pi = value;
		break;
	case CDMA_ENTRY_CI:
		cfg->entry_ci = value;
		break;
	default:
		return -EINVAL;
	}

	return len;
}

static ssize_t cdma_dbgfs_cfg_read_val(struct file *filp,
				       char *buffer, size_t count, loff_t *ppos,
				       enum cdma_dbgfs_cfg_type type)
{
	struct cdma_dbgfs_cfg *cfg = (struct cdma_dbgfs_cfg *)filp->private_data;
	char buf[BUF_SIZE] = { 0 };
	u32 value = 0;
	size_t len;

	switch (type) {
	case CDMA_QUEUE_ID:
		value = cfg->queue_id;
		break;
	case CDMA_ENTRY_PI:
		value = cfg->entry_pi;
		break;
	case CDMA_ENTRY_CI:
		value = cfg->entry_ci;
		break;
	default:
		break;
	}

	len = scnprintf(buf, sizeof(buf), "%u\n", value);

	return simple_read_from_buffer(buffer, count, ppos, buf, len);
}

static ssize_t cdma_dbgfs_cfg_write_queue_id(struct file *filp,
					     const char __user *buffer,
					     size_t count, loff_t *ppos)
{
	return cdma_dbgfs_cfg_write_val(filp, buffer, count, ppos, CDMA_QUEUE_ID);
}

static ssize_t cdma_dbgfs_cfg_read_queue_id(struct file *filp,
					    char *buffer, size_t count,
					    loff_t *ppos)
{
	return cdma_dbgfs_cfg_read_val(filp, buffer, count, ppos, CDMA_QUEUE_ID);
}

static ssize_t cdma_dbgfs_cfg_write_entry_pi(struct file *filp,
					     const char __user *buffer,
					     size_t count, loff_t *ppos)
{
	return cdma_dbgfs_cfg_write_val(filp, buffer, count, ppos, CDMA_ENTRY_PI);
}

static ssize_t cdma_dbgfs_cfg_read_entry_pi(struct file *filp,
					    char *buffer, size_t count,
					    loff_t *ppos)
{
	return cdma_dbgfs_cfg_read_val(filp, buffer, count, ppos, CDMA_ENTRY_PI);
}

static ssize_t cdma_dbgfs_cfg_write_entry_ci(struct file *filp,
					     const char __user *buffer,
					     size_t count, loff_t *ppos)
{
	return cdma_dbgfs_cfg_write_val(filp, buffer, count, ppos, CDMA_ENTRY_CI);
}

static ssize_t cdma_dbgfs_cfg_read_entry_ci(struct file *filp,
					    char *buffer, size_t count,
					    loff_t *ppos)
{
	return cdma_dbgfs_cfg_read_val(filp, buffer, count, ppos, CDMA_ENTRY_CI);
}

static struct cdma_dbgfs_cfg_info cdma_dbg_cfg[] = {
	{
		.name = "queue_id",
		{true, true, true},
		{.owner = THIS_MODULE,
		.read = cdma_dbgfs_cfg_read_queue_id,
		.write = cdma_dbgfs_cfg_write_queue_id,
		.open = simple_open, },
	}, {
		.name = "entry_pi",
		{false, false, true},
		{.owner = THIS_MODULE,
		.read = cdma_dbgfs_cfg_read_entry_pi,
		.write = cdma_dbgfs_cfg_write_entry_pi,
		.open = simple_open, },
	}, {
		.name = "entry_ci",
		{false, false, true},
		{.owner = THIS_MODULE,
		.read = cdma_dbgfs_cfg_read_entry_ci,
		.write = cdma_dbgfs_cfg_write_entry_ci,
		.open = simple_open, },
	},
};

static int cdma_dbg_create_cfg_file(struct cdma_dev *cdev,
				    struct ubase_dbg_dentry_info *dentry_info,
				    u8 array_size)
{
	struct dentry *debugfs_file;
	struct dentry *cur_dir;
	size_t i, j;

	for (i = 0; i < array_size - 1; i++) {
		cur_dir = dentry_info[i].dentry;
		for (j = 0; j < ARRAY_SIZE(cdma_dbg_cfg); j++) {
			if (!cdma_dbg_cfg[j].dentry_valid[i])
				continue;
			debugfs_file = debugfs_create_file(
				cdma_dbg_cfg[j].name, CDMA_S_IRUSR, cur_dir,
				&cdev->cdbgfs.cfg, &cdma_dbg_cfg[j].file_ops);
			if (!debugfs_file)
				return -ENOMEM;
		}
	}

	return 0;
}

int cdma_dbg_init(struct cdma_dev *cdev)
{
	struct ubase_dbg_dentry_info dbg_dentry[CDMA_DBG_DENTRY_ROOT + 1] = {0};
	struct auxiliary_device *adev = cdev->adev;
	struct dentry *ubase_root_dentry;
	struct device *dev = &adev->dev;
	int ret;

	ubase_root_dentry = ubase_diag_debugfs_root(adev);
	if (!ubase_root_dentry) {
		dev_err(dev, "dbgfs root dentry does not exist.\n");
		return -ENOENT;
	}

	memcpy(dbg_dentry, cdma_dbg_dentry, sizeof(cdma_dbg_dentry));
	cdev->cdbgfs.dbgfs.dentry = debugfs_create_dir(
		dbg_dentry[ARRAY_SIZE(dbg_dentry) - 1].name, ubase_root_dentry);
	if (IS_ERR(cdev->cdbgfs.dbgfs.dentry)) {
		dev_err(dev, "create cdma debugfs root dir failed.\n");
		return PTR_ERR(cdev->cdbgfs.dbgfs.dentry);
	}

	dbg_dentry[CDMA_DBG_DENTRY_ROOT].dentry = cdev->cdbgfs.dbgfs.dentry;
	cdev->cdbgfs.dbgfs.cmd_info = cdma_dbg_cmd;
	cdev->cdbgfs.dbgfs.cmd_info_size = ARRAY_SIZE(cdma_dbg_cmd);

	ret = ubase_dbg_create_dentry(dev, &cdev->cdbgfs.dbgfs, dbg_dentry,
				      ARRAY_SIZE(dbg_dentry) - 1);
	if (ret) {
		dev_err(dev, "create cdma debugfs dentry failed, ret = %d.\n", ret);
		goto create_dentry_err;
	}

	ret = cdma_dbg_create_cfg_file(cdev, dbg_dentry, ARRAY_SIZE(dbg_dentry));
	if (ret) {
		dev_err(dev, "create cdma debugfs cfg file failed, ret = %d.\n", ret);
		goto create_dentry_err;
	}

	return 0;

create_dentry_err:
	debugfs_remove_recursive(cdev->cdbgfs.dbgfs.dentry);
	cdev->cdbgfs.dbgfs.dentry = NULL;

	return ret;
}

void cdma_dbg_uninit(struct cdma_dev *cdev)
{
	if (!cdev->cdbgfs.dbgfs.dentry)
		return;

	debugfs_remove_recursive(cdev->cdbgfs.dbgfs.dentry);
	cdev->cdbgfs.dbgfs.dentry = NULL;
}
