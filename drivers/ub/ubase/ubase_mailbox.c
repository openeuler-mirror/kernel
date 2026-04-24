// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/dmapool.h>
#include <linux/slab.h>
#include <linux/ummu_core.h>

#include "ubase_cmd.h"
#include "ubase_trace.h"
#include "ubase_usc.h"
#include "ubase_mailbox.h"

int ubase_mbox_cmd_init(struct ubase_dev *udev)
{
	struct ubase_mbx_event_context *ctx = &udev->mb_cmd.ctx;

	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return 0;

	udev->mb_cmd.pool = dma_pool_create("ubase_mbox", udev->dev,
					    UBASE_MAILBOX_SIZE,
					    UBASE_MAILBOX_SIZE, 0);
	if (!udev->mb_cmd.pool)
		return -ENOMEM;

	sema_init(&udev->mb_cmd.sem, 1);
	init_completion(&ctx->done);

	return 0;
}

void ubase_mbox_cmd_uninit(struct ubase_dev *udev)
{
	if (!udev->mb_cmd.pool)
		return;

	ubase_mailbox_buff_free(udev);

	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return;

	dma_pool_destroy(udev->mb_cmd.pool);
	udev->mb_cmd.pool = NULL;
}

struct ubase_cmd_mailbox *__ubase_alloc_cmd_mailbox(struct ubase_dev *udev)
{
	struct ubase_cmd_mailbox *mailbox;

	if (!udev->mb_cmd.pool) {
		ubase_err(udev, "failed to alloc mailbox, pool is null.\n");
		return NULL;
	}

	mailbox = kzalloc(sizeof(*mailbox), GFP_KERNEL);
	if (!mailbox) {
		ubase_err(udev, "failed to alloc mailbox.\n");
		goto failed_alloc_mailbox;
	}

	mailbox->buf = dma_pool_zalloc(udev->mb_cmd.pool, GFP_KERNEL,
				       &mailbox->dma);
	if (!mailbox->buf) {
		ubase_err(udev, "failed to alloc buffer of mailbox.\n");
		goto failed_alloc_mailbox_buf;
	}

	atomic_set(&mailbox->count, 1);

	return mailbox;

failed_alloc_mailbox_buf:
	kfree(mailbox);
failed_alloc_mailbox:
	return NULL;
}

/**
 * ubase_alloc_cmd_mailbox() - Alloc mailbox buffer
 * @aux_dev: auxiliary device
 *
 * The function is used to alloc mailbox buffer.
 *
 * Context: Process context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct ubase_cmd_mailbox
 */
struct ubase_cmd_mailbox *ubase_alloc_cmd_mailbox(struct auxiliary_device *aux_dev)
{
	struct ubase_dev *udev;

	if (!aux_dev)
		return NULL;

	udev = __ubase_get_udev_by_adev(aux_dev);

	return __ubase_alloc_cmd_mailbox(udev);
}
EXPORT_SYMBOL(ubase_alloc_cmd_mailbox);

void __ubase_free_cmd_mailbox(struct ubase_dev *udev,
			      struct ubase_cmd_mailbox *mailbox)
{
	if (!mailbox) {
		ubase_err(udev, "Invalid mailbox.\n");
		return;
	}

	if (!atomic_dec_and_test(&mailbox->count))
		return;

	dma_pool_free(udev->mb_cmd.pool, mailbox->buf, mailbox->dma);
	kfree(mailbox);
}

/**
 * ubase_free_cmd_mailbox() - Free mailbox buffer
 * @aux_dev: auxiliary device
 * @mailbox: mailbox command address
 *
 * The function is used to free mailbox buffer.
 *
 * Context: Process context.
 */
void ubase_free_cmd_mailbox(struct auxiliary_device *aux_dev,
			    struct ubase_cmd_mailbox *mailbox)
{
	struct ubase_dev *udev;

	if (!aux_dev)
		return;

	udev = __ubase_get_udev_by_adev(aux_dev);

	trace_ubase_free_mailbox_user(udev->dev, &mailbox->count, udev->mb_cmd.ctx.seq_num);
	__ubase_free_cmd_mailbox(udev, mailbox);
}
EXPORT_SYMBOL(ubase_free_cmd_mailbox);

void ubase_mailbox_buff_free(struct ubase_dev *udev)
{
	struct ubase_mbx_event_context *ctx = &udev->mb_cmd.ctx;

	if (ctx->mbx_buff) {
		trace_ubase_free_mailbox_self(udev->dev, &ctx->mbx_buff->count, ctx->seq_num);
		__ubase_free_cmd_mailbox(udev, ctx->mbx_buff);
		ctx->mbx_buff = NULL;
	}
}

static int ubase_post_mailbox(struct ubase_dev *udev,
			      struct ubase_cmdq_desc *desc,
			      u32 timeout, u8 *complete_status, bool is_read)
{
	union ubase_mbox *mb;
	unsigned long end;
	u32 hw_run;
	int ret;

	end = msecs_to_jiffies(timeout) + jiffies;
	mb = (union ubase_mbox *)desc->data;

	while (1) {
		desc->flag = cpu_to_le16(UBASE_CMD_FLAG_NO_INTR | UBASE_CMD_FLAG_IN);
		if (is_read)
			desc->flag |= cpu_to_le16(UBASE_CMD_FLAG_WR);

		ret = ubase_send_cmd(udev, desc, 1);
		hw_run = is_read ? mb->query_hw_run : 0;
		if (!ret && !hw_run)
			break;

		if (time_after(jiffies, end)) {
			dev_err_ratelimited(udev->dev,
					    "failed to wait mbox, ret = %d, hw_run = %u.\n",
					    ret, hw_run);
			return -ETIMEDOUT;
		}

		cond_resched();
	}

	if (!ret)
		*complete_status =
			(u8)(is_read ? mb->query_status : mb->status);

	return ret;
}

static int ubase_poll_mbox_done(struct ubase_dev *udev, u32 timeout)
{
	struct ubase_cmdq_desc desc;
	u8 status = 0;
	int ret;

	ubase_cmd_setup_basic_desc(&desc, UBASE_OPC_QUERY_MB_ST, true, 1);

	ret = ubase_post_mailbox(udev, &desc, timeout, &status, true);
	if (!ret) {
		if (!status) {
			ubase_err(udev,
				  "failed to query ubase mailbox, status = %u.\n",
				  status);
			return -EBUSY;
		}
	} else
		dev_err_ratelimited(udev->dev,
				    "failed to check mbox status = %u, ret = %d.\n",
				    status, ret);

	return ret;
}

static void ubase_mbox_desc_init(struct ubase_dev *udev, union ubase_mbox *mb,
				 u64 in_param, struct ubase_mbx_attr *attr)
{
	memset(mb, 0, sizeof(*mb));
	mb->in_param_l = cpu_to_le32(lower_32_bits(in_param));
	mb->in_param_h = cpu_to_le32(upper_32_bits(in_param));
	mb->cmd = attr->op;
	mb->tag = attr->tag;
	mb->mbx_ue_id = attr->mbx_ue_id;
}

static int ubase_cmd_mbox_poll(struct ubase_dev *udev,
			       struct ubase_mbx_attr *attr,
			       struct ubase_cmd_mailbox *mailbox)
{
	struct ubase_cmdq_desc desc;
	union ubase_mbox *mb;
	u8 status = 0;
	int ret;

	if (udev->reset_stage == UBASE_RESET_STAGE_UNINIT)
		return 0;

	mb = (union ubase_mbox *)desc.data;

	ubase_cmd_setup_basic_desc(&desc, UBASE_OPC_POST_MB, false, 1);

	ubase_mbox_desc_init(udev, mb, (u64)mailbox->dma, attr);

	mb->seq_num = CMD_MBX_POLL_VALUE;

	ret = ubase_post_mailbox(udev, &desc, UBASE_MBX_TX_TIMEOUT, &status,
				 false);
	if (ret) {
		ubase_err(udev,
			  "failed to post mailbox 0x%x in poll mode, status = %u, ret = %d.\n",
			  attr->op, status, ret);
		return ret;
	}

	return ubase_poll_mbox_done(udev, UBASE_MBX_TX_TIMEOUT);
}

static int ubase_cmd_mbox_event(struct ubase_dev *udev,
				struct ubase_mbx_attr *attr,
				struct ubase_cmd_mailbox *mailbox)
{
	union ubase_mbox mb_out = {0};
	union ubase_mbox mb_in = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	if (udev->reset_stage == UBASE_RESET_STAGE_UNINIT)
		return 0;

	ubase_mbox_desc_init(udev, &mb_in, (u64)mailbox->dma, attr);

	mb_in.event_en = 1;
	__ubase_fill_inout_buf(&in, UBASE_OPC_POST_MB, false,
			       sizeof(union ubase_mbox), (void *)&mb_in);
	__ubase_fill_inout_buf(&out, UBASE_OPC_POST_MB, false,
			       sizeof(union ubase_mbox), (void *)&mb_out);

	ret = ubase_post_mailbox_by_event(udev, &in, &out, mailbox);
	if (ret)
		ubase_err(udev,
			  "failed to post mailbox 0x%x in event mode, ret = %d.\n",
			  attr->op, ret);

	return ret;
}

int ubase_create_ctx_page(struct ubase_dev *udev,
			  struct ubase_ctx_buf_cap *ctx_buf,
			  struct ubase_ctx_page **ctx_page, u32 npage)
{
	int ret;

	*ctx_page = kzalloc(sizeof(struct ubase_ctx_page), GFP_KERNEL);
	if (!(*ctx_page))
		return -ENOMEM;

	(*ctx_page)->iova = ctx_buf->dma_ctx_buf_ba + npage * PAGE_SIZE;
	refcount_set(&(*ctx_page)->refcount, 1);
	(*ctx_page)->npage = npage;
	ret = ummu_fill_pages(ctx_buf->slot, (*ctx_page)->iova,
			      UBASE_IOVA_COMM_PFN_CNT);
	if (ret) {
		ubase_err(udev, "failed to fill pages in ummu, ret = %d\n", ret);
		kfree(*ctx_page);
		*ctx_page = NULL;
	}

	return ret;
}

void ubase_destroy_ctx_page(struct ubase_dev *udev,
			    struct ubase_ctx_page *ctx_page,
			    struct ubase_ctx_buf_cap *ctx_buf)
{
	int ret;

	ret = ummu_drain_pages(ctx_buf->slot, ctx_page->iova,
			       UBASE_IOVA_COMM_PFN_CNT);
	if (ret)
		ubase_err(udev,
			  "failed to drain pages in ummu, npage = %u, ret = %d.\n",
			  ctx_page->npage, ret);

	kfree(ctx_page);
}

static int ubase_use_buf_ctx_page(struct ubase_dev *udev,
				  struct ubase_ctx_buf_cap *ctx_buf, u32 tag)
{
	u32 cnt_per_page_shift = ctx_buf->cnt_per_page_shift;
	u32 npage = tag >> cnt_per_page_shift;
	struct ubase_ctx_page *ctx_page;
	int ret;

	mutex_lock(&ctx_buf->ctx_mutex);

	ctx_page = (struct ubase_ctx_page *)xa_load(&ctx_buf->ctx_xa, npage);
	if (!ctx_page) {
		ret = ubase_create_ctx_page(udev, ctx_buf, &ctx_page, npage);
		if (ret) {
			ubase_err(udev, "failed to create context page, ret = %d.\n",
				  ret);
			goto err_create;
		}

		ret = xa_err(xa_store(&ctx_buf->ctx_xa, npage, ctx_page,
				      GFP_KERNEL));
		if (ret) {
			ubase_err(udev, "failed to store page, ret = %d.\n",
				  ret);
			goto err_store;
		}
	}

	refcount_inc(&ctx_page->refcount);
	mutex_unlock(&ctx_buf->ctx_mutex);

	atomic_set(&udev->mb_cmd.mbx_cnt, 0);
	return 0;
err_store:
	ubase_destroy_ctx_page(udev, ctx_page, ctx_buf);
err_create:
	mutex_unlock(&ctx_buf->ctx_mutex);

	return ret;
}

static void ubase_free_buf_ctx_page(struct ubase_dev *udev,
				    struct ubase_ctx_buf_cap *ctx_buf, u32 tag)
{
	struct ubase_ctx_page *ctx_page;
	u32 cnt_per_page_shift;
	u32 npage;

	if (!ctx_buf)
		return;

	cnt_per_page_shift = ctx_buf->cnt_per_page_shift;
	npage = tag >> cnt_per_page_shift;

	mutex_lock(&ctx_buf->ctx_mutex);

	ctx_page = (struct ubase_ctx_page *)xa_load(&ctx_buf->ctx_xa, npage);
	if (!ctx_page) {
		ubase_err(udev,
			  "no find ctx page in free buf page, npage = %u.\n",
			  npage);
		mutex_unlock(&ctx_buf->ctx_mutex);
		return;
	}

	refcount_dec(&ctx_page->refcount);
	if (refcount_dec_if_one(&ctx_page->refcount)) {
		ubase_info(udev,
			   "refcout of ctx page is equal to one and the ctx_page is going to erased.\n");
		xa_erase(&ctx_buf->ctx_xa, npage);
		ubase_destroy_ctx_page(udev, ctx_page, ctx_buf);
	}

	mutex_unlock(&ctx_buf->ctx_mutex);
}

static struct ubase_ctx_buf_cap*
ubase_parse_common_buf(struct ubase_mbx_attr *attr,
		       struct mbx_op_match op_matches[],
		       enum ubase_mb_type *type, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++) {
		if (attr->op == op_matches[i].op) {
			*type = op_matches[i].type;
			return op_matches[i].ctx_caps;
		}
	}

	return NULL;
}

static bool ubase_is_jfs_opcode(u8 op)
{
	switch (op) {
	case UBASE_MB_CREATE_JFS_CONTEXT:
	case UBASE_MB_MODIFY_JFS_CONTEXT:
	case UBASE_MB_DESTROY_JFS_CONTEXT:
	case UBASE_MB_QUERY_JFS_CONTEXT:
		return true;
	default:
		return false;
	}
}

static struct ubase_ctx_buf_cap*
ubase_parse_ta_opcode_buf(struct ubase_dev *udev, struct ubase_mbx_attr *attr,
			  enum ubase_mb_type *type)
{
	struct mbx_op_match ta_matches[] = {
		{UBASE_MB_CREATE_JFS_CONTEXT, UBASE_MB_CREATE, &udev->ctx_buf.jfs},
		{UBASE_MB_MODIFY_JFS_CONTEXT, UBASE_MB_MODIFY, &udev->ctx_buf.jfs},
		{UBASE_MB_DESTROY_JFS_CONTEXT, UBASE_MB_DESTROY, &udev->ctx_buf.jfs},
		{UBASE_MB_QUERY_JFS_CONTEXT, UBASE_MB_QUERY, &udev->ctx_buf.jfs},
		{UBASE_MB_CREATE_JFC_CONTEXT, UBASE_MB_CREATE, &udev->ctx_buf.jfc},
		{UBASE_MB_MODIFY_JFC_CONTEXT, UBASE_MB_MODIFY, &udev->ctx_buf.jfc},
		{UBASE_MB_DESTROY_JFC_CONTEXT, UBASE_MB_DESTROY, &udev->ctx_buf.jfc},
		{UBASE_MB_QUERY_JFC_CONTEXT, UBASE_MB_QUERY, &udev->ctx_buf.jfc},
		{UBASE_MB_CREATE_JFR_CONTEXT, UBASE_MB_CREATE, &udev->ctx_buf.jfr},
		{UBASE_MB_MODIFY_JFR_CONTEXT, UBASE_MB_MODIFY, &udev->ctx_buf.jfr},
		{UBASE_MB_DESTROY_JFR_CONTEXT, UBASE_MB_DESTROY, &udev->ctx_buf.jfr},
		{UBASE_MB_QUERY_JFR_CONTEXT, UBASE_MB_QUERY, &udev->ctx_buf.jfr},
		{UBASE_MB_CREATE_JETTY_GROUP_CONTEXT, UBASE_MB_CREATE, &udev->ctx_buf.jtg},
		{UBASE_MB_MODIFY_JETTY_GROUP_CONTEXT, UBASE_MB_MODIFY, &udev->ctx_buf.jtg},
		{UBASE_MB_DESTROY_JETTY_GROUP_CONTEXT, UBASE_MB_DESTROY, &udev->ctx_buf.jtg},
		{UBASE_MB_QUERY_JETTY_GROUP_CONTEXT, UBASE_MB_QUERY, &udev->ctx_buf.jtg},
		{UBASE_MB_CREATE_RC_CONTEXT, UBASE_MB_CREATE, &udev->ctx_buf.rc},
		{UBASE_MB_MODIFY_RC_CONTEXT, UBASE_MB_MODIFY, &udev->ctx_buf.rc},
		{UBASE_MB_DESTROY_RC_CONTEXT, UBASE_MB_DESTROY, &udev->ctx_buf.rc},
		{UBASE_MB_QUERY_RC_CONTEXT, UBASE_MB_QUERY, &udev->ctx_buf.rc},
	};
	u32 size = ARRAY_SIZE(ta_matches);

	return ubase_parse_common_buf(attr, ta_matches, type, size);
}

static struct ubase_ctx_buf_cap*
ubase_parse_opcode_buf(struct ubase_dev *udev, struct ubase_mbx_attr *attr,
		       enum ubase_mb_type *type)
{
	if (ubase_dev_dtu_supported(udev))
		return NULL;

	if (ubase_is_jfs_opcode(attr->op) &&
	    test_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits))
		return NULL;

	return ubase_parse_ta_opcode_buf(udev, attr, type);
}

static int ubase_check_buf_ctx_page(struct ubase_dev *udev,
				    struct ubase_ctx_buf_cap *ctx_buf, u32 tag)
{
	u32 cnt_per_page_shift = ctx_buf->cnt_per_page_shift;
	u32 npage = tag >> cnt_per_page_shift;
	struct ubase_ctx_page *ctx_page;

	mutex_lock(&ctx_buf->ctx_mutex);

	ctx_page = (struct ubase_ctx_page *)xa_load(&ctx_buf->ctx_xa, npage);
	if (!ctx_page) {
		ubase_err(udev,
			  "failed to find ctx page in free buf page, npage = %u.\n",
			  npage);
		mutex_unlock(&ctx_buf->ctx_mutex);
		return -EINVAL;
	}

	mutex_unlock(&ctx_buf->ctx_mutex);

	return 0;
}

static int ubase_hw_upgrade_ctx_event(struct ubase_dev *udev,
				      struct ubase_mbx_attr *attr,
				      struct ubase_cmd_mailbox *mailbox)
{
	int ret;

	down(&udev->mb_cmd.sem);
	ret = ubase_cmd_mbox_event(udev, attr, mailbox);
	up(&udev->mb_cmd.sem);

	return ret;
}

int ubase_hw_upgrade_ctx_poll(struct ubase_dev *udev,
			      struct ubase_mbx_attr *attr,
			      struct ubase_cmd_mailbox *mailbox)
{
	int ret;

	down(&udev->mb_cmd.sem);
	ret = ubase_cmd_mbox_poll(udev, attr, mailbox);
	up(&udev->mb_cmd.sem);

	return ret;
}

int __ubase_hw_upgrade_ctx(struct ubase_dev *udev,
			   struct ubase_mbx_attr *attr,
			   struct ubase_cmd_mailbox *mailbox)
{
	return ubase_hw_upgrade_ctx_event(udev, attr, mailbox);
}

int __ubase_hw_upgrade_ctx_ex(struct ubase_dev *udev,
			      struct ubase_mbx_attr *attr,
			      struct ubase_cmd_mailbox *mailbox)
{
	enum ubase_mb_type type = UBASE_MB_OTHER;
	struct ubase_ctx_buf_cap *ctx_buf;
	int ret;

	if (ubase_dev_usc_supported(udev) && ubase_ctx_in_usc(attr->op))
		return __ubase_hw_upgrade_ctx(udev, attr, mailbox);

	ctx_buf = ubase_parse_opcode_buf(udev, attr, &type);
	if (ctx_buf) {
		if (type == UBASE_MB_CREATE) {
			ret = ubase_use_buf_ctx_page(udev, ctx_buf, attr->tag);
			if (ret) {
				ubase_err(udev, "failed to write context va, ret = %d.\n",
					  ret);
				return ret;
			}
		} else if (type == UBASE_MB_QUERY) {
			ret = ubase_check_buf_ctx_page(udev, ctx_buf, attr->tag);
			if (ret) {
				ubase_info(udev,
					   "A query operation is performed before the create operation, 0 is returned by default, op = 0x%x.\n",
					   attr->op);
				return 0;
			}
		} else if (type == UBASE_MB_MODIFY || type == UBASE_MB_DESTROY) {
			ret = ubase_check_buf_ctx_page(udev, ctx_buf, attr->tag);
			if (ret) {
				ubase_info(udev,
					   "An access operation is performed before the create operation, op = 0x%x.\n",
					   attr->op);
				return ret;
			}
		}
	}

	ret = __ubase_hw_upgrade_ctx(udev, attr, mailbox);
	if (ret && type == UBASE_MB_CREATE)
		ubase_free_buf_ctx_page(udev, ctx_buf, attr->tag);

	return ret;
}

/**
 * ubase_hw_upgrade_ctx_ex() - upgrade hardware context
 * @aux_dev: auxiliary device
 * @attr: the mailbox attribute pointer
 * @mailbox: mailbox command address
 *
 * The function is used to upgrade hardware context. It can be used
 * in the following two ways:
 * 1. Combined mode: This function is used together with ubase_alloc_cmd_mailbox()
 * and ubase_free_cmd_mailbox().
 * 2. Independent mode: When used independently, the atomic variable 'count' in
 * the ubase_cmd_mailbox structure must be 0.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep
 * Return: 0 on success, negative error code otherwise
 */
int ubase_hw_upgrade_ctx_ex(struct auxiliary_device *aux_dev,
			    struct ubase_mbx_attr *attr,
			    struct ubase_cmd_mailbox *mailbox)
{
	struct ubase_dev *udev;

	if (!aux_dev || !attr || !mailbox)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(aux_dev);
	if (!test_bit(UBASE_STATE_CTX_READY_B, &udev->state_bits))
		return -EAGAIN;

	return __ubase_hw_upgrade_ctx_ex(udev, attr, mailbox);
}
EXPORT_SYMBOL(ubase_hw_upgrade_ctx_ex);
