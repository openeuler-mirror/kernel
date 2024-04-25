// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/dmapool.h>
#include <linux/iopoll.h>
#include <linux/slab.h>
#include "hnae3.h"
#include "hns3_udma_common.h"
#include "hns3_udma_cmd.h"

static int debug_switch = 1;
static int cnt_mailbox = 1;

int udma_cmd_init(struct udma_dev *udma_dev)
{
	sema_init(&udma_dev->cmd.poll_sem, 1);
	udma_dev->cmd.use_events = 0;
	udma_dev->cmd.max_cmds = CMD_MAX_NUM;
	udma_dev->cmd.pool = dma_pool_create("udma_cmd", udma_dev->dev,
					     UDMA_MAILBOX_SIZE,
					     UDMA_MAILBOX_SIZE, 0);
	if (!udma_dev->cmd.pool)
		return -ENOMEM;

	init_rwsem(&udma_dev->cmd.udma_mb_rwsem);

	return 0;
}

void udma_cmd_cleanup(struct udma_dev *udma_dev)
{
	down_write(&udma_dev->cmd.udma_mb_rwsem);
	dma_pool_destroy(udma_dev->cmd.pool);
	up_write(&udma_dev->cmd.udma_mb_rwsem);
}

int udma_cmd_use_events(struct udma_dev *udma_dev)
{
	struct udma_cmdq *udma_cmd = &udma_dev->cmd;
	int i;

	udma_cmd->context = kcalloc(udma_cmd->max_cmds, sizeof(*udma_cmd->context),
				    GFP_KERNEL);
	if (!udma_cmd->context)
		return -ENOMEM;

	for (i = 0; i < udma_cmd->max_cmds; ++i) {
		udma_cmd->context[i].token = i;
		udma_cmd->context[i].next = i + 1;
		init_completion(&udma_cmd->context[i].done);
	}
	udma_cmd->context[udma_cmd->max_cmds - 1].next = 0;
	udma_cmd->free_head = 0;

	sema_init(&udma_cmd->event_sem, udma_cmd->max_cmds);
	spin_lock_init(&udma_cmd->ctx_lock);

	udma_cmd->use_events = 1;

	return 0;
}

void udma_cmd_use_polling(struct udma_dev *udma_dev)
{
	struct udma_cmdq *udma_cmd = &udma_dev->cmd;

	kfree(udma_cmd->context);
	udma_cmd->use_events = 0;
}

struct udma_cmd_mailbox *udma_alloc_cmd_mailbox(struct udma_dev *dev)
{
	struct udma_cmd_mailbox *mailbox;

	mailbox = kzalloc(sizeof(*mailbox), GFP_KERNEL);
	if (!mailbox)
		return ERR_PTR(-ENOMEM);

	down_read(&dev->cmd.udma_mb_rwsem);
	mailbox->buf =
		dma_pool_zalloc(dev->cmd.pool, GFP_KERNEL, &mailbox->dma);
	if (!mailbox->buf) {
		up_read(&dev->cmd.udma_mb_rwsem);

		kfree(mailbox);
		return ERR_PTR(-ENOMEM);
	}

	return mailbox;
}

void udma_free_cmd_mailbox(struct udma_dev *dev,
			   struct udma_cmd_mailbox *mailbox)
{
	if (!mailbox)
		return;

	dma_pool_free(dev->cmd.pool, mailbox->buf, mailbox->dma);

	up_read(&dev->cmd.udma_mb_rwsem);

	kfree(mailbox);
}

static uint32_t udma_cmd_hw_reseted(struct udma_dev *dev,
				    uint64_t instance_stage,
				    uint64_t reset_stage)
{
	/* When hardware reset has been completed once or more, we should stop
	 * sending mailbox&cmq&doorbell to hardware. If now in .init_instance()
	 * function, we should exit with error. If now at HNAE3_INIT_CLIENT
	 * stage of soft reset process, we should exit with error, and then
	 * HNAE3_INIT_CLIENT related process can rollback the operation like
	 * notifing hardware to free resources, HNAE3_INIT_CLIENT related
	 * process will exit with error to notify NIC driver to reschedule soft
	 * reset process once again.
	 */
	dev->is_reset = true;
	dev->dis_db = true;

	if (reset_stage == UDMA_STATE_RST_INIT ||
	    instance_stage == UDMA_STATE_INIT)
		return CMD_RST_PRC_EBUSY;

	return CMD_RST_PRC_SUCCESS;
}

static uint32_t udma_cmd_hw_resetting(struct udma_dev *dev,
				      uint64_t instance_stage,
				      uint64_t reset_stage)
{
#define HW_RESET_TIMEOUT_US 1000000
#define HW_RESET_DELAY_US 1
	struct udma_priv *priv = (struct udma_priv *)dev->priv;
	struct hnae3_handle *handle = priv->handle;
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;
	uint64_t val;
	int ret;

	/* When hardware reset is detected, we should stop sending mailbox&cmq&
	 * doorbell to hardware. If now in .init_instance() function, we should
	 * exit with error. If now at HNAE3_INIT_CLIENT stage of soft reset
	 * process, we should exit with error, and then HNAE3_INIT_CLIENT
	 * related process can rollback the operation like notifing hardware to
	 * free resources, HNAE3_INIT_CLIENT related process will exit with
	 * error to notify UBNIC driver to reschedule soft reset process once
	 * again.
	 */
	dev->dis_db = true;

	ret = read_poll_timeout_atomic(ops->ae_dev_reset_cnt, val,
				       val > dev->reset_cnt, HW_RESET_DELAY_US,
				       HW_RESET_TIMEOUT_US, false, handle);
	cond_resched();
	if (!ret)
		dev->is_reset = true;

	if (!dev->is_reset || reset_stage == UDMA_STATE_RST_INIT ||
	    instance_stage == UDMA_STATE_INIT)
		return CMD_RST_PRC_EBUSY;

	return CMD_RST_PRC_SUCCESS;
}

static uint32_t udma_cmd_sw_resetting(struct udma_dev *dev)
{
	struct udma_priv *priv = (struct udma_priv *)dev->priv;
	struct hnae3_handle *handle = priv->handle;
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;

	/* When software reset is detected at .init_instance() function, we
	 * should stop sending mailbox&cmq&doorbell to hardware, and exit
	 * with error.
	 */
	dev->dis_db = true;
	if (ops->ae_dev_reset_cnt(handle) != dev->reset_cnt)
		dev->is_reset = true;

	return CMD_RST_PRC_EBUSY;
}

static uint32_t check_aedev_reset_status(struct udma_dev *dev,
					 struct hnae3_handle *handle)
{
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;
	uint64_t instance_stage;
	uint64_t reset_stage;
	uint64_t reset_cnt;
	bool sw_resetting;
	bool hw_resetting;

	/* The meaning of the following variables:
	 * reset_cnt -- The count value of completed hardware reset.
	 * hw_resetting -- Whether hardware device is resetting now.
	 * sw_resetting -- Whether UBNIC's software reset process is
	 * running now.
	 */
	instance_stage = handle->udmainfo.instance_state;
	reset_stage = handle->udmainfo.reset_state;
	reset_cnt = ops->ae_dev_reset_cnt(handle);
	if (reset_cnt != dev->reset_cnt)
		return udma_cmd_hw_reseted(dev, instance_stage, reset_stage);

	hw_resetting = ops->get_cmdq_stat(handle);
	if (hw_resetting)
		return udma_cmd_hw_resetting(dev, instance_stage, reset_stage);

	sw_resetting = ops->ae_dev_resetting(handle);
	if (sw_resetting && instance_stage == UDMA_STATE_INIT)
		return udma_cmd_sw_resetting(dev);

	return CMD_RST_PRC_OTHERS;
}

bool udma_chk_mbox_is_avail(struct udma_dev *dev, bool *busy)
{
	struct udma_priv *priv = (struct udma_priv *)dev->priv;
	uint32_t status;

	/*
	 * CMDQ fatal err or system reset means hw/fw is in an abnormal or
	 * unresponsive state, CMDQ command needs to return quickly,
	 * in order to avoid excessive printing, return CMD_RST_PRC_SUCCESS.
	 */
	if (dev->cmd.state == UDMA_CMDQ_STATE_FATAL_ERR ||
	    dev->is_reset)
		status = CMD_RST_PRC_SUCCESS;
	else
		status = check_aedev_reset_status(dev, priv->handle);

	*busy = (status == CMD_RST_PRC_EBUSY);

	return status == CMD_RST_PRC_OTHERS;
}

static int udma_cmq_csq_done(struct udma_dev *dev)
{
	struct udma_priv *priv = (struct udma_priv *)dev->priv;
	uint32_t tail = ub_read(dev, UDMA_TX_CMQ_CI_REG);

	return tail == priv->cmq.csq.head;
}

void udma_cmq_setup_basic_desc(struct udma_cmq_desc *desc,
			       enum udma_opcode_type opcode,
			       bool is_read)
{
	memset((void *)desc, 0, sizeof(struct udma_cmq_desc));
	desc->opcode = cpu_to_le16(opcode);
	desc->flag =
		cpu_to_le16(UDMA_CMD_FLAG_NO_INTR | UDMA_CMD_FLAG_IN);
	if (is_read)
		desc->flag |= cpu_to_le16(UDMA_CMD_FLAG_WR);
	else
		desc->flag &= cpu_to_le16(~UDMA_CMD_FLAG_WR);
}

static void dump_desc(struct udma_dev *dev,
		      struct udma_cmq_desc *desc)
{
	static int num_mailbox;

	if (desc->opcode == UDMA_OPC_QUERY_MB_ST ||
	    desc->opcode == UDMA_OPC_CFG_GMV_BT)
		return;

	if (desc->opcode == UDMA_OPC_POST_MB && cnt_mailbox)
		++num_mailbox;

	if (((desc->data[SUB_OPCODE_IDX] & 0xFF) ==
	     UDMA_CMD_WRITE_QPC_TIMER_BT0) ||
	    ((desc->data[SUB_OPCODE_IDX] & 0xFF) ==
	     UDMA_CMD_WRITE_CQC_TIMER_BT0))
		dev_err_ratelimited(dev->dev,
			"Send cmd opcode:0x%4x, data: %08x %08x %08x %08x %08x %08x, mlbox: %08x\n",
			desc->opcode, desc->data[0], desc->data[1],
			desc->data[2], desc->data[3], desc->data[4],
			desc->data[5], num_mailbox);
	else
		dev_info_ratelimited(dev->dev,
			"Send cmd opcode:0x%4x, data: %08x %08x %08x %08x %08x %08x, mlbox: %08x\n",
			desc->opcode, desc->data[0], desc->data[1],
			desc->data[2], desc->data[3], desc->data[4],
			desc->data[5], num_mailbox);
}

static int __udma_cmq_send(struct udma_dev *dev, struct udma_cmq_desc *desc,
			   int num)
{
	struct udma_priv *priv = (struct udma_priv *)dev->priv;
	struct udma_cmq_ring *csq = &priv->cmq.csq;
	uint32_t timeout = 0;
	uint16_t desc_ret;
	uint32_t tail;
	int ret = 0;
	int i;

	if (debug_switch)
		for (i = 0; i < num; i++)
			dump_desc(dev, desc + i);

	mutex_lock(&csq->lock);

	tail = csq->head;

	for (i = 0; i < num; i++) {
		csq->desc[csq->head++] = desc[i];
		if (csq->head == csq->desc_num)
			csq->head = 0;
	}

	/* barrier */
	wmb();

	/* Write to hardware */
	ub_write(dev, UDMA_TX_CMQ_PI_REG, csq->head);

	do {
		if (udma_cmq_csq_done(dev))
			break;
		udelay(1);
	} while (++timeout < priv->cmq.tx_timeout);

	if (udma_cmq_csq_done(dev)) {
		for (i = 0; i < num; i++) {
			/* check the result of hardware write back */
			desc[i] = csq->desc[tail++];
			if (tail == csq->desc_num)
				tail = 0;

			desc_ret = le16_to_cpu(desc[i].retval);
			if (likely(desc_ret == CMD_EXEC_SUCCESS))
				continue;

			dev_err_ratelimited(dev->dev,
					    "CMDQ IO error, opcode = %x, return = %x\n",
					    desc->opcode, desc_ret);
			ret = -EIO;
		}
	} else {
		/* FW/HW reset or incorrect number of desc */
		tail = ub_read(dev, UDMA_TX_CMQ_CI_REG);
		dev_warn(dev->dev, "CMDQ move tail from %u to %u.\n",
			 csq->head, tail);
		csq->head = tail;

		dev->cmd.state = UDMA_CMDQ_STATE_HEAD_TAIL_ERR;

		ret = -EAGAIN;
	}

	mutex_unlock(&csq->lock);

	return ret;
}

int udma_cmq_send(struct udma_dev *dev, struct udma_cmq_desc *desc, int num)
{
	bool busy;
	int ret;

	if (!udma_chk_mbox_is_avail(dev, &busy))
		return busy ? -EBUSY : 0;

	ret = __udma_cmq_send(dev, desc, num);
	if (ret) {
		if (!udma_chk_mbox_is_avail(dev, &busy))
			return busy ? -EBUSY : 0;
	}

	return ret;
}

static int udma_wait_mbox_complete(struct udma_dev *dev, uint32_t timeout,
				   uint8_t *complete_status)
{
	struct udma_mbox_status *mb_st;
	struct udma_cmq_desc desc;
	unsigned long end;
	int ret = -EBUSY;
	uint32_t status;
	bool busy;

	mb_st = (struct udma_mbox_status *)desc.data;
	end = msecs_to_jiffies(timeout) + jiffies;
	while (udma_chk_mbox_is_avail(dev, &busy)) {
		status = 0;
		udma_cmq_setup_basic_desc(&desc, UDMA_OPC_QUERY_MB_ST,
					  true);
		ret = __udma_cmq_send(dev, &desc, 1);
		if (!ret) {
			status = le32_to_cpu(mb_st->mb_status_hw_run);
			/* No pending message exists in UDMA mbox. */
			if (!(status & MB_ST_HW_RUN_M))
				break;
		} else if (!udma_chk_mbox_is_avail(dev, &busy)) {
			break;
		}

		if (time_after(jiffies, end)) {
			dev_err_ratelimited(dev->dev,
					    "failed to wait mbox status 0x%x\n",
					    status);
			return -ETIMEDOUT;
		}

		cond_resched();
		ret = -EBUSY;
	}

	if (!ret) {
		*complete_status = (uint8_t)(status & MB_ST_COMPLETE_M);
	} else if (!udma_chk_mbox_is_avail(dev, &busy)) {
		/* Ignore all errors if the mbox is unavailable. */
		ret = busy ? -EBUSY : 0;
		*complete_status = MB_ST_COMPLETE_M;
	}

	return ret;
}

static int __udma_post_mbox(struct udma_dev *dev, struct udma_cmq_desc *desc,
			    uint16_t token, int vfid_event)
{
	struct udma_mbox *mb = (struct udma_mbox *)desc->data;

	mb->token_event_en = cpu_to_le32(vfid_event << UDMA_MB_EVENT_EN_SHIFT | token);

	return udma_cmq_send(dev, desc, 1);
}

int udma_post_mbox(struct udma_dev *dev, struct udma_cmq_desc *desc,
		   uint16_t token, int vfid_event)
{
	uint8_t status = 0;
	int ret;

	/* Waiting for the mbox to be idle */
	ret = udma_wait_mbox_complete(dev, UDMA_GO_BIT_TIMEOUT_MSECS,
				      &status);
	if (unlikely(ret)) {
		dev_err_ratelimited(dev->dev,
				    "failed to check post mbox status = 0x%x, ret = %d.\n",
				    status, ret);
		return ret;
	}

	/* Post new message to mbox */
	ret = __udma_post_mbox(dev, desc, token, vfid_event);
	if (ret)
		dev_err_ratelimited(dev->dev,
				    "failed to post mailbox, ret = %d.\n", ret);

	return ret;
}

int udma_poll_mbox_done(struct udma_dev *dev, uint32_t timeout)
{
	uint8_t status = 0;
	int ret;

	ret = udma_wait_mbox_complete(dev, timeout, &status);
	if (!ret) {
		if (status != MB_ST_COMPLETE_SUCC)
			return -EBUSY;
	} else {
		dev_err_ratelimited(dev->dev,
				    "failed to check mbox status = 0x%x, ret = %d.\n",
				    status, ret);
	}

	return ret;
}

static int udma_cmd_mbox_post_hw(struct udma_dev *dev,
				 struct udma_cmq_desc *desc,
				 uint16_t token, int vfid_event)
{
	return dev->hw->post_mbox(dev, desc, token, vfid_event);
}

static int __udma_cmd_mbox_poll(struct udma_dev *dev,
				struct udma_cmq_desc *desc,
				uint32_t timeout, int vfid)
{
	int vfid_event = (vfid << 1);
	int ret, op;

	op = le32_to_cpu(((struct udma_mbox *)desc->data)->cmd_tag) & 0xff;
	ret = udma_cmd_mbox_post_hw(dev, desc, CMD_POLL_TOKEN, vfid_event);
	if (ret) {
		dev_err_ratelimited(dev->dev,
				    "failed to post mailbox %x in poll mode, ret = %d.\n",
				    op, ret);
		return ret;
	}

	return dev->hw->poll_mbox_done(dev, timeout);
}

static int udma_cmd_mbox_poll(struct udma_dev *dev, struct udma_cmq_desc *desc,
			      uint32_t timeout, int vfid)
{
	int ret;

	down(&dev->cmd.poll_sem);
	ret = __udma_cmd_mbox_poll(dev, desc, timeout, vfid);
	up(&dev->cmd.poll_sem);

	return ret;
}

void udma_cmd_event(struct udma_dev *udma_dev, uint16_t token, uint8_t status,
		    uint64_t out_param)
{
	struct udma_cmd_context *ctx =
		&udma_dev->cmd.context[token % udma_dev->cmd.max_cmds];

	if (unlikely(token != ctx->token)) {
		dev_err_ratelimited(udma_dev->dev,
				    "[cmd] invalid ae token 0x%x, context token is 0x%x.\n",
				    token, ctx->token);
		return;
	}

	ctx->result = (status == CMD_RST_PRC_SUCCESS) ? 0 : (-EIO);
	ctx->out_param = out_param;
	complete(&ctx->done);
}

static int __udma_cmd_mbox_wait(struct udma_dev *udma_dev,
				struct udma_cmq_desc *desc,
				uint32_t timeout, int vfid)
{
	struct udma_cmdq *cmd = &udma_dev->cmd;
	int vfid_event = (vfid << 1) | 0x1;
	struct device *dev = udma_dev->dev;
	struct udma_cmd_context *context;
	int ret, op;

	spin_lock(&cmd->ctx_lock);
	do {
		context = &cmd->context[cmd->free_head];
		cmd->free_head = context->next;
	} while (context->busy);
	context->token += cmd->max_cmds;
	context->busy = 1;
	spin_unlock(&cmd->ctx_lock);

	reinit_completion(&context->done);

	op = le32_to_cpu(((struct udma_mbox *)desc->data)->cmd_tag) & 0xff;
	ret = udma_cmd_mbox_post_hw(udma_dev, desc, context->token, vfid_event);
	if (ret) {
		dev_err_ratelimited(dev,
				    "failed to post mailbox %x in event mode, ret = %d.\n",
				    op, ret);
		goto out;
	}

	if (!wait_for_completion_timeout(&context->done,
					 msecs_to_jiffies(timeout))) {
		dev_err_ratelimited(dev, "[cmd]token 0x%x of mailbox 0x%x timeout.\n",
				    context->token, op);
		ret = -EBUSY;
		goto out;
	}

	ret = context->result;
	if (ret)
		dev_err_ratelimited(dev, "[cmd]token 0x%x of mailbox 0x%x error %d\n",
				    context->token, op, ret);

out:
	context->busy = 0;
	return ret;
}

static int udma_cmd_mbox_wait(struct udma_dev *dev, struct udma_cmq_desc *desc,
			      uint32_t timeout, int vfid)
{
	int ret;

	down(&dev->cmd.event_sem);
	ret = __udma_cmd_mbox_wait(dev, desc, timeout, vfid);
	up(&dev->cmd.event_sem);

	return ret;
}

int udma_cmd_mbox(struct udma_dev *dev, struct udma_cmq_desc *desc,
		  uint32_t timeout, int vfid)
{
	bool is_busy;

	if (dev->hw->chk_mbox_avail)
		if (!dev->hw->chk_mbox_avail(dev, &is_busy))
			return is_busy ? -EBUSY : 0;

	if (dev->cmd.use_events)
		return udma_cmd_mbox_wait(dev, desc, timeout, vfid);
	else
		return udma_cmd_mbox_poll(dev, desc, timeout, vfid);
}

module_param(debug_switch, int, 0444);
MODULE_PARM_DESC(debug_switch, "set debug print ON, default: 1");

module_param(cnt_mailbox, int, 0444);
MODULE_PARM_DESC(cnt_mailbox, "Count the number of mailbox, default: 1");
