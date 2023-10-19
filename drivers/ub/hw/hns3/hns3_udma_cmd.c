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

void dump_desc(struct udma_dev *dev,
	       struct udma_cmq_desc *desc)
{
	if (desc->opcode == UDMA_OPC_QUERY_MB_ST)
		return;

	if (((desc->data[SUB_OPCODE_IDX] & 0xFF) ==
	     UDMA_CMD_WRITE_QPC_TIMER_BT0) ||
	    ((desc->data[SUB_OPCODE_IDX] & 0xFF) ==
	     UDMA_CMD_WRITE_CQC_TIMER_BT0))
		dev_err_ratelimited(dev->dev,
			"Send cmd opcode:0x%4x, data: %08x %08x %08x %08x %08x %08x\n",
			desc->opcode, desc->data[0],
			desc->data[1], desc->data[2],
			desc->data[3], desc->data[4], desc->data[5]);
	else
		dev_info(dev->dev,
			"Send cmd opcode:0x%4x, data: %08x %08x %08x %08x %08x %08x\n",
			desc->opcode, desc->data[0],
			desc->data[1], desc->data[2],
			desc->data[3], desc->data[4], desc->data[5]);
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

	tail = csq->head;

	mutex_lock(&csq->lock);

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
		dev_warn(dev->dev, "CMDQ move tail from %d to %d\n",
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
