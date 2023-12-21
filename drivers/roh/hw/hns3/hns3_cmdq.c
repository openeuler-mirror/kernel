// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2020-2022 Hisilicon Limited.

#include <linux/module.h>
#include <linux/dmapool.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "core.h"
#include "hns3_device.h"
#include "hns3_common.h"
#include "hns3_reg.h"
#include "hns3_cmdq.h"

static int hns3_roh_alloc_cmdq_desc(struct hns3_roh_device *hroh_dev,
				    struct hns3_roh_cmdq_ring *ring)
{
	u32 size = ring->desc_num * sizeof(struct hns3_roh_desc);

	ring->desc = kzalloc(size, GFP_KERNEL);
	if (!ring->desc)
		return -ENOMEM;

	ring->desc_dma_addr = dma_map_single(hroh_dev->dev, ring->desc, size,
					     DMA_BIDIRECTIONAL);
	if (dma_mapping_error(hroh_dev->dev, ring->desc_dma_addr)) {
		dev_err(hroh_dev->dev, "failed to dma mapping.\n");
		ring->desc_dma_addr = 0;
		kfree(ring->desc);
		ring->desc = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void hns3_roh_free_cmdq_desc(struct hns3_roh_device *hroh_dev,
				    struct hns3_roh_cmdq_ring *ring)
{
	dma_unmap_single(hroh_dev->dev, ring->desc_dma_addr,
			 ring->desc_num * sizeof(struct hns3_roh_desc),
			 DMA_BIDIRECTIONAL);

	ring->desc_dma_addr = 0;
	kfree(ring->desc);
	ring->desc = NULL;
}

static int hns3_roh_init_cmdq_ring(struct hns3_roh_device *hroh_dev, u8 ring_type)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *ring =
		(ring_type == HNS3_ROH_CMDQ_CSQ) ? &priv->cmdq.csq : &priv->cmdq.crq;

	ring->flag = ring_type;
	ring->next_to_clean = 0;
	ring->next_to_use = 0;

	return hns3_roh_alloc_cmdq_desc(hroh_dev, ring);
}

static void hns3_roh_cmdq_clear_regs(struct hns3_roh_device *hroh_dev)
{
	hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_BASEADDR_L_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_BASEADDR_H_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_DEPTH_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_HEAD_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_TAIL_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_BASEADDR_L_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_BASEADDR_H_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_DEPTH_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_HEAD_REG, 0);
	hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_TAIL_REG, 0);
}

static void hns3_roh_cmdq_init_regs(struct hns3_roh_device *hroh_dev, u8 ring_type)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *ring =
		(ring_type == HNS3_ROH_CMDQ_CSQ) ? &priv->cmdq.csq : &priv->cmdq.crq;
	dma_addr_t dma = ring->desc_dma_addr;

	if (ring_type == HNS3_ROH_CMDQ_CSQ) {
		hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_BASEADDR_L_REG, (u32)dma);
		hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_BASEADDR_H_REG,
			       upper_32_bits(dma));
		hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_DEPTH_REG,
			       ring->desc_num >> HNS3_ROH_CMDQ_DESC_NUM);
		hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_HEAD_REG, 0);
		hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_TAIL_REG, 0);
	} else {
		hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_BASEADDR_L_REG, (u32)dma);
		hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_BASEADDR_H_REG,
			       upper_32_bits(dma));
		hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_DEPTH_REG,
			       ring->desc_num >> HNS3_ROH_CMDQ_DESC_NUM);
		hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_HEAD_REG, 0);
		hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_TAIL_REG, 0);
	}
}

int hns3_roh_cmdq_init(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	int ret;

	/* Setup the lock for command queue */
	spin_lock_init(&priv->cmdq.csq.lock);
	spin_lock_init(&priv->cmdq.crq.lock);

	/* Clear up all command register,
	 * in case there are some residual values
	 */
	hns3_roh_cmdq_clear_regs(hroh_dev);

	/* Setup the queue entries for command queue */
	priv->cmdq.csq.desc_num = HNS3_ROH_CMDQ_CSQ_DESC_NUM;
	priv->cmdq.crq.desc_num = HNS3_ROH_CMDQ_CRQ_DESC_NUM;

	/* Setup Tx write back timeout */
	priv->cmdq.tx_timeout = HNS3_ROH_CMDQ_TX_TIMEOUT;

	/* Init CSQ */
	ret = hns3_roh_init_cmdq_ring(hroh_dev, HNS3_ROH_CMDQ_CSQ);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to init csq, ret = %d\n", ret);
		return ret;
	}

	/* Init CRQ */
	ret = hns3_roh_init_cmdq_ring(hroh_dev, HNS3_ROH_CMDQ_CRQ);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to init crq, ret = %d\n", ret);
		goto err_crq;
	}

	/* Init CSQ REG */
	hns3_roh_cmdq_init_regs(hroh_dev, HNS3_ROH_CMDQ_CSQ);

	/* Init CRQ REG */
	hns3_roh_cmdq_init_regs(hroh_dev, HNS3_ROH_CMDQ_CRQ);

	clear_bit(HNS3_ROH_STATE_CMD_DISABLE, &priv->handle->rohinfo.reset_state);

	return 0;

err_crq:
	hns3_roh_free_cmdq_desc(hroh_dev, &priv->cmdq.csq);
	return ret;
}

void hns3_roh_cmdq_exit(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;

	spin_lock_bh(&priv->cmdq.csq.lock);
	spin_lock(&priv->cmdq.crq.lock);
	hns3_roh_cmdq_clear_regs(hroh_dev);
	spin_unlock(&priv->cmdq.crq.lock);
	spin_unlock_bh(&priv->cmdq.csq.lock);

	hns3_roh_free_cmdq_desc(hroh_dev, &priv->cmdq.csq);
	hns3_roh_free_cmdq_desc(hroh_dev, &priv->cmdq.crq);
}

static int hns3_roh_cmdq_space(struct hns3_roh_cmdq_ring *ring)
{
	int ntu = ring->next_to_use;
	int ntc = ring->next_to_clean;
	int used = (ntu - ntc + ring->desc_num) % ring->desc_num;

	return ring->desc_num - used - 1;
}

void hns3_roh_cmdq_setup_basic_desc(struct hns3_roh_desc *desc,
				    enum hns3_roh_opcode_type opcode,
				    bool is_read)
{
	memset((void *)desc, 0, sizeof(struct hns3_roh_desc));
	desc->opcode = cpu_to_le16(opcode);
	desc->flag = cpu_to_le16(HNS3_ROH_CMD_FLAG_NO_INTR | HNS3_ROH_CMD_FLAG_IN);
	if (is_read)
		desc->flag |= cpu_to_le16(HNS3_ROH_CMD_FLAG_WR);
}

static int hns3_roh_cmdq_csq_done(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	u32 head = hns3_roh_read(hroh_dev, HNS3_ROH_TX_CMDQ_HEAD_REG);

	return head == priv->cmdq.csq.next_to_use;
}

static int hns3_roh_cmdq_csq_clean(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *csq = &priv->cmdq.csq;
	u16 ntc = csq->next_to_clean;
	struct hns3_roh_desc *desc;
	int clean = 0;
	u32 head;

	desc = &csq->desc[ntc];
	head = hns3_roh_read(hroh_dev, HNS3_ROH_TX_CMDQ_HEAD_REG);
	while (head != ntc) {
		memset(desc, 0, sizeof(*desc));
		ntc++;
		if (ntc == csq->desc_num)
			ntc = 0;
		desc = &csq->desc[ntc];
		clean++;
	}
	csq->next_to_clean = ntc;

	return clean;
}

static int hns3_roh_cmdq_build(struct hns3_roh_device *hroh_dev,
			       struct hns3_roh_desc *desc,
			       int num, int *ntc)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *csq = &priv->cmdq.csq;
	struct hns3_roh_desc *desc_to_use = NULL;
	int handle = 0;

	if (num > hns3_roh_cmdq_space(csq)) {
		/* If CMDQ ring is full, SW HEAD and HW HEAD may be different,
		 * need update the SW HEAD pointer csq->next_to_clean
		 */
		csq->next_to_clean =
			hns3_roh_read(hroh_dev, HNS3_ROH_TX_CMDQ_HEAD_REG);
		dev_err(hroh_dev->dev, "cmdq is full, opcode %x\n", desc->opcode);
		return -EBUSY;
	}

	*ntc = csq->next_to_use;
	while (handle < num) {
		desc_to_use = &csq->desc[csq->next_to_use];
		*desc_to_use = desc[handle];
		csq->next_to_use++;
		if (csq->next_to_use == csq->desc_num)
			csq->next_to_use = 0;
		handle++;
	}

	return 0;
}

static void hns3_roh_cmd_wait_for_resp(struct hns3_roh_device *hroh_dev,
				       bool *is_completed)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	u32 timeout = 0;

	do {
		if (hns3_roh_cmdq_csq_done(hroh_dev)) {
			*is_completed = true;
			break;
		}
		udelay(1);
		timeout++;
	} while (timeout < priv->cmdq.tx_timeout);
}

static const u16 spec_opcode[] = { HNS3_ROH_OPC_QUERY_MIB_PUBLIC,
				   HNS3_ROH_OPC_QUERY_MIB_PRIVATE };

static bool hns_roh_is_special_opcode(u16 opcode)
{
	/* these commands have several descriptors,
	 * and use the first one to save opcode and return value
	 */
	u32 i;

	for (i = 0; i < ARRAY_SIZE(spec_opcode); i++)
		if (spec_opcode[i] == opcode)
			return true;

	return false;
}

static int hns3_roh_cmd_convert_err_code(u16 desc_ret)
{
	struct hns3_roh_errcode hns3_roh_cmd_errcode[] = {
		{ HNS3_ROH_CMD_EXEC_SUCCESS, 0 },
		{ HNS3_ROH_CMD_NO_AUTH, -EPERM },
		{ HNS3_ROH_CMD_NOT_SUPPORTED, -EOPNOTSUPP },
		{ HNS3_ROH_CMD_QUEUE_FULL, -EXFULL },
		{ HNS3_ROH_CMD_NEXT_ERR, -ENOSR },
		{ HNS3_ROH_CMD_UNEXE_ERR, -ENOTBLK },
		{ HNS3_ROH_CMD_PARA_ERR, -EINVAL },
		{ HNS3_ROH_CMD_RESULT_ERR, -ERANGE },
		{ HNS3_ROH_CMD_TIMEOUT, -ETIME },
		{ HNS3_ROH_CMD_HILINK_ERR, -ENOLINK },
		{ HNS3_ROH_CMD_QUEUE_ILLEGAL, -ENXIO },
		{ HNS3_ROH_CMD_INVALID, -EBADR },
	};
	u32 errcode_count = ARRAY_SIZE(hns3_roh_cmd_errcode);
	u32 i;

	for (i = 0; i < errcode_count; i++)
		if (hns3_roh_cmd_errcode[i].imp_errcode == desc_ret)
			return hns3_roh_cmd_errcode[i].common_errno;

	return -EIO;
}

static int hns3_roh_cmd_check_retval(struct hns3_roh_device *hroh_dev,
				     struct hns3_roh_desc *desc, int num,
				     int next_to_clean)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	int ntc = next_to_clean;
	u16 opcode, desc_ret;
	int handle;

	opcode = le16_to_cpu(desc[0].opcode);
	for (handle = 0; handle < num; handle++) {
		desc[handle] = priv->cmdq.csq.desc[ntc];
		ntc++;
		if (ntc >= priv->cmdq.csq.desc_num)
			ntc = 0;
	}
	if (likely(!hns_roh_is_special_opcode(opcode)))
		desc_ret = le16_to_cpu(desc[num - 1].retval);
	else
		desc_ret = le16_to_cpu(desc[0].retval);

	priv->cmdq.last_status = desc_ret;

	return hns3_roh_cmd_convert_err_code(desc_ret);
}

int hns3_roh_cmdq_send(struct hns3_roh_device *hroh_dev, struct hns3_roh_desc *desc, int num)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *csq = &priv->cmdq.csq;
	bool is_completed = false;
	int handle = 0;
	int ntc = 0;
	int ret = 0;

	if (test_bit(HNS3_ROH_STATE_CMD_DISABLE, &priv->handle->rohinfo.reset_state))
		return -EIO;

	spin_lock_bh(&csq->lock);
	ret = hns3_roh_cmdq_build(hroh_dev, desc, num, &ntc);
	if (ret) {
		spin_unlock_bh(&csq->lock);
		return ret;
	}

	/* Write to hardware */
	hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_TAIL_REG, csq->next_to_use);

	if (le16_to_cpu(desc->flag) & HNS3_ROH_CMD_FLAG_NO_INTR)
		hns3_roh_cmd_wait_for_resp(hroh_dev, &is_completed);

	if (!is_completed)
		ret = -EBADE;
	else
		ret = hns3_roh_cmd_check_retval(hroh_dev, desc, num, ntc);

	handle = hns3_roh_cmdq_csq_clean(hroh_dev);
	if (handle != num)
		dev_warn(hroh_dev->dev, "cleaned %d, need to clean %d\n", handle, num);
	spin_unlock_bh(&csq->lock);

	return ret;
}

int hns3_roh_get_link_status(struct hns3_roh_device *hroh_dev, u32 *link_status)
{
	struct hns3_roh_query_link_status_info *req;
	struct hns3_roh_desc desc;
	u32 link_val;
	int ret;

	hns3_roh_cmdq_setup_basic_desc(&desc, HNS3_ROH_OPC_QUERY_PORT_LINK_STATUS, true);
	ret = hns3_roh_cmdq_send(hroh_dev, &desc, 1);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to query link status, ret = %d\n", ret);
		return ret;
	}

	req = (struct hns3_roh_query_link_status_info *)desc.data;
	link_val = le32_to_cpu(req->query_link_status);

	*link_status = link_val ? HNS3_ROH_LINK_STATUS_UP : HNS3_ROH_LINK_STATUS_DOWN;

	return 0;
}

static void hns3_roh_dispatch_event(struct hns3_roh_device *hroh_dev, enum roh_event_type type)
{
	struct roh_event event = {0};

	event.device = &hroh_dev->roh_dev;
	event.type = type;
	roh_event_notify(&event);
}

void hns3_roh_update_link_status(struct hns3_roh_device *hroh_dev)
{
	u32 state = HNS3_ROH_LINK_STATUS_DOWN;
	enum roh_event_type type;
	int ret;

	if (test_and_set_bit(HNS3_ROH_SW_STATE_LINK_UPDATING, &hroh_dev->state))
		return;

	ret = hns3_roh_get_link_status(hroh_dev, &state);
	if (ret) {
		state = HNS3_ROH_LINK_STATUS_DOWN;
		clear_bit(HNS3_ROH_SW_STATE_LINK_UPDATING, &hroh_dev->state);
		return;
	}

	type = (state == HNS3_ROH_LINK_STATUS_DOWN) ? ROH_EVENT_LINK_DOWN : ROH_EVENT_LINK_UP;
	hns3_roh_dispatch_event(hroh_dev, type);

	clear_bit(HNS3_ROH_SW_STATE_LINK_UPDATING, &hroh_dev->state);
}

static void hns3_roh_link_fail_parse(struct hns3_roh_device *hroh_dev,
				     u8 link_fail_code)
{
	switch (link_fail_code) {
	case HNS3_ROH_LF_REF_CLOCK_LOST:
		dev_warn(hroh_dev->dev, "reference clock lost!\n");
		break;
	case HNS3_ROH_LF_XSFP_TX_DISABLE:
		dev_warn(hroh_dev->dev, "SFP tx is disabled!\n");
		break;
	case HNS3_ROH_LF_XSFP_ABSENT:
		dev_warn(hroh_dev->dev, "SFP is absent!\n");
		break;
	default:
		break;
	}
}

static void hns3_roh_handle_link_change_event(struct hns3_roh_device *hroh_dev,
					      struct hns3_roh_mbx_vf_to_pf_cmd *req)
{
	int link_status = req->msg.subcode;

	hns3_roh_task_schedule(hroh_dev, 0);

	if (link_status == HNS3_ROH_LINK_STATUS_DOWN)
		hns3_roh_link_fail_parse(hroh_dev, req->msg.data[0]);
}

static bool hns3_roh_cmd_crq_empty(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	u32 tail = hns3_roh_read(hroh_dev, HNS3_ROH_RX_CMDQ_TAIL_REG);

	return tail == priv->cmdq.crq.next_to_use;
}

void hns3_roh_mbx_handler(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *crq = &priv->cmdq.crq;
	struct hns3_roh_mbx_vf_to_pf_cmd *req;
	struct hns3_roh_desc *desc;
	unsigned int flag;

	/* handle all the mailbox requests in the queue */
	while (!hns3_roh_cmd_crq_empty(hroh_dev)) {
		desc = &crq->desc[crq->next_to_use];
		req = (struct hns3_roh_mbx_vf_to_pf_cmd *)desc->data;

		flag = le16_to_cpu(crq->desc[crq->next_to_use].flag);
		if (unlikely(!hns3_roh_get_bit(flag, HNS3_ROH_CMDQ_RX_OUTVLD_B))) {
			dev_warn(hroh_dev->dev,
				 "dropped invalid mbx message, code = %u\n",
				 req->msg.code);

			/* dropping/not processing this invalid message */
			crq->desc[crq->next_to_use].flag = 0;
			hns3_roh_mbx_ring_ptr_move_crq(crq);
			continue;
		}

		switch (req->msg.code) {
		case HNS3_ROH_MBX_PUSH_LINK_STATUS:
			hns3_roh_handle_link_change_event(hroh_dev, req);
			break;
		default:
			dev_err(hroh_dev->dev,
				"un-supported mbx message, code = %u\n",
				req->msg.code);
			break;
		}

		crq->desc[crq->next_to_use].flag = 0;
		hns3_roh_mbx_ring_ptr_move_crq(crq);
	}

	/* write back CMDQ_RQ header ptr, M7 need this ptr */
	hns3_roh_write(hroh_dev, HNS3_ROH_RX_CMDQ_HEAD_REG, crq->next_to_use);
}
