// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2020-2022 Hisilicon Limited.

#include <linux/module.h>
#include <linux/dmapool.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "core.h"
#include "hns3_common.h"
#include "hns3_cmdq.h"
#include "hns3_reg.h"

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

static int hns3_roh_cmdq_done_parse(struct hns3_roh_device *hroh_dev,
				    struct hns3_roh_desc *desc,
				    int num, int ntc)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *csq = &priv->cmdq.csq;
	struct hns3_roh_desc *desc_to_use = NULL;
	int handle = 0;
	u16 desc_ret;
	int ret;

	if (hns3_roh_cmdq_csq_done(hroh_dev)) {
		while (handle < num) {
			desc_to_use = &csq->desc[ntc];
			desc[handle] = *desc_to_use;
			desc_ret = le16_to_cpu(desc[handle].retval);
			if (desc_ret == HNS3_ROH_CMD_EXEC_SUCCESS) {
				ret = 0;
			} else if (desc_ret == HNS3_ROH_CMD_EXEC_TIMEOUT) {
				priv->cmdq.last_status = desc_ret;
				ret = -ETIME;
			} else {
				pr_err("desc_ret = %d\n", desc_ret);
				ret = -EIO;
			}

			ntc++;
			handle++;
			if (ntc == csq->desc_num)
				ntc = 0;
		}
	} else {
		ret = -EAGAIN;
	}

	return ret;
}

int hns3_roh_cmdq_send(struct hns3_roh_device *hroh_dev, struct hns3_roh_desc *desc, int num)
{
	struct hns3_roh_priv *priv = (struct hns3_roh_priv *)hroh_dev->priv;
	struct hns3_roh_cmdq_ring *csq = &priv->cmdq.csq;
	u32 timeout = 0;
	int handle = 0;
	int ntc = 0;
	int ret = 0;

	spin_lock_bh(&csq->lock);
	ret = hns3_roh_cmdq_build(hroh_dev, desc, num, &ntc);
	if (ret) {
		spin_unlock_bh(&csq->lock);
		return ret;
	}

	/* Write to hardware */
	hns3_roh_write(hroh_dev, HNS3_ROH_TX_CMDQ_TAIL_REG, csq->next_to_use);

	if (desc->flag & cpu_to_le16(HNS3_ROH_CMD_FLAG_NO_INTR)) {
		do {
			if (hns3_roh_cmdq_csq_done(hroh_dev))
				break;
			udelay(1);
			timeout++;
		} while (timeout < priv->cmdq.tx_timeout);
	}

	ret = hns3_roh_cmdq_done_parse(hroh_dev, desc, num, ntc);

	handle = hns3_roh_cmdq_csq_clean(hroh_dev);
	if (handle != num)
		dev_warn(hroh_dev->dev, "cleaned %d, need to clean %d\n", handle, num);
	spin_unlock_bh(&csq->lock);

	return ret;
}
