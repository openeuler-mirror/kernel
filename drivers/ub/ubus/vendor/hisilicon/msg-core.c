// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <linux/interrupt.h>

#include "../../ubus.h"
#include "../../msg.h"
#include "../../enum.h"
#include "hisi-msg.h"

#define HI_MSG_RQE_SIZE_128 0x80
#define hi_msg_rqe_size_hw(sz_sw) (ilog2((sz_sw) / (HI_MSG_RQE_SIZE_128)))

enum hi_sqe_ent_type { TYPE_BUS_CONTROLLER = 0, TYPE_IDEV = 1 };

struct hi_msgq_reg {
	u32 pi;
	u32 ci;
	u32 depth;
	u32 entry_size;
	u32 addr_l;
	u32 addr_h;
};

static struct hi_msgq_reg msgq_reg[MSGQ_NUM] = {
	{ SQ_PI, SQ_CI, SQ_DEPTH, 0, SQ_ADDR_L, SQ_ADDR_H },
	{ RQ_PI, RQ_CI, RQ_DEPTH, RQ_ENTRY_SIZE, RQ_ADDR_L, RQ_ADDR_H },
	{ CQ_PI, CQ_CI, CQ_DEPTH, 0, CQ_ADDR_L, CQ_ADDR_H }
};

static const char * const msgq_user_name[] = { "UBUS" };

struct hi_msgq_cfg {
	u32 depth;
	u32 entry_size;
};

static int hi_msg_queue_sw_init(struct hi_msg_core *hmc, int user,
				int idx)
{
	struct hi_msgq_cfg msgq_cfg[MSGQ_USER_NUMS][MSGQ_NUM] = {
		{ { HI_SQ_CFG_DEPTH, HI_MSG_SQE_SIZE },
		  { HI_RQ_CFG_DEPTH, HI_MSG_RQE_SIZE },
		  { HI_CQ_CFG_DEPTH, HI_MSG_CQE_SIZE } }
	};
	struct hi_msg_queue *q = &hmc->queue[idx];
	struct device *dev = hmc->dev;

	q->ci = 0;
	q->pi = 0;
	q->depth = msgq_cfg[user][idx].depth;
	q->entry_size = msgq_cfg[user][idx].entry_size;
	q->total_size = q->depth * q->entry_size;
	spin_lock_init(&q->lock);

	if (idx == MSG_SQ)
		q->total_size += HI_MSG_SQE_PLD_SIZE * q->depth;

	q->entry = dma_alloc_coherent(dev, q->total_size, &q->dma_addr,
				      GFP_KERNEL);
	if (!q->entry)
		return -ENOMEM;

	dev_info(dev, "%s queue=%d, ci=%#x, pi=%#x, depth=%#x, entry_size=%#x, size=%#lx\n",
		 msgq_user_name[user], idx, q->ci, q->pi, q->depth,
		 q->entry_size, q->total_size);

	return 0;
}

static void hi_msg_queue_sw_uninit(struct hi_msg_core *hmc, int idx)
{
	struct hi_msg_queue *q = &hmc->queue[idx];

	dma_free_coherent(hmc->dev, q->total_size, q->entry, q->dma_addr);
}

u32 hi_msg_reg_read(struct hi_msg_core *hmc, u16 offset)
{
	return readl(hmc->reg_base + offset);
}

void hi_msg_reg_write(struct hi_msg_core *hmc, u16 offset, u32 val)
{
	writel(val, hmc->reg_base + offset);
}

static void hi_msg_queue_hw_init(struct hi_msg_core *hmc, int idx)
{
	struct hi_msg_queue *q = &hmc->queue[idx];

	/* cfg depth pre */
	hi_msg_reg_write(hmc, msgq_reg[idx].depth, q->depth);

	if (idx == MSG_SQ)
		hi_msg_reg_write(hmc, msgq_reg[idx].pi, q->pi);
	else
		hi_msg_reg_write(hmc, msgq_reg[idx].ci, q->ci);

	hi_msg_reg_write(hmc, msgq_reg[idx].addr_l, q->dma_addr & 0xffffffff);
	hi_msg_reg_write(hmc, msgq_reg[idx].addr_h,
			 q->dma_addr >> BITS_PER_TYPE(u32));

	if (idx == MSG_RQ)
		hi_msg_reg_write(hmc, msgq_reg[idx].entry_size,
				 hi_msg_rqe_size_hw(HI_MSG_RQE_SIZE));
}

static void hi_msg_reset_queue(struct hi_msg_core *hmc)
{
	hi_msg_reg_write(hmc, MSGQ_RST, 1);
	hi_msg_reg_write(hmc, MSGQ_RST, 0);
}

static irqreturn_t hi_msg_irq(int irq, void *context)
{
	struct hi_msg_core *hmc = (struct hi_msg_core *)context;
	struct hi_msg_queue *cq = &hmc->queue[MSG_CQ];
	unsigned long flags;
	u32 ro;

	ro = hi_msg_reg_read(hmc, CQ_INT_RO);
	if (!ro)
		return IRQ_NONE;

	hi_msg_reg_write(hmc, CQ_INT_MASK, 0x1);

	if (hmc->irq_handler)
		hmc->irq_handler(hmc);

	if (hmc->isr_handler)
		return IRQ_WAKE_THREAD;

	hi_msg_reg_write(hmc, CQ_INT_STATUS, 0x1);

	spin_lock_irqsave(&cq->lock, flags);
	if (cq->pi == cq->ci) {
		hi_msg_reg_write(hmc, CQ_INT_STATUS, 0x1);
		hi_msg_reg_write(hmc, CQ_INT_MASK, 0x0);
	} else {
		atomic_set(&hmc->cq_int_mask, 1);
	}
	spin_unlock_irqrestore(&cq->lock, flags);

	return IRQ_HANDLED;
}

static irqreturn_t hi_msg_isr(int irq, void *context)
{
	struct hi_msg_core *hmc = (struct hi_msg_core *)context;

	hmc->isr_handler(hmc);

	hi_msg_reg_write(hmc, CQ_INT_STATUS, 0x1);
	hi_msg_reg_write(hmc, CQ_INT_MASK, 0x0);

	return IRQ_HANDLED;
}

static int hi_msg_queue_irq_init(struct hi_msg_core *hmc)
{
	int ret;

	/* Config sq int mask for imp */
	hi_msg_reg_write(hmc, SQ_INT_MSK, 0x0);

	if (!hmc->virq)
		return 0;

	ret = request_threaded_irq(hmc->virq, hi_msg_irq, hi_msg_isr,
					IRQF_ONESHOT | IRQF_SHARED,
					hmc->queue_name, hmc);
	if (ret) {
		dev_err(hmc->dev, "request msgq irq failed\n");
		return ret;
	}
	dev_info(hmc->dev, "request irq[%u] succeeded\n", hmc->virq);
	hi_msg_reg_write(hmc, MSGQ_INT_SEL, hmc->intx);
	hi_msg_reg_write(hmc, CQ_INT_STATUS, 0x1);
	hi_msg_reg_write(hmc, CQ_INT_MASK, 0x0);

	return 0;
}

static void hi_msg_queue_irq_uninit(struct hi_msg_core *hmc)
{
	if (hmc->virq) {
		hi_msg_reg_write(hmc, CQ_INT_MASK, 0x1);
		hi_msg_reg_write(hmc, CQ_INT_STATUS, 0x1);

		free_irq(hmc->virq, hmc);
	}

	hi_msg_reg_write(hmc, SQ_INT_MSK, 0x1);
}

int hi_msg_core_init(struct hi_msg_core *hmc, int user)
{
	int i, j, ret;

	hmc->user = user;
	hmc->reg_base = ioremap(hmc->q_addr, hmc->q_size);
	if (!hmc->reg_base)
		return -ENOMEM;

	for (i = 0; i < MSGQ_NUM; i++) {
		ret = hi_msg_queue_sw_init(hmc, user, i);
		if (ret)
			goto sw_uninit;
	}

	hi_msg_reset_queue(hmc);

	for (i = 0; i < MSGQ_NUM; i++)
		hi_msg_queue_hw_init(hmc, i);

	ret = hi_msg_queue_irq_init(hmc);
	if (ret)
		goto sw_uninit; /* Now i = MSGQ_NUM */

	hi_msg_debugfs_init(hmc);

	return 0;
sw_uninit:
	hi_msg_reset_queue(hmc);

	for (j = 0; j < i; j++)
		hi_msg_queue_sw_uninit(hmc, j);

	iounmap(hmc->reg_base);
	return ret;
}

void hi_msg_core_uninit(struct hi_msg_core *hmc)
{
	int i;

	hi_msg_debugfs_uninit(hmc);
	hi_msg_queue_irq_uninit(hmc);
	hi_msg_reset_queue(hmc);

	for (i = 0; i < MSGQ_NUM; i++)
		hi_msg_queue_sw_uninit(hmc, i);

	iounmap(hmc->reg_base);
}

void hi_msg_sqe_init(struct hi_msg_sqe *sqe, int msn, struct msg_info *info,
		     int task_type, u8 code)
{
	bool idev_flag = false;

	sqe->task_type = (u8)task_type;
	/* ub bus controller & idev 's local is 1 */
	if (info->uent) {
		if (info->ubc != info->uent &&
		    uent_type(info->uent) == UB_TYPE_ICONTROLLER)
			idev_flag = true;

		sqe->local = (info->ubc == info->uent || idev_flag) ? 1 : 0;
		if (sqe->local)
			sqe->dev_type = idev_flag ? TYPE_IDEV : TYPE_BUS_CONTROLLER;
	} else if (task_type == HISI_PRIVATE) {
		/* send private msgq req before ubc->uent init */
		sqe->local = 1;
		sqe->dev_type = TYPE_BUS_CONTROLLER;
	}

	/* only msg need icrc */
	sqe->icrc = (task_type == PROTOCOL_MSG) ? 1 : 0;
	sqe->opcode = code;
	sqe->p_len = info->req_pkt_size;
	sqe->msn = (u16)msn;
	/* p_addr init inside submit */
}

int hi_msg_cq_poll(struct hi_msg_core *hmc, int task_type, u16 msn)
{
	struct hi_msg_queue *cq = &hmc->queue[MSG_CQ];
	struct hi_msg_cqe *cqe;
	unsigned long flags;
	int i, cnt, idx;

	spin_lock_irqsave(&cq->lock, flags);
	cq->pi = hi_msg_reg_read(hmc, CQ_PI);
	if (cq->pi == cq->ci) {
		spin_unlock_irqrestore(&cq->lock, flags);
		return -EAGAIN;
	}

	cnt = q_used_cnt(cq);
	for (i = 0; i < cnt; i++) {
		idx = q_ptr_idx(cq, ci, i);
		cqe = cq_entry(hmc, idx);
		if (cqe->msn == msn && cqe->task_type == (u8)task_type &&
		    (task_type != PROTOCOL_MSG || cqe->type == MSG_RSP)) {
			spin_unlock_irqrestore(&cq->lock, flags);
			return idx;
		}
	}
	spin_unlock_irqrestore(&cq->lock, flags);
	return -EAGAIN;
}

int hi_message_cqe_check(struct device *dev, struct hi_msg_sqe *sqe,
			 struct hi_msg_cqe *cqe, u16 rsp_pkt_size)
{
	if (cqe->status != CQE_SUCCESS) {
		if (!hi_ver_exch_unsupp_msg(cqe))
			dev_err(dev, "cqe fail status=%u\n", cqe->status);
		return -EINVAL;
	}

	if (cqe->p_len > rsp_pkt_size || cqe->p_len > HI_MSG_RQE_SIZE) {
		dev_err(dev, "cqe p_len %#x invalid, rsp_pkt_size %#x\n",
			cqe->p_len, rsp_pkt_size);
		return -EINVAL;
	}

	if (sqe->task_type == PROTOCOL_MSG) {
		if (cqe->p_len < MSG_PKT_HEADER_SIZE) {
			dev_err(dev, "cqe p_len %u is less than msg pkt header size.\n",
				cqe->p_len);
			return -EINVAL;
		}
		if ((sqe->opcode >> 1) == (cqe->opcode >> 1))
			return 0;
	} else {
		if (sqe->opcode == cqe->opcode)
			return 0;
	}

	dev_err(dev, "opcode sqe %#x != cqe %#x\n", sqe->opcode, cqe->opcode);
	return -EINVAL;
}

void hi_msg_rqe_get(struct hi_msg_core *hmc, void *buf, struct hi_msg_cqe *cqe)
{
	u16 rqe_end_index, rqe_high_size, rqe_low_size, pi, depth;
	u32 p_len;

	depth = hmc->queue[MSG_RQ].depth;
	pi = cqe->rq_pi;
	p_len = cqe->p_len;

	rqe_end_index = pi + DIV_ROUND_UP(p_len, HI_MSG_RQE_SIZE);
	if (rqe_end_index <= depth) {
		memcpy(buf, rq_entry(hmc, pi), p_len);
		return;
	}

	/* overlap scenario */
	rqe_high_size = (depth - pi) * HI_MSG_RQE_SIZE;
	rqe_low_size = p_len - rqe_high_size;
	memcpy(buf, rq_entry(hmc, pi), rqe_high_size);
	memcpy(buf + rqe_high_size, rq_entry(hmc, 0), rqe_low_size);
}

void hi_msg_rq_update(struct hi_msg_core *hmc, int cq_idx)
{
	struct hi_msg_queue *rq = &hmc->queue[MSG_RQ];
	struct hi_msg_cqe *cqe;

	cqe = cq_entry(hmc, cq_idx);
	rq->ci = (cqe->rq_pi + DIV_ROUND_UP(cqe->p_len, HI_MSG_RQE_SIZE)) %
		 rq->depth;
	wmb(); /* Ensure the register is written correctly. */
	hi_msg_reg_write(hmc, RQ_CI, rq->ci);
}

void hi_msg_set_pkt_msn(struct msg_info *info, int task_type, u16 msn,
			u8 msgq_id)
{
	struct enum_topo_query_req *req;
	struct msg_pkt_header *header;
	void *pkt = info->req_packet;
	size_t header_sz;

	switch (task_type) {
	case PROTOCOL_ENUM:
		header_sz = ENUM_PKT_HEADER_SIZE +
			    calc_enum_pld_header_size(
				    (struct enum_pld_scan_header
					     *)(pkt + ENUM_PKT_HEADER_SIZE),
				    true);
		req = (struct enum_topo_query_req *)(pkt + header_sz);
		req->common.msn = msn;
		req->common.msgq_id = msgq_id;
		break;
	case PROTOCOL_MSG:
		header = (struct msg_pkt_header *)pkt;
		header->src_tassn = msn;
		header->msgq_id = msgq_id;
		break;
	default:
		return;
	}
}
