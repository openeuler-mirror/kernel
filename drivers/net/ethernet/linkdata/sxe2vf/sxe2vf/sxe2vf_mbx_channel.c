// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_mbx_channel.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/atomic.h>
#include "linux/random.h"
#include "sxe2vf.h"
#include "sxe2_cmd.h"
#include "sxe2vf_mbx_channel.h"
#include "sxe2_log.h"
#include "sxe2_mbx_public.h"
#include "sxe2vf_mbx_msg.h"

#define SXE2VF_MSG_HANDLING_MAX_CNT (1024)

STATIC atomic64_t g_msg_session_id;

void sxe2vf_cmd_session_id_init(void)
{
	u64 session_id;

	get_random_bytes(&session_id, sizeof(session_id));

	atomic64_set(&g_msg_session_id, session_id);
}

STATIC inline u64 sxe2vf_msg_session_id_alloc(void)
{
	return (u64)atomic64_add_return(SXE2_MSG_SESSION_ADD_ONE, &g_msg_session_id);
}

STATIC s32 sxe2vf_mbx_desc_alloc(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_mbx_queue *queue)
{
	struct sxe2vf_mbx_ring *desc = &queue->desc;
	size_t size = queue->depth * sizeof(struct sxe2vf_mbx_desc);
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);

	desc->va = dma_alloc_coherent(dev, size, &desc->pa, GFP_KERNEL);
	if (!desc->va) {
		LOG_DEV_ERR("alloc mbx desc dma mem failed, size %zu.\n", size);
		return -ENOMEM;
	}

	desc->size = size;

	DATA_DUMP(desc->va, (u32)size, "desc alloc");

	return 0;
}

STATIC void sxe2vf_mbx_desc_free(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_mbx_queue *queue)
{
	struct sxe2vf_mbx_ring *desc = &queue->desc;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);

	if (!desc->va)
		return;
	dma_free_coherent(dev, desc->size, desc->va, desc->pa);
	desc->va = NULL;
}

STATIC s32 sxe2vf_mbx_bufs_alloc(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_mbx_queue *queue)
{
	struct sxe2vf_mbx_ring *buf;
	size_t size = queue->depth * sizeof(struct sxe2vf_mbx_ring);
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	u16 i;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf) {
		LOG_DEV_ERR("alloc mbx buf va memory failed, cnt %d, size %zu.\n",
			    queue->depth, sizeof(*buf));
		return -ENOMEM;
	}

	buf->size = size;
	for (i = 0; i < queue->depth; i++) {
		buf[i].size = queue->buf_size;
		buf[i].va = dma_alloc_coherent(dev, buf[i].size, &buf[i].pa,
					       GFP_KERNEL);
		if (!buf[i].va) {
			LOG_DEV_ERR("buf[%d] alloc dma mem failed, size %zu.\n", i,
				    buf[i].size);
			ret = -ENOMEM;
			goto l_alloc_failed;
		}
	}

	queue->buf = buf;
	return 0;

l_alloc_failed:
	while (i) {
		i--;
		dma_free_coherent(dev, buf[i].size, buf[i].va, buf[i].pa);
		buf[i].va = NULL;
	}
	kfree(buf);
	return ret;
}

STATIC void sxe2vf_mbx_bufs_free(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_mbx_queue *queue)
{
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_mbx_ring *buf;
	u16 i;

	if (!queue->buf)
		return;

	for (i = 0; i < queue->depth; i++) {
		buf = &queue->buf[i];
		dma_free_coherent(dev, buf->size, buf->va, buf->pa);
		buf->va = NULL;
	}
	kfree(queue->buf);
	queue->buf = NULL;
}

STATIC s32 sxe2vf_mbx_txq_init(struct sxe2vf_adapter *adapter)
{
	s32 ret;
	struct sxe2vf_mbx_queue *q = &adapter->channel_ctxt.txq;

	mutex_lock(&q->lock);

	q->depth = SXE2VF_MBX_Q_DESC_CNT;
	q->buf_size = SXE2VF_MBX_BUF_SIZE;

	q->ntc = 0;
	q->ntu = 0;

	ret = sxe2vf_mbx_desc_alloc(adapter, q);
	if (ret) {
		LOG_ERROR_BDF("mbx txq desc alloc fail.\n");
		goto l_desc_free;
	}

	ret = sxe2vf_mbx_bufs_alloc(adapter, q);
	if (ret) {
		LOG_ERROR_BDF("mbx txq buf alloc fail.\n");
		goto l_desc_free;
	}

	sxe2vf_hw_mbx_regs_dump(&adapter->hw);
	ret = sxe2vf_hw_mbx_txq_enable(&adapter->hw, q->depth, q->desc.pa);
	sxe2vf_hw_mbx_regs_dump(&adapter->hw);
	if (ret) {
		LOG_ERROR_BDF("mbx txq enable failed.\n");
		goto l_bufs_free;
	}
	mutex_unlock(&q->lock);

	LOG_INFO_BDF("mbx txq depth:%u buf size:%u raw data size:%lu\t"
		     "out_hdr_len:%lu in_hdr_len:%lu \t"
		     "desc va:%pK pa:0x%llx.\n",
		     q->depth, q->buf_size, SXE2VF_MBX_RAW_MSG_MAX_SIZE,
		     SXE2VF_CMD_HDR_SIZE, SXE2VF_MBX_MSG_HDR_SIZE, q->desc.va,
		     q->desc.pa);

	return ret;

l_bufs_free:
	sxe2vf_mbx_bufs_free(adapter, q);

l_desc_free:
	sxe2vf_mbx_desc_free(adapter, q);
	q->depth = 0;
	q->buf_size = 0;
	mutex_unlock(&q->lock);
	return ret;
}

static void sxe2vf_mbx_txq_deinit(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mbx_queue *q = &adapter->channel_ctxt.txq;

	mutex_lock(&q->lock);
	sxe2vf_hw_mbx_txq_disable(&adapter->hw);

	sxe2vf_mbx_desc_free(adapter, q);
	sxe2vf_mbx_bufs_free(adapter, q);
	q->depth = 0;

	mutex_unlock(&q->lock);
}

STATIC void sxe2vf_mbx_rxq_desc_fill(struct sxe2vf_mbx_queue *queue, u16 idx)
{
	struct sxe2vf_mbx_desc *desc;
	struct sxe2vf_mbx_ring *buf;

	desc = SXE2VF_MBX_Q_DESC(queue, idx);
	buf = &queue->buf[idx];

	(void)memset(desc, 0, sizeof(*desc));
	(void)memset(buf->va, 0, buf->size);

	desc->flags |= cpu_to_le16(SXE2VF_MBX_DESC_BUF);
	if (buf->size > SXE2VF_MBX_DESC_LB_SIZE)
		desc->flags |= cpu_to_le16(SXE2VF_MBX_DESC_LB);

	desc->opcode = cpu_to_le16(SXE2_VF_PF_TO_VF);

	desc->data_len = cpu_to_le16((u16)buf->size);
	desc->buf_addr_h = cpu_to_le32(upper_32_bits(buf->pa));
	desc->buf_addr_l = cpu_to_le32(lower_32_bits(buf->pa));
}

static s32 sxe2vf_mbx_rxq_init(struct sxe2vf_adapter *adapter)
{
	s32 ret;
	u16 i;
	struct sxe2vf_mbx_queue *q = &adapter->channel_ctxt.rxq;

	mutex_lock(&q->lock);

	q->depth = SXE2VF_MBX_Q_DESC_CNT;
	q->buf_size = SXE2VF_MBX_BUF_SIZE;

	q->ntc = 0;
	q->ntu = 0;

	ret = sxe2vf_mbx_desc_alloc(adapter, q);
	if (ret) {
		LOG_ERROR_BDF("mbx rxq desc alloc fail.\n");
		goto l_desc_free;
	}

	ret = sxe2vf_mbx_bufs_alloc(adapter, q);
	if (ret) {
		LOG_ERROR_BDF("mbx rxq buf alloc fail.\n");
		goto l_desc_free;
	}

	for (i = 0; i < q->depth; i++)
		sxe2vf_mbx_rxq_desc_fill(q, i);

	sxe2vf_hw_mbx_regs_dump(&adapter->hw);
	ret = sxe2vf_hw_mbx_rxq_enable(&adapter->hw, q->depth, q->desc.pa);
	sxe2vf_hw_mbx_regs_dump(&adapter->hw);
	if (ret) {
		LOG_ERROR_BDF("mbx rxq enable failed.\n");
		goto l_bufs_free;
	}
	mutex_unlock(&q->lock);

	LOG_INFO_BDF("mbx rxq depth:%u buf size:%u raw data size:%lu\t"
		     "out_hdr_len:%lu\t"
		     "in_hdr_len:%lu desc va:%pK pa:0x%llx.\n",
		     q->depth, q->buf_size, SXE2VF_MBX_RAW_MSG_MAX_SIZE,
		     SXE2VF_CMD_HDR_SIZE, SXE2VF_MBX_MSG_HDR_SIZE, q->desc.va,
		     q->desc.pa);
	return ret;

l_bufs_free:
	sxe2vf_mbx_bufs_free(adapter, q);

l_desc_free:
	sxe2vf_mbx_desc_free(adapter, q);
	q->depth = 0;
	q->buf_size = 0;
	mutex_unlock(&q->lock);
	return ret;
}

static void sxe2vf_mbx_rxq_deinit(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mbx_queue *q = &adapter->channel_ctxt.rxq;

	mutex_lock(&q->lock);
	sxe2vf_hw_mbx_rxq_disable(&adapter->hw);

	sxe2vf_mbx_desc_free(adapter, q);
	sxe2vf_mbx_bufs_free(adapter, q);
	q->depth = 0;

	mutex_unlock(&q->lock);
}

s32 sxe2vf_mbx_channel_init(struct sxe2vf_adapter *adapter)
{
	s32 ret;

	ret = sxe2vf_mbx_rxq_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("mbx rxq init failed.\n");
		return ret;
	}

	ret = sxe2vf_mbx_txq_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("mbx txq init failed.\n");
		goto l_rxq_deinit;
	}

	return ret;

l_rxq_deinit:
	sxe2vf_mbx_rxq_deinit(adapter);

	return ret;
}

static void sxe2vf_mbx_channel_disable(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_msg_params params = {0};
	s32 ret;

	if (!sxe2vf_hw_mbx_txq_is_enable(hw) && !sxe2vf_hw_mbx_rxq_is_enable(hw)) {
		LOG_INFO_BDF("mbx channel is not enable.\n");
		return;
	}

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NO_RESP,
					SXE2_VF_MBX_DISABLE, NULL, 0, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("mbx channel disable msg send failed.(err:%d)\n", ret);
}

void sxe2vf_mbx_channel_deinit(struct sxe2vf_adapter *adapter)
{
	sxe2vf_mbx_channel_disable(adapter);

	sxe2vf_hw_mbx_regs_dump(&adapter->hw);

	sxe2vf_mbx_rxq_deinit(adapter);
	sxe2vf_mbx_txq_deinit(adapter);

	sxe2vf_hw_mbx_regs_dump(&adapter->hw);
}

void sxe2vf_mbx_resource_free(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mbx_queue *txq = &adapter->channel_ctxt.txq;
	struct sxe2vf_mbx_queue *rxq = &adapter->channel_ctxt.rxq;

	mutex_lock(&rxq->lock);
	sxe2vf_mbx_desc_free(adapter, rxq);
	sxe2vf_mbx_bufs_free(adapter, rxq);
	rxq->depth = 0;
	mutex_unlock(&rxq->lock);

	mutex_lock(&txq->lock);
	sxe2vf_mbx_desc_free(adapter, txq);
	sxe2vf_mbx_bufs_free(adapter, txq);
	txq->depth = 0;
	mutex_unlock(&txq->lock);
}

STATIC void sxe2vf_mbx_tx_unprepare(struct sxe2vf_msg_ctxt *msg_ctxt)
{
	struct sxe2vf_cmd_hdr *out_hdr = NULL;
	struct sxe2vf_mbx_msg_hdr *inner_hdr = NULL;

	kfree(msg_ctxt->full_msg);

	out_hdr = msg_ctxt->rcv_buf;
	inner_hdr = (struct sxe2vf_mbx_msg_hdr *)((u8 *)msg_ctxt->rcv_buf +
						  out_hdr->hdr_len);

	if (msg_ctxt->rcv_buf) {
		if (msg_ctxt->msg_raw->out_len)
			(void)memcpy(msg_ctxt->msg_raw->out_data,
				     msg_ctxt->rcv_buf + out_hdr->hdr_len +
						     inner_hdr->data_offset,
				     msg_ctxt->msg_raw->out_len);
		kfree(msg_ctxt->rcv_buf);
	}
}

STATIC s32 sxe2vf_mbx_tx_prepare(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_msg_params *msg_raw,
				 struct sxe2vf_msg_ctxt *msg_ctxt)
{
	struct sxe2vf_cmd_hdr *out_hdr;
	struct sxe2vf_mbx_msg_hdr *inner_hdr;
	u32 len;
	u32 timeout = msg_raw->timeout ? msg_raw->timeout : SXE2VF_MSG_DFLT_TIMEOUT;
	s32 ret = 0;

	if (msg_raw->in_len > SXE2VF_MBX_RAW_MSG_MAX_SIZE ||
	    msg_raw->out_len > SXE2VF_MBX_RAW_MSG_MAX_SIZE) {
		LOG_ERROR_BDF("opcode:0x%x in_len:%u out_len:%u exceed max:%lu.\n",
			      msg_raw->opcode, msg_raw->in_len, msg_raw->out_len,
			      SXE2VF_MBX_RAW_MSG_MAX_SIZE);
		return -EINVAL;
	}

	msg_ctxt->adapter = adapter;
	msg_ctxt->expired_time = jiffies + secs_to_jiffies(timeout);
	msg_ctxt->opcode = msg_raw->opcode;
	msg_ctxt->session_id = sxe2vf_msg_session_id_alloc();
	msg_ctxt->msg_raw = msg_raw;

	len = msg_raw->in_len + SXE2VF_MBX_FULL_HDR_SIZE;

	msg_ctxt->full_msg = kzalloc(len, GFP_KERNEL);
	if (!msg_ctxt->full_msg) {
		LOG_ERROR_BDF("opcode:0x%x mbx msg buffer mem:%uB malloc failed.\n",
			      msg_raw->opcode, len);
		return -ENOMEM;
	}

	out_hdr = (struct sxe2vf_cmd_hdr *)(msg_ctxt->full_msg);
	out_hdr->magic_code = cpu_to_le32(SXE2_VF_MBX_MAGIC);
	out_hdr->trace_id = cpu_to_le64(msg_raw->trace_id);
	out_hdr->session_id = cpu_to_le64(msg_ctxt->session_id);
	out_hdr->hdr_len = cpu_to_le16((u16)sizeof(*out_hdr));
	out_hdr->cmd_type = (u8)((msg_raw->opcode == SXE2_VF_MBX_DISABLE)
				 ? cpu_to_le16(SXE2VF_MSG_TYPE_DRV_TO_HW)
				 : cpu_to_le16(SXE2VF_MSG_TYPE_VF_TO_PF));
	out_hdr->in_len = cpu_to_le16((u16)len);
	out_hdr->out_len = cpu_to_le16(msg_raw->out_len);
	out_hdr->multi_packet = SXE2_CMD_HDR_MULTI_START | SXE2_CMD_HDR_MULTI_END;

	inner_hdr = (struct sxe2vf_mbx_msg_hdr *)((u8 *)out_hdr +
						  SXE2VF_CMD_HDR_SIZE);
	inner_hdr->op_code = cpu_to_le32(msg_raw->opcode);
	inner_hdr->data_offset = cpu_to_le32(SXE2VF_MBX_MSG_HDR_SIZE);
	inner_hdr->data_len = cpu_to_le32((u32)msg_raw->in_len);

	if (msg_raw->in_len)
		(void)memcpy(out_hdr->body + SXE2VF_MBX_MSG_HDR_SIZE,
			     msg_raw->in_data, msg_raw->in_len);

	msg_ctxt->rcv_len = msg_raw->out_len + SXE2VF_MBX_FULL_HDR_SIZE;
	msg_ctxt->rcv_buf = kzalloc(msg_ctxt->rcv_len, GFP_KERNEL);
	if (!msg_ctxt->rcv_buf) {
		LOG_ERROR_BDF("opcode:0x%x mbx msg rcv buf:%uB malloc failed.\n",
			      msg_raw->opcode, msg_ctxt->rcv_len);
		ret = -ENOMEM;
		goto l_free;
	}

	LOG_INFO_BDF("trace_id:0x%llx opcode:0x%x in_len:%u out_len:%u sid:0x%llx\t"
		     "prepare to send.\n",
		     msg_raw->trace_id, msg_raw->opcode, msg_raw->in_len,
		     msg_raw->out_len, msg_ctxt->session_id);

	goto l_out;

l_free:
	kfree(msg_ctxt->full_msg);

l_out:
	return ret;
}

STATIC u16 sxe2vf_mbx_txq_desc_clean(struct sxe2vf_adapter *adapter,
				     struct sxe2vf_mbx_queue *tq)
{
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_mbx_desc *desc;
	struct sxe2vf_mbx_ring *buf;

	while (sxe2vf_hw_mbx_txq_h_read(hw) != tq->ntc) {
		desc = SXE2VF_MBX_Q_DESC(tq, tq->ntc);
		buf = &tq->buf[tq->ntc];

		(void)memset(desc, 0, sizeof(*desc));
		(void)memset(buf->va, 0, buf->size);
		SXE2VF_RING_IDX_INC(tq->ntc, tq->depth);
	}

	return SXE2VF_MBX_Q_DESC_UNUSED(tq);
}

STATIC struct sxe2vf_mbx_desc *
sxe2vf_mbx_txq_desc_fill(struct sxe2vf_adapter *adapter,
			 struct sxe2vf_cmd_hdr *full_msg)
{
	struct sxe2vf_mbx_queue *txq = &adapter->channel_ctxt.txq;
	struct sxe2vf_mbx_desc *desc;
	struct sxe2vf_mbx_ring *buf;

	LOG_DEBUG_BDF("tq get the #%dth desc\n", txq->ntu);

	desc = SXE2VF_MBX_Q_DESC(txq, txq->ntu);
	buf = &txq->buf[txq->ntu];
	SXE2VF_RING_IDX_INC(txq->ntu, txq->depth);

	desc->opcode = (full_msg->cmd_type == SXE2VF_MSG_TYPE_DRV_TO_HW)
				       ? cpu_to_le16(SXE2_VF_DRV_TO_HW)
				       : cpu_to_le16(SXE2_VF_VF_TO_PF);

	desc->data_len = cpu_to_le16(full_msg->in_len);

	desc->flags |= cpu_to_le16(SXE2VF_MBX_DESC_NO_INTR);
	if (full_msg->in_len) {
		desc->flags |= cpu_to_le16(SXE2VF_MBX_DESC_BUF);
		desc->flags |= cpu_to_le16(SXE2VF_MBX_DESC_READ);
		if (full_msg->in_len > SXE2VF_MBX_DESC_LB_SIZE)
			desc->flags |= cpu_to_le16(SXE2VF_MBX_DESC_LB);

		(void)memcpy(buf->va, full_msg, full_msg->in_len);
		desc->buf_addr_h = cpu_to_le32(upper_32_bits(buf->pa));
		desc->buf_addr_l = cpu_to_le32(lower_32_bits(buf->pa));
	}

	return desc;
}

bool sxe2vf_mbx_tx_done(struct sxe2vf_mbx_desc *desc)
{
	unsigned long expired_time = (jiffies + secs_to_jiffies(SXE2VF_MBX_TIMEOUT));

	udelay(5);

	do {
		if (SXE2VF_HW_DONE(desc))
			return true;

		(void)msleep(SXE2VF_MBX_CHECK_INT);
	} while (time_before(jiffies, expired_time));

	return false;
}

STATIC s32 sxe2vf_mbx_desc_err_trans(u16 desc_ret)
{
	s32 ret;

	switch (desc_ret) {
	case 0:
		ret = 0;
		break;
	case SXE2VF_MBX_DESC_ERR_DES_ERR:
	case SXE2VF_MBX_DESC_ERR_BUF_ERR:
	case SXE2VF_MBX_DESC_ERR_BUF_NUM_ERR:
	case SXE2VF_MBX_DESC_ERR_SRC_BUSY:
		ret = -EAGAIN;
		break;
	default:
		ret = -EIO;
		break;
	}

	return ret;
}

STATIC s32 __sxe2vf_mbx_msg_send(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_cmd_hdr *full_msg)
{
	s32 ret = 0;
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_mbx_queue *txq = &adapter->channel_ctxt.txq;
	struct sxe2vf_mbx_desc *desc = NULL;
	struct sxe2vf_mbx_msg_hdr *inner_hdr =
			(struct sxe2vf_mbx_msg_hdr *)(full_msg->body);
	u32 head;

#ifdef SXE2_CFG_RELEASE
	UNUSED(inner_hdr);
#endif

	mutex_lock(&txq->lock);

	if (!txq->depth) {
		LOG_ERROR_BDF("opcode:0x%x in_len:%u mbx txq disabled,\n"
			      "\t no permit send msg.\n",
			      inner_hdr->op_code, full_msg->in_len);
		ret = -EIO;
		goto l_unlock;
	}

	head = sxe2vf_hw_mbx_txq_h_read(hw);
	if (head >= txq->depth) {
		LOG_ERROR_BDF("opcode:0x%x in_len:%u head:0x%x depth:0x%x mbx txq\t"
			      "overflow\n",
			      inner_hdr->op_code, full_msg->in_len, head,
			      txq->depth);
		ret = -EIO;
		goto l_unlock;
	}

	if (sxe2vf_mbx_txq_desc_clean(adapter, txq) == 0) {
		LOG_ERROR_BDF("opcode:0x%x in_len:%u head:0x%x mbx txq desc use\t"
			      "up\n",
			      inner_hdr->op_code, full_msg->in_len, head);
		ret = -EAGAIN;
		goto l_unlock;
	}

	desc = sxe2vf_mbx_txq_desc_fill(adapter, full_msg);

	DATA_DUMP(desc, sizeof(*desc), "mbx tq desc before");
	DATA_DUMP(full_msg, full_msg->in_len, "mbx tq buf");

	sxe2vf_hw_mbx_txq_t_write(hw, txq->ntu);

	if (!sxe2vf_mbx_tx_done(desc)) {
		sxe2vf_hw_mbx_txq_fault_clear(hw, (u32 *)&ret);
		LOG_DEBUG_BDF("desc[%u] opcode:0x%x in_len:%u mbx txq hw\t"
			      "fault:0x%x\n",
			      txq->ntu, inner_hdr->op_code, full_msg->in_len, ret);
		if (!ret)
			ret = -ETIMEDOUT;
		else
			ret = -EOVERFLOW;
		goto l_unlock;
	}

	ret = sxe2vf_mbx_desc_err_trans(le16_to_cpu(desc->ret));

	LOG_DEBUG_BDF("opcode:0x%x in_len:%u head:0x%x mbx txq send done.\n"
		      "\t(desc return:0x%x)\n",
		      inner_hdr->op_code, full_msg->in_len, head,
		      le16_to_cpu(desc->ret));

l_unlock:
	if (desc)
		DATA_DUMP(desc, sizeof(*desc), "mbx tq desc after");
	if (ret)
		sxe2vf_hw_mbx_regs_dump(&adapter->hw);
	mutex_unlock(&txq->lock);
	return ret;
}

STATIC s32 sxe2vf_msg_wait_entry_add(struct sxe2vf_msg_params *msg_raw,
				     struct sxe2vf_msg_ctxt *msg_ctxt)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = msg_ctxt->adapter;
	struct sxe2vf_wait_entry *wait_entry;
	struct sxe2vf_mbx_waitq *waitq = &adapter->channel_ctxt.waitq;

	wait_entry = kzalloc(sizeof(*wait_entry), GFP_KERNEL);
	if (!wait_entry) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("opcode:0x%x traceid:0x%llx section_id:0x%llx \t"
			      "alloc wait_entry failed.\n",
			      msg_raw->opcode, msg_raw->trace_id,
			      msg_ctxt->session_id);
		goto l_end;
	}
	wait_entry->session_id = msg_ctxt->session_id;
	wait_entry->state = SXE2VF_MSG_STATE_WAITING;
	wait_entry->rcv_len = msg_ctxt->rcv_len;
	wait_entry->rcv_buf = msg_ctxt->rcv_buf;

	spin_lock(&waitq->lock);
	hash_add(waitq->table, &wait_entry->entry, wait_entry->session_id);
	spin_unlock(&waitq->lock);

	msg_ctxt->wait_entry = wait_entry;

l_end:
	return ret;
}

STATIC void sxe2vf_cmd_wait_list_del(struct sxe2vf_msg_ctxt *msg_ctxt)
{
	struct sxe2vf_mbx_waitq *waitq = &msg_ctxt->adapter->channel_ctxt.waitq;

	if (!msg_ctxt->wait_entry)
		return;

	spin_lock(&waitq->lock);
	hash_del(&msg_ctxt->wait_entry->entry);
	spin_unlock(&waitq->lock);

	kfree(msg_ctxt->wait_entry);
	msg_ctxt->wait_entry = NULL;
}

STATIC s32 sxe2vf_msg_rsp_waitq(struct sxe2vf_msg_ctxt *msg_ctxt)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = msg_ctxt->adapter;
	unsigned long timeout;

	while (1) {
		timeout = msg_ctxt->expired_time - jiffies;

		if (time_after(jiffies, msg_ctxt->expired_time))
			break;

		ret = wait_event_timeout(adapter->channel_ctxt.waitq.wq,
					 (msg_ctxt->wait_entry->state !=
					  SXE2VF_MSG_STATE_WAITING),
					 timeout);
		if (!ret || msg_ctxt->wait_entry->state != SXE2VF_MSG_STATE_WAITING)
			break;
	}

	switch (msg_ctxt->wait_entry->state) {
	case SXE2VF_MSG_STATE_WAITING:
		ret = -ETIMEDOUT;
		msg_ctxt->wait_entry->state = SXE2VF_MSG_STATE_CANCELED;
		LOG_WARN_BDF("traceid:0x%llx opcode:0x%x timeout exit wait.\n",
			     msg_ctxt->msg_raw->trace_id, msg_ctxt->opcode);
		goto l_end;
	case SXE2VF_MSG_STATE_CANCELED:
		ret = -ECANCELED;
		LOG_WARN_BDF("traceid:0x%llx opcode:0x%x canceled exit wait.\n",
			     msg_ctxt->msg_raw->trace_id, msg_ctxt->opcode);
		goto l_end;
	case SXE2VF_MSG_STATE_FAULT:
		ret = -EFAULT;
		LOG_WARN_BDF("traceid:0x%llx opcode:0x%x fault exit wait.\n",
			     msg_ctxt->msg_raw->trace_id, msg_ctxt->opcode);
		goto l_end;
	case SXE2VF_MSG_STATE_DONE:
		ret = 0;
		LOG_INFO_BDF("traceid:0x%llx opcode:0x%x done.\n",
			     msg_ctxt->msg_raw->trace_id, msg_ctxt->opcode);
		break;
	default:
		LOG_DEV_WARN("Unexpected wait queue state: %d.\n",
			     msg_ctxt->wait_entry->state);
		SXE2_BUG();
		break;
	}

l_end:
	if (ret)
		sxe2vf_hw_mbx_regs_dump(&adapter->hw);

	return ret;
}

STATIC s32 sxe2vf_mbx_rx_prepare(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_mbx_rcv **mbx_rcv)
{
	u16 len = sizeof(struct sxe2vf_mbx_rcv) + adapter->channel_ctxt.rxq.buf_size;

	*mbx_rcv = kzalloc(len, GFP_KERNEL);
	if (!*mbx_rcv) {
		LOG_ERROR_BDF("mbx rx prepare malloc failed: size %u.\n", len);
		return -ENOMEM;
	}

	(*mbx_rcv)->buf_len = adapter->channel_ctxt.rxq.buf_size;

	return 0;
}

STATIC void sxe2vf_mbx_rx_unprepare(struct sxe2vf_mbx_rcv *mbx_rcv)
{
	kfree(mbx_rcv);
}

STATIC s32 __sxe2vf_mbx_msg_rcv(struct sxe2vf_adapter *adapter,
				struct sxe2vf_mbx_rcv *msg)
{
	s32 ret = 0;
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_mbx_queue *rxq = &adapter->channel_ctxt.rxq;
	struct sxe2vf_mbx_desc *desc;
	u16 ntc;
	struct sxe2vf_mbx_ring *buf;
	u16 data_len;

	mutex_lock(&rxq->lock);
	ntc = rxq->ntc;

	if (!rxq->depth) {
		LOG_ERROR_BDF("rxq disabled cannot rcv msg.\n");
		ret = -ENODATA;
		goto l_unlock;
	}

	desc = SXE2VF_MBX_Q_DESC(rxq, ntc);
	buf = &rxq->buf[ntc];

	if (!(desc->flags & SXE2VF_MBX_DONE)) {
		ret = -ENODATA;
		goto l_unlock;
	}

	LOG_DEBUG_BDF("rxq get the #%dth desc\n", ntc);
	DATA_DUMP(desc, sizeof(*desc), "mbx rq desc");

	if (le16_to_cpu(desc->ret)) {
		LOG_ERROR_BDF("rxq recv event failed, ret: %d.\n",
			      le16_to_cpu(desc->ret));
		ret = -EIO;
		goto l_ntc_inc;
	}

	data_len = le16_to_cpu(desc->data_len);
	if (data_len > adapter->channel_ctxt.rxq.buf_size) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rxq recv event failed, data_len: %d invalid\t"
			      "buf_len:%u.\n",
			      data_len, adapter->channel_ctxt.rxq.buf_size);
		goto l_ntc_inc;
	}
	DATA_DUMP(buf->va, data_len, "mbx rq buf");

	(void)memcpy(&msg->desc, desc, sizeof(msg->desc));
	if (data_len) {
		(void)memcpy(msg->buf, buf->va, data_len);
		msg->buf_len = data_len;
	}

	sxe2vf_mbx_rxq_desc_fill(rxq, ntc);

	sxe2vf_hw_mbx_rxq_t_write(hw, ntc);

l_ntc_inc:
	SXE2VF_RING_IDX_INC(rxq->ntc, rxq->depth);

l_unlock:
	mutex_unlock(&rxq->lock);
	return ret;
}

static void sxe2vf_mbx_rcv_clear(struct sxe2vf_adapter *adapter,
				 struct sxe2vf_mbx_rcv *mbx_rcv)
{
	mbx_rcv->buf_len = adapter->channel_ctxt.rxq.buf_size;
	(void)memset(mbx_rcv->buf, 0, mbx_rcv->buf_len);
	(void)memset(&mbx_rcv->desc, 0, sizeof(mbx_rcv->desc));
}

STATIC s32 sxe2vf_rcv_msg_valid(struct sxe2vf_cmd_hdr *out_hdr,
				struct sxe2vf_mbx_msg_hdr *inner_hdr)
{
	s32 ret = 0;
	u32 opcode = le32_to_cpu(inner_hdr->op_code);

	if (le32_to_cpu(out_hdr->magic_code) != SXE2_VF_MBX_MAGIC) {
		LOG_ERROR("traceid:0x%llx recv cmd magic:0x%x check failed.\n",
			  out_hdr->trace_id, le32_to_cpu(out_hdr->magic_code));
		ret = -EIO;
		return ret;
	}
	ret = (s32)le32_to_cpu(out_hdr->ret);
	if (ret < 0) {
		LOG_ERROR("traceid:0x%llx recv cmd failed, ret: %d.\n",
			  out_hdr->trace_id, ret);
		ret = -EIO;
		return ret;
	}

	if (opcode >= SXE2_VF_OPCODE_NR) {
		LOG_ERROR("traceid:0x%llx recv cmd opcode(%d) invalid, ret: %d.\n",
			  out_hdr->trace_id, opcode, ret);
		ret = -EIO;
		return ret;
	}

	return ret;
}

STATIC void sxe2vf_msg_waitq_wakeup(struct sxe2vf_adapter *adapter,
				    struct sxe2vf_mbx_rcv *mbx_rcv)
{
	struct sxe2vf_wait_entry *wait_entry;
	bool found = false;
	struct sxe2vf_cmd_hdr *out_hdr = (struct sxe2vf_cmd_hdr *)mbx_rcv->buf;
	struct sxe2vf_mbx_waitq *waitq = &adapter->channel_ctxt.waitq;

	spin_lock(&waitq->lock);
	hash_for_each_possible(waitq->table, wait_entry, entry,
			       le64_to_cpu(out_hdr->session_id)) {
		if (wait_entry->state != SXE2VF_MSG_STATE_WAITING ||
		    le64_to_cpu(out_hdr->session_id) != wait_entry->session_id) {
			continue;
		}

		found = true;

		SXE2_BUG_ON(mbx_rcv->buf_len > wait_entry->rcv_len);
		if (mbx_rcv->buf_len > wait_entry->rcv_len) {
			LOG_ERROR_BDF("rcv msg buf_len %d exceed caller\t"
				      "out_len:%d.\n",
				      mbx_rcv->buf_len, wait_entry->rcv_len);
			wait_entry->state = SXE2VF_MSG_STATE_FAULT;
			break;
		}
		(void)memcpy(wait_entry->rcv_buf, mbx_rcv->buf, mbx_rcv->buf_len);

		wait_entry->state = SXE2VF_MSG_STATE_DONE;
	}
	spin_unlock(&waitq->lock);

	if (found)
		wake_up(&adapter->channel_ctxt.waitq.wq);
}

void sxe2vf_waitq_entry_cancel(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_wait_entry *wait_entry;
	struct sxe2vf_mbx_waitq *waitq = &adapter->channel_ctxt.waitq;
	u32 bkt;

	spin_lock(&waitq->lock);
	hash_for_each(waitq->table, bkt, wait_entry, entry) wait_entry->state =
			SXE2VF_MSG_STATE_CANCELED;
	spin_unlock(&waitq->lock);

	wake_up(&waitq->wq);
}

static void sxe2vf_notify_msg_list_add(struct sxe2vf_adapter *adapter,
				       struct sxe2vf_mbx_rcv *mbx_rcv)
{
	struct sxe2vf_notify_msg_list *list = &adapter->channel_ctxt.list;

	mutex_lock(&list->lock);
	list_add_tail(&mbx_rcv->node, &list->head);
	mutex_unlock(&list->lock);
}

static void sxe2vf_notify_msg_list_del(struct sxe2vf_adapter *adapter,
				       struct sxe2vf_mbx_rcv **mbx_rcv)
{
	struct sxe2vf_notify_msg_list *list = &adapter->channel_ctxt.list;

	mutex_lock(&list->lock);

	if (list_empty(&list->head)) {
		*mbx_rcv = NULL;
		mutex_unlock(&list->lock);
		return;
	}

	*mbx_rcv = list_first_entry(&list->head, struct sxe2vf_mbx_rcv, node);
	list_del(&(*mbx_rcv)->node);
	mutex_unlock(&list->lock);
}

void sxe2vf_notify_msg_list_clear(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_notify_msg_list *list = &adapter->channel_ctxt.list;
	struct sxe2vf_mbx_rcv *mbx_rcv;

	mutex_lock(&list->lock);
	while (!list_empty(&list->head)) {
		mbx_rcv = list_first_entry(&list->head, struct sxe2vf_mbx_rcv, node);
		list_del(&mbx_rcv->node);
		kfree(mbx_rcv);
	}
	mutex_unlock(&list->lock);
}

STATIC void __sxe2vf_notify_msg_handle(struct sxe2vf_adapter *adapter,
				       struct sxe2vf_mbx_rcv *msg)
{
	struct sxe2vf_mbx_msg_table *msg_table = sxe2vf_mbx_msg_table_get();
	struct sxe2vf_mbx_msg_hdr *inner_hdr;
	struct sxe2vf_cmd_hdr *out_hdr;
	u32 opcode;
	s32 ret;

	out_hdr = (struct sxe2vf_cmd_hdr *)msg->buf;
	inner_hdr = (struct sxe2vf_mbx_msg_hdr *)(msg->buf + out_hdr->hdr_len);
	opcode = le32_to_cpu(inner_hdr->op_code);

	if (opcode >= SXE2_VF_OPCODE_NR) {
		LOG_ERROR("opcode(%d) invalid exceed max value:0x%x.\n", opcode,
			  SXE2_VF_OPCODE_NR);
		return;
	}

	if (msg_table[opcode].func) {
		ret = msg_table[opcode].func(adapter, ((u8 *)inner_hdr + inner_hdr->data_offset));
		if (ret)
			LOG_ERROR_BDF("opcode:0x%x vf handle result:%d.\n", opcode,
				      ret);
	} else {
		LOG_ERROR_BDF("opcode:0x%x invalid\n", opcode);
	}
}

void sxe2vf_notify_msg_wk_cb(struct work_struct *work)
{
	struct sxe2vf_work_context *wk = container_of(work,
						      struct sxe2vf_work_context,
						      msg_handle_wk);
	struct sxe2vf_adapter *adapter =
			container_of(wk, struct sxe2vf_adapter, work_ctxt);
	struct sxe2vf_mbx_rcv *msg;
	int schedule_count_th = 0;

	while (1) {
		sxe2vf_notify_msg_list_del(adapter, &msg);
		if (!msg)
			break;

		__sxe2vf_notify_msg_handle(adapter, msg);

		kfree(msg);

		schedule_count_th++;
		if (schedule_count_th == SXE2VF_MSG_HANDLING_MAX_CNT) {
			schedule_count_th = 0;
			cond_resched();
		}
	}
}

STATIC void sxe2vf_notify_msg_handle(struct sxe2vf_adapter *adapter,
				     struct sxe2vf_mbx_rcv *mbx_rcv)
{
	struct sxe2vf_mbx_rcv *tmp_msg;
	u32 len = sizeof(*tmp_msg) + mbx_rcv->buf_len;

	tmp_msg = kzalloc(len, GFP_KERNEL);
	if (!tmp_msg) {
		LOG_DEV_ERR("malloc failed, size: %u.\n", len);
		return;
	}
	memcpy(tmp_msg, mbx_rcv, len);
	INIT_LIST_HEAD(&tmp_msg->node);

	sxe2vf_notify_msg_list_add(adapter, tmp_msg);
	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_NOTIFY_MSG, 0);
}

s32 sxe2vf_mbx_msg_rcv(struct sxe2vf_adapter *adapter)
{
	s32 ret;
	struct sxe2vf_mbx_rcv *mbx_rcv;
	struct sxe2vf_cmd_hdr *out_hdr;
	struct sxe2vf_mbx_msg_hdr *inner_hdr;
	u16 idx = 0;
	u32 opcode;

	ret = sxe2vf_mbx_rx_prepare(adapter, &mbx_rcv);
	if (ret)
		return ret;

	do {
		ret = __sxe2vf_mbx_msg_rcv(adapter, mbx_rcv);
		if (ret == -ENODATA)
			goto l_free;

		out_hdr = (struct sxe2vf_cmd_hdr *)mbx_rcv->buf;
		inner_hdr = SXE2_MBX_MSG_HDR_PTR(out_hdr);
		opcode = le32_to_cpu(inner_hdr->op_code);

		ret = sxe2vf_rcv_msg_valid(out_hdr, inner_hdr);
		if (ret)
			goto l_free;

		switch (out_hdr->cmd_type) {
		case SXE2VF_MSG_TYPE_PF_TO_VF:
			sxe2vf_notify_msg_handle(adapter, mbx_rcv);
			break;
		case SXE2VF_MSG_TYPE_PF_REPLY_VF:
			sxe2vf_msg_waitq_wakeup(adapter, mbx_rcv);
			break;
		default:
			LOG_ERROR_BDF("unknown cmd type:%d opcode:0x%x.\n",
				      out_hdr->cmd_type, opcode);
			break;
		}

		idx++;

		sxe2vf_mbx_rcv_clear(adapter, mbx_rcv);
	} while (idx < SXE2VF_MBX_RQ_WEIGHT);

l_free:
	sxe2vf_mbx_rx_unprepare(mbx_rcv);
	if (ret == -ENODATA)
		ret = -ETIMEDOUT;

	return ret;
}

STATIC s32 sxe2vf_msg_rsp_polling(struct sxe2vf_msg_ctxt *msg_ctxt)
{
	s32 ret;
	struct sxe2vf_adapter *adapter = msg_ctxt->adapter;
	struct sxe2vf_mbx_rcv *mbx_rcv;
	struct sxe2vf_cmd_hdr *out_hdr;
	struct sxe2vf_mbx_msg_hdr *inner_hdr;

	ret = sxe2vf_mbx_rx_prepare(adapter, &mbx_rcv);
	if (ret)
		return ret;

	do {
		ret = __sxe2vf_mbx_msg_rcv(adapter, mbx_rcv);
		if (ret == 0) {
			out_hdr = (struct sxe2vf_cmd_hdr *)mbx_rcv->buf;
			inner_hdr = (struct sxe2vf_mbx_msg_hdr *)(mbx_rcv->buf +
								  out_hdr->hdr_len);

			ret = sxe2vf_rcv_msg_valid(out_hdr, inner_hdr);
			if (ret)
				goto l_end;

			if (le32_to_cpu(inner_hdr->op_code) != msg_ctxt->opcode ||
			    le64_to_cpu(out_hdr->session_id) !=
					    msg_ctxt->session_id) {
				LOG_ERROR_BDF("recv invalid cmd traceid:0x%llx\t"
					      "opcode:0x%x\t"
					      "session id: 0x%llx.\n",
					      le64_to_cpu(out_hdr->trace_id),
					      le32_to_cpu(inner_hdr->op_code),
					      le64_to_cpu(out_hdr->session_id));
				sxe2vf_mbx_rcv_clear(adapter, mbx_rcv);
				ret = -ETIMEDOUT;
				continue;
			}

			SXE2_BUG_ON(mbx_rcv->buf_len > msg_ctxt->rcv_len);
			(void)memcpy(msg_ctxt->rcv_buf, mbx_rcv->buf,
				     mbx_rcv->buf_len);
			goto l_end;
		} else if (ret != -ENODATA) {
			LOG_ERROR_BDF("[trace id 0x%llx] opcode:0x%x rq receive\t"
				      "error ret %d.\n",
				      msg_ctxt->msg_raw->trace_id,
				      msg_ctxt->msg_raw->opcode, ret);
			break;
		}
		(void)msleep(SXE2VF_MSG_WB_WAIT_INTERVAL);
	} while (!sxe2vf_dev_state_check(adapter) &&
		 time_before(jiffies, (unsigned long)msg_ctxt->expired_time));

l_end:
	sxe2vf_mbx_rx_unprepare(mbx_rcv);
	if (ret == -ENODATA) {
		ret = -ETIMEDOUT;
		sxe2vf_hw_mbx_regs_dump(&adapter->hw);
		LOG_ERROR_BDF("[trace id 0x%llx] opcode:0x%x polling timeout ret\t"
			      "%d.\n",
			      msg_ctxt->msg_raw->trace_id, msg_ctxt->msg_raw->opcode,
			      ret);
	}
	return ret;
}

s32 sxe2vf_err_code_trans_mbx(s32 err)
{
	s32 ret;

	if (err > -SXE2_VF_ERR_PARAM)
		return err;

	switch (err) {
	case SXE2_VF_ERR_SUCCESS:
		ret = 0;
		break;
	case -SXE2_VF_ERR_NO_MEMORY:
		ret = -ENOMEM;
		break;
	case -SXE2_VF_ERR_NOT_SUPPORTED:
		ret = -EOPNOTSUPP;
		break;
	case -SXE2_VF_ERR_PARAM:
	case -SXE2_VF_ERR_INVALID_VF_ID:
		ret = -EINVAL;
		break;
	case -SXE2_VF_ERR_HANDLE_ERROR:
	case -SXE2_VF_ERR_CQP_COMPL_ERROR:
	case -SXE2_VF_ERR_ADMIN_QUEUE_ERROR:
	case -SXE2_VF_ERR_PF_STATUS_ABNORMAL:
	default:
		ret = -EIO;
		break;
	}

	return ret;
}

s32 sxe2vf_dev_state_check(struct sxe2vf_adapter *adapter)
{
	enum sxe2vf_dev_state state;
	enum sxe2vf_reset_type reset_type;
	s32 ret = SXE2_VF_ERR_SUCCESS;

	sxe2vf_dev_state_get(adapter, &state, &reset_type);
	if (test_bit(SXE2VF_FLAG_DRV_REMOVING, adapter->flags) ||
	    state == SXE2VF_DEVSTATE_STOPPED || state == SXE2VF_DEVSTATE_RESETTING ||
	    state == SXE2VF_DEVSTATE_FAULT)
		ret = -SXE2_VF_ERR_VF_STATUS_ABNORMAL;
	return ret;
}

s32 sxe2vf_mbx_msg_send(struct sxe2vf_adapter *adapter,
			struct sxe2vf_msg_params *msg_raw)
{
	s32 ret;
	struct sxe2vf_msg_ctxt msg_ctxt;
	struct sxe2vf_cmd_hdr *out_hdr;
	struct sxe2vf_mbx_msg_hdr *inner_hdr;
	u16 retry_cnt = 0;

	ret = sxe2vf_dev_state_check(adapter);
	if (ret != SXE2_VF_ERR_SUCCESS) {
		LOG_WARN_BDF("opcode:0x%x no need send during pre check fail,\t"
			     "ret:%d.\n",
			     msg_raw->opcode, ret);
		return -EIO;
	}

	ret = sxe2vf_mbx_tx_prepare(adapter, msg_raw, &msg_ctxt);
	if (ret)
		return ret;

	if (msg_raw->mode == SXE2VF_MSG_RESP_WAIT_NOTIFY) {
		ret = sxe2vf_msg_wait_entry_add(msg_raw, &msg_ctxt);
		if (ret)
			goto l_free;
	}

	do {
		ret = __sxe2vf_mbx_msg_send(adapter, msg_ctxt.full_msg);
		if (ret != -EAGAIN)
			break;

		mdelay(SXE2VF_MSG_RETRY_INTERVAL);

	} while (++retry_cnt < SXE2VF_MSG_RETRY_COUNT);

	if (ret == -EAGAIN) {
		ret = -EBUSY;
		goto l_list_del;
	} else if (ret == -ECANCELED) {
		goto l_cancel;
	} else if (ret) {
		goto l_list_del;
	}

	if (msg_raw->mode == SXE2VF_MSG_RESP_WAIT_NOTIFY) {
		ret = sxe2vf_msg_rsp_waitq(&msg_ctxt);
	} else if (msg_raw->mode == SXE2VF_MSG_RESP_WAIT_POLLING) {
		ret = sxe2vf_msg_rsp_polling(&msg_ctxt);
	} else {
		LOG_INFO_BDF("vf msg opcode:0x%x trace_id:0x%llx in_len:%u no need\t"
			     "resp.\n",
			     msg_raw->opcode, msg_raw->trace_id, msg_raw->in_len);
		goto l_free;
	}

	if (ret == -ECANCELED || ret == -ETIMEDOUT)
		goto l_cancel;
	else if (ret)
		goto l_list_del;

	out_hdr = msg_ctxt.rcv_buf;
	ret = (s32)le32_to_cpu(out_hdr->ret);
	if (unlikely(ret < 0)) {
		LOG_ERROR_BDF("vf msg opcode:0x%x trace_id:0x%llx in_len:%u pf\t"
			      "handled fail.(err:%d)\n",
			      msg_raw->opcode, msg_raw->trace_id, msg_raw->in_len,
			      ret);
		ret = -EIO;
	} else {
		inner_hdr = (struct sxe2vf_mbx_msg_hdr *)(msg_ctxt.rcv_buf +
							  out_hdr->hdr_len);
		ret = (s32)le32_to_cpu(inner_hdr->err_code);
		if (ret) {
			LOG_ERROR_BDF("vf msg opcode:0x%x trace_id:0x%llx\t"
				      "rcv_len:%u\t"
				      "out_hdr ret:%d inner_hdr ret:%d.\n",
				      msg_raw->opcode, msg_raw->trace_id,
				      msg_ctxt.rcv_len, le32_to_cpu(out_hdr->ret),
				      le32_to_cpu(inner_hdr->err_code));
		}
		ret = sxe2vf_err_code_trans_mbx((s32)le32_to_cpu(inner_hdr->err_code));
	}

	goto l_list_del;

l_cancel:
l_list_del:
	if (msg_raw->mode == SXE2VF_MSG_RESP_WAIT_NOTIFY)
		sxe2vf_cmd_wait_list_del(&msg_ctxt);
l_free:
	sxe2vf_mbx_tx_unprepare(&msg_ctxt);
	return ret;
}
