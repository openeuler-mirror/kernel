// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_cmd_channel.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DPDK_DRIVER
#include <linux/atomic.h>
#include <linux/random.h>
#include "sxe2.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_common.h"
#include "sxe2_internal_ver.h"
#include "sxe2_misc.h"
#include "sxe2_log.h"
#include "sxe2_monitor.h"
#include "sxe2_event.h"
#include "sxe2_mbx_msg.h"

#define NS_TO_MS_UNIT (1000000)

#define SXE2_WAIT_DONE_MIN (10)
#define SXE2_WAIT_DONE_MAX (20)

#define SXE2_CMD_REQ_LEN(_cmd_hdr)   ((_cmd_hdr)->tran_in_len)
#define SXE2_CMD_RESP_LEN(_cmd_hdr)  ((_cmd_hdr)->tran_out_len)

static DEFINE_PER_CPU(union sxe2_trace_info, sxe2_trace_id);

#define TRACE_ID_CHIP_OUT_COUNT_MASK 0x0003FFFFFFFFFFFFLLU
#define TRACE_ID_CHIP_OUT_CPUID_MASK 0x3FFLLU
#define TRACE_ID_CHIP_OUT_TYPE_MASK 0xFLLU

#ifndef SXE2_TEST
#ifdef SXE2_CFG_DEBUG
#define SXE2_CMD_TQ_WB_DFLT_TIMEOUT                                                 \
	(3)
#else
#define SXE2_CMD_TQ_WB_DFLT_TIMEOUT (1)
#endif
#define SXE2_CMD_WB_WAIT_INTERVAL 1
#else
#define SXE2_CMD_TQ_WB_DFLT_TIMEOUT (0)
#define SXE2_CMD_WB_WAIT_INTERVAL 0
#endif
#define SXE2_CMD_CHNL_RELEASE_CHECK_INTERVAL 1
#define SXE2_CMD_RETRY_INTERVAL 1
#define SXE2_CMD_RETRY_COUNT 3
#define SXE2_CMD_POLLING_INTERVAL 10
#define SXE2_CMD_CHNL_RECV_MULIT_PACK_INTERVAL 3

#define SXE2_CMD_WORK_NAME "SXE2-CMD"

#define SXE2_POLLING_CMDQ_IDLE_INTERVAL (10)
#define SXE2_POLLING_CMDQ_IDLE_TIMEOUT (1000)

#define SXE2_WAIT_INTERRUPTIBLE_INTERVAL (1)
#define SXE2_CMD_RECV_MULIT_DFLT_TIMEOUT 1

#ifndef secs_to_jiffies
#define secs_to_jiffies(_secs) (msecs_to_jiffies((_secs) * 1000))
#endif

#define SXE2_HDR_SIZE(type)                                                         \
	(type == SXE2_CMD_TYPE_CLI ? SXE2_CMD_HDR_SIZE                              \
				   : (SXE2_CMD_HDR_SIZE + SXE2_DRV_MSG_HDR_SIZE))

#define SXE2_MSG_BODY(msg_hdr)                               \
	({									\
		const struct sxe2_drv_msg_hdr *__mh = (msg_hdr);			\
		(void *)__mh + le32_to_cpu(__mh->data_offset);			\
	})

#define SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, chnl_type)                             \
	(&(adapter)->cmd_channel_ctxt.channel[(chnl_type)])
#define SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, q_type)                       \
	(&(adapter)->cmd_channel_ctxt.channel[(chnl_type)]                          \
			  .queue[(q_type)])

#define SXE2_CMD_QUEUE_DESC(queue, i)                                               \
	(&(((struct sxe2_cmd_desc *)((queue)->desc.va))[i]))
#define SXE2_CMD_QUEUE_BUF(queue, i) ((queue)->buf[i].va)

#define SXE2_CMD_QUEUE_DESC_UNUSED(queue)                      \
({								\
	const struct sxe2_cmd_queue *__q = (queue);                    \
	u16 ntc = __q->ntc;                                      \
	u16 ntu = __q->ntu;                                      \
	u16 depth = __q->depth;                                  \
	(u16)(((ntc > ntu) ? 0 : depth) + ntc - ntu - 1);        \
})

#define SXE2_QUEUE_IDX_INC(i, depth) \
	do {                             \
		typeof(i) *p = &(i);         \
		(*p)++;                      \
		if ((*p) == (depth))         \
			(*p) = 0;                \
	} while (0)

#define SXE2_WB_DONE(desc) (le16_to_cpu((desc)->flags) & SXE2_CMD_DONE)
#define SXE2_CMD_RQ_WEIGHT 256

#define SXE2_MSG_HANDLING_MAX_CNT (1024)

struct workqueue_struct *sxe2_rq_recv_wq;
struct workqueue_struct *sxe2_msg_handle_wq;

STATIC atomic64_t g_cmd_session_id;

enum sxe2_cmd_work_state {
	SXE2_RQ_RECV_WORK_SCHED,
	SXE2_RQ_RECV_WORK_STOPPED,
	SXE2_MSG_HANDLE_WORK_SCHED,
	SXE2_MSG_HANDLE_WORK_STOPPED,
};

enum sxe2_cmd_exec_mode {
	SXE2_CMD_EXEC_NOTIFY,
	SXE2_CMD_EXEC_POLLING,
	SXE2_CMD_EXEC_NO_RESP,
};

static void sxe2_cmd_work_init(struct sxe2_adapter *adapter);

STATIC void sxe2_cmd_work_exit(struct sxe2_adapter *adapter);

STATIC void sxe2_msg_list_add(struct sxe2_adapter *adapter,
			      struct sxe2_recv_msg *msg);

static void sxe2_msg_list_del(struct sxe2_adapter *adapter,
			      struct sxe2_recv_msg **msg);

static void sxe2_msg_handle_work_schedule(struct sxe2_adapter *adapter);

static s32 sxe2_cmd_drv_exec(struct sxe2_adapter *adapter,
			     struct sxe2_cmd_params *cmd_params,
			     enum sxe2_cmd_type type);

#ifdef SXE2_CFG_DEBUG
STATIC void sxe2_dump_fwc(struct sxe2_adapter *adapter)
{
	struct sxe2_hw *hw = &adapter->hw;

	LOG_DEBUG_BDF("ATQT: 0x%x, ATQH: 0x%x, ARQT: 0x%x, ARQH: 0x%x.\n",
		      sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_ATQT),
		      sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_ATQH),
		      sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_ARQT),
		      sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_ARQH));
}
#endif

static inline bool is_interrupt_signal(struct task_struct *p)
{
	if (sigismember(&p->pending.signal, SIGINT) ||
	    sigismember(&p->pending.signal, SIGKILL) ||
	    sigismember(&p->pending.signal, SIGQUIT)) {
		return true;
	}
	return false;
}

STATIC bool signal_pending_is_interrupt(void)
{
	if (!signal_pending(current))
		return false;

	return is_interrupt_signal(current);
}

STATIC void sxe2_trace_id_init(void)
{
	u32 cpu;
	union sxe2_trace_info *id;

	for_each_possible_cpu(cpu) {
		id = (union sxe2_trace_info *)&per_cpu(sxe2_trace_id, cpu);
		id->sxe2_trace_id_param.cpu_id =
				(cpu & TRACE_ID_CHIP_OUT_CPUID_MASK);
		id->sxe2_trace_id_param.count = 0;
		id->sxe2_trace_id_param.type = (SXE2_CMD_TYPE_DRV_TO_FW &
						TRACE_ID_CHIP_OUT_TYPE_MASK);
	}
}

void sxe2_trace_id_alloc(u64 *trace_id)
{
	union sxe2_trace_info *trace;
	u64 trace_id_count;

	preempt_disable();
	trace = this_cpu_ptr(&sxe2_trace_id);

	trace_id_count = trace->sxe2_trace_id_param.count;
	++trace_id_count;
	trace->sxe2_trace_id_param.count =
			(trace_id_count & TRACE_ID_CHIP_OUT_COUNT_MASK);

	*trace_id = trace->id;
	preempt_enable();
}

STATIC void sxe2_cmd_queue_ops_init(struct sxe2_adapter *adapter,
				    enum sxe2_cmd_channel_type chnl_type,
				    enum sxe2_cmd_queue_type q_type)
{
	struct sxe2_cmd_queue *queue =
			SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, q_type);

	if (chnl_type == SXE2_CHNL_FW && q_type == SXE2_CMD_TQ) {
		queue->ops.enable = sxe2_hw_fw_tq_enable;
		queue->ops.disable = sxe2_hw_fw_tq_disable;
		queue->ops.is_idle = sxe2_hw_fw_tq_is_idle;
		queue->ops.write_tail = sxe2_hw_fw_tq_write_tail;
		queue->ops.read_head = sxe2_hw_fw_tq_read_head;
		queue->ops.get_error = sxe2_hw_fw_tq_get_error;
	} else if (chnl_type == SXE2_CHNL_FW && q_type == SXE2_CMD_RQ) {
		queue->ops.enable = sxe2_hw_fw_rq_enable;
		queue->ops.disable = sxe2_hw_fw_rq_disable;
		queue->ops.is_idle = sxe2_hw_fw_rq_is_idle;
		queue->ops.write_tail = sxe2_hw_fw_rq_write_tail;
		queue->ops.read_head = sxe2_hw_fw_rq_read_head;
		queue->ops.get_error = sxe2_hw_fw_rq_get_error;
	} else if (chnl_type == SXE2_CHNL_MBX && q_type == SXE2_CMD_TQ) {
		queue->ops.enable = sxe2_hw_mbx_tq_enable;
		queue->ops.disable = sxe2_hw_mbx_tq_disable;
		queue->ops.write_tail = sxe2_hw_mbx_tq_write_tail;
		queue->ops.read_head = sxe2_hw_mbx_tq_read_head;
		queue->ops.get_error = sxe2_hw_mbx_tq_get_error;
		queue->ops.is_idle = NULL;
	} else if (chnl_type == SXE2_CHNL_MBX && q_type == SXE2_CMD_RQ) {
		queue->ops.enable = sxe2_hw_mbx_rq_enable;
		queue->ops.disable = sxe2_hw_mbx_rq_disable;
		queue->ops.write_tail = sxe2_hw_mbx_rq_write_tail;
		queue->ops.read_head = sxe2_hw_mbx_rq_read_head;
		queue->ops.get_error = sxe2_hw_mbx_rq_get_error;
		queue->ops.is_idle = NULL;
	} else {
		LOG_ERROR_BDF("unknown chnl_type %d, q_type %d.\n", chnl_type,
			      q_type);
	}
}

STATIC void sxe2_cmd_channel_sw_init(struct sxe2_cmd_channel *channel)
{
	mutex_init(&channel->queue[SXE2_CMD_TQ].lock);
	mutex_init(&channel->queue[SXE2_CMD_RQ].lock);
	spin_lock_init(&channel->wq.lock);
	init_waitqueue_head(&channel->wq.wq);
	hash_init(channel->wq.table);
}

STATIC void sxe2_channel_sw_deinit(struct sxe2_cmd_channel *channel)
{
	mutex_destroy(&channel->queue[SXE2_CMD_TQ].lock);
	mutex_destroy(&channel->queue[SXE2_CMD_RQ].lock);
}

STATIC void sxe2_cmd_session_id_init(void)
{
	s64 session_id;

	get_random_bytes(&session_id, sizeof(session_id));

	atomic64_set(&g_cmd_session_id, (u64)session_id);
}

STATIC void sxe2_cmd_channel_init_once(struct sxe2_adapter *adapter)
{
	sxe2_cmd_session_id_init();
	sxe2_trace_id_init();
	sxe2_cmd_channel_sw_init(SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, SXE2_CHNL_FW));
	sxe2_cmd_channel_sw_init(SXE2_ADAPTER_TO_CMD_CHANNEL(adapter,
							     SXE2_CHNL_MBX));
	INIT_LIST_HEAD(&adapter->cmd_channel_ctxt.head);
	mutex_init(&adapter->cmd_channel_ctxt.lock);
	spin_lock_init(&adapter->cmd_channel_ctxt.recv_work_lock);
	spin_lock_init(&adapter->cmd_channel_ctxt.handle_work_lock);
	mutex_init(&adapter->cmd_channel_ctxt.event_lock);
	mutex_init(&adapter->cmd_channel_ctxt.channel[SXE2_CHNL_FW].lock);
	mutex_init(&adapter->cmd_channel_ctxt.channel[SXE2_CHNL_MBX].lock);
}

STATIC void sxe2_cmd_channel_deinit_once(struct sxe2_adapter *adapter)
{
	mutex_destroy(&adapter->cmd_channel_ctxt.event_lock);
	mutex_destroy(&adapter->cmd_channel_ctxt.lock);
	mutex_destroy(&adapter->cmd_channel_ctxt.channel[SXE2_CHNL_FW].lock);
	mutex_destroy(&adapter->cmd_channel_ctxt.channel[SXE2_CHNL_MBX].lock);
	sxe2_channel_sw_deinit(SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, SXE2_CHNL_FW));
	sxe2_channel_sw_deinit(SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, SXE2_CHNL_MBX));
}

static inline s32 sxe2_dma_alloc_coherent(struct sxe2_adapter *adapter,
					  struct sxe2_dma_mem *dma, size_t size)
{
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	dma->va = dmam_alloc_coherent(dev, size, &dma->pa, GFP_KERNEL | __GFP_ZERO);
	if (!dma->va) {
		LOG_DEV_ERR("alloc dma mem failed, size %zu.\n", size);
		ret = -ENOMEM;
		goto l_end;
	}

	dma->size = size;
l_end:
	return ret;
}

static inline void sxe2_dma_free_coherent(struct sxe2_adapter *adapter,
					  struct sxe2_dma_mem *dma)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (!dma->va)
		return;

	dmam_free_coherent(dev, dma->size, dma->va, dma->pa);
	dma->va = NULL;
	dma->pa = 0;
	dma->size = 0;
}

STATIC s32 sxe2_cmd_queue_desc_alloc(struct sxe2_adapter *adapter,
				     struct sxe2_cmd_queue *queue)
{
	struct sxe2_dma_mem *dma = &queue->desc;
	size_t size = queue->depth * sizeof(struct sxe2_cmd_desc);

	return sxe2_dma_alloc_coherent(adapter, dma, size);
}

STATIC void sxe2_cmd_queue_desc_free(struct sxe2_adapter *adapter,
				     struct sxe2_cmd_queue *queue)
{
	sxe2_dma_free_coherent(adapter, &queue->desc);
}

STATIC void sxe2_cmd_queue_bufs_free(struct sxe2_adapter *adapter,
				     struct sxe2_cmd_queue *queue)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_dma_mem *dma;
	u16 i;
	struct sxe2_recv_cache_buff *cache_buff = &queue->cache_buff;

	if (!queue->buf)
		return;

	kfree(cache_buff->buf);
	cache_buff->buf = NULL;

	for (i = 0; i < queue->depth; i++) {
		dma = &queue->buf[i];
		sxe2_dma_free_coherent(adapter, dma);
	}

	devm_kfree(dev, queue->buf);
	queue->buf = NULL;
}

STATIC s32 sxe2_cmd_queue_buf_alloc(struct sxe2_adapter *adapter,
				    struct sxe2_cmd_queue *queue, u16 idx)
{
	struct sxe2_dma_mem *dma = &queue->buf[idx];
	size_t size = queue->buf_size;

	return sxe2_dma_alloc_coherent(adapter, dma, size);
}

STATIC s32 sxe2_cmd_queue_bufs_alloc(struct sxe2_adapter *adapter,
				     struct sxe2_cmd_queue *queue)
{
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 i;

	queue->buf = devm_kcalloc(dev, queue->depth, sizeof(*queue->buf),
				  GFP_KERNEL);
	if (!queue->buf) {
		LOG_DEV_ERR("alloc buf_dma_list failed, cnt %d, size %zu.\n",
			    queue->depth, sizeof(*queue->buf));
		ret = -ENOMEM;
		goto l_end;
	}

	for (i = 0; i < queue->depth; i++) {
		ret = sxe2_cmd_queue_buf_alloc(adapter, queue, i);
		if (ret)
			goto l_alloc_failed;
	}

	queue->cache_buff.buf_offset = 0;
	queue->cache_buff.finish = true;
	queue->cache_buff.buf = kzalloc(queue->buf_size, GFP_KERNEL);
	if (!queue->cache_buff.buf) {
		LOG_DEV_ERR("alloc cache_buff failed, buf_size %d.\n",
			    queue->buf_size);
		ret = -ENOMEM;
		goto l_alloc_failed;
	}

	return 0;

l_alloc_failed:
	sxe2_cmd_queue_bufs_free(adapter, queue);
l_end:
	return ret;
}

STATIC s32 sxe2_cmd_queue_enable(struct sxe2_adapter *adapter,
				 enum sxe2_cmd_channel_type chnl_type,
				 enum sxe2_cmd_queue_type q_type)
{
	s32 ret;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_cmd_queue *queue =
			SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, q_type);

	ret = sxe2_err_code_trans_hw(queue->ops.enable(hw, queue->depth,
						       queue->desc.pa));
	if (ret)
		LOG_DEV_ERR("enable channel %d, queue %d failed.\n", chnl_type,
			    q_type);

	return ret;
}

STATIC void sxe2_cmd_queue_disable(struct sxe2_adapter *adapter,
				   enum sxe2_cmd_channel_type chnl_type,
				   enum sxe2_cmd_queue_type q_type)
{
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_cmd_queue *queue =
			SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, q_type);
	u32 total_delay = 0;

	queue->ops.disable(hw);

	if (!queue->ops.is_idle)
		return;

	do {
		if (queue->ops.is_idle(hw))
			break;
		msleep(SXE2_POLLING_CMDQ_IDLE_INTERVAL);
		total_delay++;
		if (total_delay == SXE2_POLLING_CMDQ_IDLE_TIMEOUT) {
			LOG_DEV_ERR("Cmd queue chnl_type %d, q_type %d disable\t"
				    "timeout\n",
				    chnl_type, q_type);
			total_delay = 0;
		}
	} while (1);
}

STATIC void sxe2_cmd_queue_param_init(enum sxe2_cmd_channel_type chnl_type,
				      enum sxe2_cmd_queue_type q_type,
				      struct sxe2_cmd_queue *queue)
{
	if (chnl_type == SXE2_CHNL_FW && q_type == SXE2_CMD_TQ) {
		queue->depth = SXE2_DEPTH_FW_TQ;
		queue->buf_size = SXE2_BUF_SIZE_FW_TQ;
	} else if (chnl_type == SXE2_CHNL_FW && q_type == SXE2_CMD_RQ) {
		queue->depth = SXE2_DEPTH_FW_RQ;
		queue->buf_size = SXE2_BUF_SIZE_FW_RQ;
	} else if (chnl_type == SXE2_CHNL_MBX && q_type == SXE2_CMD_TQ) {
		queue->depth = SXE2_DEPTH_MBX_TQ;
		queue->buf_size = SXE2_BUF_SIZE_MBX_TQ;
	} else if (chnl_type == SXE2_CHNL_MBX && q_type == SXE2_CMD_RQ) {
		queue->depth = SXE2_DEPTH_MBX_RQ;
		queue->buf_size = SXE2_BUF_SIZE_MBX_RQ;
	} else {
		LOG_ERROR("unknown chnl_type %d, q_type %d.\n", chnl_type, q_type);
	}
}

STATIC void sxe2_cmd_rq_desc_fill(enum sxe2_cmd_channel_type chnl_type,
				  struct sxe2_cmd_queue *queue, u16 i)
{
	struct sxe2_cmd_desc *desc;
	struct sxe2_dma_mem *buf_dma;

	desc = SXE2_CMD_QUEUE_DESC(queue, i);
	buf_dma = &queue->buf[i];

	memset(desc, 0, sizeof(*desc));
	memset(buf_dma->va, 0, buf_dma->size);

	desc->flags |= cpu_to_le16(SXE2_CMD_BUF);
	if (buf_dma->size > SXE2_CMD_LARGE_BUF_SIZE)
		desc->flags |= cpu_to_le16(SXE2_CMD_LARGE_BUF);

	if (chnl_type == SXE2_CHNL_MBX)
		desc->opcode = cpu_to_le16(SXE2_CMD_MBX_TO_PF);

	desc->data_len = cpu_to_le16((u16)buf_dma->size);
	desc->buf_addr_h = cpu_to_le32(upper_32_bits(buf_dma->pa));
	desc->buf_addr_l = cpu_to_le32(lower_32_bits(buf_dma->pa));
}

STATIC void sxe2_cmd_rq_descs_fill(enum sxe2_cmd_channel_type chnl_type,
				   struct sxe2_cmd_queue *queue)
{
	u16 i;

	for (i = 0; i < queue->depth; i++)
		sxe2_cmd_rq_desc_fill(chnl_type, queue, i);
}

STATIC s32 sxe2_cmd_queue_init(struct sxe2_adapter *adapter,
			       enum sxe2_cmd_channel_type chnl_type,
			       enum sxe2_cmd_queue_type q_type)
{
	s32 ret;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_cmd_queue *queue =
			SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, q_type);

	mutex_lock(&queue->lock);

	if (queue->is_enable) {
		ret = 0;
		goto l_end;
	}

	queue->ntu = 0;
	queue->ntc = 0;

	sxe2_cmd_queue_param_init(chnl_type, q_type, queue);

	ret = sxe2_cmd_queue_desc_alloc(adapter, queue);
	if (ret)
		goto l_end;

	ret = sxe2_cmd_queue_bufs_alloc(adapter, queue);
	if (ret)
		goto l_buf_alloc_failed;

	sxe2_cmd_queue_ops_init(adapter, chnl_type, q_type);

	ret = sxe2_cmd_queue_enable(adapter, chnl_type, q_type);
	if (ret)
		goto l_q_enable_failed;

	if (q_type == SXE2_CMD_RQ) {
		sxe2_cmd_rq_descs_fill(chnl_type, queue);
		queue->ops.write_tail(hw, queue->depth - 1);
	}

	queue->is_enable = true;

	goto l_end;

l_q_enable_failed:
	sxe2_cmd_queue_bufs_free(adapter, queue);
l_buf_alloc_failed:
	sxe2_cmd_queue_desc_free(adapter, queue);
l_end:
	mutex_unlock(&queue->lock);
	return ret;
}

STATIC void sxe2_cmd_queue_deinit(struct sxe2_adapter *adapter,
				  enum sxe2_cmd_channel_type chnl_type,
				  enum sxe2_cmd_queue_type q_type)
{
	struct sxe2_cmd_queue *queue =
			SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, q_type);

	mutex_lock(&queue->lock);

	if (!queue->is_enable) {
		mutex_unlock(&queue->lock);
		return;
	}

	queue->is_enable = false;

	sxe2_cmd_queue_disable(adapter, chnl_type, q_type);
	sxe2_cmd_queue_bufs_free(adapter, queue);
	sxe2_cmd_queue_desc_free(adapter, queue);
	mutex_unlock(&queue->lock);
}

STATIC s32 sxe2_fwc_cmd_channel_handshake(struct sxe2_adapter *adapter,
					  enum sxe2_cmd_channel_type chnl_type)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_channel_handshake_req req = {};
	struct sxe2_channel_handshake_resp resp = {};

	req.drv_ver = cpu_to_le32(SXE2_FW_COMP_VER);
	req.drv_mode = SXE2_NIC_MODE_NORMAL;
	req.timestamp = cpu_to_le64(ktime_get_real_ns() / NS_TO_MS_UNIT);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_Q_HANDSHAKE, &req, sizeof(req),
				  &resp, sizeof(resp));
	cmd.is_interruptible = false;
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("cmd channel %d handshake failed: ret %d.\n", chnl_type,
			    ret);
		ret = -EIO;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_cmd_channel_close(struct sxe2_adapter *adapter,
				      enum sxe2_cmd_channel_type chnl_type)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_Q_DISABLE, NULL, 0, NULL, 0);
	cmd.is_interruptible = false;
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("cmd channel %d disable failed: ret %d.\n", chnl_type,
			      ret);
	return ret;
}

STATIC s32 sxe2_mbxc_cmd_channel_close(struct sxe2_adapter *adapter,
				       enum sxe2_cmd_channel_type chnl_type)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_fill(&cmd, SXE2_CMD_Q_DISABLE, NULL, 0, NULL, 0,
			     SXE2_DRV_CMD_DFLT_TIMEOUT, false, true);
	ret = sxe2_cmd_drv_exec(adapter, &cmd, SXE2_CMD_TYPE_DRV_TO_HW);
	if (ret)
		LOG_ERROR_BDF("cmd channel %d disable failed: ret %d.\n", chnl_type,
			      ret);
	return ret;
}

static s32 sxe2_fw_comp_version_check(struct sxe2_adapter *adapter)
{
	u32 fw_ver = 0;
	s32 ret = 0;

	fw_ver = sxe2_fw_comp_ver_get(&adapter->hw);
	if (fw_ver == SXE2_REG_INVALID_VALUE) {
		ret = -EIO;
		LOG_DEV_ERR("get fw comp ver fail\n");
		goto l_out;
	}

	adapter->fw_ver.major = SXE2_MK_VER_MAJOR(fw_ver);
	adapter->fw_ver.minor = SXE2_MK_VER_MINOR(fw_ver);

	if (adapter->fw_ver.major != SXE2_FW_COMP_MAJOR_VER) {
		ret = -EINVAL;
		LOG_DEV_ERR("unsupport fw version expected %d.%d received %d.%d\n",
			    SXE2_FW_COMP_MAJOR_VER, SXE2_FW_COMP_MINOR_VER,
			    adapter->fw_ver.major, adapter->fw_ver.minor);
	}
l_out:
	return ret;
}

STATIC s32 sxe2_cmd_channel_init(struct sxe2_adapter *adapter,
				 enum sxe2_cmd_channel_type chnl_type)
{
	s32 ret = 0;
	struct sxe2_cmd_channel *channel =
			SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, chnl_type);

	channel->chnl_type = chnl_type;

	mutex_lock(&channel->lock);
	if (channel->is_enable)
		goto l_end;

	ret = sxe2_cmd_queue_init(adapter, chnl_type, SXE2_CMD_TQ);
	if (ret)
		goto l_end;

	ret = sxe2_cmd_queue_init(adapter, chnl_type, SXE2_CMD_RQ);
	if (ret)
		goto l_rq_init_failed;

	if (chnl_type == SXE2_CHNL_FW) {
		ret = sxe2_fw_comp_version_check(adapter);
		if (ret)
			goto l_post_init_failed;

		ret = sxe2_fwc_cmd_channel_handshake(adapter, SXE2_CHNL_FW);
		if (ret)
			goto l_post_init_failed;
	}

	channel->is_enable = true;

	mutex_unlock(&channel->lock);
	return 0;

l_post_init_failed:
	sxe2_cmd_queue_deinit(adapter, chnl_type, SXE2_CMD_RQ);
l_rq_init_failed:
	sxe2_cmd_queue_deinit(adapter, chnl_type, SXE2_CMD_TQ);
l_end:
	mutex_unlock(&channel->lock);
	return ret;
}

STATIC void sxe2_msg_list_clean(struct sxe2_adapter *adapter)
{
	struct sxe2_cmd_channel_context *ctxt = &adapter->cmd_channel_ctxt;
	struct sxe2_recv_msg *msg;

	mutex_lock(&ctxt->lock);
	while (!list_empty(&ctxt->head)) {
		msg = list_first_entry(&ctxt->head, struct sxe2_recv_msg, node);
		list_del(&msg->node);
		kfree(msg);
	}
	mutex_unlock(&ctxt->lock);
}

STATIC void sxe2_cmd_channel_deinit(struct sxe2_adapter *adapter,
				    enum sxe2_cmd_channel_type chnl_type)
{
	struct sxe2_cmd_channel *channel =
			SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, chnl_type);
	s32 ret;

	mutex_lock(&channel->lock);
	if (!channel->is_enable) {
		mutex_unlock(&channel->lock);
		return;
	}

	channel->is_enable = false;
	if (chnl_type == SXE2_CHNL_FW) {
		ret = sxe2_fwc_cmd_channel_close(adapter, chnl_type);
	} else {
		ret = sxe2_mbxc_cmd_channel_close(adapter, chnl_type);
		if (ret && (ret != -EOWNERDEAD))
			sxe2_trigger_and_wait_resetting(adapter);
	}

	sxe2_cmd_queue_deinit(adapter, chnl_type, SXE2_CMD_RQ);
	sxe2_cmd_queue_deinit(adapter, chnl_type, SXE2_CMD_TQ);

	sxe2_wait_task_cancel(channel);
	mutex_unlock(&channel->lock);
}

s32 sxe2_cmd_channels_enable(struct sxe2_adapter *adapter)
{
	s32 ret;

	sxe2_cmd_work_init(adapter);

	ret = sxe2_cmd_channel_init(adapter, SXE2_CHNL_FW);
	if (ret) {
		LOG_DEV_ERR("sxe2_cmd_channel_init fw failed, ret=%d\n", ret);
		goto l_fw_chnl_init_failed;
	}
	ret = sxe2_cmd_channel_init(adapter, SXE2_CHNL_MBX);
	if (ret) {
		LOG_DEV_ERR("sxe2_cmd_channel_init mbx failed, ret=%d\n", ret);
		goto l_mbx_chnl_init_failed;
	}
	return 0;

l_mbx_chnl_init_failed:
	sxe2_cmd_channel_deinit(adapter, SXE2_CHNL_FW);

l_fw_chnl_init_failed:
	sxe2_cmd_work_exit(adapter);
	return ret;
}

s32 sxe2_cmd_channels_init(struct sxe2_adapter *adapter)
{
	s32 ret;

	sxe2_cmd_channel_init_once(adapter);

	ret = sxe2_cmd_channels_enable(adapter);
	if (ret)
		goto l_channels_enable_failed;
	return 0;
l_channels_enable_failed:
	sxe2_cmd_channel_deinit_once(adapter);

	return ret;
}

void sxe2_cmd_channels_disable(struct sxe2_adapter *adapter)
{
	sxe2_cmd_channel_deinit(adapter, SXE2_CHNL_MBX);
	sxe2_cmd_channel_deinit(adapter, SXE2_CHNL_FW);
	sxe2_cmd_work_exit(adapter);
	sxe2_msg_list_clean(adapter);
}

s32 sxe2_mbx_channel_enable(struct sxe2_adapter *adapter)
{
	return sxe2_cmd_channel_init(adapter, SXE2_CHNL_MBX);
}

STATIC void sxe2_mbx_msg_list_clean(struct sxe2_adapter *adapter)
{
	struct sxe2_cmd_channel_context *ctxt = &adapter->cmd_channel_ctxt;
	struct sxe2_recv_msg *msg, *msg_tmp;
	struct sxe2_cmd_hdr *cmd_hdr;

	mutex_lock(&ctxt->lock);
	list_for_each_entry_safe(msg, msg_tmp, &ctxt->head, node) {
		cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;
		if (cmd_hdr->cmd_type == SXE2_CMD_TYPE_VF_TO_PF) {
			list_del(&msg->node);
			kfree(msg);
		}
	}
	mutex_unlock(&ctxt->lock);
}

void sxe2_mbx_channel_disable(struct sxe2_adapter *adapter)
{
	sxe2_cmd_channel_deinit(adapter, SXE2_CHNL_MBX);

	sxe2_mbx_msg_list_clean(adapter);
}

void sxe2_cmd_channels_deinit(struct sxe2_adapter *adapter)
{
	sxe2_cmd_channels_disable(adapter);
	sxe2_cmd_channel_deinit_once(adapter);
}

static inline void sxe2_cmd_session_id_alloc(u64 *session_id)
{
	*session_id = (u64)atomic64_add_return(1, &g_cmd_session_id);
}

static s32 sxe2_queue_head_read(struct sxe2_adapter *adapter,
				struct sxe2_cmd_queue *queue, u16 *head)
{
	struct sxe2_hw *hw = &adapter->hw;
	u32 val = queue->ops.read_head(hw);

	if (val > queue->depth) {
		LOG_DEBUG_BDF("read_head invalid value %d.\n", val);
		return -EIO;
	}

	*head = (u16)val;
	return 0;
}

STATIC s32 sxe2_cmd_recv_packet_merge(struct sxe2_adapter *adapter,
				      struct sxe2_cmd_channel *channel,
				      struct sxe2_recv_msg *msg, bool *finish)
{
	s32 ret = 0;
	struct sxe2_cmd_queue *rq = &channel->queue[SXE2_CMD_RQ];
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;
	struct sxe2_recv_cache_buff *cache_buff = &rq->cache_buff;
	struct sxe2_cmd_hdr *last_hdr = (struct sxe2_cmd_hdr *)cache_buff->buf;
	u8 curr_multi_packet = cmd_hdr->multi_packet;
	u8 last_multi_packet = last_hdr->multi_packet;

	LOG_DEBUG_BDF("cache finish: %d offset: %d hdr.\n"
		      " cache trace: 0x%llx session: 0x%llx out_len:%d in_len:%d\t"
		      "mpacket:0x%x type:%d.\n"
		      " curr  trace: 0x%llx session: 0x%llx out_len:%d in_len:%d\t"
		      "mpacket:0x%x type:%d.\n",
		      cache_buff->finish, cache_buff->buf_offset, last_hdr->trace_id,
		      last_hdr->session_id, last_hdr->tran_out_len,
		      last_hdr->cur_in_len, last_multi_packet, last_hdr->cmd_type,
		      cmd_hdr->trace_id, cmd_hdr->session_id, cmd_hdr->tran_out_len,
		      cmd_hdr->cur_in_len, curr_multi_packet, cmd_hdr->cmd_type);

	if (curr_multi_packet & SXE2_CMD_HDR_MULTI_START) {
		if (last_multi_packet != 0 &&
		    !(last_multi_packet & SXE2_CMD_HDR_MULTI_END)) {
			LOG_ERROR_BDF("data lost trace:0x%llx session:0x%llx data len: %d\t"
				      "current session_id:0x%llx.\n",
				      last_hdr->trace_id, last_hdr->session_id,
				      cache_buff->buf_offset, cmd_hdr->session_id);
		}

		memset(cache_buff->buf, 0, rq->buf_size);
		cache_buff->buf_offset = 0;
	} else {
		if (last_hdr->session_id != cmd_hdr->session_id) {
			LOG_ERROR_BDF("last session_id: 0x%llx current session_id:0x%llx.\n",
				      last_hdr->session_id, cmd_hdr->session_id);
			ret = -EBADSLT;
			goto l_mulit_packet;
		}
		if (((last_multi_packet & SXE2_CMD_HDR_MULTI_CMD_ID_MASK) + 1) !=
		    (curr_multi_packet & SXE2_CMD_HDR_MULTI_CMD_ID_MASK)) {
			LOG_ERROR_BDF("last No: %d current No:%d.\n",
				      (last_multi_packet &
				       SXE2_CMD_HDR_MULTI_CMD_ID_MASK),
				      curr_multi_packet &
						      SXE2_CMD_HDR_MULTI_CMD_ID_MASK);
			ret = -EBADRQC;
			goto l_mulit_packet;
		}
	}
	memcpy(last_hdr, cmd_hdr, cmd_hdr->hdr_len);

	if (!((curr_multi_packet & SXE2_CMD_HDR_MULTI_START) &&
	      (curr_multi_packet & SXE2_CMD_HDR_MULTI_END))) {
		last_hdr->multi_packet = curr_multi_packet;
		if ((cache_buff->buf_offset + cmd_hdr->cur_in_len) > rq->buf_size) {
			LOG_ERROR_BDF("Buffer overflow: current_len(%d) +\t"
				      "recv_len(%d) > buffer_size(%d).\n",
				      cmd_hdr->cur_in_len, cache_buff->buf_offset,
				      rq->buf_size);
			ret = -ENOMSG;
			goto l_mulit_packet;
		}
		memcpy(((u8 *)last_hdr + last_hdr->hdr_len) + cache_buff->buf_offset,
		       ((u8 *)cmd_hdr + cmd_hdr->hdr_len), cmd_hdr->cur_in_len);
		cache_buff->buf_offset += cmd_hdr->cur_in_len;
		if (curr_multi_packet & SXE2_CMD_HDR_MULTI_END) {
			memcpy(&msg->buf[cmd_hdr->hdr_len],
			       ((u8 *)last_hdr + last_hdr->hdr_len),
			       cache_buff->buf_offset);
			msg->buf_len = cache_buff->buf_offset + cmd_hdr->hdr_len;
			cache_buff->finish = true;
		} else {
			cache_buff->finish = false;
		}
	} else {
		cache_buff->finish = true;
	}

l_end:
	*finish = cache_buff->finish;
	return ret;
l_mulit_packet:
	last_hdr->session_id = 0;
	cache_buff->finish = true;
	goto l_end;
}

STATIC u8 sxe2_xor8_checksum_get(u8 *buf, u32 len)
{
	u32 i = 0;
	u8 sum = 0;

	for (i = 0; i < len; i++)
		sum ^= buf[i];
	return sum;
}

STATIC s32 sxe2_cmd_recv_single(struct sxe2_adapter *adapter,
				struct sxe2_cmd_channel *channel,
				struct sxe2_recv_msg *msg)
{
	s32 ret = 0;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_cmd_queue *rq = &channel->queue[SXE2_CMD_RQ];
	struct sxe2_cmd_desc *desc;
	u16 data_len;
	void *buf;
	u8 checksum_recv = 0;
	u8 checksum_calc = 0;

	desc = SXE2_CMD_QUEUE_DESC(rq, rq->ntc);
	buf = SXE2_CMD_QUEUE_BUF(rq, rq->ntc);

	if (!(desc->flags & SXE2_CMD_DONE)) {
		ret = -ENODATA;
		goto l_end;
	}

	LOG_DEBUG_BDF("rq get the #%dth desc\n", rq->ntc);
	DATA_DUMP(desc, sizeof(*desc), "rq cmd desc");

	if (le16_to_cpu(desc->ret)) {
		LOG_ERROR_BDF("rq recv msg failed, ret: %d.\n",
			      le16_to_cpu(desc->ret));
		ret = -EIO;
		goto l_ntc_inc;
	}

	data_len = le16_to_cpu(desc->data_len);
	if (data_len > rq->buf_size) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rq recv msg failed, data_len: %d invalid.\n",
			      data_len);
		goto l_ntc_inc;
	}

	if (channel->chnl_type == SXE2_CHNL_FW) {
		checksum_calc = sxe2_xor8_checksum_get(buf, data_len);
		checksum_recv = desc->checksum;
		if (checksum_calc != checksum_recv) {
			ret = -EINVAL;
			LOG_ERROR_BDF("rq recv msg failed, checksum resv:%d not eq calc:%d.\n",
				      checksum_recv, checksum_calc);
			goto l_ntc_inc;
		}
	}

	DATA_DUMP(buf, data_len, "rq cmd buff");
	memcpy(&msg->desc, desc, sizeof(msg->desc));
	if (data_len) {
		memcpy(msg->buf, buf, data_len);
		msg->buf_len = data_len;
	}

	sxe2_cmd_rq_desc_fill(channel->chnl_type, rq, rq->ntc);
	rq->ops.write_tail(hw, rq->ntc);

l_ntc_inc:
	SXE2_QUEUE_IDX_INC(rq->ntc, rq->depth);

l_end:
	return ret;
}

STATIC s32 sxe2_cmd_recv(struct sxe2_adapter *adapter,
			 struct sxe2_cmd_channel *channel, struct sxe2_recv_msg *msg)
{
	s32 ret = 0;
	struct sxe2_cmd_queue *rq = &channel->queue[SXE2_CMD_RQ];
	unsigned long expired_time =
			jiffies + secs_to_jiffies(SXE2_CMD_RECV_MULIT_DFLT_TIMEOUT);
	bool finish = true;
	u16 index = 0;

	mutex_lock(&rq->lock);

	if (!rq->is_enable) {
		ret = -ENODATA;
		goto l_end;
	}

	do {
		ret = sxe2_cmd_recv_single(adapter, channel, msg);
		if (ret) {
			if (index == 0 || (-ENODATA != ret)) {
				goto l_end;
			} else {
				if (!time_before(jiffies, expired_time)) {
					LOG_ERROR_BDF("pack recv time out buf_len: %d\t"
						      "data_len: %d opcode: %d invalid.\n",
						      msg->buf_len,
						      msg->desc.data_len,
						      msg->desc.opcode);
					ret = -ETIMEDOUT;
					break;
				}
				udelay(SXE2_CMD_CHNL_RECV_MULIT_PACK_INTERVAL);
				continue;
			}
		}
		ret = sxe2_cmd_recv_packet_merge(adapter, channel, msg, &finish);
		if (ret != 0) {
			LOG_ERROR_BDF("rq recv msg mulit packet, buf_len: %d\t"
				      "data_len: %d opcode: %d invalid.\n",
				      msg->buf_len, msg->desc.data_len,
				      msg->desc.opcode);
			break;
		}
		index++;
	} while (!finish);

l_end:
	mutex_unlock(&rq->lock);
	return ret;
}

STATIC void sxe2_cmd_event_handler(struct sxe2_adapter *adapter,
				   struct sxe2_recv_msg *msg)
{
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;
	struct sxe2_drv_msg_hdr *msg_hdr = SXE2_DRV_MSG_HDR_PTR(cmd_hdr);
	u16 event_code = (u16)le32_to_cpu(msg_hdr->op_code);
	s32 ret;

	ret = (s32)le32_to_cpu(msg_hdr->err_code);
	if (ret < 0) {
		LOG_ERROR_BDF("event code %d report failed: %d.\n", event_code, ret);
		return;
	}

	ret = sxe2_event_handle(adapter, event_code, SXE2_MSG_BODY(msg_hdr),
				le32_to_cpu(msg_hdr->data_len));
	if (ret)
		LOG_ERROR_BDF("event code %d handler failed: %d.\n", event_code,
			      ret);

	LOG_DEBUG_BDF("event code %d receive, result: %d.\n", event_code, ret);
}

STATIC void sxe2_cmd_rsp_handler(struct sxe2_adapter *adapter,
				 struct sxe2_cmd_channel *channel,
				 struct sxe2_recv_msg *msg)
{
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;
	struct sxe2_cmd_wait_task *cmd_wait_elem;
	bool found = false;
	unsigned long flags = 0;

	spin_lock_irqsave(&channel->wq.lock, flags);
	hash_for_each_possible(channel->wq.table, cmd_wait_elem, entry,
			       le64_to_cpu(cmd_hdr->session_id)) {
		if (cmd_wait_elem->state != SXE2_CMD_STATE_WAITING ||
		    le64_to_cpu(cmd_hdr->session_id) != cmd_wait_elem->session_id) {
			continue;
		}

		found = true;

		SXE2_BUG_ON(msg->buf_len > cmd_wait_elem->resp_len);
		if (msg->buf_len > cmd_wait_elem->resp_len) {
			LOG_ERROR_BDF("msg->buf_len %d more than out_len %d.\n",
				      msg->buf_len, cmd_wait_elem->resp_len);
			cmd_wait_elem->state = SXE2_CMD_STATE_FAULT;
			break;
		}
		memcpy(cmd_wait_elem->resp_data, msg->buf, msg->buf_len);

		cmd_wait_elem->state = SXE2_CMD_STATE_DONE;
	}
	spin_unlock_irqrestore(&channel->wq.lock, flags);

	if (found)
		wake_up(&channel->wq.wq);
}

STATIC s32 sxe2_recv_msg_check(struct sxe2_adapter *adapter,
			       struct sxe2_recv_msg *msg)
{
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;
	struct sxe2_drv_msg_hdr *msg_hdr;
	u32 hdr_len = 0;

	msg_hdr = (struct sxe2_drv_msg_hdr *)((u8 *)cmd_hdr + cmd_hdr->hdr_len);

	if (cmd_hdr->cmd_type == SXE2_CMD_TYPE_CLI)
		hdr_len = cmd_hdr->hdr_len;
	else
		hdr_len = cmd_hdr->hdr_len + msg_hdr->data_offset;

	if (msg->buf_len < hdr_len) {
		LOG_ERROR_BDF("recv cmd type %d, buf len %d hdr len :%u invalid.\n",
			      cmd_hdr->cmd_type, msg->buf_len, hdr_len);
		return -EINVAL;
	}

	if (le32_to_cpu(cmd_hdr->magic_code) != SXE2_CMD_MAGIC) {
		LOG_ERROR_BDF("recv cmd magic check failed.\n");
		return -EINVAL;
	}

	if (cmd_hdr->cmd_type != SXE2_CMD_TYPE_CLI) {
		if ((u8 *)SXE2_MSG_BODY(msg_hdr) + msg_hdr->data_len >
		    msg->buf + msg->buf_len) {
			LOG_ERROR_BDF("msg hdr buf len %d invalid.\n",
				      msg_hdr->data_len);
			return -EINVAL;
		}
	}
	return 0;
}

STATIC void sxe2_msg_handle_async(struct sxe2_adapter *adapter,
				  struct sxe2_recv_msg *msg)
{
	struct sxe2_recv_msg *tmp_msg;
	u32 len = sizeof(*tmp_msg) + msg->buf_len;

	tmp_msg = kzalloc(len, GFP_KERNEL);
	if (!tmp_msg) {
		LOG_DEV_ERR("malloc failed, size: %u.\n", len);
		return;
	}
	memcpy(tmp_msg, msg, len);
	INIT_LIST_HEAD(&tmp_msg->node);

	sxe2_msg_list_add(adapter, tmp_msg);
	sxe2_msg_handle_work_schedule(adapter);
}

STATIC void sxe2_cmd_rq_handle(struct sxe2_adapter *adapter,
			       struct sxe2_cmd_channel *channel,
			       struct sxe2_recv_msg *msg)
{
	s32 ret;
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;

	ret = sxe2_recv_msg_check(adapter, msg);
	if (ret)
		goto l_end;

	ret = (s32)le32_to_cpu(cmd_hdr->ret);
	if (ret < 0) {
		LOG_ERROR_BDF("recv cmd failed, ret: %d.\n", ret);
		goto l_end;
	}

	switch (cmd_hdr->cmd_type) {
	case SXE2_CMD_TYPE_FW_NOTIFY:
	case SXE2_CMD_TYPE_VF_TO_PF:
		sxe2_msg_handle_async(adapter, msg);
		break;
	case SXE2_CMD_TYPE_CLI:
	case SXE2_CMD_TYPE_DRV_TO_FW:
		sxe2_cmd_rsp_handler(adapter, channel, msg);
		break;
	default:
		LOG_ERROR_BDF("unknown cmd type: %d.\n", cmd_hdr->cmd_type);
		SXE2_BUG();
		break;
	}

l_end:
	return;
}

STATIC bool sxe2_cmd_rq_clean(struct sxe2_adapter *adapter,
			      enum sxe2_cmd_channel_type chnl_type)
{
	s32 ret = 0;
	struct sxe2_cmd_channel *channel =
			SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, chnl_type);
	struct sxe2_cmd_queue *rq = &channel->queue[SXE2_CMD_RQ];
	struct sxe2_recv_msg *msg;
	u16 cleaned = 0;

	msg = kzalloc(sizeof(*msg) + rq->buf_size, GFP_KERNEL);
	if (!msg) {
		LOG_ERROR_BDF("malloc failed, size: %zu.\n",
			      sizeof(*msg) + rq->buf_size);
		ret = -ENOMEM;
		goto l_end;
	}

	do {
		ret = sxe2_cmd_recv(adapter, channel, msg);
		if (ret == -ENODATA) {
			ret = 0;
			break;
		}
		if (ret == 0)
			sxe2_cmd_rq_handle(adapter, channel, msg);

		cleaned++;
	} while (cleaned < SXE2_CMD_RQ_WEIGHT);

	kfree(msg);
l_end:
	return !!ret || (cleaned == SXE2_CMD_RQ_WEIGHT);
}

STATIC void sxe2_cmd_queue_check_hw_error(struct sxe2_adapter *adapter,
					  enum sxe2_cmd_channel_type chnl_type,
					  enum sxe2_cmd_queue_type q_type)
{
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_cmd_queue *queue =
			SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, q_type);
	u32 hw_err;

	if (chnl_type == SXE2_CHNL_MBX)
		goto l_out;

	hw_err = queue->ops.get_error(hw);

	if (hw_err & SXE2_CMD_REG_LEN_CRIT_M)
		LOG_DEV_ERR("cmd channel %d queue %d critical error detected.\n",
			    chnl_type, q_type);
	if (hw_err & SXE2_CMD_REG_LEN_VFE_M)
		LOG_DEV_ERR("cmd channel %d queue %d VF error detected.\n",
			    chnl_type, q_type);

l_out:
	return;
}

bool sxe2_cmd_channel_work(struct sxe2_adapter *adapter,
			   enum sxe2_cmd_channel_type chnl_type)
{
	return sxe2_cmd_rq_clean(adapter, chnl_type);
}

void sxe2_cmd_params_fill(struct sxe2_cmd_params *cmd, enum sxe2_drv_cmd_opcode opc,
			  void *req_data, u32 req_len, void *resp_data, u32 resp_len,
			  u32 timeout, bool is_interruptible, bool no_resp)
{
	cmd->opcode = opc;
	cmd->req_data = req_data;
	cmd->req_len = (u16)req_len;
	cmd->resp_data = resp_data;
	cmd->resp_len = (u16)resp_len;
	cmd->is_interruptible = (u8)is_interruptible;
	cmd->timeout = timeout;
	cmd->no_resp = (u8)no_resp;

	sxe2_trace_id_alloc(&cmd->trace_id);
}

void sxe2_cmd_params_dflt_fill(struct sxe2_cmd_params *cmd,
			       enum sxe2_drv_cmd_opcode opc, void *in_data,
			       u32 in_len, void *out_data, u32 out_len)
{
	sxe2_cmd_params_fill(cmd, opc, in_data, in_len, out_data, out_len,
			     SXE2_DRV_CMD_DFLT_TIMEOUT, false, false);
}

void sxe2_cmd_params_no_interruptible_fill(struct sxe2_cmd_params *cmd,
					   enum sxe2_drv_cmd_opcode opc,
					   void *req_data, u32 req_len,
					   void *resp_data, u32 resp_len)
{
	cmd->opcode = opc;
	cmd->req_data = req_data;
	cmd->req_len = (u16)req_len;
	cmd->resp_data = resp_data;
	cmd->resp_len = (u16)resp_len;
	cmd->is_interruptible = false;
	cmd->timeout = SXE2_DRV_CMD_DFLT_TIMEOUT;
	cmd->no_resp = false;

	sxe2_trace_id_alloc(&cmd->trace_id);
}

STATIC void sxe2_cmd_trans(struct sxe2_cmd_params *cmd_params,
			   struct sxe2_cmd_hdr *cmd_hdr, enum sxe2_cmd_type type,
			   u64 session_id)
{
	cmd_hdr->magic_code = cpu_to_le32(SXE2_CMD_MAGIC);
	cmd_hdr->timeout = cpu_to_le32(cmd_params->timeout);
	cmd_hdr->trace_id = cpu_to_le64(cmd_params->trace_id);
	cmd_hdr->session_id = cpu_to_le64(session_id);
	SXE2_CMD_REQ_LEN(cmd_hdr) = cpu_to_le16(cmd_params->req_len);
	SXE2_CMD_RESP_LEN(cmd_hdr) = cpu_to_le16(cmd_params->resp_len);
	cmd_hdr->hdr_len = cpu_to_le16((u16)sizeof(*cmd_hdr));
	cmd_hdr->cmd_type = type;
	cmd_hdr->no_resp = (u8)cmd_params->no_resp;
	cmd_hdr->cur_in_len = cpu_to_le16(cmd_params->req_len);
	cmd_hdr->multi_packet = SXE2_CMD_HDR_MULTI_END | SXE2_CMD_HDR_MULTI_START |
				(0 & SXE2_CMD_HDR_MULTI_CMD_ID_MASK);
}

STATIC void sxe2_cmd_wait_list_fill(struct sxe2_cmd_context *cmd_ctxt)
{
	struct sxe2_cmd_wait_task *wait_task = &cmd_ctxt->wait_task;

	wait_task->session_id = cmd_ctxt->session_id;
	wait_task->state = SXE2_CMD_STATE_WAITING;
	wait_task->resp_len = cmd_ctxt->trans_info.resp_len;
	wait_task->resp_data = cmd_ctxt->trans_info.resp_buff;
}

STATIC void sxe2_cmd_wait_list_add(struct sxe2_cmd_context *cmd_ctxt)
{
	unsigned long flags;
	struct sxe2_cmd_wait_task *wait_task = &cmd_ctxt->wait_task;
	struct sxe2_cmd_channel *channel =
		SXE2_ADAPTER_TO_CMD_CHANNEL(cmd_ctxt->adapter, cmd_ctxt->chnl_type);

	spin_lock_irqsave(&channel->wq.lock, flags);
	hash_add(channel->wq.table, &wait_task->entry, wait_task->session_id);
	spin_unlock_irqrestore(&channel->wq.lock, flags);
}

STATIC void sxe2_cmd_wait_list_del(struct sxe2_cmd_context *cmd_ctxt)
{
	unsigned long flags;
	struct sxe2_cmd_channel *channel =
		SXE2_ADAPTER_TO_CMD_CHANNEL(cmd_ctxt->adapter, cmd_ctxt->chnl_type);

	spin_lock_irqsave(&channel->wq.lock, flags);
	hash_del(&cmd_ctxt->wait_task.entry);
	spin_unlock_irqrestore(&channel->wq.lock, flags);
}

STATIC s32 sxe2_cmd_check(struct sxe2_cmd_params *cmd_params,
			  enum sxe2_cmd_type type)
{
	s32 ret = 0;
	u16 req_len = cmd_params->req_len;
	u16 resp_len = cmd_params->resp_len;

	if (type != SXE2_CMD_TYPE_CLI && type != SXE2_CMD_TYPE_DRV_TO_FW &&
	    type != SXE2_CMD_TYPE_PF_TO_VF && type != SXE2_CMD_TYPE_PF_REPLY_VF &&
	    type != SXE2_CMD_TYPE_DRV_TO_HW) {
		ret = -EINVAL;
		goto l_end;
	}

	if ((!req_len && cmd_params->req_data) ||
	    (req_len && !cmd_params->req_data) ||
	    (!resp_len && cmd_params->resp_data) ||
	    (resp_len && !cmd_params->resp_data)) {
		ret = -EINVAL;
		goto l_end;
	}

	if (type == SXE2_CMD_TYPE_CLI || type == SXE2_CMD_TYPE_DRV_TO_FW) {
		if (req_len >= SXE2_CMD_MAX_TRANSMIT_DATA_SIZE ||
		    resp_len >= SXE2_CMD_MAX_TRANSMIT_DATA_SIZE) {
			ret = -EINVAL;
			goto l_end;
		}
	}

	if (type == SXE2_CMD_TYPE_PF_TO_VF || type == SXE2_CMD_TYPE_PF_REPLY_VF) {
		if (req_len >= SXE2_CMD_MAX_TRANSMIT_DATA_SIZE_MBX ||
		    resp_len >= SXE2_CMD_MAX_TRANSMIT_DATA_SIZE_MBX) {
			ret = -EINVAL;
			goto l_end;
		}
	}

l_end:
	return ret;
}

STATIC void sxe2_cmd_context_fill(struct sxe2_adapter *adapter,
				  struct sxe2_cmd_params *cmd_params,
				  enum sxe2_cmd_type type,
				  struct sxe2_cmd_context *cmd_ctxt)
{
	u32 timeout = cmd_params->timeout ? cmd_params->timeout
					  : SXE2_DRV_CMD_DFLT_TIMEOUT;

	cmd_ctxt->adapter = adapter;
	cmd_ctxt->type = type;

	cmd_ctxt->expired_time = jiffies + secs_to_jiffies(timeout);

	sxe2_cmd_session_id_alloc(&cmd_ctxt->session_id);
	cmd_ctxt->params = cmd_params;

	switch (type) {
	case SXE2_CMD_TYPE_CLI:
	case SXE2_CMD_TYPE_DRV_TO_FW:
		cmd_ctxt->chnl_type = SXE2_CHNL_FW;
		break;
	case SXE2_CMD_TYPE_PF_TO_VF:
	case SXE2_CMD_TYPE_DRV_TO_HW:
		cmd_ctxt->chnl_type = SXE2_CHNL_MBX;
		break;
	case SXE2_CMD_TYPE_PF_REPLY_VF:
		cmd_ctxt->chnl_type = SXE2_CHNL_MBX;
		cmd_ctxt->session_id = cmd_params->session_id;
		break;
	default:
		LOG_ERROR_BDF("unknown cmd type: %d.\n", type);
		break;
	}
}

STATIC s32 sxe2_cmd_add_hdr(struct sxe2_cmd_context *cmd_ctxt)
{
	s32 ret = 0;
	struct sxe2_cmd_hdr *cmd_hdr;
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	struct sxe2_cmd_trans_info *trans_info =
			&cmd_ctxt->trans_info;
	struct sxe2_cmd_params *params = cmd_ctxt->params;
	u64 trace_id = cmd_ctxt->params->trace_id;

#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif
	trans_info->req_len = params->req_len + SXE2_CMD_HDR_SIZE;
	trans_info->resp_len = params->resp_len + SXE2_CMD_HDR_SIZE;

	trans_info->req_buff = kzalloc(cmd_ctxt->trans_info.req_len, GFP_KERNEL);
	if (!trans_info->req_buff) {
		ret = -ENOMEM;
		trans_info->req_len = 0;
		LOG_ERROR_TRACEID("malloc failed: size %u.\n", trans_info->req_len);
		goto l_end;
	}
	cmd_hdr = trans_info->req_buff;

	sxe2_cmd_trans(params, cmd_hdr, cmd_ctxt->type, cmd_ctxt->session_id);

	if (params->req_len) {
		if (cmd_ctxt->type ==
		    SXE2_CMD_TYPE_CLI) {
			if (copy_from_user(cmd_hdr->body,
					   (void __user *)params->req_data,
					   params->req_len)) {
				LOG_ERROR_TRACEID("cmd trace_id=0x%llx copy from user \t"
						  "err\n",
						  cmd_ctxt->params->trace_id);
				ret = -EFAULT;
				goto l_copy_failed;
			}
		} else {
			memcpy(cmd_hdr->body, params->req_data, params->req_len);
		}
	}

	trans_info->resp_buff = kzalloc(trans_info->resp_len, GFP_KERNEL);
	if (!trans_info->resp_buff) {
		ret = -ENOMEM;
		trans_info->resp_len = 0;
		LOG_ERROR_TRACEID("malloc failed: size %u.\n", trans_info->resp_len);
		goto l_copy_failed;
	}
	return 0;

l_copy_failed:
	kfree(trans_info->req_buff);
	trans_info->req_buff = NULL;
	trans_info->req_len = 0;
l_end:
	return ret;
}

s32 sxe2_cmd_strip_hdr(struct sxe2_cmd_context *cmd_ctxt)
{
	s32 ret = 0;
	struct sxe2_cmd_hdr *cmd_hdr;
	struct sxe2_cmd_trans_info *trans_info = &cmd_ctxt->trans_info;
	struct sxe2_cmd_params *params = cmd_ctxt->params;
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	u64 trace_id = cmd_ctxt->params->trace_id;

#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif

	kfree(trans_info->req_buff);
	trans_info->req_buff = NULL;
	trans_info->req_len = 0;

	if (trans_info->resp_buff) {
		cmd_hdr = trans_info->resp_buff;
		if (params->resp_len) {
			if (cmd_ctxt->type ==
			    SXE2_CMD_TYPE_CLI) {
				if (copy_to_user((void __user *)params->resp_data,
						 ((u8 *)cmd_hdr + cmd_hdr->hdr_len),
						 params->resp_len)) {
					LOG_ERROR_TRACEID("cmd trace_id=0x%llx copy to user err\n",
							  cmd_ctxt->params->trace_id);
					ret = -EFAULT;
				}
			} else {
				memcpy(params->resp_data,
				       ((u8 *)cmd_hdr + cmd_hdr->hdr_len),
				       params->resp_len);
			}
		}
		kfree(trans_info->resp_buff);
		trans_info->resp_buff = NULL;
		trans_info->resp_len = 0;
	}

	return ret;
}

STATIC s32 sxe2_cmd_check_and_fill(struct sxe2_adapter *adapter,
				   struct sxe2_cmd_params *cmd_params,
				   enum sxe2_cmd_type type,
				   struct sxe2_cmd_context *cmd_ctxt)
{
	s32 ret;
#ifndef SXE2_TEST
	u64 trace_id = cmd_params->trace_id;
#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif
#endif

	ret = sxe2_cmd_check(cmd_params, type);
	if (ret)
		goto l_end;

	sxe2_cmd_context_fill(adapter, cmd_params, type, cmd_ctxt);

l_end:
#ifndef SXE2_TEST
	LOG_INFO_TRACEID("send cmd: cmd_type:%d, session_id:0x%llx,\t"
			 "trace_id:0x%llx, is_interruptible:%d\n"
			 "timeout:%d, opcode:0x%x req_len:%d, out_len:%d, ret:%d.\n",
			 cmd_ctxt->type, cmd_ctxt->session_id, cmd_params->trace_id,
			 cmd_params->is_interruptible, cmd_params->timeout,
			 cmd_params->opcode, cmd_params->req_len,
			 cmd_params->resp_len, ret);
#endif
	return ret;
}

STATIC void sxe2_cmd_tq_desc_fill(struct sxe2_cmd_context *cmd_ctxt,
				  struct sxe2_cmd_desc *desc)
{
	switch (cmd_ctxt->type) {
	case SXE2_CMD_TYPE_PF_TO_VF:
	case SXE2_CMD_TYPE_PF_REPLY_VF:
		desc->opcode = cpu_to_le16(SXE2_CMD_MBX_TO_VF);
		desc->custom2 = cpu_to_le32(cmd_ctxt->params->vf_idx);
		break;
	case SXE2_CMD_TYPE_VF_TO_PF:
		desc->opcode = cpu_to_le16(SXE2_CMD_MBX_TO_PF);
		break;
	case SXE2_CMD_TYPE_DRV_TO_HW:
	default:
		desc->opcode = cpu_to_le16((u16)cmd_ctxt->params->opcode);
		break;
	}

	desc->data_len = cpu_to_le16(cmd_ctxt->trans_info.req_len);

	desc->flags |= cpu_to_le16(SXE2_CMD_NO_INTR);
	if (cmd_ctxt->trans_info.req_len) {
		desc->flags |= cpu_to_le16(SXE2_CMD_BUF);
		desc->flags |= cpu_to_le16(SXE2_CMD_READ);
		if (cmd_ctxt->trans_info.req_len > SXE2_CMD_LARGE_BUF_SIZE)
			desc->flags |= cpu_to_le16(SXE2_CMD_LARGE_BUF);
	}
}

STATIC bool sxe2_cmd_tq_pending(struct sxe2_adapter *adapter,
				struct sxe2_cmd_queue *queue)
{
	u16 val;

	if (sxe2_queue_head_read(adapter, queue, &val))
		return false;

	return queue->ntc != val;
}

STATIC u16 sxe2_cmd_tq_put_desc(struct sxe2_adapter *adapter,
				struct sxe2_cmd_queue *tq)
{
	struct sxe2_cmd_desc *desc;
	struct sxe2_dma_mem *buf_dma;

	while (sxe2_cmd_tq_pending(adapter, tq)) {
		desc = SXE2_CMD_QUEUE_DESC(tq, tq->ntc);
		buf_dma = &tq->buf[tq->ntc];

		memset(desc, 0, sizeof(*desc));
		memset(buf_dma->va, 0, sizeof(buf_dma->size));
		SXE2_QUEUE_IDX_INC(tq->ntc, tq->depth);
	}

	return SXE2_CMD_QUEUE_DESC_UNUSED(tq);
}

STATIC void sxe2_cmd_tq_get_desc(struct sxe2_cmd_context *cmd_ctxt,
				 struct sxe2_cmd_desc **desc)
{
	struct sxe2_cmd_queue *tq =
		SXE2_ADAPTER_TO_CMD_QUEUE(cmd_ctxt->adapter,
					  cmd_ctxt->chnl_type,
					  SXE2_CMD_TQ);
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	struct sxe2_dma_mem *buf_dma;
	void *buf;
	u64 trace_id = cmd_ctxt->params->trace_id;
#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif

	LOG_DEBUG_TRACEID("tq get the #%dth desc\n", tq->ntu);

	*desc = SXE2_CMD_QUEUE_DESC(tq, tq->ntu);
	buf_dma = &tq->buf[tq->ntu];
	buf = buf_dma->va;
	SXE2_QUEUE_IDX_INC(tq->ntu, tq->depth);

	sxe2_cmd_tq_desc_fill(cmd_ctxt, *desc);

	if (cmd_ctxt->trans_info.req_buff) {
		memcpy(buf, cmd_ctxt->trans_info.req_buff,
		       cmd_ctxt->trans_info.req_len);
		(*desc)->buf_addr_h = cpu_to_le32(upper_32_bits(buf_dma->pa));
		(*desc)->buf_addr_l = cpu_to_le32(lower_32_bits(buf_dma->pa));
		if (cmd_ctxt->chnl_type == SXE2_CHNL_FW)
			(*desc)->checksum =
			sxe2_xor8_checksum_get(buf,
					       cmd_ctxt->trans_info.req_len);
	}
}

STATIC s32 sxe2_cmd_wait_desc_wb(struct sxe2_cmd_context *cmd_ctxt,
				 struct sxe2_cmd_desc *desc)
{
	s32 ret = 0;
	unsigned long expired_time = cmd_ctxt->expired_time;
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	u64 trace_id = cmd_ctxt->params->trace_id;
	unsigned long time_out = 0;

#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif

	udelay(6);

	time_out = (unsigned long)(jiffies +
				   secs_to_jiffies(SXE2_CMD_TQ_WB_DFLT_TIMEOUT));
	expired_time = min(expired_time, time_out);
	do {
		if (SXE2_WB_DONE(desc))
			break;
		if (cmd_ctxt->params->is_interruptible) {
			if (msleep_interruptible(SXE2_CMD_WB_WAIT_INTERVAL) &&
			    signal_pending_is_interrupt()) {
				ret = -ECANCELED;
				LOG_DEV_INFO("[trace id 0x%llx] cmd interrupted,\t"
					     "exit polling\n",
					     trace_id);
				goto l_end;
			}
		} else {
			usleep_range(SXE2_WAIT_DONE_MIN, SXE2_WAIT_DONE_MAX);
		}
	} while (time_before(jiffies, expired_time));

	if (!SXE2_WB_DONE(desc)) {
		ret = -ETIMEDOUT;
		sxe2_cmd_queue_check_hw_error(adapter, cmd_ctxt->chnl_type,
					      SXE2_CMD_TQ);
		LOG_DEBUG_TRACEID("send cmd timeout, opcode: 0x%x, ret: %d.\n",
				  cmd_ctxt->params->opcode, ret);
	}

l_end:
	return ret;
}

STATIC s32 sxe2_cmd_desc_err_trans(struct sxe2_cmd_context *cmd_ctxt,
				   struct sxe2_cmd_desc *desc)
{
	s32 ret;
	u16 desc_ret = le16_to_cpu(desc->ret);
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	u64 trace_id = cmd_ctxt->params->trace_id;

#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif

	if (desc_ret) {
		LOG_ERROR_TRACEID("send cmd failed, channel: %d, opcode: 0x%x, ret: %u.\n",
				  cmd_ctxt->chnl_type, cmd_ctxt->params->opcode,
				  desc_ret);
	}

	switch (desc_ret) {
	case 0:
		ret = 0;
		break;
	case SXE2_CMD_DESC_ERR_DES_ERR:
	case SXE2_CMD_DESC_ERR_BUF_ERR:
	case SXE2_CMD_DESC_ERR_BUF_NUM_ERR:
	case SXE2_CMD_DESC_ERR_SRC_BUSY:
		ret = -EAGAIN;
		break;
	default:
		ret = -EIO;
		break;
	}

	return ret;
}

STATIC s32 sxe2_cmd_send_single(struct sxe2_cmd_context *cmd_ctxt)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_cmd_queue *tq =
		SXE2_ADAPTER_TO_CMD_QUEUE(cmd_ctxt->adapter,
					  cmd_ctxt->chnl_type,
					  SXE2_CMD_TQ);
	struct sxe2_cmd_desc *desc = NULL;
	u16 head;
	u64 trace_id = cmd_ctxt->params->trace_id;

#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif

	if (!tq->is_enable) {
		ret = -EBUSY;
		goto l_end;
	}

	if (sxe2_queue_head_read(adapter, tq, &head)) {
		ret = -EIO;
		goto l_end;
	}

	if (sxe2_cmd_tq_put_desc(adapter, tq) == 0) {
		LOG_DEV_ERR("cmd queue is full, head: %d, ntc: %d.\n", head,
			    tq->ntc);
		ret = -EAGAIN;
		LOG_ERROR_TRACEID("cmd queue full, head: %d.\n", head);
		goto l_end;
	}

	sxe2_cmd_tq_get_desc(cmd_ctxt, &desc);

	DATA_DUMP(desc, sizeof(*desc), "tq cmd desc before");
	DATA_DUMP(cmd_ctxt->trans_info.req_buff, cmd_ctxt->trans_info.req_len,
		  "tq cmd buff");

	tq->ops.write_tail(hw, tq->ntu);
	sxe2_flush(hw);

	ret = sxe2_cmd_wait_desc_wb(cmd_ctxt, desc);
	if (ret)
		goto l_end;

	ret = sxe2_cmd_desc_err_trans(cmd_ctxt, desc);

l_end:
	if (desc)
		DATA_DUMP(desc, sizeof(*desc), "tq cmd desc after");
	return ret;
}

STATIC s32 sxe2_cmd_send(struct sxe2_cmd_context *cmd_ctxt)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	struct sxe2_cmd_queue *tq =
		SXE2_ADAPTER_TO_CMD_QUEUE(cmd_ctxt->adapter,
					  cmd_ctxt->chnl_type,
					  SXE2_CMD_TQ);
	u16 trans_in_len = 0;
	u16 current_offset = SXE2_CMD_HDR_SIZE;
	u8 multi_packet = 0;
	u8 packet_total_num = 1;
	u8 packet_index = 0;
	u16 retry_cnt = 0;
	struct sxe2_cmd_trans_info *trans_info = &cmd_ctxt->trans_info;
	struct sxe2_cmd_hdr *cmd_hdr = trans_info->req_buff;

	trans_in_len = trans_info->req_len;

	if (cmd_ctxt->chnl_type == SXE2_CHNL_FW)
		packet_total_num = (u8)DIV_ROUND_UP(trans_in_len - SXE2_CMD_HDR_SIZE,
						    SXE2_CMD_ATQ_SEND_APP_MAX_LEN);

	mutex_lock(&tq->lock);
	do {
		multi_packet = 0;
		if (packet_index == 0)
			multi_packet |= SXE2_CMD_HDR_MULTI_START;
		if ((packet_index + 1) == packet_total_num)
			multi_packet |= SXE2_CMD_HDR_MULTI_END;
		multi_packet |= packet_index;
		cmd_hdr->multi_packet = multi_packet;

		if ((current_offset + SXE2_CMD_ATQ_SEND_APP_MAX_LEN) > trans_in_len)
			trans_info->req_len = trans_in_len - current_offset +
					      SXE2_CMD_HDR_SIZE;
		else
			trans_info->req_len = SXE2_CMD_ATQ_SEND_MAX_LEN;
		cmd_hdr->cur_in_len = trans_info->req_len - SXE2_CMD_HDR_SIZE;

		if (packet_index != 0) {
			(void)memmove(trans_info->req_buff + SXE2_CMD_HDR_SIZE,
				      trans_info->req_buff + current_offset,
				      trans_info->req_len - SXE2_CMD_HDR_SIZE);
		}

		LOG_DEBUG_BDF("Tran Len:%u Packet Num:%u-%u Flag:0x%x offset:%u\t"
			      "current packet len:%u.\n",
			      trans_in_len, packet_index, packet_total_num,
			      multi_packet, current_offset, cmd_hdr->cur_in_len);
		retry_cnt = 0;
		do {
			ret = sxe2_cmd_send_single(cmd_ctxt);
			if (ret != -EAGAIN)
				break;
			mdelay(SXE2_CMD_RETRY_INTERVAL);

		} while (++retry_cnt < SXE2_CMD_RETRY_COUNT);
		if (ret != 0)
			break;
		current_offset += (trans_info->req_len - SXE2_CMD_HDR_SIZE);
		packet_index++;
	} while (packet_index < packet_total_num);

	mutex_unlock(&tq->lock);
	return ret;
}

STATIC s32 sxe2_cmd_wait_rsp(struct sxe2_cmd_context *cmd_ctxt)
{
	s32 ret;
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	struct sxe2_cmd_channel *channel =
			SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, cmd_ctxt->chnl_type);
	s32 timeout;
	u64 trace_id = cmd_ctxt->params->trace_id;

	while (1) {
		timeout = (s32)(cmd_ctxt->expired_time - jiffies);
		if (timeout < 0)
			break;

		if (cmd_ctxt->params->is_interruptible) {
			ret =
			(s32)wait_event_interruptible_timeout(channel->wq.wq,
							      (cmd_ctxt->wait_task.state !=
								SXE2_CMD_STATE_WAITING),
							      timeout);
		} else {
			ret = (s32)wait_event_timeout(channel->wq.wq,
						      (cmd_ctxt->wait_task.state !=
						       SXE2_CMD_STATE_WAITING),
						      timeout);
		}

		if (ret == -ERESTARTSYS && signal_pending_is_interrupt()) {
			ret = -ECANCELED;
			LOG_DEV_INFO("[trace id 0x%llx] cmd interrupted, exit wait.\n",
				     trace_id);
			goto l_end;
		} else if (ret == -ERESTARTSYS && !signal_pending_is_interrupt()) {
			msleep(SXE2_WAIT_INTERRUPTIBLE_INTERVAL);
			continue;
		} else {
			break;
		}
	}

	switch (cmd_ctxt->wait_task.state) {
	case SXE2_CMD_STATE_WAITING:
		ret = -ETIMEDOUT;
		cmd_ctxt->wait_task.state = SXE2_CMD_STATE_CANCELED;
		LOG_WARN_TRACEID("cmd timeout, exit wait.\n");
		goto l_end;
	case SXE2_CMD_STATE_CANCELED:
		ret = -ECANCELED;
		LOG_WARN_TRACEID("cmd canceled, exit wait.\n");
		goto l_end;
	case SXE2_CMD_STATE_FAULT:
		ret = -EFAULT;
		LOG_WARN_TRACEID("cmd fault, exit wait.\n");
		goto l_end;
	case SXE2_CMD_STATE_DONE:
		ret = 0;
		break;
	default:
		LOG_DEV_WARN("Unexpected wait queue state: %d.\n",
			     cmd_ctxt->wait_task.state);
		SXE2_BUG();
		break;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_cmd_wait_rsp_polling(struct sxe2_cmd_context *cmd_ctxt)
{
	s32 ret;
	struct sxe2_adapter *adapter = cmd_ctxt->adapter;
	struct sxe2_cmd_channel *channel =
			SXE2_ADAPTER_TO_CMD_CHANNEL(adapter, cmd_ctxt->chnl_type);
	struct sxe2_recv_msg *event;
	u64 trace_id = cmd_ctxt->params->trace_id;

	event = kzalloc(sizeof(*event) + channel->queue[SXE2_CMD_RQ].buf_size,
			GFP_KERNEL);
	if (!event) {
		LOG_ERROR_TRACEID("malloc failed, size: %zu.\n",
				  sizeof(*event) + channel->queue[SXE2_CMD_RQ]
								   .buf_size);
		ret = -ENOMEM;
		goto l_end;
	}

	do {
		ret = sxe2_cmd_recv(adapter, channel, event);
		if (ret == 0) {
			struct sxe2_cmd_hdr *cmd_hdr =
					(struct sxe2_cmd_hdr *)event->buf;

			if (le32_to_cpu(cmd_hdr->magic_code) != SXE2_CMD_MAGIC) {
				LOG_ERROR_TRACEID("recv cmd magic check failed.\n");
				ret = -EIO;
				goto l_end;
			}
			ret = (s32)le32_to_cpu(cmd_hdr->ret);
			if (ret < 0) {
				LOG_ERROR_TRACEID("recv cmd failed, ret: %d.\n",
						  ret);
				ret = -EIO;
				goto l_end;
			}
			if (cmd_hdr->cmd_type != cmd_ctxt->type ||
			    le64_to_cpu(cmd_hdr->session_id) !=
					    cmd_ctxt->session_id) {
				LOG_ERROR_TRACEID("recv invalid cmd, type: %d,\t"
						  "session id: 0x%llx cmd_ctxt session_id: 0x%llx .\n",
						  cmd_hdr->cmd_type,
						  le64_to_cpu(cmd_hdr->session_id),
						  le64_to_cpu(cmd_ctxt->session_id));
				ret = -ETIMEDOUT;
				continue;
			}

			SXE2_BUG_ON(event->buf_len > cmd_ctxt->trans_info.resp_len);
			if (event->buf_len > cmd_ctxt->trans_info.resp_len) {
				ret = -EIO;
				LOG_DEV_ERR("[trace id 0x%llx] rq receive error,\t"
					    "buf_len %d, resp_len %d.\n",
					    trace_id, event->buf_len,
					    cmd_ctxt->trans_info.resp_len);
				goto l_end;
			}
			memcpy(cmd_ctxt->trans_info.resp_buff, event->buf,
			       event->buf_len);
			goto l_end;
		} else if (ret != -ENODATA) {
			LOG_DEV_INFO("[trace id 0x%llx] rq receive error cmd, ret %d.\n",
				     trace_id, ret);
			break;
		}
		if (cmd_ctxt->params->is_interruptible) {
			if (msleep_interruptible(SXE2_CMD_WB_WAIT_INTERVAL) &&
			    signal_pending_is_interrupt()) {
				ret = -ECANCELED;
				LOG_DEV_INFO("[trace id 0x%llx] cmd interrupted,\t"
					     "exit polling\n",
					     trace_id);
				goto l_end;
			}
		} else {
			usleep_range(SXE2_WAIT_DONE_MIN, SXE2_WAIT_DONE_MAX);
		}
	} while (time_before(jiffies, (unsigned long)cmd_ctxt->expired_time));

l_end:
	kfree(event);
	if (ret == -ENODATA)
		ret = -ETIMEDOUT;
	return ret;
}

static inline bool sxe2_cmd_exec_mode_get(struct sxe2_adapter *adapter,
					  struct sxe2_cmd_params *cmd_params,
					  enum sxe2_cmd_exec_mode *mode)
{
	enum sxe2_dev_state state;
	enum sxe2_reset_type reset_type;
	bool is_resetting;

	sxe2_dev_state_get(adapter, &state, &reset_type);

	if (state == SXE2_DEVSTATE_RESETTING) {
		is_resetting = true;
		*mode = SXE2_CMD_EXEC_NO_RESP;
	} else {
		is_resetting = false;
		if (cmd_params->no_resp)
			*mode = SXE2_CMD_EXEC_NO_RESP;
		else if (adapter->cmd_channel_ctxt.mode == SXE2_CMD_POLLING)
			*mode = SXE2_CMD_EXEC_POLLING;
		else
			*mode = SXE2_CMD_EXEC_NOTIFY;
	}

	return is_resetting;
}

STATIC s32 sxe2_cmd_exec(struct sxe2_adapter *adapter,
			 struct sxe2_cmd_params *cmd_params, enum sxe2_cmd_type type)
{
	s32 ret = 0;
	struct sxe2_cmd_context cmd_ctxt = {0};
	struct sxe2_cmd_hdr *cmd_hdr;
	enum sxe2_cmd_exec_mode mode;
	unsigned long flags;
	u64 trace_id = cmd_params->trace_id;
	bool is_resetting;

#ifdef SXE2_CFG_RELEASE
	UNUSED(trace_id);
#endif

	ret = sxe2_cmd_check_and_fill(adapter, cmd_params, type, &cmd_ctxt);
	if (ret)
		goto l_end;

	ret = sxe2_cmd_add_hdr(&cmd_ctxt);
	if (ret)
		goto l_end;

	sxe2_cmd_wait_list_fill(&cmd_ctxt);

	spin_lock_irqsave(&adapter->dev_ctrl_ctxt.cmd_list_lock, flags);
	is_resetting = sxe2_cmd_exec_mode_get(adapter, cmd_params, &mode);
	if (is_resetting) {
		ret = -EOWNERDEAD;
		spin_unlock_irqrestore(&adapter->dev_ctrl_ctxt.cmd_list_lock, flags);
		goto l_strip_hdr;
	} else {
		if (mode == SXE2_CMD_EXEC_NOTIFY)
			sxe2_cmd_wait_list_add(&cmd_ctxt);
		spin_unlock_irqrestore(&adapter->dev_ctrl_ctxt.cmd_list_lock, flags);
	}

	ret = sxe2_cmd_send(&cmd_ctxt);
	if (ret == -EAGAIN) {
		ret = -EBUSY;
		goto l_list_del;
	} else if (ret == -ECANCELED) {
		goto l_cancel;
	} else if (ret) {
		goto l_list_del;
	}

	if (mode != SXE2_CMD_EXEC_NO_RESP) {
		if (mode == SXE2_CMD_EXEC_NOTIFY)
			ret = sxe2_cmd_wait_rsp(&cmd_ctxt);
		else
			ret = sxe2_cmd_wait_rsp_polling(&cmd_ctxt);
		if (ret == -ECANCELED || ret == -ETIMEDOUT)
			goto l_cancel;
		else if (ret)
			goto l_list_del;
		cmd_hdr = cmd_ctxt.trans_info.resp_buff;
		ret = (s32)cmd_hdr->ret;
		if (unlikely(ret < 0)) {
			LOG_ERROR_TRACEID("cmd transmit failed, ret: %d.\n", ret);
			ret = -EIO;
		}
	}

	goto l_list_del;

l_cancel:
l_list_del:
	if (mode == SXE2_CMD_EXEC_NOTIFY)
		sxe2_cmd_wait_list_del(&cmd_ctxt);
l_strip_hdr:
	if (sxe2_cmd_strip_hdr(&cmd_ctxt))
		ret = -EFAULT;
l_end:
#ifdef SXE2_CFG_DEBUG
	if (ret && (type == SXE2_CMD_TYPE_CLI || type == SXE2_CMD_TYPE_DRV_TO_FW))
		sxe2_dump_fwc(adapter);
#endif
	return ret;
}

STATIC s32 sxe2_cmd_add_msg_hdr(struct sxe2_adapter *adapter,
				struct sxe2_cmd_params *params,
				struct sxe2_cmd_params *params_with_hdr)
{
	s32 ret = 0;
	struct sxe2_drv_msg_hdr *msg_hdr;

	params_with_hdr->vf_idx = params->vf_idx;
	params_with_hdr->err_code = params->err_code;
	params_with_hdr->req_len = params->req_len + SXE2_DRV_MSG_HDR_SIZE;
	params_with_hdr->resp_len = params->resp_len + SXE2_DRV_MSG_HDR_SIZE;
	params_with_hdr->session_id = params->session_id;

	params_with_hdr->req_data = kzalloc(params_with_hdr->req_len, GFP_KERNEL);
	if (!params_with_hdr->req_data) {
		ret = -ENOMEM;
		params_with_hdr->req_len = 0;
		LOG_ERROR_BDF("malloc failed: size %u.\n", params_with_hdr->req_len);
		goto l_end;
	}
	msg_hdr = params_with_hdr->req_data;

	msg_hdr->err_code = cpu_to_le32((u32)params->err_code);
	msg_hdr->op_code = cpu_to_le32(params->opcode);
	msg_hdr->data_offset = cpu_to_le32(SXE2_DRV_MSG_HDR_SIZE);
	msg_hdr->data_len = cpu_to_le32((u32)params->req_len);
	msg_hdr->vf_id = cpu_to_le16(SXE2_VF_ID_INVAL);
	if (params->req_len)
		memcpy(msg_hdr->body, params->req_data, params->req_len);

	params_with_hdr->resp_data = kzalloc(params_with_hdr->resp_len, GFP_KERNEL);
	if (!params_with_hdr->resp_data) {
		ret = -ENOMEM;
		params_with_hdr->resp_len = 0;
		LOG_ERROR_BDF("malloc failed: size %u.\n",
			      params_with_hdr->resp_len);
		goto l_malloc_failed;
	}
	return 0;

l_malloc_failed:
	kfree(params_with_hdr->req_data);
	params_with_hdr->req_data = NULL;
	params_with_hdr->req_len = 0;
l_end:
	return ret;
}

STATIC void sxe2_cmd_strip_msg_hdr(struct sxe2_cmd_params *params,
				   struct sxe2_cmd_params *params_with_hdr)
{
	struct sxe2_drv_msg_hdr *msg_hdr;

	kfree(params_with_hdr->req_data);
	params_with_hdr->req_data = NULL;
	params_with_hdr->req_len = 0;

	if (params_with_hdr->resp_data) {
		msg_hdr = params_with_hdr->resp_data;
		if (params->resp_len)
			memcpy(params->resp_data, SXE2_MSG_BODY(msg_hdr),
			       params->resp_len);
		kfree(params_with_hdr->resp_data);
		params_with_hdr->resp_data = NULL;
		params_with_hdr->resp_len = 0;
	}
}

s32 sxe2_err_code_trans_fw(struct sxe2_adapter *adapter, u64 trace_id, s32 err)
{
	s32 ret = 0;

	if (unlikely(err < 0))
		LOG_ERROR_TRACEID("drv cmd exec failed, err: %d.\n", err);

	if (err > -SXE2_CMD_DRV_HW_OP_ERR)
		return err;

	switch (err) {
	case SXE2_CMD_DRV_SUCCESS:
	case SXE2_CMD_DRV_LINK_REBUILD_FAILED:
		ret = 0;
		break;
	case -SXE2_CMD_DRV_NO_FREE_VSI:
	case -SXE2_CMD_DRV_HW_NOSPC:
	case -SXE2_CMD_DRV_FW_NOMEM:
	case -SXE2_CMD_DRV_HW_NO_RES:
	case -SXE2_CMD_DRV_TXSCHED_TEID_ALLOC_FAILED:
	case -SXE2_CMD_DRV_TXSCHED_CHILDIDX_ALLOC_FAILED:
	case -SXE2_CMD_DRV_TXSCHED_ALLOC_FAILED:
		ret = -ENOMEM;
		break;
	case -SXE2_CMD_DRV_HW_OP_ERR:
	case -SXE2_CMD_DRV_UNSUPPORT:
		ret = -EOPNOTSUPP;
		break;
	case -SXE2_CMD_DRV_HW_EXIST:
	case -SXE2_CMD_DRV_HW_HID_EXIST:
		ret = -EEXIST;
		break;
	case -SXE2_CMD_DRV_HW_TIMEOUT:
	case -SXE2_CMD_DRV_TXSCHED_TIMEOUT:
		ret = -ETIMEDOUT;
		break;
	case -SXE2_OPT_DEV_BUSY:
		ret = -EBUSY;
		break;
	case -SXE2_CMD_DRV_PARAM_INVALID:
	case -SXE2_CMD_DRV_UDP_TUNNEL_WRONG_PORT:
		ret = -EINVAL;
		break;
	case -SXE2_CMD_DUMP_LOG_FAILED:
	case -SXE2_CMD_DRV_RXQ_CFG_FAIL:
	case -SXE2_CMD_DRV_TXQ_EN_FAIL:
	case -SXE2_CMD_DRV_TXQ_DISA_FAIL:
	case -SXE2_CMD_DRV_PFR_FAILED:
	case -SXE2_CMD_DRV_VFR_FAILED:
	case -SXE2_CMD_DRV_HW_RETURN:
	case -SXE2_CMD_DRV_HW_MISMATCH:
	case -SXE2_CMD_DRV_HW_NOENT:
	case -SXE2_CMD_DRV_TLV_ERROR:
	case -SXE2_CMD_DRV_TXSCHED_CFG_FAILED:
	case -SXE2_CMD_DRV_LINK_UPDATE_FAILED:
	default:
		ret = -EIO;
		break;
	}

	return ret;
}

s32 sxe2_cmd_drv_exec(struct sxe2_adapter *adapter,
		      struct sxe2_cmd_params *cmd_params, enum sxe2_cmd_type type)
{
	s32 ret;
	struct sxe2_cmd_params params_with_hdr = {0};
	struct sxe2_drv_msg_hdr *msg_hdr;

	if (type == SXE2_CMD_TYPE_PF_TO_VF || type == SXE2_CMD_TYPE_PF_REPLY_VF) {
		if (cmd_params->req_len > SXE2_DRV_CMD_MAX_MSG_SIZE_MBX ||
		    cmd_params->resp_len > SXE2_DRV_CMD_MAX_MSG_SIZE_MBX) {
			ret = -EINVAL;
			goto l_end;
		}
	} else if ((cmd_params->req_len > SXE2_DRV_CMD_MAX_MSG_SIZE) ||
		   (cmd_params->resp_len > SXE2_DRV_CMD_MAX_MSG_SIZE)) {
		ret = -EINVAL;
		goto l_end;
	}

	memcpy(&params_with_hdr, cmd_params, sizeof(*cmd_params));
	ret = sxe2_cmd_add_msg_hdr(adapter, cmd_params, &params_with_hdr);
	if (ret)
		goto l_end;

	ret = sxe2_cmd_exec(adapter, &params_with_hdr, type);
	if (ret)
		goto l_cmd_failed;

	msg_hdr = params_with_hdr.resp_data;

	ret = sxe2_err_code_trans_fw(adapter, cmd_params->trace_id,
				     (s32)le32_to_cpu(msg_hdr->err_code));

l_cmd_failed:
	sxe2_cmd_strip_msg_hdr(cmd_params, &params_with_hdr);
l_end:
	return ret;
}

s32 sxe2_cmd_fw_exec(struct sxe2_adapter *adapter,
		     struct sxe2_cmd_params *cmd_params)
{
	return sxe2_cmd_drv_exec(adapter, cmd_params, SXE2_CMD_TYPE_DRV_TO_FW);
}

s32 sxe2_cmd_mbx_reply(struct sxe2_adapter *adapter,
		       struct sxe2_cmd_params *cmd_params)
{
	return sxe2_cmd_drv_exec(adapter, cmd_params, SXE2_CMD_TYPE_PF_REPLY_VF);
}

s32 sxe2_cmd_mbx_exec(struct sxe2_adapter *adapter,
		      struct sxe2_cmd_params *cmd_params)
{
	return sxe2_cmd_drv_exec(adapter, cmd_params, SXE2_CMD_TYPE_PF_TO_VF);
}

s32 sxe2_cmd_cli_exec(struct sxe2_adapter *adapter,
		      struct sxe2_cmd_params *cmd_params)
{
	return sxe2_cmd_exec(adapter, cmd_params, SXE2_CMD_TYPE_CLI);
}

void sxe2_wait_task_cancel(struct sxe2_cmd_channel *channel)
{
	struct sxe2_cmd_wait_task *cmd_wait_elem;
	u32 bkt;
	unsigned long flags;

	spin_lock_irqsave(&channel->wq.lock, flags);
	hash_for_each(channel->wq.table, bkt, cmd_wait_elem, entry)
			cmd_wait_elem->state = SXE2_CMD_STATE_CANCELED;
	spin_unlock_irqrestore(&channel->wq.lock, flags);

	wake_up(&channel->wq.wq);
}

void sxe2_wait_task_cancel_all(struct sxe2_adapter *adapter)
{
	sxe2_wait_task_cancel(&adapter->cmd_channel_ctxt.channel[SXE2_CHNL_FW]);
	sxe2_wait_task_cancel(&adapter->cmd_channel_ctxt.channel[SXE2_CHNL_MBX]);
}

void sxe2_msg_list_add(struct sxe2_adapter *adapter, struct sxe2_recv_msg *msg)
{
	struct sxe2_cmd_channel_context *ctxt = &adapter->cmd_channel_ctxt;

	mutex_lock(&ctxt->lock);
	list_add_tail(&msg->node, &ctxt->head);
	mutex_unlock(&ctxt->lock);
}

void sxe2_msg_list_del(struct sxe2_adapter *adapter, struct sxe2_recv_msg **msg)
{
	struct sxe2_cmd_channel_context *ctxt = &adapter->cmd_channel_ctxt;

	mutex_lock(&ctxt->lock);

	if (list_empty(&ctxt->head)) {
		*msg = NULL;
		mutex_unlock(&ctxt->lock);
		return;
	}

	*msg = list_first_entry(&ctxt->head, struct sxe2_recv_msg, node);
	list_del(&(*msg)->node);
	mutex_unlock(&ctxt->lock);
}

bool sxe2_cmd_rq_pending(struct sxe2_adapter *adapter,
			 enum sxe2_cmd_channel_type chnl_type)
{
	u16 val;
	struct sxe2_cmd_queue *queue =
			SXE2_ADAPTER_TO_CMD_QUEUE(adapter, chnl_type, SXE2_CMD_RQ);

	if (sxe2_queue_head_read(adapter, queue, &val))
		return false;

	return queue->ntc != val;
}

STATIC void sxe2_rq_recv_work_complete(struct sxe2_adapter *adapter)
{
	BUG_ON(!test_bit(SXE2_RQ_RECV_WORK_SCHED,
			 &adapter->cmd_channel_ctxt.recv_work_state));

	/* in order to force CPU ordering */
	smp_mb__before_atomic();
	clear_bit(SXE2_RQ_RECV_WORK_SCHED,
		  &adapter->cmd_channel_ctxt.recv_work_state);
}

STATIC void sxe2_msg_handle_work_complete(struct sxe2_adapter *adapter)
{
	BUG_ON(!test_bit(SXE2_MSG_HANDLE_WORK_SCHED,
			 &adapter->cmd_channel_ctxt.handle_work_state));
	/* in order to force CPU ordering */
	smp_mb__before_atomic();
	clear_bit(SXE2_MSG_HANDLE_WORK_SCHED,
		  &adapter->cmd_channel_ctxt.handle_work_state);
}

STATIC bool sxe2_fw_channel_work(struct sxe2_adapter *adapter)
{
	if (sxe2_cmd_rq_pending(adapter, SXE2_CHNL_FW))
		return sxe2_cmd_channel_work(adapter, SXE2_CHNL_FW);
	else
		return false;
}

bool sxe2_mbx_channel_work(struct sxe2_adapter *adapter)
{
	if (sxe2_cmd_rq_pending(adapter, SXE2_CHNL_MBX))
		return sxe2_cmd_channel_work(adapter, SXE2_CHNL_MBX);
	else
		return false;
}

STATIC void sxe2_rq_recv_work_cb(struct work_struct *work)
{
	struct sxe2_cmd_channel_context *cmd_channel_ctxt =
		container_of(work, struct sxe2_cmd_channel_context, recv_work);
	struct sxe2_adapter *adapter =
		container_of(cmd_channel_ctxt, struct sxe2_adapter, cmd_channel_ctxt);

	(void)sxe2_fw_channel_work(adapter);
	(void)sxe2_mbx_channel_work(adapter);

	sxe2_rq_recv_work_complete(adapter);

	if (sxe2_fw_channel_work(adapter) || sxe2_mbx_channel_work(adapter))
		sxe2_rq_recv_work_schedule(adapter);
}

void sxe2_rq_recv_work_schedule(struct sxe2_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->cmd_channel_ctxt.recv_work_lock, flags);
	if (!test_bit(SXE2_RQ_RECV_WORK_STOPPED,
		      &adapter->cmd_channel_ctxt.recv_work_state) &&
	    !test_and_set_bit(SXE2_RQ_RECV_WORK_SCHED,
			      &adapter->cmd_channel_ctxt.recv_work_state)) {
		sxe2_queue_work(adapter, sxe2_rq_recv_wq,
				&adapter->cmd_channel_ctxt.recv_work);
	}
	spin_unlock_irqrestore(&adapter->cmd_channel_ctxt.recv_work_lock, flags);
}

STATIC void sxe2_msg_handle(struct sxe2_adapter *adapter, struct sxe2_recv_msg *msg)
{
	struct sxe2_cmd_hdr *cmd_hdr = (struct sxe2_cmd_hdr *)msg->buf;

	switch (cmd_hdr->cmd_type) {
	case SXE2_CMD_TYPE_FW_NOTIFY:
		sxe2_cmd_event_handler(adapter, msg);
		break;

	case SXE2_CMD_TYPE_VF_TO_PF:
		sxe2_cmd_vf_msg_handler(adapter, msg);
		break;

	default:
		LOG_ERROR_BDF("unknown cmd type: %d.\n", cmd_hdr->cmd_type);
		SXE2_BUG();
		break;
	}
}

STATIC void sxe2_msg_handle_polling(struct sxe2_adapter *adapter)
{
	struct sxe2_recv_msg *msg;
	int schedule_count_th = 0;

	while (1) {
		sxe2_msg_list_del(adapter, &msg);
		if (!msg)
			break;

		sxe2_msg_handle(adapter, msg);
		kfree(msg);

		schedule_count_th++;
		if (schedule_count_th == SXE2_MSG_HANDLING_MAX_CNT) {
			schedule_count_th = 0;
			cond_resched();
		}
	}
}

STATIC void sxe2_msg_handle_work_cb(struct work_struct *work)
{
	struct sxe2_cmd_channel_context *cmd_channel_ctxt =
		container_of(work, struct sxe2_cmd_channel_context, handle_work);
	struct sxe2_adapter *adapter =
		container_of(cmd_channel_ctxt, struct sxe2_adapter, cmd_channel_ctxt);

	sxe2_msg_handle_polling(adapter);

	sxe2_msg_handle_work_complete(adapter);

	sxe2_msg_handle_polling(adapter);
}

void sxe2_msg_handle_work_schedule(struct sxe2_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->cmd_channel_ctxt.handle_work_lock, flags);
	if (!test_bit(SXE2_MSG_HANDLE_WORK_STOPPED,
		      &adapter->cmd_channel_ctxt.handle_work_state) &&
	    !test_and_set_bit(SXE2_MSG_HANDLE_WORK_SCHED,
			      &adapter->cmd_channel_ctxt.handle_work_state)) {
		sxe2_queue_work(adapter, sxe2_msg_handle_wq,
				&adapter->cmd_channel_ctxt.handle_work);
	}
	spin_unlock_irqrestore(&adapter->cmd_channel_ctxt.handle_work_lock, flags);
}

void sxe2_cmd_work_init(struct sxe2_adapter *adapter)
{
	INIT_WORK(&adapter->cmd_channel_ctxt.recv_work, sxe2_rq_recv_work_cb);
	INIT_WORK(&adapter->cmd_channel_ctxt.handle_work, sxe2_msg_handle_work_cb);

	clear_bit(SXE2_RQ_RECV_WORK_STOPPED,
		  &adapter->cmd_channel_ctxt.recv_work_state);
	clear_bit(SXE2_MSG_HANDLE_WORK_STOPPED,
		  &adapter->cmd_channel_ctxt.handle_work_state);
}

void sxe2_cmd_work_exit(struct sxe2_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->cmd_channel_ctxt.recv_work_lock, flags);
	set_bit(SXE2_RQ_RECV_WORK_STOPPED,
		&adapter->cmd_channel_ctxt.recv_work_state);
	spin_unlock_irqrestore(&adapter->cmd_channel_ctxt.recv_work_lock, flags);
	cancel_work_sync(&adapter->cmd_channel_ctxt.recv_work);
	clear_bit(SXE2_RQ_RECV_WORK_SCHED,
		  &adapter->cmd_channel_ctxt.recv_work_state);

	spin_lock_irqsave(&adapter->cmd_channel_ctxt.handle_work_lock, flags);
	set_bit(SXE2_MSG_HANDLE_WORK_STOPPED,
		&adapter->cmd_channel_ctxt.handle_work_state);
	spin_unlock_irqrestore(&adapter->cmd_channel_ctxt.handle_work_lock, flags);
	cancel_work_sync(&adapter->cmd_channel_ctxt.handle_work);
	clear_bit(SXE2_MSG_HANDLE_WORK_SCHED,
		  &adapter->cmd_channel_ctxt.handle_work_state);
}

s32 sxe2_cmd_work_create(void)
{
	sxe2_rq_recv_wq = alloc_workqueue("%s-RQ-RECV", 0, 0, SXE2_DRV_NAME);
	if (!sxe2_rq_recv_wq) {
		LOG_PR_ERR("failed to create rq recv workqueue\n");
		return -ENOMEM;
	}

	sxe2_msg_handle_wq = alloc_workqueue("%s-MSG-HANDLE", 0, 0, SXE2_DRV_NAME);
	if (!sxe2_msg_handle_wq) {
		LOG_PR_ERR("failed to create msg handle workqueue\n");
		return -ENOMEM;
	}

	return 0;
}

void sxe2_cmd_work_destroy(void)
{
	destroy_workqueue(sxe2_rq_recv_wq);
	sxe2_rq_recv_wq = NULL;

	destroy_workqueue(sxe2_msg_handle_wq);
	sxe2_msg_handle_wq = NULL;
}

struct mutex *sxe2_cmd_channel_get_event_lock(struct sxe2_adapter *adapter)
{
	return &adapter->cmd_channel_ctxt.event_lock;
}

#endif
