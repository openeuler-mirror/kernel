// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/delay.h>

#include "ubase_cmd.h"
#include "ubase_arq.h"
#include "ubase_hw.h"

/* When use tracepoint, must define "CREATE_TRACE_POINTS" before include the
 * trace header file.
 * If many source file need include the same header file, the
 * "CREATE_TRACE_POINTS" only define once.
 */
#define CREATE_TRACE_POINTS
#include "ubase_trace.h"

static inline int ubase_alloc_cmd_queue(struct ubase_dev *udev,
					struct ubase_cmdq_ring *ring)
{
	size_t size = ring->desc_num * sizeof(struct ubase_cmdq_desc);

	ring->desc = dma_alloc_coherent(udev->dev, size, &ring->desc_dma_addr,
					GFP_KERNEL);
	if (!ring->desc)
		return -ENOMEM;

	return 0;
}

static inline void ubase_free_cmd_queue(struct ubase_dev *udev,
					struct ubase_cmdq_ring *ring)
{
	size_t size = ring->desc_num * sizeof(struct ubase_cmdq_desc);

	if (!ring->desc)
		return;

	dma_free_coherent(udev->dev, size, ring->desc, ring->desc_dma_addr);
	ring->desc = NULL;
}

static int ubase_cmd_queue_init(struct ubase_dev *udev)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	struct ubase_cmdq_ring *crq = &udev->hw.cmdq.crq;
	int ret;

	spin_lock_init(&csq->lock);
	spin_lock_init(&crq->lock);

	csq->pi = 0;
	csq->ci = 0;
	crq->pi = 0;
	crq->ci = 0;
	csq->desc_num = UBASE_CMDQ_DESC_NUM;
	crq->desc_num = UBASE_CMDQ_DESC_NUM;
	csq->tx_timeout = UBASE_CMDQ_TX_TIMEOUT;

	ret = ubase_alloc_cmd_queue(udev, csq);
	if (ret) {
		ubase_err(udev, "failed to alloc csq, ret = %d.\n", ret);
		return ret;
	}

	ret = ubase_alloc_cmd_queue(udev, crq);
	if (ret) {
		ubase_err(udev, "failed to alloc crq, ret = %d.\n", ret);
		goto err_csq;
	}

	return 0;

err_csq:
	ubase_free_cmd_queue(udev, csq);
	return ret;
}

static void ubase_cmd_queue_uninit(struct ubase_dev *udev)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	struct ubase_cmdq_ring *crq = &udev->hw.cmdq.crq;

	ubase_free_cmd_queue(udev, csq);
	ubase_free_cmd_queue(udev, crq);
}

static void ubase_cmd_init_regs(struct ubase_dev *udev)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	struct ubase_cmdq_ring *crq = &udev->hw.cmdq.crq;
	u32 reg_val;

	spin_lock_bh(&csq->lock);
	spin_lock(&crq->lock);

	/* csq init */
	ubase_write_dev(&udev->hw, UBASE_CSQ_BASEADDR_L_REG,
			lower_32_bits(csq->desc_dma_addr));
	ubase_write_dev(&udev->hw, UBASE_CSQ_BASEADDR_H_REG,
			upper_32_bits(csq->desc_dma_addr));
	reg_val = csq->desc_num >> UBASE_CMDQ_DESC_NUM_S;
	ubase_write_dev(&udev->hw, UBASE_CSQ_DEPTH_REG, reg_val);
	ubase_write_dev(&udev->hw, UBASE_CSQ_HEAD_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CSQ_TAIL_REG, 0);

	/* crq init */
	ubase_write_dev(&udev->hw, UBASE_CRQ_BASEADDR_L_REG,
			lower_32_bits(crq->desc_dma_addr));
	ubase_write_dev(&udev->hw, UBASE_CRQ_BASEADDR_H_REG,
			upper_32_bits(crq->desc_dma_addr));
	reg_val = crq->desc_num >> UBASE_CMDQ_DESC_NUM_S;
	ubase_write_dev(&udev->hw, UBASE_CRQ_DEPTH_REG, reg_val);
	ubase_write_dev(&udev->hw, UBASE_CRQ_HEAD_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CRQ_TAIL_REG, 0);

	spin_unlock(&crq->lock);
	spin_unlock_bh(&csq->lock);
}

static void ubase_cmd_uninit_regs(struct ubase_dev *udev)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	struct ubase_cmdq_ring *crq = &udev->hw.cmdq.crq;

	spin_lock_bh(&csq->lock);
	spin_lock(&crq->lock);

	ubase_write_dev(&udev->hw, UBASE_CSQ_BASEADDR_L_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CSQ_BASEADDR_H_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CSQ_DEPTH_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CSQ_HEAD_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CSQ_TAIL_REG, 0);

	ubase_write_dev(&udev->hw, UBASE_CRQ_BASEADDR_L_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CRQ_BASEADDR_H_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CRQ_DEPTH_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CRQ_HEAD_REG, 0);
	ubase_write_dev(&udev->hw, UBASE_CRQ_TAIL_REG, 0);

	spin_unlock(&crq->lock);
	spin_unlock_bh(&csq->lock);
}

static void ubase_write_desc_to_cmdq(struct ubase_dev *udev,
				     struct ubase_cmdq_desc *desc, int num)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	struct ubase_cmdq_desc *desc_to_use;
	int cnt = 0;

	while (cnt < num) {
		desc_to_use = &csq->desc[csq->pi];
		*desc_to_use = desc[cnt];
		trace_ubase_csq_tx(udev->dev, cnt, csq->pi, csq->ci, desc);
		(csq->pi)++;
		if (csq->pi >= csq->desc_num)
			csq->pi = 0;
		cnt++;
	}

	ubase_write_dev(&udev->hw, UBASE_CSQ_TAIL_REG, csq->pi);
}

static int ubase_remain_cmdq_space(struct ubase_cmdq_ring *csq)
{
	u32 used = (csq->pi - csq->ci + csq->desc_num) % csq->desc_num;

	return csq->desc_num - used - 1;
}

static bool ubase_wait_for_resp(struct ubase_dev *udev)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	u32 timeout = 0;
	u32 ci;

	do {
		ci = ubase_read_dev(&udev->hw, UBASE_CSQ_HEAD_REG);
		if (ci == csq->pi)
			return true;
		udelay(1);
		timeout++;
	} while (timeout < csq->tx_timeout);

	return false;
}

static int ubase_get_cmd_result(struct ubase_dev *udev,
				struct ubase_cmdq_desc *desc,
				int num, u32 sw_pi)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	u32 pi = sw_pi;
	int handle;
	u16 ret;

	for (handle = 0; handle < num; handle++) {
		desc[handle] = csq->desc[pi];
		trace_ubase_csq_rx(udev->dev, handle, pi, csq->ci, desc);
		pi++;
		if (pi >= csq->desc_num)
			pi = 0;
	}

	if (desc->flag & UBASE_CMD_FLAG_OUT)
		ret = le16_to_cpu(desc->ret);
	else
		ret = ETIMEDOUT;

	return -ret;
}

static int ubase_csq_data_is_valid(struct ubase_dev *udev, u32 hw_ci)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	u32 sw_ci = csq->ci;
	u32 sw_pi = csq->pi;

	if (sw_pi > sw_ci)
		return hw_ci >= sw_ci && hw_ci <= sw_pi;

	return hw_ci >= sw_ci || hw_ci <= sw_pi;
}

static int ubase_csq_clean(struct ubase_dev *udev)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	s64 hw_ci;
	int clean;

	hw_ci = ubase_read_dev(&udev->hw, UBASE_CSQ_HEAD_REG);
	/* Make sure head is ready before touch any data */
	rmb();
	if (!ubase_csq_data_is_valid(udev, hw_ci)) {
		ubase_warn(udev,
			   "the cmd head is incorrect! cmd head = (%lld, %u-%u).\n",
			   hw_ci, csq->pi, csq->ci);
		ubase_warn(udev,
			   "any further commands to the firmware are disabled!\n");
		set_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state);
		ubase_warn(udev,
			   "the firmware watchdog is expected to reset soon!\n");
		return -EIO;
	}

	clean = (int)((hw_ci - (s64)(csq->ci) + (s64)(csq->desc_num)) %
		      (s64)(csq->desc_num));
	csq->ci = hw_ci;

	return clean;
}

int ubase_send_cmd(struct ubase_dev *udev,
		   struct ubase_cmdq_desc *desc, int num)
{
	struct ubase_cmdq_ring *csq = &udev->hw.cmdq.csq;
	bool is_completed = false;
	int cleaned, free_num;
	u32 sw_pi;
	int ret;

	spin_lock_bh(&csq->lock);
	atomic_inc(&udev->hw.cmdq.csq_cnt);
	if (test_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state)) {
		ret = -EBUSY;
		goto err_unlock;
	}

	free_num = ubase_remain_cmdq_space(csq);
	if (num > free_num) {
		csq->ci = ubase_read_dev(&udev->hw, UBASE_CSQ_HEAD_REG);
		ubase_warn(udev,
			   "the requested space(%d) exceeds the remaining space(%d), csq ci: %u.\n",
			   num, free_num, csq->ci);
		ret = -EBUSY;
		goto err_unlock;
	}

	/**
	 * Record the location of desc in the ring for this time
	 * which will be use for hardware to write back
	 */
	sw_pi = csq->pi;

	ubase_write_desc_to_cmdq(udev, desc, num);
	is_completed = ubase_wait_for_resp(udev);
	if (!is_completed) {
		ret = -EBADE;
		goto err_clr_cmdq;
	}
	ret = ubase_get_cmd_result(udev, desc, num, sw_pi);

err_clr_cmdq:
	cleaned = ubase_csq_clean(udev);
	if (cleaned < 0)
		ret = cleaned;
	else if (cleaned != num)
		ubase_warn(udev,
			   "cleaned %dBD, need to clean %dBD.\n", cleaned, num);
err_unlock:
	atomic_dec(&udev->hw.cmdq.csq_cnt);
	spin_unlock_bh(&csq->lock);

	return ret;
}

static int ubase_cmd_query_version(struct ubase_dev *udev)
{
	struct ubase_query_version_cmd *resp;
	struct ubase_cmdq_desc desc;
	u32 fw_ver;
	int ret;

	ubase_cmd_setup_basic_desc(&desc, UBASE_OPC_QUERY_FW_VER, true, 1);
	ret = ubase_send_cmd(udev, &desc, 1);
	if (ret) {
		ubase_err(udev, "failed to query fw version, ret = %d.\n",
			  ret);
		return ret;
	}

	resp = (struct ubase_query_version_cmd *)desc.data;
	udev->caps.dev_caps.fw_version = le32_to_cpu(resp->fw_version);
	fw_ver = udev->caps.dev_caps.fw_version;

	ubase_info(udev, "The firmware version is %u.%u.%u.%u\n",
		   u32_get_bits(fw_ver, UBASE_FW_VERSION_BYTE3_MASK),
		   u32_get_bits(fw_ver, UBASE_FW_VERSION_BYTE2_MASK),
		   u32_get_bits(fw_ver, UBASE_FW_VERSION_BYTE1_MASK),
		   u32_get_bits(fw_ver, UBASE_FW_VERSION_BYTE0_MASK));

	return 0;
}

static inline void ubase_crq_table_init(struct ubase_dev *udev)
{
	struct ubase_crq_table *crq_table = &udev->crq_table;

	mutex_init(&crq_table->lock);
	INIT_LIST_HEAD(&crq_table->nbs.list);
}

static inline void ubase_crq_table_uninit(struct ubase_dev *udev)
{
	struct ubase_crq_table *crq_table = &udev->crq_table;

	mutex_destroy(&crq_table->lock);
}

int ubase_cmd_init(struct ubase_dev *udev)
{
	int ret;

	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		ubase_crq_table_init(udev);

	ret = ubase_cmd_queue_init(udev);
	if (ret) {
		ubase_err(udev, "failed to init ubase cmd queue.\n");
		goto err_queue_init;
	}

	ubase_arq_init(udev);

	ubase_cmd_init_regs(udev);

	atomic_set(&udev->hw.cmdq.csq_cnt, 0);

	clear_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state);

	ret = ubase_cmd_query_version(udev);
	if (ret)
		goto err_query_version;

	return 0;

err_query_version:
	set_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state);
	ubase_cmd_uninit_regs(udev);
	ubase_arq_uninit(udev);
	ubase_cmd_queue_uninit(udev);
err_queue_init:
	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		ubase_crq_table_uninit(udev);

	return ret;
}

void ubase_cmd_disable(struct ubase_dev *udev)
{
#define UBASE_CMDQ_CLEAN_WAIT_TIME	4

	__ubase_cmd_disable(udev);
	/* wait to ensure the firmware completes csq commands. */
	while (atomic_read(&udev->hw.cmdq.csq_cnt))
		msleep(UBASE_CMDQ_CLEAN_WAIT_TIME);

	ubase_cmd_uninit_regs(udev);
}

void ubase_cmd_uninit(struct ubase_dev *udev)
{
	if (udev->reset_stage != UBASE_RESET_STAGE_UNINIT) {
		ubase_cmd_disable(udev);
		/* wait to ensure the firmware completes crq commands. */
		msleep(UBASE_CMDQ_CLEAR_WAIT_TIME);
	}

	ubase_arq_uninit(udev);
	ubase_cmd_queue_uninit(udev);

	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		ubase_crq_table_uninit(udev);
}

void ubase_cmd_setup_basic_desc(struct ubase_cmdq_desc *desc,
				enum ubase_opcode_type opcode, bool is_read,
				u8 num)
{
	memset(desc, 0, sizeof(*desc));
	desc->opcode = cpu_to_le16(opcode);
	desc->flag = UBASE_CMD_FLAG_NO_INTR | UBASE_CMD_FLAG_IN;
	desc->bd_num = num;

	if (is_read)
		desc->flag |= cpu_to_le16(UBASE_CMD_FLAG_WR);
}

static u16 ubase_calc_bd_num(struct ubase_cmd_buf *buf)
{
	u32 data_size = buf->data_size > UBASE_CMD_DATA_LENGTH ?
			buf->data_size - UBASE_CMD_DATA_LENGTH : 0;

	return DIV_ROUND_UP(data_size, sizeof(struct ubase_cmdq_desc)) + 1;
}

static int ubase_cmd_buf_check(struct ubase_dev *udev, struct ubase_cmd_buf *in,
			       struct ubase_cmd_buf *out, u16 *num)
{
	if (in->is_read && (!out || !out->data || out->data_size == 0)) {
		ubase_err(udev, "output buffer is empty.\n");
		return -EINVAL;
	}

	*num = max_t(u16, ubase_calc_bd_num(in), ubase_calc_bd_num(out));
	if (*num > UBASE_CMDQ_DESC_NUM) {
		ubase_err(udev,
			  "requested space(%u) exceeds the maximum(%lu).\n",
			  max_t(u32, in->data_size, out->data_size),
			  UBASE_CMD_MAX_DESC_SIZE);
		return -EINVAL;
	}

	return 0;
}

static void ubase_cmd_setup_desc_by_inbuf(struct ubase_dev *udev,
					  struct ubase_cmd_buf *in,
					  struct ubase_cmdq_desc *desc,
					  u16 num)
{
	ubase_cmd_setup_basic_desc(&desc[0], in->opcode, in->is_read, num);
	if (in->data) {
		/* the size of the desc is the larger value between in and out.
		 * the data_size is copied and filled into the subsequent desc.
		 */
		memcpy(desc->data, in->data, in->data_size);
	}
}

static void ubase_cmd_setup_desc_by_outbuf(struct ubase_dev *udev,
					   struct ubase_cmd_buf *out,
					   struct ubase_cmdq_desc *desc)
{
	if (!out || out->data_size == 0)
		return;

	out->opcode = desc[0].opcode;
	out->is_read = (desc[0].flag & UBASE_CMD_FLAG_WR) ? true : false;
	memcpy(out->data, desc->data, out->data_size);
}

static int ubase_cmd_send_inout_real(struct ubase_dev *udev,
				     struct ubase_cmd_buf *in,
				     struct ubase_cmd_buf *out)
{
	struct ubase_cmdq_desc *desc;
	u16 num;
	int ret;

	ret = ubase_cmd_buf_check(udev, in, out, &num);
	if (ret)
		return ret;

	desc = kcalloc(num, sizeof(struct ubase_cmdq_desc), GFP_ATOMIC);
	if (!desc) {
		ubase_err(udev, "failed to alloc desc, size = %lu.\n",
			  num * sizeof(struct ubase_cmdq_desc));
		return -ENOMEM;
	}

	ubase_cmd_setup_desc_by_inbuf(udev, in, desc, num);

	ret = ubase_send_cmd(udev, desc, num);
	if (ret)
		goto err_send_cmd;

	ubase_cmd_setup_desc_by_outbuf(udev, out, desc);

err_send_cmd:
	kfree(desc);

	return ret;
}

static void ubase_free_bd_data(void *msg_data, u32 bd_num)
{
	if (!msg_data || bd_num <= 1)
		return;

	kfree(msg_data);
}

static void ubase_cmd_exec_callback(struct ubase_dev *udev, u16 opcode,
				    void *msg_data, u32 msg_data_len)
{
	struct ubase_crq_table *crq_table = &udev->crq_table;
	struct ubase_crq_event_nbs *nbs;

	if (!msg_data)
		return;

	mutex_lock(&crq_table->lock);
	list_for_each_entry(nbs, &crq_table->nbs.list, list) {
		if (nbs->nb.opcode == opcode) {
			nbs->nb.crq_handler(nbs->nb.back, msg_data,
					    msg_data_len);
			break;
		}
	}
	mutex_unlock(&crq_table->lock);
}

static void ubase_gen_multi_bd_data(struct ubase_dev *udev, u32 bd_num,
				    void **msg_data, u32 msg_data_len)
{
	struct ubase_cmdq_ring *crq = &udev->hw.cmdq.crq;
	struct ubase_cmdq_desc *desc;
	u32 pos = 0;
	u32 i;

	*msg_data = kzalloc(msg_data_len, GFP_KERNEL);
	if (!(*msg_data)) {
		ubase_err(udev, "failed to alloc crq msg data.");
		return;
	}

	for (i = 0; i < bd_num; i++) {
		desc = &crq->desc[crq->ci];
		trace_ubase_crq(udev->dev, i, crq->pi, crq->ci, desc);
		if (i == 0) {
			memcpy(*msg_data + pos,
			       desc->data, UBASE_CMD_DATA_LENGTH);
			pos += UBASE_CMD_DATA_LENGTH;
		} else {
			memcpy(*msg_data + pos, desc, sizeof(*desc));
			pos += sizeof(*desc);
		}

		UBASE_MOVE_CRQ_RING_PTR(crq);
	}
}

static void ubase_gen_single_bd_data(struct ubase_dev *udev, void **msg_data)
{
	struct ubase_cmdq_ring *crq = &udev->hw.cmdq.crq;
	struct ubase_cmdq_desc *desc;

	desc = &crq->desc[crq->ci];
	trace_ubase_crq(udev->dev, 1, crq->pi, crq->ci, desc);
	*msg_data = crq->desc[crq->ci].data;
	UBASE_MOVE_CRQ_RING_PTR(crq);
}

static void ubase_gen_bd_data(struct ubase_dev *udev, u32 bd_num,
			      void **msg_data, u32 msg_data_len)
{
	if (bd_num == 1) {
		ubase_gen_single_bd_data(udev, msg_data);
		return;
	}

	ubase_gen_multi_bd_data(udev, bd_num, msg_data, msg_data_len);
}

static bool ubase_cmd_crq_empty(struct ubase_dev *udev, struct ubase_hw *hw)
{
	hw->cmdq.crq.pi = ubase_read_dev(hw, UBASE_CRQ_TAIL_REG);

	return hw->cmdq.crq.pi == hw->cmdq.crq.ci;
}

void ubase_cmd_crq_handler(struct ubase_dev *udev)
{
	struct ubase_cmdq_ring *crq = &udev->hw.cmdq.crq;
	u32 msg_data_len;
	void *msg_data;
	u16 opcode;
	u8 bd_num;
	u8 flag;

	while (!ubase_cmd_crq_empty(udev, &udev->hw)) {
		if (test_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state)) {
			ubase_warn(udev,
				   "command queue needs re-initializing.\n");
			return;
		}

		opcode = crq->desc[crq->ci].opcode;
		bd_num = crq->desc[crq->ci].bd_num;
		flag = crq->desc[crq->ci].flag;
		msg_data_len = bd_num * sizeof(struct ubase_cmdq_desc) -
			       UBASE_CMD_HEADER_LENGTH;

		if (unlikely(!bd_num || !(flag & UBASE_CMD_FLAG_OUT))) {
			ubase_err(udev,
				  "drop invalid crq message, opcode = 0x%x, bd_num = %u, flag = 0x%x.",
				  opcode, bd_num, flag);
			UBASE_MOVE_CRQ_RING_PTR(crq);
			ubase_write_dev(&udev->hw, UBASE_CRQ_HEAD_REG, crq->ci);
			continue;
		}

		ubase_gen_bd_data(udev, bd_num, &msg_data, msg_data_len);

		if (ubase_is_arq_msg(opcode))
			ubase_add_to_arq(udev, opcode, msg_data, msg_data_len);
		else
			ubase_cmd_exec_callback(udev, opcode, msg_data,
						msg_data_len);

		ubase_free_bd_data(msg_data, bd_num);
		ubase_write_dev(&udev->hw, UBASE_CRQ_HEAD_REG, crq->ci);
	}

}

void ubase_crq_service_task(struct ubase_delay_work *ubase_work)
{
	struct ubase_dev *udev = container_of(ubase_work, struct ubase_dev,
				 service_task);
	struct ubase_crq_table *crq_table = &udev->crq_table;

	if (!test_and_clear_bit(UBASE_STATE_CRQ_SERVICE_SCHED,
				&udev->service_task.state) ||
		test_and_set_bit(UBASE_STATE_CRQ_HANDLING,
				 &udev->service_task.state))
		return;

	if (time_is_before_eq_jiffies(crq_table->last_crq_scheduled +
				      UBASE_CRQ_SCHED_TIMEOUT))
		ubase_warn(udev,
			   "crq service task is scheduled after %ums on cpu%d!\n",
			   jiffies_to_msecs(jiffies - crq_table->last_crq_scheduled),
			   smp_processor_id());

	ubase_cmd_crq_handler(udev);

	clear_bit(UBASE_STATE_CRQ_HANDLING, &udev->service_task.state);
}

static int ubase_cmd_wait_mbx_completed(struct ubase_dev *udev,
					union ubase_mbox *mbx)
{
	struct ubase_mbx_event_context *ctx = &udev->mb_cmd.ctx;
	struct ubase_irq_table *irq_table = &udev->irq_table;
	struct ubase_aeq *aeq = &irq_table->aeq;
	int ret;

	atomic_inc(&udev->mb_cmd.mbx_cnt);
	complete(&aeq->poll);
	if (!wait_for_completion_timeout(&ctx->done,
					 msecs_to_jiffies(UBASE_CMDQ_MBX_TX_TIMEOUT))) {
		ubase_err(udev,
			  "cmd seq_num 0x%x mailbox cmd code 0x%x timeout.\n",
			  ctx->seq_num, mbx->cmd);
		atomic_dec(&udev->mb_cmd.mbx_cnt);
		return -EBUSY;
	}

	ret = ctx->result;
	if (ret)
		ubase_err(udev,
			  "cmd seq_num(0x%x) mailbox cmd code(0x%x) error, ret = %d.\n",
			  ctx->seq_num, mbx->cmd, ret);

	atomic_dec(&udev->mb_cmd.mbx_cnt);

	return ret;
}

static void ubase_setup_mbx_info(struct ubase_dev *udev, union ubase_mbox *mbx)
{
	mbx->seq_num = ++udev->mb_cmd.ctx.seq_num;
	mbx->event_en = 1;
}

int ubase_post_mailbox_by_event(struct ubase_dev *udev,
				struct ubase_cmd_buf *in,
				struct ubase_cmd_buf *out,
				struct ubase_cmd_mailbox *mailbox)
{
	struct ubase_mbx_event_context *ctx = &udev->mb_cmd.ctx;
	union ubase_mbox *mbx = (union ubase_mbox *)in->data;
	unsigned long end;
	int ret;

	if (!mbx) {
		ubase_err(udev, "input mailbox data field is empty.\n");
		return -EINVAL;
	}

	if (ctx->mbx_buff) {
		ubase_err_rl(udev, udev->log_rs.mbx_buff_not_empty_cnt,
			     "Incomplete mailbox events exist.\n");
		return -EBUSY;
	}

	ubase_setup_mbx_info(udev, mbx);
	trace_ubase_alloc_mailbox_user(udev->dev, &mailbox->count, ctx->seq_num);
	if (atomic_inc_not_zero(&mailbox->count))
		ctx->mbx_buff = mailbox;

	trace_ubase_add_mailbox_count(udev->dev, &mailbox->count, ctx->seq_num);

	end = msecs_to_jiffies(UBASE_CMDQ_MBX_TX_TIMEOUT) + jiffies;
	while (1) {
		ret = __ubase_cmd_send_inout(udev, in, out);
		if (!ret)
			break;

		if (time_after(jiffies, end)) {
			dev_err_ratelimited(udev->dev,
					    "failed to wait mbox, ret = %d.\n",
					    ret);

			atomic_add_unless(&mailbox->count, -1, 0);
			return -ETIMEDOUT;
		}

		cond_resched();
	}

	return ubase_cmd_wait_mbx_completed(udev, mbx);
}

int __ubase_cmd_send_inout(struct ubase_dev *udev, struct ubase_cmd_buf *in,
			   struct ubase_cmd_buf *out)
{
	if (!in) {
		ubase_err(udev, "input buffer is empty.\n");
		return -EINVAL;
	}

	if (udev->reset_stage == UBASE_RESET_STAGE_UNINIT)
		return -EAGAIN;

	return ubase_cmd_send_inout_real(udev, in, out);
}

int __ubase_cmd_send_in(struct ubase_dev *udev, struct ubase_cmd_buf *in)
{
	struct ubase_cmd_buf out;

	out.data_size = 0;

	return __ubase_cmd_send_inout(udev, in, &out);
}

/**
 * ubase_cmd_send_inout_ex() - query(and write) cmd extension function
 * @aux_dev: auxiliary device
 * @in: the intput cmd buff
 * @out: the output cmd buff
 * @time_out: timeout duration, unit: ms
 *
 * When the timeout parameter is set to 0, this function behaves the same as
 * 'ubase_cmd_send_inout'. When the timeout parameter is not 0, if the cmdq
 * channel is disabled and it recovers within the timeout period, the cmdq can
 * still process commands normally.
 * This function is applicable to scenarios such as concurrent resets, where the
 * cmdq channel is first set to be disabled and then restored to normal operation.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_cmd_send_inout_ex(struct auxiliary_device *aux_dev,
			    struct ubase_cmd_buf *in, struct ubase_cmd_buf *out,
			    u32 time_out)
{
	struct ubase_dev *udev;
	u32 try_cnt = 0;

	if (!aux_dev || !in || !out)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(aux_dev);
	if (!time_out)
		return __ubase_cmd_send_inout(udev, in, out);

	while (test_bit(UBASE_STATE_CMD_DISABLE, &udev->hw.state) &&
	       (try_cnt * UBASE_CMDQ_WAIT_TIME) < time_out) {
		msleep(UBASE_CMDQ_WAIT_TIME);
		try_cnt++;
	}

	if ((try_cnt * UBASE_CMDQ_WAIT_TIME) >= time_out) {
		ubase_warn(udev,
			   "cmd send timeout, due to cmd enter disable state for %ums.\n",
			   try_cnt * UBASE_CMDQ_WAIT_TIME);
		return -EBUSY;
	}

	return __ubase_cmd_send_inout(udev, in, out);
}
EXPORT_SYMBOL(ubase_cmd_send_inout_ex);

/**
 * ubase_cmd_send_inout() - query(and write) cmd function
 * @aux_dev: auxiliary device
 * @in: the intput cmd buff
 * @out: the output cmd buff
 *
 * The firmware determines the processing behavior based on 'in->opcode'.
 * 'in->data_size' and 'in->data' represent the length of valid data and the
 * address where the data is stored for interaction with the firmware.
 * 'in->is_read' determines whether to read the query results.
 * 'out->data_size' and 'out->data' represent the length of valid data and the
 * address where the data is stored for the reading the query results.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_cmd_send_inout(struct auxiliary_device *aux_dev,
			 struct ubase_cmd_buf *in,
			 struct ubase_cmd_buf *out)
{
	if (!aux_dev || !in || !out)
		return -EINVAL;

	return __ubase_cmd_send_inout(__ubase_get_udev_by_adev(aux_dev), in, out);
}
EXPORT_SYMBOL(ubase_cmd_send_inout);

/**
 * ubase_cmd_send_in_ex() - write cmd extension function
 * @aux_dev: auxiliary device
 * @in: the intput cmd buff
 * @time_out: timeout duration, unit: ms
 *
 * When the timeout parameter is set to 0, this function behaves the same as
 * 'ubase_cmd_send_in'. When the timeout parameter is not 0, if the cmdq
 * channel is disabled and it recovers within the timeout period, the cmdq can
 * still process commands normally.
 * This function is applicable to scenarios such as concurrent resets, where the
 * cmdq channel is first set to disabled and then restored to normal operation.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_cmd_send_in_ex(struct auxiliary_device *aux_dev,
			 struct ubase_cmd_buf *in, u32 time_out)
{
	struct ubase_cmd_buf out;

	if (!aux_dev || !in)
		return -EINVAL;

	out.data_size = 0;

	return ubase_cmd_send_inout_ex(aux_dev, in, &out, time_out);
}
EXPORT_SYMBOL(ubase_cmd_send_in_ex);

/**
 * ubase_cmd_send_in() - write cmd function
 * @aux_dev: auxiliary device
 * @in: the intput cmd buff
 *
 * This function is only used for writing cmdq opcodes. 'in->is_read' must be
 * false. The firmware determines the processing behavior based on 'in->opcode'.
 * 'in->data_size' and 'in->data' represent the length of valid data and the
 * address where the data is stored for interaction with the firmware.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_cmd_send_in(struct auxiliary_device *aux_dev,
		      struct ubase_cmd_buf *in)
{
	if (!aux_dev || !in)
		return -EINVAL;

	return __ubase_cmd_send_in(__ubase_get_udev_by_adev(aux_dev), in);
}
EXPORT_SYMBOL(ubase_cmd_send_in);

static int __ubase_cmd_get_data_size(struct ubase_dev *udev, u16 opcode,
				     u16 *data_size)
{
	struct ubase_cmdq_desc desc;
	u8 bd_num;
	int ret;

	ubase_cmd_setup_basic_desc(&desc, opcode, true, 1);
	desc.flag |= UBASE_CMD_FLAG_GET_BD_NUM;

	ret = ubase_send_cmd(udev, &desc, 1);
	if (ret) {
		ubase_err(udev,
			  "failed to send cmd in get cmd data size, opcode = 0x%x, ret = %d.\n",
			  opcode, ret);
		return ret;
	}

	bd_num = *(u8 *)desc.data;
	if (unlikely(!bd_num)) {
		ubase_err(udev,
			  "failed to get cmd data size, bd_num = %u, opcode = 0x%x.\n",
			  bd_num, opcode);
		return -EIO;
	}

	*data_size = bd_num * sizeof(desc) - UBASE_CMD_HEADER_LENGTH;

	return 0;
}

/**
 * ubase_cmd_get_data_size() - obtain the valid data length from cmdq opcode
 * @aux_dev: auxiliary device
 * @opcode: cmdq opcode
 * @data_size: Save the valid data length of cmdq opcode
 *
 * For each opcode, the firmware has a corresponding valid data length.
 * This function queries the firmware to obtain the valid data length
 * corresponding to the opcode.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_cmd_get_data_size(struct auxiliary_device *aux_dev, u16 opcode,
			    u16 *data_size)
{
	if (!aux_dev || !data_size)
		return -EINVAL;

	return __ubase_cmd_get_data_size(__ubase_get_udev_by_adev(aux_dev),
					 opcode, data_size);
}
EXPORT_SYMBOL(ubase_cmd_get_data_size);

int __ubase_register_crq_event(struct ubase_dev *udev,
			       struct ubase_crq_event_nb *nb)
{
	struct ubase_crq_event_nbs *nbs, *tmp, *new_nbs;
	struct ubase_crq_table *crq_table;
	int ret;

	crq_table = &udev->crq_table;
	mutex_lock(&crq_table->lock);
	list_for_each_entry_safe(nbs, tmp, &crq_table->nbs.list, list) {
		if (unlikely(nbs->nb.opcode == nb->opcode)) {
			ret = -EEXIST;
			goto err_crq_register;
		}
	}

	new_nbs = kzalloc(sizeof(*new_nbs), GFP_KERNEL);
	if (!new_nbs) {
		ret = -ENOMEM;
		goto err_crq_register;
	}

	new_nbs->nb = *nb;
	list_add_tail(&new_nbs->list, &crq_table->nbs.list);
	mutex_unlock(&crq_table->lock);

	return 0;

err_crq_register:
	mutex_unlock(&crq_table->lock);

	ubase_err(udev, "failed to register crq event, opcode = 0x%x, ret = %d.\n",
		  nb->opcode, ret);
	return ret;
}

/**
 * ubase_register_crq_event() - register crq event processing function
 * @aux_dev: auxiliary device
 * @nb: the crq event notification block
 *
 * Register the crq handler function. When the firmware reports a crq event,
 * if the opcode reported by the firmware matches the registered 'nb->opcode',
 * the 'nb->crq_handler' function will be called to process it.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_register_crq_event(struct auxiliary_device *aux_dev,
			     struct ubase_crq_event_nb *nb)
{
	struct ubase_dev *udev;

	if (!aux_dev || !nb || !nb->crq_handler)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(aux_dev);
	return __ubase_register_crq_event(udev, nb);
}
EXPORT_SYMBOL(ubase_register_crq_event);

void __ubase_unregister_crq_event(struct ubase_dev *udev, u16 opcode)
{
	struct ubase_crq_event_nbs *nbs, *tmp;
	struct ubase_crq_table *crq_table;

	crq_table = &udev->crq_table;
	mutex_lock(&crq_table->lock);
	list_for_each_entry_safe(nbs, tmp, &crq_table->nbs.list, list) {
		if (nbs->nb.opcode == opcode) {
			list_del(&nbs->list);
			kfree(nbs);
			break;
		}
	}
	mutex_unlock(&crq_table->lock);
}

/**
 * ubase_unregister_crq_event() - unregister crq event processing function
 * @aux_dev: auxiliary device
 * @opcode: cmdq crq opcode
 *
 * Unregisters the crq processing function. This function is called when user
 * no longer want to handle the crq opcode events reported by the firmware.
 *
 * Context: Any context.
 */
void ubase_unregister_crq_event(struct auxiliary_device *aux_dev, u16 opcode)
{
	struct ubase_dev *udev;

	if (!aux_dev)
		return;

	udev = __ubase_get_udev_by_adev(aux_dev);
	__ubase_unregister_crq_event(udev, opcode);
}
EXPORT_SYMBOL(ubase_unregister_crq_event);

void ubase_mask_key_words(struct ubase_cmdq_desc *desc, u16 opc, int idx)
{
	struct ubase_cfg_dma_buf_req *req;
	union ubase_mbox *mb;

	switch (opc) {
	case UBASE_OPC_TP_TIMER_VA_CONFIG:
	case UBASE_OPC_TP_EXTDB_VA_CONFIG:
	case UBASE_OPC_TA_EXTDB_VA_CONFIG:
	case UBASE_OPC_TA_TIMER_VA_CONFIG:
		if (idx)
			return;
		req = (struct ubase_cfg_dma_buf_req *)desc->data;
		req->addr_l = 0;
		req->addr_h = 0;
		break;
	case UBASE_OPC_POST_MB:
		if (idx)
			return;
		mb = (union ubase_mbox *)desc->data;
		mb->in_param_l = 0;
		mb->in_param_h = 0;
		break;
	case UBASE_OPC_CFG_VPORT_BUF:
		if (idx)
			memset(desc, 0, sizeof(struct ubase_cmdq_desc));
		else
			memset(desc->data, 0, sizeof(desc->data));
		break;
	default:
		return;
	}
}
