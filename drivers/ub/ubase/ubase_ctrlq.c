// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/delay.h>

#include "ubase_dev.h"
#include "ubase_trace.h"
#include "ubase_ctrlq.h"

/* UNIC ctrlq msg white list */
static const struct ubase_ctrlq_event_nb ubase_ctrlq_wlist_unic[] = {
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_IP_ACL,
		.opcode = UBASE_CTRLQ_OPC_NOTIFY_IP,
	},
};

/* UDMA ctrlq msg white list */
static const struct ubase_ctrlq_event_nb ubase_ctrlq_wlist_udma[] = {
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_TP_ACL,
		.opcode = UBASE_CTRLQ_OPC_CHECK_TP_ACTIVE,
	},
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
		.opcode = UBASE_CTRLQ_OPC_UPDATE_SEID,
	},
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
		.opcode = UBASE_CTRLQ_OPC_UPDATE_UE_SEID_GUID,
	},
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
		.opcode = UBASE_CTRLQ_OPC_NOTIFY_RES_RATIO,
	},
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_TP_ACL,
		.opcode = UBASE_CTRLQ_OPC_TPID_DEL_DONE,
	},
};

/* CDMA ctrlq msg white list */
static const struct ubase_ctrlq_event_nb ubase_ctrlq_wlist_cdma[] = {
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
		.opcode = UBASE_CTRLQ_OPC_UPDATE_SEID,
	},
};

static int ubase_ctrlq_alloc_crq_tbl_mem(struct ubase_dev *udev)
{
	struct ubase_ctrlq_crq_table *crq_tab = &udev->ctrlq.crq_table;
	u16 cnt = 0;

	if (ubase_dev_cdma_supported(udev)) {
		cnt = ARRAY_SIZE(ubase_ctrlq_wlist_cdma);
	} else if (ubase_dev_urma_supported(udev)) {
		if (ubase_dev_unic_supported(udev))
			cnt += ARRAY_SIZE(ubase_ctrlq_wlist_unic);
		if (ubase_dev_udma_supported(udev))
			cnt += ARRAY_SIZE(ubase_ctrlq_wlist_udma);
	}

	if (!cnt)
		return -EINVAL;

	crq_tab->crq_nbs = kcalloc(cnt, sizeof(struct ubase_ctrlq_event_nb), GFP_KERNEL);
	if (!crq_tab->crq_nbs)
		return -ENOMEM;

	crq_tab->crq_nb_cnt = cnt;

	return 0;
}

static void ubase_ctrlq_free_crq_tbl_mem(struct ubase_dev *udev)
{
	struct ubase_ctrlq_crq_table *crq_tab = &udev->ctrlq.crq_table;

	kfree(crq_tab->crq_nbs);
	crq_tab->crq_nbs = NULL;
	crq_tab->crq_nb_cnt = 0;
}

static void ubase_ctrlq_init_crq_wlist(struct ubase_dev *udev)
{
	struct ubase_ctrlq_crq_table *crq_tab = &udev->ctrlq.crq_table;
	u32 offset = 0;

	if (ubase_dev_cdma_supported(udev)) {
		memcpy(crq_tab->crq_nbs, ubase_ctrlq_wlist_cdma,
		       sizeof(ubase_ctrlq_wlist_cdma));
	} else if (ubase_dev_urma_supported(udev)) {
		if (ubase_dev_unic_supported(udev)) {
			memcpy(crq_tab->crq_nbs, ubase_ctrlq_wlist_unic,
			       sizeof(ubase_ctrlq_wlist_unic));
			offset = ARRAY_SIZE(ubase_ctrlq_wlist_unic);
		}
		if (ubase_dev_udma_supported(udev)) {
			memcpy(&crq_tab->crq_nbs[offset], ubase_ctrlq_wlist_udma,
			       sizeof(ubase_ctrlq_wlist_udma));
		}
	}
}

static int ubase_ctrlq_table_init(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ue_resp_table *ue_resp_tab = &udev->ctrlq.ue_resp_table;
	struct ubase_ctrlq_ue_req_table *ue_req_tab = &udev->ctrlq.ue_req_table;
	struct ubase_ctrlq_crq_table *crq_tab = &udev->ctrlq.crq_table;
	int ret;

	ret = ubase_ctrlq_alloc_crq_tbl_mem(udev);
	if (ret)
		return ret;

	ubase_ctrlq_init_crq_wlist(udev);

	mutex_init(&crq_tab->lock);
	mutex_init(&ue_req_tab->lock);
	mutex_init(&ue_resp_tab->lock);
	INIT_LIST_HEAD(&ue_req_tab->ue_req_nbs.list);
	INIT_LIST_HEAD(&ue_resp_tab->ue_resp_nbs.list);

	return 0;
}

static void ubase_ctrlq_table_uninit(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ue_resp_table *ue_resp_tab = &udev->ctrlq.ue_resp_table;
	struct ubase_ctrlq_ue_req_table *ue_req_tab = &udev->ctrlq.ue_req_table;
	struct ubase_ctrlq_crq_table *crq_tab = &udev->ctrlq.crq_table;

	mutex_destroy(&ue_resp_tab->lock);
	mutex_destroy(&ue_req_tab->lock);
	mutex_destroy(&crq_tab->lock);

	ubase_ctrlq_free_crq_tbl_mem(udev);
}

static inline u32 ubase_ctrlq_msg_queue_depth(struct ubase_dev *udev)
{
	return (u32)udev->ctrlq.csq.depth << 1;
}

static inline u16 ubase_ctrlq_max_seq(struct ubase_dev *udev)
{
	return U16_MAX >> 1;
}

static int ubase_ctrlq_msg_queue_init(struct ubase_dev *udev)
{
	u16 msg_ctx_size = sizeof(struct ubase_ctrlq_msg_ctx);
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;
	u32 i;

	udev->ctrlq.msg_queue = kcalloc(depth, msg_ctx_size, GFP_KERNEL);
	if (!udev->ctrlq.msg_queue) {
		ubase_err(udev, "failed to alloc ctrlq msg queue.\n");
		return -ENOMEM;
	}

	for (i = 0; i < depth; i++) {
		ctx = &udev->ctrlq.msg_queue[i];
		init_completion(&ctx->done);
	}

	return 0;
}

static void ubase_ctrlq_msg_queue_uninit(struct ubase_dev *udev)
{
	kfree(udev->ctrlq.msg_queue);
	udev->ctrlq.msg_queue = NULL;
}

static int ubase_ctrlq_map_queue(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;
	u32 addr_h, addr_l;
	u64 queue_addr;
	size_t size;

	if (!ubase_dev_ctrlq_supported(udev))
		return 0;

	addr_h = ubase_read_dev(&udev->hw, UBASE_CTRLQ_CSQ_BASEADDR_H_REG);
	addr_l = ubase_read_dev(&udev->hw, UBASE_CTRLQ_CSQ_BASEADDR_L_REG);
	queue_addr = ubase_addr_gen(addr_h, addr_l);
	size = csq->depth * UBASE_CTRLQ_BB_LEN;
	csq->base_addr = devm_ioremap(udev->dev, queue_addr, size);
	if (!csq->base_addr) {
		ubase_err(udev, "failed to map ctrlq csq base addr, size = %lu.\n",
			  size);
		return -ENOMEM;
	}

	addr_h = ubase_read_dev(&udev->hw, UBASE_CTRLQ_CRQ_BASEADDR_H_REG);
	addr_l = ubase_read_dev(&udev->hw, UBASE_CTRLQ_CRQ_BASEADDR_L_REG);
	queue_addr = ubase_addr_gen(addr_h, addr_l);
	size = crq->depth * UBASE_CTRLQ_BB_LEN;
	crq->base_addr = devm_ioremap(udev->dev, queue_addr, size);
	if (!crq->base_addr) {
		ubase_err(udev, "failed to map ctrlq crq base addr, size = %lu.\n",
			  size);
		goto err_map_crq;
	}

	return 0;

err_map_crq:
	devm_iounmap(udev->dev, csq->base_addr);
	csq->base_addr = NULL;
	return -ENOMEM;
}

static void ubase_ctrlq_unmap_queue(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;

	if (!ubase_dev_ctrlq_supported(udev))
		return;

	if (csq->base_addr) {
		devm_iounmap(udev->dev, csq->base_addr);
		csq->base_addr = NULL;
	}

	if (crq->base_addr) {
		devm_iounmap(udev->dev, crq->base_addr);
		crq->base_addr = NULL;
	}
}

static void ubase_ctrlq_queue_pi_ci_init(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;
	u16 crq_hw_pi;

	if (!ubase_dev_ctrlq_supported(udev))
		return;

	csq->pi = ubase_read_dev(&udev->hw, UBASE_CTRLQ_CSQ_TAIL_REG);
	csq->ci = ubase_read_dev(&udev->hw, UBASE_CTRLQ_CSQ_HEAD_REG);

	crq_hw_pi = ubase_read_dev(&udev->hw, UBASE_CTRLQ_CRQ_TAIL_REG);
	ubase_write_dev(&udev->hw, UBASE_CTRLQ_CRQ_HEAD_REG, crq_hw_pi);
	crq->pi = crq_hw_pi;
	crq->ci = crq_hw_pi;
}

static int ubase_query_ctrlq_queue_info(struct ubase_dev *udev)
{
#define UBASE_CTRLQ_QUEUE_DEFAULT	2048

	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;

	csq->depth = UBASE_CTRLQ_QUEUE_DEFAULT;
	crq->depth = UBASE_CTRLQ_QUEUE_DEFAULT;

	return 0;
}

static int ubase_ctrlq_get_queue_depth(struct ubase_dev *udev)
{
#define ubase_reg_val_to_depth(a) ((a) << 3)

	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;
	u16 reg_val;

	if (!ubase_dev_ctrlq_supported(udev))
		return ubase_query_ctrlq_queue_info(udev);

	reg_val = (u16)ubase_read_dev(&udev->hw, UBASE_CTRLQ_CSQ_DEPTH_REG);
	csq->depth = ubase_reg_val_to_depth(reg_val);
	if (!csq->depth) {
		ubase_err(udev, "the csq depth is 0.\n");
		return -EINVAL;
	}

	reg_val = (u16)ubase_read_dev(&udev->hw, UBASE_CTRLQ_CRQ_DEPTH_REG);
	crq->depth = ubase_reg_val_to_depth(reg_val);
	if (!crq->depth) {
		ubase_err(udev, "the crq depth is 0.\n");
		return -EINVAL;
	}

	return 0;
}

static int ubase_ctrlq_queue_init(struct ubase_dev *udev)
{
#define CTRLQ_TX_TIMEOUT 3000

	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;
	int ret;

	spin_lock_init(&csq->lock);
	spin_lock_init(&crq->lock);
	spin_lock_init(&udev->ctrlq.send_lock);

	ret = ubase_ctrlq_get_queue_depth(udev);
	if (ret) {
		ubase_err(udev, "failed to get queue depth, ret = %d.\n",
			  ret);
		return ret;
	}

	csq->tx_timeout = CTRLQ_TX_TIMEOUT;
	ubase_ctrlq_queue_pi_ci_init(udev);

	ret = ubase_ctrlq_map_queue(udev);
	if (ret)
		ubase_err(udev, "failed to map ctrlq queue, ret = %d.\n",
			  ret);

	return ret;
}

static void ubase_ctrlq_queue_uninit(struct ubase_dev *udev)
{
	ubase_ctrlq_unmap_queue(udev);
}

int ubase_ctrlq_init(struct ubase_dev *udev)
{
#define UBASE_CTRLQ_SEM_VAL	8

	int ret;

	if (test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		ubase_ctrlq_queue_pi_ci_init(udev);
		goto success;
	}

	ret = ubase_ctrlq_queue_init(udev);
	if (ret)
		return ret;

	ret = ubase_ctrlq_msg_queue_init(udev);
	if (ret)
		goto err_msg_queue_init;

	ret = ubase_ctrlq_table_init(udev);
	if (ret)
		goto err_table_init;

	udev->ctrlq.csq_next_seq = 1;
	udev->ctrlq.last_clean_idx = 0;
	atomic_set(&udev->ctrlq.req_cnt, 0);
	sema_init(&udev->ctrlq.sem, UBASE_CTRLQ_SEM_VAL);
	sema_init(&udev->ctrlq.msg_queue_sem, ubase_ctrlq_msg_queue_depth(udev));

success:
	set_bit(UBASE_CTRLQ_STATE_ENABLE, &udev->ctrlq.state);
	return 0;

err_table_init:
	ubase_ctrlq_msg_queue_uninit(udev);
err_msg_queue_init:
	ubase_ctrlq_queue_uninit(udev);
	return ret;
}

static void ubase_ctrlq_clean_msg_queue(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;
	u32 i;

	spin_lock_bh(&csq->lock);
	for (i = 0; i < depth; i++) {
		ctx = &udev->ctrlq.msg_queue[i];
		ctx->valid = 0;
	}
	spin_unlock_bh(&csq->lock);
}

void ubase_ctrlq_disable_remote(struct ubase_dev *udev)
{
	struct ubase_ctrlq_chan_ctrl_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	u32 resp;
	int ret;

	if (!ubase_dev_ctrlq_supported(udev) ||
	    (ubase_shutting_down(udev) && ubase_is_ctrl_node(udev)))
		return;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	msg.opcode = UBASE_CTRLQ_OPC_CTRLQ_CTRL;
	msg.need_resp = 1;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(resp);
	msg.out = &resp;
	req.opc = UBASE_CTRLQ_CHAN_DISABLE_OPC;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret)
		ubase_err(udev, "failed to disable remote ctrlq, ret = %d.\n",
			  ret);
}

static void ubase_ctrlq_clean_pending_msgs(struct ubase_dev *udev)
{
#define UBASE_CTRLQ_CLEAN_WAIT_TIME	5

	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;
	u32 i;

	spin_lock_bh(&csq->lock);
	for (i = 0; i < depth; i++) {
		ctx = &udev->ctrlq.msg_queue[i];
		if (!completion_done(&ctx->done))
			complete(&ctx->done);
	}
	spin_unlock_bh(&csq->lock);

	while (atomic_read(&udev->ctrlq.req_cnt))
		msleep(UBASE_CTRLQ_CLEAN_WAIT_TIME);
}

void ubase_ctrlq_disable(struct ubase_dev *udev)
{
#define UBASE_CTRLQ_CLEAR_WAIT_TIME	5

	if (!test_and_clear_bit(UBASE_CTRLQ_STATE_ENABLE, &udev->ctrlq.state))
		return;

	/* wait to ensure that the crq completes the possible left
	 * over commands.
	 */
	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		while (test_bit(UBASE_STATE_CTRLQ_HANDLING,
		       &udev->service_task.state))
			msleep(UBASE_CTRLQ_CLEAR_WAIT_TIME);
	}

	ubase_ctrlq_clean_pending_msgs(udev);
}

void ubase_ctrlq_uninit(struct ubase_dev *udev)
{
	if (udev->reset_stage != UBASE_RESET_STAGE_UNINIT)
		ubase_ctrlq_disable(udev);

	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		ubase_ctrlq_table_uninit(udev);
		ubase_ctrlq_msg_queue_uninit(udev);
		ubase_ctrlq_queue_uninit(udev);
	} else {
		ubase_ctrlq_clean_msg_queue(udev);
	}
}

static u16 ubase_ctrlq_calc_bb_num(u16 in_size)
{
	u16 data_size = in_size > UBASE_CTRLQ_DATA_LEN ?
			in_size - UBASE_CTRLQ_DATA_LEN : 0;

	return (DIV_ROUND_UP(data_size, UBASE_CTRLQ_BB_LEN) + 1);
}

static u16 ubase_ctrlq_remain_space(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	u16 used;

	used = (csq->pi - csq->ci + csq->depth) % csq->depth;

	return csq->depth - used - 1;
}

static void ubase_ctrlq_fill_first_bb(struct ubase_dev *udev,
				      struct ubase_ctrlq_base_block *head,
				      struct ubase_ctrlq_msg *msg,
				      struct ubase_ctrlq_ue_info *ue_info)
{
	struct ub_entity *ue = to_ub_entity(udev->dev);

	head->service_ver = msg->service_ver;
	head->service_type = msg->service_type;
	head->opcode = msg->opcode;
	head->mbx_ue_id = ue_info ? ue_info->mbx_ue_id : 0;
	head->ret = ubase_ctrlq_msg_is_resp(msg) ? msg->resp_ret : 0;
	head->bus_ue_id = cpu_to_le16(ue_info ?
				      ue_info->bus_ue_id :
				      ue->entity_idx);
	if (msg->in)
		memcpy(head->data, msg->in,
		       min(msg->in_size, UBASE_CTRLQ_DATA_LEN));
}

static inline void ubase_ctrlq_csq_report_irq(struct ubase_dev *udev)
{
#define UBASE_CTRLQ_CSQ_IRQ_EN	BIT(16)
#define UBASE_CTRLQ_CSQ_IRQ_VEC_IDX	0

	u32 val = UBASE_CTRLQ_CSQ_IRQ_EN | UBASE_CTRLQ_CSQ_IRQ_VEC_IDX;

	ubase_write_reg(udev->hw.rs0_base.addr, 0, val);
}

static int ubase_ctrlq_send_to_cmdq(struct ubase_dev *udev,
				    struct ubase_ctrlq_base_block *head,
				    struct ubase_ctrlq_msg *msg, u8 num)
{
	u32 req_len = msg->in_size + sizeof(struct ubase_ue2ue_ctrlq_head) +
		      UBASE_CTRLQ_HDR_LEN;
	struct ubase_ue2ue_ctrlq_head ue2ue_head = {0};
	u16 seq = le16_to_cpu(head->seq);
	struct ubase_cmd_buf in;
	void *req;
	int ret;

	req = kzalloc(req_len, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	ue2ue_head.head.sub_cmd = UBASE_UE2UE_CTRLQ_MSG;
	ue2ue_head.seq = seq;
	ue2ue_head.in_size = msg->in_size;
	ue2ue_head.out_size = msg->out_size;
	ue2ue_head.need_resp = msg->need_resp;
	ue2ue_head.is_resp = msg->is_resp;
	ue2ue_head.is_async = msg->is_async;
	memcpy(req, &ue2ue_head, sizeof(ue2ue_head));
	memcpy((u8 *)req + sizeof(ue2ue_head), head, UBASE_CTRLQ_HDR_LEN);
	if (msg->in)
		memcpy((u8 *)req + sizeof(ue2ue_head) + UBASE_CTRLQ_HDR_LEN,
		       msg->in, msg->in_size);

	__ubase_fill_inout_buf(&in, UBASE_OPC_UE2UE_UBASE, false, req_len, req);
	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_err_rl(udev, ue_send_ctrlq_to_cmdq_fail,
			     "failed to send ue2ue ctrlq msg, seq = %u, ret = %d.\n",
			     seq, ret);

	kfree(req);
	return ret;
}

static inline void
ubase_fill_ctrlq_trace_info(struct ubase_ctrlq_trace_info *trace_info,
			    struct ubase_ctrlq_ring *ctrlq, u8 num,
			    u16 bus_ue_id)
{
	trace_info->pi = ctrlq->pi;
	trace_info->ci = ctrlq->ci;
	trace_info->num = num;
	trace_info->bus_ue_id = bus_ue_id;
}

static void ubase_ctrlq_send_to_csq(struct ubase_dev *udev,
				    struct ubase_ctrlq_base_block *head,
				    struct ubase_ctrlq_msg *msg, u8 num)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_trace_info trace_info = {0};
	u16 bus_ue_id = le16_to_cpu(head->bus_ue_id);
	u32 total_size = msg->in_size;
	u32 size, offset = 0;
	u8 cnt = 0;
	u8 *addr;

	ubase_fill_ctrlq_trace_info(&trace_info, csq, num, bus_ue_id);
	while (cnt < num) {
		addr = csq->base_addr + csq->pi * UBASE_CTRLQ_BB_LEN;
		if (cnt == 0) {
			memcpy_toio(addr, head, sizeof(*head));
			trace_ubase_ctrlq_csq(udev->dev, &trace_info,
					      head, sizeof(*head));
			total_size -= UBASE_CTRLQ_DATA_LEN;
			offset += UBASE_CTRLQ_DATA_LEN;
		} else {
			size = min_t(u32, total_size, UBASE_CTRLQ_BB_LEN);
			memcpy_toio(addr, (u8 *)msg->in + offset, size);
			trace_ubase_ctrlq_csq(udev->dev, &trace_info,
					      (u8 *)msg->in + offset,
					      size);
			total_size -= size;
			offset += size;
		}
		csq->pi++;
		if (csq->pi >= csq->depth)
			csq->pi = 0;
		trace_info.pi = csq->pi;

		cnt++;
	}

	ubase_write_dev(&udev->hw, UBASE_CTRLQ_CSQ_TAIL_REG, csq->pi);
	ubase_ctrlq_csq_report_irq(udev);
}

static int ubase_ctrlq_send_msg_to_sq(struct ubase_dev *udev,
				      struct ubase_ctrlq_base_block *head,
				      struct ubase_ctrlq_msg *msg, u8 num)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	int ret;

	if (ubase_dev_ctrlq_supported(udev)) {
		spin_lock_bh(&udev->ctrlq.send_lock);

		csq->ci = (u16)ubase_read_dev(&udev->hw, UBASE_CTRLQ_CSQ_HEAD_REG);
		if (num > ubase_ctrlq_remain_space(udev)) {
			spin_unlock_bh(&udev->ctrlq.send_lock);
			ubase_warn_rl(udev, ctrlq_space_insuffice,
				      "no enough space in ctrlq, ci = %u, num = %u.\n",
				      csq->ci, num);
			return -EBUSY;
		}

		ubase_ctrlq_send_to_csq(udev, head, msg, num);

		spin_unlock_bh(&udev->ctrlq.send_lock);
		return 0;
	}

	down(&udev->ctrlq.sem);
	ret = ubase_ctrlq_send_to_cmdq(udev, head, msg, num);
	up(&udev->ctrlq.sem);

	return ret;
}

static int ubase_ctrlq_wait_completed(struct ubase_dev *udev, u16 seq,
				      struct ubase_ctrlq_msg *msg, u32 timeout)
{
#define UBASE_CTRLQ_TIMEOUT_CASE_SHUT_DOWN 500

	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;
	int ret;

	ctx = &udev->ctrlq.msg_queue[seq % depth];
	if (!wait_for_completion_timeout(&ctx->done,
					 msecs_to_jiffies(timeout))) {
		ubase_err_rl(udev, ctrlq_wait_resp_timeout,
			     "ctrlq wait resp timeout, seq = %u, opcode = 0x%x, service_type = 0x%x.\n",
			     seq, msg->opcode, msg->service_type);
		return -ETIMEDOUT;
	}

	ret = ctx->result;
	if (ret)
		ubase_dbg(udev,
			  "ctrlq recv failed resp for seq = %u, opcode = 0x%x, service_type = 0x%x, ret = %d.\n",
			  seq, msg->opcode, msg->service_type, ret);

	return -ret;
}

static int ubase_ctrlq_alloc_seq(struct ubase_dev *udev, u16 *seq)
{
	struct ubase_ctrlq_msg_ctx *ctx = udev->ctrlq.msg_queue;
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	u16 max_seq = ubase_ctrlq_max_seq(udev);
	u16 next_seq = udev->ctrlq.csq_next_seq;
	u32 i, loop = 0;

	for (i = next_seq; i <= max_seq && loop < depth; i++, loop++) {
		if (!ctx[i % depth].valid)
			goto success;
	}

	/* seq 0 is not used. */
	for (i = 1; i < next_seq && loop < depth; i++, loop++) {
		if (!ctx[i % depth].valid)
			goto success;
	}

	return -EBUSY;

success:
	*seq = i;
	udev->ctrlq.csq_next_seq = i + 1;

	return 0;
}

static void ubase_ctrlq_free_seq(struct ubase_dev *udev, u16 seq)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;

	spin_lock_bh(&csq->lock);
	ctx = &udev->ctrlq.msg_queue[seq % depth];
	ctx->valid = 0;
	spin_unlock_bh(&csq->lock);
}

static void ubase_ctrlq_addto_msg_queue(struct ubase_dev *udev, u16 seq,
					struct ubase_ctrlq_msg *msg,
					struct ubase_ctrlq_ue_info *ue_info)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;
	unsigned int dead_time;

	if (!(ubase_ctrlq_msg_is_sync_req(msg) ||
	      ubase_ctrlq_msg_is_async_req(msg)))
		return;

	dead_time = UBASE_CTRLQ_DEAD_TIME(msg->timeout ? msg->timeout : csq->tx_timeout);
	ctx = &udev->ctrlq.msg_queue[seq % depth];
	ctx->valid = 1;
	ctx->is_sync = ubase_ctrlq_msg_is_sync_req(msg) ? 1 : 0;
	ctx->result = ETIME;
	ctx->dead_jiffies = jiffies + msecs_to_jiffies(dead_time);
	ctx->out = msg->out;
	ctx->out_size = msg->out_size;

	if (ue_info) {
		ctx->ue_seq = ue_info->seq;
		ctx->bus_ue_id = ue_info->bus_ue_id;
	}
	reinit_completion(&ctx->done);
}

static int ubase_ctrlq_msg_check(struct ubase_dev *udev,
				 struct ubase_ctrlq_msg *msg)
{
	if ((!msg->in && msg->in_size) || (msg->in && !msg->in_size)) {
		ubase_err(udev, "ctrlq msg in param error.\n");
		return -EINVAL;
	}

	if ((!msg->out && msg->out_size) || (msg->out && !msg->out_size)) {
		ubase_err(udev, "ctrlq msg out param error.\n");
		return -EINVAL;
	}

	if (msg->in_size > UBASE_CTRLQ_MAX_DATA_SIZE) {
		ubase_err(udev,
			  "ctrlq msg in_size(%u) exceeds the maximum(%u).\n",
			  msg->in_size, UBASE_CTRLQ_MAX_DATA_SIZE);
		return -EINVAL;
	}

	if (ubase_ctrlq_msg_is_sync_req(msg))
		return 0;

	if (ubase_ctrlq_msg_is_async_req(msg)) {
		if (msg->out) {
			ubase_err(udev, "ctrlq msg out is not NULL in async req.\n");
			return -EINVAL;
		}
		return 0;
	}

	if (ubase_ctrlq_msg_is_notify_req(msg)) {
		if (msg->out) {
			ubase_err(udev, "ctrlq msg out is not NULL in notify req.\n");
			return -EINVAL;
		}
		return 0;
	}

	if (ubase_ctrlq_msg_is_resp(msg)) {
		if (msg->out) {
			ubase_err(udev, "ctrlq msg out is not NULL in resp.\n");
			return -EINVAL;
		}
		if (!(msg->resp_seq & UBASE_CTRLQ_SEQ_MASK)) {
			ubase_err(udev, "ctrlq msg resp_seq error, resp_seq=%u.\n",
				  msg->resp_seq);
			return -EINVAL;
		}
		return 0;
	}

	ubase_err(udev, "ctrlq msg param error, is_resp=%u, is_async=%u, need_resp=%u.\n",
		  msg->is_resp, msg->is_async, msg->need_resp);
	return -EINVAL;
}

static int ubase_ctrlq_check_send_state(struct ubase_dev *udev,
					struct ubase_ctrlq_msg *msg)
{
	if (udev->reset_stage == UBASE_RESET_STAGE_UNINIT &&
	    !(msg->opcode == UBASE_CTRLQ_OPC_CTRLQ_CTRL &&
	      msg->service_type == UBASE_CTRLQ_SER_TYPE_DEV_REGISTER)) {
		ubase_dbg(udev, "ctrlq send is disabled.\n");
		return -EAGAIN;
	}

	if (!test_bit(UBASE_CTRLQ_STATE_ENABLE, &udev->ctrlq.state)) {
		ubase_warn_rl(udev, ctrlq_is_disabled,
			      "ctrlq is disabled in csq.\n");
		return -EAGAIN;
	}

	return 0;
}

static int ubase_ctrlq_acquire_send_resources(struct ubase_dev *udev,
					      struct ubase_ctrlq_msg *msg,
					      struct ubase_ctrlq_ue_info *ue_info,
					      u16 *seq)
{
#define CTRLQ_MSG_QUEUE_WAIT_MS 10000

	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	int ret;

	if (!ubase_ctrlq_msg_is_resp(msg)) {
		if (down_timeout(&udev->ctrlq.msg_queue_sem,
				 (long)msecs_to_jiffies(CTRLQ_MSG_QUEUE_WAIT_MS))) {
			ubase_err_rl(udev, ctrlq_msg_queue_wait_timeout,
				     "ctrlq msg queue wait timeout.\n");
			return -EBUSY;
		}
	}

	spin_lock_bh(&csq->lock);

	if (!ubase_ctrlq_msg_is_resp(msg)) {
		ret = ubase_ctrlq_alloc_seq(udev, seq);
		if (ret) {
			spin_unlock_bh(&csq->lock);
			up(&udev->ctrlq.msg_queue_sem);
			ubase_warn_rl(udev, ctrlq_seq_insuffice,
				      "no enough seq in ctrlq.\n");
			return ret;
		}
	} else {
		*seq = msg->resp_seq;
	}

	ubase_ctrlq_addto_msg_queue(udev, *seq, msg, ue_info);

	spin_unlock_bh(&csq->lock);

	return 0;
}

static void ubase_ctrlq_release_send_resources(struct ubase_dev *udev,
					       struct ubase_ctrlq_msg *msg,
					       u16 seq, int pret)
{
	if (pret) {
		if (!ubase_ctrlq_msg_is_resp(msg)) {
			ubase_ctrlq_free_seq(udev, seq);
			up(&udev->ctrlq.msg_queue_sem);
		}
	} else {
		if (ubase_ctrlq_msg_is_sync_req(msg) ||
		    ubase_ctrlq_msg_is_notify_req(msg)) {
			ubase_ctrlq_free_seq(udev, seq);
			up(&udev->ctrlq.msg_queue_sem);
		}
	}
}

static u32 ubase_ctrlq_get_send_timeout(struct ubase_dev *udev,
					struct ubase_ctrlq_msg *msg)
{
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;

	if (ubase_shutting_down(udev) && ubase_is_ctrl_node(udev))
		return UBASE_CTRLQ_TIMEOUT_CASE_SHUT_DOWN;

	return msg->timeout ? msg->timeout : csq->tx_timeout;
}

static bool ubase_ctrlq_send_error_retry(int ret, bool need_retry)
{
	return (ret == -ETIMEDOUT || ret == -ENOSPC || ret == -EBUSY) && need_retry;
}

static int ubase_ctrlq_do_send_with_retry(struct ubase_dev *udev,
					  struct ubase_ctrlq_msg *msg,
					  struct ubase_ctrlq_base_block *head,
					  bool need_retry)
{
	u32 timeout = ubase_ctrlq_get_send_timeout(udev, msg);
	u16 seq = le16_to_cpu(head->seq);
	u16 retry = 0;
	int ret;

	do {
		if (retry)
			ubase_dbg(udev, "ctrlq send msg retry = %u.\n", retry);

		ret = ubase_ctrlq_check_send_state(udev, msg);
		if (ret)
			return ret;

		ret = ubase_ctrlq_send_msg_to_sq(udev, head, msg, head->bb_num);
		if (ubase_ctrlq_send_error_retry(ret, need_retry))
			msleep(timeout);
		else if (ret)
			return ret;
		else if (ubase_ctrlq_msg_is_sync_req(msg))
			ret = ubase_ctrlq_wait_completed(udev, seq, msg, timeout);

		if (ubase_shutting_down(udev) && ubase_is_ctrl_node(udev))
			break;
	} while (ubase_ctrlq_send_error_retry(ret, need_retry) &&
		 retry++ < UBASE_CTRLQ_RETRY_TIMES);

	return ret;
}

static int ubase_ctrlq_do_send(struct ubase_dev *udev,
			       struct ubase_ctrlq_msg *msg,
			       u16 num, bool need_retry,
			       struct ubase_ctrlq_ue_info *ue_info)
{
	struct ubase_ctrlq_base_block head = {0};
	u16 seq;
	int ret;

	ret = ubase_ctrlq_acquire_send_resources(udev, msg, ue_info, &seq);
	if (ret)
		return ret;

	head.bb_num = num;
	head.seq = cpu_to_le16(seq);
	ubase_ctrlq_fill_first_bb(udev, &head, msg, ue_info);

	ret = ubase_ctrlq_do_send_with_retry(udev, msg, &head, need_retry);

	ubase_ctrlq_release_send_resources(udev, msg, seq, ret);

	return ret;
}

int __ubase_ctrlq_send(struct ubase_dev *udev, struct ubase_ctrlq_msg *msg,
		       bool need_retry, struct ubase_ctrlq_ue_info *ue_info)
{
	int ret;
	u16 num;

	if (!test_bit(UBASE_CTRLQ_STATE_ENABLE, &udev->ctrlq.state)) {
		dev_warn_ratelimited(udev->dev, "ctrlq is disabled.\n");
		return -EAGAIN;
	}

	ret = ubase_ctrlq_msg_check(udev, msg);
	if (ret)
		return ret;

	num = ubase_ctrlq_calc_bb_num(msg->in_size);

	atomic_inc(&udev->ctrlq.req_cnt);
	ret = ubase_ctrlq_do_send(udev, msg, num, need_retry, ue_info);
	atomic_dec(&udev->ctrlq.req_cnt);

	return ret;
}

/**
 * ubase_ctrlq_send_msg() - ctrlq message send function
 * @aux_dev: auxiliary device
 * @msg: the message to be sent
 *
 * The driver uses this function to send a ctrlq message to the management software.
 * The management software determines the module responsible for processing the message
 * based on 'msg->service_ver', 'msg->service_type', and 'msg->opcode';
 * it also retrieves the length and content of the data to be sent from
 * 'msg->in_size' and 'msg->in'.
 * When 'msg->is_resp' is set to 1, it indicates that the message is a response
 * to a ctrlq message from the management software. 'msg->resp_seq' and 'msg->resp_ret'
 * represent the sequence number and processing result of the ctrlq message from
 * the management software.
 * When 'msg->is_async' is set to 1, it indicates that the message is an asynchronous
 * request. When 'msg->need_resp' is set to 1, it indicates that the management software
 * needs to respond to the driver's ctrlq message. If 'msg->is_async' is set to 0 and
 * 'msg->need_resp' is set to 1, this function will wait synchronously for the management
 * software's response. The response information will be stored in 'msg->out'.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_ctrlq_send_msg(struct auxiliary_device *aux_dev,
			 struct ubase_ctrlq_msg *msg)
{
	if (!aux_dev || !msg)
		return -EINVAL;

	return __ubase_ctrlq_send(__ubase_get_udev_by_adev(aux_dev), msg, true,
				  NULL);
}
EXPORT_SYMBOL(ubase_ctrlq_send_msg);

static bool ubase_ctrlq_crq_is_empty(struct ubase_dev *udev, struct ubase_hw *hw)
{
	udev->ctrlq.crq.pi = ubase_read_dev(hw, UBASE_CTRLQ_CRQ_TAIL_REG);

	if (unlikely(udev->ctrlq.crq.pi >= udev->ctrlq.crq.depth)) {
		ubase_err_rl(udev, ctrlq_crq_pi_invalid,
			     "ctrlq crq pi exceeds depth, pi=%hu, depth=%hu.\n",
			     udev->ctrlq.crq.pi, udev->ctrlq.crq.depth);
		return true;
	}

	return udev->ctrlq.crq.pi == udev->ctrlq.crq.ci;
}

static void ubase_ctrlq_update_crq_ci(struct ubase_dev *udev, u8 bb_num)
{
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;

	crq->ci = (crq->ci + bb_num) % crq->depth;
	ubase_write_dev(&udev->hw, UBASE_CTRLQ_CRQ_HEAD_REG, crq->ci);
}

static void ubase_ctrlq_read_msg_data(struct ubase_dev *udev, u8 num, u8 *msg)
{
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;
	struct ubase_ctrlq_trace_info trace_info = {0};
	struct ubase_ctrlq_base_block *head;
	u16 pos = crq->ci, bus_ue_id;
	u8 i;

	for (i = 0; i < num; i++) {
		memcpy_fromio(msg + i * UBASE_CTRLQ_BB_LEN,
			      (u8 *)crq->base_addr + pos * UBASE_CTRLQ_BB_LEN,
			      UBASE_CTRLQ_BB_LEN);
		if (i == 0) {
			head = (struct ubase_ctrlq_base_block *)msg;
			bus_ue_id = le16_to_cpu(head->bus_ue_id);
			ubase_fill_ctrlq_trace_info(&trace_info, crq,
						    num, bus_ue_id);
		}
		trace_ubase_ctrlq_crq(udev->dev, &trace_info,
				      msg + i * UBASE_CTRLQ_BB_LEN,
				      UBASE_CTRLQ_BB_LEN);
		pos = (pos + 1) % crq->depth;
	}
}

static void ubase_ctrlq_send_unsupported_resp(struct ubase_dev *udev,
					      struct ubase_ctrlq_base_block *head,
					      u16 resp_seq, u8 resp_ret)
{
	struct ubase_ctrlq_msg msg = {0};
	int ret;

	msg.service_ver = head->service_ver;
	msg.service_type = head->service_type;
	msg.opcode = head->opcode;
	msg.is_resp = 1;
	msg.resp_seq = resp_seq;
	msg.resp_ret = resp_ret;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret)
		ubase_warn_rl(udev, send_ctrlq_unsup_resp_fail,
			      "failed to send ctrlq unsupport resp, ret=%d.",
			      ret);
}

static void ubase_ctrlq_crq_event_callback(struct ubase_dev *udev,
					   struct ubase_ctrlq_base_block *head,
					   void *msg_data, u16 msg_data_len,
					   u16 seq)
{
#define EDRVNOEXIST 255
#define TIME_COST_THRESHOLD 200

	struct ubase_ctrlq_crq_table *crq_tab = &udev->ctrlq.crq_table;
	unsigned long start_jiffies, time_cost = 0;
	int ret = -ENOENT;
	u32 i;

	ubase_info(udev,
		   "ctrlq recv notice req: seq=%u, ser_type=%u, ser_ver=%u, opc=0x%x.",
		   seq, head->service_type, head->service_ver, head->opcode);

	if (head->ret) {
		/* according to the definition of the CTRLQ interface,
		 * the 'ret' value of request should always be 0.
		 */
		ubase_err(udev, "ctrlq notice req ret is not 0, ret = -%u.",
			  head->ret);
		return;
	}

	mutex_lock(&crq_tab->lock);
	for (i = 0; i < crq_tab->crq_nb_cnt; i++) {
		if (crq_tab->crq_nbs[i].service_type == head->service_type &&
		    crq_tab->crq_nbs[i].opcode == head->opcode) {
			if (!crq_tab->crq_nbs[i].crq_handler) {
				ret = -EDRVNOEXIST;
				break;
			}
			start_jiffies = jiffies;
			ret = crq_tab->crq_nbs[i].crq_handler(crq_tab->crq_nbs[i].back,
							      head->service_ver,
							      msg_data,
							      msg_data_len,
							      seq);
			time_cost = jiffies_to_msecs(jiffies - start_jiffies);
			break;
		}
	}
	mutex_unlock(&crq_tab->lock);

	if (time_cost > TIME_COST_THRESHOLD)
		ubase_warn(udev, "ctrlq crq callback executed in %lums.\n",
			   time_cost);

	if (ret == -ENOENT) {
		dev_info_ratelimited(udev->dev, "this notice is not supported.");
		ubase_ctrlq_send_unsupported_resp(udev, head, seq, EOPNOTSUPP);
	} else if (ret == -EOPNOTSUPP) {
		dev_info_ratelimited(udev->dev,
				    "the notice processor return not support.");
		ubase_ctrlq_send_unsupported_resp(udev, head, seq, EOPNOTSUPP);
	} else if (ret == -EDRVNOEXIST) {
		dev_info_ratelimited(udev->dev,
				    "the notice processor is unregistered.");
		ubase_ctrlq_send_unsupported_resp(udev, head, seq, EDRVNOEXIST);
	}
}

static void ubase_ctrlq_notify_completed(struct ubase_dev *udev,
					 struct ubase_ctrlq_base_block *head,
					 u16 seq, void *msg, u16 msg_len)
{
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;

	ctx = &udev->ctrlq.msg_queue[seq % depth];
	ctx->result = head->ret;
	if (ctx->out)
		memcpy(ctx->out, msg, min(msg_len, ctx->out_size));

	complete(&ctx->done);
}

bool ubase_ctrlq_check_seq(struct ubase_dev *udev, u16 seq)
{
	bool is_pushed = !!(seq & UBASE_CTRLQ_SEQ_MASK);
	u16 max_seq = ubase_ctrlq_max_seq(udev);

	return is_pushed || (seq && seq <= max_seq);
}

int ubase_ctrlq_ue_req_event_callback(struct ubase_dev *udev,
				      struct ubase_ue2ue_ctrlq_head *cmd)
{
	struct ubase_ctrlq_base_block *head = (struct ubase_ctrlq_base_block *)(cmd + 1);
	struct ubase_ctrlq_ue_req_table *ue_req_tab = &udev->ctrlq.ue_req_table;
	struct ubase_ctrlq_ue_req_event_nbs *nbs;
	u16 bus_ue_id, len;
	int ret = 0;

	len = le16_to_cpu(cmd->in_size) + ubase_ctrlq_ue_msg_header_len();
	bus_ue_id = le16_to_cpu(cmd->head.bus_ue_id);
	mutex_lock(&ue_req_tab->lock);
	list_for_each_entry(nbs, &ue_req_tab->ue_req_nbs.list, list) {
		if (nbs->msg_nb.service_type == head->service_type &&
		    nbs->msg_nb.opcode == head->opcode) {
			trace_ubase_ue_req_callback(udev->dev, bus_ue_id, cmd, len);
			ret = nbs->msg_nb.msg_handler(nbs->msg_nb.back, cmd, len);
			break;
		}
	}
	mutex_unlock(&ue_req_tab->lock);

	return ret;
}

static int ubase_ctrlq_ue_resp_event_callback(struct ubase_dev *udev, void *resp,
					      u16 resp_len)
{
	struct ubase_ctrlq_ue_resp_table *ue_resp_tab = &udev->ctrlq.ue_resp_table;
	struct ubase_ctrlq_ue_resp_event_nbs *nbs;
	struct ubase_ue2ue_ctrlq_head *cmd = resp;
	struct ubase_ctrlq_base_block *head;
	u16 bus_ue_id;
	int ret = 0;

	head = (struct ubase_ctrlq_base_block *)(cmd + 1);
	bus_ue_id = le16_to_cpu(cmd->head.bus_ue_id);
	mutex_lock(&ue_resp_tab->lock);
	list_for_each_entry(nbs, &ue_resp_tab->ue_resp_nbs.list, list) {
		if (nbs->msg_nb.service_type == head->service_type &&
		    nbs->msg_nb.opcode == head->opcode) {
			trace_ubase_ue_resp_callback(udev->dev, bus_ue_id, resp, resp_len);
			ret = nbs->msg_nb.msg_handler(nbs->msg_nb.back, resp, resp_len);
			break;
		}
	}
	mutex_unlock(&ue_resp_tab->lock);

	return ret;
}

void ubase_ctrlq_handle_crq_msg(struct ubase_dev *udev,
				struct ubase_ctrlq_base_block *head,
				u16 seq, void *msg_data, u16 data_len)
{
	bool is_pushed = !!(seq & UBASE_CTRLQ_SEQ_MASK);
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_msg_ctx *ctx;

	if (!is_pushed) {
		spin_lock_bh(&csq->lock);
		ctx = &udev->ctrlq.msg_queue[seq % depth];
		if (!ctx->valid) {
			spin_unlock_bh(&csq->lock);
			ubase_dbg(udev,
				  "seq is invalid, opcode = 0x%x, service_type = 0x%x, seq = %u.\n",
				  head->opcode, head->service_type, seq);
			return;
		}
		if (ctx->is_sync) {
			ubase_ctrlq_notify_completed(udev, head, seq, msg_data,
						     data_len);
			spin_unlock_bh(&csq->lock);
			return;
		}
		ctx->valid = 0;
		spin_unlock_bh(&csq->lock);

		up(&udev->ctrlq.msg_queue_sem);
	}

	ubase_ctrlq_crq_event_callback(udev, head, msg_data, data_len, seq);
}

static void ubase_ctrlq_handle_self_msg(struct ubase_dev *udev,
					struct ubase_ctrlq_base_block *head)
{
	u16 seq = le16_to_cpu(head->seq);
	u16 msg_len, data_len;
	void *msg;

	msg_len = head->bb_num * UBASE_CTRLQ_BB_LEN;
	msg = kzalloc(msg_len, GFP_KERNEL);
	if (!msg) {
		ubase_err(udev,
			  "failed to alloc ctrlq crq msg data, opcode = 0x%x, service_type = 0x%x, seq = %u.\n",
			  head->opcode, head->service_type, seq);
		return;
	}

	ubase_ctrlq_read_msg_data(udev, head->bb_num, msg);
	data_len = msg_len - UBASE_CTRLQ_HDR_LEN;

	ubase_ctrlq_handle_crq_msg(udev, head, seq,
				   (u8 *)msg + UBASE_CTRLQ_HDR_LEN, data_len);

	kfree(msg);
}

static void ubase_ctrlq_handle_other_msg(struct ubase_dev *udev,
					 struct ubase_ctrlq_base_block *head)
{
	u16 resp_len, seq = le16_to_cpu(head->seq);
	bool is_pushed = !!(seq & UBASE_CTRLQ_SEQ_MASK);
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	u32 depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ue2ue_ctrlq_head *ue2ue_head;
	struct ubase_ctrlq_msg_ctx ctx = {0};
	struct ubase_cmd_buf in;
	bool need_up = false;
	int ret = 0, async;
	void *resp, *msg;

	if (!is_pushed) {
		spin_lock_bh(&csq->lock);
		ctx = udev->ctrlq.msg_queue[seq % depth];
		if (!ctx.valid) {
			spin_unlock_bh(&csq->lock);
			ubase_warn_rl(udev, ctrlq_other_seq_invalid,
				      "invalid seq = %u, opcode = 0x%x, service_type = 0x%x.\n",
				      seq, head->opcode, head->service_type);
			return;
		}
		if (!ctx.is_sync) {
			udev->ctrlq.msg_queue[seq % depth].valid = 0;
			need_up = true;
		}
		spin_unlock_bh(&csq->lock);

		if (need_up)
			up(&udev->ctrlq.msg_queue_sem);
	}

	resp_len = head->bb_num * UBASE_CTRLQ_BB_LEN +
		   sizeof(struct ubase_ue2ue_ctrlq_head);
	resp = kzalloc(resp_len, GFP_KERNEL);
	if (!resp) {
		ubase_err(udev, "failed to alloc resp mem, seq = %u.\n", seq);
		return;
	}

	msg = (u8 *)resp + sizeof(struct ubase_ue2ue_ctrlq_head);
	ubase_ctrlq_read_msg_data(udev, head->bb_num, msg);

	ue2ue_head = (struct ubase_ue2ue_ctrlq_head *)resp;
	ue2ue_head->head.sub_cmd = UBASE_UE2UE_CTRLQ_MSG;
	ue2ue_head->head.bus_ue_id = is_pushed ? head->bus_ue_id :
				     cpu_to_le16(ctx.bus_ue_id);
	ue2ue_head->seq = is_pushed ? seq : ctx.ue_seq;

	async = ubase_ctrlq_ue_resp_event_callback(udev, resp, resp_len);
	if (async)
		goto out;

	__ubase_fill_inout_buf(&in, UBASE_OPC_UE2UE_UBASE, false, resp_len, resp);
	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_warn_rl(udev, send_ue_ctrlq_msg_to_cmdq_fail,
			      "failed to send ue ctrlq msg, opc = 0x%x, service_type = 0x%x, bus_ue_id = %u, seq = %u, ret = %d.\n",
			      head->opcode, head->service_type,
			      le16_to_cpu(ue2ue_head->head.bus_ue_id),
			      ue2ue_head->seq, ret);

out:
	kfree(resp);
}

static inline void ubase_ctrlq_reset_crq_ci(struct ubase_dev *udev)
{
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;

	crq->ci = crq->pi;
	ubase_write_dev(&udev->hw, UBASE_CTRLQ_CRQ_HEAD_REG, crq->ci);
}

static bool ubase_ctrlq_check_bb_num(struct ubase_dev *udev, u8 bb_num)
{
	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;
	u32 remain_bb_num = crq->pi >= crq->ci ? crq->pi - crq->ci :
			    (u32)crq->pi + crq->depth - crq->ci;

	if (unlikely(!bb_num || bb_num > UBASE_CTRLQ_MAX_BB)) {
		dev_err_ratelimited(udev->dev,
				    "ctrlq crq bb_num(%u) is invalid.\n",
				    bb_num);
		return false;
	}

	if (unlikely(bb_num > remain_bb_num)) {
		dev_err_ratelimited(udev->dev,
				    "ctrlq crq bb_num(%u) more than the remain_bb_num(%u).\n",
				    bb_num, remain_bb_num);
		return false;
	}

	return true;
}

static void ubase_ctrlq_crq_handler(struct ubase_dev *udev)
{
#define UBASE_CTRLQ_CRQ_POLLING_BUDGET 256

	struct ubase_ctrlq_ring *crq = &udev->ctrlq.crq;
	struct ub_entity *ue = to_ub_entity(udev->dev);
	struct ubase_ctrlq_base_block head = {0};
	u32 cnt = 0;
	u8 bb_num;
	u8 *addr;
	u16 seq;

	while (cnt++ < UBASE_CTRLQ_CRQ_POLLING_BUDGET &&
	       !ubase_ctrlq_crq_is_empty(udev, &udev->hw)) {
		if (!test_bit(UBASE_CTRLQ_STATE_ENABLE, &udev->ctrlq.state)) {
			dev_err_ratelimited(udev->dev,
					    "ctrlq is disabled in crq.\n");
			return;
		}

		addr = crq->base_addr + crq->ci * UBASE_CTRLQ_BB_LEN;
		memcpy_fromio(&head, addr, UBASE_CTRLQ_HDR_LEN);
		seq = le16_to_cpu(head.seq);
		bb_num = head.bb_num;

		if (!ubase_ctrlq_check_bb_num(udev, bb_num)) {
			ubase_ctrlq_reset_crq_ci(udev);
			return;
		}

		if (!ubase_ctrlq_check_seq(udev, seq)) {
			dev_warn_ratelimited(udev->dev,
					     "ctrlq recv invalid seq, seq = %u.\n",
					     seq);
			ubase_ctrlq_update_crq_ci(udev, bb_num);
			continue;
		}

		if (le16_to_cpu(head.bus_ue_id) == ue->entity_idx)
			ubase_ctrlq_handle_self_msg(udev, &head);
		else
			ubase_ctrlq_handle_other_msg(udev, &head);

		ubase_ctrlq_update_crq_ci(udev, bb_num);
	}

	if (udev->log_rs.ctrlq_other_seq_invalid_cnt) {
		ubase_warn(udev,
			   "rate limited log: ctrlq_other_seq_invalid_cnt = %u.\n",
			   udev->log_rs.ctrlq_other_seq_invalid_cnt);
		udev->log_rs.ctrlq_other_seq_invalid_cnt = 0;
	}

	if (!ubase_ctrlq_crq_is_empty(udev, &udev->hw))
		ubase_ctrlq_task_schedule(udev, 0);
}

void ubase_ctrlq_crq_service_task(struct ubase_delay_work *ubase_work)
{
	struct ubase_dev *udev = container_of(ubase_work, struct ubase_dev,
				 ctrlq_service_task);
	struct ubase_ctrlq_crq_table *crq_tab = &udev->ctrlq.crq_table;

	if (!test_and_clear_bit(UBASE_STATE_CTRLQ_SERVICE_SCHED,
				&udev->ctrlq_service_task.state) ||
	    test_and_set_bit(UBASE_STATE_CTRLQ_HANDLING,
			     &udev->ctrlq_service_task.state))
		return;

	if (time_is_before_eq_jiffies(crq_tab->last_crq_scheduled +
				      UBASE_CTRLQ_SCHED_TIMEOUT))
		ubase_warn(udev,
			   "ctrlq crq service task is scheduled after %ums on cpu%d!\n",
			   jiffies_to_msecs(jiffies - crq_tab->last_crq_scheduled),
			   smp_processor_id());

	ubase_ctrlq_crq_handler(udev);

	crq_tab->last_crq_scheduled = jiffies;

	clear_bit(UBASE_STATE_CTRLQ_HANDLING, &udev->ctrlq_service_task.state);
}

void ubase_ctrlq_clean_service_task(struct ubase_dev *udev)
{
#define CTRLQ_MSG_CLEAN_CNT 100

	u32 i, depth = ubase_ctrlq_msg_queue_depth(udev);
	struct ubase_ctrlq_ring *csq = &udev->ctrlq.csq;
	struct ubase_ctrlq_msg_ctx *ctx;
	u32 loop = 0, up_cnt = 0;

	if (!test_bit(UBASE_CTRLQ_STATE_ENABLE, &udev->ctrlq.state) ||
	    ubase_dev_pmu_supported(udev))
		return;

	spin_lock_bh(&csq->lock);
	for (i = udev->ctrlq.last_clean_idx;
	     i < depth && loop < CTRLQ_MSG_CLEAN_CNT;
	     i++, loop++) {
		ctx = &udev->ctrlq.msg_queue[i];
		if (!ctx->is_sync && ctx->valid &&
		    time_is_before_eq_jiffies(ctx->dead_jiffies)) {
			ctx->valid = 0;
			up_cnt++;
		}
	}
	udev->ctrlq.last_clean_idx = i == depth ? 0 : i;
	spin_unlock_bh(&csq->lock);

	while (up_cnt--)
		up(&udev->ctrlq.msg_queue_sem);
}

/**
 * ubase_ctrlq_register_crq_event() - register ctrlq crq event processing function
 * @aux_dev: auxiliary device
 * @nb: the ctrlq crq event notification block
 *
 * Register the ctrlq crq handler function. When the management software reports
 * a ctrlq crq event, if the registered 'nb->opcode' and 'nb->service_type' match
 * the crq, the 'nb->crq_handler' function will be called to process it.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_ctrlq_register_crq_event(struct auxiliary_device *aux_dev,
				   struct ubase_ctrlq_event_nb *nb)
{
	struct ubase_ctrlq_crq_table *crq_tab;
	struct ubase_dev *udev;
	int ret = -ENOENT;
	u32 i;

	if (!aux_dev || !nb || !nb->crq_handler)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(aux_dev);
	crq_tab = &udev->ctrlq.crq_table;
	mutex_lock(&crq_tab->lock);
	for (i = 0; i < crq_tab->crq_nb_cnt; i++) {
		if (crq_tab->crq_nbs[i].service_type == nb->service_type &&
		    crq_tab->crq_nbs[i].opcode == nb->opcode) {
			if (crq_tab->crq_nbs[i].crq_handler) {
				ret = -EEXIST;
				break;
			}
			crq_tab->crq_nbs[i].back = nb->back;
			crq_tab->crq_nbs[i].crq_handler = nb->crq_handler;
			ret = 0;
			break;
		}
	}

	mutex_unlock(&crq_tab->lock);

	return ret;
}
EXPORT_SYMBOL(ubase_ctrlq_register_crq_event);

/**
 * ubase_ctrlq_unregister_crq_event() - unregister ctrlq crq event processing function
 * @aux_dev: auxiliary device
 * @service_type: the ctrlq service type
 * @opcode: the ctrlq opcode
 *
 * Unregisters the ctrlq crq processing function. This function is called when user
 * no longer wants to handle the 'service_type' and 'opcode' ctrlq crq events.
 *
 * Context: Any context.
 */
void ubase_ctrlq_unregister_crq_event(struct auxiliary_device *aux_dev,
				      u8 service_type, u8 opcode)
{
	struct ubase_ctrlq_crq_table *crq_tab;
	struct ubase_dev *udev;
	u32 i;

	if (!aux_dev)
		return;

	udev = __ubase_get_udev_by_adev(aux_dev);
	crq_tab = &udev->ctrlq.crq_table;
	mutex_lock(&crq_tab->lock);
	for (i = 0; i < crq_tab->crq_nb_cnt; i++) {
		if (crq_tab->crq_nbs[i].service_type == service_type &&
		    crq_tab->crq_nbs[i].opcode == opcode) {
			crq_tab->crq_nbs[i].back = NULL;
			crq_tab->crq_nbs[i].crq_handler = NULL;
			break;
		}
	}
	mutex_unlock(&crq_tab->lock);
}
EXPORT_SYMBOL(ubase_ctrlq_unregister_crq_event);

/**
 * ubase_ctrlq_register_ue_req_event() - register ctrlq ue request event processing function
 * @aux_dev: auxiliary device
 * @nb: the ctrlq ue request event notification block
 *
 * Register the ctrlq ue request handler function. When the ue reports a ctrlq
 * request event to mue, if the registered 'nb->opcode' and 'nb->service_type'
 * match the ue request event, the 'nb->msg_handler' function will be called by
 * mue to process it.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_ctrlq_register_ue_req_event(struct auxiliary_device *aux_dev,
				      struct ubase_ctrlq_ue_msg_nb *nb)
{
	struct ubase_ctrlq_ue_req_event_nbs *nbs, *tmp, *new_nbs;
	struct ubase_ctrlq_ue_req_table *ue_req_tab;
	struct ubase_dev *udev;
	int ret;

	if (!aux_dev || !nb || !nb->msg_handler)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(aux_dev);
	ue_req_tab = &udev->ctrlq.ue_req_table;
	mutex_lock(&ue_req_tab->lock);
	list_for_each_entry_safe(nbs, tmp, &ue_req_tab->ue_req_nbs.list, list) {
		if (nbs->msg_nb.service_type == nb->service_type &&
		    nbs->msg_nb.opcode == nb->opcode) {
			ret = -EEXIST;
			goto err_ue_req_register;
		}
	}

	new_nbs = kzalloc(sizeof(*new_nbs), GFP_KERNEL);
	if (!new_nbs) {
		ret = -ENOMEM;
		goto err_ue_req_register;
	}

	new_nbs->msg_nb = *nb;
	list_add_tail(&new_nbs->list, &ue_req_tab->ue_req_nbs.list);
	mutex_unlock(&ue_req_tab->lock);

	return 0;

err_ue_req_register:
	mutex_unlock(&ue_req_tab->lock);
	ubase_err(udev,
		  "failed to register ctrlq ue req event, opcode = 0x%x, service_type = 0x%x, ret = %d.\n",
		  nb->opcode, nb->service_type, ret);

	return ret;
}
EXPORT_SYMBOL(ubase_ctrlq_register_ue_req_event);

/**
 * ubase_ctrlq_unregister_ue_req_event() - unregister ctrlq ue request event processing function
 * @aux_dev: auxiliary device
 * @service_type: the ctrlq ue msg service type
 * @opcode: the ctrlq ue msg opcode
 *
 * Unregisters the ctrlq ue request event processing function. This function is
 * called when user no longer wants to handle the 'service_type' and 'opcode'
 * ctrlq ue request events.
 *
 * Context: Any context.
 */
void ubase_ctrlq_unregister_ue_req_event(struct auxiliary_device *aux_dev,
					 u8 service_type, u8 opcode)
{
	struct ubase_ctrlq_ue_req_event_nbs *nbs, *tmp;
	struct ubase_ctrlq_ue_req_table *ue_req_tab;
	struct ubase_dev *udev;

	if (!aux_dev)
		return;

	udev = __ubase_get_udev_by_adev(aux_dev);
	ue_req_tab = &udev->ctrlq.ue_req_table;
	mutex_lock(&ue_req_tab->lock);
	list_for_each_entry_safe(nbs, tmp, &ue_req_tab->ue_req_nbs.list, list) {
		if (nbs->msg_nb.service_type == service_type &&
		    nbs->msg_nb.opcode == opcode) {
			list_del(&nbs->list);
			kfree(nbs);
			break;
		}
	}
	mutex_unlock(&ue_req_tab->lock);
}
EXPORT_SYMBOL(ubase_ctrlq_unregister_ue_req_event);

/**
 * ubase_ctrlq_register_ue_resp_event() - register ctrlq ue response event processing function
 * @aux_dev: auxiliary device
 * @nb: the ctrlq ue response event notification block
 *
 * Register the ctrlq ue response handler function. When the management software
 * reports a ctrlq ue response event, if the registered 'nb->opcode' and 'nb->service_type'
 * match the ue response event, the 'nb->msg_handler' function will be called by
 * mue to process it.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_ctrlq_register_ue_resp_event(struct auxiliary_device *aux_dev,
				       struct ubase_ctrlq_ue_msg_nb *nb)
{
	struct ubase_ctrlq_ue_resp_event_nbs *nbs, *tmp, *new_nbs;
	struct ubase_ctrlq_ue_resp_table *ue_resp_tab;
	struct ubase_dev *udev;
	int ret;

	if (!aux_dev || !nb || !nb->msg_handler)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(aux_dev);
	ue_resp_tab = &udev->ctrlq.ue_resp_table;
	mutex_lock(&ue_resp_tab->lock);
	list_for_each_entry_safe(nbs, tmp, &ue_resp_tab->ue_resp_nbs.list, list) {
		if (nbs->msg_nb.service_type == nb->service_type &&
		    nbs->msg_nb.opcode == nb->opcode) {
			ret = -EEXIST;
			goto err_ue_resp_register;
		}
	}

	new_nbs = kzalloc(sizeof(*new_nbs), GFP_KERNEL);
	if (!new_nbs) {
		ret = -ENOMEM;
		goto err_ue_resp_register;
	}

	new_nbs->msg_nb = *nb;
	list_add_tail(&new_nbs->list, &ue_resp_tab->ue_resp_nbs.list);
	mutex_unlock(&ue_resp_tab->lock);

	return 0;

err_ue_resp_register:
	mutex_unlock(&ue_resp_tab->lock);
	ubase_err(udev,
		  "failed to register ctrlq ue resp event, opcode = 0x%x, service_type = 0x%x, ret = %d.\n",
		  nb->opcode, nb->service_type, ret);

	return ret;
}
EXPORT_SYMBOL(ubase_ctrlq_register_ue_resp_event);

/**
 * ubase_ctrlq_unregister_ue_resp_event() - unregister ctrlq ue response event processing function
 * @aux_dev: auxiliary device
 * @service_type: the ctrlq ue msg service type
 * @opcode: the ctrlq ue msg opcode
 *
 * Unregisters the ctrlq ue response event processing function. This function is
 * called when user no longer wants to handle the 'service_type' and 'opcode'
 * ctrlq ue response events.
 *
 * Context: Any context.
 */
void ubase_ctrlq_unregister_ue_resp_event(struct auxiliary_device *aux_dev,
					  u8 service_type, u8 opcode)
{
	struct ubase_ctrlq_ue_resp_event_nbs *nbs, *tmp;
	struct ubase_ctrlq_ue_resp_table *ue_resp_tab;
	struct ubase_dev *udev;

	if (!aux_dev)
		return;

	udev = __ubase_get_udev_by_adev(aux_dev);
	ue_resp_tab = &udev->ctrlq.ue_resp_table;
	mutex_lock(&ue_resp_tab->lock);
	list_for_each_entry_safe(nbs, tmp, &ue_resp_tab->ue_resp_nbs.list, list) {
		if (nbs->msg_nb.service_type == service_type &&
		    nbs->msg_nb.opcode == opcode) {
			list_del(&nbs->list);
			kfree(nbs);
			break;
		}
	}
	mutex_unlock(&ue_resp_tab->lock);
}
EXPORT_SYMBOL(ubase_ctrlq_unregister_ue_resp_event);

/**
 * ubase_ctrlq_ue_msg_header_len() - ctrlq ue message header length
 *
 * This function is called when user wants to get ue message header length.
 *
 * Context: Any context.
 */
u16 ubase_ctrlq_ue_msg_header_len(void)
{
	return UBASE_CTRLQ_UE_MSG_HDR_LEN;
}
EXPORT_SYMBOL(ubase_ctrlq_ue_msg_header_len);

/**
 * ubase_ctrlq_send_mue2ue_resp() - mue send ctrlq response message to ue
 * @aux_dev: auxiliary device
 * @data: the message
 * @len: the message length
 * @result: result returned to ue
 *
 * The driver uses this function to send ctrlq response message to the ue.
 * The mue needs to parse the data, fill the result into the corresponding
 * fields, calculate the required bb_num, and send the message to the ue.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_ctrlq_send_mue2ue_resp(struct auxiliary_device *adev, void *data,
				 u16 len, u8 result)
{
	struct ubase_ue2ue_ctrlq_head *cmd = data;
	struct ubase_ctrlq_base_block *head;
	struct ubase_cmd_buf in;
	struct ubase_dev *udev;
	u16 bus_ue_id;
	int ret;

	if (!adev || !data)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	if (len < UBASE_CTRLQ_UE_MSG_HDR_LEN) {
		ubase_err(udev, "invalid mue2ue ctrlq resp len(%u).\n", len);
		return -EINVAL;
	}

	bus_ue_id = le16_to_cpu(cmd->head.bus_ue_id);
	trace_ubase_send_mue2ue_resp(udev->dev, bus_ue_id, data, len);

	head = (struct ubase_ctrlq_base_block *)(cmd + 1);
	head->ret = result;
	head->bb_num = ubase_ctrlq_calc_bb_num(len - UBASE_CTRLQ_UE_MSG_HDR_LEN);

	__ubase_fill_inout_buf(&in, UBASE_OPC_UE2UE_UBASE, false, len, data);
	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_warn(udev,
			   "failed to send mue2ue ctrlq msg, opc = 0x%x, service_type = 0x%x, ret = %d.\n",
			   head->opcode, head->service_type, ret);

	return ret;
}
EXPORT_SYMBOL(ubase_ctrlq_send_mue2ue_resp);

/**
 * ubase_ctrlq_send_ue_req() - mue send ue ctrlq request message
 * @aux_dev: auxiliary device
 * @data: the message
 * @len: the message length
 *
 * The driver uses this function to send ue ctrlq request message to the management
 * software. This function fills the data content into the ctrlq message interaction
 * structure and sends the structure to the management software.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. May sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_ctrlq_send_ue_req(struct auxiliary_device *adev, void *data, u16 len)
{
	struct ubase_ue2ue_ctrlq_head *cmd = data;
	struct ubase_ctrlq_base_block *head;
	struct ubase_ctrlq_ue_info ue_info;
	struct ubase_ctrlq_msg msg = {0};
	u16 mbx_ue_id, bus_ue_id;
	struct ubase_dev *udev;
	int ret;

	if (!adev || !data)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	if (len < UBASE_CTRLQ_UE_MSG_HDR_LEN) {
		ubase_err(udev,
			  "ubase ctrlq send ue req len invalid, len = %hu.\n",
			  len);
		return -EINVAL;
	}

	if (cmd->in_size > (len - UBASE_CTRLQ_UE_MSG_HDR_LEN)) {
		ubase_err(udev,
			  "ubase ctrlq send ue req len error, len = %hu, size = %hu.\n",
			  len, cmd->in_size);
		return -EINVAL;
	}

	mbx_ue_id = le16_to_cpu(cmd->head.mbx_ue_id);
	if (!ubase_mbx_ue_id_is_valid(mbx_ue_id, udev)) {
		ubase_err(udev,
			  "ubase ctrlq send ue req mbx ue id = %hu error.\n",
			  mbx_ue_id);
		return -EINVAL;
	}

	bus_ue_id = le16_to_cpu(cmd->head.bus_ue_id);
	trace_ubase_send_ue_req(udev->dev, bus_ue_id, cmd, len);

	head = (struct ubase_ctrlq_base_block *)(cmd + 1);
	msg.service_ver = head->service_ver;
	msg.service_type = head->service_type;
	msg.opcode = head->opcode;
	msg.need_resp = cmd->need_resp;
	msg.is_resp = cmd->is_resp;
	msg.resp_seq = cmd->seq;
	msg.in = (u8 *)head + UBASE_CTRLQ_HDR_LEN;
	msg.in_size = cmd->in_size;
	msg.out = NULL;
	msg.out_size = 0;

	ue_info.bus_ue_id = le16_to_cpu(cmd->head.bus_ue_id);
	ue_info.seq = cmd->seq;
	ue_info.mbx_ue_id = mbx_ue_id;

	ret = __ubase_ctrlq_send(udev, &msg, true, &ue_info);
	if (ret)
		ubase_err(udev,
			  "failed to send opc(0x%x) ue req ctrlq, ret = %d.\n",
			  head->opcode, ret);

	return ret;
}
EXPORT_SYMBOL(ubase_ctrlq_send_ue_req);

/**
 * ubase_ctrlq_parse_ue_msg() - parse ue ctrlq message
 * @aux_dev: auxiliary device
 * @data: the message
 * @len: the message length
 * @info: information of the message
 *
 * The driver uses this function to parse ue ctrlq message. This function will
 * parse information such as service_type, mbx_ue_id, bus_ue_id, and ret and
 * fill them into the structure.
 *
 * Context: Any context.
 */
void ubase_ctrlq_parse_ue_msg(struct auxiliary_device *adev, void *data, u16 len,
			      struct ubase_ctrlq_ue_msg_info *info)
{
	struct ubase_ue2ue_ctrlq_head *cmd = data;
	struct ubase_ctrlq_base_block *head;
	struct ubase_dev *udev;
	u16 bus_ue_id;

	if (!adev || !data || !info)
		return;

	udev = __ubase_get_udev_by_adev(adev);
#ifdef CONFIG_EQUIP
	if (!ubase_dev_rack_server_supported(udev))
		return;
#endif
	if (len < UBASE_CTRLQ_UE_MSG_HDR_LEN) {
		ubase_err(udev, "invalid ue ctrlq msg len(%u).\n", len);
		return;
	}

	head = (struct ubase_ctrlq_base_block *)(cmd + 1);
	bus_ue_id = le16_to_cpu(head->bus_ue_id);
	trace_ubase_parse_ue_msg(udev->dev, bus_ue_id, data, len);
	info->service_ver = head->service_ver;
	info->mbx_ue_id = head->mbx_ue_id;
	info->bus_ue_id = bus_ue_id;
	info->ret = -head->ret;
}
EXPORT_SYMBOL(ubase_ctrlq_parse_ue_msg);
