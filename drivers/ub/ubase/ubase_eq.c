// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <ub/ubase/ubase_comm_eq.h>

#include "ubase_cmd.h"
#include "ubase_dev.h"
#include "ubase_mailbox.h"
#include "ubase_reset.h"
#include "ubase_tp.h"
#include "ubase_trace.h"
#include "ubase_eq.h"

enum ubase_eq_type {
	UBASE_EQ_TYPE_AEQ,
	UBASE_EQ_TYPE_CEQ,
};

static struct ubase_ceqe *ubase_next_ceqe(struct ubase_ceq *ceq)
{
	struct ubase_eq *eq = &ceq->eq;
	struct ubase_ceqe *ceqe;

	ceqe = (struct ubase_ceqe *)(ceq->eq.addr.addr +
				     (eq->cons_index & (eq->entries_num - 1)) *
				     eq->eqe_size);

	return !!u32_get_bits(ceqe->comp, UBASE_CEQ_CEQE_OWNER_BIT) ^
	       !!(eq->cons_index & eq->entries_num) ? ceqe : NULL;
}

static void ubase_comp_handler(struct ubase_dev *udev, u32 jfcn)
{
	struct ubase_res_caps *unic_jfc_caps = &udev->caps.unic_caps.jfc;
	u32 jfcn_end = unic_jfc_caps->start_idx + unic_jfc_caps->max_cnt;
	u32 jfcn_begin = unic_jfc_caps->start_idx;
	struct ubase_adev *uadev;
	u8 idx;

	/* CDMA exists independently, UNIC/UDMA are distinguished by jfcn. */
	if (udev->priv.uadev[UBASE_DRV_CDMA])
		idx = UBASE_DRV_CDMA;
	else if (jfcn_begin <= jfcn && jfcn < jfcn_end)
		idx = UBASE_DRV_UNIC;
	else
		idx = UBASE_DRV_UDMA;

	uadev = udev->priv.uadev[idx];
	if (unlikely(!uadev))
		return;

	atomic_notifier_call_chain(&uadev->comp_nh, jfcn, (void *)&uadev->adev);
}

static void ubase_update_eq_db(struct ubase_eq *eq, enum ubase_eq_type eq_type)
{
	struct ubase_eq_db eq_db = {0};

	eq_db.eqn = eq->eqn;
	eq_db.ci = eq->cons_index;

	if (eq_type == UBASE_EQ_TYPE_CEQ)
		eq_db.type = UBASE_EQ_DB_CMD_CEQ;

	writeq(*(__le64 *)&eq_db, eq->db_reg);
}

static irqreturn_t ubase_ceq_int_handler(int irq, void *data)
{
#define UBASE_CEQ_POLLING_BUDGET 128

	struct ubase_ceq *ceq = (struct ubase_ceq *)data;
	struct ubase_ceqe *ceqe = ubase_next_ceqe(ceq);
	struct ubase_dev *udev = ceq->udev;
	bool ceqe_found = false;
	u8 cnt = 0;
	u32 jfcn;

	while (cnt++ < UBASE_CEQ_POLLING_BUDGET && ceqe) {
		/* Make sure we read CEQ entry after we have checked the
		 * ownership bit
		 */
		dma_rmb();

		jfcn = u32_get_bits(ceqe->comp, UBASE_CEQE_COMP_CQN_M);

		trace_ubase_ceqe(udev->dev, jfcn, &ceq->eq);

		ubase_comp_handler(udev, jfcn);

		++ceq->eq.cons_index;
		ceqe_found = true;
		ceqe = ubase_next_ceqe(ceq);
	}

	if (ceqe_found)
		ubase_update_eq_db(&ceq->eq, UBASE_EQ_TYPE_CEQ);

	return IRQ_RETVAL(ceqe_found);
}

static struct ubase_aeqe *ubase_next_aeqe(struct ubase_dev *udev,
					  struct ubase_aeq *aeq)
{
	struct ubase_eq *eq = &aeq->eq;
	struct ubase_aeqe *aeqe;

	aeqe = (struct ubase_aeqe *)(eq->addr.addr +
				     (eq->cons_index & (eq->entries_num - 1)) *
				     eq->eqe_size);

	return aeqe->owner ^ !!(eq->cons_index & eq->entries_num) ? aeqe : NULL;
}

void ubase_enable_misc_vector(struct ubase_dev *udev, bool enable)
{
	ubase_write_dev(&udev->hw, UBASE_MISC_VECTOR_REG_OFFSET,
			enable ? 0 : 1);
}

static void ubase_save_ras_type(struct ubase_dev *udev, u32 reg)
{
	if (ubase_dev_ubl_supported(udev))
		set_bit(UBASE_STATE_PORT_RESETTING_B, &udev->state_bits);
}

static unsigned long ubase_check_event_cause(struct ubase_dev *udev)
{
	unsigned long event_cause = 0;
	u32 sw_handshake_0_reg;
	u32 ctrlq_src_reg;
	u32 cmdq_src_reg;

	cmdq_src_reg = ubase_read_dev(&udev->hw, UBASE_VECTOR0_CMDQ_SRC_REG);
	if (cmdq_src_reg & BIT(UBASE_VECTOR0_RX_CMDQ_INT_B))
		event_cause |= BIT(UBASE_ASYNC_EVENT_CRQ_B);

	if (ubase_dev_err_handle_supported(udev)) {
		sw_handshake_0_reg = ubase_read_dev(&udev->hw,
						    UBASE_SW_HANDSHAKE_0_REG);
		if (sw_handshake_0_reg & BIT(UBASE_SW_HANDSHAKE_0_RAS_B)) {
			ubase_save_ras_type(udev, sw_handshake_0_reg);
			event_cause |= BIT(UBASE_ASYNC_EVENT_RAS_B);
		}
	}

	if (ubase_dev_ctrlq_supported(udev)) {
		ctrlq_src_reg = ubase_read_dev(&udev->hw, UBASE_VECTOR0_CTRLQ_SRC_REG);
		if (ctrlq_src_reg & BIT(UBASE_VECTOR0_RX_CTRLQ_INT_B))
			event_cause |= BIT(UBASE_ASYNC_EVENT_CTRLQ_B);
	}

	return event_cause;
}

static void ubase_clear_event_cause(struct ubase_dev *udev,
				    unsigned long event_cause)
{
	u32 sw_handshake_0_reg;

	if (test_bit(UBASE_ASYNC_EVENT_CRQ_B, &event_cause))
		ubase_write_dev(&udev->hw, UBASE_VECTOR0_CMDQ_SRC_REG,
				BIT(UBASE_VECTOR0_RX_CMDQ_INT_B));

	if (test_bit(UBASE_ASYNC_EVENT_RAS_B, &event_cause)) {
		sw_handshake_0_reg = ubase_read_dev(&udev->hw,
						    UBASE_SW_HANDSHAKE_0_REG);
		sw_handshake_0_reg &= ~(BIT(UBASE_SW_HANDSHAKE_0_RAS_B) |
					BIT(UBASE_SW_HANDSHAKE_0_PORT_RESET_B) |
					BIT(UBASE_SW_HANDSHAKE_0_HIMAC_RESET_B));
		ubase_write_dev(&udev->hw, UBASE_SW_HANDSHAKE_0_REG,
				sw_handshake_0_reg);
	}

	if (test_bit(UBASE_ASYNC_EVENT_CTRLQ_B, &event_cause))
		ubase_write_dev(&udev->hw, UBASE_VECTOR0_CTRLQ_SRC_REG,
				BIT(UBASE_VECTOR0_RX_CTRLQ_INT_B));
}

static void ubase_clear_all_event_cause(struct ubase_dev *udev)
{
	ubase_clear_event_cause(udev,
				BIT(UBASE_ASYNC_EVENT_CRQ_B) |
				BIT(UBASE_ASYNC_EVENT_RAS_B) |
				BIT(UBASE_ASYNC_EVENT_CTRLQ_B));
}

static void ubase_crq_task_schedule(struct ubase_dev *udev)
{
	if (!test_and_set_bit(UBASE_STATE_CRQ_SERVICE_SCHED,
			      &udev->service_task.state)) {
		udev->crq_table.last_crq_scheduled = jiffies;
		mod_delayed_work(udev->ubase_wq,
				 &udev->service_task.service_task, 0);
	}
}

void ubase_errhandle_task_schedule(struct ubase_dev *udev)
{
	if (!test_and_set_bit(UBASE_SERVICE_STATE_ERR_SCHED,
			      &udev->service_task.state))
		mod_delayed_work(udev->ubase_wq,
				 &udev->service_task.service_task, 0);
}

void ubase_ctrlq_task_schedule(struct ubase_dev *udev, unsigned long delay)
{
	if (!test_and_set_bit(UBASE_STATE_CTRLQ_SERVICE_SCHED,
			      &udev->ctrlq_service_task.state)) {
		udev->ctrlq.crq_table.last_crq_scheduled = jiffies;
		mod_delayed_work(udev->ubase_ctrlq_wq,
				 &udev->ctrlq_service_task.service_task, delay);
	}
}

static int ubase_reg_event_handler(struct ubase_dev *udev)
{
	unsigned long event_cause;

	ubase_enable_misc_vector(udev, false);

	event_cause = ubase_check_event_cause(udev);
	trace_ubase_misc_event_cause(udev->dev, event_cause);
	if (test_bit(UBASE_ASYNC_EVENT_CRQ_B, &event_cause))
		ubase_crq_task_schedule(udev);

	if (test_bit(UBASE_ASYNC_EVENT_RAS_B, &event_cause))
		ubase_errhandle_task_schedule(udev);

	if (test_bit(UBASE_ASYNC_EVENT_CTRLQ_B, &event_cause))
		ubase_ctrlq_task_schedule(udev, 0);

	ubase_clear_event_cause(udev, event_cause);
	ubase_enable_misc_vector(udev, true);

	return event_cause ? IRQ_HANDLED : IRQ_NONE;
}

static bool ubase_is_udma_queue_id(u32 queue_id, struct ubase_res_caps *caps)
{
	u32 end = caps->start_idx + caps->max_cnt;
	u32 begin = caps->start_idx;

	return begin <= queue_id && queue_id < end;
}

static inline bool ubase_is_public_or_rsvd_jetty(u32 queue_id,
						 struct ubase_caps *caps)
{
	return queue_id < caps->public_jetty_cnt + caps->rsvd_jetty_cnt;
}

static bool ubase_is_udma_ras_event(struct ubase_dev *udev, u32 queue_id,
				    u8 sub_type)
{
	switch (sub_type) {
	case UBASE_SUBEVENT_TYPE_JFS_CHECK_ERROR:
		return ubase_is_public_or_rsvd_jetty(queue_id,
						     &udev->caps.dev_caps) ||
		       ubase_is_udma_queue_id(queue_id,
					      &udev->caps.udma_caps.jfs);
	case UBASE_SUBEVENT_TYPE_JFR_CHECK_ERROR:
		return ubase_is_udma_queue_id(queue_id,
					      &udev->caps.udma_caps.jfr);
	case UBASE_SUBEVENT_TYPE_JFC_CHECK_ERROR:
		return ubase_is_udma_queue_id(queue_id,
					      &udev->caps.udma_caps.jfc);
	case UBASE_SUBEVENT_TYPE_JETTY_GROUP_CHECK_ERROR:
		return true;
	default:
		break;
	}

	return false;
}

static bool ubase_is_udma_tp_event(struct ubase_dev *udev, u32 tpn)
{
	struct ubase_tpg *tpg = udev->tp_ctx.tpg;
	u32 i;

	spin_lock(&udev->tp_ctx.tpg_lock);
	if (!tpg) {
		ubase_warn(udev, "unexpected tp event, tpn = %u.\n", tpn);
		spin_unlock(&udev->tp_ctx.tpg_lock);
		return true;
	}

	for (i = 0; i < udev->caps.unic_caps.tpg.max_cnt; i++) {
		if (tpn >= tpg[i].start_tpn &&
		    tpn < tpg[i].start_tpn + tpg[i].tp_cnt) {
			spin_unlock(&udev->tp_ctx.tpg_lock);
			return false;
		}
	}
	spin_unlock(&udev->tp_ctx.tpg_lock);

	return true;
}

static bool ubase_is_udma_event(struct ubase_dev *udev, u8 event_type,
				u8 sub_type, struct ubase_aeqe *aeqe)
{
	u32 queue_id = aeqe->event.queue_event.num;

	switch (event_type) {
	case UBASE_EVENT_TYPE_CHECK_TOKEN:
		return true;
	case UBASE_EVENT_TYPE_TP_FLUSH_DONE:
	case UBASE_EVENT_TYPE_TP_LEVEL_ERROR:
		return ubase_is_udma_tp_event(udev, queue_id);
	case UBASE_EVENT_TYPE_JFR_LIMIT_REACHED:
		return ubase_is_udma_queue_id(queue_id,
					      &udev->caps.udma_caps.jfr);
	case UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR:
		return ubase_is_udma_ras_event(udev, queue_id, sub_type);
	default:
		break;
	}

	return false;
}

static bool ubase_is_comm_event(struct ubase_dev *udev, struct ubase_aeqe *aeqe)
{
	switch (aeqe->event_type) {
	case UBASE_EVENT_TYPE_MB:
		return true;
	default:
		return false;
	}

	return false;
}

static void ubase_aeq_event_handler(struct ubase_dev *udev,
				    struct ubase_aeqe *aeqe)
{
	struct ubase_aeq_notify_info info;
	u8 event_type = aeqe->event_type;
	u8 sub_type = aeqe->sub_type;
	u8 idx;

	if (event_type >= UBASE_EVENT_TYPE_MAX) {
		ubase_err_rl(udev, udev->log_rs.aeq_event_type_exceed_max_cnt,
			     "event type wrong, event_type = %u.\n", event_type);
		return;
	}

	info.event_type = event_type;
	info.sub_type = sub_type;
	info.aeqe = aeqe;

	if (ubase_is_comm_event(udev, aeqe))
		idx = UBASE_DRV_UNIC;
	else if (ubase_dev_cdma_supported(udev))
		idx = UBASE_DRV_CDMA;
	else if (ubase_is_udma_event(udev, event_type, sub_type, aeqe))
		idx = UBASE_DRV_UDMA;
	else
		idx = UBASE_DRV_UNIC;

	ubase_dbg(udev, "ubase do async work, idx = %u, event_type = %u.\n",
		  idx, event_type);

	blocking_notifier_call_chain(&udev->irq_table.nh[idx][event_type],
				     event_type, (void *)&info);
}

static void ubase_async_service_task(struct work_struct *work)
{
	struct ubase_aeq_work *aeq_work =
		container_of(work, struct ubase_aeq_work, work);
	struct ubase_aeqe *aeqe = &aeq_work->aeqe;
	struct ubase_dev *udev = aeq_work->udev;

	ubase_aeq_event_handler(udev, aeqe);

	kfree(aeq_work);
}

static void ubase_init_aeq_work(struct ubase_dev *udev, struct ubase_aeqe *aeqe)
{
	struct ubase_aeq_work *aeq_work;

	aeq_work = kzalloc(sizeof(struct ubase_aeq_work), GFP_ATOMIC);
	if (!aeq_work) {
		dev_err_ratelimited(udev->dev, "failed to alloc aeq work.\n");
		return;
	}

	aeq_work->udev = udev;
	memcpy(&aeq_work->aeqe, aeqe, sizeof(struct ubase_aeqe));
	INIT_WORK(&aeq_work->work, ubase_async_service_task);

	queue_work(udev->ubase_async_wq, &aeq_work->work);
}

static void ubase_mbx_complete(struct ubase_dev *udev, struct ubase_aeqe *aeqe)
{
	struct ubase_mbx_event_context *ctx = &udev->mb_cmd.ctx;

	if (aeqe->event.cmd.seq_num != ctx->seq_num)
		return;

	ubase_mailbox_buff_free(udev);

	ctx->result = aeqe->event.cmd.status == 0 ? 0 : -EIO;
	ctx->out_param = aeqe->event.cmd.out_param;

	complete(&ctx->done);
}

static int ubase_async_event_handler(struct ubase_dev *udev)
{
	struct ubase_aeq *aeq = &udev->irq_table.aeq;
	struct ubase_eq *eq = &aeq->eq;
	struct ubase_aeqe *aeqe;
	unsigned long flags;

	raw_spin_lock_irqsave(&aeq->aeq_lock, flags);

	aeqe = ubase_next_aeqe(udev, aeq);
	while (aeqe) {
		dma_rmb();

		trace_ubase_aeqe(udev->dev, aeqe, eq);

		if (aeqe->event_type == UBASE_EVENT_TYPE_MB)
			ubase_mbx_complete(udev, aeqe);
		else
			ubase_init_aeq_work(udev, aeqe);

		++aeq->eq.cons_index;
		aeqe = ubase_next_aeqe(udev, aeq);

		ubase_update_eq_db(&aeq->eq, UBASE_EQ_TYPE_AEQ);
	}

	raw_spin_unlock_irqrestore(&aeq->aeq_lock, flags);

	return IRQ_HANDLED;
}

static irqreturn_t ubase_misc_int_handler(int irq, void *data)
{
	struct ubase_dev *udev = (struct ubase_dev *)data;

	return IRQ_RETVAL(ubase_reg_event_handler(udev));
}

static irqreturn_t ubase_aeq_int_handler(int irq, void *data)
{
	struct ubase_dev *udev = (struct ubase_dev *)data;

	return IRQ_RETVAL(ubase_async_event_handler(udev));
}

static void ubase_construct_eq_ctx(struct ubase_eq *eq,
				   struct ubase_eq_ctx *ctx, u32 tid)
{
	ctx->state = eq->state;
	ctx->arm_st = eq->arm_st;
	ctx->eqe_size = eq->eqe_size == UBASE_DEFAULT_EQE_SIZE ? 1 : 0;
	ctx->pi = UBASE_EQ_INIT_PROD_IDX;
	ctx->shift = ilog2(eq->entries_num) - UBASE_CTX_SHIFT_BASE;
	ctx->eqe_coalesce_period = eq->eq_period;
	ctx->ci = UBASE_EQ_INIT_CONS_IDX;
	ctx->eqe_coalesce_cnt = eq->coalesce_cnt;
	ctx->eqe_base_addr_l = eq->addr.dma_addr >>
		UBASE_EQE_BA_L_OFFSET & UBASE_EQE_BA_L_VALID_BIT;
	ctx->eqe_base_addr_h = eq->addr.dma_addr >>
		UBASE_EQE_BA_H_OFFSET & UBASE_EQE_BA_H_VALID_BIT;
	ctx->eqe_token_id = tid;
	ctx->irq_num = eq->eqc_irqn;
	ctx->pi_bypass = UBASE_EQ_INIT_PROD_IDX;
	ctx->state2 = eq->state;
}

static int ubase_fill_eq_attribute(struct ubase_dev *udev, struct ubase_eq *eq,
				   u32 eqn, struct ubase_irq *irq,
				   enum ubase_eq_type eq_type)
{
	struct ubase_eq_addr *eq_addr = &eq->addr;

	if (eq_type == UBASE_EQ_TYPE_AEQ) {
		eq->eqe_size = udev->caps.dev_caps.aeqe_size;
		eq->entries_num = udev->caps.dev_caps.aeqe_depth;
		eq->eq_period = EQC_EQ_DEFAULT_PERIOD_INDX;
		eq->eqc_irqn = eqn + udev->caps.dev_caps.num_misc_vectors;
	} else {
		eq->eqe_size = udev->caps.dev_caps.ceqe_size;
		eq->entries_num = udev->caps.dev_caps.ceqe_depth;
		eq->eqc_irqn = eqn + udev->caps.dev_caps.num_misc_vectors +
			       udev->caps.dev_caps.num_aeq_vectors;
		eq->eq_period = EQC_EQ_DEFAULT_PERIOD_INDX;
	}

	eq->cons_index = 0;
	eq->db_reg = udev->hw.mem_base.addr;
	eq->eqn = eqn;
	eq->state = UBASE_EQ_STAT_VALID;
	eq->arm_st = UBASE_EQ_ALWAYS_ARMED;
	eq->coalesce_cnt = UBASE_EQ_COALESCE_0;
	eq->irqn = irq->irqn;

	eq_addr->size = eq->entries_num * eq->eqe_size;
	eq_addr->addr = dma_alloc_coherent(udev->dev, eq_addr->size,
					   &eq_addr->dma_addr, GFP_KERNEL);
	if (!eq_addr->addr) {
		ubase_err(udev, "failed to alloc eqe base addr.\n");
		return -ENOMEM;
	}

	return 0;
}

static int ubase_create_eq(struct ubase_dev *udev, struct ubase_eq *eq, u32 eqn,
			   struct ubase_irq *irq, enum ubase_eq_type eq_type)
{
	struct ubase_cmd_mailbox *mbx;
	struct ubase_mbx_attr attr;
	int mbx_cmd;
	int ret;

	ret = ubase_fill_eq_attribute(udev, eq, eqn, irq, eq_type);
	if (ret) {
		ubase_err(udev, "failed to fill eq attribute.\n");
		return ret;
	}

	mbx_cmd = eq_type == UBASE_EQ_TYPE_AEQ ? UBASE_MB_CREATE_AEQ_CONTEXT :
						 UBASE_MB_CREATE_CEQ_CONTEXT;
	mbx = __ubase_alloc_cmd_mailbox(udev);
	if (IS_ERR_OR_NULL(mbx)) {
		ubase_err(udev, "failed to alloc mailbox for create EQC.\n");
		ret = -ENOMEM;
		goto err_alloc_mailbox;
	}
	ubase_construct_eq_ctx(eq, (struct ubase_eq_ctx *)mbx->buf,
			       udev->caps.dev_caps.tid);
	ubase_fill_mbx_attr(&attr, eq->eqn, mbx_cmd, 0);
	ret = ubase_hw_upgrade_ctx_poll(udev, &attr, mbx);
	if (ret) {
		ubase_err(udev, "failed to create EQC, ret = %d.\n", ret);
		goto err_upgrade_ctx;
	}

	__ubase_free_cmd_mailbox(udev, mbx);

	return 0;

err_upgrade_ctx:
	__ubase_free_cmd_mailbox(udev, mbx);
err_alloc_mailbox:
	dma_free_coherent(udev->dev, eq->addr.size, eq->addr.addr,
			  eq->addr.dma_addr);
	eq->addr.addr = NULL;

	return ret;
}

static int ubase_destroy_eq(struct ubase_dev *udev, struct ubase_eq *eq,
			    enum ubase_eq_type eq_type)
{
	struct ubase_cmd_mailbox *mbx;
	struct ubase_mbx_attr attr;
	int mbx_cmd;
	int ret;

	mbx_cmd = eq_type == UBASE_EQ_TYPE_AEQ ? UBASE_MB_DESTROY_AEQ_CONTEXT :
						 UBASE_MB_DESTROY_CEQ_CONTEXT;

	mbx = __ubase_alloc_cmd_mailbox(udev);
	if (IS_ERR_OR_NULL(mbx)) {
		ubase_err(udev,
			  "failed to alloc mailbox for destroy EQC.\n");
		return -ENOMEM;
	}
	ubase_fill_mbx_attr(&attr, eq->eqn, mbx_cmd, 0);
	ret = ubase_hw_upgrade_ctx_poll(udev, &attr, mbx);
	if (ret)
		ubase_err(udev, "failed to destroy EQC, ret = %d.\n", ret);

	__ubase_free_cmd_mailbox(udev, mbx);
	dma_free_coherent(udev->dev, eq->addr.size, eq->addr.addr,
			  eq->addr.dma_addr);
	eq->addr.addr = NULL;

	return ret;
}

static int ubase_request_misc_irq(struct ubase_dev *udev)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	struct ubase_irq *irq;
	int ret;

	if (ubase_ubus_irq_vector(udev->dev, 0) == -EOPNOTSUPP)
		return 0;

	irq = irq_table->irqs[UBASE_MISC_IRQ_INDEX];
	snprintf(irq->name, UBASE_INT_NAME_LEN, "ubase%d-%s-%d",
		 udev->dev_id, "misc", 0);
	ret = request_irq(irq->irqn, ubase_misc_int_handler, 0, irq->name, udev);
	if (ret) {
		ubase_err(udev,
			  "failed to request misc irq, ret = %d.\n", ret);
		return ret;
	}

	ubase_enable_misc_vector(udev, true);

	return ret;
}

static inline void ubase_poll_aeqe(struct ubase_dev *udev,
				   struct ubase_aeq *aeq)
{
#define UBASE_KEEP_POLL_TIME	10
#define UBASE_POLL_MSLEEP	20

	unsigned long keep, end;

	keep = msecs_to_jiffies(UBASE_KEEP_POLL_TIME) + jiffies;
	end = msecs_to_jiffies(UBASE_CMDQ_MBX_TX_TIMEOUT) + jiffies;

	while (time_before(jiffies, end)) {
		ubase_async_event_handler(udev);
		if (!atomic_read(&udev->mb_cmd.mbx_cnt) ||
		    kthread_should_stop())
			break;

		if (time_after(jiffies, keep))
			msleep(UBASE_POLL_MSLEEP);
		else
			udelay(1);
	}
}

static int ubase_ae_task_handle(void *data)
{
#define UBASE_WAIT_COMPLETION_TIME 1000

	struct ubase_dev *udev = (struct ubase_dev *)data;
	struct ubase_irq_table *irq_table = &udev->irq_table;
	struct ubase_aeq *aeq = &irq_table->aeq;

	ubase_info(udev, "ubase ae task start.\n");

	while (!kthread_should_stop()) {
		if (wait_for_completion_timeout(&aeq->poll,
						msecs_to_jiffies(UBASE_WAIT_COMPLETION_TIME)))
			ubase_poll_aeqe(udev, aeq);
	}

	ubase_info(udev, "ubase ae task exit.\n");
	return 0;
}

static int ubase_request_aeq_irq(struct ubase_dev *udev)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	char task_name[UBASE_INT_NAME_LEN] = {0};
	struct ubase_aeq *aeq = &irq_table->aeq;
	struct ubase_irq *irq;
	int ret;

	if (ubase_dev_pmu_supported(udev))
		return 0;

	irq = irq_table->irqs[UBASE_AEQ_IRQ_INDEX];
	snprintf(irq->name, UBASE_INT_NAME_LEN, "ubase%d-%s-%d",
		 udev->dev_id, "aeq", 0);

	ret = ubase_create_eq(udev, &aeq->eq, 0, irq, UBASE_EQ_TYPE_AEQ);
	if (ret) {
		ubase_err(udev, "failed to create aeq, ret = %d.\n", ret);
		return ret;
	}

	if (ubase_ubus_irq_vector(udev->dev, 0) == -EOPNOTSUPP)
		return 0;

	raw_spin_lock_init(&aeq->aeq_lock);
	ret = request_irq(irq->irqn, ubase_aeq_int_handler, 0, irq->name, udev);
	if (ret) {
		ubase_err(udev,
			  "failed to request aeq irq, ret = %d.\n", ret);

		if (ubase_destroy_eq(udev, &irq_table->aeq.eq, UBASE_EQ_TYPE_AEQ))
			ubase_err(udev, "failed to destroy aeq.\n");
		return ret;
	}

	init_completion(&aeq->poll);

	snprintf(task_name, UBASE_INT_NAME_LEN, "ubase_ae%d", udev->dev_id);
	aeq->ae_task = kthread_run(ubase_ae_task_handle, udev, task_name);
	if (IS_ERR(aeq->ae_task)) {
		ret = PTR_ERR(aeq->ae_task);
		ubase_err(udev, "failed to create ae task thread, ret = %d\n",
			  ret);
		free_irq(aeq->eq.irqn, udev);
		if (ubase_destroy_eq(udev, &irq_table->aeq.eq,
				     UBASE_EQ_TYPE_AEQ))
			ubase_err(udev, "failed to destroy aeq.\n");
		return ret;
	}

	return 0;
}

static void ubase_free_misc_irq(struct ubase_dev *udev)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	struct ubase_irq *irq;

	if (!irq_table->irqs)
		return;

	ubase_enable_misc_vector(udev, false);

	irq = irq_table->irqs[UBASE_MISC_IRQ_INDEX];
	if (ubase_ubus_irq_vector(udev->dev, 0) != -EOPNOTSUPP)
		free_irq(irq->irqn, udev);
}

static void ubase_free_ceq_irqs(struct ubase_dev *udev)
{
	struct ubase_ceqs *ceqs = &udev->irq_table.ceqs;
	u32 i;

	if (ubase_dev_pmu_supported(udev))
		return;

	for (i = 0; i < ceqs->num; i++) {
		if (ubase_ubus_irq_vector(udev->dev, 0) != -EOPNOTSUPP)
			free_irq(ceqs->ceq[i].eq.irqn, &ceqs->ceq[i]);
	}
}

static void ubase_free_aeq_irq(struct ubase_dev *udev)
{
	struct ubase_aeq *aeq = &udev->irq_table.aeq;
	int ret;

	if (ubase_dev_pmu_supported(udev))
		return;

	if (!aeq->ae_task)
		return;

	if (ubase_shutting_down(udev))
		complete(&aeq->poll);

	ret = kthread_stop(aeq->ae_task);
	if (ret)
		ubase_err(udev, "failed to stop ae task thread, ret = %d\n",
			  ret);

	aeq->ae_task = NULL;

	if (ubase_ubus_irq_vector(udev->dev, 0) != -EOPNOTSUPP)
		free_irq(aeq->eq.irqn, udev);
}

static void ubase_destroy_ceqs(struct ubase_dev *udev)
{
	struct ubase_ceqs *ceqs = &udev->irq_table.ceqs;
	u32 i;

	if (ubase_dev_pmu_supported(udev))
		return;

	if (!ceqs->ceq)
		return;

	for (i = 0; i < ceqs->num; i++) {
		if (ubase_destroy_eq(udev, &ceqs->ceq[i].eq, UBASE_EQ_TYPE_CEQ))
			ubase_err(udev, "failed to destroy ceq[%u].\n", i);
	}
	mutex_lock(&udev->irq_table.ceq_lock);
	devm_kfree(udev->dev, ceqs->ceq);
	ceqs->ceq = NULL;
	mutex_unlock(&udev->irq_table.ceq_lock);
}

static void ubase_destroy_aeq(struct ubase_dev *udev)
{
	struct ubase_aeq *aeq = &udev->irq_table.aeq;

	if (ubase_dev_pmu_supported(udev))
		return;

	if (!aeq->eq.addr.addr)
		return;

	if (ubase_destroy_eq(udev, &aeq->eq, UBASE_EQ_TYPE_AEQ))
		ubase_err(udev, "failed to destroy aeq.\n");
}

static int ubase_request_ceq_irq(struct ubase_dev *udev, struct ubase_ceq *ceq,
				 u32 index)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	struct ubase_irq *irq;
	int ret;

	irq = irq_table->irqs[index + UBASE_CEQ_IRQ_INDEX];
	snprintf(irq->name, UBASE_INT_NAME_LEN, "ubase%d-%s-%u",
		 udev->dev_id, "ceq", index);
	ceq->udev = udev;
	ret = ubase_create_eq(udev, &ceq->eq, index, irq, UBASE_EQ_TYPE_CEQ);
	if (ret) {
		ubase_err(udev,
			  "failed to create ceq[%u], ret = %d.\n", index, ret);
		return ret;
	}

	if (ubase_ubus_irq_vector(udev->dev, 0) == -EOPNOTSUPP)
		return 0;

	ret = request_irq(irq->irqn, ubase_ceq_int_handler, 0, irq->name, ceq);
	if (ret) {
		ubase_err(udev, "failed to request ceq[%u], ret = %d.\n",
			  index, ret);
		if (ubase_destroy_eq(udev, &ceq->eq, UBASE_EQ_TYPE_CEQ))
			ubase_err(udev, "failed to destroy ceq.\n");
	}

	return ret;
}

static int ubase_request_ceq_irqs(struct ubase_dev *udev)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	struct ubase_ceqs *ceqs = &irq_table->ceqs;
	u32 ceq_irq_num, i;
	int ret;

	if (ubase_dev_pmu_supported(udev))
		return 0;

	mutex_lock(&udev->irq_table.ceq_lock);
	ceq_irq_num = udev->caps.dev_caps.num_ceq_vectors;
	ceqs->ceq = devm_kcalloc(udev->dev, ceq_irq_num,
				 sizeof(struct ubase_ceq), GFP_KERNEL);
	if (!ceqs->ceq) {
		mutex_unlock(&udev->irq_table.ceq_lock);
		return -ENOMEM;
	}
	mutex_unlock(&udev->irq_table.ceq_lock);

	ceqs->num = ceq_irq_num;

	for (i = 0; i < ceq_irq_num; i++) {
		ret = ubase_request_ceq_irq(udev, &ceqs->ceq[i], i);
		if (ret) {
			ubase_err(udev,
				  "failed to request ceq[%u] irq, ret = %d.\n",
				  i, ret);
			ceqs->num = i;
			goto err_alloc_ceq;
		}
	}

	return 0;

err_alloc_ceq:
	ubase_free_ceq_irqs(udev);
	ubase_destroy_ceqs(udev);

	return ret;
}

static int ubase_irq_init(struct ubase_dev *udev)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	u32 irqs_num = irq_table->irqs_num;
	struct ubase_irq **irqs;
	int ret;
	u32 i;

	irqs = kcalloc(irqs_num, sizeof(struct ubase_irq *), GFP_KERNEL);
	if (!irqs) {
		ubase_err(udev, "failed to alloc irqs.\n");
		return -ENOMEM;
	}

	for (i = 0; i < irqs_num; i++) {
		irqs[i] = kzalloc(sizeof(struct ubase_irq), GFP_KERNEL);
		if (!irqs[i]) {
			ubase_err(udev, "failed to alloc ubase irq[%u].\n", i);
			ret = -ENOMEM;
			goto err_alloc_ubase_irq;
		}

		if (ubase_ubus_irq_vector(udev->dev, 0) == -EOPNOTSUPP)
			continue;

		irqs[i]->irqn = ubase_ubus_irq_vector(udev->dev, i);
		if (irqs[i]->irqn < 0) {
			ubase_err(udev,
				  "failed to get irq[%u] num, err irq num = %d.\n",
				  i, irqs[i]->irqn);
			ret = irqs[i]->irqn;
			kfree(irqs[i]);
			goto err_alloc_ubase_irq;
		}
	}
	irq_table->irqs = irqs;

	return 0;

err_alloc_ubase_irq:
	for (; i > 0; i--)
		kfree(irqs[i - 1]);
	kfree(irqs);
	irq_table->irqs = NULL;

	return ret;
}

static void ubase_irq_uninit(struct ubase_dev *udev)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	u32 i;

	if (!irq_table->irqs)
		return;

	for (i = 0; i < irq_table->irqs_num; i++)
		kfree(irq_table->irqs[i]);
	kfree(irq_table->irqs);
	irq_table->irqs = NULL;
}

static int ubase_request_irq(struct ubase_dev *udev)
{
	int ret;

	ret = ubase_request_misc_irq(udev);
	if (ret) {
		ubase_err(udev,
			  "failed to request ubase misc irq, ret = %d.\n", ret);
		goto err_misc_init;
	}

	ret = ubase_request_aeq_irq(udev);
	if (ret) {
		ubase_err(udev,
			  "failed to request ubase aeq irq, ret = %d.\n", ret);
		goto err_aeq_init;
	}

	ret = ubase_request_ceq_irqs(udev);
	if (ret) {
		ubase_err(udev,
			  "failed to request ubase ceq irqs, ret = %d.\n", ret);
		goto err_ceq_init;
	}

	return 0;

err_ceq_init:
	ubase_free_aeq_irq(udev);
	ubase_destroy_aeq(udev);
err_aeq_init:
	ubase_free_misc_irq(udev);
err_misc_init:
	return ret;
}

static void ubase_free_irq(struct ubase_dev *udev)
{
	ubase_free_ceq_irqs(udev);
	ubase_free_aeq_irq(udev);
	ubase_free_misc_irq(udev);
}

int ubase_irq_table_init(struct ubase_dev *udev)
{
	struct ubase_irq_table *irq_table = &udev->irq_table;
	int i, j, ret;

	if (ubase_dev_pmu_supported(udev) && !ubase_pmu_irq_supported(udev))
		return 0;

	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits)) {
		for (i = 0; i < UBASE_DRV_MAX; i++) {
			for (j = 0; j < UBASE_EVENT_TYPE_MAX; j++)
				BLOCKING_INIT_NOTIFIER_HEAD(&irq_table->nh[i][j]);
		}
		mutex_init(&udev->irq_table.ceq_lock);
	}

	ret = ubase_ubus_irq_vectors_alloc(udev->dev);
	if (ret) {
		ubase_err(udev, "failed to alloc irq vectors, ret = %d.\n",
			  ret);
		goto err_irq_res_init;
	}

	ret = ubase_irq_init(udev);
	if (ret) {
		ubase_err(udev, "failed to init ubase irq, ret = %d.\n", ret);
		goto err_irq_init;
	}

	ubase_clear_all_event_cause(udev);

	ret = ubase_request_irq(udev);
	if (ret) {
		ubase_err(udev, "failed to request ubase irq, ret = %d.\n",
			  ret);
		goto err_request_irq;
	}

	clear_bit(UBASE_STATE_IRQ_INVALID_B, &udev->state_bits);

	return 0;

err_request_irq:
	ubase_irq_uninit(udev);
err_irq_init:
	ubase_ubus_irq_vectors_free(udev->dev);
err_irq_res_init:
	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		mutex_destroy(&udev->irq_table.ceq_lock);

	return ret;
}

void ubase_irq_table_free(struct ubase_dev *udev)
{
	if (test_and_set_bit(UBASE_STATE_IRQ_INVALID_B, &udev->state_bits))
		return;

	ubase_free_irq(udev);
	ubase_irq_uninit(udev);
	ubase_ubus_irq_vectors_free(udev->dev);
}

void ubase_irq_table_uninit(struct ubase_dev *udev)
{
	if (ubase_dev_pmu_supported(udev) && !ubase_pmu_irq_supported(udev))
		return;

	ubase_irq_table_free(udev);
	ubase_destroy_ceqs(udev);
	ubase_destroy_aeq(udev);

	if (!test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		mutex_destroy(&udev->irq_table.ceq_lock);
}

void ubase_disable_ce_irqs(struct ubase_dev *udev)
{
	struct ubase_ceqs *ceqs = &udev->irq_table.ceqs;
	u32 i;

	if (ubase_dev_pmu_supported(udev))
		return;

	if (test_bit(UBASE_STATE_IRQ_INVALID_B, &udev->state_bits))
		return;

	for (i = 0; i < ceqs->num; i++)
		disable_irq(ceqs->ceq[i].eq.irqn);
}

static int __ubase_event_register(struct ubase_dev *udev,
				  struct ubase_event_nb *cb)
{
	struct blocking_notifier_head *nh;
	int ret;

	if (cb->drv_type >= UBASE_DRV_MAX) {
		ubase_err(udev, "register unsupported drv_type(%u).\n",
			  cb->drv_type);
		return -EINVAL;
	}

	if (cb->event_type >= UBASE_EVENT_TYPE_MAX) {
		ubase_err(udev, "register unsupported event type(%u).\n",
			  cb->event_type);
		return -EINVAL;
	}

	nh = udev->irq_table.nh[cb->drv_type];
	ret = blocking_notifier_chain_register(&nh[cb->event_type], &cb->nb);
	if (ret)
		ubase_err(udev,
			  "failed to notifier chain register, type = %u, ret = %d.\n",
			  cb->event_type, ret);

	return ret;
}

/**
 * ubase_event_register() - register asynchronous event processing function
 * @adev: auxiliary device
 * @cb: asynchronous event notification block
 *
 * This function uses 'blocking_notifier_chain_register' to register the
 * asynchronous event handling function. When the ubase driver receives an
 * asynchronous event and matches it with the registered event notification
 * block, it calls the registered function via 'blocking_notifier_call_chain'.
 *
 * Context: Process context, Takes and releases the RCU lock.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_event_register(struct auxiliary_device *adev,
			 struct ubase_event_nb *cb)
{
	if (!adev || !cb)
		return -EINVAL;

	return __ubase_event_register(__ubase_get_udev_by_adev(adev), cb);
}
EXPORT_SYMBOL(ubase_event_register);

static void __ubase_event_unregister(struct ubase_dev *udev,
				     struct ubase_event_nb *cb)
{
	struct blocking_notifier_head *nh;
	int ret;

	if (cb->drv_type >= UBASE_DRV_MAX) {
		ubase_err(udev, "unregister unsupported drv_type(%u).\n",
			  cb->drv_type);
		return;
	}

	if (cb->event_type >= UBASE_EVENT_TYPE_MAX) {
		ubase_err(udev, "unregister unsupported event type(%u).\n",
			  cb->event_type);
		return;
	}

	nh = udev->irq_table.nh[cb->drv_type];
	ret = blocking_notifier_chain_unregister(&nh[cb->event_type], &cb->nb);
	if (ret)
		ubase_err(udev,
			  "failed to unregister notifier chain, type = %u, ret = %d.\n",
			  cb->event_type, ret);
}

/**
 * ubase_event_unregister() - unregister asynchronous event processing function
 * @adev: auxiliary device
 * @cb: ubase asynchronous event notification block
 *
 * This function uses 'blocking_notifier_chain_unregister' to unregister the
 * asynchronous event handling function.
 *
 * Context: Process context, Takes and releases the RCU lock.
 */
void ubase_event_unregister(struct auxiliary_device *adev,
			    struct ubase_event_nb *cb)
{
	if (!adev || !cb)
		return;

	__ubase_event_unregister(__ubase_get_udev_by_adev(adev), cb);
}
EXPORT_SYMBOL(ubase_event_unregister);

/**
 * ubase_comp_register() - register completion event processing function
 * @adev: auxiliary device
 * @comp_handler: completion event processing function. nb: struct notifier_block,
 * jfcn: jfc index, data: self-defined data pointer.
 *
 * This function uses 'atomic_notifier_chain_register' to register the
 * completion event handling function. When the ubase driver receives a
 * completion event that matches a registered auxiliary device, it calls the
 * registered function via 'atomic_notifier_call_chain'.
 *
 * Context: Process context, may sleep
 * Return: 0 on success, negative error code otherwise
 */
int ubase_comp_register(struct auxiliary_device *adev,
			int (*comp_handler)(struct notifier_block *nb,
					    unsigned long jfcn, void *data))
{
	struct ubase_adev *uadev;
	int ret;

	if (!adev || !comp_handler)
		return -EINVAL;

	uadev = container_of(adev, struct ubase_adev, adev);
	uadev->comp_notifier.notifier_call = comp_handler;

	if (ubase_shutting_down(uadev->udev))
		return 0;

	ret = atomic_notifier_chain_register(&uadev->comp_nh,
					     &uadev->comp_notifier);
	if (ret)
		ubase_err(uadev->udev,
			  "failed to register comp notifier chain, ret = %d.\n",
			  ret);

	return ret;
}
EXPORT_SYMBOL(ubase_comp_register);

/**
 * ubase_comp_unregister() - unregister completion event processing function
 * @adev: auxiliary device
 *
 * This function uses 'atomic_notifier_chain_unregister' to unregister the
 * completion event handling function.
 *
 * Context: Process context, Takes and releases the RCU lock.
 */
void ubase_comp_unregister(struct auxiliary_device *adev)
{
	struct ubase_adev *uadev;
	int ret;

	if (!adev)
		return;

	uadev = container_of(adev, struct ubase_adev, adev);
	if (ubase_shutting_down(uadev->udev))
		return;

	ret = atomic_notifier_chain_unregister(&uadev->comp_nh,
					       &uadev->comp_notifier);
	if (ret)
		ubase_err(uadev->udev,
			  "failed to unregister comp notifier chain, ret = %d.\n",
			  ret);
}
EXPORT_SYMBOL(ubase_comp_unregister);

static int ubase_ae_entity_level_error(struct notifier_block *nb,
				       unsigned long event, void *data)
{
	struct ubase_event_nb *ev_nb = container_of(nb,
						    struct ubase_event_nb, nb);
	struct ubase_aeq_notify_info *info = data;
	struct ubase_dev *udev = ev_nb->back;

	ubase_err(udev,
		  "ubase async event for ue level error, event_type=0x%x, sub_type=0x%x.\n",
		  info->event_type, info->sub_type);

	__ubase_reset_event(udev, UBASE_UE_RESET);

	return 0;
}

static void __ubase_unregister_ae_event(struct ubase_dev *udev, int num)
{
	int i;

	for (i = 0; i < num; i++)
		__ubase_event_unregister(udev, &udev->irq_table.aeq.cb[i]);
}

void ubase_unregister_ae_event(struct ubase_dev *udev)
{
	__ubase_unregister_ae_event(udev, UBASE_AE_LEVEL_NUM);
}

int ubase_register_ae_event(struct ubase_dev *udev)
{
	struct ubase_event_nb ubase_ae_nbs[UBASE_AE_LEVEL_NUM] = {
		{
			.drv_type = UBASE_DRV_UNIC,
			.event_type = UBASE_EVENT_TYPE_TP_FLUSH_DONE,
			.nb = { ubase_ae_tp_flush_done },
			.back = udev
		}, {
			.drv_type = UBASE_DRV_UNIC,
			.event_type = UBASE_EVENT_TYPE_TP_LEVEL_ERROR,
			.nb = { ubase_ae_tp_level_error },
			.back = udev
		}, {
			.drv_type = UBASE_DRV_UNIC,
			.event_type = UBASE_EVENT_TYPE_ENTITY_LEVEL_ERROR,
			.nb = { ubase_ae_entity_level_error },
			.back = udev
		}
	};
	struct ubase_aeq *aeq = &udev->irq_table.aeq;
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(ubase_ae_nbs); i++) {
		aeq->cb[i] = ubase_ae_nbs[i];
		ret = __ubase_event_register(udev, &aeq->cb[i]);
		if (ret) {
			ubase_err(udev,
				  "failed to register asyn event[%u], ret = %d",
				  aeq->cb[i].event_type, ret);
			__ubase_unregister_ae_event(udev, i);
			return ret;
		}
	}

	return 0;
}
