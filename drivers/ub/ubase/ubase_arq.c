// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include "ubase_arq.h"
#include "ubase_cmd.h"

void ubase_arq_init(struct ubase_dev *udev)
{
	struct ubase_arq_msg_ring *arq = &udev->arq;

	arq->ci = 0;
	arq->pi = 0;
	atomic_set(&arq->count, 0);
}

void ubase_arq_uninit(struct ubase_dev *udev)
{
	struct ubase_arq_msg_ring *arq = &udev->arq;
	int i;

	for (i = 0; i < MAX_ARQ_MSG_NUM; i++) {
		kfree(arq->msg[i].data);
		arq->msg[i].data = NULL;
	}
}

static void ubase_send_activate_resp(struct ubase_dev *udev, __le16 bus_ue_id,
				     __le16 msn, int result)
{
	struct ubase_activate_resp resp = {0};
	struct ubase_cmd_buf in;
	int ret;

	resp.bus_ue_id = bus_ue_id;
	resp.msn = msn;
	resp.result = result < 0 ? (u8)(-result) : (u8)result;
	ubase_fill_inout_buf(&in, UBASE_OPC_ACTIVATE_RESP, false, sizeof(resp),
			     &resp);
	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_err(udev,
			  "failed to send activate dev resp, ue id = %u, msn = %u, ret = %d.\n",
			  le16_to_cpu(bus_ue_id), le16_to_cpu(msn), ret);
}

static int ubase_activate_ue(struct ubase_dev *udev, struct ub_entity *ue,
			     u16 msn, u16 bus_ue_id)
{
	int ret;

	ret = ub_activate_entity(ue, bus_ue_id);
	if (ret)
		dev_err(udev->dev,
			"failed to activate ue dev, ue id = %u, msn = %u, ret = %d.\n",
			bus_ue_id, msn, ret);

	return ret;
}

static int ubase_deactivate_ue(struct ubase_dev *udev, struct ub_entity *ue,
			       u16 msn, u16 bus_ue_id)
{
	int ret;

	ret = ub_deactivate_entity(ue, bus_ue_id);
	if (ret)
		dev_err(udev->dev,
			"failed to deactivate ue dev, ue id=%u, msn=%u, ret=%d.\n",
			bus_ue_id, msn, ret);

	return ret;
}

static void ubase_handle_activate_req(struct ubase_dev *udev, void *data,
				      u32 len)
{
	struct ubase_activate_req *req = data;
	u16 bus_ue_id = le16_to_cpu(req->bus_ue_id);
	u16 msn = le16_to_cpu(req->msn);
	struct ub_entity *ue;
	int ret;

	if (!ubase_activate_proxy_supported(udev))
		return;

	udev->act_ctx.other.shutdown = req->shutdown;

	ue = container_of(udev->dev, struct ub_entity, dev);
	if (req->activate)
		ret = ubase_activate_ue(udev, ue, msn, bus_ue_id);
	else
		ret = ubase_deactivate_ue(udev, ue, msn, bus_ue_id);

	if (ret != -ETIMEDOUT)
		ubase_send_activate_resp(udev, req->bus_ue_id, req->msn, ret);
}

struct ubase_arq_event {
	u16 opcode;
	u16 len;
	void (*arq_handler)(struct ubase_dev *udev, void *data, u32 len);
} ubase_arq_map[] = {
	{
		.opcode = UBASE_OPC_ACTIVATE_REQ,
		.len = sizeof(struct ubase_activate_req),
		.arq_handler = ubase_handle_activate_req,
	},
};

bool ubase_is_arq_msg(u16 opcode)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ubase_arq_map); i++) {
		if (ubase_arq_map[i].opcode == opcode)
			return true;
	}

	return false;
}

static struct ubase_arq_event *ubase_get_arq_event(u16 opcode, u32 data_len)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ubase_arq_map); i++) {
		if (ubase_arq_map[i].opcode == opcode)
			return data_len != ubase_arq_map[i].len ?
				NULL : &ubase_arq_map[i];
	}

	return NULL;
}

void ubase_cmd_arq_handler(struct ubase_delay_work *ubase_work)
{
	struct ubase_dev *udev = container_of(ubase_work, struct ubase_dev,
					      arq_service_task);
	struct ubase_arq_msg_ring *arq = &udev->arq;
	struct ubase_arq_event *event;
	struct ubase_arq_msg *msg;

	if (!test_and_clear_bit(UBASE_STATE_ARQ_SERVICE_SCHED,
				&udev->arq_service_task.state) ||
	    test_and_set_bit(UBASE_STATE_ARQ_HANDLING,
			     &udev->arq_service_task.state))
		return;

	while (atomic_read(&arq->count) > 0) {
		/* Prevent read operations from being reordered, ensuring
		 * the correct read order of the message queue.
		 */
		smp_rmb();
		msg = &arq->msg[arq->ci];
		event = ubase_get_arq_event(msg->opcode, msg->data_len);
		if (event)
			event->arq_handler(udev, msg->data, msg->data_len);
		kfree(msg->data);
		msg->data = NULL;

		arq->ci = (arq->ci + 1) % MAX_ARQ_MSG_NUM;
		atomic_dec(&arq->count);
	}

	clear_bit(UBASE_STATE_ARQ_HANDLING, &udev->arq_service_task.state);
}

static void ubase_arq_task_schedule(struct ubase_dev *udev)
{
	if (!test_and_set_bit(UBASE_STATE_ARQ_SERVICE_SCHED,
			      &udev->arq_service_task.state))
		mod_delayed_work(udev->ubase_arq_wq,
				 &udev->arq_service_task.service_task, 0);
}

void ubase_add_to_arq(struct ubase_dev *udev, u16 opcode, void *msg_data,
		      u32 msg_data_len)
{
	struct ubase_arq_msg_ring *arq = &udev->arq;

	if (atomic_read(&arq->count) >= MAX_ARQ_MSG_NUM) {
		ubase_warn_rl(udev, arq_queue_full,
			      "arq queue full, drop opcode = 0x%x.\n", opcode);
		return;
	}

	arq->msg[arq->pi].data = kzalloc(msg_data_len, GFP_KERNEL);
	if (!arq->msg[arq->pi].data) {
		ubase_err(udev,
			  "failed to alloc arq msg data, opcode = 0x%x.\n",
			  opcode);
		return;
	}

	memcpy(arq->msg[arq->pi].data, msg_data, msg_data_len);
	arq->msg[arq->pi].data_len = msg_data_len;
	arq->msg[arq->pi].opcode = opcode;
	arq->pi = (arq->pi + 1) % MAX_ARQ_MSG_NUM;
	/* Prevent write operation reordering, and ensure that the counter is
	 * updated only after the write operation to the message queue is
	 * completed.
	 */
	smp_wmb();
	atomic_inc(&arq->count);

	ubase_arq_task_schedule(udev);
}
