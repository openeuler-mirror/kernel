// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus msg: " fmt

#include <linux/delay.h>
#include <linux/limits.h>
#include <linux/module.h>

#include "pool.h"
#include "link.h"
#include "msg.h"

u8 err_to_msg_rsp(int err)
{
	if (err >= 0)
		return err;

	switch (err) {
	case -ENOMEM:
		return UB_MSG_RSP_EXEC_ENOMEM;
	case -EACCES:
		return UB_MSG_RSP_EXEC_EACCES;
	case -EFAULT:
		return UB_MSG_RSP_EXEC_EFAULT;
	case -EBUSY:
		return UB_MSG_RSP_EXEC_EBUSY;
	case -ENODEV:
		return UB_MSG_RSP_EXEC_ENODEV;
	case -EINVAL:
		return UB_MSG_RSP_EXEC_EINVAL;
	case -ENOEXEC:
		return UB_MSG_RSP_EXEC_ENOEXEC;
	default:
		return UB_MSG_RSP_UNKNOWN;
	}
}

static LIST_HEAD(message_device_list);
static DEFINE_SPINLOCK(message_device_lock);

int message_device_register(struct message_device *mdev)
{
	spin_lock(&message_device_lock);
	list_add_tail(&mdev->list, &message_device_list);
	spin_unlock(&message_device_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(message_device_register);

void message_device_unregister(struct message_device *mdev)
{
	spin_lock(&message_device_lock);
	list_del(&mdev->list);
	spin_unlock(&message_device_lock);
}
EXPORT_SYMBOL_GPL(message_device_unregister);

static struct dev_message *dev_message_get(struct ub_entity *uent)
{
	struct dev_message *msg = uent->message;

	if (msg)
		return msg;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return NULL;

	uent->message = msg;

	return msg;
}

static void dev_message_put(struct ub_entity *uent)
{
	kfree(uent->message);
	uent->message = NULL;
}

int message_probe_device(struct ub_entity *uent)
{
	if (!dev_message_get(uent))
		return -ENOMEM;

	if (!uent->message->mdev)
		uent->message->mdev = uent->ubc->mdev;

	return 0;
}

void message_remove_device(struct ub_entity *uent)
{
	if (!uent->message)
		return;

	dev_message_put(uent);
}

int message_sync_request(struct message_device *mdev, struct msg_info *info,
			 u8 code)
{
	int ret, i = 1;

	if (mdev->ops->sync_request) {
		while (1) {
			ret = mdev->ops->sync_request(mdev, info, code);
			if (ret != -ETIMEDOUT)
				return ret;

			i++;

			if (!msg_retry || i > RETRY_COUNT)
				return -ETIMEDOUT;
		}
	}

	return -ENOTTY;
}

int message_send(struct message_device *mdev, struct msg_info *info,
		 u8 code)
{
	if (mdev->ops->send)
		return mdev->ops->send(mdev, info, code);

	return -ENOTTY;
}

int message_response(struct message_device *mdev, struct msg_info *info,
		     u8 code)
{
	if (mdev->ops->response)
		return mdev->ops->response(mdev, info, code);

	return -ENOTTY;
}
EXPORT_SYMBOL_GPL(message_response);

int message_sync_enum(struct message_device *mdev, struct msg_info *info,
		      u8 cmd)
{
	int ret, i = 1;

	if (mdev->ops->sync_enum) {
		while (1) {
			ret = mdev->ops->sync_enum(mdev, info, cmd);
			if (ret != -ETIMEDOUT)
				return ret;

			i++;

			if (!msg_retry || i > RETRY_COUNT)
				return -ETIMEDOUT;
		}
	}

	return -ENOTTY;
}

static struct workqueue_struct *rx_msg_wq[UB_MSG_CODE_NUM];
struct workqueue_struct *get_rx_msg_wq(u8 msg_code)
{
	return rx_msg_wq[msg_code];
}

static atomic_t msg_rx_flag;

int message_rx_init(void)
{
	const char *msg_name[UB_MSG_CODE_NUM] = {
		NULL, "link wq", NULL, "vdm wq",
		NULL, NULL, "pool wq", NULL
	};
	struct workqueue_struct *q;
	int i;

	for (i = 0; i < UB_MSG_CODE_NUM; i++) {
		if (!msg_name[i])
			continue;
		q = create_singlethread_workqueue(msg_name[i]);
		if (!q) {
			pr_err("alloc workqueue[%d] failed\n", i);
			message_rx_uninit();
			return -ENOMEM;
		}

		rx_msg_wq[i] = q;
	}

	wmb(); /* Ensure the register is written correctly. */
	atomic_set(&msg_rx_flag, 1);

	return 0;
}

void message_rx_uninit(void)
{
#define MSG_RX_WAIT_US 15000
	struct workqueue_struct *q;
	int i;

	atomic_set(&msg_rx_flag, 0);
	wmb(); /* Ensure the register is written correctly. */
	/* For cpus still handle rx msg in interrupt context */
	udelay(MSG_RX_WAIT_US);

	for (i = 0; i < UB_MSG_CODE_NUM; i++) {
		q = rx_msg_wq[i];
		if (q) {
			flush_workqueue(q);
			destroy_workqueue(q);
			rx_msg_wq[i] = NULL;
		}
	}
}

static struct ub_rx_msg_task *
message_rx_task_alloc_and_init(struct ub_bus_controller *ubc, void *pkt, u16 len,
			       work_func_t func)
{
	struct ub_rx_msg_task *task;

	task = kzalloc(sizeof(*task), GFP_ATOMIC);
	if (!task)
		return (struct ub_rx_msg_task *)ERR_PTR(-ENOMEM);

	task->pkt = kzalloc(len, GFP_ATOMIC);
	if (!task->pkt) {
		kfree(task);
		return (struct ub_rx_msg_task *)ERR_PTR(-ENOMEM);
	}

	memcpy(task->pkt, pkt, len);
	task->len = len;
	task->ubc = ubc;
	INIT_WORK(&task->work, func);

	return task;
}

static void message_rx_task_free(struct ub_rx_msg_task *task)
{
	kfree(task->pkt);
	kfree(task);
}

static bool msg_rx_code_valid(struct ub_bus_controller *ubc, u8 code)
{
	u8 msg = msg_code(code);

	if (msg_type(code) == MSG_RSP)
		return false;

	switch (msg) {
	case UB_MSG_CODE_RAS:
	case UB_MSG_CODE_CFG:
	case UB_MSG_CODE_EXCH:
	case UB_MSG_CODE_SEC:
	case UB_MSG_CODE_MAX:
		return false;

	case UB_MSG_CODE_POOL:
		if (!ubc->cluster)
			return false;
		break;

	default:
		break;
	}

	if (!rx_msg_wq[msg]) {
		dev_err(&ubc->dev, "no workqueue registered for msg %u\n", msg);
		return false;
	}

	return true;
}

static rx_msg_handler_t rx_msg_handler[UB_MSG_CODE_NUM] = {
	NULL,
	ub_link_msg_handler,
	NULL,
	NULL,
	NULL,
	NULL,
	ub_pool_rx_msg_handler,
};

static void message_rx_work(struct work_struct *work)
{
	struct ub_rx_msg_task *task = container_of(work, struct ub_rx_msg_task,
						   work);
	struct msg_pkt_header *header = (struct msg_pkt_header *)task->pkt;
	u8 msg_code = header->msgetah.msg_code;
	struct ub_bus_controller *ubc = task->ubc;
	rx_msg_handler_t handler;

	handler = rx_msg_handler[msg_code];

	if (msg_code == UB_MSG_CODE_VDM)
		handler = ubc->mdev->ops->vdm_rx_handler;

	if (handler)
		handler(ubc, task->pkt, task->len);
	else
		dev_err(&ubc->dev, "rx msg code not support, code=%#x\n",
			msg_code);

	message_rx_task_free(task);
}

int message_rx_handler(struct ub_bus_controller *ubc, void *pkt, u16 len)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	struct msg_extended_header *msgetah = &header->msgetah;
	struct ub_rx_msg_task *task;

	if (!atomic_read(&msg_rx_flag))
		return -EBUSY;

	if (len < MSG_PKT_HEADER_SIZE) {
		dev_err(&ubc->dev, "rx msg len invalid, len=%#x\n", len);
		return -EINVAL;
	}

	if (msgetah->plen != len - MSG_PKT_HEADER_SIZE) {
		dev_err(&ubc->dev, "rx msg plen invalid, len=%#x, plen=%#x\n",
			len, msgetah->plen);
		return -EINVAL;
	}

	if (!msg_rx_code_valid(ubc, msgetah->code)) {
		dev_err(&ubc->dev, "rx msg code invalid, code=%#x\n",
			msgetah->code);
		return -EINVAL;
	}

	dev_info(&ubc->dev, "rx msg coming, code=%#x\n", msgetah->code);

	task = message_rx_task_alloc_and_init(ubc, pkt, len, message_rx_work);
	if (IS_ERR(task))
		return PTR_ERR(task);

	queue_work(rx_msg_wq[msgetah->msg_code], &task->work);
	return 0;
}
EXPORT_SYMBOL_GPL(message_rx_handler);

static int handle_vdm_rsp_msg(struct ub_entity *uent, struct ub_vdm_pld *vdm_pld,
			      struct msg_info *info)
{
	struct msg_pkt_header *header;

	header = (struct msg_pkt_header *)info->rsp_packet;
	if (header->msgetah.plen > vdm_pld->rsp_buf_len) {
		ub_err(uent, "rsp msg len error, plen=%u, buf_len=%u\n",
		       header->msgetah.plen, vdm_pld->rsp_buf_len);
		return -ENOMEM;
	}

	if (header->msgetah.rsp_status) {
		ub_err(uent, " vdm rsp msg status error, status=%u\n",
		       header->msgetah.rsp_status);
		return -EINVAL;
	}

	vdm_pld->rsp_pld_len = header->msgetah.plen;
	if (!vdm_pld->rsp_pld) {
		if (!vdm_pld->rsp_pld_len)
			return 0;

		ub_err(uent, "rsp_pld is NULL\n");
		return -EINVAL;
	}

	memcpy(vdm_pld->rsp_pld, info->rsp_packet + MSG_PKT_HEADER_SIZE,
	       vdm_pld->rsp_pld_len);

	return 0;
}

int ub_vdm_message(struct ub_entity *uent, struct ub_vdm_pld *vdm_pld)
{
	struct msg_pkt_header *header;
	struct msg_info info = {};
	void *req_pkt;
	void *rsp_pkt;
	u32 pkt_size;
	int ret;
	u8 code;

	if (!uent || !uent->message || !uent->message->mdev || !vdm_pld ||
	    !vdm_pld->req_pld || !vdm_pld->req_pld_len) {
		pr_err("input data error\n");
		return -EINVAL;
	}

	if (vdm_pld->req_pld_len > SZ_1K ||
	    MSG_PKT_HEADER_SIZE + vdm_pld->rsp_buf_len > U16_MAX) {
		ub_err(uent, "input vdm msg too long\n");
		return -EINVAL;
	}

	req_pkt = kzalloc(MSG_PKT_HEADER_SIZE + vdm_pld->req_pld_len, GFP_ATOMIC);
	if (!req_pkt)
		return -ENOMEM;

	rsp_pkt = kzalloc(MSG_PKT_HEADER_SIZE + vdm_pld->rsp_buf_len, GFP_ATOMIC);
	if (!rsp_pkt) {
		kfree(req_pkt);
		return -ENOMEM;
	}

	code = code_gen(UB_MSG_CODE_VDM, vdm_pld->sub_msg_code, MSG_REQ);
	header = (struct msg_pkt_header *)req_pkt;
	pkt_size = msg_size_gen((vdm_pld->req_pld_len + MSG_PKT_HEADER_SIZE),
				(vdm_pld->rsp_buf_len + MSG_PKT_HEADER_SIZE));
	ub_msg_pkt_header_init(header, uent, vdm_pld->req_pld_len, code, false);
	memcpy(req_pkt + MSG_PKT_HEADER_SIZE, vdm_pld->req_pld,
	       vdm_pld->req_pld_len);
	message_info_init(&info, uent, req_pkt, rsp_pkt, pkt_size);
	ret = message_sync_request(uent->message->mdev, &info, code);
	if (ret) {
		ub_err(uent, "message sync execute error, ret=%d\n", ret);
		goto out;
	}

	ret = handle_vdm_rsp_msg(uent, vdm_pld, &info);

out:
	kfree(req_pkt);
	kfree(rsp_pkt);

	return ret;
}
EXPORT_SYMBOL_GPL(ub_vdm_message);
