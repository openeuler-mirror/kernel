// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: <%s:%d> " fmt, __func__, __LINE__

#include <linux/slab.h>
#include <linux/wait.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "udma_jfc.h"
#include "udma_jfr.h"
#include "udma_jetty.h"
#include "udma_ctrlq_tp.h"
#include "udma_safe_mode.h"

int udma_init_mbox_over_cmdq(struct udma_dev *udev)
{
	struct udma_mbox_over_cmdq_info *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	mutex_init(&info->tbl_lock);
	mutex_init(&info->seq_lock);
	xa_init(&info->seq_tbl);
	info->seq_num = 0;
	udev->mbox_over_cmdq_info = info;

	return 0;
}

void udma_uninit_mbox_over_cmdq(struct udma_dev *udev)
{
	struct udma_mbox_over_cmdq_info *info = udev->mbox_over_cmdq_info;
	struct udma_mbox_over_cmdq_completion *wait_completion;
	unsigned long index = 0;

	if (!info)
		return;

	mutex_lock(&info->tbl_lock);
	if (!xa_empty(&info->seq_tbl))
		xa_for_each(&info->seq_tbl, index, wait_completion)
			xa_erase(&info->seq_tbl, index);
	xa_destroy(&info->seq_tbl);
	mutex_unlock(&info->tbl_lock);
	mutex_destroy(&info->tbl_lock);
	mutex_destroy(&info->seq_lock);
	kfree(info);
}

static int udma_get_trans_len_by_op(uint8_t op)
{
#define UDMA_CTX_MULTIPLE 2

	switch (op) {
	/* ctx len */
	case UDMA_CMD_CREATE_JFC_CONTEXT:
		return sizeof(struct udma_jfc_ctx);
	case UDMA_CMD_CREATE_JFS_CONTEXT:
		return sizeof(struct udma_jetty_ctx);
	case UDMA_CMD_CREATE_JFR_CONTEXT:
		return sizeof(struct udma_jfr_ctx);
	case UDMA_CMD_CREATE_JETTY_GROUP_CONTEXT:
		return sizeof(struct udma_jetty_grp_ctx);

	/* ctx + mask len */
	case UDMA_CMD_MODIFY_JFC_CONTEXT:
		return sizeof(struct udma_jfc_ctx) * UDMA_CTX_MULTIPLE;
	case UDMA_CMD_MODIFY_JFS_CONTEXT:
		return sizeof(struct udma_jetty_ctx) * UDMA_CTX_MULTIPLE;
	case UDMA_CMD_MODIFY_JFR_CONTEXT:
		return sizeof(struct udma_jfr_ctx) * UDMA_CTX_MULTIPLE;
	case UDMA_CMD_MODIFY_JETTY_GROUP_CONTEXT:
		return sizeof(struct udma_jetty_grp_ctx) * UDMA_CTX_MULTIPLE;
	default:
		return 0;
	}
}

static int udma_get_resp_len_by_op(uint8_t op)
{
	switch (op) {
	/* ctx len */
	case UDMA_CMD_QUERY_JFC_CONTEXT:
		return sizeof(struct udma_jfc_ctx);
	case UDMA_CMD_QUERY_JFS_CONTEXT:
		return sizeof(struct udma_jetty_ctx);
	case UDMA_CMD_QUERY_JFR_CONTEXT:
		return sizeof(struct udma_jfr_ctx);
	case UDMA_CMD_QUERY_JETTY_GROUP_CONTEXT:
		return sizeof(struct udma_jetty_grp_ctx);
	default:
		return 0;
	}
}

static inline uint32_t udma_get_seq_for_cmdq(struct udma_dev *udev)
{
	uint32_t seq;

	mutex_lock(&udev->mbox_over_cmdq_info->seq_lock);
	seq = ++udev->mbox_over_cmdq_info->seq_num;
	mutex_unlock(&udev->mbox_over_cmdq_info->seq_lock);

	return seq;
}

static int udma_wait_resp_from_proxy(struct udma_dev *udev,
				     struct ubase_proxy_req_msg *req,
				     struct ubase_cmd_mailbox *mbox)
{
#define UDMA_WAIT_RESP_TIME msecs_to_jiffies(500)

	struct udma_mbox_over_cmdq_info *info = udev->mbox_over_cmdq_info;
	struct udma_mbox_over_cmdq_completion wait_completion;
	int ret;

	wait_completion.mbox = mbox;
	wait_completion.mbox_len = udma_get_resp_len_by_op(req->opcode);
	wait_completion.ret_success = false;
	wait_completion.ret = -EFAULT;

	mutex_lock(&info->tbl_lock);
	ret = xa_err(__xa_store(&info->seq_tbl, req->seq_num, &wait_completion, GFP_KERNEL));
	mutex_unlock(&info->tbl_lock);
	if (ret) {
		dev_err(udev->dev, "save response completion failed, ret = %d.\n", ret);
		return -EFAULT;
	}

	init_completion(&wait_completion.ret_completion);
	(void)wait_for_completion_timeout(&wait_completion.ret_completion, UDMA_WAIT_RESP_TIME);

	mutex_lock(&info->tbl_lock);
	if (xa_load(&info->seq_tbl, req->seq_num))
		xa_erase(&info->seq_tbl, req->seq_num);
	mutex_unlock(&info->tbl_lock);

	if (!wait_completion.ret_success)
		dev_err(udev->dev, "wait response failed.\n");

	return wait_completion.ret;
}

int udma_post_mbox_over_cmdq(struct udma_dev *udev,
			     struct ubase_mbx_attr *attr,
			     struct ubase_cmd_mailbox *mbox)
{
	struct ubase_proxy_req_msg *req;
	uint16_t ctx_len, data_len;
	struct ubase_cmd_buf in;
	int ret;

	ctx_len = udma_get_trans_len_by_op(attr->op);
	data_len = sizeof(*req) + ctx_len;

	req = kzalloc(data_len, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->module = UBASE_MODULE_UDMA_TO_PROXY;
	req->opcode = attr->op;
	req->tag = attr->tag;
	req->seq_num = udma_get_seq_for_cmdq(udev);
	req->data_len = ctx_len;
	if (req->data_len)
		memcpy(req->data, mbox->buf, req->data_len);

	udma_fill_buf(&in, UBASE_OPC_UE_TO_PROXY, false, data_len, req);
	ret = ubase_cmd_send_in(udev->comdev.adev, &in);
	if (ret) {
		dev_err(udev->dev, "send mailbox request message failed, ret is %d.\n", ret);
		goto post_process;
	}

	ret = udma_wait_resp_from_proxy(udev, req, mbox);

post_process:
	kfree(req);

	return ret;
}

int udma_recv_resp_from_proxy(void *dev, void *data, uint32_t len)
{
	struct udma_dev *udev = get_udma_dev((struct auxiliary_device *)dev);
	struct udma_mbox_over_cmdq_info *info = udev->mbox_over_cmdq_info;
	struct udma_mbox_over_cmdq_completion *wait_completion;
	struct ubase_proxy_resp_msg *resp;
	uint32_t data_len;

	if (len < sizeof(*resp)) {
		dev_err(udev->dev, "length of response is too small, len = %u.\n", len);
		return -EINVAL;
	}
	resp = (struct ubase_proxy_resp_msg *)data;

	mutex_lock(&info->tbl_lock);
	wait_completion = xa_load(&info->seq_tbl, resp->seq_num);
	if (!wait_completion) {
		mutex_unlock(&info->tbl_lock);
		dev_err(udev->dev, "sequence of response is invalid, seq = %u.\n", resp->seq_num);
		return -EINVAL;
	}

	data_len = len - sizeof(*resp);
	if (data_len < wait_completion->mbox_len) {
		mutex_unlock(&info->tbl_lock);
		dev_err(udev->dev, "length of data in response is invalid, len = %u.\n", data_len);
		return -EINVAL;
	}

	if (resp->data_len != wait_completion->mbox_len) {
		mutex_unlock(&info->tbl_lock);
		dev_err(udev->dev, "expect len = %u, but get len = %u.\n",
			wait_completion->mbox_len, resp->data_len);
		return -EINVAL;
	}

	wait_completion->ret = resp->ret;
	if (resp->data_len)
		memcpy(wait_completion->mbox->buf, resp->data, resp->data_len);

	wait_completion->ret_success = true;
	xa_erase(&info->seq_tbl, resp->seq_num);
	complete(&wait_completion->ret_completion);
	mutex_unlock(&info->tbl_lock);

	return 0;
}
