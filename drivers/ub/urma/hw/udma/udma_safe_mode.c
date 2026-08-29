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
	if (!xa_empty(&info->seq_tbl)) {
		xa_for_each(&info->seq_tbl, index, wait_completion) {
			if (wait_completion)
				complete(&wait_completion->ret_completion);
			__xa_erase(&info->seq_tbl, index);
		}
	}

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
		return sizeof(struct udma_jetty_ctx) + UDMA_JFS_MASK_OFFSET;
	case UDMA_CMD_MODIFY_JFR_CONTEXT:
		return sizeof(struct udma_jfr_ctx) * UDMA_CTX_MULTIPLE;
	case UDMA_CMD_MODIFY_JETTY_GROUP_CONTEXT:
		return sizeof(struct udma_jetty_grp_ctx) * UDMA_CTX_MULTIPLE;
	default:
		return 0;
	}
}

static uint16_t udma_get_resp_len_by_op(uint8_t op)
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

static inline void udma_init_req(struct udma_dev *udev,
				 struct ubase_proxy_req_msg *req,
				 struct ubase_mbx_attr *attr,
				 struct ubase_cmd_mailbox *mbox)
{
	req->module = UBASE_MODULE_UDMA_TO_PROXY;
	req->opcode = attr->op;
	req->tag = attr->tag;
	req->seq_num = udma_get_seq_for_cmdq(udev);
	req->data_len = udma_get_trans_len_by_op(attr->op);
	if (req->data_len)
		memcpy(req->data, mbox->buf, req->data_len);
}

static inline void udma_init_wait_completion(struct udma_mbox_over_cmdq_completion *wait_completion,
					     struct ubase_proxy_req_msg *req,
					     struct ubase_cmd_mailbox *mbox)
{
	wait_completion->mbox = mbox;
	wait_completion->mbox_len = udma_get_resp_len_by_op(req->opcode);
	wait_completion->ret_success = false;
	wait_completion->ret = -EFAULT;
	init_completion(&wait_completion->ret_completion);
}

static inline int udma_store_wait_completion(struct udma_dev *udev,
					     struct udma_mbox_over_cmdq_completion *wait_completion,
					     struct ubase_proxy_req_msg *req)
{
	struct udma_mbox_over_cmdq_info *info = udev->mbox_over_cmdq_info;
	int ret;

	mutex_lock(&info->tbl_lock);
	ret = xa_err(__xa_store(&info->seq_tbl, req->seq_num, wait_completion, GFP_KERNEL));
	mutex_unlock(&info->tbl_lock);

	return ret;
}

static inline void udma_remove_wait_completion(struct udma_dev *udev,
					struct udma_mbox_over_cmdq_completion *wait_completion,
					struct ubase_proxy_req_msg *req)
{
	struct udma_mbox_over_cmdq_info *info = udev->mbox_over_cmdq_info;

	mutex_lock(&info->tbl_lock);
	if (xa_load(&info->seq_tbl, req->seq_num))
		__xa_erase(&info->seq_tbl, req->seq_num);
	mutex_unlock(&info->tbl_lock);
}

int udma_post_mbox_over_cmdq(struct udma_dev *udev,
			     struct ubase_mbx_attr *attr,
			     struct ubase_cmd_mailbox *mbox)
{
#define UDMA_WAIT_RESP_TIME msecs_to_jiffies(500)

	struct udma_mbox_over_cmdq_completion *wait_completion;
	struct ubase_proxy_req_msg *req;
	struct ubase_cmd_buf in;
	uint16_t data_len;
	int ret;

	data_len = sizeof(*req) + udma_get_trans_len_by_op(attr->op);
	req = kzalloc(data_len, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	wait_completion = kzalloc(sizeof(*wait_completion), GFP_KERNEL);
	if (!wait_completion) {
		ret = -ENOMEM;
		goto alloc_wait_completion_err;
	}

	udma_init_req(udev, req, attr, mbox);
	udma_init_wait_completion(wait_completion, req, mbox);
	ret = udma_store_wait_completion(udev, wait_completion, req);
	if (ret) {
		dev_err(udev->dev, "store wait_completion failed, ret is %d.\n", ret);
		goto store_wait_completion_err;
	}

	udma_fill_buf(&in, UBASE_OPC_UE_TO_PROXY, false, data_len, req);
	ret = ubase_cmd_send_in(udev->comdev.adev, &in);
	if (ret) {
		dev_err(udev->dev, "send command queue to ubaseproxy failed, ret is %d.\n", ret);
		goto post_process;
	}

	(void)wait_for_completion_timeout(&wait_completion->ret_completion, UDMA_WAIT_RESP_TIME);
	if (wait_completion->ret_success) {
		ret = wait_completion->ret;
	} else {
		dev_err(udev->dev, "wait response from ubaseproxy failed, seq = %u.\n",
			req->seq_num);
		ret = -ETIMEDOUT;
	}

post_process:
	udma_remove_wait_completion(udev, wait_completion, req);
store_wait_completion_err:
	kfree(wait_completion);
alloc_wait_completion_err:
	kfree(req);

	return ret;
}

int udma_recv_resp_from_proxy(void *dev, void *data, uint32_t len)
{
	struct udma_dev *udev = get_udma_dev((struct auxiliary_device *)dev);
	struct udma_mbox_over_cmdq_info *info = udev->mbox_over_cmdq_info;
	struct udma_mbox_over_cmdq_completion *wait_completion;
	struct ubase_proxy_resp_msg *resp;
	uint16_t expect_len;
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

	expect_len = wait_completion->mbox_len;
	if (resp->data_len != expect_len) {
		mutex_unlock(&info->tbl_lock);
		dev_err(udev->dev, "expect len = %u, but get len = %u.\n",
			expect_len, resp->data_len);
		return -EINVAL;
	}

	wait_completion->ret = resp->ret;
	if (resp->data_len)
		memcpy(wait_completion->mbox->buf, resp->data, resp->data_len);

	wait_completion->ret_success = true;
	__xa_erase(&info->seq_tbl, resp->seq_num);
	complete(&wait_completion->ret_completion);
	mutex_unlock(&info->tbl_lock);

	return 0;
}
