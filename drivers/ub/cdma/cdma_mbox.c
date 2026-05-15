// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include "cdma_mbox.h"

static int cdma_post_mailbox(struct cdma_dev *cdev, struct ubase_mbx_attr *attr,
			     struct ubase_cmd_mailbox *mailbox)
{
	int ret;

	ret = ubase_hw_upgrade_ctx_ex(cdev->adev, attr, mailbox);
	if (ret)
		dev_err(cdev->dev,
			"send mailbox err, tag = 0x%x, op = %u, mbx_ue_id = %u, ret = %d\n",
			attr->tag, attr->op, attr->mbx_ue_id, ret);

	return ret;
}

int cdma_post_mailbox_ctx(struct cdma_dev *cdev, void *ctx, u32 size,
			  struct ubase_mbx_attr *attr)
{
	struct ubase_cmd_mailbox *mailbox;
	int ret;

	mailbox = cdma_alloc_cmd_mailbox(cdev);
	if (!mailbox) {
		dev_err(cdev->dev, "alloc mailbox failed, opcode = %u\n",
			attr->op);
		return -ENOMEM;
	}

	if (ctx && size)
		memcpy(mailbox->buf, ctx, size);

	ret = cdma_post_mailbox(cdev, attr, mailbox);

	cdma_free_cmd_mailbox(cdev, mailbox);

	return ret;
}

struct ubase_cmd_mailbox *cdma_mailbox_query_ctx(struct cdma_dev *cdev,
						 struct ubase_mbx_attr *attr)
{
	struct ubase_cmd_mailbox *mailbox;
	int ret;

	mailbox = cdma_alloc_cmd_mailbox(cdev);
	if (!mailbox) {
		dev_err(cdev->dev, "alloc mailbox failed, opcode = %u\n",
			attr->op);
		return NULL;
	}

	ret = cdma_post_mailbox(cdev, attr, mailbox);
	if (ret) {
		cdma_free_cmd_mailbox(cdev, mailbox);
		return NULL;
	}

	return mailbox;
}
