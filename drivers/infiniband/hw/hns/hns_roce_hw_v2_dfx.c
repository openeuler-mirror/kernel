// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Hisilicon Limited.

#include "hnae3.h"
#include "hns_roce_device.h"
#include "hns_roce_cmd.h"
#include "hns_roce_hw_v2.h"

int hns_roce_v2_query_cqc_info(struct hns_roce_dev *hr_dev, u32 cqn,
			       int *buffer)
{
	struct hns_roce_v2_cq_context *context;
	struct hns_roce_cmd_mailbox *mailbox;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	context = mailbox->buf;
	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, cqn, 0,
				HNS_ROCE_CMD_QUERY_CQC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (ret) {
		dev_err(hr_dev->dev, "QUERY cqc cmd process error\n");
		goto err_mailbox;
	}

	memcpy(buffer, context, sizeof(*context));

err_mailbox:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}


int hns_roce_v2_query_qpc_info(struct hns_roce_dev *hr_dev, u32 qpn,
			       int *buffer)
{
	struct hns_roce_v2_qp_context *context;
	struct hns_roce_cmd_mailbox *mailbox;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, qpn, 0,
				HNS_ROCE_CMD_QUERY_QPC,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (ret) {
		dev_err(hr_dev->dev, "QUERY qpc cmd process error\n");
		goto err_mailbox;
	}

	context = mailbox->buf;
	memcpy(buffer, context, sizeof(*context));

err_mailbox:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

int hns_roce_v2_query_mpt_info(struct hns_roce_dev *hr_dev, u32 key,
			       int *buffer)
{
	struct hns_roce_v2_mpt_entry *context;
	struct hns_roce_cmd_mailbox *mailbox;
	int ret;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	context = mailbox->buf;
	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, key_to_hw_index(key),
				0, HNS_ROCE_CMD_QUERY_MPT,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (ret) {
		dev_err(hr_dev->dev, "QUERY mpt cmd process error\n");
		goto err_mailbox;
	}

	memcpy(buffer, context, sizeof(*context));

err_mailbox:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

