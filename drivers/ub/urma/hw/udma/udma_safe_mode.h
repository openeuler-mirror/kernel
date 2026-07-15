/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef UDMA_SAFE_MODE_H
#define UDMA_SAFE_MODE_H

#include <linux/slab.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "udma_def.h"
#include "udma_cmd.h"

struct udma_mbox_over_cmdq_info {
	struct xarray seq_tbl;
	struct mutex tbl_lock;
	uint32_t seq_num;
	struct mutex seq_lock;
};

struct udma_mbox_over_cmdq_completion {
	int ret;
	uint16_t mbox_len;
	struct ubase_cmd_mailbox *mbox;
	struct completion ret_completion;
	bool ret_success;
};

int udma_init_mbox_over_cmdq(struct udma_dev *udev);
void udma_uninit_mbox_over_cmdq(struct udma_dev *udev);
int udma_post_mbox_over_cmdq(struct udma_dev *udev,
			     struct ubase_mbx_attr *attr,
			     struct ubase_cmd_mailbox *mbox);
int udma_recv_resp_from_proxy(void *dev, void *data, uint32_t len);

#endif /* UDMA_SAFE_MODE_H */
