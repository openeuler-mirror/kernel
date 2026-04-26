/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_MAILBOX_H__
#define __UBASE_MAILBOX_H__

#include <ub/ubase/ubase_comm_mbx.h>

#include "ubase_dev.h"

#define CMD_MBX_POLL_VALUE 0xffff
#define UBASE_MAILBOX_SIZE 4096
#define UBASE_MBX_TX_TIMEOUT 30000

enum ubase_mb_type {
	UBASE_MB_CREATE,
	UBASE_MB_MODIFY,
	UBASE_MB_DESTROY,
	UBASE_MB_QUERY,
	UBASE_MB_OTHER,
};

struct mbx_op_match {
	u32			op;
	enum ubase_mb_type	type;
	struct ubase_ctx_buf_cap	*ctx_caps;
};

int ubase_mbox_cmd_init(struct ubase_dev *udev);
void ubase_mbox_cmd_uninit(struct ubase_dev *udev);
struct ubase_cmd_mailbox *__ubase_alloc_cmd_mailbox(struct ubase_dev *udev);
void __ubase_free_cmd_mailbox(struct ubase_dev *udev,
			      struct ubase_cmd_mailbox *mailbox);
void ubase_destroy_ctx_page(struct ubase_dev *udev,
			    struct ubase_ctx_page *ctx_page,
			    struct ubase_ctx_buf_cap *ctx_buf);
int ubase_hw_upgrade_ctx_poll(struct ubase_dev *udev,
			      struct ubase_mbx_attr *attr,
			      struct ubase_cmd_mailbox *mailbox);
int __ubase_hw_upgrade_ctx(struct ubase_dev *udev,
			   struct ubase_mbx_attr *attr,
			   struct ubase_cmd_mailbox *mailbox);
int __ubase_hw_upgrade_ctx_ex(struct ubase_dev *udev,
			      struct ubase_mbx_attr *attr,
			      struct ubase_cmd_mailbox *mailbox);
int ubase_create_ctx_page(struct ubase_dev *udev,
			  struct ubase_ctx_buf_cap *ctx_buf,
			  struct ubase_ctx_page **ctx_page, u32 npage);
void ubase_mailbox_buff_free(struct ubase_dev *udev);

#endif /* __UBASE_MAILBOX_H__ */
