/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_MBX_H__
#define __UBASEPROXY_MBX_H__

#include "ubaseproxy_dev.h"

#define UBASEPROXY_CTXLEN_AND_MASK 2

enum ubaseproxy_mb_type {
	UBASEPROXY_MB_CREATE,
	UBASEPROXY_MB_MODIFY,
	UBASEPROXY_MB_DESTROY,
	UBASEPROXY_MB_QUERY,
	UBASEPROXY_MB_OTHER,
};

struct ubaseproxy_mbx_op_match {
	u32				op;
	enum ubaseproxy_mb_type		type;
	struct ubase_ctx_buf_cap	*ctx_caps;
};

int ubaseproxy_post_mbox(struct ubaseproxy_dev *udev,
			 struct ubase_proxy_req_msg *req,
			 struct ubase_cmd_mailbox *mailbox);
int ubaseproxy_handle_mbox_req(struct ubaseproxy_dev *udev,
			       struct ubase_proxy_req_msg *req);
int ubaseproxy_send_mbx_based_ue_req(struct ubaseproxy_dev *udev,
				     struct ubase_proxy_req_msg *req);
int ubaseproxy_send_resp_to_ue(struct ubaseproxy_dev *udev,
			       struct ubase_proxy_req_msg *req,
			       struct ubase_cmd_mailbox *mailbox,
			       struct ubase_ctx_result *ctx_res);

#endif /* __UBASEPROXY_MBX_H__ */
