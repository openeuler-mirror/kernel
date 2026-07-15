// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_dev.h"
#include "ubaseproxy_event.h"
#include "ubaseproxy_jfc.h"
#include "ubaseproxy_jfr.h"
#include "ubaseproxy_jfs.h"
#include "ubaseproxy_mbx.h"

static struct ubase_ctx_buf_cap *
ubaseproxy_parse_ctx_buf(struct ubaseproxy_dev *udev, struct ubase_mbx_attr *attr,
			 enum ubaseproxy_mb_type *type)
{
	struct ubaseproxy_ue_ctx_buf *ue_ctx_buf =
		ubaseproxy_get_ue_ctx_buf(udev, attr->mbx_ue_id);
	struct ubaseproxy_mbx_op_match matches[] = {
		{UBASE_MB_CREATE_JFS_CONTEXT, UBASEPROXY_MB_CREATE, &ue_ctx_buf->jfs},
		{UBASE_MB_MODIFY_JFS_CONTEXT, UBASEPROXY_MB_MODIFY, &ue_ctx_buf->jfs},
		{UBASE_MB_QUERY_JFS_CONTEXT, UBASEPROXY_MB_QUERY, &ue_ctx_buf->jfs},
		{UBASE_MB_DESTROY_JFS_CONTEXT, UBASEPROXY_MB_DESTROY, &ue_ctx_buf->jfs},
		{UBASE_MB_CREATE_JFR_CONTEXT, UBASEPROXY_MB_CREATE, &ue_ctx_buf->jfr},
		{UBASE_MB_MODIFY_JFR_CONTEXT, UBASEPROXY_MB_MODIFY, &ue_ctx_buf->jfr},
		{UBASE_MB_QUERY_JFR_CONTEXT, UBASEPROXY_MB_QUERY, &ue_ctx_buf->jfr},
		{UBASE_MB_DESTROY_JFR_CONTEXT, UBASEPROXY_MB_DESTROY, &ue_ctx_buf->jfr},
		{UBASE_MB_CREATE_JFC_CONTEXT, UBASEPROXY_MB_CREATE, &ue_ctx_buf->jfc},
		{UBASE_MB_MODIFY_JFC_CONTEXT, UBASEPROXY_MB_MODIFY,  &ue_ctx_buf->jfc},
		{UBASE_MB_QUERY_JFC_CONTEXT, UBASEPROXY_MB_QUERY, &ue_ctx_buf->jfc},
		{UBASE_MB_DESTROY_JFC_CONTEXT, UBASEPROXY_MB_DESTROY, &ue_ctx_buf->jfc},
		{UBASE_MB_CREATE_JETTY_GROUP_CONTEXT, UBASEPROXY_MB_CREATE, &ue_ctx_buf->jtg},
		{UBASE_MB_MODIFY_JETTY_GROUP_CONTEXT, UBASEPROXY_MB_MODIFY, &ue_ctx_buf->jtg},
		{UBASE_MB_QUERY_JETTY_GROUP_CONTEXT, UBASEPROXY_MB_QUERY, &ue_ctx_buf->jtg},
		{UBASE_MB_DESTROY_JETTY_GROUP_CONTEXT, UBASEPROXY_MB_DESTROY, &ue_ctx_buf->jtg},
		{UBASE_MB_CREATE_RC_CONTEXT, UBASEPROXY_MB_CREATE, &ue_ctx_buf->rc},
		{UBASE_MB_MODIFY_RC_CONTEXT, UBASEPROXY_MB_MODIFY, &ue_ctx_buf->rc},
		{UBASE_MB_QUERY_RC_CONTEXT, UBASEPROXY_MB_QUERY, &ue_ctx_buf->rc},
		{UBASE_MB_DESTROY_RC_CONTEXT, UBASEPROXY_MB_DESTROY, &ue_ctx_buf->rc},
	};
	u32 size = ARRAY_SIZE(matches), i;

	for (i = 0; i < size; i++) {
		if (attr->op == matches[i].op) {
			*type = matches[i].type;
			return matches[i].ctx_caps;
		}
	}

	return NULL;
}

int ubaseproxy_post_mbox(struct ubaseproxy_dev *udev,
			 struct ubase_proxy_req_msg *req,
			 struct ubase_cmd_mailbox *mailbox)
{
	enum ubaseproxy_mb_type type = UBASEPROXY_MB_OTHER;
	struct auxiliary_device *adev = udev->comdev.adev;
	struct ubase_ctx_buf_cap *ctx_buf;
	struct ubase_mbx_attr attr = {0};
	u16 mbx_ue_id, tag, opcode;
	int ret;

	if (req->data_len)
		memcpy(mailbox->buf, req->data, req->data_len);

	mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	tag = req->tag;
	opcode = req->opcode;

	ubase_fill_mbx_attr(&attr, tag, opcode, mbx_ue_id);
	ctx_buf = ubaseproxy_parse_ctx_buf(udev, &attr, &type);

	ret = ubase_hw_upgrade_ctx_for_proxy(adev, &attr, mailbox);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to post mailbox for ue, tag = %u, opcode = 0x%x, mbx_ue_id = %u, ret = %d.\n",
			       tag, opcode, mbx_ue_id, ret);

	return ret;
}

int ubaseproxy_send_mbx_based_ue_req(struct ubaseproxy_dev *udev,
				     struct ubase_proxy_req_msg *req)
{
	struct ubase_cmd_mailbox *mailbox;
	int ret;

	mailbox = ubase_alloc_cmd_mailbox(udev->comdev.adev);
	if (IS_ERR_OR_NULL(mailbox))
		return -ENOMEM;

	ret = ubaseproxy_post_mbox(udev, req, mailbox);

	ubase_free_cmd_mailbox(udev->comdev.adev, mailbox);

	return ret;
}

int ubaseproxy_send_resp_to_ue(struct ubaseproxy_dev *udev,
			       struct ubase_proxy_req_msg *req,
			       struct ubase_cmd_mailbox *mailbox,
			       struct ubase_ctx_result *ctx_res)
{
	struct ubase_proxy_resp_msg *resp;
	struct ubase_cmd_buf in;
	u32 msg_len;
	int ret;

	msg_len = sizeof(*resp) + ctx_res->len;
	resp = kzalloc(msg_len, GFP_KERNEL);
	if (!resp) {
		ubaseproxy_err(udev, "failed to alloc resp.\n");
		return -ENOMEM;
	}

	resp->bus_ue_id = req->bus_ue_id;
	resp->mbx_ue_id = req->mbx_ue_id;
	resp->seq_num = req->seq_num;
	resp->ret = ctx_res->ret;
	resp->data_len = ctx_res->len;
	if (resp->data_len && mailbox && mailbox->buf)
		memcpy(resp->data, mailbox->buf, resp->data_len);

	ubase_fill_inout_buf(&in, ctx_res->opcode, false, msg_len, resp);
	ret = ubase_cmd_send_in(udev->comdev.adev, &in);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send mbox resp msg, ret = %d.\n",
			       ret);

	kfree(resp);

	return ret;
}

struct ubaseproxy_handler {
	u16 opcode;
	int (*handler)(struct ubaseproxy_dev *udev, struct ubase_proxy_req_msg *req);
} g_ctx_handler[] = {
	{UBASE_MB_CREATE_JFC_CONTEXT, ubaseproxy_handle_create_jfc_ctx_req},
	{UBASE_MB_CREATE_JFS_CONTEXT, ubaseproxy_handle_create_jfs_ctx_req},
	{UBASE_MB_CREATE_JFR_CONTEXT, ubaseproxy_handle_create_jfr_ctx_req},
	{UBASE_MB_DESTROY_JFC_CONTEXT, ubaseproxy_handle_destroy_jfc_ctx_req},
	{UBASE_MB_DESTROY_JFS_CONTEXT, ubaseproxy_handle_destroy_jfs_ctx_req},
	{UBASE_MB_DESTROY_JFR_CONTEXT, ubaseproxy_handle_destroy_jfr_ctx_req},
	{UBASE_MB_MODIFY_JFC_CONTEXT, ubaseproxy_handle_modify_jfc_ctx_req},
	{UBASE_MB_MODIFY_JFS_CONTEXT, ubaseproxy_handle_modify_jfs_ctx_req},
	{UBASE_MB_MODIFY_JFR_CONTEXT, ubaseproxy_handle_modify_jfr_ctx_req},
	{UBASE_MB_QUERY_JFC_CONTEXT, ubaseproxy_handle_query_jfc_ctx_req},
	{UBASE_MB_QUERY_JFS_CONTEXT, ubaseproxy_handle_query_jfs_ctx_req},
	{UBASE_MB_QUERY_JFR_CONTEXT, ubaseproxy_handle_query_jfr_ctx_req},
};

int ubaseproxy_handle_mbox_req(struct ubaseproxy_dev *udev,
			       struct ubase_proxy_req_msg *req)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(g_ctx_handler); i++) {
		if (g_ctx_handler[i].opcode == req->opcode)
			return g_ctx_handler[i].handler(udev, req);
	}

	ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id), mbx_opcode,
			   "opcode = 0x%x is not supported.\n", req->opcode);

	return -EINVAL;
}
