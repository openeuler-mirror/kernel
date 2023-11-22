// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore message table implementation
 * Author: Yang Yijian
 * Create: 2023-07-05
 * Note:
 * History: 2023-07-05: Create file
 */

#include <linux/slab.h>
#include <urma/ubcore_types.h>
#include "ubcore_log.h"
#include <urma/ubcore_api.h>
#include "ubcore_netlink.h"
#include "ubcore_vtp.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_priv.h"
#include "ubcore_msg.h"

#define UBCORE_MSG_TIMEOUT 10000 /* 10s */

static LIST_HEAD(g_msg_session_list);
static DEFINE_SPINLOCK(g_msg_session_lock);
static atomic_t g_msg_seq = ATOMIC_INIT(0);

static uint32_t ubcore_get_msg_seq(void)
{
	return (uint32_t)atomic_inc_return(&g_msg_seq);
}

static void ubcore_free_msg_session(struct kref *kref)
{
	struct ubcore_msg_session *s = container_of(kref, struct ubcore_msg_session, kref);
	unsigned long flags;

	spin_lock_irqsave(&g_msg_session_lock, flags);
	list_del(&s->node);
	spin_unlock_irqrestore(&g_msg_session_lock, flags);
	kfree(s);
}

static struct ubcore_msg_session *ubcore_find_msg_session(uint32_t seq)
{
	struct ubcore_msg_session *tmp, *target = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_msg_session_lock, flags);
	list_for_each_entry(tmp, &g_msg_session_list, node) {
		if (tmp->req->hdr.msg_id == seq) {
			target = tmp;
			kref_get(&target->kref);
			break;
		}
	}
	spin_unlock_irqrestore(&g_msg_session_lock, flags);
	return target;
}

static void ubcore_destroy_msg_session(struct ubcore_msg_session *s)
{
	(void)kref_put(&s->kref, ubcore_free_msg_session);
}

static struct ubcore_msg_session *ubcore_create_msg_session(struct ubcore_msg *msg)
{
	struct ubcore_msg_session *s;
	unsigned long flags;

	s = kzalloc(sizeof(struct ubcore_msg_session), GFP_KERNEL);
	if (s == NULL)
		return NULL;

	s->req = msg;
	spin_lock_irqsave(&g_msg_session_lock, flags);
	list_add_tail(&s->node, &g_msg_session_list);
	spin_unlock_irqrestore(&g_msg_session_lock, flags);
	kref_init(&s->kref);
	init_completion(&s->comp);
	return s;
}

static struct ubcore_nlmsg *ubcore_get_fe2uvs_nlmsg(struct ubcore_device *dev,
	struct ubcore_msg *msg)
{
	uint32_t payload_len = (uint32_t)sizeof(*msg) + msg->hdr.len;
	struct ubcore_nlmsg *nlmsg;

	nlmsg = ubcore_alloc_nlmsg(payload_len, NULL, NULL);
	if (nlmsg == NULL)
		return NULL;

	nlmsg->transport_type = dev->transport_type;
	nlmsg->msg_type = UBCORE_NL_FE2TPF_REQ;
	(void)memcpy(nlmsg->payload, msg, payload_len);
	return nlmsg;
}

/* called when recv nl response from uvs */
static int ubcore_forward_uvs2fe_msg(struct ubcore_nlmsg *msg, void *user_arg)
{
	struct ubcore_device *dev = (struct ubcore_device *)user_arg;
	int ret;

	ret = ubcore_send_msg(dev, (struct ubcore_msg *)msg->payload);
	return ret;
}

static int ubcore_forward_fe2uvs_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	struct ubcore_nl_resp_cb cb;
	struct ubcore_nlmsg *nlmsg;
	int ret;

	nlmsg = ubcore_get_fe2uvs_nlmsg(dev, msg);
	if (nlmsg == NULL)
		return -ENOMEM;

	cb.callback = ubcore_forward_uvs2fe_msg;
	cb.user_arg = dev;
	ret = ubcore_nl_send_nowait(nlmsg, &cb);
	if (ret) {
		kfree(nlmsg);
		return -EIO;
	}

	return 0;
}

/* msg is a copy of received msg from driver */
static int ubcore_fe2tpf_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	int ret;

	ret = ubcore_forward_fe2uvs_msg(dev, msg);
	kfree(msg);
	return ret;
}

/* msg is a copy of received msg from driver */
static int ubcore_tpf2fe_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	struct ubcore_msg_session *s;

	s = ubcore_find_msg_session(msg->hdr.msg_id);
	if (s == NULL) {
		ubcore_log_err("Failed to find msg session with seq %u", msg->hdr.msg_id);
		kfree(msg);
		return -ENXIO;
	}
	s->resp = msg;
	kref_put(&s->kref, ubcore_free_msg_session);

	if (s->cb.callback == NULL) {
		complete(&s->comp);
	} else {
		s->cb.callback(dev, msg, s->cb.user_arg);
		kfree(msg);
		kfree(s->req);
		ubcore_destroy_msg_session(s);
	}
	return 0;
}

static int ubcore_mpf2tpf_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	return 0;
}

static int ubcore_tpf2mpf_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	return 0;
}

static ubcore_req_handler g_ubcore_msg_type_handlers[] = {
	[UBCORE_MSG_TYPE_FE2TPF] = ubcore_fe2tpf_msg,
	[UBCORE_MSG_TYPE_MPF2TPF] = ubcore_mpf2tpf_msg,
	[UBCORE_MSG_TYPE_TPF2FE] = ubcore_tpf2fe_msg,
	[UBCORE_MSG_TYPE_TPF2MPF] = ubcore_tpf2mpf_msg,
};

static void ubcore_fill_tpf_dev_name(struct ubcore_msg *msg)
{
	struct ubcore_create_vtp_req *create;
	struct ubcore_create_vtp_req *destroy;
	struct ubcore_msg_discover_eid_req *eid_req;
	struct ubcore_msg_config_device_req *config_dev;
	struct ubcore_device *tpf_dev;

	tpf_dev = ubcore_find_tpf_device(NULL, UBCORE_TRANSPORT_UB);
	if (tpf_dev == NULL)
		return;

	if (msg->hdr.type != UBCORE_MSG_TYPE_FE2TPF) {
		ubcore_put_device(tpf_dev);
		return;
	}

	switch (msg->hdr.opcode) {
	case UBCORE_MSG_CREATE_VTP:
		create = (struct ubcore_create_vtp_req *)msg->data;
		(void)memcpy(create->tpfdev_name, tpf_dev->dev_name,
			UBCORE_MAX_DEV_NAME);
		break;
	case UBCORE_MSG_DESTROY_VTP:
		destroy = (struct ubcore_create_vtp_req *)msg->data;
		(void)memcpy(destroy->tpfdev_name, tpf_dev->dev_name,
			UBCORE_MAX_DEV_NAME);
		break;
	case UBCORE_MSG_ALLOC_EID:
	case UBCORE_MSG_DEALLOC_EID:
		eid_req = (struct ubcore_msg_discover_eid_req *)msg->data;
		(void)memcpy(eid_req->tpfdev_name, tpf_dev->dev_name,
			UBCORE_MAX_DEV_NAME);
		break;
	case UBCORE_MSG_CONFIG_DEVICE:
		config_dev = (struct ubcore_msg_config_device_req *)msg->data;
		(void)memcpy(config_dev->tpfdev_name, tpf_dev->dev_name,
			UBCORE_MAX_DEV_NAME);
		break;
	case UBCORE_MSG_STOP_PROC_VTP_MSG:
	case UBCORE_MSG_QUERY_VTP_MIG_STATUS:
	case UBCORE_MSG_FLOW_STOPPED:
	case UBCORE_MSG_MIG_ROLLBACK:
	case UBCORE_MSG_MIG_VM_START:
	    ubcore_log_err("Wrong type when try to full tpf dev name\n");
		break;
	default:
		ubcore_log_err("Unrecognized type of opcode %d\n", (int)msg->hdr.opcode);
	}
	ubcore_put_device(tpf_dev);
}

static struct ubcore_msg *ubcore_copy_msg(struct ubcore_msg *msg)
{
	uint32_t len = (uint32_t)sizeof(struct ubcore_msg) + msg->hdr.len;
	struct ubcore_msg *resp;

	resp = kzalloc(len, GFP_KERNEL);
	if (resp == NULL)
		return NULL;

	(void)memcpy(resp, msg, len);
	return resp;
}

static struct ubcore_msg *ubcore_migrate_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	uint32_t len;
	struct ubcore_nl_function_mig_req *mig_resp;
	struct ubcore_function_mig_req *mig_msg;
	struct ubcore_msg *resp;

	len = (uint32_t)sizeof(struct ubcore_msg) +
		(uint32_t)sizeof(struct ubcore_nl_function_mig_req);
	mig_msg = (struct ubcore_function_mig_req *)msg->data;
	resp = kzalloc(len, GFP_KERNEL);
	if (resp == NULL) {
		ubcore_log_err("Failed to kzalloc msg resp!\n");
		return NULL;
	}

	resp->hdr.type = msg->hdr.type;
	resp->hdr.ep = msg->hdr.ep;
	resp->hdr.opcode = msg->hdr.opcode;
	resp->hdr.msg_id = msg->hdr.msg_id;
	resp->hdr.len = sizeof(struct ubcore_nl_function_mig_req);

	mig_resp = (struct ubcore_nl_function_mig_req *)resp->data;
	mig_resp->mig_fe_idx = mig_msg->mig_fe_idx;
	(void)strcpy(mig_resp->dev_name, dev->dev_name);

	return resp;
}

int ubcore_recv_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	struct ubcore_msg *handle_msg;
	int ret;

	if (dev == NULL || msg == NULL) {
		ubcore_log_err("Invalid parameter in recv msg\n!");
		return -EINVAL;
	}

	if (msg->hdr.opcode >= UBCORE_MSG_STOP_PROC_VTP_MSG) {
		handle_msg = ubcore_migrate_msg(dev, msg);
		if (handle_msg == NULL) {
			ubcore_log_err("null msg when handle migrate\n!");
			return -EINVAL;
		}
	} else {
		handle_msg = ubcore_copy_msg(msg);
		if (handle_msg == NULL) {
			ubcore_log_err("Failed to create handle msg req!\n");
			return -ENOMEM;
		}
		/* fill tpf_dev name */
		ubcore_fill_tpf_dev_name(handle_msg);
	}

	ret = g_ubcore_msg_type_handlers[handle_msg->hdr.type](dev, handle_msg);

	/* do not free copy here */
	return ret;
}
EXPORT_SYMBOL(ubcore_recv_msg);

int ubcore_send_msg(struct ubcore_device *dev, struct ubcore_msg *msg)
{
	int ret;

	if (dev == NULL || dev->ops->send_msg == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		return -EINVAL;
	}

	ret = dev->ops->send_msg(dev, msg);
	if (ret != 0) {
		ubcore_log_err("Failed to send message! msg_id = %u!\n", msg->hdr.msg_id);
		return -EIO;
	}
	return 0;
}

int ubcore_send_fe2tpf_msg(struct ubcore_device *dev, struct ubcore_msg *req,
	bool wait, struct ubcore_resp_cb *cb)
{
	unsigned long leavetime;
	struct ubcore_msg_session *s;
	int ret;

	req->hdr.msg_id = ubcore_get_msg_seq();
	s = ubcore_create_msg_session(req);
	if (s == NULL) {
		ubcore_log_err("Failed to create req session!\n");
		return -ENOMEM;
	}

	ret = ubcore_send_msg(dev, req);
	if (ret != 0) {
		ubcore_log_err("Failed to send req, msg_id = %u, opcode = %hu.\n",
			req->hdr.msg_id, (uint16_t)req->hdr.opcode);
		ubcore_destroy_msg_session(s);
		return -EIO;
	}

	if (!wait) {
		s->cb = *cb;
		return 0;
	}

	leavetime = wait_for_completion_timeout(&s->comp, msecs_to_jiffies(UBCORE_MSG_TIMEOUT));
	if (leavetime == 0) {
		ubcore_log_err("Failed to wait req reply, msg_id = %u, opcode = %hu, leavetime =  %lu.\n",
			req->hdr.msg_id, (uint16_t)req->hdr.opcode, leavetime);
		ubcore_destroy_msg_session(s);
		return -EIO;
	}

	ubcore_log_info("Success to wait req reply, msg_id = %u, opcode = %hu, leavetime =  %lu.\n",
			req->hdr.msg_id, (uint16_t)req->hdr.opcode, leavetime);

	ret = cb->callback(dev, s->resp, cb->user_arg);
	kfree(s->resp);
	kfree(s->req);
	ubcore_destroy_msg_session(s);
	return ret;
}

static int ubcore_msg_discover_eid_cb(struct ubcore_device *dev,
	struct ubcore_msg *msg, void *msg_ctx)
{
	struct ubcore_msg_discover_eid_resp *data;
	struct ubcore_ueid_cfg cfg;
	union ubcore_eid eid = {0};
	int ret;

	if (dev == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	data = (struct ubcore_msg_discover_eid_resp *)(void *)msg->data;
	if (msg == NULL || msg->hdr.type != UBCORE_MSG_TYPE_TPF2FE ||
		data == NULL || data->ret != 0 ||
		(msg->hdr.opcode != UBCORE_MSG_ALLOC_EID &&
			msg->hdr.opcode != UBCORE_MSG_DEALLOC_EID)) {
		ubcore_log_err("Failed to query data from the UVS. Use the default value.\n");
		return -EINVAL;
	}

	if (msg->hdr.opcode == UBCORE_MSG_ALLOC_EID) {
		ret = ubcore_update_eidtbl_by_idx(dev, &data->eid, data->eid_index, true);
	} else {
		eid = data->eid;
		(void)memset(&data->eid, 0, sizeof(union ubcore_eid));
		ret = ubcore_update_eidtbl_by_idx(dev, &data->eid, data->eid_index, false);
	}
	if (ret != 0)
		return ret;

	/* pf need update ueid */
	if (!dev->attr.virtualization) {
		if (msg->hdr.opcode == UBCORE_MSG_ALLOC_EID)
			cfg.eid = data->eid;
		else
			cfg.eid = eid;

		cfg.eid_index = data->eid_index;
		cfg.upi = data->upi;
		if (msg->hdr.opcode == UBCORE_MSG_ALLOC_EID)
			ret = ubcore_add_ueid(dev, UBCORE_NON_VIRTUALIZATION_FE_IDX, &cfg);
		else
			ret = ubcore_delete_ueid(dev, UBCORE_NON_VIRTUALIZATION_FE_IDX, &cfg);
	}
	return ret;
}

int ubcore_msg_discover_eid(struct ubcore_device *dev, uint32_t eid_index,
	enum ubcore_msg_opcode op)
{
	struct ubcore_msg_discover_eid_req *data;
	struct ubcore_msg *req_msg;
	uint32_t data_len;
	struct ubcore_resp_cb cb = {
		.callback = ubcore_msg_discover_eid_cb,
		.user_arg = NULL
	};
	int ret;

	data_len = sizeof(struct ubcore_msg_discover_eid_req);
	req_msg = kcalloc(1, sizeof(struct ubcore_msg) + data_len, GFP_KERNEL);
	if (req_msg == NULL) {
		ubcore_log_err("alloc req_msg failed.\n");
		return -ENOMEM;
	}
	req_msg->hdr.type = UBCORE_MSG_TYPE_FE2TPF;
	req_msg->hdr.len = data_len;
	req_msg->hdr.opcode = op;
	data = (struct ubcore_msg_discover_eid_req *)req_msg->data;
	data->eid_index = eid_index;
	data->eid_type = dev->cfg.pattern;
	data->virtualization = dev->attr.virtualization;
	(void)memcpy(data->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);

	ret = ubcore_send_fe2tpf_msg(dev, req_msg, true, &cb);
	if (ret != 0)
		ubcore_log_err("send fe2tpf failed.\n");

	return ret;
}
