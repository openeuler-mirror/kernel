// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore connection manager implementation, interacts with ubcm
 * Author: Wang Hang
 * Create: 2025-02-18
 * Note:
 * History: 2025-02-18: create file
 */

#include <linux/errno.h>
#include <linux/list.h>
#include "ubcore_log.h"
#include "ubcore_cm.h"
#include "ubcore_comm.h"

static ubcore_cm_eid_ops g_eid_ops;
static ubcore_cm_send g_send;

struct cm_ep_entry {
	struct list_head list;
	struct ubcore_device *dev;
	uint32_t eid_index;
	struct ubcore_comm_endpoint *ep;
};
static LIST_HEAD(g_cm_ep_list);
static DEFINE_SPINLOCK(g_cm_ep_lock);

static struct ubcore_comm_endpoint *
ubcore_cm_lookup_ep(struct ubcore_device *dev, union ubcore_eid *local_eid)
{
	struct cm_ep_entry *cur;
	uint32_t idx;
	struct ubcore_comm_endpoint *ep = NULL;

	spin_lock(&dev->eid_table.lock);
	if (IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
		spin_unlock(&dev->eid_table.lock);
		return NULL;
	}
	for (idx = 0; idx < dev->eid_table.eid_cnt; idx++) {
		if (dev->eid_table.eid_entries[idx].valid &&
		    memcmp(&dev->eid_table.eid_entries[idx].eid, local_eid,
			   sizeof(union ubcore_eid)) == 0)
			break;
	}
	spin_unlock(&dev->eid_table.lock);
	if (idx >= dev->eid_table.eid_cnt)
		return NULL;

	spin_lock(&g_cm_ep_lock);
	list_for_each_entry(cur, &g_cm_ep_list, list) {
		if (cur->dev == dev && cur->eid_index == idx) {
			ep = cur->ep;
			break;
		}
	}
	spin_unlock(&g_cm_ep_lock);
	return ep;
}

static int ubcore_call_cm_send_ops(struct ubcore_device *dev,
				   struct ubcore_cm_send_buf *send_buf)
{
	if (!g_send) {
		ubcore_log_err(
			"ubcore_cm_send_ops function not registered yet!");
		return -EINVAL;
	}

	return g_send(dev, send_buf);
}

int ubcore_call_cm_eid_ops(struct ubcore_device *dev,
			   struct ubcore_eid_info *eid_info,
			   enum ubcore_mgmt_event_type event_type)
{
	if (!g_eid_ops) {
		ubcore_log_err(
			"ubcore_cm_eid_ops function not registered yet!");
		return -EINVAL;
	}

	return g_eid_ops(dev, eid_info, event_type);
}

void ubcore_register_cm_eid_ops(ubcore_cm_eid_ops eid_ops)
{
	g_eid_ops = eid_ops;
	ubcore_log_info("ubcore_cm_eid_ops function registered!");
}

void ubcore_register_cm_send_ops(ubcore_cm_send cm_send)
{
	g_send = cm_send;
	ubcore_log_info("ubcore_cm_send_ops function registered!");
}

int ubcore_cm_recv(struct ubcore_device *dev, struct ubcore_cm_recv_cr *recv_cr)
{
	union ubcore_eid addr;

	if (!dev || !recv_cr || !recv_cr->cr) {
		ubcore_log_err("Invalid param: dev, recv_cr or cr is null");
		return -EINVAL;
	}
	addr = recv_cr->cr->remote_id.eid;
	struct ubcore_net_msg msg = { 0 };
	struct ubcore_comm_endpoint *ep;

	if (recv_cr->payload != 0 && recv_cr->payload_len < MSG_HDR_SIZE) {
		ubcore_log_err("Invalid recv_cr payload");
		return -EINVAL;
	}
	(void)memcpy(&msg, (void *)(recv_cr->payload), MSG_HDR_SIZE);
	msg.data = (void *)(recv_cr->payload + MSG_HDR_SIZE);

	ubcore_log_info("Handle cm message, " MSG_FMT, MSG_ARG(&msg));

	ep = ubcore_cm_lookup_ep(dev, &recv_cr->local_eid);
	if (ep && ep->recv_cb)
		ep->recv_cb(ep, dev, &msg, &addr);
	else
		ubcore_net_handle_msg(dev, &msg, &addr);

	return 0;
}

void ubcore_cm_register_endpoint(struct ubcore_comm_endpoint *ep,
				 struct ubcore_device *dev, uint32_t eid_index)
{
	struct cm_ep_entry *entry;

	if (!ep || !dev) {
		ubcore_log_err("Invalid param: ep or dev is null");
		return;
	}
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;
	entry->dev = dev;
	entry->eid_index = eid_index;
	entry->ep = ep;
	INIT_LIST_HEAD(&entry->list);

	spin_lock(&g_cm_ep_lock);
	list_add_tail(&entry->list, &g_cm_ep_list);
	spin_unlock(&g_cm_ep_lock);
}

void ubcore_cm_unregister_endpoint(struct ubcore_comm_endpoint *ep)
{
	struct cm_ep_entry *cur, *tmp;

	spin_lock(&g_cm_ep_lock);
	list_for_each_entry_safe(cur, tmp, &g_cm_ep_list, list) {
		if (cur->ep == ep) {
			list_del(&cur->list);
			spin_unlock(&g_cm_ep_lock);
			kfree(cur);
			return;
		}
	}
	spin_unlock(&g_cm_ep_lock);
}

int ubcore_ubcm_send_to(struct ubcore_device *dev, union ubcore_eid addr,
			struct ubcore_net_msg *msg)
{
	uint16_t send_buf_len;
	struct ubcore_cm_send_buf *send_buf = NULL;
	int ret;

	if (!dev || !msg) {
		ubcore_log_err("Invalid param: dev or msg is null");
		return -EINVAL;
	}
	if (msg->len > 0 && !msg->data) {
		ubcore_log_err("Invalid param: msg->data is null when len > 0");
		return -EINVAL;
	}

	send_buf_len =
		sizeof(struct ubcore_cm_send_buf) + MSG_HDR_SIZE + msg->len;
	send_buf = kcalloc(1, send_buf_len, GFP_KERNEL);
	if (IS_ERR_OR_NULL(send_buf)) {
		ubcore_log_err("Failed to alloc cm send buf memory.\n");
		return -ENOMEM;
	}

	send_buf->dst_eid = addr;
	send_buf->msg_type = UBCORE_CM_CONN_MSG;
	send_buf->payload_len = MSG_HDR_SIZE + msg->len;
	(void)memcpy(send_buf->payload, msg, MSG_HDR_SIZE);
	if (msg->len > 0)
		(void)memcpy(send_buf->payload + MSG_HDR_SIZE, msg->data,
			     msg->len);

	ret = ubcore_call_cm_send_ops(dev, send_buf);
	if (ret != 0)
		ubcore_log_err("Failed to send cm message, ret:%d, " MSG_FMT,
			       ret, MSG_ARG(msg));

	kfree(send_buf);
	return ret;
}

int ubcore_ubcm_send(struct ubcore_device *dev, void *conn,
		     struct ubcore_net_msg *msg)
{
	if (!conn) {
		ubcore_log_err("Invalid param: conn is null");
		return -EINVAL;
	}
	return ubcore_ubcm_send_to(dev, *(union ubcore_eid *)conn, msg);
}
