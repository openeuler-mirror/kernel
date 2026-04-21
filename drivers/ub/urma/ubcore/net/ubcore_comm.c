// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore comm module implementation (替代 ubcore_net)
 */

#include <linux/list.h>
#include <linux/slab.h>
#include "ubcore_log.h"
#include "ubcore_comm.h"
#include "ubcore_protocol.h"
#include "ubcore_cm.h"

static struct ubcore_comm_endpoint *g_default_ep;
static LIST_HEAD(g_ep_list);
static DEFINE_SPINLOCK(g_ep_lock);

/* ubcm transport ops */
static int ubcore_comm_ubcm_create(struct ubcore_comm_endpoint *ep, void *cfg);
static void ubcore_comm_ubcm_destroy(struct ubcore_comm_endpoint *ep);
static int ubcore_comm_ubcm_send(struct ubcore_comm_endpoint *ep,
				 struct ubcore_device *dev,
				 void *conn, struct ubcore_net_msg *msg);
static int ubcore_comm_ubcm_send_to(struct ubcore_comm_endpoint *ep,
				    struct ubcore_device *dev,
				    union ubcore_eid addr,
				    struct ubcore_net_msg *msg);

static const struct ubcore_comm_ops ubcore_comm_ubcm_ops = {
	.create = ubcore_comm_ubcm_create,
	.destroy = ubcore_comm_ubcm_destroy,
	.send = ubcore_comm_ubcm_send,
	.send_to = ubcore_comm_ubcm_send_to,
};

struct ubcore_net_msg_descriptor {
	ubcore_net_msg_handler handler;
	uint16_t msg_len;
};

static const char *const msg_type_str_list[UBCORE_NET_MSG_MAX] = {
	[UBCORE_NET_CREATE_REQ] = "create-req",
	[UBCORE_NET_CREATE_RESP] = "create-resp",
	[UBCORE_NET_CREATE_ACK] = "create-ack",
	[UBCORE_NET_DESTROY_REQ] = "destroy-req",
	[UBCORE_NET_DESTROY_RESP] = "destroy-resp",
	[UBCORE_NET_BONDING_SEG_INFO_REQ] = "seg_req",
	[UBCORE_NET_BONDING_SEG_INFO_RESP] = "seg_resp",
	[UBCORE_NET_BONDING_JETTY_INFO_REQ] = "jetty_req",
	[UBCORE_NET_BONDING_JETTY_INFO_RESP] = "jetty_resp",
	[UBCORE_NET_BONDING_USER_MSG] = "bonding-user-msg",
};

enum ubcore_connect_type {
	UBCORE_CONNECT_WK_JETTY = 0U,
	UBCORE_CONNECT_SOCK,
};

static struct ubcore_net_msg_descriptor g_msg_descriptors[UBCORE_NET_MSG_MAX];

uint32_t g_ubcore_connect_type = UBCORE_CONNECT_WK_JETTY;

const char *msg_type_str(enum ubcore_net_msg_type type)
{
	return (type < UBCORE_NET_MSG_MAX) ? msg_type_str_list[type] : "unknown";
}

int ubcore_net_register_msg_handler(enum ubcore_net_msg_type type,
				    ubcore_net_msg_handler handler,
				    uint16_t msg_len)
{
	if (type >= UBCORE_NET_MSG_MAX || g_msg_descriptors[type].handler != NULL) {
		ubcore_log_err("Failed to register msg handler, type:%s",
			       msg_type_str(type));
		return -EINVAL;
	}
	g_msg_descriptors[type].handler = handler;
	g_msg_descriptors[type].msg_len = msg_len;
	return 0;
}

void ubcore_net_handle_msg(struct ubcore_device *dev,
			   struct ubcore_net_msg *msg, void *conn)
{
	struct ubcore_net_msg_descriptor *desc;

	if (!dev || !msg) {
		ubcore_log_err("Invalid param: dev or msg is null");
		return;
	}
	if (msg->type >= UBCORE_NET_MSG_MAX) {
		ubcore_log_err("Invalid net msg type, " MSG_FMT, MSG_ARG(msg));
		return;
	}
	desc = &g_msg_descriptors[msg->type];
	if (desc->msg_len != 0 && msg->len != desc->msg_len) {
		ubcore_log_err("Invalid net msg len, expected: %u, " MSG_FMT,
			       desc->msg_len, MSG_ARG(msg));
		return;
	}
	if (!desc->handler) {
		ubcore_log_err("No handler for net msg, " MSG_FMT, MSG_ARG(msg));
		return;
	}
	desc->handler(dev, msg, conn);
}

static bool ubcore_is_loopback(struct ubcore_device *dev,
			       union ubcore_eid *addr)
{
	uint32_t idx;

	if (!dev || !addr)
		return false;
	spin_lock(&dev->eid_table.lock);
	for (idx = 0; idx < dev->eid_table.eid_cnt; idx++) {
		if (dev->eid_table.eid_entries[idx].valid &&
		    memcmp(addr, &dev->eid_table.eid_entries[idx].eid,
			   sizeof(union ubcore_eid)) == 0) {
			spin_unlock(&dev->eid_table.lock);
			return true;
		}
	}
	spin_unlock(&dev->eid_table.lock);
	return false;
}

int ubcore_net_send(struct ubcore_device *dev, struct ubcore_net_msg *msg,
		    void *conn)
{
	struct ubcore_comm_endpoint *ep;

	if (!dev || !msg) {
		ubcore_log_err("Invalid param: dev or msg is null");
		return -EINVAL;
	}
	if (!conn) {
		ubcore_log_info("Loopback detected, using shortcut.");
		ubcore_net_handle_msg(dev, msg, NULL);
		return 0;
	}
	ep = ubcore_comm_get_default_endpoint();
	if (ep)
		return ubcore_comm_send(ep, dev, conn, msg);

	switch (g_ubcore_connect_type) {
	case UBCORE_CONNECT_WK_JETTY:
		return ubcore_ubcm_send(dev, conn, msg);
	case UBCORE_CONNECT_SOCK:
	default:
		ubcore_log_err("connect type unrecognized!");
		return -EINVAL;
	}
}

int ubcore_net_send_to(struct ubcore_device *dev, struct ubcore_net_msg *msg,
		       union ubcore_eid addr)
{
	struct ubcore_comm_endpoint *ep;

	if (!dev || !msg) {
		ubcore_log_err("Invalid param: dev or msg is null");
		return -EINVAL;
	}
	if (ubcore_is_loopback(dev, &addr)) {
		ubcore_log_info("Loopback detected, using shortcut.");
		ubcore_net_handle_msg(dev, msg, NULL);
		return 0;
	}
	ep = ubcore_comm_get_default_endpoint();
	if (ep)
		return ubcore_comm_send_to(ep, dev, addr, msg);

	switch (g_ubcore_connect_type) {
	case UBCORE_CONNECT_WK_JETTY:
		return ubcore_ubcm_send_to(dev, addr, msg);
	case UBCORE_CONNECT_SOCK:
	default:
		ubcore_log_err("connect type unrecognized!");
		return -EINVAL;
	}
}

static void ubcore_comm_default_recv_cb(struct ubcore_comm_endpoint *ep,
					struct ubcore_device *dev,
					struct ubcore_net_msg *msg, void *conn)
{
	(void)ep;
	ubcore_net_handle_msg(dev, msg, conn);
}

struct ubcore_comm_endpoint *
ubcore_comm_create_endpoint(enum ubcore_comm_type type,
			    union ubcore_comm_cfg *cfg,
			    ubcore_comm_recv_cb recv_cb)
{
	struct ubcore_comm_endpoint *ep;
	const struct ubcore_comm_ops *ops;
	int ret;

	if (!cfg || !recv_cb) {
		ubcore_log_err("Invalid param for comm endpoint");
		return NULL;
	}

	switch (type) {
	case UBCORE_COMM_UBCM_WK_JETTY:
		ops = &ubcore_comm_ubcm_ops;
		break;
	case UBCORE_COMM_SOCK:
	default:
		ubcore_log_err("Unsupported comm type: %d", type);
		return NULL;
	}

	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (!ep)
		return NULL;

	ep->type = type;
	ep->ops = ops;
	ep->recv_cb = recv_cb;
	INIT_LIST_HEAD(&ep->list);

	ret = ep->ops->create(ep, cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to create comm endpoint, type:%d ret:%d",
			      type, ret);
		kfree(ep);
		return NULL;
	}

	spin_lock(&g_ep_lock);
	list_add_tail(&ep->list, &g_ep_list);
	spin_unlock(&g_ep_lock);

	return ep;
}

void ubcore_comm_destroy_endpoint(struct ubcore_comm_endpoint *ep)
{
	if (!ep)
		return;

	spin_lock(&g_ep_lock);
	list_del(&ep->list);
	if (g_default_ep == ep)
		g_default_ep = NULL;
	spin_unlock(&g_ep_lock);

	if (ep->ops && ep->ops->destroy)
		ep->ops->destroy(ep);
	kfree(ep);
}

int ubcore_comm_send(struct ubcore_comm_endpoint *ep,
		     struct ubcore_device *dev,
		     void *conn, struct ubcore_net_msg *msg)
{
	if (!ep || !ep->ops || !ep->ops->send)
		return -EINVAL;
	return ep->ops->send(ep, dev, conn, msg);
}

int ubcore_comm_send_to(struct ubcore_comm_endpoint *ep,
			struct ubcore_device *dev,
			union ubcore_eid addr,
			struct ubcore_net_msg *msg)
{
	if (!ep || !ep->ops || !ep->ops->send_to)
		return -EINVAL;
	return ep->ops->send_to(ep, dev, addr, msg);
}

struct ubcore_comm_endpoint *ubcore_comm_get_default_endpoint(void)
{
	return g_default_ep;
}

void ubcore_comm_set_default_endpoint(struct ubcore_comm_endpoint *ep)
{
	g_default_ep = ep;
}

/* -------- ubcm transport -------- */
struct ubcore_comm_ubcm_priv {
	struct ubcore_device *dev;
	uint32_t eid_index;
};

static int ubcore_comm_ubcm_create(struct ubcore_comm_endpoint *ep, void *cfg)
{
	struct ubcore_comm_ubcm_cfg *ubcm_cfg = cfg;
	struct ubcore_comm_ubcm_priv *priv;

	if (!ubcm_cfg || !ubcm_cfg->dev) {
		ubcore_log_err("ubcm cfg is null");
		return -EINVAL;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = ubcm_cfg->dev;
	priv->eid_index = ubcm_cfg->eid_index;
	ep->priv = priv;

	ubcore_cm_register_endpoint(ep, ubcm_cfg->dev, ubcm_cfg->eid_index);
	return 0;
}

static void ubcore_comm_ubcm_destroy(struct ubcore_comm_endpoint *ep)
{
	struct ubcore_comm_ubcm_priv *priv = ep->priv;

	if (priv) {
		ubcore_cm_unregister_endpoint(ep);
		kfree(priv);
		ep->priv = NULL;
	}
}

static int ubcore_comm_ubcm_send(struct ubcore_comm_endpoint *ep,
				 struct ubcore_device *dev,
				 void *conn, struct ubcore_net_msg *msg)
{
	struct ubcore_comm_ubcm_priv *priv = ep->priv;

	if (!priv || !conn || !msg)
		return -EINVAL;
	(void)dev;
	return ubcore_ubcm_send(priv->dev, conn, msg);
}

static int ubcore_comm_ubcm_send_to(struct ubcore_comm_endpoint *ep,
				    struct ubcore_device *dev,
				    union ubcore_eid addr,
				    struct ubcore_net_msg *msg)
{
	if (!dev || !msg) {
		ubcore_log_err("Invalid param: dev or msg is null");
		return -EINVAL;
	}
	(void)ep;
	return ubcore_ubcm_send_to(dev, addr, msg);
}

/* -------- init / default endpoint -------- */
struct ubcore_comm_endpoint *
ubcore_comm_create_default(enum ubcore_comm_type type,
			   union ubcore_comm_cfg *cfg)
{
	struct ubcore_comm_endpoint *ep;

	ep = ubcore_comm_create_endpoint(type, cfg, ubcore_comm_default_recv_cb);
	if (!ep)
		return NULL;

	ubcore_comm_set_default_endpoint(ep);
	return ep;
}

void ubcore_comm_uninit(void)
{
	struct ubcore_comm_endpoint *ep, *tmp;

	spin_lock(&g_ep_lock);
	list_for_each_entry_safe(ep, tmp, &g_ep_list, list) {
		list_del(&ep->list);
		spin_unlock(&g_ep_lock);
		ubcore_comm_destroy_endpoint(ep);
		spin_lock(&g_ep_lock);
	}
	g_default_ep = NULL;
	spin_unlock(&g_ep_lock);
}
