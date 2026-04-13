// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore connect adapter implementation file
 * Author: Wang Hang
 * Create: 2025-06-19
 * Note:
 * History: 2025-06-19: create file
 */

#include <linux/random.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubcore_log.h"
#include "net/ubcore_protocol.h"
#include "net/ubcore_comm.h"
#include "net/ubcore_session.h"
#include "ubcore_connect_adapter.h"
#include "ubcore_priv.h"
#include "ubcore_hash_table.h"

enum msg_create_conn_result {
	CREATE_CONN_SUCCESS = 0,
	GET_TP_LIST_ERROR,
	ACTIVE_TP_ERROR,
	CREATE_CONN_FAIL
};

struct session_data_create_conn {
	uint64_t peer_tp_handle;
	uint32_t rx_psn;
	int ret;
};

struct msg_create_conn_req {
	struct ubcore_get_tp_cfg get_tp_cfg;
	uint64_t tp_handle;
	uint32_t tx_psn;
/* Only for RC + RTP */
	uint32_t src_jetty_id;
	uint32_t dst_jetty_id;
};

struct msg_create_conn_resp {
	uint64_t tp_handle;
	uint32_t tx_psn;
	int result; /* Refer to enum msg_create_conn_result */
};

struct msg_destroy_conn_req {
	union ubcore_tp_handle tp_handle;
	union ubcore_tp_handle peer_tp_handle;
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t src_jetty_id;
	uint32_t dst_jetty_id;
	enum ubcore_transport_mode trans_mode;
};

/* Default as 128 ms */
uint32_t ubcore_conn_timeout = UBCORE_DEF_CONN_TIMEOUT;

uint32_t ubcore_get_conn_timeout(void)
{
	return ubcore_conn_timeout;
}

static int ubcore_active_tp(struct ubcore_device *dev,
			    struct ubcore_active_tp_cfg *active_cfg)
{
	int ret;

	if (!dev || !dev->ops || !dev->ops->active_tp ||
	    active_cfg == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ubcore_log_info("Active tp, local tp_hdl: %llu, peer tp_hdl: %llu.\n",
			active_cfg->tp_handle.value,
			active_cfg->peer_tp_handle.value);
	ret = dev->ops->active_tp(dev, active_cfg);
	if (ret != 0)
		ubcore_log_err(
			"Failed to active tp, ret: %d, local tpid: %u.\n", ret,
			(uint32_t)active_cfg->tp_handle.bs.tpid);

	return ret;
}

static int ubcore_deactive_tp(struct ubcore_device *dev,
				union ubcore_tp_handle tp_handle,
				struct ubcore_udata *udata)
{
	int ret;

	if (!dev || !dev->ops || !dev->ops->deactive_tp) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->deactive_tp(dev, tp_handle, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to deactivate tp, ret: %d.\n", ret);
		return ret;
	}

	return ret;
}

static struct ubcore_session *
create_session_for_create_connection(struct ubcore_device *dev)
{
	struct ubcore_session *session;
	struct session_data_create_conn *session_data;

	session_data =
		kzalloc(sizeof(struct session_data_create_conn), GFP_KERNEL);
	if (IS_ERR_OR_NULL(session_data)) {
		ubcore_log_err("Failed to alloc create user arg");
		return NULL;
	}

	session_data->ret = -1;

	session = ubcore_session_create(dev, session_data,
		ubcore_get_conn_timeout(), NULL, NULL);
	if (!session) {
		ubcore_log_err("Failed to alloc session for create connection");
		kfree(session_data);
		return NULL;
	}

	return session;
}

static int send_create_req(struct ubcore_device *dev, uint32_t session_id,
			   struct msg_create_conn_req *req)
{
	struct ubcore_net_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_CREATE_REQ;
	msg.len = (uint16_t)sizeof(struct msg_create_conn_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubcore_net_send_to(dev, &msg, req->get_tp_cfg.peer_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg, dev_name is %s, peer_eid is "EID_FMT"\n",
			dev->dev_name, EID_ARGS(req->get_tp_cfg.peer_eid));
		return ret;
	}
	return 0;
}

static int send_create_resp(struct ubcore_device *dev, void *conn,
			    uint32_t session_id,
			    struct msg_create_conn_resp *resp)
{
	struct ubcore_net_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_CREATE_RESP;
	msg.len = (uint16_t)sizeof(struct msg_create_conn_resp);
	msg.session_id = session_id;
	msg.data = resp;

	ret = ubcore_net_send(dev, &msg, conn);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

static int ubcore_add_ex_tp_info(struct ubcore_device *dev, uint64_t tp_handle)
{
	struct ubcore_ex_tp_info *ex_tp_info = NULL;
	uint32_t hash;
	int ret;

	ex_tp_info = kzalloc(sizeof(struct ubcore_ex_tp_info), GFP_KERNEL);
	if (!ex_tp_info)
		return -ENOMEM;
	ex_tp_info->tp_handle = tp_handle;
	kref_init(&ex_tp_info->ref_cnt);

	hash = ubcore_get_ex_tp_hash(&tp_handle);
	ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_EX_TP],
					 &ex_tp_info->hnode, hash);
	if (ret != 0) {
		ubcore_log_err("Failed to add ex tp info, tp_handle: %llu.\n",
			       tp_handle);
		kfree(ex_tp_info);
	}

	return ret;
}

struct ubcore_ex_tp_info *
ubcore_find_remove_ex_tp_info(struct ubcore_device *dev, uint64_t tp_handle)
{
	struct ubcore_ex_tp_info *ex_tp_info = NULL;
	uint32_t hash;

	hash = ubcore_get_ex_tp_hash(&tp_handle);
	spin_lock(&dev->ht[UBCORE_HT_EX_TP].lock);
	if (!dev->ht[UBCORE_HT_EX_TP].head) {
		spin_unlock(&dev->ht[UBCORE_HT_EX_TP].lock);
		return NULL;
	}

	ex_tp_info = ubcore_hash_table_lookup_nolock(&dev->ht[UBCORE_HT_EX_TP],
						     hash, &tp_handle);
	if (!ex_tp_info) {
		spin_unlock(&dev->ht[UBCORE_HT_EX_TP].lock);
		ubcore_log_info("Do not find ex_tp_info, tp_handle: %llu.\n",
				tp_handle);
		return NULL;
	}
	ubcore_hash_table_remove_nolock(&dev->ht[UBCORE_HT_EX_TP],
					&ex_tp_info->hnode);
	spin_unlock(&dev->ht[UBCORE_HT_EX_TP].lock);

	return ex_tp_info;
}

static bool ubcore_check_ex_tp_info(struct ubcore_device *dev,
				    uint64_t tp_handle)
{
	struct ubcore_ex_tp_info *ex_tp_info = NULL;

	ex_tp_info = ubcore_find_remove_ex_tp_info(dev, tp_handle);
	if (!ex_tp_info)
		return false;

	kfree(ex_tp_info);
	return true;
}

static bool ubcore_is_loopback(struct ubcore_device *dev,
			       union ubcore_eid *peer_eid)
{
	uint32_t eid_idx;

	spin_lock(&dev->eid_table.lock);
	for (eid_idx = 0; eid_idx < dev->eid_table.eid_cnt; eid_idx++) {
		if (dev->eid_table.eid_entries[eid_idx].valid &&
			memcmp(peer_eid, &dev->eid_table.eid_entries[eid_idx].eid,
			sizeof(union ubcore_eid)) == 0) {
			spin_unlock(&dev->eid_table.lock);
			return true;
		}
	}
	spin_unlock(&dev->eid_table.lock);

	return false;
}

/* free local tp_handle after exchange tp_info error */
static void ubcore_free_local_tpid(struct ubcore_device *dev,
				uint64_t tp_handle, uint32_t tx_psn,
				struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_cfg = { 0 };
	union ubcore_tp_handle local_tp_hdl;
	int ret;

	active_cfg.tp_handle.value = tp_handle;
	active_cfg.peer_tp_handle.value = tp_handle;
	active_cfg.tp_attr.tx_psn = tx_psn;
	active_cfg.tp_attr.rx_psn = tx_psn;

	ubcore_log_info("Try to free local_tpid: %u.\n",
			(uint32_t)active_cfg.tp_handle.bs.tpid);
	ret = ubcore_active_tp(dev, &active_cfg);
	if (ret != 0)
		ubcore_log_err("Failed to active tp, ret: %d.\n", ret);

	local_tp_hdl.value = tp_handle;
	ret = ubcore_deactive_tp(dev, local_tp_hdl, udata);
	if (ret != 0)
		ubcore_log_err("Failed to deactivate tp, ret: %d.\n", ret);
}

int ubcore_exchange_tp_info(struct ubcore_device *dev,
				struct ubcore_get_tp_cfg *cfg, uint64_t tp_handle,
				uint32_t tx_psn, uint64_t *peer_tp_handle,
				uint32_t *rx_psn, struct ubcore_udata *udata)
{
	struct session_data_create_conn *session_data;
	struct msg_create_conn_req req = { 0 };
	struct ubcore_session *session;
	int ret;

	if (!dev || !cfg || !peer_tp_handle || !rx_psn) {
		return -EINVAL;
	}

	if (ubcore_is_loopback(dev, &cfg->peer_eid)) {
		*peer_tp_handle = tp_handle;
		*rx_psn = tx_psn;
		ubcore_log_info("Finish to handle loop back tp: %llu.\n", tp_handle);
		return 0;
	}

	session = create_session_for_create_connection(dev);
	if (!session) {
		ubcore_free_local_tpid(dev, tp_handle, tx_psn, udata);
		return -ENOMEM;
	}

	req.get_tp_cfg = *cfg;
	req.tp_handle = tp_handle;
	req.tx_psn = tx_psn;
	ret = send_create_req(dev, ubcore_session_get_id(session), &req);
	if (ret != 0) {
		ubcore_session_complete(session);
		ubcore_session_ref_release(session);
		ubcore_free_local_tpid(dev, tp_handle, tx_psn, udata);
		return ret;
	}

	ubcore_session_wait(session);
	session_data =
		(struct session_data_create_conn *)ubcore_session_get_data(
			session);
	ret = session_data->ret;
	if (ret != 0) {
		ubcore_log_err("Failed to send create req message, ret: %d.\n",
			       ret);
		ubcore_session_ref_release(session);
		ubcore_free_local_tpid(dev, tp_handle, tx_psn, udata);
		return ret;
	}
	*peer_tp_handle = session_data->peer_tp_handle;
	*rx_psn = session_data->rx_psn;
	ubcore_session_ref_release(session);

	ret = ubcore_add_ex_tp_info(dev, tp_handle);
	ubcore_log_info("[EXCHANGE_TP_INFO] dev:%s tp_handle:%llu peer_tp:%llu",
		dev->dev_name, tp_handle, *peer_tp_handle);
	ubcore_log_info("  local_eid " EID_FMT " peer_eid " EID_FMT,
		EID_ARGS(cfg->local_eid), EID_ARGS(cfg->peer_eid));
	/* ubcore_add_ex_tp_info result will not have effect on excange_tp_info result */
	return ret;
}
EXPORT_SYMBOL(ubcore_exchange_tp_info);

/* Only for RC + RTP */
int ubcore_exchange_tpid_info(struct ubcore_device *dev,
	struct ubcore_get_tp_cfg *cfg, struct ubcore_ex_tpid_info *info,
	struct ubcore_udata *udata)
{
	struct session_data_create_conn *session_data;
	struct msg_create_conn_req req = { 0 };
	struct ubcore_session *session;
	int ret;

	if (!dev || !cfg || !info) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (ubcore_is_loopback(dev, &cfg->peer_eid)) {
		info->peer_tp_handle = info->tp_handle;
		info->rx_psn = info->tx_psn;
		ubcore_log_info("Finish to handle loop back tp: %llu.\n",
			info->tp_handle);
		return 0;
	}

	session = create_session_for_create_connection(dev);
	if (!session) {
		ubcore_free_local_tpid(dev, info->tp_handle, info->tx_psn, udata);
		return -ENOMEM;
	}

	req.get_tp_cfg = *cfg;
	req.tp_handle = info->tp_handle;
	req.tx_psn = info->tx_psn;
	req.src_jetty_id = info->local_jetty_id;
	req.dst_jetty_id = info->peer_jetty_id;
	ret = send_create_req(dev, ubcore_session_get_id(session), &req);
	if (ret != 0) {
		ubcore_log_err("Failed to send create req message");
		ubcore_session_complete(session);
		ubcore_session_ref_release(session);
		ubcore_free_local_tpid(dev, info->tp_handle, info->tx_psn, udata);
		return ret;
	}

	ubcore_session_wait(session);
	session_data =
		(struct session_data_create_conn *)ubcore_session_get_data(
			session);
	ret = session_data->ret;
	if (ret != 0) {
		ubcore_log_err("Failed to send create req message, ret: %d.\n",
			       ret);
		ubcore_session_ref_release(session);
		ubcore_free_local_tpid(dev, info->tp_handle, info->tx_psn, udata);
		return ret;
	}
	info->peer_tp_handle = session_data->peer_tp_handle;
	info->rx_psn = session_data->rx_psn;
	ubcore_session_ref_release(session);

	ret = ubcore_add_ex_tp_info(dev, info->tp_handle);
	ubcore_log_info("exchange tp_handle is %llu\n",
		(unsigned long long)info->tp_handle);
	/* ubcore_add_ex_tp_info result will not have effect on excange_tp_info result */
	if (ret != 0)
		ubcore_log_err("Failed to add ex tp info, ret: %d.\n", ret);
	return 0;
}

static inline uint32_t ubcore_get_tpid_hash(struct ubcore_tpid_key *key)
{
	return jhash(key, sizeof(struct ubcore_tpid_key), 0);
}

struct ubcore_tpid_ctx *ubcore_fget_tpid_ctx(
	struct ubcore_device *dev, struct ubcore_tpid_key *key)
{
	struct ubcore_tpid_ctx *ctx = NULL;
	uint32_t hash;

	hash = ubcore_get_tpid_hash(key);
	ctx = ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_RC_TP_ID],
		hash, key);
	ubcore_log_info("Find tpid_ctx result: %d, hash: %u.\n",
		(int)(ctx != NULL), hash);

	return ctx;
}

void ubcore_tpid_get(void *obj)
{
	struct ubcore_tpid_ctx *ctx = obj;

	kref_get(&ctx->ref);
}

static void ubcore_tpid_ctx_free(struct kref *ref)
{
	struct ubcore_tpid_ctx *ctx = container_of(ref,
		struct ubcore_tpid_ctx, ref);

	kfree(ctx);
}

static void ubcore_tpid_put(struct ubcore_tpid_ctx *ctx)
{
	kref_put(&ctx->ref, ubcore_tpid_ctx_free);
}

void ubcore_reuse_target_rtp_tpid(struct ubcore_device *dev,
	struct ubcore_tpid_ctx *ctx, struct ubcore_get_tp_cfg *cfg,
	struct ubcore_net_msg *msg, void *conn)
{
	struct msg_create_conn_resp resp = { 0 };
	int ret;

	if (cfg->flag.bs.rtp != 1 || cfg->trans_mode != UBCORE_TP_RC) {
		ubcore_log_err("Invalid operation.\n");
		ubcore_tpid_put(ctx);
		ret = -EINVAL;
		goto send_resp;
	}

	if (!ctx->is_init) {
		ubcore_log_err("Duplicate operation.\n");
		ubcore_tpid_put(ctx);
		ret = -EINVAL;
		goto send_resp;
	}

	/* Reuse */
	ubcore_log_info("Reuse tpid: %llu.\n", ctx->tp_handle);
	resp.tp_handle = ctx->tp_handle;
	resp.tx_psn = ctx->tx_psn;
	ret = CREATE_CONN_SUCCESS;

send_resp:
	resp.result = ret;
	if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
		ubcore_log_err("Failed to send create resp message.\n");
}

static inline void fill_tpid_ctx(struct ubcore_tpid_ctx *ctx,
	struct ubcore_tpid_key *key, struct ubcore_active_tp_cfg *cfg,
	bool is_init)
{
	ctx->tp_handle = cfg->tp_handle.value;
	ctx->peer_tp_handle = cfg->peer_tp_handle.value;
	kref_init(&ctx->ref);
	ctx->trans_mode = UBCORE_TP_RC;
	ctx->key = *key;
	ctx->tp_type = UBCORE_RTP;
	ctx->is_init = is_init;
	ctx->tx_psn = cfg->tp_attr.tx_psn;
	ctx->rx_psn = cfg->tp_attr.rx_psn;
}

void ubcore_fadd_target_tpid_ctx(struct ubcore_device *dev,
	struct ubcore_tpid_key *key, struct ubcore_active_tp_cfg *cfg,
	struct msg_create_conn_resp *resp)
{
	struct ubcore_tpid_ctx *add_ctx = NULL;
	struct ubcore_tpid_ctx *ctx = NULL;
	struct ubcore_hash_table *ht;
	uint32_t hash;

	hash = ubcore_get_tpid_hash(key);
	ht = &dev->ht[UBCORE_HT_RC_TP_ID];

	add_ctx = kzalloc(sizeof(struct ubcore_tpid_ctx), GFP_KERNEL);
	if (IS_ERR_OR_NULL(add_ctx))
		return;

	spin_lock(&ht->lock);
	ctx = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (ctx && ctx->is_init) {
		resp->tp_handle = ctx->tp_handle;
		spin_unlock(&ht->lock);
		ubcore_log_info("Find tpid in initiator, hash: %u.\n", hash);
		(void)ubcore_deactive_tp(dev, cfg->tp_handle, NULL);
		kfree(add_ctx);
		return;
	}
	if (ctx && !ctx->is_init) {
		spin_unlock(&ht->lock);
		ubcore_log_info("Find tpid in target, hash: %u.\n", hash);
		kfree(add_ctx);
		return;
	}

	fill_tpid_ctx(add_ctx, key, cfg, false);
	ubcore_log_info("add_ctx tp_handle is %llu, peer_tp_handle is %llu.",
		add_ctx->tp_handle, add_ctx->peer_tp_handle);
	add_ctx->tp_state = UBCORE_TP_ACTIVE;
	ubcore_hash_table_add_nolock(ht, &add_ctx->hnode, hash);
	spin_unlock(&ht->lock);
}

static void handle_create_req(struct ubcore_device *dev, struct ubcore_net_msg *msg, void *conn)
{
	struct msg_create_conn_req *req = (struct msg_create_conn_req *)msg->data;
	struct ubcore_get_tp_cfg get_tp_cfg = req->get_tp_cfg;
	struct ubcore_active_tp_cfg active_cfg = {0};
	struct msg_create_conn_resp resp = {0};
	struct ubcore_tp_info tp_info = {0};
	uint32_t tp_cnt = 1;
	uint64_t tp_handle;
	uint32_t tx_psn;
	int ret;

	get_tp_cfg.local_eid = req->get_tp_cfg.peer_eid;
	get_tp_cfg.peer_eid = req->get_tp_cfg.local_eid;
	ret = ubcore_get_tp_list(dev, &get_tp_cfg, &tp_cnt, &tp_info, NULL);
	if (ret != 0 || tp_cnt != 1) {
		ubcore_log_err("Failed to get tp list, local eid " EID_FMT
			       ", peer eid " EID_FMT ", ret %d.\n",
			       EID_ARGS(get_tp_cfg.local_eid),
			       EID_ARGS(get_tp_cfg.peer_eid), ret);
		ret = GET_TP_LIST_ERROR;
		goto send_resp;
	}

	tp_handle = tp_info.tp_handle.value;
	tx_psn = get_random_u32();

	active_cfg.tp_handle.value = tp_handle;
	active_cfg.peer_tp_handle.value = req->tp_handle;
	active_cfg.tp_attr.rx_psn = req->tx_psn;
	active_cfg.tp_attr.tx_psn = tx_psn;

	ubcore_log_info("Rcv req, local eid " EID_FMT ", peer eid " EID_FMT
		", tphdl: %llu, p_tphdl: %llu, tx_psn: %u, rx_psn: %u.\n",
		EID_ARGS(get_tp_cfg.local_eid),
		EID_ARGS(get_tp_cfg.peer_eid), tp_info.tp_handle.value,
		active_cfg.peer_tp_handle.value, tx_psn, req->tx_psn);

	ret = ubcore_active_tp(dev, &active_cfg);
	if (ret != 0) {
		ubcore_log_err("Failed to active tp, ret: %d.\n", ret);
		ret = ACTIVE_TP_ERROR;
		goto send_resp;
	}

	resp.tp_handle = tp_handle;
	resp.tx_psn = tx_psn;
	ret = CREATE_CONN_SUCCESS;

send_resp:
	resp.result = ret;
	if (send_create_resp(dev, conn, msg->session_id, &resp) != 0)
		ubcore_log_err("Failed to send create resp message.\n");
}

static void handle_create_resp(struct ubcore_device *dev, struct ubcore_net_msg *msg, void *conn)
{
	struct msg_create_conn_resp *resp = (struct msg_create_conn_resp *)msg->data;
	struct ubcore_session *session;
	struct session_data_create_conn *session_data;

	session = ubcore_session_find(msg->session_id);
	if (!session) {
		ubcore_log_err(
			"Failed to find session %u on handle create-resp",
			msg->session_id);
		return;
	}
	session_data = (struct session_data_create_conn *)ubcore_session_get_data(session);
	session_data->rx_psn = resp->tx_psn;
	session_data->peer_tp_handle = resp->tp_handle;
	session_data->ret = resp->result;
	ubcore_log_info("Create response result: %d.\n", resp->result);

	ubcore_session_complete(session);
	ubcore_session_ref_release(session);
}

static int send_destroy_req(struct ubcore_device *dev, union ubcore_eid peer_addr,
	union ubcore_tp_handle peer_tp_handle, uint32_t s_jetty_id, uint32_t d_jetty_id,
	union ubcore_eid local_addr, enum ubcore_transport_mode trans_mode)
{
	struct ubcore_net_msg msg = { 0 };
	struct msg_destroy_conn_req req = { 0 };
	int ret;

	req.tp_handle = peer_tp_handle;
	req.src_jetty_id = s_jetty_id;
	req.dst_jetty_id = d_jetty_id;
	req.local_eid = local_addr;
	req.peer_eid = peer_addr;
	req.trans_mode = trans_mode;

	msg.type = UBCORE_NET_DESTROY_REQ;
	msg.len = (uint16_t)sizeof(struct msg_destroy_conn_req);
	msg.session_id = 0;
	msg.data = &req;

	ret = ubcore_net_send_to(dev, &msg, peer_addr);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

int ubcore_adapter_layer_disconnect(struct ubcore_vtpn *vtpn)
{
	union ubcore_tp_handle peer_tp_handle =
		(union ubcore_tp_handle)vtpn->peer_tp_handle;
	union ubcore_tp_handle tp_handle =
		(union ubcore_tp_handle)vtpn->tp_handle;
	union ubcore_eid peer_eid = vtpn->peer_eid;
	struct ubcore_device *dev = vtpn->ub_dev;
	struct ubcore_udata udata = {0};
	bool ctp = tp_handle.bs.ctp;
	int ret;

	if (vtpn->trans_mode == UBCORE_TP_RC) {
		ret = ubcore_deactive_tp(dev, tp_handle, NULL);
	} else {
		if (vtpn->uspace)
			ret = ubcore_deactive_tp(dev, tp_handle, &udata);
		else
			ret = ubcore_deactive_tp(dev, tp_handle, NULL);
	}
	if (ret != 0) {
		ubcore_log_err("Failed to deactivate tp, ret: %d, tphdl: %llu.\n",
			ret, tp_handle.value);
		return ret;
	}

	if (ubcore_is_loopback(dev, &peer_eid)) {
		ubcore_log_info(
			"Loop-back, tp_handle: %llu,peer_tp_handle: %llu.\n",
			vtpn->tp_handle, vtpn->peer_tp_handle);
		return 0;
	}
	if (!ubcore_check_ex_tp_info(dev, vtpn->tp_handle)) {
		ubcore_log_info(
			"No need to notify destroy request, tp_handle: %llu.\n",
			vtpn->tp_handle);
		return 0;
	}

	/* Only send destroy request for RM/RC TP */
	if ((vtpn->trans_mode == UBCORE_TP_RM || vtpn->trans_mode == UBCORE_TP_RC) && !ctp &&
		ubcore_check_ctrlplane_compat(dev->ops->import_jetty)) {
		if (vtpn->trans_mode == UBCORE_TP_RC) {
			ret = send_destroy_req(dev, peer_eid, peer_tp_handle, vtpn->local_jetty,
				vtpn->peer_jetty, vtpn->local_eid, vtpn->trans_mode);
		} else
			ret = send_destroy_req(dev, peer_eid, peer_tp_handle, 0, 0, vtpn->local_eid,
				vtpn->trans_mode);
	}
	if (ret != 0)
		ubcore_log_err("Failed to send destroy req message");

	return 0;
}

static void handle_destroy_req(struct ubcore_device *dev,
			       struct ubcore_net_msg *msg, void *conn)
{
	struct msg_destroy_conn_req *req =
		(struct msg_destroy_conn_req *)msg->data;
	int ret;

	/* Target tp_handle get from kernel space */
	ret = ubcore_deactive_tp(dev, req->tp_handle, NULL);
	if (ret != 0)
		ubcore_log_err("Failed to deactivate tp, ret: %d, tphdl: %llu",
			ret, req->tp_handle.value);
}

/* Only for impoprt_jetty/jfr, thus only for RM/UM */
static int ubcore_fill_get_tp_cfg(struct ubcore_device *dev,
				  struct ubcore_get_tp_cfg *get_tp_cfg,
				  struct ubcore_tjetty_cfg *cfg)
{
	uint32_t eid_index = cfg->eid_index;

	if (cfg->tp_type == UBCORE_CTP)
		get_tp_cfg->flag.bs.ctp = 1;
	else if (cfg->tp_type == UBCORE_RTP)
		get_tp_cfg->flag.bs.rtp = 1;
	else
		get_tp_cfg->flag.bs.utp = 1;

	get_tp_cfg->trans_mode = cfg->trans_mode;

	spin_lock(&dev->eid_table.lock);
	if (eid_index >= dev->eid_table.eid_cnt ||
	    dev->eid_table.eid_entries == NULL ||
	    dev->eid_table.eid_entries[eid_index].valid == false) {
		spin_unlock(&dev->eid_table.lock);
		ubcore_log_err("Invalid parameter, eid_index: %u.\n",
			       eid_index);
		return -EINVAL;
	}
	get_tp_cfg->local_eid = dev->eid_table.eid_entries[eid_index].eid;
	spin_unlock(&dev->eid_table.lock);
	get_tp_cfg->peer_eid = cfg->id.eid;

	return 0;
}

struct ubcore_tjetty *ubcore_import_jfr_compat(struct ubcore_device *dev,
					       struct ubcore_tjetty_cfg *cfg,
					       struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct ubcore_get_tp_cfg get_tp_cfg = { 0 };
	struct ubcore_tp_info tp_list = { 0 };
	struct ubcore_tjetty *tjfr = NULL;
	uint32_t tp_cnt = 1;
	int ret;

	if (cfg->trans_mode != UBCORE_TP_RM &&
	    cfg->trans_mode != UBCORE_TP_UM) {
		ubcore_log_err("Invalid trans_mode %d.\n",
			       (int)cfg->trans_mode);
		return ERR_PTR(-EINVAL);
	}

	if (ubcore_fill_get_tp_cfg(dev, &get_tp_cfg, cfg) != 0)
		return NULL;

	ret = ubcore_get_tp_list(dev, &get_tp_cfg, &tp_cnt, &tp_list, NULL);
	if (ret != 0 || tp_cnt != 1) {
		ubcore_log_err("Failed to get tp list, ret: %d, tp_cnt: %u.\n",
			       ret, tp_cnt);
		return ret == 0 ? ERR_PTR(-UBCORE_DRV_ERRNO) : ERR_PTR(ret);
	}

	active_tp_cfg.tp_handle = tp_list.tp_handle;

	if (cfg->trans_mode == UBCORE_TP_RM &&
		cfg->tp_type == UBCORE_RTP) {
		active_tp_cfg.tp_attr.tx_psn = get_random_u32();
		ret = ubcore_exchange_tp_info(
			dev, &get_tp_cfg, tp_list.tp_handle.value,
			active_tp_cfg.tp_attr.tx_psn,
			&active_tp_cfg.peer_tp_handle.value,
			&active_tp_cfg.tp_attr.rx_psn, udata);
		if (ret != 0) {
			ubcore_log_err("Exchange_tp_info Failed: dev_name is %s,local_tp_handle is %llu",
				dev->dev_name, tp_list.tp_handle.value);
			ubcore_log_err("  local eid " EID_FMT ", peer eid " EID_FMT,
				EID_ARGS(get_tp_cfg.local_eid),
				EID_ARGS(get_tp_cfg.peer_eid));
			return NULL;
		}
	}

	tjfr = ubcore_import_jfr_ex(dev, cfg, &active_tp_cfg, udata);

	return tjfr;
}

struct ubcore_tjetty *ubcore_import_jetty_compat(struct ubcore_device *dev,
						 struct ubcore_tjetty_cfg *cfg,
						 struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	struct ubcore_get_tp_cfg get_tp_cfg = { 0 };
	struct ubcore_tp_info tp_list = { 0 };
	struct ubcore_tjetty *tjetty = NULL;
	uint32_t tp_cnt = 1;
	int ret;

	if (cfg->trans_mode == UBCORE_TP_RM ||
	    cfg->trans_mode == UBCORE_TP_UM) {
		if (ubcore_fill_get_tp_cfg(dev, &get_tp_cfg, cfg) != 0)
			return NULL;

		ret = ubcore_get_tp_list(dev, &get_tp_cfg, &tp_cnt, &tp_list,
					 NULL);
		if (ret != 0 || tp_cnt != 1) {
			ubcore_log_err(
				"Failed to get tp list, ret: %d, tp_cnt: %u.\n",
				ret, tp_cnt);
			return ret == 0 ? ERR_PTR(-UBCORE_DRV_ERRNO) : ERR_PTR(ret);
		}

		active_tp_cfg.tp_handle = tp_list.tp_handle;

		if (cfg->trans_mode == UBCORE_TP_RM &&
			cfg->tp_type == UBCORE_RTP) {
			active_tp_cfg.tp_attr.tx_psn = get_random_u32();
			ret = ubcore_exchange_tp_info(
				dev, &get_tp_cfg, tp_list.tp_handle.value,
				active_tp_cfg.tp_attr.tx_psn,
				&active_tp_cfg.peer_tp_handle.value,
				&active_tp_cfg.tp_attr.rx_psn, udata);
			if (ret != 0) {
				ubcore_log_err("Exchange_tp_info Failed: dev_name is %s, local_tp_handle is %llu",
					dev->dev_name, tp_list.tp_handle.value);
				ubcore_log_err("localeid " EID_FMT ", peereid " EID_FMT,
					EID_ARGS(get_tp_cfg.local_eid),
					EID_ARGS(get_tp_cfg.peer_eid));
				return NULL;
			}
		}
	}

	tjetty = ubcore_import_jetty_ex(dev, cfg, &active_tp_cfg, udata);
	if (IS_ERR_OR_NULL(tjetty))
		ubcore_log_err("Failed to import jetty ex.\n");

	return tjetty;
}

void ubcore_fadd_init_tpid_ctx(struct ubcore_device *dev,
	struct ubcore_tpid_key *key, struct ubcore_active_tp_cfg *cfg,
	struct ubcore_vtpn *vtpn)
{
	struct ubcore_tpid_ctx *add_ctx = NULL;
	struct ubcore_tpid_ctx *ctx = NULL;
	struct ubcore_hash_table *ht;
	uint32_t hash;

	hash = ubcore_get_tpid_hash(key);
	ht = &dev->ht[UBCORE_HT_RC_TP_ID];

	add_ctx = kzalloc(sizeof(struct ubcore_tpid_ctx), GFP_KERNEL);
	if (IS_ERR_OR_NULL(add_ctx))
		return;

	spin_lock(&ht->lock);
	ctx = ubcore_hash_table_lookup_nolock(ht, hash, key);
	if (ctx && ctx->is_init) {
		spin_unlock(&ht->lock);
		ubcore_log_warn("Find tpid in initiator, hash: %u.\n", hash);
		kfree(add_ctx);
		return;
	}
	if (ctx && !ctx->is_init) {
		ubcore_log_info("Find tpid in target, hash: %u.\n", hash);
		spin_unlock(&ht->lock);
		(void)ubcore_deactive_tp(dev, cfg->tp_handle, NULL);
		kfree(add_ctx);
		return;
	}

	fill_tpid_ctx(add_ctx, key, cfg, true);
	ubcore_log_info("add_ctx has tp_handle:%llu, peer_tp_handle:%llu.\n",
		add_ctx->tp_handle, add_ctx->peer_tp_handle);
	add_ctx->tp_state = UBCORE_TP_ENABLE;
	ubcore_hash_table_add_nolock(ht, &add_ctx->hnode, hash);
	spin_unlock(&ht->lock);
}

int ubcore_reuse_init_rtp_tpid(struct ubcore_jetty *jetty,
	struct ubcore_tjetty *tjetty, struct ubcore_tpid_ctx *ctx,
	struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = { 0 };
	int ret;

	if (ctx->is_init) {
		ubcore_log_err("Invalid operation, tp_handle: %llu.\n",
			ctx->tp_handle);
		ubcore_tpid_put(ctx);
		return -EINVAL;
	}

	/* Reuse */
	active_tp_cfg.tp_handle.value = ctx->tp_handle;
	active_tp_cfg.peer_tp_handle.value = ctx->peer_tp_handle;
	active_tp_cfg.tp_attr.tx_psn = ctx->tx_psn;
	active_tp_cfg.tp_attr.rx_psn = ctx->rx_psn;
	active_tp_cfg.tag = 0;
	ubcore_log_info("tp_handle is %llu, peer_tp_handle is %llu.",
		ctx->tp_handle, ctx->peer_tp_handle);

	ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
	if (ret != 0) {
		ubcore_log_err("Failed to bind jetty in target, ret: %d.\n", ret);
		ubcore_tpid_put(ctx);
	}
	ubcore_tpid_get(ctx);
	return ret;
}

int ubcore_bind_jetty_compat(struct ubcore_jetty *jetty,
	struct ubcore_tjetty *tjetty, struct ubcore_udata *udata)
{
	struct ubcore_active_tp_cfg active_tp_cfg = {0};
	struct ubcore_get_tp_cfg get_tp_cfg = {0};
	struct ubcore_device *dev = jetty->ub_dev;
	struct ubcore_tp_info tp_list = { 0 };
	uint32_t tp_cnt = 1;
	int ret;

	ret = ubcore_fill_get_tp_cfg(dev, &get_tp_cfg, &tjetty->cfg);
	if (ret != 0)
		return ret;

	ret = ubcore_get_tp_list(dev, &get_tp_cfg, &tp_cnt, &tp_list, NULL);
	if (ret != 0 || tp_cnt != 1) {
		ubcore_log_err("Failed to get tp list, ret: %d, tp_cnt: %u.\n",
			       ret, tp_cnt);
		return ret == 0 ? -UBCORE_DRV_ERRNO : ret;
	}

	active_tp_cfg.tp_handle = tp_list.tp_handle;
	active_tp_cfg.tp_attr.tx_psn = get_random_u32();

	if (tjetty->cfg.tp_type == UBCORE_RTP) {
		ret = ubcore_exchange_tp_info(dev, &get_tp_cfg,
			tp_list.tp_handle.value, active_tp_cfg.tp_attr.tx_psn,
			&active_tp_cfg.peer_tp_handle.value,
			&active_tp_cfg.tp_attr.rx_psn, udata);
		if (ret != 0) {
			ubcore_log_err("Failed to exchange tp info, ret: %d.\n", ret);
			return ret;
		}
		ubcore_log_info("Finish to exchange tp info.\n");
	}

	ret = ubcore_bind_jetty_ex(jetty, tjetty, &active_tp_cfg, udata);
	if (ret != 0) {
		ubcore_log_err("Failed to bind jetty ex, ret: %d.\n", ret);
		return ret;
	}
	atomic_dec(&tjetty->use_cnt);

	return ret;
}

void ubcore_exchange_init(void)
{
	ubcore_net_register_msg_handler(UBCORE_NET_CREATE_REQ,
					handle_create_req,
					sizeof(struct msg_create_conn_req));
	ubcore_net_register_msg_handler(UBCORE_NET_CREATE_RESP,
					handle_create_resp,
					sizeof(struct msg_create_conn_resp));
	ubcore_net_register_msg_handler(UBCORE_NET_DESTROY_REQ,
					handle_destroy_req,
					sizeof(struct msg_destroy_conn_req));
}
