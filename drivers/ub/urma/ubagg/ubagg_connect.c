// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg connect implementation file
 * Author: Chen Chongyu
 * Create: 2026-05-13
 * Note:
 * History: 2026-05-13: create file
 */

#include <linux/module.h>
#include <ub/urma/ubcore_uapi.h>

#include "ubagg_hash_table.h"
#include "ubagg_ioctl.h"
#include "ubagg_session.h"
#include "ubagg_topo_info.h"
#include "ubagg_log.h"
#include "ubagg_msg.h"
#include "ubagg_types.h"
#include "ubagg_device.h"

#include "ubagg_connect.h"

#define UBAGG_NS_TO_MS 1000000
#define UBAGG_EXC_THRESHOLD_MS 20

struct session_data_exchange_udata {
	int *result;
	void *udata_out;
	uint32_t udata_out_size;
};

struct msg_seg_info_req {
	struct ubcore_ubva ubva;
	uint64_t len;
	uint32_t token_id;
};

struct msg_jetty_info_req {
	struct ubcore_jetty_id jetty_id;
	bool is_jfr;
};

struct msg_seg_info_resp {
	int result;
	struct ubagg_seg_exchange_info seg_info;
};

struct msg_jetty_info_resp {
	int result;
	struct ubagg_jetty_exchange_info jetty_info;
};

static struct ubcore_device *find_phys_dev(struct ubcore_device *bonding_dev,
					   uint32_t ue_id)
{
	struct ubagg_topo_node *topo_info;
	union ubcore_eid *primary_eid;
	union ubcore_eid bonding_eid;
	int dev_id;
	uint32_t eid_idx;
	bool is_eid_found = false;
	bool is_bonding_dev_found = false;

	if (bonding_dev == NULL) {
		ubagg_log_err("bonding_dev is NULL");
		return NULL;
	}
	if (ue_id >= IODIE_NUM) {
		ubagg_log_err("Invalid ue_id: %u.\n", ue_id);
		return NULL;
	}
	topo_info = get_current_topo_node();
	if (!topo_info) {
		ubagg_log_err("Failed get global topo info");
		return NULL;
	}

	spin_lock(&bonding_dev->eid_table.lock);
	for (eid_idx = 0; eid_idx < bonding_dev->eid_table.eid_cnt; eid_idx++) {
		if (bonding_dev->eid_table.eid_entries[eid_idx].valid) {
			bonding_eid =
				bonding_dev->eid_table.eid_entries[eid_idx].eid;
			is_eid_found = true;
			break;
		}
	}
	spin_unlock(&bonding_dev->eid_table.lock);
	if (!is_eid_found) {
		ubagg_log_err("Failed to find bonding eid.\n");
		return NULL;
	}

	for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
		if (memcmp((union ubcore_eid *)topo_info->agg_devs[dev_id]
				   .agg_eid,
			   &bonding_eid, sizeof(union ubcore_eid)) == 0) {
			is_bonding_dev_found = true;
			break;
		}
	}
	if (!is_bonding_dev_found) {
		ubagg_log_err("Failed to find bonding device.\n");
		return NULL;
	}

	primary_eid = (union ubcore_eid *)topo_info->agg_devs[dev_id]
			      .ues[ue_id]
			      .primary_eid;

	return ubcore_get_device_by_eid(primary_eid, UBCORE_TRANSPORT_UB);
}

static struct ubagg_session *alloc_xchg_session(struct ubcore_device *dev,
						int *result, void *udata_out,
						uint32_t udata_out_size)
{
	struct ubagg_session *session;
	struct session_data_exchange_udata *session_data;

	session_data =
		kzalloc(sizeof(struct session_data_exchange_udata), GFP_KERNEL);
	if (IS_ERR_OR_NULL(session_data)) {
		ubagg_log_err("Failed to alloc exchange seg info user arg");
		return NULL;
	}
	session_data->result = result;
	session_data->udata_out = udata_out;
	session_data->udata_out_size = udata_out_size;

	session = ubagg_session_create(NULL, session_data,
				       UBAGG_CONN_MAX_TIMEOUT, NULL, NULL);
	if (!session) {
		ubagg_log_err("Failed to alloc session for exchange seg info");
		kfree(session_data);
		return NULL;
	}

	return session;
}

static int send_seg_req(struct ubcore_device *dev, uint32_t session_id,
			struct msg_seg_info_req *req, uint32_t ue_id)
{
	struct ubcore_comm_msg msg = { 0 };
	union ubcore_eid dest_eid = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_COMM_MSG_SEG_INFO_REQ;
	msg.version = UBAGG_BONDING_MSG_CUR_VERSION;
	msg.len = sizeof(struct msg_seg_info_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubagg_get_primary_eid_by_agg_eid(&req->ubva.eid, &dest_eid,
					       ue_id);
	if (ret != 0)
		return ret;

	ubagg_log_info_rl("Send seg info req to " EID_FMT "\n",
		       EID_ARGS(dest_eid));
	ret = ubcore_send_comm_msg_to(dev, &msg, dest_eid);
	if (ret != 0) {
		ubagg_log_err_rl("Failed to send msg.\n");
		return ret;
	}
	return 0;
}

static int send_seg_resp(struct ubcore_device *dev, void *conn,
			 uint32_t session_id, struct msg_seg_info_resp *resp)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_COMM_MSG_SEG_INFO_RESP;
	msg.version = UBAGG_BONDING_MSG_CUR_VERSION;
	msg.len = sizeof(struct msg_seg_info_resp);
	msg.session_id = session_id;
	msg.data = resp;

	ret = ubcore_send_comm_msg(dev, &msg, conn);
	if (ret != 0) {
		ubagg_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

static int send_jetty_req(struct ubcore_device *dev, uint32_t session_id,
			  struct msg_jetty_info_req *req, uint32_t ue_id)
{
	struct ubcore_comm_msg msg = { 0 };
	union ubcore_eid dest_eid = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_COMM_MSG_JETTY_INFO_REQ;
	msg.version = UBAGG_BONDING_MSG_CUR_VERSION;
	msg.len = sizeof(struct msg_jetty_info_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubagg_get_primary_eid_by_agg_eid(&req->jetty_id.eid, &dest_eid,
					       ue_id);
	if (ret != 0)
		return ret;

	ubagg_log_info_rl("Send jetty info req to " EID_FMT "\n",
		       EID_ARGS(dest_eid));
	ret = ubcore_send_comm_msg_to(dev, &msg, dest_eid);
	if (ret != 0) {
		ubagg_log_err_rl("Failed to send msg to " EID_FMT "\n",
				 EID_ARGS(dest_eid));
		return ret;
	}
	return 0;
}

static int send_jetty_resp(struct ubcore_device *dev, void *conn,
			   uint32_t session_id,
			   struct msg_jetty_info_resp *resp)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_COMM_MSG_JETTY_INFO_RESP;
	msg.version = UBAGG_BONDING_MSG_CUR_VERSION;
	msg.len = sizeof(struct msg_jetty_info_resp);
	msg.session_id = session_id;
	msg.data = resp;

	ret = ubcore_send_comm_msg(dev, &msg, conn);
	if (ret != 0) {
		ubagg_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

int ubagg_connect_xchg_seg(struct ubcore_seg *seg, uint32_t ue_idx,
			   struct ubcore_device *dev,
			   struct ubagg_seg_exchange_info *seg_info)
{
	struct ubcore_device *physical_dev;
	struct msg_seg_info_req req = { 0 };
	struct ubagg_session *session;
	uint64_t start, duration;
	int ret, result = -1;

	start = ktime_get_ns();

	physical_dev = find_phys_dev(dev, ue_idx);
	if (!physical_dev) {
		ubagg_log_err("Failed find physical device");
		return -EINVAL;
	}

	session = alloc_xchg_session(physical_dev, &result, seg_info,
				     sizeof(*seg_info));
	if (!session) {
		ret = -ENOMEM;
		goto put_device;
	}

	req.ubva = seg->ubva;
	req.len = seg->len;
	req.token_id = seg->token_id;
	ret = send_seg_req(physical_dev, ubagg_session_get_id(session), &req,
			   ue_idx);
	if (ret != 0) {
		ubagg_session_complete(session);
		goto release_session;
	}
	ubagg_session_wait(session);

	if (result != 0) {
		ubagg_log_err_rl("Failed to exchange udata, ret: %d.\n", result);
		ret = result;
		goto release_session;
	}

	duration = (ktime_get_ns() - start) / UBAGG_NS_TO_MS;
	if (duration > UBAGG_EXC_THRESHOLD_MS)
		ubagg_log_info_rl(
			"[EXC_INFO]exchange_seg_info consumes: %llu.\n",
			duration);

	ubagg_session_ref_release(session);
	ubcore_put_device(physical_dev);
	return 0;

release_session:
	ubagg_session_ref_release(session);
put_device:
	ubcore_put_device(physical_dev);
	return ret;
}

int ubagg_connect_xchg_jetty(struct ubcore_tjetty_cfg *cfg, uint32_t ue_idx,
			     bool is_jfr, struct ubcore_device *dev,
			     struct ubagg_jetty_exchange_info *jetty_info)
{
	struct ubcore_device *physical_dev;
	struct msg_jetty_info_req req = { 0 };
	struct ubagg_session *session;
	uint64_t start, duration;
	int ret, result = -1;

	start = ktime_get_ns();

	physical_dev = find_phys_dev(dev, ue_idx);
	if (!physical_dev) {
		ubagg_log_err("Failed find physical device");
		return -EINVAL;
	}

	session = alloc_xchg_session(physical_dev, &result, jetty_info,
				     sizeof(*jetty_info));
	if (!session) {
		ret = -ENOMEM;
		goto put_device;
	}

	req.is_jfr = is_jfr;
	req.jetty_id = cfg->id;
	ret = send_jetty_req(physical_dev, ubagg_session_get_id(session), &req,
			     ue_idx);
	if (ret != 0) {
		ubagg_session_complete(session);
		goto release_session;
	}
	ubagg_session_wait(session);

	if (result != 0) {
		ubagg_log_err_rl("Failed to exchange udata, ret: %d.\n", result);
		ret = result;
		goto release_session;
	}

	duration = (ktime_get_ns() - start) / UBAGG_NS_TO_MS;
	if (duration > UBAGG_EXC_THRESHOLD_MS)
		ubagg_log_info_rl(
			"[EXC_INFO]exchange_jetty_info consumes: %llu.\n",
			duration);

	ubagg_session_ref_release(session);
	ubcore_put_device(physical_dev);
	return 0;

release_session:
	ubagg_session_ref_release(session);
put_device:
	ubcore_put_device(physical_dev);
	return ret;
}

static void handle_seg_req(struct ubcore_device *dev,
			   struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_seg_info_req *req = (struct msg_seg_info_req *)msg->data;
	struct ubagg_device *ubagg_dev =
		ubagg_get_device_by_eid(&req->ubva.eid);
	struct ubagg_hash_table *ubagg_seg_ht;
	struct ubagg_seg_hash_node *tmp_seg = NULL;
	struct msg_seg_info_resp resp = { 0 };
	int ret = 0;

	if (ubagg_dev == NULL || ubagg_dev->segment_bitmap == NULL) {
		ubagg_log_err("ubagg_dev->segment_bitmap NULL");
		ret = -1;
		goto send_resp_and_put_device;
	}

	ubagg_seg_ht = &ubagg_dev->ubagg_ht[UBAGG_HT_SEGMENT_HT];
	spin_lock(&ubagg_seg_ht->lock);
	tmp_seg = ubagg_hash_table_lookup_nolock(ubagg_seg_ht, req->token_id,
						 &req->token_id);
	if (tmp_seg == NULL) {
		spin_unlock(&ubagg_seg_ht->lock);
		ubagg_log_err("Failed to find seg.\n");
		ret = -1;
		goto send_resp_and_put_device;
	}

	resp.seg_info = tmp_seg->ex_info;
	spin_unlock(&ubagg_seg_ht->lock);

send_resp_and_put_device:
	resp.result = ret;
	if (send_seg_resp(dev, conn, msg->session_id, &resp) != 0)
		ubagg_log_err("Failed to send seg info resp message.\n");
	if (ubagg_dev != NULL)
		ubagg_put_device(ubagg_dev);
}

static void handle_jetty_req(struct ubcore_device *dev,
			     struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_jetty_info_req *req = (struct msg_jetty_info_req *)msg->data;
	struct ubagg_device *ubagg_dev =
		ubagg_get_device_by_eid(&req->jetty_id.eid);
	struct ubagg_hash_table *ht = NULL;
	struct msg_jetty_info_resp resp = { 0 };
	int ret = 0;

	if (ubagg_dev == NULL || ubagg_dev->segment_bitmap == NULL) {
		ubagg_log_err("ubagg_dev->segment_bitmap NULL");
		ret = -1;
		goto send_resp_and_put_device;
	}

	if (req->is_jfr) {
		struct ubagg_jfr_hash_node *tmp_jfr = NULL;

		ht = &ubagg_dev->ubagg_ht[UBAGG_HT_JFR_HT];
		spin_lock(&ht->lock);
		tmp_jfr = ubagg_hash_table_lookup_nolock(ht, req->jetty_id.id,
							 &req->jetty_id.id);
		if (tmp_jfr == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jfr, jetty_id:%u.\n",
				      req->jetty_id.id);
			ret = -1;
			goto send_resp_and_put_device;
		}

		resp.jetty_info = tmp_jfr->ex_info;
		spin_unlock(&ht->lock);
	} else {
		struct ubagg_jetty_hash_node *tmp_jetty = NULL;

		ht = &ubagg_dev->ubagg_ht[UBAGG_HT_JETTY_HT];
		spin_lock(&ht->lock);
		tmp_jetty = ubagg_hash_table_lookup_nolock(ht, req->jetty_id.id,
							   &req->jetty_id.id);
		if (tmp_jetty == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jetty, jetty_id:%u.\n",
				      req->jetty_id.id);
			ret = -1;
			goto send_resp_and_put_device;
		}

		resp.jetty_info = tmp_jetty->ex_info;
		spin_unlock(&ht->lock);
	}

send_resp_and_put_device:
	resp.result = ret;
	if (send_jetty_resp(dev, conn, msg->session_id, &resp) != 0)
		ubagg_log_err("Failed to send jetty info resp message.\n");
	if (ubagg_dev != NULL)
		ubagg_put_device(ubagg_dev);
}

static void handle_xchg_resp(struct ubcore_device *dev, void *conn,
			     uint32_t session_id, int result, void *data)
{
	struct ubagg_session *session;
	struct session_data_exchange_udata *session_data;

	session = ubagg_session_find(session_id);
	if (!session) {
		ubagg_log_err(
			"Failed to find session %u on handle bonding-seg-info-req",
			session_id);
		return;
	}
	session_data =
		(struct session_data_exchange_udata *)ubagg_session_get_data(
			session);

	if (result != 0) {
		*session_data->result = result;
		ubagg_log_err("Failed to exchange udata, ret: %d.\n", result);
		goto complete_session;
	}

	memcpy(session_data->udata_out, data, session_data->udata_out_size);
	*session_data->result = 0;
	ubagg_log_info("Create response result: %d.\n", result);

complete_session:
	ubagg_session_complete(session);
	ubagg_session_ref_release(session);
}

static void handle_seg_resp(struct ubcore_device *dev,
			    struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_seg_info_resp *resp = (struct msg_seg_info_resp *)msg->data;

	handle_xchg_resp(dev, conn, msg->session_id, resp->result,
			 &resp->seg_info);
}

static void handle_jetty_resp(struct ubcore_device *dev,
			      struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_jetty_info_resp *resp =
		(struct msg_jetty_info_resp *)msg->data;

	handle_xchg_resp(dev, conn, msg->session_id, resp->result,
			 &resp->jetty_info);
}

static const struct ubagg_msg_desc g_connect_msg_descs[] = {
	{
		.type = UBAGG_COMM_MSG_SEG_INFO_REQ,
		.handler = handle_seg_req,
		.expected_len = sizeof(struct msg_seg_info_req),
	},
	{
		.type = UBAGG_COMM_MSG_SEG_INFO_RESP,
		.handler = handle_seg_resp,
		.expected_len = sizeof(struct msg_seg_info_resp),
	},
	{
		.type = UBAGG_COMM_MSG_JETTY_INFO_REQ,
		.handler = handle_jetty_req,
		.expected_len = sizeof(struct msg_jetty_info_req),
	},
	{
		.type = UBAGG_COMM_MSG_JETTY_INFO_RESP,
		.handler = handle_jetty_resp,
		.expected_len = sizeof(struct msg_jetty_info_resp),
	},
};

int ubagg_connect_init(void)
{
	return ubagg_msg_register_handlers(g_connect_msg_descs,
					   ARRAY_SIZE(g_connect_msg_descs));
}

void ubagg_connect_uninit(void)
{
	ubagg_msg_unregister_handlers(g_connect_msg_descs,
				      ARRAY_SIZE(g_connect_msg_descs));
}
