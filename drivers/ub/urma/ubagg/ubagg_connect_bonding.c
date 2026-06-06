// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore connect bonding implementation file
 * Author: Chen Chongyu
 * Create: 2026-05-13
 * Note:
 * History: 2026-05-13: create file
 */

#include <linux/module.h>
#include <ub/urma/ubcore_uapi.h>
#include "ubagg_connect_bonding.h"
#include "ubagg_hash_table.h"
#include "ubagg_ioctl.h"
#include "ubagg_session.h"
#include "ubagg_topo_info.h"
#include "ubagg_log.h"
#include "ubagg_netlink.h"
#include "ubagg_types.h"

#define BONDING_UDATA_BUF_LEN 1928

struct session_data_exchange_udata {
	int *result;
	char *udata_out;
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
	char seg_info[BONDING_UDATA_BUF_LEN];
};

struct msg_jetty_info_resp {
	int result;
	char jetty_info[BONDING_UDATA_BUF_LEN];
};

static int ubagg_get_bonding_ue_idx_from_udata(struct ubcore_udata *udata,
						uint32_t *ue_idx)
{
	unsigned long byte;

	if (!udata || !udata->udrv_data) {
		ubagg_log_err("udata or udrv_data is null.\n");
		return -EINVAL;
	}

	if (!udata->udrv_data->in_addr ||
	    udata->udrv_data->in_len < sizeof(*ue_idx)) {
		ubagg_log_err("invalid udata in_addr or in_len:%u.\n",
			       udata->udrv_data->in_len);
		return -EINVAL;
	}

	byte = copy_from_user(ue_idx,
			      (void __user *)(uintptr_t)udata->udrv_data->in_addr,
			      sizeof(*ue_idx));
	if (byte != 0) {
		ubagg_log_err("failed to copy ue_idx from user, byte:%lu.\n",
			       byte);
		return -EFAULT;
	}

	if (*ue_idx >= IODIE_NUM) {
		ubagg_log_err("invalid ue_idx:%u.\n", *ue_idx);
		return -EINVAL;
	}

	return 0;
}

static struct ubcore_device *ubagg_find_physical_device(struct ubcore_device *agg_dev,
							 uint32_t ue_id)
{
	struct ubagg_topo_node *topo_info;
	union ubcore_eid *primary_eid;
	union ubcore_eid agg_dev_eid;
	int dev_id;
	uint32_t eid_idx;
	bool is_eid_found = false;
	bool is_agg_dev_found = false;

	if (agg_dev == NULL) {
		ubagg_log_err("agg_dev is NULL");
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

	spin_lock(&agg_dev->eid_table.lock);
	for (eid_idx = 0; eid_idx < agg_dev->eid_table.eid_cnt; eid_idx++) {
		if (agg_dev->eid_table.eid_entries[eid_idx].valid) {
			agg_dev_eid = agg_dev->eid_table.eid_entries[eid_idx].eid;
			is_eid_found = true;
			break;
		}
	}
	spin_unlock(&agg_dev->eid_table.lock);
	if (!is_eid_found) {
		ubagg_log_err("Failed to find agg_dev_eid.\n");
		return NULL;
	}

	for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
		if (memcmp((union ubcore_eid *)topo_info->agg_devs[dev_id].agg_eid, &agg_dev_eid,
			sizeof(union ubcore_eid)) == 0) {
			is_agg_dev_found = true;
			break;
		}
	}
	if (!is_agg_dev_found) {
		ubagg_log_err("Failed to find agg_dev.\n");
		return NULL;
	}

	primary_eid = (union ubcore_eid *)topo_info->agg_devs[dev_id].ues[ue_id].primary_eid;

	return ubcore_get_device_by_eid(primary_eid, UBCORE_TRANSPORT_UB);
}

static struct ubcore_device *ubagg_find_bonding_device(union ubcore_eid *eid)
{
	struct ubagg_topo_node *topo_info;
	union ubcore_eid *agg_eid;
	int dev_id, ue_id, port_id;
	bool is_found = false;

	topo_info = get_current_topo_node();
	if (!topo_info) {
		ubagg_log_err("Failed get global topo info");
		return NULL;
	}

	for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
		if (!is_agg_dev_valid(&topo_info->agg_devs[dev_id]))
			continue;

		if (memcmp(eid,
			(union ubcore_eid *)topo_info->agg_devs[dev_id].agg_eid,
			sizeof(union ubcore_eid)) == 0) {
			is_found = true;
			break;
		}

		for (ue_id = 0; ue_id < IODIE_NUM; ue_id++) {
			if (memcmp(eid,
				(union ubcore_eid *)
				topo_info->agg_devs[dev_id].ues[ue_id].primary_eid,
				sizeof(union ubcore_eid)) == 0) {
				is_found = true;
				break;
			}
			for (port_id = 0; port_id < PORT_NUM; port_id++) {
				if (memcmp(eid, (union ubcore_eid *)
					topo_info->agg_devs[dev_id].ues[ue_id].port_eid[port_id],
					sizeof(union ubcore_eid)) == 0) {
					is_found = true;
					break;
				}
			}
		}
	}
	if (!is_found) {
		ubagg_log_err("Failed to find bonding device.\n");
		return NULL;
	}

	agg_eid = (union ubcore_eid *)topo_info->agg_devs[dev_id].agg_eid;
	return ubcore_get_device_by_eid(agg_eid, UBCORE_TRANSPORT_UB);
}

static struct ubagg_session *
create_session_for_exchange_udata(struct ubcore_device *dev,
			int *result, char *udata_out, uint32_t udata_out_size)
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

	session = ubagg_session_create(dev, session_data,
		UBAGG_CONN_MAX_TIMEOUT, NULL, NULL);
	if (!session) {
		ubagg_log_err("Failed to alloc session for exchange seg info");
		kfree(session_data);
		return NULL;
	}

	return session;
}

static int send_seg_info_req(struct ubcore_device *dev, uint32_t session_id,
			     struct msg_seg_info_req *req, uint32_t ue_id)
{
	struct ubcore_comm_msg msg = { 0 };
	union ubcore_eid dest_eid = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_NET_BONDING_SEG_INFO_REQ;
	msg.len = sizeof(struct msg_seg_info_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubagg_get_primary_eid_by_agg_eid(&req->ubva.eid, &dest_eid, ue_id);
	if (ret != 0)
		return ret;

	ubagg_log_info("Send seg info req to " EID_FMT "\n", EID_ARGS(dest_eid));
	ret = ubcore_send_comm_msg_to(dev, &msg, dest_eid);
	if (ret != 0) {
		ubagg_log_err("Failed to send msg.\n");
		return ret;
	}
	return 0;
}

static int send_seg_info_resp(struct ubcore_device *dev, void *conn,
			      uint32_t session_id,
			      struct msg_seg_info_resp *resp)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_NET_BONDING_SEG_INFO_RESP;
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

static int send_jetty_info_req(struct ubcore_device *dev, uint32_t session_id,
			       struct msg_jetty_info_req *req, uint32_t ue_id)
{
	struct ubcore_comm_msg msg = { 0 };
	union ubcore_eid dest_eid = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_NET_BONDING_JETTY_INFO_REQ;
	msg.len = sizeof(struct msg_jetty_info_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubagg_get_primary_eid_by_agg_eid(&req->jetty_id.eid,
						    &dest_eid, ue_id);
	if (ret != 0)
		return ret;

	ubagg_log_info("Send jetty info req to " EID_FMT "\n", EID_ARGS(dest_eid));
	ret = ubcore_send_comm_msg_to(dev, &msg, dest_eid);
	if (ret != 0) {
		ubagg_log_err_rl("Failed to send msg to " EID_FMT"\n", EID_ARGS(dest_eid));
		return ret;
	}
	return 0;
}

static int send_jetty_info_resp(struct ubcore_device *dev, void *conn,
				uint32_t session_id,
				struct msg_jetty_info_resp *resp)
{
	struct ubcore_comm_msg msg = { 0 };
	int ret;

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_NET_BONDING_JETTY_INFO_RESP;
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

int ubagg_connect_exchange_udata_when_import_seg(struct ubcore_seg *seg,
				struct ubcore_udata *udata, struct ubcore_device *dev)
{
	struct ubcore_device *physical_dev;
	struct msg_seg_info_req req = { 0 };
	struct ubagg_session *session;
	char buf[BONDING_UDATA_BUF_LEN];
	uint32_t ue_idx;
	uint64_t start, duration;
	int ret, result = -1;

	start = ktime_get_ns();

	ret = ubagg_get_bonding_ue_idx_from_udata(udata, &ue_idx);
	if (ret != 0)
		return ret;

	physical_dev = ubagg_find_physical_device(dev, ue_idx);
	if (!physical_dev) {
		ubagg_log_err("Failed find physical device");
		return -EINVAL;
	}
	if (udata->udrv_data->out_len > BONDING_UDATA_BUF_LEN) {
		ubagg_log_err("Invalid udata out len:%u\n",
			       udata->udrv_data->out_len);
		ubagg_put_ubcore_device(physical_dev);
		return -EINVAL;
	}

	session = create_session_for_exchange_udata(physical_dev, &result, buf,
						    sizeof(buf));
	if (!session) {
		ret = -ENOMEM;
		goto put_device;
	}

	req.ubva = seg->ubva;
	req.len = seg->len;
	req.token_id = seg->token_id;
	ret = send_seg_info_req(physical_dev, ubagg_session_get_id(session),
				&req, ue_idx);
	if (ret != 0) {
		ubagg_session_complete(session);
		goto release_session;
	}
	ubagg_session_wait(session);

	if (result != 0) {
		ubagg_log_err("Failed to exchange udata, ret: %d.\n", result);
		ret = result;
		goto release_session;
	}

	ret = copy_to_user((void __user *)udata->udrv_data->out_addr, buf,
			   udata->udrv_data->out_len);
	if (ret != 0) {
		ubagg_log_err("Failed to copy to user, ret: %d.\n", ret);
		goto release_session;
	}

	duration = (ktime_get_ns() - start) / UBAGG_NS_TO_MS;
	if (duration > UBAGG_EXC_THRESHOLD_MS)
		ubagg_log_info_rl("[EXC_INFO]exchange_seg_info consumes: %llu.\n",
			duration);

	ubagg_session_ref_release(session);
	ubagg_put_ubcore_device(physical_dev);
	return 0;

release_session:
	ubagg_session_ref_release(session);
put_device:
	ubagg_put_ubcore_device(physical_dev);
	return ret;
}

int ubagg_connect_exchange_udata_when_import_jetty(
	struct ubcore_tjetty_cfg *cfg, struct ubcore_udata *udata, bool is_jfr,
	struct ubcore_device *dev)
{
	struct ubcore_device *physical_dev;
	struct msg_jetty_info_req req = { 0 };
	struct ubagg_session *session;
	char buf[BONDING_UDATA_BUF_LEN];
	uint64_t start, duration;
	uint32_t ue_idx;
	int ret, result = -1;

	start = ktime_get_ns();

	ret = ubagg_get_bonding_ue_idx_from_udata(udata, &ue_idx);
	if (ret != 0)
		return ret;

	physical_dev = ubagg_find_physical_device(dev, ue_idx);
	if (!physical_dev) {
		ubagg_log_err("Failed find physical device");
		return -EINVAL;
	}
	if (udata->udrv_data->out_len > BONDING_UDATA_BUF_LEN) {
		ubagg_log_err("Invalid udata out len:%u\n",
			       udata->udrv_data->out_len);
		ubagg_put_ubcore_device(physical_dev);
		return -EINVAL;
	}

	session = create_session_for_exchange_udata(physical_dev, &result, buf,
						    sizeof(buf));
	if (!session) {
		ret = -ENOMEM;
		goto put_device;
	}

	req.is_jfr = is_jfr;
	req.jetty_id = cfg->id;
	ret = send_jetty_info_req(physical_dev, ubagg_session_get_id(session),
				  &req, ue_idx);
	if (ret != 0) {
		ubagg_session_complete(session);
		goto release_session;
	}
	ubagg_session_wait(session);

	if (result != 0) {
		ubagg_log_err("Failed to exchange udata, ret: %d.\n", result);
		ret = result;
		goto release_session;
	}

	ret = copy_to_user((void __user *)udata->udrv_data->out_addr, buf,
			   udata->udrv_data->out_len);
	if (ret != 0) {
		ubagg_log_err("Failed to copy to user, ret: %d.\n", ret);
		goto release_session;
	}

	duration = (ktime_get_ns() - start) / UBAGG_NS_TO_MS;
	if (duration > UBAGG_EXC_THRESHOLD_MS)
		ubagg_log_info_rl("[EXC_INFO]exchange_jetty_info consumes: %llu.\n",
			duration);

	ubagg_session_ref_release(session);
	ubagg_put_ubcore_device(physical_dev);
	return 0;

release_session:
	ubagg_session_ref_release(session);
put_device:
	ubagg_put_ubcore_device(physical_dev);
	return ret;
}

static void handle_seg_info_req(struct ubcore_device *dev,
				struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_seg_info_req *req = (struct msg_seg_info_req *)msg->data;
	struct ubcore_device *bonding_dev = ubagg_find_bonding_device(&req->ubva.eid);
	struct ubagg_device *ubagg_dev = to_ubagg_dev(bonding_dev);
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

	memcpy(resp.seg_info, tmp_seg->ex_info.slaves, sizeof(tmp_seg->ex_info.slaves));
	spin_unlock(&ubagg_seg_ht->lock);

send_resp_and_put_device:
	resp.result = ret;
	if (send_seg_info_resp(dev, conn, msg->session_id, &resp) != 0)
		ubagg_log_err("Failed to send seg info resp message.\n");
	ubagg_put_ubcore_device(bonding_dev);
}

static void handle_jetty_info_req(struct ubcore_device *dev,
				  struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_jetty_info_req *req = (struct msg_jetty_info_req *)msg->data;
	struct ubcore_device *bonding_dev = ubagg_find_bonding_device(&req->jetty_id.eid);
	struct ubagg_device *ubagg_dev = to_ubagg_dev(bonding_dev);
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
		tmp_jfr = ubagg_hash_table_lookup_nolock(ht, req->jetty_id.id, &req->jetty_id.id);
		if (tmp_jfr == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jfr, jetty_id:%u.\n", req->jetty_id.id);
			ret = -1;
			goto send_resp_and_put_device;
		}

		memcpy(resp.jetty_info, &tmp_jfr->ex_info, sizeof(tmp_jfr->ex_info));
		spin_unlock(&ht->lock);
	} else {
		struct ubagg_jetty_hash_node *tmp_jetty = NULL;

		ht = &ubagg_dev->ubagg_ht[UBAGG_HT_JETTY_HT];
		spin_lock(&ht->lock);
		tmp_jetty = ubagg_hash_table_lookup_nolock(ht, req->jetty_id.id, &req->jetty_id.id);
		if (tmp_jetty == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jetty, jetty_id:%u.\n", req->jetty_id.id);
			ret = -1;
			goto send_resp_and_put_device;
		}

		memcpy(resp.jetty_info, &tmp_jetty->ex_info, sizeof(tmp_jetty->ex_info));
		spin_unlock(&ht->lock);
	}

send_resp_and_put_device:
	resp.result = ret;
	if (send_jetty_info_resp(dev, conn, msg->session_id, &resp) != 0)
		ubagg_log_err("Failed to send jetty info resp message.\n");
	ubagg_put_ubcore_device(bonding_dev);
}

static void handle_exchange_udata_resp(struct ubcore_device *dev, void *conn,
				       uint32_t session_id, int result,
				       void *data)
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

static void handle_seg_info_resp(struct ubcore_device *dev,
				 struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_seg_info_resp *resp = (struct msg_seg_info_resp *)msg->data;

	handle_exchange_udata_resp(dev, conn, msg->session_id, resp->result,
				   resp->seg_info);
}

static void handle_jetty_info_resp(struct ubcore_device *dev,
				   struct ubcore_comm_msg *msg, void *conn)
{
	struct msg_jetty_info_resp *resp =
		(struct msg_jetty_info_resp *)msg->data;

	handle_exchange_udata_resp(dev, conn, msg->session_id, resp->result,
				   &resp->jetty_info);
}

void handle_bonding_msg(struct ubcore_device *dev,
			       struct ubcore_comm_msg *msg, void *conn)
{
	uint16_t expected;

	if (!msg) {
		ubagg_log_err("Invalid param: msg is null");
		return;
	}
	if (msg->version != UBAGG_BONDING_MSG_CUR_VERSION) {
		ubagg_log_err_rl("Unsupported msg version %u, expected %u",
				 msg->version, UBAGG_BONDING_MSG_CUR_VERSION);
		return;
	}

	switch (msg->type) {
	case UBAGG_NET_BONDING_SEG_INFO_REQ:
		expected = sizeof(struct msg_seg_info_req);
		if (msg->len != expected) {
			ubagg_log_err("Invalid param: SEG_INFO_REQ len %u, expected %u",
				       msg->len, expected);
			return;
		}
		handle_seg_info_req(dev, msg, conn);
		break;
	case UBAGG_NET_BONDING_SEG_INFO_RESP:
		expected = sizeof(struct msg_seg_info_resp);
		if (msg->len != expected) {
			ubagg_log_err("Invalid param: SEG_INFO_RESP len %u, expected %u",
				       msg->len, expected);
			return;
		}
		handle_seg_info_resp(dev, msg, conn);
		break;
	case UBAGG_NET_BONDING_JETTY_INFO_REQ:
		expected = sizeof(struct msg_jetty_info_req);
		if (msg->len != expected) {
			ubagg_log_err("Invalid param: JETTY_INFO_REQ len %u, expected %u",
				       msg->len, expected);
			return;
		}
		handle_jetty_info_req(dev, msg, conn);
		break;
	case UBAGG_NET_BONDING_JETTY_INFO_RESP:
		expected = sizeof(struct msg_jetty_info_resp);
		if (msg->len != expected) {
			ubagg_log_err("Invalid param: JETTY_INFO_RESP len %u, expected %u",
				       msg->len, expected);
			return;
		}
		handle_jetty_info_resp(dev, msg, conn);
		break;
	case UBAGG_NET_USER_MSG:
		ubagg_nl_bonding_user_msg_handler(dev, msg, conn);
		break;
	default:
		ubagg_log_err("Unhandled msg type %u in bonding service", msg->type);
	}
}
