// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore connect bonding implementation file
 * Author: Wang Hang
 * Create: 2025-08-07
 * Note:
 * History: 2025-08-07: create file
 */

#include <ub/urma/ubcore_uapi.h>
#include "ubcore_connect_bonding.h"
#include "net/ubcore_protocol.h"
#include "net/ubcore_comm.h"
#include "net/ubcore_session.h"
#include "ubcore_priv.h"
#include "ubcore_topo_info.h"
#include "ubcore_log.h"

#define BONDING_UDATA_BUF_LEN 1800

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

static struct ubcore_device *ubcore_find_physical_device(struct ubcore_device *agg_dev)
{
	struct ubcore_topo_map *topo_map;
	struct ubcore_topo_node *topo_info;
	union ubcore_eid *primary_eid;
	union ubcore_eid agg_dev_eid;
	int dev_id;
	uint32_t eid_idx;
	bool is_eid_found = false;
	bool is_agg_dev_found = false;

	if (agg_dev == NULL) {
		ubcore_log_err("agg_dev is NULL");
		return NULL;
	}
	topo_map = ubcore_get_global_topo_map();
	if (!topo_map) {
		ubcore_log_err("Failed get global topo map");
		return NULL;
	}

	topo_info = ubcore_get_cur_topo_info(topo_map);
	if (!topo_info) {
		ubcore_log_err("Failed get global topo info");
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
		ubcore_log_err("Failed to find agg_dev_eid.\n");
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
		ubcore_log_err("Failed to find agg_dev.\n");
		return NULL;
	}

	primary_eid = (union ubcore_eid *)topo_info->agg_devs[dev_id].ues[0].primary_eid;

	return ubcore_find_device(primary_eid, UBCORE_TRANSPORT_UB);
}

static struct ubcore_device *ubcore_find_bonding_device(union ubcore_eid *eid)
{
	struct ubcore_topo_map *topo_map;
	struct ubcore_topo_node *topo_info;
	union ubcore_eid *agg_eid;
	int dev_id, ue_id, port_id;
	bool is_found = false;

	topo_map = ubcore_get_global_topo_map();
	if (!topo_map) {
		ubcore_log_err("Failed get global topo map");
		return NULL;
	}

	topo_info = ubcore_get_cur_topo_info(topo_map);
	if (!topo_info) {
		ubcore_log_err("Failed get global topo info");
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
		ubcore_log_err("Failed to find bonding device.\n");
		return NULL;
	}

	agg_eid = (union ubcore_eid *)topo_info->agg_devs[dev_id].agg_eid;
	return ubcore_find_device(agg_eid, UBCORE_TRANSPORT_UB);
}

static struct ubcore_session *
create_session_for_exchange_udata(struct ubcore_device *dev,
			int *result, char *udata_out, uint32_t udata_out_size)
{
	struct ubcore_session *session;
	struct session_data_exchange_udata *session_data;

	session_data =
		kzalloc(sizeof(struct session_data_exchange_udata), GFP_KERNEL);
	if (IS_ERR_OR_NULL(session_data)) {
		ubcore_log_err("Failed to alloc exchange seg info user arg");
		return NULL;
	}
	session_data->result = result;
	session_data->udata_out = udata_out;
	session_data->udata_out_size = udata_out_size;

	session = ubcore_session_create(dev, session_data, 0, NULL, NULL);
	if (!session) {
		ubcore_log_err("Failed to alloc session for exchange seg info");
		kfree(session_data);
		return NULL;
	}

	return session;
}

static int send_seg_info_req(struct ubcore_device *dev, uint32_t session_id,
			     struct msg_seg_info_req *req)
{
	struct ubcore_net_msg msg = { 0 };
	union ubcore_eid dest_eid = { 0 };
	int ret;

	msg.type = UBCORE_NET_BONDING_SEG_INFO_REQ;
	msg.len = sizeof(struct msg_seg_info_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubcore_get_primary_eid_by_agg_eid(&req->ubva.eid, &dest_eid);
	if (ret != 0)
		return ret;

	ubcore_log_info("Send seg info req to " EID_FMT ", Send cm messagem: " MSG_FMT "\n",
		EID_ARGS(dest_eid), MSG_ARG(&msg));
	ret = ubcore_net_send_to(dev, &msg, dest_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg.\n");
		return ret;
	}
	return 0;
}

static int send_seg_info_resp(struct ubcore_device *dev, void *conn,
			      uint32_t session_id,
			      struct msg_seg_info_resp *resp)
{
	struct ubcore_net_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_BONDING_SEG_INFO_RESP;
	msg.len = sizeof(struct msg_seg_info_resp);
	msg.session_id = session_id;
	msg.data = resp;

	ret = ubcore_net_send(dev, &msg, conn);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

static int send_jetty_info_req(struct ubcore_device *dev, uint32_t session_id,
			       struct msg_jetty_info_req *req)
{
	struct ubcore_net_msg msg = { 0 };
	union ubcore_eid dest_eid = { 0 };
	int ret;

	msg.type = UBCORE_NET_BONDING_JETTY_INFO_REQ;
	msg.len = sizeof(struct msg_jetty_info_req);
	msg.session_id = session_id;
	msg.data = req;

	ret = ubcore_get_primary_eid_by_agg_eid(&req->jetty_id.eid,
						    &dest_eid);
	if (ret != 0)
		return ret;

	ubcore_log_info("Send jetty info req to " EID_FMT "\n", EID_ARGS(dest_eid));
	ret = ubcore_net_send_to(dev, &msg, dest_eid);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg to " EID_FMT"\n", EID_ARGS(dest_eid));
		return ret;
	}
	return 0;
}

static int send_jetty_info_resp(struct ubcore_device *dev, void *conn,
				uint32_t session_id,
				struct msg_jetty_info_resp *resp)
{
	struct ubcore_net_msg msg = { 0 };
	int ret;

	msg.type = UBCORE_NET_BONDING_JETTY_INFO_RESP;
	msg.len = sizeof(struct msg_jetty_info_resp);
	msg.session_id = session_id;
	msg.data = resp;

	ret = ubcore_net_send(dev, &msg, conn);
	if (ret != 0) {
		ubcore_log_err("Failed to send msg");
		return ret;
	}
	return 0;
}

int ubcore_connect_exchange_udata_when_import_seg(struct ubcore_seg *seg,
				struct ubcore_udata *udata, struct ubcore_device *dev)
{
	struct ubcore_device *physical_dev = ubcore_find_physical_device(dev);
	struct msg_seg_info_req req = { 0 };
	struct ubcore_session *session;
	char buf[BONDING_UDATA_BUF_LEN];
	int ret, result = -1;

	if (!physical_dev) {
		ubcore_log_err("Failed find physical device");
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
	ret = send_seg_info_req(physical_dev, ubcore_session_get_id(session),
				&req);
	if (ret != 0) {
		ubcore_session_complete(session);
		goto release_session;
	}
	ubcore_session_wait(session);

	if (result != 0) {
		ubcore_log_err("Failed to exchange udata, ret: %d.\n", result);
		ret = result;
		goto release_session;
	}

	ret = copy_to_user((void __user *)udata->udrv_data->out_addr, buf,
			   udata->udrv_data->out_len);
	if (ret != 0) {
		ubcore_log_err("Failed to copy to user, ret: %d.\n", ret);
		goto release_session;
	}

	ubcore_session_ref_release(session);
	ubcore_put_device(physical_dev);
	return 0;

release_session:
	ubcore_session_ref_release(session);
put_device:
	ubcore_put_device(physical_dev);
	return ret;
}

int ubcore_connect_exchange_udata_when_import_jetty(
	struct ubcore_tjetty_cfg *cfg, struct ubcore_udata *udata, bool is_jfr,
	struct ubcore_device *dev)
{
	struct ubcore_device *physical_dev = ubcore_find_physical_device(dev);
	struct msg_jetty_info_req req = { 0 };
	struct ubcore_session *session;
	char buf[BONDING_UDATA_BUF_LEN];
	int ret, result = -1;

	if (!physical_dev) {
		ubcore_log_err("Failed find physical device");
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
	ret = send_jetty_info_req(physical_dev, ubcore_session_get_id(session),
				  &req);
	if (ret != 0) {
		ubcore_session_complete(session);
		goto release_session;
	}
	ubcore_session_wait(session);

	if (result != 0) {
		ubcore_log_err("Failed to exchange udata, ret: %d.\n", result);
		ret = result;
		goto release_session;
	}

	ret = copy_to_user((void __user *)udata->udrv_data->out_addr, buf,
			   udata->udrv_data->out_len);
	if (ret != 0) {
		ubcore_log_err("Failed to copy to user, ret: %d.\n", ret);
		goto release_session;
	}

	ubcore_session_ref_release(session);
	ubcore_put_device(physical_dev);
	return 0;

release_session:
	ubcore_session_ref_release(session);
put_device:
	ubcore_put_device(physical_dev);
	return ret;
}

static void handle_seg_info_req(struct ubcore_device *dev,
				struct ubcore_net_msg *msg, void *conn)
{
	struct msg_seg_info_req *req = (struct msg_seg_info_req *)msg->data;
	struct ubcore_device *bonding_dev = ubcore_find_bonding_device(&req->ubva.eid);
	int ret = 0;

	struct msg_seg_info_resp resp = { 0 };
	struct ubcore_user_ctl k_user_ctl = {
		.in.opcode = 5,
		.in.addr = (uint64_t)req,
		.in.len = sizeof(*req),
		.out.addr = (uint64_t)(&resp.seg_info),
		.out.len = sizeof(resp.seg_info),
	};

	ret = ubcore_user_control(bonding_dev, &k_user_ctl);
	if (ret != 0) {
		ubcore_log_err("Failed to get seg info by user ctl");
		goto put_device;
	}

	resp.result = ret;
	if (send_seg_info_resp(dev, conn, msg->session_id, &resp) != 0) {
		ubcore_log_err("Failed to send create resp message.\n");
		goto put_device;
	}

put_device:
	ubcore_put_device(bonding_dev);
}

static void handle_jetty_info_req(struct ubcore_device *dev,
				  struct ubcore_net_msg *msg, void *conn)
{
	struct msg_jetty_info_req *req = (struct msg_jetty_info_req *)msg->data;
	struct ubcore_device *bonding_dev = ubcore_find_bonding_device(&req->jetty_id.eid);
	int ret = 0;

	struct msg_jetty_info_resp resp = { 0 };
	struct ubcore_user_ctl k_user_ctl = {
		.in.opcode = 6,
		.in.addr = (uint64_t)req,
		.in.len = sizeof(*req),
		.out.addr = (uint64_t)(&resp.jetty_info),
		.out.len = sizeof(resp.jetty_info),
	};

	ret = ubcore_user_control(bonding_dev, &k_user_ctl);
	if (ret != 0) {
		ubcore_log_err("Failed to get jetty info by user ctl");
		goto put_device;
	}

	resp.result = ret;
	if (send_jetty_info_resp(dev, conn, msg->session_id, &resp) != 0) {
		ubcore_log_err("Failed to send create resp message.\n");
		goto put_device;
	}

put_device:
	ubcore_put_device(bonding_dev);
}

static void handle_exchange_udata_resp(struct ubcore_device *dev, void *conn,
				       uint32_t session_id, int result,
				       void *data)
{
	struct ubcore_session *session;
	struct session_data_exchange_udata *session_data;

	session = ubcore_session_find(session_id);
	if (!session) {
		ubcore_log_err(
			"Failed to find session %u on handle bonding-seg-info-req",
			session_id);
		return;
	}
	session_data =
		(struct session_data_exchange_udata *)ubcore_session_get_data(
			session);

	if (result != 0) {
		*session_data->result = result;
		ubcore_log_err("Failed to exchange udata, ret: %d.\n", result);
		goto complete_session;
	}

	memcpy(session_data->udata_out, data, session_data->udata_out_size);
	*session_data->result = 0;
	ubcore_log_info("Create response result: %d.\n", result);

complete_session:
	ubcore_session_complete(session);
	ubcore_session_ref_release(session);
}

static void handle_seg_info_resp(struct ubcore_device *dev,
				 struct ubcore_net_msg *msg, void *conn)
{
	struct msg_seg_info_resp *resp = (struct msg_seg_info_resp *)msg->data;

	handle_exchange_udata_resp(dev, conn, msg->session_id, resp->result,
				   resp->seg_info);
}

static void handle_jetty_info_resp(struct ubcore_device *dev,
				   struct ubcore_net_msg *msg, void *conn)
{
	struct msg_jetty_info_resp *resp =
		(struct msg_jetty_info_resp *)msg->data;

	handle_exchange_udata_resp(dev, conn, msg->session_id, resp->result,
				   &resp->jetty_info);
}

void ubcore_connect_bonding_init(void)
{
	ubcore_net_register_msg_handler(UBCORE_NET_BONDING_SEG_INFO_REQ,
					handle_seg_info_req,
					sizeof(struct msg_seg_info_req));
	ubcore_net_register_msg_handler(UBCORE_NET_BONDING_SEG_INFO_RESP,
					handle_seg_info_resp,
					sizeof(struct msg_seg_info_resp));
	ubcore_net_register_msg_handler(UBCORE_NET_BONDING_JETTY_INFO_REQ,
					handle_jetty_info_req,
					sizeof(struct msg_jetty_info_req));
	ubcore_net_register_msg_handler(UBCORE_NET_BONDING_JETTY_INFO_RESP,
					handle_jetty_info_resp,
					sizeof(struct msg_jetty_info_resp));
}
