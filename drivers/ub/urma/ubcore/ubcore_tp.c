// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: ubcore tp implementation
 * Author: Yan Fangfang
 * Create: 2022-08-25
 * Note:
 * History: 2022-08-25: Create file
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include "ubcore_log.h"
#include "ubcore_netlink.h"
#include "ubcore_priv.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_tp_table.h"
#include "ubcore_tp.h"

#define UB_PROTOCOL_HEAD_BYTES 313
#define UB_MTU_BITS_BASE_SHIFT 7

static inline uint32_t get_udrv_in_len(const struct ubcore_udata *udata)
{
	return ((udata == NULL || udata->udrv_data == NULL) ? 0 : udata->udrv_data->in_len);
}

static inline int get_udrv_in_data(uint8_t *dst, uint32_t dst_len, struct ubcore_udata *udata)
{
	if (udata == NULL || udata->udrv_data == NULL || udata->udrv_data->in_len == 0)
		return 0;

	if (udata->uctx != NULL) {
		if (dst_len < udata->udrv_data->in_len)
			return -1;
		return (int)copy_from_user(dst, (void __user *)(uintptr_t)udata->udrv_data->in_addr,
					   udata->udrv_data->in_len);
	} else {
		(void)memcpy(dst, (void *)udata->udrv_data->in_addr, udata->udrv_data->in_len);
		return 0;
	}
}

static inline void ubcore_set_net_addr_with_eid(struct ubcore_net_addr *net_addr,
						const union ubcore_eid *eid)
{
	memset(net_addr, 0, sizeof(struct ubcore_net_addr));
	(void)memcpy(net_addr, eid, UBCORE_EID_SIZE);
}

static inline int ubcore_mtu_enum_to_int(enum ubcore_mtu mtu)
{
	return 1 << ((int)mtu + UB_MTU_BITS_BASE_SHIFT);
}

enum ubcore_mtu ubcore_get_mtu(int mtu)
{
	mtu = mtu - UB_PROTOCOL_HEAD_BYTES;

	if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_8192))
		return UBCORE_MTU_8192;
	if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_4096))
		return UBCORE_MTU_4096;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_2048))
		return UBCORE_MTU_2048;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_1024))
		return UBCORE_MTU_1024;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_512))
		return UBCORE_MTU_512;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_256))
		return UBCORE_MTU_256;
	else
		return 0;
}
EXPORT_SYMBOL(ubcore_get_mtu);

static int ubcore_get_active_mtu(const struct ubcore_device *dev, uint8_t port_num,
				 enum ubcore_mtu *mtu)
{
	struct ubcore_device_status st = { 0 };

	if (port_num >= dev->attr.port_cnt || dev->ops->query_device_status == NULL) {
		ubcore_log_err("Invalid parameter");
		return -1;
	}
	if (dev->ops->query_device_status(dev, &st) != 0) {
		ubcore_log_err("Failed to query query_device_status for port %d", port_num);
		return -1;
	}
	if (st.port_status[port_num].state != UBCORE_PORT_ACTIVE) {
		ubcore_log_err("Port %d is not active", port_num);
		return -1;
	}
	*mtu = st.port_status[port_num].active_mtu;
	return 0;
}

static struct ubcore_nlmsg *ubcore_alloc_nlmsg(size_t payload_len, const union ubcore_eid *src_eid,
					       const union ubcore_eid *dst_eid)
{
	struct ubcore_nlmsg *msg = kzalloc(sizeof(struct ubcore_nlmsg) + payload_len, GFP_KERNEL);

	if (msg == NULL)
		return NULL;

	msg->src_eid = *src_eid;
	msg->dst_eid = *dst_eid;
	msg->payload_len = payload_len;
	return msg;
}

static struct ubcore_nlmsg *ubcore_get_destroy_tp_req(struct ubcore_tp *tp,
						      const struct ubcore_ta_data *ta)
{
	struct ubcore_nl_destroy_tp_req *destroy;
	struct ubcore_nlmsg *req;

	req = ubcore_alloc_nlmsg(sizeof(struct ubcore_nl_destroy_tp_req), &tp->local_eid,
				 &tp->peer_eid);
	if (req == NULL)
		return NULL;

	req->msg_type = UBCORE_NL_DESTROY_TP_REQ;
	req->transport_type = tp->ub_dev->transport_type;
	destroy = (struct ubcore_nl_destroy_tp_req *)req->payload;
	destroy->trans_mode = tp->trans_mode;
	destroy->tpn = tp->tpn;
	destroy->peer_tpn = tp->peer_tpn;
	if (ta != NULL)
		destroy->ta = *ta;
	else
		destroy->ta.type = UBCORE_TA_NONE;

	return req;
}

static int ubcore_init_create_tp_req(struct ubcore_nl_create_tp_req *create, struct ubcore_tp *tp,
				     const struct ubcore_ta_data *ta, struct ubcore_udata *udata)
{
	create->tpn = tp->tpn;
	create->local_net_addr = tp->local_net_addr;
	create->peer_net_addr = tp->peer_net_addr;
	create->trans_mode = tp->trans_mode;
	create->mtu = tp->mtu;
	create->rx_psn = tp->rx_psn;
	create->cfg.flag = tp->flag;
	create->cfg.congestion_alg = tp->ub_dev->attr.dev_cap.congestion_ctrl_alg;

	if (ta != NULL)
		create->ta = *ta;
	else
		create->ta.type = UBCORE_TA_NONE;

	create->ext_len = tp->tp_ext.len;
	create->udrv_in_len = get_udrv_in_len(udata);
	if (tp->tp_ext.len > 0)
		(void)memcpy(create->ext_udrv, (void *)tp->tp_ext.addr, tp->tp_ext.len);

	if (get_udrv_in_data(create->ext_udrv + tp->tp_ext.len, create->udrv_in_len, udata) != 0) {
		ubcore_log_err("Failed to get udrv data");
		return -1;
	}

	return 0;
}

static struct ubcore_nlmsg *ubcore_get_create_tp_req(struct ubcore_tp *tp,
						     struct ubcore_ta_data *ta,
						     struct ubcore_udata *udata)
{
	uint32_t payload_len =
		sizeof(struct ubcore_nl_create_tp_req) + tp->tp_ext.len + get_udrv_in_len(udata);
	struct ubcore_nlmsg *req;

	req = ubcore_alloc_nlmsg(payload_len, &tp->local_eid, &tp->peer_eid);
	if (req == NULL)
		return NULL;

	req->transport_type = tp->ub_dev->transport_type;
	req->msg_type = UBCORE_NL_CREATE_TP_REQ;

	if (ubcore_init_create_tp_req((struct ubcore_nl_create_tp_req *)req->payload, tp, ta,
				      udata) != 0) {
		kfree(req);
		ubcore_log_err("Failed to init create tp req");
		return NULL;
	}
	return req;
}

static int ubcore_set_tp_peer_ext(struct ubcore_tp_attr *attr, const uint8_t *ext_addr,
				  const uint32_t ext_len)
{
	void *peer_ext = NULL;

	if (ext_len == 0 || ext_addr == NULL)
		return 0;

	/* copy resp ext from req or response */
	peer_ext = kzalloc(ext_len, GFP_KERNEL);
	if (peer_ext == NULL)
		return -ENOMEM;

	(void)memcpy(peer_ext, ext_addr, ext_len);

	attr->peer_ext.addr = (uintptr_t)peer_ext;
	attr->peer_ext.len = ext_len;
	return 0;
}

static inline void ubcore_unset_tp_peer_ext(struct ubcore_tp_attr *attr)
{
	if (attr->peer_ext.addr != 0)
		kfree((void *)attr->peer_ext.addr);
}

static int ubcore_negotiate_optimal_cc_alg(uint16_t local_congestion_alg,
					   uint16_t peer_local_congestion_alg)
{
	int i;

	/* TODO Configure congestion control priority based on UVS */
	for (i = 0; i <= UBCORE_TP_CC_DIP; i++) {
		if ((0x1 << (uint32_t)i) & local_congestion_alg & peer_local_congestion_alg)
			return i;
	}
	return -1;
}

static int ubcore_set_initiator_peer(const struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
				     union ubcore_tp_attr_mask *mask,
				     const struct ubcore_nl_create_tp_resp *resp)
{
	mask->value = 0;
	mask->bs.flag = 1;
	mask->bs.peer_tpn = 1;
	mask->bs.mtu = 1;
	mask->bs.tx_psn = 1;
	mask->bs.state = 1;

	memset(attr, 0, sizeof(*attr));
	attr->flag.bs.oor_en = tp->flag.bs.oor_en & resp->flag.bs.oor_en;
	attr->flag.bs.sr_en = tp->flag.bs.sr_en & resp->flag.bs.sr_en;
	attr->flag.bs.spray_en = tp->flag.bs.spray_en & resp->flag.bs.spray_en;
	attr->flag.bs.cc_en = tp->flag.bs.cc_en & resp->flag.bs.cc_en;
	attr->flag.bs.cc_alg = resp->flag.bs.cc_alg; /* negotiated with the remote */
	attr->peer_tpn = resp->peer_tpn;
	attr->mtu = min(tp->mtu, resp->peer_mtu);
	attr->tx_psn = resp->peer_rx_psn;
	attr->state = UBCORE_TP_STATE_RTS;

	if (tp->peer_ext.addr != 0)
		return 0;

	mask->bs.peer_ext = 1;
	return ubcore_set_tp_peer_ext(attr, resp->peer_ext, resp->peer_ext_len);
}

static struct ubcore_nlmsg *ubcore_get_query_tp_req(struct ubcore_device *dev,
						    const union ubcore_eid *remote_eid,
						    enum ubcore_transport_mode trans_mode)
{
	uint32_t payload_len = sizeof(struct ubcore_nl_query_tp_req);
	struct ubcore_nl_query_tp_req *query;
	struct ubcore_nlmsg *req;

	req = ubcore_alloc_nlmsg(payload_len, &dev->attr.eid, remote_eid);
	if (req == NULL)
		return NULL;

	req->transport_type = dev->transport_type;
	req->msg_type = UBCORE_NL_QUERY_TP_REQ;
	query = (struct ubcore_nl_query_tp_req *)req->payload;
	query->trans_mode = trans_mode;
	return req;
}

static int ubcore_query_tp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
			   enum ubcore_transport_mode trans_mode,
			   struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;
	struct ubcore_nl_query_tp_resp *resp;
	int ret = 0;

	req_msg = ubcore_get_query_tp_req(dev, remote_eid, trans_mode);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get query tp req");
		return -1;
	}

	resp_msg = ubcore_nl_send_wait(req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to wait query response");
		kfree(req_msg);
		return -1;
	}

	resp = (struct ubcore_nl_query_tp_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != UBCORE_NL_QUERY_TP_RESP || resp == NULL ||
	    resp->ret != UBCORE_NL_RESP_SUCCESS) {
		ret = -1;
		ubcore_log_err("Query tp request is rejected with type %d ret %d",
			       resp_msg->msg_type, (resp == NULL ? 1 : resp->ret));
	} else {
		(void)memcpy(query_tp_resp, resp, sizeof(struct ubcore_nl_query_tp_resp));
	}
	kfree(resp_msg);
	kfree(req_msg);
	return ret;
}

static void ubcore_get_ta_data_from_ta(const struct ubcore_ta *ta, struct ubcore_ta_data *ta_data)
{
	struct ubcore_jetty *jetty;
	struct ubcore_jfs *jfs;

	ta_data->type = ta->type;
	switch (ta->type) {
	case UBCORE_TA_JFS_TJFR:
		jfs = ta->jfs;
		ta_data->jetty_id.eid = jfs->ub_dev->attr.eid;
		if (jfs->uctx != NULL)
			ta_data->jetty_id.uasid = jfs->uctx->uasid;
		ta_data->jetty_id.id = jfs->id;
		ta_data->tjetty_id = ta->tjetty_id;
		break;
	case UBCORE_TA_JETTY_TJETTY:
		jetty = ta->jetty;
		ta_data->jetty_id.eid = jetty->ub_dev->attr.eid;
		if (jetty->uctx != NULL)
			ta_data->jetty_id.uasid = jetty->uctx->uasid;
		ta_data->jetty_id.id = jetty->id;
		ta_data->tjetty_id = ta->tjetty_id;
		break;
	case UBCORE_TA_NONE:
	case UBCORE_TA_VIRT:
	default:
		return;
	}
}

static struct ubcore_nlmsg *ubcore_exchange_tp(struct ubcore_tp *tp, struct ubcore_ta *ta,
					       struct ubcore_udata *udata)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;

	struct ubcore_nl_create_tp_resp *resp;
	struct ubcore_ta_data ta_data = { 0 };

	if (ta != NULL)
		ubcore_get_ta_data_from_ta(ta, &ta_data);

	req_msg = ubcore_get_create_tp_req(tp, &ta_data, udata);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get create tp req");
		return NULL;
	}

	resp_msg = ubcore_nl_send_wait(req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to wait create_tp response %pI6c", &tp->peer_eid);
		kfree(req_msg);
		return NULL;
	}

	resp = (struct ubcore_nl_create_tp_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != req_msg->msg_type + 1 || resp == NULL ||
	    resp->ret != UBCORE_NL_RESP_SUCCESS) {
		ubcore_log_err("Create tp request is rejected with type %d ret %d",
			       resp_msg->msg_type, (resp == NULL ? 1 : resp->ret));
		kfree(resp_msg);
		resp_msg = NULL;
	}

	kfree(req_msg);
	return resp_msg;
}

int ubcore_destroy_tp(struct ubcore_tp *tp)
{
	if (!ubcore_have_tp_ops(tp->ub_dev)) {
		ubcore_log_err("TP ops is NULL");
		return -1;
	}

	if (tp->peer_ext.len > 0 && tp->peer_ext.addr != 0)
		kfree((void *)tp->peer_ext.addr);

	return tp->ub_dev->ops->destroy_tp(tp);
}
EXPORT_SYMBOL(ubcore_destroy_tp);

static void ubcore_set_tp_flag(union ubcore_tp_flag *flag, const struct ubcore_tp_cfg *cfg,
			       const struct ubcore_device *dev)
{
	flag->bs.target = cfg->flag.bs.target;
	flag->bs.sr_en = cfg->flag.bs.sr_en;
	flag->bs.spray_en = cfg->flag.bs.spray_en;
	flag->bs.oor_en = cfg->flag.bs.oor_en;
	flag->bs.cc_en = cfg->flag.bs.cc_en;
}

static void ubcore_set_tp_init_cfg(struct ubcore_tp *tp, const struct ubcore_tp_cfg *cfg)
{
	ubcore_set_tp_flag(&tp->flag, cfg, tp->ub_dev);
	tp->local_net_addr = cfg->local_net_addr;
	tp->peer_net_addr = cfg->peer_net_addr;
	tp->local_eid = cfg->local_eid;
	tp->peer_eid = cfg->peer_eid;
	tp->trans_mode = cfg->trans_mode;
	tp->rx_psn = cfg->rx_psn;
	tp->tx_psn = 0;
	tp->mtu = cfg->mtu;
	tp->data_udp_start = cfg->data_udp_start;
	tp->ack_udp_start = cfg->ack_udp_start;
	tp->udp_range = cfg->udp_range;
	tp->retry_num = cfg->retry_num;
	tp->ack_timeout = cfg->ack_timeout;
	tp->tc = cfg->tc;
}

static struct ubcore_tp *ubcore_create_tp(struct ubcore_device *dev,
					  const struct ubcore_tp_cfg *cfg,
					  struct ubcore_udata *udata)
{
	struct ubcore_tp *tp = NULL;

	if (!ubcore_have_tp_ops(dev)) {
		ubcore_log_err("Invalid parameter");
		return NULL;
	}

	tp = dev->ops->create_tp(dev, cfg, udata);
	if (tp == NULL) {
		ubcore_log_err("Failed to create tp towards remote eid %pI6c", &cfg->peer_eid);
		return NULL;
	}
	tp->ub_dev = dev;
	ubcore_set_tp_init_cfg(tp, cfg);
	tp->state = UBCORE_TP_STATE_RESET;
	tp->priv = NULL;
	atomic_set(&tp->use_cnt, 1);
	return tp;
}

/* send request to destroy remote peer tp */
static int ubcore_destroy_peer_tp(struct ubcore_tp *tp, struct ubcore_ta *ta)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;
	struct ubcore_nl_destroy_tp_resp *resp;
	struct ubcore_ta_data ta_data = { 0 };
	int ret = 0;

	if (tp == NULL) {
		ubcore_log_err("Invalid parameter");
		return -1;
	}

	if (ta != NULL)
		ubcore_get_ta_data_from_ta(ta, &ta_data);

	req_msg = ubcore_get_destroy_tp_req(tp, &ta_data);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get destroy tp req");
		return -1;
	}

	resp_msg = ubcore_nl_send_wait(req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to get destroy tp response");
		kfree(req_msg);
		return -1;
	}

	resp = (struct ubcore_nl_destroy_tp_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != UBCORE_NL_DESTROY_TP_RESP || resp == NULL ||
	    resp->ret != UBCORE_NL_RESP_SUCCESS) {
		ubcore_log_err("Destroy tp request is rejected with type %d ret %d",
			       resp_msg->msg_type, (resp == NULL ? 1 : resp->ret));
		ret = -1;
	}

	kfree(resp_msg);
	kfree(req_msg);
	return ret;
}

/* Destroy both local tp and remote peer tp */
static int ubcore_destroy_local_peer_tp(struct ubcore_tp *tp, struct ubcore_ta *ta)
{
	struct ubcore_device *dev = tp->ub_dev;
	int ret;

	/* Do not send destroy request to the remote if we are in the VM */
	if (!dev->attr.virtualization) {
		ret = ubcore_destroy_peer_tp(tp, ta);
		if (ret != 0) {
			ubcore_log_err("Failed to destroy peer tp");
			return ret;
		}
	}
	return ubcore_destroy_tp(tp);
}

static void ubcore_abort_tp(struct ubcore_tp *tp, struct ubcore_tp_meta *meta)
{
	struct ubcore_tp *target;

	if (tp == NULL)
		return;

	target = ubcore_find_remove_tp(meta->ht, meta->hash, &meta->key);
	if (target == NULL || target != tp) {
		ubcore_log_warn("TP is not found, already removed or under use\n");
		return;
	}

	(void)ubcore_destroy_tp(tp);
}

/* destroy initiator and peer tp created by ubcore_connect_vtp, called by ubcore_destroy_vtp */
static int ubcore_disconnect_vtp(struct ubcore_tp *tp)
{
	struct ubcore_tp_node *tp_node = tp->priv;
	struct ubcore_device *dev = tp->ub_dev;

	if (atomic_dec_return(&tp->use_cnt) == 0) {
		struct ubcore_ta ta;

		ta.type = UBCORE_TA_VIRT;

		ubcore_remove_tp_node(&dev->ht[UBCORE_HT_TP], tp_node);
		return ubcore_destroy_local_peer_tp(tp, &ta);
	}
	return 0;
}

static void ubcore_set_multipath_tp_cfg(struct ubcore_tp_cfg *cfg,
					enum ubcore_transport_mode trans_mode,
					struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	cfg->flag.bs.sr_en = query_tp_resp->cfg.flag.bs.sr_en;
	cfg->flag.bs.spray_en = query_tp_resp->cfg.flag.bs.spray_en;
	cfg->flag.bs.oor_en = query_tp_resp->cfg.flag.bs.oor_en;
	cfg->flag.bs.cc_en = query_tp_resp->cfg.flag.bs.cc_en;
	cfg->udp_range = query_tp_resp->cfg.tp_range;
	if (trans_mode == UBCORE_TP_RC) {
		cfg->data_udp_start = query_tp_resp->cfg.data_rctp_start;
		cfg->ack_udp_start = query_tp_resp->cfg.ack_rctp_start;
	} else if (trans_mode == UBCORE_TP_RM) {
		cfg->data_udp_start = query_tp_resp->cfg.data_rmtp_start;
		cfg->ack_udp_start = query_tp_resp->cfg.ack_rmtp_start;
	}
}

static int ubcore_set_initiator_tp_cfg(struct ubcore_tp_cfg *cfg, struct ubcore_device *dev,
				       enum ubcore_transport_mode trans_mode,
				       const union ubcore_eid *remote_eid,
				       struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	cfg->flag.value = 0;
	cfg->flag.bs.target = 0;
	cfg->trans_mode = trans_mode;
	cfg->local_eid = dev->attr.eid;

	if (dev->attr.virtualization) {
		cfg->peer_eid = *remote_eid;
		ubcore_set_net_addr_with_eid(&cfg->local_net_addr, &dev->attr.eid);
		ubcore_set_net_addr_with_eid(&cfg->peer_net_addr, remote_eid);
	} else {
		if (dev->netdev == NULL)
			ubcore_log_warn("Could not find netdev.\n");

		cfg->peer_eid = query_tp_resp->dst_eid; /* set eid to be the remote underlay eid */
		cfg->local_net_addr = query_tp_resp->src_addr;
		if (dev->netdev != NULL && dev->netdev->dev_addr != NULL)
			(void)memcpy(cfg->local_net_addr.mac, dev->netdev->dev_addr,
				     dev->netdev->addr_len);
		if (dev->netdev != NULL)
			cfg->local_net_addr.vlan = (uint64_t)dev->netdev->vlan_features;
		cfg->peer_net_addr = query_tp_resp->dst_addr;
		ubcore_set_multipath_tp_cfg(cfg, trans_mode, query_tp_resp);
	}

	/* set mtu to active mtu temperately */
	if (ubcore_get_active_mtu(dev, 0, &cfg->mtu) != 0) {
		ubcore_log_err("Failed to get active mtu");
		return -1;
	}
	/* set psn to 0 temperately */
	cfg->rx_psn = 0;
	return 0;
}

static int ubcore_query_initiator_tp_cfg(struct ubcore_tp_cfg *cfg, struct ubcore_device *dev,
					 const union ubcore_eid *remote_eid,
					 enum ubcore_transport_mode trans_mode)
{
	struct ubcore_nl_query_tp_resp query_tp_resp;

	/* Do not query tp as TPS is not running on VM */
	if (dev->attr.virtualization)
		return ubcore_set_initiator_tp_cfg(cfg, dev, trans_mode, remote_eid, NULL);

	if (ubcore_query_tp(dev, remote_eid, trans_mode, &query_tp_resp) != 0) {
		ubcore_log_err("Failed to query tp");
		return -1;
	}
	return ubcore_set_initiator_tp_cfg(cfg, dev, trans_mode, NULL, &query_tp_resp);
}

static int ubcore_modify_tp_to_rts(const struct ubcore_device *dev, struct ubcore_tp *tp)
{
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;

	mask.value = 0;
	mask.bs.state = 1;
	attr.state = UBCORE_TP_STATE_RTS;

	if (dev->ops->modify_tp(tp, &attr, mask) != 0) {
		/* tp->peer_ext.addr will be freed when called ubcore_destroy_tp */
		ubcore_log_err("Failed to modify tp");
		return -1;
	}
	tp->state = UBCORE_TP_STATE_RTS;
	return 0;
}

#define ubcore_mod_tp_attr_with_mask(tp, attr, field, mask)	\
	(tp->field = mask.bs.field ? attr->field : tp->field)

static void ubcore_modify_tp_attr(struct ubcore_tp *tp, const struct ubcore_tp_attr *attr,
				  union ubcore_tp_attr_mask mask)
{
	/* flag and mod flag must have the same layout */
	if (mask.bs.flag)
		tp->flag.value = tp->flag.bs.target | (attr->flag.value << 1);

	ubcore_mod_tp_attr_with_mask(tp, attr, peer_tpn, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, state, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, tx_psn, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, rx_psn, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, mtu, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, cc_pattern_idx, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, peer_ext, mask);
}

static int ubcore_enable_tp(const struct ubcore_device *dev, struct ubcore_tp_node *tp_node,
			    struct ubcore_ta *ta, struct ubcore_udata *udata)
{
	struct ubcore_tp *tp = tp_node->tp;
	struct ubcore_nlmsg *resp_msg;
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;
	int ret;

	/* Do not exchange tp with remote in the VM */
	if (dev->attr.virtualization)
		return 0;

	mutex_lock(&tp_node->lock);
	if (tp->state == UBCORE_TP_STATE_RTR) {
		ret = ubcore_modify_tp_to_rts(dev, tp);
		mutex_unlock(&tp_node->lock);
		return ret;
	}
	mutex_unlock(&tp_node->lock);

	/* send request to connection agent and set peer cfg and peer ext from response */
	resp_msg = ubcore_exchange_tp(tp, ta, udata);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to exchange tp info");
		return -1;
	}

	mutex_lock(&tp_node->lock);
	if (tp->state == UBCORE_TP_STATE_RTS) {
		mutex_unlock(&tp_node->lock);
		kfree(resp_msg);
		ubcore_log_info("TP %u is already at RTS", tp->tpn);
		return 0;
	}

	ret = ubcore_set_initiator_peer(
		tp, &attr, &mask,
		(const struct ubcore_nl_create_tp_resp *)(void *)resp_msg->payload);

	/* Here we can free resp msg after use */
	kfree(resp_msg);

	if (ret != 0) {
		mutex_unlock(&tp_node->lock);
		(void)ubcore_destroy_peer_tp(tp, ta);
		ubcore_unset_tp_peer_ext(&attr);
		ubcore_log_err("Failed to set initiator peer");
		return -1;
	}

	ret = dev->ops->modify_tp(tp, &attr, mask);
	if (ret != 0) {
		mutex_unlock(&tp_node->lock);
		(void)ubcore_destroy_peer_tp(tp, ta);
		ubcore_unset_tp_peer_ext(&attr);
		ubcore_log_err("Failed to modify tp");
		return -1;
	}
	ubcore_modify_tp_attr(tp, &attr, mask);
	mutex_unlock(&tp_node->lock);
	return 0;
}

/* create vtp and connect to a remote vtp peer, called by ubcore_create_vtp */
static struct ubcore_tp *ubcore_connect_vtp(struct ubcore_device *dev,
					    const union ubcore_eid *remote_eid,
					    enum ubcore_transport_mode trans_mode,
					    struct ubcore_udata *udata)
{
	struct ubcore_tp_cfg cfg = { 0 };
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp *tp = NULL;
	struct ubcore_ta ta;

	if (ubcore_query_initiator_tp_cfg(&cfg, dev, remote_eid, trans_mode) != 0) {
		ubcore_log_err("Failed to init tp cfg");
		return NULL;
	}

	tp = ubcore_create_tp(dev, &cfg, udata);
	if (tp == NULL) {
		ubcore_log_err("Failed to create tp");
		return NULL;
	}

	tp_node = ubcore_add_tp_with_tpn(dev, tp);
	if (tp_node == NULL) {
		(void)ubcore_destroy_tp(tp);
		ubcore_log_err("Failed to add vtp");
		return NULL;
	}

	ta.type = UBCORE_TA_VIRT;
	/* send request to connection agent and set peer cfg and peer ext from response */
	if (ubcore_enable_tp(dev, tp_node, &ta, udata) != 0) {
		ubcore_remove_tp_node(&dev->ht[UBCORE_HT_TP], tp_node);
		(void)ubcore_destroy_tp(tp);
		ubcore_log_err("Failed to enable tp");
		return NULL;
	}
	return tp;
}

static int ubcore_set_target_peer(const struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
				  union ubcore_tp_attr_mask *mask,
				  const struct ubcore_nl_create_tp_req *create)
{
	int ret;

	mask->value = 0;
	mask->bs.peer_tpn = 1;
	mask->bs.mtu = 1;
	mask->bs.tx_psn = 1;
	mask->bs.state = 1;
	mask->bs.flag = 1;

	memset(attr, 0, sizeof(*attr));
	attr->peer_tpn = create->tpn;
	attr->mtu = min(tp->mtu, create->mtu);
	attr->tx_psn = create->rx_psn;
	attr->state = UBCORE_TP_STATE_RTR;

	/* Negotiate local and remote optimal algorithms */
	ret = ubcore_negotiate_optimal_cc_alg(tp->ub_dev->attr.dev_cap.congestion_ctrl_alg,
					      create->cfg.congestion_alg);
	if (ret == -1) {
		ubcore_log_err("No congestion control algorithm available");
		return -1;
	}
	attr->flag.value = tp->flag.value >> 1;
	attr->flag.bs.cc_alg = (enum ubcore_tp_cc_alg)ret;

	if (tp->peer_ext.addr != 0)
		return 0;

	mask->bs.peer_ext = 1;
	return ubcore_set_tp_peer_ext(attr, create->ext_udrv, create->ext_len);
}

static struct ubcore_nlmsg *ubcore_get_destroy_tp_response(enum ubcore_nl_resp_status ret,
							   struct ubcore_nlmsg *req)
{
	struct ubcore_nl_destroy_tp_resp *destroy_resp;
	struct ubcore_nlmsg *resp = NULL;

	resp = ubcore_alloc_nlmsg(sizeof(struct ubcore_nl_destroy_tp_resp), &req->dst_eid,
				  &req->src_eid);
	if (resp == NULL) {
		ubcore_log_err("Failed to alloc destroy tp response");
		return NULL;
	}

	resp->msg_type = UBCORE_NL_DESTROY_TP_RESP;
	resp->nlmsg_seq = req->nlmsg_seq;
	resp->transport_type = req->transport_type;
	destroy_resp = (struct ubcore_nl_destroy_tp_resp *)resp->payload;
	destroy_resp->ret = ret;

	return resp;
}

static struct ubcore_nlmsg *ubcore_get_create_tp_response(struct ubcore_tp *tp,
							  struct ubcore_nlmsg *req)
{
	uint32_t payload_len =
		sizeof(struct ubcore_nl_create_tp_resp) + (tp == NULL ? 0 : tp->tp_ext.len);
	struct ubcore_nl_create_tp_resp *create_resp;
	struct ubcore_nlmsg *resp = NULL;

	resp = ubcore_alloc_nlmsg(payload_len, &req->dst_eid, &req->src_eid);
	if (resp == NULL) {
		ubcore_log_err("Failed to alloc create tp response");
		return NULL;
	}

	resp->msg_type = req->msg_type + 1;
	resp->nlmsg_seq = req->nlmsg_seq;
	resp->transport_type = req->transport_type;
	create_resp = (struct ubcore_nl_create_tp_resp *)resp->payload;
	if (tp == NULL) {
		create_resp->ret = UBCORE_NL_RESP_FAIL;
		return resp;
	}

	create_resp->ret = UBCORE_NL_RESP_SUCCESS;
	create_resp->flag = tp->flag;
	create_resp->peer_tpn = tp->tpn;
	create_resp->peer_mtu = tp->mtu;
	create_resp->peer_rx_psn = tp->rx_psn;
	create_resp->peer_ext_len = tp->tp_ext.len;
	if (tp->tp_ext.len > 0)
		(void)memcpy(create_resp->peer_ext, (void *)tp->tp_ext.addr, tp->tp_ext.len);

	return resp;
}

static void ubcore_set_multipath_target_tp_cfg(struct ubcore_tp_cfg *cfg,
					       enum ubcore_transport_mode trans_mode,
					       const struct ubcore_multipath_tp_cfg *tp_cfg)
{
	cfg->flag.bs.sr_en = tp_cfg->flag.bs.sr_en;
	cfg->flag.bs.oor_en = tp_cfg->flag.bs.oor_en;
	cfg->flag.bs.spray_en = tp_cfg->flag.bs.spray_en;
	cfg->flag.bs.cc_en = tp_cfg->flag.bs.cc_en;
	cfg->udp_range = tp_cfg->tp_range;
	if (trans_mode == UBCORE_TP_RC) {
		cfg->data_udp_start = tp_cfg->data_rctp_start;
		cfg->ack_udp_start = tp_cfg->ack_rctp_start;
	} else if (trans_mode == UBCORE_TP_RM) {
		cfg->data_udp_start = tp_cfg->data_rmtp_start;
		cfg->ack_udp_start = tp_cfg->ack_rmtp_start;
	}
}

static int ubcore_set_target_tp_cfg(struct ubcore_tp_cfg *cfg, const struct ubcore_device *dev,
				    struct ubcore_nlmsg *req, struct ubcore_ta *ta)
{
	struct ubcore_nl_create_tp_req *create =
		(struct ubcore_nl_create_tp_req *)(void *)req->payload;

	/* set ubcore_ta */
	cfg->ta = ta;
	ubcore_set_multipath_target_tp_cfg(cfg, create->trans_mode, &create->cfg);
	cfg->flag.bs.target = !create->cfg.flag.bs.target;
	cfg->trans_mode = create->trans_mode;
	cfg->local_eid = dev->attr.eid; /* or req->dst_eid */
	cfg->peer_eid = req->src_eid;

	if (dev->netdev == NULL)
		ubcore_log_warn("Could not find netdev.\n");

	cfg->local_net_addr = create->peer_net_addr;
	if (dev->netdev != NULL && dev->netdev->dev_addr != NULL)
		(void)memcpy(cfg->local_net_addr.mac, dev->netdev->dev_addr, dev->netdev->addr_len);
	if (dev->netdev != NULL)
		cfg->local_net_addr.vlan = (uint64_t)dev->netdev->vlan_features;
	cfg->peer_net_addr = create->local_net_addr;

	/* set mtu to active mtu temperately */
	if (ubcore_get_active_mtu(dev, 0, &cfg->mtu) != 0) {
		ubcore_log_err("Failed to get active mtu");
		return -1;
	}
	cfg->mtu = min(cfg->mtu, create->mtu);
	/* set psn to 0 temperately */
	cfg->rx_psn = 0;
	/* todonext: set cc */
	return 0;
}

static struct ubcore_tp *ubcore_create_target_tp(struct ubcore_device *dev,
						 struct ubcore_nlmsg *req, struct ubcore_ta *ta)
{
	struct ubcore_nl_create_tp_req *create =
		(struct ubcore_nl_create_tp_req *)(void *)req->payload;
	/* create tp parameters */
	struct ubcore_udrv_priv udrv_data = { .in_addr = (uintptr_t)(create->ext_udrv +
								    create->ext_len),
					      .in_len = create->udrv_in_len,
					      .out_addr = 0,
					      .out_len = 0 };
	struct ubcore_udata udata = { .uctx = NULL, .udrv_data = &udrv_data };
	struct ubcore_tp_cfg cfg = { 0 };
	struct ubcore_tp *tp = NULL;

	if (ubcore_set_target_tp_cfg(&cfg, dev, req, ta) != 0) {
		ubcore_log_err("Failed to init tp cfg in create target tp.\n");
		return NULL;
	}

	tp = ubcore_create_tp(dev, &cfg, &udata);
	if (tp == NULL) {
		ubcore_log_err("Failed to create tp in create target tp.\n");
		return NULL;
	}

	return tp;
}

static int ubcore_modify_target_tp(const struct ubcore_device *dev, struct ubcore_tp_node *tp_node,
				   const struct ubcore_nl_create_tp_req *create)
{
	struct ubcore_tp *tp = tp_node->tp;
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;
	int ret = 0;

	mutex_lock(&tp_node->lock);

	switch (tp->state) {
	case UBCORE_TP_STATE_RTS:
		ubcore_log_info("Reuse existing tp with tpn %u", tp->tpn);
		break;
	case UBCORE_TP_STATE_RESET:
		/* Modify target tp to RTR */
		if (ubcore_set_target_peer(tp, &attr, &mask, create) != 0) {
			ubcore_log_err("Failed to set target peer");
			ret = -1;
			break;
		}
		if (dev->ops->modify_tp(tp, &attr, mask) != 0) {
			ubcore_unset_tp_peer_ext(&attr);
			ubcore_log_err("Failed to modify tp");
			ret = -1;
			break;
		}
		ubcore_modify_tp_attr(tp, &attr, mask);
		fallthrough;
	case UBCORE_TP_STATE_RTR:
		/* For RC target TP: modify to RTR only, to RTS when call bind_jetty;
		 * For IB RM target TP: modify to RTR only, to RTS when call advise_jetty
		 */
		if (tp->trans_mode == UBCORE_TP_RC || (dev->transport_type == UBCORE_TRANSPORT_IB))
			break;

		/* TRANSPORT_UB: modify target tp to RTS when receive ACK from intiator,
		 * currently, modify target tp to RTS immediately after target tp is modified to RTR
		 */
		ret = ubcore_modify_tp_to_rts(dev, tp);
		break;
	case UBCORE_TP_STATE_ERROR:
	default:
		ret = -1;
		break;
	}

	mutex_unlock(&tp_node->lock);
	return ret;
}

static struct ubcore_tp *ubcore_accept_target_tp(struct ubcore_device *dev,
						 struct ubcore_nlmsg *req,
						 struct ubcore_tp_advice *advice)
{
	struct ubcore_nl_create_tp_req *create =
		(struct ubcore_nl_create_tp_req *)(void *)req->payload;
	struct ubcore_tp_meta *meta = &advice->meta;
	struct ubcore_tp *new_tp = NULL; /* new created target tp */
	struct ubcore_tp_node *tp_node;

	tp_node = ubcore_hash_table_lookup(meta->ht, meta->hash, &meta->key);
	if (tp_node == NULL) {
		new_tp = ubcore_create_target_tp(dev, req, &advice->ta);
		if (new_tp == NULL) {
			ubcore_log_err("Failed to create target tp towards remote eid %pI6c",
				       &req->src_eid);
			return NULL;
		}
		tp_node = ubcore_add_tp_node(meta->ht, meta->hash, &meta->key, new_tp, &advice->ta);
		if (tp_node == NULL) {
			(void)ubcore_destroy_tp(new_tp);
			ubcore_log_err(
				"Failed to add target tp towards remote eid %pI6c to the tp table",
				&req->src_eid);
			return NULL;
		}
		if (tp_node->tp != new_tp) {
			(void)ubcore_destroy_tp(new_tp);
			new_tp = NULL;
		}
	}

	if (ubcore_modify_target_tp(dev, tp_node, create) != 0) {
		ubcore_abort_tp(new_tp, meta);
		ubcore_log_err("Failed to modify tp");
		return NULL;
	}
	return tp_node->tp;
}

static int ubcore_parse_ta(struct ubcore_device *dev, struct ubcore_ta_data *ta_data,
			   struct ubcore_tp_advice *advice)
{
	struct ubcore_tp_meta *meta;
	struct ubcore_jetty *jetty;
	struct ubcore_jfr *jfr;

	(void)memset(advice, 0, sizeof(struct ubcore_tp_advice));
	meta = &advice->meta;
	advice->ta.type = ta_data->type;

	switch (ta_data->type) {
	case UBCORE_TA_JFS_TJFR:
		jfr = ubcore_find_jfr(dev, ta_data->tjetty_id.id);
		if (jfr != NULL) {
			meta->ht = ubcore_get_tptable(jfr->tptable);
			advice->ta.jfr = jfr;
			advice->ta.tjetty_id = ta_data->jetty_id;
		}
		break;
	case UBCORE_TA_JETTY_TJETTY:
		/* todonext: add kref to jetty, as it may be destroyed any time */
		jetty = ubcore_find_jetty(dev, ta_data->tjetty_id.id);
		if (jetty != NULL) {
			if (jetty->jetty_cfg.trans_mode == UBCORE_TP_RC &&
			    jetty->remote_jetty != NULL &&
			    memcmp(&jetty->remote_jetty->cfg.id, &ta_data->jetty_id,
				   sizeof(struct ubcore_jetty_id))) {
				ubcore_log_err(
					"the same jetty is binded with another remote jetty.\n");
				return -1;
			}
			meta->ht = ubcore_get_tptable(jetty->tptable);
			advice->ta.jetty = jetty;
			advice->ta.tjetty_id = ta_data->jetty_id;
		}
		break;
	case UBCORE_TA_NONE:
	case UBCORE_TA_VIRT:
	default:
		return -1;
	}
	ubcore_init_tp_key_jetty_id(&meta->key, &ta_data->jetty_id);

	/* jetty and jfs should be indexed consecutively */
	meta->hash = ubcore_get_jetty_hash(&ta_data->jetty_id);
	return 0;
}

static struct ubcore_tp *ubcore_advise_target_tp(struct ubcore_device *dev,
						 struct ubcore_nlmsg *req)
{
	struct ubcore_nl_create_tp_req *create =
		(struct ubcore_nl_create_tp_req *)(void *)req->payload;
	struct ubcore_tp_advice advice;
	struct ubcore_tp_meta *meta;
	struct ubcore_tp *tp;

	meta = &advice.meta;
	if (ubcore_parse_ta(dev, &create->ta, &advice) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", create->ta.type);
		return NULL;
	} else if (meta->ht == NULL) {
		ubcore_log_err("tp table is already released");
		return NULL;
	}

	tp = ubcore_accept_target_tp(dev, req, &advice);
	/* pair with get_tptable in parse_ta */
	ubcore_put_tptable(meta->ht);
	return tp;
}

static struct ubcore_tp *ubcore_accept_target_vtp(struct ubcore_device *dev,
						  struct ubcore_nlmsg *req)
{
	struct ubcore_nl_create_tp_req *create =
		(struct ubcore_nl_create_tp_req *)(void *)req->payload;
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp *tp = NULL;

	tp = ubcore_create_target_tp(dev, req, NULL);
	if (tp == NULL) {
		ubcore_log_err("Failed to create tp");
		return NULL;
	}

	tp_node = ubcore_add_tp_with_tpn(dev, tp);
	if (tp_node == NULL) {
		ubcore_log_err("Failed to add tp to the tp table in the device");
		goto destroy_tp;
	}

	if (ubcore_modify_target_tp(dev, tp_node, create) != 0) {
		ubcore_log_err("Failed to modify tp");
		goto remove_tp_node;
	}

	return tp;

remove_tp_node:
	ubcore_remove_tp_node(&dev->ht[UBCORE_HT_TP], tp_node);
destroy_tp:
	(void)ubcore_destroy_tp(tp);
	return NULL;
}

static struct ubcore_tp *ubcore_bind_target_tp(struct ubcore_device *dev, struct ubcore_nlmsg *req)
{
	return ubcore_advise_target_tp(dev, req);
}

struct ubcore_nlmsg *ubcore_handle_create_tp_req(struct ubcore_nlmsg *req)
{
	struct ubcore_nl_create_tp_req *create =
		(struct ubcore_nl_create_tp_req *)(void *)req->payload;
	struct ubcore_tp *tp = NULL;
	struct ubcore_device *dev;

	if (req->payload_len < sizeof(struct ubcore_nl_create_tp_req)) {
		ubcore_log_err("Invalid create req");
		return NULL;
	}

	dev = ubcore_find_device(&req->dst_eid, req->transport_type);
	if (dev == NULL || !ubcore_have_tp_ops(dev)) {
		if (dev != NULL)
			ubcore_put_device(dev);
		ubcore_log_err("Failed to find device or device ops invalid");
		return ubcore_get_create_tp_response(NULL, req);
	}

	if (create->ta.type == UBCORE_TA_VIRT) {
		tp = ubcore_accept_target_vtp(dev, req);
	} else if (create->trans_mode == UBCORE_TP_RC) {
		tp = ubcore_bind_target_tp(dev, req);
	} else if (create->trans_mode == UBCORE_TP_RM &&
		   dev->transport_type == UBCORE_TRANSPORT_IB) {
		tp = ubcore_advise_target_tp(dev, req);
	}

	if (tp == NULL)
		ubcore_log_err("Failed to create target tp towards remote eid %pI6c",
			       &req->src_eid);

	ubcore_put_device(dev);
	return ubcore_get_create_tp_response(tp, req);
}
EXPORT_SYMBOL(ubcore_handle_create_tp_req);

/* destroy target vtp created by ubcore_accept_target_vtp */
static int ubcore_unaccept_target_vtp(struct ubcore_device *dev,
				      struct ubcore_nl_destroy_tp_req *destroy)
{
	struct ubcore_tp *tp = ubcore_remove_tp_with_tpn(dev, destroy->peer_tpn);

	if (tp == NULL) {
		ubcore_log_warn("tp is not found or already destroyed %u", destroy->peer_tpn);
		return 0;
	}
	return ubcore_destroy_tp(tp);
}

/* destroy target RM tp created by ubcore_advise_target_tp */
static int ubcore_unadvise_target_tp(struct ubcore_device *dev,
				     struct ubcore_nl_destroy_tp_req *destroy)
{
	struct ubcore_tp_advice advice;
	struct ubcore_tp_meta *meta;
	struct ubcore_tp *tp = NULL;

	meta = &advice.meta;
	if (ubcore_parse_ta(dev, &destroy->ta, &advice) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", destroy->ta.type);
		return -1;
	} else if (meta->ht == NULL) {
		ubcore_log_warn("tp table is already released");
		return 0;
	}

	tp = ubcore_find_remove_tp(meta->ht, meta->hash, &meta->key);
	/* pair with get_tptable in parse_ta */
	ubcore_put_tptable(meta->ht);
	if (tp == NULL) {
		ubcore_log_warn("tp is not found, already destroyed or under use %u",
				destroy->peer_tpn);
		return 0;
	}

	return ubcore_destroy_tp(tp);
}

/* destroy target RC tp created by ubcore_bind_target_tp */
static int ubcore_unbind_target_tp(struct ubcore_device *dev,
				   struct ubcore_nl_destroy_tp_req *destroy)
{
	return ubcore_unadvise_target_tp(dev, destroy);
}

struct ubcore_nlmsg *ubcore_handle_destroy_tp_req(struct ubcore_nlmsg *req)
{
	struct ubcore_nl_destroy_tp_req *destroy =
		(struct ubcore_nl_destroy_tp_req *)(void *)req->payload;
	struct ubcore_device *dev;
	int ret = -1;

	if (req->payload_len != sizeof(struct ubcore_nl_destroy_tp_req)) {
		ubcore_log_err("Invalid destroy req");
		return NULL;
	}

	dev = ubcore_find_device(&req->dst_eid, req->transport_type);
	if (dev == NULL || !ubcore_have_tp_ops(dev)) {
		if (dev != NULL)
			ubcore_put_device(dev);
		ubcore_log_err("Failed to find device or device ops invalid");
		return ubcore_get_destroy_tp_response(UBCORE_NL_RESP_FAIL, req);
	}

	if (destroy->ta.type == UBCORE_TA_VIRT) {
		ret = ubcore_unaccept_target_vtp(dev, destroy);
	} else if (destroy->trans_mode == UBCORE_TP_RC) {
		ret = ubcore_unbind_target_tp(dev, destroy);
	} else if (destroy->trans_mode == UBCORE_TP_RM &&
		   dev->transport_type == UBCORE_TRANSPORT_IB) {
		ret = ubcore_unadvise_target_tp(dev, destroy);
	}
	ubcore_put_device(dev);
	return ubcore_get_destroy_tp_response((enum ubcore_nl_resp_status)ret, req);
}
EXPORT_SYMBOL(ubcore_handle_destroy_tp_req);

struct ubcore_tp *ubcore_create_vtp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
				    enum ubcore_transport_mode trans_mode,
				    struct ubcore_udata *udata)
{
	if (dev == NULL || dev->attr.virtualization || remote_eid == NULL ||
	    !ubcore_have_tp_ops(dev)) {
		ubcore_log_err("Invalid parameter");
		return NULL;
	}

	switch (dev->transport_type) {
	case UBCORE_TRANSPORT_IB: /* alpha */
		if (trans_mode == UBCORE_TP_RM || trans_mode == UBCORE_TP_RC)
			return ubcore_connect_vtp(dev, remote_eid, trans_mode, udata);
		break;
	case UBCORE_TRANSPORT_UB: /* beta */
	case UBCORE_TRANSPORT_IP:
	case UBCORE_TRANSPORT_INVALID:
	case UBCORE_TRANSPORT_MAX:
	default:
		break;
	}
	return NULL;
}
EXPORT_SYMBOL(ubcore_create_vtp);

int ubcore_destroy_vtp(struct ubcore_tp *vtp)
{
	enum ubcore_transport_mode trans_mode;
	struct ubcore_device *dev;

	if (vtp == NULL || vtp->ub_dev == NULL || vtp->priv == NULL ||
	    vtp->ub_dev->attr.virtualization) {
		ubcore_log_err("Invalid para");
		return -1;
	}
	dev = vtp->ub_dev;
	trans_mode = vtp->trans_mode;
	switch (dev->transport_type) {
	case UBCORE_TRANSPORT_IB: /* alpha */
		if (trans_mode == UBCORE_TP_RM || trans_mode == UBCORE_TP_RC)
			return ubcore_disconnect_vtp(vtp);
		break;
	case UBCORE_TRANSPORT_UB: /* beta */
	case UBCORE_TRANSPORT_IP:
	case UBCORE_TRANSPORT_INVALID:
	case UBCORE_TRANSPORT_MAX:
	default:
		break;
	}
	return -1;
}
EXPORT_SYMBOL(ubcore_destroy_vtp);

static inline void ubcore_set_ta_for_tp_cfg(struct ubcore_device *dev, struct ubcore_ta *ta,
					    struct ubcore_tp_cfg *cfg)
{
	if (dev->transport_type == UBCORE_TRANSPORT_IB)
		cfg->ta = ta;
	else
		cfg->ta = NULL;
}

int ubcore_bind_tp(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
		   struct ubcore_tp_advice *advice, struct ubcore_udata *udata)
{
	struct ubcore_device *dev = jetty->ub_dev;
	struct ubcore_tp_cfg cfg = { 0 };
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp *new_tp = NULL;

	if (ubcore_query_initiator_tp_cfg(&cfg, dev, (union ubcore_eid *)&tjetty->cfg.id.eid,
					  tjetty->cfg.trans_mode) != 0) {
		ubcore_log_err("Failed to init tp cfg.\n");
		return -1;
	}

	mutex_lock(&tjetty->lock);
	if (tjetty->tp != NULL) {
		mutex_unlock(&tjetty->lock);
		ubcore_log_err("The same tjetty, different jetty, prevent duplicate bind.\n");
		return -1;
	}

	ubcore_set_ta_for_tp_cfg(dev, &advice->ta, &cfg);

	/* driver gurantee to return the same tp if we have created it as a target */
	new_tp = ubcore_create_tp(dev, &cfg, udata);
	if (new_tp == NULL) {
		ubcore_log_err("Failed to create tp.\n");
		mutex_unlock(&tjetty->lock);
		return -1;
	}

	tp_node = ubcore_add_tp_node(advice->meta.ht, advice->meta.hash, &advice->meta.key, new_tp,
				     &advice->ta);
	if (tp_node == NULL) {
		(void)ubcore_destroy_tp(new_tp);
		mutex_unlock(&tjetty->lock);
		ubcore_log_err("Failed to find and add tp\n");
		return -1;
	} else if (tp_node != NULL && tp_node->tp != new_tp) {
		(void)ubcore_destroy_tp(new_tp);
		new_tp = NULL;
	}
	tjetty->tp = tp_node->tp;
	mutex_unlock(&tjetty->lock);

	/* send request to connection agent and set peer cfg and peer ext from response */
	if (ubcore_enable_tp(dev, tp_node, &advice->ta, udata) != 0) {
		mutex_lock(&tjetty->lock);
		tjetty->tp = NULL;
		mutex_unlock(&tjetty->lock);
		ubcore_abort_tp(new_tp, &advice->meta);
		ubcore_log_err("Failed to enable tp.\n");
		return -1;
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_bind_tp);

int ubcore_unbind_tp(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
		     struct ubcore_tp_advice *advice)
{
	if (tjetty->tp == NULL) {
		ubcore_log_warn("TP is not found, already removed or under use\n");
		return 0;
	}
	if (ubcore_unadvise_tp(jetty->ub_dev, advice) != 0) {
		ubcore_log_warn("failed to unbind tp\n");
		return -1;
	}
	mutex_lock(&tjetty->lock);
	tjetty->tp = NULL;
	mutex_unlock(&tjetty->lock);
	return 0;
}
EXPORT_SYMBOL(ubcore_unbind_tp);

int ubcore_advise_tp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
		     struct ubcore_tp_advice *advice, struct ubcore_udata *udata)
{
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp_cfg cfg = { 0 };
	struct ubcore_tp *new_tp;

	/* Must call driver->create_tp with udata if we are advising jetty */
	tp_node = ubcore_hash_table_lookup(advice->meta.ht, advice->meta.hash, &advice->meta.key);
	if (tp_node != NULL && !tp_node->tp->flag.bs.target) {
		atomic_inc(&tp_node->tp->use_cnt);
		return 0;
	}

	if (ubcore_query_initiator_tp_cfg(&cfg, dev, remote_eid, UBCORE_TP_RM) != 0) {
		ubcore_log_err("Failed to init tp cfg");
		return -1;
	}

	ubcore_set_ta_for_tp_cfg(dev, &advice->ta, &cfg);

	/* driver gurantee to return the same tp if we have created it as a target */
	new_tp = ubcore_create_tp(dev, &cfg, udata);
	if (new_tp == NULL) {
		ubcore_log_err("Failed to create tp");
		return -1;
	}

	tp_node = ubcore_add_tp_node(advice->meta.ht, advice->meta.hash, &advice->meta.key, new_tp,
				     &advice->ta);
	if (tp_node == NULL) {
		(void)ubcore_destroy_tp(new_tp);
		ubcore_log_err("Failed to find and add tp\n");
		return -1;
	} else if (tp_node != NULL && tp_node->tp != new_tp) {
		(void)ubcore_destroy_tp(new_tp);
		new_tp = NULL;
	}

	if (ubcore_enable_tp(dev, tp_node, &advice->ta, udata) != 0) {
		ubcore_abort_tp(new_tp, &advice->meta);
		ubcore_log_err("Failed to enable tp");
		return -1;
	}

	if (new_tp == NULL)
		atomic_inc(&tp_node->tp->use_cnt);

	return 0;
}
EXPORT_SYMBOL(ubcore_advise_tp);

int ubcore_unadvise_tp(struct ubcore_device *dev, struct ubcore_tp_advice *advice)
{
	struct ubcore_tp *tp =
		ubcore_find_remove_tp(advice->meta.ht, advice->meta.hash, &advice->meta.key);
	if (tp == NULL) {
		ubcore_log_warn("TP is not found, already removed or under use\n");
		return 0;
	}

	return ubcore_destroy_local_peer_tp(tp, &advice->ta);
}
EXPORT_SYMBOL(ubcore_unadvise_tp);

static void ubcore_get_ta_from_tp(struct ubcore_ta *ta, struct ubcore_tp *tp)
{
	struct ubcore_tp_node *tp_node = (struct ubcore_tp_node *)tp->priv;

	ta->type = UBCORE_TA_NONE;
	switch (tp->trans_mode) {
	case UBCORE_TP_RC:
	case UBCORE_TP_RM:
		/* ta is none for UB native device */
		if (tp_node != NULL)
			*ta = tp_node->ta;
		break;
	case UBCORE_TP_UM:
	default:
		break;
	}
}

static struct ubcore_nlmsg *ubcore_get_restore_tp_req(struct ubcore_tp *tp)
{
	uint32_t payload_len = sizeof(struct ubcore_nl_restore_tp_req);
	struct ubcore_nl_restore_tp_req *restore;
	struct ubcore_ta ta;
	struct ubcore_nlmsg *req;

	req = ubcore_alloc_nlmsg(payload_len, &tp->local_eid, &tp->peer_eid);
	if (req == NULL)
		return NULL;

	req->transport_type = tp->ub_dev->transport_type;
	req->msg_type = UBCORE_NL_RESTORE_TP_REQ;
	restore = (struct ubcore_nl_restore_tp_req *)(void *)req->payload;
	restore->trans_mode = tp->trans_mode;
	restore->tpn = tp->tpn;
	restore->peer_tpn = tp->peer_tpn;
	restore->rx_psn = get_random_u32();

	ubcore_get_ta_from_tp(&ta, tp);
	ubcore_get_ta_data_from_ta(&ta, &restore->ta);

	return req;
}

static struct ubcore_nlmsg *ubcore_get_restore_tp_response(struct ubcore_nlmsg *req,
							   struct ubcore_tp *tp)
{
	struct ubcore_nl_restore_tp_resp *restore_resp;
	struct ubcore_nlmsg *resp = NULL;

	resp = ubcore_alloc_nlmsg(sizeof(struct ubcore_nl_restore_tp_resp), &req->dst_eid,
				  &req->src_eid);
	if (resp == NULL) {
		ubcore_log_err("Failed to alloc restore tp response");
		return NULL;
	}

	resp->msg_type = UBCORE_NL_RESTORE_TP_RESP;
	resp->nlmsg_seq = req->nlmsg_seq;
	resp->transport_type = req->transport_type;
	restore_resp = (struct ubcore_nl_restore_tp_resp *)resp->payload;

	if (tp == NULL) {
		restore_resp->ret = UBCORE_NL_RESP_FAIL;
		return resp;
	}

	restore_resp->peer_rx_psn = tp->rx_psn;
	return resp;
}

static int ubcore_restore_tp_to_rts(const struct ubcore_device *dev, struct ubcore_tp *tp,
				    uint32_t rx_psn, uint32_t tx_psn)
{
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;

	mask.value = 0;
	mask.bs.state = 1;
	mask.bs.rx_psn = 1;
	mask.bs.tx_psn = 1;

	attr.state = UBCORE_TP_STATE_RTS;
	attr.rx_psn = rx_psn;
	attr.tx_psn = tx_psn;

	if (dev->ops->modify_tp(tp, &attr, mask) != 0) {
		/* tp->peer_ext.addr will be freed when called ubcore_destroy_tp */
		ubcore_log_err("Failed to modify tp");
		return -1;
	}

	tp->state = UBCORE_TP_STATE_RTS;
	tp->rx_psn = rx_psn;
	tp->tx_psn = tx_psn;

	return 0;
}

void ubcore_restore_tp(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;
	struct ubcore_nl_restore_tp_resp *resp;
	struct ubcore_nl_restore_tp_req *req;

	/* Currently, only try to restore tp in the UBCORE_TRANSPORT_IB device,
	 * Do not send retore tp req from target to inititor,
	 * Do not restore UM TP, as it is only visable by the driver
	 */
	if (dev->transport_type != UBCORE_TRANSPORT_IB || tp->flag.bs.target || tp->priv == NULL ||
	    tp->trans_mode == UBCORE_TP_UM || tp->state != UBCORE_TP_STATE_ERROR ||
	    !ubcore_have_tp_ops(dev))
		return;

	req_msg = ubcore_get_restore_tp_req(tp);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get restore tp req");
		return;
	}

	resp_msg = ubcore_nl_send_wait(req_msg);
	if (resp_msg == NULL) {
		ubcore_log_err("Failed to wait restore tp response %pI6c", &tp->peer_eid);
		kfree(req_msg);
		return;
	}

	req = (struct ubcore_nl_restore_tp_req *)(void *)req_msg->payload;
	resp = (struct ubcore_nl_restore_tp_resp *)(void *)resp_msg->payload;
	if (resp_msg->msg_type != req_msg->msg_type + 1 || resp == NULL ||
	    resp->ret != UBCORE_NL_RESP_SUCCESS) {
		ubcore_log_err("Restore tp request is rejected with type %d ret %d",
			       resp_msg->msg_type, (resp == NULL ? 1 : resp->ret));
		kfree(resp_msg);
		kfree(req_msg);
		return;
	}

	if (ubcore_restore_tp_to_rts(dev, tp, req->rx_psn, resp->peer_rx_psn) != 0)
		ubcore_log_err("Failed to restore tp with tpn %u", tp->tpn);

	kfree(req_msg);
	kfree(resp_msg);
	ubcore_log_info("Restored tp with tpn %u", tp->tpn);
}
EXPORT_SYMBOL(ubcore_restore_tp);

/* restore target RM tp created by ubcore_advise_target_tp */
static struct ubcore_tp *ubcore_restore_advised_target_tp(struct ubcore_device *dev,
							  struct ubcore_nl_restore_tp_req *restore)
{
	struct ubcore_tp_advice advice;
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp_meta *meta;
	struct ubcore_tp *tp;

	meta = &advice.meta;
	if (ubcore_parse_ta(dev, &restore->ta, &advice) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", restore->ta.type);
		return NULL;
	} else if (meta->ht == NULL) {
		ubcore_log_err("tp table is already released");
		return NULL;
	}

	tp_node = ubcore_hash_table_lookup(meta->ht, meta->hash, &meta->key);
	/* pair with get_tptable in parse_ta */
	ubcore_put_tptable(meta->ht);
	if (tp_node == NULL) {
		ubcore_log_err("tp is not found%u", restore->peer_tpn);
		return NULL;
	}

	tp = tp_node->tp;
	if (ubcore_restore_tp_to_rts(dev, tp, get_random_u32(), restore->rx_psn) != 0) {
		ubcore_log_err("Failed to modify tp to rts %u", restore->rx_psn);
		return NULL;
	}
	return tp;
}

static struct ubcore_tp *ubcore_restore_bound_target_tp(struct ubcore_device *dev,
							struct ubcore_nl_restore_tp_req *restore)
{
	return ubcore_restore_advised_target_tp(dev, restore);
}

static struct ubcore_tp *ubcore_handle_restore_tp(struct ubcore_device *dev,
						  struct ubcore_nl_restore_tp_req *restore)
{
	if (dev->transport_type != UBCORE_TRANSPORT_IB || restore->trans_mode == UBCORE_TP_UM ||
	    restore->ta.type == UBCORE_TA_NONE || restore->ta.type >= UBCORE_TA_VIRT)
		return NULL;

	if (restore->trans_mode == UBCORE_TP_RM)
		return ubcore_restore_advised_target_tp(dev, restore);
	else
		return ubcore_restore_bound_target_tp(dev, restore);
}

struct ubcore_nlmsg *ubcore_handle_restore_tp_req(struct ubcore_nlmsg *req)
{
	struct ubcore_nl_restore_tp_req *restore =
		(struct ubcore_nl_restore_tp_req *)(void *)req->payload;
	struct ubcore_device *dev;
	struct ubcore_tp *tp;

	if (req->payload_len != sizeof(struct ubcore_nl_restore_tp_req)) {
		ubcore_log_err("Invalid restore req");
		return NULL;
	}

	dev = ubcore_find_device(&req->dst_eid, req->transport_type);
	if (dev == NULL || !ubcore_have_tp_ops(dev)) {
		if (dev != NULL)
			ubcore_put_device(dev);
		ubcore_log_err("Failed to find device or device ops invalid");
		return ubcore_get_restore_tp_response(req, NULL);
	}

	tp = ubcore_handle_restore_tp(dev, restore);
	if (tp == NULL)
		ubcore_log_err("Failed to restore target tp towards remote eid %pI6c",
			       &req->src_eid);

	ubcore_put_device(dev);
	return ubcore_get_restore_tp_response(req, tp);
}
EXPORT_SYMBOL(ubcore_handle_restore_tp_req);

int ubcore_config_utp(struct ubcore_device *dev, const union ubcore_eid *eid,
		      const struct ubcore_utp_attr *attr, union ubcore_utp_attr_mask mask)
{
	struct ubcore_res_dev_val dev_val = { 0 };
	struct ubcore_res_key key_val;
	struct ubcore_res_val val;
	uint32_t i;

	if (dev == NULL || eid == NULL || attr == NULL || dev->ops == NULL ||
	    dev->ops->query_res == NULL || dev->ops->config_utp == NULL) {
		ubcore_log_err("dev ops has a null pointer.\n");
		return -1;
	}
	if (dev->transport_type == UBCORE_TRANSPORT_IB) {
		ubcore_log_err(
			"The configuration modification of this version of utp is not supported.\n");
		return -1;
	}
	// Query the utp_list under the device
	val.addr = (uintptr_t)&dev_val;
	val.len = sizeof(struct ubcore_res_dev_val);
	key_val.type = UBCORE_RES_KEY_URMA_DEV;
	key_val.key = eid->in4.addr;
	if (dev->ops->query_res(dev, &key_val, &val) != 0) {
		ubcore_log_err("failed to query res.\n");
		return -1;
	}
	for (i = 0; dev_val.utp_list != NULL && i < dev_val.utp_cnt; i++) {
		if (dev->ops->config_utp(dev, dev_val.utp_list[i], attr, mask) != 0) {
			ubcore_log_err("failed to config utp.\n");
			return -1;
		}
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_config_utp);

int ubcore_show_utp(struct ubcore_device *dev, const union ubcore_eid *eid)
{
	struct ubcore_res_dev_val dev_val = { 0 };
	struct ubcore_res_utp_val utp_val = { 0 };
	struct ubcore_res_key key_val;
	struct ubcore_res_val val;
	uint32_t i;

	if (dev == NULL || eid == NULL || dev->ops == NULL || dev->ops->query_res == NULL) {
		ubcore_log_err("dev ops has a null pointer.\n");
		return -1;
	}
	// Query the utp_list under the device
	val.addr = (uintptr_t)&dev_val;
	val.len = sizeof(struct ubcore_res_dev_val);
	key_val.type = UBCORE_RES_KEY_URMA_DEV;
	key_val.key = eid->in4.addr;
	if (dev->ops->query_res(dev, &key_val, &val) != 0) {
		ubcore_log_err("failed to query res.\n");
		return -1;
	}
	for (i = 0; dev_val.utp_list != NULL && i < dev_val.utp_cnt; i++) {
		// Query the utp_val under the utp list
		val.addr = (uintptr_t)&utp_val;
		val.len = sizeof(struct ubcore_res_utp_val);
		key_val.type = UBCORE_RES_KEY_UTP;
		key_val.key = dev_val.utp_list[i];
		if (dev->ops->query_res(dev, &key_val, &val) != 0) {
			ubcore_log_err("failed to query res.\n");
			return -1;
		}
		ubcore_log_info("-----------utp_info---------\n");
		ubcore_log_info("--utp_id:          %d\n", (int)utp_val.utp_id);
		ubcore_log_info("--spray_en:        %d\n", (int)utp_val.spray_en);
		ubcore_log_info("--data_udp_start:  %d\n", (int)utp_val.data_udp_start);
		ubcore_log_info("--udp_range:       %d\n", (int)utp_val.udp_range);
		ubcore_log_info("----------------------------\n");
	}
	return 0;
}
EXPORT_SYMBOL(ubcore_show_utp);
