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
#include <linux/if_vlan.h>
#include <linux/version.h>
#include "ubcore_log.h"
#include "ubcore_netlink.h"
#include "ubcore_priv.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_tp_table.h"
#include "ubcore_msg.h"
#include "ubcore_vtp.h"
#include "ubcore_tp.h"

#define UB_PROTOCOL_HEAD_BYTES 313
#define UB_MTU_BITS_BASE_SHIFT 7
#define UBCORE_TP_ATTR_MASK 0x7FFFF

static inline uint32_t get_udrv_in_len(struct ubcore_udata *udata)
{
	return ((udata == NULL || udata->udrv_data == NULL) ? 0 : udata->udrv_data->in_len);
}

static inline int get_udrv_in_data(uint8_t *dst, uint32_t dst_len, struct ubcore_udata *udata)
{
	if (get_udrv_in_len(udata) == 0)
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

static inline int ubcore_mtu_enum_to_int(enum ubcore_mtu mtu)
{
	return 1 << ((int)mtu + UB_MTU_BITS_BASE_SHIFT);
}

enum ubcore_mtu ubcore_get_mtu(int mtu)
{
	int tmp_mtu = mtu - UB_PROTOCOL_HEAD_BYTES;

	if (mtu < 0)
		return 0;

	if (tmp_mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_8192))
		return UBCORE_MTU_8192;
	if (tmp_mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_4096))
		return UBCORE_MTU_4096;
	else if (tmp_mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_2048))
		return UBCORE_MTU_2048;
	else if (tmp_mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_1024))
		return UBCORE_MTU_1024;
	else if (tmp_mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_512))
		return UBCORE_MTU_512;
	else if (tmp_mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_256))
		return UBCORE_MTU_256;
	else
		return 0;
}
EXPORT_SYMBOL(ubcore_get_mtu);

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
		destroy->ta.ta_type = UBCORE_TA_NONE;

	return req;
}

static int ubcore_set_tp_peer_ext(struct ubcore_tp_attr *attr, uint64_t ext_addr,
				  uint32_t ext_len)
{
	void *peer_ext = NULL;
	int ret;

	/* ext is unused */
	if (ext_len == 0 || ext_addr == 0)
		return 0;

	/* copy resp ext from req or response */
	peer_ext = kzalloc(ext_len, GFP_KERNEL);
	if (peer_ext == NULL)
		return -ENOMEM;

	ret = (int)copy_from_user(peer_ext, (void __user *)(uintptr_t)ext_addr, ext_len);
	attr->peer_ext.addr = (uint64_t)peer_ext;
	attr->peer_ext.len = ext_len;
	return ret;
}

static inline void ubcore_unset_tp_peer_ext(struct ubcore_tp_attr *attr)
{
	if (attr->peer_ext.addr != 0)
		kfree((void *)attr->peer_ext.addr);
}

static void ubcore_get_ta_data_from_ta(const struct ubcore_ta *ta,
	enum ubcore_transport_type trans_type, struct ubcore_ta_data *ta_data)
{
	struct ubcore_jetty *jetty;
	struct ubcore_jfs *jfs;

	ta_data->ta_type = ta->type;
	switch (ta->type) {
	case UBCORE_TA_JFS_TJFR:
		jfs = ta->jfs;
		if (jfs->jfs_cfg.eid_index >= jfs->ub_dev->eid_table.eid_cnt)
			return;
		ta_data->jetty_id.eid =
			jfs->ub_dev->eid_table.eid_entries[jfs->jfs_cfg.eid_index].eid;
		ta_data->jetty_id.id = jfs->id;
		ta_data->tjetty_id = ta->tjetty_id;
		break;
	case UBCORE_TA_JETTY_TJETTY:
		jetty = ta->jetty;
		if (jetty->jetty_cfg.eid_index >= jetty->ub_dev->eid_table.eid_cnt)
			return;
		ta_data->jetty_id.eid =
			jetty->ub_dev->eid_table.eid_entries[jetty->jetty_cfg.eid_index].eid;
		ta_data->jetty_id.id = jetty->id;
		ta_data->tjetty_id = ta->tjetty_id;
		break;
	case UBCORE_TA_NONE:
	case UBCORE_TA_VIRT:
	default:
		return;
	}
	ta_data->trans_type = trans_type;
}

static int ubcore_nl_handle_create_tp_resp_cb(struct ubcore_device *dev,
	struct ubcore_resp *resp, void *user_arg)
{
	struct ubcore_create_vtp_resp *vtp_resp;

	vtp_resp = (struct ubcore_create_vtp_resp *)resp->data;
	if (vtp_resp->ret == UBCORE_MSG_RESP_FAIL) {
		ubcore_log_err("failed to create vtp: response error");
		return -1;
	} else if (vtp_resp->ret == UBCORE_MSG_RESP_IN_PROGRESS) {
		ubcore_log_err("failed: try to create vtp which is being created. Try again later");
		return -1;
	} else if (vtp_resp->ret == UBCORE_MSG_RESP_RC_JETTY_ALREADY_BIND) {
		ubcore_log_err("failed: rc jetty already bind by other jetty");
		return -1;
	}
	return 0;
}

int ubcore_destroy_tp(struct ubcore_tp *tp)
{
	if (tp == NULL)
		return -EINVAL;
	if (!ubcore_have_tp_ops(tp->ub_dev)) {
		ubcore_log_err("TP ops is NULL");
		return -EINVAL;
	}
	if (tp->peer_ext.len > 0 && tp->peer_ext.addr != 0)
		kfree((void *)tp->peer_ext.addr);

	return tp->ub_dev->ops->destroy_tp(tp);
}
EXPORT_SYMBOL(ubcore_destroy_tp);

static void ubcore_set_tp_flag(union ubcore_tp_flag *flag, struct ubcore_tp_cfg *cfg,
			       struct ubcore_device *dev)
{
	flag->bs.target = cfg->flag.bs.target;
}

void ubcore_set_tp_init_cfg(struct ubcore_tp *tp, struct ubcore_tp_cfg *cfg)
{
	ubcore_set_tp_flag(&tp->flag, cfg, tp->ub_dev);
	if (tp->ub_dev->transport_type == UBCORE_TRANSPORT_IB ||
		(tp->ub_dev->transport_type == UBCORE_TRANSPORT_UB &&
		tp->trans_mode == UBCORE_TP_RC)) {
		tp->local_jetty = cfg->local_jetty;
		tp->peer_jetty = cfg->peer_jetty;
	} else {
		tp->local_eid = cfg->local_eid;
		tp->peer_eid = cfg->peer_eid;
	}

	tp->trans_mode = cfg->trans_mode;
	tp->tx_psn = 0;
	tp->retry_num = cfg->retry_num;
	tp->ack_timeout = cfg->ack_timeout;
	tp->dscp = cfg->dscp;
	tp->oor_cnt = cfg->oor_cnt;
}

struct ubcore_tp *ubcore_create_tp(struct ubcore_device *dev,
					  struct ubcore_tp_cfg *cfg,
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
	/* The driver may return the old tp pointer */
	if (tp->state != UBCORE_TP_STATE_RESET)
		return tp;

	tp->ub_dev = dev;
	ubcore_set_tp_init_cfg(tp, cfg);
	tp->state = UBCORE_TP_STATE_RESET;
	ubcore_log_info("tp state:(set to RESET) with tpn %u", tp->tpn);
	tp->priv = NULL;
	atomic_set(&tp->use_cnt, 0);

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
		ubcore_get_ta_data_from_ta(ta, tp->ub_dev->transport_type, &ta_data);

	req_msg = ubcore_get_destroy_tp_req(tp, &ta_data);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get destroy tp req");
		return -1;
	}

	resp_msg = ubcore_nl_send_wait(tp->ub_dev, req_msg);
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

/* destroy initiator and peer tp created by ubcore_connect_fe_tp, called by ubcore_destroy_vtp */
static int ubcore_disconnect_fe_tp(struct ubcore_tp *tp)
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

int ubcore_fill_netaddr_macvlan(struct ubcore_net_addr *netaddr, struct net_device *netdev,
	enum ubcore_net_addr_type type)
{
	netaddr->type = type;

	/* UB does not have a mac address
	 * to prevent the duplication of the mac address from hanging
	 */
	if (netdev->type == UBCORE_NETDEV_UB_TYPE) {
		ubcore_log_err("Pure ub does not support uboe mac\n");
		return -1;
	}
	(void)memcpy(netaddr->mac, netdev->dev_addr, netdev->addr_len);
	if (is_vlan_dev(netdev))
		netaddr->vlan = vlan_dev_vlan_id(netdev);
	else
		netaddr->vlan = 0;

	return 0;
}

/* check if current tp state can be truned into new tp state */
int ubcore_modify_tp_state_check(struct ubcore_tp *tp, enum ubcore_tp_state new_state)
{
	int ret = 0;

	switch (tp->state) {
	case UBCORE_TP_STATE_RESET:
		if (new_state != UBCORE_TP_STATE_RTR)
			ret = -1;
		break;
	case UBCORE_TP_STATE_RTR:
		if (new_state != UBCORE_TP_STATE_ERR && new_state != UBCORE_TP_STATE_RTS)
			ret = -1;
		break;
	case UBCORE_TP_STATE_RTS:
		if (new_state != UBCORE_TP_STATE_ERR && new_state != UBCORE_TP_STATE_SUSPENDED)
			ret = -1;
		break;
	case UBCORE_TP_STATE_SUSPENDED:
		if (new_state != UBCORE_TP_STATE_RTS && new_state != UBCORE_TP_STATE_ERR)
			ret = -1;
		break;
	case UBCORE_TP_STATE_ERR:
		/* ERR -> ERR is allowed */
		if (new_state != UBCORE_TP_STATE_ERR && new_state != UBCORE_TP_STATE_RESET)
			ret = -1;
		break;
	default:
		ret = -1;
		break;
	}

	if (ret != 0) {
		ubcore_log_err("modify_tp state check WARNING: tpn = %u; old_state %u -> new_state %u",
			tp->tpn, (uint32_t)tp->state, (uint32_t)new_state);
	} else {
		ubcore_log_info("modify_tp state check: tpn = %u; old_state %u -> new_state %u",
			tp->tpn, (uint32_t)tp->state, (uint32_t)new_state);
	}

	return ret;
}

int ubcore_modify_tp_state(struct ubcore_device *dev, struct ubcore_tp *tp,
	enum ubcore_tp_state new_state, struct ubcore_tp_attr *attr, union ubcore_tp_attr_mask mask)
{
	if (ubcore_modify_tp_state_check(tp, new_state) != 0)
		return -1;

	if (tp->state == UBCORE_TP_STATE_ERR && new_state == UBCORE_TP_STATE_ERR) {
		ubcore_log_info("tp is already in ERR state and tpn = %u",
			tp->tpn);
		return 0;
	}

	if (dev == NULL || dev->ops == NULL || dev->ops->modify_tp(tp, attr, mask) != 0) {
		/* tp->peer_ext.addr will be freed when called ubcore_destroy_tp */
		ubcore_log_err("Failed to modify tp to %u from state %u and tpn = %u",
			(uint32_t)new_state, (uint32_t)tp->state, tp->tpn);
		return -1;
	}
	tp->state = new_state;
	ubcore_log_info("tp state:(%u to %u) with tpn %u, peer_tpn %u",
		(uint32_t)tp->state, (uint32_t)new_state, tp->tpn, tp->peer_tpn);
	return 0;
}

static int ubcore_modify_tp_to_rts(const struct ubcore_device *dev, struct ubcore_tp *tp)
{
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;

	mask.value = 0;
	mask.bs.state = 1;
	attr.state = UBCORE_TP_STATE_RTS;
	attr.tx_psn = 0;

	if (dev->ops->modify_tp(tp, &attr, mask) != 0) {
		/* tp->peer_ext.addr will be freed when called ubcore_destroy_tp */
		ubcore_log_err("Failed to modify tp");
		return -1;
	}
	tp->state = UBCORE_TP_STATE_RTS;
	ubcore_log_info("tp state:(RTR to RTS) with tpn %u, peer_tpn %u", tp->tpn, tp->peer_tpn);
	return 0;
}

#define ubcore_mod_tp_attr_with_mask(tp, attr, field, mask)	\
	(tp->field = mask.bs.field ? attr->field : tp->field)

void ubcore_modify_tp_attr(struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
	union ubcore_tp_attr_mask mask)
{
	if (mask.bs.flag) {
		tp->flag.bs.oor_en = attr->flag.bs.oor_en;
		tp->flag.bs.sr_en = attr->flag.bs.sr_en;
		tp->flag.bs.cc_en = attr->flag.bs.cc_en;
		tp->flag.bs.cc_alg = attr->flag.bs.cc_alg;
		tp->flag.bs.spray_en = attr->flag.bs.spray_en;
	}

	ubcore_mod_tp_attr_with_mask(tp, attr, peer_tpn, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, state, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, tx_psn, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, rx_psn, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, mtu, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, cc_pattern_idx, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, peer_ext, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, local_net_addr_idx, mask);
	ubcore_mod_tp_attr_with_mask(tp, attr, port_id, mask);
}

/* create vtp and connect to a remote vtp peer, called by ubcore_create_vtp */
static struct ubcore_tp *ubcore_connect_fe_tp(struct ubcore_device *dev,
	union ubcore_eid *remote_eid, enum ubcore_transport_mode trans_mode,
	struct ubcore_udata *udata)
{
	struct ubcore_tp *tp = NULL;

	return tp;
}

static int ubcore_set_target_peer(struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
	union ubcore_tp_attr_mask *mask, struct ubcore_tp_attr *tp_attr, struct ubcore_udata udata)
{
	mask->value = 0;
	mask->value = UBCORE_TP_ATTR_MASK;

	memset(attr, 0, sizeof(*attr));
	(void)memcpy(attr, tp_attr, sizeof(struct ubcore_tp_attr));
	attr->tx_psn = tp_attr->rx_psn;
	attr->state = UBCORE_TP_STATE_RTR;

	if (tp->peer_ext.addr != 0)
		return 0;

	return ubcore_set_tp_peer_ext(attr, udata.udrv_data->in_addr, udata.udrv_data->in_len);
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
	uint32_t payload_len = (uint32_t)sizeof(struct ubcore_nl_create_tp_resp) +
		(tp == NULL ? 0 : tp->tp_ext.len);
	struct ubcore_nl_create_tp_resp *create_resp;
	struct ubcore_nlmsg *resp = NULL;

	if (payload_len < (uint32_t)sizeof(struct ubcore_nl_create_tp_resp)) {
		/* If the value overflows, tp must exist */
		ubcore_log_err("tp_ext len %u is err", tp->tp_ext.len);
		return NULL;
	}

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
		(void)memcpy(create_resp->peer_ext, (void *)tp->tp_ext.addr,
		tp->tp_ext.len);

	return resp;
}

static void ubcore_set_jetty_for_tp_param(struct ubcore_ta *ta,
	enum ubcore_transport_mode trans_mode, struct ubcore_vtp_param *vtp_param)
{
	struct ubcore_jetty *jetty;
	struct ubcore_jfs *jfs;

	(void)memset(vtp_param, 0, sizeof(struct ubcore_vtp_param));
	if (ta == NULL)
		return;

	switch (ta->type) {
	case UBCORE_TA_JFS_TJFR:
		jfs = ta->jfs;
		if (jfs->jfs_cfg.eid_index >= jfs->ub_dev->eid_table.eid_cnt)
			return;
		vtp_param->local_eid =
			jfs->ub_dev->eid_table.eid_entries[jfs->jfs_cfg.eid_index].eid;
		vtp_param->local_jetty = jfs->id;
		vtp_param->eid_index = jfs->jfs_cfg.eid_index;
		break;
	case UBCORE_TA_JETTY_TJETTY:
		jetty = ta->jetty;
		if (jetty->jetty_cfg.eid_index >= jetty->ub_dev->eid_table.eid_cnt)
			return;
		vtp_param->local_eid =
			jetty->ub_dev->eid_table.eid_entries[jetty->jetty_cfg.eid_index].eid;
		vtp_param->local_jetty = jetty->id;
		vtp_param->eid_index = jetty->jetty_cfg.eid_index;
		break;
	case UBCORE_TA_NONE:
	case UBCORE_TA_VIRT:
	default:
		return;
	}
	vtp_param->trans_mode = trans_mode;
	vtp_param->peer_eid = ta->tjetty_id.eid;
	vtp_param->peer_jetty = ta->tjetty_id.id;
	vtp_param->eid_index = 0;
	vtp_param->ta = *ta;
}

static struct ubcore_tp *ubcore_create_target_tp(struct ubcore_device *dev,
						 struct ubcore_nlmsg *req, struct ubcore_ta *ta)
{
	struct ubcore_nl_create_tp_req *create =
		(struct ubcore_nl_create_tp_req *)(void *)req->payload;
	/* create tp parameters */
	struct ubcore_udrv_priv udrv_data  = {
		.in_addr = (uint64_t)(create->ext_udrv + create->ext_len),
		.in_len = create->udrv_in_len,
		.out_addr = 0,
		.out_len = 0
	};
	struct ubcore_udata udata = {
		.uctx = NULL,
		.udrv_data = &udrv_data
	};
	struct ubcore_tp_cfg cfg = {0};
	struct ubcore_tp *tp = NULL;

	tp = ubcore_create_tp(dev, &cfg, &udata);
	if (tp == NULL) {
		ubcore_log_err("Failed to create tp in create target tp.\n");
		return NULL;
	}

	return tp;
}

int ubcore_modify_tp(struct ubcore_device *dev, struct ubcore_tp_node *tp_node,
	struct ubcore_tp_attr *tp_attr, struct ubcore_udata udata)
{
	struct ubcore_tp *tp = tp_node->tp;
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;
	int ret = 0;

	mutex_lock(&tp_node->lock);

	switch (tp->state) {
	case UBCORE_TP_STATE_RTS:
		ubcore_log_info("Reuse tp state:(RTS) with tpn %u, peer_tpn %u",
			tp->tpn, tp->peer_tpn);
		break;
	case UBCORE_TP_STATE_RESET:
		/* Modify target tp to RTR */
		if (ubcore_set_target_peer(tp, &attr, &mask, tp_attr, udata) != 0) {
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
		ubcore_log_info(
			"tp state:(RESET to RTR) with tpn %u, peer_tpn %u", tp->tpn, tp->peer_tpn);
		break;
	case UBCORE_TP_STATE_RTR:
		ret = ubcore_modify_tp_to_rts(dev, tp);
		ubcore_log_info(
			"tp state:(RTR to RTS) with tpn %u, peer_tpn %u", tp->tpn, tp->peer_tpn);
		break;
	case UBCORE_TP_STATE_SUSPENDED:
		ubcore_log_info("tp state: TP_STATE_SUSPENDED\n");
		fallthrough;
	case UBCORE_TP_STATE_ERR:
		ubcore_log_info("tp state: TP_STATE_ERR\n");
		fallthrough;
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
	return tp_node->tp;
}

static int ubcore_parse_ta(struct ubcore_device *dev, struct ubcore_ta_data *ta_data,
			   struct ubcore_tp_advice *advice)
{
	struct ubcore_tp_meta *meta;
	struct ubcore_jetty *jetty;
	struct ubcore_jfs *jfs;

	(void)memset(advice, 0, sizeof(struct ubcore_tp_advice));
	meta = &advice->meta;
	advice->ta.type = ta_data->ta_type;

	switch (ta_data->ta_type) {
	case UBCORE_TA_JFS_TJFR:
		jfs = ubcore_find_jfs(dev, ta_data->tjetty_id.id);
		if (jfs != NULL) {
			meta->ht = ubcore_get_tptable(jfs->tptable);
			advice->ta.jfs = jfs;
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
		ubcore_log_err("Failed to parse ta with type %u", (uint32_t)create->ta.ta_type);
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
	return tp;

destroy_tp:
	(void)ubcore_destroy_tp(tp);
	return NULL;
}

static struct ubcore_tp *ubcore_bind_target_tp(struct ubcore_device *dev,
	struct ubcore_nlmsg *req)
{
	return ubcore_advise_target_tp(dev, req);
}

struct ubcore_nlmsg *ubcore_handle_create_tp_req(struct ubcore_nlmsg *req)
{
	struct ubcore_nl_create_tp_req *create;
	struct ubcore_tp *tp = NULL;
	struct ubcore_device *dev;

	if (req == NULL)
		return NULL;
	create = (struct ubcore_nl_create_tp_req *)(void *)req->payload;
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

	if (create->ta.ta_type == UBCORE_TA_VIRT) {
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

/* destroy target RM tp created by ubcore_advise_target_tp */
static int ubcore_unadvise_target_tp(struct ubcore_device *dev,
				     struct ubcore_nl_destroy_tp_req *destroy)
{
	struct ubcore_tp_advice advice;
	struct ubcore_tp_meta *meta;
	struct ubcore_tp *tp = NULL;

	meta = &advice.meta;
	if (ubcore_parse_ta(dev, &destroy->ta, &advice) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", (uint32_t)destroy->ta.ta_type);
		return -1;
	} else if (meta->ht == NULL) {
		ubcore_log_warn("tp table is already released");
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
	struct ubcore_nl_destroy_tp_req *destroy;
	struct ubcore_device *dev;
	int ret = -1;

	if (req == NULL) {
		ubcore_log_err("Failed to destroy tp req, req is NULL");
		return NULL;
	}

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

	destroy = (struct ubcore_nl_destroy_tp_req *)(void *)req->payload;
	if (destroy->ta.ta_type == UBCORE_TA_VIRT) {
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

struct ubcore_tp *ubcore_create_vtp(struct ubcore_device *dev, union ubcore_eid *remote_eid,
				    enum ubcore_transport_mode trans_mode,
				    struct ubcore_udata *udata)
{
	if (!ubcore_have_tp_ops(dev) || dev->attr.virtualization || remote_eid == NULL) {
		ubcore_log_err("Invalid parameter");
		return NULL;
	}

	switch (dev->transport_type) {
	case UBCORE_TRANSPORT_IB: /* alpha */
		if (trans_mode == UBCORE_TP_RM || trans_mode ==  UBCORE_TP_RC)
			return ubcore_connect_fe_tp(dev, remote_eid, trans_mode, udata);
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
			return ubcore_disconnect_fe_tp(vtp);
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

static int ubcore_init_create_tp_req(struct ubcore_device *dev, struct ubcore_vtp_param *tp_param,
	struct ubcore_tp *tp, struct ubcore_udata *udata, struct ubcore_create_vtp_req *data)
{
	data->trans_mode = tp_param->trans_mode;
	data->local_eid = tp_param->local_eid;
	data->peer_eid = tp_param->peer_eid;
	data->eid_index = tp_param->eid_index;
	data->local_jetty = tp_param->local_jetty;
	data->peer_jetty = tp_param->peer_jetty;
	(void)strcpy(data->dev_name, dev->dev_name);
	data->virtualization = dev->attr.virtualization;

	ubcore_get_ta_data_from_ta(&tp_param->ta, dev->transport_type, &data->ta_data);
	data->udrv_in_len = get_udrv_in_len(udata);
	data->ext_len = tp->tp_ext.len;

	if (get_udrv_in_data(data->udrv_ext, get_udrv_in_len(udata), udata) != 0) {
		ubcore_log_err("Failed to get udrv data");
		return -1;
	}
	if (tp->tp_ext.len > 0)
		(void)memcpy(data->udrv_ext + get_udrv_in_len(udata),
			(void *)tp->tp_ext.addr, tp->tp_ext.len);

	return 0;
}

static int ubcore_send_create_tp_req(struct ubcore_device *dev, struct ubcore_vtp_param *tp_param,
	struct ubcore_tp *tp, struct ubcore_udata *udata)
{
	struct ubcore_create_vtp_req *data;
	struct ubcore_req *req_msg;
	struct ubcore_resp_cb cb;
	uint32_t payload_len;
	uint32_t udata_len;
	uint32_t tp_len;
	int ret;

	tp_len = tp->tp_ext.len;
	udata_len = get_udrv_in_len(udata);
	if ((uint32_t)sizeof(struct ubcore_create_vtp_req) + tp_len > ULONG_MAX - udata_len)
		return -ERANGE;

	payload_len = (uint32_t)sizeof(struct ubcore_create_vtp_req) +
		tp_len + udata_len;
	req_msg = kcalloc(1, sizeof(struct ubcore_req) + payload_len, GFP_KERNEL);
	if (req_msg == NULL)
		return -ENOMEM;

	req_msg->opcode = UBCORE_MSG_CREATE_VTP;
	req_msg->len = payload_len;
	data = (struct ubcore_create_vtp_req *)req_msg->data;
	if (ubcore_init_create_tp_req(dev, tp_param, tp, udata, data) != 0) {
		kfree(req_msg);
		return -ENOEXEC;
	}
	/* for alpha end */
	cb.callback = ubcore_nl_handle_create_tp_resp_cb;
	cb.user_arg = NULL;
	ret = ubcore_send_fe2tpf_msg(dev, req_msg, &cb);
	if (ret != 0)
		ubcore_log_err("send fe2tpf failed.\n");
	kfree(req_msg);
	return ret;
}

static int ubcore_handle_del_tp_resp(struct ubcore_device *dev, struct ubcore_resp *resp,
	void *user_arg)
{
	struct ubcore_destroy_vtp_resp *vtp_resp = (struct ubcore_destroy_vtp_resp *)resp->data;

	if (vtp_resp->ret == UBCORE_MSG_RESP_FAIL) {
		ubcore_log_err("failed to destroy vtp: response error");
		return -1;
	} else if (vtp_resp->ret == UBCORE_MSG_RESP_IN_PROGRESS) {
		ubcore_log_err("failed: try to del vtp which is being created. Try again later");
		return -1;
	}
	return 0;
}

static int ubcore_send_del_tp_req(struct ubcore_device *dev, struct ubcore_vtp_param *tp_param)
{
	struct ubcore_create_vtp_req *data;
	struct ubcore_req *req_msg;
	struct ubcore_resp_cb cb;
	int ret;

	req_msg = kcalloc(1, sizeof(struct ubcore_req) +
		sizeof(struct ubcore_create_vtp_req), GFP_KERNEL);
	if (req_msg == NULL)
		return -ENOMEM;

	req_msg->opcode = UBCORE_MSG_DESTROY_VTP;
	req_msg->len = sizeof(struct ubcore_create_vtp_req);
	data = (struct ubcore_create_vtp_req *)req_msg->data;
	data->trans_mode = tp_param->trans_mode;
	data->local_eid = tp_param->local_eid;
	data->peer_eid = tp_param->peer_eid;
	data->eid_index = tp_param->eid_index;
	data->local_jetty = tp_param->local_jetty;
	data->peer_jetty = tp_param->peer_jetty;
	(void)strcpy(data->dev_name, dev->dev_name);
	data->virtualization = dev->attr.virtualization;
	/* for alpha start */
	ubcore_get_ta_data_from_ta(&tp_param->ta, dev->transport_type, &data->ta_data);
	/* for alpha end */
	cb.callback = ubcore_handle_del_tp_resp;
	cb.user_arg = NULL;
	ret = ubcore_send_fe2tpf_msg(dev, req_msg, &cb);
	if (ret != 0)
		ubcore_log_err("send fe2tpf failed.\n");
	kfree(req_msg);
	return ret;
}

static struct ubcore_nlmsg *ubcore_get_query_tp_req(struct ubcore_device *dev,
	enum ubcore_transport_mode trans_mode)
{
	uint32_t payload_len = sizeof(struct ubcore_nl_query_tp_req);
	struct ubcore_nl_query_tp_req *query;
	struct ubcore_nlmsg *req;

	req = kzalloc(sizeof(struct ubcore_nlmsg) + payload_len, GFP_KERNEL);
	if (req == NULL)
		return NULL;

	req->transport_type = dev->transport_type;
	req->msg_type = UBCORE_NL_QUERY_TP_REQ;
	req->payload_len = payload_len;
	query = (struct ubcore_nl_query_tp_req *)req->payload;
	query->trans_mode = trans_mode;
	(void)memcpy(query->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	query->fe_idx = dev->attr.fe_idx;
	return req;
}

static int ubcore_query_tp(struct ubcore_device *dev,
	enum ubcore_transport_mode trans_mode,
	struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	struct ubcore_nlmsg *req_msg, *resp_msg;
	struct ubcore_nl_query_tp_resp *resp;
	int ret = 0;

	req_msg = ubcore_get_query_tp_req(dev, trans_mode);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get query tp req");
		return -1;
	}

	resp_msg = ubcore_nl_send_wait(dev, req_msg);
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

static void ubcore_set_initiator_tp_cfg(struct ubcore_tp_cfg *cfg,
	struct ubcore_vtp_param *tp_param, struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	cfg->flag.bs.target = 0;
	cfg->local_jetty.eid = tp_param->local_eid;
	cfg->local_jetty.id = tp_param->local_jetty;
	cfg->peer_jetty.eid = tp_param->peer_eid;
	cfg->peer_jetty.id = tp_param->peer_jetty;
	cfg->trans_mode = tp_param->trans_mode;
	cfg->retry_factor = query_tp_resp->retry_factor;
	cfg->retry_num = query_tp_resp->retry_num;
	cfg->ack_timeout = query_tp_resp->ack_timeout;
	cfg->dscp = query_tp_resp->dscp;
	cfg->oor_cnt = query_tp_resp->oor_cnt;
}

static int ubcore_query_initiator_tp_cfg(struct ubcore_tp_cfg *cfg, struct ubcore_device *dev,
	struct ubcore_vtp_param *tp_param)
{
	struct ubcore_nl_query_tp_resp query_tp_resp;

	if (ubcore_query_tp(dev, tp_param->trans_mode, &query_tp_resp) != 0) {
		ubcore_log_err("Failed to query tp");
		return -1;
	}
	ubcore_set_initiator_tp_cfg(cfg, tp_param, &query_tp_resp);
	return 0;
}

int ubcore_bind_tp(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
	struct ubcore_tp_advice *advice, struct ubcore_udata *udata)
{
	struct ubcore_device *dev = jetty->ub_dev;
	struct ubcore_vtp_param tp_param = { 0 };
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp *new_tp = NULL;
	struct ubcore_tp_cfg tp_cfg = { 0 };

	if (jetty == NULL || tjetty == NULL || advice == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	mutex_lock(&tjetty->lock);
	if (tjetty->tp != NULL) {
		mutex_unlock(&tjetty->lock);
		ubcore_log_err("The same tjetty, different jetty, prevent duplicate bind.\n");
		return -1;
	}
	mutex_unlock(&tjetty->lock);

	ubcore_set_jetty_for_tp_param(&advice->ta, UBCORE_TP_RC, &tp_param);
	if (ubcore_query_initiator_tp_cfg(&tp_cfg, dev, &tp_param) != 0) {
		ubcore_log_err("Failed to init tp cfg.\n");
		return -1;
	}
	/* driver gurantee to return the same tp if we have created it as a target */
	new_tp = ubcore_create_tp(dev, &tp_cfg, udata);
	if (new_tp == NULL) {
		ubcore_log_err("Failed to create tp");
		return -1;
	}
	tp_node = ubcore_add_tp_node(advice->meta.ht, advice->meta.hash, &advice->meta.key,
		new_tp, &advice->ta);
	if (tp_node == NULL) {
		(void)ubcore_destroy_tp(new_tp);
		ubcore_log_err("Failed to find and add tp\n");
		return -1;
	} else if (tp_node != NULL && tp_node->tp != new_tp) {
		(void)ubcore_destroy_tp(new_tp);
		new_tp = NULL;
	}
	if (ubcore_send_create_tp_req(dev, &tp_param, tp_node->tp, udata) != 0) {
		ubcore_log_err("Failed to send tp req");
		return -1;
	}
	mutex_lock(&tjetty->lock);
	tjetty->tp = tp_node->tp;
	mutex_unlock(&tjetty->lock);
	return 0;
}
EXPORT_SYMBOL(ubcore_bind_tp);

int ubcore_unbind_tp(struct ubcore_jetty *jetty, struct ubcore_tjetty *tjetty,
		     struct ubcore_tp_advice *advice)
{
	struct ubcore_vtp_param tp_param;

	if (jetty == NULL || tjetty == NULL || advice == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	mutex_lock(&tjetty->lock);
	if (tjetty->tp == NULL) {
		mutex_unlock(&tjetty->lock);
		ubcore_log_warn("TP is not found, already removed or under use\n");
		return 0;
	}
	mutex_unlock(&tjetty->lock);

	ubcore_set_jetty_for_tp_param(&advice->ta, UBCORE_TP_RC, &tp_param);
	if (ubcore_send_del_tp_req(jetty->ub_dev, &tp_param) != 0) {
		ubcore_log_warn("failed to unbind tp\n");
		return -1;
	}
	mutex_lock(&tjetty->lock);
	tjetty->tp = NULL;
	mutex_unlock(&tjetty->lock);
	return 0;
}
EXPORT_SYMBOL(ubcore_unbind_tp);

/* udata may be empty because the data may come from the user space or kernel space. */
int ubcore_advise_tp(struct ubcore_device *dev, union ubcore_eid *remote_eid,
	struct ubcore_tp_advice *advice, struct ubcore_udata *udata)
{
	struct ubcore_vtp_param tp_param = {0};
	struct ubcore_tp_cfg tp_cfg = { 0 };
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp *new_tp;

	if (dev == NULL || remote_eid == NULL || advice == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	/* Must call driver->create_tp with udata if we are advising jetty */
	tp_node = ubcore_hash_table_lookup(advice->meta.ht, advice->meta.hash, &advice->meta.key);
	if (tp_node != NULL && tp_node->tp != NULL && !tp_node->tp->flag.bs.target)
		return 0;

	ubcore_set_jetty_for_tp_param(&advice->ta, UBCORE_TP_RM, &tp_param);
	if (ubcore_query_initiator_tp_cfg(&tp_cfg, dev, &tp_param) != 0) {
		ubcore_log_err("Failed to init tp cfg.\n");
		return -1;
	}
	/* advise tp requires the user to pass in the pin memory operation
	 * and cannot be used in the uvs context ioctl to create tp
	 */
	new_tp = ubcore_create_tp(dev, &tp_cfg, udata);
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

	if (ubcore_send_create_tp_req(dev, &tp_param, tp_node->tp, udata) != 0) {
		ubcore_find_remove_tp(advice->meta.ht, advice->meta.hash, &advice->meta.key);
		ubcore_log_err("Failed to send tp req");
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(ubcore_advise_tp);

int ubcore_unadvise_tp(struct ubcore_device *dev, struct ubcore_tp_advice *advice)
{
	struct ubcore_vtp_param tp_param;

	if (dev == NULL || advice == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ubcore_set_jetty_for_tp_param(&advice->ta, UBCORE_TP_RM, &tp_param);
	return ubcore_send_del_tp_req(dev, &tp_param);
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
	uint32_t payload_len = (uint32_t)sizeof(struct ubcore_nl_restore_tp_req);
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
	ubcore_get_ta_data_from_ta(&ta, tp->ub_dev->transport_type, &restore->ta);

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

static int ubcore_restore_tp_to_reset(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;

	mask.value = 0;
	mask.bs.state = 1;
	attr.state = UBCORE_TP_STATE_RESET;
	ubcore_log_info("restore tp to reset(mask): state: %u", mask.bs.state);
	ubcore_log_info("restore tp to reset(attr): state: %u", (uint32_t)attr.state);

	if (ubcore_modify_tp_state(dev, tp, UBCORE_TP_STATE_RESET, &attr, mask) != 0)
		return -1;

	return 0;
}

static int ubcore_restore_tp_to_rts(struct ubcore_device *dev, struct ubcore_tp *tp,
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
	ubcore_log_info("restore tp to rts(mask): state: %u, rx_psn: %u, tx_psn: %u",
		mask.bs.state, mask.bs.rx_psn, mask.bs.tx_psn);
	ubcore_log_info("restore tp to rts(attr): state: %u, rx_psn: %u, tx_psn: %u",
		(uint32_t)attr.state, attr.rx_psn, attr.tx_psn);

	if (ubcore_modify_tp_state(dev, tp, UBCORE_TP_STATE_RTS, &attr, mask) != 0)
		return -1;

	tp->rx_psn = rx_psn;
	tp->tx_psn = tx_psn;

	return 0;
}

int ubcore_restore_tp_error_to_rtr(struct ubcore_device *dev, struct ubcore_tp *tp,
	uint32_t rx_psn, uint32_t tx_psn, uint16_t data_udp_start, uint16_t ack_udp_start)
{
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;

	mask.value = 0;
	mask.bs.state = 1;
	mask.bs.rx_psn = 1;
	mask.bs.tx_psn = 1;
	mask.bs.data_udp_start = 1;
	mask.bs.ack_udp_start = 1;

	attr.state = UBCORE_TP_STATE_RTR;
	attr.rx_psn = rx_psn;
	attr.tx_psn = tx_psn;
	attr.data_udp_start = data_udp_start;
	attr.ack_udp_start = ack_udp_start;
	ubcore_log_info(
		"restore tp to rtr(mask): state: %u, rx_psn: %u, tx_psn: %u, data_udp: %u, ack_udp: %u",
		mask.bs.state, mask.bs.rx_psn, mask.bs.tx_psn,
		mask.bs.data_udp_start, mask.bs.ack_udp_start);
	ubcore_log_info(
		"restore tp to rtr(attr): state: %u, rx_psn: %u, tx_psn: %u, data_udp: %hu, ack_udp: %hu",
		(uint32_t)attr.state, attr.rx_psn, attr.tx_psn,
		attr.data_udp_start, attr.ack_udp_start);

	if (ubcore_modify_tp_state(dev, tp, UBCORE_TP_STATE_RTR, &attr, mask) != 0)
		return -1;

	tp->rx_psn = rx_psn;
	tp->tx_psn = tx_psn;
	tp->data_udp_start = data_udp_start;
	tp->ack_udp_start = ack_udp_start;

	return 0;
}

int ubcore_restore_tp_error_to_rts(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;

	mask.value = 0;
	mask.bs.state = 1;

	attr.state = UBCORE_TP_STATE_RTS;

	ubcore_log_info("restore tp to rts, state mask: %u state: %u",
		mask.bs.state, (uint32_t)attr.state);

	if (ubcore_modify_tp_state(dev, tp, UBCORE_TP_STATE_RTS, &attr, mask) != 0)
		return -1;

	return 0;
}

int ubcore_change_tp_to_err(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;

	mask.value = 0;
	mask.bs.state = 1;

	attr.state = UBCORE_TP_STATE_ERR;

	if (ubcore_modify_tp_state(dev, tp, UBCORE_TP_STATE_ERR, &attr, mask) != 0)
		return -1;

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
	if (!ubcore_have_tp_ops(dev) || tp == NULL ||
		dev->transport_type != UBCORE_TRANSPORT_IB || tp->flag.bs.target ||
		tp->priv == NULL || tp->trans_mode == UBCORE_TP_UM ||
		tp->state != UBCORE_TP_STATE_ERR)
		return;

	req_msg = ubcore_get_restore_tp_req(tp);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get restore tp req");
		return;
	}

	resp_msg = ubcore_nl_send_wait(dev, req_msg);
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

static struct ubcore_nlmsg *ubcore_get_tp_error_req(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	uint32_t payload_len = (uint32_t)sizeof(struct ubcore_tp_error_req);
	struct ubcore_tp_error_req *error_req;
	struct ubcore_nlmsg *req;

	req = ubcore_alloc_nlmsg(payload_len, &tp->local_eid, &tp->peer_eid);
	if (req == NULL)
		return NULL;

	req->transport_type = tp->ub_dev->transport_type;
	req->msg_type = UBCORE_NL_TP_ERROR_REQ;
	error_req = (struct ubcore_tp_error_req *)(void *)req->payload;
	error_req->tpgn = tp->tpg->tpgn;
	error_req->tpn = tp->tpn;
	error_req->data_udp_start = tp->data_udp_start;
	error_req->ack_udp_start = tp->ack_udp_start;
	error_req->tx_psn = tp->tx_psn;
	error_req->peer_tpn = tp->peer_tpn;
	error_req->trans_mode = tp->trans_mode;
	error_req->sip_idx = tp->local_net_addr_idx;
	error_req->local_eid = tp->local_eid;
	error_req->peer_eid = tp->peer_eid;
	ubcore_log_info("report tp error: tx_psn: %u, data_udp: %hu, ack_udp: %hu",
		tp->tx_psn, tp->data_udp_start, tp->ack_udp_start);
	if (tp->trans_mode == UBCORE_TP_RC) {
		error_req->local_jetty_id = tp->local_jetty.id;
		error_req->peer_jetty_id = tp->peer_jetty.id;
	}
	(void)memcpy(error_req->tpf_dev_name, dev->dev_name,
		UBCORE_MAX_DEV_NAME);

	return req;
}

void ubcore_report_tp_error(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	struct ubcore_nlmsg *req_msg;
	int ret;

	if (tp->state != UBCORE_TP_STATE_RESET) {
		if (ubcore_change_tp_to_err(dev, tp) != 0) {
			ubcore_log_err("Failed to change tp to err");
			return;
		}

		if (ubcore_restore_tp_to_reset(dev, tp) != 0) {
			ubcore_log_err("Failed to restore tp to reset");
			return;
		}
	}

	req_msg = ubcore_get_tp_error_req(dev, tp);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get tp error req");
		return;
	}

	ret = ubcore_nl_send_nowait_without_cb(req_msg);
	if (ret)
		ubcore_log_err("Failed to nowait send tp error request");
	else
		ubcore_log_info("Success to nowait send tp error request");

	kfree(req_msg);
}

static struct ubcore_nlmsg *ubcore_get_tp_suspend_req(struct ubcore_device *dev,
	struct ubcore_tp *tp)
{
	uint32_t payload_len = (uint32_t)sizeof(struct ubcore_tp_suspend_req);
	struct ubcore_tp_suspend_req *suspend_req;
	struct ubcore_nlmsg *req;

	req = ubcore_alloc_nlmsg(payload_len, &tp->local_eid, &tp->peer_eid);
	if (req == NULL)
		return NULL;

	req->transport_type = tp->ub_dev->transport_type;
	req->msg_type = UBCORE_NL_TP_SUSPEND_REQ;
	suspend_req = (struct ubcore_tp_suspend_req *)(void *)req->payload;
	suspend_req->tpgn = tp->tpg->tpgn;
	suspend_req->tpn = tp->tpn;
	suspend_req->data_udp_start = tp->data_udp_start;
	suspend_req->ack_udp_start = tp->ack_udp_start;
	suspend_req->sip_idx = tp->local_net_addr_idx;
	ubcore_log_info("report tp suspend: data_udp_start: %hu, ack_udp_start: %hu",
		tp->data_udp_start, tp->ack_udp_start);
	(void)memcpy(suspend_req->tpf_dev_name, dev->dev_name,
		UBCORE_MAX_DEV_NAME);

	return req;
}

void ubcore_report_tp_suspend(struct ubcore_device *dev, struct ubcore_tp *tp)
{
	struct ubcore_nlmsg *req_msg;
	int ret;

	req_msg = ubcore_get_tp_suspend_req(dev, tp);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get tp suspend req");
		return;
	}

	ret = ubcore_nl_send_nowait_without_cb(req_msg);
	if (ret)
		ubcore_log_err("Failed to nowait send tp suspend request");
	else
		ubcore_log_info("Success to nowait send tp suspend request");

	kfree(req_msg);
}

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
		ubcore_log_err("Failed to parse ta with type %u", (uint32_t)restore->ta.ta_type);
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
	if (dev->transport_type != UBCORE_TRANSPORT_IB ||
	    restore == NULL || restore->trans_mode == UBCORE_TP_UM ||
	    restore->ta.ta_type == UBCORE_TA_NONE || restore->ta.ta_type >= UBCORE_TA_VIRT)
		return NULL;

	if (restore->trans_mode == UBCORE_TP_RM)
		return ubcore_restore_advised_target_tp(dev, restore);
	else
		return ubcore_restore_bound_target_tp(dev, restore);
}

struct ubcore_nlmsg *ubcore_handle_restore_tp_req(struct ubcore_nlmsg *req)
{
	struct ubcore_nl_restore_tp_req *restore;
	struct ubcore_device *dev;
	struct ubcore_tp *tp;

	if (req == NULL || req->payload_len != sizeof(struct ubcore_nl_restore_tp_req)) {
		ubcore_log_err("Invalid restore req");
		return NULL;
	}

	restore = (struct ubcore_nl_restore_tp_req *)(void *)req->payload;
	dev = ubcore_find_device(&req->dst_eid, req->transport_type);
	if (!ubcore_have_tp_ops(dev)) {
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
