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
 * Description: ubcore vtp implementation
 * Author: Yan Fangfang
 * Create: 2023-07-14
 * Note:
 * History: 2023-07-14: Create file
 */

#include <linux/slab.h>
#include "ubcore_msg.h"
#include "ubcore_log.h"
#include "ubcore_hash_table.h"
#include "ubcore_priv.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_netdev.h"
#include "ubcore_vtp.h"

static int ubcore_handle_create_vtp_resp(struct ubcore_device *dev,
	struct ubcore_resp *resp, void *user_arg)
{
	struct ubcore_create_vtp_resp *vtp_resp = (struct ubcore_create_vtp_resp *)resp->data;
	struct ubcore_vtpn *vtpn = (struct ubcore_vtpn *)user_arg;

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
	/* tpf may return a new vtpn */
	vtpn->vtpn = vtp_resp->vtpn;
	atomic_set(&vtpn->state, (int)UBCORE_VTPS_READY);
	return 0;
}

static int ubcore_send_create_vtp_req(struct ubcore_device *dev,
	struct ubcore_vtp_param *p, struct ubcore_vtpn *vtpn)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_create_vtp_req);
	struct ubcore_create_vtp_req *create;
	struct ubcore_req *req;
	struct ubcore_resp_cb cb;
	int ret;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return -ENOMEM;
	req->opcode = UBCORE_MSG_CREATE_VTP;
	req->len = data_len;

	create = (struct ubcore_create_vtp_req *)req->data;
	create->vtpn = vtpn->vtpn;
	create->trans_mode = p->trans_mode;
	create->local_eid = p->local_eid;
	create->peer_eid = p->peer_eid;
	create->eid_index = p->eid_index;
	create->local_jetty = p->local_jetty;
	create->peer_jetty = p->peer_jetty;
	(void)strcpy(create->dev_name, dev->dev_name);
	create->virtualization = dev->attr.virtualization;

	cb.callback = ubcore_handle_create_vtp_resp;
	cb.user_arg = vtpn;
	ret = ubcore_send_fe2tpf_msg(dev, req, &cb);
	kfree(req);
	return ret;
}

static int ubcore_handle_del_vtp_resp(struct ubcore_device *dev,
	struct ubcore_resp *resp, void *user_arg)
{
	struct ubcore_destroy_vtp_resp *vtp_resp = (struct ubcore_destroy_vtp_resp *)resp->data;
	struct ubcore_vtpn *vtpn = (struct ubcore_vtpn *)user_arg;

	if (vtp_resp->ret == UBCORE_MSG_RESP_FAIL) {
		ubcore_log_err("failed to destroy vtp: response error");
		return -1;
	} else if (vtp_resp->ret == UBCORE_MSG_RESP_IN_PROGRESS) {
		ubcore_log_err("failed: try to del vtp which is being created. Try again later");
		return -1;
	}
	atomic_set(&vtpn->state, (int)UBCORE_VTPS_DELETED);
	return 0;
}

static int ubcore_send_del_vtp_req(struct ubcore_vtpn *vtpn)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_create_vtp_req);
	struct ubcore_create_vtp_req *destroy;
	struct ubcore_req *req;
	struct ubcore_resp_cb cb;
	int ret;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return -ENOMEM;
	req->opcode = UBCORE_MSG_DESTROY_VTP;
	req->len = data_len;

	destroy = (struct ubcore_create_vtp_req *)req->data;
	destroy->vtpn = vtpn->vtpn;
	destroy->trans_mode = vtpn->trans_mode;
	destroy->local_eid = vtpn->local_eid;
	destroy->peer_eid = vtpn->peer_eid;
	destroy->eid_index = vtpn->eid_index;
	destroy->local_jetty = vtpn->local_jetty;
	destroy->peer_jetty = vtpn->peer_jetty;
	(void)memcpy(destroy->dev_name, vtpn->ub_dev->dev_name, UBCORE_MAX_DEV_NAME);
	destroy->virtualization = vtpn->ub_dev->attr.virtualization;

	cb.callback = ubcore_handle_del_vtp_resp;
	cb.user_arg = vtpn;
	ret = ubcore_send_fe2tpf_msg(vtpn->ub_dev, req, &cb);
	kfree(req);
	return ret;
}

static struct ubcore_vtpn *ubcore_alloc_vtpn(struct ubcore_device *dev,
	struct ubcore_vtp_param *param)
{
	struct ubcore_vtpn *vtpn;

	if (dev->ops == NULL || dev->ops->alloc_vtpn == NULL)
		return NULL;

	vtpn = dev->ops->alloc_vtpn(dev);
	if (vtpn == NULL) {
		ubcore_log_err("failed to alloc vtpn!, dev_name:%s", dev->dev_name);
		return NULL;
	}

	vtpn->ub_dev = dev;
	atomic_set(&vtpn->use_cnt, 1);
	atomic_set(&vtpn->state, (int)UBCORE_VTPS_CREATING);
	vtpn->trans_mode = param->trans_mode;
	vtpn->local_eid = param->local_eid;
	vtpn->peer_eid = param->peer_eid;
	vtpn->eid_index = param->eid_index;
	vtpn->local_jetty = param->local_jetty;
	vtpn->peer_jetty = param->peer_jetty;
	return vtpn;
}

static int ubcore_free_vtpn(struct ubcore_vtpn *vtpn)
{
	struct ubcore_device *dev = vtpn->ub_dev;

	if (dev == NULL || dev->ops == NULL || dev->ops->free_vtpn == NULL) {
		ubcore_log_err("dev == NULL || dev->ops == NULL || dev->ops->free_vtpn == NULL");
		return -EINVAL;
	}

	if (atomic_dec_return(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
			vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		return 0;
	}
	atomic_set(&vtpn->state, (int)UBCORE_VTPS_DELETED);

	return dev->ops->free_vtpn(vtpn);
}

static int ubcore_find_add_vtpn(struct ubcore_device *dev,
	struct ubcore_vtpn *new_vtpn, struct ubcore_vtpn **exist_vtpn)
{
	struct ubcore_hash_table *ht;

	ht = &dev->ht[UBCORE_HT_VTPN];
	if (ht->head == NULL) {
		ubcore_log_err("hash table's head equals NULL");
		return -EINVAL;
	}

	*exist_vtpn = ubcore_hash_table_lookup_nolock(ht,
		ubcore_get_vtpn_hash(&new_vtpn->trans_mode), &new_vtpn->trans_mode);
	if (*exist_vtpn != NULL)
		return -EEXIST;

	ubcore_hash_table_add_nolock(ht, &new_vtpn->hnode,
		ubcore_get_vtpn_hash(&new_vtpn->trans_mode));

	return 0;
}

static struct ubcore_vtpn *ubcore_connect_rm_um_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_param *param)
{
	struct ubcore_vtpn *exist_vtpn;
	struct ubcore_hash_table *ht;
	struct ubcore_vtpn *new_vtpn;
	struct ubcore_vtpn *old_vtpn;
	int ret;

	ht = &dev->ht[UBCORE_HT_VTPN];
	/* reuse */

	spin_lock(&ht->lock);
	old_vtpn = ubcore_hash_table_lookup_nolock(ht, ubcore_get_vtpn_hash(&param->trans_mode),
		&param->trans_mode);
	if (old_vtpn != NULL && atomic_read(&old_vtpn->state) == (int)UBCORE_VTPS_READY) {
		atomic_inc(&old_vtpn->use_cnt);
		ubcore_log_info("reuse vtpn, with vtpn id = %u, use cnt = %d",
			old_vtpn->vtpn, atomic_read(&old_vtpn->use_cnt));
		spin_unlock(&ht->lock);
		return old_vtpn;
	} else if (old_vtpn != NULL && atomic_read(&old_vtpn->state) == (int)UBCORE_VTPS_CREATING) {
		ubcore_log_info("vtpn is already in the list but its creation hasn't completed yet");
		spin_unlock(&ht->lock);
		return NULL;
	}

	if (old_vtpn != NULL)
		ubcore_log_warn("found existed vtpn state = %u and use_cnt = %u",
			(uint32_t)atomic_read(&old_vtpn->state),
			(uint32_t)atomic_read(&old_vtpn->use_cnt));

	new_vtpn = ubcore_alloc_vtpn(dev, param);
	if (new_vtpn == NULL) {
		ubcore_log_err("failed to alloc vtpn!");
		spin_unlock(&ht->lock);
		return NULL;
	}

	/* Conncurrency: only one thread can add vtpn to table successfully */
	ret = ubcore_find_add_vtpn(dev, new_vtpn, &exist_vtpn);
	if (ret == -EINVAL) {
		(void)ubcore_free_vtpn(new_vtpn);
		new_vtpn = NULL;
		spin_unlock(&ht->lock);
		return NULL;
	} else if (ret == -EEXIST) {
		(void)ubcore_free_vtpn(new_vtpn);
		new_vtpn = NULL;

		if (atomic_read(&exist_vtpn->state) == (int)UBCORE_VTPS_READY) {
			atomic_inc(&exist_vtpn->use_cnt);
			ubcore_log_info("success to reuse the vtpn %u, it is ready, reuse cnt %d",
				exist_vtpn->vtpn, atomic_read(&exist_vtpn->use_cnt));
		} else {
			exist_vtpn = NULL;
			ubcore_log_err("failed to reuse the vtpn, it is not ready");
		}

		spin_unlock(&ht->lock);
		return exist_vtpn;
	}

	/* TODO: port_idx use 0, for now tp_cnt = 1 */
	if (ubcore_check_port_state(dev, 0) != 0 ||
		ubcore_send_create_vtp_req(dev, param, new_vtpn) != 0) {
		ubcore_hash_table_remove_nolock(ht, &new_vtpn->hnode);
		(void)ubcore_free_vtpn(new_vtpn);
		ubcore_log_err("failed to send create vtp req");
		spin_unlock(&ht->lock);
		return NULL;
	}
	spin_unlock(&ht->lock);

	return new_vtpn;
}

struct ubcore_vtpn *ubcore_connect_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_param *param)
{
	struct ubcore_vtpn *vtpn;

	if (dev == NULL || param == NULL) {
		ubcore_log_err("Invalid param");
		return NULL;
	}

	if (param->trans_mode == UBCORE_TP_RM || param->trans_mode == UBCORE_TP_UM)
		return ubcore_connect_rm_um_vtp(dev, param);

	vtpn = ubcore_alloc_vtpn(dev, param);
	if (vtpn == NULL)
		return NULL;

	if (ubcore_check_port_state(dev, 0) != 0 || ubcore_send_create_vtp_req(dev, param, vtpn)) {
		(void)ubcore_free_vtpn(vtpn);
		ubcore_log_err("failed to send create vtp req");
		return NULL;
	}
	return vtpn;
}

static int ubcore_disconnect_rm_um_vtp(struct ubcore_vtpn *vtpn)
{
	struct ubcore_device *dev = vtpn->ub_dev;
	int ret;

	if (vtpn->ub_dev == NULL)
		return -EINVAL;

	if (atomic_dec_return(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
			vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		return 0;
	}

	if (atomic_read(&vtpn->state) != UBCORE_VTPS_READY) {
		ubcore_log_err("vtpn state is not in ready state, it is in %d state",
			atomic_read(&vtpn->state));
		return -1;
	}
	atomic_set(&vtpn->state, (int)UBCORE_VTPS_DELETING);

	ret = ubcore_send_del_vtp_req(vtpn);
	if (ret != 0) {
		ubcore_log_err("failed to send del vtp req");
		atomic_set(&vtpn->state, (int)UBCORE_VTPS_READY);
		return ret;
	}

	ubcore_hash_table_remove(&dev->ht[UBCORE_HT_VTPN], &vtpn->hnode);

	ret = ubcore_free_vtpn(vtpn);
	if (ret != 0) {
		ubcore_hash_table_add(&vtpn->ub_dev->ht[UBCORE_HT_VTPN], &vtpn->hnode,
			ubcore_get_vtpn_hash(&vtpn->trans_mode));
		ubcore_log_err("failed to free vtp");
		/* TODO roll back, start connect_vtp process again */
		return ret;
	}

	return 0;
}

int ubcore_disconnect_vtp(struct ubcore_vtpn *vtpn)
{
	int ret;

	if (vtpn == NULL) {
		ubcore_log_err("vtp has been deleted\n");
		return -1;
	}

	if (vtpn->trans_mode == UBCORE_TP_RM || vtpn->trans_mode == UBCORE_TP_UM)
		return ubcore_disconnect_rm_um_vtp(vtpn);

	ret = ubcore_send_del_vtp_req(vtpn);
	if (ret != 0) {
		ubcore_log_err("failed to send del vtp req");
		return ret;
	}

	ret = ubcore_free_vtpn(vtpn);
	if (ret != 0) {
		ubcore_log_err("failed to free vtp");
		return ret;
	}

	return 0;
}

static int ubcore_find_add_vtp(struct ubcore_device *dev,
	enum ubcore_transport_mode mode, struct ubcore_vtp *vtp)
{
	int ret;

	switch (mode) {
	case UBCORE_TP_RM:
		ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_RM_VTP], &vtp->hnode,
			ubcore_get_vtp_hash(&vtp->cfg.local_eid));
		break;
	case UBCORE_TP_RC:
		ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_RC_VTP], &vtp->hnode,
			ubcore_get_rc_vtp_hash(&vtp->cfg.peer_eid));
		break;
	case UBCORE_TP_UM:
		ret = ubcore_hash_table_find_add(&dev->ht[UBCORE_HT_UM_VTP], &vtp->hnode,
			ubcore_get_vtp_hash(&vtp->cfg.local_eid));
		break;
	default:
		ubcore_log_err("unknown mode");
		ret = -EINVAL;
		break;
	}

	return ret;
}

struct ubcore_vtp *ubcore_map_vtp(struct ubcore_device *dev, struct ubcore_vtp_cfg *cfg)
{
	struct ubcore_vtp *vtp;
	int ret;

	if (dev->ops == NULL || dev->ops->create_vtp == NULL)
		return NULL;

	vtp = dev->ops->create_vtp(dev, cfg, NULL);
	if (vtp == NULL) {
		ubcore_log_err("Failed to create vtp");
		return NULL;
	}

	vtp->ub_dev = dev;

	ret = ubcore_find_add_vtp(dev, cfg->trans_mode, vtp);
	if (ret != 0) {
		(void)dev->ops->destroy_vtp(vtp);
		vtp = NULL;
		ubcore_log_err("Failed to add vtp to the vtp table");
		return vtp;
	}

	if (cfg->flag.bs.clan_tp) {
		atomic_inc(&cfg->ctp->use_cnt);
	} else {
		if (cfg->trans_mode != UBCORE_TP_UM)
			atomic_inc(&cfg->tpg->use_cnt);
		else
			atomic_inc(&cfg->utp->use_cnt);
	}

	return vtp;
}

static void ubcore_remove_vtp(struct ubcore_device *dev,
	enum ubcore_transport_mode mode, struct ubcore_vtp *vtp)
{
	switch (mode) {
	case UBCORE_TP_RM:
		ubcore_hash_table_remove(&dev->ht[UBCORE_HT_RM_VTP], &vtp->hnode);
		break;
	case UBCORE_TP_RC:
		ubcore_hash_table_remove(&dev->ht[UBCORE_HT_RC_VTP], &vtp->hnode);
		break;
	case UBCORE_TP_UM:
		ubcore_hash_table_remove(&dev->ht[UBCORE_HT_UM_VTP], &vtp->hnode);
		break;
	default:
		ubcore_log_err("unknown mode");
		break;
	}
}

int ubcore_unmap_vtp(struct ubcore_vtp *vtp)
{
	struct ubcore_device *dev = vtp->ub_dev;
	struct ubcore_vtp_cfg cfg;
	int ret = 0;

	if (vtp == NULL || dev == NULL || dev->ops == NULL || dev->ops->destroy_vtp == NULL)
		return -EINVAL;

	cfg = vtp->cfg;

	ubcore_remove_vtp(dev, cfg.trans_mode, vtp);

	if (vtp->cfg.vtpn == UINT_MAX)
		kfree(vtp);
	else
		ret = dev->ops->destroy_vtp(vtp);
	if (ret != 0) {
		(void)ubcore_find_add_vtp(dev, cfg.trans_mode, vtp);
		ubcore_log_err("Failed to destroy vtp");
		return ret;
	}

	if (cfg.flag.bs.clan_tp) {
		atomic_dec(&cfg.ctp->use_cnt);
	} else {
		if (cfg.trans_mode != UBCORE_TP_UM)
			atomic_dec(&cfg.tpg->use_cnt);
		else
			atomic_dec(&cfg.utp->use_cnt);
	}

	return ret;
}

int ubcore_check_and_unmap_vtp(struct ubcore_vtp *vtp, uint32_t role)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_vtp *new_vtp = NULL;
	struct ubcore_vtp_cfg cfg;
	int ret = 0;

	if (vtp == NULL || vtp->ub_dev == NULL || vtp->ub_dev->ops == NULL ||
		vtp->ub_dev->ops->destroy_vtp == NULL)
		return -EINVAL;

	dev = vtp->ub_dev;

	if (vtp->role != UBCORE_VTP_DUPLEX)
		return ubcore_unmap_vtp(vtp);

	cfg = vtp->cfg;

	if (role == UBCORE_VTP_INITIATOR) {
		// delete original vtp, create pseudo vtp
		new_vtp = kcalloc(1, sizeof(struct ubcore_vtp), GFP_KERNEL);
		if (new_vtp == NULL)
			return -ENOMEM;

		new_vtp->ub_dev = dev;
		new_vtp->role = UBCORE_VTP_TARGET;
		(void)memcpy(&new_vtp->cfg, &vtp->cfg, sizeof(struct ubcore_vtp_cfg));

		ubcore_remove_vtp(dev, cfg.trans_mode, vtp);
		ret = dev->ops->destroy_vtp(vtp);
		if (ret != 0) {
			(void)ubcore_find_add_vtp(dev, cfg.trans_mode, vtp);
			kfree(new_vtp);
			ubcore_log_err("Failed to destroy vtp");
			return ret;
		}

		ret = ubcore_find_add_vtp(dev, new_vtp->cfg.trans_mode, new_vtp);
		if (ret != 0) {
			kfree(new_vtp);
			if (cfg.flag.bs.clan_tp) {
				atomic_dec(&cfg.ctp->use_cnt);
			} else {
				if (cfg.trans_mode != UBCORE_TP_UM)
					atomic_dec(&cfg.tpg->use_cnt);
				else
					atomic_dec(&cfg.utp->use_cnt);
			}
			ubcore_log_err("Failed to add new vtp to the vtp table");
			return -1;
		}
	} else {
		vtp->role = UBCORE_VTP_INITIATOR;
	}

	return ret;
}

struct ubcore_vtp *ubcore_find_vtp(struct ubcore_device *dev,
	enum ubcore_transport_mode mode, union ubcore_eid *local_eid, union ubcore_eid *peer_eid)
{
	struct ubcore_vtp *vtp_entry;

	switch (mode) {
	case UBCORE_TP_RM:
		vtp_entry = ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_RM_VTP],
			ubcore_get_vtp_hash(local_eid), local_eid);
		break;
	case UBCORE_TP_RC:
		vtp_entry = ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_RC_VTP],
			ubcore_get_rc_vtp_hash(peer_eid), peer_eid);
		break;
	case UBCORE_TP_UM:
		vtp_entry = ubcore_hash_table_lookup(&dev->ht[UBCORE_HT_UM_VTP],
			ubcore_get_vtp_hash(local_eid), local_eid);
		break;
	default:
		ubcore_log_err("unknown mode");
		vtp_entry = NULL;
	}
	return vtp_entry;
}

void ubcore_set_vtp_param(struct ubcore_device *dev, struct ubcore_jetty *jetty,
	struct ubcore_tjetty_cfg *cfg, struct ubcore_vtp_param *vtp_param)
{
	if (cfg->eid_index >= dev->eid_table.eid_cnt) {
		ubcore_log_err("invalid param, eid_index[%u] >= eid_cnt[%u]",
			cfg->eid_index, dev->eid_table.eid_cnt);
		return;
	}

	vtp_param->trans_mode = cfg->trans_mode;
	/*
	 * RM/UM VTP for userspace app: get local eid from ucontext
	 * RM/UM VTP for kernel app: how to get local eid ?
	 * RC VTP: get eid from jetty
	 */
	vtp_param->local_eid = dev->eid_table.eid_entries[cfg->eid_index].eid;
	vtp_param->peer_eid = cfg->id.eid;
	if (jetty != NULL)
		vtp_param->local_jetty = jetty->id;
	else
		vtp_param->local_jetty = 0;

	vtp_param->peer_jetty = cfg->id.id;
	vtp_param->eid_index = cfg->eid_index;
}

int ubcore_config_function_migrate_state(struct ubcore_device *dev, uint16_t fe_idx,
	uint32_t cnt, struct ubcore_ueid_cfg *cfg, enum ubcore_mig_state state)
{
	int ret;

	if (cfg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("ubcore ueid cfg is null");
		return ret;
	}

	if (dev == NULL || dev->ops == NULL || dev->ops->config_function_migrate_state == NULL) {
		ret = -EINVAL;
		ubcore_log_err("invalid param");
		return ret;
	}

	ret = dev->ops->config_function_migrate_state(dev, fe_idx, cnt, cfg, state);
	if (ret < 0)
		ubcore_log_err("Fail to config function migrate state");

	return ret;
}

int ubcore_modify_vtp(struct ubcore_device *dev, struct ubcore_vtp_param *vtp_param,
	struct ubcore_vtp_attr *vattr, union ubcore_vtp_attr_mask *vattr_mask)
{
	struct ubcore_vtp *vtp;
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->modify_vtp == NULL) {
		ret = -EINVAL;
		ubcore_log_err("invalid param");
		return ret;
	}

	vtp = ubcore_find_vtp(dev, vtp_param->trans_mode,
		&vtp_param->local_eid, &vtp_param->peer_eid);
	if (vtp == NULL) {
		ubcore_log_err("Fail to find vtp when modify vtp");
		return -EINVAL;
	}

	ret = dev->ops->modify_vtp(vtp, vattr, vattr_mask);
	if (ret != 0) {
		ubcore_log_err("Fail to modify vtp when call ubcore ops");
		return -EINVAL;
	}

	return 0;
}

struct ubcore_vtp *ubcore_check_and_map_vtp(struct ubcore_device *dev, struct ubcore_vtp_cfg *cfg,
	uint32_t role)
{
	uint32_t vtp_role = role;
	struct ubcore_vtp *vtp;
	int ret;

	if (dev->ops == NULL || dev->ops->create_vtp == NULL)
		return NULL;

	vtp = ubcore_find_vtp(dev, cfg->trans_mode, &cfg->local_eid, &cfg->peer_eid);
	if (vtp != NULL) {
		ubcore_log_info("vtp already exists");
		if (vtp->cfg.vtpn == UINT_MAX) { // only this may happen
			vtp_role = (role == vtp->role) ? role : UBCORE_VTP_DUPLEX;
			// delete original vtp
			ubcore_log_info("vtpn is UINT_MAX, delete old one");
			ubcore_remove_vtp(dev, cfg->trans_mode, vtp);
			kfree(vtp);
		} else { // this should never happen
			if (cfg->vtpn != UINT_MAX) {
				ubcore_log_warn("origin vtpn is not UINT_MAX, input vtpn is not UINT_MAX");
				return vtp;
			}
			ubcore_log_warn("origin vtpn is not UINT_MAX, input vtpn is UINT_MAX");
			return NULL;
		}
	}

	vtp = dev->ops->create_vtp(dev, cfg, NULL);
	if (vtp == NULL) {
		ubcore_log_err("Failed to create vtp");
		return NULL;
	}

	vtp->ub_dev = dev;
	vtp->role = vtp_role;

	ret = ubcore_find_add_vtp(dev, cfg->trans_mode, vtp);
	if (ret != 0) {
		(void)dev->ops->destroy_vtp(vtp);
		vtp = NULL;
		ubcore_log_err("Failed to add vtp to the vtp table");
		return vtp;
	}

	if (cfg->flag.bs.clan_tp) {
		atomic_inc(&cfg->ctp->use_cnt);
	} else {
		if (cfg->trans_mode != UBCORE_TP_UM)
			atomic_inc(&cfg->tpg->use_cnt);
		else
			atomic_inc(&cfg->utp->use_cnt);
	}

	return vtp;
}

struct ubcore_vtp *ubcore_check_and_map_target_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_cfg *cfg)
{
	struct ubcore_vtp *vtp = NULL;
	int ret;

	vtp = ubcore_find_vtp(dev, cfg->trans_mode, &cfg->local_eid, &cfg->peer_eid);
	if (vtp != NULL)
		return vtp;

	vtp = kcalloc(1, sizeof(struct ubcore_vtp), GFP_KERNEL);
	if (vtp == NULL)
		return NULL;

	vtp->ub_dev = dev;
	(void)memcpy(&vtp->cfg, cfg, sizeof(struct ubcore_vtp_cfg));

	ret = ubcore_find_add_vtp(dev, cfg->trans_mode, vtp);
	if (ret != 0) {
		kfree(vtp);
		vtp = NULL;
		ubcore_log_err("Failed to add vtp to the vtp table");
		return vtp;
	}

	if (cfg->flag.bs.clan_tp) {
		atomic_inc(&cfg->ctp->use_cnt);
	} else {
		if (cfg->trans_mode != UBCORE_TP_UM)
			atomic_inc(&cfg->tpg->use_cnt);
		else
			atomic_inc(&cfg->utp->use_cnt);
	}

	return vtp;
}

uint32_t ubcore_get_all_vtp_cnt(struct ubcore_hash_table *ht)
{
	struct ubcore_vtp *vtp;
	uint32_t cnt = 0;
	uint32_t i = 0;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return cnt;
	}

	for (; i < ht->p.size; i++) {
		hlist_for_each_entry(vtp, &ht->head[i], hnode) {
			++cnt;
		}
	}

	spin_unlock(&ht->lock);
	return cnt;
}

struct ubcore_vtp **ubcore_get_all_vtp(struct ubcore_hash_table *ht,
	uint32_t *dev_vtp_cnt)
{
	struct ubcore_vtp **vtp_entry;
	struct ubcore_vtp *vtp;
	uint32_t i = 0, j = 0;

	*dev_vtp_cnt = ubcore_get_all_vtp_cnt(ht);
	vtp_entry = kcalloc(1, (*dev_vtp_cnt) * (uint32_t)sizeof(struct ubcore_vtp *), GFP_KERNEL);
	if (vtp_entry == NULL)
		return NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return NULL;
	}

	for (; i < ht->p.size; i++) {
		hlist_for_each_entry(vtp, &ht->head[i], hnode) {
			vtp_entry[j++] = vtp;
		}
	}

	spin_unlock(&ht->lock);
	return vtp_entry;
}
