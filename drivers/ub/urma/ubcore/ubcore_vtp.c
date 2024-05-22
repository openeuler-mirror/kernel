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
#include "ubcore_tpg.h"
#include "ubcore_utp.h"
#include "ubcore_vtp.h"

static int ubcore_handle_create_vtp_resp(struct ubcore_device *dev,
	struct ubcore_resp *resp, void *user_arg)
{
	struct ubcore_create_vtp_resp *vtp_resp = (struct ubcore_create_vtp_resp *)resp->data;
	struct ubcore_vtpn *vtpn = (struct ubcore_vtpn *)user_arg;

	if (resp == NULL || resp->len < sizeof(struct ubcore_create_vtp_resp)) {
		ubcore_log_err("invalid ubcore_create_vtp_resp len");
		return (int)UBCORE_MSG_RESP_FAIL;
	}

	switch (vtp_resp->ret) {
	case UBCORE_MSG_RESP_FAIL:
		ubcore_log_err("failed to create vtp: response error.\n");
		break;
	case UBCORE_MSG_RESP_IN_PROGRESS:
		ubcore_log_err("failed: try to del vtp which is being created. Try again later.\n");
		break;
	case UBCORE_MSG_RESP_RC_JETTY_ALREADY_BIND:
		ubcore_log_err("failed: rc jetty already bind by other jetty.\n");
		break;
	case UBCORE_MSG_RESP_LIMIT_RATE:
		ubcore_log_err("failed: the current link setup speed has reached the maximum value.\n");
		break;
	case UBCORE_MSG_RESP_SUCCESS:
		/* tpf may return a new vtpn */
		vtpn->vtpn = vtp_resp->vtpn;
		break;
	default:
		ubcore_log_err("unknown the state of vtp reply to create.\n");
		break;
	}

	return vtp_resp->ret;
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
	create->sub_trans_mode = p->sub_trans_mode;
	create->rc_share_tp = p->rc_share_tp;
	create->trans_mode = p->trans_mode;
	create->local_eid = p->local_eid;
	create->peer_eid = p->peer_eid;
	create->eid_index = p->eid_index;
	create->local_jetty = p->local_jetty;
	create->peer_jetty = p->peer_jetty;
	(void)strncpy(create->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME - 1);
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

	if (resp == NULL || resp->len < sizeof(struct ubcore_destroy_vtp_resp)) {
		ubcore_log_err("invalid parameter");
		return (int)UBCORE_MSG_RESP_FAIL;
	}

	switch (vtp_resp->ret) {
	case UBCORE_MSG_RESP_SUCCESS:
		break;
	case UBCORE_MSG_RESP_FAIL:
		ubcore_log_err("failed to destroy vtp: response error");
		break;
	case UBCORE_MSG_RESP_IN_PROGRESS:
		ubcore_log_err("failed: try to del vtp which is being deleted. Try again later.\n");
		break;
	/* the status of the delete vtp reply is unknown */
	case UBCORE_MSG_RESP_RC_JETTY_ALREADY_BIND:
	case UBCORE_MSG_RESP_LIMIT_RATE:
	default:
		ubcore_log_err("failed: the state of vtp reply to del is unknown.\n");
		break;
	}

	return (int)vtp_resp->ret;
}

static int ubcore_send_del_vtp_req(struct ubcore_vtpn *vtpn, struct ubcore_vtp_param *param)
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
	if (param != NULL) {
		destroy->sub_trans_mode = param->sub_trans_mode;
		destroy->rc_share_tp = param->rc_share_tp;
	}
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
		return ERR_PTR(-EINVAL);

	vtpn = dev->ops->alloc_vtpn(dev);
	if (IS_ERR_OR_NULL(vtpn)) {
		ubcore_log_err("failed to alloc vtpn!, dev_name:%s", dev->dev_name);
		return UBCORE_CHECK_RETURN_ERR_PTR(vtpn, ENOEXEC);
	}

	vtpn->ub_dev = dev;
	atomic_set(&vtpn->use_cnt, 0);
	kref_init(&vtpn->ref_cnt);
	init_completion(&vtpn->comp);
	vtpn->trans_mode = param->trans_mode;
	vtpn->local_eid = param->local_eid;
	vtpn->peer_eid = param->peer_eid;
	vtpn->eid_index = param->eid_index;
	vtpn->local_jetty = param->local_jetty;
	vtpn->peer_jetty = param->peer_jetty;
	vtpn->state = UBCORE_VTPS_RESET;
	mutex_init(&vtpn->state_lock);
	return vtpn;
}

static void ubcore_vtpn_kref_release(struct kref *ref_cnt)
{
	struct ubcore_vtpn *vtpn = container_of(ref_cnt, struct ubcore_vtpn, ref_cnt);

	complete(&vtpn->comp);
}

static void ubcore_vtpn_kref_put(struct ubcore_vtpn *vtpn)
{
	(void)kref_put(&vtpn->ref_cnt, ubcore_vtpn_kref_release);
}

void ubcore_vtpn_get(void *obj)
{
	struct ubcore_vtpn *vtpn = obj;

	kref_get(&vtpn->ref_cnt);
}

static void ubcore_vtp_unmap_attr(struct ubcore_vtp_cfg *cfg)
{
	if (cfg->vtpn == UINT_MAX)
		return;

	if (cfg->flag.bs.clan_tp) {
		atomic_dec(&cfg->ctp->use_cnt);
		return;
	}
	if (cfg->trans_mode != UBCORE_TP_UM)
		ubcore_tpg_kref_put(cfg->tpg);
	else
		ubcore_utp_kref_put(cfg->utp);
}

static void ubcore_vtp_kref_release(struct kref *ref_cnt)
{
	struct ubcore_vtp *vtp = container_of(ref_cnt, struct ubcore_vtp, ref_cnt);
	struct ubcore_device *ub_dev = vtp->ub_dev;
	struct ubcore_vtp_cfg cfg = vtp->cfg;

	/* pseudo vtp */
	if (vtp->cfg.vtpn == UINT_MAX) {
		kfree(vtp);
		return;
	}
	if (ub_dev == NULL || ub_dev->ops == NULL || ub_dev->ops->destroy_vtp == NULL)
		return;
	ub_dev->ops->destroy_vtp(vtp);
	ubcore_vtp_unmap_attr(&cfg);
}

void ubcore_vtp_kref_put(struct ubcore_vtp *vtp)
{
	(void)kref_put(&vtp->ref_cnt, ubcore_vtp_kref_release);
}

void ubcore_vtp_get(void *obj)
{
	struct ubcore_vtp *vtp = obj;

	kref_get(&vtp->ref_cnt);
}

static int ubcore_free_vtpn(struct ubcore_vtpn *vtpn)
{
	struct ubcore_device *dev = vtpn->ub_dev;

	if (dev == NULL || dev->ops == NULL || dev->ops->free_vtpn == NULL) {
		ubcore_log_err("dev == NULL || dev->ops == NULL || dev->ops->free_vtpn == NULL");
		return -EINVAL;
	}

	if (atomic_read(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
			vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		return 0;
	}
	ubcore_vtpn_kref_put(vtpn);
	wait_for_completion(&vtpn->comp);
	mutex_destroy(&vtpn->state_lock);
	return dev->ops->free_vtpn(vtpn);
}

static struct ubcore_hash_table *ubcore_get_vtpn_ht(struct ubcore_device *dev,
	enum ubcore_transport_mode trans_mode, uint32_t sub_trans_mode,
	uint32_t rc_share_tp)
{
	if (trans_mode == UBCORE_TP_RM ||
		is_create_rc_shared_tp(trans_mode, sub_trans_mode, rc_share_tp))
		return &dev->ht[UBCORE_HT_RM_VTPN];

	if (trans_mode == UBCORE_TP_RC)
		return &dev->ht[UBCORE_HT_RC_VTPN];

	if (trans_mode == UBCORE_TP_UM)
		return &dev->ht[UBCORE_HT_UM_VTPN];

	return NULL;
}

static struct ubcore_vtpn *ubcore_find_get_vtpn(struct ubcore_device *dev,
	struct ubcore_vtp_param *param)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	ht = ubcore_get_vtpn_ht(dev, param->trans_mode, param->sub_trans_mode, param->rc_share_tp);
	if (ht == NULL)
		return NULL;

	hash = ubcore_get_vtpn_hash(ht, &param->local_eid);
	return ubcore_hash_table_lookup_get(ht, hash, &param->local_eid);
}

static int ubcore_find_add_vtpn(struct ubcore_device *dev, struct ubcore_vtpn *new_vtpn,
	struct ubcore_vtpn **exist_vtpn, struct ubcore_vtp_param *p)
{
	struct ubcore_hash_table *ht;
	uint32_t hash;

	ht = ubcore_get_vtpn_ht(dev, new_vtpn->trans_mode,
		p->sub_trans_mode, p->rc_share_tp);
	if (ht == NULL || ht->head == NULL) {
		ubcore_log_err("hash table's head equals NULL");
		return -EINVAL;
	}
	hash = ubcore_get_vtpn_hash(ht, &new_vtpn->local_eid);

	spin_lock(&ht->lock);
	*exist_vtpn = ubcore_hash_table_lookup_nolock_get(ht, hash, &new_vtpn->local_eid);
	if (*exist_vtpn != NULL) {
		spin_unlock(&ht->lock);
		return -EEXIST;
	}
	ubcore_hash_table_add_nolock(ht, &new_vtpn->hnode, hash);
	spin_unlock(&ht->lock);
	return 0;
}

void ubcore_hash_table_rmv_vtpn(struct ubcore_device *dev, struct ubcore_vtpn *vtpn,
	struct ubcore_vtp_param *param)
{
	struct ubcore_hash_table *ht;

	if (param != NULL)
		ht = ubcore_get_vtpn_ht(dev, vtpn->trans_mode,
			param->sub_trans_mode, param->rc_share_tp);
	else
		ht = ubcore_get_vtpn_ht(dev, vtpn->trans_mode, 0, 0);
	if (ht == NULL)
		return;
	ubcore_hash_table_remove(ht, &vtpn->hnode);
}

static struct ubcore_vtpn *ubcore_reuse_vtpn(struct ubcore_device *dev, struct ubcore_vtpn *vtpn)
{
	mutex_lock(&vtpn->state_lock);
	if (vtpn->state == UBCORE_VTPS_READY) {
		atomic_inc(&vtpn->use_cnt);
		mutex_unlock(&vtpn->state_lock);
		ubcore_log_info("Success to reuse vtpn:%u", vtpn->vtpn);
		ubcore_vtpn_kref_put(vtpn);
		return vtpn;
	}

	if (vtpn->state == UBCORE_VTPS_RESET) {
		mutex_unlock(&vtpn->state_lock);
		ubcore_log_warn("failed to reuse vtpn:%u, use_cnt:%d",
			vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		ubcore_vtpn_kref_put(vtpn);
		return NULL;
	}

	mutex_unlock(&vtpn->state_lock);
	ubcore_log_err("Unknown states, vtpn:%u, state:%d", vtpn->vtpn, (int)vtpn->state);
	ubcore_vtpn_kref_put(vtpn);
	return NULL;
}

struct ubcore_vtpn *ubcore_connect_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_param *param)
{
	struct ubcore_vtpn *exist_vtpn = NULL;
	struct ubcore_vtpn *vtpn;
	int ret;

	if (dev == NULL || param == NULL) {
		ubcore_log_err("Invalid param");
		return ERR_PTR(-EINVAL);
	}

	if (ubcore_check_port_state(dev) != 0) {
		ubcore_log_err("Check port status Failed");
		return NULL;
	}

	// 1. try to reuse vtpn
	vtpn = ubcore_find_get_vtpn(dev, param);
	if (vtpn != NULL)
		return ubcore_reuse_vtpn(dev, vtpn);

	// 2. alloc new vtpn
	vtpn = ubcore_alloc_vtpn(dev, param);
	if (IS_ERR_OR_NULL(vtpn)) {
		ubcore_log_err("failed to alloc vtpn!");
		return vtpn;
	}

	// 3. add vtpn to hashtable
	ret = ubcore_find_add_vtpn(dev, vtpn, &exist_vtpn, param);
	if (ret == -EEXIST && exist_vtpn != NULL) {
		exist_vtpn = ubcore_reuse_vtpn(dev, exist_vtpn);  // reuse immediately
		(void)ubcore_free_vtpn(vtpn);
		return exist_vtpn;
	} else if (ret != 0) {
		(void)ubcore_free_vtpn(vtpn);
		return NULL;
	}

	// 4. Send connecting msg
	mutex_lock(&vtpn->state_lock);
	ret = ubcore_send_create_vtp_req(dev, param, vtpn);
	if (ret == 0) {
		atomic_inc(&vtpn->use_cnt);
		vtpn->state = UBCORE_VTPS_READY;
	}
	mutex_unlock(&vtpn->state_lock);

	// 5. failed roll back
	if (ret != 0) {
		ubcore_log_err("failed to send create vtp req, vtpn:%u", vtpn->vtpn);
		ubcore_hash_table_rmv_vtpn(dev, vtpn, param);
		(void)ubcore_free_vtpn(vtpn);
		return ERR_PTR(ret);
	}

	ubcore_log_info("connect vtpn:%u", vtpn->vtpn);
	return vtpn;
}

int ubcore_disconnect_vtp(struct ubcore_vtpn *vtpn, struct ubcore_vtp_param *param)
{
	struct ubcore_device *dev;
	int ret = 0;

	if (vtpn == NULL || vtpn->ub_dev == NULL)
		return -EINVAL;

	dev = vtpn->ub_dev;
	if (atomic_dec_return(&vtpn->use_cnt) > 0) {
		ubcore_log_info("vtpn in use, vtpn id = %u, vtpn use_cnt = %d",
			vtpn->vtpn, atomic_read(&vtpn->use_cnt));
		return 0;
	}

	mutex_lock(&vtpn->state_lock);
	if (atomic_read(&vtpn->use_cnt) > 0) {
		mutex_unlock(&vtpn->state_lock);
		return 0;
	}
	if (vtpn->state == UBCORE_VTPS_READY) {
		ret = ubcore_send_del_vtp_req(vtpn, param);
		vtpn->state = UBCORE_VTPS_RESET;
	}
	mutex_unlock(&vtpn->state_lock);

	ubcore_log_info("disconnect vtpn:%u, ret:%d", vtpn->vtpn, ret);
	if (atomic_read(&vtpn->use_cnt) == 0) {
		ubcore_hash_table_rmv_vtpn(dev, vtpn, param);
		(void)ubcore_free_vtpn(vtpn);
	}

	return 0;
}

static int ubcore_find_add_vtp(struct ubcore_device *dev,
	enum ubcore_transport_mode mode, struct ubcore_vtp *vtp)
{
	struct ubcore_hash_table *ht = NULL;
	uint32_t hash;

	switch (mode) {
	case UBCORE_TP_RM:
		ht = &dev->ht[UBCORE_HT_RM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	case UBCORE_TP_RC:
		ht = &dev->ht[UBCORE_HT_RC_VTP];
		hash = ubcore_get_rc_vtp_hash(&vtp->cfg.peer_eid);
		break;
	case UBCORE_TP_UM:
		ht = &dev->ht[UBCORE_HT_UM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	default:
		ubcore_log_err("unknown mode");
		return -EINVAL;
	}
	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		return -1;
	}
	/* Old entry with the same key exists */
	if (ubcore_hash_table_lookup_nolock(ht, hash,
		ubcore_ht_key(ht, &vtp->hnode)) != NULL) {
		spin_unlock(&ht->lock);
		ubcore_log_warn("find vtp vtpn:%u hash :%u", vtp->cfg.vtpn, hash);
		return -1;
	}
	ubcore_hash_table_add_nolock(ht, &vtp->hnode, hash);
	ubcore_vtp_get(vtp);
	spin_unlock(&ht->lock);

	return 0;
}

static void ubcore_vtp_map_attr(struct ubcore_vtp *vtp, struct ubcore_vtp_cfg *cfg)
{
	vtp->cfg.fe_idx = cfg->fe_idx;
	vtp->cfg.local_jetty = cfg->local_jetty;
	vtp->cfg.local_eid = cfg->local_eid;
	vtp->cfg.peer_eid = cfg->peer_eid;
	vtp->cfg.peer_jetty = cfg->peer_jetty;
	vtp->cfg.flag = cfg->flag;
	vtp->cfg.trans_mode = cfg->trans_mode;

	if (cfg->flag.bs.clan_tp) {
		vtp->cfg.ctp = cfg->ctp;
		atomic_inc(&cfg->ctp->use_cnt);
		return;
	}
	if (cfg->trans_mode != UBCORE_TP_UM) {
		vtp->cfg.tpg = cfg->tpg;
		ubcore_tpg_get(cfg->tpg);
	} else {
		vtp->cfg.utp = cfg->utp;
		ubcore_utp_get(cfg->utp);
	}
}

struct ubcore_vtp *ubcore_create_and_map_vtp(struct ubcore_device *dev, struct ubcore_vtp_cfg *cfg)
{
	struct ubcore_vtp *vtp;
	int ret;

	if (dev->ops == NULL || dev->ops->create_vtp == NULL)
		return ERR_PTR(-EINVAL);

	vtp = dev->ops->create_vtp(dev, cfg, NULL);
	if (IS_ERR_OR_NULL(vtp)) {
		ubcore_log_err("Failed to create vtp");
		if (vtp == NULL)
			return ERR_PTR(-ENOEXEC);
		return vtp;
	}
	kref_init(&vtp->ref_cnt);

	vtp->ub_dev = dev;

	ret = ubcore_find_add_vtp(dev, cfg->trans_mode, vtp);
	if (ret != 0) {
		ubcore_vtp_kref_put(vtp);
		vtp = NULL;
		ubcore_log_err("Failed to add vtp to the vtp table");
		return ERR_PTR(-ENOEXEC);
	}
	ubcore_vtp_map_attr(vtp, cfg);

	return vtp;
}

static void ubcore_remove_vtp(struct ubcore_device *dev,
	enum ubcore_transport_mode mode, struct ubcore_vtp *vtp)
{
	struct ubcore_hash_table *ht = NULL;
	struct ubcore_vtp *find_vtp = NULL;
	uint32_t hash;

	switch (mode) {
	case UBCORE_TP_RM:
		ht = &dev->ht[UBCORE_HT_RM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	case UBCORE_TP_RC:
		ht = &dev->ht[UBCORE_HT_RC_VTP];
		hash = ubcore_get_rc_vtp_hash(&vtp->cfg.peer_eid);
		break;
	case UBCORE_TP_UM:
		ht = &dev->ht[UBCORE_HT_UM_VTP];
		hash = ubcore_get_vtp_hash(&vtp->cfg.local_eid);
		break;
	default:
		ubcore_log_err("unknown mode");
		return;
	}
	spin_lock(&ht->lock);
	find_vtp = ubcore_hash_table_lookup_nolock(ht, hash,
			ubcore_ht_key(ht, &vtp->hnode));
	if (find_vtp == NULL) {
		spin_unlock(&ht->lock);
		ubcore_log_warn("vtp:%d no find", vtp->cfg.vtpn);
		return;
	}
	ubcore_hash_table_remove_nolock(ht, &find_vtp->hnode);
	/* Pair with kref get in ubcore_find_add_vtp */
	ubcore_vtp_kref_put(find_vtp);
	spin_unlock(&ht->lock);
}

int ubcore_unmap_vtp(struct ubcore_vtp *vtp)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_vtp_cfg cfg;
	int ret = 0;

	if (vtp == NULL)
		return -EINVAL;

	dev = vtp->ub_dev;
	if (dev == NULL || dev->ops == NULL || dev->ops->destroy_vtp == NULL)
		return -EINVAL;

	cfg = vtp->cfg;

	ubcore_remove_vtp(dev, cfg.trans_mode, vtp);

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
		new_vtp->eid_idx = vtp->eid_idx;
		new_vtp->upi = vtp->upi;
		new_vtp->share_mode = vtp->share_mode;
		(void)memcpy(&new_vtp->cfg, &vtp->cfg, sizeof(struct ubcore_vtp_cfg));
		new_vtp->cfg.vtpn = UINT_MAX;
		kref_init(&new_vtp->ref_cnt);

		ubcore_remove_vtp(dev, cfg.trans_mode, vtp);

		ret = ubcore_find_add_vtp(dev, new_vtp->cfg.trans_mode, new_vtp);
		ubcore_vtp_kref_put(new_vtp);
		if (ret != 0) {
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
		ubcore_log_err("unknown mode %u", mode);
		vtp_entry = NULL;
	}
	return vtp_entry;
}

struct ubcore_vtp *ubcore_find_get_vtp(struct ubcore_device *dev,
	enum ubcore_transport_mode mode, union ubcore_eid *local_eid, union ubcore_eid *peer_eid)
{
	struct ubcore_vtp *vtp_entry;

	switch (mode) {
	case UBCORE_TP_RM:
		vtp_entry = ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_RM_VTP],
			ubcore_get_vtp_hash(local_eid), local_eid);
		break;
	case UBCORE_TP_RC:
		vtp_entry = ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_RC_VTP],
			ubcore_get_rc_vtp_hash(peer_eid), peer_eid);
		break;
	case UBCORE_TP_UM:
		vtp_entry = ubcore_hash_table_lookup_get(&dev->ht[UBCORE_HT_UM_VTP],
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
	if (cfg->eid_index >= dev->eid_table.eid_cnt ||
		IS_ERR_OR_NULL(dev->eid_table.eid_entries)) {
		ubcore_log_err("invalid param, eid_index[%u] >= eid_cnt[%u]",
			cfg->eid_index, dev->eid_table.eid_cnt);
		return;
	}

	vtp_param->trans_mode = cfg->trans_mode;
	vtp_param->sub_trans_mode = cfg->flag.bs.sub_trans_mode;
	vtp_param->rc_share_tp = cfg->flag.bs.rc_share_tp;
	/*
	 * RM/UM VTP for userspace app: get local eid from ucontext
	 * RM/UM VTP for kernel app: how to get local eid ?
	 * RC VTP: get eid from jetty
	 */
	vtp_param->local_eid = dev->eid_table.eid_entries[cfg->eid_index].eid;
	vtp_param->peer_eid = cfg->id.eid;
	if (jetty != NULL)
		vtp_param->local_jetty = jetty->jetty_id.id;
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

	vtp = ubcore_find_get_vtp(dev, vtp_param->trans_mode,
		&vtp_param->local_eid, &vtp_param->peer_eid);
	if (vtp == NULL) {
		ubcore_log_err("Fail to find vtp when modify vtp");
		return -EINVAL;
	}

	if (vtp->role != UBCORE_VTP_TARGET) { // switch to mig dest
		if (vtp_param->trans_mode == UBCORE_TP_UM)
			ubcore_utp_kref_put(vtp->cfg.utp);
		else
			ubcore_tpg_kref_put(vtp->cfg.tpg);
	}

	ret = dev->ops->modify_vtp(vtp, vattr, vattr_mask);
	ubcore_vtp_kref_put(vtp);
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

	vtp = ubcore_find_get_vtp(dev, cfg->trans_mode, &cfg->local_eid, &cfg->peer_eid);
	if (vtp != NULL) {
		ubcore_log_info("vtp already exists");
		if (vtp->cfg.vtpn == UINT_MAX) { // only this may happen
			vtp_role = (role == vtp->role) ? role : UBCORE_VTP_DUPLEX;
			// delete original vtp
			ubcore_remove_vtp(dev, cfg->trans_mode, vtp);
			ubcore_vtp_kref_put(vtp);
		} else { // this should never happen
			if (cfg->vtpn != UINT_MAX) {
				ubcore_log_warn("origin vtpn is not UINT_MAX, input vtpn is not UINT_MAX");
				return vtp;
			}
			ubcore_vtp_kref_put(vtp);
			ubcore_log_warn("origin vtpn is not UINT_MAX, input vtpn is UINT_MAX");
			return NULL;
		}
	}

	vtp = dev->ops->create_vtp(dev, cfg, NULL);
	if (vtp == NULL) {
		ubcore_log_err("Failed to create vtp");
		return NULL;
	}
	kref_init(&vtp->ref_cnt);
	vtp->ub_dev = dev;
	vtp->role = vtp_role;

	ret = ubcore_find_add_vtp(dev, cfg->trans_mode, vtp);
	if (ret != 0) {
		ubcore_vtp_kref_put(vtp);
		ubcore_log_err("Failed to add vtp to the vtp table");
		return NULL;
	}
	ubcore_vtp_map_attr(vtp, cfg);

	return vtp;
}

struct ubcore_vtp *ubcore_check_and_map_target_vtp(struct ubcore_device *dev,
	struct ubcore_vtp_cfg *cfg, uint32_t role)
{
	struct ubcore_vtp *vtp = NULL;
	int ret;

	vtp = ubcore_find_get_vtp(dev, cfg->trans_mode, &cfg->local_eid, &cfg->peer_eid);
	if (vtp != NULL)
		return vtp;

	vtp = kcalloc(1, sizeof(struct ubcore_vtp), GFP_KERNEL);
	if (vtp == NULL)
		return NULL;

	vtp->ub_dev = dev;
	(void)memcpy(&vtp->cfg, cfg, sizeof(struct ubcore_vtp_cfg));
	vtp->role = role;
	kref_init(&vtp->ref_cnt);

	ret = ubcore_find_add_vtp(dev, cfg->trans_mode, vtp);
	if (ret != 0) {
		ubcore_vtp_kref_put(vtp);
		ubcore_log_err("Failed to add vtp to the vtp table");
		return NULL;
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
	if (*dev_vtp_cnt == 0)
		return NULL;

	vtp_entry = kcalloc(1, (*dev_vtp_cnt) * (uint32_t)sizeof(struct ubcore_vtp *), GFP_KERNEL);
	if (vtp_entry == NULL)
		return NULL;

	spin_lock(&ht->lock);
	if (ht->head == NULL) {
		spin_unlock(&ht->lock);
		kfree(vtp_entry);
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
