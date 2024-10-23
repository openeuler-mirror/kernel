// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#include <linux/acpi.h>
#include <linux/iommu.h>
#include "hns3_udma_jfr.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_jfs.h"
#include "hns3_udma_jetty.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_dca.h"
#include "hns3_udma_dfx.h"
#include "hns3_udma_eid.h"
#include "hns3_udma_tp.h"

struct hns3_udma_qp *get_qp(struct hns3_udma_dev *udma_device, uint32_t qpn)
{
	return (struct hns3_udma_qp *)xa_load(&udma_device->qp_table.xa, qpn);
}

static enum hns3_udma_qp_state to_hns3_udma_qp_state(enum ubcore_tp_state state)
{
	switch (state) {
	case UBCORE_TP_STATE_RESET:
		return QPS_RESET;
	case UBCORE_TP_STATE_RTR:
		return QPS_RTR;
	case UBCORE_TP_STATE_RTS:
		return QPS_RTS;
	case UBCORE_TP_STATE_ERR:
		return QPS_ERR;
	default:
		return QPS_ERR;
	}
}

struct hns3_udma_modify_tp_attr *hns3_udma_get_m_attr(struct ubcore_tp *tp, struct hns3_udma_qp *qp,
						      struct ubcore_tp_attr *attr,
						      union ubcore_tp_attr_mask mask)
{
	struct hns3_udma_modify_tp_attr *m_attr;

	m_attr = kzalloc(sizeof(*m_attr), GFP_KERNEL);
	if (!m_attr)
		return NULL;

	memcpy(m_attr->dmac, tp->peer_net_addr.mac, sizeof(m_attr->dmac));
	m_attr->data_udp_start = tp->data_udp_start;
	m_attr->ack_udp_start = tp->ack_udp_start;
	m_attr->udp_range = tp->udp_range;
	m_attr->sgid_index = qp->qp_attr.eid_index;
	*(uint32_t *)(&m_attr->dipv4) = *(uint32_t *)(tp->peer_eid.raw +
						      SGID_H_SHIFT);
	memcpy(m_attr->dgid, tp->peer_eid.raw, sizeof(tp->peer_eid.raw));

	if (!qp->qp_attr.is_tgt) {
		m_attr->retry_cnt = tp->retry_num;
		m_attr->ack_timeout = tp->ack_timeout;
		m_attr->rnr_retry = qp->rnr_retry;
		m_attr->priority = qp->priority;
		if (qp->qp_attr.is_jetty)
			m_attr->min_rnr_timer = qp->min_rnr_timer;
	} else {
		m_attr->min_rnr_timer = qp->min_rnr_timer;
		if (qp->qp_attr.is_jetty) {
			m_attr->retry_cnt = tp->retry_num;
			m_attr->ack_timeout = tp->ack_timeout;
			m_attr->rnr_retry = qp->rnr_retry;
			m_attr->priority = qp->priority;
		}
	}

	return m_attr;
}

int hns3_udma_modify_tp(struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
			union ubcore_tp_attr_mask mask)
{
	struct hns3_udma_modify_tp_attr *m_attr;
	enum hns3_udma_qp_state target_state;
	enum hns3_udma_qp_state curr_state;
	struct hns3_udma_dev *udma_device;
	struct hns3_udma_tp *utp;
	struct hns3_udma_qp *qp;
	int ret = -EINVAL;

	if (!tp)
		goto error;

	udma_device = to_hns3_udma_dev(tp->ub_dev);
	utp = to_hns3_udma_tp(tp);
	qp = &utp->qp;

	curr_state = to_hns3_udma_qp_state(tp->state);

	if (mask.bs.state)
		target_state = to_hns3_udma_qp_state(attr->state);
	else
		target_state = QPS_ERR;

	m_attr = hns3_udma_get_m_attr(tp, qp, attr, mask);
	if (!m_attr)
		goto error;

	qp->udma_device = udma_device;
	qp->send_jfc = qp->qp_attr.send_jfc;
	qp->recv_jfc = qp->qp_attr.recv_jfc;
	memcpy(&qp->m_attr, m_attr, sizeof(struct hns3_udma_modify_tp_attr));
	qp->ubcore_path_mtu = attr->mtu;
	ret = hns3_udma_modify_qp_common(qp, attr, mask, curr_state, target_state);
	kfree(m_attr);
error:
	return ret;
}

void *hns3_udma_erase_tp(struct hns3_udma_tp *udma_tp)
{
	struct hns3_udma_qp_attr *qp_attr;
	struct hns3_udma_jetty *jetty;
	struct hns3_udma_jfr *jfr;
	struct hns3_udma_jfs *jfs;

	qp_attr = &udma_tp->qp.qp_attr;
	jetty = qp_attr->jetty;
	jfr = qp_attr->jfr;
	jfs = qp_attr->jfs;

	if (qp_attr->is_jetty && jetty->tp_mode == UBCORE_TP_RC) {
		if (jetty->rc_node.tp == NULL)
			return NULL;

		if (jetty->rc_node.tpn == udma_tp->ubcore_tp.tpn) {
			jetty->rc_node.tp = NULL;
			jetty->rc_node.tpn = 0;
		}
	} else {
		if (jfr)
			return xa_erase(&jfr->tp_table_xa,
					udma_tp->ubcore_tp.tpn);
		else if (jfs)
			return xa_erase(&jfs->node_table,
					udma_tp->ubcore_tp.tpn);
	}

	return udma_tp;
}

static void store_tpn(struct hns3_udma_dev *udma_device, struct hns3_udma_tp *tp)
{
	struct tpn_list *tpn_new;
	struct tpn_list *tpn_now;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = hns3_udma_find_dfx_dev(udma_device, &i);
	if (ret)
		return;

	tpn_new = kzalloc(sizeof(struct tpn_list), GFP_KERNEL);
	if (!tpn_new) {
		read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
		return;
	}

	lock = &g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry(tpn_now,
			    &g_hns3_udma_dfx_list[i].dfx->tpn_list->node, node) {
		if (tpn_now->tpn == tp->ubcore_tp.tpn)
			goto found;
	}

	tpn_new->tpn = tp->ubcore_tp.tpn;
	list_add(&tpn_new->node, &g_hns3_udma_dfx_list[i].dfx->tpn_list->node);
	++g_hns3_udma_dfx_list[i].dfx->tpn_cnt;
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);

	return;

found:
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
	kfree(tpn_new);
}

static void delete_tpn(struct hns3_udma_dev *udma_device, struct ubcore_tp *tp)
{
	struct tpn_list *tpn_now, *tpn_tmp;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = hns3_udma_find_dfx_dev(udma_device, &i);
	if (ret)
		return;

	lock = &g_hns3_udma_dfx_list[i].dfx->tpn_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry_safe(tpn_now, tpn_tmp,
				 &g_hns3_udma_dfx_list[i].dfx->tpn_list->node,
				 node) {
		if (tpn_now->tpn == tp->tpn) {
			list_del(&tpn_now->node);
			--g_hns3_udma_dfx_list[i].dfx->tpn_cnt;
			kfree(tpn_now);
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_hns3_udma_dfx_list[i].rwlock);
}

int hns3_udma_destroy_tp(struct ubcore_tp *tp)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(tp->ub_dev);
	union ubcore_tp_attr_mask ubcore_attr_mask;
	enum hns3_udma_qp_state curr_state;
	struct hns3_udma_tp *udma_tp;
	struct hns3_udma_qp *qp;
	int ret = 0;

	udma_tp = to_hns3_udma_tp(tp);
	if (!hns3_udma_erase_tp(udma_tp)) {
		dev_warn(udma_device->dev,
			 "tp(tpn = 0x%x) has already been destroyed.\n", tp->tpn);
		return 0;
	}

	if (dfx_switch)
		delete_tpn(udma_device, tp);

	qp = &udma_tp->qp;
	curr_state = to_hns3_udma_qp_state(tp->state);
	ubcore_attr_mask.value = 0;

	if (qp->state != QPS_RESET) {
		ret = hns3_udma_modify_qp_common(qp, NULL, ubcore_attr_mask, curr_state, QPS_RESET);
		if (ret) {
			dev_err(udma_device->dev,
				"Modify QP 0x%06llx to Reset failed(%d).\n",
				qp->qpn, ret);
		}
	}

	hns3_udma_destroy_qp_common(udma_device, qp, NULL);

	kfree(udma_tp);

	return 0;
}

static void hns3_udma_set_tp(struct ubcore_device *dev, const struct ubcore_tp_cfg *cfg,
			     struct hns3_udma_tp *tp)
{
	tp->ubcore_tp.tpn = tp->qp.qpn;
	tp->ubcore_tp.ub_dev = dev;
	tp->ubcore_tp.flag.bs.target = cfg->flag.bs.target;
	tp->ubcore_tp.local_eid = cfg->local_eid;
	tp->ubcore_tp.peer_eid = cfg->peer_eid;
	tp->ubcore_tp.trans_mode = cfg->trans_mode;
	tp->ubcore_tp.retry_num = cfg->retry_num;
	tp->ubcore_tp.ack_timeout = cfg->ack_timeout;
	tp->ubcore_tp.dscp = cfg->dscp;
	tp->ubcore_tp.state = UBCORE_TP_STATE_RESET;
}

static void copy_attr_to_pre_tp(struct hns3_udma_dev *udma_device,
				struct hns3_udma_qp *from_qp, struct hns3_udma_qp *to_qp)
{
	if (from_qp->qp_attr.is_tgt)
		return;

	to_qp->sge = from_qp->sge;
	to_qp->sq = from_qp->sq;
	to_qp->sdb = from_qp->sdb;
	to_qp->priority = from_qp->priority;
	to_qp->dca_ctx = from_qp->dca_ctx;
	to_qp->en_flags = from_qp->en_flags;
	to_qp->buff_size = from_qp->buff_size;
	if (to_qp->en_flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		hns3_udma_enable_dca(udma_device, to_qp);

	hns3_udma_mtr_move(&from_qp->mtr, &to_qp->mtr);

	to_qp->qp_attr.cap.max_send_wr = from_qp->qp_attr.cap.max_send_wr;
	to_qp->qp_attr.cap.max_send_sge = from_qp->qp_attr.cap.max_send_sge;
	to_qp->qp_attr.cap.max_inline_data =
					from_qp->qp_attr.cap.max_inline_data;

	from_qp->no_free_wqe_buf = true;
	to_qp->force_free_wqe_buf = true;
}

static int hns3_udma_store_jetty_tp(struct hns3_udma_dev *udma_device,
				    struct hns3_udma_jetty *jetty, struct hns3_udma_tp *tp,
				    struct ubcore_tp **fail_ret_tp)
{
	uint32_t tjetty_hash;
	uint32_t hash;
	int ret = 0;

	hash = hns3_udma_get_jetty_hash(&tp->tjetty_id);
	if (jetty->tp_mode != UBCORE_TP_RC)
		return 0;

	if (jetty->rc_node.tp == NULL) {
		jetty->rc_node.tp = tp;
		jetty->rc_node.tpn = tp->ubcore_tp.tpn;
		jetty->rc_node.tjetty_id = tp->tjetty_id;
	} else {
		tjetty_hash =
			hns3_udma_get_jetty_hash(&jetty->rc_node.tjetty_id);
		if (tjetty_hash == hash &&
			(tp->qp.en_flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)) {
			copy_attr_to_pre_tp(udma_device, &tp->qp,
					    &jetty->rc_node.tp->qp);
			*fail_ret_tp = &jetty->rc_node.tp->ubcore_tp;
		} else if (tjetty_hash == hash) {
			*fail_ret_tp = &jetty->rc_node.tp->ubcore_tp;
		} else {
			dev_err(udma_device->dev,
				"jetty has bind a target jetty, jetty_id = %u.\n",
				jetty->rc_node.tjetty_id.id);
			return -EEXIST;
		}
	}

	return ret;
}

static int hns3_udma_store_tp(struct hns3_udma_dev *udma_device, struct hns3_udma_tp *tp,
			      struct ubcore_tp **fail_ret_tp)
{
	struct hns3_udma_qp_attr *qp_attr;
	struct hns3_udma_jetty *jetty;
	struct hns3_udma_jfr *jfr;
	struct hns3_udma_jfs *jfs;
	int ret = 0;

	qp_attr = &tp->qp.qp_attr;
	jfr = qp_attr->jfr;
	jfs = qp_attr->jfs;
	jetty = qp_attr->jetty;

	if (qp_attr->is_jetty) {
		ret = hns3_udma_store_jetty_tp(udma_device, jetty, tp, fail_ret_tp);
		if (ret) {
			dev_err(udma_device->dev,
				"failed store jetty tp, ret = %d.\n", ret);
			return ret;
		}
	} else {
		if (jfr) {
			ret = xa_err(xa_store(&jfr->tp_table_xa,
					      tp->ubcore_tp.tpn, tp,
					      GFP_KERNEL));
			if (ret) {
				dev_err(udma_device->dev,
					"failed store jfr tp, ret = %d.\n", ret);
				return ret;
			}
		} else if (jfs) {
			ret = xa_err(xa_store(&jfs->node_table,
					      tp->ubcore_tp.tpn, tp,
					      GFP_KERNEL));
			if (ret) {
				dev_err(udma_device->dev,
					"failed store jfs tp, ret = %d.\n", ret);
				return ret;
			}
		}
	}

	return ret;
}

static void lock_jetty(struct hns3_udma_qp_attr *qp_attr)
{
	struct hns3_udma_jetty *jetty = qp_attr->jetty;

	if (qp_attr->is_jetty)
		mutex_lock(&jetty->tp_mutex);
}

static void unlock_jetty(struct hns3_udma_qp_attr *qp_attr)
{
	struct hns3_udma_jetty *jetty = qp_attr->jetty;

	if (qp_attr->is_jetty)
		mutex_unlock(&jetty->tp_mutex);
}

struct ubcore_tp *hns3_udma_create_tp(struct ubcore_device *dev, struct ubcore_tp_cfg *cfg,
				      struct ubcore_udata *udata)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct ubcore_tp *fail_ret_tp = NULL;
	struct hns3_udma_tp *tp;
	int ret;

	if (!udata || !udata->udrv_data || !udata->uctx) {
		dev_err(udma_dev->dev, "tp udata or uctx is null.\n");
		return ERR_PTR(-EINVAL);
	}

	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return ERR_PTR(-ENOMEM);

	ret = hns3_udma_fill_qp_attr(udma_dev, &tp->qp.qp_attr, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "failed to fill qp attr.\n");
		goto failed_alloc_tp;
	}
	tp->tjetty_id.id = tp->qp.qp_attr.tgt_id;
	tp->tjetty_id.eid = cfg->peer_eid;
	tp->sub_trans_mode = HNS3_UDMA_SUB_TRANS_MODE_NORMAL_TP;

	lock_jetty(&tp->qp.qp_attr);
	ret = hns3_udma_create_qp_common(udma_dev, &tp->qp, udata);
	if (ret) {
		dev_err(udma_dev->dev,
			"Failed to create qp common with ret is %d.\n", ret);
		unlock_jetty(&tp->qp.qp_attr);
		goto failed_alloc_tp;
	}

	hns3_udma_set_tp(dev, cfg, tp);

	ret = hns3_udma_store_tp(udma_dev, tp, &fail_ret_tp);
	if (ret || fail_ret_tp)
		goto failed_create_qp;

	ret = hns3_udma_init_qpc(udma_dev, &tp->qp);
	if (ret)
		goto failed_init_qpc;

	unlock_jetty(&tp->qp.qp_attr);

	if (dfx_switch)
		store_tpn(udma_dev, tp);

	return &tp->ubcore_tp;

failed_init_qpc:
	hns3_udma_erase_tp(tp);
failed_create_qp:
	unlock_jetty(&tp->qp.qp_attr);
	hns3_udma_destroy_qp_common(udma_dev, &tp->qp, fail_ret_tp);
failed_alloc_tp:
	kfree(tp);

	return fail_ret_tp;
}

struct hns3_udma_tp *hns3_udma_create_user_tp(struct hns3_udma_dev *udma_dev,
					      struct hns3_udma_jetty *jetty,
					      struct ubcore_jetty_cfg *cfg,
					      struct ubcore_udata *udata)
{
	struct hns3_udma_tp *tp;
	int ret;

	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return ERR_PTR(-ENOMEM);

	hns3_udma_fill_jetty_qp_attr(udma_dev, &tp->qp.qp_attr, jetty, udata->uctx, cfg);
	ret = hns3_udma_create_qp_common(udma_dev, &tp->qp, udata);
	if (ret) {
		dev_err(udma_dev->dev,
			"Failed to create qp common, ret is %d.\n", ret);
		goto failed_create_qp;
	}

	tp->ubcore_tp.tpn = tp->qp.qpn;
	tp->ubcore_tp.ub_dev = &udma_dev->ub_dev;
	tp->sub_trans_mode = HNS3_UDMA_SUB_TRANS_MODE_USER_TP;
	ret = hns3_udma_init_qpc(udma_dev, &tp->qp);
	if (ret)
		goto failed_init_qpc;

	if (dfx_switch)
		store_tpn(udma_dev, tp);

	return tp;

failed_init_qpc:
	hns3_udma_destroy_qp_common(udma_dev, &tp->qp, NULL);
failed_create_qp:
	kfree(tp);

	return NULL;
}

static int check_modify_user_tp_attr(struct ubcore_device *dev,
				     struct ubcore_tp_attr *attr,
				     union ubcore_tp_attr_mask mask)
{
	enum ubcore_tp_state state;
	int ret = 0;

	if (!mask.bs.state) {
		dev_err(&dev->dev, "invalid tp attr mask.\n");
		ret = -EINVAL;
		goto out;
	}

	state = attr->state;
	if (state != UBCORE_TP_STATE_RTR && state != UBCORE_TP_STATE_RTS &&
	    state != UBCORE_TP_STATE_ERR) {
		dev_err(&dev->dev, "invalid tp state:%d.\n", state);
		ret = -EINVAL;
		goto out;
	}

	if (mask.bs.mtu) {
		if (attr->mtu != UBCORE_MTU_1024 &&
		    attr->mtu != UBCORE_MTU_4096) {
			dev_err(&dev->dev, "invalid mtu:%d.\n", attr->mtu);
			ret = -EINVAL;
		}
	}
out:
	return ret;
}

int hns3_udma_modify_user_tp(struct ubcore_device *dev, uint32_t tpn,
			     struct ubcore_tp_cfg *cfg,
			     struct ubcore_tp_attr *attr,
			     union ubcore_tp_attr_mask mask)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct hns3_udma_tp *tp;
	struct hns3_udma_qp *qp;
	unsigned long flags;
	int ret;

	if (attr->state != UBCORE_TP_STATE_RTS) {
		dev_err(&dev->dev, "Invalid TP STATE %d, only supports TP STATE RTS.\n",
			attr->state);
		return -EINVAL;
	}

	xa_lock_irqsave(&udma_dev->qp_table.xa, flags);
	qp = (struct hns3_udma_qp *)xa_load(&udma_dev->qp_table.xa, tpn);
	if (qp)
		refcount_inc(&qp->refcount);
	xa_unlock_irqrestore(&udma_dev->qp_table.xa, flags);

	if (!qp) {
		dev_err(&dev->dev, "find qp failed, tpn = %u.\n", tpn);
		return -EINVAL;
	}

	tp = container_of(qp, struct hns3_udma_tp, qp);
	if (tp->sub_trans_mode != HNS3_UDMA_SUB_TRANS_MODE_USER_TP) {
		dev_err(&dev->dev, "invalid tp sub_trans_mode.\n");
		ret = -EINVAL;
		goto out;
	}
	ret = check_modify_user_tp_attr(dev, attr, mask);
	if (ret) {
		dev_err(&dev->dev, "invalid tp attr.\n");
		goto out;
	}
	hns3_udma_set_tp(dev, cfg, tp);
	hns3_udma_ipv4_map_to_eid(attr->peer_net_addr.net_addr.in4.addr,
			     &tp->ubcore_tp.peer_eid);
	ret = hns3_udma_modify_tp(&tp->ubcore_tp, attr, mask);
	if (ret)
		dev_err(&dev->dev, "modify user tp failed, ret = %d.\n", ret);

out:
	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);

	return ret;
}
