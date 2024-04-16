// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
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
#include "hns3_udma_jfs.h"
#include "hns3_udma_jetty.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_dca.h"
#include "hns3_udma_dfx.h"
#include "hns3_udma_tp.h"
struct udma_qp *get_qp(struct udma_dev *udma_device, uint32_t qpn)
{
	return (struct udma_qp *)xa_load(&udma_device->qp_table.xa, qpn);
}

static enum udma_qp_state to_udma_qp_state(enum ubcore_tp_state state)
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

struct udma_modify_tp_attr *udma_get_m_attr(struct ubcore_tp *tp, struct udma_qp *qp,
					    struct ubcore_tp_attr *attr,
					    union ubcore_tp_attr_mask mask)
{
	struct udma_modify_tp_attr *m_attr;

	m_attr = kzalloc(sizeof(*m_attr), GFP_KERNEL);
	if (m_attr == NULL)
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

int udma_modify_tp(struct ubcore_tp *tp, struct ubcore_tp_attr *attr,
		   union ubcore_tp_attr_mask mask)
{
	struct udma_modify_tp_attr *m_attr;
	enum udma_qp_state target_state;
	enum udma_qp_state curr_state;
	struct udma_dev *udma_device;
	struct udma_tp *utp;
	struct udma_qp *qp;
	int ret = -EINVAL;

	udma_device = to_udma_dev(tp->ub_dev);
	utp = to_udma_tp(tp);

	qp = &utp->qp;
	if (!qp)
		goto error;

	curr_state = to_udma_qp_state(tp->state);

	if (mask.bs.state)
		target_state = to_udma_qp_state(attr->state);
	else
		target_state = QPS_ERR;

	m_attr = udma_get_m_attr(tp, qp, attr, mask);
	if (!m_attr)
		goto error;

	qp->udma_device = udma_device;
	qp->send_jfc = qp->qp_attr.send_jfc;
	qp->recv_jfc = qp->qp_attr.recv_jfc;
	qp->m_attr = m_attr;
	if (attr)
		qp->ubcore_path_mtu = attr->mtu;
	ret = udma_modify_qp_common(qp, attr, mask, curr_state, target_state);
	kfree(m_attr);
	qp->m_attr = NULL;
error:
	return ret;
}

void *udma_erase_tp(struct udma_tp *udma_tp)
{
	struct udma_qp_attr *qp_attr;
	struct udma_jetty *jetty;
	struct udma_tp *pre_tp;
	struct udma_jfr *jfr;
	struct udma_jfs *jfs;
	uint32_t hash;

	qp_attr = &udma_tp->qp.qp_attr;
	jetty = qp_attr->jetty;
	jfr = qp_attr->jfr;
	jfs = qp_attr->jfs;

	if (qp_attr->is_jetty) {
		if (jetty->tp_mode == UBCORE_TP_RM) {
			hash = udma_get_jetty_hash(&udma_tp->tjetty_id);
			pre_tp = (struct udma_tp *)xa_load(&jetty->srm_node_table,
							  hash);
			if (!pre_tp)
				return NULL;

			if (pre_tp->qp.qpn == udma_tp->qp.qpn)
				xa_erase(&jetty->srm_node_table, hash);
		} else if (jetty->tp_mode == UBCORE_TP_RC) {
			if (jetty->rc_node.tp == NULL)
				return NULL;

			if (jetty->rc_node.tpn == udma_tp->ubcore_tp.tpn) {
				jetty->rc_node.tp = NULL;
				jetty->rc_node.tpn = 0;
			}
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

static void store_tpn(struct udma_dev *udma_device, struct udma_tp *tp)
{
	struct tpn_list *tpn_new;
	struct tpn_list *tpn_now;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = udma_find_dfx_dev(udma_device, &i);
	if (ret)
		return;

	tpn_new = kzalloc(sizeof(struct tpn_list), GFP_KERNEL);
	if (!tpn_new) {
		read_unlock(&g_udma_dfx_list[i].rwlock);
		return;
	}

	lock = &g_udma_dfx_list[i].dfx->tpn_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry(tpn_now,
			    &g_udma_dfx_list[i].dfx->tpn_list->node, node) {
		if (tpn_now->tpn == tp->ubcore_tp.tpn)
			goto found;
	}

	tpn_new->tpn = tp->ubcore_tp.tpn;
	list_add(&tpn_new->node, &g_udma_dfx_list[i].dfx->tpn_list->node);
	++g_udma_dfx_list[i].dfx->tpn_cnt;
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);

	return;

found:
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
	kfree(tpn_new);
}

static void delete_tpn(struct udma_dev *udma_device, struct ubcore_tp *tp)
{
	struct tpn_list *tpn_now, *tpn_tmp;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = udma_find_dfx_dev(udma_device, &i);
	if (ret)
		return;

	lock = &g_udma_dfx_list[i].dfx->tpn_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry_safe(tpn_now, tpn_tmp,
				 &g_udma_dfx_list[i].dfx->tpn_list->node,
				 node) {
		if (tpn_now->tpn == tp->tpn) {
			list_del(&tpn_now->node);
			--g_udma_dfx_list[i].dfx->tpn_cnt;
			kfree(tpn_now);
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
}

int udma_destroy_tp(struct ubcore_tp *tp)
{
	struct udma_dev *udma_device = to_udma_dev(tp->ub_dev);
	union ubcore_tp_attr_mask ubcore_attr_mask;
	enum udma_qp_state curr_state;
	struct udma_tp *udma_tp;
	struct udma_qp *qp;
	int ret = 0;

	udma_tp = to_udma_tp(tp);
	if (!udma_erase_tp(udma_tp)) {
		dev_warn(udma_device->dev,
			 "tp(tpn = 0x%x) has already been destroyed.\n", tp->tpn);
		return 0;
	}

	if (dfx_switch)
		delete_tpn(udma_device, tp);

	qp = &udma_tp->qp;
	curr_state = to_udma_qp_state(tp->state);
	ubcore_attr_mask.value = 0;
	qp->m_attr = NULL;

	if (qp->state != QPS_RESET) {
		ret = udma_modify_qp_common(qp, NULL, ubcore_attr_mask, curr_state, QPS_RESET);
		if (ret) {
			dev_err(udma_device->dev,
				"Modify QP 0x%06llx to Reset failed(%d).\n",
				qp->qpn, ret);
			goto error;
		}
	}

	udma_destroy_qp_common(udma_device, qp, NULL);

	kfree(udma_tp);

	return ret;

error:
	return -EINVAL;
}

static void udma_set_tp(struct ubcore_device *dev, const struct ubcore_tp_cfg *cfg,
			struct udma_tp *tp)
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

static void copy_attr_to_pre_tp(struct udma_dev *udma_device, bool is_rm,
				struct udma_qp *from_qp, struct udma_qp *to_qp)
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
	if (to_qp->en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_enable_dca(udma_device, to_qp);

	udma_mtr_move(&from_qp->mtr, &to_qp->mtr);
	if (is_rm)
		copy_send_jfc(from_qp, to_qp);

	to_qp->qp_attr.cap.max_send_wr = from_qp->qp_attr.cap.max_send_wr;
	to_qp->qp_attr.cap.max_send_sge = from_qp->qp_attr.cap.max_send_sge;
	to_qp->qp_attr.cap.max_inline_data =
					from_qp->qp_attr.cap.max_inline_data;

	from_qp->no_free_wqe_buf = true;
	to_qp->force_free_wqe_buf = true;
}

static int udma_store_jetty_tp(struct udma_dev *udma_device,
			       struct udma_jetty *jetty, struct udma_tp *tp,
			       struct ubcore_tp **fail_ret_tp)
{
	struct udma_tp *pre_tp;
	uint32_t tjetty_hash;
	uint32_t hash;
	int ret = 0;

	hash = udma_get_jetty_hash(&tp->tjetty_id);
	if (jetty->tp_mode == UBCORE_TP_RM) {
		pre_tp = (struct udma_tp *)xa_load(&jetty->srm_node_table, hash);
		if (pre_tp) {
			copy_attr_to_pre_tp(udma_device, true, &tp->qp,
					    &pre_tp->qp);
			*fail_ret_tp = &pre_tp->ubcore_tp;
			return 0;
		}

		ret = xa_err(xa_store(&jetty->srm_node_table,
				      hash, tp, GFP_KERNEL));
		if (ret)
			dev_err(udma_device->dev,
				"failed store jetty tp xarray, ret = %d\n", ret);
	} else if (jetty->tp_mode == UBCORE_TP_RC) {
		if (jetty->rc_node.tp == NULL) {
			jetty->rc_node.tp = tp;
			jetty->rc_node.tpn = tp->ubcore_tp.tpn;
			jetty->rc_node.tjetty_id = tp->tjetty_id;
		} else {
			tjetty_hash =
				udma_get_jetty_hash(&jetty->rc_node.tjetty_id);
			if (tjetty_hash == hash &&
			    (tp->qp.en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)) {
				copy_attr_to_pre_tp(udma_device, false, &tp->qp,
						    &jetty->rc_node.tp->qp);
				*fail_ret_tp = &jetty->rc_node.tp->ubcore_tp;
			} else if (tjetty_hash == hash) {
				*fail_ret_tp = &jetty->rc_node.tp->ubcore_tp;
			} else {
				dev_err(udma_device->dev,
					"jetty has bind a target jetty, jetty_id = %d.\n",
					jetty->rc_node.tjetty_id.id);
				return -EEXIST;
			}
		}
	}

	return ret;
}

static int udma_store_tp(struct udma_dev *udma_device, struct udma_tp *tp,
			 struct ubcore_tp **fail_ret_tp)
{
	struct udma_qp_attr *qp_attr;
	struct udma_jetty *jetty;
	struct udma_jfr *jfr;
	struct udma_jfs *jfs;
	int ret = 0;

	qp_attr = &tp->qp.qp_attr;
	jfr = qp_attr->jfr;
	jfs = qp_attr->jfs;
	jetty = qp_attr->jetty;

	if (qp_attr->is_jetty) {
		ret = udma_store_jetty_tp(udma_device, jetty, tp, fail_ret_tp);
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

static void lock_jetty(struct udma_qp_attr *qp_attr)
{
	struct udma_jetty *jetty = qp_attr->jetty;

	if (qp_attr->is_jetty)
		mutex_lock(&jetty->tp_mutex);
}

static void unlock_jetty(struct udma_qp_attr *qp_attr)
{
	struct udma_jetty *jetty = qp_attr->jetty;

	if (qp_attr->is_jetty)
		mutex_unlock(&jetty->tp_mutex);
}

struct ubcore_tp *udma_create_tp(struct ubcore_device *dev, struct ubcore_tp_cfg *cfg,
				 struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct ubcore_tp *fail_ret_tp = NULL;
	struct udma_tp *tp;
	int ret;

	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return ERR_PTR(-ENOMEM);

	ret = udma_fill_qp_attr(udma_dev, &tp->qp.qp_attr, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "failed to fill qp attr.\n");
		goto failed_alloc_tp;
	}
	tp->tjetty_id.id = tp->qp.qp_attr.tgt_id;
	tp->tjetty_id.eid = cfg->peer_eid;

	lock_jetty(&tp->qp.qp_attr);
	ret = udma_create_qp_common(udma_dev, &tp->qp, udata);
	if (ret) {
		dev_err(udma_dev->dev,
			"Failed to create qp common with ret is %d.\n", ret);
		unlock_jetty(&tp->qp.qp_attr);
		goto failed_alloc_tp;
	}

	udma_set_tp(dev, cfg, tp);

	ret = udma_store_tp(udma_dev, tp, &fail_ret_tp);
	if (ret || fail_ret_tp)
		goto failed_create_qp;

	ret = udma_init_qpc(udma_dev, &tp->qp);
	if (ret)
		goto failed_init_qpc;

	unlock_jetty(&tp->qp.qp_attr);

	if (dfx_switch)
		store_tpn(udma_dev, tp);

	return &tp->ubcore_tp;

failed_init_qpc:
	udma_erase_tp(tp);
failed_create_qp:
	unlock_jetty(&tp->qp.qp_attr);
	udma_destroy_qp_common(udma_dev, &tp->qp, fail_ret_tp);
failed_alloc_tp:
	kfree(tp);

	return fail_ret_tp;
}
