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
#include "hns3_udma_tp.h"

static enum udma_qp_state to_udma_qp_state(enum ubcore_tp_state state)
{
	switch (state) {
	case UBCORE_TP_STATE_RESET:
		return QPS_RESET;
	case UBCORE_TP_STATE_RTR:
		return QPS_RTR;
	case UBCORE_TP_STATE_RTS:
		return QPS_RTS;
	case UBCORE_TP_STATE_ERROR:
		return QPS_ERR;
	default:
		return QPS_ERR;
	}
}

struct udma_modify_tp_attr *udma_get_m_attr(struct ubcore_tp *tp, struct udma_qp *qp,
					    const struct ubcore_tp_attr *attr,
					    union ubcore_tp_attr_mask mask)
{
	struct udma_modify_tp_attr *m_attr;

	m_attr = kzalloc(sizeof(*m_attr), GFP_KERNEL);
	if (m_attr == NULL)
		return NULL;

	memcpy(m_attr->dmac, tp->peer_net_addr.mac, sizeof(m_attr->dmac));

	m_attr->max_dest_rd_atomic = 0;
	m_attr->max_rd_atomic = 0;
	m_attr->rq_psn = tp->rx_psn;
	m_attr->hop_limit = MAX_HOP_LIMIT;
	m_attr->sgid_index = 0;
	*(uint32_t *)(&m_attr->dipv4) = *(uint32_t *)(tp->peer_eid.raw +
						      SGID_H_SHIFT);
	memcpy(m_attr->dgid, tp->peer_eid.raw, sizeof(tp->peer_eid.raw));

	if (!qp->qp_attr.is_tgt) {
		m_attr->retry_cnt = qp->retry_cnt;
		m_attr->ack_timeout = qp->ack_timeout;
		m_attr->rnr_retry = qp->rnr_retry;
		m_attr->priority = qp->priority;
	} else {
		m_attr->min_rnr_timer = qp->min_rnr_timer;
	}

	if (mask.bs.peer_tpn)
		m_attr->dest_qp_num = attr->peer_tpn;

	if (mask.bs.tx_psn)
		m_attr->sq_psn = attr->tx_psn;
	else
		m_attr->sq_psn = tp->tx_psn;

	if (mask.bs.mtu)
		m_attr->path_mtu = attr->mtu;

	return m_attr;
}

int udma_modify_tp(struct ubcore_tp *tp, const struct ubcore_tp_attr *attr,
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
	if (attr)
		qp->ubcore_path_mtu = attr->mtu;
	ret = udma_modify_qp_common(qp, m_attr, curr_state, target_state);
	kfree(m_attr);
error:
	return ret;
}

void *udma_erase_tp(struct udma_tp *udma_tp)
{
	struct udma_qp_attr *qp_attr;
	struct udma_jfr *jfr;
	struct udma_jfs *jfs;

	qp_attr = &udma_tp->qp.qp_attr;
	jfr = qp_attr->jfr;
	jfs = qp_attr->jfs;

	if (jfr)
		return xa_erase(&jfr->tp_table_xa,
				udma_tp->ubcore_tp.tpn);

	if (jfs)
		return xa_erase(&jfs->node_table,
				udma_tp->ubcore_tp.tpn);

	return udma_tp;
}

int udma_destroy_tp(struct ubcore_tp *tp)
{
	struct udma_dev *udma_device = to_udma_dev(tp->ub_dev);
	enum udma_qp_state curr_state;
	struct udma_tp *udma_tp;
	struct udma_qp *qp;
	int ret = 0;

	udma_tp = to_udma_tp(tp);
	if (!udma_erase_tp(udma_tp)) {
		dev_err(udma_device->dev,
			"failed to find tp, tpn = 0x%x\n", tp->tpn);
		return 0;
	}

	qp = &udma_tp->qp;
	curr_state = to_udma_qp_state(tp->state);

	if (qp->state != QPS_RESET) {
		ret = udma_modify_qp_common(qp, NULL, curr_state, QPS_RESET);
		if (ret) {
			dev_err(udma_device->dev,
				"Modify QP 0x%06llx to Reset failed(%d).\n",
				qp->qpn, ret);
			goto error;
		}
	}

	udma_destroy_qp_common(udma_device, qp);

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
	tp->ubcore_tp.flag.bs.oor_en = cfg->flag.bs.oor_en;
	tp->ubcore_tp.flag.bs.sr_en = cfg->flag.bs.sr_en;
	tp->ubcore_tp.flag.bs.spray_en = cfg->flag.bs.spray_en;
	tp->ubcore_tp.local_net_addr = cfg->local_net_addr;
	tp->ubcore_tp.peer_net_addr = cfg->peer_net_addr;
	tp->ubcore_tp.local_eid = cfg->local_eid;
	tp->ubcore_tp.peer_eid = cfg->peer_eid;
	tp->ubcore_tp.trans_mode = cfg->trans_mode;
	tp->ubcore_tp.rx_psn = cfg->rx_psn;
	tp->ubcore_tp.mtu = cfg->mtu;
	tp->ubcore_tp.data_udp_start = cfg->data_udp_start;
	tp->ubcore_tp.ack_udp_start = cfg->ack_udp_start;
	tp->ubcore_tp.udp_range = cfg->udp_range;
	tp->ubcore_tp.retry_num = cfg->retry_num;
	tp->ubcore_tp.ack_timeout = cfg->ack_timeout;
	tp->ubcore_tp.tc = cfg->tc;
	tp->ubcore_tp.state = UBCORE_TP_STATE_RESET;
}

static int udma_store_tp(struct udma_dev *udma_device, struct udma_tp *tp,
			 struct ubcore_tp **fail_ret_tp)
{
	struct udma_qp_attr *qp_attr;
	struct udma_jfr *jfr;
	struct udma_jfs *jfs;
	int ret = 0;

	qp_attr = &tp->qp.qp_attr;
	jfr = qp_attr->jfr;
	jfs = qp_attr->jfs;
	if (jfr) {
		ret = xa_err(xa_store(&jfr->tp_table_xa, tp->ubcore_tp.tpn, tp,
				      GFP_KERNEL));
		if (ret) {
			dev_err(udma_device->dev,
				"failed store jfr tp, ret = %d\n", ret);
			return ret;
		}
	} else if (jfs) {
		ret = xa_err(xa_store(&jfs->node_table, tp->ubcore_tp.tpn, tp,
				      GFP_KERNEL));
		if (ret) {
			dev_err(udma_device->dev,
				"failed store jfs tp, ret = %d\n", ret);
			return ret;
		}
	}

	return ret;
}

struct ubcore_tp *udma_create_tp(struct ubcore_device *dev, const struct ubcore_tp_cfg *cfg,
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

	ret = udma_create_qp_common(udma_dev, &tp->qp, udata);
	if (ret) {
		dev_err(udma_dev->dev,
			"Failed to create qp common with ret is %d.\n", ret);
		goto failed_alloc_tp;
	}

	udma_set_tp(dev, cfg, tp);

	ret = udma_store_tp(udma_dev, tp, &fail_ret_tp);
	if (ret || fail_ret_tp)
		goto failed_create_qp;

	return &tp->ubcore_tp;

failed_create_qp:
	udma_destroy_qp_common(udma_dev, &tp->qp);
failed_alloc_tp:
	kfree(tp);

	return fail_ret_tp;
}
