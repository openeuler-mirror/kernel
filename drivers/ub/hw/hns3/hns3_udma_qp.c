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

#include <linux/compiler.h>
#include <linux/spinlock.h>
#include "hns3_udma_abi.h"
#include "hns3_udma_jfr.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_qp.h"

static int udma_alloc_reorder_cq_buf(struct udma_dev *udma_dev,
				     struct udma_qp_attr *qp_attr)
{
	struct udma_caps *caps = &udma_dev->caps;
	int buff_sz;

	buff_sz = (1 << caps->reorder_cq_shift) * caps->cqe_sz;
	qp_attr->reorder_cq_size = buff_sz;
	qp_attr->reorder_cq_page = dma_alloc_coherent(udma_dev->dev, buff_sz,
						      &qp_attr->reorder_cq_addr,
						      GFP_KERNEL);
	if (!qp_attr->reorder_cq_page) {
		dev_err(udma_dev->dev, "Dma alloc coherent failed\n");
		return -ENOMEM;
	}
	return 0;
}

static void udma_free_reorder_cq_buf(struct udma_dev *udma_dev,
				     struct udma_qp_attr *qp_attr)
{
	if (qp_attr->reorder_cq_page)
		dma_free_coherent(udma_dev->dev, qp_attr->reorder_cq_size,
				  qp_attr->reorder_cq_page,
				  qp_attr->reorder_cq_addr);
}

int fill_jfr_qp_attr(struct udma_dev *udma_dev, struct udma_qp_attr *qp_attr,
		     struct udma_create_tp_ucmd *ucmd)
{
	struct udma_jfr *udma_jfr;
	struct ubcore_jfr *jfr;

	udma_jfr = (struct udma_jfr *)xa_load(&udma_dev->jfr_table.xa,
					      ucmd->tgt_id.jfr_id);
	if (IS_ERR_OR_NULL(udma_jfr)) {
		dev_err(udma_dev->dev, "failed to find jfr\n");
		return -EINVAL;
	}
	jfr = &udma_jfr->ubcore_jfr;
	qp_attr->jfr = udma_jfr;
	qp_attr->recv_jfc = to_udma_jfc(jfr->jfr_cfg.jfc);
	qp_attr->uctx = qp_attr->jfr->ubcore_jfr.uctx;
	qp_attr->qpn_map = &qp_attr->jfr->qpn_map;

	if (jfr->jfr_cfg.trans_mode == UBCORE_TP_UM) {
		dev_err(udma_dev->dev, "jfr tp mode error\n");
		return -EINVAL;
	}

	qp_attr->qp_type = QPT_RC;
	qp_attr->cap.min_rnr_timer = jfr->jfr_cfg.min_rnr_timer;

	return 0;
}

int udma_fill_qp_attr(struct udma_dev *udma_dev, struct udma_qp_attr *qp_attr,
		      const struct ubcore_tp_cfg *cfg, struct ubcore_udata *udata)
{
	bool is_target = udata->uctx == NULL ? true : false;
	struct udma_create_tp_ucmd ucmd;
	struct udma_ucontext *udma_ctx;
	int status = 0;

	if (!udata)
		return 0;

	if (!is_target) {
		status = copy_from_user(&ucmd, (void *)udata->udrv_data->in_addr,
					min(udata->udrv_data->in_len,
					    (uint32_t)sizeof(ucmd)));
		if (status) {
			dev_err(udma_dev->dev, "failed to copy create tp ucmd\n");
			return status;
		}
	} else {
		memcpy(&ucmd, (void *)udata->udrv_data->in_addr,
		       min(udata->udrv_data->in_len, (uint32_t)sizeof(ucmd)));
	}

	qp_attr->is_tgt = is_target;
	qp_attr->is_jetty = ucmd.is_jetty;
	qp_attr->remote_eid = cfg->peer_eid;
	qp_attr->local_eid = cfg->local_eid;
	udma_ctx = to_udma_ucontext(udata->uctx);

	if (!is_target) {
		qp_attr->pdn = udma_ctx->pdn;
		/* TODO:  fill_jfs_qp_attr */
		return 0;
	}

	if (!ucmd.is_jetty)
		return fill_jfr_qp_attr(udma_dev, qp_attr, &ucmd);

	return status;
}

static void set_rq_size(struct udma_qp *qp, struct udma_qp_cap *cap)
{
	/* set rq param to 0 */
	qp->rq.wqe_cnt = 0;
	qp->rq.max_gs = 1;
	cap->max_recv_wr = 0;
	cap->max_recv_sge = 0;
}

static int set_qp_param(struct udma_dev *udma_dev, struct udma_qp *qp,
			struct ubcore_udata *udata,
			struct udma_create_tp_ucmd *ucmd)
{
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	struct device *dev = udma_dev->dev;
	int ret = 0;

	qp->qp_type = qp_attr->qp_type;

	if (!qp_attr->is_tgt) {
		qp->retry_cnt = qp_attr->cap.retry_cnt;
		qp->ack_timeout = qp_attr->cap.ack_timeout;
		qp->rnr_retry = qp_attr->cap.rnr_retry;
		qp->priority = qp_attr->priority;
	}

	if (qp_attr->cap.max_inline_data > udma_dev->caps.max_sq_inline)
		qp_attr->cap.max_inline_data = udma_dev->caps.max_sq_inline;

	qp->max_inline_data = qp_attr->cap.max_inline_data;

	set_rq_size(qp, &qp_attr->cap);

	if (udata && udata->uctx != NULL) {
		ret = copy_from_user(ucmd, (void *)udata->udrv_data->in_addr,
				     min(udata->udrv_data->in_len,
					 (uint32_t)sizeof(struct udma_create_tp_ucmd)));
		if (ret) {
			dev_err(dev, "failed to copy create tp ucmd\n");
			return ret;
		}

	}

	return ret;
}

static uint8_t get_least_load_bankid_for_qp(struct udma_bank *bank)
{
	uint32_t least_load = bank[0].inuse;
	uint8_t bankid = 0;
	uint32_t bankcnt;
	uint8_t i;

	for (i = 1; i < UDMA_QP_BANK_NUM; i++) {
		bankcnt = bank[i].inuse;
		if (bankcnt < least_load) {
			least_load = bankcnt;
			bankid = i;
		}
	}

	return bankid;
}

static int alloc_qpn_with_bankid(struct udma_bank *bank, uint8_t bankid,
				 uint64_t *qpn)
{
	int idx;

	idx = ida_alloc_range(&bank->ida, bank->next, bank->max, GFP_KERNEL);
	if (idx < 0) {
		idx = ida_alloc_range(&bank->ida, bank->min, bank->max,
				     GFP_KERNEL);
		if (idx < 0)
			return idx;
	}

	bank->next =
		((uint32_t)idx + 1) > bank->max ? bank->min : (uint32_t)idx + 1;

	/* the lower 3 bits is bankid */
	*qpn = (idx << 3) | bankid;

	return 0;
}

static int alloc_qpn(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	struct udma_qpn_bitmap *qpn_map = qp->qp_attr.qpn_map;
	struct device *dev = udma_dev->dev;
	uint64_t num = 0;
	uint8_t bankid;
	int ret;

	if (qpn_map->qpn_shift == 0 || qp->qp_type == QPT_UD) {
		qp->qpn = gen_qpn(qpn_map->qpn_prefix,
				  qpn_map->jid << qpn_map->qpn_shift, 0);
	} else {
		mutex_lock(&qpn_map->bank_mutex);
		bankid = get_least_load_bankid_for_qp(qpn_map->bank);
		ret = alloc_qpn_with_bankid(&qpn_map->bank[bankid], bankid,
					    &num);
		if (ret) {
			dev_err(dev, "failed to alloc QPN, ret = %d\n", ret);
			mutex_unlock(&qpn_map->bank_mutex);
			return ret;
		}
		qpn_map->bank[bankid].inuse++;
		mutex_unlock(&qpn_map->bank_mutex);
		qp->qpn = gen_qpn(qpn_map->qpn_prefix,
				  qpn_map->jid << qpn_map->qpn_shift, num);
	}
	atomic_inc(&qpn_map->ref_num);

	return 0;
}

static void init_qpn_bitmap(struct udma_qpn_bitmap *qpn_map, uint32_t qpn_shift)
{
	int i;

	qpn_map->qpn_shift = qpn_shift;
	mutex_init(&qpn_map->bank_mutex);
	/* reserved 0 for UD */
	qpn_map->bank[0].min = 1;
	qpn_map->bank[0].inuse = 1;
	qpn_map->bank[0].next = qpn_map->bank[0].min;
	for (i = 0; i < UDMA_QP_BANK_NUM; i++) {
		ida_init(&qpn_map->bank[i].ida);
		qpn_map->bank[i].max = (1 << qpn_shift) / UDMA_QP_BANK_NUM - 1;
	}
}

void init_jetty_x_qpn_bitmap(struct udma_dev *dev,
			     struct udma_qpn_bitmap *qpn_map,
			     uint32_t jetty_x_shift,
			     uint32_t prefix, uint32_t jid)
{
#define QPN_SHIFT_MIN 3
	int qpn_shift;

	qpn_shift = dev->caps.num_qps_shift - jetty_x_shift -
		    UDMA_JETTY_X_PREFIX_BIT_NUM;
	if (qpn_shift <= QPN_SHIFT_MIN) {
		qpn_map->qpn_shift = 0;
		return;
	}

	qpn_map->qpn_prefix = prefix <<
			      (dev->caps.num_qps_shift -
			      UDMA_JETTY_X_PREFIX_BIT_NUM);
	qpn_map->jid = jid;
	init_qpn_bitmap(qpn_map, qpn_shift);
}

void clean_jetty_x_qpn_bitmap(struct udma_qpn_bitmap *qpn_map)
{
	int i;

	if (!qpn_map->qpn_shift)
		return;
	mutex_lock(&qpn_map->bank_mutex);
	for (i = 0; i < UDMA_QP_BANK_NUM; i++)
		ida_destroy(&qpn_map->bank[i].ida);
	mutex_unlock(&qpn_map->bank_mutex);
}


static int alloc_qpc(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	struct udma_qp_table *qp_table = &udma_dev->qp_table;
	struct device *dev = udma_dev->dev;
	int ret;

	/* Alloc memory for QPC */
	ret = udma_table_get(udma_dev, &qp_table->qp_table, qp->qpn);
	if (ret) {
		dev_err(dev, "Failed to get QPC table\n");
		goto err_out;
	}

	/* Alloc memory for IRRL */
	ret = udma_table_get(udma_dev, &qp_table->irrl_table, qp->qpn);
	if (ret) {
		dev_err(dev, "Failed to get IRRL table\n");
		goto err_put_qp;
	}

	if (udma_dev->caps.trrl_entry_sz) {
		/* Alloc memory for TRRL */
		ret = udma_table_get(udma_dev, &qp_table->trrl_table,
				     qp->qpn);
		if (ret) {
			dev_err(dev, "Failed to get TRRL table\n");
			goto err_put_irrl;
		}
	}

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL) {
		/* Alloc memory for SCC CTX */
		ret = udma_table_get(udma_dev, &qp_table->sccc_table,
				     qp->qpn);
		if (ret) {
			dev_err(dev, "Failed to get SCC CTX table\n");
			goto err_put_trrl;
		}
	}

	if (udma_dev->caps.reorder_cq_buffer_en) {
		ret = udma_alloc_reorder_cq_buf(udma_dev, &qp->qp_attr);
		if (ret)
			dev_warn(udma_dev->dev,
				 "failed to alloc reorder cq buffer.\n");
	}

	return 0;

err_put_trrl:
	if (udma_dev->caps.trrl_entry_sz)
		udma_table_put(udma_dev, &qp_table->trrl_table, qp->qpn);
err_put_irrl:
	udma_table_put(udma_dev, &qp_table->irrl_table, qp->qpn);
err_put_qp:
	udma_table_put(udma_dev, &qp_table->qp_table, qp->qpn);
err_out:
	return ret;
}

static void udma_lock_cqs(struct udma_jfc *send_jfc, struct udma_jfc *recv_jfc)
			  __acquires(&send_jfc->lock)
			  __acquires(&recv_jfc->lock)
{
	if (unlikely(send_jfc == NULL && recv_jfc == NULL)) {
		__acquire(&send_jfc->lock);
		__acquire(&recv_jfc->lock);
	} else if (unlikely(send_jfc != NULL && recv_jfc == NULL)) {
		spin_lock_irq(&send_jfc->lock);
		__acquire(&recv_jfc->lock);
	} else if (unlikely(send_jfc == NULL && recv_jfc != NULL)) {
		spin_lock_irq(&recv_jfc->lock);
		__acquire(&send_jfc->lock);
	} else if (send_jfc == recv_jfc) {
		spin_lock_irq(&send_jfc->lock);
		__acquire(&recv_jfc->lock);
	} else if (send_jfc->cqn < recv_jfc->cqn) {
		spin_lock_irq(&send_jfc->lock);
		spin_lock_nested(&recv_jfc->lock, SINGLE_DEPTH_NESTING);
	} else {
		spin_lock_irq(&recv_jfc->lock);
		spin_lock_nested(&send_jfc->lock, SINGLE_DEPTH_NESTING);
	}
}

static void udma_unlock_cqs(struct udma_jfc *send_jfc,
			    struct udma_jfc *recv_jfc)
			__releases(&send_jfc->lock)
			__releases(&recv_jfc->lock)
{
	if (unlikely(send_jfc == NULL && recv_jfc == NULL)) {
		__release(&recv_jfc->lock);
		__release(&send_jfc->lock);
	} else if (unlikely(send_jfc != NULL && recv_jfc == NULL)) {
		__release(&recv_jfc->lock);
		spin_unlock(&send_jfc->lock);
	} else if (unlikely(send_jfc == NULL && recv_jfc != NULL)) {
		__release(&send_jfc->lock);
		spin_unlock(&recv_jfc->lock);
	} else if (send_jfc == recv_jfc) {
		__release(&recv_jfc->lock);
		spin_unlock_irq(&send_jfc->lock);
	} else if (send_jfc->cqn < recv_jfc->cqn) {
		spin_unlock(&recv_jfc->lock);
		spin_unlock_irq(&send_jfc->lock);
	} else {
		spin_unlock(&send_jfc->lock);
		spin_unlock_irq(&recv_jfc->lock);
	}
}

static void add_qp_to_list(struct udma_dev *udma_dev, struct udma_qp *qp,
			   struct udma_jfc *send_jfc, struct udma_jfc *recv_jfc)
{
	unsigned long flags;

	spin_lock_irqsave(&udma_dev->qp_list_lock, flags);
	udma_lock_cqs(send_jfc, recv_jfc);

	list_add_tail(&qp->node, &udma_dev->qp_list);

	if (send_jfc)
		list_add_tail(&qp->sq_node, &send_jfc->sq_list);
	if (recv_jfc)
		list_add_tail(&qp->rq_node, &recv_jfc->rq_list);

	udma_unlock_cqs(send_jfc, recv_jfc);
	spin_unlock_irqrestore(&udma_dev->qp_list_lock, flags);
}

static int udma_qp_store(struct udma_dev *udma_dev,
			 struct udma_qp *qp)
{
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	struct xarray *xa = &udma_dev->qp_table.xa;
	int ret;

	ret = xa_err(xa_store_irq(xa, qp->qpn, qp, GFP_KERNEL));
	if (ret)
		dev_err(udma_dev->dev, "Failed to xa store for QPC\n");
	else
		/* add QP to device's QP list for softwc */
		add_qp_to_list(udma_dev, qp, qp_attr->send_jfc,
			       qp_attr->recv_jfc);

	return ret;
}

static void udma_qp_remove(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	struct xarray *xa = &udma_dev->qp_table.xa;
	struct udma_jfc *send_jfc;
	struct udma_jfc *recv_jfc;
	unsigned long flags;

	send_jfc = qp_attr->send_jfc;
	recv_jfc = qp_attr->recv_jfc;

	xa_lock_irqsave(xa, flags);
	__xa_erase(xa, qp->qpn);
	xa_unlock_irqrestore(xa, flags);

	spin_lock_irqsave(&udma_dev->qp_list_lock, flags);
	udma_lock_cqs(send_jfc, recv_jfc);

	list_del(&qp->node);

	if (send_jfc)
		list_del(&qp->sq_node);
	if (recv_jfc)
		list_del(&qp->rq_node);

	udma_unlock_cqs(send_jfc, recv_jfc);
	spin_unlock_irqrestore(&udma_dev->qp_list_lock, flags);
}

static void free_qpc(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	struct udma_qp_table *qp_table = &udma_dev->qp_table;

	if (udma_dev->caps.reorder_cq_buffer_en)
		udma_free_reorder_cq_buf(udma_dev, &qp->qp_attr);

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL)
		udma_table_put(udma_dev, &qp_table->sccc_table, qp->qpn);

	if (udma_dev->caps.trrl_entry_sz)
		udma_table_put(udma_dev, &qp_table->trrl_table, qp->qpn);

	udma_table_put(udma_dev, &qp_table->irrl_table, qp->qpn);
}

static inline uint8_t get_qp_bankid(uint64_t qpn)
{
	/* The lower 3 bits of QPN are used to hash to different banks */
	return (uint8_t)(qpn & QP_BANKID_MASK);
}

static void free_qpn(struct udma_qp *qp)
{
	struct udma_qpn_bitmap *qpn_map = qp->qp_attr.qpn_map;
	uint8_t bankid;

	if (qpn_map->qpn_shift == 0 || qp->qp_type == QPT_UD)
		return;

	bankid = get_qp_bankid(qp->qpn);

	mutex_lock(&qpn_map->bank_mutex);
	if (!ida_is_empty(&qpn_map->bank[bankid].ida)) {
		ida_free(&qpn_map->bank[bankid].ida,
			 (qp->qpn & GENMASK(qpn_map->qpn_shift - 1, 0)) >>
			 QP_BANKID_SHIFT);
	}
	qpn_map->bank[bankid].inuse--;
	mutex_unlock(&qpn_map->bank_mutex);
}

int udma_create_qp_common(struct udma_dev *udma_dev, struct udma_qp *qp,
			  struct ubcore_udata *udata)
{
	struct device *dev = udma_dev->dev;
	struct udma_create_tp_ucmd ucmd;
	struct udma_create_tp_resp resp;
	int ret;

	qp->state = QPS_RESET;

	ret = set_qp_param(udma_dev, qp, udata, &ucmd);
	if (ret) {
		dev_err(dev, "failed to set QP param, ret = %d.\n", ret);
		return ret;
	}

	ret = alloc_qpn(udma_dev, qp);
	if (ret) {
		dev_err(dev, "failed to alloc QPN, ret = %d.\n", ret);
		goto err_qpn;
	}

	if (!qp->qpn) {
		ret = -EINVAL;
		goto err_qpn;
	}

	ret = alloc_qpc(udma_dev, qp);
	if (ret) {
		dev_err(dev, "failed to alloc QP context, ret = %d.\n",
			ret);
		goto err_qpc;
	}

	ret = udma_qp_store(udma_dev, qp);
	if (ret) {
		dev_err(dev, "failed to store QP, ret = %d.\n", ret);
		goto err_store;
	}

	if (udata && udata->uctx) {
		resp.cap_flags = qp->en_flags;
		resp.qpn = qp->qpn;
		resp.priority = qp->priority;
		resp.path_mtu = udma_dev->caps.max_mtu;
		ret = copy_to_user((void *)udata->udrv_data->out_addr, &resp,
				   min(udata->udrv_data->out_len,
				       (uint32_t)sizeof(resp)));
		if (ret) {
			dev_err(dev, "copy qp resp failed!\n");
			goto err_copy;
		}
	}

	refcount_set(&qp->refcount, 1);
	init_completion(&qp->free);

	return 0;

err_copy:
	udma_qp_remove(udma_dev, qp);
err_store:
	free_qpc(udma_dev, qp);
err_qpc:
	free_qpn(qp);
err_qpn:
	return ret;
}

void udma_destroy_qp_common(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	udma_qp_remove(udma_dev, qp);

	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);
	wait_for_completion(&qp->free);

	free_qpc(udma_dev, qp);
	free_qpn(qp);
}

int udma_init_qp_table(struct udma_dev *dev)
{
	struct udma_qp_table *qp_table = &dev->qp_table;
	uint32_t reserved_from_bot;
	uint32_t i;

	qp_table->idx_table.spare_idx = kcalloc(dev->caps.num_qps,
					sizeof(uint32_t), GFP_KERNEL);
	if (!qp_table->idx_table.spare_idx)
		return -ENOMEM;

	mutex_init(&qp_table->bank_mutex);
	xa_init(&qp_table->xa);

	reserved_from_bot = dev->caps.reserved_qps;

	for (i = 0; i < reserved_from_bot; i++) {
		dev->qp_table.bank[get_qp_bankid(i)].inuse++;
		dev->qp_table.bank[get_qp_bankid(i)].min++;
	}

	for (i = 0; i < UDMA_QP_BANK_NUM; i++) {
		ida_init(&dev->qp_table.bank[i].ida);
		dev->qp_table.bank[i].max = dev->caps.num_qps /
						UDMA_QP_BANK_NUM - 1;
		dev->qp_table.bank[i].next = dev->qp_table.bank[i].min;
	}

	return 0;
}

void udma_cleanup_qp_table(struct udma_dev *dev)
{
	int i;

	for (i = 0; i < UDMA_QP_BANK_NUM; i++)
		ida_destroy(&dev->qp_table.bank[i].ida);
	kfree(dev->qp_table.idx_table.spare_idx);
}

void udma_qp_event(struct udma_dev *udma_dev, uint32_t qpn, int event_type)
{
	struct device *dev = udma_dev->dev;
	struct udma_qp *qp;

	xa_lock(&udma_dev->qp_table.xa);
	qp = (struct udma_qp *)xa_load(&udma_dev->qp_table.xa, qpn);
	if (qp)
		refcount_inc(&qp->refcount);
	xa_unlock(&udma_dev->qp_table.xa);

	if (!qp) {
		dev_warn(dev, "Async event for bogus QP 0x%08x\n", qpn);
		return;
	}

	if (qp->event)
		qp->event(qp, (enum udma_event)event_type);

	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);
}
