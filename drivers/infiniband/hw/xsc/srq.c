// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/slab.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include "xsc_ib.h"
#include "common/srq.h"
#include "user.h"
#include <linux/list_sort.h>

static int xsc_init_cache_wr(struct ib_srq_init_attr *attr, struct xsc_ib_srq *srq)
{
	int srqn = srq->xsrq.srqn;
	struct xsc_srq_cache_wr *cache_wr = srq->xsrq.cache_wr;

	memset(&cache_wr[srqn], 0, sizeof(struct xsc_srq_cache_wr));
	cache_wr[srqn].max_wr_num = attr->attr.max_wr;
	return 0;
}

void xsc_resotre_cache_srq_wrs(struct xsc_ib_srq *srq, struct xsc_ib_qp *qp)
{
	int srqn = srq->xsrq.srqn;
	struct xsc_srq_cache_wr *cache_wr = srq->xsrq.cache_wr;

	if (qp->srq_tail_wr)
		qp->srq_tail_wr->next = cache_wr[srqn].head_wr;
	if (cache_wr[srqn].head_wr && qp->srq_head_wr)
		cache_wr[srqn].head_wr = qp->srq_head_wr;
}

void xsc_free_one_cache_srq_wr(struct xsc_ib_srq *srq, struct xsc_ib_qp *qp, u64 wr_id)
{
	struct ib_recv_wr *tmp_wr, *prev_wr = NULL;
	int srqn = srq->xsrq.srqn;
	struct xsc_srq_cache_wr *cache_wr = srq->xsrq.cache_wr;
	unsigned long flags;

	spin_lock_irqsave(&srq->lock, flags);
	tmp_wr = qp->srq_head_wr;
	for (; tmp_wr; tmp_wr = tmp_wr->next) {
		if (tmp_wr->wr_id == wr_id) {
			if (prev_wr)
				prev_wr->next = tmp_wr->next;
			else
				qp->srq_head_wr = tmp_wr->next;

			kfree(tmp_wr->sg_list);
			kfree(tmp_wr);
			break;
		}
		prev_wr = tmp_wr;
	}
	cache_wr[srqn].wr_num--;
	spin_unlock_irqrestore(&srq->lock, flags);
}

void xsc_free_all_cache_wrs(struct ib_recv_wr *wr)
{
	struct ib_recv_wr *prev_wr = NULL;

	for (; wr; wr = wr->next) {
		kfree(prev_wr);
		kfree(wr->sg_list);
		prev_wr = wr;
	}
	kfree(prev_wr);
}

static void xsc_destroy_cache_wr(struct xsc_ib_srq *srq)
{
	int srqn = srq->xsrq.srqn;
	struct xsc_srq_cache_wr *cache_wr = srq->xsrq.cache_wr;

	xsc_free_all_cache_wrs(cache_wr[srqn].head_wr);
	memset(&cache_wr[srqn], 0, sizeof(struct xsc_srq_cache_wr));
}

static void xsc_ib_srq_event(struct xsc_core_srq *srq, enum xsc_event type)
{
	struct ib_event event;
	struct ib_srq *ibsrq = &to_xibsrq(srq)->ibsrq;

	if (ibsrq->event_handler) {
		event.device      = ibsrq->device;
		event.element.srq = ibsrq;
		switch (type) {
		default:
			pr_warn("xsc_ib: Unexpected event type %d on SRQ %06x\n",
				type, srq->srqn);
			return;
		}

		ibsrq->event_handler(&event, ibsrq->srq_context);
	}
}

static int create_srq_user(struct ib_pd *pd, struct xsc_ib_srq *srq,
			   struct ib_srq_init_attr *init_attr,
			   struct ib_udata *udata, int buf_size)
{
	struct xsc_ib_dev *dev = to_mdev(pd->device);
	struct xsc_ib_create_srq ucmd = {};
	size_t ucmdlen;

	ucmdlen = min(udata->inlen, sizeof(ucmd));

	if (ib_copy_from_udata(&ucmd, udata, ucmdlen)) {
		xsc_ib_dbg(dev, "failed copy udata\n");
		return -EFAULT;
	}

	if (ucmd.reserved0 || ucmd.reserved1)
		return -EINVAL;

	if (udata->inlen > sizeof(ucmd) &&
	    !ib_is_udata_cleared(udata, sizeof(ucmd),
				 udata->inlen - sizeof(ucmd)))
		return -EINVAL;

	srq->create_type = XSC_SRQ_USER;

	return 0;
}

static int create_srq_kernel(struct xsc_ib_dev *dev, struct xsc_ib_srq *srq,
			     struct ib_srq_init_attr *init_attr, int buf_size)
{
	srq->create_type = XSC_SRQ_KERNEL;
	return 0;
}

static void destroy_srq_user(struct xsc_ib_srq *srq, struct ib_udata *udata)
{
}

static void destroy_srq_kernel(struct xsc_ib_dev *dev, struct xsc_ib_srq *srq)
{
}

int xsc_ib_create_srq(struct ib_srq *ib_srq,
		      struct ib_srq_init_attr *init_attr,
		      struct ib_udata *udata)
{
	struct xsc_ib_dev *dev;
	struct xsc_ib_srq *srq;
	int err;
	struct ib_pd *pd = ib_srq->pd;
	int max_srqs;

	if (pd) {
		dev = to_mdev(pd->device);
	} else {
		pr_warn("%s: no PD for SRQ\n", __func__);
		err = -EINVAL;
		goto err_ret;
	}

	if (init_attr->srq_type != IB_SRQT_BASIC || !xsc_max_srq) {
		err = -EOPNOTSUPP;
		goto err_ret;
	}

	if (xsc_srq_min_wr > xsc_srq_max_wr) {
		xsc_ib_err(dev, "srq parameters not available!!\n");
		err = -EINVAL;
		goto err_ret;
	}

	max_srqs = roundup_pow_of_two(min_t(unsigned int, xsc_max_srq, XSC_MAX_SRQ_NUM));

	/* Sanity check SRQ size before proceeding */
	if (init_attr->attr.max_wr >= dev->xdev->caps.max_srq_wqes) {
		xsc_ib_dbg(dev, "max_wr %d, cap %d\n",
			   init_attr->attr.max_wr,
			   dev->xdev->caps.max_srq_wqes);
		err = -EINVAL;
		goto err_ret;
	}

	srq = to_xsrq(ib_srq);

	mutex_init(&srq->mutex);
	spin_lock_init(&srq->lock);
	srq->xsrq.max    = roundup_pow_of_two(init_attr->attr.max_wr + 1);
	srq->xsrq.max_gs = init_attr->attr.max_sge;

	if (udata)
		err = create_srq_user(pd, srq, NULL, udata, 0);
	else
		err = create_srq_kernel(dev, srq, init_attr, 0);

	if (err) {
		xsc_ib_dbg(dev, "create srq rsc failed, ret %d", err);
		goto err_create_rsc;
	}

	err = xsc_core_create_srq(dev->xdev, &srq->xsrq);
	if (err) {
		xsc_ib_err(dev, "create srq failed, err=%d\n", err);
		goto err_create;
	}
	xsc_ib_dbg(dev, "create SRQ with srqn 0x%x, max_wr %d\n",
		   srq->xsrq.srqn, init_attr->attr.max_wr);

	srq->xsrq.event = xsc_ib_srq_event;
	srq->ibsrq.ext.xrc.srq_num = srq->xsrq.srqn;
	if (srq->xsrq.srqn >= max_srqs) {
		xsc_ib_err(dev, "srq %d exceeded range, max srq number %d!!\n",
			   srq->xsrq.srqn, max_srqs);
		err = -EINVAL;
		goto err_rsp;
	}

	if (udata) {
		struct xsc_ib_create_srq_resp resp = {
			.srqn = srq->xsrq.srqn,
		};

		if (ib_copy_to_udata(udata, &resp,
				     min(udata->outlen, sizeof(resp)))) {
			xsc_ib_dbg(dev, "copy to user failed\n");
			err = -EFAULT;
			goto err_rsp;
		}
	} else {
		err = xsc_init_cache_wr(init_attr, srq);
		if (err)
			goto err_rsp;
		INIT_LIST_HEAD(&srq->xsrq.srq_qp_list);
	}

	init_attr->attr.max_wr = srq->xsrq.max - 1;

	return 0;
err_rsp:
	xsc_core_destroy_srq(dev->xdev, &srq->xsrq);
err_create:
	if (udata)
		destroy_srq_user(srq, udata);
	else
		destroy_srq_kernel(dev, srq);
err_create_rsc:
err_ret:
	return err;
}

int xsc_ib_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
		      enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	/* We don't support resizing SRQs yet */
	if (attr_mask & IB_SRQ_MAX_WR)
		return -EINVAL;

	if (attr_mask & IB_SRQ_LIMIT)
		return -EOPNOTSUPP;

	return 0;
}

int xsc_ib_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *srq_attr)
{
	struct xsc_ib_srq *srq = to_xsrq(ibsrq);

	srq_attr->srq_limit = 0;
	srq_attr->max_wr    = srq->xsrq.max - 1;
	srq_attr->max_sge   = srq->xsrq.max_gs;

	return 0;
}

xsc_ib_destroy_srq_def()
{
	struct xsc_ib_srq *xsrq = to_xsrq(srq);
	struct xsc_ib_dev *dev = to_mdev(srq->device);

	xsc_core_destroy_srq(dev->xdev, &xsrq->xsrq);
	if (xsrq->create_type == XSC_SRQ_USER) {
		destroy_srq_user(xsrq, NULL);
	} else {
		xsc_destroy_cache_wr(xsrq);
		destroy_srq_kernel(dev, xsrq);
	}

	xsc_ib_dbg(dev, "destroy srq %d successfully.\n", xsrq->xsrq.srqn);
	return 0;
}

static int cmp_flush_wqe_cnt(void *priv,
			     const struct list_head *a,
			     const struct list_head *b)
{
	const struct xsc_srq_qp_node *na =
		list_entry(a, struct xsc_srq_qp_node, entry);
	const struct xsc_srq_qp_node *nb =
		list_entry(b, struct xsc_srq_qp_node, entry);

	int fa = atomic_read(&(to_xqp(na->ibqp)->rq.flush_wqe_cnt));
	int fb = atomic_read(&(to_xqp(nb->ibqp)->rq.flush_wqe_cnt));

	return fa - fb;
}

static int xsc_cache_srq_wr(struct xsc_ib_srq *srq, const struct ib_recv_wr *wr, int *nreq)
{
	int i, n;
	int srqn = srq->xsrq.srqn;
	struct xsc_srq_cache_wr *cache_wr = srq->xsrq.cache_wr;
	struct ib_recv_wr *head_wr = NULL, *new_wr = NULL, *prev_wr = NULL;

	for (n = 0; wr; wr = wr->next, n++) {
		new_wr = kcalloc(1, sizeof(struct ib_recv_wr), GFP_KERNEL);
		if (prev_wr)
			prev_wr->next = new_wr;
		else
			head_wr = new_wr;
		new_wr->wr_id = wr->wr_id;
		new_wr->sg_list = kcalloc(wr->num_sge, sizeof(struct ib_sge), GFP_KERNEL);
		for (i = 0; i < wr->num_sge; i++)
			memcpy(&new_wr->sg_list[i], &wr->sg_list[i], sizeof(struct ib_sge));
		new_wr->num_sge = wr->num_sge;
		prev_wr = new_wr;
	};

	if (!cache_wr[srqn].head_wr)
		cache_wr[srqn].head_wr = head_wr;
	else
		cache_wr[srqn].tail_wr->next = head_wr;

	cache_wr[srqn].tail_wr = new_wr;
	cache_wr[srqn].wr_num += n;
	*nreq = n;

	if (cache_wr[srqn].wr_num > cache_wr[srqn].max_wr_num)
		return -1;
	else
		return 0;
}

void xsc_post_cache_wrs(struct xsc_ib_srq *srq, struct xsc_ib_qp *qp, int wr_num, bool init)
{
	int srqn = srq->xsrq.srqn;
	struct xsc_srq_cache_wr *cache_wr = srq->xsrq.cache_wr;
	int err = 0;
	int i;
	const struct ib_recv_wr *tmp_wr;
	const struct ib_recv_wr *bad_wr;
	struct ib_recv_wr *wr_head, *next_wr;

	if (!cache_wr[srqn].head_wr)
		return;

	wr_head = cache_wr[srqn].head_wr;
	next_wr = cache_wr[srqn].head_wr;

	if (init)
		qp->srq_head_wr = wr_head;
	else
		qp->srq_tail_wr->next = wr_head;

	qp->srq_tail_wr = wr_head;
	for (i = 0; next_wr && i < (wr_num - 1); i++) {
		next_wr = next_wr->next;
		if (next_wr)
			qp->srq_tail_wr = next_wr;
	}

	cache_wr[srqn].head_wr = qp->srq_tail_wr->next;
	qp->srq_tail_wr->next = NULL;
	tmp_wr = wr_head;
	err = xsc_ib_post_recv_nodrain(&qp->ibqp, tmp_wr, &bad_wr);
	if (err) {
		qp->srq_tail_wr->next = cache_wr[srqn].head_wr;
		qp->srq_tail_wr = NULL;
		for (; wr_head && (bad_wr->wr_id != wr_head->wr_id); wr_head = wr_head->next)
			qp->srq_tail_wr = wr_head;

		if (!qp->srq_tail_wr) {
			cache_wr[srqn].head_wr = wr_head;
			qp->srq_head_wr = NULL;
		} else {
			cache_wr[srq->xsrq.srqn].head_wr = qp->srq_tail_wr->next;
			qp->srq_tail_wr->next = NULL;
		}
	}
}

int xsc_ib_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr)
{
	struct xsc_ib_srq *srq = to_xsrq(ibsrq);
	struct xsc_ib_dev *dev = to_mdev(ibsrq->device);
	struct xsc_srq_qp_node *qp_node;
	struct xsc_ib_qp *qp;
	unsigned long flags;
	int err = 0;
	int flush_wqe_cnt = 0;
	int nreq = 0;
	int wr_num = 0;
	unsigned int srq_wr_num;

	spin_lock_irqsave(&srq->lock, flags);

	err = xsc_cache_srq_wr(srq, wr, &nreq);
	if (err) {
		xsc_ib_err(dev, "No more space to cache SRQ WRs...");
		err = -EINVAL;
		*bad_wr = wr;
		goto out;
	}

	if (list_empty(&srq->xsrq.srq_qp_list))
		goto out;

	list_sort(NULL, &srq->xsrq.srq_qp_list, cmp_flush_wqe_cnt);

	list_for_each_entry(qp_node, &srq->xsrq.srq_qp_list, entry) {
		if (!qp_node || nreq <= 0)
			break;

		qp = to_xqp(qp_node->ibqp);
		flush_wqe_cnt = atomic_read(&qp->rq.flush_wqe_cnt);
		srq_wr_num = min_t(unsigned int, xsc_srq_max_wr, dev->xdev->caps.max_wqes);
		srq_wr_num = max_t(unsigned int, srq_wr_num, XSC_SRQ_MIN_WR_NUM);
		wr_num = min_t(int, nreq, (srq_wr_num - flush_wqe_cnt));
		nreq -= wr_num;
		xsc_ib_dbg(dev, "srq_qp_list qp node qp %d, flush cnt %d, nreq %d, wr_num %d\n",
			   qp_node->qp_id, flush_wqe_cnt, nreq, wr_num);
		xsc_post_cache_wrs(srq, qp, wr_num, false);
	}

out:
	spin_unlock_irqrestore(&srq->lock, flags);

	return err;
}

