/*
 * Copyright (c) 2016 Hisilicon Limited.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/pci.h>
#include <linux/platform_device.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_umem.h>
#include "hns_roce_common.h"
#include "hns_roce_device.h"
#include "hns_roce_hem.h"
#include <rdma/hns-abi.h>

#define SQP_NUM				(2 * HNS_ROCE_MAX_PORTS)

static void flush_work_handle(struct work_struct *work)
{
	struct hns_roce_flush_work *flush_work = container_of(work,
					struct hns_roce_flush_work, work);
	struct hns_roce_qp *hr_qp = flush_work->hr_qp;
	struct device *dev = flush_work->hr_dev->dev;
	struct ib_qp_attr attr;
	int attr_mask;
	int ret;

	attr_mask = IB_QP_STATE;
	attr.qp_state = IB_QPS_ERR;
	hr_qp->flush_en = 1;

	ret = hns_roce_modify_qp(&hr_qp->ibqp, &attr, attr_mask, NULL);
	if (ret)
		dev_err(dev, "Modify qp to err for flush cqe fail(%d)\n", ret);

	kfree(flush_work);
	if (atomic_dec_and_test(&hr_qp->refcount))
		complete(&hr_qp->free);
}

void init_flush_work(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	struct hns_roce_flush_work *flush_work;

	flush_work = kzalloc(sizeof(struct hns_roce_flush_work), GFP_ATOMIC);
	if (ZERO_OR_NULL_PTR(flush_work)) {
		dev_err(hr_dev->dev, "Init flush work queue fail!\n");
		return;
	}
	flush_work->hr_dev = hr_dev;
	flush_work->hr_qp = hr_qp;
	INIT_WORK(&flush_work->work, flush_work_handle);
	atomic_inc(&hr_qp->refcount);
	queue_work(hr_dev->flush_workq, &flush_work->work);
}
EXPORT_SYMBOL_GPL(init_flush_work);

void hns_roce_qp_event(struct hns_roce_dev *hr_dev, u32 qpn, int event_type)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;
	struct device *dev = hr_dev->dev;
	struct hns_roce_qp *qp;

	spin_lock(&qp_table->lock);

	qp = __hns_roce_qp_lookup(hr_dev, qpn);
	if (qp)
		atomic_inc(&qp->refcount);

	spin_unlock(&qp_table->lock);

	if (!qp) {
		dev_warn(dev, "Async event for bogus QP 0x%08x\n", qpn);
		return;
	}

	if (event_type == HNS_ROCE_EVENT_TYPE_WQ_CATAS_ERROR ||
	    event_type == HNS_ROCE_EVENT_TYPE_INV_REQ_LOCAL_WQ_ERROR ||
	    event_type == HNS_ROCE_EVENT_TYPE_LOCAL_WQ_ACCESS_ERROR) {
		qp->state = IB_QPS_ERR;
		init_flush_work(hr_dev, qp);
	}

	qp->event(qp, (enum hns_roce_event)event_type);

	if (atomic_dec_and_test(&qp->refcount))
		complete(&qp->free);
}
EXPORT_SYMBOL_GPL(hns_roce_qp_event);

static void hns_roce_ib_qp_event(struct hns_roce_qp *hr_qp,
				 enum hns_roce_event type)
{
	struct ib_event event;
	struct ib_qp *ibqp = &hr_qp->ibqp;

	if (ibqp->event_handler) {
		event.device = ibqp->device;
		event.element.qp = ibqp;
		switch (type) {
		case HNS_ROCE_EVENT_TYPE_PATH_MIG:
			event.event = IB_EVENT_PATH_MIG;
			break;
		case HNS_ROCE_EVENT_TYPE_COMM_EST:
			event.event = IB_EVENT_COMM_EST;
			break;
		case HNS_ROCE_EVENT_TYPE_SQ_DRAINED:
			event.event = IB_EVENT_SQ_DRAINED;
			break;
		case HNS_ROCE_EVENT_TYPE_SRQ_LAST_WQE_REACH:
			event.event = IB_EVENT_QP_LAST_WQE_REACHED;
			break;
		case HNS_ROCE_EVENT_TYPE_WQ_CATAS_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;
		case HNS_ROCE_EVENT_TYPE_PATH_MIG_FAILED:
			event.event = IB_EVENT_PATH_MIG_ERR;
			break;
		case HNS_ROCE_EVENT_TYPE_INV_REQ_LOCAL_WQ_ERROR:
			event.event = IB_EVENT_QP_REQ_ERR;
			break;
		case HNS_ROCE_EVENT_TYPE_LOCAL_WQ_ACCESS_ERROR:
			event.event = IB_EVENT_QP_ACCESS_ERR;
			break;
		default:
			dev_dbg(ibqp->device->dev.parent,
				"roce_ib:Unexpected eventtype %d on QP%06lx\n",
				type, hr_qp->qpn);
			return;
		}
		ibqp->event_handler(&event, ibqp->qp_context);
	}
}

static int hns_roce_reserve_range_qp(struct hns_roce_dev *hr_dev, int cnt,
				     int align, unsigned long *base)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;

	return hns_roce_bitmap_alloc_range(&qp_table->bitmap, cnt, align, base);
}

enum hns_roce_qp_state to_hns_roce_state(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:
		return HNS_ROCE_QP_STATE_RST;
	case IB_QPS_INIT:
		return HNS_ROCE_QP_STATE_INIT;
	case IB_QPS_RTR:
		return HNS_ROCE_QP_STATE_RTR;
	case IB_QPS_RTS:
		return HNS_ROCE_QP_STATE_RTS;
	case IB_QPS_SQD:
		return HNS_ROCE_QP_STATE_SQD;
	case IB_QPS_ERR:
		return HNS_ROCE_QP_STATE_ERR;
	default:
		return HNS_ROCE_QP_NUM_STATE;
	}
}
EXPORT_SYMBOL_GPL(to_hns_roce_state);

static int hns_roce_gsi_qp_alloc(struct hns_roce_dev *hr_dev, unsigned long qpn,
				 struct hns_roce_qp *hr_qp)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;
	int ret;

	if (!qpn)
		return -EINVAL;

	hr_qp->qpn = qpn;

	spin_lock_irq(&qp_table->lock);
	ret = radix_tree_insert(&hr_dev->qp_table_tree,
				hr_qp->qpn & (hr_dev->caps.num_qps - 1), hr_qp);
	spin_unlock_irq(&qp_table->lock);
	if (ret) {
		dev_err(hr_dev->dev, "GSI QPC radix insert failed(%d), qpn is 0x%lx\n",
			ret, hr_qp->qpn);
		goto err_put_irrl;
	}

	atomic_set(&hr_qp->refcount, 1);
	init_completion(&hr_qp->free);

	return 0;

err_put_irrl:

	return ret;
}

static int hns_roce_qp_alloc(struct hns_roce_dev *hr_dev, unsigned long qpn,
			     struct hns_roce_qp *hr_qp)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;
	struct device *dev = hr_dev->dev;
	int ret;

	if (!qpn)
		return -EINVAL;

	hr_qp->qpn = qpn;

	/* Alloc memory for QPC */
	ret = hns_roce_table_get(hr_dev, &qp_table->qp_table, hr_qp->qpn);
	if (ret) {
		dev_err(dev, "QPC table get failed(%d), qpn 0x%lx\n", ret,
			hr_qp->qpn);
		goto err_out;
	}

	/* Alloc memory for IRRL */
	ret = hns_roce_table_get(hr_dev, &qp_table->irrl_table, hr_qp->qpn);
	if (ret) {
		dev_err(dev, "IRRL table get failed(%d), qpn 0x%lx\n", ret,
			hr_qp->qpn);
		goto err_put_qp;
	}

	if (hr_dev->caps.trrl_entry_sz) {
		/* Alloc memory for TRRL */
		ret = hns_roce_table_get(hr_dev, &qp_table->trrl_table,
					 hr_qp->qpn);
		if (ret) {
			dev_err(dev, "TRRL table get failed(%d), qpn 0x%lx\n",
				ret, hr_qp->qpn);
			goto err_put_irrl;
		}
	}

	if (hr_dev->caps.scc_ctx_entry_sz) {
		/* Alloc memory for SCC CTX */
		ret = hns_roce_table_get(hr_dev, &qp_table->scc_ctx_table,
					 hr_qp->qpn);
		if (ret) {
			dev_err(dev, "SCC CTX table get failed(%d), qpn 0x%lx\n",
				ret, hr_qp->qpn);
			goto err_put_trrl;
		}
	}

	spin_lock_irq(&qp_table->lock);
	ret = radix_tree_insert(&hr_dev->qp_table_tree,
				hr_qp->qpn & (hr_dev->caps.num_qps - 1), hr_qp);
	spin_unlock_irq(&qp_table->lock);
	if (ret) {
		dev_err(dev, "QPC radix_tree_insert failed(%d), qpn - 0x%lx\n",
			ret, hr_qp->qpn);
		goto err_put_scc_ctx;
	}

	atomic_set(&hr_qp->refcount, 1);
	init_completion(&hr_qp->free);

	return 0;

err_put_scc_ctx:
	if (hr_dev->caps.scc_ctx_entry_sz)
		hns_roce_table_put(hr_dev, &qp_table->scc_ctx_table,
				   hr_qp->qpn);

err_put_trrl:
	if (hr_dev->caps.trrl_entry_sz)
		hns_roce_table_put(hr_dev, &qp_table->trrl_table, hr_qp->qpn);

err_put_irrl:
	hns_roce_table_put(hr_dev, &qp_table->irrl_table, hr_qp->qpn);

err_put_qp:
	hns_roce_table_put(hr_dev, &qp_table->qp_table, hr_qp->qpn);

err_out:
	return ret;
}

void hns_roce_qp_remove(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;
	unsigned long flags;

	spin_lock_irqsave(&qp_table->lock, flags);
	radix_tree_delete(&hr_dev->qp_table_tree,
			  hr_qp->qpn & (hr_dev->caps.num_qps - 1));
	spin_unlock_irqrestore(&qp_table->lock, flags);
}
EXPORT_SYMBOL_GPL(hns_roce_qp_remove);

void hns_roce_qp_free(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;

	if (atomic_dec_and_test(&hr_qp->refcount))
		complete(&hr_qp->free);
	wait_for_completion(&hr_qp->free);

	if ((hr_qp->ibqp.qp_type) != IB_QPT_GSI) {
		if (hr_dev->caps.trrl_entry_sz)
			hns_roce_table_put(hr_dev, &qp_table->trrl_table,
					   hr_qp->qpn);
		hns_roce_table_put(hr_dev, &qp_table->irrl_table, hr_qp->qpn);
	}
}
EXPORT_SYMBOL_GPL(hns_roce_qp_free);

void hns_roce_release_range_qp(struct hns_roce_dev *hr_dev, int base_qpn,
			       int cnt)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;

	if (base_qpn < hr_dev->caps.reserved_qps)
		return;

	hns_roce_bitmap_free_range(&qp_table->bitmap, base_qpn, cnt, BITMAP_RR);
}
EXPORT_SYMBOL_GPL(hns_roce_release_range_qp);

static u32 proc_rq_sge(struct hns_roce_dev *dev, struct hns_roce_qp *hr_qp,
	int user)
{
	u32 max_sge = dev->caps.max_rq_sg;

	if (dev->pci_dev->revision > PCI_REVISION_ID_HIP08_B)
		return max_sge;

	/* Reserve SGEs only for HIP08 in kernel; The userspace driver will
	 * calculate number of max_sge with reserved SGEs when allocating wqe
	 * buf, so there is no need to do this again in kernel. But the number
	 * may exceed the capacity of SGEs recorded in the firmware, so the
	 * kernel driver should just adapt the value accordingly.
	 */
	if (user)
		max_sge = roundup_pow_of_two(max_sge + 1);
	else
		hr_qp->rq.rsv_sge = 1;

	return max_sge;
}

static int set_rq_size(struct hns_roce_dev *hr_dev, struct ib_qp_cap *cap,
		       struct hns_roce_qp *hr_qp, int has_rq,  bool user)
{
	u32 max_sge = proc_rq_sge(hr_dev, hr_qp, user);
	struct device *dev = hr_dev->dev;
	u32 cnt;

	/* If srq exist, set zero for relative number of rq */
	if (!has_rq) {
		hr_qp->rq.wqe_cnt = 0;
		hr_qp->rq.max_gs = 0;
		hr_qp->rq_inl_buf.wqe_cnt = 0;
		cap->max_recv_wr = 0;
		cap->max_recv_sge = 0;

		return 0;
	}

	/* Check the validity of QP support capacity */
	if (!cap->max_recv_sge || cap->max_recv_wr > hr_dev->caps.max_wqes ||
	    cap->max_recv_sge > max_sge) {
		dev_err(dev, "RQ config error, depth=%u, sge=%u\n",
			cap->max_recv_wr, cap->max_recv_sge);
		return -EINVAL;
	}

	cnt = roundup_pow_of_two(max(cap->max_recv_wr, hr_dev->caps.min_wqes));
	hr_qp->rq.max_gs =
		roundup_pow_of_two(cap->max_recv_sge + hr_qp->rq.rsv_sge);

	if (hr_dev->caps.max_rq_sg <= HNS_ROCE_SGE_IN_WQE)
		hr_qp->rq.wqe_shift = ilog2(hr_dev->caps.max_rq_desc_sz);
	else
		hr_qp->rq.wqe_shift = ilog2(hr_dev->caps.max_rq_desc_sz *
					    hr_qp->rq.max_gs);

	hr_qp->rq.wqe_cnt = cnt;
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RQ_INLINE &&
	    hr_qp->ibqp.qp_type != IB_QPT_UD &&
	    hr_qp->ibqp.qp_type != IB_QPT_GSI)
		hr_qp->rq_inl_buf.wqe_cnt = cnt;
	else
		hr_qp->rq_inl_buf.wqe_cnt = 0;

	cap->max_recv_wr = cnt;
	cap->max_recv_sge = hr_qp->rq.max_gs - hr_qp->rq.rsv_sge;

	return 0;
}

static u32 get_wqe_ext_sge_cnt(struct hns_roce_qp *qp)
{
	/* GSI/UD QP only has extended sge */
	if (qp->ibqp.qp_type == IB_QPT_GSI || qp->ibqp.qp_type == IB_QPT_UD)
		return qp->sq.max_gs;

	if (qp->sq.max_gs > HNS_ROCE_SGE_IN_WQE)
		return qp->sq.max_gs - HNS_ROCE_SGE_IN_WQE;

	return 0;
}

static void set_ext_sge_param(struct hns_roce_dev *hr_dev, u32 sq_wqe_cnt,
			      struct hns_roce_qp *hr_qp, struct ib_qp_cap *cap)
{
	u32 total_sge_cnt;
	u32 wqe_sge_cnt;

	hr_qp->sge.sge_shift = HNS_ROCE_SGE_SHIFT;

	if (hr_dev->hw_rev == HNS_ROCE_HW_VER1) {
		hr_qp->sq.max_gs = HNS_ROCE_SGE_IN_WQE;
		return;
	}

	hr_qp->sq.max_gs = max(1U, cap->max_send_sge);

	wqe_sge_cnt = get_wqe_ext_sge_cnt(hr_qp);

	/* If the number of extended sge is not zero, they MUST use the
	 * space of HNS_HW_PAGE_SIZE at least.
	 */
	if (wqe_sge_cnt) {
		total_sge_cnt = roundup_pow_of_two(sq_wqe_cnt * wqe_sge_cnt);
		hr_qp->sge.sge_cnt = max(total_sge_cnt,
				(u32)HNS_HW_PAGE_SIZE / HNS_ROCE_SGE_SIZE);
	}
}

static int check_sq_size_with_integrity(struct hns_roce_dev *hr_dev,
					struct ib_qp_cap *cap,
					struct hns_roce_ib_create_qp *ucmd)
{
	u32 roundup_sq_stride = roundup_pow_of_two(hr_dev->caps.max_sq_desc_sz);
	u8 max_sq_stride = ilog2(roundup_sq_stride);

	/* Sanity check SQ size before proceeding */
	if (ucmd->log_sq_stride > max_sq_stride ||
	    ucmd->log_sq_stride < HNS_ROCE_IB_MIN_SQ_STRIDE) {
		dev_err(hr_dev->dev, "failed to check SQ stride size\n");
		return -EINVAL;
	}

	if (cap->max_send_sge > hr_dev->caps.max_sq_sg) {
		dev_err(hr_dev->dev, "failed to check SQ SGE size %u\n",
			cap->max_send_sge);
		return -EINVAL;
	}

	return 0;
}

static int set_user_sq_size(struct hns_roce_dev *hr_dev,
			    struct ib_qp_cap *cap, struct hns_roce_qp *hr_qp,
			    struct hns_roce_ib_create_qp *ucmd)
{
	struct device *dev = hr_dev->dev;
	u32 cnt = 0;
	int ret;

	if (check_shl_overflow(1, ucmd->log_sq_bb_count, &cnt) ||
	    cnt > hr_dev->caps.max_wqes)
		return -EINVAL;

	ret = check_sq_size_with_integrity(hr_dev, cap, ucmd);
	if (ret) {
		dev_err(dev, "failed to check user SQ size\n");
		return ret;
	}

	set_ext_sge_param(hr_dev, cnt, hr_qp, cap);

	hr_qp->sq.wqe_shift = ucmd->log_sq_stride;
	hr_qp->sq.wqe_cnt = cnt;

	return 0;
}

static int set_wqe_buf_attr(struct hns_roce_dev *hr_dev,
			    struct hns_roce_qp *hr_qp,
			    struct hns_roce_buf_attr *buf_attr)
{
	int buf_size;
	int idx = 0;

	hr_qp->buff_size = 0;

	/* SQ WQE */
	hr_qp->sq.offset = 0;
	buf_size = to_hr_hem_entries_size(hr_qp->sq.wqe_cnt,
					  hr_qp->sq.wqe_shift);
	if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = hr_dev->caps.wqe_sq_hop_num;
		idx++;
		hr_qp->buff_size += buf_size;
	}

	/* extend SGE WQE in SQ */
	hr_qp->sge.offset = hr_qp->buff_size;
	buf_size = to_hr_hem_entries_size(hr_qp->sge.sge_cnt,
					  hr_qp->sge.sge_shift);
	if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = hr_dev->caps.wqe_sge_hop_num;
		idx++;
		hr_qp->buff_size += buf_size;
	}

	/* RQ WQE */
	hr_qp->rq.offset = hr_qp->buff_size;
	buf_size = to_hr_hem_entries_size(hr_qp->rq.wqe_cnt,
					  hr_qp->rq.wqe_shift);
	if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = hr_dev->caps.wqe_rq_hop_num;
		idx++;
		hr_qp->buff_size += buf_size;
	}

	if (hr_qp->buff_size < 1)
		return -EINVAL;

	buf_attr->region_count = idx;

	buf_attr->mtt_only = false;
	buf_attr->page_shift = HNS_HW_PAGE_SHIFT + hr_dev->caps.mtt_buf_pg_sz;

	return 0;
}

static int set_kernel_sq_size(struct hns_roce_dev *hr_dev,
			      struct ib_qp_cap *cap, struct hns_roce_qp *hr_qp)
{
	struct device *dev = hr_dev->dev;
	u32 cnt;

	if (!cap->max_send_wr || cap->max_send_wr > hr_dev->caps.max_wqes ||
	    cap->max_send_sge > hr_dev->caps.max_sq_sg) {
		dev_err(dev, "failed to check SQ WR or SGE num, ret = %d.\n",
			-EINVAL);
		return -EINVAL;
	}

	cnt = roundup_pow_of_two(max(cap->max_send_wr, hr_dev->caps.min_wqes));
	if (cnt > hr_dev->caps.max_wqes) {
		dev_err(dev, "failed to check WQE num %u\n", cnt);
		return -EINVAL;
	}

	hr_qp->sq.wqe_shift = ilog2(hr_dev->caps.max_sq_desc_sz);
	hr_qp->sq.wqe_cnt = cnt;

	set_ext_sge_param(hr_dev, cnt, hr_qp, cap);

	/* sync the parameters of kernel QP to user's configuration */
	cap->max_send_wr = cnt;
	cap->max_send_sge = hr_qp->sq.max_gs;

	/* We don't support inline sends for kernel QPs (yet) */
	cap->max_inline_data = 0;

	return 0;
}

static int hns_roce_qp_has_sq(struct ib_qp_init_attr *attr)
{
	if (attr->qp_type == IB_QPT_XRC_TGT || !attr->cap.max_send_wr)
		return 0;

	return 1;
}

static int hns_roce_qp_has_rq(struct ib_qp_init_attr *attr)
{
	if (attr->qp_type == IB_QPT_XRC_INI ||
	    attr->qp_type == IB_QPT_XRC_TGT || attr->srq ||
	    !attr->cap.max_recv_wr)
		return 0;

	return 1;
}

static int hns_roce_alloc_recv_inline_buffer(struct hns_roce_qp *hr_qp,
					     struct ib_qp_init_attr *init_attr)
{
	int ret;
	int i;

	/* allocate recv inline buf */
	hr_qp->rq_inl_buf.wqe_list = kcalloc(hr_qp->rq.wqe_cnt,
					     sizeof(struct hns_roce_rinl_wqe),
					     GFP_KERNEL);
	if (!hr_qp->rq_inl_buf.wqe_list) {
		ret = -ENOMEM;
		goto err;
	}

	hr_qp->rq_inl_buf.wqe_cnt = hr_qp->rq.wqe_cnt;

	/* Firstly, allocate a list of sge space buffer */
	hr_qp->rq_inl_buf.wqe_list[0].sg_list =
					kcalloc(hr_qp->rq_inl_buf.wqe_cnt,
					init_attr->cap.max_recv_sge *
					sizeof(struct hns_roce_rinl_sge),
					GFP_KERNEL);
	if (!hr_qp->rq_inl_buf.wqe_list[0].sg_list) {
		ret = -ENOMEM;
		goto err_wqe_list;
	}

	for (i = 1; i < hr_qp->rq_inl_buf.wqe_cnt; i++)
		/* Secondly, reallocate the buffer */
		hr_qp->rq_inl_buf.wqe_list[i].sg_list =
				     &hr_qp->rq_inl_buf.wqe_list[0].sg_list[i *
				     init_attr->cap.max_recv_sge];

	return 0;

err_wqe_list:
	kfree(hr_qp->rq_inl_buf.wqe_list);

err:
	return ret;
}

static void hns_roce_free_recv_inline_buffer(struct hns_roce_qp *hr_qp)
{
	kfree(hr_qp->rq_inl_buf.wqe_list[0].sg_list);
	kfree(hr_qp->rq_inl_buf.wqe_list);
}

static int alloc_wqe_buf(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			 struct hns_roce_buf_attr *buf_attr,
			 struct ib_uobject *uobject, unsigned long addr)
{
	struct device *dev = hr_dev->dev;
	int ret;

	ret = hns_roce_mtr_create(hr_dev, &hr_qp->mtr, buf_attr,
				  PAGE_SHIFT + hr_dev->caps.mtt_ba_pg_sz,
				  uobject ? uobject->context : NULL, addr);
	if (ret)
		dev_err(dev, "failed to create WQE mtr, ret = %d.\n", ret);

	return ret;
}

static void free_wqe_buf(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			 struct ib_uobject *uobject)
{
	hns_roce_mtr_destroy(hr_dev, &hr_qp->mtr);
}

static void hns_roce_add_cq_to_qp(struct hns_roce_dev *hr_dev,
				  struct hns_roce_qp *hr_qp,
				  struct ib_cq *send_cq, struct ib_cq *recv_cq)
{
	struct hns_roce_cq *hr_send_cq, *hr_recv_cq;
	unsigned long flags;

	if (hr_dev->hw_rev != HNS_ROCE_HW_VER1) {
		hr_send_cq = send_cq ? to_hr_cq(send_cq) : NULL;
		hr_recv_cq = recv_cq ? to_hr_cq(recv_cq) : NULL;

		spin_lock_irqsave(&hr_dev->qp_lock, flags);
		hns_roce_lock_cqs(hr_send_cq, hr_recv_cq);

		list_add_tail(&hr_qp->list, &hr_dev->qp_list);
		if (hr_send_cq)
			list_add_tail(&hr_qp->send_list, &hr_send_cq->sq_list);
		if (hr_recv_cq)
			list_add_tail(&hr_qp->recv_list, &hr_recv_cq->rq_list);

		hns_roce_unlock_cqs(hr_send_cq, hr_recv_cq);
		spin_unlock_irqrestore(&hr_dev->qp_lock, flags);
	}
}

static int alloc_qp_buf(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			struct ib_qp_init_attr *init_attr,
			struct ib_uobject *uobject, unsigned long addr)
{
	struct hns_roce_buf_attr buf_attr = {};
	struct device *dev = hr_dev->dev;
	bool is_rq_buf_inline;
	int ret;

	is_rq_buf_inline = (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RQ_INLINE) &&
			   hns_roce_qp_has_rq(init_attr);
	if (is_rq_buf_inline) {
		ret = hns_roce_alloc_recv_inline_buffer(hr_qp, init_attr);
		if (ret) {
			dev_err(hr_dev->dev, "Failed to alloc inline RQ buffer\n");
			return ret;
		}
	}

	ret = set_wqe_buf_attr(hr_dev, hr_qp, &buf_attr);
	if (ret) {
		dev_err(dev, "failed to set WQE attr, ret = %d.\n", ret);
		goto err_inline;
	}

	ret = alloc_wqe_buf(hr_dev, hr_qp, &buf_attr, uobject, addr);
	if (ret) {
		dev_err(dev, "failed to alloc WQE buf, ret = %d.\n", ret);
		goto err_inline;
	}

	return 0;

err_inline:
	if (is_rq_buf_inline)
		hns_roce_free_recv_inline_buffer(hr_qp);

	return ret;
}

static void free_qp_buf(struct hns_roce_qp *hr_qp, struct ib_pd *ib_pd)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(hr_qp->ibqp.device);

	free_wqe_buf(hr_dev, hr_qp, ib_pd->uobject);

	if ((hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RQ_INLINE) &&
	     hr_qp->rq.wqe_cnt)
		hns_roce_free_recv_inline_buffer(hr_qp);
}

static int set_qp_param(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			struct ib_qp_init_attr *init_attr,
			struct ib_udata *udata,
			struct hns_roce_ib_create_qp *ucmd)
{
	int ret;

	hr_qp->ibqp.qp_type = init_attr->qp_type;

	if (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR)
		hr_qp->sq_signal_bits = IB_SIGNAL_ALL_WR;
	else
		hr_qp->sq_signal_bits = IB_SIGNAL_REQ_WR;

	ret = set_rq_size(hr_dev, &init_attr->cap, hr_qp,
			  hns_roce_qp_has_rq(init_attr), !!udata);
	if (ret) {
		dev_err(hr_dev->dev, "Failed to set user RQ size\n");
		return ret;
	}

	if (udata) {
		if (ib_copy_from_udata(ucmd, udata, sizeof(*ucmd))) {
			dev_err(hr_dev->dev, "Failed to copy QP ucmd\n");
			return -EFAULT;
		}

		ret = set_user_sq_size(hr_dev, &init_attr->cap, hr_qp, ucmd);
		if (ret)
			dev_err(hr_dev->dev, "Failed to set user SQ size\n");
	} else {
		if (init_attr->create_flags &
		    IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK) {
			dev_err(hr_dev->dev, "Failed to check multicast loopback\n");
			return -EINVAL;
		}

		if (init_attr->create_flags & IB_QP_CREATE_IPOIB_UD_LSO) {
			dev_err(hr_dev->dev, "Failed to check ipoib ud lso\n");
			return -EINVAL;
		}

		ret = set_kernel_sq_size(hr_dev, &init_attr->cap, hr_qp);
		if (ret)
			dev_err(hr_dev->dev, "Failed to set kernel SQ size\n");
	}

	return ret;
}

static int hns_roce_create_qp_common(struct hns_roce_dev *hr_dev,
				     struct ib_pd *ib_pd,
				     struct ib_qp_init_attr *init_attr,
				     struct ib_udata *udata, unsigned long sqpn,
				     struct hns_roce_qp *hr_qp)
{
	struct device *dev = hr_dev->dev;
	struct hns_roce_ib_create_qp ucmd;
	struct hns_roce_ib_create_qp_resp resp = {};
	unsigned long qpn = 0;
	int ret;

	mutex_init(&hr_qp->mutex);
	spin_lock_init(&hr_qp->sq.lock);
	spin_lock_init(&hr_qp->rq.lock);

	hr_qp->state = IB_QPS_RESET;
	hr_qp->next_state = IB_QPS_RESET;

	ret = set_qp_param(hr_dev, hr_qp, init_attr, udata, &ucmd);
	if (ret) {
		dev_err(dev, "hns_roce_set_rq_size failed(%d).\n", ret);
		return ret;
	}

	if (ib_pd->uobject) {
		if ((hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SQ_RECORD_DB) &&
		    (udata->inlen >= sizeof(ucmd)) &&
		    (udata->outlen >= sizeof(resp)) &&
		    hns_roce_qp_has_sq(init_attr)) {
			ret = hns_roce_db_map_user(
					to_hr_ucontext(ib_pd->uobject->context),
					ucmd.sdb_addr, &hr_qp->sdb);
			if (ret) {
				dev_err(dev, "SQ record doorbell map failed(%d)!\n",
					ret);
				goto err_out;
			}

			/* indicate kernel supports sq record db */
			resp.cap_flags |= HNS_ROCE_SUPPORT_SQ_RECORD_DB;
			hr_qp->sdb_en = 1;
		}

		if ((hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RECORD_DB) &&
		    (udata->outlen >= sizeof(resp)) &&
		    hns_roce_qp_has_rq(init_attr)) {
			ret = hns_roce_db_map_user(
					to_hr_ucontext(ib_pd->uobject->context),
					ucmd.db_addr, &hr_qp->rdb);
			if (ret) {
				dev_err(dev, "RQ record doorbell map failed(%d)!\n",
					ret);
				goto err_sq_dbmap;
			}

			/* indicate kernel supports rq record db */
			resp.cap_flags |= HNS_ROCE_SUPPORT_RQ_RECORD_DB;
			hr_qp->rdb_en = 1;
		}
	} else {
		/* QP doorbell register address */
		hr_qp->sq.db_reg_l = hr_dev->reg_base + hr_dev->sdb_offset +
				     DB_REG_OFFSET * hr_dev->priv_uar.index;
		hr_qp->rq.db_reg_l = hr_dev->reg_base + hr_dev->odb_offset +
				     DB_REG_OFFSET * hr_dev->priv_uar.index;

		if ((hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RECORD_DB) &&
		    hns_roce_qp_has_rq(init_attr)) {
			ret = hns_roce_alloc_db(hr_dev, &hr_qp->rdb, 0);
			if (ret) {
				dev_err(dev, "RQ record doorbell alloc failed(%d)!\n",
					ret);
				goto err_out;
			}
			*hr_qp->rdb.db_record = 0;
			hr_qp->rdb_en = 1;
		}

		hr_qp->sq.wrid = kcalloc(hr_qp->sq.wqe_cnt, sizeof(u64),
					       GFP_KERNEL);
		if (ZERO_OR_NULL_PTR(hr_qp->sq.wrid)) {
			ret = -ENOMEM;
			goto err_db;
		}

		if (hr_qp->rq.wqe_cnt) {
			hr_qp->rq.wrid = kcalloc(hr_qp->rq.wqe_cnt, sizeof(u64),
						 GFP_KERNEL);
			if (ZERO_OR_NULL_PTR(hr_qp->rq.wrid)) {
				ret = -ENOMEM;
				goto err_sq_wrid;
			}
		}
	}

	if (sqpn) {
		qpn = sqpn;
	} else {
		/* Get QPN */
		ret = hns_roce_reserve_range_qp(hr_dev, 1, 1, &qpn);
		if (ret) {
			dev_err(dev, "hns_roce_reserve_range_qp alloc qpn error\n");
			goto err_buf;
		}
	}

	ret = alloc_qp_buf(hr_dev, hr_qp, init_attr, ib_pd->uobject,
			   ucmd.buf_addr);
	if (ret) {
		dev_err(hr_dev->dev, "Failed to alloc QP buffer\n");
		goto err_db;
	}

	if (init_attr->qp_type == IB_QPT_GSI &&
	    hr_dev->hw_rev == HNS_ROCE_HW_VER1) {
		/* In v1 engine, GSI QP context in RoCE engine's register */
		ret = hns_roce_gsi_qp_alloc(hr_dev, qpn, hr_qp);
		if (ret) {
			dev_err(dev, "Alloc GSI QP failed(%d)!\n", ret);
			goto err_qpn;
		}
	} else {
		ret = hns_roce_qp_alloc(hr_dev, qpn, hr_qp);
		if (ret) {
			dev_err(dev, "Failed to alloc qp!\n");
			goto err_qpn;
		}
	}

	if (sqpn)
		hr_qp->doorbell_qpn = 1;
	else
		hr_qp->doorbell_qpn = (u32)(hr_qp->qpn);

	if (ib_pd->uobject) {
		ret = ib_copy_to_udata(udata, &resp, min(udata->outlen, sizeof(resp)));
		if (ret)
			goto err_qp;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_FLOW_CTRL) {
		ret = hr_dev->hw->qp_flow_control_init(hr_dev, hr_qp);
		if (ret) {
			dev_err(hr_dev->dev, "QP flow control init failure(%d)!",
				ret);
			goto err_qp;
		}
	}

	hr_qp->event = hns_roce_ib_qp_event;
	hns_roce_add_cq_to_qp(hr_dev, hr_qp, init_attr->send_cq,
			      init_attr->recv_cq);

	return 0;

err_qp:
	if (init_attr->qp_type == IB_QPT_GSI &&
		hr_dev->hw_rev == HNS_ROCE_HW_VER1)
		hns_roce_qp_remove(hr_dev, hr_qp);
	else
		hns_roce_qp_free(hr_dev, hr_qp);

err_qpn:
	if (!sqpn)
		hns_roce_release_range_qp(hr_dev, qpn, 1);

err_buf:
	free_qp_buf(hr_qp, ib_pd);

	if (ib_pd->uobject) {
		if ((hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RECORD_DB) &&
		    (udata->outlen >= sizeof(resp)) &&
		    hns_roce_qp_has_rq(init_attr))
			hns_roce_db_unmap_user(
					to_hr_ucontext(ib_pd->uobject->context),
					&hr_qp->rdb);
	} else {
		if (hr_qp->rq.wqe_cnt)
			kfree(hr_qp->rq.wrid);
	}

err_sq_dbmap:
	if (ib_pd->uobject)
		if ((hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SQ_RECORD_DB) &&
		    (udata->inlen >= sizeof(ucmd)) &&
		    (udata->outlen >= sizeof(resp)) &&
		    hns_roce_qp_has_sq(init_attr))
			hns_roce_db_unmap_user(
					to_hr_ucontext(ib_pd->uobject->context),
					&hr_qp->sdb);
err_sq_wrid:
	if (!ib_pd->uobject)
		kfree(hr_qp->sq.wrid);

err_db:
	if (!ib_pd->uobject && hns_roce_qp_has_rq(init_attr) &&
	    (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RECORD_DB))
		hns_roce_free_db(hr_dev, &hr_qp->rdb);

err_out:
	return ret;
}

void hns_roce_qp_destroy(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp)
{
	hns_roce_qp_free(hr_dev, hr_qp);

	/* Not special_QP, free their QPN */
	if (hr_qp->ibqp.qp_type != IB_QPT_GSI)
		hns_roce_release_range_qp(hr_dev, hr_qp->qpn, 1);

	free_qp_buf(hr_qp, hr_qp->ibqp.pd);

	if (hr_qp->ibqp.pd->uobject) {
		struct hns_roce_ucontext *context =
			to_hr_ucontext(hr_qp->ibqp.pd->uobject->context);

		if (hr_qp->sq.wqe_cnt && (hr_qp->sdb_en == 1))
			hns_roce_db_unmap_user(context, &hr_qp->sdb);

		if (hr_qp->rq.wqe_cnt && (hr_qp->rdb_en == 1))
			hns_roce_db_unmap_user(context, &hr_qp->rdb);
	} else {
		kfree(hr_qp->sq.wrid);
		kfree(hr_qp->rq.wrid);
		if (hr_qp->rq.wqe_cnt)
			hns_roce_free_db(hr_dev, &hr_qp->rdb);
	}

	kfree(hr_qp);
}
EXPORT_SYMBOL_GPL(hns_roce_qp_destroy);

struct ib_qp *hns_roce_create_qp(struct ib_pd *pd,
				 struct ib_qp_init_attr *init_attr,
				 struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = pd ? to_hr_dev(pd->device) :
				      to_hr_dev(init_attr->xrcd->device);
	struct device *dev = hr_dev->dev;
	struct hns_roce_qp *hr_qp;
	u16 xrcdn = 0;
	int ret;

	switch (init_attr->qp_type) {
	case IB_QPT_XRC_TGT:
		if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC))
			return ERR_PTR(-EINVAL);
		pd = to_hr_xrcd(init_attr->xrcd)->pd;
		xrcdn = to_hr_xrcd(init_attr->xrcd)->xrcdn;
		init_attr->send_cq = to_hr_xrcd(init_attr->xrcd)->cq;
	case IB_QPT_XRC_INI:
		if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC))
			return ERR_PTR(-EINVAL);
		init_attr->recv_cq = init_attr->send_cq;
	case IB_QPT_UC:
	case IB_QPT_RC: {
		hr_qp = kzalloc(sizeof(*hr_qp), GFP_KERNEL);
		if (!hr_qp)
			return ERR_PTR(-ENOMEM);

		ret = hns_roce_create_qp_common(hr_dev, pd, init_attr, udata, 0,
						hr_qp);
		if (ret) {
			dev_err(dev, "Create RC QP 0x%06lx failed(%d)\n",
				hr_qp->qpn, ret);
			kfree(hr_qp);
			return ERR_PTR(ret);
		}

		hr_qp->ibqp.qp_num = hr_qp->qpn;
		hr_qp->xrcdn = xrcdn;
		break;
	}
	case IB_QPT_GSI: {
		/* Userspace is not allowed to create special QPs: */
		if (pd->uobject) {
			dev_err(dev, "not support usr space GSI\n");
			return ERR_PTR(-EINVAL);
		}

		hr_qp = kzalloc(sizeof(*hr_qp), GFP_KERNEL);
		if (!hr_qp)
			return ERR_PTR(-ENOMEM);

		hr_qp->port = init_attr->port_num - 1;
		hr_qp->phy_port = hr_dev->iboe.phy_port[hr_qp->port];

		/* when hw version is v1, the sqpn is allocated */
		if (hr_dev->caps.max_sq_sg <= HNS_ROCE_MAX_SGE_NUM)
			hr_qp->ibqp.qp_num = HNS_ROCE_MAX_PORTS +
					     hr_dev->iboe.phy_port[hr_qp->port];
		else
			hr_qp->ibqp.qp_num = 1;

		ret = hns_roce_create_qp_common(hr_dev, pd, init_attr, udata,
						hr_qp->ibqp.qp_num, hr_qp);
		if (ret) {
			dev_err(dev, "Create GSI QP failed(%d)!\n", ret);
			kfree(hr_qp);
			return ERR_PTR(ret);
		}

		break;
	}
	default:{
		dev_err(dev, "not support QP type %d\n", init_attr->qp_type);
		return ERR_PTR(-EINVAL);
	}
	}

	rdfx_func_cnt(hr_dev, RDFX_FUNC_CREATE_QP);
	rdfx_alloc_qp_buf(hr_dev, hr_qp);

	hns_roce_inc_rdma_hw_stats(pd->device, HW_STATS_QP_ALLOC);
	return &hr_qp->ibqp;
}
EXPORT_SYMBOL_GPL(hns_roce_create_qp);

int to_hr_qp_type(int qp_type)
{
	int transport_type;

	if (qp_type == IB_QPT_RC)
		transport_type = SERV_TYPE_RC;
	else if (qp_type == IB_QPT_UC)
		transport_type = SERV_TYPE_UC;
	else if (qp_type == IB_QPT_UD)
		transport_type = SERV_TYPE_UD;
	else if (qp_type == IB_QPT_GSI)
		transport_type = SERV_TYPE_UD;
	else if (qp_type == IB_QPT_XRC_INI || qp_type == IB_QPT_XRC_TGT)
		transport_type = SERV_TYPE_XRC;
	else
		transport_type = -1;

	return transport_type;
}
EXPORT_SYMBOL_GPL(to_hr_qp_type);

static int check_mtu_validate(struct hns_roce_dev *hr_dev,
			      struct hns_roce_qp *hr_qp,
			      struct ib_qp_attr *attr, int attr_mask)
{
	struct device *dev = hr_dev->dev;
	enum ib_mtu active_mtu;
	int p;

	p = attr_mask & IB_QP_PORT ? (attr->port_num - 1) : hr_qp->port;
	    active_mtu = iboe_get_mtu(hr_dev->iboe.netdevs[p]->mtu);

	if ((hr_dev->caps.max_mtu >= IB_MTU_2048 &&
	     attr->path_mtu > hr_dev->caps.max_mtu) ||
	     attr->path_mtu < IB_MTU_256 || attr->path_mtu > active_mtu) {
		dev_err(dev, "attr path_mtu(%d)invalid while modify qp(0x%lx)",
			attr->path_mtu, hr_qp->qpn);
		return -EINVAL;
	}

	return 0;
}

static int hns_roce_check_qp_attr(struct ib_qp *ibqp, struct ib_qp_attr *attr,
				  int attr_mask)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibqp->device);
	struct hns_roce_qp *hr_qp = to_hr_qp(ibqp);
	struct device *dev = hr_dev->dev;
	int ret = 0;
	int p;

	if ((attr_mask & IB_QP_PORT) &&
	    (attr->port_num == 0 || attr->port_num > hr_dev->caps.num_ports)) {
		dev_err(dev, "attr port_num invalid.attr->port_num=%d\n",
			attr->port_num);
		return -EINVAL;
	}

	if (attr_mask & IB_QP_PKEY_INDEX) {
		p = attr_mask & IB_QP_PORT ? (attr->port_num - 1) : hr_qp->port;
		if (attr->pkey_index >= hr_dev->caps.pkey_table_len[p]) {
			dev_err(dev,
				"Attr pkey_index(%d) invalid.Max index is %d.\n",
				attr->pkey_index,
				hr_dev->caps.pkey_table_len[p]);
			return -EINVAL;
		}
	}

	if (attr_mask & IB_QP_PATH_MTU) {
		ret = check_mtu_validate(hr_dev, hr_qp, attr, attr_mask);
		if (ret)
			return ret;
	}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC &&
	    attr->max_rd_atomic > hr_dev->caps.max_qp_init_rdma) {
		dev_err(dev, "Attr max_rd_atomic(%d) invalid, max is %d.\n",
			attr->max_rd_atomic, hr_dev->caps.max_qp_init_rdma);
		return -EINVAL;
	}

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC &&
	    attr->max_dest_rd_atomic > hr_dev->caps.max_qp_dest_rdma) {
		dev_err(dev,
			"Attr max_dest_rd_atomic(%d) invalid, max is %d.\n",
			attr->max_dest_rd_atomic,
			hr_dev->caps.max_qp_dest_rdma);
		return -EINVAL;
	}

	return ret;
}

int hns_roce_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		       int attr_mask, struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibqp->device);
	struct hns_roce_qp *hr_qp = to_hr_qp(ibqp);
	enum ib_qp_state cur_state, new_state;
	struct device *dev = hr_dev->dev;
	int ret = 0;

	rdfx_func_cnt(hr_dev, RDFX_FUNC_MODIFY_QP);

	mutex_lock(&hr_qp->mutex);

	if (attr_mask & IB_QP_CUR_STATE && attr->cur_qp_state != hr_qp->state)
		goto out;

	cur_state = hr_qp->state;
	new_state = attr_mask & IB_QP_STATE ?
		    attr->qp_state : cur_state;

	hr_qp->next_state = new_state;
	hr_qp->attr_mask = attr_mask;

	if (ibqp->pd->uobject &&
	    (attr_mask & IB_QP_STATE) && new_state == IB_QPS_ERR) {
		if (hr_qp->sdb_en == 1) {
			hr_qp->sq.head = *(int *)(hr_qp->sdb.virt_addr);

			if (hr_qp->rdb_en == 1)
				hr_qp->rq.head = *(int *)(hr_qp->rdb.virt_addr);
		} else {
			dev_warn(dev, "flush cqe is not supported in userspace!\n");
			ret = -EINVAL;
			goto out;
		}
	}

	if (!ib_modify_qp_is_ok(cur_state, new_state, ibqp->qp_type, attr_mask,
				IB_LINK_LAYER_ETHERNET)) {
		dev_err(dev, "ib_modify_qp_is_ok failed. type: %d, cur_state: %d, new_state: %d, mask: 0x%x.\n",
			ibqp->qp_type, cur_state, new_state, attr_mask);
		ret = -EINVAL;
		goto out;
	}

	ret = hns_roce_check_qp_attr(ibqp, attr, attr_mask);
	if (ret)
		goto out;

	if (cur_state == new_state && cur_state == IB_QPS_RESET) {
		if (hr_dev->hw_rev == HNS_ROCE_HW_VER1) {
			ret = -EPERM;
			dev_err(dev, "RST2RST state is not supported\n");
		}

		goto out;
	}

	ret = hr_dev->hw->modify_qp(ibqp, attr, attr_mask, cur_state,
				    new_state);
	if (ret)
		dev_err(dev, "Modify QP(%08x) failed(%d).\n", ibqp->qp_num,
			ret);

out:
	mutex_unlock(&hr_qp->mutex);

	return ret;
}

void hns_roce_lock_cqs(struct hns_roce_cq *send_cq, struct hns_roce_cq *recv_cq)
		       __acquires(&send_cq->lock) __acquires(&recv_cq->lock)
{
	if (unlikely(!send_cq && !recv_cq)) {
		__acquire(&send_cq->lock);
		__acquire(&recv_cq->lock);
	} else if (unlikely(send_cq && !recv_cq)) {
		spin_lock_irq(&send_cq->lock);
		__acquire(&recv_cq->lock);
	} else if (unlikely(!send_cq && recv_cq)) {
		spin_lock_irq(&recv_cq->lock);
		__acquire(&send_cq->lock);
	} else if (send_cq == recv_cq) {
		spin_lock_irq(&send_cq->lock);
		__acquire(&recv_cq->lock);
	} else if (send_cq->cqn < recv_cq->cqn) {
		spin_lock_irq(&send_cq->lock);
		spin_lock_nested(&recv_cq->lock, SINGLE_DEPTH_NESTING);
	} else {
		spin_lock_irq(&recv_cq->lock);
		spin_lock_nested(&send_cq->lock, SINGLE_DEPTH_NESTING);
	}
}
EXPORT_SYMBOL_GPL(hns_roce_lock_cqs);

void hns_roce_unlock_cqs(struct hns_roce_cq *send_cq,
			 struct hns_roce_cq *recv_cq) __releases(&send_cq->lock)
			 __releases(&recv_cq->lock)
{
	if (unlikely(!send_cq && !recv_cq)) {
		__release(&recv_cq->lock);
		__release(&send_cq->lock);
	} else if (unlikely(send_cq && !recv_cq)) {
		spin_unlock(&send_cq->lock);
		__release(&recv_cq->lock);
	} else if (unlikely(!send_cq && recv_cq)) {
		spin_unlock(&recv_cq->lock);
		__release(&send_cq->lock);
	} else if (send_cq == recv_cq) {
		__release(&recv_cq->lock);
		spin_unlock_irq(&send_cq->lock);
	} else if (send_cq->cqn < recv_cq->cqn) {
		spin_unlock(&recv_cq->lock);
		spin_unlock_irq(&send_cq->lock);
	} else {
		spin_unlock(&send_cq->lock);
		spin_unlock_irq(&recv_cq->lock);
	}
}
EXPORT_SYMBOL_GPL(hns_roce_unlock_cqs);

static void *get_wqe(struct hns_roce_qp *hr_qp, int offset)
{
	return hns_roce_buf_offset(hr_qp->mtr.kmem, offset);
}

void *get_recv_wqe(struct hns_roce_qp *hr_qp, int n)
{
	return get_wqe(hr_qp, hr_qp->rq.offset + (n << hr_qp->rq.wqe_shift));
}
EXPORT_SYMBOL_GPL(get_recv_wqe);

void *get_send_wqe(struct hns_roce_qp *hr_qp, int n)
{
	return get_wqe(hr_qp, hr_qp->sq.offset + (n << hr_qp->sq.wqe_shift));
}
EXPORT_SYMBOL_GPL(get_send_wqe);

void *get_send_extend_sge(struct hns_roce_qp *hr_qp, int n)
{
	return get_wqe(hr_qp, hr_qp->sge.offset + (n << hr_qp->sge.sge_shift));
}
EXPORT_SYMBOL_GPL(get_send_extend_sge);

bool hns_roce_wq_overflow(struct hns_roce_wq *hr_wq, int nreq,
			  struct ib_cq *ib_cq)
{
	struct hns_roce_cq *hr_cq;
	u32 cur;

	cur = hr_wq->head - hr_wq->tail;
	if (likely(cur + nreq < hr_wq->wqe_cnt))
		return false;

	hr_cq = to_hr_cq(ib_cq);
	spin_lock(&hr_cq->lock);
	cur = hr_wq->head - hr_wq->tail;
	spin_unlock(&hr_cq->lock);

	return cur + nreq >= hr_wq->wqe_cnt;
}
EXPORT_SYMBOL_GPL(hns_roce_wq_overflow);

int hns_roce_init_qp_table(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_qp_table *qp_table = &hr_dev->qp_table;
	int reserved_from_top = 0;
	int reserved_from_bot;
	int ret;

	spin_lock_init(&qp_table->lock);
	INIT_RADIX_TREE(&hr_dev->qp_table_tree, GFP_ATOMIC);

	reserved_from_bot = hr_dev->caps.reserved_qps;

	ret = hns_roce_bitmap_init(&qp_table->bitmap, hr_dev->caps.num_qps,
				   hr_dev->caps.num_qps - 1, reserved_from_bot,
				   reserved_from_top);
	if (ret) {
		dev_err(hr_dev->dev, "qp bitmap init failed!error=%d\n",
			ret);
		return ret;
	}

	return 0;
}

void hns_roce_cleanup_qp_table(struct hns_roce_dev *hr_dev)
{
	hns_roce_bitmap_cleanup(&hr_dev->qp_table.bitmap);
}
