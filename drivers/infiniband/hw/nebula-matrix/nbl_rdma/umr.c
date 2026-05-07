// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <rdma/ib_cache.h>
#include "wr.h"
#include "main.h"
#include "umr.h"

static void nbl_recover_umr_qp(struct nbl_device *dev, struct nbl_pd *pd);

void nbl_umr_resource_cleanup(struct nbl_device *dev)
{
}

int nbl_umr_resource_init(struct nbl_device *dev)
{
	return 0;
}

static void nbl_umr_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct nbl_umr_context *context =
		container_of(wc->wr_cqe, struct nbl_umr_context, cqe);

	context->status = wc->status;
	complete(&context->done);
}

static inline void nbl_umr_init_context(struct nbl_umr_context *context)
{
	context->cqe.done = nbl_umr_done;
	init_completion(&context->done);
}

static int nbl_umr_post_send_wait(struct nbl_device *dev, struct ib_send_wr *wr, struct ib_qp *qp)
{
	struct umr_common *umrc = &dev->umrc;
	struct nbl_umr_context umr_context;
	struct nbl_pd *pd = to_nbl_pd(qp->pd);
	int err = 0;

	nbl_umr_init_context(&umr_context);

	down(&pd->sem);
	do {
		if (umrc->state != NBL_UMR_STATE_ACTIVE) {
			err = -EFAULT;
			break;
		}
		wr->wr_cqe = &umr_context.cqe;
		err = ib_post_send(qp, wr, NULL);
		if (err)
			break;

		wait_for_completion(&umr_context.done);
		if (umr_context.status != IB_WC_SUCCESS) {
			nbl_recover_umr_qp(dev, pd);
			err = -EFAULT;
		}
	} while (0);
	up(&pd->sem);

	return err;
}

static struct ib_qp *umr_to_umrqp(struct ib_mr *mr)
{
	struct nbl_pd *pd = to_nbl_pd(mr->pd);

	if (likely(pd->umr_qp))
		return pd->umr_qp;
	else
		return NULL;
}

int nbl_umr_revoke_mr(struct nbl_mr *mr)
{
	struct ib_mr *ibmr = &mr->ibmr;
	struct nbl_device *nbl_dev = to_nbl_dev(ibmr->device);
	struct ib_send_wr wr = {};
	struct ib_qp *umr_qp = umr_to_umrqp(ibmr);

	if (!umr_qp)
		return -EFAULT;

	wr.num_sge = 0;
	wr.next = NULL;
	wr.opcode = IB_WR_LOCAL_INV;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.ex.invalidate_rkey = ibmr->rkey;

	return nbl_umr_post_send_wait(nbl_dev, &wr, umr_qp);
}

int nbl_umr_dmabuf_invcb_mr(struct nbl_mr *mr)
{
	struct ib_mr *ibmr = &mr->ibmr;
	struct nbl_device *nbl_dev = to_nbl_dev(ibmr->device);
	struct ib_send_wr wr = {};
	struct ib_qp *umr_qp = umr_to_umrqp(ibmr);

	if (!umr_qp)
		return -EFAULT;

	wr.num_sge = 0;
	wr.next = NULL;
	wr.opcode = IB_WR_LOCAL_INV;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.ex.invalidate_rkey = mr->stag;

	return nbl_umr_post_send_wait(nbl_dev, &wr, umr_qp);/* TODO: flush PBL */
}

struct ib_qp *nbl_prepare_umr_qp(struct ib_pd *pd, struct ib_qp_init_attr *attr)
{
	struct ib_qp *qp;
	struct nbl_qp *nqp;

	nqp = kzalloc(sizeof(struct nbl_qp), GFP_KERNEL);
	if (!nqp)
		return NULL;
	qp = &nqp->ibqp;

	qp->device = pd->device;
	qp->pd = pd;
	qp->uobject = NULL;
	qp->real_qp = qp;
	qp->qp_type = attr->qp_type;
	qp->send_cq = attr->send_cq;
	qp->recv_cq = attr->recv_cq;
	qp->port = attr->port_num;
	qp->max_write_sge = attr->cap.max_send_sge;
	qp->max_read_sge = min_t(u32, attr->cap.max_send_sge,
				 pd->device->attrs.max_sge_rd);

	atomic_set(&qp->usecnt, 0);
	spin_lock_init(&qp->mr_lock);
	INIT_LIST_HEAD(&qp->rdma_mrs);
	INIT_LIST_HEAD(&qp->sig_mrs);

	return qp;
}

int nbl_create_umr_qp(struct nbl_device *nbl_dev, struct nbl_pd *pd)
{
	return 0;
}

void nbl_destroy_umr_qp(const struct nbl_pd *pd)
{
}

static void nbl_recover_umr_qp(struct nbl_device *dev, struct nbl_pd *pd)
{


	nbl_destroy_umr_qp(pd);

	if (nbl_create_umr_qp(dev, pd))
		nbl_pr_err("recover umr qp failed\n");
	else
		return;
}

void nbl_test_umr_revoke(struct nbl_device *dev, u32 stag)
{
	struct nbl_mr *mr;
	unsigned long flags;

	stag = stag >> 8; /* high 24bits of stag index to mr */

	if (stag >= dev->rf->max_mr) {
		nbl_pr_err("mr lkey:%d out of max\n", stag);
		return;
	}

	spin_lock_irqsave(&dev->rf->mrtable_lock, flags);
	mr = dev->rf->mr_table[stag];
	spin_unlock_irqrestore(&dev->rf->mrtable_lock, flags);

	if (!mr) {
		nbl_pr_err("mr:%d does not exist\n", stag);
		return;
	}

	if (!nbl_umr_revoke_mr(mr))
		nbl_pr_dbg("revoke umr success\n");
	else
		nbl_pr_err("Couldn't revoke UMR\n");
}
