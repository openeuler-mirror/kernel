// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include "wr.h"
#include "umr.h"

void __nbl_umr_resource_cleanup(struct nbl_device *dev)
{
	if (dev->umrc.state == NBL_UMR_STATE_UNINIT)
		return;

	if (dev->umrc.qp)
		ib_destroy_qp(dev->umrc.qp);
	ib_free_cq(dev->umrc.cq);
	ib_dealloc_pd(dev->umrc.pd);

	nbl_pr_dbg("UMR resource exit ok\n");
}

void nbl_umr_resource_cleanup(struct nbl_device *dev)
{
	const struct nbl_feature_ops *ops = dev->rf->product->feature_ops;

	if (nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_UMR))
		ops->umr_resource_cleanup(dev);
}

static int nbl_umr_qp_rst2rts(struct ib_qp *qp)
{
	struct ib_qp_attr attr = {};
	int ret;

	attr.qp_state = IB_QPS_INIT;
	attr.port_num = 1;
	attr.qkey = NBL_DEFF_QKEY;
	ret = ib_modify_qp(qp, &attr,
			   IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT | IB_QP_QKEY);
	if (ret) {
		nbl_pr_err("Couldn't modify UMR QP, err %d\n", ret);
		return ret;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_RTR;

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		nbl_pr_err("Couldn't modify umr QP to rtr, err %d\n", ret);
		return ret;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_RTS;
	ret = ib_modify_qp(qp, &attr, IB_QP_STATE | IB_QP_SQ_PSN);
	if (ret) {
		nbl_pr_err("Couldn't modify umr QP to rts, err %d\n", ret);
		return ret;
	}

	return 0;
}

static int nbl_umr_qp_recover(struct nbl_device *dev)
{
	struct ib_qp_init_attr init_attr = {};
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;
	int ret;

	ib_destroy_qp(dev->umrc.qp);

	pd = dev->umrc.pd;
	cq = dev->umrc.cq;

	init_attr.send_cq = cq;
	init_attr.recv_cq = cq;
	init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	init_attr.cap.max_send_wr = MAX_UMR_WR;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_wr = MAX_UMR_WR;
	init_attr.cap.max_recv_sge = 1;
	init_attr.qp_type = NBL_IB_QPT_REG_UMR;
	init_attr.port_num = 1;
	qp = ib_create_qp(pd, &init_attr);
	if (IS_ERR(qp)) {
		nbl_pr_err("UMR recreate qp err\n");
		ret = PTR_ERR(qp);
		goto err_recreate;
	}

	ret = nbl_umr_qp_rst2rts(qp);
	if (ret) {
		nbl_pr_err("UMR remodify qp2rts err\n");
		goto err_remodify;
	}

	dev->umrc.qp = qp;
	dev->umrc.state = NBL_UMR_STATE_ACTIVE;
	return 0;

err_remodify:
	ib_destroy_qp(qp);
err_recreate:
	dev->umrc.qp = NULL;
	dev->umrc.state = NBL_UMR_STATE_ERR;
	return ret;
}

int __nbl_umr_resource_init(struct nbl_device *dev)
{
	struct ib_qp_init_attr init_attr = {};
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;
	int ret;

	pd = ib_alloc_pd(&dev->ibdev, 0);
	if (IS_ERR(pd)) {
		nbl_pr_err("Couldn't create PD for sync UMR QP\n");
		return PTR_ERR(pd);
	}

	cq = ib_alloc_cq(&dev->ibdev, NULL, MAX_UMR_CQE, 0, IB_POLL_SOFTIRQ);
	if (IS_ERR(cq)) {
		nbl_pr_err("Couldn't create CQ for sync UMR QP\n");
		ret = PTR_ERR(cq);
		goto destroy_pd;
	}

	init_attr.send_cq = cq;
	init_attr.recv_cq = cq;
	init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	init_attr.cap.max_send_wr = MAX_UMR_WR;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_wr = MAX_UMR_WR;
	init_attr.cap.max_recv_sge = 1;
	init_attr.qp_type = NBL_IB_QPT_REG_UMR;
	init_attr.port_num = 1;
	qp = ib_create_qp(pd, &init_attr);
	if (IS_ERR(qp)) {
		nbl_pr_err("Couldn't create sync UMR QP\n");
		ret = PTR_ERR(qp);
		goto destroy_cq;
	}

	ret = nbl_umr_qp_rst2rts(qp);
	if (ret)
		goto destroy_qp;

	dev->umrc.qp = qp;
	dev->umrc.cq = cq;
	dev->umrc.pd = pd;

	sema_init(&dev->umrc.sem, 1);
	dev->umrc.state = NBL_UMR_STATE_ACTIVE;

	nbl_pr_dbg("UMR resource init ok\n");

	return 0;

destroy_qp:
	ib_destroy_qp(qp);
destroy_cq:
	ib_free_cq(cq);
destroy_pd:
	ib_dealloc_pd(pd);
	return ret;
}

int nbl_umr_resource_init(struct nbl_device *dev)
{
	const struct nbl_feature_ops *ops = dev->rf->product->feature_ops;

	if (!nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_UMR))
		return 0;

	return ops->umr_resource_init(dev);
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

static int nbl_umr_post_send_wait(struct nbl_device *dev, struct umr_wr *umrwr)
{
	struct umr_common *umrc = &dev->umrc;
	struct nbl_umr_context umr_context;
	int err = 0;

	nbl_umr_init_context(&umr_context);

	down(&umrc->sem);
	do {
		if (umrc->state != NBL_UMR_STATE_ACTIVE) {
			err = -EFAULT;
			break;
		}

		err = nbl_umr_post_send(umrc->qp, &umr_context.cqe, umrwr);
		if (err) {
			nbl_pr_err("UMR post send failed, err %d\n", err);
			break;
		}

		wait_for_completion(&umr_context.done);

		if (umr_context.status == IB_WC_SUCCESS)
			break;

		nbl_pr_err("UMR failed(wc stat: %u), now recover umr qp\n",
			umr_context.status);
		err = nbl_umr_qp_recover(dev);
		if (err)
			nbl_pr_err("UMR recover failed, err %d\n", err);

		err = -EFAULT;
	} while (0);
	up(&umrc->sem);

	return err;
}

int nbl_umr_revoke_mr(struct nbl_mr *mr)
{
	struct ib_mr *ibmr = &mr->ibmr;
	struct nbl_device *nbl_dev = to_nbl_dev(ibmr->device);
	struct umr_wr wr = {};

	if (!nbl_product_cap_enabled(nbl_dev->rf, NBL_PRODUCT_CAP_UMR))
		return -EOPNOTSUPP;

	wr.opcode = NBL_UMR_OP_REVOKE;
	wr.mkey = mr->stag;

	return nbl_umr_post_send_wait(nbl_dev, &wr);
}

int nbl_umr_dmabuf_invcb_mr(struct nbl_mr *mr)
{
	struct ib_mr *ibmr = &mr->ibmr;
	struct nbl_device *nbl_dev = to_nbl_dev(ibmr->device);
	struct umr_wr wr = {};

	if (!nbl_product_cap_enabled(nbl_dev->rf, NBL_PRODUCT_CAP_UMR))
		return -EOPNOTSUPP;

	wr.opcode = NBL_UMR_OP_FLDPBL;
	wr.mkey = mr->stag;

	return nbl_umr_post_send_wait(nbl_dev, &wr);
}

void nbl_invalidate_umem(struct ib_umem *umem, void *priv)
{
	struct nbl_mr *mr = priv;

	nbl_umr_revoke_mr(mr);
}

int nbl_umr_dbgfs_handle(struct nbl_device *dev, u32 stag, u8 op)
{
	struct nbl_pci_f *rf = dev->rf;
	struct umr_wr wr = {};

	if (!nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_UMR) ||
	    dev->umrc.state == NBL_UMR_STATE_UNINIT) {
		nbl_pr_err("UMR is not supported or initialized\n");
		return -EOPNOTSUPP;
	}

	wr.opcode = op;
	wr.mkey = stag;

	return nbl_umr_post_send_wait(dev, &wr);
}
