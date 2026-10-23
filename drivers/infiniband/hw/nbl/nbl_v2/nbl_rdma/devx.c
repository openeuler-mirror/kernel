// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * user access module
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: Peter.Pan <peter.pan@nebula-matrix.com>
 */

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <rdma/uverbs_types.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/nbl_user_ioctl_cmds.h>
#include <rdma/ib_umem.h>
#include <rdma/uverbs_std_types.h>
#include "main.h"
#include "alloc.h"
#include "cq.h"
#include "qp.h"
#include "verbs.h"
#include "cqp.h"
#include "ah.h"
#include "defs.h"
#include "mem.h"
#include "user.h"
#include "debug.h"
#include "ceq.h"
#include "devx.h"
#include "device.h"
#define UVERBS_MODULE_NAME nbl_ib
#include <rdma/uverbs_named_ioctl.h>

static int nbl_dv_get_umem_info(struct nbl_device *nbldev, u32 umem_id,
			u32 offset, int q_size, bool *is_continus)
{
	struct devx_umem *umem = nbldev->rf->devx_umem_table[umem_id];

	if (!umem) {
		nbl_pr_err("No this umem: %d.", umem_id);
		return -EFAULT;
	}

	return nbl_check_umem_period_contiguous(umem->umem, offset, q_size, is_continus);
}

static int nbl_dv_get_first_sg_dma_addr(struct nbl_device *nbldev,
			u32 umem_id, u32 offset, dma_addr_t *pa)
{
	struct devx_umem *umem = nbldev->rf->devx_umem_table[umem_id];
	int err;

	err = nbl_get_umem_period_start(umem->umem, offset, pa);
	if (err) {
		nbl_pr_err("nbl_get_umem_period_start err: %d", err);
		return err;
	}
	if (!IS_ALIGNED(*pa, NBL_ADAPTER_PAGE_SIZE)) {
		nbl_pr_err("address not 4K aligned: 0x%llx.", (u64)*pa);
		return -EFAULT;
	}

	return 0;
}

static int nbl_dv_copy_user_pgaddrs(struct nbl_device *nbldev, u32 umem_id,
			u32 offset, int q_size, u64 *pas)
{
	struct devx_umem *umem = nbldev->rf->devx_umem_table[umem_id];

	if (!IS_ALIGNED(offset, NBL_ADAPTER_PAGE_SIZE) ||
		!IS_ALIGNED(q_size, NBL_ADAPTER_PAGE_SIZE)) {
		nbl_pr_err("address not 4K aligned: offset: %d, size: %d",
			offset, q_size);
		return -EFAULT;
	}

	return nbl_copy_period_pgaddrs(umem->umem, pas, offset, q_size);
}

static int nbl_dv_umem_buf_release(struct nbl_device *dev,
	struct nbl_buf_desc *bd)
{
	struct nbl_sc_dev *sc_dev = &dev->rf->sc_dev;

	if (!bd->pa_continuous) {
		dma_free_coherent(sc_dev->hw->device, NBL_ADAPTER_PAGE_SIZE,
					bd->kmem.va, bd->kmem.pa);
		bd->kmem.va = NULL;
		nbl_ib_dbg(sc_dev, "destroy user, 0-level page freed ok.\n");
	}

	return 0;
}

static int nbl_dv_umem_buf_get(struct nbl_device *nbldev, u32 umem_id,
	u32 offset, u32 q_size, struct nbl_buf_desc *info)
{
	struct nbl_sc_dev *sc_dev = &nbldev->rf->sc_dev;
	bool is_contiguous = false;
	int status;

	status = nbl_dv_get_umem_info(nbldev, umem_id, offset, q_size, &is_contiguous);
	if (status) {
		nbl_ib_err(sc_dev, "dv get umem info err %d\n", status);
		return status;
	}

	info->cq_pg_num = (q_size >> NBL_ADAPTER_PAGE_SHIFT); /* 4K num */

	if (is_contiguous) {
		status = nbl_dv_get_first_sg_dma_addr(nbldev, umem_id, offset, &info->kmem.pa);
		if (status) {
			nbl_ib_err(sc_dev, "dv get continus first pa err %d\n", status);
			return status;
		}

		info->pa_continuous = true;
		info->kmem.va = NULL;
	} else {
		info->kmem.va = nbl_dma_alloc_coherent(sc_dev->hw,
						 NBL_ADAPTER_PAGE_SIZE,
						 &info->kmem.pa, GFP_KERNEL);
		if (!info->kmem.va) {
			nbl_ib_err(sc_dev, "dv alloc kmem va NULL\n");
			return -ENOMEM;
		}
		info->pa_continuous = false;
		status = nbl_dv_copy_user_pgaddrs(nbldev,
					umem_id, offset, q_size, info->kmem.va);
		if (status) {
			nbl_ib_err(sc_dev, "dv copy user pgaddrs err %d\n", status);
			dma_free_coherent(sc_dev->hw->device,
					  NBL_ADAPTER_PAGE_SIZE, info->kmem.va,
					  info->kmem.pa);
			return status;
		}
	}

	return 0;
}

static void nbl_dv_free_user_qp_buffer(struct device *device, struct nbl_dma_mem *mem,
				bool page_mode)
{
	if (page_mode == NBL_LEVEL1_PAGE_MODE)
		dma_free_coherent(device, NBL_ADAPTER_PAGE_SIZE,
					mem->va, mem->pa);
}

static void nbl_dv_free_qp_buffer(struct nbl_qp *qp)
{
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	struct device  *device = qp->device;

	if (uk_qp->has_sq)
		nbl_dv_free_user_qp_buffer(device, &sc_qp->sqmem, sc_qp->sq_pm);

	if (uk_qp->has_rq)
		nbl_dv_free_user_qp_buffer(device, &sc_qp->rqmem, sc_qp->rq_pm);
}

static int nbl_dv_alloc_user_qp_buffer(struct nbl_qp *qp,
			u32 umem_id, u32 offset, int q_size, bool is_sq)
{
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_sc_dev *sc_dev = &nbldev->rf->sc_dev;
	struct nbl_hw *hw = sc_dev->hw;
	struct nbl_dma_mem *mem;
	bool is_contiguous;
	int status = 0;

	status = nbl_dv_get_umem_info(nbldev, umem_id, offset, q_size, &is_contiguous);
	if (status) {
		nbl_ib_err(sc_dev, "dv qp get umem info err %d\n", status);
		return status;
	}

	if (is_sq)
		mem = &qp->sc_qp.sqmem;
	else
		mem = &qp->sc_qp.rqmem;

	if (is_contiguous) {
		if (is_sq)
			qp->sc_qp.sq_pm = NBL_LEVEL0_PAGE_MODE;
		else
			qp->sc_qp.rq_pm = NBL_LEVEL0_PAGE_MODE;

		/* Attention, here mem->va has no use */
		status = nbl_dv_get_first_sg_dma_addr(nbldev, umem_id, offset, &mem->pa);
		if (status) {
			nbl_ib_err(sc_dev, "dv qp get continus first pa err %d\n", status);
			return status;
		}
	} else {
		if (is_sq)
			qp->sc_qp.sq_pm = NBL_LEVEL1_PAGE_MODE;
		else
			qp->sc_qp.rq_pm = NBL_LEVEL1_PAGE_MODE;

		/* just support one page by now*/
		mem->va = nbl_dma_alloc_coherent(hw,
					     NBL_ADAPTER_PAGE_SIZE, &mem->pa,
					     GFP_KERNEL);
		if (!mem->va) {
			nbl_ib_err(sc_dev, "dv qp dma alloc coherent failed.\n");
			return -ENOMEM;
		}

		status = nbl_dv_copy_user_pgaddrs(nbldev, umem_id, offset, q_size, mem->va);
		if (status) {
			nbl_ib_err(sc_dev, "dv qp copy nbl user pgaddrs failed %d\n", status);
			dma_free_coherent(hw->device,
					  NBL_ADAPTER_PAGE_SIZE, mem->va,
					  mem->pa);
			return status;
		}
	}

	return 0;
}

static inline u32 nbl_dv_get_qpn(struct nbl_qp *qp)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	return uk_qp->qpn;
}

static void nbl_dv_qp_init(struct nbl_ucontext *uctx,
		struct nbl_qp *nblqp, u32 *in, u32 *out)
{
	struct nbl_device *nbldev = uctx->nbl_dev;
	struct nbl_sc_dev *sc_dev = &nbldev->rf->sc_dev;
	struct nbl_uk_attrs *uk_attrs = &sc_dev->hw_attrs.uk_attrs;

	nblqp->nbldev = nbldev;
	nblqp->device = sc_dev->hw->device;
	nblqp->sc_qp.sc_dev = sc_dev;
	nblqp->sc_qp.uk_qp.uk_attrs = uk_attrs;
	nblqp->sc_qp.uk_qp.dwqe_en = false;

	/* get ibgda para */
	nblqp->dev_obj->sq_umem_valid = NBLDV_GET(create_qp_in, in, sq_umem_valid);
	nblqp->dev_obj->rq_umem_valid = NBLDV_GET(create_qp_in, in, rq_umem_valid);
	nblqp->dev_obj->use_srq = NBLDV_GET(create_qp_in, in, use_srq);

	nblqp->dev_obj->srqn = NBLDV_GET(create_qp_in, in, srqn);
	nblqp->dev_obj->pdn = NBLDV_GET(create_qp_in, in, pdn);
	nblqp->dev_obj->cqn_snd = NBLDV_GET(create_qp_in, in, cqn_snd);
	nblqp->dev_obj->max_recv_sge = NBLDV_GET(create_qp_in, in, max_recv_sge);
	nblqp->dev_obj->cqn_rcv = NBLDV_GET(create_qp_in, in, cqn_rcv);

	nblqp->dev_obj->log_sq_size = NBLDV_GET(create_qp_in, in, log_sq_size);
	nblqp->dev_obj->sq_umem_id = NBLDV_GET(create_qp_in, in, sq_umem_id);
	nblqp->dev_obj->sq_umem_offset = NBLDV_GET(create_qp_in, in, sq_umem_offset);

	nblqp->dev_obj->log_rq_size = NBLDV_GET(create_qp_in, in, log_rq_size);
	nblqp->dev_obj->rq_umem_id = NBLDV_GET(create_qp_in, in, rq_umem_id);
	nblqp->dev_obj->rq_umem_offset = NBLDV_GET(create_qp_in, in, rq_umem_offset);

	nblqp->qp_state = NBL_QP_STATE_RST;
}

static void nbl_dv_process_qp_type(struct nbl_qp *qp)
{
	struct nbl_dv_qp_info *dev_obj = qp->dev_obj;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	if (dev_obj->use_srq) {
		/* QP use srq */
		uk_qp->use_srq = true;
		uk_qp->has_rq = false;
		uk_qp->srqn = dev_obj->srqn;
	} else {
		uk_qp->use_srq = false;
		uk_qp->has_rq = true;
	}

	uk_qp->has_sq = true;

	if (qp->nbldev->rf->sc_dev.srp_en) {
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_SRP;
		uk_qp->qp_caps = NBL_WRITE_WITH_IMM |
					NBL_SEND_WITH_IMM | NBL_SRP_EN;
	} else {
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_RC;
		uk_qp->qp_caps = NBL_WRITE_WITH_IMM | NBL_SEND_WITH_IMM;
	}
	if (nbl_product_cap_enabled(qp->nbldev->rf, NBL_PRODUCT_CAP_ATOMIC))
		uk_qp->qp_caps |= NBL_ATOMIC;

	/* IBGDA only RC or SRP */
	uk_qp->qp_type = IB_QPT_RC;
}

static int nbl_dv_user_qp_shadow(struct nbl_ucontext *uctx, struct nbl_qp *qp,
			u32 *out)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	struct nbl_hmc_obj_sd_info *qp_sd_info = rf->qp_sd_info;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	struct nbl_ctx_hmc_base_info hmc_info;
	u32 shadh;
	u32 shadl;
	bool found;
	int ret;

	ret = nbl_get_qpc_base_addr(rf, uk_qp->qpn, &hmc_info, qp_sd_info);
	if (ret) {
		nbl_pr_err("get nbl qpc base addr failed.\n");
		return ret;
	}

	shadh = upper_32_bits(hmc_info.pa);
	shadl = lower_32_bits(hmc_info.pa);
	NBLDV_SET(create_qp_out, out, shadow_base_addr_h, shadh);
	NBLDV_SET(create_qp_out, out, shadow_base_addr_l, shadl);
	NBLDV_SET(create_qp_out, out, qpc_size, hmc_info.ctx_size);
	NBLDV_SET(create_qp_out, out, shadow_size, hmc_info.shadow_size);
	NBLDV_SET(create_qp_out, out, shadow_offset, hmc_info.shadow_offset);
	NBLDV_SET(create_qp_out, out, page_size, hmc_info.page_size);

	qp->sc_qp.qp_shadow.va = hmc_info.va + hmc_info.shadow_offset;
	qp->sc_qp.qp_shadow.pa = hmc_info.pa + hmc_info.shadow_offset;
	qp->sc_qp.qp_shadow.size = hmc_info.shadow_size;

	found = nbl_find_shadow_mmap(uctx, hmc_info.pa,
				     hmc_info.page_size);
	if (!found) {
		nbl_pr_dbg(
			"not find valid shadow node, and start to add new shadow node.\n");
		return nbl_add_shadow_mmap(uctx, hmc_info.va, hmc_info.pa,
					   hmc_info.page_size);
	}

	return 0;
}

static int nbl_dv_create_user_qp(struct nbl_ucontext *uctx,
		struct nbl_qp *qp, u32 *out)
{
	struct device *device = qp->device;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	struct nbl_dv_qp_info *dev_obj = qp->dev_obj;
	int state;

	qp->user_mode = 1;

	uk_qp->max_send_wr = (1 << dev_obj->log_sq_size);
	uk_qp->sq_size = dev_obj->log_sq_size;
	state = nbl_dv_alloc_user_qp_buffer(qp,
				dev_obj->sq_umem_id, dev_obj->sq_umem_offset,
				(uk_qp->max_send_wr << 6), true);
	if (state)
		return -ENOMEM;

	if (uk_qp->has_rq) {
		nbl_calc_rqwqe_size(uk_qp, qp->dev_obj->max_recv_sge);
		uk_qp->max_recv_wr = (1 << dev_obj->log_rq_size);
		uk_qp->rq_size = dev_obj->log_rq_size;
		state = nbl_dv_alloc_user_qp_buffer(qp,
				dev_obj->rq_umem_id, dev_obj->rq_umem_offset,
				(uk_qp->max_recv_wr << 6), false);
		if (state)
			goto free_sq_buffer;
	} else {
		uk_qp->max_recv_wr = 0;
		uk_qp->rq_size = 0;
	}

	nbl_dv_user_qp_shadow(uctx, qp, out);

	return 0;

free_sq_buffer:
	nbl_dv_free_user_qp_buffer(device, &sc_qp->sqmem, sc_qp->sq_pm);
	return state;
}

static void nbl_dv_uk_qp_init(struct nbl_qp *qp)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	struct nbl_uk_attrs *uk_attrs = uk_qp->uk_attrs;

	uk_qp->max_send_sge = uk_attrs->max_hw_wq_sges;
	uk_qp->max_recv_sge = 1; /* TODO, add cfg rq sge num */
	uk_qp->back_qp = qp;
	uk_qp->sig_all = false;
}

static int nbl_dv_qp_ref_init(struct nbl_pci_f *rf, struct nbl_qp *qp)
{
	int state;

	state = nbl_cqp_create_qp_cmd(qp);
	if (state)
		return state;

	rf->qp_table[qp->sc_qp.uk_qp.qpn] = qp;
	refcount_set(&qp->refcnt, 1);
	/* flush cnt init to 2 for sq/rq ae come when flush */
	refcount_set(&qp->flush_cnt, NBL_QP_FLUSH_AE_EXP_NUM);

	init_completion(&qp->free_qp);
	init_completion(&qp->flush_qp);
	init_completion(&qp->qp_err);
	mutex_init(&qp->modify_mutex);
	spin_lock_init(&qp->lock);

	return 0;
}

static void nbl_dv_copy_data_to_user(struct nbl_pci_f *rf,
		struct nbl_uk_qp *uk_qp, u32 *out)
{
	NBLDV_SET(create_qp_out, out, qpn, uk_qp->qpn);
	NBLDV_SET(create_qp_out, out, qp_caps, uk_qp->qp_caps);
	NBLDV_SET(create_qp_out, out, seq_num, uk_qp->seq_num);
	NBLDV_SET(create_qp_out, out, dport_id, rf->sc_dev.dport_id);
	NBLDV_SET(create_qp_out, out, dport, rf->sc_dev.dport);
	NBLDV_SET(create_qp_out, out, fwd, rf->sc_dev.fwd);
	NBLDV_SET(create_qp_out, out, rss_lag_en, rf->sc_dev.rss_lag_en);
	NBLDV_SET(create_qp_out, out, tunnel_en, rf->sc_dev.tunnel_en);
	NBLDV_SET(create_qp_out, out, rqe_mult, uk_qp->rqe_mult);
	NBLDV_SET(create_qp_out, out, max_recv_wr, uk_qp->max_recv_wr);
	NBLDV_SET(create_qp_out, out, max_send_wr, uk_qp->max_send_wr);
}

static int nbl_dv_destroy_qp(struct nbl_device *nbldev, struct nbl_qp *nblqp)
{
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct ib_qp *ibqp = &nblqp->ibqp;
	struct nbl_sc_qp *sc_qp = &nblqp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	int ret;

	/* Call qp2err first */
	nbl_modify_qp_to_err(nblqp, NULL);

	nbl_qp_rem_ref(ibqp);
	wait_for_completion(&nblqp->free_qp);

	ret = nbl_cqp_destroy_qp_cmd(nblqp);
	if (ret)
		nbl_ib_err(sc_dev, "destroy qp cqp ret:%d, qpn :%d\n", ret,
				uk_qp->qpn);
	memset(nblqp->sc_qp.qp_shadow.va, 0, nblqp->sc_qp.qp_shadow.size);

	nbl_dv_free_qp_buffer(nblqp);
	nbl_free_qp_hw_queue_mem(rf, sc_qp);
	nbl_free_qp_num(rf, uk_qp->qpn);

	return 0;
}

static int nbl_dv_check_qp_init_attr(struct nbl_qp *nblqp,
	struct nbl_uk_attrs *uk_attrs)
{
	if (nblqp->dev_obj->max_recv_sge > uk_attrs->max_hw_wq_sges) {
		nbl_pr_err("inv para, init_attr max_recv_sge: %u\n",
			nblqp->dev_obj->max_recv_sge);
		return -EINVAL;
	}

	return 0;
}

static int nbl_dv_create_qp(struct nbl_ucontext *uctx,
		struct nbl_qp *qp, u32 *in, u32 *out)
{
	struct nbl_device *nbldev = uctx->nbl_dev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	int state = 0;

	qp->dev_obj = kzalloc(sizeof(struct nbl_dv_qp_info), GFP_KERNEL);
	if (!qp->dev_obj)
		return -ENOMEM;
	qp->is_dev_obj = true;

	nbl_dv_qp_init(uctx, qp, in, out);

	state = nbl_dv_check_qp_init_attr(qp, uk_qp->uk_attrs);
	if (state)
		goto free_qp;

	nbl_dv_process_qp_type(qp);
	state = nbl_get_qp_num(qp);
	if (state)
		goto free_qp;
	nbl_ib_dbg(&rf->sc_dev, "dev obj create qp[%d]\n", qp->ibqp.qp_num);

	state = nbl_alloc_hw_queue_mem(rf, qp);
	if (state)
		goto free_qpn;

	state = nbl_dv_create_user_qp(uctx, qp, out);
	if (state)
		goto free_hw_queue_mem;

	nbl_dv_uk_qp_init(qp);
	nbl_fill_qpc_seq_num(rf, sc_qp);
	nbl_fill_qpc_info(qp, &qp->ctx_info);
	nbl_fill_qp_ctx(qp, sc_qp->qp_ctx_mem.va);
	nbl_copy_qp_ctx(qp);
	state = nbl_dv_qp_ref_init(rf, qp);
	if (state)
		goto free_qp_buffer;

	nbl_dv_copy_data_to_user(rf, uk_qp, out);

	return 0;

free_qp_buffer:
	nbl_dv_free_qp_buffer(qp);
free_hw_queue_mem:
	nbl_free_qp_hw_queue_mem(rf, sc_qp);
free_qpn:
	nbl_free_qp_num(rf, uk_qp->qpn);
free_qp:
	kfree(qp->dev_obj);
	return state;
}

static int nbl_dv_get_ah_info(struct nbl_qp *qp,
				struct nbl_qp_ctx *ctx_info, u32 *in)
{
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	u16 src_addr_idx;
	u8 seq_num;
	u8 src_ip[NBL_SRC_IP_SIZE];
	u16 udp_sport;
	int ret = 0;

	/* TODO, flow lable */
	ctx_info->hop_limit = NBLDV_GET(init2rtr_qp_in, in, hop_limit);
	ctx_info->tclass = NBLDV_GET(init2rtr_qp_in, in, tclass);
	if (nbldev->tcd[0].val >= 0)
		ctx_info->tclass = nbldev->tcd[0].val;
	if (ctx_info->cc_mode == NBL_QCN && (ctx_info->tclass & ECN_CE) != ECN_ECT_1)
		ctx_info->tclass |= ECN_ECT_0;
	ctx_info->sch_net_tc = NBL_GET_PRI_FROM_T2P(
		rf->sc_dev.tc2pri, NBL_GET_PRI_FROM_TOS(ctx_info->tclass));
	uk_qp->db_tc = ctx_info->sch_net_tc;

	memcpy(ctx_info->dest_ip, NBLDV_ADDR_OF(init2rtr_qp_in, in, dst_ip),
		NBLDV_FLD_SZ_BYTES(init2rtr_qp_in, dst_ip));
	memcpy(ctx_info->dest_mac, NBLDV_ADDR_OF(init2rtr_qp_in, in, dst_mac_47_32),
		sizeof(ctx_info->dest_mac));

	if (nbl_gid_in_src_addr_table(nbldev, (union ib_gid *)&ctx_info->dest_ip)) {
		qp->dst_is_local = true;
		ctx_info->dport = NBL_DEFAULT_DPORT_HOST;
		ctx_info->dport_id = rf->vsi_id;
	} else
		qp->dst_is_local = false;

	if (ipv6_addr_v4mapped((struct in6_addr *)ctx_info->dest_ip))
		ctx_info->ipv4 = true;

	ctx_info->vlan_en = false; /* TODO, vlan tag */

	ret = nbl_get_src_addr_info(nbldev,
				NBLDV_GET(init2rtr_qp_in, in, sgid_index),
				&src_addr_idx, src_ip, &seq_num);
	if (ret) {
		nbl_pr_err("get src addr index failed, function_id: %u, sgid_index: %u.\n",
			nbldev->rf->sc_dev.function_id,
			NBLDV_GET(init2rtr_qp_in, in, sgid_index));
		ret = -ENODATA;
		return ret;
	}

	ctx_info->src_addr_idx = src_addr_idx;
	ctx_info->src_addr_idx_seq_num = seq_num;
	memcpy(qp->src_ip, src_ip, NBL_SRC_IP_SIZE);

	udp_sport = NBLDV_GET(init2rtr_qp_in, in, udp_sport);
	if (udp_sport <= IB_ROCE_UDP_ENCAP_VALID_PORT_MAX &&
		udp_sport >= IB_ROCE_UDP_ENCAP_VALID_PORT_MIN)
		ctx_info->udp_sport = udp_sport;
	else
		ctx_info->udp_sport = get_random_u32() % (IB_ROCE_UDP_ENCAP_VALID_PORT_MAX + 1 -
				IB_ROCE_UDP_ENCAP_VALID_PORT_MIN) +
			IB_ROCE_UDP_ENCAP_VALID_PORT_MIN;

	return 0;
}

static int nbl_dv_get_ctx_info(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
	u16 opcode, u32 *in)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	u8 min_rnr_timer;
	u8 timeout;

	u32 max_qp_dest_rd_atom = qp->nbldev->rf->sc_dev.hw_attrs.max_qp_dest_rd_atom;
	u32 max_qp_rd_atom = qp->nbldev->rf->sc_dev.hw_attrs.max_qp_rd_atom;
	int ret;

	if (opcode == NBL_CMD_OP_RST2INIT_QP) {
		/* QP access flag */
		ctx_info->read_en = NBLDV_GET(rst2init_qp_in, in, rre);
		ctx_info->write_en = NBLDV_GET(rst2init_qp_in, in, rwe);
		if (uk_qp->qp_caps & NBL_ATOMIC)
			ctx_info->atomic_en = NBLDV_GET(rst2init_qp_in, in, rae);
	} else if (opcode == NBL_CMD_OP_INIT2RTR_QP) {
		/* DEST QPN */
		ctx_info->dest_qpn = NBLDV_GET(init2rtr_qp_in, in, dst_qp_num);
		nbl_check_srp_ext_bmp_en(qp, ctx_info);

		/* RQ PSN */
		ctx_info->rq_psn = NBLDV_GET(init2rtr_qp_in, in, rq_psn);
		ctx_info->rxp_hpsn = (ctx_info->rq_psn - 1) & NBL_QPC_HPSN_MASK;

		/* MTU */
		if (nbl_get_mtu(ctx_info, qp->nbldev, NBLDV_GET(init2rtr_qp_in, in, patch_mtu)))
			return -EINVAL;

		/* RNR */
		min_rnr_timer = NBLDV_GET(init2rtr_qp_in, in, min_rnr_timer);
		if (min_rnr_timer > NBL_MAX_RNR_TIMER)
			ctx_info->local_rnr_timer_value = NBL_DEFAULT_RNR_TIMER;
		else
			ctx_info->local_rnr_timer_value = min_rnr_timer;
		uk_qp->qp_max_dest_rd_atom = NBLDV_GET(init2rtr_qp_in, in, max_dest_rd_atomic);
		if (uk_qp->qp_max_dest_rd_atom > max_qp_dest_rd_atom)
			return -EINVAL;

		nbl_rtr_set_irq_size(uk_qp->qp_max_dest_rd_atom, ctx_info);
		/* ADDR INFO */
		ret = nbl_dv_get_ah_info(qp, ctx_info, in);
		if (ret)
			return ret;
	} else if (opcode == NBL_CMD_OP_RTR2RTS_QP) {
		timeout = NBLDV_GET(rtr2rts_qp_in, in, timeout);
		if (timeout > NBL_RTO_MAX_VALUE)
			return -EINVAL;
		ctx_info->rto_timer_value = rto_arry[timeout];

		ctx_info->tx_retry_th = NBLDV_GET(rtr2rts_qp_in, in, retry_cnt);
		ctx_info->rnr_retry = NBLDV_GET(rtr2rts_qp_in, in, rnr_retry);

		ctx_info->sq_psn = NBLDV_GET(rtr2rts_qp_in, in, sq_psn);
		ctx_info->psn_max = ctx_info->sq_psn - 1;

		/* OST READ ATOMIC */
		uk_qp->qp_max_rd_atom = NBLDV_GET(rtr2rts_qp_in, in, max_rd_atomic);
		if (uk_qp->qp_max_rd_atom > max_qp_rd_atom)
			return -EINVAL;
		if (nbl_rts_set_irq_size(uk_qp->qp_max_rd_atom,
				uk_qp->qp_max_dest_rd_atom, ctx_info))
			return -EINVAL;
	} else {
		nbl_pr_dbg("TODO\n");
	}

	return 0;
}

static int nbl_dv_get_ibst(u16 opcode, enum ib_qp_state *ibst)
{
	switch (opcode) {
	case NBL_CMD_OP_RST2INIT_QP:
		*ibst = IB_QPS_INIT;
		break;
	case NBL_CMD_OP_INIT2RTR_QP:
		*ibst = IB_QPS_RTR;
		break;
	case NBL_CMD_OP_RTR2RTS_QP:
		*ibst = IB_QPS_RTS;
		break;
	default:
		/* never here */
		nbl_pr_err("unknown dv qp state: %u\n", opcode);
		return -EINVAL;
	}

	return 0;
}

static int nbl_dv_modify_sw_qp_state(struct nbl_qp *qp,
	struct nbl_qp_ctx *ctx_info, enum ib_qp_state ibst)
{
	if (nbl_check_qp_state(qp, ibst, ctx_info))
		return -EINVAL;

	nbl_fill_qp_ctx(qp, qp->sc_qp.qp_ctx_mem.va);

	return 0;
}

static int nbl_dv_modify_hw_qp_state(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
	enum ib_qp_state ibst)
{
	bool issue_flush = false;
	unsigned long flags;

	if (nbl_cqp_modify_qp_cmd(qp->nbldev, qp, ctx_info->qp_st)) {
		nbl_pr_err("nbl modify qp cmd failed. qpn:%#x qp_type :%d, cur_state:%s next state:%s\n",
				qp->ibqp.qp_num, qp->ibqp.qp_type,
				nbl_qp_stat_to_str(qp->qp_state),
				nbl_qp_stat_to_str(ctx_info->qp_st));
		return -EINVAL;
	}

	spin_lock_irqsave(&qp->lock, flags);
	/* qp_state ibqp_state flush_issued used not here, so add spin lock */
	qp->qp_state = ctx_info->qp_st;
	qp->ibqp_state = ibst;
	if ((ctx_info->qp_st == NBL_QP_STATE_ERR) &&
		!qp->flush_issued) {
		qp->flush_issued = true;
		issue_flush = true;
	}
	spin_unlock_irqrestore(&qp->lock, flags);

	if (issue_flush) {
		down(&qp->nbldev->rf->qp_flush_sem);
		/* flush oper is just do our best,
		 * even meet err, we must continue,
		 * so cancel return check here.
		 */
		nbl_flush_operation(qp, qp->nbldev);
		up(&qp->nbldev->rf->qp_flush_sem);
		complete(&qp->qp_err);
	}

	return 0;
}

/* dv modify qp case 1 (protected by mutex lock) */
static int __nbl_dv_modify_qp(struct nbl_ucontext *uctx,
		struct nbl_qp *qp, u16 opcode, u32 *in, u32 *out)
{
	struct nbl_qp_ctx *ctx_info;
	enum ib_qp_state ibst;
	int ret;

	ret = nbl_dv_get_ibst(opcode, &ibst);
	if (ret)
		return ret;

	ctx_info = &qp->ctx_info;
	ret = nbl_dv_get_ctx_info(qp, ctx_info, opcode, in);
	if (ret)
		return ret;

	ret = nbl_dv_modify_sw_qp_state(qp, ctx_info, ibst);
	if (ret)
		return ret;

	ret = nbl_dv_modify_hw_qp_state(qp, ctx_info, ibst);
	if (ret)
		return ret;

	/* TODO, handle reset */

	return 0;
}

static int nbl_dv_modify_qp(struct nbl_ucontext *uctx,
		struct nbl_qp *qp, u16 opcode, u32 *in, u32 *out)
{
	int ret = 0;

	mutex_lock(&qp->modify_mutex);
	ret = __nbl_dv_modify_qp(uctx, qp, opcode, in, out);
	mutex_unlock(&qp->modify_mutex);

	return ret;
}

/* dv modify qp2err (protected by mutex lock), called from qp.c */
int nbl_dv_modify_qp_to_err(struct nbl_qp *qp)
{
	struct nbl_qp_ctx *ctx_info;
	enum ib_qp_state ibst = IB_QPS_ERR;
	int ret;

	ctx_info = &qp->ctx_info;
	ret = nbl_dv_modify_sw_qp_state(qp, ctx_info, ibst);
	if (ret)
		return ret;

	ret = nbl_dv_modify_hw_qp_state(qp, ctx_info, ibst);
	if (ret)
		return ret;

	return 0;
}

static int nbl_dv_destroy_cq(struct nbl_device *nbldev, struct nbl_cq *nblcq)
{
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_res_table *cq_table = &rf->cq_table;
	struct nbl_sc_cq *sccq = &nblcq->sc_cq;
	struct nbl_cq_uk *ukcq = &sccq->cq_uk;
	struct nbl_cq *tmp;

	spin_lock(&cq_table->lock);
	tmp = radix_tree_delete(&cq_table->tree, nblcq->cq_num);
	spin_unlock(&cq_table->lock);
	if (!tmp || tmp != nblcq)
		nbl_pr_err("cq table del err for cq %u\n", nblcq->cq_num);

	rf->cqp_ops->cqp_destroy_cq(rf, sccq);
	nbl_dv_umem_buf_release(nbldev, &ukcq->bdes);

	set_64bit_val(ukcq->shadow_area, 0, 0); /* clean shadow area pi/ci part */

	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_cqs, ukcq->cq_id);

	return 0;
}

static int nbl_dv_cq_user_shadow_init(struct nbl_pci_f *rf, struct nbl_sc_cq *cq,
				struct nbl_ucontext *uctx, u32 *out)
{
	struct nbl_hmc_obj_sd_info *cq_sd_info = rf->cq_sd_info;
	struct nbl_cq_uk *cq_uk = &cq->cq_uk;
	struct shadow_node *cqc_shadow = NULL;
	u32 shadh;
	u32 shadl;

	shadh = upper_32_bits(cq_uk->cqc_base_pa);
	shadl = lower_32_bits(cq_uk->cqc_base_pa);
	NBLDV_SET(create_cq_out, out, shadow_base_addr_h, shadh);
	NBLDV_SET(create_cq_out, out, shadow_base_addr_l, shadl);
	NBLDV_SET(create_cq_out, out, cqc_size, NBL_CQ_CTX_SIZE);
	/* shadow offset from a page 4K OR 2M, for user mode easy calc */
	NBLDV_SET(create_cq_out, out, shadow_offset, cq_uk->shdw_page_offset);
	NBLDV_SET(create_cq_out, out, shadow_size, NBL_CQ_SHADOW_SIZE);
	NBLDV_SET(create_cq_out, out, page_size, cq_sd_info->page_sz);

	cqc_shadow = nbl_find_shadow_mmap(uctx, cq_uk->cqc_base_pa, cq_sd_info->page_sz);
	if (!cqc_shadow)
		return nbl_add_shadow_mmap(uctx, cq_uk->cqc_base_va,
					   cq_uk->cqc_base_pa, cq_sd_info->page_sz);

	return 0;
}

static int nbl_dv_create_cq(struct nbl_ucontext *uctx,
		struct nbl_cq *nblcq, u32 *in, u32 *out)
{
	struct nbl_device *nbldev = uctx->nbl_dev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_res_table *cq_table = &rf->cq_table;
	struct nbl_sc_cq *sccq = &nblcq->sc_cq;
	struct nbl_cq_uk *ukcq = &sccq->cq_uk;
	u32 cq_num = 0;
	int ret;

	sccq->bak_nbl_cq = nblcq;
	sccq->ceq_id = NBLDV_GET(create_cq_in, in, eqn);
	ret = nbl_alloc_rsrc(&rf->rsrc_lock, rf->allocated_cqs, rf->max_cq, &cq_num,
				  &rf->next_cq);
	if (ret) {
		nbl_ib_err(&rf->sc_dev, "CQ id request error, device cq max:%d\n", rf->max_cq);
		return ret;
	}
	nblcq->cq_num = cq_num;
	ukcq->cq_id = cq_num;

	/* TODO, nblcq->refcnt if need */
	nblcq->user_mode = true;
	ukcq->cq_size = (1 << NBLDV_GET(create_cq_in, in, log_cq_size));
	ret = nbl_dv_umem_buf_get(nbldev, NBLDV_GET(create_cq_in, in, umem_id),
		NBLDV_GET(create_cq_in, in, umem_offset),
		(ukcq->cq_size << 6), &ukcq->bdes);
	if (ret)
		goto free_rsrc;

	ret = nbl_create_cq_kernel_shadow(rf, nblcq, rf->cq_sd_info);
	if (ret)
		goto free_buf;

	nbl_sc_cq_init(rf, sccq);

	ret = nbl_dv_cq_user_shadow_init(rf, sccq, uctx, out);
	if (ret)
		goto free_buf;

	sccq->cq_cc = (NBLDV_GET(create_cq_in, in, cc) == 1) ? true : false;

	ret = rf->cqp_ops->cqp_create_cq(rf, sccq);
	if (ret)
		goto free_buf;

	spin_lock(&cq_table->lock);
	ret = radix_tree_insert(&cq_table->tree, nblcq->cq_num, nblcq);
	spin_unlock(&cq_table->lock);
	if (ret)
		goto free_buf;

	return 0;

free_buf:
	nbl_dv_umem_buf_release(nbldev, &ukcq->bdes);
free_rsrc:
	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_cqs, ukcq->cq_id);
	return ret;
}

static bool devx_is_obj_modify_cmd(const void *in, u16 *opcode)
{
	*opcode = NBLDV_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (*opcode) {
	case NBL_CMD_OP_RST2INIT_QP:
	case NBL_CMD_OP_INIT2RTR_QP:
	case NBL_CMD_OP_RTR2RTS_QP:
		return true;
	default:
		return false;
	}
}

static bool devx_is_obj_create_cmd(const void *in, u16 *opcode)
{
	*opcode = NBLDV_GET(general_obj_in_cmd_hdr, in, opcode);

	switch (*opcode) {
	case NBL_CMD_OP_CREATE_CQ:
	case NBL_CMD_OP_CREATE_QP:
		return true;
	default:
		return false;
	}
}

static int UVERBS_HANDLER(NBL_IB_METHOD_DEVX_QUERY_EQN)(
	struct uverbs_attr_bundle *attrs)
{
	return 0;
}

static int UVERBS_HANDLER(NBL_IB_METHOD_DEVX_QUERY_UAR)(
	struct uverbs_attr_bundle *attrs)
{
	return 0;
}

static int UVERBS_HANDLER(NBL_IB_METHOD_DEVX_OTHER)(
	struct uverbs_attr_bundle *attrs)
{
	void *cmd_in = uverbs_attr_get_alloced_ptr(
		attrs, NBL_IB_ATTR_DEVX_OTHER_CMD_IN);
	int cmd_out_len = uverbs_attr_get_len(attrs,
					NBL_IB_ATTR_DEVX_OTHER_CMD_OUT);
	void *cmd_out;
	int err;

	/* TODO, parse cmd and get info from hw */
	nbl_pr_info("cmd in is 0x%x\n", ((u8 *)cmd_in)[0]);

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	/* TODO, handle copy to user space */
	err = uverbs_copy_to(attrs, NBL_IB_ATTR_DEVX_OTHER_CMD_OUT, cmd_out,
			      cmd_out_len);

	return err;
}

static int devx_obj_cleanup(struct ib_uobject *uobject,
			    enum rdma_remove_reason why,
			    struct uverbs_attr_bundle *attrs)
{
	struct devx_obj *obj = uobject->object;
	int ret;

	if (obj->type == DEVX_OBJ_TYPE_QP)
		ret = nbl_dv_destroy_qp(obj->nbldev, &obj->nblqp);
	else if (obj->type == DEVX_OBJ_TYPE_CQ)
		ret = nbl_dv_destroy_cq(obj->nbldev, &obj->nblcq);
	else
		return -EINVAL;

	if (ret)
		return ret;

	kfree(obj);

	return 0;
}

static int UVERBS_HANDLER(NBL_IB_METHOD_DEVX_OBJ_CREATE)(
	struct uverbs_attr_bundle *attrs)
{
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs, NBL_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN);
	int cmd_out_len =  uverbs_attr_get_len(attrs,
					NBL_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT);
	int cmd_in_len = uverbs_attr_get_len(attrs,
					NBL_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN);
	void *cmd_out;
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, NBL_IB_ATTR_DEVX_OBJ_CREATE_HANDLE);
	struct nbl_ucontext *uctx = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct nbl_ucontext, ibucontext);
	struct nbl_device *nbldev = uctx->nbl_dev;
	struct devx_obj *obj;
	u16 opcode;
	int err = -EFAULT;

	if (!devx_is_obj_create_cmd(cmd_in, &opcode))
		return -EINVAL;

	nbl_pr_dbg("obj create with op 0x%x, cmd in len %d\n", opcode, cmd_in_len);

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	obj = kzalloc(sizeof(struct devx_obj), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	if (opcode == NBL_CMD_OP_CREATE_QP) {
		obj->type = DEVX_OBJ_TYPE_QP;
		err = nbl_dv_create_qp(uctx, &obj->nblqp, cmd_in, cmd_out);
		if (err)
			goto obj_free;

		obj->obj_id = nbl_dv_get_qpn(&obj->nblqp);
		NBLDV_SET(create_qp_out, cmd_out, qpn, obj->obj_id);
	} else if (opcode == NBL_CMD_OP_CREATE_CQ) {
		obj->type = DEVX_OBJ_TYPE_CQ;
		err = nbl_dv_create_cq(uctx, &obj->nblcq, cmd_in, cmd_out);
		if (err)
			goto obj_free;

		obj->obj_id = obj->nblcq.cq_num;
		NBLDV_SET(create_cq_out, cmd_out, cqn, obj->obj_id);
	}

	obj->nbldev = nbldev;
	uobj->object = obj;

	err = uverbs_copy_to(attrs, NBL_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT, cmd_out, cmd_out_len);
	if (err)
		goto obj_destroy;

	return 0;

obj_destroy:
	/* the object is already in the hw tables (rf->qp_table/cq_table), so
	 * destroy it here: the uverbs abort path only unwinds objects whose
	 * handler called uverbs_finalize_uobj_create()
	 */
	if (obj->type == DEVX_OBJ_TYPE_QP)
		nbl_dv_destroy_qp(obj->nbldev, &obj->nblqp);
	else if (obj->type == DEVX_OBJ_TYPE_CQ)
		nbl_dv_destroy_cq(obj->nbldev, &obj->nblcq);

	nbl_pr_err("obj create err: %d\n", err);
obj_free:
	kfree(obj);
	return err;
}

static int UVERBS_HANDLER(NBL_IB_METHOD_DEVX_OBJ_MODIFY)(
	struct uverbs_attr_bundle *attrs)
{
	void *cmd_in = uverbs_attr_get_alloced_ptr(attrs, NBL_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN);
	int cmd_out_len = uverbs_attr_get_len(attrs,
					NBL_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT);
	struct ib_uobject *uobj = uverbs_attr_get_uobject(attrs,
							  NBL_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE);
	struct nbl_ucontext *uctx = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct nbl_ucontext, ibucontext);
	struct devx_obj *obj = uobj->object;
	void *cmd_out;
	u16 opcode;
	int err;

	if (obj->type != DEVX_OBJ_TYPE_QP)
		return -EINVAL;

	if (!devx_is_obj_modify_cmd(cmd_in, &opcode))
		return -EINVAL;

	cmd_out = uverbs_zalloc(attrs, cmd_out_len);
	if (IS_ERR(cmd_out))
		return PTR_ERR(cmd_out);

	err = nbl_dv_modify_qp(uctx, &obj->nblqp, opcode, cmd_in, cmd_out);
	if (err)
		return err;

	return uverbs_copy_to(attrs, NBL_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT,
			      cmd_out, cmd_out_len);
}

static int UVERBS_HANDLER(NBL_IB_METHOD_DEVX_OBJ_QUERY)(
	struct uverbs_attr_bundle *attrs)
{
	return 0;
}

static void devx_umem_rem_ref(struct devx_umem *umem)
{
	struct nbl_pci_f *rf = umem->dev->rf;
	unsigned long flags;

	spin_lock_irqsave(&rf->devx_umem_table_lock, flags);
	if (!refcount_dec_and_test(&umem->refcnt)) {
		nbl_pr_dbg("umem refcnt is not zero.");
		spin_unlock_irqrestore(&rf->devx_umem_table_lock, flags);
		return;
	}

	rf->devx_umem_table[umem->umem_id] = NULL;
	spin_unlock_irqrestore(&rf->devx_umem_table_lock, flags);
	complete(&umem->free_umem);
}

static int devx_umem_cleanup(struct ib_uobject *uobject,
			    enum rdma_remove_reason why,
			    struct uverbs_attr_bundle *attrs)
{
	struct devx_umem *obj = uobject->object;
	struct nbl_device *dev = obj->dev;
	struct nbl_pci_f *rf = dev->rf;

	if (!rf->devx_umem_table[obj->umem_id]) {
		nbl_pr_err("no this umem_id in umem_table.");
		return -EFAULT;
	}

	devx_umem_rem_ref(obj);
	wait_for_completion(&obj->free_umem);

	nbl_free_rsrc(&rf->devx_umem_table_lock,
		rf->allocated_devx_umem, obj->umem_id);
	nbl_ib_umem_release(obj->umem, obj->nbl_peer);
	kfree(obj);
	return 0;
}

static int devx_umem_get(struct nbl_device *dev, struct ib_ucontext *ucontext,
				 struct uverbs_attr_bundle *attrs,
				 struct devx_umem *obj)
{
	u64 addr;
	size_t size;
	u32 access;
	int err;

	if (uverbs_copy_from(&addr, attrs, NBL_IB_ATTR_DEVX_UMEM_REG_ADDR) ||
		uverbs_copy_from(&size, attrs, NBL_IB_ATTR_DEVX_UMEM_REG_LEN)) {
		nbl_pr_err("No addr or len in attr err.");
		return -EFAULT;
	}

	err = uverbs_get_flags32(&access, attrs,
				 NBL_IB_ATTR_DEVX_UMEM_REG_ACCESS,
				 IB_ACCESS_LOCAL_WRITE |
				 IB_ACCESS_REMOTE_WRITE |
				 IB_ACCESS_REMOTE_READ);
	if (err)
		return err;

	err = ib_check_mr_access(&dev->ibdev, access);
	if (err) {
		nbl_pr_err("ib_check_mr_access err.");
		return err;
	}

	obj->nbl_peer = false;
	/* maybe gpu mem */
#ifdef CONFIG_INFINIBAND_PEER_MEMORY
	obj->umem = ib_umem_get_peer(&dev->ibdev, addr, size,
		access, 0);
#else
	obj->umem = ib_umem_get(&dev->ibdev, addr, size, access);
#endif
	if (IS_ERR(obj->umem)) {
		nbl_pr_err("ib_umem_get err.");
		return PTR_ERR(obj->umem);
	}

	return 0;
}

static int UVERBS_HANDLER(NBL_IB_METHOD_DEVX_UMEM_REG)(
	struct uverbs_attr_bundle *attrs)
{
	struct devx_umem *obj;
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, NBL_IB_ATTR_DEVX_UMEM_REG_HANDLE);
	struct nbl_ucontext *uctx = rdma_udata_to_drv_context(
		&attrs->driver_udata, struct nbl_ucontext, ibucontext);
	struct nbl_device *dev = to_nbl_dev(uctx->ibucontext.device);
	u32 umem_id;
	int err;

	obj = kzalloc(sizeof(struct devx_umem), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	err = devx_umem_get(dev, &uctx->ibucontext, attrs, obj);
	if (err) {
		nbl_pr_err("umem get err.");
		goto err_obj_free;
	}

	/* alloc umem id */
	err = nbl_alloc_rsrc(&dev->rf->devx_umem_table_lock,
		dev->rf->allocated_devx_umem, dev->rf->max_devx_umem, &umem_id,
		&dev->rf->next_devx_umem);
	if (err) {
		nbl_pr_err("alloc umem id failed.");
		goto err_umem_release;
	}

	dev->rf->devx_umem_table[umem_id] = obj;
	refcount_set(&obj->refcnt, 1);
	init_completion(&obj->free_umem);

	obj->dev = dev;
	uobj->object = obj;
	obj->umem_id = umem_id;
	uverbs_finalize_uobj_create(attrs, NBL_IB_ATTR_DEVX_UMEM_REG_HANDLE);
	err = uverbs_copy_to(attrs, NBL_IB_ATTR_DEVX_UMEM_REG_OUT_ID,
		&umem_id, sizeof(umem_id));
	return err;

err_umem_release:
	nbl_ib_umem_release(obj->umem, obj->nbl_peer);
err_obj_free:
	kfree(obj);
	return err;
}

static int mmap_obj_cleanup(struct ib_uobject *uobject,
			    enum rdma_remove_reason why,
			    struct uverbs_attr_bundle *attrs)
{
	struct rdma_user_mmap_entry *entry = uobject->object;

	rdma_user_mmap_entry_remove(entry);
	return 0;
}

static int UVERBS_HANDLER(NBL_IB_METHOD_UAR_OBJ_ALLOC)(
	struct uverbs_attr_bundle *attrs)
{
	struct ib_uobject *uobj = uverbs_attr_get_uobject(
		attrs, NBL_IB_ATTR_UAR_OBJ_ALLOC_HANDLE);
	struct nbl_ucontext *uctx;
	struct rdma_user_mmap_entry *entry;
	u32 page_idx;
	u64 bar_offset;
	u64 mmap_offset;
	u32 length;
	int err;

	uctx = to_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(uctx))
		return PTR_ERR(uctx);

	mutex_lock(&uctx->ext_sqdb_mutex);
	if (!uctx->ext_sqdb_offset_last ||
	    (uctx->ext_sqdb_offset_first + uctx->ext_sqdb_alloced_num * PAGE_SIZE) >
		uctx->ext_sqdb_offset_last) {
		mutex_unlock(&uctx->ext_sqdb_mutex);
		nbl_pr_err("devx alloc db no page left err\n");
		return -ENOMEM;
	}
	page_idx = uctx->ext_sqdb_alloced_num;
	bar_offset = uctx->ext_sqdb_offset_first + uctx->ext_sqdb_alloced_num * PAGE_SIZE;
	uctx->ext_sqdb_alloced_num++;
	mutex_unlock(&uctx->ext_sqdb_mutex);

	entry = nbl_user_mmap_entry_insert(
		uctx, bar_offset, NBL_MMAP_IO_NC, &mmap_offset);
	if (!entry) {
		/* give the doorbell page back if nobody allocated one after us */
		mutex_lock(&uctx->ext_sqdb_mutex);
		if (uctx->ext_sqdb_alloced_num == page_idx + 1)
			uctx->ext_sqdb_alloced_num--;
		mutex_unlock(&uctx->ext_sqdb_mutex);
		return -ENOMEM;
	}
	length = PAGE_SIZE;
	uobj->object = entry;
	uverbs_finalize_uobj_create(attrs, NBL_IB_ATTR_UAR_OBJ_ALLOC_HANDLE);
	err = uverbs_copy_to(attrs, NBL_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET,
			     &mmap_offset, sizeof(mmap_offset));
	if (err)
		return err;
	err = uverbs_copy_to(attrs, NBL_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID,
			     &page_idx, sizeof(page_idx));
	if (err)
		return err;
	err = uverbs_copy_to(attrs, NBL_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH,
			     &length, sizeof(length));
	nbl_pr_dbg("ext db page %u, bar offset 0x%llx, len %u, mmap offset 0x%llx\n",
		page_idx, bar_offset, length, mmap_offset);
	return err;
}

DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_DEVX_QUERY_EQN,
	UVERBS_ATTR_PTR_IN(NBL_IB_ATTR_DEVX_QUERY_EQN_USER_VEC,
			   UVERBS_ATTR_TYPE(u32),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(NBL_IB_ATTR_DEVX_QUERY_EQN_DEV_EQN,
			    UVERBS_ATTR_TYPE(u32),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_DEVX_QUERY_UAR,
	UVERBS_ATTR_PTR_IN(NBL_IB_ATTR_DEVX_QUERY_UAR_USER_IDX,
			   UVERBS_ATTR_TYPE(u32),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(NBL_IB_ATTR_DEVX_QUERY_UAR_DEV_IDX,
			    UVERBS_ATTR_TYPE(u32),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_DEVX_OTHER,
	UVERBS_ATTR_PTR_IN(
		NBL_IB_ATTR_DEVX_OTHER_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		NBL_IB_ATTR_DEVX_OTHER_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_DEVX_OBJ_CREATE,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_DEVX_OBJ_CREATE_HANDLE,
			NBL_IB_OBJECT_DEVX_OBJ,
			UVERBS_ACCESS_NEW,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(
		NBL_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		NBL_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	NBL_IB_METHOD_DEVX_OBJ_DESTROY,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_DEVX_OBJ_DESTROY_HANDLE,
			NBL_IB_OBJECT_DEVX_OBJ,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_DEVX_OBJ_MODIFY,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE,
			NBL_IB_OBJECT_DEVX_OBJ,
			UVERBS_ACCESS_READ,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(
		NBL_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		NBL_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_DEVX_OBJ_QUERY,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_DEVX_OBJ_QUERY_HANDLE,
			NBL_IB_OBJECT_DEVX_OBJ,
			UVERBS_ACCESS_READ,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(
		NBL_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_in_cmd_hdr)),
		UA_MANDATORY,
		UA_ALLOC_AND_COPY),
	UVERBS_ATTR_PTR_OUT(
		NBL_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT,
		UVERBS_ATTR_MIN_SIZE(NBLDV_ST_SZ_BYTES(general_obj_out_cmd_hdr)),
		UA_MANDATORY));

#define NBL_UVERBS_ATTR_SIZE(_enum_type)                                       \
	UVERBS_ATTR_SIZE(sizeof(u64) + BUILD_BUG_ON_ZERO(!sizeof(_enum_type)), \
			 sizeof(u64))
DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_DEVX_UMEM_REG,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_DEVX_UMEM_REG_HANDLE,
			NBL_IB_OBJECT_DEVX_UMEM, UVERBS_ACCESS_NEW,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(NBL_IB_ATTR_DEVX_UMEM_REG_ADDR,
			   UVERBS_ATTR_TYPE(u64), UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(NBL_IB_ATTR_DEVX_UMEM_REG_LEN, UVERBS_ATTR_TYPE(u64),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(NBL_IB_ATTR_DEVX_UMEM_REG_DMABUF_FD,
			   UVERBS_ATTR_TYPE(u32)),
	UVERBS_ATTR_FLAGS_IN(NBL_IB_ATTR_DEVX_UMEM_REG_ACCESS,
			     enum ib_access_flags),
	UVERBS_ATTR_PTR_IN(NBL_IB_ATTR_DEVX_UMEM_REG_PGSZ_BITMAP,
			   NBL_UVERBS_ATTR_SIZE(u64)),
	UVERBS_ATTR_PTR_OUT(NBL_IB_ATTR_DEVX_UMEM_REG_OUT_ID,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	NBL_IB_METHOD_DEVX_UMEM_DEREG,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_DEVX_UMEM_DEREG_HANDLE,
			NBL_IB_OBJECT_DEVX_UMEM,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	NBL_IB_METHOD_UAR_OBJ_ALLOC,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_UAR_OBJ_ALLOC_HANDLE, NBL_IB_OBJECT_UAR,
			UVERBS_ACCESS_NEW, UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(NBL_IB_ATTR_UAR_OBJ_ALLOC_TYPE,
			   NBL_UVERBS_ATTR_SIZE(enum nbl_ib_uapi_uar_alloc_type),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(NBL_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(NBL_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH,
			    UVERBS_ATTR_TYPE(u32), UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(NBL_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET,
			    UVERBS_ATTR_TYPE(u64), UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	NBL_IB_METHOD_UAR_OBJ_DESTROY,
	UVERBS_ATTR_IDR(NBL_IB_ATTR_UAR_OBJ_DESTROY_HANDLE,
			NBL_IB_OBJECT_UAR,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(NBL_IB_OBJECT_DEVX,
			      &UVERBS_METHOD(NBL_IB_METHOD_DEVX_OTHER),
			      &UVERBS_METHOD(NBL_IB_METHOD_DEVX_QUERY_UAR),
			      &UVERBS_METHOD(NBL_IB_METHOD_DEVX_QUERY_EQN));

DECLARE_UVERBS_NAMED_OBJECT(NBL_IB_OBJECT_DEVX_OBJ,
			    UVERBS_TYPE_ALLOC_IDR(devx_obj_cleanup),
			    &UVERBS_METHOD(NBL_IB_METHOD_DEVX_OBJ_CREATE),
			    &UVERBS_METHOD(NBL_IB_METHOD_DEVX_OBJ_DESTROY),
			    &UVERBS_METHOD(NBL_IB_METHOD_DEVX_OBJ_MODIFY),
			    &UVERBS_METHOD(NBL_IB_METHOD_DEVX_OBJ_QUERY));

DECLARE_UVERBS_NAMED_OBJECT(NBL_IB_OBJECT_DEVX_UMEM,
			    UVERBS_TYPE_ALLOC_IDR(devx_umem_cleanup),
			    &UVERBS_METHOD(NBL_IB_METHOD_DEVX_UMEM_REG),
			    &UVERBS_METHOD(NBL_IB_METHOD_DEVX_UMEM_DEREG));

DECLARE_UVERBS_NAMED_OBJECT(NBL_IB_OBJECT_UAR,
			    UVERBS_TYPE_ALLOC_IDR(mmap_obj_cleanup),
			    &UVERBS_METHOD(NBL_IB_METHOD_UAR_OBJ_ALLOC),
			    &UVERBS_METHOD(NBL_IB_METHOD_UAR_OBJ_DESTROY));

static bool devx_is_supported(struct ib_device *device)
{
	struct nbl_device *nbldev = to_nbl_dev(device);

	return nbl_product_cap_enabled(nbldev->rf, NBL_PRODUCT_CAP_DEVX);
}

const struct uapi_definition nbl_ib_devx_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		NBL_IB_OBJECT_DEVX,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		NBL_IB_OBJECT_DEVX_OBJ,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		NBL_IB_OBJECT_DEVX_UMEM,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(
		NBL_IB_OBJECT_UAR,
		UAPI_DEF_IS_OBJ_SUPPORTED(devx_is_supported)),
	{},
};
