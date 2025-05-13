// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <rdma/ib_umem.h>
#include "xsc_ib.h"
#include "user.h"
#include "common/xsc_hsi.h"
#include "common/xsc_lag.h"
#include <linux/crc32.h>
#include <linux/dma-direct.h>
#include <rdma/ib_addr.h>
/* not supported currently */
static int wq_signature;

#ifndef ETH_P_IBOE
#define ETH_P_IBOE	0x8915
#endif

#define MAD_QUEUE_DEPTH        128

enum {
	XSC_IB_CACHE_LINE_SIZE	= 64,
};

#define MAC_INVALID		0xff

#define LAG_PORT_NUM_MASK_EN		0x80000000
#define LAG_PORT_NUM_MASK_EN_OFFSET	31
#define LAG_PORT_NUM_MASK		0x30000
#define LAG_PORT_NUM_OFFSET		16

#define UDP_SPORT_MASK_EN		0x40000000
#define UDP_SPORT_MASK_EN_OFFSET	30
#define UDP_SPORT_MASK			0xffff
#define UDP_SPORT_OFFSET		0

static const u32 xsc_ib_opcode[] = {
	[IB_WR_SEND]			= XSC_MSG_OPCODE_SEND,
	[IB_WR_SEND_WITH_IMM]		= XSC_MSG_OPCODE_SEND,
	[IB_WR_RDMA_WRITE]		= XSC_MSG_OPCODE_RDMA_WRITE,
	[IB_WR_RDMA_WRITE_WITH_IMM]	= XSC_MSG_OPCODE_RDMA_WRITE,
	[IB_WR_RDMA_READ]		= XSC_MSG_OPCODE_RDMA_READ,
	[IB_WR_LOCAL_INV]		= XSC_MSG_OPCODE_SEND,
	[IB_WR_REG_MR]			= XSC_MSG_OPCODE_SEND,
	[IB_WR_SEND_WITH_INV]		= XSC_MSG_OPCODE_SEND,
};

static int is_qp0(enum ib_qp_type qp_type)
{
	return qp_type == IB_QPT_SMI;
}

static int is_qp1(enum ib_qp_type qp_type)
{
	return qp_type == IB_QPT_GSI;
}

static int is_sqp(enum ib_qp_type qp_type)
{
	return is_qp0(qp_type) || is_qp1(qp_type);
}

static void *get_wqe(struct xsc_ib_qp *qp, int offset)
{
	return xsc_buf_offset(&qp->buf, offset);
}

static void *get_recv_wqe(struct xsc_ib_qp *qp, int n)
{
	return get_wqe(qp, qp->rq.offset + (n << qp->rq.wqe_shift));
}

static void *get_seg_wqe(void *first, int n)
{
	return first + (n << XSC_BASE_WQE_SHIFT);
}

void *xsc_get_send_wqe(struct xsc_ib_qp *qp, int n)
{
	return get_wqe(qp, qp->sq.offset + (n << qp->sq.wqe_shift));
}

static int iboe_tos_to_sl(struct net_device *ndev, int tos)
{
	int prio;
	struct net_device *dev;

	prio = rt_tos2priority(tos);
	dev = is_vlan_dev(ndev) ? vlan_dev_real_dev(ndev) : ndev;
	if (dev->num_tc)
		return netdev_get_prio_tc_map(dev, prio);

#if IS_ENABLED(CONFIG_VLAN_8021Q)
	if (is_vlan_dev(ndev))
		return (vlan_dev_get_egress_qos_mask(ndev, prio) &
				VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
#endif
	return 0;
}

static inline void set_remote_addr_seg(struct xsc_core_device *xdev,
				       struct xsc_wqe_data_seg *remote_seg,
				       u32 msg_len, u64 remote_addr, u32 rkey)
{
	xsc_set_data_seg(xdev, remote_seg, remote_addr, rkey, msg_len);
}

static void set_local_data_seg(struct xsc_core_device *xdev,
			       struct xsc_wqe_data_seg *data_seg, struct ib_sge *sg)
{
	xsc_set_data_seg(xdev, data_seg, sg->addr, sg->lkey, sg->length);
}

static int set_data_inl_seg(struct xsc_ib_qp *qp, const struct ib_send_wr *wr, void *ctrl)
{
	struct xsc_wqe_data_seg *data_seg;
	unsigned int seg_index;
	void *addr;
	int len;
	int i;

	for (i = 0, seg_index = 1; i < wr->num_sge; ++i, ++seg_index) {
		if (likely(wr->sg_list[i].length)) {
			addr = (void *)wr->sg_list[i].addr;
			len  = wr->sg_list[i].length;

			if (unlikely(len > qp->max_inline_data))
				return -ENOMEM;

			data_seg = get_seg_wqe(ctrl, seg_index);
			data_seg->in_line = 1;
			data_seg->len = len;
			memcpy(data_seg->in_line_data, addr, len);
		}
	}

	return 0;
}

static __be32 send_ieth(const struct ib_send_wr *wr)
{
	switch (wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		return wr->ex.imm_data;
	default:
		return 0;
	}
}

static void xsc_ib_qp_event(struct xsc_core_qp *qp, int type)
{
	struct ib_qp *ibqp = &to_xibqp(qp)->ibqp;
	struct ib_event event;

	if (ibqp->event_handler) {
		event.device     = ibqp->device;
		event.element.qp = ibqp;
		switch (type) {
		case XSC_EVENT_TYPE_WQ_CATAS_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;
		case XSC_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
			event.event = IB_EVENT_QP_REQ_ERR;
			break;
		case XSC_EVENT_TYPE_WQ_ACCESS_ERROR:
			event.event = IB_EVENT_QP_ACCESS_ERR;
			break;
		default:
			pr_warn("xsc_ib: Unexpected event type %d on QP %06x\n", type, qp->qpn);
			return;
		}

		ibqp->event_handler(&event, ibqp->qp_context);
	}
}

static int set_rq_size(struct xsc_ib_dev *dev, struct ib_qp_cap *cap,
		       int has_rq, struct xsc_ib_qp *qp, struct xsc_ib_create_qp *ucmd)
{
	bool check_res = false;
	u32 wqe_cnt = cap->max_recv_wr ? roundup_pow_of_two(cap->max_recv_wr) : 0;

	/* Sanity check RQ size before proceeding */
	check_res = xsc_check_max_qp_depth(dev->xdev, &wqe_cnt, dev->xdev->caps.max_wqes);
	if (check_res) {
		xsc_ib_err(dev, "max_recv_wr:%d exceed max rq depth\n", cap->max_recv_wr);
		return -EINVAL;
	}

	if (!has_rq) {
		qp->rq.max_gs = 0;
		qp->rq.wqe_cnt = 0;
		qp->rq.wqe_shift = 0;
	} else {
		if (ucmd) {
			qp->rq.wqe_cnt = ucmd->rq_wqe_count;
			qp->rq.wqe_shift = ucmd->rq_wqe_shift;
			qp->rq.max_gs = 1;
			qp->rq.max_post = qp->rq.wqe_cnt;
		} else {
			qp->rq.wqe_cnt = wqe_cnt;
			qp->rq.wqe_shift = dev->xdev->caps.recv_wqe_shift;
			qp->rq.max_gs = dev->xdev->caps.recv_ds_num;
			qp->rq.max_post = qp->rq.wqe_cnt;
		}
	}

	return 0;
}

static int calc_sq_size(struct xsc_ib_dev *dev, struct ib_qp_init_attr *attr,
			struct xsc_ib_qp *qp)
{
	int wqe_size;
	int wq_size;
	bool check_res = false;

	if (!attr->cap.max_send_wr) {
		xsc_ib_err(dev, "invalid max_send_wr:%d\n", attr->cap.max_send_wr);
		return -1;
	}

	wqe_size = 1 << dev->xdev->caps.send_wqe_shift;
	qp->max_inline_data = (dev->xdev->caps.send_ds_num - 2) * sizeof(struct xsc_wqe_data_seg);
	attr->cap.max_inline_data = qp->max_inline_data;

	attr->cap.max_send_wr = min_t(u32, attr->cap.max_send_wr, dev->xdev->caps.max_wqes);
	qp->sq.wqe_cnt = roundup_pow_of_two(attr->cap.max_send_wr);

	check_res = xsc_check_max_qp_depth(dev->xdev, &qp->sq.wqe_cnt, dev->xdev->caps.max_wqes);
	if (check_res) {
		xsc_ib_err(dev, "max_send_wr:%d exceed max sq depth\n", attr->cap.max_send_wr);
		return -EINVAL;
	}
	qp->sq.ds_cnt = qp->sq.wqe_cnt << (dev->xdev->caps.send_wqe_shift - XSC_BASE_WQE_SHIFT);
	wq_size = qp->sq.wqe_cnt * wqe_size;
	qp->sq.wqe_shift = ilog2(wqe_size);
	qp->sq.max_gs = dev->xdev->caps.send_ds_num - XSC_CTRL_SEG_NUM - XSC_RADDR_SEG_NUM;
	qp->sq.max_post = qp->sq.wqe_cnt;

	return wq_size;
}

static int qp_has_rq(struct ib_qp_init_attr *attr)
{
	if (attr->qp_type == IB_QPT_XRC_INI ||
	    attr->qp_type == IB_QPT_XRC_TGT || attr->srq ||
	    !attr->cap.max_recv_wr)
		return 0;

	return 1;
}

static enum xsc_qp_state to_xsc_state(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:	return XSC_QP_STATE_RST;
	case IB_QPS_INIT:	return XSC_QP_STATE_INIT;
	case IB_QPS_RTR:	return XSC_QP_STATE_RTR;
	case IB_QPS_RTS:	return XSC_QP_STATE_RTS;
	case IB_QPS_SQD:	return XSC_QP_STATE_SQD;
	case IB_QPS_SQE:	return XSC_QP_STATE_SQER;
	case IB_QPS_ERR:	return XSC_QP_STATE_ERR;
	default:		return -1;
	}
}

static char *qp_state_to_str(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:	return "RST";
	case IB_QPS_INIT:	return "INIT";
	case IB_QPS_RTR:	return "RTR";
	case IB_QPS_RTS:	return "RTS";
	case IB_QPS_SQD:	return "SQD";
	case IB_QPS_SQE:	return "SQE";
	case IB_QPS_ERR:	return "ERR";
	default:		return "UNKNOWN";
	}
}

static int create_user_qp(struct xsc_ib_dev *dev, struct ib_pd *pd,
			  struct xsc_ib_qp *qp, struct ib_udata *udata,
			  struct xsc_create_qp_mbox_in **in,
			  struct xsc_ib_create_qp_resp *resp, int *inlen)
{
	struct xsc_ib_ucontext *context;
	struct xsc_ib_create_qp ucmd;
	int page_shift;
	int npages;
	u32 offset;
	int ncont;
	int err;
	int hw_npages;

	err = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
	if (err) {
		xsc_ib_err(dev, "failed to copy from udata, err=%d\n", err);
		return err;
	}
	xsc_ib_info(dev, "buf_addr:0x%lx db_addr:0x%lx sq cnt:%u, rq cnt:%u, rq shift:%u\n",
		    (uintptr_t)ucmd.buf_addr, (uintptr_t)ucmd.db_addr,
		    ucmd.sq_wqe_count, ucmd.rq_wqe_count, ucmd.rq_wqe_shift);

	context = to_xucontext(pd->uobject->context);

	qp->sq.ds_cnt = ucmd.sq_wqe_count;
	qp->sq.wqe_cnt = ucmd.sq_wqe_count;
	qp->sq.wqe_shift = XSC_BASE_WQE_SHIFT;
	qp->rq.ds_cnt = ucmd.rq_wqe_count;
	qp->rq.wqe_cnt = ucmd.rq_wqe_count;
	qp->rq.wqe_shift = XSC_BASE_WQE_SHIFT;

	qp->buf_size = (qp->sq.wqe_cnt << qp->sq.wqe_shift) + (qp->rq.wqe_cnt << qp->rq.wqe_shift);

	qp->umem = ib_umem_get(&dev->ib_dev, ucmd.buf_addr, qp->buf_size, 0);
	if (IS_ERR(qp->umem)) {
		xsc_ib_err(dev, "umem_get failed\n");
		err = PTR_ERR(qp->umem);
		goto err_uuar;
	}

	xsc_ib_cont_pages(qp->umem, ucmd.buf_addr, &npages, &page_shift,
			  &ncont, NULL);
	if (ncont != npages) {
		// TODO: peer memory support failed
		page_shift = PAGE_SHIFT;
		ncont = npages;
	}

	hw_npages = DIV_ROUND_UP(qp->buf_size, PAGE_SIZE_4K);
	err = xsc_ib_get_buf_offset(ucmd.buf_addr, page_shift, &offset);
	if (err) {
		xsc_ib_err(dev, "bad offset:%d\n", offset);
		goto err_umem;
	}
	xsc_ib_info(dev, "npage:%d, page_shift:%d, ncont:%d, offset:%d, hw_npages %d\n",
		    npages, page_shift, ncont, offset, hw_npages);

	*inlen = sizeof(**in) + sizeof(*((*in)->req.pas)) * hw_npages;
	*in = xsc_vzalloc(*inlen);
	if (!*in) {
		err = -ENOMEM;
		goto err_umem;
	}
	xsc_ib_populate_pas(dev, qp->umem, page_shift, (*in)->req.pas, hw_npages, true);
	(*in)->req.pa_num = cpu_to_be16(hw_npages);

	err = ib_copy_to_udata(udata, resp, sizeof(*resp));
	if (err) {
		xsc_ib_err(dev, "failed to copy to udata, err=%d\n", err);
		goto err_umem;
	}
	qp->create_type = XSC_QP_USER;

	return 0;

err_umem:
	ib_umem_release(qp->umem);

err_uuar:
	return err;
}

static void destroy_qp_user(struct ib_pd *pd, struct xsc_ib_qp *qp)
{
	struct xsc_ib_ucontext *context;

	context = to_xucontext(pd->uobject->context);
	ib_umem_release(qp->umem);
}

#define MAX_QP1_SQ_HDR_SIZE_V2	512
#define MAX_QP1_SQ_HDR_SIZE	86
	/* Ethernet header	=  14 */
	/* ib_grh		=  40 (provided by MAD) */
	/* ib_bth + ib_deth	=  20 */
	/* MAD			= 256 (provided by MAD) */
	/* iCRC			=   4 */
#define MAX_QP1_RQ_HDR_SIZE_V2	512

static int create_kernel_qp(struct xsc_ib_dev *dev,
			    struct ib_qp_init_attr *init_attr,
			    struct xsc_ib_qp *qp,
			    struct xsc_create_qp_mbox_in **in, int *inlen)
{
	int err;
	int sq_size;
	int hw_npages;

	sq_size = calc_sq_size(dev, init_attr, qp);
	if (sq_size < 0) {
		err = -EINVAL;
		xsc_ib_err(dev, "err %d\n", err);
		return err;
	}

	qp->rq.ds_cnt = qp->rq.wqe_cnt << (qp->rq.wqe_shift - XSC_BASE_WQE_SHIFT);
	qp->rq.offset = 0;
	qp->sq.offset = qp->rq.wqe_cnt << qp->rq.wqe_shift;
	qp->buf_size = qp->sq.offset + sq_size;
	qp->send_psn = 0;

	err = xsc_buf_alloc(dev->xdev, qp->buf_size, PAGE_SIZE, &qp->buf);
	if (err) {
		xsc_ib_err(dev, "failed to alloc qp buffer,err=%d\n", err);
		return err;
	}

	qp->sq.qend = qp->buf.direct.buf + qp->sq.offset + sq_size;
	hw_npages = DIV_ROUND_UP(qp->buf_size, PAGE_SIZE_4K);
	*inlen = sizeof(**in) + sizeof(*(*in)->req.pas) * hw_npages;
	*in = xsc_vzalloc(*inlen);
	if (!*in) {
		err = -ENOMEM;
		goto err_buf;
	}

	xsc_fill_page_array(&qp->buf, (*in)->req.pas, hw_npages);
	(*in)->req.pa_num = cpu_to_be16(hw_npages);

	qp->sq.wrid = kcalloc(qp->sq.wqe_cnt, sizeof(*qp->sq.wrid), GFP_KERNEL);
	qp->sq.wr_data = kcalloc(qp->sq.wqe_cnt, sizeof(*qp->sq.wr_data), GFP_KERNEL);
	qp->rq.wrid = kcalloc(qp->rq.wqe_cnt, sizeof(*qp->rq.wrid), GFP_KERNEL);
	qp->sq.w_list = kcalloc(qp->sq.wqe_cnt, sizeof(*qp->sq.w_list), GFP_KERNEL);
	qp->sq.wqe_head = kcalloc(qp->sq.wqe_cnt, sizeof(*qp->sq.wqe_head), GFP_KERNEL);
	qp->sq.wr_opcode = kcalloc(qp->sq.wqe_cnt, sizeof(*qp->sq.wr_opcode), GFP_KERNEL);
	qp->sq.need_flush = kcalloc(qp->sq.wqe_cnt, sizeof(*qp->sq.need_flush), GFP_KERNEL);

	if (!qp->sq.wrid || !qp->sq.wr_data || !qp->rq.wrid ||
	    !qp->sq.w_list || !qp->sq.wqe_head || !qp->sq.wr_opcode || !qp->sq.need_flush) {
		err = -ENOMEM;
		goto err_wrid;
	}
	qp->create_type = XSC_QP_KERNEL;

	if (init_attr->qp_type == IB_QPT_GSI) {
		qp->sq.mad_index = 0;
		qp->sq.mad_queue_depth = MAD_QUEUE_DEPTH;
		qp->sq.hdr_size = MAX_QP1_SQ_HDR_SIZE_V2 * MAD_QUEUE_DEPTH;
		qp->sq.hdr_buf = ib_dma_alloc_coherent(&dev->ib_dev,
						       qp->sq.hdr_size,
						       &qp->sq.hdr_dma,
						       GFP_KERNEL);
		if (!qp->sq.hdr_buf) {
			err = -ENOMEM;
			xsc_ib_err(dev, "Failed to create sq_hdr_buf");
			goto err_wrid;
		}
	}

	return 0;

err_wrid:
	kfree(qp->sq.need_flush);
	kfree(qp->sq.wr_opcode);
	kfree(qp->sq.wqe_head);
	kfree(qp->sq.w_list);
	kfree(qp->sq.wrid);
	kfree(qp->sq.wr_data);
	kfree(qp->rq.wrid);

err_buf:
	xsc_buf_free(dev->xdev, &qp->buf);
	return err;
}

static void destroy_qp_kernel(struct xsc_ib_dev *dev, struct xsc_ib_qp *qp)
{
	if (qp->sq.hdr_buf)
		ib_dma_free_coherent(&dev->ib_dev, qp->sq.hdr_size,
				     qp->sq.hdr_buf, qp->sq.hdr_dma);
	kfree(qp->sq.need_flush);
	kfree(qp->sq.wr_opcode);
	kfree(qp->sq.wqe_head);
	kfree(qp->sq.w_list);
	kfree(qp->sq.wrid);
	kfree(qp->sq.wr_data);
	kfree(qp->rq.wrid);
	xsc_buf_free(dev->xdev, &qp->buf);
}

static u8 ib_to_xsc_qp_type(enum ib_qp_type qp_type, __u32 flags)
{
	if (qp_type == IB_QPT_RC) {
		return XSC_QUEUE_TYPE_RDMA_RC;
	} else if ((qp_type == IB_QPT_GSI) || (qp_type == IB_QPT_SMI)) {
		return XSC_QUEUE_TYPE_RDMA_MAD;
	} else if (qp_type == IB_QPT_RAW_PACKET) {
		if (flags & XSC_QP_FLAG_RAWPACKET_TSO)
			return XSC_QUEUE_TYPE_RAW_TSO;
		else if (flags & XSC_QP_FLAG_RAWPACKET_TX)
			return XSC_QUEUE_TYPE_RAW_TX;
		else if (flags & XSC_QP_FLAG_RAWPACKET_SNIFFER)
			return XSC_QUEUE_TYPE_SNIFFER;
		else
			return XSC_QUEUE_TYPE_RAW;
	} else {
		return XSC_QUEUE_TYPE_INVALID;
	}
}

static int create_qp_common(struct xsc_ib_dev *dev, struct ib_pd *pd,
			    struct ib_qp_init_attr *init_attr,
			    struct ib_udata *udata, struct xsc_ib_qp *qp)
{
	struct xsc_ib_resources *devr = &dev->devr;
	struct xsc_ib_create_qp_resp resp;
	struct xsc_create_qp_mbox_in *in = NULL;
	struct xsc_ib_create_qp ucmd;
	int inlen = sizeof(*in);
	int err;
	char buf[256];
	char *ptr = buf;
	int ret = 0;

	mutex_init(&qp->mutex);
	spin_lock_init(&qp->sq.lock);
	spin_lock_init(&qp->rq.lock);
	spin_lock_init(&qp->lock);

	if (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR)
		qp->sq_signal_bits = XSC_WQE_CTRL_CQ_UPDATE;

	if (pd && pd->uobject) {
		if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd))) {
			xsc_ib_err(dev, "failed to copy from udata\n");
			return -EFAULT;
		}

		qp->wq_sig = !!(ucmd.flags & XSC_QP_FLAG_SIGNATURE);
		qp->scat_cqe = !!(ucmd.flags & XSC_QP_FLAG_SCATTER_CQE);
	} else {
		qp->wq_sig = !!wq_signature;
	}

	qp->has_rq = qp_has_rq(init_attr);

	err = set_rq_size(dev, &init_attr->cap, qp->has_rq,
			  qp, (pd && pd->uobject) ? &ucmd : NULL);
	if (err) {
		xsc_ib_err(dev, "failed to set rq size %d\n", err);
		return err;
	}

	if (pd) {
		if (pd->uobject) {
			err = create_user_qp(dev, pd, qp, udata, &in, &resp, &inlen);
			if (err)
				xsc_ib_err(dev, "failed to create user qp, err = %d\n", err);
		} else {
			err = create_kernel_qp(dev, init_attr, qp, &in, &inlen);
			if (err)
				xsc_ib_err(dev, "failed to create kernel qp, err = %d\n", err);
			else
				qp->pa_lkey = to_mpd(pd)->pa_lkey;
		}

		if (err)
			return err;
	} else {
		in = xsc_vzalloc(sizeof(*in));
		if (!in)
			return -ENOMEM;

		qp->create_type = XSC_QP_EMPTY;
	}

	if (is_sqp(init_attr->qp_type))
		qp->port = init_attr->port_num;

	in->req.qp_type = init_attr->qp_type;
	if (is_qp1(init_attr->qp_type))
		in->req.input_qpn = cpu_to_be16(1);

	if (init_attr->qp_type != XSC_IB_QPT_REG_UMR)
		in->req.pdn = cpu_to_be32(to_mpd(pd ? pd : devr->p0)->pdn);

	if (qp->rq.ds_cnt)
		in->req.log_rq_sz = ilog2(qp->rq.ds_cnt);

	if (qp->sq.ds_cnt)
		in->req.log_sq_sz = ilog2(qp->sq.ds_cnt);
	else
		in->req.log_sq_sz = ilog2(0x80);

	if (init_attr->send_cq) {
		qp->send_cq = init_attr->send_cq;
		in->req.cqn_send = to_xcq(init_attr->send_cq)->xcq.cqn;
		in->req.cqn_send = cpu_to_be16(in->req.cqn_send);
	}

	if (init_attr->recv_cq) {
		qp->recv_cq = init_attr->recv_cq;
		in->req.cqn_recv = to_xcq(init_attr->recv_cq)->xcq.cqn;
		in->req.cqn_recv = cpu_to_be16(in->req.cqn_recv);
	}

	in->req.qp_type = ib_to_xsc_qp_type(init_attr->qp_type, ucmd.flags);

	if (in->req.qp_type == XSC_QUEUE_TYPE_INVALID) {
		xsc_ib_err(dev, "invalid qp type:%d\n", init_attr->qp_type);
		goto err_create;
	}
	in->req.glb_funcid = cpu_to_be16(dev->xdev->glb_func_id);
	in->req.page_shift = PAGE_SHIFT;

	qp->xqp.qp_type_internal = in->req.qp_type;

	err = xsc_core_create_qp(dev->xdev, &qp->xqp, in, inlen);
	if (err) {
		xsc_ib_err(dev, "create qp failed, err=%d\n", err);
		goto err_create;
	}

	qp->doorbell_qpn = qp->xqp.qpn;

	qp->xqp.event = xsc_ib_qp_event;
	qp->xqp.qp_type = init_attr->qp_type;
	ret += snprintf(ptr + ret, 256 - ret, "pdn=%d,", to_mpd(pd ? pd : devr->p0)->pdn);
	ret += snprintf(ptr + ret, 256 - ret, "log_rq_sz=%d,", in->req.log_rq_sz);
	ret += snprintf(ptr + ret, 256 - ret, "log_sq_sz=%d,", in->req.log_sq_sz);
	ret += snprintf(ptr + ret, 256 - ret, "scqn=%d,", to_xcq(init_attr->send_cq)->xcq.cqn);
	ret += snprintf(ptr + ret, 256 - ret, "rcqn=%d", to_xcq(init_attr->recv_cq)->xcq.cqn);

	xsc_ib_info(dev, "succeeded to create qp:%d, %s\n", qp->xqp.qpn, buf);

	xsc_vfree(in);

	return 0;

err_create:
	if (qp->create_type == XSC_QP_USER)
		destroy_qp_user(pd, qp);
	else if (qp->create_type == XSC_QP_KERNEL)
		destroy_qp_kernel(dev, qp);

	xsc_vfree(in);
	return err;
}

static void xsc_ib_lock_cqs(struct xsc_ib_cq *send_cq, struct xsc_ib_cq *recv_cq)
	__acquires(&send_cq->lock) __acquires(&recv_cq->lock)
{
	if (send_cq) {
		if (recv_cq) {
			if (send_cq->xcq.cqn < recv_cq->xcq.cqn)  {
				spin_lock_irq(&send_cq->lock);
				spin_lock_nested(&recv_cq->lock,
						 SINGLE_DEPTH_NESTING);
			} else if (send_cq->xcq.cqn == recv_cq->xcq.cqn) {
				spin_lock_irq(&send_cq->lock);
				__acquire(&recv_cq->lock);
			} else {
				spin_lock_irq(&recv_cq->lock);
				spin_lock_nested(&send_cq->lock,
						 SINGLE_DEPTH_NESTING);
			}
		} else {
			spin_lock_irq(&send_cq->lock);
		}
	} else if (recv_cq) {
		spin_lock_irq(&recv_cq->lock);
	}
}

static void xsc_ib_unlock_cqs(struct xsc_ib_cq *send_cq, struct xsc_ib_cq *recv_cq)
	__releases(&send_cq->lock) __releases(&recv_cq->lock)
{
	if (send_cq) {
		if (recv_cq) {
			if (send_cq->xcq.cqn < recv_cq->xcq.cqn)  {
				spin_unlock(&recv_cq->lock);
				spin_unlock_irq(&send_cq->lock);
			} else if (send_cq->xcq.cqn == recv_cq->xcq.cqn) {
				__release(&recv_cq->lock);
				spin_unlock_irq(&send_cq->lock);
			} else {
				spin_unlock(&send_cq->lock);
				spin_unlock_irq(&recv_cq->lock);
			}
		} else {
			spin_unlock_irq(&send_cq->lock);
		}
	} else if (recv_cq) {
		spin_unlock_irq(&recv_cq->lock);
	}
}

static struct xsc_ib_pd *get_pd(struct xsc_ib_qp *qp)
{
	return to_mpd(qp->ibqp.pd);
}

static void get_cqs(struct xsc_ib_qp *qp,
		    struct xsc_ib_cq **send_cq, struct xsc_ib_cq **recv_cq)
{
	switch (qp->ibqp.qp_type) {
	case IB_QPT_XRC_TGT:
		*send_cq = NULL;
		*recv_cq = NULL;
		break;
	case XSC_IB_QPT_REG_UMR:
	case IB_QPT_XRC_INI:
		*send_cq = to_xcq(qp->ibqp.send_cq);
		*recv_cq = NULL;
		break;

	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UC:
	case IB_QPT_UD:
	case IB_QPT_RAW_IPV6:
	case IB_QPT_RAW_ETHERTYPE:
		*send_cq = to_xcq(qp->ibqp.send_cq);
		*recv_cq = to_xcq(qp->ibqp.recv_cq);
		break;

	case IB_QPT_RAW_PACKET:
	case IB_QPT_MAX:
	default:
		*send_cq = NULL;
		*recv_cq = NULL;
		break;
	}
}

static void destroy_qp_common(struct xsc_ib_dev *dev, struct xsc_ib_qp *qp)
{
	struct xsc_ib_cq *send_cq, *recv_cq;
	struct xsc_modify_qp_mbox_in *in;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return;

	if (qp->xqp.qp_type_internal == XSC_QUEUE_TYPE_RAW ||
	    qp->xqp.qp_type_internal == XSC_QUEUE_TYPE_RAW_TSO ||
	    qp->xqp.qp_type_internal == XSC_QUEUE_TYPE_RAW_TX ||
	    qp->state != IB_QPS_RESET)
		if (xsc_core_qp_modify(dev->xdev, to_xsc_state(qp->state),
				       XSC_QP_STATE_RST, in, sizeof(*in), &qp->xqp))
			xsc_ib_warn(dev, "modify QP %06x to RESET failed\n", qp->xqp.qpn);

	get_cqs(qp, &send_cq, &recv_cq);

	if (qp->create_type == XSC_QP_KERNEL) {
		xsc_ib_lock_cqs(send_cq, recv_cq);
		__xsc_ib_cq_clean(recv_cq, qp->xqp.qpn);
		if (send_cq != recv_cq)
			__xsc_ib_cq_clean(send_cq, qp->xqp.qpn);
		xsc_ib_unlock_cqs(send_cq, recv_cq);
	}

	err = xsc_core_destroy_qp(dev->xdev, &qp->xqp);
	if (err)
		xsc_ib_warn(dev, "failed to destroy QP 0x%x\n", qp->xqp.qpn);
	kfree(in);

	if (qp->create_type == XSC_QP_KERNEL)
		destroy_qp_kernel(dev, qp);
	else if (qp->create_type == XSC_QP_USER)
		destroy_qp_user(&get_pd(qp)->ibpd, qp);
}

static const char *ib_qp_type_str(enum ib_qp_type type)
{
	switch (type) {
	case IB_QPT_SMI:
		return "IB_QPT_SMI";
	case IB_QPT_GSI:
		return "IB_QPT_GSI";
	case IB_QPT_RC:
		return "IB_QPT_RC";
	case IB_QPT_UC:
		return "IB_QPT_UC";
	case IB_QPT_UD:
		return "IB_QPT_UD";
	case IB_QPT_RAW_IPV6:
		return "IB_QPT_RAW_IPV6";
	case IB_QPT_RAW_ETHERTYPE:
		return "IB_QPT_RAW_ETHERTYPE";
	case IB_QPT_XRC_INI:
		return "IB_QPT_XRC_INI";
	case IB_QPT_XRC_TGT:
		return "IB_QPT_XRC_TGT";
	case IB_QPT_RAW_PACKET:
		return "IB_QPT_RAW_PACKET";
	case XSC_IB_QPT_REG_UMR:
		return "XSC_IB_QPT_REG_UMR";
	case IB_QPT_MAX:
	default:
		return "Invalid QP type";
	}
}

struct ib_qp *xsc_ib_create_qp(struct ib_pd *pd,
			       struct ib_qp_init_attr *init_attr,
			       struct ib_udata *udata)
{
	struct xsc_ib_dev *dev;
	struct xsc_ib_qp *qp;
	int err;

	if (pd) {
		dev = to_mdev(pd->device);
	} else {
		/* being cautious here */
		if (init_attr->qp_type != IB_QPT_XRC_TGT &&
		    init_attr->qp_type != XSC_IB_QPT_REG_UMR) {
			pr_warn("%s: no PD for transport %s\n", __func__,
				ib_qp_type_str(init_attr->qp_type));
			return ERR_PTR(-EINVAL);
		}
		dev = to_mdev(to_mxrcd(init_attr->xrcd)->ibxrcd.device);
	}

	if (init_attr->qp_type != IB_QPT_RAW_PACKET) {
		if (!is_support_rdma(dev->xdev) ||
		    (is_qp1(init_attr->qp_type) && !is_support_rdma_cm(dev->xdev))) {
			return ERR_PTR(-EPROTONOSUPPORT);
		}
	}

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp)
		return ERR_PTR(-ENOMEM);

	qp->xqp.mac_id = MAC_INVALID;

	switch (init_attr->qp_type) {
	case IB_QPT_RC:
	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_RAW_PACKET:
		err = create_qp_common(dev, pd, init_attr, udata, qp);
		if (err) {
			xsc_ib_err(dev, "create_qp_common failed\n");
			kfree(qp);
			return ERR_PTR(err);
		}

		if (is_qp0(init_attr->qp_type)) {
			qp->ibqp.qp_num = 0;
		} else if (is_qp1(init_attr->qp_type)) {
			qp->ibqp.qp_num = 1;
			dev->xdev->gsi_qpn = qp->xqp.qpn;
		} else {
			qp->ibqp.qp_num = qp->xqp.qpn;
		}

		break;

	case IB_QPT_RAW_IPV6:
	case IB_QPT_RAW_ETHERTYPE:
	case IB_QPT_MAX:
	default:
		xsc_ib_err(dev, "unsupported qp type %d\n",
			   init_attr->qp_type);
		/* Don't support raw QPs */
		kfree(qp);
		return ERR_PTR(-EINVAL);
	}

	return &qp->ibqp;
}

xsc_ib_destroy_qp_def()
{
	struct xsc_ib_dev *dev = to_mdev(qp->device);
	struct xsc_ib_qp *xqp = to_xqp(qp);
	struct xsc_core_device *xdev = dev->xdev;
	struct xsc_lag *lag;
	struct xsc_err_state_qp_node *tmp = NULL, *err_rq_node = NULL, *err_sq_node = NULL;

	if (qp->qp_type == IB_QPT_RC) {
		if (xqp->recv_cq) {
			list_for_each_entry_safe(err_rq_node, tmp,
						 &to_xcq(xqp->recv_cq)->err_state_qp_list, entry) {
				if (err_rq_node->qp_id == xqp->xqp.qpn && !err_rq_node->is_sq) {
					list_del(&err_rq_node->entry);
					kfree(err_rq_node);
				}
			}
		}

		if (xqp->send_cq) {
			list_for_each_entry_safe(err_sq_node, tmp,
						 &to_xcq(xqp->send_cq)->err_state_qp_list, entry) {
				if (err_sq_node->qp_id == xqp->xqp.qpn && err_sq_node->is_sq) {
					list_del(&err_sq_node->entry);
					kfree(err_sq_node);
				}
			}
		}
	}

	destroy_qp_common(dev, xqp);

	xsc_board_lag_lock(xdev);
	if (xqp->xqp.mac_id != MAC_INVALID && xsc_lag_is_roce(xdev)) {
		lag = xsc_get_lag(xdev);
		atomic_dec(&lag->qp_cnt[xqp->xqp.mac_id]);
	}
	xsc_board_lag_unlock(xdev);

	kfree(xqp);
	return 0;
}

static inline u16 xsc_calc_udp_sport(u32 lqpn, u32 rqpn)
{
	unsigned char *p;
	u8 ports[2];
	u16 sport;
	u64 tqpn;

	tqpn = ((u64)(lqpn & 0xffffff)) * ((u64)(rqpn & 0xffffff));
	p = (unsigned char *)&tqpn;
	ports[0] = p[0] ^ p[2] ^ p[4];
	ports[1] = p[1] ^ p[3] ^ p[5];
	sport = *((u16 *)ports) | 0xC000;

	return sport;
}

static inline void xsc_path_set_udp_sport(struct xsc_qp_path *path,
					  const struct rdma_ah_attr *ah,
					  u32 lqpn, u32 rqpn)
{
	if ((ah->grh.flow_label & UDP_SPORT_MASK) != 0) {
		if ((ah->grh.flow_label & UDP_SPORT_MASK_EN) == 0)
			path->sport = cpu_to_be16(xsc_flow_label_to_udp_sport(ah->grh.flow_label));
		else
			path->sport = cpu_to_be16((ah->grh.flow_label & UDP_SPORT_MASK) >>
							UDP_SPORT_OFFSET);
	} else {
		path->sport = cpu_to_be16(xsc_calc_udp_sport(lqpn, rqpn));
	}
}

static int xsc_set_path(struct xsc_ib_dev *dev, const struct rdma_ah_attr *ah,
			struct xsc_qp_path *path, u8 port, int attr_mask,
			u32 path_flags, const struct ib_qp_attr *attr, struct xsc_ib_qp *qp)
{
	struct ib_global_route *grh = rdma_ah_retrieve_grh((struct rdma_ah_attr *)ah);
	union ib_gid *dgid = &grh->dgid;
	const struct ib_gid_attr *sgid_attr = grh->sgid_attr;
	union ib_gid *sgid = &((struct ib_gid_attr *)sgid_attr)->gid;
	union {
		struct sockaddr     _sockaddr;
		struct sockaddr_in  _sockaddr_in;
		struct sockaddr_in6 _sockaddr_in6;
	} sgid_addr, dgid_addr;
	int force_pcp, force_dscp;
	char buf[256] = {0};
	char *ptr = buf;
	int ret = 0;


	if (ah->type == RDMA_AH_ATTR_TYPE_ROCE) {
		if (!(rdma_ah_get_ah_flags(ah) & IB_AH_GRH))
			return -EINVAL;

		if (qp->ibqp.qp_type == IB_QPT_RC ||
		    qp->ibqp.qp_type == IB_QPT_UC ||
		    qp->ibqp.qp_type == IB_QPT_XRC_INI ||
		    qp->ibqp.qp_type == IB_QPT_XRC_TGT)
			xsc_path_set_udp_sport(path, ah, qp->ibqp.qp_num, attr->dest_qp_num);

		if (sgid_attr->gid_type != IB_GID_TYPE_ROCE_UDP_ENCAP) {
			xsc_ib_err(dev, "gid type not ROCEv2\n");
			return -EINVAL;
		}

		force_dscp = dev->force_dscp;
		if (force_dscp == DSCP_PCP_UNSET)
			path->ecn_dscp = (grh->traffic_class >> 2) & 0x3f;
		else
			path->ecn_dscp = force_dscp;
		path->hop_limit = grh->hop_limit;

		rdma_gid2ip((struct sockaddr *)&sgid_addr, sgid);
		rdma_gid2ip((struct sockaddr *)&dgid_addr, dgid);

		if (sgid_addr._sockaddr.sa_family == AF_INET &&
		    dgid_addr._sockaddr.sa_family == AF_INET) {
			memcpy(path->sip, &sgid_addr._sockaddr_in.sin_addr.s_addr,
			       sizeof(struct in_addr));
			memcpy(path->dip, &dgid_addr._sockaddr_in.sin_addr.s_addr,
			       sizeof(struct in_addr));
			path->af_type = AF_INET;
			ret += snprintf(ptr + ret, 256 - ret, "sip=%#x,",
					be32_to_cpu(path->sip[0]));
			ret += snprintf(ptr + ret, 256 - ret, "dip=%#x,",
					be32_to_cpu(path->dip[0]));
		} else if (sgid_addr._sockaddr.sa_family == AF_INET6 &&
			   dgid_addr._sockaddr.sa_family == AF_INET6) {
			memcpy(path->sip, &sgid_addr._sockaddr_in6.sin6_addr.s6_addr,
			       sizeof(path->sip));
			memcpy(path->dip, &dgid_addr._sockaddr_in6.sin6_addr.s6_addr,
			       sizeof(path->dip));
			path->af_type = AF_INET6;
			ret += snprintf(ptr + ret, 256 - ret, "sip=%08x%08x%08x%08x,",
					be32_to_cpu(path->sip[0]), be32_to_cpu(path->sip[1]),
					be32_to_cpu(path->sip[2]), be32_to_cpu(path->sip[3]));
			ret += snprintf(ptr + ret, 256 - ret, "dip=%08x%08x%08x%08x,",
					be32_to_cpu(path->dip[0]), be32_to_cpu(path->dip[1]),
					be32_to_cpu(path->dip[2]), be32_to_cpu(path->dip[3]));
		} else {
			return -EINVAL;
		}

		ether_addr_copy(path->smac, dev->netdev->dev_addr);

		memcpy(path->dmac, ah->roce.dmac, sizeof(ah->roce.dmac));
		ret += snprintf(ptr + ret, 256 - ret, "smac=%02x%02x%02x%02x%02x%02x,",
				path->smac[0], path->smac[1], path->smac[2],
				path->smac[3], path->smac[4], path->smac[5]);
		ret += snprintf(ptr + ret, 256 - ret, "dmac=%02x%02x%02x%02x%02x%02x",
				path->dmac[0], path->dmac[1], path->dmac[2],
				path->dmac[3], path->dmac[4], path->dmac[5]);
		xsc_ib_info(dev, "ib path info:%s\n", buf);

		if (is_vlan_dev(sgid_attr->ndev)) {
			path->vlan_valid = 1;
			path->vlan_id = cpu_to_be16(vlan_dev_vlan_id(sgid_attr->ndev));

			force_pcp = dev->force_pcp;
			if (force_pcp == DSCP_PCP_UNSET)
				path->dci_cfi_prio_sl = (ah->sl & 0x7);
			else
				path->dci_cfi_prio_sl = force_pcp;
		} else {
			path->vlan_valid = 0;
		}
	}
	xsc_ib_info(dev, "path dscp %d pcp %d\n", path->ecn_dscp, path->dci_cfi_prio_sl);
	return 0;
}

static inline u8 __xsc_get_min_qp_cnt_mac(struct xsc_lag *lag)
{
	int array_size = lag->xsc_member_cnt;
	int min = atomic_read(&lag->qp_cnt[0]);
	u8 mac_index = 0, i;

	for (i = 0; i < array_size; i++) {
		if (atomic_read(&lag->qp_cnt[i]) < min) {
			min = atomic_read(&lag->qp_cnt[i]);
			mac_index = i;
		}
	}

	return mac_index;
}

static int xsc_ib_err_state_qp(struct xsc_ib_dev *dev, struct xsc_ib_qp *qp,
			       enum xsc_qp_state cur_state, enum xsc_qp_state state)
{
	struct xsc_err_state_qp_node *tmp = NULL, *err_rq_node = NULL, *err_sq_node = NULL;
	int ret = 0;

	xsc_ib_dbg(dev, "modify qp: qpid %d, cur_qp_state %d, qp_state %d\n",
		   qp->xqp.qpn, cur_state, state);
	if (cur_state == XSC_QP_STATE_ERR && state != XSC_QP_STATE_ERR) {
		if (qp->recv_cq) {
			list_for_each_entry_safe(err_rq_node, tmp,
						 &to_xcq(qp->recv_cq)->err_state_qp_list, entry) {
				if (err_rq_node->qp_id == qp->xqp.qpn && !err_rq_node->is_sq) {
					list_del(&err_rq_node->entry);
					kfree(err_rq_node);
				}
			}
		}

		if (qp->send_cq) {
			list_for_each_entry_safe(err_sq_node, tmp,
						 &to_xcq(qp->send_cq)->err_state_qp_list, entry) {
				if (err_sq_node->qp_id == qp->xqp.qpn && err_sq_node->is_sq) {
					list_del(&err_sq_node->entry);
					kfree(err_sq_node);
				}
			}
		}
		return ret;
	}

	if (cur_state != XSC_QP_STATE_ERR && state == XSC_QP_STATE_ERR) {
		if (qp->recv_cq) {
			err_rq_node = kzalloc(sizeof(*err_rq_node), GFP_KERNEL);
			if (!err_rq_node)
				return -ENOMEM;
			err_rq_node->qp_id = qp->xqp.qpn;
			err_rq_node->is_sq = false;
			list_add_tail(&err_rq_node->entry, &to_xcq(qp->recv_cq)->err_state_qp_list);
		}

		if (qp->send_cq) {
			err_sq_node = kzalloc(sizeof(*err_sq_node), GFP_KERNEL);
			if (!err_sq_node)
				return -ENOMEM;
			err_sq_node->qp_id = qp->xqp.qpn;
			err_sq_node->is_sq = true;
			list_add_tail(&err_sq_node->entry, &to_xcq(qp->send_cq)->err_state_qp_list);
		}
	}
	return ret;
}

static inline void xsc_set_qp_access_flag(struct xsc_modify_qp_mbox_in *in,
					  struct xsc_qp_context *context, int access_flags)
{
	in->hdr.ver = cpu_to_be16(XSC_QP_CONTEXT_V1);
	context->qp_access_flags = 0;

	if (access_flags & IB_ACCESS_REMOTE_READ)
		context->qp_access_flags |= QP_ACCESS_REMOTE_READ;
	if (access_flags & IB_ACCESS_REMOTE_WRITE)
		context->qp_access_flags |= QP_ACCESS_REMOTE_WRITE;
	context->qp_access_flags = cpu_to_be32(context->qp_access_flags);
}

static int __xsc_ib_modify_qp(struct ib_qp *ibqp,
			      const struct ib_qp_attr *attr, int attr_mask,
			      enum ib_qp_state cur_state, enum ib_qp_state new_state)
{
	struct xsc_ib_dev *dev = to_mdev(ibqp->device);
	struct xsc_ib_qp *qp = to_xqp(ibqp);
	struct xsc_ib_cq *send_cq, *recv_cq;
	struct xsc_qp_context *context;
	struct xsc_modify_qp_mbox_in *in;
	struct xsc_qp_path path;
	int sqd_event;
	int err;
	struct xsc_lag *lag;
	u8 lag_port_num;
	char buf[256] = {0};
	char *ptr = buf;
	int ret = 0;
	struct xsc_core_device *xdev = dev->xdev;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	context = &qp->ctx;

	if (attr_mask & IB_QP_PATH_MTU) {
		if (attr->path_mtu != IB_MTU_1024 &&
		    attr->path_mtu != IB_MTU_4096) {
			xsc_ib_warn(dev, "invalid mtu %d\n", attr->path_mtu);
		}

		context->mtu_mode = (attr->path_mtu < IB_MTU_4096) ? 0 : 1;
		ret = snprintf(ptr, 256, "path_mtu=%d,", attr->path_mtu);
	}

	if (attr_mask & IB_QP_DEST_QPN) {
		context->remote_qpn = cpu_to_be32(attr->dest_qp_num);
		ret += snprintf(ptr + ret, 256 - ret, "dest_qp_num=%d,", attr->dest_qp_num);
	}

	if (attr_mask & IB_QP_AV) {
		err = xsc_set_path(dev, &attr->ah_attr, &path,
				   attr_mask & IB_QP_PORT ? attr->port_num : qp->port,
				   attr_mask, 0, attr, qp);
		if (err)
			goto out;

		context->src_udp_port = path.sport;
		context->dscp = path.ecn_dscp;
		context->hop_limit = path.hop_limit;
		context->ip_type = (path.af_type == AF_INET ? 0 : 1);
		context->ip_type = cpu_to_be16(context->ip_type);
		memcpy(context->dip, path.dip, sizeof(context->dip));
		memcpy(context->sip, path.sip, sizeof(context->sip));
		memcpy(context->dmac, path.dmac, sizeof(path.dmac));
		memcpy(context->smac, path.smac, sizeof(path.smac));

		context->vlan_valid = path.vlan_valid;
		context->dci_cfi_prio_sl = path.dci_cfi_prio_sl;
		context->vlan_id = path.vlan_id;

		xsc_board_lag_lock(xdev);
		if (xsc_lag_is_roce(xdev)) {
			lag = xsc_get_lag(xdev);
			context->lag_id = cpu_to_be16(lag->lag_id);
			context->lag_sel_en = 1;
			lag_port_num = lag->xsc_member_cnt;
			if ((attr->ah_attr.grh.flow_label & LAG_PORT_NUM_MASK_EN) != 0) {
				context->lag_sel = ((attr->ah_attr.grh.flow_label &
							LAG_PORT_NUM_MASK) >>
							LAG_PORT_NUM_OFFSET) %
							lag_port_num;
			} else {
				context->lag_sel = __xsc_get_min_qp_cnt_mac(lag);
			}

			if (qp->xqp.mac_id != MAC_INVALID &&
			    context->lag_sel != qp->xqp.mac_id)
				atomic_dec(&lag->qp_cnt[qp->xqp.mac_id]);

			qp->xqp.mac_id = context->lag_sel;
			atomic_inc(&lag->qp_cnt[qp->xqp.mac_id]);
		}
		xsc_board_lag_unlock(xdev);
	}

	if (attr_mask & IB_QP_RNR_RETRY) {
		context->rnr_retry = attr->rnr_retry;
		ret += snprintf(ptr + ret, 256 - ret, "rnr_retry=%d,", attr->rnr_retry);
	}

	if (attr_mask & IB_QP_RETRY_CNT) {
		context->retry_cnt = attr->retry_cnt;
		ret += snprintf(ptr + ret, 256 - ret, "retry_cnt=%d,", attr->retry_cnt);
	}

	if (attr_mask & IB_QP_SQ_PSN) {
		context->next_send_psn = cpu_to_be32(attr->sq_psn);
		ret += snprintf(ptr + ret, 256 - ret, "sq_psn=%#x,", attr->sq_psn);
	}

	if (attr_mask & IB_QP_RQ_PSN) {
		context->next_recv_psn = cpu_to_be32(attr->rq_psn);
		ret += snprintf(ptr + ret, 256 - ret, "rq_psn=%#x,", attr->rq_psn);
	}

	if (attr_mask & IB_QP_ACCESS_FLAGS) {
		xsc_set_qp_access_flag(in, context, attr->qp_access_flags);
		ret += snprintf(ptr + ret, 256 - ret, "qp_access_flags=%#x,\n",
				attr->qp_access_flags);
	}

	if (cur_state == IB_QPS_RTS && new_state == IB_QPS_SQD	&&
	    attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY && attr->en_sqd_async_notify)
		sqd_event = 1;
	else
		sqd_event = 0;

	memcpy(&in->ctx, context, sizeof(*context));
	err = xsc_core_qp_modify(xdev, to_xsc_state(cur_state),
				 to_xsc_state(new_state), in, sqd_event,
				 &qp->xqp);
	if (err) {
		xsc_ib_err(dev, "failed to modify qp[%d] from %s to %s\n",
			   qp->xqp.qpn, qp_state_to_str(cur_state), qp_state_to_str(new_state));
		goto out;
	}

	qp->state = new_state;
	xsc_ib_info(dev, "succeeded to modify qp[%d] from %s to %s with attr_mask=%#x, %s\n",
		    qp->xqp.qpn, qp_state_to_str(cur_state), qp_state_to_str(new_state),
		    attr_mask, buf);

	if (attr_mask & IB_QP_ACCESS_FLAGS)
		qp->atomic_rd_en = attr->qp_access_flags;
	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		qp->resp_depth = attr->max_dest_rd_atomic;
	if (attr_mask & IB_QP_PORT)
		qp->port = attr->port_num;
	if (attr_mask & IB_QP_ALT_PATH)
		qp->alt_port = attr->alt_port_num;

	/*
	 * If we moved a kernel QP to RESET, clean up all old CQ
	 * entries and reinitialize the QP.
	 */
	if (new_state == IB_QPS_RESET && !ibqp->uobject) {
		get_cqs(qp, &send_cq, &recv_cq);
		xsc_ib_cq_clean(recv_cq, qp->xqp.qpn);
		if (send_cq != recv_cq)
			xsc_ib_cq_clean(send_cq, qp->xqp.qpn);

		qp->rq.head = 0;
		qp->rq.tail = 0;
		qp->sq.head = 0;
		qp->sq.tail = 0;
		qp->sq.cur_post = 0;
		qp->sq.last_poll = 0;
	}

	if (!err && (attr_mask & IB_QP_STATE))
		err = xsc_ib_err_state_qp(dev, qp, to_xsc_state(cur_state),
					  to_xsc_state(new_state));
out:
	kfree(in);
	return err;
}

int xsc_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		     int attr_mask, struct ib_udata *udata)
{
	struct xsc_ib_dev *dev = to_mdev(ibqp->device);
	struct xsc_ib_qp *qp = to_xqp(ibqp);
	enum ib_qp_state cur_state, new_state;
	int err = -EINVAL;

	mutex_lock(&qp->mutex);

	cur_state = attr_mask & IB_QP_CUR_STATE ? attr->cur_qp_state : qp->state;
	new_state = attr_mask & IB_QP_STATE ? attr->qp_state : cur_state;

	if ((attr_mask & IB_QP_PORT) &&
	    (attr->port_num == 0 || attr->port_num > dev->xdev->caps.num_ports)) {
		xsc_ib_err(dev, "error port num\n");
		goto out;
	}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC &&
	    attr->max_rd_atomic > dev->xdev->caps.max_ra_res_qp) {
		xsc_ib_err(dev, "rd atomic:%u exeeded", attr->max_rd_atomic);
		goto out;
	}

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC &&
	    attr->max_dest_rd_atomic > dev->xdev->caps.max_ra_req_qp) {
		xsc_ib_err(dev, "dest rd atomic:%u exeeded", attr->max_dest_rd_atomic);
		goto out;
	}

	if (cur_state == new_state && cur_state == IB_QPS_RESET) {
		err = 0;
		goto out;
	}

	if (!ib_modify_qp_is_ok(cur_state, new_state, ibqp->qp_type, attr_mask)) {
		xsc_ib_err(dev, "ib_modify_qp not ok, type=%d mask=0x%x state from%d to%d\n",
			   ibqp->qp_type, attr_mask, cur_state, new_state);
		goto out;
	}

	err = __xsc_ib_modify_qp(ibqp, attr, attr_mask, cur_state, new_state);
out:
	mutex_unlock(&qp->mutex);
	return err;
}

static int xsc_wq_overflow(struct xsc_ib_wq *wq, int nreq, struct xsc_ib_cq *cq)
{
	unsigned int cur;

	cur = wq->head - wq->tail;
	if (likely(cur + nreq < wq->max_post))
		return 0;

	spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	spin_unlock(&cq->lock);

	return cur + nreq >= wq->max_post;
}


static inline void xsc_post_send_db(struct xsc_ib_qp *qp,
				    struct xsc_core_device *xdev,
				    int nreq)
{
	u32 next_pid;

	if (unlikely(!nreq))
		return;

	qp->sq.head += nreq;

	next_pid = qp->sq.head << (qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT);
	xsc_update_tx_db(xdev, qp->doorbell_qpn, next_pid);
}

static inline u32 xsc_crc32(struct xsc_ib_dev *dev, u32 crc, u8 *buf, size_t len)
{
	u32 i;

	for (i = 0; i < len; i++)
		crc = dev->crc_32_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);

	return crc;
}

#define BTH_QPN_MASK		(0x00ffffff)
#define BTH_PSN_MASK		(0x00ffffff)

/* Compute a partial ICRC for all the IB transport headers. */
static u32 xsc_icrc_hdr(struct xsc_ib_dev *dev, void *pkt, u32 size, u32 *icrc)
{
	struct iphdr *ip4h = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct udphdr *udph;
	struct ib_unpacked_eth *eth;
	struct rxe_bth *bth;
	struct ib_unpacked_deth *deth;
	struct ib_unpacked_vlan *vlan;
	int crc;
	int crc_field_len;
	__be16 l3_type;
	u8 *l3_start;

	int hdr_size;

	/* pseudo header buffer size is calculate using ipv6 header size since
	 * it is bigger than ipv4
	 */
	u8 pshdr[sizeof(struct udphdr) +
		sizeof(struct ipv6hdr) +
		sizeof(*bth) + sizeof(*deth)];

	eth = pkt;

	if (eth->type == htons(ETH_P_8021Q)) {
		vlan = (struct ib_unpacked_vlan *)(eth + 1);
		l3_type = vlan->type;
		l3_start = (u8 *)(vlan + 1);
		size -= 4;
	} else {
		l3_type = eth->type;
		l3_start = (u8 *)(eth + 1);
	}

	hdr_size = sizeof(struct udphdr) +
		(l3_type == htons(ETH_P_IP) ?
		sizeof(struct iphdr) : sizeof(struct ipv6hdr));

	crc_field_len = hdr_size + sizeof(*bth) + sizeof(*deth);

	if (crc_field_len != size) {
		xsc_ib_err(dev, "Unmatched hdr: expect %d actual %d\n",
			   crc_field_len, size);
		return -EINVAL;
	}

	ip4h = (struct iphdr *)(l3_start);
	ip6h = (struct ipv6hdr *)(l3_start);
	udph = (struct udphdr *)(ip4h + 1);
	bth = (struct rxe_bth *)(udph + 1);

	memcpy(pshdr, l3_start, crc_field_len);

	/* This seed is the result of computing a CRC with a seed of
	 * 0xfffffff and 8 bytes of 0xff representing a masked LRH.
	 */
	crc = 0xdebb20e3;

	if (l3_type == htons(ETH_P_IP)) { /* IPv4 */
		memcpy(pshdr, ip4h, hdr_size);
		ip4h = (struct iphdr *)pshdr;
		udph = (struct udphdr *)(ip4h + 1);

		ip4h->ttl = 0xff;
		ip4h->check = CSUM_MANGLED_0;
		ip4h->tos = 0xff;
	} else {				/* IPv6 */
		memcpy(pshdr, ip6h, hdr_size);
		ip6h = (struct ipv6hdr *)pshdr;
		udph = (struct udphdr *)(ip6h + 1);

		memset(ip6h->flow_lbl, 0xff, sizeof(ip6h->flow_lbl));
		ip6h->priority = 0xf;
		ip6h->hop_limit = 0xff;
	}
	udph->check = CSUM_MANGLED_0;

	bth = (struct rxe_bth *)(udph + 1);
	/* exclude bth.resv8a */
	bth->qpn |= cpu_to_be32(~BTH_QPN_MASK);

	*icrc = xsc_crc32(dev, crc, pshdr, crc_field_len);

	return 0;
}

/* Routine for sending QP1 packets for RoCE V1 an V2
 */
 // TO BE DONE: sq hdr buf should be create dynamically for mult entry
static int build_qp1_send_v2(struct xsc_ib_dev *dev,
			     struct xsc_ib_qp *qp,
			     const struct ib_send_wr *wr,
			     struct ib_sge *sge,
			     int payload_size, u32 *crc)
{
	struct xsc_ib_ah *ah = container_of(ud_wr((struct ib_send_wr *)wr)->ah, struct xsc_ib_ah,
					    ibah);
	const struct ib_gid_attr *sgid_attr = ah->ibah.sgid_attr;
	u16 ether_type;
	union ib_gid dgid;
	bool is_eth = false;
	bool is_vlan = false;
	bool is_grh = false;
	bool is_udp = false;
	u8 ip_version = 0;
	u16 vlan_id = 0xFFFF;
	int rc = 0;
	int cm_pcp = 0;
	void *hdr_buf;

	memset(&qp->qp1_hdr, 0, sizeof(qp->qp1_hdr));

	if (!qp->sq.hdr_buf) {
		xsc_ib_err(dev, "QP1 buffer is empty!");
		return -ENOMEM;
	}
	hdr_buf = (u8 *)qp->sq.hdr_buf + MAX_QP1_SQ_HDR_SIZE_V2 * qp->sq.mad_index;

	if (!sgid_attr || !sgid_attr->ndev) {
		xsc_ib_err(dev, "sgid_addr or ndev is null\n");
		return -ENXIO;
	}

	if (is_vlan_dev(sgid_attr->ndev))
		vlan_id = vlan_dev_vlan_id(sgid_attr->ndev);

	is_udp = sgid_attr->gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP;
	memcpy(&dgid.raw, &ah->av.rgid, 16);
	if (is_udp) {
		if (ipv6_addr_v4mapped((struct in6_addr *)&sgid_attr->gid)) {
			ip_version = 4;
			ether_type = ETH_P_IP;
		} else {
			ip_version = 6;
			ether_type = ETH_P_IPV6;
		}
		is_grh = false;
	} else {
		ether_type = ETH_P_IBOE;
		is_grh = true;
	}

	is_eth = true;
	is_vlan = (vlan_id && (vlan_id < 0x1000)) ? true : false;

	ib_ud_header_init(payload_size, !is_eth, is_eth, is_vlan, is_grh,
			  ip_version, is_udp, 0, &qp->qp1_hdr);

	/* ETH */
	ether_addr_copy(qp->qp1_hdr.eth.dmac_h, ah->av.rmac);
	ether_addr_copy(qp->qp1_hdr.eth.smac_h, dev->netdev->dev_addr);

	/* For vlan, check the sgid for vlan existence */
	if (!is_vlan) {
		qp->qp1_hdr.eth.type = cpu_to_be16(ether_type);
	} else {
		if (dev->cm_pcp != DSCP_PCP_UNSET)
			cm_pcp = dev->cm_pcp << 13;
		else
			cm_pcp = (iboe_tos_to_sl(sgid_attr->ndev, ah->av.tclass) << 13);
		qp->qp1_hdr.vlan.type = cpu_to_be16(ether_type);
		qp->qp1_hdr.vlan.tag = cpu_to_be16(vlan_id | cm_pcp);
	}

#define ECN_CAPABLE_TRANSPORT 0x2
	if (is_grh || ip_version == 6) {
		memcpy(qp->qp1_hdr.grh.source_gid.raw, sgid_attr->gid.raw,
		       sizeof(sgid_attr->gid));
		memcpy(qp->qp1_hdr.grh.destination_gid.raw, ah->av.rgid,
		       sizeof(ah->av.rgid));
		qp->qp1_hdr.grh.hop_limit     = ah->av.hop_limit;

		if (dev->cm_dscp != DSCP_PCP_UNSET)
			qp->qp1_hdr.grh.traffic_class = (dev->cm_dscp << 2) | ECN_CAPABLE_TRANSPORT;
		else
			qp->qp1_hdr.grh.traffic_class = ECN_CAPABLE_TRANSPORT;
	}

	if (ip_version == 4) {
		if (dev->cm_dscp != DSCP_PCP_UNSET)
			qp->qp1_hdr.ip4.tos = (dev->cm_dscp << 2) | ECN_CAPABLE_TRANSPORT;
		else
			qp->qp1_hdr.ip4.tos = ECN_CAPABLE_TRANSPORT;
		qp->qp1_hdr.ip4.id = 0;
		qp->qp1_hdr.ip4.frag_off = htons(IP_DF);
		qp->qp1_hdr.ip4.ttl = ah->av.hop_limit;

		memcpy(&qp->qp1_hdr.ip4.saddr, sgid_attr->gid.raw + 12, 4);
		memcpy(&qp->qp1_hdr.ip4.daddr, ah->av.rgid + 12, 4);
		qp->qp1_hdr.ip4.check = ib_ud_ip4_csum(&qp->qp1_hdr);
	}

	if (is_udp) {
		qp->qp1_hdr.udp.dport = htons(ROCE_V2_UDP_DPORT);
		qp->qp1_hdr.udp.sport = htons(ah->av.udp_sport);
		qp->qp1_hdr.udp.csum = 0;
		xsc_ib_dbg(dev, "CM packet used udp_sport=%d\n", ah->av.udp_sport);
	}

	/* BTH */
	if (wr->opcode == IB_WR_SEND_WITH_IMM) {
		qp->qp1_hdr.bth.opcode = IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		qp->qp1_hdr.immediate_present = 1;
	} else {
		qp->qp1_hdr.bth.opcode = IB_OPCODE_UD_SEND_ONLY;
	}
	if (wr->send_flags & IB_SEND_SOLICITED)
		qp->qp1_hdr.bth.solicited_event = 1;
	/* pad_count */
	qp->qp1_hdr.bth.pad_count = (4 - payload_size) & 3;

	/* P_key for QP1 is for all members */
	qp->qp1_hdr.bth.pkey = cpu_to_be16(0xFFFF);
	qp->qp1_hdr.bth.destination_qpn = IB_QP1;
	qp->qp1_hdr.bth.ack_req = 0;
	qp->send_psn++;
	qp->send_psn &= BTH_PSN_MASK;
	qp->qp1_hdr.bth.psn = cpu_to_be32(qp->send_psn);
	/* DETH */
	/* Use the priviledged Q_Key for QP1 */
	qp->qp1_hdr.deth.qkey = cpu_to_be32(IB_QP1_QKEY);
	qp->qp1_hdr.deth.source_qpn = IB_QP1;

	/* Pack the QP1 to the transmit buffer */
	sge->addr = (dma_addr_t)(qp->sq.hdr_dma + MAX_QP1_SQ_HDR_SIZE_V2 * qp->sq.mad_index);
	sge->lkey = 0xFFFFFFFF;
	sge->length = MAX_QP1_SQ_HDR_SIZE;

	ib_ud_header_pack(&qp->qp1_hdr, hdr_buf);
	/*
	 * Max Header buf size for IPV6 RoCE V2 is 86,
	 * which is same as the QP1 SQ header buffer.
	 * Header buf size for IPV4 RoCE V2 can be 66.
	 * ETH(14) + VLAN(4)+ IP(20) + UDP (8) + BTH(20).
	 * Subtract 20 bytes from QP1 SQ header buf size
	 */
	if (is_udp && ip_version == 4)
		sge->length -= 20;
	/*
	 * Max Header buf size for RoCE V1 is 78.
	 * ETH(14) + VLAN(4) + GRH(40) + BTH(20).
	 * Subtract 8 bytes from QP1 SQ header buf size
	 */
	if (!is_udp)
		sge->length -= 8;

	/* Subtract 4 bytes for non vlan packets */
	if (!is_vlan)
		sge->length -= 4;

	rc = xsc_icrc_hdr(dev, hdr_buf, sge->length - sizeof(struct ib_unpacked_eth), crc);
	if (rc) {
		xsc_ib_err(dev, "CRC error: hdr size %ld\n",
			   sge->length - sizeof(struct ib_unpacked_eth));
	}
	return rc;
}

static void zero_send_ds(struct xsc_ib_qp *qp, int idx)
{
	void *seg;
	int i;
	int ds_num;
	u64 *p;

	ds_num = XSC_SEND_SEG_NUM << (qp->sq.wqe_shift - XSC_SEND_WQE_SHIFT);
	seg = (void *)xsc_get_send_wqe(qp, idx);
	for (i = 1; i < ds_num; i++) {
		p = get_seg_wqe(seg, i);
		p[0] = 0;
		p[1] = 0;
	}
}

int xsc_ib_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		     const struct ib_send_wr **bad_wr)
{
	struct xsc_ib_qp *qp = to_xqp(ibqp);
	struct xsc_ib_dev *dev = to_mdev(ibqp->device);
	void *seg;
	struct xsc_send_wqe_ctrl_seg *ctrl;
	struct xsc_wqe_data_seg *data_seg;
	u32 crc;
	int nreq;
	int err = 0;
	int i;
	unsigned int idx;
	unsigned long irqflag = 0;
	struct ib_sge sg;
	u8 *cur_p = NULL;
	u8 *mad_send_base = NULL;
	struct ib_wc wc;
	void *vaddr;
	int sig = 0;
	if (wr->opcode == IB_WR_LOCAL_INV) {
		wc.status = IB_WC_SUCCESS;
		wc.wr_cqe = wr->wr_cqe;
		wc.qp = ibqp;
		sig = qp->sq_signal_bits == XSC_WQE_CTRL_CQ_UPDATE ?
			1 : wr->send_flags & IB_SEND_SIGNALED;
		if (xsc_wr_invalidate_mr(dev, wr))
			wc.status = IB_WC_GENERAL_ERR;

		if (wr->wr_cqe && wr->wr_cqe->done && sig)
			wr->wr_cqe->done(qp->send_cq, &wc);
		wr = wr->next;
		if (!wr)
			return 0;
	}

	if (wr->opcode == IB_WR_REG_MR) {
		wc.status = IB_WC_SUCCESS;
		wc.qp = ibqp;
		sig = qp->sq_signal_bits == XSC_WQE_CTRL_CQ_UPDATE ?
			1 : wr->send_flags & IB_SEND_SIGNALED;
		if (xsc_wr_reg_mr(dev, wr))
			wc.status = IB_WC_GENERAL_ERR;

		if (virt_addr_valid(wr->wr_cqe)) {
			if (wr->wr_cqe && wr->wr_cqe->done && sig)
				wr->wr_cqe->done(qp->send_cq, &wc);
		} else {
			xsc_ib_info(dev, "Error: system not support SMC-R-V2 feature!!!\n");
			return 0;
		}

		wr = wr->next;
		if (!wr)
			return (wc.status == IB_WC_SUCCESS) ? 0 : -1;
	}

	spin_lock_irqsave(&qp->sq.lock, irqflag);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		unsigned int seg_index = 1;
		unsigned int msg_len = 0;
		struct ib_sge *sgl = &wr->sg_list[0];
		int sg_n = wr->num_sge;

		if (unlikely(wr->opcode < 0 || wr->opcode >= ARRAY_SIZE(xsc_ib_opcode))) {
			xsc_ib_err(dev, "bad opcode %d\n", wr->opcode);
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(xsc_wq_overflow(&qp->sq, nreq,
					     to_xcq(qp->ibqp.send_cq)))) {
			xsc_ib_err(dev, "send work queue overflow\n");
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->sq.max_gs)) {
			xsc_ib_err(dev, "max gs exceeded %d (max = %d)\n",
				   wr->num_sge, qp->sq.max_gs);
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->opcode == IB_WR_RDMA_READ && wr->num_sge > 1)) {
			xsc_ib_err(dev, "rdma read, max gs exceeded %d (max = 1)\n",
				   wr->num_sge);
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		idx = qp->sq.cur_post & (qp->sq.wqe_cnt - 1);
		zero_send_ds(qp, idx);
		seg = xsc_get_send_wqe(qp, idx);
		ctrl = seg;
		ctrl->wqe_id = cpu_to_le16(qp->sq.cur_post <<
				(qp->sq.wqe_shift - XSC_BASE_WQE_SHIFT));
		ctrl->ds_data_num = 0;
		ctrl->se = wr->send_flags & IB_SEND_SOLICITED ? 1 : 0;
		ctrl->ce = wr->send_flags & IB_SEND_SIGNALED ? 1 : 0;
		for (i = 0; i < wr->num_sge; ++i) {
			if (likely(wr->sg_list[i].length))
				msg_len += wr->sg_list[i].length;
		}
		ctrl->msg_len = msg_len;
		ctrl->with_immdt = 0;

		if (unlikely(wr->opcode == IB_WR_RDMA_READ && msg_len == 0)) {
			xsc_ib_err(dev, "rdma read, msg len should not be 0\n");
			/* workaround, return success for posting zero-length read */
			err = 0;
			goto out;
		}
		switch (ibqp->qp_type) {
		case IB_QPT_RC:
			ctrl->ds_data_num = wr->num_sge;
			switch (wr->opcode) {
			case IB_WR_SEND_WITH_INV:
			case IB_WR_SEND:
				break;
			case IB_WR_SEND_WITH_IMM:
				ctrl->with_immdt = 1;
				WR_LE_32(ctrl->opcode_data, RD_BE_32(send_ieth(wr)));
				break;
			case IB_WR_RDMA_WRITE_WITH_IMM:
				ctrl->with_immdt = 1;
				WR_LE_32(ctrl->opcode_data, RD_BE_32(send_ieth(wr)));
			case IB_WR_RDMA_READ:
			case IB_WR_RDMA_WRITE:
				if (ctrl->msg_len == 0)
					break;
				ctrl->ds_data_num++;
				data_seg = get_seg_wqe(ctrl, seg_index);
				set_remote_addr_seg(dev->xdev, data_seg,
						    msg_len,
						    rdma_wr(wr)->remote_addr,
						    rdma_wr(wr)->rkey);
				seg_index++;
				break;
			case IB_WR_REG_MR:
				break;
			default:
				xsc_ib_err(dev, "debug: opcode:%u NOT supported\n", wr->opcode);
				err = EPERM;
				*bad_wr = wr;
				goto out;
			}
			ctrl->msg_opcode = xsc_ib_opcode[wr->opcode];
			break;
		case IB_QPT_UD:
		case IB_QPT_GSI:
			ctrl->msg_opcode = xsc_get_mad_msg_opcode(dev->xdev);
			ctrl->ds_data_num++;
			data_seg = get_seg_wqe(ctrl, seg_index);
			mad_send_base = (u8 *)qp->sq.hdr_buf +
				MAX_QP1_SQ_HDR_SIZE_V2 * qp->sq.mad_index;

			err = build_qp1_send_v2(dev, qp, wr, &sg, msg_len, &crc);
			if (err) {
				*bad_wr = wr;
				goto out;
			}

			cur_p = mad_send_base + sg.length;
			for (i = 0; i < wr->num_sge; ++i) {
				if (likely(wr->sg_list[i].length)) {
					vaddr = xsc_ib_send_mad_sg_virt_addr(&dev->ib_dev, wr, i);
					memcpy(cur_p, vaddr, wr->sg_list[i].length);
				}
				cur_p += wr->sg_list[i].length;
			}
			crc = xsc_crc32(dev, crc, mad_send_base + sg.length, ctrl->msg_len);
			ctrl->msg_len += sg.length;
			seg_index++;

			*(u32 *)&mad_send_base[ctrl->msg_len] = ~crc;
			ctrl->msg_len += sizeof(crc);
			sg.length = ctrl->msg_len;
			set_local_data_seg(dev->xdev, data_seg, &sg);
			xsc_ib_info(dev, "qp[%d] send MAD packet, msg_len:%d\n",
				    qp->xqp.qpn, ctrl->msg_len);
			qp->sq.mad_index = (qp->sq.mad_index + 1) % MAD_QUEUE_DEPTH;

			sg_n = 0;
			break;
		default:
			xsc_ib_err(dev, "qp type:%u NOT supported\n", ibqp->qp_type);
			err = EPERM;
			*bad_wr = wr;
			goto out;
		}

		if (wr->opcode == IB_WR_REG_MR) {
			nreq--;
			continue;
		}

		if (wr->send_flags & IB_SEND_INLINE && wr->num_sge) {
			err = set_data_inl_seg(qp, wr, ctrl);
			if (unlikely(err)) {
				*bad_wr = wr;
				xsc_ib_err(dev, "inline layout failed, err %d\n", err);
				goto out;
			}
		} else {
			for (i = 0; i < sg_n; ++i, ++seg_index) {
				if (likely(sgl[i].length)) {
					data_seg = get_seg_wqe(ctrl, seg_index);
					set_local_data_seg(dev->xdev, data_seg, &sgl[i]);
				}
			}
		}
		qp->sq.wrid[idx] = wr->wr_id;
		qp->sq.wqe_head[idx] = qp->sq.head + nreq;
		qp->sq.cur_post += 1;
		if (ctrl->ce) {
			atomic_inc(&qp->sq.flush_wqe_cnt);
			qp->sq.need_flush[idx] = 1;
		}
		qp->sq.wr_opcode[idx] = wr->opcode;
	}
out:
	xsc_ib_dbg(dev, "nreq:%d\n", nreq);
	xsc_post_send_db(qp, dev->xdev, nreq);
	spin_unlock_irqrestore(&qp->sq.lock, irqflag);

	return err;
}

int xsc_ib_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		     const struct ib_recv_wr **bad_wr)
{
	struct xsc_ib_qp *qp = to_xqp(ibqp);
	struct xsc_ib_dev *dev = to_mdev(ibqp->device);
	struct xsc_core_device *xdev = dev->xdev;
	struct xsc_wqe_data_seg *recv_head;
	struct xsc_wqe_data_seg *data_seg;
	unsigned long flags;
	int err = 0;
	u16 next_pid = 0;
	int nreq;
	u16 idx;
	int i;

	spin_lock_irqsave(&qp->rq.lock, flags);

	idx = qp->rq.head & (qp->rq.wqe_cnt - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(xsc_wq_overflow(&qp->rq, nreq, to_xcq(qp->ibqp.recv_cq)))) {
			xsc_ib_err(dev, "recv work queue overflow\n");
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->rq.max_gs)) {
			xsc_ib_err(dev, "max gs exceeded %d (max = %d)\n",
				   wr->num_sge, qp->rq.max_gs);
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		recv_head = get_recv_wqe(qp, idx);

		for (i = 0; i < wr->num_sge; ++i) {
			if (unlikely(!wr->sg_list[i].length))
				continue;
			data_seg = get_seg_wqe(recv_head, i);
			data_seg->in_line = 0;
			WR_LE_64(data_seg->va, wr->sg_list[i].addr);
			WR_LE_32(data_seg->mkey, wr->sg_list[i].lkey);
			if (is_qp1(qp->xqp.qp_type))
				WR_LE_32(data_seg->seg_len, xdev->caps.rx_pkt_len_max);
			else
				WR_LE_32(data_seg->seg_len, wr->sg_list[i].length);
		}

		qp->rq.wrid[idx] = wr->wr_id;

		idx = (idx + 1) & (qp->rq.wqe_cnt - 1);
		atomic_inc(&qp->rq.flush_wqe_cnt);
	}

out:
	if (likely(nreq)) {
		qp->rq.head += nreq;
		next_pid = qp->rq.head << (qp->rq.wqe_shift - XSC_BASE_WQE_SHIFT);

		xsc_update_rx_db(xdev, qp->doorbell_qpn, next_pid);
	}

	spin_unlock_irqrestore(&qp->rq.lock, flags);

	return err;
}

static inline enum ib_qp_state to_ib_qp_state(enum xsc_qp_state xsc_state)
{
	switch (xsc_state) {
	case XSC_QP_STATE_RST:      return IB_QPS_RESET;
	case XSC_QP_STATE_INIT:     return IB_QPS_INIT;
	case XSC_QP_STATE_RTR:      return IB_QPS_RTR;
	case XSC_QP_STATE_RTS:      return IB_QPS_RTS;
	case XSC_QP_STATE_SQ_DRAINING:
	case XSC_QP_STATE_SQD:      return IB_QPS_SQD;
	case XSC_QP_STATE_SQER:     return IB_QPS_SQE;
	case XSC_QP_STATE_ERR:      return IB_QPS_ERR;
	default:		     return -1;
	}
}

static inline enum ib_mig_state to_ib_mig_state(int xsc_mig_state)
{
	switch (xsc_mig_state) {
	case XSC_QP_PM_ARMED:		return IB_MIG_ARMED;
	case XSC_QP_PM_REARM:		return IB_MIG_REARM;
	case XSC_QP_PM_MIGRATED:	return IB_MIG_MIGRATED;
	default: return -1;
	}
}

int xsc_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		    struct ib_qp_init_attr *qp_init_attr)
{
	struct xsc_ib_dev *dev = to_mdev(ibqp->device);
	struct xsc_ib_qp *qp = to_xqp(ibqp);
	struct xsc_query_qp_mbox_out *outb;
	struct xsc_qp_context *context;
	int err = 0;

	mutex_lock(&qp->mutex);
	outb = kzalloc(sizeof(*outb), GFP_KERNEL);
	if (!outb) {
		err = -ENOMEM;
		goto out;
	}
	context = &outb->ctx;
	err = xsc_core_qp_query(dev->xdev, &qp->xqp, outb, sizeof(*outb));
	if (err)
		goto out_free;

	if (qp->xqp.err_occurred) {
		qp->state = IB_QPS_ERR;
		qp->xqp.err_occurred = 0;
	}
	qp_attr->qp_state	     = qp->state;
	qp_attr->path_mtu	     = context->mtu_mode ? IB_MTU_4096 : IB_MTU_1024;
	qp_attr->rq_psn		     = be32_to_cpu(context->next_recv_psn) & 0xffffff;
	qp_attr->sq_psn		     = be32_to_cpu(context->next_send_psn) & 0xffffff;
	qp_attr->dest_qp_num	     = be32_to_cpu(context->remote_qpn) & 0xffffff;
	qp_attr->sq_draining = 0;
	qp_attr->retry_cnt	    = context->retry_cnt;
	qp_attr->rnr_retry	    = context->rnr_retry;
	qp_attr->cur_qp_state	     = qp_attr->qp_state;
	qp_attr->cap.max_recv_wr     = qp->rq.wqe_cnt;
	qp_attr->cap.max_recv_sge    = qp->rq.max_gs;

	if (!ibqp->uobject) {
		qp_attr->cap.max_send_wr  = qp->sq.wqe_cnt;
		qp_attr->cap.max_send_sge = qp->sq.max_gs;
	} else {
		qp_attr->cap.max_send_wr  = qp->sq.wqe_cnt;
		qp_attr->cap.max_send_sge = qp->sq.max_gs;
	}

	/* We don't support inline sends for kernel QPs (yet), and we
	 * don't know what userspace's value should be.
	 */
	qp_attr->cap.max_inline_data = 0;

	qp_init_attr->cap	     = qp_attr->cap;

	qp_init_attr->create_flags = 0;
	if (qp->flags & XSC_IB_QP_BLOCK_MULTICAST_LOOPBACK)
		qp_init_attr->create_flags |= IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK;

	qp_init_attr->sq_sig_type = qp->sq_signal_bits & XSC_WQE_CTRL_CQ_UPDATE ?
		IB_SIGNAL_ALL_WR : IB_SIGNAL_REQ_WR;

out_free:
	kfree(outb);

out:
	mutex_unlock(&qp->mutex);
	return err;
}

struct xsc_ib_drain_cqe {
	struct ib_cqe cqe;
	struct completion done;
};

static void xsc_ib_drain_qp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct xsc_ib_drain_cqe *cqe = container_of(wc->wr_cqe,
						     struct xsc_ib_drain_cqe, cqe);

	complete(&cqe->done);
}

void xsc_ib_drain_rq(struct ib_qp *qp)
{
	struct ib_cq *cq = qp->recv_cq;
	struct xsc_ib_cq *xcq = to_xcq(cq);
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	struct xsc_ib_drain_cqe rdrain;
	const struct ib_recv_wr rwr = {
		.next = NULL,
		{.wr_cqe = &rdrain.cqe,},
	};
	const struct ib_recv_wr *bad_rwr;
	int ret;
	struct xsc_ib_dev *dev = to_mdev(qp->device);

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		xsc_ib_err(dev, "failed to drain recv queue: %d\n", ret);
		return;
	}

	rdrain.cqe.done = xsc_ib_drain_qp_done;
	init_completion(&rdrain.done);

	ret = xsc_ib_post_recv(qp, &rwr, &bad_rwr);
	if (ret) {
		xsc_ib_err(dev, "failed to drain recv queue: %d\n", ret);
		return;
	}

	xcq->xcq.comp(&xcq->xcq);
	wait_for_completion(&rdrain.done);
}

void xsc_ib_drain_sq(struct ib_qp *qp)
{
	struct ib_cq *cq = qp->send_cq;
	struct xsc_ib_cq *xcq = to_xcq(cq);
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	struct xsc_ib_drain_cqe sdrain;
	const struct ib_send_wr *bad_swr;
	const struct ib_send_wr swr = {
		.next = NULL,
		{ .wr_cqe	= &sdrain.cqe, },
		.opcode	= IB_WR_RDMA_WRITE,
		.send_flags = IB_SEND_SIGNALED,
	};
	int ret;
	struct xsc_ib_dev *dev = to_mdev(qp->device);

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		xsc_ib_err(dev, "failed to drain recv queue: %d\n", ret);
		return;
	}

	sdrain.cqe.done = xsc_ib_drain_qp_done;
	init_completion(&sdrain.done);

	ret = xsc_ib_post_send(qp, &swr, &bad_swr);
	if (ret) {
		xsc_ib_err(dev, "failed to drain send queue: %d\n", ret);
		return;
	}

	xcq->xcq.comp(&xcq->xcq);
	wait_for_completion(&sdrain.done);
}

