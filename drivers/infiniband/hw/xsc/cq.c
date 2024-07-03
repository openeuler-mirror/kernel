// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kref.h>
#include <rdma/ib_umem.h>
#include "xsc_ib.h"
#include "user.h"
#include "common/xsc_hsi.h"
#include <linux/dma-direct.h>

enum {
	CQ_OK					=  0,
	CQ_EMPTY				= -1,
	CQ_POLL_ERR				= -2
};

enum {
	XSC_CQE_APP_TAG_MATCHING = 1,
};

enum {
	XSC_CQE_APP_OP_TM_CONSUMED = 0x1,
	XSC_CQE_APP_OP_TM_EXPECTED = 0x2,
	XSC_CQE_APP_OP_TM_UNEXPECTED = 0x3,
	XSC_CQE_APP_OP_TM_NO_TAG = 0x4,
	XSC_CQE_APP_OP_TM_APPEND = 0x5,
	XSC_CQE_APP_OP_TM_REMOVE = 0x6,
	XSC_CQE_APP_OP_TM_NOOP = 0x7,
	XSC_CQE_APP_OP_TM_CONSUMED_SW_RDNV = 0x9,
	XSC_CQE_APP_OP_TM_CONSUMED_MSG = 0xA,
	XSC_CQE_APP_OP_TM_CONSUMED_MSG_SW_RDNV = 0xB,
	XSC_CQE_APP_OP_TM_MSG_COMPLETION_CANCELED = 0xC,
};

static const u32 xsc_msg_opcode[][2][2] = {
	[XSC_MSG_OPCODE_SEND][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_REQ_SEND,
	[XSC_MSG_OPCODE_SEND][XSC_REQ][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_REQ_SEND_IMMDT,
	[XSC_MSG_OPCODE_SEND][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_RSP_RECV,
	[XSC_MSG_OPCODE_SEND][XSC_RSP][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_RSP_RECV_IMMDT,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_REQ_WRITE,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_REQ][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_REQ_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_WRITE][XSC_RSP][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_RSP_WRITE_IMMDT,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_REQ_READ,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_REQ][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_RDMA_READ][XSC_RSP][XSC_WITH_IMMDT] = XSC_OPCODE_RDMA_CQE_ERROR,
	[XSC_MSG_OPCODE_MAD][XSC_REQ][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_MAD_REQ_SEND,
	[XSC_MSG_OPCODE_MAD][XSC_RSP][XSC_WITHOUT_IMMDT] = XSC_OPCODE_RDMA_MAD_RSP_RECV,
};

static const u32 xsc_cqe_opcode[] = {
	[XSC_OPCODE_RDMA_REQ_SEND]		= IB_WC_SEND,
	[XSC_OPCODE_RDMA_REQ_SEND_IMMDT]	= IB_WC_SEND,
	[XSC_OPCODE_RDMA_RSP_RECV]		= IB_WC_RECV,
	[XSC_OPCODE_RDMA_RSP_RECV_IMMDT]	= IB_WC_RECV,
	[XSC_OPCODE_RDMA_REQ_WRITE]		= IB_WC_RDMA_WRITE,
	[XSC_OPCODE_RDMA_REQ_WRITE_IMMDT]	= IB_WC_RDMA_WRITE,
	[XSC_OPCODE_RDMA_RSP_WRITE_IMMDT]	= IB_WC_RECV_RDMA_WITH_IMM,
	[XSC_OPCODE_RDMA_REQ_READ]		= IB_WC_RDMA_READ,
	[XSC_OPCODE_RDMA_MAD_REQ_SEND]		= IB_WC_SEND,
	[XSC_OPCODE_RDMA_MAD_RSP_RECV]		= IB_WC_RECV,
};

int xsc_stall_num_loop = 60;
int xsc_stall_cq_poll_min = 60;
int xsc_stall_cq_poll_max = 100000;
int xsc_stall_cq_inc_step = 100;
int xsc_stall_cq_dec_step = 10;

static inline u8 xsc_get_cqe_opcode(struct xsc_cqe *cqe)
{
	if (cqe->is_error)
		return cqe->type ? XSC_OPCODE_RDMA_RSP_ERROR : XSC_OPCODE_RDMA_REQ_ERROR;
	if (cqe->msg_opcode > XSC_MSG_OPCODE_MAD)
		return XSC_OPCODE_RDMA_CQE_ERROR;
	return xsc_msg_opcode[cqe->msg_opcode][cqe->type][cqe->with_immdt];
}

static void xsc_ib_cq_comp(struct xsc_core_cq *cq)
{
	struct ib_cq *ibcq = &to_xibcq(cq)->ibcq;

	ibcq->comp_handler(ibcq, ibcq->cq_context);
}

static void xsc_ib_cq_event(struct xsc_core_cq *xcq, enum xsc_event type)
{
	struct xsc_ib_cq *cq = container_of(xcq, struct xsc_ib_cq, xcq);
	struct xsc_ib_dev *dev = to_mdev(cq->ibcq.device);
	struct ib_cq *ibcq = &cq->ibcq;
	struct ib_event event;

	if (type != XSC_EVENT_TYPE_CQ_ERROR) {
		xsc_ib_err(dev, "Unexpected event type %d on CQ %06x\n",
			   type, xcq->cqn);
		return;
	}

	if (ibcq->event_handler) {
		event.device     = &dev->ib_dev;
		event.event      = IB_EVENT_CQ_ERR;
		event.element.cq = ibcq;
		ibcq->event_handler(&event, ibcq->cq_context);
	}
}

static void *get_cqe_from_buf(struct xsc_ib_cq_buf *buf, int n, int size)
{
	return xsc_buf_offset(&buf->buf, n * size);
}

static void *get_cqe(struct xsc_ib_cq *cq, int n)
{
	return get_cqe_from_buf(&cq->buf, n, cq->xcq.cqe_sz);
}

static void *get_sw_cqe(struct xsc_ib_cq *cq, int n)
{
	struct xsc_cqe *cqe;

	cqe = (struct xsc_cqe *)get_cqe(cq, n & (cq->ibcq.cqe - 1));

	return ((cqe->owner & XSC_CQE_OWNER_MASK) ^
		!!(n & cq->ibcq.cqe)) ? NULL : cqe;
}

static inline void handle_good_req(struct ib_wc *wc,
				   struct xsc_cqe *cqe,
				   u8 opcode)
{
	wc->opcode = xsc_cqe_opcode[opcode];
	if (opcode == XSC_OPCODE_RDMA_REQ_READ)
		wc->byte_len  = RD_LE_32(cqe->msg_len);
	wc->status = IB_WC_SUCCESS;
}

static void handle_responder(struct ib_wc *wc, struct xsc_cqe *cqe,
			     struct xsc_ib_qp *qp, u8 opcode)
{
	struct xsc_ib_wq *wq = &qp->rq;
	u16 idx;

	wc->byte_len = RD_LE_32(cqe->msg_len);
	wc->opcode = xsc_cqe_opcode[opcode];
	wc->status = IB_WC_SUCCESS;

	idx = wq->tail & (wq->wqe_cnt - 1);
	wc->wr_id = wq->wrid[idx];
	++wq->tail;
}

struct ib_mad_list_head {
	struct list_head list;
	struct ib_cqe cqe;
	struct ib_mad_queue *mad_queue;
};

struct ib_mad_private_header {
	struct ib_mad_list_head mad_list;
	struct ib_mad_recv_wc recv_wc;
	struct ib_wc wc;
	u64 mapping;
} __packed;

struct ib_mad_private {
	struct ib_mad_private_header header;
	size_t mad_size;
	struct ib_grh grh;
	u8 mad[];
} __packed;

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

static void xsc_handle_rdma_mad_resp_recv(struct xsc_ib_cq *cq,
					  struct xsc_ib_qp **cur_qp,
					  struct ib_wc *wc,
					  struct xsc_cqe *cqe,
					  u8 opcode)
{
	struct xsc_ib_dev *dev = to_mdev(cq->ibcq.device);
	void *recv;
	struct xsc_wqe_data_seg *data_seg;
	struct iphdr *ip4h = NULL;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct ib_unpacked_eth *eth;
	struct ib_unpacked_vlan *vlan;
	struct ib_grh *grh;
	struct ib_mad *mad;
	struct rxe_bth *bth;
	struct rxe_deth *deth;
	unsigned int pading_sz = 0;
	struct xsc_ib_wq *wq;
	int idx;
	u16 eth_type;
	void *l3_start;

	wq = &(*cur_qp)->rq;
	idx = wq->tail & (wq->wqe_cnt - 1);

	handle_responder(wc, cqe, *cur_qp, opcode);

	data_seg = get_seg_wqe(get_recv_wqe(*cur_qp, idx), 0);
	recv = phys_to_virt(dma_to_phys(dev->ib_dev.dma_device, data_seg->va));

	eth = (struct ib_unpacked_eth *)recv;
	grh = (struct ib_grh *)recv;
	if (eth->type == htons(ETH_P_8021Q)) {
		vlan = (struct ib_unpacked_vlan *)(eth + 1);
		eth_type = ntohs(vlan->type);
		l3_start = vlan + 1;

		wc->vlan_id = ntohs(vlan->tag) & 0x0fff;
		wc->sl = (ntohs(vlan->tag) >> 13) & 0x7;
		wc->wc_flags |= IB_WC_WITH_VLAN;
	} else {
		eth_type = ntohs(eth->type);
		l3_start = eth + 1;
	}

	if (eth_type == ETH_P_IP) {
		ip4h = (struct iphdr *)l3_start;
		udph = (struct udphdr *)(ip4h + 1);
	} else {
		ip6h = (struct ipv6hdr *)l3_start;
		udph = (struct udphdr *)(ip6h + 1);
	}
	bth = (struct rxe_bth *)(udph + 1);
	deth = (struct rxe_deth *)(bth + 1);
	mad = (struct ib_mad *)(deth + 1);

	if (eth_type == ETH_P_IP) {
		pading_sz = sizeof(*grh) - sizeof(*ip4h);
		memmove((u8 *)(grh + 1) - sizeof(*ip4h), ip4h, sizeof(*ip4h));
		memset(grh, 0, pading_sz);
	} else {
		memmove(grh, ip6h, sizeof(*ip6h));
	}
	memmove(grh + 1, mad, sizeof(*mad));

	wc->wc_flags |= IB_WC_GRH;

	xsc_ib_dbg(dev, "recv cqe idx:%u, len:%u\n", wq->tail, wc->byte_len);
	wc->status = IB_WC_SUCCESS;
}

static int xsc_poll_one(struct xsc_ib_cq *cq,
			struct xsc_ib_qp **cur_qp,
			struct ib_wc *wc)
{
	struct xsc_ib_dev *dev = to_mdev(cq->ibcq.device);
	struct xsc_core_qp *xqp;
	struct xsc_ib_wq *wq;
	u8 opcode;
	u32 qpn;
	int idx;
	struct xsc_cqe *cqe;
	u32 *p = NULL;

	cqe = get_sw_cqe(cq, cq->xcq.cons_index);
	if (!cqe)
		return -EAGAIN;

	++cq->xcq.cons_index;

	/* Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	rmb();

	p = (u32 *)cqe;

	qpn = cqe->qp_id;
	qpn = le32_to_cpu(qpn);
	if (!*cur_qp || (qpn != (*cur_qp)->ibqp.qp_num)) {
		/* We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		xqp = __xsc_qp_lookup(dev->xdev, qpn);
		if (unlikely(!xqp)) {
			xsc_ib_warn(dev, "CQE@CQ %d for unknown QPN %d\n",
				    cq->xcq.cqn, qpn);
			return -EINVAL;
		}

		*cur_qp = to_xibqp(xqp);
	}

	memset(wc, 0, sizeof(*wc));
	wc->qp = &(*cur_qp)->ibqp;
	opcode = xsc_get_cqe_opcode(cqe);
	switch (opcode) {
	case XSC_OPCODE_RDMA_REQ_SEND:
	case XSC_OPCODE_RDMA_REQ_WRITE:
	case XSC_OPCODE_RDMA_REQ_READ:
	case XSC_OPCODE_RDMA_MAD_REQ_SEND:
		wq = &(*cur_qp)->sq;
		idx = cqe->wqe_id >> (wq->wqe_shift - XSC_BASE_WQE_SHIFT);
		idx &= (wq->wqe_cnt - 1);
		handle_good_req(wc, cqe, opcode);
		wc->wr_id = wq->wrid[idx];
		wq->tail = wq->wqe_head[idx] + 1;
		xsc_ib_dbg(dev, "wqeid:%u, wq tail:%u qpn:%u\n", idx, wq->tail, qpn);
		wc->status = IB_WC_SUCCESS;
		break;
	case XSC_OPCODE_RDMA_RSP_RECV:
		wq = &(*cur_qp)->rq;
		handle_responder(wc, cqe, *cur_qp, opcode);
		xsc_ib_dbg(dev, "recv cqe idx:%u, len:%u, qpn:%u\n", wq->tail, wc->byte_len, qpn);
		wc->status = IB_WC_SUCCESS;
		break;

	case XSC_OPCODE_RDMA_MAD_RSP_RECV:
		xsc_ib_dbg(dev, "recv MAD, qpn:%u\n", qpn);
		xsc_handle_rdma_mad_resp_recv(cq, cur_qp, wc, cqe, opcode);
		break;

	default:
		xsc_ib_err(dev, "completion error\n%08x %08x %08x %08x %08x %08x\n",
			   p[0], p[1], p[2], p[3], p[5], p[6]);
		wc->status = IB_WC_GENERAL_ERR;
		wc->wr_id = 0;
		break;
	}

	return 0;
}

int xsc_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct xsc_ib_cq *cq = to_xcq(ibcq);
	struct xsc_core_cq *xcq = &cq->xcq;
	struct xsc_ib_qp *cur_qp = NULL;
	int npolled = 0;
	int err = 0;
	unsigned long flags;
	u32 next_cid;

	spin_lock_irqsave(&cq->lock, flags);
	next_cid = xcq->cons_index;

	for (npolled = 0; npolled < num_entries; npolled++) {
		err = xsc_poll_one(cq, &cur_qp, wc + npolled);
		if (err)
			break;
	}

	/* make sure cqe read out before update ci */
	rmb();

	if (next_cid != xcq->cons_index)
		xsc_cq_set_ci(xcq);

	spin_unlock_irqrestore(&cq->lock, flags);

	return npolled;
}

int xsc_cqe_is_empty(struct xsc_ib_cq *cq)
{
	struct xsc_cqe *cqe = get_sw_cqe(cq, cq->xcq.cons_index);

	if (!cqe)
		return 1;

	return 0;
}

int xsc_ib_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
#ifdef MSIX_SUPPORT
	union xsc_cq_doorbell db;
	struct xsc_ib_cq *xcq = to_xcq(ibcq);
	struct xsc_core_cq *cq = &xcq->xcq;
	int ret = 0;
	unsigned long irq_flags;

	spin_lock_irqsave(&xcq->lock, irq_flags);
	db.val = 0;
	db.cq_next_cid = cq->cons_index;
	db.cq_id = cq->cqn;
	if (flags & IB_CQ_NEXT_COMP)
		db.arm = 0;
	else if (flags & IB_CQ_SOLICITED)
		db.arm = 1;/* arm next:0 arm solicited:1 */

	if ((flags & IB_CQ_REPORT_MISSED_EVENTS) && (!xsc_cqe_is_empty(xcq))) {
		ret = 1;
		goto out;
	}

	/* make sure val write to memory done */
	wmb();
	writel(db.val, REG_ADDR(cq->dev, cq->arm_db));
out:
	spin_unlock_irqrestore(&xcq->lock, irq_flags);
	return ret;
#else
	if ((flags & IB_CQ_REPORT_MISSED_EVENTS))
		return 1;
	return 0;
#endif
}

static int alloc_cq_buf(struct xsc_ib_dev *dev, struct xsc_ib_cq_buf *buf,
			int nent, int cqe_size)
{
	int err;

	err = xsc_buf_alloc(dev->xdev, nent * cqe_size,
			    PAGE_SIZE, &buf->buf);
	if (err)
		return err;

	buf->cqe_size = cqe_size;

	return 0;
}

static void free_cq_buf(struct xsc_ib_dev *dev, struct xsc_ib_cq_buf *buf)
{
	xsc_buf_free(dev->xdev, &buf->buf);
}

static int create_cq_user(struct xsc_ib_dev *dev, struct ib_udata *udata,
			  struct ib_ucontext *context, struct xsc_ib_cq *cq,
			  int entries, struct xsc_create_cq_mbox_in **cqb,
			  int *cqe_size, int *index, int *inlen)
{
	struct xsc_ib_create_cq ucmd;
	int page_shift;
	int npages;
	int ncont;
	int err;
	int log_cq_sz;
	int hw_npages;

	if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd)))
		return -EFAULT;

	*cqe_size = ucmd.cqe_size;

	cq->buf.umem = ib_umem_get(&dev->ib_dev, ucmd.buf_addr,
				   entries * ucmd.cqe_size,
				   IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(cq->buf.umem)) {
		err = PTR_ERR(cq->buf.umem);
		return err;
	}

	xsc_ib_cont_pages(cq->buf.umem, ucmd.buf_addr, &npages, &page_shift,
			  &ncont, NULL);
	if (ncont != npages) {
		xsc_ib_dbg(dev, "bad page_shift:%d, ncont:%d\n", page_shift, ncont);
		/* amber doesn't support compound pages */
		page_shift = PAGE_SHIFT;
		ncont = npages;
		xsc_ib_dbg(dev, "overwrite to page_shift:%d, ncont:%d\n", page_shift, ncont);
	}
	log_cq_sz = ilog2(entries);
	hw_npages = DIV_ROUND_UP((1 << log_cq_sz) * sizeof(struct xsc_cqe), PAGE_SIZE_4K);
	xsc_ib_dbg(dev, "addr 0x%llx, entries %d, size %u, npages %d, page_shift %d, ncont %d, hw_npages %d\n",
		   ucmd.buf_addr, entries, ucmd.cqe_size, npages, page_shift, ncont, hw_npages);

	*inlen = sizeof(**cqb) + sizeof(*(*cqb)->pas) * hw_npages;
	*cqb = xsc_vzalloc(*inlen);
	if (!*cqb) {
		err = -ENOMEM;
		goto err_umem;
	}
	xsc_ib_populate_pas(dev, cq->buf.umem, page_shift, (*cqb)->pas, hw_npages, true);
	(*cqb)->ctx.pa_num = cpu_to_be16(hw_npages);

	return 0;

err_umem:
	ib_umem_release(cq->buf.umem);
	return err;
}

static void destroy_cq_user(struct xsc_ib_cq *cq, struct ib_udata *udata)
{
	ib_umem_release(cq->buf.umem);
}

static int create_cq_kernel(struct xsc_ib_dev *dev, struct xsc_ib_cq *cq,
			    int entries, int cqe_size,
			    struct xsc_create_cq_mbox_in **cqb,
			    int *index, int *inlen)
{
	int err;
	int i = 0;
	struct xsc_cqe *cqe = NULL;
	int hw_npages;

	cq->xcq.cqe_sz = cqe_size;

	err = alloc_cq_buf(dev, &cq->buf, entries, cqe_size);
	if (err)
		return err;

	for (i = 0; i < entries; i++) {
		cqe = (struct xsc_cqe *)get_cqe(cq, i);
		cqe->owner = 1;
	}

	hw_npages = DIV_ROUND_UP(entries * cqe_size, PAGE_SIZE_4K);
	*inlen = sizeof(**cqb) + sizeof(*(*cqb)->pas) * hw_npages;
	*cqb = xsc_vzalloc(*inlen);
	if (!*cqb) {
		err = -ENOMEM;
		goto err_buf;
	}
	xsc_fill_page_array(&cq->buf.buf, (*cqb)->pas, hw_npages);
	(*cqb)->ctx.pa_num = cpu_to_be16(hw_npages);

	return 0;

err_buf:
	free_cq_buf(dev, &cq->buf);
	return err;
}

static void destroy_cq_kernel(struct xsc_ib_dev *dev, struct xsc_ib_cq *cq)
{
	free_cq_buf(dev, &cq->buf);
}

xsc_ib_create_cq_def()
{
	struct ib_device *ibdev = ibcq->device;
	int entries = attr->cqe;
	int vector = attr->comp_vector;
	struct xsc_create_cq_mbox_in *cqb = NULL;
	struct xsc_ib_dev *dev = to_mdev(ibdev);
	struct xsc_ib_cq *cq;
	int index;
	int inlen;
	int cqe_size;
	int irqn;
	int err;
	unsigned int eqn;

	entries = roundup_pow_of_two(entries);

	xsc_ib_dbg(dev, "entries:%d, vector:%d, max_cqes:%d\n", entries, vector,
		   dev->xdev->caps.max_cqes);

	if (entries > dev->xdev->caps.max_cqes)
		entries = dev->xdev->caps.max_cqes;
	cq = to_xcq(ibcq);
	cq->ibcq.cqe = entries;
	mutex_init(&cq->resize_mutex);
	spin_lock_init(&cq->lock);
	cq->resize_buf = NULL;
	cq->resize_umem = NULL;

	if (udata) {
		err = create_cq_user(dev, udata, NULL, cq, entries,
				     &cqb, &cqe_size, &index, &inlen);
		if (err)
			goto err_create;
	} else {
		cqe_size = sizeof(struct xsc_cqe);
		err = create_cq_kernel(dev, cq, entries, cqe_size, &cqb, &index, &inlen);
		if (err)
			goto err_create;
	}

	cq->cqe_size = cqe_size;
	cqb->ctx.log_cq_sz = ilog2(entries);
	cqb->ctx.glb_func_id = cpu_to_be16(dev->xdev->glb_func_id);

	err = xsc_vector2eqn(dev->xdev, vector, &eqn, &irqn);
	if (err)
		goto err_cqb;

	cqb->ctx.eqn = eqn;
	cqb->ctx.eqn = cpu_to_be16(cqb->ctx.eqn);

	err = xsc_core_create_cq(dev->xdev, &cq->xcq, cqb, inlen);
	if (err)
		goto err_cqb;

	xsc_ib_dbg(dev, "cqn 0x%x\n", cq->xcq.cqn);
	cq->xcq.irqn = irqn;
	cq->xcq.comp  = xsc_ib_cq_comp;
	cq->xcq.event = xsc_ib_cq_event;

	if (udata) {
		if (ib_copy_to_udata(udata, &cq->xcq.cqn, sizeof(__u32))) {
			err = -EFAULT;
			goto err_cmd;
		}
	}

	xsc_vfree(cqb);

	return 0;

err_cmd:
	xsc_core_destroy_cq(dev->xdev, &cq->xcq);

err_cqb:
	xsc_vfree(cqb);
	if (udata)
		destroy_cq_user(cq, udata);
	else
		destroy_cq_kernel(dev, cq);

err_create:
	return RET_VALUE(err);
}

xsc_ib_destroy_cq_def()
{
	struct xsc_ib_dev *dev = to_mdev(cq->device);
	struct xsc_ib_cq *xcq = to_xcq(cq);

	xsc_core_destroy_cq(dev->xdev, &xcq->xcq);
	if (udata)
		destroy_cq_user(xcq, udata);
	else
		destroy_cq_kernel(dev, xcq);

	return 0;
}

static int is_equal_rsn(struct xsc_cqe *cqe, u32 rsn)
{
	u32 qpn = le32_to_cpu(cqe->qp_id);
	return rsn == qpn;
}

void __xsc_ib_cq_clean(struct xsc_ib_cq *cq, u32 rsn)
{
	struct xsc_cqe *cqe, *dest;
	u32 prod_index;
	int nfreed = 0;
	u8 owner_bit;

	if (!cq)
		return;

	/* First we need to find the current producer index, so we
	 * know where to start cleaning from.  It doesn't matter if HW
	 * adds new entries after this loop -- the QP we're worried
	 * about is already in RESET, so the new entries won't come
	 * from our QP and therefore don't need to be checked.
	 */
	for (prod_index = cq->xcq.cons_index; get_sw_cqe(cq, prod_index); prod_index++)
		if (prod_index == cq->xcq.cons_index + cq->ibcq.cqe)
			break;

	/* Now sweep backwards through the CQ, removing CQ entries
	 * that match our QP by copying older entries on top of them.
	 */
	while ((int)(--prod_index) - (int)cq->xcq.cons_index >= 0) {
		cqe = (struct xsc_cqe *)get_cqe(cq, prod_index & (cq->ibcq.cqe - 1));
		if (is_equal_rsn(cqe, rsn)) {
			++nfreed;
		} else if (nfreed) {
			dest = (struct xsc_cqe *)get_cqe(cq, (prod_index + nfreed) &
							 (cq->ibcq.cqe - 1));
			owner_bit = dest->owner & XSC_CQE_OWNER_MASK;
			memcpy(dest, cqe, cq->xcq.cqe_sz);
			dest->owner = owner_bit |
				(dest->owner & ~XSC_CQE_OWNER_MASK);
		}
	}

	if (nfreed) {
		cq->xcq.cons_index += nfreed;
		/* Make sure update of buffer contents is done before
		 * updating consumer index.
		 */
		wmb();
		xsc_cq_set_ci(&cq->xcq);
	}
}

void xsc_ib_cq_clean(struct xsc_ib_cq *cq, u32 qpn)
{
	if (!cq)
		return;

	spin_lock_irq(&cq->lock);
	__xsc_ib_cq_clean(cq, qpn);
	spin_unlock_irq(&cq->lock);
}

