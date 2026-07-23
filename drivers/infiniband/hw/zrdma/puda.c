// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "osdep.h"
#include "status.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "protos.h"
#include "puda.h"
#include "ws.h"

/**
 * zxdh_puda_get_listbuf - get buffer from puda list
 * @list: list to use for buffers (ILQ or IEQ)
 */
static struct zxdh_puda_buf *zxdh_puda_get_listbuf(struct list_head *list)
{
	struct zxdh_puda_buf *buf = NULL;

	if (!list_empty(list)) {
		buf = (struct zxdh_puda_buf *)list->next;
		list_del((struct list_head *)&buf->list);
	}

	return buf;
}

/**
 * zxdh_puda_ret_bufpool - return buffer to rsrc list
 * @rsrc: resource to use for buffer
 * @buf: buffer to return to resource
 */
void zxdh_puda_ret_bufpool(struct zxdh_puda_rsrc *rsrc, struct zxdh_puda_buf *buf)
{
	unsigned long flags;

	buf->do_lpb = false;
	spin_lock_irqsave(&rsrc->bufpool_lock, flags);
	list_add(&buf->list, &rsrc->bufpool);
	spin_unlock_irqrestore(&rsrc->bufpool_lock, flags);
	rsrc->avail_buf_count++;
}

/**
 * zxdh_puda_get_next_send_wqe - return next wqe for processing
 * @qp: puda qp for wqe
 * @wqe_idx: wqe index for caller
 */
static __le64 *zxdh_puda_get_next_send_wqe(struct zxdh_qp_uk *qp, u32 *wqe_idx)
{
	__le64 *wqe = NULL;
	int ret_code = 0;

	*wqe_idx = ZXDH_RING_CURRENT_HEAD(qp->sq_ring);
	if (!*wqe_idx)
		qp->swqe_polarity = !qp->swqe_polarity;
	ZXDH_RING_MOVE_HEAD(qp->sq_ring, ret_code);
	if (ret_code)
		return wqe;

	wqe = qp->sq_base[*wqe_idx].elem;

	return wqe;
}

/**
 * zxdh_puda_send - complete send wqe for transmit
 * @qp: puda qp for send
 * @info: buffer information for transmit
 */
int zxdh_puda_send(struct zxdh_sc_qp *qp, struct zxdh_puda_send_info *info)
{
	__le64 *wqe;
	u32 iplen, l4len;
	u64 hdr[2];
	u32 wqe_idx;
	u8 iipt;

	/* number of 32 bits DWORDS in header */
	l4len = info->tcplen >> 2;
	if (info->ipv4) {
		iipt = 3;
		iplen = 5;
	} else {
		iipt = 1;
		iplen = 10;
	}

	wqe = zxdh_puda_get_next_send_wqe(&qp->qp_uk, &wqe_idx);
	if (!wqe)
		return -ENOSPC;

	qp->qp_uk.sq_wrtrk_array[wqe_idx].wrid = (uintptr_t)info->scratch;
	/* Third line of WQE descriptor */
	/* maclen is in words */

	if (qp->dev->hw_attrs.uk_attrs.hw_rev >= ZXDH_GEN_2) {
		hdr[0] = 0; /* Dest_QPN and Dest_QKey only for UD */
		hdr[1] = FIELD_PREP(ZXDH_UDA_QPSQ_OPCODE, ZXDH_OP_TYPE_SEND) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_L4LEN, l4len) |
			 FIELD_PREP(IRDMAQPSQ_AHID, info->ah_id) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_SIGCOMPL, 1) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_VALID, qp->qp_uk.swqe_polarity);

		/* Forth line of WQE descriptor */

		set_64bit_val(wqe, 0, info->paddr);
		set_64bit_val(wqe, 8,
			      FIELD_PREP(IRDMAQPSQ_FRAG_LEN, info->len) |
				      FIELD_PREP(ZXDH_UDA_QPSQ_VALID, qp->qp_uk.swqe_polarity));
	} else {
		hdr[0] = FIELD_PREP(ZXDH_UDA_QPSQ_MACLEN, info->maclen >> 1) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_IPLEN, iplen) | FIELD_PREP(ZXDH_UDA_QPSQ_L4T, 1) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_IIPT, iipt) |
			 FIELD_PREP(ZXDH_GEN1_UDA_QPSQ_L4LEN, l4len);

		hdr[1] = FIELD_PREP(ZXDH_UDA_QPSQ_OPCODE, ZXDH_OP_TYPE_SEND) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_SIGCOMPL, 1) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_DOLOOPBACK, info->do_lpb) |
			 FIELD_PREP(ZXDH_UDA_QPSQ_VALID, qp->qp_uk.swqe_polarity);

		/* Forth line of WQE descriptor */

		set_64bit_val(wqe, 0, info->paddr);
		set_64bit_val(wqe, 8, FIELD_PREP(IRDMAQPSQ_GEN1_FRAG_LEN, info->len));
	}

	set_64bit_val(wqe, 16, hdr[0]);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 24, hdr[1]);

	print_hex_dump_debug("PUDA: PUDA SEND WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe, 32, false);
	zxdh_uk_qp_post_wr(&qp->qp_uk);
	return 0;
}

/**
 * zxdh_puda_send_buf - transmit puda buffer
 * @rsrc: resource to use for buffer
 * @buf: puda buffer to transmit
 */
void zxdh_puda_send_buf(struct zxdh_puda_rsrc *rsrc, struct zxdh_puda_buf *buf)
{
	struct zxdh_puda_send_info info = {};
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&rsrc->bufpool_lock, flags);
	/* if no wqe available or not from a completion and we have
	 * pending buffers, we must queue new buffer
	 */
	if (!rsrc->tx_wqe_avail_cnt || (buf && !list_empty(&rsrc->txpend))) {
		list_add_tail(&buf->list, &rsrc->txpend);
		spin_unlock_irqrestore(&rsrc->bufpool_lock, flags);
		rsrc->stats_sent_pkt_q++;
		if (rsrc->type == ZXDH_PUDA_RSRC_TYPE_ILQ)
			pr_err("PUDA: adding to txpend\n");
		return;
	}
	rsrc->tx_wqe_avail_cnt--;
	/* if we are coming from a completion and have pending buffers
	 * then Get one from pending list
	 */
	if (!buf) {
		buf = zxdh_puda_get_listbuf(&rsrc->txpend);
		if (!buf)
			goto done;
	}

	info.scratch = buf;
	info.paddr = buf->mem.pa;
	info.len = buf->totallen;
	info.tcplen = buf->tcphlen;
	info.ipv4 = buf->ipv4;

	if (rsrc->dev->hw_attrs.uk_attrs.hw_rev >= ZXDH_GEN_2) {
		info.ah_id = buf->ah_id;
	} else {
		info.maclen = buf->maclen;
		info.do_lpb = buf->do_lpb;
	}

	/* Synch buffer for use by device */
	dma_sync_single_for_cpu(rsrc->dev->hw->device, buf->mem.pa, buf->mem.size,
				DMA_BIDIRECTIONAL);
	ret = zxdh_puda_send(&rsrc->qp, &info);
	if (ret) {
		rsrc->tx_wqe_avail_cnt++;
		rsrc->stats_sent_pkt_q++;
		list_add(&buf->list, &rsrc->txpend);
		if (rsrc->type == ZXDH_PUDA_RSRC_TYPE_ILQ)
			pr_info("PUDA: adding to puda_send\n");
	} else {
		rsrc->stats_pkt_sent++;
	}
done:
	spin_unlock_irqrestore(&rsrc->bufpool_lock, flags);
}
