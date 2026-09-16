// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/bpf_trace.h>
#include <net/xdp_sock.h>
#include <net/xdp.h>
#include <net/busy_poll.h>
#include "nse.h"
#include "nse_lib.h"
#include "nse_base.h"
#include "nse_type.h"
#include "nse_xsk.h"
#include "nse_txrx.h"
#include "nse_txrx_lib.h"
#include "nse_irq.h"

/**
 * nse_qp_reset_stats - Resets all stats for rings of given index
 * @vsi: VSI that contains rings of interest
 * @q_idx: ring index in array
 */
static void nse_qp_reset_stats(struct nse_vsi *vsi, u16 q_idx)
{
	memset(&vsi->rx_rings[q_idx]->rx_stats, 0,
	       sizeof(vsi->rx_rings[q_idx]->rx_stats));
	memset(&vsi->tx_rings[q_idx]->stats, 0,
	       sizeof(vsi->tx_rings[q_idx]->stats));
	if (nse_is_xdp_ena_vsi(vsi))
		memset(&vsi->xdp_rings[q_idx]->stats, 0,
		       sizeof(vsi->xdp_rings[q_idx]->stats));
}

/**
 * nse_qp_clean_rings - Cleans all the rings of a given index
 * @vsi: VSI that contains rings of interest
 * @q_idx: ring index in array
 */
static void nse_qp_clean_rings(struct nse_vsi *vsi, u16 q_idx)
{
	nse_clean_tx_ring(vsi->tx_rings[q_idx]);
	if (nse_is_xdp_ena_vsi(vsi))
		nse_clean_tx_ring(vsi->xdp_rings[q_idx]);

	nse_clean_rx_ring(vsi->rx_rings[q_idx]);
}

/**
 * nse_qvec_toggle_napi - Enables/disables NAPI for a given q_vector
 * @vsi: VSI that has netdev
 * @q_vector: q_vector that has NAPI context
 * @enable: true for enable, false for disable
 */
static void
nse_qvec_toggle_napi(struct nse_vsi *vsi, struct nse_q_vector *q_vector,
		     bool enable)
{
	if (!vsi->netdev || !q_vector)
		return;

	if (enable)
		napi_enable(&q_vector->napi);
	else
		napi_disable(&q_vector->napi);
}

/**
 * nse_qvec_dis_irq - Mask off queue interrupt generation on given ring
 * @vsi: the VSI that contains queue vector being un-configured
 * @rx_ring: Rx ring that will have its IRQ disabled
 * @q_vector: queue vector
 */
static void
nse_qvec_dis_irq(struct nse_vsi *vsi, struct nse_ring *rx_ring,
		 struct nse_q_vector *q_vector)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int base = vsi->base_vector;
	u16 rxq_abs_id;

	/* TXQ is being stopped in nse_vsi_stop_tx_ring, so handle
	 * here only RXQ
	 *
	 *  here don't write RXQ context CAUSE_EN bit, that is too heavy. But just pause/disable
	 * this RXQ.
	 */
	rxq_abs_id = pf->lan_rxq_space_start + rx_ring->reg_idx;

	(void)nse_aq_lan_disable_rxq(hw, rxq_abs_id,
					rx_ring->already_in_irqll ? rx_ring->irqll_msix :
						NSE_AQC_CONF_IRQLL_INVALID_MSIX);

	rx_ring->already_in_irqll = false;

	if (q_vector) {
		u16 v_idx = q_vector->v_idx;

		wr32(hw, NSE_REG_INT_DYN_CTLN(q_vector->reg_idx),
				(NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M |
				 NSE_REG_INT_DYN_CTLN_INTMSK_M));

		nse_flush(hw);

		if (!nse_no_irq)
			synchronize_irq(nse_get_irq_num(pf, v_idx + base));
	}
}

/**
 * nse_qvec_cfg_msix - Enable IRQ for given queue vector
 * @vsi: the VSI that contains queue vector
 * @q_vector: queue vector
 */
static void
nse_qvec_cfg_msix(struct nse_vsi *vsi, struct nse_q_vector *q_vector)
{
	u16 reg_idx = q_vector->reg_idx;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_ring *ring;

	nse_cfg_itr(hw, q_vector);

	nse_for_each_ring(ring, q_vector->tx)
		nse_cfg_txq_interrupt(vsi, ring->reg_idx, reg_idx);

	nse_for_each_ring(ring, q_vector->rx)
		nse_cfg_rxq_interrupt(vsi, ring->reg_idx, reg_idx);

	nse_flush(hw);
}

/**
 * nse_qvec_ena_irq - Enable IRQ for given queue vector
 * @vsi: the VSI that contains queue vector
 * @q_vector: queue vector
 */
static void nse_qvec_ena_irq(struct nse_vsi *vsi, struct nse_q_vector *q_vector)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;

	nse_irq_dynamic_ena(hw, vsi, q_vector);

	nse_flush(hw);
}

/**
 * nse_qp_dis - Disables a queue pair
 * @vsi: VSI of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int nse_qp_dis(struct nse_vsi *vsi, u16 q_idx)
{
	struct nse_txq_meta txq_meta = { };
	struct nse_ring *tx_ring, *rx_ring;
	struct nse_q_vector *q_vector;
	int timeout = 50;
	int err;

	if (q_idx >= vsi->num_rxq || q_idx >= vsi->num_txq)
		return -EINVAL;

	tx_ring = vsi->tx_rings[q_idx];
	rx_ring = vsi->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	while (test_and_set_bit(NSE_CFG_BUSY, vsi->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}
	netif_tx_stop_queue(netdev_get_tx_queue(vsi->netdev, q_idx));

	nse_qvec_dis_irq(vsi, rx_ring, q_vector);

	nse_fill_txq_meta(vsi, tx_ring, &txq_meta);
	err = nse_vsi_stop_tx_ring(vsi, tx_ring, &txq_meta, false);
	if (err)
		return err;
	if (nse_is_xdp_ena_vsi(vsi)) {
		struct nse_ring *xdp_ring = vsi->xdp_rings[q_idx];

		memset(&txq_meta, 0, sizeof(txq_meta));
		nse_fill_txq_meta(vsi, xdp_ring, &txq_meta);
		err = nse_vsi_stop_tx_ring(vsi, xdp_ring, &txq_meta, false);
		if (err)
			return err;
	}
	err = nse_vsi_ctrl_one_rx_ring(vsi, false, q_idx);
	if (err)
		return err;

	nse_qvec_toggle_napi(vsi, q_vector, false);
	nse_qp_clean_rings(vsi, q_idx);
	nse_qp_reset_stats(vsi, q_idx);

	return 0;
}

/**
 * nse_qp_ena - Enables a queue pair
 * @vsi: VSI of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int nse_qp_ena(struct nse_vsi *vsi, u16 q_idx)
{
	struct nse_ring *tx_ring, *rx_ring;
	struct nse_ring *xdp_ring = NULL;
	struct nse_q_vector *q_vector;
	int err;

	if (q_idx >= vsi->num_rxq || q_idx >= vsi->num_txq)
		return -EINVAL;

	tx_ring = vsi->tx_rings[q_idx];
	rx_ring = vsi->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	err = nse_vsi_cfg_txq(tx_ring);
	if (err)
		goto out;

	if (nse_is_xdp_ena_vsi(vsi)) {
		xdp_ring = vsi->xdp_rings[q_idx];

		err = nse_vsi_cfg_txq(xdp_ring);
		if (err)
			goto out;
		nse_set_ring_xdp(xdp_ring);
		xdp_ring->xsk_pool = nse_xsk_umem(xdp_ring);
	}

	err = nse_vsi_cfg_rxq(rx_ring);
	if (err)
		goto out;

	nse_qvec_cfg_msix(vsi, q_vector);

	err = nse_vsi_ctrl_one_rx_ring(vsi, true, q_idx);
	if (err)
		goto out;

	err = nse_vsi_start_tx_ring(vsi, tx_ring);
	if (err)
		goto out;

	if (xdp_ring) {	/* nse_is_xdp_ena_vsi(vsi) == true */
		err = nse_vsi_start_tx_ring(vsi, xdp_ring);
		if (err)
			goto out;
	}

	clear_bit(NSE_CFG_BUSY, vsi->state);
	nse_qvec_toggle_napi(vsi, q_vector, true);
	nse_qvec_ena_irq(vsi, q_vector);

	netif_tx_start_queue(netdev_get_tx_queue(vsi->netdev, q_idx));

out:
	return err;
}

/**
 * nse_xsk_umem_disable - disable a UMEM region
 * @vsi: Current VSI
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int nse_xsk_umem_disable(struct nse_vsi *vsi, u16 qid)
{
	struct xsk_buff_pool *umem = xsk_get_pool_from_qid(vsi->netdev, qid);

	if (!umem)
		return -EINVAL;

	clear_bit(qid, vsi->af_xdp_zc_qps);

	xsk_pool_dma_unmap(umem, NSE_RX_DMA_ATTR);

	return 0;
}

/**
 * nse_xsk_umem_enable - enable a UMEM region
 * @vsi: Current VSI
 * @umem: pointer to a requested UMEM region
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int
nse_xsk_umem_enable(struct nse_vsi *vsi, struct xsk_buff_pool *umem, u16 qid)
{
	int err;

	if (vsi->type != NSE_VSI_PF)
		return -EINVAL;

	if (qid >= vsi->netdev->real_num_rx_queues ||
	    qid >= vsi->netdev->real_num_tx_queues)
		return -EINVAL;

	err = xsk_pool_dma_map(umem, nse_pf_to_dev(vsi->back),
			       NSE_RX_DMA_ATTR);

	if (err)
		return err;

	set_bit(qid, vsi->af_xdp_zc_qps);

	return 0;
}

/**
 * nse_xsk_umem_setup - enable/disable a UMEM region depending on its state
 * @vsi: Current VSI
 * @umem: UMEM to enable/associate to a ring, NULL to disable
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
int nse_xsk_umem_setup(struct nse_vsi *vsi, struct xsk_buff_pool *umem, u16 qid)
{
	bool if_up, umem_present = !!umem;
	int ret = 0, umem_failure = 0;

	if_up = (vsi->netdev->flags & IFF_UP) && nse_is_xdp_ena_vsi(vsi);

	if (if_up) {
		ret = nse_qp_dis(vsi, qid);
		if (ret) {
			netdev_err(vsi->netdev, "nse_qp_dis error = %d\n", ret);
			goto xsk_umem_if_up;
		}
	}

	umem_failure = umem_present ? nse_xsk_umem_enable(vsi, umem, qid) :
				      nse_xsk_umem_disable(vsi, qid);

xsk_umem_if_up:
	if (if_up) {
		ret = nse_qp_ena(vsi, qid);
		if (!ret && umem_present)
			napi_schedule(&vsi->xdp_rings[qid]->q_vector->napi);
		else if (ret)
			netdev_err(vsi->netdev, "nse_qp_ena error = %d\n", ret);
	}

	if (umem_failure) {
		netdev_err(vsi->netdev, "Could not %sable UMEM, error = %d\n",
			   umem_present ? "en" : "dis", umem_failure);
		return umem_failure;
	}

	return ret;
}

/**
 * nse_alloc_rx_bufs_zc - allocate a number of Rx buffers
 * @rx_ring: Rx ring
 * @count: The number of buffers to allocate
 *
 * This function allocates a number of Rx buffers from the fill ring
 * or the internal recycle mechanism and places them on the Rx ring.
 *
 * Returns false if all allocations were successful, true if any fail.
 * NOTE: this function header description doesn't do kdoc style
 *       because of the function pointer creating problems.
 */
bool nse_alloc_rx_bufs_zc(struct nse_ring *rx_ring, int count)
{
	union nse_32b_rx_desc *rx_desc;
	u16 ntu = rx_ring->next_to_use;
	struct nse_rx_buf *rx_buf;
	bool ret = false;
	dma_addr_t dma;

	if (!count)
		return false;

	rx_desc = NSE_RX_DESC(rx_ring, ntu);
	rx_buf = &rx_ring->rx_buf[ntu];

	do {
		rx_buf->xdp = xsk_buff_alloc(rx_ring->xsk_pool);
		if (!rx_buf->xdp) {
			ret = true;
			break;
		}

		dma = xsk_buff_xdp_get_dma(rx_buf->xdp);
		rx_desc->read.pkt_addr = cpu_to_le64(dma);
		rx_desc->wb.status_error0 = 0;

		rx_desc++;
		rx_buf++;
		ntu++;

		if (unlikely(ntu == rx_ring->count)) {
			rx_desc = NSE_RX_DESC(rx_ring, 0);
			rx_buf = rx_ring->rx_buf;
			ntu = 0;
		}
	} while (--count);

	if (rx_ring->next_to_use != ntu)
		nse_release_rx_desc(rx_ring, ntu);

	return ret;
}

/**
 * nse_bump_ntc - Bump the next_to_clean counter of an Rx ring
 * @rx_ring: Rx ring
 */
static void nse_bump_ntc(struct nse_ring *rx_ring)
{
	int ntc = rx_ring->next_to_clean + 1;

	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;
	prefetch(NSE_RX_DESC(rx_ring, ntc));
}

/**
 * nse_construct_skb_zc - Create an sk_buff from zero-copy buffer
 * @rx_ring: Rx ring
 * @rx_buf: zero-copy Rx buffer
 * @xdp: xdp buffer
 *
 * This function allocates a new skb from a zero-copy Rx buffer.
 *
 * Returns the skb on success, NULL on failure.
 */
static struct sk_buff *
nse_construct_skb_zc(struct nse_ring *rx_ring, struct nse_rx_buf *rx_buf,
		     struct xdp_buff *xdp)
{
	unsigned int metasize = xdp->data - xdp->data_meta;
	unsigned int datasize = xdp->data_end - xdp->data;
	unsigned int datasize_hard = xdp->data_end -
				     xdp->data_hard_start;
	struct sk_buff *skb;

	skb = napi_alloc_skb(&rx_ring->q_vector->napi, datasize_hard);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	memcpy(__skb_put(skb, datasize), xdp->data, datasize);

	if (metasize)
		skb_metadata_set(skb, metasize);

	xsk_buff_free(rx_buf->xdp);
	rx_buf->xdp = NULL;

	return skb;
}

/**
 * nse_run_xdp_zc - Executes an XDP program in zero-copy path
 * @rx_ring: Rx ring
 * @xdp: xdp_buff used as input to the XDP program
 *
 * Returns any of NSE_XDP_{PASS, CONSUMED, TX, REDIR}
 */
static int
nse_run_xdp_zc(struct nse_ring *rx_ring, struct xdp_buff *xdp)
{
	int err, result = NSE_XDP_PASS;
	struct bpf_prog *xdp_prog;
	struct nse_ring *xdp_ring;
	u32 act;

	rcu_read_lock();
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);
	if (!xdp_prog) {
		rcu_read_unlock();
		return NSE_XDP_PASS;
	}

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		xdp_ring = rx_ring->vsi->xdp_rings[rx_ring->q_index];
		result = nse_xmit_xdp_buff(xdp, xdp_ring);
		break;
	case XDP_REDIRECT:
		err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		result = !err ? NSE_XDP_REDIR : NSE_XDP_CONSUMED;
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, act);
		fallthrough; /* not supported action */
	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		fallthrough; /* handle aborts by dropping frame */
	case XDP_DROP:
		result = NSE_XDP_CONSUMED;
		break;
	}

	rcu_read_unlock();
	return result;
}

/**
 * nse_clean_rx_irq_zc - consumes packets from the hardware ring
 * @rx_ring: AF_XDP Rx ring
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int nse_clean_rx_irq_zc(struct nse_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	u16 cleaned_count = NSE_DESC_UNUSED(rx_ring);
	unsigned int xdp_xmit = 0;
	bool failure = false;
	u8 xdp_has_vlan_flags = 0;

	while (likely(total_rx_packets < (unsigned int)budget)) {
		union nse_32b_rx_desc *rx_desc;
		unsigned int size, xdp_res = 0;
		struct nse_rx_buf *rx_buf;
		struct sk_buff *skb;
		u16 stat_err_bits;
		u16 vlan_tag = 0;
		u8 rx_ptype;

		if (cleaned_count >= NSE_RX_BUF_WRITE) {
			failure |= nse_alloc_rx_bufs_zc(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = NSE_RX_DESC(rx_ring, rx_ring->next_to_clean);

		stat_err_bits = BIT(NSE_RXD_STATUS0_DD_S);
		if (!nse_test_staterr(rx_desc->wb.status_error0, stat_err_bits))
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we have
		 * verified the descriptor has been written back.
		 */
		dma_rmb();

		size = le16_to_cpu(rx_desc->wb.pktlen_sph_reentry) &
				   NSE_RXD_PKT_LEN_M;
		if (!size)
			break;

		rx_buf = &rx_ring->rx_buf[rx_ring->next_to_clean];
		if (!rx_buf->xdp)
			break;

		rx_buf->xdp->data_end = rx_buf->xdp->data + size;
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp, rx_ring->xsk_pool);

		xdp_res = nse_run_xdp_zc(rx_ring, rx_buf->xdp);
		if (xdp_res) {
			if (xdp_res & (NSE_XDP_TX | NSE_XDP_REDIR))
				xdp_xmit |= xdp_res;
			else
				xsk_buff_free(rx_buf->xdp);
			rx_buf->xdp = NULL;
			total_rx_bytes += size;
			total_rx_packets++;
			cleaned_count++;

			nse_bump_ntc(rx_ring);
			continue;
		}

		/* XDP_PASS path */
		skb = nse_construct_skb_zc(rx_ring, rx_buf, rx_buf->xdp);
		if (!skb) {
			rx_ring->rx_stats.alloc_buf_failed++;
			break;
		}

		cleaned_count++;
		nse_bump_ntc(rx_ring);

		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		total_rx_bytes += skb->len;
		total_rx_packets++;

		vlan_tag = nse_get_vlan_tag_from_rx_desc(rx_desc, &xdp_has_vlan_flags);

		rx_ptype = rx_desc->wb.ptype;
		if (nse_process_skb_fields(rx_ring, rx_desc, skb, rx_ptype)) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		nse_receive_skb(rx_ring, skb, vlan_tag, xdp_has_vlan_flags);
	}

	nse_finalize_xdp_rx(rx_ring, xdp_xmit);
	nse_update_rx_ring_stats(rx_ring, total_rx_packets, total_rx_bytes);

	if (xsk_uses_need_wakeup(rx_ring->xsk_pool)) {
		if (failure || rx_ring->next_to_clean == rx_ring->next_to_use)
			xsk_set_rx_need_wakeup(rx_ring->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_pool);

		return (int)total_rx_packets;
	}

	return failure ? budget : (int)total_rx_packets;
}

/**
 * nse_xmit_zc - Completes AF_XDP entries, and cleans XDP entries
 * @xdp_ring: XDP Tx ring
 * @budget: max number of frames to xmit
 *
 * Returns true if cleanup/transmission is done.
 */
static bool nse_xmit_zc(struct nse_ring *xdp_ring, int budget)
{
	unsigned int sent_frames = 0, total_bytes = 0;
	struct nse_tx_desc *tx_desc = NULL;
	u16 ntu = xdp_ring->next_to_use;
	struct xdp_desc desc;
	dma_addr_t dma;

	while (likely(budget-- > 0)) {
		struct nse_tx_buf *tx_buf;

		tx_buf = &xdp_ring->tx_buf[ntu];

		if (!xsk_tx_peek_desc(xdp_ring->xsk_pool, &desc))
			break;

		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma,
						 desc.len);
		tx_buf->bytecount = desc.len;

		tx_desc = NSE_TX_DESC(xdp_ring, ntu);
		tx_desc->buf_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz =
			nse_build_ctob(xdp_ring, NSE_TXD_EOP_M, (u64)desc.len, desc.len, true);

		xdp_ring->next_rs_idx = ntu;
		ntu++;
		if (ntu == xdp_ring->count)
			ntu = 0;
		sent_frames++;
		total_bytes += tx_buf->bytecount;
	}

	if (tx_desc) {
		xdp_ring->next_to_use = ntu;

		/* Set RS bit for the last frame and bump tail ptr */
		tx_desc->cmd_type_offset_bsz |= cpu_to_le64(NSE_TXD_RS_M);

#if defined(NSE_DEBUG_EXT)
		xdp_ring->tx_stats.tx_rs++;
		xdp_ring->tx_stats.tx_no_rs += (sent_frames - 1);
#endif

		nse_xdp_ring_update_tail(xdp_ring);
		xsk_tx_release(xdp_ring->xsk_pool);
		nse_update_tx_ring_stats(xdp_ring, sent_frames, total_bytes);
	}

	return budget > 0;
}

/**
 * nse_clean_xdp_tx_buf - Free and unmap XDP Tx buffer
 * @xdp_ring: XDP Tx ring
 * @tx_buf: Tx buffer to clean
 */
static void
nse_clean_xdp_tx_buf(struct nse_ring *xdp_ring, struct nse_tx_buf *tx_buf)
{
	xdp_return_frame((struct xdp_frame *)tx_buf->raw_buf);
	xdp_ring->xdp_tx_active--;
	dma_unmap_single(xdp_ring->dev, dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * nse_clean_tx_irq_zc - Completes AF_XDP entries, and cleans XDP entries
 * @xdp_ring: XDP Tx ring
 *
 * Returns true if cleanup/transmission is done.
 */
bool nse_clean_tx_irq_zc(struct nse_ring *xdp_ring)
{
	u16 next_rs_idx = xdp_ring->next_rs_idx;
	u16 ntc = xdp_ring->next_to_clean;
	u16 frames_ready = 0, send_budget;
	struct nse_tx_desc *next_rs_desc;
	struct nse_tx_buf *tx_buf;
	u32 xsk_frames = 0;
	u16 i;

	next_rs_desc = NSE_TX_DESC(xdp_ring, next_rs_idx);
	if (next_rs_desc->cmd_type_offset_bsz &
	    cpu_to_le64(NSE_TXD_DD_M)) {
		if (next_rs_idx >= ntc)
			frames_ready = next_rs_idx - ntc;
		else
			frames_ready = next_rs_idx + xdp_ring->count - ntc;
	}

	if (!frames_ready)
		goto out_xmit;

	if (likely(!xdp_ring->xdp_tx_active)) {
		xsk_frames = frames_ready;
		goto skip;
	}

#if defined(NSE_DEBUG_EXT)
	xdp_ring->tx_stats.clean_tx_irq_zc_cnt++;
#endif

	for (i = 0; i < frames_ready; i++) {
		tx_buf = &xdp_ring->tx_buf[ntc];

		if (tx_buf->raw_buf) {
			nse_clean_xdp_tx_buf(xdp_ring, tx_buf);
			tx_buf->raw_buf = NULL;
		} else {
			xsk_frames++;
		}

		++ntc;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}

skip:
	xdp_ring->next_to_clean += frames_ready;
	if (unlikely(xdp_ring->next_to_clean >= xdp_ring->count))
		xdp_ring->next_to_clean -= xdp_ring->count;

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);

out_xmit:
	if (xsk_uses_need_wakeup(xdp_ring->xsk_pool))
		xsk_set_tx_need_wakeup(xdp_ring->xsk_pool);
	send_budget = NSE_DESC_UNUSED(xdp_ring);
	send_budget = min_t(u16, send_budget, xdp_ring->count >> 2);
	return nse_xmit_zc(xdp_ring, send_budget);
}

int nse_clean_tx_irq_zc_on_hw_head(struct nse_ring *xdp_ring, u16 head,
				   struct nse_txcq_ring *cq_ring)
{
	u16 ntc = xdp_ring->next_to_clean;
	u16 frames_ready = 0, send_budget;
	struct nse_tx_buf *tx_buf;
	u32 xsk_frames = 0;
	u16 i;
	u64 total_bytes = 0;

	if (ntc != head) {
		if (head > ntc)
			frames_ready = head - ntc;
		else
			frames_ready = head + xdp_ring->count - ntc;
	}

	if (!frames_ready)
		goto out_xmit;

	if (likely(!xdp_ring->xdp_tx_active)) {
		xsk_frames = frames_ready;
		goto skip;
	}

	for (i = 0; i < frames_ready; i++) {
		tx_buf = &xdp_ring->tx_buf[ntc];

		total_bytes += tx_buf->bytecount;

		if (tx_buf->raw_buf) {
			nse_clean_xdp_tx_buf(xdp_ring, tx_buf);
			tx_buf->raw_buf = NULL;
		} else {
			xsk_frames++;
		}

		++ntc;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}

skip:
	xdp_ring->next_to_clean += frames_ready;
	if (unlikely(xdp_ring->next_to_clean >= xdp_ring->count))
		xdp_ring->next_to_clean -= xdp_ring->count;

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);

out_xmit:
	if (xsk_uses_need_wakeup(xdp_ring->xsk_pool))
		xsk_set_tx_need_wakeup(xdp_ring->xsk_pool);
	send_budget = NSE_DESC_UNUSED(xdp_ring);
	send_budget = min_t(u16, send_budget, xdp_ring->count >> 2);
	(void)nse_xmit_zc(xdp_ring, send_budget);

	if (cq_ring)
		nse_update_txcq_ring_stats(cq_ring, frames_ready, total_bytes, frames_ready);

	return frames_ready;
}

/**
 * nse_xsk_wakeup - Implements ndo_xsk_wakeup
 * @netdev: net_device
 * @queue_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative on error, zero otherwise.
 */
int
nse_xsk_wakeup(struct net_device *netdev, u32 queue_id,
	       u32 __always_unused flags)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_q_vector *q_vector;
	struct nse_vsi *vsi = np->vsi;
	struct nse_ring *ring;

	if (test_bit(NSE_VSI_DOWN, vsi->state))
		return -ENETDOWN;

	if (!nse_is_xdp_ena_vsi(vsi))
		return -ENXIO;

	if (queue_id >= vsi->num_txq)
		return -ENXIO;

	if (!vsi->xdp_rings[queue_id]->xsk_pool)
		return -ENXIO;

	ring = vsi->xdp_rings[queue_id];

	/* The idea here is that if NAPI is running, mark a miss, so
	 * it will run again. If not, trigger an interrupt and
	 * schedule the NAPI from interrupt context. If NAPI would be
	 * scheduled here, the interrupt affinity would not be
	 * honored.
	 */
	q_vector = ring->q_vector;
	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		nse_trigger_sw_intr(&vsi->back->hw, q_vector);

	return 0;
}

/**
 * nse_xsk_any_rx_ring_ena - Checks if Rx rings have AF_XDP UMEM attached
 * @vsi: VSI to be checked
 *
 * Returns true if any of the Rx rings has an AF_XDP UMEM attached
 */
bool nse_xsk_any_rx_ring_ena(struct nse_vsi *vsi)
{
	int i;

	nse_for_each_rxq(vsi, i) {
		if (xsk_get_pool_from_qid(vsi->netdev, i))
			return true;
	}

	return false;
}

/**
 * nse_xsk_clean_rx_ring - clean UMEM queues connected to a given Rx ring
 * @rx_ring: ring to be cleaned
 */
void nse_xsk_clean_rx_ring(struct nse_ring *rx_ring)
{
	u16 i;

	for (i = 0; i < rx_ring->count; i++) {
		struct nse_rx_buf *rx_buf = &rx_ring->rx_buf[i];

		if (!rx_buf->addr)
			continue;

		rx_buf->addr = NULL;
	}
}

/**
 * nse_xsk_clean_xdp_ring - Clean the XDP Tx ring and its UMEM queues
 * @xdp_ring: XDP_Tx ring
 */
void nse_xsk_clean_xdp_ring(struct nse_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean, ntu = xdp_ring->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct nse_tx_buf *tx_buf = &xdp_ring->tx_buf[ntc];

		if (tx_buf->raw_buf)
			nse_clean_xdp_tx_buf(xdp_ring, tx_buf);
		else
			xsk_frames++;

		tx_buf->raw_buf = NULL;

		ntc++;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}

