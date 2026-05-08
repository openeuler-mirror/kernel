// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_tx.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/if_macvlan.h>
#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_tx.h"
#include "sxe2_hw.h"
#include "sxe2_vsi.h"
#include "sxe2_log.h"
#include "sxe2_cmd.h"
#include "sxe2_dcb.h"
#include "sxe2_queue.h"
#include "sxe2_netdev.h"
#include "sxe2_common.h"
#include "sxe2_txsched.h"
#include "sxe2_dev_ctrl.h"
#include "sxe2_skb_dump.h"
#include "sxe2_fnav.h"
#include "sxe2_xsk.h"

#define SXE2_MIN_TX_LEN 17

#define SXE2_DFLT_IRQ_WORK    256
#define SXE2_CACHE_LINE_BYTES 64
#define SXE2_DESCS_PER_CACHE_LINE (SXE2_CACHE_LINE_BYTES / sizeof(union sxe2_tx_data_desc))
#define SXE2_DESCS_FOR_CTXT_DESC    1
#define SXE2_DESCS_FOR_SKB_DATA_PTR 1

#define SXE2_MAX_DATA_DESC_PER_SKB 15
#define SXE2_TSO_SEG_DESC_USE_FOR_FRAGMENT (SXE2_MAX_DATA_DESC_PER_SKB - 2)

#define SXE2_TX_DESC_NEEDED (MAX_SKB_FRAGS + SXE2_DESCS_FOR_CTXT_DESC + \
			     SXE2_DESCS_PER_CACHE_LINE + SXE2_DESCS_FOR_SKB_DATA_PTR)
#define SXE2_TX_WAKE_THRESHOLD (SXE2_TX_DESC_NEEDED * 2)

#define SXE2_MAX_DATA_PER_TXD ((1u << 14) - 1)

#ifdef SXE2_TX_4K_AILGN
#define SXE2_MAX_READ_REQ_SIZE 4096
#define SXE2_MAX_DATA_PER_TXD_ALIGNED (~(SXE2_MAX_READ_REQ_SIZE - 1) & SXE2_MAX_DATA_PER_TXD)

#define SXE2_ESTIMATE_DESC_COUNT_FOR_SKB_FRAG(frag_size) ((((frag_size) * 85) >> 20) + 1)
#else

#define SXE2_MAX_DATA_PER_TXD_ALIGNED SXE2_MAX_DATA_PER_TXD

#define SXE2_ESTIMATE_DESC_COUNT_FOR_SKB_FRAG(frag_size) (((frag_size) >> 14) + 1)

#endif

#define SXE2_FNAV_DESC_CLEAN_DELAY 10
#define SXE2_FNAV_DESC_NEED_USE	   2

static struct netdev_queue *sxe2_netdev_txq_get(const struct sxe2_queue *txq)
{
	return netdev_get_tx_queue(txq->netdev, txq->idx_in_vsi);
}

STATIC void sxe2_tx_buffer_unmap(struct sxe2_queue *txq,
				 struct sxe2_tx_buf *tx_buf)
{
	if (tx_buf->skb) {
		if (sxe2_queue_is_xdp(txq)) {
			page_frag_free(tx_buf->raw_buf);
		} else {
			dev_kfree_skb_any(tx_buf->skb);

			if (dma_unmap_len(tx_buf, len)) {
				dma_unmap_single(txq->dev,
						 dma_unmap_addr(tx_buf, dma),
						 dma_unmap_len(tx_buf, len),
						 DMA_TO_DEVICE);
			}
		}
	} else if (dma_unmap_len(tx_buf, len)) {
		dma_unmap_page(txq->dev, dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	}

	tx_buf->next_to_watch = NULL;
	tx_buf->skb	      = NULL;
	dma_unmap_len_set(tx_buf, len, 0);
}

void sxe2_tx_ring_clean(struct sxe2_queue *txq)
{
	u16 i;
	u32 size;

#ifdef HAVE_AF_XDP_ZC_SUPPORT
	if (sxe2_queue_is_xdp(txq) && txq->xsk_pool) {
		sxe2_xsk_clean_xdp_ring(txq);
		goto tx_skip_free;
	}
#endif

	if (!txq->tx_buf)
		return;

	for (i = 0; i < txq->depth; i++)
		sxe2_tx_buffer_unmap(txq, &txq->tx_buf[i]);

#ifdef HAVE_AF_XDP_ZC_SUPPORT
tx_skip_free:
#endif
	(void)memset(txq->tx_buf, 0, sizeof(*txq->tx_buf) * txq->depth);

	size = ALIGN(txq->depth * sizeof(union sxe2_tx_data_desc), PAGE_SIZE);
	(void)memset(txq->desc.base_addr, 0, size);

	txq->next_to_use   = 0;
	txq->next_to_clean = 0;

	if (txq->netdev)
		netdev_tx_reset_queue(sxe2_netdev_txq_get(txq));
}

void sxe2_tx_ring_free(struct sxe2_queue *txq)
{
	u32 size;

	if (txq->tx_buf) {
		devm_kfree(txq->dev, txq->tx_buf);
		txq->tx_buf = NULL;
	}

	if (txq->desc.base_addr) {
		size = ALIGN(txq->depth * sizeof(union sxe2_tx_data_desc),
			     PAGE_SIZE);
		dmam_free_coherent(txq->dev, size, txq->desc.base_addr,
				   txq->desc.dma);
		txq->desc.base_addr = NULL;
	}
}

static void sxe2_tx_rings_free(struct sxe2_vsi *vsi)
{
	u32 i;

	sxe2_for_each_vsi_txq(vsi, i)
		sxe2_tx_ring_free(vsi->txqs.q[i]);
}

static void sxe2_tx_ring_res_free(struct sxe2_queue *txq)
{
	sxe2_tx_ring_clean(txq);
	sxe2_tx_ring_free(txq);
}

void sxe2_tx_rings_res_free(struct sxe2_vsi *vsi)
{
	u32 i;

	sxe2_for_each_vsi_txq(vsi, i)
		sxe2_tx_ring_res_free(vsi->txqs.q[i]);

	if (sxe2_xdp_is_enable(vsi)) {
		for (i = 0; i < vsi->num_xdp_txq; i++)
			sxe2_tx_ring_res_free(vsi->xdp_rings.q[i]);
	}
}

s32 sxe2_tx_ring_alloc(struct sxe2_queue *txq, struct sxe2_vsi *vsi)
{
	u32 size;
	struct device *dev		 = txq->dev;
	struct sxe2_adapter *adapter	 = txq->vsi->adapter;
	struct sxe2_desc_ring *desc_ring = &txq->desc;

	txq->tx_buf = devm_kcalloc(dev, sizeof(struct sxe2_tx_buf), txq->depth,
				   GFP_KERNEL);
	if (!txq->tx_buf) {
		LOG_ERROR_BDF("unable to allocate memory for tx buf ring\n");
		goto l_end;
	}

	size = ALIGN(txq->depth * sizeof(union sxe2_tx_data_desc), PAGE_SIZE);
	desc_ring->base_addr =
		dmam_alloc_coherent(dev, size, &desc_ring->dma, GFP_KERNEL);
	if (!desc_ring->base_addr) {
		LOG_DEV_ERR("unable to allocate memory for the Tx descriptor ring, size=%u\n",
			    size);
		goto l_alloc_failed;
	}

	if (vsi->netdev)
		txq->netdev = vsi->netdev;
	txq->next_to_use   = 0;
	txq->next_to_clean = 0;
	txq->tx_tstamps = &adapter->ptp_ctxt.tx;
	return 0;

l_alloc_failed:
	devm_kfree(dev, txq->tx_buf);
	txq->tx_buf = NULL;
l_end:
	return -ENOMEM;
}

static void sxe2_txq_tc_setup(struct sxe2_vsi *vsi)
{
	u8 n;
	u32 i;
	u16 qoffset, qcount;
	struct sxe2_queue *txq;

	if (!test_bit(SXE2_FLAG_DCB_ENABLE, vsi->adapter->flags)) {
		sxe2_for_each_vsi_txq(vsi, i) {
			txq	    = vsi->txqs.q[i];
			txq->dcb_tc = 0;
		}
	}

	sxe2_for_each_tc(n) {
		if (!(vsi->tc.tc_map & BIT(n)))
			break;

		qoffset = vsi->tc.info[n].txq_offset;
		qcount	= vsi->tc.info[n].txq_cnt;
		for (i = qoffset; i < (qoffset + qcount); i++)
			vsi->txqs.q[i]->dcb_tc = n;
	}
}

s32 sxe2_tx_rings_alloc(struct sxe2_vsi *vsi)
{
	s32 ret;
	u16 i;
	struct sxe2_adapter *adapter = vsi->adapter;

	sxe2_for_each_vsi_txq(vsi, i) {
		ret = sxe2_tx_ring_alloc(vsi->txqs.q[i], vsi);
		if (ret) {
			LOG_ERROR_BDF("allocation for Tx queue %d failed, ret=%d\n", i, ret);
			goto l_end;
		}
	}

	sxe2_txq_tc_setup(vsi);

	return 0;
l_end:
	while (i--)
		sxe2_tx_ring_free(vsi->txqs.q[i]);

	return ret;
}

STATIC void sxe2_txq_xps_configure(struct sxe2_queue *txq)
{
	if (!txq->irq_data || !txq->netdev)
		return;
	if (test_and_set_bit(SXE2_TX_XPS_INIT_DONE, txq->xps_state))
		return;

	(void)netif_set_xps_queue(txq->netdev, &txq->irq_data->affinity_mask,
				  txq->idx_in_vsi);
}

s32 sxe2_txq_ctxt_fill(struct sxe2_vsi *vsi, struct sxe2_queue *txq,
		       struct sxe2_txq_ctxt *ctxt)
{
	struct sxe2_adapter *adapter = vsi->adapter;

	txq->desc.tail = sxe2_reg_addr_get(&adapter->hw, SXE2_TXQ_LEGACY_DBLL(txq->idx_in_pf));
	if (IS_ERR(txq->desc.tail)) {
		LOG_ERROR_BDF("vsi:%u queue:%u tail addr: %ld error.\n",
			      vsi->idx_in_dev, txq->idx_in_vsi,
			      PTR_ERR(txq->desc.tail));
		return -EFAULT;
	}

	ctxt->q_idx_in_nic = adapter->q_ctxt.txq_base_idx_in_dev + txq->idx_in_pf;

	ctxt->base_addr = txq->desc.dma;

	ctxt->port_idx = adapter->port_idx;
	ctxt->pf_idx   = adapter->pf_idx;
	ctxt->cgd_idx  = txq->dcb_tc + (SXE2_TC_MAX_CNT * adapter->port_idx);

	if (txq->vsi->type == SXE2_VSI_T_VF) {
		ctxt->vmvf_idx = adapter->vf_ctxt.vfid_base + txq->vsi->vf_node->vf_idx;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_VF;
	} else if (txq->vsi->type == SXE2_VSI_T_PF) {
		ctxt->vmvf_idx	= 0;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_PF;
	} else if (txq->vsi->type == SXE2_VSI_T_LB) {
		ctxt->vmvf_idx	= 0;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_PF;
	} else if (txq->vsi->type == SXE2_VSI_T_MACVLAN) {
		ctxt->vmvf_idx	= 0;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_VM;
	} else if (txq->vsi->type == SXE2_VSI_T_ESW) {
		ctxt->vmvf_idx	= vsi->idx_in_dev;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_VM;
	} else if (txq->vsi->type == SXE2_VSI_T_CTRL) {
		ctxt->vmvf_idx	= 0;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_PF;
	} else if (txq->vsi->type == SXE2_VSI_T_DPDK_PF) {
		ctxt->vmvf_idx	= 0;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_PF;
	} else if (txq->vsi->type == SXE2_VSI_T_DPDK_ESW) {
		ctxt->vmvf_idx	= 0;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_PF;
	} else if (txq->vsi->type == SXE2_VSI_T_DPDK_VF) {
		ctxt->vmvf_idx =
			adapter->vf_ctxt.vfid_base + txq->vsi->vf_node->vf_idx;
		ctxt->vmvf_type = SXE2_TXQ_VMVF_TYPE_VF;
	} else {
		LOG_INFO_BDF("vsi is neither pf nor vf.\n");
	}
	ctxt->tsyn_enable = 0;

	ctxt->alt_vlan = 0;
	ctxt->adv_sso = 0;
	ctxt->wb_mode = 0;
	ctxt->itr_notify_mode = 0;
	ctxt->legacy_enable = SXE2_TXQ_LEGACY;

	if (vsi->type == SXE2_VSI_T_CTRL && !vsi->vf_node)
		ctxt->src_vsi = adapter->vsi_ctxt.main_vsi->idx_in_dev;
	else if (vsi->type == SXE2_VSI_T_CTRL && vsi->vf_node && vsi->vf_node->vsi)
		ctxt->src_vsi = vsi->vf_node->vsi->idx_in_dev;
	else
		ctxt->src_vsi = vsi->idx_in_dev;

	ctxt->q_idx_in_func = txq->idx_in_pf;
	ctxt->qlen   = txq->depth;
	ctxt->ptp_en = 1;

	return 0;
}

s32 sxe2_fwc_txq_ctxt_cfg(struct sxe2_vsi *vsi,
			  struct sxe2_fwc_cfg_txq_req *req)
{
	s32 ret;
	struct sxe2_cmd_params cmd	  = { 0 };
	struct sxe2_fwc_cfg_txq_resp resp = { 0 };
	struct sxe2_adapter *adapter	  = vsi->adapter;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQ_CFG_AND_ENABLE, req,
				  sizeof(*req), &resp, sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("txq cfg failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC bool sxe2_hw_txq_enable_check(struct sxe2_vsi *vsi,
				     struct sxe2_queue *txq)
{
	s32 ret;
	struct sxe2_cmd_params cmd	 = {};
	struct sxe2_fwc_st_txq_req req	 = {};
	struct sxe2_fwc_st_txq_resp resp = {};
	struct sxe2_adapter *adapter	 = vsi->adapter;

	req.txq_idx_in_nic = adapter->q_ctxt.txq_base_idx_in_dev + txq->idx_in_pf;
	req.txq_idx_in_func = txq->idx_in_pf;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQ_STATE, &req, sizeof(req),
				  &resp, sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("txq enable check failed, ret=%d\n", ret);
		return false;
	}

	LOG_INFO_BDF("hw tx txq[%u] enable %d\n", txq->idx_in_pf, resp.state);

	return resp.state;
}

s32 sxe2_hw_txqs_disable_check(struct sxe2_vsi *vsi)
{
	u32 i;
	s32 ret			     = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_queue **txq	     = vsi->txqs.q;

	sxe2_for_each_vsi_txq(vsi, i) {
		if (sxe2_hw_txq_enable_check(vsi, txq[i])) {
			LOG_ERROR_BDF("txq enable check: txq_in_vsi %d txq_in_pf %d is enable.\n",
				      txq[i]->idx_in_vsi, txq[i]->idx_in_pf);
			ret = -EBUSY;
			break;
		}
	}

	return ret;
}

s32 sxe2_hw_txq_configure(struct sxe2_vsi *vsi, struct sxe2_queue *txq)
{
	s32 ret;
	struct sxe2_fwc_cfg_txq_req req = {};
	struct sxe2_adapter *adapter	= vsi->adapter;

	ret = sxe2_txq_ctxt_fill(vsi, txq, &req.ctxt);
	if (ret)
		return ret;

	if (sxe2_txsched_support_chk(adapter)) {
		ret = sxe2_txsched_txq_node_add(adapter, vsi, txq,
						SXE2_TXSCHED_NODE_OWNER_LAN, &req);
		if (ret) {
			LOG_ERROR("hw tx txq[%u] start failed\n",
				  txq->idx_in_pf);
			return ret;
		}
	} else {
		ret = sxe2_fwc_txq_ctxt_cfg(vsi, &req);
		if (ret) {
			LOG_ERROR("hw tx txq[%u] start failed\n",
				  txq->idx_in_pf);
			return ret;
		}
	}

	LOG_INFO_BDF("hw tx txq[%u] start success\n", txq->idx_in_pf);

	return ret;
}

s32 sxe2_tx_hw_cfg(struct sxe2_vsi *vsi)
{
	u32 i = 0;
	u32 j;
	s32 ret			= 0;
	struct sxe2_queue **txq = vsi->txqs.q;

	sxe2_for_each_vsi_txq(vsi, i) {
		sxe2_txq_xps_configure(txq[i]);
		ret = sxe2_hw_txq_configure(vsi, txq[i]);
		if (ret)
			break;
	}

	if (ret) {
		for (j = 0; j < i; j++)
			(void)sxe2_txq_stop(vsi, txq[j]);
	}

	return ret;
}

s32 sxe2_xdp_tx_hw_cfg(struct sxe2_vsi *vsi)
{
	u32 i = 0;
	u32 j;
	s32 ret	= 0;
	struct sxe2_queue **txq = vsi->xdp_rings.q;

	for (i = 0; i < vsi->num_xdp_txq; i++) {
		ret = sxe2_hw_txq_configure(vsi, txq[i]);
		if (ret)
			goto end;
	}

#ifdef HAVE_AF_XDP_ZC_SUPPORT
	for (i = 0; i < vsi->num_xdp_txq; i++)
		vsi->xdp_rings.q[i]->xsk_pool = sxe2_xsk_pool(vsi->xdp_rings.q[i]);
#endif

end:
	if (ret) {
		for (j = 0; j < i; j++)
			(void)sxe2_txq_stop(vsi, txq[j]);
	}

	return ret;
}

s32 sxe2_fwc_txq_stop(struct sxe2_vsi *vsi, struct sxe2_queue *txq)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_disable_txq_req req;
	struct sxe2_adapter *adapter = vsi->adapter;

	req.txq_idx_in_nic = adapter->q_ctxt.txq_base_idx_in_dev + txq->idx_in_pf;
	req.txq_idx_in_func = txq->idx_in_pf;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXQ_DISABLE, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("txq disable failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_txq_stop(struct sxe2_vsi *vsi, struct sxe2_queue *txq)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (sxe2_txsched_support_chk(adapter)) {
		ret = sxe2_txsched_txq_node_del(adapter, txq);
		if (ret) {
			LOG_ERROR_BDF("vsi %d type %d hw tx txq[%u] stop failed\n",
				      vsi->id_in_pf, vsi->type, txq->idx_in_pf);
			return ret;
		}
	} else {
		ret = sxe2_fwc_txq_stop(vsi, txq);
		if (ret) {
			LOG_ERROR_BDF("vsi %d type %d hw tx txq[%u] stop failed\n",
				      vsi->id_in_pf, vsi->type, txq->idx_in_pf);
			return ret;
		}
	}

	LOG_INFO_BDF("hw tx txq[%u] stop success\n", txq->idx_in_pf);
	return ret;
}

s32 sxe2_txqs_stop(struct sxe2_vsi *vsi)
{
	u32 i;
	s32 ret = 0;
	s32 rc = 0;
	struct sxe2_queue **txq = vsi->txqs.q;

	sxe2_for_each_vsi_txq(vsi, i) {
		rc = sxe2_txq_stop(vsi, txq[i]);
		if (rc)
			ret = rc;
	}

	return ret;
}

s32 sxe2_xdp_txqs_stop(struct sxe2_vsi *vsi)
{
	u32 i;
	s32 ret = 0;
	s32 rc = 0;
	struct sxe2_queue **txq = vsi->xdp_rings.q;

	for (i = 0; i < vsi->num_xdp_txq; i++) {
		rc = sxe2_txq_stop(vsi, txq[i]);
		if (rc)
			ret = rc;
	}

	return ret;
}

s32 sxe2_tx_cfg(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	ret = sxe2_tx_rings_alloc(vsi);
	if (ret) {
		LOG_ERROR_BDF("tx resource alloc failed, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_tx_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("tx hw configure failed, ret=%d\n", ret);
		goto l_free;
	}

	return 0;

l_free:
	sxe2_tx_rings_free(vsi);

l_end:
	return ret;
}

s32 sxe2_xdp_tx_cfg(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	s64 i;

	for (i = 0; i < vsi->num_xdp_txq; i++) {
		if (!vsi->xdp_rings.q[i]->tx_buf) {
			if (sxe2_tx_ring_alloc(vsi->xdp_rings.q[i], vsi))
				goto free_xdp_rings;
		}
	}

	ret = sxe2_xdp_tx_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("tx hw configure failed, ret=%d\n", ret);
		goto l_end;
	}

	return 0;

free_xdp_rings:
	ret = -ENOMEM;
	for (; i >= 0; i--)
		if (vsi->xdp_rings.q[i])
			sxe2_tx_ring_free(vsi->xdp_rings.q[i]);

l_end:
	return ret;
}

static inline u16 sxe2_tx_desc_unused_count(struct sxe2_queue *txq)
{
	u16 ntc = txq->next_to_clean;
	u16 ntu = txq->next_to_use;
	u16 unused_tx_desc_cnt;

	unused_tx_desc_cnt = (u16)(((ntc > ntu) ? 0 : txq->depth) + ntc - ntu - 1);
	return unused_tx_desc_cnt;
}

STATIC s32 sxe2_maybe_stop_tx(struct sxe2_queue *txq, u16 desc_cnt)
{
	s32 ret = 0;

	netif_stop_subqueue(txq->netdev, txq->idx_in_vsi);

	/* in order to force CPU ordering */
	smp_mb();

	if (likely(sxe2_tx_desc_unused_count(txq) < desc_cnt)) {
		ret = -EBUSY;
		goto l_end;
	}

	netif_start_subqueue(txq->netdev, txq->idx_in_vsi);

	++txq->stats->tx_stats.tx_restart;

l_end:
	return ret;
}

static u32 sxe2_tx_desc_count(struct sk_buff *skb)
{
	u32 count = 0, size = skb_headlen(skb);
	u32 nr_frags	       = skb_shinfo(skb)->nr_frags;
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];

	for (;;) {
		count += SXE2_ESTIMATE_DESC_COUNT_FOR_SKB_FRAG(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

static s32 sxe2_tso(struct sxe2_queue *txq, struct sxe2_tx_buf *first_buf,
		    struct sxe2_tx_offload_info *offload)
{
	s32 ret;
	u32 paylen;
	union sxe2_ip_hdr ip;
	union sxe2_l4_hdr l4;
	u8 l4_start, header_len;
	u64 cd_mss, cd_tso_len;
	struct sk_buff *skb	     = first_buf->skb;
	struct sxe2_adapter *adapter = offload->adapter;

	if (skb->ip_summed != CHECKSUM_PARTIAL || !skb_is_gso(skb)) {
		ret = 0;
		goto l_end;
	}
#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
		LOG_DEBUG_BDF("tx tso start\n");

#endif

	ret = skb_cow_head(skb, 0);
	if (ret < 0) {
		LOG_ERROR_BDF("skb cow head failed, ret=%d\n", ret);
		goto l_end;
	}

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);
	if (ip.v4->version == 4) {
		ip.v4->tot_len = 0;
		ip.v4->check   = 0;
	} else {
		ip.v6->payload_len = 0;
	}

	if (skb_shinfo(skb)->gso_type &
	    (SKB_GSO_GRE | SKB_GSO_GRE_CSUM | SKB_GSO_IPXIP4 | SKB_GSO_IPXIP6 |
	     SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM)) {
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
			LOG_DEBUG_BDF("tunnel tso start\n");

#endif
		if (!(skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM)) {
			l4.udp->len = 0;

			l4_start = (u8)(l4.hdr - skb->data);

			paylen = skb->len - l4_start;
			csum_replace_by_diff(&l4.udp->check, (__force __wsum)htonl(paylen));
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
				LOG_DEBUG_BDF("udp tunnel tso, out head csum replace\n");
#endif
		}

		if (ip.v4->version == 4)
			ip.v4->frag_off |= htons(IP_DF);

		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);
		if (ip.v4->version == 4) {
			ip.v4->tot_len = 0;
			ip.v4->check   = 0;
		} else {
			ip.v6->payload_len = 0;
		}
	}

	l4_start = (u8)(l4.hdr - skb->data);

	paylen = skb->len - l4_start;
#ifdef NETIF_F_GSO_UDP_L4
	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		csum_replace_by_diff(&l4.udp->check, (__force __wsum)htonl(paylen));

		header_len = (u8)sizeof(l4.udp) + l4_start;
	} else {
		csum_replace_by_diff(&l4.tcp->check, (__force __wsum)htonl(paylen));

		header_len = (u8)((l4.tcp->doff * 4) + l4_start);
	}
#else
	csum_replace_by_diff(&l4.tcp->check, (__force __wsum)htonl(paylen));

	header_len = (u8)((l4.tcp->doff * 4) + l4_start);
#endif

	first_buf->gso_segs = skb_shinfo(skb)->gso_segs;
	first_buf->bytecount += (first_buf->gso_segs - 1) * header_len;
	txq->stats->tx_stats.tx_tso_packets += first_buf->gso_segs;
	txq->stats->tx_stats.tx_tso_bytes += first_buf->bytecount;

	cd_tso_len = skb->len - header_len;
	cd_mss	   = skb_shinfo(skb)->gso_size;

	first_buf->tx_features |= SXE2_TX_FEATURE_TSO;

	sxe2_tx_desc_setup_for_tso(offload, cd_tso_len, cd_mss);

	return 0;

l_end:
	return ret;
}

STATIC s32 sxe2_tx_csum(struct sxe2_queue *txq, struct sxe2_tx_buf *first_buf,
			struct sxe2_tx_offload_info *offload)
{
	s32 ret;
	bool gso_enable;
	u8 l4_proto = 0;
	unsigned char *exthdr;
	union sxe2_ip_hdr ip;
	union sxe2_l4_hdr l4;
	__be16 frag_off, protocol;
	u32 l4_len = 0, l3_len, l2_len;
	u32 cmd = 0, tunnel = 0;
	struct sk_buff *skb	     = first_buf->skb;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = offload->adapter;
#endif

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		txq->stats->tx_stats.tx_csum_none++;
		return 0;
	}

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
		LOG_DEBUG_BDF("tx checksum offload start\n");

#endif

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	l2_len = (u32)(ip.hdr - skb->data);

	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IP))
		first_buf->tx_features |= SXE2_TX_FEATURE_IPV4;
	else if (protocol == htons(ETH_P_IPV6))
		first_buf->tx_features |= SXE2_TX_FEATURE_IPV6;

	if (skb->encapsulation) {
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
			LOG_DEBUG_BDF("tx tunnel checksum offload\n");
#endif
		if (first_buf->tx_features & SXE2_TX_FEATURE_IPV4) {
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
				LOG_DEBUG_BDF("tx tunnel out ipv4 checksum offload\n");

#endif
			tunnel |= (first_buf->tx_features &
				   SXE2_TX_FEATURE_TSO) ? SXE2_TXCD_IPV4 : SXE2_TXCD_IPV4_NO_CSUM;
			l4_proto = ip.v4->protocol;

		} else if (first_buf->tx_features & SXE2_TX_FEATURE_IPV6) {
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
				LOG_DEBUG_BDF("tx tunnel out ipv6 checksum offload\n");

#endif
			tunnel |= SXE2_TXCD_EIPT_IPV6;
			exthdr	 = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			ret	 = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);
			if (ret < 0) {
				ret = -1;
				goto l_end;
			}
		}

		switch (l4_proto) {
		case IPPROTO_UDP:
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
				LOG_DEBUG_BDF("tx tunnel out udp checksum offload\n");
#endif
			tunnel |= SXE2_TXCD_QW0_L4TUNT_UDP_M;
			first_buf->tx_features |= SXE2_TX_FEATURE_TUNNEL;
			break;
		case IPPROTO_GRE:
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
				LOG_DEBUG_BDF("tx tunnel out gre checksum offload\n");
#endif
			tunnel |= SXE2_TXCD_QW0_L4TUNT_GRE_M;
			first_buf->tx_features |= SXE2_TX_FEATURE_TUNNEL;
			break;
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
				LOG_DEBUG_BDF("tx tunnel out ipip/ipv6 checksum offload\n");
#endif
			first_buf->tx_features |= SXE2_TX_FEATURE_TUNNEL;
			l4.hdr = skb_inner_network_header(skb);
			break;
		default:
			if (first_buf->tx_features & SXE2_TX_FEATURE_TSO) {
				ret = -1;
				goto l_end;
			}

			(void)skb_checksum_help(skb);
			ret = 0;
			goto l_end;
		}

		tunnel |= ((l4.hdr - ip.hdr) / 4) << SXE2_TXCD_QW0_EIPLEN_S;

		ip.hdr = skb_inner_network_header(skb);

		tunnel |= ((ip.hdr - l4.hdr) / 2) << SXE2_TXCD_QW0_L4TUNLEN_S;

		gso_enable = skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL;

		if ((first_buf->tx_features & SXE2_TX_FEATURE_TSO) &&
		    !gso_enable &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM)) {
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
				LOG_DEBUG_BDF("tx udp tunnel checksum offload\n");

#endif
			tunnel |= SXE2_TXCD_QW0_L4T_CS_M;
		}

		offload->ctxt_desc_tunnel |= tunnel;
		offload->ctxt_desc_qw1 |= (u64)SXE2_TX_DESC_DTYPE_CTXT;

		l4.hdr	 = skb_inner_transport_header(skb);
		l4_proto = 0;

		first_buf->tx_features &=
			~(SXE2_TX_FEATURE_IPV4 | SXE2_TX_FEATURE_IPV6);
		if (ip.v4->version == 4)
			first_buf->tx_features |= SXE2_TX_FEATURE_IPV4;
		if (ip.v6->version == 6)
			first_buf->tx_features |= SXE2_TX_FEATURE_IPV6;
		txq->stats->tx_stats.tx_csum_partial_inner++;
	} else {
		txq->stats->tx_stats.tx_csum_partial++;
	}

	if (first_buf->tx_features & SXE2_TX_FEATURE_IPV4) {
		l4_proto = ip.v4->protocol;
		if (first_buf->tx_features & SXE2_TX_FEATURE_TSO)
			cmd |= SXE2_TXDD_CMD_IIPT_IPV4_CSUM;
		else
			cmd |= SXE2_TXDD_CMD_IIPT_IPV4;

	} else if (first_buf->tx_features & SXE2_TX_FEATURE_IPV6) {
		cmd |= SXE2_TXDD_CMD_IIPT_IPV6;
		exthdr	 = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr)
			(void)ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);

	} else {
		ret = -1;
		goto l_end;
	}

	l3_len = (u32)(l4.hdr - ip.hdr);

	switch (l4_proto) {
	case IPPROTO_TCP:
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
			LOG_DEBUG_BDF("tx tcp checksum offload\n");

#endif
		cmd |= SXE2_TXDD_CMD_L4T_EOFT_TCP;
		l4_len = l4.tcp->doff;
		break;
	case IPPROTO_UDP:
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
			LOG_DEBUG_BDF("tx udp checksum offload\n");

#endif
		cmd |= SXE2_TXDD_CMD_L4T_EOFT_UDP;
		l4_len = (sizeof(struct udphdr) >> 2);
		break;
#ifdef HAVE_SCTP
	case IPPROTO_SCTP:
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
			LOG_DEBUG_BDF("tx sctp checksum offload\n");

#endif
		cmd |= SXE2_TXDD_CMD_L4T_EOFT_SCTP;
		l4_len = sizeof(struct sctphdr) >> 2;
		break;
#endif

	default:
		if (first_buf->tx_features & SXE2_TX_FEATURE_TSO)
			return -1;
		(void)skb_checksum_help(skb);
		ret = 0;
		goto l_end;
	}

	sxe2_tx_desc_setup_for_csum(offload, l2_len, l3_len, l4_len, cmd);
	first_buf->tx_features |= SXE2_TX_FEATURE_MACLEN;

	return 0;
l_end:
	return ret;
}

static void sxe2_tx_vlan(struct sxe2_queue *txq, struct sxe2_tx_buf *first_buf,
			 struct sxe2_tx_offload_info *offload)
{
	struct sk_buff *skb = first_buf->skb;
	union sxe2_ip_hdr ip;
	u32 l2_len;

	if (!skb_vlan_tag_present(skb) && eth_type_vlan((__be16)skb->protocol))
		return;

	if (skb_vlan_tag_present(skb)) {
		txq->stats->tx_stats.tx_vlan_insert++;
		sxe2_tx_desc_setup_for_vlan(offload, skb_vlan_tag_get(skb));
	}

	if ((offload->data_desc_cmd & SXE2_TXDD_CMD_IL2TAG1) &&
	    !(first_buf->tx_features & SXE2_TX_FEATURE_MACLEN)) {
		ip.hdr = skb_network_header(skb);
		l2_len = (u32)(ip.hdr - skb->data);
		offload->data_desc_offset |= ((l2_len / 2) << SXE2_TXDD_MACLEN_S);
	}
}

static void sxe2_request_tstamp(struct sxe2_queue *txq,
				struct sxe2_tx_buf *first_buf,
				struct sxe2_tx_offload_info *offload)
{
	s32 idx;
	struct net_device *netdev = netif_is_macvlan(txq->netdev) ?
			macvlan_dev_real_dev(txq->netdev) : txq->netdev;
	struct sxe2_netdev_priv *np  = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sk_buff *skb	     = first_buf->skb;

	if (!adapter->ptp_ctxt.ptp_tx_enable)
		return;

	if (likely(!(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)))
		return;

	if (first_buf->tx_features & SXE2_TX_FEATURE_TSO)
		return;

	idx = sxe2_ptp_txts_request(txq->tx_tstamps, skb);
	if (idx < 0)
		return;

	sxe2_tx_desc_setup_for_ptp(offload, (u64)idx);

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
		LOG_DEBUG_BDF("QW1:0x%llx,ptp index:%d\n", offload->ctxt_desc_qw1, idx);

#endif
}

STATIC s32 sxe2_tx_feature_offload(struct sxe2_queue *txq,
				   struct sxe2_tx_buf *first_buf,
				   struct sxe2_tx_offload_info *offload)
{
	s32 ret;
	u16 ntu			  = txq->next_to_use;
	struct net_device *netdev = netif_is_macvlan(txq->netdev) ?
			macvlan_dev_real_dev(txq->netdev) : txq->netdev;
	struct sxe2_netdev_priv *np  = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_tx_context_desc *ctxt_desc;

	offload->adapter = adapter;

	ret = sxe2_tso(txq, first_buf, offload);
	if (ret < 0)
		goto l_end;

#ifdef HAVE_MACSEC_SUPPORT
	if (sxe2_macsec_offload(adapter, first_buf->skb))
		offload->data_desc_cmd |= SXE2_TXDD_CMD_MACSEC;
#endif

	if (xfrm_offload(first_buf->skb)) {
		ret = sxe2_ipsec_tx(txq, first_buf, offload);
		if (ret)
			goto l_end;
	}

	ret = sxe2_tx_csum(txq, first_buf, offload);
	if (ret < 0)
		goto l_end;

	sxe2_request_tstamp(txq, first_buf, offload);

	sxe2_tx_vlan(txq, first_buf, offload);

	if (test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, offload->adapter->flags))
		sxe2_eswitch_tx_desc_setup(offload, first_buf->skb);

	if (offload->ctxt_desc_qw1 & SXE2_TX_DESC_DTYPE_CTXT) {
		ctxt_desc = SXE2_TXCD(txq, ntu);
		ntu++;
		txq->next_to_use = (ntu < txq->depth) ? ntu : 0;

		ctxt_desc->tunneling_params = cpu_to_le32(offload->ctxt_desc_tunnel);
		ctxt_desc->l2tag2 = cpu_to_le16(offload->ctxt_desc_l2tag2);
		ctxt_desc->qw1	  = cpu_to_le64(offload->ctxt_desc_qw1);
		ctxt_desc->ipset_offset = cpu_to_le16(offload->ctxt_desc_ipsec_offset);

#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
			LOG_DEBUG_BDF("desc:qw1=0x%llx\n", ctxt_desc->qw1);

#endif
	}

l_end:
	return ret;
}

static void sxe2_tx_dma_err(struct sxe2_queue *txq,
			    struct sxe2_tx_buf *first_buf, u16 ntu)
{
	struct sxe2_tx_buf *tx_buf;

	for (;;) {
		tx_buf = &txq->tx_buf[ntu];

		sxe2_tx_buffer_unmap(txq, tx_buf);
		if (tx_buf == first_buf)
			break;

		if (ntu == 0)
			ntu += txq->depth;

		--ntu;
	}

	txq->next_to_use = ntu;
}

static inline void sxe2_tx_desc_update(struct sxe2_queue *txq,
				       union sxe2_tx_data_desc **desc,
				       u16 *ntu)
{
	++(*ntu);
	++(*desc);
	if (txq->depth == *ntu) {
		*desc = SXE2_TX_DESC(txq, 0);
		*ntu  = 0;
	}
}

STATIC s32 sxe2_tx_desc_ring_map(struct sxe2_queue *txq,
				 struct sxe2_tx_buf *first_buf,
				 struct sxe2_tx_offload_info *offload,
				 union sxe2_tx_data_desc **desc, u16 *ntu)
{
	u32 max_data;
	dma_addr_t dma;
	skb_frag_t *frag;
	struct sk_buff *skb = first_buf->skb;
	u32 map_size = skb_headlen(skb);
	u32 remaining_size	   = skb->data_len;
	struct sxe2_tx_buf *tx_buf = first_buf;
	struct sxe2_adapter *adapter = txq->vsi->adapter;

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("skb dma map start, line_size=%u, \t"
			      " total_frag_len=%u, skb_len=%u, ntu=%u\n",
			      skb_headlen(skb), skb->data_len, skb->len, *ntu);
	}
#endif

	dma = dma_map_single(txq->dev, skb->data, map_size, DMA_TO_DEVICE);

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (dma_mapping_error(txq->dev, dma)) {
			LOG_ERROR_BDF("tx dma map failed\n");
			goto l_dma_err;
		}

		dma_unmap_len_set(tx_buf, len, map_size);
		dma_unmap_addr_set(tx_buf, dma, dma);
		(*desc)->read.buf_addr = cpu_to_le64(dma);

		max_data = SXE2_MAX_DATA_PER_TXD_ALIGNED;

#ifdef SXE2_TX_4K_AILGN
		max_data += -dma & (SXE2_MAX_READ_REQ_SIZE - 1);
#endif

		while (unlikely(map_size > SXE2_MAX_DATA_PER_TXD)) {
			(*desc)->read.cmd_type_offset_bsz =
				sxe2_tx_data_desc_qword1_setup(offload, max_data);

			sxe2_tx_desc_update(txq, desc, ntu);
			dma += max_data;
			map_size -= max_data;

			max_data	       = SXE2_MAX_DATA_PER_TXD_ALIGNED;
			(*desc)->read.buf_addr = cpu_to_le64(dma);
		}

		if (likely(!remaining_size)) {
			offload->data_desc_cmd |= SXE2_TXDD_CMD_EOP | SXE2_TXDD_CMD_RS;
			(*desc)->read.cmd_type_offset_bsz =
				sxe2_tx_data_desc_qword1_setup(offload, map_size);

#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
				LOG_DEBUG_BDF("skb dma map, current_map_size=%u, \t"
					      "remaining_size=%u, desc_ptr=%p, dma_addr=%#llx, \t"
					      "desc.buffer_addr = %#llx, cmd_type=0x%llx\n",
					      map_size, remaining_size, *desc, (u64)dma,
					      (*desc)->read.buf_addr,
					      (*desc)->read.cmd_type_offset_bsz);
			}
#endif
			break;
		}

		(*desc)->read.cmd_type_offset_bsz =
			sxe2_tx_data_desc_qword1_setup(offload, map_size);

#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
				LOG_DEBUG_BDF("skb dma map, current_map_size=%u, \t"
					      "remaining_size=%u, desc_ptr=%p, dma_addr=%#llx, \t"
					      "desc.buffer_addr = %#llx, cmd_type=0x%llx\n",
					      map_size, remaining_size, *desc, (u64)dma,
					      (*desc)->read.buf_addr,
					      (*desc)->read.cmd_type_offset_bsz);
		}
#endif

		sxe2_tx_desc_update(txq, desc, ntu);

		map_size = skb_frag_size(frag);
		remaining_size -= map_size;

		dma = skb_frag_dma_map(txq->dev, frag, 0, map_size,
				       DMA_TO_DEVICE);

		tx_buf = &txq->tx_buf[*ntu];
	}

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
		LOG_DEBUG_BDF("skb dma map end\n");

#endif
	return 0;

l_dma_err:
	sxe2_tx_dma_err(txq, first_buf, *ntu);
	return -ENOMEM;
}

s32 sxe2_xmit_pkt(struct sxe2_queue *txq, struct sxe2_tx_buf *first_buf,
		  struct sxe2_tx_offload_info *offload)
{
	s32 ret;
	u16 ntu			      = txq->next_to_use;
	union sxe2_tx_data_desc *desc = SXE2_TX_DESC(txq, ntu);
	struct sxe2_adapter *adapter  = txq->vsi->adapter;
	bool xmit_more;

	ret = sxe2_tx_desc_ring_map(txq, first_buf, offload, &desc, &ntu);
	if (ret)
		goto l_end;

	ntu++;
	if (ntu == txq->depth)
		ntu = 0;

	skb_tx_timestamp(first_buf->skb);

	/* in order to force CPU ordering */
	wmb();

	first_buf->next_to_watch = desc;

	txq->next_to_use = ntu;

	if (unlikely(sxe2_tx_desc_unused_count(txq) <= SXE2_TX_DESC_NEEDED)) {
		ret = sxe2_maybe_stop_tx(txq, SXE2_TX_DESC_NEEDED);
		if (ret < 0) {
			LOG_WARN_BDF("the desc is not enough in the queue[%u],\t"
				     "to stop the queue, \t"
				     "desc_cnt < SXE2_TX_DESC_NEEDED[%u]\n",
				     txq->idx_in_vsi, (u32)SXE2_TX_DESC_NEEDED);
		}
	}

	xmit_more = netdev_xmit_more();

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("xmit end, ring idx=%u, next_to_use=%d, \t"
			      "next_to_clean=%d, next_to_watch=%pK xmit_more %d \t"
			      "desc left %d SXE2_TX_DESC_NEEDED %d\n",
			      txq->idx_in_pf, txq->next_to_use,
			      txq->next_to_clean, first_buf->next_to_watch, xmit_more,
			      sxe2_tx_desc_unused_count(txq), (u32)SXE2_TX_DESC_NEEDED);
	}
#endif

	txq->stats->tx_stats.tx_xmit_more += xmit_more;
	if (__netdev_tx_sent_queue(sxe2_netdev_txq_get(txq),
				   first_buf->bytecount, xmit_more)) {
		writel(ntu, txq->desc.tail);
	}

	return 0;

l_end:
	txq->stats->tx_stats.tx_queue_dropped++;
	return ret;
}

static bool sxe2_chk_linearize_for_tso(struct sxe2_queue *txq,
				       struct sk_buff *skb)
{
	u32 i;
	bool ret;
	s32 nr_frags, sum;
	const skb_frag_t *frag, *stale;

	nr_frags = skb_shinfo(skb)->nr_frags;
	if (nr_frags < (SXE2_MAX_DATA_DESC_PER_SKB - 1)) {
		ret = false;
		goto l_end;
	}

	txq->stats->tx_stats.tx_tso_linearize_chk++;

	sum = 1 - skb_shinfo(skb)->gso_size;

	frag = &skb_shinfo(skb)->frags[0];
	for (i = 0; i < SXE2_TSO_SEG_DESC_USE_FOR_FRAGMENT - 1; i++)
		sum += (s32)skb_frag_size(frag++);
	nr_frags -= SXE2_TSO_SEG_DESC_USE_FOR_FRAGMENT;

	for (stale = &skb_shinfo(skb)->frags[0];; stale++) {
		s32 stale_size = (s32)skb_frag_size(stale);

		sum += (s32)skb_frag_size(frag++);

		if (stale_size > (s32)SXE2_MAX_DATA_PER_TXD) {
#ifdef SXE2_TX_4K_AILGN
			int align_pad = -(skb_frag_off(stale)) &
					(SXE2_MAX_READ_REQ_SIZE - 1);

			sum -= align_pad;
			stale_size -= align_pad;
#endif
			do {
				sum -= (s32)SXE2_MAX_DATA_PER_TXD_ALIGNED;
				stale_size -= (s32)SXE2_MAX_DATA_PER_TXD_ALIGNED;
			} while (stale_size > (s32)SXE2_MAX_DATA_PER_TXD);
		}

		if (sum < 0) {
			ret = true;
			goto l_end;
		}

		if (!nr_frags--)
			break;

		sum -= stale_size;
	}

	ret = false;
l_end:
	return ret;
}

static bool sxe2_chk_linearize(struct sxe2_queue *txq, struct sk_buff *skb,
			       u32 desc_needed)
{
	if (likely(desc_needed < SXE2_MAX_DATA_DESC_PER_SKB))
		return false;

	if (skb_is_gso(skb))
		return sxe2_chk_linearize_for_tso(txq, skb);

	return true;
}

static netdev_tx_t sxe2_queue_xmit(struct sk_buff *skb, struct sxe2_queue *txq)
{
	s32 res;
	netdev_tx_t ret = NETDEV_TX_OK;
	u32 need_desc_count;
	struct sxe2_tx_buf *first_buf = NULL;
	struct sxe2_adapter *adapter  = txq->vsi->adapter;
	struct sxe2_tx_offload_info offload = {};

	sxe2_trace(queue_xmit, txq, skb);

	need_desc_count = sxe2_tx_desc_count(skb);
	if (sxe2_chk_linearize(txq, skb, need_desc_count)) {
		if (__skb_linearize(skb)) {
			LOG_WARN_BDF("skb linearize failed, drop pkg, txq_idx=%d",
				     txq->idx_in_vsi);
			goto l_free;
		}

		need_desc_count = SXE2_ESTIMATE_DESC_COUNT_FOR_SKB_FRAG(skb->len);
		txq->stats->tx_stats.tx_linearize++;
	}

	need_desc_count += (SXE2_DESCS_PER_CACHE_LINE + SXE2_DESCS_FOR_CTXT_DESC);
	if (unlikely(sxe2_tx_desc_unused_count(txq) < need_desc_count)) {
		if (sxe2_maybe_stop_tx(txq, (u16)need_desc_count)) {
			txq->stats->tx_stats.tx_busy++;
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
				LOG_WARN_BDF("txq desc is not enough, txq_idx=%d need desc %u \t"
					     "max %lu pkt len %u data len %u pkt frags %u",
					     txq->idx_in_vsi, need_desc_count, SXE2_TX_DESC_NEEDED,
					     skb->len, skb->data_len, skb_shinfo(skb)->nr_frags);
			}
#endif
			ret = NETDEV_TX_BUSY;
			goto l_end;
		}
	}

	netdev_txq_bql_enqueue_prefetchw(sxe2_netdev_txq_get(txq));

	first_buf = sxe2_tx_first_buffer_get(skb, txq);

	res = sxe2_tx_feature_offload(txq, first_buf, &offload);
	if (res < 0) {
		LOG_ERROR_BDF("tx offload failed, tx queue->idx=%u\n",
			      txq->idx_in_vsi);
		goto l_free;
	}

	res = sxe2_xmit_pkt(txq, first_buf, &offload);
	if (res) {
		LOG_ERROR_BDF("tx dma mapping err, queue idx=%u\n",
			      txq->idx_in_vsi);
	}

	return NETDEV_TX_OK;

l_free:
	sxe2_trace(queue_xmit_drop, txq, skb);
	dev_kfree_skb_any(skb);
	if (first_buf)
		first_buf->skb = NULL;
l_end:
	return ret;
}

netdev_tx_t sxe2_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	netdev_tx_t ret;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi	    = np->vsi;
	struct sxe2_queue *txq;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = vsi->adapter;
#endif

	txq = vsi->txqs.q[skb->queue_mapping];
	if (!txq) {
		ret = NETDEV_TX_BUSY;
		goto l_end;
	}

	if (skb_put_padto(skb, SXE2_MIN_TX_LEN)) {
		ret = NETDEV_TX_OK;
		goto l_end;
	}

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
		SKB_DUMP(skb);

#endif

	return sxe2_queue_xmit(skb, txq);
l_end:
	return ret;
}

s32 sxe2_prgm_fnav_fltr(struct sxe2_vsi *vsi,
			struct sxe2_tx_fnav_desc *fnav_desc, u8 *raw_packet)
{
	struct sxe2_queue *txq;
	struct device *dev;
	u32 i = 0;
	dma_addr_t dma;
	u16 ntu;
	struct sxe2_tx_buf *first_buf, *tx_buf;
	struct sxe2_tx_fnav_desc *f_desc;
	union sxe2_tx_data_desc *d_desc;
	struct sxe2_tx_offload_info offload;

	if (!vsi)
		return -ENOENT;
	txq = vsi->txqs.q[0];
	if (!txq || !txq->desc.base_addr)
		return -ENOENT;
	dev = txq->dev;

	while (sxe2_tx_desc_unused_count(txq) < SXE2_FNAV_DESC_NEED_USE) {
		if (i > SXE2_FNAV_DESC_CLEAN_DELAY)
			return -EAGAIN;

		i++;
		(void)msleep_interruptible(1);
	}

	dma = dma_map_single(dev, raw_packet, SXE2_FNAV_MAX_RAW_PKT_SIZE,
			     DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma))
		return -EINVAL;

	ntu	  = txq->next_to_use;
	first_buf = &txq->tx_buf[ntu];
	f_desc	  = SXE2_TXFD(txq, ntu);
	(void)memcpy(f_desc, fnav_desc, sizeof(*f_desc));

	ntu++;
	if (unlikely(ntu == txq->depth))
		ntu = 0;
	tx_buf = &txq->tx_buf[ntu];
	d_desc = SXE2_TX_DESC(txq, ntu);

	ntu++;
	if (unlikely(ntu == txq->depth))
		ntu = 0;
	txq->next_to_use = ntu;

	(void)memset(tx_buf, 0, sizeof(*tx_buf));
	dma_unmap_len_set(tx_buf, len, SXE2_FNAV_MAX_RAW_PKT_SIZE);
	dma_unmap_addr_set(tx_buf, dma, dma);

	d_desc->read.buf_addr = cpu_to_le64(dma);
	offload.adapter	      = txq->vsi->adapter;
	offload.data_desc_cmd = SXE2_TXDD_CMD_EOP | SXE2_TXDD_CMD_RS |
				SXE2_TXDD_CMD_DUMMY | SXE2_TXDD_CMD_RE;
	offload.data_desc_offset = 0;
	offload.data_desc_l2tag1 = 0;

	tx_buf->tx_features = SXE2_TX_FEATURE_DUMMY_PKT;
	tx_buf->raw_buf	    = (void *)raw_packet;
	tx_buf->gso_segs    = 1;
	tx_buf->bytecount   = SXE2_FNAV_MAX_RAW_PKT_SIZE;

	d_desc->read.cmd_type_offset_bsz =
		sxe2_tx_data_desc_qword1_setup(&offload, SXE2_FNAV_MAX_RAW_PKT_SIZE);

	/* in order to force CPU ordering */
	wmb();

	first_buf->next_to_watch = d_desc;

	writel(ntu, txq->desc.tail);

	return 0;
}

static inline void sxe2_tx_skb_unmap(struct sxe2_queue *txq,
				     struct sxe2_tx_buf *tx_buf)
{
	dma_unmap_single(txq->dev, dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);

	dma_unmap_len_set(tx_buf, len, 0);
}

static inline void sxe2_tx_desc_buf_update(struct sxe2_queue *txq,
					   struct sxe2_tx_buf **tx_buf,
					   union sxe2_tx_data_desc **tx_desc,
					   u32 *ntc)
{
	(*tx_buf)++;
	(*tx_desc)++;
	++(*ntc);
	if (unlikely(!(*ntc))) {
		*ntc -= txq->depth;
		*tx_buf	 = txq->tx_buf;
		*tx_desc = SXE2_TX_DESC(txq, 0);
	}
}

static void sxe2_tx_desc_ring_unmap(struct sxe2_queue *txq, s32 napi_budget,
				    u16 *budget,
				    struct sxe2_queue_stats *queue_stats)
{
	struct sxe2_tx_buf *tx_buf;
	u32 ntc = txq->next_to_clean;
	union sxe2_tx_data_desc *tx_desc;
	union sxe2_tx_data_desc *eop_desc;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = txq->vsi->adapter;
#endif

	tx_buf	= &txq->tx_buf[ntc];
	tx_desc = SXE2_TX_DESC(txq, ntc);
	ntc -= txq->depth;

	do {
		eop_desc = tx_buf->next_to_watch;

		if (!eop_desc)
			break;

#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_DEBUG_BDF("tx queue clean start: queue idx=%u, reg_idx=%u, \t"
				      "next_to_use=%d, next_to_clean=%d, budget=%d, \t"
				      "next_to_watch=%pK, eop_desc.wb.dd=%#08llx\n",
				      txq->idx_in_vsi, txq->idx_in_pf, txq->next_to_use,
				      txq->next_to_clean, *budget, tx_buf->next_to_watch,
				      ((union sxe2_tx_data_desc *)tx_buf->next_to_watch)->wb.dd);
		}
#endif

		prefetchw(&tx_buf->skb->users);

		/* in order to force CPU ordering */
		smp_rmb();

		sxe2_trace(clean_tx_irq, txq, tx_desc, tx_buf);

		if (!(eop_desc->wb.dd & cpu_to_le64(SXE2_TX_DESC_DTYPE_DESC_DONE)))
			break;

		tx_buf->next_to_watch = NULL;

		queue_stats->bytes += tx_buf->bytecount;
		queue_stats->packets += tx_buf->gso_segs;

		if (sxe2_queue_is_xdp(txq))
			page_frag_free(tx_buf->raw_buf);
		else
			napi_consume_skb(tx_buf->skb, napi_budget);

#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_DEBUG_BDF("tx queue clean: budget=%d, bytes=%llu, packet=%llu\n",
				      *budget, queue_stats->bytes, queue_stats->packets);
		}
#endif

		sxe2_tx_skb_unmap(txq, tx_buf);
		tx_buf->skb = NULL;

		while (tx_desc != eop_desc) {
			sxe2_trace(clean_tx_irq_unmap, txq, tx_desc, tx_buf);
			sxe2_tx_desc_buf_update(txq, &tx_buf, &tx_desc, &ntc);

			if (dma_unmap_len(tx_buf, len))
				sxe2_tx_skb_unmap(txq, tx_buf);
		}
		sxe2_trace(clean_tx_irq_unmap_eop, txq, tx_desc, tx_buf);
		sxe2_tx_desc_buf_update(txq, &tx_buf, &tx_desc, &ntc);

		prefetch(tx_desc);

		--*budget;
	} while (likely(*budget));

	ntc += txq->depth;
	txq->next_to_clean = (u16)ntc;

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("tx queue clean end: queue idx=%u, reg_idx=%u, next_to_use=%d, \t"
			      "next_to_clean=%d, budget=%d\n",
			      txq->idx_in_vsi, txq->idx_in_pf, txq->next_to_use,
			      txq->next_to_clean, *budget);
	}
#endif
}

void sxe2_ctrl_txq_irq_clean(struct sxe2_queue *txq)
{
	struct sxe2_irq_data *irq_data = txq->irq_data;
	u32 ntc			       = txq->next_to_clean;
	int budget		       = SXE2_DFLT_IRQ_WORK;
	union sxe2_tx_data_desc *tx_desc;
	union sxe2_tx_data_desc *eop_desc;
	struct sxe2_tx_buf *tx_buf;
	struct sxe2_queue_stats queue_stats = {};

	tx_buf	= &txq->tx_buf[ntc];
	tx_desc = SXE2_TX_DESC(txq, ntc);
	ntc -= txq->depth;

	do {
		eop_desc = tx_buf->next_to_watch;

		if (!eop_desc)
			break;

		LOG_DEBUG_IRQ("tx queue clean start: queue idx=%u, reg_idx=%u, \t"
			      "next_to_use=%d, next_to_clean=%d, budget=%d, \t"
			      "next_to_watch=%pK, eop_desc.wb.dd=%#08llx\n",
			      txq->idx_in_vsi, txq->idx_in_pf, txq->next_to_use,
			      txq->next_to_clean, budget, tx_buf->next_to_watch,
			      ((union sxe2_tx_data_desc *)tx_buf->next_to_watch)->wb.dd);

		/* in order to force CPU ordering */
		smp_rmb();

		if (!(eop_desc->wb.dd & cpu_to_le64(SXE2_TX_DESC_DTYPE_DESC_DONE)))
			break;

		tx_buf->next_to_watch = NULL;

		tx_desc->read.buf_addr		  = 0;
		tx_desc->read.cmd_type_offset_bsz = 0;

		sxe2_tx_desc_buf_update(txq, &tx_buf, &tx_desc, &ntc);
		if (dma_unmap_len(tx_buf, len)) {
			dma_unmap_single(txq->dev, dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);
		}
		queue_stats.bytes += tx_buf->bytecount;
		queue_stats.packets += tx_buf->gso_segs;
		if (tx_buf->tx_features & SXE2_TX_FEATURE_DUMMY_PKT)
			devm_kfree(txq->dev, tx_buf->raw_buf);

		tx_buf->raw_buf	      = NULL;
		tx_buf->tx_features   = 0;
		tx_buf->next_to_watch = NULL;
		tx_buf->bytecount     = 0;
		tx_buf->gso_segs      = 0;
		dma_unmap_addr_set(tx_buf, dma, 0);
		dma_unmap_len_set(tx_buf, len, 0);
		tx_desc->read.buf_addr		  = 0;
		tx_desc->read.cmd_type_offset_bsz = 0;

		sxe2_tx_desc_buf_update(txq, &tx_buf, &tx_desc, &ntc);

		budget--;
	} while (likely(budget));

	ntc += txq->depth;
	txq->next_to_clean = (u16)ntc;

	sxe2_tx_pkt_stats_update(txq, &queue_stats);

	sxe2_hw_irq_enable(&irq_data->vsi->adapter->hw, irq_data->idx_in_pf);
}

bool sxe2_txq_irq_clean(struct sxe2_queue *txq, s32 napi_budget)
{
	u16 budget			    = SXE2_DFLT_IRQ_WORK;
	struct sxe2_queue_stats queue_stats = {};
	struct sxe2_adapter *adapter	    = txq->vsi->adapter;

	if (txq->netdev)
		netdev_txq_bql_complete_prefetchw(sxe2_netdev_txq_get(txq));

	sxe2_tx_desc_ring_unmap(txq, napi_budget, &budget, &queue_stats);

	sxe2_tx_pkt_stats_update(txq, &queue_stats);

	if (sxe2_queue_is_xdp(txq))
		return !!budget;

	netdev_tx_completed_queue(sxe2_netdev_txq_get(txq),
				  (u32)queue_stats.packets, (u32)queue_stats.bytes);

	if (unlikely(queue_stats.packets && netif_carrier_ok(txq->netdev) &&
		     (sxe2_tx_desc_unused_count(txq) >= SXE2_TX_WAKE_THRESHOLD))) {
		/* in order to force CPU ordering */
		smp_mb();

		if (netif_tx_queue_stopped(sxe2_netdev_txq_get(txq)) &&
		    !test_bit(SXE2_VSI_S_DOWN, txq->vsi->state)) {
			netif_tx_wake_queue(sxe2_netdev_txq_get(txq));
			++txq->stats->tx_stats.tx_restart;
			LOG_WARN_BDF("\n\n txq idx=%u, wake_up\n\n",
				     txq->idx_in_vsi);
		}
	}

	return !!budget;
}

#ifdef HAVE_XDP_SUPPORT
s32 sxe2_xmit_xdp_ring(void *data, u16 size, struct sxe2_queue *xdp_ring)
{
	u16 ntu = xdp_ring->next_to_use;
	union sxe2_tx_data_desc *tx_desc;
	struct sxe2_tx_buf *tx_buf;
	struct sxe2_tx_offload_info offload;
	dma_addr_t dma;

	if (!unlikely(SXE2_DESC_UNUSED(xdp_ring))) {
		xdp_ring->stats->tx_stats.tx_busy++;
		return SXE2_XDP_CONSUMED;
	}

	dma = dma_map_single(xdp_ring->dev, data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(xdp_ring->dev, dma))
		return SXE2_XDP_CONSUMED;

	tx_buf		  = &xdp_ring->tx_buf[ntu];
	tx_buf->bytecount = size;
	tx_buf->gso_segs  = 1;
	tx_buf->raw_buf	  = data;

	dma_unmap_len_set(tx_buf, len, size);
	dma_unmap_addr_set(tx_buf, dma, dma);

	offload.adapter		 = xdp_ring->vsi->adapter;
	offload.data_desc_cmd	 = SXE2_TXDD_CMD_EOP | SXE2_TXDD_CMD_RS;
	offload.data_desc_offset = 0;
	offload.data_desc_l2tag1 = 0;

	tx_desc		       = SXE2_TX_DESC(xdp_ring, ntu);
	tx_desc->read.buf_addr = cpu_to_le64(dma);
	tx_desc->read.cmd_type_offset_bsz = sxe2_tx_data_desc_qword1_setup(&offload, size);

	/* in order to force CPU ordering */
	smp_wmb();

	ntu++;
	if (ntu == xdp_ring->depth)
		ntu = 0;

	tx_buf->next_to_watch = tx_desc;
	xdp_ring->next_to_use = ntu;

	return SXE2_XDP_TX;
}

s32 sxe2_xmit_xdp_buff(struct xdp_buff *xdp, struct sxe2_queue *xdp_ring)
{
	struct xdp_frame *xdpf = xdp_convert_buff_to_frame(xdp);

	if (unlikely(!xdpf))
		return SXE2_XDP_CONSUMED;

	return sxe2_xmit_xdp_ring(xdpf->data, xdpf->len, xdp_ring);
}
#endif

static u16 sxe2_txq_pending_get(struct sxe2_queue *txq)
{
	u16 head, tail;
	u16 pending_txq_seq;

	head = txq->next_to_clean;
	tail = txq->next_to_use;

	if (head != tail) {
		pending_txq_seq = (u16)((head < tail) ? (tail - head) : (tail + txq->depth - head));
		return pending_txq_seq;
	}

	return 0;
}

void sxe2_tx_hang_check_subtask(struct sxe2_adapter *adapter)
{
	u32 i;
	s32 packets;
	struct sxe2_vsi *vsi;
	struct sxe2_queue *txq;
	struct sxe2_queue_stats *txq_stats;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = adapter->vsi_ctxt.main_vsi;

	if (!vsi || test_bit(SXE2_VSI_S_DOWN, vsi->state))
		goto unlock;

	if (!(vsi->netdev && netif_carrier_ok(vsi->netdev)))
		goto unlock;

	sxe2_for_each_vsi_txq(vsi, i) {
		txq = vsi->txqs.q[i];
		if (!txq)
			continue;

		txq_stats = txq->stats;
		if (!txq_stats)
			continue;

		if (txq->desc.base_addr) {
			packets = txq_stats->packets & INT_MAX;
			if (txq_stats->prev_pkt == packets) {
				sxe2_hw_irq_trigger(&adapter->hw,
						    txq->irq_data->idx_in_pf);
				continue;
			}

			/* in order to force CPU ordering */
			smp_rmb();
			txq_stats->prev_pkt = sxe2_txq_pending_get(txq) ? packets : -1;
		}
	}

unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

static inline bool sxe2_find_q_in_range(u16 low, u16 high, u32 txq)
{
	return (txq >= low) && (txq < high);
}

STATIC bool sxe2_is_pfc_causing_hung_q(struct sxe2_adapter *adapter,
				       u32 txqueue)
{
	u8 num_tcs = 0, i, tc, up_in_tc = 0;
	u64 ref_prio_xoff[SXE2_MAX_USER_PRIORITY];
	struct sxe2_vsi *vsi	      = adapter->vsi_ctxt.main_vsi;
	struct sxe2_dcb_stats *stats  = &adapter->pf_stats.dcb_stats;
	struct sxe2_dcbx_cfg *dcb_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	if (!vsi)
		return false;

	sxe2_for_each_tc(i)
		if (vsi->tc.tc_map & BIT(i))
			num_tcs++;

	for (tc = 0; tc < num_tcs - 1; tc++)
		if (sxe2_find_q_in_range(vsi->tc.info[tc].txq_offset,
					 vsi->tc.info[tc + 1].txq_offset,
					 txqueue))
			break;

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		if (dcb_cfg->ets.prio_tbl[i] == tc)
			up_in_tc |= BIT(i);
	}

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++)
		if (up_in_tc & BIT(i))
			ref_prio_xoff[i] = stats->curr_pause_stats.prio_xoff_rx[i];

	sxe2_dcb_stats_update(adapter);

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++)
		if (up_in_tc & BIT(i))
			if (stats->curr_pause_stats.prio_xoff_rx[i] >
			    ref_prio_xoff[i])
				return true;

	return false;
}

void sxe2_tx_timeout(struct net_device *netdev, u32 txqueue)
{
	u32 i;
	struct sxe2_netdev_priv *np  = netdev_priv(netdev);
	struct sxe2_vsi *vsi	     = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_queue *txq	     = NULL;
	struct netdev_queue *ntxq = NULL;

	adapter->tx_timeout_count++;

	if (sxe2_is_pfc_causing_hung_q(adapter, txqueue)) {
		LOG_DEV_INFO("fake Tx hang detected on queue %u, \t"
			     "timeout caused by PFC storm\n",
			     txqueue);
		return;
	}

	sxe2_for_each_vsi_txq(vsi, i) {
		if (vsi->txqs.q[i] && vsi->txqs.q[i]->desc.base_addr) {
			if (txqueue == vsi->txqs.q[i]->idx_in_vsi) {
				txq = vsi->txqs.q[i];
				break;
			}
		}
	}

	if (time_after(jiffies, (adapter->tx_timeout_last_recovery + HZ * 20)))
		adapter->tx_timeout_recovery_level = 1;
	else if (time_before(jiffies, (adapter->tx_timeout_last_recovery +
				       netdev->watchdog_timeo)))
		return;

	if (txq) {
		ntxq = sxe2_netdev_txq_get(txq);
		LOG_NETDEV_INFO("tx_timeout: VSI_num: %u, Q %u, NTC: 0x%x, \t"
				"NTU: 0x%x netdev txq state %lu\t"
				"(BIT: 0 - DRV_XOFF; 1 - STACK_XOFF; 2- FROZEN)\n",
				vsi->idx_in_dev, txqueue, txq->next_to_clean,
				txq->next_to_use, ntxq->state);
	}

	adapter->tx_timeout_last_recovery = jiffies;
	LOG_NETDEV_INFO("tx_timeout recovery level %d, txqueue %u\n",
			adapter->tx_timeout_recovery_level, txqueue);

	switch (adapter->tx_timeout_recovery_level) {
	case 1:
		(void)sxe2_reset_async(adapter, SXE2_RESET_PFR);
		break;
	case 2:
		(void)sxe2_reset_async(adapter, SXE2_RESET_CORER);
		break;
	default:
		LOG_NETDEV_ERR("tx_timeout recovery unsuccessful, \t"
			       "device is in unrecoverable state\n");

		break;
	}

	adapter->tx_timeout_recovery_level++;
}

static void sxe2_txq_ucmd_err_handle(struct sxe2_vsi *vsi,
				     struct sxe2_txq_ucmd_en_params *params, u32 q_err_id)
{
	u32 i = 0;
	struct sxe2_queue *txq;
	struct sxe2_txq_ucmd_ctxt *q_ctxt_info;

	for (i = 0; i < q_err_id; i++) {
		q_ctxt_info = &params->ctxts[i];
		txq = vsi->txqs.q[q_ctxt_info->queue_id];

		if (q_ctxt_info->sched_mode == SXE2_SCHED_MODE_TM &&
		    q_ctxt_info->sched_mode == SXE2_SCHED_MODE_HIGH_PERFORMANCE)
			(void)sxe2_fwc_txq_stop(vsi, txq);
		else if (q_ctxt_info->sched_mode == SXE2_SCHED_MODE_DEFAULT)
			(void)sxe2_txq_stop(vsi, txq);
	}
}

static bool sxe2_txq_cfg_param_is_valid(struct sxe2_adapter *adapter,
					struct sxe2_txq_ucmd_en_params *params)
{
	u16 i;
	struct sxe2_vsi *vsi;
	struct sxe2_txq_ucmd_ctxt *ctxt;

	if (!sxe2_vsi_id_is_valid(adapter, params->vsi_idx)) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_idx);
		return false;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_idx);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_idx);
		return false;
	}

	if (params->q_cnt > vsi->txqs.q_cnt || !params->q_cnt) {
		LOG_ERROR_BDF("txq cnt:%u invalid max:%u vsi_id:%d.\n",
			      params->q_cnt, vsi->txqs.q_cnt, params->vsi_idx);
		return false;
	}

	for (i = 0; i < params->q_cnt; i++) {
		ctxt = &params->ctxts[i];
		if (ctxt->queue_id >= vsi->txqs.q_cnt ||
		    ctxt->sched_mode >= SXE2_UCMD_TXQ_MODE_INVALID ||
		    !sxe2_queue_depth_is_valid(ctxt->depth)) {
			LOG_ERROR_BDF("vsi_id:%u vsi_id_in_dev:%d  queue_id:%u\n"
				      "txq cnt:%u depth:%u\n",
				      params->vsi_idx, vsi->idx_in_dev,
				      ctxt->queue_id, vsi->txqs.q_cnt,
				      ctxt->depth);
			return false;
		}
	}

	return true;
}

s32 sxe2_txq_cfg_ena_common_handle(struct sxe2_adapter *adapter,
				   struct sxe2_txq_ucmd_en_params *params)
{
	s32 ret = 0;
	u32 i = 0;
	u16 q_cnt;
	struct sxe2_queue *txq;
	struct sxe2_vsi *vsi;
	struct sxe2_txq_ucmd_ctxt *q_ctxt_info;
	enum sxe2_txsched_node_owner owner;
	struct sxe2_fwc_cfg_txq_req req = {.ctxt = {0}, .leaf = {0}};

	if (!adapter || !params) {
		LOG_ERROR_BDF("tx cfg enable params invalid.\n");
		ret = -EINVAL;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (!sxe2_txq_cfg_param_is_valid(adapter, params)) {
		LOG_ERROR_BDF("tx cfg enable params invalid.\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_idx);
	if (!vsi) {
		ret = -EINVAL;
		LOG_ERROR_BDF("vsi_id:%d vsi null.\n", params->vsi_idx);
		goto l_unlock;
	}
	q_cnt = params->q_cnt;
	for (i = 0; i < q_cnt; i++) {
		q_ctxt_info = &params->ctxts[i];
		txq = vsi->txqs.q[q_ctxt_info->queue_id];

		txq->depth = q_ctxt_info->depth;
		txq->desc.dma = q_ctxt_info->dma_addr;

		ret = sxe2_txq_ctxt_fill(vsi, txq, &req.ctxt);
		if (ret) {
			LOG_ERROR("q_id[%#x] depth[%#x]\n",
				  le16_to_cpu(q_ctxt_info->queue_id), txq->depth);
			goto l_unlock;
		}

		if (q_ctxt_info->sched_mode == SXE2_UCMD_TXQ_MODE_TM)
			req.ctxt.is_tm = 1;

		if (q_ctxt_info->sched_mode == SXE2_UCMD_TXQ_MODE_TM ||
		    q_ctxt_info->sched_mode == SXE2_UCMD_TXQ_MODE_HIGH_PERFORMANCE) {
			ret = sxe2_fwc_txq_ctxt_cfg(vsi, &req);
			if (ret) {
				LOG_ERROR("q_id[%#x] depth[%#x] txq[%#x]\n",
					  le16_to_cpu(q_ctxt_info->queue_id),
					  txq->depth, txq->idx_in_pf);
				goto l_unlock;
			}

		} else if (q_ctxt_info->sched_mode == SXE2_UCMD_TXQ_MODE_DEFAULT) {
			owner = ((vsi->type == SXE2_VSI_T_DPDK_PF) ||
				 (vsi->type == SXE2_VSI_T_DPDK_VF)) ?
				 SXE2_TXSCHED_NODE_OWNER_USER : SXE2_TXSCHED_NODE_OWNER_LAN;

			ret = sxe2_txsched_txq_node_add(adapter, vsi, txq, owner, &req);
			if (ret) {
				LOG_ERROR("hw tx txq[%u] start failed\n",
					  txq->idx_in_pf);
				goto l_unlock;
			}
		}
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
l_end:
	if (ret)
		sxe2_txq_ucmd_err_handle(vsi, params, i);

	return ret;
}

static bool sxe2_txq_dis_param_is_valid(struct sxe2_adapter *adapter,
					struct sxe2_txq_ucmd_dis_params *params)
{
	struct sxe2_vsi *vsi;

	if (!sxe2_vsi_id_is_valid(adapter, params->vsi_id)) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_id);
		return false;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_id);
		return false;
	}

	if (params->q_idx > vsi->txqs.q_cnt) {
		LOG_ERROR_BDF("txq id:%u invalid max:%u vsi_id:%d.\n",
			      params->q_idx, vsi->txqs.q_cnt, params->vsi_id);
		return false;
	}

	if (params->sched_mode >= SXE2_UCMD_TXQ_MODE_INVALID) {
		LOG_ERROR_BDF("sched_mode:%u invalid max:%u vsi_id:%d.\n",
			      params->sched_mode, SXE2_UCMD_TXQ_MODE_INVALID,
			      params->vsi_id);
		return false;
	}

	return true;
}

s32 sxe2_txq_dis_common_handle(struct sxe2_adapter *adapter,
			       struct sxe2_txq_ucmd_dis_params *params)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;
	struct sxe2_queue *txq;

	if (!adapter || !params) {
		LOG_ERROR_BDF("tx cfg enable params invalid.\n");
		ret = -EINVAL;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (!sxe2_txq_dis_param_is_valid(adapter, params)) {
		LOG_ERROR_BDF("tx queue disable params invalid.\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("tx queue disable failed, vsi=NULL, vsi_idx=%d\n",
			      params->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	txq = vsi->txqs.q[params->q_idx];

	if (params->sched_mode == SXE2_UCMD_TXQ_MODE_TM ||
	    params->sched_mode == SXE2_UCMD_TXQ_MODE_HIGH_PERFORMANCE) {
		ret = sxe2_fwc_txq_stop(vsi, txq);
		if (ret) {
			LOG_ERROR_BDF("vsi %d type %d hw tx txq[%u] stop failed\n",
				      vsi->idx_in_dev, vsi->type, txq->idx_in_pf);
			goto l_unlock;
		}
	} else if (params->sched_mode == SXE2_UCMD_TXQ_MODE_DEFAULT) {
		ret = sxe2_txsched_txq_node_del(adapter, txq);
		if (ret) {
			LOG_ERROR_BDF("vsi %d type %d hw tx txq[%u] stop failed\n",
				      vsi->idx_in_dev, vsi->type, txq->idx_in_pf);
			goto l_unlock;
		}
	}

	LOG_INFO_BDF("vsi %d type %d hw tx txq[%u] stop success\n",
		     vsi->idx_in_dev, vsi->type, txq->idx_in_pf);
l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	return ret;
}
