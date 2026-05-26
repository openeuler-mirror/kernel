// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: ipourma urma resource management
 */
#include <linux/timer.h>
#include "ipourma_err.h"
#include "ipourma_ub.h"
#include "ipourma_netdev.h"
#include "ub/urma/ubcore_uapi.h"
#include "ipourma_res.h"

u32 ipourma_tx_ring_size __read_mostly = IPOURMA_TX_RING_SIZE;
u32 ipourma_rx_ring_size __read_mostly = IPOURMA_RX_RING_SIZE;
u32 ipourma_register_seg_size __read_mostly = IPOURMA_REGISTER_SEG_SIZE;
u32 ipourma_jfs_depth;
static u32 ipourma_jfr_depth;
u32 ipourma_tx_jfc_depth;
static u32 ipourma_rx_jfc_depth;

void ipourma_ub_size_init(void)
{
	ipourma_jfs_depth = ipourma_tx_ring_size;
	ipourma_jfr_depth = ipourma_rx_ring_size;
	ipourma_tx_jfc_depth = ipourma_jfs_depth * (IPOURMA_TX_JFC_DEPTH / IPOURMA_JFS_DEPTH);
	ipourma_rx_jfc_depth = ipourma_jfr_depth * (IPOURMA_RX_JFC_DEPTH / IPOURMA_JFR_DEPTH);
}

static void ipourma_uninit_tx_bufs(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	if (IS_ERR_OR_NULL(priv->tx_ring[eid_idx]))
		return;
	for (u32 i = 0; i < ipourma_tx_ring_size; i++) {
		priv->tx_ring[eid_idx][i].seg[0] = NULL;
		priv->tx_ring[eid_idx][i].buf_aligned = NULL;
	}

	if (!IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[eid_idx])) {
		for (size_t i = 0; i < priv->tx_buf_num; i++) {
			if (IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[eid_idx][i]))
				continue;
			ubcore_unregister_seg(priv->ipourma_ub_tx_seg[eid_idx][i]);
			priv->ipourma_ub_tx_seg[eid_idx][i] = NULL;
		}
		kfree(priv->ipourma_ub_tx_seg[eid_idx]);
		priv->ipourma_ub_tx_seg[eid_idx] = NULL;
	}

	if (!IS_ERR_OR_NULL(priv->tx_buf_aligned[eid_idx])) {
		for (size_t i = 0; i < priv->tx_buf_num; i++) {
			if (IS_ERR_OR_NULL(priv->tx_buf_aligned[eid_idx][i]))
				continue;
			kfree(priv->tx_buf_aligned[eid_idx][i]);
			priv->tx_buf_aligned[eid_idx][i] = NULL;
		}
		kfree(priv->tx_buf_aligned[eid_idx]);
		priv->tx_buf_aligned[eid_idx] = NULL;
	}
}

void ipourma_uninit_rx_bufs(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	for (u32 i = 0; i < ipourma_rx_ring_size; i++) {
		if (!IS_ERR_OR_NULL(priv->rx_ring[eid_idx][i].seg[0]))
			priv->rx_ring[eid_idx][i].seg[0] = NULL;
		if (!IS_ERR_OR_NULL(priv->rx_ring[eid_idx][i].buf_aligned))
			priv->rx_ring[eid_idx][i].buf_aligned = NULL;

		if (!IS_ERR_OR_NULL(priv->rx_ring[eid_idx][i].skb_pass_up)) {
			dev_kfree_skb_any(priv->rx_ring[eid_idx][i].skb_pass_up);
			priv->rx_ring[eid_idx][i].skb_pass_up = NULL;
		}
	}

	if (!IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[eid_idx])) {
		kfree(priv->ipourma_ub_rx_seg[eid_idx]);
		priv->ipourma_ub_rx_seg[eid_idx] = NULL;
	}

	if (IS_ERR_OR_NULL(priv->rx_buf_aligned[eid_idx]))
		return;
	for (u32 i = 0; i < priv->rx_buf_num; i++) {
		if (IS_ERR_OR_NULL(priv->rx_buf_aligned[eid_idx][i]))
			continue;
		kfree(priv->rx_buf_aligned[eid_idx][i]);
		priv->rx_buf_aligned[eid_idx][i] = NULL;
	}
	kfree(priv->rx_buf_aligned[eid_idx]);
	priv->rx_buf_aligned[eid_idx] = NULL;
}

void ipourma_uninit_rings_by_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	if (!IS_ERR_OR_NULL(priv->tx_ring) && !IS_ERR_OR_NULL(priv->tx_ring[eid_idx])) {
		ipourma_uninit_tx_bufs(priv, eid_idx);
		vfree(priv->tx_ring[eid_idx]);
		priv->tx_ring[eid_idx] = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->rx_ring) && !IS_ERR_OR_NULL(priv->rx_ring[eid_idx])) {
		ipourma_uninit_rx_bufs(priv, eid_idx);
		kfree(priv->rx_ring[eid_idx]);
		priv->rx_ring[eid_idx] = NULL;
	}
}

void ipourma_uninit_rings(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	if (!IS_ERR_OR_NULL(priv->tx_ring)) {
		for (u32 i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
			if (IS_ERR_OR_NULL(priv->tx_ring[i]))
				continue;
			ipourma_uninit_tx_bufs(priv, i);
			vfree(priv->tx_ring[i]);
			priv->tx_ring[i] = NULL;
		}
		kfree(priv->tx_ring);
		priv->tx_ring = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->tx_head)) {
		kfree(priv->tx_head);
		priv->tx_head = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->tx_tail)) {
		kfree(priv->tx_tail);
		priv->tx_tail = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->tx_count)) {
		kfree(priv->tx_count);
		priv->tx_count = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->rx_ring)) {
		for (u32 i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
			if (IS_ERR_OR_NULL(priv->rx_ring[i]))
				continue;
			ipourma_uninit_rx_bufs(priv, i);
			kfree(priv->rx_ring[i]);
			priv->rx_ring[i] = NULL;
		}
		kfree(priv->rx_ring);
		priv->rx_ring = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->tx_ring_locks)) {
		kfree(priv->tx_ring_locks);
		priv->tx_ring_locks = NULL;
	}
}

static int ipourma_alloc_tx_buf_aligned(struct ipourma_dev_priv *priv, u32 eid_idx, u32 idx)
{
	u32 offset = (idx * priv->tx_buf_size) % ipourma_register_seg_size;
	u32 blk_idx = idx * priv->tx_buf_size / ipourma_register_seg_size;
	struct ipourma_tx_buf *tx_buf = &priv->tx_ring[eid_idx][idx];

	tx_buf->buf_aligned = priv->tx_buf_aligned[eid_idx][blk_idx] + offset;

	if (IS_ERR_OR_NULL(tx_buf->buf_aligned) ||
		(u64)(tx_buf->buf_aligned) % IPOURMA_SEGMENT_ALIGN_SIZE != 0) {
		tx_buf->buf_aligned = NULL;
		netdev_warn(priv->dev, "%s: addr = 0x%llx, align = %d\n",
					ipourma_err_desc(IPOURMA_ADDRESS_NOT_ALIGNED),
					(u64)tx_buf->buf_aligned, IPOURMA_SEGMENT_ALIGN_SIZE);
		return IPOURMA_ADDRESS_NOT_ALIGNED;
	}

	tx_buf->seg[0] = priv->ipourma_ub_tx_seg[eid_idx][blk_idx];
	tx_buf->tx_sge[0].addr = (u64)tx_buf->buf_aligned;
	tx_buf->tx_sge[0].tseg = tx_buf->seg[0];

	return IPOURMA_OK;
}

static inline void ipourma_init_tx_wr(struct ipourma_tx_buf *tx_buf)
{
	/* only init the fixed fields */
	tx_buf->tx_wr.user_ctx = tx_buf->idx;
	tx_buf->tx_wr.opcode = UBCORE_OPC_SEND;
	tx_buf->tx_wr.send.src.sge = tx_buf->tx_sge;
	tx_buf->tx_wr.flag.bs.complete_enable = 1;
}

static inline void ipourma_init_rx_wr(struct ipourma_rx_buf *rx_buf)
{
	/* only init the fixed fields */
	rx_buf->rx_wr.user_ctx = rx_buf->idx;
	rx_buf->rx_wr.src.sge = rx_buf->rx_sge;
	rx_buf->rx_wr.src.num_sge = IPOURMA_MAX_RX_SGES;
}

static int ipourma_init_tx_bufs(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	struct ubcore_seg_cfg cfg = { 0 };
	int ret = IPOURMA_OK;
	u32 i;

	priv->tx_buf_aligned[eid_idx] = kcalloc(priv->tx_buf_num, sizeof(u8 *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_buf_aligned[eid_idx]))
		goto alloc_tx_bufs_failed;
	priv->ipourma_ub_tx_seg[eid_idx] = kcalloc(priv->tx_buf_num,
						   sizeof(struct ubcore_target_seg **),
						   GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[eid_idx]))
		goto alloc_tx_bufs_failed;
	for (i = 0; i < priv->tx_buf_num; i++) {
		priv->tx_buf_aligned[eid_idx][i] = kzalloc(ipourma_register_seg_size, GFP_KERNEL);
		if (IS_ERR_OR_NULL(priv->tx_buf_aligned[eid_idx][i]))
			goto alloc_tx_bufs_failed;
		ipourma_build_seg_cfg(&cfg, (u64)priv->tx_buf_aligned[eid_idx][i],
						ipourma_register_seg_size);
		priv->ipourma_ub_tx_seg[eid_idx][i] = ubcore_register_seg(priv->urma_dev,
									  &cfg, NULL);
		if (IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[eid_idx][i]))
			goto alloc_tx_bufs_failed;
	}
	for (i = 0; i < ipourma_tx_ring_size; i++) {
		priv->tx_ring[eid_idx][i].priv = priv;
		priv->tx_ring[eid_idx][i].idx = i;
		priv->tx_ring[eid_idx][i].eid_index = eid_idx;
		INIT_WORK(&(priv->tx_ring[eid_idx][i].work), ipourma_post_send);
		ipourma_init_tx_wr(&(priv->tx_ring[eid_idx][i]));
		ret = ipourma_alloc_tx_buf_aligned(priv, eid_idx, i);
		if (ret != IPOURMA_OK)
			goto alloc_tx_bufs_failed;
	}

	return ret;
alloc_tx_bufs_failed:
	ipourma_uninit_tx_bufs(priv, eid_idx);
	return IPOURMA_ADDRESS_NOT_ALIGNED;
}

static int ipourma_init_rx_bufs(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	struct ubcore_seg_cfg cfg = { 0 };
	int i;
	int ret;

	ret = IPOURMA_OK;
	priv->rx_buf_aligned[eid_idx] = kcalloc(priv->rx_buf_num, sizeof(u8 *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->rx_buf_aligned[eid_idx]))
		return IPOURMA_ADDRESS_NOT_ALIGNED;
	for (i = 0; i < priv->rx_buf_num; i++) {
		priv->rx_buf_aligned[eid_idx][i] = kzalloc(ipourma_register_seg_size,
							   GFP_KERNEL);
		if (IS_ERR_OR_NULL(priv->rx_buf_aligned[eid_idx][i])) {
			ret = IPOURMA_ADDRESS_NOT_ALIGNED;
			goto alloc_rx_buf_aligned_err;
		}
	}
	priv->ipourma_ub_rx_seg[eid_idx] = kcalloc(priv->rx_buf_num,
				sizeof(struct ubcore_target_seg *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[eid_idx])) {
		ret = IPOURMA_ADDRESS_NOT_ALIGNED;
		goto alloc_rx_seg_err;
	}
	for (i = 0; i < priv->rx_buf_num; i++) {
		ipourma_build_seg_cfg(&cfg, (u64)priv->rx_buf_aligned[eid_idx][i],
							ipourma_register_seg_size);
		priv->ipourma_ub_rx_seg[eid_idx][i] = ubcore_register_seg(priv->urma_dev,
										&cfg, NULL);
		if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[eid_idx][i])) {
			ret = IPOURMA_ADDRESS_NOT_ALIGNED;
			goto reg_rx_seg_err;
		}
	}

	for (i = 0; i < ipourma_rx_ring_size; i++) {
		priv->rx_ring[eid_idx][i].priv = priv;
		priv->rx_ring[eid_idx][i].idx = i;
		priv->rx_ring[eid_idx][i].eid_index = eid_idx;
		INIT_WORK(&(priv->rx_ring[eid_idx][i].work), ipourma_replenish_segments);
		ipourma_init_rx_wr(&(priv->rx_ring[eid_idx][i]));
	}

	return IPOURMA_OK;
reg_rx_seg_err:
	for (i--; i >= 0; i--) {
		if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[eid_idx][i]))
			continue;
		ubcore_unregister_seg(priv->ipourma_ub_rx_seg[eid_idx][i]);
		priv->ipourma_ub_rx_seg[eid_idx][i] = NULL;
	}
	kfree(priv->ipourma_ub_rx_seg[eid_idx]);
	priv->ipourma_ub_rx_seg[eid_idx] = NULL;
alloc_rx_seg_err:
	i = priv->rx_buf_num;
alloc_rx_buf_aligned_err:
	for (i--; i >= 0; i--) {
		if (IS_ERR_OR_NULL(priv->rx_buf_aligned[eid_idx][i]))
			continue;
		kfree(priv->rx_buf_aligned[eid_idx][i]);
		priv->rx_buf_aligned[eid_idx][i] = NULL;
	}
	kfree(priv->rx_buf_aligned[eid_idx]);
	priv->rx_buf_aligned[eid_idx] = NULL;
	return IPOURMA_ADDRESS_NOT_ALIGNED;
}

static void cleanup_tx_ring_by_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	struct ipourma_tx_buf *tx_ring = priv->tx_ring[eid_idx];
	unsigned long flags;

	if (IS_ERR_OR_NULL(tx_ring))
		return;

	spin_lock_irqsave(&priv->tx_ring_locks[eid_idx], flags);
	priv->tx_head[eid_idx] = 0;
	priv->tx_tail[eid_idx] = 0;
	priv->tx_ring_is_full[eid_idx] = false;
	for (u32 i = 0; i < ipourma_tx_ring_size; i++) {
		if (unlikely(tx_ring[i].tx_buf_in_use == 1)) {
			tx_ring[i].tx_buf_in_use = 0;
			dev_kfree_skb_any(tx_ring[i].skb);
		}
	}
	spin_unlock_irqrestore(&priv->tx_ring_locks[eid_idx], flags);
}

int ipourma_init_rings_by_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	int ret = IPOURMA_OK;

	priv->tx_ring[eid_idx] = vzalloc(sizeof(struct ipourma_tx_buf) * ipourma_tx_ring_size);
	if (IS_ERR_OR_NULL(priv->tx_ring[eid_idx]))
		return IPOURMA_ALLOC_TX_RING_FAILED;

	ret = ipourma_init_tx_bufs(priv, eid_idx);
	if (ret != IPOURMA_OK)
		goto init_tx_bufs_failed;

	priv->rx_ring[eid_idx] = kcalloc(ipourma_rx_ring_size, sizeof(struct ipourma_rx_buf),
								GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->rx_ring[eid_idx]))
		goto alloc_rx_ring_failed;

	ret = ipourma_init_rx_bufs(priv, eid_idx);
	if (ret != IPOURMA_OK)
		goto init_rx_bufs_failed;

	spin_lock_init(&priv->tx_ring_locks[eid_idx]);
	return ret;

init_rx_bufs_failed:
	kfree(priv->rx_ring[eid_idx]);
	priv->rx_ring[eid_idx] = NULL;
alloc_rx_ring_failed:
	ipourma_uninit_tx_bufs(priv, eid_idx);
init_tx_bufs_failed:
	vfree(priv->tx_ring[eid_idx]);
	priv->tx_ring[eid_idx] = NULL;
	return ret;
}

static void ipourma_reset_tx_bufs_by_eid(struct ipourma_dev_priv *priv,
					 struct ubcore_cr *cr, u32 eid_idx)
{
	struct ubcore_jetty_attr attr = {
		.mask = UBCORE_JETTY_STATE,
		.state = UBCORE_JETTY_STATE_ERROR,
	};
	struct net_device *dev = priv->dev;
	int tx_cr_num = 0;

	if (IS_ERR_OR_NULL(priv->jetty[eid_idx]))
		return;

	/* Clear the SQEs that have not been processed by the hardware */
	tx_cr_num = ubcore_flush_jetty(priv->jetty[eid_idx], ipourma_tx_ring_size, cr);
	if (unlikely(tx_cr_num < 0)) {
		netdev_err(dev, "%s\n", ipourma_err_desc(IPOURMA_FLUSH_JETTY_FAILED));
		return;
	}
	for (int j = 0; j < tx_cr_num; j++) {
		priv->runtime_stats.tx_stats.cqe_recved++;
		ipourma_handle_tx_wc(dev, priv, &cr[j]);
	}

	/* Clear the SQEs currently being processed by the hardware */
	if (unlikely(ubcore_modify_jetty(priv->jetty[eid_idx], &attr, NULL) != 0)) {
		netdev_err(dev, "%s\n", ipourma_err_desc(IPOURMA_MODIFY_JETTY_FAILED));
		return;
	}
	tx_cr_num = ubcore_poll_jfc(priv->tx_jfc, ipourma_tx_ring_size, cr);
	if (unlikely(tx_cr_num < 0)) {
		priv->runtime_stats.tx_stats.poll_jfc_failed++;
		netdev_err(dev, "%s:%d\n", ipourma_err_desc(IPOURMA_POLL_JFC_FAILED),
				tx_cr_num);
		return;
	}
	for (int i = 0; i < tx_cr_num; i++) {
		priv->runtime_stats.tx_stats.cqe_recved++;
		ipourma_handle_tx_wc(dev, priv, &cr[i]);
	}
}

static int ipourma_reset_tx_bufs(struct ipourma_dev_priv *priv, struct ubcore_cr *cr)
{
	if (IS_ERR_OR_NULL(priv->jetty))
		return IPOURMA_OK;
	for (u32 i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
		if (!IS_ERR_OR_NULL(cr))
			ipourma_reset_tx_bufs_by_eid(priv, cr, i);
		cleanup_tx_ring_by_eid(priv, i);
		ipourma_uninit_tx_bufs(priv, i);
	}
	atomic_set(&priv->tx_ring_blocked, 0);
	return IPOURMA_OK;
}

static void ipourma_reset_rx_buf_by_eid(struct ipourma_dev_priv *priv,
					struct ubcore_cr *cr, u32 eid_idx)
{
	struct ubcore_jfr_attr attr = {
		.mask = UBCORE_JFR_STATE,
		.state = UBCORE_JFR_STATE_ERROR,
	};
	struct net_device *dev = priv->dev;
	int rx_cr_num = 0;

	if (IS_ERR_OR_NULL(priv->jfr[eid_idx]))
		return;
	if (unlikely(ubcore_modify_jfr(priv->jfr[eid_idx], &attr, NULL) != 0)) {
		netdev_err(dev, "%s\n", ipourma_err_desc(IPOURMA_MODIFY_JFR_FAILED));
		return;
	}
	rx_cr_num = ubcore_poll_jfc(priv->rx_jfc, ipourma_rx_ring_size, cr);
	if (unlikely(rx_cr_num < 0)) {
		priv->runtime_stats.rx_stats.poll_jfc_failed++;
		netdev_dbg(dev, "%s:%d\n", ipourma_err_desc(IPOURMA_POLL_JFC_FAILED),
				rx_cr_num);
		return;
	}

	for (int i = 0; i < rx_cr_num; i++) {
		priv->runtime_stats.rx_stats.cqe_recved++;
		ipourma_handle_rx_wc(dev, priv, &cr[i]);
	}
}

static inline void ipourma_unregister_rx_seg_by_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	if (IS_ERR_OR_NULL(priv->rx_ring[eid_idx]))
		return;
	for (u32 i = 0; i < ipourma_rx_ring_size; i++) {
		if (!IS_ERR_OR_NULL(priv->rx_ring[eid_idx][i].seg[0]))
			priv->rx_ring[eid_idx][i].seg[0] = NULL;
	}
}

static int ipourma_reset_rx_bufs(struct ipourma_dev_priv *priv, struct ubcore_cr *cr)
{
	if (IS_ERR_OR_NULL(priv->jfr))
		return IPOURMA_OK;

	for (u32 i = 0; i < IPOURMA_MAX_EID_CNT; i++) {
		if (!IS_ERR_OR_NULL(cr))
			ipourma_reset_rx_buf_by_eid(priv, cr, i);
		ipourma_unregister_rx_seg_by_eid(priv, i);
		if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[i]))
			continue;
		for (u32 j = 0; j < priv->rx_buf_num; j++) {
			if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[i][j]))
				continue;
			ubcore_unregister_seg(priv->ipourma_ub_rx_seg[i][j]);
			priv->ipourma_ub_rx_seg[i][j] = NULL;
		}
	}
	return IPOURMA_OK;
}

void ipourma_reset_rings(struct ipourma_dev_priv *priv)
{
	size_t size = sizeof(struct ubcore_cr) * ipourma_rx_ring_size;
	struct ubcore_cr *cr = NULL;

	cr = vzalloc(size);
	if (IS_ERR_OR_NULL(cr))
		netdev_err(priv->dev, "%s\n", ipourma_err_desc(IPOURMA_ALLOC_CR_FAILED));

	ipourma_reset_tx_bufs(priv, cr);
	ipourma_reset_rx_bufs(priv, cr);
	for (u32 i = 0; i < IPOURMA_MAX_EID_CNT; i++)
		ipourma_uninit_urma_resources_by_eid(priv, i);
	if (!IS_ERR_OR_NULL(cr))
		vfree(cr);
}

static inline void ipourma_restart_rx_segments(struct ipourma_dev_priv *priv,
						struct ipourma_rx_buf *rx_req)
{
	struct ubcore_seg_cfg cfg = { 0 };

	ipourma_build_seg_cfg(&cfg, (u64)rx_req->buf_aligned, priv->skb_buf_size);
	ipourma_register_rx_segments(priv->dev, &cfg, rx_req);
}

static void ipourma_restart_rings_by_eid(struct ipourma_dev_priv *priv, int eid_idx)
{
	struct ubcore_seg_cfg cfg = {0};
	int ret = IPOURMA_OK;

	if (eid_is_empty(&priv->eid_info[eid_idx].eid) ||
		!IS_ERR_OR_NULL(priv->jetty[eid_idx]) ||
		!IS_ERR_OR_NULL(priv->jfr[eid_idx]))
		return;
	ret = ipourma_init_urma_resources_by_eid(priv, eid_idx);
	if (ret != IPOURMA_OK)
		return;
	ret = ipourma_init_tx_bufs(priv, eid_idx);
	if (ret != IPOURMA_OK)
		goto init_tx_bufs_err;

	for (int j = 0; j < priv->rx_buf_num; j++) {
		ipourma_build_seg_cfg(&cfg, (u64)priv->rx_buf_aligned[eid_idx][j],
						ipourma_register_seg_size);
		priv->ipourma_ub_rx_seg[eid_idx][j] = ubcore_register_seg(priv->urma_dev,
										&cfg, NULL);
		if (!IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[eid_idx][j]))
			continue;
		goto register_tx_seg_err;
	}
	for (int j = 0; j < ipourma_rx_ring_size; j++) {
		ipourma_restart_rx_segments(priv, &priv->rx_ring[eid_idx][j]);
		ipourma_urma_post_recv(priv->dev, eid_idx, j);
	}
register_tx_seg_err:
	ipourma_uninit_tx_bufs(priv, eid_idx);
init_tx_bufs_err:
	ipourma_uninit_urma_resources_by_eid(priv, eid_idx);
}

int ipourma_restart_rings(struct ipourma_dev_priv *priv)
{
	if (!priv->need_restart_ring) {
		priv->need_restart_ring = true;
		return IPOURMA_OK;
	}

	if (IS_ERR_OR_NULL(priv->jetty) || IS_ERR_OR_NULL(priv->jfr))
		return -EINVAL;
	for (int i = 0; i < IPOURMA_MAX_EID_CNT; i++)
		ipourma_restart_rings_by_eid(priv, i);

	if (IS_ERR_OR_NULL(priv->net_config_wq))
		return -EINVAL;
	queue_work(priv->net_config_wq, &(priv->set_ip));
	queue_work(priv->net_config_wq, &(priv->set_route));

	return IPOURMA_OK;
}

static int ipourma_init_rings_tables(struct net_device *dev)
{
	size_t size = sizeof(spinlock_t) * IPOURMA_MAX_EID_CNT;
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	int cnt = IPOURMA_MAX_EID_CNT;

	priv->tx_head = kcalloc(cnt, sizeof(u32), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_head))
		goto tx_head_failed;
	priv->tx_tail = kcalloc(cnt, sizeof(u32), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_tail))
		goto tx_tail_failed;
	priv->tx_count = kcalloc(cnt, sizeof(u32), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_count))
		goto tx_count_failed;
	priv->tx_ring = kcalloc(cnt, sizeof(struct ipourma_tx_buf *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_ring))
		goto tx_ring_failed;
	priv->rx_ring = kcalloc(cnt, sizeof(struct ipourma_rx_buf *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->rx_ring))
		goto rx_ring_failed;
	priv->tx_ring_locks = kzalloc(size, GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_ring_locks))
		goto tx_ring_locks_failed;
	return IPOURMA_OK;

tx_ring_locks_failed:
	kfree(priv->rx_ring);
rx_ring_failed:
	kfree(priv->tx_ring);
tx_ring_failed:
	kfree(priv->tx_count);
tx_count_failed:
	kfree(priv->tx_tail);
tx_tail_failed:
	kfree(priv->tx_head);
tx_head_failed:
	netdev_err(priv->dev, "%s\n", ipourma_err_desc(IPOURMA_INIT_RINGS_TABLE_FAILED));
	return IPOURMA_INIT_RINGS_TABLE_FAILED;
}

/**
 * @note: tx_buf & rx_buf are initialized dynamically
 */
int ipourma_init_rings(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	int ret = IPOURMA_OK;

	priv->skb_buf_size = priv->urma_mtu < IPOURMA_SEGMENT_ALIGN_SIZE ?
					IPOURMA_SEGMENT_ALIGN_SIZE : priv->urma_mtu;

	ret = ipourma_init_rings_tables(dev);
	if (ret != IPOURMA_OK)
		return ret;

	if (priv->urma_mtu > IPOURMA_SEGMENT_ALIGN_SIZE) {
		priv->tx_buf_size = (priv->urma_mtu + IPOURMA_SEGMENT_ALIGN_SIZE - 1) &
							~(IPOURMA_SEGMENT_ALIGN_SIZE - 1);
	} else {
		priv->tx_buf_size = IPOURMA_SEGMENT_ALIGN_SIZE;
	}
	priv->rx_buf_num = DIV_ROUND_UP(ipourma_rx_ring_size * priv->skb_buf_size,
					ipourma_register_seg_size);
	priv->tx_buf_num = DIV_ROUND_UP(ipourma_tx_ring_size * priv->tx_buf_size,
					ipourma_register_seg_size);

	return ret;
}

void ipourma_uninit_tjetty_hmap(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	cancel_delayed_work_sync(&priv->tjetty_lru.tjetty_aging_work);
	ipourma_lru_clear(&priv->tjetty_lru);
	kfree(priv->tjetty_lru.tjetty_hmap.buckets);
	priv->tjetty_lru.tjetty_hmap.buckets = NULL;
}

int ipourma_init_tjetty_hmap(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct ipourma_tjetty_hmap *tjetty_hmap = &priv->tjetty_lru.tjetty_hmap;
	int ret = IPOURMA_OK;

	tjetty_hmap->hash_seed = get_random_u32();
	tjetty_hmap->buckets =
		kcalloc(IPOURMA_TJETTY_HMAP_SIZE, sizeof(struct hlist_head), GFP_KERNEL);
	if (IS_ERR_OR_NULL(tjetty_hmap->buckets)) {
		netdev_warn(priv->dev, "%s\n",
			ipourma_err_desc(IPOURMA_INIT_TJETTY_HMAP_FAILED));
		return IPOURMA_INIT_TJETTY_HMAP_FAILED;
	}

	for (int i = 0; i < IPOURMA_TJETTY_HMAP_SIZE; i++)
		INIT_HLIST_HEAD(tjetty_hmap->buckets + i);

	ipourma_init_tjetty_aging_work(&priv->tjetty_lru);

	return ret;
}

static int ipourma_jetty_set_priority(struct ipourma_dev_priv *priv,
					struct ubcore_jetty_cfg *jetty_cfg)
{
	if (jetty_cfg->trans_mode == UBCORE_TP_RM) {
		jetty_cfg->priority = ipourma_ctp_sl;
		netdev_info(priv->dev,
					"ipourma create jetty set priority : %d, ty_type : ctp\n",
					ipourma_ctp_sl);
	} else if (jetty_cfg->trans_mode == UBCORE_TP_UM) {
		jetty_cfg->priority = ipourma_utp_sl;
		netdev_info(priv->dev,
					"ipourma create jetty set priority : %d, ty_type : utp\n",
					ipourma_utp_sl);
	} else
		return -EINVAL;
	return IPOURMA_OK;
}

static struct ubcore_jfr *ipourma_create_jfr(
	struct net_device *dev, u32 depth, u32 eid_index)
{
	struct ubcore_jfr_cfg jfr_cfg = { 0 };
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	jfr_cfg.depth = depth;
	jfr_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	jfr_cfg.trans_mode = priv->urma_transport_mode;
	jfr_cfg.eid_index = priv->eid_info[eid_index].eid_index;
	jfr_cfg.max_sge = IPOURMA_MAX_URMA_RECV_SGES;
	jfr_cfg.jfc = priv->rx_jfc;

	return ubcore_create_jfr(priv->urma_dev, &jfr_cfg, NULL, NULL);
}

static struct ubcore_jetty *ipourma_create_jetty(struct net_device *dev,
	u32 jetty_id, u32 eid_index)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	struct ubcore_jetty_cfg jetty_cfg = {0};
	int max_send_sge;
	int max_recv_sge;

	max_send_sge = (IPOURMA_MAX_TX_SGES < IPOURMA_MAX_URMA_SEND_SGES) ?
		IPOURMA_MAX_TX_SGES : IPOURMA_MAX_URMA_SEND_SGES;
	max_recv_sge = (IPOURMA_MAX_RX_SGES < IPOURMA_MAX_URMA_RECV_SGES) ?
		IPOURMA_MAX_RX_SGES : IPOURMA_MAX_URMA_RECV_SGES;

	/* some values should dynamically get from the device */
	jetty_cfg.id = jetty_id;
	jetty_cfg.flag.bs.share_jfr = 1;
	jetty_cfg.trans_mode = priv->urma_transport_mode;
	jetty_cfg.eid_index = priv->eid_info[eid_index].eid_index;
	jetty_cfg.jfs_depth = IPOURMA_JFS_DEPTH;
	jetty_cfg.priority = 0;
	jetty_cfg.max_send_sge = max_send_sge;
	jetty_cfg.max_send_rsge = IPOURMA_MAX_URMA_RECV_SGES;
	jetty_cfg.jfr_depth = ipourma_jfr_depth;
	jetty_cfg.max_recv_sge = max_recv_sge;
	jetty_cfg.send_jfc = priv->tx_jfc;
	jetty_cfg.recv_jfc = priv->rx_jfc;
	jetty_cfg.jfr = priv->jfr[eid_index];
	if (ipourma_jetty_set_priority(priv, &jetty_cfg) != IPOURMA_OK)
		return NULL;

	return ubcore_create_jetty(priv->urma_dev, &jetty_cfg, NULL, NULL);
}

static struct ubcore_jfc *ipourma_create_jfc(struct net_device *dev,
					     ubcore_comp_callback_t jfce_handler,
					     u32 depth)
{
	struct ubcore_jfc_cfg jfc_cfg = { 0 };
	struct ubcore_jfc *jfc = NULL;
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	jfc_cfg.depth = depth;
	jfc = ubcore_create_jfc(priv->urma_dev, &jfc_cfg, jfce_handler, NULL, NULL);
	if (IS_ERR_OR_NULL(jfc)) {
		netdev_warn(dev, "%s\n", ipourma_err_desc(IPOURMA_CREATE_JFC_FAILED));
		return NULL;
	}
	if (ubcore_rearm_jfc(jfc, false) != 0)
		netdev_warn(dev, "%s\n", ipourma_err_desc(IPOURMA_REARM_JFC_FAILED));

	return jfc;
}

static void ipourma_uninit_misc(struct ipourma_dev_priv *priv)
{
	struct ipourma_set_ip_work *set_ip_work, *next_work;

	spin_lock(&priv->set_ip_lock);
	atomic_set(&priv->need_set_ip, 0);
	list_for_each_entry_safe(set_ip_work, next_work, &priv->set_ip_list, list) {
		list_del(&set_ip_work->list);
		/* set_ip_work may schedule itself, cancel twice to make sure need_set_ip work */
		cancel_delayed_work_sync(&set_ip_work->d_work);
		cancel_delayed_work_sync(&set_ip_work->d_work);
		kfree(set_ip_work);
	}
	spin_unlock(&priv->set_ip_lock);

	if (!IS_ERR_OR_NULL(priv->tjetty_lru.tjetty_wq)) {
		flush_workqueue(priv->tjetty_lru.tjetty_wq);
		destroy_workqueue(priv->tjetty_lru.tjetty_wq);
		priv->tjetty_lru.tjetty_wq = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->net_config_wq)) {
		cancel_delayed_work_sync(&priv->redundant_dwork);
		flush_workqueue(priv->net_config_wq);
		destroy_workqueue(priv->net_config_wq);
		priv->net_config_wq = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->rx_wq)) {
		destroy_workqueue(priv->rx_wq);
		priv->rx_wq = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->tx_wq)) {
		destroy_workqueue(priv->tx_wq);
		priv->tx_wq = NULL;
	}
}

static void ipourma_uninit_urma_resources_table(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	if (!IS_ERR_OR_NULL(priv->jetty)) {
		kfree(priv->jetty);
		priv->jetty = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->jfr)) {
		kfree(priv->jfr);
		priv->jfr = NULL;
	}
}

void ipourma_uninit_urma_resources_by_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	if (!IS_ERR_OR_NULL(priv->jetty) && !IS_ERR_OR_NULL(priv->jetty[eid_idx])) {
		ubcore_delete_jetty(priv->jetty[eid_idx]);
		priv->jetty[eid_idx] = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->jfr) && !IS_ERR_OR_NULL(priv->jfr[eid_idx])) {
		ubcore_delete_jfr(priv->jfr[eid_idx]);
		priv->jfr[eid_idx] = NULL;
	}
}

void ipourma_uninit_urma_resources(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	ipourma_uninit_misc(priv);

	if (IS_ERR_OR_NULL(priv->jetty))
		return;
	for (int i = 0; i < IPOURMA_MAX_EID_CNT; i++)
		ipourma_uninit_urma_resources_by_eid(priv, i);
	ipourma_uninit_urma_resources_table(dev);
	if (!IS_ERR_OR_NULL(priv->rx_jfc)) {
		ubcore_delete_jfc(priv->rx_jfc);
		priv->rx_jfc = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->tx_jfc)) {
		ubcore_delete_jfc(priv->tx_jfc);
		priv->tx_jfc = NULL;
	}
}

static int ipourma_init_misc(struct ipourma_dev_priv *priv)
{
	int ctp_en = 0;

	priv->max_send_sge = IPOURMA_MAX_URMA_SEND_SGES;
	priv->urma_mtu = IPOURMA_URMA_MAX_MTU;
	priv->urma_op_mode = UBCORE_OPC_SEND;
	priv->urma_transport_mode = ctp_en ? UBCORE_TP_RM : UBCORE_TP_UM;

	priv->tjetty_lru.tjetty_wq = alloc_workqueue("ipourma_tjetty_wq", WQ_MEM_RECLAIM, 0);
	if (IS_ERR_OR_NULL(priv->tjetty_lru.tjetty_wq))
		goto tjetty_wq_failed;

	priv->tx_wq = alloc_ordered_workqueue("ipourma_tx_wq", 0);
	if (IS_ERR_OR_NULL(priv->tx_wq))
		goto tx_wq_failed;

	priv->rx_wq = alloc_workqueue("ipourma_rx_wq", WQ_MEM_RECLAIM, 0);
	if (IS_ERR_OR_NULL(priv->rx_wq))
		goto rx_wq_failed;

	/* Net configurations should be called in order. */
	priv->net_config_wq = alloc_ordered_workqueue("net_config_wq", 0);
	if (IS_ERR_OR_NULL(priv->net_config_wq))
		goto net_config_wq_failed;

	return IPOURMA_OK;
net_config_wq_failed:
	destroy_workqueue(priv->rx_wq);
	priv->rx_wq = NULL;
rx_wq_failed:
	destroy_workqueue(priv->tx_wq);
	priv->tx_wq = NULL;
tx_wq_failed:
	destroy_workqueue(priv->tjetty_lru.tjetty_wq);
	priv->tjetty_lru.tjetty_wq = NULL;
tjetty_wq_failed:
	return -1;
}

static int ipourma_init_urma_resources_table(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	int ret = IPOURMA_OK;

	priv->jfr = kcalloc(IPOURMA_MAX_EID_CNT, sizeof(struct ubcore_jfr *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->jfr)) {
		ret = IPOURMA_CREATE_JFR_TABLE_FAILED;
		goto jfr_table_failed;
	}
	priv->jetty = kcalloc(IPOURMA_MAX_EID_CNT, sizeof(struct ubcore_jetty *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->jetty)) {
		ret = IPOURMA_CREATE_JETTY_TABLE_FAILED;
		goto jetty_table_failed;
	}
	return ret;
jetty_table_failed:
	kfree(priv->jfr);
	priv->jfr = NULL;
jfr_table_failed:
	return ret;
}

static bool ipourma_check_dev_name(struct net_device *dev)
{
	char buf[IPOURMA_MAX_DEV_NAME] = {0};
	u16 dev_num = 0;
	int ret = 0;

	if (IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(dev->name))
		return false;
	ret = sscanf(dev->name, "ipourma%hu", &dev_num);
	if (ret != 1)
		return false;
	ret = snprintf(buf, IPOURMA_MAX_DEV_NAME, "ipourma%hu", dev_num);
	if (ret <= 0 || strcmp(buf, dev->name) != 0)
		return false;
	return true;
}

int ipourma_init_urma_resources_by_eid(struct ipourma_dev_priv *priv, u32 eid_idx)
{
	struct net_device *dev = priv->dev;
	int ret = IPOURMA_OK;

	if (!ipourma_check_dev_name(dev)) {
		ret = IPOURMA_INVALID_DEV_NAME;
		goto invalid_name;
	}

	priv->jfr[eid_idx] = ipourma_create_jfr(dev, ipourma_jfr_depth, eid_idx);
	if (IS_ERR_OR_NULL(priv->jfr[eid_idx])) {
		ret = IPOURMA_CREATE_JFR_FAILED;
		pr_err("create jfr error, dev: %s, i = %u\n", dev->name, eid_idx);
		goto jfr_failed;
	}
	priv->jetty[eid_idx] = ipourma_create_jetty(dev,
				IPOURMA_WELL_KNOWN_JETTY_ID + eid_idx, eid_idx);
	if (IS_ERR_OR_NULL(priv->jetty[eid_idx])) {
		ret = IPOURMA_CREATE_JETTY_FAILED;
		pr_err("create tx jetty error, dev: %s, i = %u\n", dev->name, eid_idx);
		goto jetty_failed;
	}

	return ret;

jetty_failed:
	ubcore_delete_jfr(priv->jfr[eid_idx]);
	priv->jfr[eid_idx] = NULL;
jfr_failed:
	return ret;
invalid_name:
	return ret;
}

int ipourma_init_urma_resources(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	int ret = IPOURMA_OK;

	if (!ipourma_check_dev_name(dev))
		goto invalid_name;

	ret = ipourma_init_urma_resources_table(dev);
	if (ret != IPOURMA_OK)
		goto init_table_failed;

	priv->tx_jfc = ipourma_create_jfc(dev, ipourma_handle_tx_cqe,
								ipourma_tx_jfc_depth);
	if (IS_ERR_OR_NULL(priv->tx_jfc)) {
		ret = IPOURMA_CREATE_JFC_FAILED;
		pr_err("create tx jfc error, dev: %s\n", dev->name);
		goto tx_jfc_failed;
	}
	priv->rx_jfc = ipourma_create_jfc(dev, ipourma_handle_rx_cqe,
								ipourma_rx_jfc_depth);
	if (IS_ERR_OR_NULL(priv->rx_jfc)) {
		ret = IPOURMA_CREATE_JFC_FAILED;
		pr_err("create rx jfc error, dev: %s\n", dev->name);
		goto rx_jfc_failed;
	}

	ret = ipourma_init_misc(priv);
	if (ret != IPOURMA_OK) {
		pr_err("%s create wq failed.\n", dev->name);
		goto init_misc_failed;
	}

	return ret;

init_misc_failed:
	ubcore_delete_jfc(priv->rx_jfc);
rx_jfc_failed:
	ubcore_delete_jfc(priv->tx_jfc);
	priv->tx_jfc = NULL;
tx_jfc_failed:
	ipourma_uninit_urma_resources_table(priv->dev);
init_table_failed:
	return ret;
invalid_name:
	return ret;
}
