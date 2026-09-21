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

static int ipourma_adjust_ring_size(struct ipourma_dev_priv *priv)
{
	struct ubcore_device_attr attr = {0};
	u32 tx_ring, rx_ring;
	int ret;

	ret = ubcore_query_device_attr(priv->urma_dev, &attr);
	if (ret != 0) {
		netdev_err(priv->dev, "query device attr failed, ret = %d\n", ret);
		return ret;
	}

	priv->jetty_cnt = (u32)ipourma_min_eid_cnt;
	if (priv->jetty_cnt > attr.dev_cap.max_jetty) {
		netdev_err(priv->dev, "jetty cnt %u exceeds device max_jetty %u\n",
			priv->jetty_cnt, attr.dev_cap.max_jetty);
		return -EINVAL;
	}

	tx_ring = min(ipourma_tx_ring_size, attr.dev_cap.max_jfs_depth);
	rx_ring = min(ipourma_rx_ring_size, attr.dev_cap.max_jfr_depth);
	tx_ring = min(tx_ring, attr.dev_cap.max_jfc_depth / priv->jetty_cnt);
	rx_ring = min(rx_ring, attr.dev_cap.max_jfc_depth / priv->jetty_cnt);
	if (tx_ring == 0 || rx_ring == 0) {
		netdev_err(priv->dev,
			"device capability clips ring size to 0, tx %u rx %u, max_jfs %u max_jfr %u max_jfc %u\n",
			tx_ring, rx_ring, attr.dev_cap.max_jfs_depth,
			attr.dev_cap.max_jfr_depth, attr.dev_cap.max_jfc_depth);
		return -EINVAL;
	}

	if (tx_ring < IPOURMA_MIN_TX_RING_SIZE)
		netdev_warn(priv->dev,
			"tx ring size %u is below the minimum %u, limited by device capability\n",
			tx_ring, IPOURMA_MIN_TX_RING_SIZE);
	if (rx_ring < IPOURMA_MIN_RX_RING_SIZE)
		netdev_warn(priv->dev,
			"rx ring size %u is below the minimum %u, limited by device capability\n",
			rx_ring, IPOURMA_MIN_RX_RING_SIZE);

	priv->tx_ring_size = tx_ring;
	priv->rx_ring_size = rx_ring;
	priv->jfs_depth = tx_ring;
	priv->jfr_depth = rx_ring;
	priv->tx_jfc_depth = tx_ring * priv->jetty_cnt;
	priv->rx_jfc_depth = rx_ring * priv->jetty_cnt;

	netdev_info(priv->dev, "ipourma jetty cnt: %u, tx ring size: %u, rx ring size: %u\n",
		priv->jetty_cnt, priv->tx_ring_size, priv->rx_ring_size);
	return IPOURMA_OK;
}

static void ipourma_uninit_tx_bufs(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	if (IS_ERR_OR_NULL(priv->tx_ring) || IS_ERR_OR_NULL(priv->tx_ring[jetty_idx]))
		return;
	for (u32 i = 0; i < priv->tx_ring_size; i++) {
		priv->tx_ring[jetty_idx][i].seg[0] = NULL;
		priv->tx_ring[jetty_idx][i].buf_aligned = NULL;
	}

	if (!IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg) &&
		!IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[jetty_idx])) {
		for (size_t i = 0; i < priv->tx_buf_num; i++) {
			if (IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[jetty_idx][i]))
				continue;
			ubcore_unregister_seg(priv->ipourma_ub_tx_seg[jetty_idx][i]);
			priv->ipourma_ub_tx_seg[jetty_idx][i] = NULL;
		}
		kfree(priv->ipourma_ub_tx_seg[jetty_idx]);
		priv->ipourma_ub_tx_seg[jetty_idx] = NULL;
	}

	if (!IS_ERR_OR_NULL(priv->tx_buf_aligned) &&
		!IS_ERR_OR_NULL(priv->tx_buf_aligned[jetty_idx])) {
		for (size_t i = 0; i < priv->tx_buf_num; i++) {
			if (IS_ERR_OR_NULL(priv->tx_buf_aligned[jetty_idx][i]))
				continue;
			kfree(priv->tx_buf_aligned[jetty_idx][i]);
			priv->tx_buf_aligned[jetty_idx][i] = NULL;
		}
		kfree(priv->tx_buf_aligned[jetty_idx]);
		priv->tx_buf_aligned[jetty_idx] = NULL;
	}
}

void ipourma_uninit_rx_bufs(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	if (IS_ERR_OR_NULL(priv->rx_ring) || IS_ERR_OR_NULL(priv->rx_ring[jetty_idx]))
		return;
	for (u32 i = 0; i < priv->rx_ring_size; i++) {
		if (!IS_ERR_OR_NULL(priv->rx_ring[jetty_idx][i].seg[0]))
			priv->rx_ring[jetty_idx][i].seg[0] = NULL;
		if (!IS_ERR_OR_NULL(priv->rx_ring[jetty_idx][i].buf_aligned))
			priv->rx_ring[jetty_idx][i].buf_aligned = NULL;

		if (!IS_ERR_OR_NULL(priv->rx_ring[jetty_idx][i].skb_pass_up)) {
			dev_kfree_skb_any(priv->rx_ring[jetty_idx][i].skb_pass_up);
			priv->rx_ring[jetty_idx][i].skb_pass_up = NULL;
		}
	}

	if (!IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg) &&
		!IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[jetty_idx])) {
		for (size_t i = 0; i < priv->rx_buf_num; i++) {
			if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[jetty_idx][i]))
				continue;
			ubcore_unregister_seg(priv->ipourma_ub_rx_seg[jetty_idx][i]);
			priv->ipourma_ub_rx_seg[jetty_idx][i] = NULL;
		}
		kfree(priv->ipourma_ub_rx_seg[jetty_idx]);
		priv->ipourma_ub_rx_seg[jetty_idx] = NULL;
	}

	if (IS_ERR_OR_NULL(priv->rx_buf_aligned) ||
		IS_ERR_OR_NULL(priv->rx_buf_aligned[jetty_idx]))
		return;
	for (u32 i = 0; i < priv->rx_buf_num; i++) {
		if (IS_ERR_OR_NULL(priv->rx_buf_aligned[jetty_idx][i]))
			continue;
		kfree(priv->rx_buf_aligned[jetty_idx][i]);
		priv->rx_buf_aligned[jetty_idx][i] = NULL;
	}
	kfree(priv->rx_buf_aligned[jetty_idx]);
	priv->rx_buf_aligned[jetty_idx] = NULL;
}

void ipourma_uninit_rings_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	if (!IS_ERR_OR_NULL(priv->tx_ring) && !IS_ERR_OR_NULL(priv->tx_ring[jetty_idx])) {
		ipourma_uninit_tx_bufs(priv, jetty_idx);
		vfree(priv->tx_ring[jetty_idx]);
		priv->tx_ring[jetty_idx] = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->rx_ring) && !IS_ERR_OR_NULL(priv->rx_ring[jetty_idx])) {
		ipourma_uninit_rx_bufs(priv, jetty_idx);
		kfree(priv->rx_ring[jetty_idx]);
		priv->rx_ring[jetty_idx] = NULL;
	}
}

void ipourma_uninit_rings(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	if (!IS_ERR_OR_NULL(priv->tx_ring)) {
		for (u32 i = 0; i < priv->jetty_cnt; i++) {
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
		for (u32 i = 0; i < priv->jetty_cnt; i++) {
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
	if (!IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg)) {
		kfree(priv->ipourma_ub_tx_seg);
		priv->ipourma_ub_tx_seg = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg)) {
		kfree(priv->ipourma_ub_rx_seg);
		priv->ipourma_ub_rx_seg = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->tx_buf_aligned)) {
		kfree(priv->tx_buf_aligned);
		priv->tx_buf_aligned = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->rx_buf_aligned)) {
		kfree(priv->rx_buf_aligned);
		priv->rx_buf_aligned = NULL;
	}
}

static int ipourma_alloc_tx_buf_aligned(struct ipourma_dev_priv *priv, u32 jetty_idx, u32 idx)
{
	u32 blk_idx = idx / priv->tx_bufs_per_blk;
	u32 offset = (idx % priv->tx_bufs_per_blk) * priv->tx_buf_size;
	struct ipourma_tx_buf *tx_buf = &priv->tx_ring[jetty_idx][idx];

	tx_buf->buf_aligned = priv->tx_buf_aligned[jetty_idx][blk_idx] + offset;

	if (IS_ERR_OR_NULL(tx_buf->buf_aligned)) {
		tx_buf->buf_aligned = NULL;
		return IPOURMA_ADDRESS_NOT_ALIGNED;
	}

	tx_buf->seg[0] = priv->ipourma_ub_tx_seg[jetty_idx][blk_idx];
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

static int ipourma_init_tx_bufs(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	struct ubcore_seg_cfg cfg = { 0 };
	int ret = IPOURMA_OK;
	u32 i;

	priv->tx_buf_aligned[jetty_idx] = kcalloc(priv->tx_buf_num, sizeof(u8 *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_buf_aligned[jetty_idx]))
		goto alloc_tx_bufs_failed;
	priv->ipourma_ub_tx_seg[jetty_idx] = kcalloc(priv->tx_buf_num,
						   sizeof(struct ubcore_target_seg **),
						   GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[jetty_idx]))
		goto alloc_tx_bufs_failed;
	for (i = 0; i < priv->tx_buf_num; i++) {
		priv->tx_buf_aligned[jetty_idx][i] = kzalloc(ipourma_register_seg_size, GFP_KERNEL);
		if (IS_ERR_OR_NULL(priv->tx_buf_aligned[jetty_idx][i]))
			goto alloc_tx_bufs_failed;
		ipourma_build_seg_cfg(&cfg, (u64)priv->tx_buf_aligned[jetty_idx][i],
						ipourma_register_seg_size);
		priv->ipourma_ub_tx_seg[jetty_idx][i] = ubcore_register_seg(priv->urma_dev,
									  &cfg, NULL);
		if (IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg[jetty_idx][i]))
			goto alloc_tx_bufs_failed;
	}
	for (i = 0; i < priv->tx_ring_size; i++) {
		priv->tx_ring[jetty_idx][i].priv = priv;
		priv->tx_ring[jetty_idx][i].idx = i;
		priv->tx_ring[jetty_idx][i].jetty_index = jetty_idx;
		INIT_WORK(&(priv->tx_ring[jetty_idx][i].work), ipourma_post_send);
		ipourma_init_tx_wr(&(priv->tx_ring[jetty_idx][i]));
		ret = ipourma_alloc_tx_buf_aligned(priv, jetty_idx, i);
		if (ret != IPOURMA_OK)
			goto alloc_tx_bufs_failed;
	}

	return ret;
alloc_tx_bufs_failed:
	ipourma_uninit_tx_bufs(priv, jetty_idx);
	return IPOURMA_ADDRESS_NOT_ALIGNED;
}

static int ipourma_init_rx_bufs(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	struct ubcore_seg_cfg cfg = { 0 };
	int i;
	int ret;

	ret = IPOURMA_OK;
	priv->rx_buf_aligned[jetty_idx] = kcalloc(priv->rx_buf_num, sizeof(u8 *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->rx_buf_aligned[jetty_idx]))
		return IPOURMA_ADDRESS_NOT_ALIGNED;
	for (i = 0; i < priv->rx_buf_num; i++) {
		priv->rx_buf_aligned[jetty_idx][i] = kzalloc(ipourma_register_seg_size,
							   GFP_KERNEL);
		if (IS_ERR_OR_NULL(priv->rx_buf_aligned[jetty_idx][i])) {
			ret = IPOURMA_ADDRESS_NOT_ALIGNED;
			goto alloc_rx_buf_aligned_err;
		}
	}
	priv->ipourma_ub_rx_seg[jetty_idx] = kcalloc(priv->rx_buf_num,
				sizeof(struct ubcore_target_seg *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[jetty_idx])) {
		ret = IPOURMA_ADDRESS_NOT_ALIGNED;
		goto alloc_rx_seg_err;
	}
	for (i = 0; i < priv->rx_buf_num; i++) {
		ipourma_build_seg_cfg(&cfg, (u64)priv->rx_buf_aligned[jetty_idx][i],
							ipourma_register_seg_size);
		priv->ipourma_ub_rx_seg[jetty_idx][i] = ubcore_register_seg(priv->urma_dev,
										&cfg, NULL);
		if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[jetty_idx][i])) {
			ret = IPOURMA_ADDRESS_NOT_ALIGNED;
			goto reg_rx_seg_err;
		}
	}

	for (i = 0; i < priv->rx_ring_size; i++) {
		priv->rx_ring[jetty_idx][i].priv = priv;
		priv->rx_ring[jetty_idx][i].idx = i;
		priv->rx_ring[jetty_idx][i].jetty_index = jetty_idx;
		INIT_WORK(&(priv->rx_ring[jetty_idx][i].work), ipourma_replenish_segments);
		ipourma_init_rx_wr(&(priv->rx_ring[jetty_idx][i]));
	}

	return IPOURMA_OK;
reg_rx_seg_err:
	for (i--; i >= 0; i--) {
		if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[jetty_idx][i]))
			continue;
		ubcore_unregister_seg(priv->ipourma_ub_rx_seg[jetty_idx][i]);
		priv->ipourma_ub_rx_seg[jetty_idx][i] = NULL;
	}
	kfree(priv->ipourma_ub_rx_seg[jetty_idx]);
	priv->ipourma_ub_rx_seg[jetty_idx] = NULL;
alloc_rx_seg_err:
	i = priv->rx_buf_num;
alloc_rx_buf_aligned_err:
	for (i--; i >= 0; i--) {
		if (IS_ERR_OR_NULL(priv->rx_buf_aligned[jetty_idx][i]))
			continue;
		kfree(priv->rx_buf_aligned[jetty_idx][i]);
		priv->rx_buf_aligned[jetty_idx][i] = NULL;
	}
	kfree(priv->rx_buf_aligned[jetty_idx]);
	priv->rx_buf_aligned[jetty_idx] = NULL;
	return IPOURMA_ADDRESS_NOT_ALIGNED;
}

static void cleanup_tx_ring_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	struct ipourma_tx_buf *tx_ring = priv->tx_ring[jetty_idx];
	unsigned long flags;

	if (IS_ERR_OR_NULL(tx_ring))
		return;

	spin_lock_irqsave(&priv->tx_ring_locks[jetty_idx], flags);
	priv->tx_head[jetty_idx] = 0;
	priv->tx_tail[jetty_idx] = 0;
	priv->tx_ring_is_full[jetty_idx] = false;
	for (u32 i = 0; i < priv->tx_ring_size; i++) {
		if (unlikely(tx_ring[i].tx_buf_in_use == 1)) {
			tx_ring[i].tx_buf_in_use = 0;
			dev_kfree_skb_any(tx_ring[i].skb);
		}
	}
	spin_unlock_irqrestore(&priv->tx_ring_locks[jetty_idx], flags);
}

int ipourma_init_rings_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	int ret = IPOURMA_OK;

	priv->tx_ring[jetty_idx] = vzalloc(sizeof(struct ipourma_tx_buf) * priv->tx_ring_size);
	if (IS_ERR_OR_NULL(priv->tx_ring[jetty_idx]))
		return IPOURMA_ALLOC_TX_RING_FAILED;

	ret = ipourma_init_tx_bufs(priv, jetty_idx);
	if (ret != IPOURMA_OK)
		goto init_tx_bufs_failed;

	priv->rx_ring[jetty_idx] = kcalloc(priv->rx_ring_size, sizeof(struct ipourma_rx_buf),
								GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->rx_ring[jetty_idx]))
		goto alloc_rx_ring_failed;

	ret = ipourma_init_rx_bufs(priv, jetty_idx);
	if (ret != IPOURMA_OK)
		goto init_rx_bufs_failed;

	spin_lock_init(&priv->tx_ring_locks[jetty_idx]);
	return ret;

init_rx_bufs_failed:
	kfree(priv->rx_ring[jetty_idx]);
	priv->rx_ring[jetty_idx] = NULL;
alloc_rx_ring_failed:
	ipourma_uninit_tx_bufs(priv, jetty_idx);
init_tx_bufs_failed:
	vfree(priv->tx_ring[jetty_idx]);
	priv->tx_ring[jetty_idx] = NULL;
	return ret;
}

static void ipourma_reset_tx_bufs_by_jetty(struct ipourma_dev_priv *priv,
					 struct ubcore_cr *cr, u32 jetty_idx)
{
	struct ubcore_jetty_attr attr = {
		.mask = UBCORE_JETTY_STATE,
		.state = UBCORE_JETTY_STATE_ERROR,
	};
	struct net_device *dev = priv->dev;
	int tx_cr_num = 0;

	if (IS_ERR_OR_NULL(priv->jetty[jetty_idx]))
		return;

	/* Clear the SQEs that have not been processed by the hardware */
	tx_cr_num = ubcore_flush_jetty(priv->jetty[jetty_idx], priv->tx_ring_size, cr);
	if (unlikely(tx_cr_num < 0)) {
		netdev_err(dev, "%s\n", ipourma_err_desc(IPOURMA_FLUSH_JETTY_FAILED));
		return;
	}
	for (int j = 0; j < tx_cr_num; j++) {
		priv->runtime_stats.tx_stats.cqe_recved++;
		ipourma_handle_tx_wc(dev, priv, &cr[j]);
	}

	/* Clear the SQEs currently being processed by the hardware */
	if (unlikely(ubcore_modify_jetty(priv->jetty[jetty_idx], &attr, NULL) != 0)) {
		netdev_err(dev, "%s\n", ipourma_err_desc(IPOURMA_MODIFY_JETTY_FAILED));
		return;
	}
	tx_cr_num = ubcore_poll_jfc(priv->tx_jfc, priv->tx_ring_size, cr);
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
	for (u32 i = 0; i < priv->jetty_cnt; i++) {
		if (!IS_ERR_OR_NULL(cr))
			ipourma_reset_tx_bufs_by_jetty(priv, cr, i);
		cleanup_tx_ring_by_jetty(priv, i);
		ipourma_uninit_tx_bufs(priv, i);
	}
	atomic_set(&priv->tx_ring_blocked, 0);
	return IPOURMA_OK;
}

static void ipourma_reset_rx_buf_by_jetty(struct ipourma_dev_priv *priv,
					struct ubcore_cr *cr, u32 jetty_idx)
{
	struct ubcore_jfr_attr attr = {
		.mask = UBCORE_JFR_STATE,
		.state = UBCORE_JFR_STATE_ERROR,
	};
	struct net_device *dev = priv->dev;
	int rx_cr_num = 0;

	if (IS_ERR_OR_NULL(priv->jfr[jetty_idx]))
		return;
	if (unlikely(ubcore_modify_jfr(priv->jfr[jetty_idx], &attr, NULL) != 0)) {
		netdev_err(dev, "%s\n", ipourma_err_desc(IPOURMA_MODIFY_JFR_FAILED));
		return;
	}
	rx_cr_num = ubcore_poll_jfc(priv->rx_jfc, priv->rx_ring_size, cr);
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

static inline void ipourma_unregister_rx_seg_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	if (IS_ERR_OR_NULL(priv->rx_ring[jetty_idx]))
		return;
	for (u32 i = 0; i < priv->rx_ring_size; i++) {
		if (!IS_ERR_OR_NULL(priv->rx_ring[jetty_idx][i].seg[0]))
			priv->rx_ring[jetty_idx][i].seg[0] = NULL;
	}
}

static int ipourma_reset_rx_bufs(struct ipourma_dev_priv *priv, struct ubcore_cr *cr)
{
	if (IS_ERR_OR_NULL(priv->jfr))
		return IPOURMA_OK;

	for (u32 i = 0; i < priv->jetty_cnt; i++) {
		if (!IS_ERR_OR_NULL(cr))
			ipourma_reset_rx_buf_by_jetty(priv, cr, i);
		ipourma_unregister_rx_seg_by_jetty(priv, i);
		if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg) ||
			IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[i]))
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
	size_t size = sizeof(struct ubcore_cr) *
		max(priv->tx_ring_size, priv->rx_ring_size);
	struct ubcore_cr *cr = NULL;

	cr = vzalloc(size);
	if (IS_ERR_OR_NULL(cr))
		netdev_err(priv->dev, "%s\n", ipourma_err_desc(IPOURMA_ALLOC_CR_FAILED));

	ipourma_reset_tx_bufs(priv, cr);
	ipourma_reset_rx_bufs(priv, cr);
	for (u32 i = 0; i < priv->jetty_cnt; i++)
		ipourma_uninit_urma_resources_by_jetty(priv, i);
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

static int ipourma_restart_rings_by_jetty(struct ipourma_dev_priv *priv, int jetty_idx)
{
	struct ubcore_seg_cfg cfg = {0};
	int ret = IPOURMA_OK;
	int j = 0;

	if (!IS_ERR_OR_NULL(priv->jetty[jetty_idx]) ||
		!IS_ERR_OR_NULL(priv->jfr[jetty_idx]))
		return IPOURMA_OK;
	if (IS_ERR_OR_NULL(priv->tx_ring[jetty_idx]) ||
		IS_ERR_OR_NULL(priv->rx_ring[jetty_idx]))
		return ipourma_urma_init_by_jetty(priv, (u32)jetty_idx);
	ret = ipourma_init_urma_resources_by_jetty(priv, jetty_idx);
	if (ret != IPOURMA_OK)
		return ret;
	ret = ipourma_init_tx_bufs(priv, jetty_idx);
	if (ret != IPOURMA_OK)
		goto init_tx_bufs_err;

	for (j = 0; j < priv->rx_buf_num; j++) {
		ipourma_build_seg_cfg(&cfg, (u64)priv->rx_buf_aligned[jetty_idx][j],
						ipourma_register_seg_size);
		priv->ipourma_ub_rx_seg[jetty_idx][j] = ubcore_register_seg(priv->urma_dev,
										&cfg, NULL);
		if (!IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg[jetty_idx][j]))
			continue;
		ret = IS_ERR(priv->ipourma_ub_rx_seg[jetty_idx][j]) ?
			PTR_ERR(priv->ipourma_ub_rx_seg[jetty_idx][j]) : -ENOMEM;
		priv->ipourma_ub_rx_seg[jetty_idx][j] = NULL;
		goto register_rx_seg_err;
	}
	for (j = 0; j < priv->rx_ring_size; j++) {
		ipourma_restart_rx_segments(priv, &priv->rx_ring[jetty_idx][j]);
		ret = ipourma_urma_post_recv(priv->dev, jetty_idx, j);
		if (ret != IPOURMA_OK) {
			j = priv->rx_buf_num;
			goto register_rx_seg_err;
		}
	}
	return ret;

register_rx_seg_err:
	while (--j >= 0) {
		ubcore_unregister_seg(priv->ipourma_ub_rx_seg[jetty_idx][j]);
		priv->ipourma_ub_rx_seg[jetty_idx][j] = NULL;
	}
	ipourma_uninit_tx_bufs(priv, jetty_idx);
init_tx_bufs_err:
	ipourma_uninit_urma_resources_by_jetty(priv, jetty_idx);
	return ret;
}

int ipourma_restart_rings(struct ipourma_dev_priv *priv)
{
	int ret;

	if (!priv->need_restart_ring) {
		priv->need_restart_ring = true;
		return IPOURMA_OK;
	}

	if (priv->anchor_eid_idx < 0) {
		int idx = -1;

		for (u32 i = 0; i < UBCORE_MAX_SIP; i++) {
			if (!eid_is_empty(&priv->eid_info[i].eid)) {
				idx = (int)i;
				break;
			}
		}
		if (idx < 0) {
			netdev_err(priv->dev, "no available eid, refuse to open\n");
			return -EIO;
		}
		priv->anchor_eid_idx = idx;
	}

	if (IS_ERR_OR_NULL(priv->jetty) || IS_ERR_OR_NULL(priv->jfr))
		return -EINVAL;
	for (int i = 0; i < (int)priv->jetty_cnt; i++) {
		ret = ipourma_restart_rings_by_jetty(priv, i);
		if (ret != IPOURMA_OK) {
			netdev_err(priv->dev, "restart rings failed on jetty %d, ret = %d\n",
					i, ret);
			priv->anchor_eid_idx = -1;
			ipourma_reset_rings(priv);
			return ret;
		}
	}

	if (IS_ERR_OR_NULL(priv->net_config_wq))
		return -EINVAL;
	queue_work(priv->net_config_wq, &(priv->set_ip));
	queue_work(priv->net_config_wq, &(priv->set_route));

	return IPOURMA_OK;
}

static int ipourma_init_rings_tables(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	size_t size = sizeof(spinlock_t) * priv->jetty_cnt;
	int cnt = priv->jetty_cnt;

	priv->ipourma_ub_tx_seg = kcalloc(cnt, sizeof(struct ubcore_target_seg **),
						GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->ipourma_ub_tx_seg))
		goto ub_tx_seg_failed;
	priv->ipourma_ub_rx_seg = kcalloc(cnt, sizeof(struct ubcore_target_seg **),
						GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->ipourma_ub_rx_seg))
		goto ub_rx_seg_failed;
	priv->tx_buf_aligned = kcalloc(cnt, sizeof(u8 **), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->tx_buf_aligned))
		goto tx_buf_aligned_failed;
	priv->rx_buf_aligned = kcalloc(cnt, sizeof(u8 **), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->rx_buf_aligned))
		goto rx_buf_aligned_failed;
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
	kfree(priv->rx_buf_aligned);
	priv->rx_buf_aligned = NULL;
rx_buf_aligned_failed:
	kfree(priv->tx_buf_aligned);
	priv->tx_buf_aligned = NULL;
tx_buf_aligned_failed:
	kfree(priv->ipourma_ub_rx_seg);
	priv->ipourma_ub_rx_seg = NULL;
ub_rx_seg_failed:
	kfree(priv->ipourma_ub_tx_seg);
	priv->ipourma_ub_tx_seg = NULL;
ub_tx_seg_failed:
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

	ret = ipourma_adjust_ring_size(priv);
	if (ret != IPOURMA_OK)
		return ret;

	priv->skb_buf_size = priv->urma_mtu;
	priv->tx_buf_size = priv->urma_mtu;
	if (priv->tx_buf_size > ipourma_register_seg_size ||
		priv->skb_buf_size > ipourma_register_seg_size) {
		netdev_err(priv->dev,
			"buf size %u exceeds register seg size %u, increase page_level\n",
			max(priv->tx_buf_size, priv->skb_buf_size),
			ipourma_register_seg_size);
		return -EINVAL;
	}
	priv->tx_bufs_per_blk = ipourma_register_seg_size / priv->tx_buf_size;
	priv->rx_bufs_per_blk = ipourma_register_seg_size / priv->skb_buf_size;
	priv->rx_buf_num = DIV_ROUND_UP(priv->rx_ring_size, priv->rx_bufs_per_blk);
	priv->tx_buf_num = DIV_ROUND_UP(priv->tx_ring_size, priv->tx_bufs_per_blk);

	ret = ipourma_init_rings_tables(dev);

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

static int ipourma_jetty_pick_sl(const struct ubcore_device_attr *attr, int ctp_en)
{
	int best_idx = -1;
	int i;

	for (i = 0; i < UBCORE_MAX_PRIORITY_CNT; i++) {
		if (ctp_en) {
			if (attr->dev_cap.priority_info[i].tp_type.bs.ctp != 1)
				continue;
		} else {
			if (attr->dev_cap.priority_info[i].tp_type.bs.utp != 1 &&
			    attr->dev_cap.priority_info[i].tp_type.bs.rtp != 1)
				continue;
		}
		/* pick the entry with the largest SL value, not the largest index */
		if (best_idx == -1 ||
		    attr->dev_cap.priority_info[i].SL >
		    attr->dev_cap.priority_info[best_idx].SL)
			best_idx = i;
	}

	return best_idx;
}

static int ipourma_jetty_set_priority(struct ipourma_dev_priv *priv,
					struct ubcore_jetty_cfg *jetty_cfg)
{
	struct ubcore_device_attr attr = {0};
	int ctp_en, sl = IPOURMA_SL_INVALID, ret;

	ret = ubcore_query_device_attr(priv->urma_dev, &attr);
	if (ret != 0)
		return ret;
	ctp_en = priv->urma_dev->attr.dev_cap.feature.bs.ctp_en;
	if (ctp_en == 1) {
		if (ipourma_ctp_sl >= 0 &&
		    ipourma_ctp_sl < UBCORE_MAX_PRIORITY_CNT &&
		    attr.dev_cap.priority_info[ipourma_ctp_sl].tp_type.bs.ctp == 1)
			sl = ipourma_ctp_sl;
	} else {
		if (ipourma_utp_sl >= 0 &&
		    ipourma_utp_sl < UBCORE_MAX_PRIORITY_CNT &&
		    (attr.dev_cap.priority_info[ipourma_utp_sl].tp_type.bs.utp == 1 ||
		     attr.dev_cap.priority_info[ipourma_utp_sl].tp_type.bs.rtp == 1))
			sl = ipourma_utp_sl;
	}

	if (sl < 0)
		sl = ipourma_jetty_pick_sl(&attr, ctp_en);

	if (sl < 0) {
		netdev_err(priv->dev,
			   "ipourma set jetty priority failed, no usable SL for %s\n",
			   ctp_en ? "ctp" : "utp");
		return -EINVAL;
	}

	jetty_cfg->priority = sl;
	netdev_info(priv->dev,
		    "ipourma create jetty set priority : %d, tp_type : %s\n",
		    sl, ctp_en ? "ctp" : "utp");
	return IPOURMA_OK;
}

static struct ubcore_jfr *ipourma_create_jfr(
	struct net_device *dev, u32 depth, u32 eid_index)
{
	struct ubcore_jfr_cfg jfr_cfg = { 0 };
	struct ipourma_dev_priv *priv = netdev_priv(dev);
	int ctp_en;

	ctp_en = priv->urma_dev->attr.dev_cap.feature.bs.ctp_en;

	jfr_cfg.depth = depth;
	jfr_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	jfr_cfg.flag.bs.order_type = ctp_en ? UBCORE_OL : UBCORE_DEF_ORDER;
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
	int ctp_en;

	max_send_sge = (IPOURMA_MAX_TX_SGES < IPOURMA_MAX_URMA_SEND_SGES) ?
		IPOURMA_MAX_TX_SGES : IPOURMA_MAX_URMA_SEND_SGES;
	max_recv_sge = (IPOURMA_MAX_RX_SGES < IPOURMA_MAX_URMA_RECV_SGES) ?
		IPOURMA_MAX_RX_SGES : IPOURMA_MAX_URMA_RECV_SGES;

	ctp_en = priv->urma_dev->attr.dev_cap.feature.bs.ctp_en;
	/* some values should dynamically get from the device */
	jetty_cfg.id = jetty_id;
	jetty_cfg.flag.bs.share_jfr = 1;
	if (ctp_en == 1)
		jetty_cfg.flag.bs.order_type = UBCORE_OL;
	jetty_cfg.trans_mode = priv->urma_transport_mode;
	jetty_cfg.eid_index = priv->eid_info[eid_index].eid_index;
	jetty_cfg.jfs_depth = priv->jfs_depth;
	jetty_cfg.priority = 0;
	jetty_cfg.max_send_sge = max_send_sge;
	jetty_cfg.max_send_rsge = IPOURMA_MAX_URMA_RECV_SGES;
	jetty_cfg.jfr_depth = priv->jfr_depth;
	jetty_cfg.max_recv_sge = max_recv_sge;
	jetty_cfg.send_jfc = priv->tx_jfc;
	jetty_cfg.recv_jfc = priv->rx_jfc;
	jetty_cfg.jfr = priv->jfr[jetty_id - IPOURMA_WELL_KNOWN_JETTY_ID];
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
	netdev_dbg(dev, "jfc_id=%u\n", jfc->id);
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

void ipourma_uninit_urma_resources_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	if (!IS_ERR_OR_NULL(priv->jetty) && !IS_ERR_OR_NULL(priv->jetty[jetty_idx])) {
		ubcore_delete_jetty(priv->jetty[jetty_idx]);
		priv->jetty[jetty_idx] = NULL;
	}
	if (!IS_ERR_OR_NULL(priv->jfr) && !IS_ERR_OR_NULL(priv->jfr[jetty_idx])) {
		ubcore_delete_jfr(priv->jfr[jetty_idx]);
		priv->jfr[jetty_idx] = NULL;
	}
}

void ipourma_uninit_urma_resources(struct net_device *dev)
{
	struct ipourma_dev_priv *priv = netdev_priv(dev);

	ipourma_uninit_misc(priv);

	if (IS_ERR_OR_NULL(priv->jetty))
		return;
	for (int i = 0; i < (int)priv->jetty_cnt; i++)
		ipourma_uninit_urma_resources_by_jetty(priv, i);
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
	priv->max_send_sge = IPOURMA_MAX_URMA_SEND_SGES;
	priv->urma_op_mode = UBCORE_OPC_SEND;
	priv->urma_transport_mode = UBCORE_TP_UM;

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

	priv->jfr = kcalloc(priv->jetty_cnt, sizeof(struct ubcore_jfr *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv->jfr)) {
		ret = IPOURMA_CREATE_JFR_TABLE_FAILED;
		goto jfr_table_failed;
	}
	priv->jetty = kcalloc(priv->jetty_cnt, sizeof(struct ubcore_jetty *), GFP_KERNEL);
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

int ipourma_init_urma_resources_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx)
{
	struct net_device *dev = priv->dev;
	int ret = IPOURMA_OK;

	if (priv->anchor_eid_idx < 0) {
		netdev_err(dev, "no anchor eid, refuse to create urma resources\n");
		return -EINVAL;
	}
	if (!ipourma_check_dev_name(dev)) {
		ret = IPOURMA_INVALID_DEV_NAME;
		goto invalid_name;
	}

	priv->jfr[jetty_idx] = ipourma_create_jfr(dev, priv->jfr_depth,
						(u32)priv->anchor_eid_idx);
	if (IS_ERR_OR_NULL(priv->jfr[jetty_idx])) {
		ret = IPOURMA_CREATE_JFR_FAILED;
		pr_err("create jfr error, dev: %s, i = %u\n", dev->name, jetty_idx);
		goto jfr_failed;
	}
	priv->jetty[jetty_idx] = ipourma_create_jetty(dev,
				IPOURMA_WELL_KNOWN_JETTY_ID + jetty_idx,
				(u32)priv->anchor_eid_idx);
	if (IS_ERR_OR_NULL(priv->jetty[jetty_idx])) {
		ret = IPOURMA_CREATE_JETTY_FAILED;
		pr_err("create tx jetty error, dev: %s, i = %u\n", dev->name, jetty_idx);
		goto jetty_failed;
	}

	return ret;

jetty_failed:
	ubcore_delete_jfr(priv->jfr[jetty_idx]);
	priv->jfr[jetty_idx] = NULL;
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
								priv->tx_jfc_depth);
	if (IS_ERR_OR_NULL(priv->tx_jfc)) {
		ret = IPOURMA_CREATE_JFC_FAILED;
		pr_err("create tx jfc error, dev: %s\n", dev->name);
		goto tx_jfc_failed;
	}
	priv->rx_jfc = ipourma_create_jfc(dev, ipourma_handle_rx_cqe,
								priv->rx_jfc_depth);
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
