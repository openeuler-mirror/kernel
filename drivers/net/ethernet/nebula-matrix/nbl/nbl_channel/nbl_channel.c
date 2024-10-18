// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_channel.h"

static int nbl_chan_add_msg_handler(struct nbl_channel_mgt *chan_mgt, u16 msg_type,
				    nbl_chan_resp func, void *priv)
{
	struct nbl_chan_msg_node_data handler = {0};
	int ret;

	handler.func = func;
	handler.priv = priv;

	ret = nbl_common_alloc_hash_node(chan_mgt->handle_hash_tbl, &msg_type, &handler);

	return ret;
}

static int nbl_chan_init_msg_handler(struct nbl_channel_mgt *chan_mgt, u8 user_notify)
{
	struct nbl_hash_tbl_key tbl_key;
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	int ret = 0;

	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_chan_notify_userdev *notify;

	if (user_notify) {
		notify = devm_kzalloc(dev, sizeof(struct nbl_chan_notify_userdev), GFP_KERNEL);
		if (!notify)
			return -ENOMEM;

		mutex_init(&notify->lock);
		chan_mgt->notify = notify;
	}

	NBL_HASH_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common), sizeof(u16),
			      sizeof(struct nbl_chan_msg_node_data),
			      NBL_CHAN_HANDLER_TBL_BUCKET_SIZE, false);

	chan_mgt->handle_hash_tbl = nbl_common_init_hash_table(&tbl_key);
	if (!chan_mgt->handle_hash_tbl) {
		ret = -ENOMEM;
		goto alloc_hashtbl_failed;
	}

	return 0;

alloc_hashtbl_failed:
	if (user_notify) {
		chan_mgt->notify = NULL;
		devm_kfree(dev, notify);
	}

	return ret;
}

static void nbl_chan_remove_msg_handler(struct nbl_channel_mgt *chan_mgt)
{
	struct nbl_hash_tbl_del_key del_key = {0};

	nbl_common_remove_hash_table(chan_mgt->handle_hash_tbl, &del_key);

	chan_mgt->handle_hash_tbl = NULL;

	if (chan_mgt->notify) {
		devm_kfree(NBL_COMMON_TO_DEV(chan_mgt->common), chan_mgt->notify);
		chan_mgt->notify = NULL;
	}
}

static bool nbl_chan_is_admiq(struct nbl_chan_info *chan_info)
{
	return chan_info->chan_type == NBL_CHAN_TYPE_ADMINQ;
}

static void nbl_chan_init_queue_param(struct nbl_chan_info *chan_info,
				      u16 num_txq_entries, u16 num_rxq_entries,
				      u16 txq_buf_size, u16 rxq_buf_size)
{
	spin_lock_init(&chan_info->txq_lock);
	chan_info->num_txq_entries = num_txq_entries;
	chan_info->num_rxq_entries = num_rxq_entries;
	chan_info->txq_buf_size = txq_buf_size;
	chan_info->rxq_buf_size = rxq_buf_size;
}

static int nbl_chan_init_tx_queue(struct nbl_common_info *common,
				  struct nbl_chan_info *chan_info)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(common);
	struct nbl_chan_ring *txq = &chan_info->txq;
	size_t size = chan_info->num_txq_entries * sizeof(struct nbl_chan_tx_desc);

	txq->desc = dmam_alloc_coherent(dma_dev, size, &txq->dma, GFP_KERNEL | __GFP_ZERO);
	if (!txq->desc) {
		dev_err(dev, "Allocate DMA for chan tx descriptor ring failed\n");
		return -ENOMEM;
	}

	chan_info->wait = devm_kcalloc(dev, chan_info->num_txq_entries,
				       sizeof(struct nbl_chan_waitqueue_head), GFP_KERNEL);
	if (!chan_info->wait)
		goto req_wait_queue_failed;

	txq->buf = devm_kcalloc(dev, chan_info->num_txq_entries,
				sizeof(struct nbl_chan_buf), GFP_KERNEL);
	if (!txq->buf)
		goto req_num_txq_entries;

	return 0;

req_num_txq_entries:
	devm_kfree(dev, chan_info->wait);
req_wait_queue_failed:
	dmam_free_coherent(dma_dev, size, txq->desc, txq->dma);

	txq->desc = NULL;
	txq->dma = 0;
	chan_info->wait = NULL;

	return -ENOMEM;
}

static int nbl_chan_init_rx_queue(struct nbl_common_info *common,
				  struct nbl_chan_info *chan_info)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(common);
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	size_t size = chan_info->num_rxq_entries * sizeof(struct nbl_chan_rx_desc);

	rxq->desc = dmam_alloc_coherent(dma_dev, size, &rxq->dma, GFP_KERNEL | __GFP_ZERO);
	if (!rxq->desc) {
		dev_err(dev, "Allocate DMA for chan rx descriptor ring failed\n");
		return -ENOMEM;
	}

	rxq->buf = devm_kcalloc(dev, chan_info->num_rxq_entries,
				sizeof(struct nbl_chan_buf), GFP_KERNEL);
	if (!rxq->buf) {
		dmam_free_coherent(dma_dev, size, rxq->desc, rxq->dma);
		rxq->desc = NULL;
		rxq->dma = 0;
		return -ENOMEM;
	}

	return 0;
}

static void nbl_chan_remove_tx_queue(struct nbl_common_info *common,
				     struct nbl_chan_info *chan_info)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(common);
	struct nbl_chan_ring *txq = &chan_info->txq;
	size_t size = chan_info->num_txq_entries * sizeof(struct nbl_chan_tx_desc);

	devm_kfree(dev, txq->buf);
	txq->buf = NULL;

	devm_kfree(dev, chan_info->wait);
	chan_info->wait = NULL;

	dmam_free_coherent(dma_dev, size, txq->desc, txq->dma);
	txq->desc = NULL;
	txq->dma = 0;
}

static void nbl_chan_remove_rx_queue(struct nbl_common_info *common,
				     struct nbl_chan_info *chan_info)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(common);
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	size_t size = chan_info->num_rxq_entries * sizeof(struct nbl_chan_rx_desc);

	devm_kfree(dev, rxq->buf);
	rxq->buf = NULL;

	dmam_free_coherent(dma_dev, size, rxq->desc, rxq->dma);
	rxq->desc = NULL;
	rxq->dma = 0;
}

static int nbl_chan_init_queue(struct nbl_common_info *common,
			       struct nbl_chan_info *chan_info)
{
	int err;

	err = nbl_chan_init_tx_queue(common, chan_info);
	if (err)
		return err;

	err = nbl_chan_init_rx_queue(common, chan_info);
	if (err)
		goto setup_rx_queue_err;

	return 0;

setup_rx_queue_err:
	nbl_chan_remove_tx_queue(common, chan_info);
	return err;
}

static void nbl_chan_config_queue(struct nbl_channel_mgt *chan_mgt,
				  struct nbl_chan_info *chan_info, bool tx)
{
	struct nbl_phy_ops *phy_ops;
	struct nbl_chan_ring *ring;
	dma_addr_t dma_addr;
	int size_bwid = ilog2(chan_info->num_rxq_entries);

	phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	if (tx)
		ring = &chan_info->txq;
	else
		ring = &chan_info->rxq;

	dma_addr = ring->dma;

	if (nbl_chan_is_admiq(chan_info)) {
		if (tx)
			phy_ops->config_adminq_txq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt),
						   dma_addr, size_bwid);
		else
			phy_ops->config_adminq_rxq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt),
						   dma_addr, size_bwid);
	} else {
		if (tx)
			phy_ops->config_mailbox_txq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt),
						    dma_addr, size_bwid);
		else
			phy_ops->config_mailbox_rxq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt),
						    dma_addr, size_bwid);
	}
}

static int nbl_chan_alloc_all_tx_bufs(struct nbl_channel_mgt *chan_mgt,
				      struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct nbl_chan_buf *buf;
	struct device *dev = NBL_COMMON_TO_DEV(chan_mgt->common);
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(chan_mgt->common);
	u16 i;

	for (i = 0; i < chan_info->num_txq_entries; i++) {
		buf = &txq->buf[i];
		buf->va = dmam_alloc_coherent(dma_dev, chan_info->txq_buf_size,
					      &buf->pa, GFP_KERNEL | __GFP_ZERO);
		if (!buf->va) {
			dev_err(dev, "Allocate buffer for chan tx queue failed\n");
			goto err;
		}
	}

	txq->next_to_clean = 0;
	txq->next_to_use = 0;
	txq->tail_ptr = 0;

	return 0;
err:
	while (i--) {
		buf = &txq->buf[i];
		dmam_free_coherent(dma_dev, chan_info->txq_buf_size, buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}

	return -ENOMEM;
}

static int nbl_chan_cfg_mailbox_qinfo_map_table(struct nbl_channel_mgt *chan_mgt)
{
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);
	u16 func_id;
	u32 pf_mask;

	pf_mask = phy_ops->get_host_pf_mask(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
	for (func_id = 0; func_id < NBL_MAX_PF; func_id++) {
		if (!(pf_mask & (1 << func_id)))
			phy_ops->cfg_mailbox_qinfo(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt), func_id,
						   common->bus, common->devid,
						   NBL_COMMON_TO_PCI_FUNC_ID(common) + func_id);
	}

	return 0;
}

static int nbl_chan_cfg_adminq_qinfo_map_table(struct nbl_channel_mgt *chan_mgt)
{
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	phy_ops->cfg_adminq_qinfo(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt),
				  common->bus, common->devid,
				  NBL_COMMON_TO_PCI_FUNC_ID(common));

	return 0;
}

static int nbl_chan_cfg_qinfo_map_table(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	int err;

	if (!nbl_chan_is_admiq(chan_info))
		err = nbl_chan_cfg_mailbox_qinfo_map_table(chan_mgt);
	else
		err = nbl_chan_cfg_adminq_qinfo_map_table(chan_mgt);

	return err;
}

static void nbl_chan_free_all_tx_bufs(struct nbl_channel_mgt *chan_mgt,
				      struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct nbl_chan_buf *buf;
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(chan_mgt->common);
	u16 i;

	for (i = 0; i < chan_info->num_txq_entries; i++) {
		buf = &txq->buf[i];
		dmam_free_coherent(dma_dev, chan_info->txq_buf_size,
				   buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}
}

#define NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt, tail_ptr, qid)			\
do {												\
	typeof(phy_ops) _phy_ops = (phy_ops);							\
	typeof(chan_mgt) _chan_mgt = (chan_mgt);						\
	typeof(tail_ptr) _tail_ptr = (tail_ptr);						\
	typeof(qid) _qid = (qid);								\
	if (nbl_chan_is_admiq(chan_info))							\
		(_phy_ops)->update_adminq_queue_tail_ptr(NBL_CHAN_MGT_TO_PHY_PRIV(_chan_mgt),	\
							_tail_ptr, _qid);			\
	else											\
		(_phy_ops)->update_mailbox_queue_tail_ptr(NBL_CHAN_MGT_TO_PHY_PRIV(_chan_mgt),	\
							_tail_ptr, _qid);			\
} while (0)

static int nbl_chan_alloc_all_rx_bufs(struct nbl_channel_mgt *chan_mgt,
				      struct nbl_chan_info *chan_info)
{
	struct nbl_phy_ops *phy_ops;
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	struct nbl_chan_buf *buf;
	struct nbl_chan_rx_desc *desc;
	struct device *dev = NBL_COMMON_TO_DEV(chan_mgt->common);
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(chan_mgt->common);
	u32 retry_times = 0;
	u16 i;

	phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	for (i = 0; i < chan_info->num_rxq_entries; i++) {
		buf = &rxq->buf[i];
		buf->va = dmam_alloc_coherent(dma_dev, chan_info->rxq_buf_size,
					      &buf->pa, GFP_KERNEL | __GFP_ZERO);
		if (!buf->va) {
			dev_err(dev, "Allocate buffer for chan rx queue failed\n");
			goto err;
		}
	}

	desc = rxq->desc;
	for (i = 0; i < chan_info->num_rxq_entries - 1; i++) {
		buf = &rxq->buf[i];
		desc[i].flags = NBL_CHAN_RX_DESC_AVAIL;
		desc[i].buf_addr = buf->pa;
		desc[i].buf_len = chan_info->rxq_buf_size;
	}

	rxq->next_to_clean = 0;
	rxq->next_to_use = chan_info->num_rxq_entries - 1;
	rxq->tail_ptr = chan_info->num_rxq_entries - 1;

	/* mb for doorbell */
	mb();

	NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt, rxq->tail_ptr, NBL_MB_RX_QID);

	for (retry_times = 0; retry_times < 3; retry_times++) {
		NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt,
					  rxq->tail_ptr, NBL_MB_RX_QID);
		usleep_range(NBL_CHAN_TX_WAIT_US * 50, NBL_CHAN_TX_WAIT_US * 60);
	}

	return 0;
err:
	while (i--) {
		buf = &rxq->buf[i];
		dmam_free_coherent(dma_dev, chan_info->rxq_buf_size,
				   buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}

	return -ENOMEM;
}

static void nbl_chan_free_all_rx_bufs(struct nbl_channel_mgt *chan_mgt,
				      struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	struct nbl_chan_buf *buf;
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(chan_mgt->common);
	u16 i;

	for (i = 0; i < chan_info->num_rxq_entries; i++) {
		buf = &rxq->buf[i];
		dmam_free_coherent(dma_dev, chan_info->rxq_buf_size,
				   buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}
}

static int nbl_chan_alloc_all_bufs(struct nbl_channel_mgt *chan_mgt,
				   struct nbl_chan_info *chan_info)
{
	int err;

	err = nbl_chan_alloc_all_tx_bufs(chan_mgt, chan_info);
	if (err)
		return err;

	err = nbl_chan_alloc_all_rx_bufs(chan_mgt, chan_info);
	if (err)
		goto alloc_rx_bufs_err;

	return 0;

alloc_rx_bufs_err:
	nbl_chan_free_all_tx_bufs(chan_mgt, chan_info);
	return err;
}

static void nbl_chan_stop_queue(struct nbl_channel_mgt *chan_mgt,
				struct nbl_chan_info *chan_info)
{
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	if (nbl_chan_is_admiq(chan_info)) {
		phy_ops->stop_adminq_rxq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
		phy_ops->stop_adminq_txq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
	} else {
		phy_ops->stop_mailbox_rxq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
		phy_ops->stop_mailbox_txq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
	}
}

static void nbl_chan_free_all_bufs(struct nbl_channel_mgt *chan_mgt,
				   struct nbl_chan_info *chan_info)
{
	nbl_chan_free_all_tx_bufs(chan_mgt, chan_info);
	nbl_chan_free_all_rx_bufs(chan_mgt, chan_info);
}

static void nbl_chan_remove_queue(struct nbl_common_info *common,
				  struct nbl_chan_info *chan_info)
{
	nbl_chan_remove_tx_queue(common, chan_info);
	nbl_chan_remove_rx_queue(common, chan_info);
}

static int nbl_chan_teardown_queue(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	nbl_chan_stop_queue(chan_mgt, chan_info);

	nbl_chan_free_all_bufs(chan_mgt, chan_info);

	nbl_chan_remove_queue(common, chan_info);

	return 0;
}

static int nbl_chan_setup_queue(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	int err;

	nbl_chan_init_queue_param(chan_info, NBL_CHAN_QUEUE_LEN, NBL_CHAN_QUEUE_LEN,
				  NBL_CHAN_BUF_LEN, NBL_CHAN_BUF_LEN);

	err = nbl_chan_init_queue(common, chan_info);
	if (err)
		return err;

	nbl_chan_config_queue(chan_mgt, chan_info, true); /* tx */
	nbl_chan_config_queue(chan_mgt, chan_info, false); /* rx */

	err = nbl_chan_alloc_all_bufs(chan_mgt, chan_info);
	if (err)
		goto chan_q_setup_fail;

	return 0;

chan_q_setup_fail:
	nbl_chan_teardown_queue(chan_mgt, chan_type);
	return err;
}

static void nbl_chan_shutdown_queue(struct nbl_channel_mgt *chan_mgt, u8 chan_type, bool tx)
{
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	if (tx) {
		if (nbl_chan_is_admiq(chan_info))
			phy_ops->stop_adminq_txq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
		else
			phy_ops->stop_mailbox_txq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));

		nbl_chan_free_all_tx_bufs(chan_mgt, chan_info);
		nbl_chan_remove_tx_queue(common, chan_info);
	} else {
		if (nbl_chan_is_admiq(chan_info))
			phy_ops->stop_adminq_rxq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
		else
			phy_ops->stop_mailbox_rxq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));

		nbl_chan_free_all_rx_bufs(chan_mgt, chan_info);
		nbl_chan_remove_rx_queue(common, chan_info);
	}
}

static int nbl_chan_start_txq(struct nbl_channel_mgt *chan_mgt, u8 chan_type)
{
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	int ret;

	ret = nbl_chan_init_tx_queue(common, chan_info);
	if (ret)
		return ret;

	nbl_chan_config_queue(chan_mgt, chan_info, true); /* tx */

	ret = nbl_chan_alloc_all_tx_bufs(chan_mgt, chan_info);
	if (ret)
		goto alloc_buf_failed;

	return 0;

alloc_buf_failed:
	nbl_chan_shutdown_queue(chan_mgt, chan_type, true);
	return ret;
}

static int nbl_chan_start_rxq(struct nbl_channel_mgt *chan_mgt, u8 chan_type)
{
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	int ret;

	ret = nbl_chan_init_rx_queue(common, chan_info);
	if (ret)
		return ret;

	nbl_chan_config_queue(chan_mgt, chan_info, false); /* rx */

	ret = nbl_chan_alloc_all_rx_bufs(chan_mgt, chan_info);
	if (ret)
		goto alloc_buf_failed;

	return 0;

alloc_buf_failed:
	nbl_chan_shutdown_queue(chan_mgt, chan_type, false);
	return ret;
}

static int nbl_chan_reset_queue(struct nbl_channel_mgt *chan_mgt, u8 chan_type, bool tx)
{
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	int ret = 0;

	/* If someone else is doing resetting, don't bother */
	if (test_bit(NBL_CHAN_RESETTING, chan_info->state))
		return 0;

	/* Make sure rx won't enter if we are resetting */
	set_bit(NBL_CHAN_RESETTING, chan_info->state);
	if (chan_info->clean_task)
		nbl_common_flush_task(chan_info->clean_task);

	/* Make sure tx won't enter if we are resetting */
	spin_lock(&chan_info->txq_lock);

	/* If we are in a race, and someone else has finished it, just return */
	if (!test_bit(NBL_CHAN_RESETTING, chan_info->state)) {
		spin_unlock(&chan_info->txq_lock);
		return 0;
	}

	nbl_chan_shutdown_queue(chan_mgt, chan_type, tx);

	if (tx)
		ret = nbl_chan_start_txq(chan_mgt, chan_type);
	else
		ret = nbl_chan_start_rxq(chan_mgt, chan_type);

	/* Make sure we clear this bit inside lock, so that we don't reset it twice if race */
	clear_bit(NBL_CHAN_RESETTING, chan_info->state);
	spin_unlock(&chan_info->txq_lock);

	return ret;
}

static bool nbl_chan_check_dma_err(struct nbl_channel_mgt *chan_mgt, u8 chan_type, bool tx)
{
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	if (chan_type == NBL_CHAN_TYPE_MAILBOX)
		return phy_ops->check_mailbox_dma_err(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt), tx);
	else
		return phy_ops->check_adminq_dma_err(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt), tx);
}

static u16 nbl_chan_update_txqueue(struct nbl_channel_mgt *chan_mgt,
				   struct nbl_chan_info *chan_info, u16 dstid,
				   enum nbl_chan_msg_type msg_type,
				   void *arg, size_t arg_len)
{
	struct device *dev = NBL_COMMON_TO_DEV(chan_mgt->common);
	struct nbl_chan_ring *txq;
	struct nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_buf *tx_buf;
	u16 next_to_use;

	txq = &chan_info->txq;
	next_to_use = txq->next_to_use;
	tx_buf = NBL_CHAN_TX_RING_TO_BUF(txq, next_to_use);
	tx_desc = NBL_CHAN_TX_RING_TO_DESC(txq, next_to_use);

	tx_desc->dstid = dstid;
	tx_desc->msg_type = msg_type;
	tx_desc->msgid = next_to_use;
	if (arg_len > NBL_CHAN_BUF_LEN - sizeof(*tx_desc)) {
		dev_err(dev, "%s, arg_len:%ld, too long!", __func__, arg_len);
		return -1;
	}

	if (arg_len > NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN) {
		memcpy(tx_buf->va, arg, arg_len);
		tx_desc->buf_addr = tx_buf->pa;
		tx_desc->buf_len = arg_len;
		tx_desc->data_len = 0;
	} else {
		memcpy(tx_desc->data, arg, arg_len);
		tx_desc->buf_len = 0;
		tx_desc->data_len = arg_len;
	}
	tx_desc->flags = NBL_CHAN_TX_DESC_AVAIL;

	/* wmb */
	wmb();
	txq->next_to_use++;
	if (txq->next_to_use == chan_info->num_txq_entries)
		txq->next_to_use = 0;
	txq->tail_ptr++;

	return next_to_use;
}

static int nbl_chan_kick_tx_ring(struct nbl_channel_mgt *chan_mgt,
				 struct nbl_chan_info *chan_info)
{
	struct nbl_phy_ops *phy_ops;
	struct nbl_common_info *common = chan_mgt->common;
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_chan_ring *txq;
	struct nbl_chan_tx_desc *tx_desc;
	int i;

	phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	txq = &chan_info->txq;

	/* mb for doorbell */
	mb();

	NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt, txq->tail_ptr, NBL_MB_TX_QID);

	tx_desc = NBL_CHAN_TX_RING_TO_DESC(txq, txq->next_to_clean);

	i = 0;
	while (!(tx_desc->flags & NBL_CHAN_TX_DESC_USED)) {
		udelay(NBL_CHAN_TX_WAIT_US);
		i++;

		if (!(i % NBL_CHAN_TX_REKICK_WAIT_TIMES)) {
			NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt, txq->tail_ptr,
						  NBL_MB_TX_QID);
		}

		if (i == NBL_CHAN_TX_WAIT_TIMES) {
			dev_err(dev, "bus:%u, dev:%u, func:%u, chan send message type: %d timeout\n",
				common->bus, common->devid, NBL_COMMON_TO_PCI_FUNC_ID(common),
				tx_desc->msg_type);
			return -1;
		}
	}

	txq->next_to_clean = txq->next_to_use;
	return 0;
}

static void nbl_chan_recv_ack_msg(void *priv, u16 srcid, u16 msgid,
				  void *data, u32 data_len)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NULL;
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_chan_waitqueue_head *wait_head;
	u32 *payload = (u32 *)data;
	u32 ack_msgid;
	u32 ack_msgtype;

	if (srcid == NBL_CHAN_ADMINQ_FUNCTION_ID)
		chan_info = NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	else
		chan_info = NBL_CHAN_MGT_TO_MAILBOX(chan_mgt);

	ack_msgtype = *payload;
	ack_msgid = *(payload + 1);
	wait_head = &chan_info->wait[ack_msgid];
	wait_head->ack_err = *(payload + 2);

	if (ack_msgtype != wait_head->msg_type)
		nbl_debug(common, NBL_DEBUG_MBX,
			  "ack_msgtype %d donot match msg_type %d\n",
			  ack_msgtype, wait_head->msg_type);
	if (wait_head->status != NBL_MBX_STATUS_WAITING) {
		nbl_warn(common, NBL_DEBUG_MBX, "Skip ack with status %d", wait_head->status);
		return;
	}

	if (wait_head->ack_err >= 0 && (data_len > 3 * sizeof(u32))) {
		if (data_len - 3 * sizeof(u32) != wait_head->ack_data_len) {
			dev_err(dev, "%x:%x.%x payload_len donot match ack_data_len!, srcid:%u,\n"
				"msgtype:%u, msgid:%u, data_len:%u, ack_data_len:%u\n",
				common->bus, common->devid, NBL_COMMON_TO_PCI_FUNC_ID(common),
				srcid, ack_msgtype, ack_msgid, data_len, wait_head->ack_data_len);
			goto wakeup;
		}
		memcpy((char *)wait_head->ack_data, payload + 3, data_len - 3 * sizeof(int));
	}

wakeup:
	/* wmb */
	wmb();
	wait_head->acked = 1;
	if (wait_head->need_waked)
		wake_up(&wait_head->wait_queue);
}

static inline u16 nbl_unused_msg_ring_count(u32 head, u32 tail)
{
	return ((tail > head) ? 0 : NBL_USER_DEV_SHMMSGBUF_SIZE) + tail - head - 1;
}

static int nbl_chan_msg_forward_userdev(struct nbl_channel_mgt *chan_mgt,
					struct nbl_chan_tx_desc *tx_desc)
{
	struct device *dev = NBL_COMMON_TO_DEV(chan_mgt->common);
	void *shm_msg_ring = chan_mgt->notify->shm_msg_ring;
	char *data = (char *)shm_msg_ring + 8;
	u32 *head = (u32 *)shm_msg_ring, tmp;
	u32 tail = *(head + 1);
	u32 total_len = sizeof(struct nbl_chan_tx_desc) + sizeof(u32), copy_len;

	if (!tx_desc->data_len)
		total_len += ALIGN(tx_desc->buf_len, 4);

	tmp = *head;
	if (total_len > nbl_unused_msg_ring_count(tmp, tail)) {
		dev_err(dev, "user msg ring not enough for msg\n");
		return -E2BIG;
	}

	/* save total_len */
	*(u32 *)(data + tmp) = total_len;
	tmp += sizeof(u32);
	total_len -= sizeof(u32);
	if (tmp >= NBL_USER_DEV_SHMMSGBUF_SIZE)
		tmp -= NBL_USER_DEV_SHMMSGBUF_SIZE;

	copy_len = NBL_USER_DEV_SHMMSGBUF_SIZE - tmp;
	copy_len = min(copy_len, total_len);
	memcpy(data + tmp, tx_desc, copy_len);
	if (total_len > copy_len)
		memcpy(data, (char *)tx_desc + copy_len, total_len - copy_len);

	tmp += total_len;
	if (tmp >= NBL_USER_DEV_SHMMSGBUF_SIZE)
		tmp -= NBL_USER_DEV_SHMMSGBUF_SIZE;

	/* make sure to update head after content */
	smp_wmb();
	*head = tmp;
	eventfd_signal(chan_mgt->notify->eventfd, 1);

	return 0;
}

static void nbl_chan_recv_msg(struct nbl_channel_mgt *chan_mgt, void *data, u32 data_len)
{
	struct nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_msg_node_data *msg_handler;
	struct device *dev = NBL_COMMON_TO_DEV(chan_mgt->common);
	u16 msg_type, payload_len, srcid, msgid, warn = 1;
	void *payload;

	tx_desc = data;
	msg_type = tx_desc->msg_type;
	dev_dbg(dev, "%s recv msg_type: %d\n", __func__, tx_desc->msg_type);

	srcid = tx_desc->srcid;
	msgid = tx_desc->msgid;
	if (msg_type >= NBL_CHAN_MSG_MAX) {
		dev_err(dev, "Invalid chan message type %u\n", msg_type);
		return;
	}

	if (tx_desc->data_len) {
		payload = (void *)tx_desc->data;
		payload_len = tx_desc->data_len;
	} else {
		payload = (void *)(tx_desc + 1);
		payload_len = tx_desc->buf_len;
	}

	msg_handler = nbl_common_get_hash_node(chan_mgt->handle_hash_tbl, &msg_type);
	if (msg_handler) {
		warn = 0;
		msg_handler->func(msg_handler->priv, srcid, msgid, payload, payload_len);
	}

	if (chan_mgt->notify) {
		mutex_lock(&chan_mgt->notify->lock);
		if (chan_mgt->notify->eventfd && test_bit(msg_type, chan_mgt->notify->msgtype) &&
		    chan_mgt->notify->shm_msg_ring) {
			warn = 0;
			nbl_chan_msg_forward_userdev(chan_mgt, tx_desc);
		}
		mutex_unlock(&chan_mgt->notify->lock);
	}

	if (warn)
		dev_warn(dev, "Recv channel msg_type: %d, but msg_handler is null!\n",
			 tx_desc->msg_type);
}

static void nbl_chan_advance_rx_ring(struct nbl_channel_mgt *chan_mgt,
				     struct nbl_chan_info *chan_info,
				     struct nbl_chan_ring *rxq)
{
	struct nbl_phy_ops *phy_ops;
	struct nbl_chan_rx_desc *rx_desc;
	struct nbl_chan_buf *rx_buf;
	u16 next_to_use;

	phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	next_to_use = rxq->next_to_use;
	rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_use);
	rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_use);

	rx_desc->flags = NBL_CHAN_RX_DESC_AVAIL;
	rx_desc->buf_addr = rx_buf->pa;
	rx_desc->buf_len = chan_info->rxq_buf_size;

	/* wmb */
	wmb();
	rxq->next_to_use++;
	if (rxq->next_to_use == chan_info->num_rxq_entries)
		rxq->next_to_use = 0;
	rxq->tail_ptr++;

	NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt, rxq->tail_ptr, NBL_MB_RX_QID);
}

static void nbl_chan_clean_queue(struct nbl_channel_mgt *chan_mgt, struct nbl_chan_info *chan_info)
{
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	struct nbl_chan_rx_desc *rx_desc;
	struct nbl_chan_buf *rx_buf;
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	u16 next_to_clean;

	next_to_clean = rxq->next_to_clean;
	rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_clean);
	rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_clean);
	while (rx_desc->flags & NBL_CHAN_RX_DESC_USED) {
		if (!(rx_desc->flags & NBL_CHAN_RX_DESC_WRITE))
			nbl_debug(common, NBL_DEBUG_MBX,
				  "mailbox rx flag 0x%x has no NBL_CHAN_RX_DESC_WRITE\n",
				  rx_desc->flags);

		dma_rmb();
		nbl_chan_recv_msg(chan_mgt, rx_buf->va, rx_desc->buf_len);

		nbl_chan_advance_rx_ring(chan_mgt, chan_info, rxq);

		next_to_clean++;
		if (next_to_clean == chan_info->num_rxq_entries)
			next_to_clean = 0;
		rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_clean);
		rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_clean);
	}
	rxq->next_to_clean = next_to_clean;
}

void nbl_chan_clean_queue_subtask(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	if (!test_bit(NBL_CHAN_INTERRUPT_READY, chan_info->state) ||
	    test_bit(NBL_CHAN_RESETTING, chan_info->state))
		return;

	nbl_chan_clean_queue(chan_mgt, chan_info);
}

static int nbl_chan_send_msg(void *priv, struct nbl_chan_send_info *chan_send)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_chan_info *chan_info = NULL;
	struct nbl_chan_waitqueue_head *wait_head;
	u16 msgid;
	int i = NBL_CHAN_TX_WAIT_ACK_TIMES, ret;
	int resend_times = 0;

	if (chan_send->dstid == NBL_CHAN_ADMINQ_FUNCTION_ID)
		chan_info = NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	else
		chan_info = NBL_CHAN_MGT_TO_MAILBOX(chan_mgt);

resend:
	spin_lock(&chan_info->txq_lock);
	msgid = nbl_chan_update_txqueue(chan_mgt, chan_info, chan_send->dstid,
					chan_send->msg_type,
					chan_send->arg, chan_send->arg_len);

	if (msgid == 0xFFFF) {
		spin_unlock(&chan_info->txq_lock);
		dev_err(dev, "chan tx queue full, send msgtype:%u to dstid:%u failed\n",
			chan_send->msg_type, chan_send->dstid);
		return -1;
	}

	if (!chan_send->ack) {
		ret = nbl_chan_kick_tx_ring(chan_mgt, chan_info);
		spin_unlock(&chan_info->txq_lock);
		if (ret)
			goto check_tx_dma_err;
		else
			return ret;
	}

	wait_head = &chan_info->wait[msgid];
	init_waitqueue_head(&wait_head->wait_queue);
	wait_head->ack_data = chan_send->resp;
	wait_head->ack_data_len = chan_send->resp_len;
	wait_head->acked = 0;
	wait_head->msg_type = chan_send->msg_type;
	wait_head->need_waked = 1;
	wait_head->status = NBL_MBX_STATUS_WAITING;
	ret = nbl_chan_kick_tx_ring(chan_mgt, chan_info);
	spin_unlock(&chan_info->txq_lock);
	if (ret)
		goto check_tx_dma_err;

	if (test_bit(NBL_CHAN_INTERRUPT_READY, chan_info->state)) {
		ret = wait_event_timeout(wait_head->wait_queue, wait_head->acked,
					 NBL_CHAN_ACK_WAIT_TIME);
		if (!ret) {
			dev_err(dev, "wait bus:%u, dev:%u, func:%u, chan send message type: %d\n"
				"msg id: %u wait ack timeout\n", common->bus, common->devid,
				NBL_COMMON_TO_PCI_FUNC_ID(common), chan_send->msg_type, msgid);
			wait_head->status = NBL_MBX_STATUS_TIMEOUT;
			goto check_rx_dma_err;
		}

		/* rmb for ack */
		rmb();
		return wait_head->ack_err;
	}

	/*polling wait mailbox ack*/
	while (i--) {
		nbl_chan_clean_queue(chan_mgt, chan_info);

		if (wait_head->acked)
			return wait_head->ack_err;
		usleep_range(NBL_CHAN_TX_WAIT_ACK_US_MIN, NBL_CHAN_TX_WAIT_ACK_US_MAX);
	}

	wait_head->status = NBL_MBX_STATUS_TIMEOUT;
	dev_err(dev, "polling bus:%u, dev:%u, func:%u, chan send message type: %d msg id: %u\n"
		"wait ack timeout\n", common->bus, common->devid,
		NBL_COMMON_TO_PCI_FUNC_ID(common), chan_send->msg_type, msgid);

check_rx_dma_err:
	if (nbl_chan_check_dma_err(chan_mgt, chan_info->chan_type, false)) {
		dev_err(dev, "nbl channel rx dma error\n");
		nbl_chan_reset_queue(chan_mgt, chan_info->chan_type, false);
		chan_info->rxq_reset_times++;
	}

check_tx_dma_err:
	if (nbl_chan_check_dma_err(chan_mgt, chan_info->chan_type, true)) {
		dev_err(dev, "nbl channel tx dma error\n");
		nbl_chan_reset_queue(chan_mgt, chan_info->chan_type, true);
		chan_info->txq_reset_times++;
	}

	resend_times++;
	if (resend_times > NBL_CHAN_RESEND_MAX_TIMES) {
		dev_err(dev, "nbl channel resend_times %d\n", resend_times);
		return -1;
	}

	i = NBL_CHAN_TX_WAIT_ACK_TIMES;
	goto resend;
}

static int nbl_chan_send_ack(void *priv, struct nbl_chan_ack_info *chan_ack)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_send_info chan_send;
	u32 *tmp;
	u32 len = 3 * sizeof(u32) + chan_ack->data_len;

	tmp = kzalloc(len, GFP_ATOMIC);
	if (!tmp)
		return -ENOMEM;

	tmp[0] = chan_ack->msg_type;
	tmp[1] = chan_ack->msgid;
	tmp[2] = (u32)chan_ack->err;
	if (chan_ack->data && chan_ack->data_len)
		memcpy(&tmp[3], chan_ack->data, chan_ack->data_len);

	NBL_CHAN_SEND(chan_send, chan_ack->dstid, NBL_CHAN_MSG_ACK, tmp, len, NULL, 0, 0);
	nbl_chan_send_msg(chan_mgt, &chan_send);
	kfree(tmp);

	return 0;
}

static int nbl_chan_register_msg(void *priv, u16 msg_type, nbl_chan_resp func, void *callback_priv)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	int ret;

	ret = nbl_chan_add_msg_handler(chan_mgt, msg_type, func, callback_priv);

	return ret;
}

static bool nbl_chan_check_queue_exist(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt;
	struct nbl_chan_info *chan_info;

	if (!priv)
		return false;

	chan_mgt = (struct nbl_channel_mgt *)priv;
	chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	return chan_info ? true : false;
}

static int nbl_chan_set_queue_interrupt_state(void *priv, u8 chan_type, bool ready)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	if (ready)
		set_bit(NBL_CHAN_INTERRUPT_READY, chan_info->state);
	else
		clear_bit(NBL_CHAN_INTERRUPT_READY, chan_info->state);

	return 0;
}

static int nbl_chan_dump_txq(void *priv, struct seq_file *m, u8 type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = type == NBL_CHAN_TYPE_MAILBOX ?
						  NBL_CHAN_MGT_TO_MAILBOX(chan_mgt) :
						  NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct nbl_chan_waitqueue_head *wait;
	struct nbl_chan_tx_desc *desc;
	int i;

	seq_printf(m, "txq size:%u, next_to_use:%u, tail_ptr:%u, next_to_clean:%u\n",
		   chan_info->num_txq_entries, txq->next_to_use, txq->tail_ptr, txq->next_to_clean);
	seq_printf(m, "reset times %d\n", chan_info->txq_reset_times);

	for (i = 0; i < chan_info->num_txq_entries; i++) {
		desc = NBL_CHAN_TX_RING_TO_DESC(txq, i);
		wait = &chan_info->wait[i];
		seq_printf(m, "%u: flags 0x%x, srcid %u, dstid %u, data_len %u,\n"
			   "buf_len %u, msg_type %u, msgid %u, ", i,
			   desc->flags, desc->srcid, desc->dstid,
			   desc->data_len, desc->buf_len, desc->msg_type, desc->msgid);
		seq_printf(m, "acked %u, ack_err %u, ack_data_len %u,\n"
			   "need_waked %u, msg_type %u\n", wait->acked, wait->ack_err,
			   wait->ack_data_len, wait->need_waked, wait->msg_type);
	}

	return 0;
}

static int nbl_chan_dump_rxq(void *priv, struct seq_file *m, u8 type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = type == NBL_CHAN_TYPE_MAILBOX ?
						  NBL_CHAN_MGT_TO_MAILBOX(chan_mgt) :
						  NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	struct nbl_chan_rx_desc *rx_desc;
	struct nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_buf *rx_buf;
	int i;

	seq_printf(m, "rxq size:%u, next_to_use:%u, tail_ptr:%u, next_to_clean:%u\n",
		   chan_info->num_rxq_entries, rxq->next_to_use, rxq->tail_ptr, rxq->next_to_clean);
	seq_printf(m, "reset times %d\n", chan_info->rxq_reset_times);
	for (i = 0; i < chan_info->num_rxq_entries; i++) {
		rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, i);
		rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, i);
		tx_desc = (struct nbl_chan_tx_desc *)rx_buf->va;
		seq_printf(m, "%u: rx_desc flags 0x%x, buf_len 0x%x, buf_id 0x%x, buffer_addr 0x%llx,\n"
			   "tx_dedc srcid %u, dstid %u, data_len %u, buf_len %u, msg_type %u, msgid %u\n",
			   i, rx_desc->flags, rx_desc->buf_len, rx_desc->buf_id, rx_desc->buf_addr,
			   tx_desc->srcid, tx_desc->dstid, tx_desc->data_len, tx_desc->buf_len,
			   tx_desc->msg_type, tx_desc->msgid);
	}

	return 0;
}

static u32 nbl_chan_get_adminq_tx_buf_size(void *priv)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *adminq = NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);

	return adminq->txq_buf_size;
}

static int nbl_chan_set_listener_info(void *priv, void *shm_ring, struct eventfd_ctx *eventfd)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;

	mutex_lock(&chan_mgt->notify->lock);

	chan_mgt->notify->shm_msg_ring = shm_ring;
	if (chan_mgt->notify->eventfd)
		eventfd_ctx_put(chan_mgt->notify->eventfd);
	chan_mgt->notify->eventfd = eventfd;

	mutex_unlock(&chan_mgt->notify->lock);

	return 0;
}

static int nbl_chan_set_listener_msgtype(void *priv, int msgtype)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;

	if (msgtype >= NBL_CHAN_MSG_MAILBOX_MAX)
		return -EINVAL;

	mutex_lock(&chan_mgt->notify->lock);
	set_bit(msgtype, chan_mgt->notify->msgtype);
	mutex_unlock(&chan_mgt->notify->lock);

	return 0;
}

static void nbl_chan_clear_listener_info(void *priv)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;

	mutex_lock(&chan_mgt->notify->lock);
	if (chan_mgt->notify->eventfd)
		eventfd_ctx_put(chan_mgt->notify->eventfd);
	chan_mgt->notify->eventfd = NULL;

	bitmap_zero(chan_mgt->notify->msgtype, NBL_CHAN_MSG_MAILBOX_MAX);
	if (chan_mgt->notify->shm_msg_ring)
		memset(chan_mgt->notify->shm_msg_ring, 0, NBL_USER_DEV_SHMMSGRING_SIZE);
	mutex_unlock(&chan_mgt->notify->lock);
}

static void nbl_chan_keepalive_resp(void *priv, u16 srcid, u16 msgid, void *data, u32 data_len)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_ack_info chan_ack;

	NBL_CHAN_ACK(chan_ack, srcid, NBL_CHAN_MSG_KEEP_ALIVE, msgid, 0, NULL, 0);

	nbl_chan_send_ack(chan_mgt, &chan_ack);
}

static void nbl_chan_keepalive(struct delayed_work *work)
{
	struct nbl_chan_keepalive_info *keepalive =
		container_of(work, struct nbl_chan_keepalive_info, keepalive_task);
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)keepalive->chan_mgt;
	struct nbl_chan_send_info chan_send;
	u32 delay_time;

	NBL_CHAN_SEND(chan_send, keepalive->keepalive_dest, NBL_CHAN_MSG_KEEP_ALIVE,
		      NULL, 0, NULL, 0, 1);

	if (nbl_chan_send_msg(chan_mgt, &chan_send)) {
		if (keepalive->fail_cnt < NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_THRESH)
			keepalive->fail_cnt++;

		if (keepalive->fail_cnt >= NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_THRESH &&
		    keepalive->timeout < NBL_CHAN_KEEPALIVE_MAX_TIMEOUT) {
			get_random_bytes(&delay_time, sizeof(delay_time));
			keepalive->timeout += delay_time % NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_GAP;

			keepalive->fail_cnt = 0;
		}
	} else {
		if (keepalive->success_cnt < NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_THRESH)
			keepalive->success_cnt++;

		if (keepalive->success_cnt >= NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_THRESH &&
		    keepalive->timeout > NBL_CHAN_KEEPALIVE_DEFAULT_TIMEOUT * 2) {
			get_random_bytes(&delay_time, sizeof(delay_time));
			keepalive->timeout -= delay_time % NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_GAP;

			keepalive->success_cnt = 0;
		}
	}

	nbl_common_queue_delayed_work_keepalive(work, jiffies_to_msecs(keepalive->timeout));
}

static int nbl_chan_setup_keepalive(void *priv, u16 dest_id, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	struct nbl_chan_keepalive_info *keepalive = &chan_info->keepalive;
	u32 delay_time;

	get_random_bytes(&delay_time, sizeof(delay_time));
	delay_time = delay_time % NBL_CHAN_KEEPALIVE_TIMEOUT_UPDATE_GAP;

	keepalive->timeout = NBL_CHAN_KEEPALIVE_DEFAULT_TIMEOUT + delay_time;
	keepalive->chan_mgt = chan_mgt;
	keepalive->keepalive_dest = dest_id;
	keepalive->success_cnt = 0;
	keepalive->fail_cnt = 0;

	nbl_chan_add_msg_handler(chan_mgt, NBL_CHAN_MSG_KEEP_ALIVE,
				 nbl_chan_keepalive_resp, chan_mgt);

	nbl_common_alloc_delayed_task(&keepalive->keepalive_task, nbl_chan_keepalive);

	nbl_common_queue_delayed_work_keepalive(&keepalive->keepalive_task,
						jiffies_to_msecs(keepalive->timeout));

	return 0;
}

static void nbl_chan_remove_keepalive(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	nbl_common_release_delayed_task(&chan_info->keepalive.keepalive_task);
}

static void nbl_chan_register_chan_task(void *priv, u8 chan_type, struct work_struct *task)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	chan_info->clean_task = task;
}

static struct nbl_channel_ops chan_ops = {
	.send_msg			= nbl_chan_send_msg,
	.send_ack			= nbl_chan_send_ack,
	.register_msg			= nbl_chan_register_msg,
	.cfg_chan_qinfo_map_table	= nbl_chan_cfg_qinfo_map_table,
	.check_queue_exist		= nbl_chan_check_queue_exist,
	.setup_queue			= nbl_chan_setup_queue,
	.teardown_queue			= nbl_chan_teardown_queue,
	.set_queue_interrupt_state	= nbl_chan_set_queue_interrupt_state,
	.clean_queue_subtask		= nbl_chan_clean_queue_subtask,

	/* for mailbox register msg for userdev */
	.set_listener_info		= nbl_chan_set_listener_info,
	.set_listener_msgtype		= nbl_chan_set_listener_msgtype,
	.clear_listener_info		= nbl_chan_clear_listener_info,
	.dump_txq			= nbl_chan_dump_txq,
	.dump_rxq			= nbl_chan_dump_rxq,
	.get_adminq_tx_buf_size		= nbl_chan_get_adminq_tx_buf_size,

	.setup_keepalive		= nbl_chan_setup_keepalive,
	.remove_keepalive		= nbl_chan_remove_keepalive,
	.register_chan_task		= nbl_chan_register_chan_task,
};

static int nbl_chan_setup_chan_mgt(struct nbl_adapter *adapter,
				   struct nbl_init_param *param,
				   struct nbl_channel_mgt_leonis **chan_mgt_leonis)
{
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_chan_info *mailbox;
	struct nbl_chan_info *adminq = NULL;
	int ret;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	phy_ops_tbl = NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);

	*chan_mgt_leonis = devm_kzalloc(dev, sizeof(struct nbl_channel_mgt_leonis), GFP_KERNEL);
	if (!*chan_mgt_leonis)
		goto alloc_channel_mgt_leonis_fail;

	NBL_CHAN_MGT_TO_COMMON(&(*chan_mgt_leonis)->chan_mgt) = common;
	(*chan_mgt_leonis)->chan_mgt.phy_ops_tbl = phy_ops_tbl;

	mailbox = devm_kzalloc(dev, sizeof(struct nbl_chan_info), GFP_KERNEL);
	if (!mailbox)
		goto alloc_mailbox_fail;
	mailbox->chan_type = NBL_CHAN_TYPE_MAILBOX;
	NBL_CHAN_MGT_TO_MAILBOX(&(*chan_mgt_leonis)->chan_mgt) = mailbox;

	if (param->caps.has_ctrl || param->caps.has_factory_ctrl) {
		adminq = devm_kzalloc(dev, sizeof(struct nbl_chan_info), GFP_KERNEL);
		if (!adminq)
			goto alloc_adminq_fail;
		adminq->chan_type = NBL_CHAN_TYPE_ADMINQ;
		NBL_CHAN_MGT_TO_ADMINQ(&(*chan_mgt_leonis)->chan_mgt) = adminq;
	}

	ret = nbl_chan_init_msg_handler(&(*chan_mgt_leonis)->chan_mgt, param->caps.has_user);
	if (ret)
		goto init_chan_msg_handle;

	return 0;

init_chan_msg_handle:
	if (adminq)
		devm_kfree(dev, adminq);
alloc_adminq_fail:
	devm_kfree(dev, mailbox);
alloc_mailbox_fail:
	devm_kfree(dev, *chan_mgt_leonis);
	*chan_mgt_leonis = NULL;
alloc_channel_mgt_leonis_fail:
	return -ENOMEM;
}

static void nbl_chan_remove_chan_mgt(struct nbl_common_info *common,
				     struct nbl_channel_mgt_leonis **chan_mgt_leonis)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);

	nbl_chan_remove_msg_handler(&(*chan_mgt_leonis)->chan_mgt);
	if (NBL_CHAN_MGT_TO_ADMINQ(&(*chan_mgt_leonis)->chan_mgt))
		devm_kfree(dev, NBL_CHAN_MGT_TO_ADMINQ(&(*chan_mgt_leonis)->chan_mgt));
	devm_kfree(dev, NBL_CHAN_MGT_TO_MAILBOX(&(*chan_mgt_leonis)->chan_mgt));

	devm_kfree(dev, *chan_mgt_leonis);
	*chan_mgt_leonis = NULL;
}

static void nbl_chan_remove_ops(struct device *dev, struct nbl_channel_ops_tbl **chan_ops_tbl)
{
	if (!dev || !chan_ops_tbl)
		return;

	devm_kfree(dev, *chan_ops_tbl);
	*chan_ops_tbl = NULL;
}

static int nbl_chan_setup_ops(struct device *dev, struct nbl_channel_ops_tbl **chan_ops_tbl,
			      struct nbl_channel_mgt_leonis *chan_mgt)
{
	int ret;
	*chan_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_channel_ops_tbl), GFP_KERNEL);
	if (!*chan_ops_tbl)
		return -ENOMEM;

	NBL_CHAN_OPS_TBL_TO_OPS(*chan_ops_tbl) = &chan_ops;
	NBL_CHAN_OPS_TBL_TO_PRIV(*chan_ops_tbl) = chan_mgt;

	if (!chan_mgt)
		return 0;

	ret = nbl_chan_add_msg_handler(&chan_mgt->chan_mgt, NBL_CHAN_MSG_ACK,
				       nbl_chan_recv_ack_msg, chan_mgt);
	if (ret)
		goto err;

	return 0;

err:
	devm_kfree(dev, *chan_ops_tbl);
	*chan_ops_tbl = NULL;

	return -1;
}

int nbl_chan_init_common(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_channel_mgt_leonis **chan_mgt_leonis;
	struct nbl_channel_ops_tbl **chan_ops_tbl;
	int ret = 0;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	chan_mgt_leonis = (struct nbl_channel_mgt_leonis **)&NBL_ADAPTER_TO_CHAN_MGT(adapter);
	chan_ops_tbl = &NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	ret = nbl_chan_setup_chan_mgt(adapter, param, chan_mgt_leonis);
	if (ret)
		goto setup_mgt_fail;

	ret = nbl_chan_setup_ops(dev, chan_ops_tbl, *chan_mgt_leonis);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	nbl_chan_remove_chan_mgt(common, chan_mgt_leonis);
setup_mgt_fail:
	return ret;
}

void nbl_chan_remove_common(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_channel_mgt_leonis **chan_mgt_leonis;
	struct nbl_channel_ops_tbl **chan_ops_tbl;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	chan_mgt_leonis = (struct nbl_channel_mgt_leonis **)&NBL_ADAPTER_TO_CHAN_MGT(adapter);
	chan_ops_tbl = &NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	nbl_chan_remove_chan_mgt(common, chan_mgt_leonis);
	nbl_chan_remove_ops(dev, chan_ops_tbl);
}

