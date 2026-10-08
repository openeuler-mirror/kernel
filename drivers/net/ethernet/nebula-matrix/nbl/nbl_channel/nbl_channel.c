// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_channel.h"
#include "nbl_cmdq.h"

static int nbl_chan_send_ack(void *priv, struct nbl_chan_ack_info *chan_ack);

static void nbl_chan_delete_msg_handler(struct nbl_channel_mgt *chan_mgt, u16 msg_type)
{
	u8 chan_type;
	struct nbl_chan_info *chan_info;

	nbl_common_free_hash_node(chan_mgt->handle_hash_tbl, &msg_type);

	if (msg_type < NBL_CHAN_MSG_ADMINQ_GET_EMP_VERSION)
		chan_type = NBL_CHAN_TYPE_MAILBOX;
	else
		chan_type = NBL_CHAN_TYPE_ADMINQ;

	chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	if (chan_info && chan_info->clean_task)
		nbl_common_flush_task(chan_info->clean_task);
}

static int nbl_chan_add_msg_handler(struct nbl_channel_mgt *chan_mgt, u16 msg_type,
				    nbl_chan_resp func, void *priv)
{
	struct nbl_chan_msg_node_data handler = {0};
	int ret;

	handler.func = func;
	handler.priv = priv;

	ret = nbl_common_alloc_hash_node(chan_mgt->handle_hash_tbl, &msg_type, &handler, NULL);

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
	nbl_common_remove_hash_table(chan_mgt->handle_hash_tbl, NULL);

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
				      u16 txq_buf_size, u16 rxq_buf_size,
				      u16 product_type)
{
	spin_lock_init(&chan_info->txq_lock);
	chan_info->num_txq_entries = num_txq_entries;
	chan_info->num_rxq_entries = num_rxq_entries;
	chan_info->txq_buf_size = txq_buf_size;
	chan_info->rxq_buf_size = rxq_buf_size;
	chan_info->product_type = product_type;
	chan_info->failed_cnt = 0;
}

static int nbl_chan_init_tx_queue(struct nbl_common_info *common,
				  struct nbl_chan_info *chan_info)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *dma_dev = NBL_COMMON_TO_DMA_DEV(common);
	struct nbl_chan_ring *txq = &chan_info->txq;
	size_t size = chan_info->num_txq_entries * sizeof(union nbl_chan_tx_desc);
	u32 i;

	txq->desc = dmam_alloc_coherent(dma_dev, size, &txq->dma, GFP_KERNEL | __GFP_ZERO);
	if (!txq->desc) {
		dev_err(dev, "Allocate DMA for chan tx descriptor ring failed\n");
		return -ENOMEM;
	}

	chan_info->wait = devm_kcalloc(dev, chan_info->num_txq_entries,
				       sizeof(struct nbl_chan_waitqueue_head), GFP_KERNEL);
	if (!chan_info->wait)
		goto req_wait_queue_failed;

	for (i = 0; i < chan_info->num_txq_entries; i++)
		atomic_set(&chan_info->wait[i].status, NBL_MBX_STATUS_IDLE);

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
	size_t size = chan_info->num_rxq_entries * sizeof(union nbl_chan_rx_desc);

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
	size_t size = chan_info->num_txq_entries * sizeof(union nbl_chan_tx_desc);

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
	size_t size = chan_info->num_rxq_entries * sizeof(union nbl_chan_rx_desc);

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
			phy_ops->config_mailbox_txq_rst(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt),
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

static int nbl_chan_cfg_mailbox_qinfo_map_table(struct nbl_channel_mgt *chan_mgt,
						unsigned long *owned_pf_bitmap, u8 max_pf, u16 bdf)
{
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);
	u16 func_id;
	u8 bus = 0;
	u8 devid = 0;

	bus = PCI_BUS_NUM(bdf);
	devid = PCI_SLOT(bdf & 0xff);

	for_each_set_bit(func_id, owned_pf_bitmap, max_pf) {
		phy_ops->cfg_mailbox_qinfo(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt), func_id,
					   bus, devid, func_id);
	}

	return 0;
}

static int nbl_chan_cfg_adminq_qinfo_map_table(struct nbl_channel_mgt *chan_mgt, u16 bdf)
{
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);
	u8 bus = 0;
	u8 devid = 0;

	bus = PCI_BUS_NUM(bdf);
	devid = PCI_SLOT(bdf & 0xff);
	phy_ops->cfg_adminq_qinfo(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt),
				  bus, devid,
				  NBL_COMMON_TO_PCI_FUNC_ID(common));

	return 0;
}

static int nbl_chan_cfg_qinfo_map_table(void *priv, u8 chan_type,
					unsigned long *owned_pf_bitmap, u8 max_pf, u16 bdf)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	int err;

	if (!nbl_chan_is_admiq(chan_info))
		err = nbl_chan_cfg_mailbox_qinfo_map_table(chan_mgt, owned_pf_bitmap, max_pf, bdf);
	else
		err = nbl_chan_cfg_adminq_qinfo_map_table(chan_mgt, bdf);

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
	union nbl_chan_rx_desc *rx_desc;
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

	rx_desc = rxq->desc;
	for (i = 0; i < chan_info->num_rxq_entries - 1; i++) {
		buf = &rxq->buf[i];
		DESC_W(&rx_desc[i], flags, NBL_CHAN_RX_DESC_AVAIL);
		DESC_W(&rx_desc[i], buf_addr, buf->pa);
		DESC_W(&rx_desc[i], buf_len, chan_info->rxq_buf_size);
	}

	rxq->next_to_clean = 0;
	rxq->next_to_use = chan_info->num_rxq_entries - 1;
	rxq->tail_ptr = chan_info->num_rxq_entries - 1;
	/* make sure queue init writes are visible before updating the tail pointer */
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

static bool nbl_chan_check_finished(struct nbl_chan_info *chan_info)
{
	struct nbl_chan_waitqueue_head *wait = NULL;
	int status;
	int i;

	/* ensure chan send msg has been finished */
	spin_lock(&chan_info->txq_lock);
	spin_unlock(&chan_info->txq_lock);

	/* ensure chan send waiting ack has been finished */
	for (i = 0; i < NBL_CHAN_QUEUE_LEN; i++) {
		wait = &chan_info->wait[i];
		status = atomic_read(&wait->status);
		if (status != NBL_MBX_STATUS_IDLE && status != NBL_MBX_STATUS_TIMEOUT)
			return 0;
	}

	return 1;
}

static int nbl_chan_teardown_queue(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	if (!chan_info->inited)
		return 0;

	if (!nbl_chan_check_finished(chan_info))
		return -EAGAIN;

	nbl_chan_stop_queue(chan_mgt, chan_info);

	nbl_chan_free_all_bufs(chan_mgt, chan_info);

	nbl_chan_remove_queue(common, chan_info);
	chan_info->inited = false;

	return 0;
}

static int nbl_chan_setup_queue(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	int err;

	if (chan_info->inited)
		return 0;

	nbl_chan_init_queue_param(chan_info, NBL_CHAN_QUEUE_LEN, NBL_CHAN_QUEUE_LEN,
				  NBL_CHAN_BUF_LEN, NBL_CHAN_BUF_LEN, common->product_type);

	err = nbl_chan_init_queue(common, chan_info);
	if (err)
		return err;

	nbl_chan_config_queue(chan_mgt, chan_info, true); /* tx */
	nbl_chan_config_queue(chan_mgt, chan_info, false); /* rx */

	err = nbl_chan_alloc_all_bufs(chan_mgt, chan_info);
	if (err)
		goto chan_q_setup_fail;

	chan_info->inited = true;

	return 0;

chan_q_setup_fail:
	nbl_chan_teardown_queue(chan_mgt, chan_type);
	return err;
}

static int nbl_chan_update_txqueue(struct nbl_channel_mgt *chan_mgt,
				   struct nbl_chan_info *chan_info, struct nbl_chan_tx_param *param)
{
	struct nbl_chan_ring *txq = &chan_info->txq;
	union nbl_chan_tx_desc *tx_desc = NBL_CHAN_TX_RING_TO_DESC(txq, txq->next_to_use);
	struct nbl_chan_buf *tx_buf = NBL_CHAN_TX_RING_TO_BUF(txq, txq->next_to_use);

	if (param->arg_len > NBL_CHAN_BUF_LEN - sizeof(*tx_desc))
		return -EINVAL;

	DESC_W(tx_desc, dstid, param->dstid);
	DESC_W(tx_desc, msg_type, param->msg_type);
	DESC_W(tx_desc, msgid, param->msgid);

	if (param->arg_len > NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN) {
		memcpy(tx_buf->va, param->arg, param->arg_len);
		DESC_W(tx_desc, buf_addr, tx_buf->pa);
		DESC_W(tx_desc, buf_len, param->arg_len);
		DESC_W(tx_desc, data_len, 0);
	} else {
		memcpy(DESC_R(tx_desc, data), param->arg, param->arg_len);
		DESC_W(tx_desc, buf_len, 0);
		DESC_W(tx_desc, data_len, param->arg_len);
	}

	DESC_W(tx_desc, flags, NBL_CHAN_TX_DESC_AVAIL);

	/* wmb */
	wmb();
	txq->next_to_use = NBL_NEXT_ID(txq->next_to_use, chan_info->num_txq_entries - 1);
	txq->tail_ptr++;

	return 0;
}

static int nbl_chan_kick_tx_ring(struct nbl_channel_mgt *chan_mgt,
				 struct nbl_chan_info *chan_info, u16 dst_funcid)
{
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct nbl_chan_ring *txq = &chan_info->txq;
	union nbl_chan_tx_desc *tx_desc;
	int i = 0;
	/* pf2vf channel fwd by hw, it fast then emp */
	int tx_kick_timeout = (dst_funcid != NBL_CHAN_ADMINQ_FUNCTION_ID) ?
				NBL_CHAN_TX_PFVF_WAIT_TIMES : NBL_CHAN_TX_PF2EMP_WAIT_TIMES;
	int tx_rekick_timeout = (dst_funcid != NBL_CHAN_ADMINQ_FUNCTION_ID) ?
				tx_kick_timeout / 4 : NBL_CHAN_TX_PF2EMP_FIRST_REKICK_WAIT_TIMES;

	/* make sure tx descriptors are visible before updating the tail pointer */
	mb();

	NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt, txq->tail_ptr, NBL_MB_TX_QID);
	tx_desc = NBL_CHAN_TX_RING_TO_DESC(txq, txq->next_to_clean);

	while (!(DESC_R(tx_desc, flags) & NBL_CHAN_TX_DESC_USED)) {
		udelay(NBL_CHAN_TX_WAIT_US);
		i++;

		/* Hardware may does not detect tx db, so driver need rekick */
		if (i > 0 && (i % tx_rekick_timeout) == 0) {
			NBL_UPDATE_QUEUE_TAIL_PTR(chan_info, phy_ops, chan_mgt,
						  txq->tail_ptr, NBL_MB_TX_QID);
			tx_rekick_timeout = tx_kick_timeout / 4;
		}

		if (i >= tx_kick_timeout) {
			nbl_err(common, NBL_DEBUG_MBX, "chan kick message type: %d timeout\n",
				DESC_R(tx_desc, msg_type));
			NBL_OPS_CALL(phy_ops->dump_mailbox_dbg,
				     (NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt)));
			return -EAGAIN;
		}
	}

	txq->next_to_clean = txq->next_to_use;
	return 0;
}

static void nbl_chan_recv_ack_msg(void *priv, u16 srcid, u16 msgid, void *data, u32 data_len)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct nbl_chan_info *chan_info = NULL;
	struct nbl_chan_waitqueue_head *wait_head = NULL;
	union nbl_chan_msg_id ack_msgid = {{0}};
	u32 *payload = (u32 *)data;
	u32 ack_datalen = 0, ack_msgtype = 0, copy_len = 0;
	u16 wait_msg_type;
	u16 wait_ack_data_len;

	if (srcid == NBL_CHAN_ADMINQ_FUNCTION_ID && NBL_CHAN_MGT_TO_ADMINQ(chan_mgt))
		chan_info = NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	else
		chan_info = NBL_CHAN_MGT_TO_MAILBOX(chan_mgt);

	ack_datalen = data_len - 3 * sizeof(u32);
	ack_msgtype = *payload;
	ack_msgid.id = *(u16 *)(payload + 1);
	wait_head = &chan_info->wait[ack_msgid.info.loc];
	wait_msg_type = READ_ONCE(wait_head->msg_type);
	wait_ack_data_len = READ_ONCE(wait_head->ack_data_len);
	WRITE_ONCE(wait_head->ack_err, *(payload + 2));
	chan_info->failed_cnt = 0;

	if (wait_msg_type != ack_msgtype) {
		nbl_warn(common, NBL_DEBUG_MBX, "Skip ack msg type donot match, wait_head msgtype:%u msg_index:%u status:%d ack_data_len:%d, ack msgtype:%u msgid:%u datalen:%d\n",
			 wait_msg_type, wait_head->msg_index, atomic_read(&wait_head->status),
			 wait_ack_data_len, ack_msgtype, ack_msgid.id, ack_datalen);
		return;
	}

	if (wait_head->msg_index != ack_msgid.info.index) {
		nbl_warn(common, NBL_DEBUG_MBX, "Skip ack index donot match, wait_head msgtype:%u msg_index:%u status:%d ack_data_len:%d, ack msgtype:%u msgid:%u datalen:%d\n",
			 wait_msg_type, wait_head->msg_index, atomic_read(&wait_head->status),
			 wait_ack_data_len, ack_msgtype, ack_msgid.id, ack_datalen);
		return;
	}

	if (atomic_cmpxchg(&wait_head->status, NBL_MBX_STATUS_WAITING, NBL_MBX_STATUS_ACKD) !=
	    NBL_MBX_STATUS_WAITING) {
		nbl_warn(common, NBL_DEBUG_MBX, "Skip ack with invalid status, wait_head msgtype:%u msg_index:%u status:%d ack_data_len:%d, ack msgtype:%u msgid:%u datalen:%d\n",
			 wait_msg_type, wait_head->msg_index, atomic_read(&wait_head->status),
			 wait_ack_data_len, ack_msgtype, ack_msgid.id, ack_datalen);
		return;
	}

	if (ack_datalen != wait_ack_data_len)
		nbl_debug(common, NBL_DEBUG_MBX, "Channel payload_len donot match ack_data_len, msgtype:%u, msgid:%u, rcv_data_len:%u, expect_data_len:%u\n",
			  ack_msgtype, ack_msgid.id, ack_datalen, wait_ack_data_len);

	copy_len = min_t(u32, wait_ack_data_len, ack_datalen);
	if (wait_head->ack_err >= 0 && copy_len > 0)
		memcpy(wait_head->ack_data, payload + 3, copy_len);
	WRITE_ONCE(wait_head->ack_data_len, (u16)copy_len);

	/* wmb */
	wmb();
	WRITE_ONCE(wait_head->acked, 1);
	if (READ_ONCE(wait_head->need_waked))
		wake_up(&wait_head->wait_queue);
}

static inline u16 nbl_unused_msg_ring_count(u32 head, u32 tail)
{
	return ((tail > head) ? 0 : NBL_USER_DEV_SHMMSGBUF_SIZE) + tail - head - 1;
}

static int nbl_chan_msg_forward_userdev(struct nbl_channel_mgt *chan_mgt,
					struct nbl_chan_info *chan_info,
					union nbl_chan_tx_desc *tx_desc)
{
	struct device *dev = NBL_COMMON_TO_DEV(chan_mgt->common);
	void *shm_msg_ring = chan_mgt->notify->shm_msg_ring;
	char *data = (char *)shm_msg_ring + 8;
	u32 *head = (u32 *)shm_msg_ring, tmp;
	u32 tail = *(head + 1);
	u32 total_len = sizeof(union nbl_chan_tx_desc) + sizeof(u32), copy_len;

	if (!DESC_R(tx_desc, data_len))
		total_len += ALIGN(DESC_R(tx_desc, buf_len), 4);

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

static void nbl_chan_recv_msg(struct nbl_channel_mgt *chan_mgt, struct nbl_chan_info *chan_info,
			      void *data, u32 data_len)
{
	struct nbl_chan_ack_info chan_ack;
	union nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_msg_node_data *msg_handler;
	struct device *dev = NBL_COMMON_TO_DEV(chan_mgt->common);
	u16 msg_type, payload_len, srcid, msgid, warn = 1;
	void *payload;

	tx_desc = data;

	msg_type = DESC_R(tx_desc, msg_type);
	srcid = DESC_R(tx_desc, srcid);
	msgid = DESC_R(tx_desc, msgid);
	dev_dbg(dev, "recv msg_type:%d, srcid:%d, msgid:%d, flags:0x%x, data_len:%d, buf_len:%d\n",
		msg_type, srcid, msgid,
		DESC_R(tx_desc, flags), DESC_R(tx_desc, data_len), DESC_R(tx_desc, buf_len));

	if (msg_type >= NBL_CHAN_MSG_MAX)
		goto send_warning;

	if (DESC_R(tx_desc, data_len)) {
		payload = (void *)DESC_R(tx_desc, data);
		payload_len = DESC_R(tx_desc, data_len);
	} else {
		payload = (void *)(tx_desc + 1);
		payload_len = DESC_R(tx_desc, buf_len);
	}

	msg_handler = nbl_common_get_hash_node(chan_mgt->handle_hash_tbl, &msg_type);
	if (msg_handler) {
		warn = 0;
		msg_handler->func(msg_handler->priv, srcid, msgid, payload, payload_len);
	}

	if (chan_mgt->notify && msg_type < NBL_CHAN_MSG_MAILBOX_MAX) {
		mutex_lock(&chan_mgt->notify->lock);
		if (chan_mgt->notify->eventfd && test_bit(msg_type, chan_mgt->notify->msgtype) &&
		    chan_mgt->notify->shm_msg_ring) {
			warn = 0;
			nbl_chan_msg_forward_userdev(chan_mgt, chan_info, tx_desc);
		}
		mutex_unlock(&chan_mgt->notify->lock);
	}

send_warning:
	if (warn) {
		NBL_CHAN_ACK(chan_ack, srcid, msg_type, msgid, -EPERM, NULL, 0);
		nbl_chan_send_ack(chan_mgt, &chan_ack);
		dev_warn(dev, "Recv channel msg_type: %d, no msg_handler!\n", msg_type);
	}
}

static void nbl_chan_advance_rx_ring(struct nbl_channel_mgt *chan_mgt,
				     struct nbl_chan_info *chan_info,
				     struct nbl_chan_ring *rxq)
{
	struct nbl_phy_ops *phy_ops;
	union nbl_chan_rx_desc *rx_desc;
	struct nbl_chan_buf *rx_buf;
	u16 next_to_use;

	phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	next_to_use = rxq->next_to_use;
	rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_use);
	rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_use);

	DESC_W(rx_desc, flags, NBL_CHAN_RX_DESC_AVAIL);
	DESC_W(rx_desc, buf_addr, rx_buf->pa);
	DESC_W(rx_desc, buf_len, chan_info->rxq_buf_size);
	memset(rx_buf->va, 0, chan_info->rxq_buf_size);

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
	union nbl_chan_rx_desc *rx_desc;
	struct nbl_chan_buf *rx_buf;
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	u16 next_to_clean;

	next_to_clean = rxq->next_to_clean;
	rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_clean);
	rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_clean);

	while (DESC_R(rx_desc, flags) & NBL_CHAN_RX_DESC_USED) {
		dma_rmb();
		if (!(DESC_R(rx_desc, flags) & NBL_CHAN_RX_DESC_WRITE))
			nbl_warn(common, NBL_DEBUG_MBX,
				 "mailbox rx flag 0x%x has no NBL_CHAN_RX_DESC_WRITE\n",
				 DESC_R(rx_desc, flags));
		else
			nbl_chan_recv_msg(chan_mgt, chan_info,
					  rx_buf->va, DESC_R(rx_desc, buf_len));

		nbl_chan_advance_rx_ring(chan_mgt, chan_info, rxq);

		next_to_clean++;
		if (next_to_clean == chan_info->num_rxq_entries)
			next_to_clean = 0;
		rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, next_to_clean);
		rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, next_to_clean);
	}
	rxq->next_to_clean = next_to_clean;
}

static u16 nbl_chan_get_translate_msg_id(struct nbl_channel_mgt *chan_mgt,
					 struct nbl_chan_send_info *chan_send)
{
	u16 msg_id = U16_MAX;
	u32 i;

	if (!chan_send->ack)
		return NBL_USERDEV_TRANSLATE_MAX;

	spin_lock(&chan_mgt->translate_lock);
	for (i = 0; i < NBL_USERDEV_TRANSLATE_MAX; i++) {
		if (chan_mgt->pend_msg[i].msg)
			continue;

		chan_mgt->pend_msg[i].msg = chan_send;
		msg_id = i;
		break;
	}
	spin_unlock(&chan_mgt->translate_lock);

	return msg_id;
}

static int nbl_chan_translate_configuration(struct nbl_channel_mgt *chan_mgt,
					    struct nbl_chan_send_info *chan_send)
{
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_chan_info *chan_info = NBL_CHAN_GET_INFO(chan_mgt, chan_send->dstid);
	union nbl_chan_tx_desc *tx_desc;
	void *data;
	u32 data_len;
	int ret = 0;
	u16 id;

	if (chan_send->msg_type == NBL_CHAN_MSG_ACK) {
		u32 *tmp;
		u16 msg_id;

		tmp = (u32 *)chan_send->arg;
		msg_id = tmp[1];

		if (msg_id >= NBL_USERDEV_TRANSLATE_MAX)
			return 0;

		if (!chan_mgt->pend_msg[msg_id].msg)
			return 0;

		chan_mgt->pend_msg[msg_id].ack_ret = tmp[2];
		if (chan_mgt->pend_msg[msg_id].msg->ack > 0 &&
		    (chan_send->arg_len > 3 * sizeof(u32))) {
			u32 ack_data_len = chan_send->arg_len - 3 * sizeof(u32);

			memcpy((char *)chan_mgt->pend_msg[msg_id].msg->resp, tmp + 3, ack_data_len);
			chan_mgt->pend_msg[msg_id].msg->ack_len = (u16)ack_data_len;
		}

		return 0;
	}

	data_len = sizeof(union nbl_chan_tx_desc) + chan_send->arg_len;
	data = kzalloc(data_len, GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	tx_desc = (union nbl_chan_tx_desc *)data;
	DESC_W(tx_desc, srcid, NBL_COMMON_TO_MGT_PF(common));
	DESC_W(tx_desc, dstid, chan_send->dstid);
	DESC_W(tx_desc, data_len, 0);
	DESC_W(tx_desc, buf_len, chan_send->arg_len);
	DESC_W(tx_desc, msg_type, chan_send->msg_type);
	memcpy((char *)(tx_desc + 1), chan_send->arg, chan_send->arg_len);

	id = nbl_chan_get_translate_msg_id(chan_mgt, chan_send);
	if (id == U16_MAX) {
		ret = -EBUSY;
		goto free_data;
	}

	DESC_W(tx_desc, msgid, id);
	nbl_chan_recv_msg(chan_mgt, chan_info, data, data_len);
	if (!chan_send->ack)
		goto free_data;

	spin_lock(&chan_mgt->translate_lock);
	ret = chan_mgt->pend_msg[id].ack_ret;
	chan_mgt->pend_msg[id].msg = NULL;
	spin_unlock(&chan_mgt->translate_lock);

free_data:
	kfree(data);

	return ret;
}

static void nbl_chan_clean_queue_subtask(void *priv, u8 chan_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	if (!test_bit(NBL_CHAN_INTERRUPT_READY, chan_info->state) ||
	    test_bit(NBL_CHAN_RESETTING, chan_info->state))
		return;

	nbl_chan_clean_queue(chan_mgt, chan_info);
}

static int nbl_chan_get_msg_id(struct nbl_chan_info *chan_info, union nbl_chan_msg_id *msgid)
{
	struct nbl_chan_waitqueue_head *wait = NULL;
	int valid_loc = chan_info->wait_head_index, i;
	int status;

	for (i = 0; i < NBL_CHAN_QUEUE_LEN; i++) {
		wait = &chan_info->wait[valid_loc];
		status = atomic_read(&wait->status);
		if (status == NBL_MBX_STATUS_IDLE || status == NBL_MBX_STATUS_TIMEOUT) {
			wait->msg_index = NBL_NEXT_ID(wait->msg_index, NBL_CHAN_MSG_INDEX_MAX - 1);
			msgid->info.index = wait->msg_index;
			msgid->info.loc = valid_loc;

			valid_loc = NBL_NEXT_ID(valid_loc, chan_info->num_txq_entries - 1);
			chan_info->wait_head_index = valid_loc;
			return 0;
		}

		valid_loc = NBL_NEXT_ID(valid_loc, chan_info->num_txq_entries - 1);
	}

	return -ENOSPC;
}

static u32 nbl_chan_pf_relay_emp[] = {
	NBL_CHAN_MSG_GET_FIRMWARE_VERSION,
	NBL_CHAN_MSG_SET_SFP_STATE,
	NBL_CHAN_MSG_SET_ETH_LOOPBACK,
	NBL_CHAN_MSG_GET_PORT_STATE,
	NBL_CHAN_MSG_SET_PORT_ADVERTISING,
	NBL_CHAN_MSG_GET_MODULE_INFO,
	NBL_CHAN_MSG_GET_MODULE_EEPROM,
	NBL_CHAN_MSG_SET_ETH_MAC_ADDR,
	NBL_CHAN_MSG_NWAY_RESET,
	NBL_CHAN_MSG_GET_ETH_STATS,
	NBL_CHAN_MSG_GET_MODULE_TEMPERATURE,
	NBL_CHAN_MSG_GET_ETH_ABNORMAL_STATS,
	NBL_CHAN_MSG_GET_ETH_CTRL_STATS,
	NBL_CHAN_MSG_GET_PAUSE_STATS,
	NBL_CHAN_MSG_GET_ETH_MAC_STATS,
	NBL_CHAN_MSG_GET_FEC_STATS,
	NBL_CHAN_MSG_GET_RMON_STATS,
	NBL_CHAN_MSG_SET_WOL
};

static int nbl_chan_get_msg_ack_timeout_and_resend(struct nbl_chan_send_info *chan_send)
{
	u32 msg_num;
	u32 i;

	if (chan_send->msg_type >= NBL_CHAN_MSG_ADMINQ_BEGIN)
		return NBL_CHAN_PF2EMP_ACK_WAIT_TIME;

	msg_num = sizeof(nbl_chan_pf_relay_emp) / sizeof(u32);
	for (i = 0; i < msg_num; i++) {
		if (chan_send->msg_type == nbl_chan_pf_relay_emp[i])
			return NBL_CHAN_PF_RELAY_EMP_ACK_WAIT_TIME;
	}

	return NBL_CHAN_PFVF_ACK_WAIT_TIME;
}

static int nbl_chan_send_msg(void *priv, struct nbl_chan_send_info *chan_send)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = NBL_CHAN_MGT_TO_COMMON(chan_mgt);
	struct nbl_chan_info *chan_info = NBL_CHAN_GET_INFO(chan_mgt, chan_send->dstid);
	struct nbl_chan_waitqueue_head *wait_head;
	union nbl_chan_msg_id msgid = {{0}};
	struct nbl_chan_tx_param tx_param = {0};
	int ret;
	int i = NBL_CHAN_TX_WAIT_ACK_TIMES;
	int chan_ack_timeout_val;

	if (chan_send->arg_len > NBL_CHAN_BUF_LEN - sizeof(union nbl_chan_tx_desc))
		return -EINVAL;

	/* for channel msg translate when df200 userdev */
	if (!chan_info || (common->has_ctrl && chan_send->dstid == NBL_COMMON_TO_MGT_PF(common)))
		return nbl_chan_translate_configuration(chan_mgt, chan_send);

	if (chan_info->failed_cnt >= NBL_CHANNEL_FREEZE_FAILED_CNT)
		return -EPIPE;

	chan_ack_timeout_val = nbl_chan_get_msg_ack_timeout_and_resend(chan_send);

	spin_lock(&chan_info->txq_lock);

	if (test_bit(NBL_CHAN_ABNORMAL, chan_info->state)) {
		spin_unlock(&chan_info->txq_lock);
		return -EIO;
	}

	ret = nbl_chan_get_msg_id(chan_info, &msgid);
	if (ret) {
		spin_unlock(&chan_info->txq_lock);
		nbl_err(common, NBL_DEBUG_MBX, "Channel tx wait head full, send msgtype:%u to dstid:%u failed\n",
			chan_send->msg_type, chan_send->dstid);
		return ret;
	}

	tx_param.msg_type = chan_send->msg_type;
	tx_param.arg = chan_send->arg;
	tx_param.arg_len = chan_send->arg_len;
	tx_param.dstid = chan_send->dstid;
	tx_param.msgid = msgid.id;

	ret = nbl_chan_update_txqueue(chan_mgt, chan_info, &tx_param);
	if (ret) {
		spin_unlock(&chan_info->txq_lock);
		nbl_err(common, NBL_DEBUG_MBX, "Channel tx queue full, send msgtype:%u to dstid:%u failed\n",
			chan_send->msg_type, chan_send->dstid);
		return ret;
	}

	wait_head = &chan_info->wait[msgid.info.loc];
	init_waitqueue_head(&wait_head->wait_queue);
	WRITE_ONCE(wait_head->acked, 0);
	WRITE_ONCE(wait_head->ack_data, chan_send->resp);
	WRITE_ONCE(wait_head->ack_data_len, chan_send->resp_len);
	WRITE_ONCE(wait_head->msg_type, chan_send->msg_type);
	WRITE_ONCE(wait_head->need_waked, chan_send->ack);
	wait_head->msg_index = msgid.info.index;
	if (chan_send->ack)
		atomic_set(&wait_head->status, NBL_MBX_STATUS_WAITING);
	else
		atomic_set(&wait_head->status, NBL_MBX_STATUS_IDLE);

	ret = nbl_chan_kick_tx_ring(chan_mgt, chan_info, chan_send->dstid);

	spin_unlock(&chan_info->txq_lock);

	if (ret) {
		chan_info->failed_cnt++;
		atomic_set(&wait_head->status, NBL_MBX_STATUS_TIMEOUT);
		return -EFAULT;
	}
	chan_info->failed_cnt = 0;

	if (!chan_send->ack)
		return 0;

	if (test_bit(NBL_CHAN_INTERRUPT_READY, chan_info->state)) {
wait_again:
		ret = wait_event_timeout(wait_head->wait_queue, READ_ONCE(wait_head->acked),
					 chan_ack_timeout_val);
		if (!ret) {
			if (atomic_cmpxchg(&wait_head->status, NBL_MBX_STATUS_WAITING,
					   NBL_MBX_STATUS_TIMEOUT) != NBL_MBX_STATUS_WAITING)
				goto wait_again;

			nbl_err(common, NBL_DEBUG_MBX, "Channel waiting ack failed, message type: %d, msg id: %u\n",
				chan_send->msg_type, msgid.id);
			return -EFAULT;
		}

		/* read barrier to order the status check before reading the emp ack */
		rmb();
		chan_send->ack_len = READ_ONCE(wait_head->ack_data_len);
		atomic_set(&wait_head->status, NBL_MBX_STATUS_IDLE);

		return READ_ONCE(wait_head->ack_err);
	}

	/*polling wait mailbox ack*/
	while (i--) {
		nbl_chan_clean_queue(chan_mgt, chan_info);

		if (READ_ONCE(wait_head->acked)) {
			chan_send->ack_len = READ_ONCE(wait_head->ack_data_len);
			atomic_set(&wait_head->status, NBL_MBX_STATUS_IDLE);
			return READ_ONCE(wait_head->ack_err);
		}
		usleep_range(NBL_CHAN_TX_WAIT_ACK_US_MIN, NBL_CHAN_TX_WAIT_ACK_US_MAX);
	}

	atomic_set(&wait_head->status, NBL_MBX_STATUS_TIMEOUT);
	nbl_err(common, NBL_DEBUG_MBX, "Channel polling ack failed, message type: %d msg id: %u\n",
		chan_send->msg_type, msgid.id);

	return -EFAULT;
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

static void nbl_chan_unregister_msg(void *priv, u16 msg_type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;

	nbl_chan_delete_msg_handler(chan_mgt, msg_type);
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

static int nbl_chan_dump_txq(void *priv, struct seq_file *m, u8 type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = type == NBL_CHAN_TYPE_MAILBOX ?
						  NBL_CHAN_MGT_TO_MAILBOX(chan_mgt) :
						  NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	struct nbl_chan_ring *txq = &chan_info->txq;
	struct nbl_chan_waitqueue_head *wait;
	union nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_buf *tx_buf;
	u32 *payload;
	u16 payload_len = 0;
	union nbl_chan_msg_id ack_msgid = {{0}};
	u32 ack_msgtype = 0;
	int ack_err;
	int i;

	seq_printf(m, "q_base_addr:%pad, txq size:%u, next_to_use:%u, tail_ptr:%u, next_to_clean:%u\n",
		   &txq->dma, chan_info->num_txq_entries, txq->next_to_use,
		   txq->tail_ptr, txq->next_to_clean);
	seq_printf(m, "reset times %d\n", chan_info->txq_reset_times);
	seq_printf(m, "failed_cnt %u\n", chan_info->failed_cnt);

	for (i = 0; i < chan_info->num_txq_entries; i++) {
		tx_desc = NBL_CHAN_TX_RING_TO_DESC(txq, i);
		tx_buf = NBL_CHAN_TX_RING_TO_BUF(txq, i);
		wait = &chan_info->wait[i];
		seq_printf(m, "%u: flags 0x%x srcid %u dstid %u data_len %u buf_len %u msg_type %u msgid %u",
			   i, DESC_R(tx_desc, flags),
			   DESC_R(tx_desc, srcid), DESC_R(tx_desc, dstid),
			   DESC_R(tx_desc, data_len), DESC_R(tx_desc, buf_len),
			   DESC_R(tx_desc, msg_type), DESC_R(tx_desc, msgid));

		if (DESC_R(tx_desc, msg_type) == NBL_CHAN_MSG_ACK) {
			if (DESC_R(tx_desc, data_len)) {
				payload = (void *)DESC_R(tx_desc, data);
				payload_len = DESC_R(tx_desc, data_len);
			} else {
				payload = (void *)(tx_buf->va);
				payload_len = DESC_R(tx_desc, buf_len);
			}
			if (payload_len >= 12) {
				ack_msgtype = *payload;
				ack_msgid.id = *(u16 *)(payload + 1);
				ack_err = *(payload + 2);
				seq_printf(m, " (ack_msgtype %u ack_msgid %u ack_err %d)",
					   ack_msgtype, ack_msgid.id, ack_err);
			}
		}
		seq_printf(m, ", wait acked %u ack_err %u ack_data_len %u need_waked %u msg_type %u\n",
			   READ_ONCE(wait->acked), READ_ONCE(wait->ack_err),
			   READ_ONCE(wait->ack_data_len), READ_ONCE(wait->need_waked),
			   READ_ONCE(wait->msg_type));
	}

	return 0;
}

static int nbl_chan_set_txq(void *priv, u8 type, u32 value)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = type == NBL_CHAN_TYPE_MAILBOX ?
						  NBL_CHAN_MGT_TO_MAILBOX(chan_mgt) :
						  NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	if (value)
		chan_info->failed_cnt = 0;

	return 0;
}

static int nbl_chan_dump_rxq(void *priv, struct seq_file *m, u8 type)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = type == NBL_CHAN_TYPE_MAILBOX ?
						  NBL_CHAN_MGT_TO_MAILBOX(chan_mgt) :
						  NBL_CHAN_MGT_TO_ADMINQ(chan_mgt);
	struct nbl_chan_ring *rxq = &chan_info->rxq;
	union nbl_chan_rx_desc *rx_desc;
	union nbl_chan_tx_desc *tx_desc;
	struct nbl_chan_buf *rx_buf;
	u32 *payload;
	u16 payload_len = 0;
	int i;
	union nbl_chan_msg_id ack_msgid = {{0}};
	u32 ack_msgtype = 0;
	int ack_err;

	seq_printf(m, "q_base_addr:%pad, rxq size:%u, next_to_use:%u, tail_ptr:%u, next_to_clean:%u\n",
		   &rxq->dma, chan_info->num_rxq_entries, rxq->next_to_use,
		   rxq->tail_ptr, rxq->next_to_clean);
	seq_printf(m, "reset times %d\n", chan_info->rxq_reset_times);
	for (i = 0; i < chan_info->num_rxq_entries; i++) {
		rx_desc = NBL_CHAN_RX_RING_TO_DESC(rxq, i);
		rx_buf = NBL_CHAN_RX_RING_TO_BUF(rxq, i);
		tx_desc = (union nbl_chan_tx_desc *)rx_buf->va;

		seq_printf(m, "%u: rx_desc flags 0x%x buf_len 0x%x buf_id 0x%x buffer_addr 0x%llx, tx_desc srcid %u dstid %u data_len %u buf_len %u msg_type %u msgid %u",
			   i, DESC_R(rx_desc, flags), DESC_R(rx_desc, buf_len),
			   DESC_R(rx_desc, buf_id), DESC_R(rx_desc, buf_addr),
			   DESC_R(tx_desc, srcid), DESC_R(tx_desc, dstid),
			   DESC_R(tx_desc, data_len), DESC_R(tx_desc, buf_len),
			   DESC_R(tx_desc, msg_type), DESC_R(tx_desc, msgid));

		if (DESC_R(tx_desc, msg_type) == NBL_CHAN_MSG_ACK) {
			if (DESC_R(tx_desc, data_len)) {
				payload = (void *)DESC_R(tx_desc, data);
				payload_len = DESC_R(tx_desc, data_len);
			} else {
				payload = (void *)(tx_desc + 1);
				payload_len = DESC_R(tx_desc, buf_len);
			}
			if (payload_len >= 12) {
				ack_msgtype = *payload;
				ack_msgid.id = *(u16 *)(payload + 1);
				ack_err = *(payload + 2);
				seq_printf(m, " (ack_msgtype %u ack_msgid %u ack_err %d)",
					   ack_msgtype, ack_msgid.id, ack_err);
			}
		}
		seq_puts(m, "\n");
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

static void nbl_chan_register_chan_task(void *priv, u8 chan_type, struct work_struct *task)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	chan_info->clean_task = task;
}

static void nbl_chan_set_queue_state(void *priv, enum nbl_chan_state state, u8 chan_type, u8 set)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_chan_info *chan_info = NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt, chan_type);

	if (chan_info) {
		if (set)
			set_bit(state, chan_info->state);
		else
			clear_bit(state, chan_info->state);
	}
}

static struct nbl_channel_ops chan_ops = {
	.send_msg			= nbl_chan_send_msg,
	.send_ack			= nbl_chan_send_ack,
	.register_msg			= nbl_chan_register_msg,
	.unregister_msg			= nbl_chan_unregister_msg,
	.cfg_chan_qinfo_map_table	= nbl_chan_cfg_qinfo_map_table,
	.check_queue_exist		= nbl_chan_check_queue_exist,
	.setup_queue			= nbl_chan_setup_queue,
	.teardown_queue			= nbl_chan_teardown_queue,
	.clean_queue_subtask		= nbl_chan_clean_queue_subtask,

	/* for mailbox register msg for userdev */
	.set_listener_info		= nbl_chan_set_listener_info,
	.set_listener_msgtype		= nbl_chan_set_listener_msgtype,
	.clear_listener_info		= nbl_chan_clear_listener_info,
	.dump_txq			= nbl_chan_dump_txq,
	.set_txq			= nbl_chan_set_txq,
	.dump_rxq			= nbl_chan_dump_rxq,
	.get_adminq_tx_buf_size		= nbl_chan_get_adminq_tx_buf_size,

	.init_cmdq			= nbl_chan_cmdq_mgt_start,
	.deinit_cmdq			= nbl_chan_cmdq_mgt_stop,
	.send_cmd			= nbl_chan_send_cmdq,

	.register_chan_task		= nbl_chan_register_chan_task,
	.set_queue_state		= nbl_chan_set_queue_state,
};

static int nbl_chan_setup_chan_mgt(struct nbl_adapter *adapter,
				   struct nbl_init_param *param,
				   struct nbl_channel_mgt_common **chan_mgt_common)
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

	*chan_mgt_common = devm_kzalloc(dev, sizeof(struct nbl_channel_mgt_common), GFP_KERNEL);
	if (!*chan_mgt_common)
		goto alloc_channel_mgt_leonis_fail;

	NBL_CHAN_MGT_TO_COMMON(&(*chan_mgt_common)->chan_mgt) = common;
	(*chan_mgt_common)->chan_mgt.phy_ops_tbl = phy_ops_tbl;
	spin_lock_init(&(*chan_mgt_common)->chan_mgt.translate_lock);

	mailbox = devm_kzalloc(dev, sizeof(struct nbl_chan_info), GFP_KERNEL);
	if (!mailbox)
		goto alloc_mailbox_fail;
	mailbox->chan_type = NBL_CHAN_TYPE_MAILBOX;
	NBL_CHAN_MGT_TO_MAILBOX(&(*chan_mgt_common)->chan_mgt) = mailbox;

	if (param->caps.has_ctrl) {
		adminq = devm_kzalloc(dev, sizeof(struct nbl_chan_info), GFP_KERNEL);
		if (!adminq)
			goto alloc_adminq_fail;
		adminq->chan_type = NBL_CHAN_TYPE_ADMINQ;
		NBL_CHAN_MGT_TO_ADMINQ(&(*chan_mgt_common)->chan_mgt) = adminq;
	}

	ret = nbl_chan_init_msg_handler(&(*chan_mgt_common)->chan_mgt, param->caps.has_user);
	if (ret)
		goto init_chan_msg_handle;

	return 0;

init_chan_msg_handle:
	if (adminq)
		devm_kfree(dev, adminq);
alloc_adminq_fail:
	devm_kfree(dev, mailbox);
alloc_mailbox_fail:
	devm_kfree(dev, *chan_mgt_common);
	*chan_mgt_common = NULL;
alloc_channel_mgt_leonis_fail:
	return -ENOMEM;
}

static void nbl_chan_remove_chan_mgt(struct nbl_common_info *common,
				     struct nbl_channel_mgt_common **chan_mgt_common)
{
	struct device *dev = NBL_COMMON_TO_DEV(common);

	nbl_chan_remove_msg_handler(&(*chan_mgt_common)->chan_mgt);
	if (NBL_CHAN_MGT_TO_ADMINQ(&(*chan_mgt_common)->chan_mgt))
		devm_kfree(dev, NBL_CHAN_MGT_TO_ADMINQ(&(*chan_mgt_common)->chan_mgt));
	devm_kfree(dev, NBL_CHAN_MGT_TO_MAILBOX(&(*chan_mgt_common)->chan_mgt));

	/* check and remove command queue */
	if ((*chan_mgt_common)->chan_mgt.cmdq_mgt)
		nbl_chan_cmdq_mgt_stop(dev, &(*chan_mgt_common)->chan_mgt,
				       common->tc_inst_id);

	devm_kfree(dev, *chan_mgt_common);
	*chan_mgt_common = NULL;
}

static void nbl_chan_remove_ops(struct device *dev, struct nbl_channel_ops_tbl **chan_ops_tbl)
{
	if (!dev || !chan_ops_tbl)
		return;

	devm_kfree(dev, *chan_ops_tbl);
	*chan_ops_tbl = NULL;
}

static int nbl_chan_setup_ops(struct device *dev, struct nbl_channel_ops_tbl **chan_ops_tbl,
			      struct nbl_channel_mgt_common *chan_mgt_common)
{
	int ret;
	*chan_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_channel_ops_tbl), GFP_KERNEL);
	if (!*chan_ops_tbl)
		return -ENOMEM;

	NBL_CHAN_OPS_TBL_TO_OPS(*chan_ops_tbl) = &chan_ops;
	NBL_CHAN_OPS_TBL_TO_PRIV(*chan_ops_tbl) = chan_mgt_common;

	if (!chan_mgt_common)
		return 0;

	ret = nbl_chan_add_msg_handler(&chan_mgt_common->chan_mgt, NBL_CHAN_MSG_ACK,
				       nbl_chan_recv_ack_msg, chan_mgt_common);
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
	struct nbl_channel_mgt_common **chan_mgt_common;
	struct nbl_channel_ops_tbl **chan_ops_tbl;
	int ret = 0;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	chan_mgt_common = (struct nbl_channel_mgt_common **)&NBL_ADAPTER_TO_CHAN_MGT(adapter);
	chan_ops_tbl = &NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	ret = nbl_chan_setup_chan_mgt(adapter, param, chan_mgt_common);
	if (ret)
		goto setup_mgt_fail;

	ret = nbl_chan_setup_ops(dev, chan_ops_tbl, *chan_mgt_common);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	nbl_chan_remove_chan_mgt(common, chan_mgt_common);
setup_mgt_fail:
	return ret;
}

void nbl_chan_remove_common(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_channel_mgt_common **chan_mgt_common;
	struct nbl_channel_ops_tbl **chan_ops_tbl;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	chan_mgt_common = (struct nbl_channel_mgt_common **)&NBL_ADAPTER_TO_CHAN_MGT(adapter);
	chan_ops_tbl = &NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	nbl_chan_remove_chan_mgt(common, chan_mgt_common);
	nbl_chan_remove_ops(dev, chan_ops_tbl);
}

static int nbl_chan_setup_chan_mgt_draco(struct nbl_adapter *adapter,
					 struct nbl_init_param *param,
					 struct nbl_channel_mgt_common **chan_mgt_common)
{
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_chan_info *mailbox;
	int ret;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	phy_ops_tbl = NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);

	*chan_mgt_common = devm_kzalloc(dev, sizeof(struct nbl_channel_mgt_common), GFP_KERNEL);
	if (!*chan_mgt_common)
		goto alloc_channel_mgt_common_fail;

	NBL_CHAN_MGT_TO_COMMON(&(*chan_mgt_common)->chan_mgt) = common;
	(*chan_mgt_common)->chan_mgt.phy_ops_tbl = phy_ops_tbl;
	spin_lock_init(&(*chan_mgt_common)->chan_mgt.translate_lock);

	mailbox = devm_kzalloc(dev, sizeof(struct nbl_chan_info), GFP_KERNEL);
	if (!mailbox)
		goto alloc_mailbox_fail;
	mailbox->chan_type = NBL_CHAN_TYPE_MAILBOX;
	NBL_CHAN_MGT_TO_MAILBOX(&(*chan_mgt_common)->chan_mgt) = mailbox;

	ret = nbl_chan_init_msg_handler(&(*chan_mgt_common)->chan_mgt, param->caps.has_user);
	if (ret)
		goto init_chan_msg_handle;

	return 0;

init_chan_msg_handle:
	devm_kfree(dev, mailbox);
alloc_mailbox_fail:
	devm_kfree(dev, *chan_mgt_common);
	*chan_mgt_common = NULL;
alloc_channel_mgt_common_fail:
	return -ENOMEM;
}

int nbl_chan_init_draco(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_channel_mgt_common **chan_mgt_common;
	struct nbl_channel_ops_tbl **chan_ops_tbl;
	int ret = 0;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	chan_mgt_common = (struct nbl_channel_mgt_common **)&NBL_ADAPTER_TO_CHAN_MGT(adapter);
	chan_ops_tbl = &NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter);

	ret = nbl_chan_setup_chan_mgt_draco(adapter, param, chan_mgt_common);
	if (ret)
		goto setup_mgt_fail;

	ret = nbl_chan_setup_ops(dev, chan_ops_tbl, *chan_mgt_common);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	nbl_chan_remove_chan_mgt(common, chan_mgt_common);
setup_mgt_fail:
	return ret;
}
