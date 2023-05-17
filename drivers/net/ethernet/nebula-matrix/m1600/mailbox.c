// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/delay.h>

#include "hw.h"
#include "common.h"
#include "interrupt.h"
#include "txrx.h"
#include "ethtool.h"
#include "macvlan.h"
#include "sriov.h"
#include "mailbox.h"

void nbl_af_set_mailbox_bdf_for_all_func(struct nbl_hw *hw)
{
	struct nbl_mailbox_qinfo_map mb_qinfo_map;
	u16 bdf;
	unsigned int i;

	bdf = (((u16)hw->bus) << 8) | PCI_DEVFN((u16)hw->devid, (u16)hw->function);
	memset(&mb_qinfo_map, 0, sizeof(mb_qinfo_map));
	for (i = 0; i < NBL_MAX_FUNC; i++) {
		mb_qinfo_map.function = PCI_FUNC(bdf);
		mb_qinfo_map.devid = PCI_SLOT(bdf);
		mb_qinfo_map.bus = bdf >> 8;
		mb_qinfo_map.valid = 0;
		wr32_for_each(hw, NBL_MAILBOX_M_QINFO_MAP_REG_ARR(i), (u32 *)&mb_qinfo_map,
			      sizeof(mb_qinfo_map));
		bdf++;
	}
}

static void nbl_mailbox_init(struct nbl_mailbox_info *mailbox)
{
	spin_lock_init(&mailbox->txq_lock);

	mutex_init(&mailbox->send_normal_msg_lock);
	mailbox->acked = 0;

	mailbox->num_txq_entries = NBL_MAILBOX_QUEUE_LEN;
	mailbox->num_rxq_entries = NBL_MAILBOX_QUEUE_LEN;
	mailbox->txq_buf_size = NBL_MAILBOX_BUF_LEN;
	mailbox->rxq_buf_size = NBL_MAILBOX_BUF_LEN;
}

static int nbl_mailbox_setup_tx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_mailbox_ring *txq = &mailbox->txq;
	size_t size = mailbox->num_txq_entries * sizeof(struct nbl_mailbox_tx_desc);

	txq->desc = dmam_alloc_coherent(dev, size, &txq->dma, GFP_KERNEL | __GFP_ZERO);
	if (!txq->desc)
		return -ENOMEM;

	txq->buf = devm_kcalloc(dev, mailbox->num_txq_entries,
				sizeof(struct nbl_mailbox_buf), GFP_KERNEL);
	if (!txq->buf) {
		dmam_free_coherent(dev, size, txq->desc, txq->dma);
		txq->desc = NULL;
		txq->dma = 0;
		return -ENOMEM;
	}

	return 0;
}

static void nbl_mailbox_teardown_tx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_mailbox_ring *txq = &mailbox->txq;
	size_t size = mailbox->num_txq_entries * sizeof(struct nbl_mailbox_tx_desc);

	devm_kfree(dev, txq->buf);
	txq->buf = NULL;

	dmam_free_coherent(dev, size, txq->desc, txq->dma);
	txq->desc = NULL;
	txq->dma = 0;
}

static int nbl_mailbox_setup_rx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_mailbox_ring *rxq = &mailbox->rxq;
	size_t size = mailbox->num_rxq_entries * sizeof(struct nbl_mailbox_rx_desc);

	rxq->desc = dmam_alloc_coherent(dev, size, &rxq->dma, GFP_KERNEL | __GFP_ZERO);
	if (!rxq->desc)
		return -ENOMEM;

	rxq->buf = devm_kcalloc(dev, mailbox->num_rxq_entries,
				sizeof(struct nbl_mailbox_buf), GFP_KERNEL);
	if (!rxq->buf) {
		dmam_free_coherent(dev, size, rxq->desc, rxq->dma);
		rxq->desc = NULL;
		rxq->dma = 0;
		return -ENOMEM;
	}

	return 0;
}

static void nbl_mailbox_teardown_rx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_mailbox_ring *rxq = &mailbox->rxq;
	size_t size = mailbox->num_rxq_entries * sizeof(struct nbl_mailbox_rx_desc);

	devm_kfree(dev, rxq->buf);
	rxq->buf = NULL;

	dmam_free_coherent(dev, size, rxq->desc, rxq->dma);
	rxq->desc = NULL;
	rxq->dma = 0;
}

static int nbl_mailbox_setup_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	int err;

	err = nbl_mailbox_setup_tx_queue(hw, mailbox);
	if (err)
		return err;

	err = nbl_mailbox_setup_rx_queue(hw, mailbox);
	if (err)
		goto setup_rx_queue_err;

	return 0;

setup_rx_queue_err:
	nbl_mailbox_teardown_tx_queue(hw, mailbox);
	return err;
}

static void nbl_mailbox_teardown_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	nbl_mailbox_teardown_tx_queue(hw, mailbox);
	nbl_mailbox_teardown_rx_queue(hw, mailbox);
}

static void nbl_mailbox_reset_tx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	u32 value = NBL_MAILBOX_TX_RESET;

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_TX_CMD_FIELD, value);
}

static void nbl_mailbox_reset_rx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	u32 value = NBL_MAILBOX_RX_RESET;

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_RX_CMD_FIELD, value);
}

static void nbl_mailbox_reset_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	nbl_mailbox_reset_tx_queue(hw, mailbox);
	nbl_mailbox_reset_rx_queue(hw, mailbox);
}

static void nbl_mailbox_config_tx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct nbl_mailbox_ring *txq = &mailbox->txq;
	dma_addr_t dma_addr = txq->dma;
	int size_bwid = ilog2(mailbox->num_txq_entries);

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_TX_BASE_ADDR_L_FIELD, (u32)(dma_addr & 0xFFFFFFFF));
	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_TX_BASE_ADDR_H_FIELD, (u32)(dma_addr >> 32));
	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_TX_SIZE_BWID_FIELD, (u32)size_bwid);
}

static void nbl_mailbox_config_rx_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct nbl_mailbox_ring *rxq = &mailbox->rxq;
	dma_addr_t dma_addr = rxq->dma;
	int size_bwid = ilog2(mailbox->num_rxq_entries);

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_RX_BASE_ADDR_L_FIELD, (u32)(dma_addr & 0xFFFFFFFF));
	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_RX_BASE_ADDR_H_FIELD, (u32)(dma_addr >> 32));
	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_RX_SIZE_BWID_FIELD, (u32)size_bwid);
}

static void nbl_mailbox_config_queue(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	nbl_mailbox_config_tx_queue(hw, mailbox);
	nbl_mailbox_config_rx_queue(hw, mailbox);
}

static int nbl_mailbox_alloc_all_tx_bufs(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct nbl_mailbox_ring *txq = &mailbox->txq;
	struct nbl_mailbox_buf *buf;
	u16 i;

	for (i = 0; i < mailbox->num_txq_entries; i++) {
		buf = &txq->buf[i];
		buf->va = dmam_alloc_coherent(nbl_hw_to_dev(hw), mailbox->txq_buf_size,
					      &buf->pa, GFP_KERNEL | __GFP_ZERO);
		if (!buf->va) {
			pr_err("Allocate buffer for mailbox tx queue failed\n");
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
		dmam_free_coherent(nbl_hw_to_dev(hw), mailbox->txq_buf_size, buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}

	return -ENOMEM;
}

static void nbl_mailbox_free_all_tx_bufs(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct nbl_mailbox_ring *txq = &mailbox->txq;
	struct nbl_mailbox_buf *buf;
	u16 i;

	for (i = 0; i < mailbox->num_txq_entries; i++) {
		buf = &txq->buf[i];
		dmam_free_coherent(nbl_hw_to_dev(hw), mailbox->txq_buf_size, buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}
}

static int nbl_mailbox_alloc_all_rx_bufs(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct nbl_mailbox_ring *rxq = &mailbox->rxq;
	struct nbl_mailbox_buf *buf;
	struct nbl_mailbox_rx_desc *desc;
	u16 i;

	for (i = 0; i < mailbox->num_rxq_entries; i++) {
		buf = &rxq->buf[i];
		buf->va = dmam_alloc_coherent(nbl_hw_to_dev(hw), mailbox->rxq_buf_size,
					      &buf->pa, GFP_KERNEL | __GFP_ZERO);
		if (!buf->va) {
			pr_err("Allocate buffer for mailbox rx queue failed\n");
			goto err;
		}
	}

	desc = rxq->desc;
	for (i = 0; i < mailbox->num_rxq_entries - 1; i++) {
		buf = &rxq->buf[i];
		desc[i].flags = NBL_MAILBOX_RX_DESC_AVAIL;
		desc[i].buf_addr = buf->pa;
		desc[i].buf_len = mailbox->rxq_buf_size;
	}

	/* Make sure the descriptor has been written */
	wmb();
	rxq->next_to_clean = 0;
	rxq->next_to_use = mailbox->num_rxq_entries - 1;
	rxq->tail_ptr = mailbox->num_rxq_entries - 1;
	nbl_mailbox_update_rxq_tail_ptr(hw, rxq->tail_ptr);

	return 0;
err:
	while (i--) {
		buf = &rxq->buf[i];
		dmam_free_coherent(nbl_hw_to_dev(hw), mailbox->rxq_buf_size, buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}

	return -ENOMEM;
}

static void nbl_mailbox_free_all_rx_bufs(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	struct nbl_mailbox_ring *rxq = &mailbox->rxq;
	struct nbl_mailbox_buf *buf;
	u16 i;

	for (i = 0; i < mailbox->num_rxq_entries; i++) {
		buf = &rxq->buf[i];
		dmam_free_coherent(nbl_hw_to_dev(hw), mailbox->rxq_buf_size, buf->va, buf->pa);
		buf->va = NULL;
		buf->pa = 0;
	}
}

static int nbl_mailbox_alloc_all_bufs(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	int err;

	err = nbl_mailbox_alloc_all_tx_bufs(hw, mailbox);
	if (err)
		return err;

	err = nbl_mailbox_alloc_all_rx_bufs(hw, mailbox);
	if (err)
		goto alloc_rx_bufs_err;

	return 0;

alloc_rx_bufs_err:
	nbl_mailbox_free_all_tx_bufs(hw, mailbox);
	return err;
}

static void nbl_mailbox_free_all_bufs(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox)
{
	nbl_mailbox_free_all_tx_bufs(hw, mailbox);
	nbl_mailbox_free_all_rx_bufs(hw, mailbox);
}

static void nbl_mailbox_start_tx_queue(struct nbl_hw *hw)
{
	u32 value = NBL_MAILBOX_TX_ENABLE;

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_TX_CMD_FIELD, value);
}

static void nbl_mailbox_stop_tx_queue(struct nbl_hw *hw)
{
	u32 value = 0;

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_TX_CMD_FIELD, value);
}

static void nbl_mailbox_start_rx_queue(struct nbl_hw *hw)
{
	u32 value = NBL_MAILBOX_RX_ENABLE;

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_RX_CMD_FIELD, value);
}

static void nbl_mailbox_stop_rx_queue(struct nbl_hw *hw)
{
	u32 value = 0;

	mb_wr32(hw, NBL_MAILBOX_QINFO_CFG_RX_CMD_FIELD, value);
}

static void nbl_mailbox_start_queue(struct nbl_hw *hw)
{
	nbl_mailbox_start_tx_queue(hw);
	nbl_mailbox_start_rx_queue(hw);
}

static void nbl_mailbox_stop_queue(struct nbl_hw *hw)
{
	nbl_mailbox_stop_tx_queue(hw);
	nbl_mailbox_stop_rx_queue(hw);
}

int nbl_setup_mailbox(struct nbl_hw *hw)
{
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;

	nbl_mailbox_init(mailbox);

	err = nbl_mailbox_setup_queue(hw, mailbox);
	if (err)
		return err;

	nbl_mailbox_reset_queue(hw, mailbox);

	nbl_mailbox_config_queue(hw, mailbox);

	err = nbl_mailbox_alloc_all_bufs(hw, mailbox);
	if (err)
		goto alloc_buf_err;

	nbl_mailbox_start_queue(hw);

	return 0;

alloc_buf_err:
	nbl_mailbox_teardown_queue(hw, mailbox);

	return err;
}

void nbl_teardown_mailbox(struct nbl_hw *hw)
{
	struct nbl_mailbox_info *mailbox = &hw->mailbox;

	nbl_mailbox_stop_queue(hw);

	nbl_mailbox_free_all_bufs(hw, mailbox);

	nbl_mailbox_teardown_queue(hw, mailbox);
}

static void nbl_mailbox_send_msg(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox,
				 u16 dstid, enum nbl_mailbox_msg_type msg_type, void *arg,
				 size_t arg_len)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_mailbox_ring *txq;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_buf *tx_buf;
	unsigned long flags;
	u16 next_to_use;
	int i;

	spin_lock_irqsave(&mailbox->txq_lock, flags);

	txq = &mailbox->txq;
	next_to_use = txq->next_to_use;
	tx_buf = NBL_MAILBOX_TX_BUF(txq, next_to_use);
	tx_desc = NBL_MAILBOX_TX_DESC(txq, next_to_use);

	tx_desc->dstid = dstid;
	tx_desc->msg_type = msg_type;
	WARN_ON(arg_len > NBL_MAILBOX_BUF_LEN - sizeof(*tx_desc));
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		memcpy(tx_buf->va, arg, arg_len);
		tx_desc->buf_addr = tx_buf->pa;
		tx_desc->buf_len = arg_len;
		tx_desc->data_len = 0;
	} else {
		memcpy(tx_desc->data, arg, arg_len);
		tx_desc->buf_len = 0;
		tx_desc->data_len = arg_len;
	}
	tx_desc->flags = NBL_MAILBOX_TX_DESC_AVAIL;

	/* Make sure the descriptor has been written */
	wmb();
	txq->next_to_use++;
	if (txq->next_to_use == mailbox->num_txq_entries)
		txq->next_to_use = 0;
	txq->tail_ptr++;
	nbl_mailbox_update_txq_tail_ptr(hw, txq->tail_ptr);

	i = 0;
	while (!(tx_desc->flags & NBL_MAILBOX_TX_DESC_USED)) {
		udelay(NBL_MAILBOX_TX_WAIT_US);
		i++;
		if (i == NBL_MAILBOX_TX_WAIT_TIMES) {
			dev_err(dev, "Mailbox send message type: %d with descriptor %u timeout\n",
				msg_type, txq->next_to_use);
			break;
		}

		if (!(i % NBL_MAILBOX_TX_UPDATE_NOTIFY_LIMITS))
			nbl_mailbox_update_txq_tail_ptr(hw, txq->tail_ptr);
	}

	txq->next_to_clean = txq->next_to_use;

	spin_unlock_irqrestore(&mailbox->txq_lock, flags);
}

static void nbl_mailbox_poll_once_rxq(struct nbl_hw *hw);

int nbl_mailbox_req_cfg_msix_map_table(struct nbl_hw *hw, u16 requested)
{
	struct nbl_mailbox_cfg_msix_map_table_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_MSIX_MAP_TABLE;
	/* ensure request message related variables are completely written */
	wmb();
	arg.requested = requested;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_MSIX_MAP_TABLE, &arg, sizeof(arg));

	i = 0;
	nbl_mailbox_poll_once_rxq(hw);
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure msix map table ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		nbl_mailbox_poll_once_rxq(hw);
		cpu_relax();
	}
	/* Make sure the mailbox varaiable ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

void nbl_mailbox_req_destroy_msix_map_table(struct nbl_hw *hw)
{
	struct nbl_mailbox_dummy_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_DESTROY_MSIX_MAP_TABLE;
	/* ensure request message related variables are completely written */
	wmb();

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_DESTROY_MSIX_MAP_TABLE, &arg, sizeof(arg));

	i = 0;
	nbl_mailbox_poll_once_rxq(hw);
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait destroy msix map table ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		nbl_mailbox_poll_once_rxq(hw);
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_send_ack_msg(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox,
				     u16 dstid, int err, unsigned int req_msg_type)
{
	struct nbl_mailbox_ack_msg_ret ack_msg_ret;

	ack_msg_ret.req_msg_type = req_msg_type;
	ack_msg_ret.err = err;
	nbl_mailbox_send_msg(hw, mailbox, dstid, NBL_MAILBOX_ACK,
			     &ack_msg_ret, sizeof(ack_msg_ret));
}

static void nbl_mailbox_send_ack_msg_with_data(struct nbl_hw *hw, struct nbl_mailbox_info *mailbox,
					       u16 dstid, int err, unsigned int req_msg_type,
					       void *data, u32 data_len)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_mailbox_ring *txq;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_buf *tx_buf;
	struct nbl_mailbox_ack_msg_ret ack_msg_ret;
	unsigned long flags;
	u16 next_to_use;
	size_t arg_len;
	int i;

	spin_lock_irqsave(&mailbox->txq_lock, flags);

	txq = &mailbox->txq;
	next_to_use = txq->next_to_use;
	tx_buf = NBL_MAILBOX_TX_BUF(txq, next_to_use);
	tx_desc = NBL_MAILBOX_TX_DESC(txq, next_to_use);

	tx_desc->dstid = dstid;
	tx_desc->msg_type = NBL_MAILBOX_ACK;

	ack_msg_ret.req_msg_type = req_msg_type;
	ack_msg_ret.err = err;
	arg_len = data_len + sizeof(ack_msg_ret);
	WARN_ON(arg_len > NBL_MAILBOX_BUF_LEN - sizeof(*tx_desc));
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		memcpy(tx_buf->va, &ack_msg_ret, sizeof(ack_msg_ret));
		memcpy((char *)(tx_buf->va) + sizeof(ack_msg_ret), data, data_len);
		tx_desc->buf_addr = tx_buf->pa;
		tx_desc->buf_len = arg_len;
		tx_desc->data_len = 0;
	} else {
		memcpy(tx_desc->data, &ack_msg_ret, sizeof(ack_msg_ret));
		memcpy((char *)(tx_desc->data) + sizeof(ack_msg_ret), data, data_len);
		tx_desc->buf_len = 0;
		tx_desc->data_len = arg_len;
	}
	tx_desc->flags = NBL_MAILBOX_TX_DESC_AVAIL;

	/* Make sure the descriptor has been written */
	wmb();
	txq->next_to_use++;
	if (txq->next_to_use == mailbox->num_txq_entries)
		txq->next_to_use = 0;
	txq->tail_ptr++;
	nbl_mailbox_update_txq_tail_ptr(hw, txq->tail_ptr);

	i = 0;
	while (!(tx_desc->flags & NBL_MAILBOX_TX_DESC_USED)) {
		udelay(NBL_MAILBOX_TX_WAIT_US);
		i++;
		if (i == NBL_MAILBOX_TX_WAIT_TIMES) {
			dev_err(dev, "Mailbox send message type: %d with descriptor %u timeout\n",
				NBL_MAILBOX_ACK, txq->next_to_use);
			break;
		}

		if (!(i % NBL_MAILBOX_TX_UPDATE_NOTIFY_LIMITS))
			nbl_mailbox_update_txq_tail_ptr(hw, txq->tail_ptr);
	}

	txq->next_to_clean = txq->next_to_use;

	spin_unlock_irqrestore(&mailbox->txq_lock, flags);
}

static void nbl_mailbox_recv_ack_msg(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct device *dev = nbl_hw_to_dev(hw);
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	struct nbl_mailbox_tx_desc *tx_desc = data;
	struct nbl_mailbox_ack_msg_ret *payload;
	u16 payload_len;

	if (tx_desc->data_len) {
		payload = (struct nbl_mailbox_ack_msg_ret *)tx_desc->data;
		payload_len = tx_desc->data_len;
	} else {
		payload = (struct nbl_mailbox_ack_msg_ret *)(tx_desc + 1);
		payload_len = tx_desc->buf_len;
	}

	if (mailbox->ack_req_msg_type != payload->req_msg_type) {
		dev_warn(dev, "Unexpected ack message for type %u\n", payload->req_msg_type);
		return;
	}

	mailbox->ack_err = payload->err;
	if (mailbox->ack_err >= 0 && (payload_len - sizeof(*payload))) {
		WARN_ON(payload_len - sizeof(*payload) != mailbox->ack_data_len);
		memcpy((char *)mailbox->ack_data, payload + 1, payload_len - sizeof(*payload));
	}
	/* Make sure the mailbox info has been written */
	wmb();
	mailbox->acked = 1;
}

static void nbl_mailbox_resp_cfg_msix_map_table(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_msix_map_table_arg *arg;
	u16 arg_len;
	u16 srcid;
	u16 requested;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure msix map table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_msix_map_table_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure msix map table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_msix_map_table_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	requested = arg->requested;
	err = nbl_af_configure_func_msix_map(hw, srcid, requested);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

static void nbl_mailbox_resp_destroy_msix_map_table(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	u16 arg_len;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(struct nbl_mailbox_dummy_arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Clean msix map table mailbox message has wrong argument size\n");
			return;
		}
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Clean msix map table mailbox message has wrong argument size\n");
			return;
		}
	}

	srcid = tx_desc->srcid;
	nbl_af_destroy_func_msix_map(hw, srcid);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

static void nbl_af_enable_mailbox_irq(struct nbl_hw *hw, u16 func_id, u16 vector_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_mailbox_qinfo_map mb_qinfo_map;
	struct nbl_msix_info msix_info;
	u16 global_vector_id;
	u8 bus;
	u8 devid;
	u8 function;

	if (!func_res)
		return;

	if (vector_id >= func_res->num_interrupts) {
		pr_err("Mailbox %u request to enable mailbox MSIX irq with vector id %u, but it has %u irq vectors in total\n",
		       func_id, vector_id, func_res->num_interrupts);
		return;
	}
	global_vector_id = func_res->interrupts[vector_id];

	nbl_af_compute_bdf(hw, func_id, &bus, &devid, &function);

	memset(&msix_info, 0, sizeof(msix_info));
	msix_info.intrl_pnum = 0;
	msix_info.intrl_rate = 0;
	msix_info.function = function;
	msix_info.devid = devid;
	msix_info.bus = bus;
	msix_info.valid = 1;
	wr32_for_each(hw, NBL_PADPT_MSIX_INFO_REG_ARR(global_vector_id),
		      (u32 *)&msix_info, sizeof(msix_info));

	rd32_for_each(hw, NBL_MAILBOX_M_QINFO_MAP_REG_ARR(func_id), (u32 *)&mb_qinfo_map,
		      sizeof(mb_qinfo_map));
	mb_qinfo_map.msix_idx = global_vector_id;
	mb_qinfo_map.valid = 1;
	wr32_for_each(hw, NBL_MAILBOX_M_QINFO_MAP_REG_ARR(func_id), (u32 *)&mb_qinfo_map,
		      sizeof(mb_qinfo_map));
}

static void nbl_mailbox_req_enable_mailbox_irq(struct nbl_hw *hw, u16 vector_id)
{
	struct nbl_mailbox_enable_mailbox_irq_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_ENABLE_MAILBOX_IRQ;
	/* ensure request message related variables are completely written */
	wmb();

	arg.vector_id = vector_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_ENABLE_MAILBOX_IRQ, &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait enable mailbox irq ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_enable_mailbox_irq(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_enable_mailbox_irq_arg *arg;
	u16 arg_len;
	u16 srcid;
	u16 vector_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Enable mailbox irq mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_enable_mailbox_irq_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Enable mailbox irq mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_enable_mailbox_irq_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	vector_id = arg->vector_id;
	nbl_af_enable_mailbox_irq(hw, srcid, vector_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_enable_irq(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u16 local_vector_id;

	local_vector_id = adapter->num_lan_msix;
	/* AF has an hidden forward queue */
	local_vector_id += is_af(hw) ? 1 : 0;
	if (is_af(hw))
		nbl_af_enable_mailbox_irq(hw, 0, local_vector_id);
	else
		nbl_mailbox_req_enable_mailbox_irq(hw, local_vector_id);
}

static void nbl_af_disable_mailbox_irq(struct nbl_hw *hw, u16 func_id, u16 vector_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_mailbox_qinfo_map mb_qinfo_map;
	struct nbl_msix_info msix_info;
	u16 global_vector_id;

	if (!func_res)
		return;

	if (vector_id >= func_res->num_interrupts) {
		pr_err("Mailbox %u request to disable mailbox MSIX irq with vector id %u, but it has %u irq vectors in total\n",
		       func_id, vector_id, func_res->num_interrupts);
		return;
	}
	global_vector_id = func_res->interrupts[vector_id];

	rd32_for_each(hw, NBL_MAILBOX_M_QINFO_MAP_REG_ARR(func_id), (u32 *)&mb_qinfo_map,
		      sizeof(mb_qinfo_map));
	mb_qinfo_map.valid = 0;
	wr32_for_each(hw, NBL_MAILBOX_M_QINFO_MAP_REG_ARR(func_id), (u32 *)&mb_qinfo_map,
		      sizeof(mb_qinfo_map));

	memset(&msix_info, 0, sizeof(msix_info));
	wr32_for_each(hw, NBL_PADPT_MSIX_INFO_REG_ARR(global_vector_id),
		      (u32 *)&msix_info, sizeof(msix_info));
}

static void nbl_mailbox_req_disable_mailbox_irq(struct nbl_hw *hw, u16 vector_id)
{
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_DISABLE_MAILBOX_IRQ;
	/* ensure request message related variables are completely written */
	wmb();

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_DISABLE_MAILBOX_IRQ,
			     &vector_id, sizeof(vector_id));

	i = 0;
	nbl_mailbox_poll_once_rxq(hw);
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait disable mailbox irq ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
		nbl_mailbox_poll_once_rxq(hw);
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_disable_mailbox_irq(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_disable_mailbox_irq_arg *arg;
	u16 arg_len;
	u16 srcid;
	u16 local_vector_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Disable mailbox irq mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_disable_mailbox_irq_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Disable mailbox irq mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_disable_mailbox_irq_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_vector_id = arg->local_vector_id;
	nbl_af_disable_mailbox_irq(hw, srcid, local_vector_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_disable_irq(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u16 local_vector_id;

	local_vector_id = adapter->num_lan_msix;
	/* AF has an hidden forward queue */
	local_vector_id += is_af(hw) ? 1 : 0;
	if (is_af(hw))
		nbl_af_disable_mailbox_irq(hw, 0, local_vector_id);
	else
		nbl_mailbox_req_disable_mailbox_irq(hw, local_vector_id);
}

int nbl_mailbox_req_get_vsi_id(struct nbl_hw *hw)
{
	struct nbl_mailbox_dummy_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_VSI_ID;
	/* ensure request message related variables are completely written */
	wmb();

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_VSI_ID, &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get vsi id ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_vsi_id(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_dummy_arg *arg;
	u16 arg_len;
	u16 srcid;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get vsi id mailbox message has wrong argument size\n");
			return;
		}
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get vsi id mailbox message has wrong argument size\n");
			return;
		}
	}

	srcid = tx_desc->srcid;
	err = (int)(unsigned int)srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

int nbl_mailbox_req_register_vf_bar_info(struct nbl_hw *hw, u64 vf_bar_start, u64 vf_bar_len)
{
	struct nbl_mailbox_register_vf_bar_info_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_REGISTER_VF_BAR_INFO;
	/* ensure request message related variables are completely written */
	wmb();

	arg.vf_bar_start = vf_bar_start;
	arg.vf_bar_len = vf_bar_len;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_REGISTER_VF_BAR_INFO, &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait register vf bar info ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return 0;
}

static void nbl_mailbox_resp_register_vf_bar_info(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_register_vf_bar_info_arg *arg;
	u16 arg_len;
	u16 srcid;
	u64 vf_bar_start;
	u64 vf_bar_len;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Register vf bar info mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_register_vf_bar_info_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Register vf bar info mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_register_vf_bar_info_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	vf_bar_start = arg->vf_bar_start;
	vf_bar_len = arg->vf_bar_len;
	nbl_af_register_vf_bar_info(hw, srcid, vf_bar_start, vf_bar_len);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

int nbl_mailbox_req_get_vf_bar_base_addr(struct nbl_hw *hw, u64 *base_addr)
{
	struct nbl_mailbox_dummy_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_VF_BAR_BASE_ADDR;
	mailbox->ack_data = (char *)base_addr;
	mailbox->ack_data_len = sizeof(*base_addr);

	/* Make sure the mailbox info has been written */
	wmb();
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_VF_BAR_BASE_ADDR,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get VF BAR base address ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return 0;
}

static void nbl_mailbox_resp_get_vf_bar_base_addr(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	u16 arg_len;
	u16 srcid;
	u64 base_addr;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(struct nbl_mailbox_dummy_arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get VF BAR base address mailbox message has wrong argument size\n");
			return;
		}
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get VF BAR base address mailbox message has wrong argument size\n");
			return;
		}
	}

	srcid = tx_desc->srcid;
	base_addr = nbl_af_compute_vf_bar_base_addr(hw, srcid);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &base_addr, sizeof(base_addr));
}

int nbl_mailbox_req_cfg_qid_map(struct nbl_hw *hw, u8 num_queues, u64 notify_addr)
{
	struct nbl_mailbox_cfg_qid_map_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_QID_MAP;
	/* ensure request message related variables are completely written */
	wmb();

	arg.num_queues = num_queues;
	arg.notify_addr = notify_addr;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_QID_MAP, &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure qid map ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_cfg_qid_map(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_qid_map_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 num_queues;
	u64 notify_addr;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure qid map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_qid_map_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure qid map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_qid_map_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	num_queues = arg->num_queues;
	notify_addr = arg->notify_addr;
	err = nbl_af_configure_qid_map(hw, srcid, num_queues, notify_addr);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

void nbl_mailbox_req_clear_qid_map(struct nbl_hw *hw, u64 notify_addr)
{
	struct nbl_mailbox_clear_qid_map_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CLEAR_QID_MAP;
	/* ensure request message related variables are completely written */
	wmb();

	arg.notify_addr = notify_addr;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CLEAR_QID_MAP, &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait clear qid map ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_clear_qid_map(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_clear_qid_map_arg *arg;
	u16 arg_len;
	u16 srcid;
	u64 notify_addr;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(struct nbl_mailbox_clear_qid_map_arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Clear qid map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_clear_qid_map_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Clear qid map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_clear_qid_map_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	notify_addr = arg->notify_addr;
	nbl_af_clear_qid_map(hw, srcid, notify_addr);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_enable_promisc(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_mailbox_cfg_promisc_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	if (!mutex_trylock(&mailbox->send_normal_msg_lock)) {
		pr_info("Can not enable promiscuous mode for accessing lock failed\n");
		return;
	}

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_PROMISC;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.enable = true;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_PROMISC,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		udelay(5);
		i++;
		if (i == 200000) {
			pr_warn("Wait enable eth port promiscuous ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

void nbl_mailbox_req_disable_promisc(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_mailbox_cfg_promisc_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	if (!mutex_trylock(&mailbox->send_normal_msg_lock)) {
		pr_info("Can not disable promiscuous mode for accessing lock failed\n");
		return;
	}

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_PROMISC;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.enable = false;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_PROMISC,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		udelay(5);
		i++;
		if (i == 200000) {
			pr_warn("Wait disable eth port promiscuous ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_promisc(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_promisc_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	bool enable;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure eth port promiscuous mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_promisc_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure eth port promiscuous mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_promisc_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	enable = arg->enable;
	if (!enable)
		nbl_af_disable_promisc(hw, eth_port_id);
	else
		nbl_af_enable_promisc(hw, eth_port_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_ingress_eth_port_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_mailbox_cfg_ingress_eth_port_table_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_INGRESS_ETH_PORT_TABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.vsi_id = vsi_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_INGRESS_ETH_PORT_TABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure ingress eth port table ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_ingress_eth_port_table(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_ingress_eth_port_table_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	u8 vsi_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure ingress ETH port table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_ingress_eth_port_table_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure ingress ETH port table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_ingress_eth_port_table_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	vsi_id = arg->vsi_id;
	nbl_af_configure_ingress_eth_port_table(hw, eth_port_id, vsi_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_src_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_mailbox_cfg_src_vsi_table_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_SRC_VSI_TABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.vsi_id = vsi_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_SRC_VSI_TABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure source vsi table ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_src_vsi_table(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_src_vsi_table_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	u8 vsi_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure source vsi table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_src_vsi_table_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure source vsi table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_src_vsi_table_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	vsi_id = arg->vsi_id;
	nbl_af_configure_src_vsi_table(hw, eth_port_id, vsi_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_dest_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_mailbox_cfg_dest_vsi_table_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_DEST_VSI_TABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.vsi_id = vsi_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_DEST_VSI_TABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure destination vsi table ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_dest_vsi_table(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_dest_vsi_table_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	u8 vsi_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure destination vsi table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_dest_vsi_table_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure destination vsi table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_dest_vsi_table_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	vsi_id = arg->vsi_id;
	nbl_af_configure_dest_vsi_table(hw, eth_port_id, vsi_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_tx_ring(struct nbl_hw *hw, dma_addr_t dma, u16 desc_num,
				 u8 vsi_id, u8 local_queue_id)
{
	struct nbl_mailbox_cfg_tx_ring_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_TX_RING;
	/* ensure request message related variables are completely written */
	wmb();

	arg.vsi_id = vsi_id;
	arg.local_queue_id = local_queue_id;
	arg.desc_num = desc_num;
	arg.dma = dma;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_TX_RING,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure tx ring ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_tx_ring(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_tx_ring_arg *arg;
	u16 arg_len;
	u16 srcid;
	dma_addr_t dma;
	u16 desc_num;
	u8 vsi_id;
	u8 local_queue_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure tx ring mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_tx_ring_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure tx ring mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_tx_ring_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	vsi_id = arg->vsi_id;
	local_queue_id = arg->local_queue_id;
	desc_num = arg->desc_num;
	dma = arg->dma;
	nbl_af_hw_config_tx_ring(hw, srcid, dma, desc_num, vsi_id, local_queue_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_rx_ring(struct nbl_hw *hw, dma_addr_t dma, u16 desc_num,
				 u32 buf_len, u8 local_queue_id)
{
	struct nbl_mailbox_cfg_rx_ring_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_RX_RING;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_queue_id = local_queue_id;
	arg.desc_num = desc_num;
	arg.buf_len = buf_len;
	arg.dma = dma;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_RX_RING,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure rx ring ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_rx_ring(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_rx_ring_arg *arg;
	u16 arg_len;
	u16 srcid;
	dma_addr_t dma;
	u16 desc_num;
	u32 buf_len;
	u8 local_queue_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure rx ring mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_rx_ring_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure rx ring mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_rx_ring_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	buf_len = arg->buf_len;
	local_queue_id = arg->local_queue_id;
	desc_num = arg->desc_num;
	dma = arg->dma;
	nbl_af_hw_config_rx_ring(hw, srcid, dma, desc_num, buf_len, local_queue_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_queue_map(struct nbl_hw *hw, u8 local_queue_id, bool rx,
				   u16 local_vector_id, bool enable, bool msix_enable)
{
	struct nbl_mailbox_cfg_queue_map_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_QUEUE_MAP;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_queue_id = local_queue_id;
	arg.rx = rx;
	arg.local_vector_id = local_vector_id;
	arg.enable = enable;
	arg.msix_enable = msix_enable;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_QUEUE_MAP,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure queue map ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_queue_map(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_queue_map_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 local_queue_id;
	bool rx;
	u16 local_vector_id;
	bool enable;
	bool msix_enable;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure queue map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_queue_map_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure queue map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_queue_map_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_queue_id = arg->local_queue_id;
	rx = arg->rx;
	local_vector_id = arg->local_vector_id;
	enable = arg->enable;
	msix_enable = arg->msix_enable;
	nbl_af_configure_queue_map(hw, srcid, local_queue_id, rx, local_vector_id,
				   enable, msix_enable);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_control_queue(struct nbl_hw *hw, u8 local_queue_id, bool rx, bool enable)
{
	struct nbl_mailbox_control_queue_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CONTROL_QUEUE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_queue_id = local_queue_id;
	arg.rx = rx;
	arg.enable = enable;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CONTROL_QUEUE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait control queue enable/disable ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_control_queue(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_control_queue_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 local_queue_id;
	bool rx;
	bool enable;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Control queue mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_control_queue_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Control queue mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_control_queue_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_queue_id = arg->local_queue_id;
	rx = arg->rx;
	enable = arg->enable;
	nbl_af_control_queue(hw, srcid, local_queue_id, rx, enable);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

int nbl_mailbox_req_reset_tx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	struct nbl_mailbox_reset_tx_queue_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_RESET_TX_QUEUE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_queue_id = local_queue_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_RESET_TX_QUEUE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait reset tx queue ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_reset_tx_queue(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_reset_tx_queue_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 local_queue_id;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Reset tx queue mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reset_tx_queue_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Reset tx queue mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reset_tx_queue_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_queue_id = arg->local_queue_id;
	err = nbl_af_reset_tx_queue(hw, srcid, local_queue_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

int nbl_mailbox_req_wait_rx_queue_reset_done(struct nbl_hw *hw, u8 local_queue_id)
{
	struct nbl_mailbox_wait_rx_queue_reset_done_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_WAIT_RX_QUEUE_RESET_DONE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_queue_id = local_queue_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_WAIT_RX_QUEUE_RESET_DONE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait reset rx queue done ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_wait_rx_queue_reset_done(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_wait_rx_queue_reset_done_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 local_queue_id;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Wait rx queue reset done mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_wait_rx_queue_reset_done_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Wait rx queue reset done mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_wait_rx_queue_reset_done_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_queue_id = arg->local_queue_id;
	err = nbl_af_wait_rx_queue_reset_done(hw, srcid, local_queue_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

int nbl_mailbox_req_reset_rx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	struct nbl_mailbox_reset_rx_queue_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_RESET_RX_QUEUE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_queue_id = local_queue_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_RESET_RX_QUEUE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait reset rx queue ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_reset_rx_queue(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_reset_rx_queue_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 local_queue_id;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Reset rx queue mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reset_rx_queue_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Reset rx queue mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reset_rx_queue_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_queue_id = arg->local_queue_id;
	err = nbl_af_reset_rx_queue(hw, srcid, local_queue_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

void nbl_mailbox_req_cfg_port_map(struct nbl_hw *hw, u8 eth_port_id, u8 local_queue_id)
{
	struct nbl_mailbox_cfg_port_map_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_PORT_MAP;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.local_queue_id = local_queue_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_PORT_MAP,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure port map ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_port_map(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_port_map_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	u8 local_queue_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure port map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_port_map_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure port map mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_port_map_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	local_queue_id = arg->local_queue_id;
	nbl_af_configure_port_map(hw, srcid, eth_port_id, local_queue_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_rss_group_table(struct nbl_hw *hw, u8 vsi_id, u8 rx_queue_num)
{
	struct nbl_mailbox_cfg_rss_group_table_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_RSS_GROUP_TABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.vsi_id = vsi_id;
	arg.rx_queue_num = rx_queue_num;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_RSS_GROUP_TABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure rss group table ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_rss_group_table(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_rss_group_table_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 vsi_id;
	u8 rx_queue_num;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure rss group table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_rss_group_table_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure rss group table mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_rss_group_table_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	vsi_id = arg->vsi_id;
	rx_queue_num = arg->rx_queue_num;
	nbl_af_configure_rss_group_table(hw, srcid, vsi_id, rx_queue_num);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_cfg_msix_irq(struct nbl_hw *hw, u16 local_vector_id)
{
	struct nbl_mailbox_cfg_msix_irq_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CFG_MSIX_IRQ;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_vector_id = local_vector_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CFG_MSIX_IRQ,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure MSIX irq ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_cfg_msix_irq(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_cfg_msix_irq_arg *arg;
	u16 arg_len;
	u16 srcid;
	u16 local_vector_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure msix irq mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_msix_irq_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure msix irq mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_cfg_msix_irq_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_vector_id = arg->local_vector_id;
	nbl_af_configure_msix_irq(hw, srcid, local_vector_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_clear_msix_irq_conf(struct nbl_hw *hw, u16 local_vector_id)
{
	struct nbl_mailbox_clear_msix_irq_conf_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CLEAR_MSIX_IRQ_CONF;
	/* ensure request message related variables are completely written */
	wmb();

	arg.local_vector_id = local_vector_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CLEAR_MSIX_IRQ_CONF,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait clear MSIX irq configuration ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_clear_msix_irq_conf(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_clear_msix_irq_conf_arg *arg;
	u16 arg_len;
	u16 srcid;
	u16 local_vector_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Clear msix irq configuration mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_clear_msix_irq_conf_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Clear msix irq configuration mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_clear_msix_irq_conf_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	local_vector_id = arg->local_vector_id;
	nbl_af_clear_msix_irq_conf(hw, srcid, local_vector_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_eth_tx_enable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_mailbox_eth_tx_enable_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_ETH_TX_ENABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_ETH_TX_ENABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait enable eth tx ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_eth_tx_enable(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_adapter *adapter = hw->back;
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_eth_tx_enable_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("ETH tx enable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_tx_enable_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("ETH tx enable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_tx_enable_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_eth_tx_enable(adapter, eth_port_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_eth_tx_disable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_mailbox_eth_tx_disable_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_ETH_TX_DISABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_ETH_TX_DISABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait disable eth tx ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_eth_tx_disable(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_adapter *adapter = hw->back;
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_eth_tx_disable_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("ETH tx disable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_tx_disable_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("ETH tx disable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_tx_disable_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_eth_tx_disable(adapter, eth_port_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_eth_rx_enable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_mailbox_eth_rx_enable_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_ETH_RX_ENABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_ETH_RX_ENABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait enable eth rx ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_eth_rx_enable(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_adapter *adapter = hw->back;
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_eth_rx_enable_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("ETH rx enable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_rx_enable_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("ETH rx enable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_rx_enable_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_eth_rx_enable(adapter, eth_port_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_eth_rx_disable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_mailbox_eth_rx_disable_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_ETH_RX_DISABLE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_ETH_RX_DISABLE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait disable eth rx ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_eth_rx_disable(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_adapter *adapter = hw->back;
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_eth_rx_disable_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("ETH rx disable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_rx_disable_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("ETH rx disable mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_eth_rx_disable_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_eth_rx_disable(adapter, eth_port_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

#ifdef CONFIG_PCI_IOV
void nbl_mailbox_req_enter_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_mailbox_enter_forward_ring_mode_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_ENTER_FORWARD_RING_MODE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.vsi_id = vsi_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_ENTER_FORWARD_RING_MODE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait enter forward ring mode ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_enter_forward_ring_mode(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_enter_forward_ring_mode_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	u8 vsi_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Enter forward ring mode mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_enter_forward_ring_mode_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Enter forward ring mode mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_enter_forward_ring_mode_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	vsi_id = arg->vsi_id;
	nbl_af_enter_forward_ring_mode(hw, eth_port_id, vsi_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_leave_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id)
{
	struct nbl_mailbox_leave_forward_ring_mode_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_LEAVE_FORWARD_RING_MODE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.vsi_id = vsi_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_LEAVE_FORWARD_RING_MODE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait leave forward ring mode ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_leave_forward_ring_mode(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_leave_forward_ring_mode_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	u8 vsi_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Leave forward ring mode mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_leave_forward_ring_mode_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Leave forward ring mode mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_leave_forward_ring_mode_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	vsi_id = arg->vsi_id;
	nbl_af_leave_forward_ring_mode(hw, eth_port_id, vsi_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}
#endif

u32 nbl_mailbox_req_get_firmware_version(struct nbl_hw *hw)
{
	struct nbl_mailbox_dummy_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	u32 firmware_version;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_FIRMWARE_VERSION;
	mailbox->ack_data = (char *)&firmware_version;
	mailbox->ack_data_len = sizeof(firmware_version);
	/* Make sure mailbox info hae been written */
	wmb();
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_FIRMWARE_VERSION,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get firmware version ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return firmware_version;
}

static void nbl_mailbox_resp_get_firmware_version(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	u16 arg_len;
	u32 firmware_version;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(struct nbl_mailbox_dummy_arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get firmware version mailbox message has wrong argument size\n");
			return;
		}
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get firmware version mailbox message has wrong argument size\n");
			return;
		}
	}

	firmware_version = nbl_af_get_firmware_version(hw);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &firmware_version, sizeof(firmware_version));
}

int nbl_mailbox_req_get_module_eeprom(struct nbl_hw *hw, u8 eth_port_id,
				      struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_mailbox_get_module_eeprom_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_MODULE_EEPROM;
	mailbox->ack_data = (char *)data;
	mailbox->ack_data_len = eeprom->len;
	/* Make sure mailbox info hae been written */
	wmb();
	arg.eth_port_id = eth_port_id;
	arg.eeprom = *eeprom;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_MODULE_EEPROM,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get module eeprom ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_module_eeprom(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_module_eeprom_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;
	struct ethtool_eeprom *eeprom;
	u8 *recv_data;
	int err = 0;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get module eeprom mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_module_eeprom_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get module eeprom mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_module_eeprom_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	eeprom = &arg->eeprom;
	recv_data = kmalloc(eeprom->len, GFP_ATOMIC);
	if (!recv_data) {
		pr_err("Allocate memory to store module eeprom failed\n");
		err = -ENOMEM;
	}
	if (!err)
		err = nbl_af_get_module_eeprom(hw, eth_port_id, eeprom, recv_data);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	if (err < 0)
		nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
	else
		nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, err, req_msg_type,
						   recv_data, eeprom->len);

	kfree(recv_data);
}

int nbl_mailbox_req_get_module_info(struct nbl_hw *hw, u8 eth_port_id, struct ethtool_modinfo *info)
{
	struct nbl_mailbox_get_module_info_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_MODULE_INFO;
	mailbox->ack_data = (char *)info;
	mailbox->ack_data_len = sizeof(*info);
	/* Make sure mailbox info hae been written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_MODULE_INFO,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get module information ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_module_info(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_module_info_arg *arg;
	struct ethtool_modinfo info;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;
	int err = 0;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get module information mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_module_info_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get module information mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_module_info_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	err = nbl_af_get_module_info(hw, eth_port_id, &info);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	if (err < 0)
		nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
	else
		nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, err, req_msg_type,
						   &info, sizeof(info));
}

int nbl_mailbox_req_get_eeprom(struct nbl_hw *hw, u32 offset, u32 length, u8 *bytes)
{
	struct nbl_mailbox_get_eeprom_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_EEPROM;
	mailbox->ack_data = (char *)bytes;
	mailbox->ack_data_len = length;
	/* Make sure mailbox info hae been written */
	wmb();
	arg.offset = offset;
	arg.length = length;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_EEPROM,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get eeprom ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_eeprom(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_eeprom_arg *arg;
	u16 arg_len;
	u16 srcid;
	u32 offset;
	u32 length;
	u8 *recv_data;
	unsigned int req_msg_type;
	int err = 0;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get eeprom mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_eeprom_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get eeprom mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_eeprom_arg *)tx_desc->data;
	}

	offset = arg->offset;
	length = arg->length;
	recv_data = kmalloc(length, GFP_ATOMIC);
	if (!recv_data) {
		pr_err("Allocate memory to store eeprom content failed\n");
		err = -ENOMEM;
	}
	if (!err)
		err = nbl_af_get_eeprom(hw, offset, length, recv_data);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	if (err < 0)
		nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
	else
		nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, err, req_msg_type,
						   recv_data, length);

	kfree(recv_data);
}

enum NBL_MODULE_INPLACE_STATUS
nbl_mailbox_req_check_module_inplace(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_mailbox_check_module_inplace_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	enum NBL_MODULE_INPLACE_STATUS inplace;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CHECK_MODULE_INPLACE;
	mailbox->ack_data = (char *)&inplace;
	mailbox->ack_data_len = sizeof(inplace);
	/* ensure args are completely written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CHECK_MODULE_INPLACE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait check module inplace information ack message timeout\n");
			goto err_out;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return inplace;

err_out:
	mutex_unlock(&mailbox->send_normal_msg_lock);
	return NBL_MODULE_NOT_INPLACE;
}

static void nbl_mailbox_resp_check_module_inplace(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_check_module_inplace_arg *arg;
	u16 arg_len;
	u8 eth_port_id;
	u16 srcid;
	enum NBL_MODULE_INPLACE_STATUS inplace;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Check module inplace mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_check_module_inplace_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Check module inplace mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_check_module_inplace_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	inplace = nbl_af_check_module_inplace(hw, eth_port_id);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &inplace, sizeof(inplace));
}

u32 nbl_mailbox_req_get_rxlos(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_mailbox_get_rxlos_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	u32 rxlos;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_RXLOS;
	mailbox->ack_data = (char *)&rxlos;
	mailbox->ack_data_len = sizeof(rxlos);
	/* ensure args are completely written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_RXLOS,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get rxlos information ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return rxlos;
}

static void nbl_mailbox_resp_get_rxlos(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_rxlos_arg *arg;
	u16 arg_len;
	u8 eth_port_id;
	u16 srcid;
	u32 rxlos;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get rxlos mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_rxlos_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get rxlos mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_rxlos_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	rxlos = nbl_af_get_rxlos(hw, eth_port_id);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &rxlos, sizeof(rxlos));
}

void nbl_mailbox_req_reset_eth(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_mailbox_reset_eth_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_RESET_ETH;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_RESET_ETH,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait reset eth ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_reset_eth(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_reset_eth_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Reset eth mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reset_eth_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("reset eth mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reset_eth_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_reset_eth(hw, eth_port_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

int nbl_mailbox_req_config_module_speed(struct nbl_hw *hw, u8 target_speed, u8 eth_port_id)
{
	struct nbl_mailbox_config_module_speed_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int speed_stat;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CONFIG_MODULE_SPEED;
	mailbox->ack_data = (char *)&speed_stat;
	mailbox->ack_data_len = sizeof(speed_stat);
	/* ensure args are completely written */
	wmb();
	arg.eth_port_id = eth_port_id;
	arg.target_speed = target_speed;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CONFIG_MODULE_SPEED,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait set eth speed information ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return speed_stat;
}

static void nbl_mailbox_resp_config_module_speed(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_config_module_speed_arg *arg;
	u16 arg_len;
	u8 eth_port_id;
	u8 target_speed;
	u16 srcid;
	int speed_stat;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Set eth speed mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_config_module_speed_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Set eth speed mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_config_module_speed_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	target_speed = arg->target_speed;
	speed_stat = nbl_af_config_module_speed(hw, target_speed, eth_port_id);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &speed_stat, sizeof(speed_stat));
}

int nbl_mailbox_req_link_speed(struct nbl_hw *hw, u8 eth_port_id, u32 *speed_stat)
{
	struct nbl_mailbox_get_link_speed_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_LINK_SPEED;
	mailbox->ack_data = (char *)speed_stat;
	mailbox->ack_data_len = sizeof(*speed_stat);
	/* ensure args are completely written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_LINK_SPEED,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get link speed information ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* make sure receive mailbox->acked before read ack_err */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_link_speed(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_link_speed_arg *arg;
	u16 arg_len;
	u8 eth_port_id;
	int ret;
	u32 speed_stat;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get link speed mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_link_speed_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get link speed mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_link_speed_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	ret = nbl_af_query_link_speed(hw, eth_port_id, &speed_stat);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, ret, req_msg_type,
					   &speed_stat, sizeof(speed_stat));
}

u64 nbl_mailbox_req_reg_test(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_mailbox_reg_test_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	u64 test_val;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_REG_TEST;
	mailbox->ack_data = (char *)&test_val;
	mailbox->ack_data_len = sizeof(test_val);
	/* ensure args are completely written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_REG_TEST,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait reg test information ack message timeout\n");
			goto err_out;
		}
		cpu_relax();
	}
	/* make sure receive mailbox->acked before read ack_err */
	rmb();
	err = mailbox->ack_err;
	if (err) {
		pr_err("Reg test mailbox ack error: %d\n", err);
		goto err_out;
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return test_val;

err_out:
	mutex_unlock(&mailbox->send_normal_msg_lock);
	return 1;
}

static void nbl_mailbox_resp_reg_test(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_reg_test_arg *arg;
	u16 arg_len;
	u8 eth_port_id;
	u16 srcid;
	u64 test_val;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Ethtool reg test mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reg_test_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Ethtool reg test mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_reg_test_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	test_val = nbl_af_reg_test(hw, eth_port_id);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &test_val, sizeof(test_val));
}

int nbl_mailbox_req_get_ethtool_dump_regs(struct nbl_hw *hw, u32 *regs_buff, u32 count)
{
	struct nbl_mailbox_get_ethtool_dump_regs_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_ETHTOOL_DUMP_REGS;
	mailbox->ack_data = (char *)regs_buff;
	mailbox->ack_data_len = count * sizeof(u32);
	/* make sure mailbox is setup before send */
	wmb();
	arg.count = count;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_ETHTOOL_DUMP_REGS,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get ethtool dump regs information ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* make sure receive mailbox->acked before read ack_err */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_ethtool_dump_regs(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_ethtool_dump_regs_arg *arg;
	u16 arg_len;
	u16 srcid;
	u32 count;
	u32 size;
	u32 *regs_buff;
	unsigned int req_msg_type;
	int err = 0;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Ethtool get regs mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_ethtool_dump_regs_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Ethtool get regs mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_ethtool_dump_regs_arg *)tx_desc->data;
	}

	count = arg->count;
	size = count * sizeof(u32);
	regs_buff = kmalloc(size, GFP_ATOMIC);
	if (!regs_buff) {
		pr_err("Allocate memory to ethtool get regs content failed\n");
		err = -ENOMEM;
	}
	if (!err)
		nbl_af_get_ethtool_dump_regs(hw, regs_buff, count);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	if (err < 0)
		nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
	else
		nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, err,
						   req_msg_type, regs_buff, size);

	kfree(regs_buff);
}

int nbl_mailbox_req_get_board_info(struct nbl_hw *hw, u8 eth_port_id,
				   union nbl_board_info *board_info)
{
	struct nbl_mailbox_get_board_info_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_BOARD_INFO;
	mailbox->ack_data = (char *)board_info;
	mailbox->ack_data_len = sizeof(*board_info);
	/* Make sure mailbox info hae been written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_BOARD_INFO,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get board information ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_board_info(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_board_info_arg *arg;
	union nbl_board_info board_info;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get board info mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_board_info_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get board info mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_board_info_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	err = nbl_af_get_board_info(hw, eth_port_id, &board_info);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	if (err < 0)
		nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
	else
		nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, err, req_msg_type,
						   &board_info, sizeof(board_info));
}

bool nbl_mailbox_req_query_link_status(struct nbl_hw *hw, u8 eth_port_id)
{
	struct nbl_mailbox_query_link_status_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	bool link_up;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_QUERY_LINK_STATUS;
	mailbox->ack_data = (char *)&link_up;
	mailbox->ack_data_len = sizeof(link_up);
	/* Make sure mailbox info hae been written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_QUERY_LINK_STATUS,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait query link status ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			/* assume link is down when timeout */
			return false;
		}
		cpu_relax();
	}
	/* Make sure ack_err read in order */
	rmb();
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return link_up;
}

static void nbl_mailbox_resp_query_link_status(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_query_link_status_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	bool link_up;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Query link status mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_query_link_status_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Query link status mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_query_link_status_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	link_up = nbl_af_query_link_status(hw, eth_port_id);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &link_up, sizeof(link_up));
}

int nbl_mailbox_req_set_phy_id(struct nbl_hw *hw, u8 eth_port_id, enum ethtool_phys_id_state state)
{
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	struct nbl_mailbox_set_phy_id_arg arg;
	int i;
	int ret;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_SET_PHY_ID;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.state = state;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_SET_PHY_ID,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait set phy id status ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			/* return -EINVAL when timeout */
			return -EINVAL;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	mailbox->acked = 0;
	ret = mailbox->ack_err;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return ret;
}

static void nbl_mailbox_resp_set_phy_id(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_set_phy_id_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	enum ethtool_phys_id_state state;
	unsigned int req_msg_type;
	int ret;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Set phy id mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_set_phy_id_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Set phy id mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_set_phy_id_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	state = arg->state;

	ret = nbl_af_set_phys_id(hw, eth_port_id, state);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, ret, req_msg_type);
}

void nbl_mailbox_req_set_pauseparam(struct nbl_hw *hw, u8 eth_port_id, struct nbl_fc_info fc)
{
	struct nbl_mailbox_set_pause_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_SET_PAUSEPARAM;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.fc = fc;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_SET_PAUSEPARAM,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait set pauseparam ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_set_pauseparam(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_set_pause_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("set_pauseparam mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_set_pause_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("set_pauseparam mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_set_pause_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_set_pauseparam(hw, eth_port_id, arg->fc);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_write_mac_to_logic(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr)
{
	struct nbl_mailbox_write_mac_to_logic_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_WRITE_MAC_TO_LOGIC;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	memcpy(arg.smac, mac_addr, ETH_ALEN);

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_WRITE_MAC_TO_LOGIC,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait write mac to logic ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_write_mac_to_logic(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_write_mac_to_logic_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("write_mac_to_logic mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_write_mac_to_logic_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("write_mac_to_logic mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_write_mac_to_logic_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_write_mac_to_logic(hw, eth_port_id, arg->smac);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

void nbl_mailbox_req_get_pause_stats(struct nbl_hw *hw, u8 eth_port_id,
				     struct ethtool_pause_stats *stats)
{
	struct nbl_mailbox_get_pause_stats_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_PAUSE_STATS;
	mailbox->ack_data = (char *)stats;
	mailbox->ack_data_len = sizeof(*stats);
	/* ensure args are completely written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_PAUSE_STATS,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get pause stats ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_get_pause_stats(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_pause_stats_arg *arg;
	struct ethtool_pause_stats stats;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get pause stats mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_pause_stats_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get pause stats mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_pause_stats_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	nbl_af_get_pause_stats(hw, eth_port_id, &stats);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &stats, sizeof(stats));
}

void nbl_mailbox_req_init_pkt_len_limit(struct nbl_hw *hw, u8 eth_port_id,
					struct nbl_pkt_len_limit pkt_len_limit)
{
	struct nbl_mailbox_init_pkt_len_limit_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_INIT_PKT_LEN_LIMIT;
	/* ensure request message related variables are completely written */
	wmb();

	arg.eth_port_id = eth_port_id;
	arg.pkt_len_limit = pkt_len_limit;

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_INIT_PKT_LEN_LIMIT,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait init pkt len limit ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return;
		}
		cpu_relax();
	}
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);
}

static void nbl_mailbox_resp_init_pkt_len_limit(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_init_pkt_len_limit_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("init_pkt_len_limit mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_init_pkt_len_limit_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("init_pkt_len_limit mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_init_pkt_len_limit_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	eth_port_id = arg->eth_port_id;
	nbl_af_init_pkt_len_limit(hw, eth_port_id, arg->pkt_len_limit);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

int nbl_mailbox_req_get_coalesce(struct nbl_hw *hw, struct ethtool_coalesce *ec,
				 u16 local_vector_id)
{
	struct nbl_mailbox_get_coalesce_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;
	int err;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_COALESCE;
	mailbox->ack_data = (char *)ec;
	mailbox->ack_data_len = sizeof(*ec);
	/* ensure args are completely written */
	wmb();
	arg.local_vector_id = local_vector_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_COALESCE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get coalesce ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_coalesce(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_get_coalesce_arg *arg;
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct ethtool_coalesce ec;
	u16 local_vector_id;
	u16 arg_len;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(struct nbl_mailbox_get_coalesce_arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get coalesce mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_coalesce_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get coalesce mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_coalesce_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	memset(&ec, 0, sizeof(ec));
	local_vector_id = arg->local_vector_id;
	nbl_af_get_coalesce(hw, &ec, srcid, local_vector_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   &ec, sizeof(ec));
}

int nbl_mailbox_req_set_coalesce(struct nbl_hw *hw, u16 local_vector_id,
				 u16 num_q_vectors, u32 regval)
{
	struct nbl_mailbox_set_coalesce_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int i;
	int err;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_SET_COALESCE;
	/* ensure request message related variables are completely written */
	wmb();

	arg.num_q_vectors = num_q_vectors;
	arg.regval = regval;
	arg.local_vector_id = local_vector_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_SET_COALESCE,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait set coalesce ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_set_coalesce(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_set_coalesce_arg *arg;
	u32 regval;
	u16 local_vector_id;
	u16 num_q_vectors;
	u16 arg_len;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(struct nbl_mailbox_set_coalesce_arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Set coalesce mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_set_coalesce_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Set coalesce mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_set_coalesce_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	regval = arg->regval;
	local_vector_id = arg->local_vector_id;
	num_q_vectors = arg->num_q_vectors;
	nbl_af_set_coalesce(hw, srcid, local_vector_id, num_q_vectors, regval);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

int nbl_mailbox_req_get_eth_stats(struct nbl_hw *hw, u8 eth_port_id, struct nbl_hw_stats *hw_stats)
{
	struct nbl_mailbox_get_eth_stats_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_GET_ETH_STATS;
	mailbox->ack_data = (char *)hw_stats;
	mailbox->ack_data_len = sizeof(*hw_stats);
	/* ensure args are completely written */
	wmb();
	arg.eth_port_id = eth_port_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_GET_ETH_STATS,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait get eth stats ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_get_eth_stats(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_eth_stats_arg *arg;
	struct nbl_hw_stats hw_stats;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	unsigned int req_msg_type;
	int ret;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get eth stats mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_eth_stats_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get eth stats mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_eth_stats_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	ret = nbl_af_get_eth_stats(hw, eth_port_id, &hw_stats);

	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, ret, req_msg_type,
					   &hw_stats, sizeof(hw_stats));
}

int nbl_mailbox_req_configure_mac_addr(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u8 vsi_id)
{
	struct nbl_mailbox_configure_mac_addr_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CONFIGURE_MAC_ADDR;
	/* ensure request message related variables are completely written */
	wmb();

	memcpy(arg.mac_addr, mac_addr, ETH_ALEN);
	arg.eth_port_id = eth_port_id;
	arg.vsi_id = vsi_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CONFIGURE_MAC_ADDR,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait configure mac addr ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_configure_mac_addr(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_configure_mac_addr_arg *arg;
	u16 arg_len;
	u8 *mac_addr;
	u8 eth_port_id;
	u8 vsi_id;
	u16 srcid;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Configure mac addr mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_configure_mac_addr_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Configure mac addr mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_configure_mac_addr_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	mac_addr = arg->mac_addr;
	vsi_id = arg->vsi_id;
	srcid = tx_desc->srcid;
	err = nbl_af_configure_mac_addr(hw, srcid, eth_port_id, mac_addr, vsi_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

int nbl_mailbox_req_clear_mac_addr(struct nbl_hw *hw)
{
	struct nbl_mailbox_dummy_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CLEAR_MAC_ADDR;
	/* ensure request message related variables are completely written */
	wmb();

	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CLEAR_MAC_ADDR,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait clear mac addr ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_clear_mac_addr(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_dummy_arg *arg;
	u16 arg_len;
	u16 srcid;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Clear mac addr mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_dummy_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Clear mac addr mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_dummy_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	err = nbl_af_clear_mac_addr(hw, srcid);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

int nbl_mailbox_req_change_mac_addr(struct nbl_hw *hw, u8 *mac_addr, u8 vsi_id)
{
	struct nbl_mailbox_change_mac_addr_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_CHANGE_MAC_ADDR;
	/* ensure request message related variables are completely written */
	wmb();

	memcpy(arg.mac_addr, mac_addr, ETH_ALEN);
	arg.vsi_id = vsi_id;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_CHANGE_MAC_ADDR,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait change mac addr ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_change_mac_addr(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_change_mac_addr_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 *mac_addr;
	u8 vsi_id;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Change mac addr mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_change_mac_addr_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Change mac addr mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_change_mac_addr_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	mac_addr = arg->mac_addr;
	vsi_id = arg->vsi_id;
	err = nbl_af_change_mac_addr(hw, srcid, mac_addr, vsi_id);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

int nbl_mailbox_req_operate_vlan_id(struct nbl_hw *hw, u16 vlan_id, u8 vsi_id, bool add)
{
	struct nbl_mailbox_operate_vlan_id_arg arg;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	int err;
	int i;

	mutex_lock(&mailbox->send_normal_msg_lock);

	mailbox->ack_req_msg_type = NBL_MAILBOX_OPERATE_VLAN_ID;
	/* ensure request message related variables are completely written */
	wmb();

	arg.vsi_id = vsi_id;
	arg.vlan_id = vlan_id;
	arg.add = add;
	nbl_mailbox_send_msg(hw, mailbox, 0, NBL_MAILBOX_OPERATE_VLAN_ID,
			     &arg, sizeof(arg));

	i = 0;
	while (!mailbox->acked) {
		usleep_range(100, 200);
		i++;
		if (i == 10000) {
			pr_warn("Wait operate vlan id ack message timeout\n");
			mutex_unlock(&mailbox->send_normal_msg_lock);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	/* ensure ack is received */
	rmb();
	err = mailbox->ack_err;
	mailbox->acked = 0;
	mutex_unlock(&mailbox->send_normal_msg_lock);

	return err;
}

static void nbl_mailbox_resp_operate_vlan_id(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_operate_vlan_id_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 vsi_id;
	u16 vlan_id;
	bool add;
	unsigned int req_msg_type;
	int err;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Operate vlan id mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_operate_vlan_id_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Operate vlan id mailbox msg has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_operate_vlan_id_arg *)tx_desc->data;
	}

	srcid = tx_desc->srcid;
	vsi_id = arg->vsi_id;
	vlan_id = arg->vlan_id;
	add = arg->add;
	err = nbl_af_operate_vlan_id(hw, srcid, vlan_id, vsi_id, add);

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, err, req_msg_type);
}

/* when receive hello, goodbye and release done msg, do noting but ack */
static void nbl_mailbox_resp_hello_msg(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;
	srcid = tx_desc->srcid;

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

static void nbl_mailbox_resp_goodbye_msg(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;
	srcid = tx_desc->srcid;

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

static void nbl_mailbox_resp_release_done_msg(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	u16 srcid;
	unsigned int req_msg_type;

	tx_desc = data;
	srcid = tx_desc->srcid;

	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	nbl_mailbox_send_ack_msg(hw, mailbox, srcid, 0, req_msg_type);
}

static void nbl_af_get_pmd_vsi_stats(struct nbl_hw *hw, u8 vsi_id, u8 eth_port_id,
				     struct nbl_pmd_stats *stats)
{
	u8 i;
	u32 rxq_pkt_drop_cnt;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[vsi_id];
	u8 nb_rx_queues = func_res->num_txrx_queues;
	u8 global_rx_qid;
	u64 value_high;
	u64 value_low;

	stats->nb_rx_queues = nb_rx_queues;

	for (i = 0; i < nb_rx_queues; i++) {
		global_rx_qid = func_res->txrx_queues[i];
		rd32_for_each(hw, NBL_UVN_DROP_CNT_REG_ARR(global_rx_qid),
			      (u32 *)&rxq_pkt_drop_cnt, sizeof(u32));
		stats->pkt_drop_cnt[i] = rxq_pkt_drop_cnt;
	}

	value_low = rd32(hw, NBL_ETH_RX_BAD_FCS_CNT_L_REG(eth_port_id)) +
		    rd32(hw, NBL_ETH_RX_FRAMING_ERR_CNT_L_REG(eth_port_id)) +
		    rd32(hw, NBL_ETH_RX_BADCODE_CNT_L_REG(eth_port_id));
	value_high = (rd32(hw, NBL_ETH_RX_BAD_FCS_CNT_H_REG(eth_port_id)) & 0xFFFF) +
		     (rd32(hw, NBL_ETH_RX_FRAMING_ERR_CNT_H_REG(eth_port_id)) & 0xFFFF) +
		     (rd32(hw, NBL_ETH_RX_BADCODE_CNT_H_REG(eth_port_id)) & 0xFFFF);
	stats->ierrors = (value_high << 32) + value_low;

	value_low = rd32(hw, NBL_ETH_TX_BAD_FCS_CNT_L_REG(eth_port_id)) +
			 rd32(hw, NBL_ETH_TX_FRAME_ERROR_CNT_L_REG(eth_port_id));
	value_high = (rd32(hw, NBL_ETH_TX_BAD_FCS_CNT_H_REG(eth_port_id)) & 0xFFFF) +
			 (rd32(hw, NBL_ETH_TX_FRAME_ERROR_CNT_H_REG(eth_port_id)) & 0xFFFF);
	stats->oerrors = (value_high << 32) + value_low;

	stats->eth_ipackets = rd32(hw, NBL_URMUX_ETHX_RX_PKT_REG(eth_port_id));

	value_low = rd32(hw, NBL_URMUX_ETHX_RX_BYTE_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_URMUX_ETHX_RX_BYTE_H_REG(eth_port_id));
	stats->eth_ibytes = (value_high << 32) + value_low;

	stats->eth_opackets = rd32(hw, NBL_DMUX_ETHX_TX_PKT_REG(eth_port_id));

	value_low = rd32(hw, NBL_DMUX_ETHX_TX_BYTE_L_REG(eth_port_id));
	value_high = rd32(hw, NBL_DMUX_ETHX_TX_BYTE_H_REG(eth_port_id));
	stats->eth_obytes = (value_high << 32) + value_low;
}

static void nbl_mailbox_resp_get_pmd_stats(struct nbl_hw *hw, void *data, u32 datalen)
{
	struct nbl_mailbox_info *mailbox;
	struct nbl_mailbox_tx_desc *tx_desc;
	struct nbl_mailbox_get_pmd_stats_arg *arg;
	u16 arg_len;
	u16 srcid;
	u8 eth_port_id;
	struct nbl_pmd_stats *stats;
	unsigned int req_msg_type;

	tx_desc = data;

	arg_len = (u16)sizeof(*arg);
	if (arg_len > NBL_MAILBOX_TX_DESC_EMBEDDED_DATA_LEN) {
		if (tx_desc->buf_len != arg_len) {
			pr_err("Get pmd stats mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_pmd_stats_arg *)(tx_desc + 1);
	} else {
		if (tx_desc->data_len != arg_len) {
			pr_err("Get pmd stats mailbox message has wrong argument size\n");
			return;
		}
		arg = (struct nbl_mailbox_get_pmd_stats_arg *)tx_desc->data;
	}

	eth_port_id = arg->eth_port_id;
	srcid = tx_desc->srcid;
	mailbox = &hw->mailbox;
	req_msg_type = tx_desc->msg_type;
	stats = kmalloc(sizeof(*stats), GFP_ATOMIC | __GFP_ZERO);
	if (!stats) {
		nbl_mailbox_send_ack_msg(hw, mailbox, srcid, -ENOMEM, req_msg_type);
		return;
	}

	nbl_af_get_pmd_vsi_stats(hw, srcid, eth_port_id, stats);
	nbl_mailbox_send_ack_msg_with_data(hw, mailbox, srcid, 0, req_msg_type,
					   stats, sizeof(*stats));

	kfree(stats);
}

static void nbl_mailbox_advance_rx_ring(struct nbl_hw *hw, struct nbl_mailbox_ring *rxq)
{
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	struct nbl_mailbox_rx_desc *rx_desc;
	struct nbl_mailbox_buf *rx_buf;
	u16 next_to_use;

	next_to_use = rxq->next_to_use;
	rx_desc = NBL_MAILBOX_RX_DESC(rxq, next_to_use);
	rx_buf = NBL_MAILBOX_RX_BUF(rxq, next_to_use);

	rx_desc->flags = NBL_MAILBOX_RX_DESC_AVAIL;
	rx_desc->buf_addr = rx_buf->pa;
	rx_desc->buf_len = mailbox->rxq_buf_size;

	/* Make sure descriptor hae been written */
	wmb();
	rxq->next_to_use++;
	if (rxq->next_to_use == mailbox->num_rxq_entries)
		rxq->next_to_use = 0;
	rxq->tail_ptr++;
	nbl_mailbox_update_rxq_tail_ptr(hw, rxq->tail_ptr);
}

#define NBL_FUNC_ARR_ENTRY(type, func)[type] = func
static nbl_mailbox_msg_handler nbl_mailbox_handlers[NBL_MAILBOX_TYPE_MAX] = {
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_ACK, nbl_mailbox_recv_ack_msg),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_MSIX_MAP_TABLE, nbl_mailbox_resp_cfg_msix_map_table),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_DESTROY_MSIX_MAP_TABLE,
			   nbl_mailbox_resp_destroy_msix_map_table),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_ENABLE_MAILBOX_IRQ, nbl_mailbox_resp_enable_mailbox_irq),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_DISABLE_MAILBOX_IRQ, nbl_mailbox_resp_disable_mailbox_irq),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_VSI_ID, nbl_mailbox_resp_get_vsi_id),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_REGISTER_VF_BAR_INFO, nbl_mailbox_resp_register_vf_bar_info),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_VF_BAR_BASE_ADDR, nbl_mailbox_resp_get_vf_bar_base_addr),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_QID_MAP, nbl_mailbox_resp_cfg_qid_map),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CLEAR_QID_MAP, nbl_mailbox_resp_clear_qid_map),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_PROMISC, nbl_mailbox_resp_cfg_promisc),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_INGRESS_ETH_PORT_TABLE,
			   nbl_mailbox_resp_cfg_ingress_eth_port_table),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_SRC_VSI_TABLE, nbl_mailbox_resp_cfg_src_vsi_table),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_DEST_VSI_TABLE, nbl_mailbox_resp_cfg_dest_vsi_table),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_TX_RING, nbl_mailbox_resp_cfg_tx_ring),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_RX_RING, nbl_mailbox_resp_cfg_rx_ring),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_QUEUE_MAP, nbl_mailbox_resp_cfg_queue_map),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CONTROL_QUEUE, nbl_mailbox_resp_control_queue),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_RESET_TX_QUEUE, nbl_mailbox_resp_reset_tx_queue),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_RESET_RX_QUEUE, nbl_mailbox_resp_reset_rx_queue),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_WAIT_RX_QUEUE_RESET_DONE,
			   nbl_mailbox_resp_wait_rx_queue_reset_done),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_PORT_MAP, nbl_mailbox_resp_cfg_port_map),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_RSS_GROUP_TABLE, nbl_mailbox_resp_cfg_rss_group_table),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CFG_MSIX_IRQ, nbl_mailbox_resp_cfg_msix_irq),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CLEAR_MSIX_IRQ_CONF, nbl_mailbox_resp_clear_msix_irq_conf),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_ETH_TX_ENABLE, nbl_mailbox_resp_eth_tx_enable),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_ETH_RX_ENABLE, nbl_mailbox_resp_eth_rx_enable),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_ETH_TX_DISABLE, nbl_mailbox_resp_eth_tx_disable),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_ETH_RX_DISABLE, nbl_mailbox_resp_eth_rx_disable),
#ifdef CONFIG_PCI_IOV
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_ENTER_FORWARD_RING_MODE,
			   nbl_mailbox_resp_enter_forward_ring_mode),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_LEAVE_FORWARD_RING_MODE,
			   nbl_mailbox_resp_leave_forward_ring_mode),
#endif
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_FIRMWARE_VERSION, nbl_mailbox_resp_get_firmware_version),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_MODULE_EEPROM, nbl_mailbox_resp_get_module_eeprom),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_MODULE_INFO, nbl_mailbox_resp_get_module_info),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_EEPROM, nbl_mailbox_resp_get_eeprom),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CHECK_MODULE_INPLACE, nbl_mailbox_resp_check_module_inplace),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_RXLOS, nbl_mailbox_resp_get_rxlos),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_RESET_ETH, nbl_mailbox_resp_reset_eth),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CONFIG_MODULE_SPEED, nbl_mailbox_resp_config_module_speed),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_LINK_SPEED, nbl_mailbox_resp_get_link_speed),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_REG_TEST, nbl_mailbox_resp_reg_test),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_ETHTOOL_DUMP_REGS,
			   nbl_mailbox_resp_get_ethtool_dump_regs),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_BOARD_INFO, nbl_mailbox_resp_get_board_info),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_QUERY_LINK_STATUS, nbl_mailbox_resp_query_link_status),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_SET_PHY_ID, nbl_mailbox_resp_set_phy_id),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_SET_PAUSEPARAM, nbl_mailbox_resp_set_pauseparam),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_WRITE_MAC_TO_LOGIC, nbl_mailbox_resp_write_mac_to_logic),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_PAUSE_STATS, nbl_mailbox_resp_get_pause_stats),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_INIT_PKT_LEN_LIMIT, nbl_mailbox_resp_init_pkt_len_limit),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_COALESCE, nbl_mailbox_resp_get_coalesce),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_SET_COALESCE, nbl_mailbox_resp_set_coalesce),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_ETH_STATS, nbl_mailbox_resp_get_eth_stats),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CONFIGURE_MAC_ADDR, nbl_mailbox_resp_configure_mac_addr),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CLEAR_MAC_ADDR, nbl_mailbox_resp_clear_mac_addr),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_CHANGE_MAC_ADDR, nbl_mailbox_resp_change_mac_addr),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_OPERATE_VLAN_ID, nbl_mailbox_resp_operate_vlan_id),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GET_PMD_VSI_STATS, nbl_mailbox_resp_get_pmd_stats),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_HELLO_MSG, nbl_mailbox_resp_hello_msg),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_GOODBYE_MSG, nbl_mailbox_resp_goodbye_msg),
	NBL_FUNC_ARR_ENTRY(NBL_MAILBOX_RESOURE_RELEASE_DONE, nbl_mailbox_resp_release_done_msg),
};

static void nbl_mailbox_recv_msg(struct nbl_hw *hw, void *data, u32 data_len)
{
	struct nbl_mailbox_tx_desc *tx_desc;
	u16 msg_type;

	tx_desc = data;
	msg_type = tx_desc->msg_type;
	if (msg_type >= NBL_MAILBOX_TYPE_MAX) {
		pr_err("Invalid mailbox message type %u\n", msg_type);
		return;
	}
	nbl_mailbox_handlers[msg_type](hw, data, data_len);
}

/* This function is only used when mailbox interrupt has
 * not been setup yet.
 */
static void nbl_mailbox_poll_once_rxq(struct nbl_hw *hw)
{
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	struct nbl_mailbox_ring *rxq = &mailbox->rxq;
	struct nbl_mailbox_rx_desc *rx_desc;
	struct nbl_mailbox_buf *rx_buf;
	u16 next_to_clean;

	next_to_clean = rxq->next_to_clean;
	rx_desc = NBL_MAILBOX_RX_DESC(rxq, next_to_clean);
	rx_buf = NBL_MAILBOX_RX_BUF(rxq, next_to_clean);
	while (rx_desc->flags & NBL_MAILBOX_RX_DESC_USED) {
		dma_rmb();
		nbl_mailbox_recv_msg(hw, rx_buf->va, rx_desc->buf_len);

		nbl_mailbox_advance_rx_ring(hw, rxq);

		next_to_clean++;
		if (next_to_clean == mailbox->num_rxq_entries)
			next_to_clean = 0;
		rx_desc = NBL_MAILBOX_RX_DESC(rxq, next_to_clean);
		rx_buf = NBL_MAILBOX_RX_BUF(rxq, next_to_clean);
	}
	rxq->next_to_clean = next_to_clean;
}

static void nbl_clean_mailbox(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	struct nbl_mailbox_ring *rxq = &mailbox->rxq;
	struct nbl_mailbox_rx_desc *rx_desc;
	struct nbl_mailbox_buf *rx_buf;
	u16 next_to_clean;

	next_to_clean = rxq->next_to_clean;
	rx_desc = NBL_MAILBOX_RX_DESC(rxq, next_to_clean);
	rx_buf = NBL_MAILBOX_RX_BUF(rxq, next_to_clean);
	while (rx_desc->flags & NBL_MAILBOX_RX_DESC_USED) {
		dma_rmb();
		nbl_mailbox_recv_msg(hw, rx_buf->va, rx_desc->buf_len);

		nbl_mailbox_advance_rx_ring(hw, rxq);

		next_to_clean++;
		if (next_to_clean == mailbox->num_rxq_entries)
			next_to_clean = 0;
		rx_desc = NBL_MAILBOX_RX_DESC(rxq, next_to_clean);
		rx_buf = NBL_MAILBOX_RX_BUF(rxq, next_to_clean);
	}
	rxq->next_to_clean = next_to_clean;
}

void nbl_clean_mailbox_subtask(struct nbl_adapter *adapter)
{
	if (!test_and_clear_bit(NBL_MAILBOX_EVENT_PENDING, adapter->state))
		return;

	nbl_clean_mailbox(adapter);
}

static irqreturn_t nbl_msix_clean_mailbox(int __always_unused irq, void *data)
{
	struct nbl_hw *hw = data;
	struct nbl_adapter *adapter = hw->back;

	set_bit(NBL_MAILBOX_EVENT_PENDING, adapter->state);
	nbl_service_task1_schedule(adapter);
	return IRQ_HANDLED;
}

int nbl_mailbox_request_irq(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_mailbox_info *mailbox = &hw->mailbox;
	u16 local_vector_id;
	u32 irq_num;
	int err;

	/* The first several MSIX irq is used by tx/rx queue,
	 * and the last one is used by mailbox.
	 */
	local_vector_id = adapter->num_lan_msix;
	/* AF has an hidden forward queue used to process
	 * protocol packets.
	 */
	local_vector_id += is_af(hw) ? 1 : 0;
	irq_num = adapter->msix_entries[local_vector_id].vector;

	snprintf(mailbox->name, sizeof(mailbox->name) - 1, "%s-%s",
		 dev_name(dev), "mailbox");

	err = devm_request_irq(dev, irq_num, nbl_msix_clean_mailbox,
			       0, mailbox->name, hw);
	if (err) {
		dev_err(dev, "Request mailbox irq handler failed\n");
		return err;
	}

	return 0;
}

void nbl_mailbox_free_irq(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_hw *hw = &adapter->hw;
	u16 local_vector_id;
	u32 irq_num;

	local_vector_id = adapter->num_lan_msix;
	/* AF has an hidden forward queue used to process
	 * protocol packets.
	 */
	local_vector_id += is_af(hw) ? 1 : 0;
	irq_num = adapter->msix_entries[local_vector_id].vector;

	devm_free_irq(dev, irq_num, hw);
}
