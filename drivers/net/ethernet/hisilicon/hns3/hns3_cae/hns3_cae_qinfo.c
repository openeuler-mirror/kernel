// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "hns3_cae_qinfo.h"

int hns3_get_q_rx_fbd(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;
	int tqps_num;

	tqps_num = net_priv->ae_handle->kinfo.num_tqps;
	ring = &net_priv->ring[ring_id + tqps_num];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_RX_RING_FBDNUM_REG);

	return num;
}

int hns3_get_q_rx_ebd(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;
	int tqps_num;

	tqps_num = net_priv->ae_handle->kinfo.num_tqps;
	ring = &net_priv->ring[ring_id + tqps_num];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_RX_RING_EBDNUM_REG);

	return num;
}

int hns3_get_q_tx_fbd(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;

	ring = &net_priv->ring[ring_id];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_TX_RING_FBDNUM_REG);

	return num;
}

int hns3_get_q_tx_ebd(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;

	ring = &net_priv->ring[ring_id];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_TX_RING_EBDNUM_REG);

	return num;
}

int hns3_get_q_rx_tail(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;
	int tqps_num;

	tqps_num = net_priv->ae_handle->kinfo.num_tqps;
	ring = &net_priv->ring[ring_id + tqps_num];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_RX_RING_TAIL_REG);

	return num;
}

int hns3_get_q_rx_head(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;
	int tqps_num;

	tqps_num = net_priv->ae_handle->kinfo.num_tqps;
	ring = &net_priv->ring[ring_id + tqps_num];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_RX_RING_HEAD_REG);

	return num;
}

int hns3_get_q_tx_tail(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;

	ring = &net_priv->ring[ring_id];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_TX_RING_TAIL_REG);

	return num;
}

int hns3_get_q_tx_head(struct hns3_nic_priv *net_priv, int ring_id)
{
	struct hns3_enet_ring *ring;
	int num;

	ring = &net_priv->ring[ring_id];
	num = readl_relaxed(ring->tqp->io_base + HNS3_RING_TX_RING_HEAD_REG);

	return num;
}

int hns3_cae_qinfo_cfg(struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size,
		       void *buf_out, u32 out_size)
{
	struct qinfo_param *out_info;
	int tqps_num;
	int ring_id;
	int rx_head;
	int rx_tail;
	int rx_ebd;
	int rx_fbd;
	int tx_head;
	int tx_tail;
	int tx_ebd;
	int tx_fbd;
	bool check;

	check = !buf_in || in_size < sizeof(int) ||
		!buf_out || out_size < sizeof(struct qinfo_param);
	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	tqps_num = net_priv->ae_handle->kinfo.num_tqps;
	out_info = (struct qinfo_param *)buf_out;
	ring_id = *((int *)buf_in);

	if (ring_id > tqps_num || ring_id < 0) {
		pr_err("please input valid qid\n");
		return -1;
	}
	rx_head = hns3_get_q_rx_head(net_priv, ring_id);
	rx_tail = hns3_get_q_rx_tail(net_priv, ring_id);
	rx_ebd = hns3_get_q_rx_ebd(net_priv, ring_id);
	rx_fbd = hns3_get_q_rx_fbd(net_priv, ring_id);
	tx_head = hns3_get_q_tx_head(net_priv, ring_id);
	tx_tail = hns3_get_q_tx_tail(net_priv, ring_id);
	tx_ebd = hns3_get_q_tx_ebd(net_priv, ring_id);
	tx_fbd = hns3_get_q_tx_fbd(net_priv, ring_id);
	out_info->qid = ring_id;
	out_info->rx_head = rx_head;
	out_info->rx_tail = rx_tail;
	out_info->rx_ebd = rx_ebd;
	out_info->rx_fbd = rx_fbd;
	out_info->tx_head = tx_head;
	out_info->tx_tail = tx_tail;
	out_info->tx_ebd = tx_ebd;
	out_info->tx_fbd = tx_fbd;
	return 0;
}
