// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "hns3_cae_qres.h"

int hns3_get_qres_rx_value(struct hns3_nic_priv *net_priv, int ring_id,
			   enum param_type type)
{
	struct hns3_enet_ring *ring;
	int tqps_num;
	int num;

	tqps_num = net_priv->ae_handle->kinfo.num_tqps;
	ring = &net_priv->ring[ring_id + tqps_num];
	switch (type) {
	case RX_HEAD_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_RX_RING_HEAD_REG);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case RX_TAIL_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_RX_RING_TAIL_REG);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case RX_EBD_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_RX_RING_EBDNUM_REG_ADRR);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case RX_FBD_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_RX_RING_FBDNUM_REG);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case RX_SOFTWARE_HEAD_TYPE:
		num = ring->next_to_use;
		break;
	case RX_SOFTWARE_TAIL_TYPE:
		num = ring->next_to_clean;
		break;
	default:
		pr_err("please input valid param type!\n");
		return -1;
	}

	return num;
}

int hns3_get_qres_tx_value(struct hns3_nic_priv *net_priv, int ring_id,
			   enum param_type type)
{
	struct hns3_enet_ring *ring;
	int num;

	ring = &net_priv->ring[ring_id];
	switch (type) {
	case TX_HEAD_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_TX_RING_HEAD_REG);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case TX_TAIL_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_TX_RING_TAIL_REG);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case TX_EBD_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_TX_RING_EBDNUM_REG_ADRR);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case TX_FBD_TYPE:
		num = readl_relaxed(ring->tqp->io_base +
				    HNS3_RING_TX_RING_FBDNUM_REG);
		/* Make sure num taken effect before other data is touched */
		rmb();
		break;
	case TX_SOFTWARE_HEAD_TYPE:
		num = ring->next_to_use;
		break;
	case TX_SOFTWARE_TAIL_TYPE:
		num = ring->next_to_clean;
		break;
	default:
		pr_err("please input valid param type!\n");
		return -1;
	}

	return num;
}

void fill_queue_info(struct hns3_nic_priv *net_priv,
		     struct qres_param *out_info, int ring_id)
{
	/* rx info */
	out_info->qid = ring_id;
	out_info->rx_head = hns3_get_qres_rx_value(net_priv, ring_id,
						   RX_HEAD_TYPE);
	out_info->rx_tail = hns3_get_qres_rx_value(net_priv, ring_id,
						   RX_TAIL_TYPE);
	out_info->rx_ebd = hns3_get_qres_rx_value(net_priv, ring_id,
						  RX_EBD_TYPE);
	out_info->rx_fbd = hns3_get_qres_rx_value(net_priv, ring_id,
						  RX_FBD_TYPE);
	out_info->rx_software_head =
	    hns3_get_qres_rx_value(net_priv, ring_id,
				   RX_SOFTWARE_HEAD_TYPE);
	out_info->rx_software_tail =
	    hns3_get_qres_rx_value(net_priv, ring_id,
				   RX_SOFTWARE_TAIL_TYPE);
	/* tx info */
	out_info->tx_head = hns3_get_qres_tx_value(net_priv, ring_id,
						   TX_HEAD_TYPE);
	out_info->tx_tail = hns3_get_qres_tx_value(net_priv, ring_id,
						   TX_TAIL_TYPE);
	out_info->tx_ebd = hns3_get_qres_tx_value(net_priv, ring_id,
						  TX_EBD_TYPE);
	out_info->tx_fbd = hns3_get_qres_tx_value(net_priv, ring_id,
						  TX_FBD_TYPE);
	out_info->tx_software_head =
	    hns3_get_qres_tx_value(net_priv, ring_id,
				   TX_SOFTWARE_HEAD_TYPE);
	out_info->tx_software_tail =
	    hns3_get_qres_tx_value(net_priv, ring_id,
				   TX_SOFTWARE_TAIL_TYPE);
}

int hns3_test_qres_cfg(struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
	struct qres_bufin_param *qres_in_param;
	struct hns3_enet_ring *ring;
	struct qres_param *out_info;
	int bd_index;
	int tqps_num;
	int ring_id;
	bool check;

	check = !buf_in || in_size < sizeof(struct qres_bufin_param) ||
		!buf_out || out_size < sizeof(struct qres_param);
	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	tqps_num = net_priv->ae_handle->kinfo.num_tqps;
	out_info = (struct qres_param *)buf_out;
	qres_in_param = (struct qres_bufin_param *)buf_in;
	ring_id = qres_in_param->queue_id;
	bd_index = qres_in_param->BD_id;

	out_info->num_tqps = tqps_num;

	if (ring_id >= tqps_num || ring_id < 0) {
		pr_err("please input valid qid\n");
		return -1;
	}

	if (qres_in_param->mtype == MTYPE_QUEUE_INFO) {
		fill_queue_info(net_priv, out_info, ring_id);
	} else if (qres_in_param->mtype == MTYPE_BD_INFO) {
		if (qres_in_param->queue_type == TYPE_TX) {
			ring = &net_priv->ring[ring_id];
			if (bd_index >= ring->desc_num || bd_index < 0) {
				out_info->num_bd = ring->desc_num;
				pr_err("please input valid TX BD_id\n");
				return -1;
			}
			out_info->desc = ring->desc[bd_index];
		} else if (qres_in_param->queue_type == TYPE_RX) {
			ring = &net_priv->ring[ring_id + tqps_num];
			if (bd_index >= ring->desc_num || bd_index < 0) {
				out_info->num_bd = ring->desc_num;
				pr_err("please input valid RX BD_id\n");
				return -1;
			}
			out_info->desc = ring->desc[bd_index];
		}
	}

	return 0;
}
