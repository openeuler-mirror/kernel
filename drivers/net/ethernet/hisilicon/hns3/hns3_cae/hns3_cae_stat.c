// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.
#include "hns3_cae_cmd.h"
#include "hns3_cae_stat.h"

const struct ring_stats_name hns3_ring_stats_name[] = {
	{"io_err_cnt", IO_ERR_CNT},
	{"sw_err_cnt", SW_ERR_CNT},
	{"seg_pkt_cnt", SEG_PKT_CNT},
	{"tx_pkts", TX_PKTS},
	{"tx_bytes", TX_BYTES},
	{"tx_err_cnt", TX_ERR_CNT},
	{"restart_queue", RESTART_QUEUE},
	{"tx_busy", TX_BUSY},
	{"rx_pkts", RX_PKTS},
	{"rx_bytes", RX_BYTES},
	{"rx_err_cnt", RX_ERR_CNT},
	{"reuse_pg_cnt", REUSE_PG_CNT},
	{"err_pkt_len", ERR_PKT_LEN},
	{"err_bd_num", ERR_BD_NUM},
	{"l2_err", L2_ERR},
	{"l3l4_csum_err", L3L4_CSUM_ERR},
	{"rx_multicast", RX_MULTICAST},
};

static int hns3_get_stat_val(struct ring_stats *r_stats, char val_name[],
			     u64 **val)
{
	u32 stats_name_id = 0;
	u32 i;

	if (!r_stats || !val_name || !val) {
		pr_info("%s param is null.\n", __func__);
		return HCLGE_ERR_CSQ_ERROR;
	}

	*val = NULL;

	for (i = 0; i < ARRAY_SIZE(hns3_ring_stats_name); i++) {
		if (!strcmp(val_name, hns3_ring_stats_name[i].stats_name)) {
			stats_name_id = hns3_ring_stats_name[i].stats_namd_id;
			break;
		}
	}
	switch (stats_name_id) {
	case IO_ERR_CNT:
		*val = &r_stats->io_err_cnt;
		break;
	case SW_ERR_CNT:
		*val = &r_stats->sw_err_cnt;
		break;
	case SEG_PKT_CNT:
		*val = &r_stats->seg_pkt_cnt;
		break;
	case TX_PKTS:
		*val = &r_stats->tx_pkts;
		break;
	case TX_BYTES:
		*val = &r_stats->tx_bytes;
		break;
	case TX_ERR_CNT:
		*val = &r_stats->tx_err_cnt;
		break;
	case RESTART_QUEUE:
		*val = &r_stats->restart_queue;
		break;
	case TX_BUSY:
		*val = &r_stats->tx_busy;
		break;
	case RX_PKTS:
		*val = &r_stats->rx_pkts;
		break;
	case RX_BYTES:
		*val = &r_stats->rx_bytes;
		break;
	case RX_ERR_CNT:
		*val = &r_stats->rx_err_cnt;
		break;
	case REUSE_PG_CNT:
		*val = &r_stats->reuse_pg_cnt;
		break;
	case ERR_PKT_LEN:
		*val = &r_stats->err_pkt_len;
		break;
	case ERR_BD_NUM:
		*val = &r_stats->err_bd_num;
		break;
	case L2_ERR:
		*val = &r_stats->l2_err;
		break;
	case L3L4_CSUM_ERR:
		*val = &r_stats->l3l4_csum_err;
		break;
	case RX_MULTICAST:
		*val = &r_stats->rx_multicast;
		break;
	default:
		pr_info("val name [%s] is not existed.\n", val_name);
		return HCLGE_ERR_CSQ_ERROR;
	}

	return HCLGE_STATUS_SUCCESS;
}

int hns3_read_stat_mode_cfg(struct hns3_nic_priv *nic_dev,
			    void *buf_in, u32 in_size,
			    void *buf_out, u32 out_size)
{
	struct stat_sw_mode_param *stat_sw_param;
	struct hnae3_knic_private_info *kinfo;
	u64 *ret_data = (u64 *)buf_out;
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	u64 *val = NULL;
	u32 ring_idx;
	int ret;

	handle = nic_dev->ae_handle;
	vport = hns3_cae_get_vport(handle);
	hdev = vport->back;
	kinfo = &handle->kinfo;
	stat_sw_param = (struct stat_sw_mode_param *)buf_in;

	if (!buf_out || out_size < sizeof(u64)) {
		dev_err(&hdev->pdev->dev, "Get stat buf out is null.\n");
		return HCLGE_ERR_CSQ_ERROR;
	}

	ring_idx = stat_sw_param->ring_idx;
	if (ring_idx >= kinfo->num_tqps) {
		dev_err(&hdev->pdev->dev,
			"Get stat ring_idx[%d] >= num_tqps[%d].\n", ring_idx,
			kinfo->num_tqps);
		return HCLGE_ERR_CSQ_ERROR;
	}

	if (stat_sw_param->is_rx)
		ring_idx += kinfo->num_tqps;

	ret = hns3_get_stat_val(&nic_dev->ring[ring_idx].stats,
				stat_sw_param->val_name, &val);
	if (ret || !val) {
		pr_info("get stat val name [%s] error.\n",
			stat_sw_param->val_name);
		return HCLGE_ERR_CSQ_ERROR;
	}

	*ret_data = le64_to_cpu(*val);

	return HCLGE_STATUS_SUCCESS;
}

int hns3_set_stat_mode_cfg(struct hns3_nic_priv *nic_dev,
			   void *buf_in, u32 in_size,
			   void *buf_out, u32 out_size)
{
	struct stat_sw_mode_param *stat_sw_param;
	struct hnae3_knic_private_info *kinfo;
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	u64 *val = NULL;
	u32 ring_idx;
	int ret;

	handle = nic_dev->ae_handle;
	vport = hns3_cae_get_vport(handle);
	hdev = vport->back;
	kinfo = &handle->kinfo;
	stat_sw_param = (struct stat_sw_mode_param *)buf_in;

	ring_idx = stat_sw_param->ring_idx;
	if (ring_idx >= kinfo->num_tqps) {
		dev_err(&hdev->pdev->dev,
			"Set stat ring_idx[%d] >= num_tqps[%d].\n", ring_idx,
			kinfo->num_tqps);
		return HCLGE_ERR_CSQ_ERROR;
	}

	if (stat_sw_param->is_rx)
		ring_idx += kinfo->num_tqps;

	ret = hns3_get_stat_val(&nic_dev->ring[ring_idx].stats,
				stat_sw_param->val_name, &val);
	if (ret || !val) {
		pr_info("Set stat val name [%s] error.\n",
			stat_sw_param->val_name);
		return HCLGE_ERR_CSQ_ERROR;
	}

	*val = cpu_to_le64(stat_sw_param->data);

	return HCLGE_STATUS_SUCCESS;
}

int hns3_stat_mode_cfg(struct hns3_nic_priv *nic_dev,
		       void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
	struct stat_sw_mode_param *mode_param;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(struct stat_sw_mode_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	mode_param = (struct stat_sw_mode_param *)buf_in;
	if (mode_param->is_read == 1)
		ret = hns3_read_stat_mode_cfg(nic_dev, buf_in, in_size, buf_out,
					      out_size);
	else
		ret = hns3_set_stat_mode_cfg(nic_dev, buf_in, in_size, buf_out,
					     out_size);

	return ret;
}
