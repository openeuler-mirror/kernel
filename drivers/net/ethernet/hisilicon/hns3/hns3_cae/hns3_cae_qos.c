// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "hclge_main.h"
#include "hclge_cmd.h"
#include "hns3_enet.h"
#include "hns3_cae_qos.h"

struct hclge_dev *get_val_hdev(struct hns3_nic_priv *net_priv)
{
	struct hnae3_handle *handle;
	struct hclge_vport *vport;

	handle = net_priv->ae_handle;
	vport = hclge_get_vport(handle);
	return vport->back;
}

int hns3_cmd_rx_priv_wl_config(struct hclge_dev *hdev, u16 tc,
			       u32 high, u32 low, u32 en)
{
	struct hclge_rx_priv_wl_buf *req;
	enum hclge_cmd_status status;
	struct hclge_desc desc[2];
	int idx;
	int i;
	int j;

	for (i = 0; i < 2; i++) {
		hclge_cmd_setup_basic_desc(&desc[i],
					   HCLGE_OPC_RX_PRIV_WL_ALLOC, false);
		req = (struct hclge_rx_priv_wl_buf *)desc[i].data;
		/* The first descriptor set the NEXT bit to 1 */
		if (i == 0)
			desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(HCLGE_CMD_FLAG_NEXT);

		for (j = 0; j < HCLGE_TC_NUM_ONE_DESC; j++) {
			idx = i * HCLGE_TC_NUM_ONE_DESC + j;
			if ((tc >> idx) & 0x01) {
				req->tc_wl[j].high = cpu_to_le16(high);
				req->tc_wl[j].high |=
				    cpu_to_le16(en << HCLGE_RX_PRIV_EN_B);
				req->tc_wl[j].low = cpu_to_le16(low);
				req->tc_wl[j].low |=
				    cpu_to_le16(en << HCLGE_RX_PRIV_EN_B);
			}
		}
	}

	/* Send 2 descriptor at one time */
	status = hclge_cmd_send(&hdev->hw, desc, 2);
	if (status) {
		dev_err(&hdev->pdev->dev,
			"Set rx private waterline fail, status %d\n", status);
		return status;
	}
	return 0;
}

int hns3_cae_rx_priv_buff_wl_cfg(struct hns3_nic_priv *net_priv,
				 void *buf_in, u32 in_size,
				 void *buf_out, u32 out_size)
{
	struct hclge_dev *hdev = get_val_hdev(net_priv);
	struct hns3_rx_priv_buff_wl_param *in_info;
	bool check;

	check = !buf_in || in_size < sizeof(struct hns3_rx_priv_buff_wl_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	if (!hnae3_dev_dcb_supported(hdev)) {
		dev_err(&hdev->pdev->dev,
			"This device is not support this cmd!\n");
		return -EPERM;
	}
	in_info = (struct hns3_rx_priv_buff_wl_param *)buf_in;
	pr_err("wl is_set param, tc_no = 0x%x, hight = 0x%x, low = 0x%x\n",
	       in_info->tc_no, in_info->high_wl, in_info->low_wl);

	return hns3_cmd_rx_priv_wl_config(hdev, in_info->tc_no,
					  in_info->high_wl, in_info->low_wl, 1);
}

int hns3_cmd_common_thrd_config(struct hclge_dev *hdev, u16 tc,
				u32 high, u32 low, u32 en)
{
	struct hclge_rx_com_thrd *req;
	enum hclge_cmd_status status;
	struct hclge_desc desc[2];
	int idx;
	int i;
	int j;

	for (i = 0; i < 2; i++) {
		hclge_cmd_setup_basic_desc(&desc[i],
					   HCLGE_OPC_RX_COM_THRD_ALLOC, false);
		req = (struct hclge_rx_com_thrd *)desc[i].data;

		if (i == 0)
			desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(HCLGE_CMD_FLAG_NEXT);

		for (j = 0; j < HCLGE_TC_NUM_ONE_DESC; j++) {
			idx = i * HCLGE_TC_NUM_ONE_DESC + j;
			if ((tc >> idx) & 0x01) {
				req->com_thrd[j].high = cpu_to_le16(high);
				req->com_thrd[j].high |=
				    cpu_to_le16(en << HCLGE_RX_PRIV_EN_B);
				req->com_thrd[j].low = cpu_to_le16(low);
				req->com_thrd[j].low |=
				    cpu_to_le16(en << HCLGE_RX_PRIV_EN_B);
			}
		}
	}

	/* Send 2 descriptors at one time */
	status = hclge_cmd_send(&hdev->hw, desc, 2);
	if (status) {
		dev_err(&hdev->pdev->dev,
			"Set rx common threshold fail, status %d\n", status);
		return status;
	}

	return 0;
}

int hns3_cae_common_thrd_cfg(struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size)
{
	struct hclge_dev *hdev = get_val_hdev(net_priv);
	struct hns3_rx_priv_buff_wl_param *in_info;
	bool check;

	check = !buf_in || in_size < sizeof(struct hns3_rx_priv_buff_wl_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	if (!hnae3_dev_dcb_supported(hdev)) {
		dev_err(&hdev->pdev->dev,
			"This device is not support this cmd!\n");
		return -EPERM;
	}
	in_info = (struct hns3_rx_priv_buff_wl_param *)buf_in;
	pr_info("common thrd is_set param, tc_no = 0x%x, hight = 0x%x, low = 0x%x\n",
		in_info->tc_no, in_info->high_wl, in_info->low_wl);

	return hns3_cmd_common_thrd_config(hdev, in_info->tc_no,
					   in_info->high_wl, in_info->low_wl,
					   1);
}

int hns3_cmd_common_wl_config(struct hclge_dev *hdev, u32 high, u32 low, u32 en)
{
	enum hclge_cmd_status status;
	struct hclge_desc desc;

	struct hclge_rx_com_wl *req = (struct hclge_rx_com_wl *)desc.data;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_COM_WL_ALLOC, false);
	req->com_wl.high = cpu_to_le16(high);
	req->com_wl.high |= cpu_to_le16(en << HCLGE_RX_PRIV_EN_B);
	req->com_wl.low = cpu_to_le16(low);
	req->com_wl.low |= cpu_to_le16(en << HCLGE_RX_PRIV_EN_B);
	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (status) {
		dev_err(&hdev->pdev->dev,
			"Set rx common waterline fail, status %d\n", status);
		return status;
	}

	return 0;
}

int hns3_cae_common_wl_cfg(struct hns3_nic_priv *net_priv,
			   void *buf_in, u32 in_size,
			   void *buf_out, u32 out_size)
{
	struct hns3_rx_priv_buff_wl_param *out_info;
	struct hns3_rx_priv_buff_wl_param *in_info;
	enum hclge_cmd_status status;
	struct hclge_rx_com_wl *req;
	struct hclge_vport *vport;
	struct hclge_desc desc;
	struct hclge_dev *hdev;
	bool check;

	check = !buf_in || in_size < sizeof(struct hns3_rx_priv_buff_wl_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	out_info = (struct hns3_rx_priv_buff_wl_param *)buf_out;
	in_info = (struct hns3_rx_priv_buff_wl_param *)buf_in;

	if (in_info->is_read == IS_WRITE) {
		status = hns3_cmd_common_wl_config(hdev, in_info->high_wl,
						   in_info->low_wl, 1);
	} else {
		check = !buf_out ||
			out_size < sizeof(struct hns3_rx_priv_buff_wl_param);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}

		hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_COM_WL_ALLOC,
					   true);
		status = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (status != 0) {
			dev_err(&hdev->pdev->dev,
				"get rx common waterline fail, status = %d\n",
				status);
			return status;
		}
		req = (struct hclge_rx_com_wl *)desc.data;
		out_info->high_wl = req->com_wl.high;
		out_info->low_wl = req->com_wl.low;
	}

	return status;
}

int hns3_cae_rx_buff_cfg(struct hns3_nic_priv *net_priv,
			 void *buf_in, u32 in_size,
			 void *buf_out, u32 out_size)
{
	struct hclge_rx_priv_buff_cmd *recv;
	struct hns3_rx_buff_param *out_info;
	struct hns3_rx_buff_param *in_info;
	enum hclge_cmd_status status;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	bool check;
	int i;

	check = !buf_in || in_size < sizeof(struct hns3_rx_buff_param) ||
		!buf_out || out_size < sizeof(struct hns3_rx_buff_param);
	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	out_info = (struct hns3_rx_buff_param *)buf_out;
	in_info = (struct hns3_rx_buff_param *)buf_in;

	if (in_info->is_read == IS_READ) {
		hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_PRIV_BUFF_ALLOC,
					   true);
		recv = (struct hclge_rx_priv_buff_cmd *)desc.data;
		status = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (status) {
			pr_err("rx buff get cmd send failed!\n");
			return status;
		}

		for (i = 0; i < HCLGE_MAX_TC_NUM; i++)
			out_info->buff_size[i] = recv->buf_num[i];

		out_info->share_buff = recv->shared_buf;
	}

	return 0;
}

int hns3_cae_tx_buff_cfg(struct hns3_nic_priv *net_priv,
			 void *buf_in, u32 in_size,
			 void *buf_out, u32 out_size)
{
	struct hclge_tx_buff_alloc_cmd *recv;
	struct hns3_tx_buff_param *out_info;
	struct hns3_tx_buff_param *in_info;
	enum hclge_cmd_status status;
	struct hclge_vport *vport;
	struct hclge_desc desc;
	struct hclge_dev *hdev;
	bool check;
	int i;

	check = !buf_in || in_size < sizeof(struct hns3_tx_buff_param) ||
		!buf_out || out_size < sizeof(struct hns3_tx_buff_param);
	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	out_info = (struct hns3_tx_buff_param *)buf_out;
	in_info = (struct hns3_tx_buff_param *)buf_in;

	if (in_info->is_read == IS_READ) {
		hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TX_BUFF_ALLOC,
					   true);
		status = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (status) {
			pr_err("tx buff get cmd send failed!\n");
			return status;
		}
		recv = (struct hclge_tx_buff_alloc_cmd *)desc.data;

		for (i = 0; i < HCLGE_MAX_TC_NUM; i++)
			out_info->buff_size[i] = recv->tx_pkt_buff[i];
	}

	return 0;
}

int hns3_cae_show_comm_thres(struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size)
{
	struct hclge_dev *hdev = get_val_hdev(net_priv);
	struct hns3_total_priv_wl_param *out_info;
	struct hclge_rx_com_thrd *req;
	enum hclge_cmd_status status;
	struct hclge_desc desc[2];
	bool check;
	int idx;
	int i;
	int j;

	check = !buf_out || out_size < sizeof(struct hns3_total_priv_wl_param);
	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	out_info = (struct hns3_total_priv_wl_param *)buf_out;

	for (i = 0; i < 2; i++) {
		hclge_cmd_setup_basic_desc(&desc[i],
					   HCLGE_OPC_RX_COM_THRD_ALLOC, true);
		if (i == 0)
			desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
	}

	status = hclge_cmd_send(&hdev->hw, desc, 2);
	if (status) {
		dev_err(&hdev->pdev->dev,
			"Get rx common threshold fail, status = %d\n", status);
		return status;
	}

	for (i = 0; i < 2; i++) {
		req = (struct hclge_rx_com_thrd *)desc[i].data;
		for (j = 0; j < HCLGE_TC_NUM_ONE_DESC; j++) {
			idx = i * HCLGE_TC_NUM_ONE_DESC + j;
			out_info->priv_wl[idx].high = req->com_thrd[j].high;
			out_info->priv_wl[idx].low = req->com_thrd[j].low;
		}
	}

	return 0;
}

int hns3_cae_show_rx_priv_wl(struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size)
{
	struct hclge_dev *hdev = get_val_hdev(net_priv);
	struct hns3_total_priv_wl_param *out_info;
	struct hclge_rx_priv_wl_buf *req;
	enum hclge_cmd_status status;
	struct hclge_desc desc[2];
	bool check;
	int idx;
	int i;
	int j;

	check = !buf_out || out_size < sizeof(struct hns3_total_priv_wl_param);
	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	out_info = (struct hns3_total_priv_wl_param *)buf_out;

	for (i = 0; i < 2; i++) {
		hclge_cmd_setup_basic_desc(&desc[i], HCLGE_OPC_RX_PRIV_WL_ALLOC,
					   true);
		if (i == 0)
			desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
	}

	status = hclge_cmd_send(&hdev->hw, desc, 2);
	if (status) {
		dev_err(&hdev->pdev->dev,
			"Get rx private waterline fail, statu = %d\n", status);
		return status;
	}

	for (i = 0; i < 2; i++) {
		req = (struct hclge_rx_priv_wl_buf *)desc[i].data;
		for (j = 0; j < HCLGE_TC_NUM_ONE_DESC; j++) {
			idx = i * HCLGE_TC_NUM_ONE_DESC + j;
			out_info->priv_wl[idx].high = req->tc_wl[j].high;
			out_info->priv_wl[idx].low = req->tc_wl[j].low;
		}
	}

	return 0;
}

int hns3_cae_qcn_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
#define HCLGE_OPC_QCN_CFG	0x1A01
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	int qcn_bypass;
	u32 qcn_cfg;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(int);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	qcn_bypass = *(int *)(buf_in);
	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_QCN_CFG, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		return ret;
	qcn_cfg = desc.data[0] & HNS3_QCN_SHAP_BYPASS_MASK;
	hclge_cmd_reuse_desc(&desc, false);
	desc.data[0] = (qcn_cfg | ((qcn_bypass << HNS3_QCN_SHAP_BYPASS_OFF) &
				   HNS3_QOS_QCN_BYPASS_MASK)) &
		       HNS3_QOS_QCN_MASK;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}
