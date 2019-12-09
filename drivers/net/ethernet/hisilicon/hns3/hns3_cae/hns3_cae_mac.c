// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_mac.h"

int hns3_cae_mac_loop_cfg(struct hns3_nic_priv *net_priv,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size)
{
	struct hns3_cae_cfg_serdes_mode_cmd *req1;
	struct hns3_cae_cfg_mac_mode_cmd *req2;
	struct hns3_cae_loop_param *out_info;
	struct hns3_cae_loop_param *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(struct hns3_cae_loop_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct hns3_cae_loop_param *)buf_in;
	out_info = (struct hns3_cae_loop_param *)buf_out;

	req1 = (struct hns3_cae_cfg_serdes_mode_cmd *)&desc.data[0];
	req2 = (struct hns3_cae_cfg_mac_mode_cmd *)&desc.data[0];

	if (in_info->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct hns3_cae_loop_param);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}

		hns3_cae_cmd_setup_basic_desc(&desc,
					      HCLGE_OPC_CONFIG_MAC_MODE, true);
		ret = hns3_cae_cmd_send(hdev, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"mac loopback read fail, ret = %d.\n", ret);
			return -EIO;
		}
		out_info->tx2rx_loop_en =
		    hnae3_get_bit(req2->txrx_pad_fcs_loop_en,
				  HCLGE_MAC_APP_LP_B);
		out_info->rx2tx_loop_en =
		    hnae3_get_bit(req2->txrx_pad_fcs_loop_en,
				  HCLGE_MAC_LINE_LP_B);
		hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_SERDES_LOOPBACK,
					      true);
		ret = hns3_cae_cmd_send(hdev, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"serdes loopback read fail, ret = %d.\n", ret);
			return -EIO;
		}
		out_info->serial_tx2rx_loop_en =
		    hnae3_get_bit(req1->loop_en, SERDES_SERIAL_INNER_LOOP_B);
		out_info->parallel_rx2tx_loop_en =
		    hnae3_get_bit(req1->loop_en, SERDES_PARALLEL_OUTER_LOOP_B);
		out_info->parallel_tx2rx_loop_en =
		    hnae3_get_bit(req1->loop_en, SERDES_PARALLEL_INNER_LOOP_B);
	} else {
		if (in_info->tx2rx_loop_en < MAINTAIN_LOOP_MODE ||
		    in_info->rx2tx_loop_en < MAINTAIN_LOOP_MODE) {
			hns3_cae_cmd_setup_basic_desc(&desc,
						      HCLGE_OPC_CONFIG_MAC_MODE,
						      true);
			ret = hns3_cae_cmd_send(hdev, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"mac loopback set fail, ret = %d.\n",
					ret);
				return -EIO;
			}

			/* 0: off, 1:on, >=2: not set. */
			if (in_info->tx2rx_loop_en < MAINTAIN_LOOP_MODE)
				hnae3_set_bit(req2->txrx_pad_fcs_loop_en,
					      HCLGE_MAC_APP_LP_B,
					      in_info->tx2rx_loop_en);

			/* 0: off, 1:on, >=2: not set. */
			if (in_info->rx2tx_loop_en < MAINTAIN_LOOP_MODE)
				hnae3_set_bit(req2->txrx_pad_fcs_loop_en,
					      HCLGE_MAC_LINE_LP_B,
					      in_info->rx2tx_loop_en);

			hns3_cae_cmd_reuse_desc(&desc, false);
			ret = hns3_cae_cmd_send(hdev, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"mac loopback set fail, ret = %d.\n",
					ret);
				return -EIO;
			}
		} else {
			hns3_cae_cmd_setup_basic_desc(&desc,
						      HCLGE_OPC_SERDES_LOOPBACK,
						      true);
			ret = hns3_cae_cmd_send(hdev, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"mac loopback set fail, ret = %d.\n",
					ret);
				return -EIO;
			}

			/* 0: off, 1:on, >=2: not set. */
			if (in_info->serial_tx2rx_loop_en <
			    MAINTAIN_LOOP_MODE) {
				hnae3_set_bit(req1->loop_en,
					      SERDES_SERIAL_INNER_LOOP_B,
					      in_info->serial_tx2rx_loop_en);
				hnae3_set_bit(req1->loop_valid,
					      SERDES_SERIAL_INNER_LOOP_B, true);
			}
			/* 0: off, 1:on, >=2: not set. */
			if (in_info->parallel_rx2tx_loop_en <
			    MAINTAIN_LOOP_MODE) {
				hnae3_set_bit(req1->loop_en,
					      SERDES_PARALLEL_OUTER_LOOP_B,
					      in_info->parallel_rx2tx_loop_en);
				hnae3_set_bit(req1->loop_valid,
					      SERDES_PARALLEL_OUTER_LOOP_B,
					      true);
			}
			/* 0: off, 1:on, >=2: not set. */
			if (in_info->parallel_tx2rx_loop_en <
			    MAINTAIN_LOOP_MODE) {
				hnae3_set_bit(req1->loop_en,
					      SERDES_PARALLEL_INNER_LOOP_B,
					      in_info->parallel_tx2rx_loop_en);
				hnae3_set_bit(req1->loop_valid,
					      SERDES_PARALLEL_INNER_LOOP_B,
					      true);
			}

			hns3_cae_cmd_reuse_desc(&desc, false);
			ret = hns3_cae_cmd_send(hdev, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"serdes loopback set fail, ret = %d.\n",
					ret);
				return -EIO;
			}
		}
	}

	return 0;
}
