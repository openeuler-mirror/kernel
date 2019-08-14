// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifdef CONFIG_HNS3_TEST
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/phy_fixed.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_priv_rss.h"

#define HASH_ALG_MASK 0XFC

static int hclge_set_rss_algo_key(struct hclge_dev *hdev,
				  const u8 hfunc, const u8 *key)
{
	struct hclge_rss_config_cmd *req;
	enum hclge_cmd_status status;
	struct hclge_desc desc;
	int key_offset;
	int key_size;

	req = (struct hclge_rss_config_cmd *)desc.data;
	for (key_offset = 0; key_offset < 3; key_offset++) {
		hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RSS_GENERIC_CONFIG,
					   false);
		req->hash_config |= (hfunc & HCLGE_RSS_HASH_ALGO_MASK);
		req->hash_config |= (key_offset << HCLGE_RSS_HASH_KEY_OFFSET_B);
		if (key_offset == 2)
			key_size =
			    HCLGE_RSS_KEY_SIZE - HCLGE_RSS_HASH_KEY_NUM * 2;
		else
			key_size = HCLGE_RSS_HASH_KEY_NUM;
		memcpy(req->hash_key,
		       key + key_offset * HCLGE_RSS_HASH_KEY_NUM, key_size);
		status = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (status) {
			dev_err(&hdev->pdev->dev,
				"Configure RSS algo fail, status = %d\n",
				status);
			return -EINVAL;
		}
	}

	return 0;
}

static int hns3_test_set_rss_cfg(struct hns3_nic_priv *net_priv,
				 void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	struct hclge_rss_config_cmd *in_info;
	enum hclge_cmd_status status;
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	u8 hash_config;
	u8 *key;

	handle = net_priv->ae_handle;
	vport = hclge_get_vport(handle);
	hdev = vport->back;
	key = vport->rss_hash_key;

	in_info = (struct hclge_rss_config_cmd *)buf_in;
	hash_config =
	    ((u8)(vport->rss_algo) & (HASH_ALG_MASK)) | in_info->hash_config;
	status = hclge_set_rss_algo_key(hdev, hash_config, key);
	if (status) {
		dev_err(&hdev->pdev->dev,
			"hclge_set_rss_algo_key, status = %d\n", status);
		return -EINVAL;
	}
	vport->rss_algo = hash_config;

	return 0;
}

static int hns3_test_get_rss_cfg(struct hns3_nic_priv *net_priv,
				 void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	struct hclge_rss_config_cmd *req;
	enum hclge_cmd_status status;
	u8 *out_buf = (u8 *)buf_out;
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;

	handle = net_priv->ae_handle;
	vport = hclge_get_vport(handle);
	hdev = vport->back;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RSS_GENERIC_CONFIG, true);
	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (status) {
		dev_err(&hdev->pdev->dev, "%s fail, status is %d.\n",
			__func__, status);
		return status;
	}
	req = (struct hclge_rss_config_cmd *)desc.data;
	*out_buf = req->hash_config;

	return 0;
}

int hns3_test_rss_cfg(struct hns3_nic_priv *net_priv,
		      void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	struct rss_config *mode_param;
	int ret;

	mode_param = (struct rss_config *)buf_in;
	if (!mode_param) {
		pr_err("%s error: mode_param NULL.\n", __func__);
		return -EINVAL;
	}
	if (mode_param->is_read == 1)
		ret = hns3_test_get_rss_cfg(net_priv, buf_in, in_size, buf_out,
					    out_size);
	else
		ret = hns3_test_set_rss_cfg(net_priv, buf_in, in_size, buf_out,
					    out_size);

	return ret;
}
#endif
