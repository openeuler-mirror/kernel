// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

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
#include "hns3_ext.h"
#include "hns3_cae_mactbl.h"

int hns3_test_opt_mactbl(struct hns3_nic_priv *net_priv,
			 void *buf_in, u32 in_size,
			 void *buf_out, u32 out_size)
{
	struct hns3_mac_tbl_para *out = (struct hns3_mac_tbl_para *)buf_out;
	struct hns3_mac_tbl_para *in = (struct hns3_mac_tbl_para *)buf_in;
	struct net_device *netdev = net_priv->netdev;
	struct hnae3_handle *h;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(struct hns3_mac_tbl_para) ||
		!buf_out || out_size < sizeof(struct hns3_mac_tbl_para);
	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	h = hns3_get_handle(netdev);
	if (!h->ae_algo->ops->priv_ops)
		return -EOPNOTSUPP;

	out->op_cmd = in->op_cmd;
	memcpy(out->mac_addr, in->mac_addr, sizeof(in->mac_addr));
	ret = h->ae_algo->ops->priv_ops(h, HNS3_EXT_OPC_OPT_MAC_TABLE, in, 0);
	if (!ret) {
		out->result = HNS3_MACTBL_RESULT_SUCCESS;
		return 0;
	} else if (ret == -ENOENT) {
		out->result = HNS3_MACTBL_RESULT_NOEXIST;
		return 0;
	}

	out->result = HNS3_MACTBL_RESULT_FAIL;

	return ret;
}
