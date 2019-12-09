// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#if (!defined CONFIG_EXT_TEST) && (defined CONFIG_IT_VALIDATION)

#include "hns3_cae_pfc_storm.h"
#include "hns3_enet.h"

static int hns3_cae_set_pfc_storm_cfg(struct hns3_nic_priv *net_priv,
				      void *buf_in, u32 in_size)
{
	struct cmd_pfc_storm_param *prelude_in;
	struct net_device *netdev;
	struct hclge_vport *vport;
	struct hnae3_handle *h;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	int ret;

	prelude_in = (struct cmd_pfc_storm_param *)buf_in;
	netdev = net_priv->netdev;
	h = hns3_get_handle(netdev);
	vport = hns3_cae_get_vport(h);
	hdev = vport->back;

	hns3_cae_cmd_setup_basic_desc(&desc,
				      HCLGE_OPC_CFG_PAUSE_STORM_PARA,
				      false);
	desc.data[0] = prelude_in->pfc_storm_param_mkii.dir;
	desc.data[1] = prelude_in->pfc_storm_param_mkii.enable;
	desc.data[2] = prelude_in->pfc_storm_param_mkii.period_ms;
	desc.data[3] = prelude_in->pfc_storm_param_mkii.times;
	desc.data[4] = prelude_in->pfc_storm_param_mkii.recovery_period_ms;
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "set pfc storm para failed %d\n",
			ret);
		return ret;
	}

	return 0;
}

static int hns3_cae_get_pfc_storm_cfg(struct hns3_nic_priv *net_priv,
				      void *buf_in, u32 in_size, void *buf_out,
				      u32 out_size)
{
	struct cmd_pfc_storm_param *prelude_in;
	struct cmd_pfc_storm_param *info_dstn;
	struct net_device *netdev;
	struct hclge_vport *vport;
	struct hnae3_handle *h;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	int check;
	int ret;

	check = !buf_out || out_size < sizeof(struct cmd_pfc_storm_param);
	if (check) {
		pr_err("input param buf_out error in %s.\n", __func__);
		return -EFAULT;
	}

	prelude_in = (struct cmd_pfc_storm_param *)buf_in;
	info_dstn = (struct cmd_pfc_storm_param *)buf_out;
	netdev = net_priv->netdev;
	h = hns3_get_handle(netdev);
	vport = hns3_cae_get_vport(h);
	hdev = vport->back;

	hns3_cae_cmd_setup_basic_desc(&desc,
				      HCLGE_OPC_CFG_PAUSE_STORM_PARA,
				      true);
	desc.data[0] = prelude_in->pfc_storm_param_mkii.dir;
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get pfc storm para failed %d\n",
			ret);
		return ret;
	}

	info_dstn->pfc_storm_param_mkii.dir =
					   prelude_in->pfc_storm_param_mkii.dir;
	info_dstn->pfc_storm_param_mkii.enable = desc.data[1];
	info_dstn->pfc_storm_param_mkii.period_ms = desc.data[2];
	info_dstn->pfc_storm_param_mkii.times = desc.data[3];
	info_dstn->pfc_storm_param_mkii.recovery_period_ms = desc.data[4];

	return 0;
}

int hns3_cae_pfc_storm_cfg(struct hns3_nic_priv *net_priv, void *buf_in,
			   u32 in_size, void *buf_out, u32 out_size)
{
	struct cmd_pfc_storm_param *para_in;
	int check;
	int ret;

	check = !buf_in || in_size < sizeof(struct cmd_pfc_storm_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	para_in = (struct cmd_pfc_storm_param *)buf_in;
	if (para_in->op_code == SET_PFC_STORM_PARA) {
		ret = hns3_cae_set_pfc_storm_cfg(net_priv, buf_in, in_size);
	} else if (para_in->op_code == GET_PFC_STORM_PARA) {
		ret = hns3_cae_get_pfc_storm_cfg(net_priv, buf_in, in_size,
						 buf_out, out_size);
	} else {
		ret = -EOPNOTSUPP;
	}

	return ret;
}

#endif
