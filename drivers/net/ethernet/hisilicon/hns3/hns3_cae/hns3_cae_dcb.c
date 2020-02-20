// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hclge_tm.h"
#include "hclge_cmd.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_dcb.h"
#define FUNKY_BUF_ERR -1
#define MAX_DEV_LISTED 20

struct hns3_cae_dcb_info dcb_all_info[MAX_DEV_LISTED];

static int check_and_set_curr_dev(const struct hns3_nic_priv *net_priv)
{
	int i;

	for (i = 0; i < MAX_DEV_LISTED; i++) {
		if (!dcb_all_info[i].net_priv) {
			dcb_all_info[i].net_priv = net_priv;
			break;
		} else if (dcb_all_info[i].net_priv == net_priv) {
			break;
		}
	}
	if (i == MAX_DEV_LISTED)
		return FUNKY_BUF_ERR;
	return i;
}

int hns3_cae_dcb_cfg(const struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out,
		     u32 out_size)
{
	struct hns3_cae_dcb_cfg_param *out_info =
				       (struct hns3_cae_dcb_cfg_param *)buf_out;
	struct hns3_cae_dcb_cfg_param *in_info =
					(struct hns3_cae_dcb_cfg_param *)buf_in;
	bool check = !buf_in || in_size < sizeof(struct hns3_cae_dcb_cfg_param);
	int curr_dev_idx;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	curr_dev_idx = check_and_set_curr_dev(net_priv);
	if (curr_dev_idx < 0) {
		pr_err("Exceed MAX_DEV_LISTED: %d\n", MAX_DEV_LISTED);
		return -1;
	}
	if (in_info->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct hns3_cae_dcb_cfg_param);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		out_info->dcb_en =
		    dcb_all_info[curr_dev_idx].dcb_cfg_info.dcb_en;
	} else {
		if (in_info->cfg_flag & HNS3_CAE_DCB_DCB_CFG_FLAG)
			dcb_all_info[curr_dev_idx].dcb_cfg_info.dcb_en =
			    in_info->dcb_en;
	}

	return 0;
}

static int hns3_cae_cfg_pfc_en(u8 is_read, struct hclge_dev *hdev,
			       struct hns3_cae_pfc_cfg_param *info, int dev_idx)
{
	struct hclge_desc desc;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc,
				      HNS3_CAE_OPC_CFG_PFC_PAUSE_EN, true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		pr_err("read pfc enable status fail!ret = %d\n", ret);
		return ret;
	}
	if (is_read) {
		info->prien = ((desc.data[0] & 0xff00) >> 8);
		info->pfc_en = ((desc.data[0] & 0x3) == 0x3);
	} else {
		hns3_cae_cmd_reuse_desc(&desc, false);
		if (info->cfg_flag & HNS3_CAE_PFC_EN_CFG_FLAG) {
			desc.data[0] = (desc.data[0] & (~0x3)) |
				       (info->pfc_en << 0) |
				       (info->pfc_en << 1);
			dcb_all_info[dev_idx].pfc_cfg_info.pfc_en =
			    info->pfc_en;
		}
		if (info->cfg_flag & HNS3_CAE_PFC_PRIEN_CFG_FLAG) {
			desc.data[0] = (desc.data[0] & (~0xff00)) |
				       (info->prien << 8);
			dcb_all_info[dev_idx].pfc_cfg_info.prien =
			    info->prien;
		}
		ret = hns3_cae_cmd_send(hdev, &desc, 1);
		if (ret) {
			pr_err("set pfc cmd return fail!ret = %d\n", ret);
			return ret;
		}
	}

	return ret;
}

static int hns3_cae_cfg_pause_param(struct hclge_dev *hdev,
				    struct hns3_cae_pfc_cfg_param *info,
				    u8 is_read)
{
	struct hclge_desc desc;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc,
				      HNS3_CAE_OPC_CFG_PAUSE_PARAM, true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		pr_err("pause param cfg cmd send fail\n");
		return ret;
	}

	if (is_read) {
		info->pause_time = desc.data[2] & 0xffff;
		info->pause_gap = (desc.data[1] & 0xff0000) >> 16;
		return 0;
	}

	if (info->cfg_flag & HNS3_CAE_PFC_TIME_CFG_FLAG)
		desc.data[2] = (desc.data[2] & (~0xffff)) | info->pause_time;

	if (info->cfg_flag & HNS3_CAE_PFC_GAP_CFG_FLAG)
		desc.data[1] = (desc.data[1] & (~0xff0000)) |
			       (info->pause_gap << 16);

	hns3_cae_cmd_reuse_desc(&desc, false);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"mac pause param cfg fail, ret = %d.\n", ret);
		return ret;
	}
	return 0;
}

int hns3_cae_dcb_pfc_cfg(const struct hns3_nic_priv *net_priv,
			 void *buf_in, u32 in_size,
			 void *buf_out, u32 out_size)
{
	struct hns3_cae_pfc_cfg_param *out_info =
				       (struct hns3_cae_pfc_cfg_param *)buf_out;
	struct hns3_cae_pfc_cfg_param *in_info =
					(struct hns3_cae_pfc_cfg_param *)buf_in;
	bool check = !buf_in || in_size < sizeof(struct hns3_cae_pfc_cfg_param);
	struct hclge_vport *vport = NULL;
	struct net_device *ndev = NULL;
	struct hnae3_handle *h = NULL;
	struct hclge_dev *hdev = NULL;
	int curr_dev_idx;
	int ret;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	curr_dev_idx = check_and_set_curr_dev(net_priv);
	if (curr_dev_idx < 0) {
		pr_err("Exceed MAX_DEV_LISTED: %d\n", MAX_DEV_LISTED);
		return -EINVAL;
	}
	h = net_priv->ae_handle;
	vport = hns3_cae_get_vport(h);
	ndev = h->netdev;
	hdev = vport->back;

	if (!in_info->is_read &&
	    !dcb_all_info[curr_dev_idx].dcb_cfg_info.dcb_en) {
		pr_err("please enable dcb cfg first!\n");
		return -EPERM;
	}

	if (!hnae3_dev_dcb_supported(hdev) || vport->vport_id != 0) {
		pr_err("this device doesn't support dcb!\n");
		return -EOPNOTSUPP;
	}

	if (in_info->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct hns3_cae_pfc_cfg_param);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		ret = hns3_cae_cfg_pfc_en(in_info->is_read, hdev,
					  out_info, curr_dev_idx);
		if (ret)
			return ret;
		ret = hns3_cae_cfg_pause_param(hdev, out_info, true);
		if (ret)
			return ret;
	} else {
		struct ieee_pfc pfc = {0};

		if (in_info->cfg_flag & HNS3_CAE_PFC_PRIEN_CFG_FLAG) {
			pfc.pfc_en = in_info->prien;
			dcb_all_info[curr_dev_idx].pfc_cfg_info.prien =
			    in_info->prien;
			if (ndev->dcbnl_ops->ieee_setpfc) {
#ifdef CONFIG_EXT_TEST
				rtnl_lock();
#endif
				ret = ndev->dcbnl_ops->ieee_setpfc(ndev, &pfc);
#ifdef CONFIG_EXT_TEST
				rtnl_unlock();
#endif
				if (ret)
					return ret;
			}
		}

		if ((in_info->cfg_flag & HNS3_CAE_PFC_TIME_CFG_FLAG) ||
		    (in_info->cfg_flag & HNS3_CAE_PFC_GAP_CFG_FLAG)) {
			ret = hns3_cae_cfg_pause_param(hdev, in_info, false);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static void hns3_cae_disable_ets_cfg(struct hclge_dev *hdev,
				     struct ieee_ets *ets, int dev_idx)
{
	u8 percent = 0;
	int i;

	for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++) {
		ets->prio_tc[i] = hdev->tm_info.prio_tc[i];
		ets->tc_tsa[i] = IEEE_8021QAZ_TSA_ETS;
		dcb_all_info[dev_idx].ets_cfg_info.schedule[i] = 0;
	}
	for (i = 0; i < hdev->tm_info.num_tc; i++) {
		ets->tc_tx_bw[i] = 100 / hdev->tm_info.num_tc;
		dcb_all_info[dev_idx].ets_cfg_info.bw[i] =
		    ets->tc_tx_bw[i];
		percent += ets->tc_tx_bw[i];
	}
	if (percent != 100) {
		ets->tc_tx_bw[i - 1] += (100 - percent);
		dcb_all_info[dev_idx].ets_cfg_info.bw[i - 1] =
		    ets->tc_tx_bw[i - 1];
	}
}

static void hns3_cae_enable_ets_cfg(struct hclge_dev *hdev,
				    struct ieee_ets *ets,
				    struct hns3_cae_ets_cfg_param *info,
				    int dev_idx)
{
	int i;

	if (info->cfg_flag & HNS3_CAE_ETS_UP2TC_CFG_FLAG) {
		for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++) {
			ets->prio_tc[i] = info->up2tc[i];
			dcb_all_info[dev_idx].ets_cfg_info.up2tc[i] =
			    info->up2tc[i];
		}
	} else {
		for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++)
			ets->prio_tc[i] = hdev->tm_info.prio_tc[i];
	}

	if (info->cfg_flag & HNS3_CAE_ETS_BANDWIDTH_CFG_FLAG) {
		for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++) {
			ets->tc_tx_bw[i] = info->bw[i];
			dcb_all_info[dev_idx].ets_cfg_info.bw[i] =
			    info->bw[i];
		}
	} else {
		for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++)
			ets->tc_tx_bw[i] = hdev->tm_info.pg_info[0].tc_dwrr[i];
	}

	if (info->cfg_flag & HNS3_CAE_ETS_SCHEDULE_CFG_FLAG) {
		for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++) {
			ets->tc_tsa[i] = info->schedule[i] ?
			    IEEE_8021QAZ_TSA_STRICT : IEEE_8021QAZ_TSA_ETS;
			dcb_all_info[dev_idx].ets_cfg_info.schedule[i] =
				info->schedule[i];
		}
	} else {
		for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++)
			ets->tc_tsa[i] = hdev->tm_info.tc_info[i].tc_sch_mode ?
			    IEEE_8021QAZ_TSA_ETS : IEEE_8021QAZ_TSA_STRICT;
	}
}

int hns3_cae_dcb_ets_cfg(const struct hns3_nic_priv *net_priv,
			 void *buf_in, u32 in_size,
			 void *buf_out, u32 out_size)
{
#define BYTELEN 4
	struct hns3_cae_ets_cfg_param *out_info =
				       (struct hns3_cae_ets_cfg_param *)buf_out;
	struct hns3_cae_ets_cfg_param *in_info =
					(struct hns3_cae_ets_cfg_param *)buf_in;
	bool check = !buf_in ||
		     in_size < sizeof(struct hns3_cae_ets_cfg_param) ||
		     !buf_out ||
		     out_size < sizeof(struct hns3_cae_ets_cfg_param);
	struct hclge_vport *vport = NULL;
	struct net_device *ndev = NULL;
	struct hclge_dev *hdev = NULL;
	struct hnae3_handle *h = NULL;
	struct hclge_desc desc;
	int curr_dev_idx;
	int ret;
	u32 i;

	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	curr_dev_idx = check_and_set_curr_dev(net_priv);
	if (curr_dev_idx < 0) {
		pr_err("Exceed MAX_DEV_LISTED: %d\n", MAX_DEV_LISTED);
		return -EINVAL;
	}
	h = net_priv->ae_handle;
	vport = hns3_cae_get_vport(h);
	ndev = h->netdev;
	hdev = vport->back;

	if (!in_info->is_read &&
	    !dcb_all_info[curr_dev_idx].dcb_cfg_info.dcb_en) {
		pr_err("please enable dcb cfg first!\n");
		return -EPERM;
	}

	if (!hnae3_dev_dcb_supported(hdev) || vport->vport_id != 0) {
		pr_err("this device doesn't support dcb!\n");
		return -EOPNOTSUPP;
	}

	if (in_info->is_read) {
		hns3_cae_cmd_setup_basic_desc(&desc,
					      HNS3_CAE_OPC_PRI_TO_TC_MAPPING,
					      true);
		ret = hns3_cae_cmd_send(hdev, &desc, 1);
		if (ret) {
			pr_err("read up2tc mapping fail!\n");
			return ret;
		}
		out_info->ets_en =
		    dcb_all_info[curr_dev_idx].ets_cfg_info.ets_en;
		for (i = 0; i < HNS3_CAE_ETS_MAC_TC_NUM; i++) {
			out_info->up2tc[i] =
			    (desc.data[0] & (0xfU << (BYTELEN * i))) >>
			    (BYTELEN * i);
			dcb_all_info[curr_dev_idx].ets_cfg_info.up2tc[i] =
			    out_info->up2tc[i];
			out_info->bw[i] = hdev->tm_info.pg_info[0].tc_dwrr[i];
			dcb_all_info[curr_dev_idx].ets_cfg_info.bw[i] =
			    hdev->tm_info.pg_info[0].tc_dwrr[i];
			out_info->schedule[i] =
			    !hdev->tm_info.tc_info[i].tc_sch_mode;
			dcb_all_info[curr_dev_idx].ets_cfg_info.schedule[i] =
			    !hdev->tm_info.tc_info[i].tc_sch_mode;
		}
	} else {
		struct ieee_ets ets = {0};

		if (in_info->cfg_flag & HNS3_CAE_ETS_EN_CFG_FLAG)
			dcb_all_info[curr_dev_idx].ets_cfg_info.ets_en =
			    in_info->ets_en;

		if (!dcb_all_info[curr_dev_idx].ets_cfg_info.ets_en)
			hns3_cae_disable_ets_cfg(hdev, &ets, curr_dev_idx);
		else
			hns3_cae_enable_ets_cfg(hdev, &ets, in_info,
						curr_dev_idx);

		if (ndev->dcbnl_ops->ieee_setets) {
#ifdef CONFIG_EXT_TEST
			rtnl_lock();
#endif
			ret = ndev->dcbnl_ops->ieee_setets(ndev, &ets);
#ifdef CONFIG_EXT_TEST
			rtnl_unlock();
#endif
			if (ret)
				return ret;
		}

		out_info->cfg_flag = in_info->cfg_flag;
		out_info->is_read = in_info->is_read;
		out_info->ets_en =
		    dcb_all_info[curr_dev_idx].ets_cfg_info.ets_en;
	}

	return 0;
}
