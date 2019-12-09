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
#include "hns3_cae_vlan.h"

int hns3_test_upmapping_cfg(struct hns3_nic_priv *net_priv,
			    void *buf_in, u32 in_size,
			    void *buf_out, u32 out_size)
{
#define HCLGE_OPC_VLANUP_MAPPING_VF_TX_CFG	0x0F10
#define HCLGE_OPC_VLANUP_MAPPING_PORT_TX_CFG	0x0F11
	struct nictool_vlanup_param *out_info;
	struct nictool_vlanup_param *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(struct nictool_vlanup_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct nictool_vlanup_param *)buf_in;
	out_info = (struct nictool_vlanup_param *)buf_out;

	if (in_info->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct nictool_vlanup_param);
		if (check) {
			pr_err("input param buf_out is null in %s function\n",
			       __func__);
			return 0;
		}

		if (in_info->map_flag & NICTOOL_VLANUP_VF_CFG_FLAG) {
			hclge_cmd_setup_basic_desc
			    (&desc, HCLGE_OPC_VLANUP_MAPPING_VF_TX_CFG, true);
			if (in_info->pf_valid) {
				desc.data[0] |= NICTOOL_PFVLD_MASK;
				desc.data[0] |=
				    (in_info->pf_id & NICTOOL_PFID_MASK);
				out_info->pf_id = in_info->pf_id;
			}
			desc.data[0] |=
			    ((in_info->vf_id << 3) & NICTOOL_VFID_MASK);
			desc.data[1] |= in_info->module & NICTOOL_MODULE_MASK;
			out_info->vf_id = in_info->vf_id;
			ret = hclge_cmd_send(&hdev->hw, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"vf up mapping read fail, ret = %d.\n",
					ret);
				return -EIO;
			}
			out_info->ti2oupm = desc.data[2];
			out_info->tv2pupm = desc.data[4];
		} else if (in_info->map_flag & NICTOOL_VLANUP_TC_CFG_FLAG) {
			hclge_cmd_setup_basic_desc
			    (&desc, HCLGE_OPC_VLANUP_MAPPING_PORT_TX_CFG, true);
			desc.data[0] |= in_info->tc_id & NICTOOL_TCID_MASK;
			desc.data[1] |= in_info->module & NICTOOL_MODULE_MASK;
			out_info->tc_id = in_info->tc_id;
			ret = hclge_cmd_send(&hdev->hw, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"port up mapping read fail, ret = %d.\n",
					ret);
				return -EIO;
			}
			out_info->tp2nupm = desc.data[2];
			out_info->tag_en = (desc.data[4] & NICTOOL_TAGEN_MASK) |
			    (((desc.data[4] >> 4) & NICTOOL_TAGEN_MASK) << 2);
		}
		out_info->module = in_info->module;
		out_info->map_flag = in_info->map_flag;
	} else {
		if (in_info->map_flag & NICTOOL_VLANUP_VF_CFG_FLAG) {
			hclge_cmd_setup_basic_desc
			    (&desc, HCLGE_OPC_VLANUP_MAPPING_VF_TX_CFG, true);
			if (in_info->pf_valid) {
				desc.data[0] |= NICTOOL_PFVLD_MASK;
				desc.data[0] |=
				    (in_info->pf_id & NICTOOL_PFID_MASK);
			}
			desc.data[0] |=
			    ((in_info->vf_id << 3) & NICTOOL_VFID_MASK);
			desc.data[1] |= (in_info->module & NICTOOL_MODULE_MASK);
			ret = hclge_cmd_send(&hdev->hw, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"vf up mapping set fail, ret = %d.\n",
					ret);
				return -EIO;
			}

			hclge_cmd_reuse_desc(&desc, false);
			if (in_info->map_flag & NICTOOL_VLANUP_TI2OUPM_FLAG)
				desc.data[2] = in_info->ti2oupm;
			if (in_info->map_flag & NICTOOL_VLANUP_TV2PUPM_FLAG)
				desc.data[4] = in_info->tv2pupm;
			ret = hclge_cmd_send(&hdev->hw, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"vf up mapping set fail, ret = %d.\n",
					ret);
				return -EIO;
			}
		} else if (in_info->map_flag & NICTOOL_VLANUP_TC_CFG_FLAG) {
			hclge_cmd_setup_basic_desc
			    (&desc, HCLGE_OPC_VLANUP_MAPPING_PORT_TX_CFG, true);
			desc.data[0] = (in_info->tc_id & NICTOOL_TCID_MASK);
			desc.data[1] = (in_info->module & NICTOOL_MODULE_MASK);
			ret = hclge_cmd_send(&hdev->hw, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"port up mapping set fail, ret = %d.\n",
					ret);
				return -EIO;
			}

			hclge_cmd_reuse_desc(&desc, false);
			if (in_info->map_flag & NICTOOL_VLANUP_TP2NUPM_FLAG)
				desc.data[2] = in_info->tp2nupm;
			if (in_info->map_flag & NICTOOL_VLANUP_CTRL_CFG_FLAG) {
				desc.data[4] = (in_info->tag_en &
						NICTOOL_TAGEN_MASK) |
				    (((in_info->tag_en >> 2) &
				      NICTOOL_TAGEN_MASK) << 4);
			}
			ret = hclge_cmd_send(&hdev->hw, &desc, 1);
			if (ret) {
				dev_err(&hdev->pdev->dev,
					"port up mapping set fail, ret = %d.\n",
					ret);
				return -EIO;
			}
		}
	}

	return 0;
}
