// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hns3_enet.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_checksum.h"

static int hns3_cae_chs_set(struct hclge_dev *hdev, u8 chs_type, u8 enable)
{
	struct hns3_cae_chs_cmd_param *recv = NULL;
	struct hclge_desc desc;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_CHECKSUM_CHECK_EN, true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		pr_err("chs get cmd send failed!\n");
		return ret;
	}

	recv = (struct hns3_cae_chs_cmd_param *)desc.data;
	switch (chs_type) {
	case CKS_OUTER_L3_EN:
		hnae3_set_bit(recv->outer_en, HCLGE_CHS_OUT_L3_B, enable);
		break;
	case CKS_OUTER_UDP_EN:
		hnae3_set_bit(recv->outer_en, HCLGE_CHS_OUT_UDP_B, enable);
		break;
	case CKS_INNER_L3_EN:
		hnae3_set_bit(recv->inner_en, HCLGE_CHS_INNER_L3_B, enable);
		break;
	case CKS_INNER_TCP_EN:
		hnae3_set_bit(recv->inner_en, HCLGE_CHS_INNER_TCP_B, enable);
		break;
	case CKS_INNER_UDP_EN:
		hnae3_set_bit(recv->inner_en, HCLGE_CHS_INNER_UDP_B, enable);
		break;
	case CKS_INNER_SCTP_EN:
		hnae3_set_bit(recv->inner_en, HCLGE_CHS_INNER_SCTP_B, enable);
		break;
	default:
		break;
	}

	hns3_cae_cmd_reuse_desc(&desc, false);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);

	return ret;
}

static int hns3_cae_chs_get(struct hclge_dev *hdev, u8 chs_type, u8 *enable)
{
	struct hns3_cae_chs_cmd_param *recv = NULL;
	struct hclge_desc desc;
	u8 inner_sctp_en;
	u8 inner_tcp_en;
	u8 inner_udp_en;
	u8 outer_udp_en;
	u8 outer_l3_en;
	u8 inner_l3_en;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_CHECKSUM_CHECK_EN, true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		pr_err("chs get cmd send failed!\n");
		return ret;
	}

	recv = (struct hns3_cae_chs_cmd_param *)desc.data;
	outer_l3_en = hnae3_get_bit(recv->outer_en, HCLGE_CHS_OUT_L3_B);
	outer_udp_en = hnae3_get_bit(recv->outer_en, HCLGE_CHS_OUT_UDP_B);
	inner_l3_en = hnae3_get_bit(recv->inner_en, HCLGE_CHS_INNER_L3_B);
	inner_tcp_en = hnae3_get_bit(recv->inner_en, HCLGE_CHS_INNER_TCP_B);
	inner_udp_en = hnae3_get_bit(recv->inner_en, HCLGE_CHS_INNER_UDP_B);
	inner_sctp_en = hnae3_get_bit(recv->inner_en, HCLGE_CHS_INNER_SCTP_B);

	switch (chs_type) {
	case CKS_OUTER_L3_EN:
		*enable = outer_l3_en;
		break;
	case CKS_OUTER_UDP_EN:
		*enable = outer_udp_en;
		break;
	case CKS_INNER_L3_EN:
		*enable = inner_l3_en;
		break;
	case CKS_INNER_TCP_EN:
		*enable = inner_tcp_en;
		break;
	case CKS_INNER_UDP_EN:
		*enable = inner_udp_en;
		break;
	case CKS_INNER_SCTP_EN:
		*enable = inner_sctp_en;
		break;
	default:
		break;
	}

	return ret;
}

int hns3_cae_chs_cfg(const struct hns3_nic_priv *net_priv, void *buf_in,
		     u32 in_size, void *buf_out, u32 out_size)
{
	struct hns3_cae_chs_param *in_info =
					    (struct hns3_cae_chs_param *)buf_in;
	struct hclge_vport *vport = NULL;
	struct hclge_dev *hdev = NULL;
	u8 *out_info = NULL;
	bool check = !buf_in || in_size < sizeof(struct hns3_cae_chs_param);
	u8 is_set;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hns3_cae_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	out_info = (u8 *)buf_out;
	is_set = in_info->is_set;

	if (in_info->type >= CKS_MAX) {
		pr_err("chs type is %d, param err!\n", in_info->type);
		return -1;
	}

	if (in_info->is_enable != 0 && in_info->is_enable != 1) {
		pr_err("chs enable is %d, param err!\n", in_info->is_enable);
		return -1;
	}
	if (is_set) {
		if (hns3_cae_chs_set(hdev, in_info->type, in_info->is_enable)) {
			pr_err("set chs type(%d) enable failed!\n",
			       in_info->type);
			return -1;
		}
	} else {
		check = !buf_out || out_size < sizeof(u8);
		if (check) {
			pr_err("input param buf_out error in %s.\n", __func__);
			return -EFAULT;
		}
		if (hns3_cae_chs_get(hdev, in_info->type, out_info)) {
			pr_err("get chs type(%d) enable failed!\n",
			       in_info->type);
			return -1;
		}
		pr_err("chs type(%d) enable status is %d\n",
		       in_info->type, *out_info);
	}

	return 0;
}
