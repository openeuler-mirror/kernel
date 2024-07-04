// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2024 Hisilicon Limited.

#include "hclgevf_main.h"
#include "hclgevf_dcb.h"
#include "hnae3.h"

#define BW_PERCENT	100

static void hclgevf_ieee_ets_to_prio_tc_map(struct hclge_mbx_tc_info *tc_info,
					    struct ieee_ets *ets)
{
#define HCLGEVF_PRI_SHIFT		4
	u32 prio_tc_map = 0;
	u32 i;

	for (i = 0; i < HNAE3_MAX_USER_PRIO; i++)
		prio_tc_map |= (ets->prio_tc[i] & 0xF) <<
				(i * HCLGEVF_PRI_SHIFT);

	tc_info->prio_tc_map = cpu_to_le32(prio_tc_map);
}

static u8 hclgevf_get_ets_tc_num(struct ieee_ets *ets)
{
	u8 max_tc_id = 0;
	u8 i;

	for (i = 0; i < HNAE3_MAX_USER_PRIO; i++) {
		if (ets->prio_tc[i] > max_tc_id)
			max_tc_id = ets->prio_tc[i];
	}

	/* return max tc number, max tc id need to plus 1 */
	return max_tc_id + 1;
}

static int hclgevf_ieee_ets_to_mbx_tc_info(struct hclge_mbx_tc_info *tc_info,
					   struct ieee_ets *ets)
{
	u8 i;

	tc_info->num_tc = hclgevf_get_ets_tc_num(ets);
	tc_info->tc_sch_mode = 0;
	for (i = 0; i < HNAE3_MAX_TC; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_STRICT:
			tc_info->tc_dwrr[i] = 0;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			tc_info->tc_sch_mode |= BIT(i);
			tc_info->tc_dwrr[i] = ets->tc_tx_bw[i];
			break;
		default:
			return -EINVAL;
		}
	}

	hclgevf_ieee_ets_to_prio_tc_map(tc_info, ets);

	return 0;
}

void hclgevf_update_tc_info(struct hclgevf_dev *hdev)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	u8 i;

	hdev->hw_tc_map = 0;
	for (i = 0; i < kinfo->tc_info.num_tc; i++) {
		hdev->hw_tc_map |= BIT(i);
		kinfo->tc_info.tqp_offset[i] = i * kinfo->rss_size;
		kinfo->tc_info.tqp_count[i] = kinfo->rss_size;
	}

	for (i = kinfo->tc_info.num_tc; i < HNAE3_MAX_TC; i++) {
		/* Set to default queue if TC is disable */
		kinfo->tc_info.tqp_offset[i] = 0;
		kinfo->tc_info.tqp_count[i] = 1;
	}
}

static int hclgevf_tx_ring_tc_config_cmd(struct hclgevf_dev *hdev, u16 txq_id,
					 u8 tc_id)
{
	struct hclgevf_tx_ring_tx_cmd *req;
	struct hclge_desc desc;

	req = (struct hclgevf_tx_ring_tx_cmd *)desc.data;

	hclgevf_cmd_setup_basic_desc(&desc, HCLGE_OPC_TQP_TX_QUEUE_TC, false);
	req->tqp_id = cpu_to_le16(txq_id & HCLGEVF_RING_ID_MASK);
	req->tc_id = tc_id;

	return hclgevf_cmd_send(&hdev->hw, &desc, 1);
}

int hclgevf_tx_ring_tc_config(struct hclgevf_dev *hdev)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	u16 i, j, qid;
	int ret;

	for (i = 0; i < kinfo->tc_info.num_tc; i++) {
		for (j = 0; j < kinfo->tc_info.tqp_count[i]; j++) {
			qid = kinfo->tc_info.tqp_offset[i] + j;
			ret = hclgevf_tx_ring_tc_config_cmd(hdev, qid, i);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static int hclgevf_update_rss_tc_config(struct hclgevf_dev *hdev)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	int ret;

	hclgevf_update_rss_size(&hdev->nic, kinfo->req_rss_size);
	hclgevf_update_tc_info(hdev);
	hclge_comm_rss_indir_init_cfg(hdev->ae_dev, &hdev->rss_cfg);
	ret = hclge_comm_set_rss_indir_table(hdev->ae_dev, &hdev->hw.hw,
					     hdev->rss_cfg.rss_indirection_tbl);
	if (ret)
		return ret;

	return hclgevf_init_rss_tc_mode(hdev, kinfo->rss_size);
}

static int hclgevf_set_vf_multi_tc(struct hclgevf_dev *hdev, struct ieee_ets *ets)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	struct hclge_vf_to_pf_msg send_msg;
	struct hclge_mbx_tc_info *tc_info;
	int ret;

	hclgevf_build_send_msg(&send_msg, HCLGE_MBX_SET_TC, 0);

	tc_info = (struct hclge_mbx_tc_info *)send_msg.data;
	ret = hclgevf_ieee_ets_to_mbx_tc_info(tc_info, ets);
	if (ret)
		return ret;

	ret = hclgevf_send_mbx_msg(hdev, &send_msg, true, NULL, 0);
	if (ret)
		return ret;

	kinfo->tc_info.num_tc = tc_info->num_tc;
	memcpy(kinfo->tc_info.prio_tc, ets->prio_tc,
	       sizeof_field(struct hnae3_tc_info, prio_tc));
	memcpy(&hdev->tc_info, tc_info, sizeof(*tc_info));

	return hclgevf_update_rss_tc_config(hdev);
}

static int hclgevf_ets_validate(struct hclgevf_dev *hdev, struct ieee_ets *ets)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	u8 num_tc = hclgevf_get_ets_tc_num(ets);
	bool has_ets_tc = false;
	u32 total_ets_bw = 0;
	int i;

	if (num_tc > kinfo->tc_info.max_tc || num_tc > hdev->num_tqps) {
		dev_err(&hdev->pdev->dev, "failed to check ets tc num: %u\n",
			num_tc);
		return -EINVAL;
	}

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		if (ets->tc_tsa[i] != IEEE_8021QAZ_TSA_STRICT &&
		    ets->tc_tsa[i] != IEEE_8021QAZ_TSA_ETS) {
			dev_err(&hdev->pdev->dev,
				"failed to check ets sched type %d\n", i);
			return -EINVAL;
		}
		if (ets->tc_tsa[i] == IEEE_8021QAZ_TSA_ETS) {
			if (!ets->tc_tx_bw[i] || i >= num_tc) {
				dev_err(&hdev->pdev->dev,
					"tc%d ets error, num_tc is %u\n",
					i, num_tc);
				return -EINVAL;
			}
			total_ets_bw += ets->tc_tx_bw[i];
			has_ets_tc = true;
		}
	}

	if (has_ets_tc && total_ets_bw != BW_PERCENT)
		return -EINVAL;

	return 0;
}

static bool hclgevf_compare_ieee_ets(struct hclgevf_dev *hdev,
				     struct ieee_ets *ets)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	u32 i;

	if (ets->ets_cap != kinfo->tc_info.max_tc)
		return false;

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		if (ets->tc_tx_bw[i] != hdev->tc_info.tc_dwrr[i])
			return false;
		if (ets->prio_tc[i] != kinfo->tc_info.prio_tc[i])
			return false;

		if (hdev->tc_info.tc_sch_mode & BIT(i)) {
			if (ets->tc_tsa[i] != IEEE_8021QAZ_TSA_ETS)
				return false;
		} else {
			if (ets->tc_tsa[i] != IEEE_8021QAZ_TSA_STRICT)
				return false;
		}
	}
	return true;
}

static bool hclgevf_ets_not_need_config(struct hclgevf_dev *hdev,
					struct ieee_ets *ets)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	u8 num_tc = hclgevf_get_ets_tc_num(ets);

	if (num_tc == kinfo->tc_info.num_tc && num_tc == 1)
		return true;

	return hclgevf_compare_ieee_ets(hdev, ets);
}

static int hclgevf_ieee_setets(struct hnae3_handle *h, struct ieee_ets *ets)
{
	struct hclgevf_dev *hdev = hclgevf_ae_get_hdev(h);
	int ret1;
	int ret;

	ret = hclgevf_ets_validate(hdev, ets);
	if (ret)
		return -EINVAL;

	if (hclgevf_ets_not_need_config(hdev, ets))
		return 0;

	ret = hclgevf_notify_client(hdev, HNAE3_DOWN_CLIENT);
	if (ret)
		return ret;
	ret = hclgevf_notify_client(hdev, HNAE3_UNINIT_CLIENT);
	if (ret)
		return ret;

	ret1 = hclgevf_set_vf_multi_tc(hdev, ets);

	ret = hclgevf_notify_client(hdev, HNAE3_INIT_CLIENT);
	if (ret)
		return ret;

	ret = hclgevf_notify_client(hdev, HNAE3_UP_CLIENT);
	if (ret)
		return ret;
	return ret1;
}

static void hclgevf_tm_info_to_ieee_ets(struct hclgevf_dev *hdev,
					struct ieee_ets *ets)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;
	u32 i;

	memset(ets, 0, sizeof(*ets));
	ets->willing = 1;
	ets->ets_cap = kinfo->tc_info.max_tc;

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		ets->prio_tc[i] = kinfo->tc_info.prio_tc[i];
		if (i < hdev->tc_info.num_tc)
			ets->tc_tx_bw[i] = hdev->tc_info.tc_dwrr[i];
		else
			ets->tc_tx_bw[i] = 0;

		if (hdev->tc_info.tc_sch_mode & BIT(i))
			ets->tc_tsa[i] = IEEE_8021QAZ_TSA_ETS;
		else
			ets->tc_tsa[i] = IEEE_8021QAZ_TSA_STRICT;
	}
}

static int hclgevf_ieee_getets(struct hnae3_handle *h, struct ieee_ets *ets)
{
	struct hclgevf_dev *hdev = hclgevf_ae_get_hdev(h);

	hclgevf_tm_info_to_ieee_ets(hdev, ets);

	return 0;
}

static u8 hclgevf_getdcbx(struct hnae3_handle *h)
{
	return DCB_CAP_DCBX_VER_IEEE;
}

static const struct hnae3_dcb_ops hclgevf_dcb_ops = {
	.ieee_getets	= hclgevf_ieee_getets,
	.ieee_setets	= hclgevf_ieee_setets,
	.getdcbx	= hclgevf_getdcbx,
};

void hclgevf_dcb_init(struct hclgevf_dev *hdev)
{
	struct hnae3_knic_private_info *kinfo = &hdev->nic.kinfo;

	if (!hnae3_ae_dev_vf_multi_tcs_supported(hdev))
		return;

	memset(&hdev->tc_info, 0, sizeof(hdev->tc_info));
	hdev->tc_info.num_tc = 1;
	hdev->tc_info.tc_dwrr[0] = BW_PERCENT;
	hdev->tc_info.tc_sch_mode = BIT(0);
	kinfo->dcb_ops = &hclgevf_dcb_ops;
}
