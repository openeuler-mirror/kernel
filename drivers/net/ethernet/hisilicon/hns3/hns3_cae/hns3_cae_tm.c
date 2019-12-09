// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hnae3.h"
#include "hclge_main.h"
#include "hclge_tm.h"
#include "hclge_cmd.h"
#include "hns3_cae_tm.h"

static int hns3_test_tm_schd_mode_set(struct hclge_dev *hdev,
				      enum hclge_opcode_type opcode,
				      u8 mode, u16 id)
{
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, opcode, false);

	if (mode == HCLGE_SCH_MODE_DWRR)
		desc.data[1] = 1;
	else
		desc.data[1] = 0;

	desc.data[0] = cpu_to_le32(id);

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

static int hns3_test_tm_schd_mode_get(struct hclge_dev *hdev,
				      enum hclge_opcode_type opcode,
				      u8 *mode, u16 id)
{
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, opcode, true);
	desc.data[0] = cpu_to_le32(id);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*mode = desc.data[1];

	return ret;
}

int hns3_test_tm_q_to_qs_set(struct hclge_dev *hdev, u16 q_id, u16 qs_id)
{
	struct hclge_nq_to_qs_link_cmd *map;
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_NQ_TO_QS_LINK, false);
	map = (struct hclge_nq_to_qs_link_cmd *)desc.data;
	map->nq_id = cpu_to_le16(q_id);
	map->qset_id = cpu_to_le16(qs_id | HCLGE_TM_Q_QS_LINK_VLD_MSK);

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_q_to_qs_get(struct hclge_dev *hdev, u16 q_id, u16 *qs_id)
{
	struct hclge_nq_to_qs_link_cmd *map;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_NQ_TO_QS_LINK, true);
	map = (struct hclge_nq_to_qs_link_cmd *)desc.data;
	map->nq_id = cpu_to_le16(q_id);
	map->qset_id = cpu_to_le16(*qs_id | HCLGE_TM_Q_QS_LINK_VLD_MSK);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*qs_id = map->qset_id & HNS3_TEST_QS_ID_MSK;

	return ret;
}

int hns3_test_tm_qs_to_pri_set(struct hclge_dev *hdev, u16 qs_id, u8 pri)
{
	struct hclge_qs_to_pri_link_cmd *map;
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_QS_TO_PRI_LINK, false);
	map = (struct hclge_qs_to_pri_link_cmd *)desc.data;
	map->qs_id = cpu_to_le16(qs_id);
	map->priority = pri;
	map->link_vld = HCLGE_TM_QS_PRI_LINK_VLD_MSK;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_qs_to_pri_get(struct hclge_dev *hdev, u16 qs_id, u8 *pri)
{
	struct hclge_qs_to_pri_link_cmd *map;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_QS_TO_PRI_LINK, true);
	map = (struct hclge_qs_to_pri_link_cmd *)desc.data;
	map->qs_id = cpu_to_le16(qs_id);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*pri = map->priority;

	return ret;
}

int hns3_test_tm_qs_weight_set(struct hclge_dev *hdev, u16 qs_id, u8 dwrr)
{
	struct hclge_qs_weight_cmd *weight;
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_QS_WEIGHT, false);
	weight = (struct hclge_qs_weight_cmd *)desc.data;
	weight->qs_id = cpu_to_le16(qs_id);
	weight->dwrr = dwrr;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_qs_weight_get(struct hclge_dev *hdev, u16 qs_id, u8 *dwrr)
{
	struct hclge_qs_weight_cmd *weight;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_QS_WEIGHT, true);
	weight = (struct hclge_qs_weight_cmd *)desc.data;
	weight->qs_id = cpu_to_le16(qs_id);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*dwrr = weight->dwrr;

	return ret;
}

int hns3_test_tm_pri_weight_set(struct hclge_dev *hdev, u8 pri_id, u8 dwrr)
{
	struct hclge_priority_weight_cmd *weight;
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_PRI_WEIGHT, false);
	weight = (struct hclge_priority_weight_cmd *)desc.data;
	weight->pri_id = pri_id;
	weight->dwrr = dwrr;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_pri_weight_get(struct hclge_dev *hdev, u8 pri_id, u8 *dwrr)
{
	struct hclge_priority_weight_cmd *weight;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_PRI_WEIGHT, true);
	weight = (struct hclge_priority_weight_cmd *)desc.data;
	weight->pri_id = pri_id;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*dwrr = weight->dwrr;

	return ret;
}

int hns3_test_tm_pri_pg_bitmap_set(struct hclge_dev *hdev, u8 pg_id, u8 bitmap)
{
	struct hclge_pg_to_pri_link_cmd *map;
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_PG_TO_PRI_LINK, false);
	map = (struct hclge_pg_to_pri_link_cmd *)desc.data;
	map->pg_id = cpu_to_le16(pg_id);
	map->pri_bit_map = bitmap;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_pri_pg_bitmap_get(struct hclge_dev *hdev, u8 pg_id,
				   u8 *bitmap)
{
	struct hclge_pg_to_pri_link_cmd *map;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_PG_TO_PRI_LINK, true);
	map = (struct hclge_pg_to_pri_link_cmd *)desc.data;
	map->pg_id = cpu_to_le16(pg_id);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		return ret;

	*bitmap = map->pri_bit_map;

	return 0;
}

int hns3_test_tm_qs_bp_bitmap_set(struct hclge_dev *hdev, u8 tc, u8 gp_id,
				  u32 map)
{
	struct hclge_bp_to_qs_map_cmd *bp_to_qs_map_cmd;
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_BP_TO_QSET_MAPPING,
				   false);
	bp_to_qs_map_cmd = (struct hclge_bp_to_qs_map_cmd *)desc.data;
	bp_to_qs_map_cmd->tc_id = tc;
	bp_to_qs_map_cmd->qs_group_id = gp_id;
	/* Qset and tc is one by one mapping */
	bp_to_qs_map_cmd->qs_bit_map = map;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_qs_bp_bitmap_get(struct hclge_dev *hdev, u8 tc, u8 gp_id,
				  u32 *map)
{
	struct hclge_bp_to_qs_map_cmd *bp_to_qs_map_cmd;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_BP_TO_QSET_MAPPING,
				   true);
	bp_to_qs_map_cmd = (struct hclge_bp_to_qs_map_cmd *)desc.data;
	bp_to_qs_map_cmd->tc_id = tc;
	bp_to_qs_map_cmd->qs_group_id = gp_id;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret)
		return ret;

	*map = bp_to_qs_map_cmd->qs_bit_map;
	return 0;
}

int hns3_test_tm_pri_shapping_set(struct hclge_dev *hdev,
				  enum hclge_shap_bucket bucket, u8 pri_id,
				  u32 shaper)
{
	struct hclge_pri_shapping_cmd *shap_cfg_cmd;
	enum hclge_opcode_type opcode;
	struct hclge_desc desc;

	opcode = bucket == HCLGE_TM_SHAP_P_BUCKET ?
	    HCLGE_OPC_TM_PRI_P_SHAPPING : HCLGE_OPC_TM_PRI_C_SHAPPING;
	hclge_cmd_setup_basic_desc(&desc, opcode, false);
	shap_cfg_cmd = (struct hclge_pri_shapping_cmd *)desc.data;
	shap_cfg_cmd->pri_id = pri_id;
	shap_cfg_cmd->pri_shapping_para = shaper;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_pri_shapping_get(struct hclge_dev *hdev,
				  enum hclge_shap_bucket bucket, u8 pri_id,
				  u32 *shaper)
{
	struct hclge_pri_shapping_cmd *shap_cfg_cmd;
	enum hclge_opcode_type opcode;
	struct hclge_desc desc;
	int ret;

	opcode = bucket == HCLGE_TM_SHAP_P_BUCKET ?
	    HCLGE_OPC_TM_PRI_P_SHAPPING : HCLGE_OPC_TM_PRI_C_SHAPPING;
	hclge_cmd_setup_basic_desc(&desc, opcode, true);
	shap_cfg_cmd = (struct hclge_pri_shapping_cmd *)desc.data;
	shap_cfg_cmd->pri_id = pri_id;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	*shaper = shap_cfg_cmd->pri_shapping_para;

	return ret;
}

int hns3_test_tm_pg_weight_set(struct hclge_dev *hdev, u8 pg_id, u8 dwrr)
{
	struct hclge_pg_weight_cmd *weight;
	struct hclge_desc desc;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_PG_WEIGHT, false);
	weight = (struct hclge_pg_weight_cmd *)desc.data;
	weight->pg_id = pg_id;
	weight->dwrr = dwrr;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_pg_weight_get(struct hclge_dev *hdev, u8 pg_id, u8 *dwrr)
{
	struct hclge_pg_weight_cmd *weight;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_PG_WEIGHT, true);
	weight = (struct hclge_pg_weight_cmd *)desc.data;
	weight->pg_id = pg_id;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*dwrr = weight->dwrr;

	return ret;
}

int hns3_test_tm_pg_shapping_set(struct hclge_dev *hdev,
				 enum hclge_shap_bucket bucket, u8 pg_id,
				 u32 shaper)
{
	struct hclge_pg_shapping_cmd *shap_cfg_cmd;
	enum hclge_opcode_type opcode;
	struct hclge_desc desc;

	opcode = bucket == HCLGE_TM_SHAP_P_BUCKET ? HCLGE_OPC_TM_PG_P_SHAPPING :
	    HCLGE_OPC_TM_PG_C_SHAPPING;
	hclge_cmd_setup_basic_desc(&desc, opcode, false);
	shap_cfg_cmd = (struct hclge_pg_shapping_cmd *)desc.data;
	shap_cfg_cmd->pg_id = pg_id;
	shap_cfg_cmd->pg_shapping_para = shaper;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_pg_shapping_get(struct hclge_dev *hdev,
				 enum hclge_shap_bucket bucket, u8 pg_id,
				 u32 *shaper)
{
	struct hclge_pg_shapping_cmd *shap_cfg_cmd;
	enum hclge_opcode_type opcode;
	struct hclge_desc desc;
	int ret;

	opcode = bucket == HCLGE_TM_SHAP_P_BUCKET ? HCLGE_OPC_TM_PG_P_SHAPPING :
	    HCLGE_OPC_TM_PG_C_SHAPPING;
	hclge_cmd_setup_basic_desc(&desc, opcode, true);
	shap_cfg_cmd = (struct hclge_pg_shapping_cmd *)desc.data;
	shap_cfg_cmd->pg_id = pg_id;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*shaper = shap_cfg_cmd->pg_shapping_para;

	return ret;
}

int hns3_test_tm_port_shapping_set(struct hclge_dev *hdev, u32 shaper)
{
	struct hclge_port_shapping_cmd *shap_cfg_cmd;
	enum hclge_opcode_type opcode;
	struct hclge_desc desc;

	opcode = HCLGE_OPC_TM_PORT_SHAPPING;
	hclge_cmd_setup_basic_desc(&desc, opcode, false);
	shap_cfg_cmd = (struct hclge_port_shapping_cmd *)desc.data;
	shap_cfg_cmd->port_shapping_para = shaper;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

int hns3_test_tm_port_shapping_get(struct hclge_dev *hdev, u32 *shaper)
{
	struct hclge_port_shapping_cmd *shap_cfg_cmd;
	enum hclge_opcode_type opcode;
	struct hclge_desc desc;
	int ret;

	opcode = HCLGE_OPC_TM_PORT_SHAPPING;
	hclge_cmd_setup_basic_desc(&desc, opcode, true);
	shap_cfg_cmd = (struct hclge_port_shapping_cmd *)desc.data;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret)
		*shaper = shap_cfg_cmd->port_shapping_para;

	return ret;
}

static int hns3_test_tm_ets_tc_dwrr_set(struct hclge_dev *hdev, u8 *weight)
{
#define DEFAULT_TC_WEIGHT	1
#define DEFAULT_TC_OFFSET	14
	struct nictool_ets_tc_weight_cmd *ets_weight;
	struct hclge_desc desc;
	int i;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_ETS_TC_WEIGHT, false);
	ets_weight = (struct nictool_ets_tc_weight_cmd *)desc.data;

	for (i = 0; i < MAX_TC_NUM; i++)
		ets_weight->tc_weight[i] = weight[i];

	ets_weight->weight_offset = DEFAULT_TC_OFFSET;

	return hclge_cmd_send(&hdev->hw, &desc, 1);
}

static int hns3_test_tm_ets_tc_dwrr_get(struct hclge_dev *hdev, u8 *weight)
{
	struct nictool_ets_tc_weight_cmd *ets_weight;
	struct hclge_desc desc;
	int ret, i;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_ETS_TC_WEIGHT, true);
	ets_weight = (struct nictool_ets_tc_weight_cmd *)desc.data;

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (!ret) {
		for (i = 0; i < MAX_TC_NUM; i++)
			weight[i] = ets_weight->tc_weight[i];
	}

	return ret;
}

static int hns3_test_tm_operate_nic_regs(struct hclge_dev *hdev,
					 u64 addr, u64 *value, u8 is_read)
{
#define HNS3_WRITE_READ_REG_CMD  0x7014
	struct hclge_desc desc;
	int ret;

	if (is_read) {
		hclge_cmd_setup_basic_desc(&desc, HNS3_WRITE_READ_REG_CMD,
					   true);
		desc.data[0] = (u32)(addr & 0xffffffff);
		desc.data[1] = (u32)(addr >> 32);
		desc.data[4] = 32;
		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"read addr 0x%llx failed! ret = %d.\n",
				addr, ret);
			return ret;
		}
		*value = (u64)desc.data[2] | ((u64)desc.data[3] << 32);
	} else {
		hclge_cmd_setup_basic_desc(&desc, HNS3_WRITE_READ_REG_CMD,
					   false);
		desc.data[0] = (u32)(addr & 0xffffffff);
		desc.data[1] = (u32)(addr >> 32);
		desc.data[2] = (u32)(*value & 0xffffffff);
		desc.data[3] = (u32)(*value >> 32);
		desc.data[4] = 32;
		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				" write addr 0x%llx value 0x%llx failed! ret = %d.\n",
				addr, *value, ret);
			return ret;
		}
	}

	return 0;
}

int hns3_test_queue_cfg(struct hns3_nic_priv *net_priv,
			void *buf_in, u32 in_size,
			void *buf_out, u32 out_size)
{
	struct nictool_queue_cfg_info *out_info;
	struct nictool_queue_cfg_info *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	int is_read;
	bool check;

	check = !buf_in || in_size < sizeof(struct nictool_queue_cfg_info);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct nictool_queue_cfg_info *)buf_in;
	out_info = (struct nictool_queue_cfg_info *)buf_out;
	is_read = in_info->is_read;

	if (is_read) {
		check = !buf_out ||
			out_size < sizeof(struct nictool_queue_cfg_info);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		out_info->queue_id = in_info->queue_id;
		if (hns3_test_tm_q_to_qs_get(hdev, in_info->queue_id,
					     &out_info->qs)) {
			pr_err("%s,%d:get queue(%d) to qs failed!\n", __func__,
			       __LINE__, in_info->queue_id);
			return -1;
		}
	} else {
		if (hns3_test_tm_q_to_qs_set(hdev, in_info->queue_id,
					     in_info->qs)) {
			pr_err("%s,%d:set queue(%d) to qs(%d) failed!\n",
			       __func__, __LINE__,
			       in_info->queue_id, in_info->qs);
			return -1;
		}
	}

	return 0;
}

static int hns3_test_qs_set_new_map(int tc, u32 map,
				    struct hclge_dev *hdev,
				    struct nictool_qs_cfg_info *in_info)
{
	u32 bp_map = map;
	u16 qs_id;
	int gp_id;
	int offset;

	qs_id = in_info->qs_id;
	gp_id = qs_id / 32;
	offset = qs_id % 32;

	if (tc < MAX_TC_NUM) {
		/* clear old bit */
		bp_map &= ~BIT(offset);
		if (hns3_test_tm_qs_bp_bitmap_set(hdev, tc, gp_id, bp_map)) {
			pr_err("%s,%d:set qs(%d) bp map failed!\n", __func__,
			       __LINE__, qs_id);
			return -1;
		}
		/* set new bit */
		if (hns3_test_tm_qs_bp_bitmap_get
		    (hdev, in_info->tc, gp_id, &bp_map)) {
			pr_err("%s,%d:get qs(%d) bp map failed!\n", __func__,
			       __LINE__, qs_id);
			return -1;
		}

		bp_map |= BIT(offset);
		if (hns3_test_tm_qs_bp_bitmap_set
		    (hdev, in_info->tc, gp_id, bp_map)) {
			pr_err("%s,%d:set qs(%d) bp map failed!\n", __func__,
			       __LINE__, qs_id);
			return -1;
		}
	}

	return 0;
}

int hns3_test_qs_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
	struct nictool_qs_cfg_info *out_info;
	struct nictool_qs_cfg_info *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	int is_read;
	int offset;
	u32 bp_map;
	bool check;
	u16 qs_id;
	int gp_id;
	int tc;

	check = !buf_in || in_size < sizeof(struct nictool_qs_cfg_info);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct nictool_qs_cfg_info *)buf_in;
	out_info = (struct nictool_qs_cfg_info *)buf_out;
	is_read = in_info->is_read;
	qs_id = in_info->qs_id;
	gp_id = qs_id / 32;
	offset = qs_id % 32;

	for (tc = 0; tc < MAX_TC_NUM; tc++) {
		if (hns3_test_tm_qs_bp_bitmap_get(hdev, tc, gp_id, &bp_map)) {
			pr_err("%s,%d:get qs(%d) bp map failed!\n", __func__,
			       __LINE__, qs_id);
			return -1;
		}
		if (bp_map & BIT(offset))
			break;
	}

	if (is_read) {
		check = !buf_out ||
			out_size < sizeof(struct nictool_qs_cfg_info);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		out_info->qs_id = qs_id;
		out_info->tc = tc;
		if (hns3_test_tm_qs_to_pri_get(hdev, qs_id, &out_info->pri)) {
			pr_err("%s,%d:get qs(%d) to pri failed!\n", __func__,
			       __LINE__, qs_id);
			return -1;
		}

		if (hns3_test_tm_schd_mode_get
		    (hdev, HCLGE_OPC_TM_QS_SCH_MODE_CFG, &out_info->mode,
		     qs_id)) {
			pr_err("%s,%d:get qs(%d) mode failed!\n", __func__,
			       __LINE__, qs_id);
			return -1;
		}

		if (hns3_test_tm_qs_weight_get(hdev, qs_id,
					       &out_info->weight)) {
			pr_err("%s,%d:get qs(%d) weight failed!\n", __func__,
			       __LINE__, qs_id);
			return -1;
		}

	} else {
		if ((in_info->flag & HNS3_TM_QSET_MAPPING_FLAG) &&
		    hns3_test_tm_qs_to_pri_set(hdev, qs_id, in_info->pri)) {
			pr_err("%s,%d:set qs(%d) to pri(%d) failed!\n",
			       __func__, __LINE__, qs_id, in_info->pri);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_QSET_MODE_CFG_FLAG) &&
		    hns3_test_tm_schd_mode_set(hdev,
					       HCLGE_OPC_TM_QS_SCH_MODE_CFG,
					       in_info->mode, qs_id)) {
			pr_err("%s,%d:set qs(%d) mode(%d) failed!\n", __func__,
			       __LINE__, qs_id, in_info->mode);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_QSET_WEIGHT_CFG_FLAG) &&
		    hns3_test_tm_qs_weight_set(hdev, qs_id, in_info->weight)) {
			pr_err("%s,%d:set qs(%d) weight(%d) failed!\n",
			       __func__, __LINE__, qs_id, in_info->weight);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_QSET_BP_CFG_FLAG) &&
		    hns3_test_qs_set_new_map(tc, bp_map, hdev, in_info)) {
			pr_err("%s,%d:set qset %d bp cfg to tc %d failed!\n",
			       __func__, __LINE__, qs_id, in_info->tc);
			return -1;
		}
	}

	return 0;
}

static int hns3_test_pri_pg_set_map(struct hclge_dev *hdev,
				    int cur_pg, u8 map,
				    struct nictool_pri_cfg_info *in_info)
{
	u8 bitmap = map;
	u16 pri_id = in_info->pri_id;

	/* clear old map */
	if (in_info->pg != cur_pg) {
		bitmap &= ~BIT(pri_id);
		if (hns3_test_tm_pri_pg_bitmap_set(hdev, cur_pg, bitmap)) {
			pr_err("%s,%d:set pg(%d) pri_map failed!\n", __func__,
			       __LINE__, cur_pg);
			return -1;
		}

		bitmap = 0;
		if (hns3_test_tm_pri_pg_bitmap_get(hdev, in_info->pg,
						   &bitmap)) {
			pr_err("%s,%d:get pg(%d) pri_map failed!\n", __func__,
			       __LINE__, in_info->pg);
			return -1;
		}
	}

	/* set new map */
	bitmap |= BIT(pri_id);
	if (hns3_test_tm_pri_pg_bitmap_set(hdev, in_info->pg, bitmap)) {
		pr_err("%s,%d:set pg(%d) pri_map failed!\n", __func__, __LINE__,
		       in_info->pg);
		return -1;
	}

	return 0;
}

int hns3_test_pri_cfg(struct hns3_nic_priv *net_priv,
		      void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
	struct nictool_pri_cfg_info *out_info;
	struct nictool_pri_cfg_info *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	int is_read;
	u16 pri_id;
	int cur_pg;
	bool check;
	u8 bitmap;

	check = !buf_in || in_size < sizeof(struct nictool_pri_cfg_info);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct nictool_pri_cfg_info *)buf_in;
	out_info = (struct nictool_pri_cfg_info *)buf_out;
	is_read = in_info->is_read;

	pri_id = in_info->pri_id;

	for (cur_pg = 0; cur_pg < MAX_PG_NUM; cur_pg++) {
		bitmap = 0;
		if (hns3_test_tm_pri_pg_bitmap_get(hdev, cur_pg, &bitmap)) {
			pr_err("%s,%d:get pg(%d) pri_map failed!\n", __func__,
			       __LINE__, cur_pg);
			return -1;
		}

		if (bitmap & BIT(pri_id))
			break;
	}

	if (cur_pg == MAX_PG_NUM) {
		pr_err("%s,%d:find pri(%d) to pg failed!\n", __func__, __LINE__,
		       pri_id);
		return -1;
	}

	if (is_read) {
		check = !buf_out ||
			out_size < sizeof(struct nictool_pri_cfg_info);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		out_info->pri_id = pri_id;
		out_info->pg = cur_pg;
		if (hns3_test_tm_pri_shapping_get(hdev, HCLGE_TM_SHAP_C_BUCKET,
						  pri_id,
						  &out_info->c_shaping)) {
			pr_err("%s,%d:get pri(%d) c shaping failed!\n",
			       __func__, __LINE__, pri_id);
			return -1;
		}

		if (hns3_test_tm_pri_shapping_get(hdev, HCLGE_TM_SHAP_P_BUCKET,
						  pri_id,
						  &out_info->p_shaping)) {
			pr_err("%s,%d:get pri(%d) p shaping failed!\n",
			       __func__, __LINE__, pri_id);
			return -1;
		}

		if (hns3_test_tm_schd_mode_get
		    (hdev, HCLGE_OPC_TM_PRI_SCH_MODE_CFG, &out_info->mode,
		     pri_id)) {
			pr_err("%s,%d:get pri(%d) mode failed!\n", __func__,
			       __LINE__, pri_id);
			return -1;
		}

		if (hns3_test_tm_pri_weight_get
		    (hdev, pri_id, &out_info->weight)) {
			pr_err("%s,%d:set pri(%d) weight failed!\n", __func__,
			       __LINE__, pri_id);
			return -1;
		}
	} else {
		if ((in_info->flag & HNS3_TM_PRI_MAPPING_FLAG) &&
		    hns3_test_pri_pg_set_map(hdev, cur_pg, bitmap, in_info)) {
			pr_err("%s,%d:set pri(%d) mapping to pg(%d) failed!\n",
			       __func__, __LINE__, pri_id, in_info->pg);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_PRI_CSHAP_CFG_FLAG) &&
		    hns3_test_tm_pri_shapping_set(hdev, HCLGE_TM_SHAP_C_BUCKET,
						  pri_id, in_info->c_shaping)) {
			pr_err("%s,%d:set pri(%d) c shaping(%u)) failed!\n",
			       __func__, __LINE__, pri_id, in_info->c_shaping);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_PRI_PSHAP_CFG_FLAG) &&
		    hns3_test_tm_pri_shapping_set(hdev, HCLGE_TM_SHAP_P_BUCKET,
						  pri_id, in_info->p_shaping)) {
			pr_err("%s,%d:set pri(%d) p shaping(%u) failed!\n",
			       __func__, __LINE__, pri_id, in_info->p_shaping);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_PRI_MODE_CFG_FLAG) &&
		    hns3_test_tm_schd_mode_set(hdev,
					       HCLGE_OPC_TM_PRI_SCH_MODE_CFG,
					       in_info->mode, pri_id)) {
			pr_err("%s,%d:set pri(%d) mode(%d) failed!\n", __func__,
			       __LINE__, pri_id, in_info->mode);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_PRI_WEIGHT_CFG_FLAG) &&
		    hns3_test_tm_pri_weight_set(hdev, pri_id,
						in_info->weight)) {
			pr_err("%s,%d:set pri(%d) weight(%d) failed!\n",
			       __func__, __LINE__, pri_id, in_info->weight);
			return -1;
		}
	}

	return 0;
}

int hns3_test_pg_cfg(struct hns3_nic_priv *net_priv, void *buf_in, u32 in_size,
		     void *buf_out, u32 out_size)
{
	struct nictool_pg_cfg_info *out_info;
	struct nictool_pg_cfg_info *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	int is_read;
	bool check;
	u16 pg_id;

	check = !buf_in || in_size < sizeof(struct nictool_pg_cfg_info);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct nictool_pg_cfg_info *)buf_in;
	out_info = (struct nictool_pg_cfg_info *)buf_out;
	is_read = in_info->is_read;
	pg_id = in_info->pg_id;

	if (is_read) {
		check = !buf_out ||
			out_size < sizeof(struct nictool_pg_cfg_info);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		out_info->pg_id = pg_id;
		if (hns3_test_tm_pg_shapping_get(hdev, HCLGE_TM_SHAP_C_BUCKET,
						 pg_id,
						 &out_info->c_shaping)) {
			pr_err("%s,%d:get pg(%d) c shaping failed!\n", __func__,
			       __LINE__, pg_id);
			return -1;
		}

		if (hns3_test_tm_pg_shapping_get(hdev, HCLGE_TM_SHAP_P_BUCKET,
						 pg_id,
						 &out_info->p_shaping)) {
			pr_err("%s,%d:get pg(%d) p shaping failed!\n", __func__,
			       __LINE__, pg_id);
			return -1;
		}

		if (hns3_test_tm_schd_mode_get
		    (hdev, HCLGE_OPC_TM_PG_SCH_MODE_CFG, &out_info->mode,
		     pg_id)) {
			pr_err("%s,%d:get pg(%d) mode failed!\n", __func__,
			       __LINE__, pg_id);
			return -1;
		}

		if (hns3_test_tm_pg_weight_get(hdev, pg_id,
					       &out_info->weight)) {
			pr_err("%s,%d:set pg(%d) weight failed!\n", __func__,
			       __LINE__, pg_id);
			return -1;
		}

	} else {
		if ((in_info->flag & HNS3_TM_PG_CSHAP_CFG_FLAG) &&
		    hns3_test_tm_pg_shapping_set(hdev, HCLGE_TM_SHAP_C_BUCKET,
						 pg_id, in_info->c_shaping)) {
			pr_err("%s,%d:set pg(%d) c shaping(%u) failed!\n",
			       __func__, __LINE__, pg_id, in_info->c_shaping);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_PG_PSHAP_CFG_FLAG) &&
		    hns3_test_tm_pg_shapping_set(hdev, HCLGE_TM_SHAP_P_BUCKET,
						 pg_id, in_info->p_shaping)) {
			pr_err("%s,%d:set pg(%d) p shaping(%u) failed!\n",
			       __func__, __LINE__, pg_id, in_info->p_shaping);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_PG_MODE_CFG_FLAG) &&
		    hns3_test_tm_schd_mode_set(hdev,
					       HCLGE_OPC_TM_PG_SCH_MODE_CFG,
					       in_info->mode, pg_id)) {
			pr_err("%s,%d:set pg(%d) mode(%d) failed!\n", __func__,
			       __LINE__, pg_id, in_info->mode);
			return -1;
		}

		if ((in_info->flag & HNS3_TM_PG_WEIGHT_CFG_FLAG) &&
		    hns3_test_tm_pg_weight_set(hdev, pg_id, in_info->weight)) {
			pr_err("%s,%d:set pg(%d) weight(%d) failed!\n",
			       __func__, __LINE__, pg_id, in_info->weight);
			return -1;
		}
	}

	return 0;
}

int hns3_test_port_cfg(struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
	struct nictool_port_cfg_info *out_info;
	struct nictool_port_cfg_info *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	u16 port_id;
	int is_read;
	bool check;

	check = !buf_in || in_size < sizeof(struct nictool_port_cfg_info);
	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct nictool_port_cfg_info *)buf_in;
	out_info = (struct nictool_port_cfg_info *)buf_out;
	is_read = in_info->is_read;
	port_id = in_info->port_id;

	if (is_read) {
		check = !buf_out ||
			out_size < sizeof(struct nictool_port_cfg_info);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		out_info->port_id = port_id;
		if (hns3_test_tm_port_shapping_get(hdev, &out_info->shaping)) {
			pr_err("%s,%d:get port p shaping failed!\n", __func__,
			       __LINE__);
			return -1;
		}
	} else {
		if ((in_info->flag & HNS3_TM_PORT_PSHAP_CFG_FLAG) &&
		    hns3_test_tm_port_shapping_set(hdev, in_info->shaping)) {
			pr_err("%s,%d:set port p shaping(%u) failed!\n",
			       __func__, __LINE__, in_info->shaping);
			return -1;
		}
	}

	return 0;
}

int hns3_test_ets_cfg(struct hns3_nic_priv *net_priv,
		      void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
#define HNS3_TM_ETS_PORT_SHAPING		0x130820850
	struct nictool_ets_cfg_info *out_info;
	struct nictool_ets_cfg_info *in_info;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	u8 weight[8];
	int is_read;
	bool check;
	u16 tc_id;
	u8 mac_id;
	u64 value;
	u64 addr;

	check = !buf_in || in_size < sizeof(struct nictool_ets_cfg_info) ||
		!buf_out || out_size < sizeof(struct nictool_ets_cfg_info);
	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(net_priv->ae_handle);
	hdev = vport->back;
	in_info = (struct nictool_ets_cfg_info *)buf_in;
	out_info = (struct nictool_ets_cfg_info *)buf_out;
	is_read = in_info->is_read;
	tc_id = in_info->tc_id;
	mac_id = in_info->mac_id;
	addr = (u64)HNS3_TM_ETS_PORT_SHAPING + ((u64)mac_id << 20);
	out_info->tc_id = tc_id;
	out_info->mac_id = mac_id;
	if (is_read) {
		if (hns3_test_tm_ets_tc_dwrr_get(hdev, weight)) {
			pr_err("%s,%d:get ets tc dwrr failed!\n", __func__,
			       __LINE__);
			return -1;
		}
		out_info->weight = weight[tc_id];
		if (hns3_test_tm_operate_nic_regs(hdev, addr, &value,
						  is_read)) {
			pr_err("%s,%d:get ets port shaper failed!\n", __func__,
			       __LINE__);
			return -1;
		}
		out_info->shaping = (u32)value;
	} else {
		if (hns3_test_tm_ets_tc_dwrr_get(hdev, weight)) {
			pr_err("%s,%d:get ets tc dwrr failed!\n", __func__,
			       __LINE__);
			return -1;
		}
		weight[tc_id] = in_info->weight;
		if ((in_info->flag & HNS3_TM_ETS_TC_CFG_FLAG) &&
		    hns3_test_tm_ets_tc_dwrr_set(hdev, weight)) {
			pr_err("%s,%d:set ets tc dwrr failed!\n", __func__,
			       __LINE__);
			return -1;
		}
		value = (u64)in_info->shaping;
		if ((in_info->flag & HNS3_TM_ETS_PSHAP_CFG_FLAG) &&
		    hns3_test_tm_operate_nic_regs(hdev, addr, &value,
						  is_read)) {
			pr_err("%s,%d:set ets port shaping(%u) failed!\n",
			       __func__, __LINE__, in_info->shaping);
			return -1;
		}
	}

	return 0;
}
