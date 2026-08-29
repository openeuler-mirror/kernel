// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <ub/ubase/ubase_comm_debugfs.h>

#include "ubase_cmd.h"
#include "ubase_ctrlq.h"
#include "ubase_debugfs.h"
#include "ubase_hw.h"
#include "ubase_mailbox.h"
#include "ubase_qos_debugfs.h"

int ubase_dbg_dump_sl_vl_map(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	u8 i, sl_vl[UBASE_MAX_SL_NUM] = {0};
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_sl_vl_map(udev, sl_vl);
	if (ret)
		return ret;

	seq_puts(s, "sl  sw_vl  hw_vl\n");
	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		seq_printf(s, "%-4u", i);
		seq_printf(s, "%-7u", udev->qos.adev_qos.ue_sl_vl[i]);
		seq_printf(s, "%-7u", sl_vl[i]);
		seq_puts(s, "\n");
	}

	return ret;
}

/**
 * ubase_dbg_get_sl_vl_map() - get sl vl map
 * @dev: device
 * @map: debug sl vl map
 *
 * The function is used to get sl vl map.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_dbg_get_sl_vl_map(struct device *dev, struct ubase_dbg_sl_vl_map *map)
{
	u8 sl_vl[UBASE_MAX_SL_NUM] = {0};
	struct ubase_dev *udev;
	int ret;

	if (!dev || !map)
		return -EINVAL;

	udev = dev_get_drvdata(dev);
	if (!ubase_dev_urma_supported(udev) && !ubase_dev_cdma_supported(udev))
		return -EOPNOTSUPP;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_sl_vl_map(udev, sl_vl);
	if (ret)
		return ret;

	memcpy(map->hw_vl, sl_vl, UBASE_MAX_SL_NUM);

	return 0;
}
EXPORT_SYMBOL(ubase_dbg_get_sl_vl_map);

int ubase_dbg_dump_udma_dscp_vl_map(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	int i;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	seq_puts(s, "dscp   vl\n");
	for (i = 0; i < UBASE_MAX_DSCP; i++) {
		seq_printf(s, "%-7d", i);
		seq_printf(s, "%-4u", udev->qos.adev_qos.dscp_vl[i]);
		seq_puts(s, "\n");
	}

	return 0;
}

/**
 * ubase_dbg_get_dscp_vl_map() - get dscp vl map
 * @dev: device
 * @map: debug dscp vl map
 *
 * The function is used to get dscp vl map.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_dbg_get_dscp_vl_map(struct device *dev,
			      struct ubase_dbg_dscp_vl_map *map)
{
	struct ubase_query_vl_map_cmd resp = {0};
	struct ubase_dev *udev;
	int ret;

	if (!dev || !map)
		return -EINVAL;

	udev = dev_get_drvdata(dev);
	if (!ubase_dev_eth_mac_supported(udev))
		return -EOPNOTSUPP;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_vl_map(udev, &resp);
	if (ret)
		return ret;

	memcpy(map->hw_vl, resp.dscp_vl, sizeof(map->hw_vl));

	return 0;
}
EXPORT_SYMBOL(ubase_dbg_get_dscp_vl_map);

int ubase_dbg_dump_ets_tc_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_cfg_ets_vl_sch_cmd resp = {0};
	unsigned long vl_bitmap = 0;
	struct ubase_caps *caps;
	u32 port_bitmap;
	int ret;
	u8 i;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	     test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	caps = &udev->caps.dev_caps;
	port_bitmap = 1 << caps->io_port_id;
	for (i = 0; i < caps->vl_num; i++) {
		vl_bitmap |= 1 << caps->req_vl[i];
		vl_bitmap |= 1 << caps->resp_vl[i];
	}

	ret = ubase_query_ets_tc(udev, port_bitmap, vl_bitmap, &resp);
	if (ret)
		return ret;

	seq_puts(s, "TC_ID  SCH_MODE   WEIGHT\n");
	vl_bitmap = le16_to_cpu(resp.vl_bitmap);
	for (i = 0; i < UBASE_MAX_VL_NUM; i++) {
		if (!test_bit(i, &vl_bitmap))
			continue;

		seq_printf(s, "%-7u", i);
		seq_printf(s, "%-11s", resp.vl_bw[i] ? "dwrr" : "sp");
		seq_printf(s, "%-9u", resp.vl_bw[i]);
		seq_puts(s, "\n");
	}

	return 0;
}

int ubase_dbg_dump_ets_tcg_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_ets_tcg_cmd resp = {0};
	int ret;
	u8 i;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	     test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_ets_tcg(udev, &resp);
	if (ret)
		return ret;

	seq_puts(s, "TCG_ID  SCH_MODE   WEIGHT   TC_BITMAP   RATE(Mbps)   ");
	seq_puts(s, "IR_B   IR_U   IR_S   BS_B   BS_S\n");
	for (i = 0; i < UBASE_MAX_TCG_NUM; i++) {
		seq_printf(s, "%-8u", i);
		seq_printf(s, "%-11s", resp.tcg_weight[i] ? "dwrr" : "sp");
		seq_printf(s, "%-9u", resp.tcg_weight[i]);
		seq_printf(s, "0x%04x%-6s", le16_to_cpu(resp.tcg_tc_map[i]), "");
		seq_printf(s, "%-13u", le32_to_cpu(resp.tcg_info[i].rate));
		seq_printf(s, "%-7u", resp.tcg_info[i].ir_b);
		seq_printf(s, "%-7u", resp.tcg_info[i].ir_u);
		seq_printf(s, "%-7u", resp.tcg_info[i].ir_s);
		seq_printf(s, "%-7u", resp.tcg_info[i].bs_b);
		seq_printf(s, "%-7u", resp.tcg_info[i].bs_s);
		seq_puts(s, "\n");
	}

	return 0;
}

int ubase_dbg_dump_ets_port_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_ets_port_cmd resp = {0};
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	     test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_ets_port(udev, &resp);
	if (ret)
		return ret;

	seq_printf(s, "RATE(Mbps): %u ", le32_to_cpu(resp.port_info.rate));
	seq_printf(s, "IR_B: %u ", resp.port_info.ir_b);
	seq_printf(s, "IR_U: %u ", resp.port_info.ir_u);
	seq_printf(s, "IR_S: %u ", resp.port_info.ir_s);
	seq_printf(s, "BS_B: %u ", resp.port_info.bs_b);
	seq_printf(s, "BS_S: %u", resp.port_info.bs_s);
	seq_puts(s, "\n");

	return 0;
}

int ubase_dbg_dump_vl_bitmap(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_ctrlq_query_vl_resp resp = {0};
	struct ubase_ctrlq_query_vl_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	u16 vl_bitmap;
	int ret = 0;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_QOS;
	msg.opcode = UBASE_CTRLQ_OPC_QUERY_VL;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(resp);
	msg.out = &resp;

	ret = __ubase_ctrlq_send(udev, &msg, true, NULL);
	if (ret) {
		ubase_err(udev,
			  "failed to send ctrlq msg when query vl, ret = %d.\n",
			  ret);
		return ret;
	}

	vl_bitmap = le16_to_cpu(resp.vl_bitmap);

	seq_printf(s, "vl bitmap : 0x%x\n", vl_bitmap);

	return 0;
}

static void ubase_dbg_dump_adev_vl_info(struct seq_file *s,
					struct ubase_dev *udev)
{
	struct ubase_adev_utp_qos *utp_qos = &udev->qos.utp_qos;
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;

	seq_puts(s, "tp_req_vl:");
	ubase_dbg_dump_arr_info(s, qos->tp_req_vl, qos->tp_vl_num);

	seq_puts(s, "ctp_req_vl:");
	ubase_dbg_dump_arr_info(s, qos->ctp_req_vl, qos->ctp_vl_num);

	seq_puts(s, "nic_vl:");
	ubase_dbg_dump_arr_info(s, qos->nic_vl, qos->nic_vl_num);

	seq_puts(s, "utp_vl:");
	ubase_dbg_dump_arr_info(s, utp_qos->utp_vl, utp_qos->utp_vl_num);
}

static void ubase_dbg_dump_adev_sl_info(struct seq_file *s,
					struct ubase_dev *udev)
{
	struct ubase_adev_utp_qos *utp_qos = &udev->qos.utp_qos;
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;

	seq_puts(s, "tp_sl:");
	ubase_dbg_dump_arr_info(s, qos->tp_sl, qos->tp_sl_num);

	seq_puts(s, "ctp_sl:");
	ubase_dbg_dump_arr_info(s, qos->ctp_sl, qos->ctp_sl_num);

	seq_puts(s, "nic_sl:");
	ubase_dbg_dump_arr_info(s, qos->nic_sl, qos->nic_sl_num);

	seq_puts(s, "utp_sl:");
	ubase_dbg_dump_arr_info(s, utp_qos->utp_sl, utp_qos->utp_sl_num);
}

int ubase_dbg_dump_adev_qos_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_adev_utp_qos *utp_qos = &udev->qos.utp_qos;
	struct ubase_adev_qos *qos = &udev->qos.adev_qos;
	struct ubase_dbg_adev_qos_info {
		const char *format;
		u8 qos_info;
	} adev_qos_info[] = {
		{"tp_vl_num: %u\n", qos->tp_vl_num},
		{"ctp_vl_num: %u\n", qos->ctp_vl_num},
		{"tp_resp_vl_offset: %u\n", qos->tp_resp_vl_offset},
		{"ctp_resp_vl_offset: %u\n", qos->ctp_resp_vl_offset},
		{"tp_sl_num: %u\n", qos->tp_sl_num},
		{"ctp_sl_num: %u\n", qos->ctp_sl_num},
		{"nic_sl_num: %u\n", qos->nic_sl_num},
		{"nic_vl_num: %u\n", qos->nic_vl_num},
		{"ue_max_vl_id: %u\n", qos->ue_max_vl_id},
		{"utp_sl_num: %u\n", utp_qos->utp_sl_num},
		{"utp_vl_num: %u\n", utp_qos->utp_vl_num},
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(adev_qos_info); i++)
		seq_printf(s, adev_qos_info[i].format, adev_qos_info[i].qos_info);

	ubase_dbg_dump_adev_vl_info(s, udev);
	ubase_dbg_dump_adev_sl_info(s, udev);

	return 0;
}

static void ubase_dbg_fill_fst_fvt(struct seq_file *s,
				   struct ubase_query_fst_fvt_rqmt_cmd *resp)
{
	seq_puts(s, "\tFST:\n");
	seq_printf(s, "\t\tsl_queue_vl_num: %u\n",
		   le16_to_cpu(resp->sl_queue_vl_num));
	seq_printf(s, "\t\tsl_queue_start_qid: %u\n",
		   le16_to_cpu(resp->sl_queue_start_qid));
	seq_puts(s, "\tFVT:\n");
	seq_printf(s, "\t\tfvt_vl_size: %u\n", le16_to_cpu(resp->fvt_vl_size));
	seq_printf(s, "\t\tfvt_rqmt_offset: %u\n",
		   le16_to_cpu(resp->fvt_rqmt_offset));
}

static void ubase_dbg_fill_fst_revert(struct seq_file *s,
				      struct ubase_query_fst_fvt_rqmt_cmd *resp)
{
	u16 vl_num = min(UBASE_MAX_VL_NUM, le16_to_cpu(resp->sl_queue_vl_num));
	u16 j;

	seq_puts(s, "\tFST_REVERT:\n");
	seq_puts(s, "\t\tFST_IDX  UE_IDX   QUE_IDX   VL_NUM\n");

	for (j = 0; j < vl_num; j++) {
		seq_puts(s, "\t\t");
		seq_printf(s, "%-9u", le16_to_cpu(resp->fstr_info[j].fst_idx));
		seq_printf(s, "%-10u", resp->fstr_info[j].queue_ue_num);
		seq_printf(s, "%-10u", resp->fstr_info[j].queue_que_num);
		seq_printf(s, "%-9u", le16_to_cpu(resp->fstr_info[j].queue_vl_num));
		seq_puts(s, "\n");
	}
}

static void ubase_dbg_fill_rqmt(struct seq_file *s,
				struct ubase_query_fst_fvt_rqmt_cmd *resp)
{
	u16 vl_size = min(UBASE_MAX_VL_NUM, le16_to_cpu(resp->fvt_vl_size));
	u16 j;

	seq_puts(s, "\tRQMT:\n");
	seq_puts(s, "\t\tFST_IDX  QUE_IDX   QUE_SHIFT\n");

	for (j = 0; j < vl_size; j++) {
		seq_puts(s, "\t\t");
		seq_printf(s, "%-9u", le16_to_cpu(resp->rqmt_info[j].fst_idx));
		seq_printf(s, "%-10u",
			   le16_to_cpu(resp->rqmt_info[j].start_queue_idx));
		seq_printf(s, "%-12u",
			   le16_to_cpu(resp->rqmt_info[j].queue_quantity_shift));
		seq_puts(s, "\n");
	}

	seq_puts(s, "\n");
}

static void ubase_dbg_fill_tbl_content(struct seq_file *s,
				       struct ubase_query_fst_fvt_rqmt_cmd *resp)
{
	ubase_dbg_fill_fst_fvt(s, resp);

	ubase_dbg_fill_fst_revert(s, resp);

	ubase_dbg_fill_rqmt(s, resp);
}

int ubase_dbg_dump_fsv_fvt_rqmt(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_fst_fvt_rqmt_cmd resp = {0};
	struct ubase_ue_node *ue_node;
	u16 ue_id;
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	     test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	seq_puts(s, "current ue:\n");
	ret = ubase_query_fst_fvt_rqmt(udev, &resp, 0);
	if (ret)
		return ret;

	ubase_dbg_fill_tbl_content(s, &resp);

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list) {
		ue_id = ue_node->bus_ue_id;
		memset(&resp, 0, sizeof(resp));

		seq_printf(s, "ue%u:\n", ue_id);

		ret = ubase_query_fst_fvt_rqmt(udev, &resp, ue_id);
		if (ret)
			goto out;
		ubase_dbg_fill_tbl_content(s, &resp);
	}

out:
	mutex_unlock(&udev->ue_list_lock);
	return ret;
}

static void ubase_dbg_fill_tm_queue_seq(struct seq_file *s,
					struct ubase_query_tm_queue_cmd *resp)
{
	u16 bitmap = le16_to_cpu(resp->link_vld_bitmap);
	u8 i;

	seq_puts(s, "QUEUE_ID   QSET_ID   VL_ID  LINK_VLD_BITMAP\n");

	for (i = 0; i < resp->queue_num; i++) {
		seq_printf(s, "%-11u", resp->queue_id[i]);
		seq_printf(s, "%-10u", resp->qset_id[i]);
		seq_printf(s, "%-7u", resp->queue_vl[i]);
		seq_printf(s, "%-16u", ((u32)bitmap >> i) & 1U);
		seq_puts(s, "\n");
	}
}

int ubase_dbg_dump_tm_queue_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_tm_queue_cmd resp = {0};
	struct ubase_ue_node *ue_node;
	u16 ue_id = 0;
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_tm_queue(udev, ue_id, &resp);
	if (ret)
		return ret;

	seq_printf(s, "current ue: %u\n", ue_id);

	ubase_dbg_fill_tm_queue_seq(s, &resp);

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list) {
		ue_id = ue_node->bus_ue_id;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_query_tm_queue(udev, ue_id, &resp);
		if (ret)
			goto out;

		seq_printf(s, "\ncurrent ue: %u\n", ue_id);

		ubase_dbg_fill_tm_queue_seq(s, &resp);
	}

out:
	mutex_unlock(&udev->ue_list_lock);
	return ret;
}

static void ubase_dbg_fill_tm_qset_sharper_seq(struct ubase_query_tm_qset_cmd *resp,
					       struct seq_file *s, int qset_id)
{
	if (!resp->rate_limit_bypass) {
		seq_printf(s, "%-7u", resp->ir_b[qset_id]);
		seq_printf(s, "%-7u", resp->ir_u[qset_id]);
		seq_printf(s, "%-7u", resp->ir_s[qset_id]);
		seq_printf(s, "%-7u", resp->bs_b[qset_id]);
		seq_printf(s, "%-7u", resp->bs_s[qset_id]);
		seq_printf(s, "%-16u", le32_to_cpu(resp->rate[qset_id]));
		return;
	}

	seq_puts(s, "--     --     --     --     --     --              ");
}

static void ubase_dbg_fill_tm_qset_seq(struct seq_file *s,
				       struct ubase_query_tm_qset_cmd *resp)
{
	u16 link_vld = le16_to_cpu(resp->qset_pri_link_vld);
	u16 sch_mode = le16_to_cpu(resp->qset_sch_mode);
	u8 i;

	seq_puts(s, "QSET_ID   PRI_ID   LINK_VLD_BITMAP SCH_MODE   WEIGHT   ");
	seq_puts(s, "IR_B   IR_U   IR_S   BS_B   BS_S   RATE(Mbps)\n");

	for (i = 0; i < resp->qset_num; i++) {
		seq_printf(s, "%-10u", resp->qset_id[i]);
		seq_printf(s, "%-9u", resp->pri_id[i]);
		seq_printf(s, "%-16u", ((u32)link_vld >> i) & 1U);
		seq_printf(s, "%-11u", ((u32)sch_mode >> i) & 1U);
		seq_printf(s, "%-9u", resp->qset_weight[i]);

		ubase_dbg_fill_tm_qset_sharper_seq(resp, s, i);
		seq_puts(s, "\n");
	}
}

int ubase_dbg_dump_tm_qset_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_tm_qset_cmd resp = {0};
	struct ubase_ue_node *ue_node;
	u16 ue_id = 0;
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_tm_qset(udev, ue_id, &resp);
	if (ret)
		return ret;

	seq_printf(s, "current ue: %u\n", ue_id);

	ubase_dbg_fill_tm_qset_seq(s, &resp);

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list) {
		ue_id = ue_node->bus_ue_id;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_query_tm_qset(udev, ue_id, &resp);
		if (ret)
			goto out;

		seq_printf(s, "\ncurrent ue: %u\n", ue_id);

		ubase_dbg_fill_tm_qset_seq(s, &resp);
	}

out:
	mutex_unlock(&udev->ue_list_lock);
	return ret;
}

static void ubase_dbg_fill_tm_pri_csharper_seq(struct ubase_query_tm_pri_cmd *resp,
					       struct seq_file *s)
{
	if (!resp->c_rate_limit_bypass) {
		seq_printf(s, "%-9u", resp->c_ir_b);
		seq_printf(s, "%-9u", resp->c_ir_u);
		seq_printf(s, "%-9u", resp->c_ir_s);
		seq_printf(s, "%-9u", resp->c_bs_b);
		seq_printf(s, "%-9u", resp->c_bs_s);
		seq_printf(s, "%-15u", le32_to_cpu(resp->c_rate));
		return;
	}

	seq_puts(s, "--       --       --       --       --       --             ");
}

static void ubase_dbg_fill_tm_pri_psharper_seq(struct ubase_query_tm_pri_cmd *resp,
					       struct seq_file *s)
{
	if (!resp->p_rate_limit_bypass) {
		seq_printf(s, "%-9u", resp->p_ir_b);
		seq_printf(s, "%-9u", resp->p_ir_u);
		seq_printf(s, "%-9u", resp->p_ir_s);
		seq_printf(s, "%-9u", resp->p_bs_b);
		seq_printf(s, "%-9u", resp->p_bs_s);
		seq_printf(s, "%-15u", le32_to_cpu(resp->p_rate));
		return;
	}

	seq_puts(s, "--       --       --       --       --       --             ");
}

static void ubase_dbg_fill_tm_pri_seq(struct seq_file *s,
				     struct ubase_query_tm_pri_cmd *resp)
{
	seq_puts(s, "PRI_ID   PG_ID   SCH_MODE  WEIGHT   ");
	seq_puts(s, "C_IR_B   C_IR_U   C_IR_S   C_BS_B   C_BS_S   C_RATE(Mbps)   ");
	seq_puts(s, "P_IR_B   P_IR_U   P_IR_S   P_BS_B   P_BS_S   P_RATE(Mbps)\n");

	seq_printf(s, "%-9u", resp->pri_id);
	seq_printf(s, "%-8u", resp->pg_id);
	seq_printf(s, "%-10u", resp->pri_sch_mode);
	seq_printf(s, "%-9u", resp->pri_weight);

	ubase_dbg_fill_tm_pri_csharper_seq(resp, s);

	ubase_dbg_fill_tm_pri_psharper_seq(resp, s);
	seq_puts(s, "\n");
}

int ubase_dbg_dump_tm_pri_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_tm_pri_cmd resp = {0};
	struct ubase_ue_node *ue_node;
	u16 ue_id = 0;
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_tm_pri(udev, ue_id, &resp);
	if (ret)
		return ret;

	seq_printf(s, "current ue: %u\n", ue_id);

	ubase_dbg_fill_tm_pri_seq(s, &resp);

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list) {
		ue_id = ue_node->bus_ue_id;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_query_tm_pri(udev, ue_id, &resp);
		if (ret)
			goto out;

		seq_printf(s, "\ncurrent ue: %u\n", ue_id);

		ubase_dbg_fill_tm_pri_seq(s, &resp);
	}

out:
	mutex_unlock(&udev->ue_list_lock);
	return ret;
}

static void ubase_dbg_fill_tm_pg_csharper_seq(struct ubase_query_tm_pg_cmd *resp,
					      struct seq_file *s)
{
	if (!resp->c_rate_limit_bypass) {
		seq_printf(s, "%-9u", resp->c_ir_b);
		seq_printf(s, "%-9u", resp->c_ir_u);
		seq_printf(s, "%-9u", resp->c_ir_s);
		seq_printf(s, "%-9u", resp->c_bs_b);
		seq_printf(s, "%-9u", resp->c_bs_s);
		seq_printf(s, "%-15u", le32_to_cpu(resp->c_rate));
		return;
	}

	seq_puts(s, "--       --       --       --       --       --             ");
}

static void ubase_dbg_fill_tm_pg_psharper_seq(struct ubase_query_tm_pg_cmd *resp,
					      struct seq_file *s)
{
	if (!resp->p_rate_limit_bypass) {
		seq_printf(s, "%-9u", resp->p_ir_b);
		seq_printf(s, "%-9u", resp->p_ir_u);
		seq_printf(s, "%-9u", resp->p_ir_s);
		seq_printf(s, "%-9u", resp->p_bs_b);
		seq_printf(s, "%-9u", resp->p_bs_s);
		seq_printf(s, "%-15u", le32_to_cpu(resp->p_rate));
		return;
	}

	seq_puts(s, "--       --       --       --       --       --             ");
}

static void ubase_dbg_fill_tm_pg_seq(struct seq_file *s,
				     struct ubase_query_tm_pg_cmd *resp)
{
	seq_puts(s, "PG_ID   SCH_MODE  WEIGHT   ");
	seq_puts(s, "C_IR_B   C_IR_U   C_IR_S   C_BS_B   C_BS_S   C_RATE(Mbps)   ");
	seq_puts(s, "P_IR_B   P_IR_U   P_IR_S   P_BS_B   P_BS_S   P_RATE(Mbps)\n");

	seq_printf(s, "%-8u", resp->pg_id);
	seq_printf(s, "%-10u", resp->pg_sch_mode);
	seq_printf(s, "%-9u", resp->pg_weight);

	ubase_dbg_fill_tm_pg_csharper_seq(resp, s);

	ubase_dbg_fill_tm_pg_psharper_seq(resp, s);
	seq_puts(s, "\n");
}

int ubase_dbg_dump_tm_pg_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_tm_pg_cmd resp = {0};
	struct ubase_ue_node *ue_node;
	u16 ue_id = 0;
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_tm_pg(udev, ue_id, &resp);
	if (ret)
		return ret;

	seq_printf(s, "current ue: %u\n", ue_id);

	ubase_dbg_fill_tm_pg_seq(s, &resp);

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list) {
		ue_id = ue_node->bus_ue_id;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_query_tm_pg(udev, ue_id, &resp);
		if (ret)
			goto out;

		seq_printf(s, "\ncurrent ue: %u\n", ue_id);

		ubase_dbg_fill_tm_pg_seq(s, &resp);
	}

out:
	mutex_unlock(&udev->ue_list_lock);
	return ret;
}

static void ubase_dbg_fill_tm_port_sharper_seq(struct ubase_query_tm_port_cmd *resp,
					       struct seq_file *s)
{
	if (!resp->rate_limit_bypass) {
		seq_printf(s, "%-7u", resp->ir_b);
		seq_printf(s, "%-7u", resp->ir_u);
		seq_printf(s, "%-7u", resp->ir_s);
		seq_printf(s, "%-7u", resp->bs_b);
		seq_printf(s, "%-7u", resp->bs_s);
		seq_printf(s, "%-13u", le32_to_cpu(resp->rate));
		return;
	}

	seq_puts(s, "--     --     --     --     --     --           ");
}

int ubase_dbg_dump_tm_port_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_query_tm_port_cmd resp = {0};
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_tm_port(udev, &resp);
	if (ret)
		return ret;

	seq_puts(s, "IR_B   IR_U   IR_S   BS_B   BS_S   RATE(Mbps)\n");

	ubase_dbg_fill_tm_port_sharper_seq(&resp, s);
	seq_puts(s, "\n");

	return 0;
}

int ubase_dbg_dump_initial_qset_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_initial_qset_qos *initial_qos = &udev->qos.initial_qos;
	u8 i;

	if (!initial_qos->num)
		return -EOPNOTSUPP;

	seq_puts(s, "vl   qset_id   weight   rate(Mbps)\n");

	for (i = 0; i < initial_qos->num; i++) {
		seq_printf(s, "%-7u", initial_qos->vl[i]);
		seq_printf(s, "%-10u", initial_qos->qset_id[i]);
		seq_printf(s, "%-9u", initial_qos->qset_weight[i]);
		seq_printf(s, "%-7u\n", initial_qos->rate[i]);
	}

	return 0;
}
