// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/inetdevice.h>
#include "urma/ubcore_api.h"
#include "hnae3.h"
#include "hns3_udma_abi.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_eq.h"
#include "hns3_udma_qp.h"
#include "hns3_udma_dfx.h"
#include "hns3_udma_sysfs.h"
#include "hns3_udma_debugfs.h"

bool dfx_switch;

static const struct pci_device_id udma_hw_pci_tbl[] = {
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_UDMA_OVER_UBL),
	  HNAE3_DEV_SUPPORT_UDMA_OVER_UBL_DCB_BITS },
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_UDMA),
	  HNAE3_DEV_SUPPORT_UDMA_DCB_BITS },
	/* required last entry */
	{}
};

static int udma_cmq_query_hw_info(struct udma_dev *udma_dev)
{
	struct udma_query_version *resp;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_QUERY_HW_VER, true);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		return ret;

	resp = (struct udma_query_version *)desc.data;

	return 0;
}

static int udma_query_fw_ver(struct udma_dev *udma_dev)
{
	struct udma_query_fw_info *resp;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_QUERY_FW_VER, true);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		return ret;

	resp = (struct udma_query_fw_info *)desc.data;
	udma_dev->caps.fw_ver = le32_to_cpu(resp->fw_ver);

	return 0;
}

static int udma_query_func_id(struct udma_dev *udma_dev)
{
	struct udma_hw_id_query_cmq *resp;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_QUERY_HW_ID, true);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		if (desc.retval != CMD_NOT_EXIST)
			dev_warn(udma_dev->dev,
				 "failed to query hw id, ret = %d.\n", ret);

		goto invalid_val;
	}

	resp = (struct udma_hw_id_query_cmq *)desc.data;
	udma_dev->chip_id = resp->chip_id;
	udma_dev->die_id = resp->die_id;
	udma_dev->func_id = (uint16_t)le32_to_cpu(resp->func_id);
	return 0;

invalid_val:
	udma_dev->func_id = UDMA_INVALID_ID;
	return ret;
}

static int udma_query_func_info(struct udma_dev *udma_dev)
{
	struct udma_pf_func_info *resp;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_QUERY_FUNC_INFO, true);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		return ret;

	resp = (struct udma_pf_func_info *)desc.data;
	udma_dev->func_num = le32_to_cpu(resp->own_func_num);
	udma_dev->cong_algo_tmpl_id = le32_to_cpu(resp->own_mac_id);

	return udma_query_func_id(udma_dev);
}

static int udma_config_global_param(struct udma_dev *udma_dev)
{
	struct udma_cmq_desc desc;
	struct udma_cmq_req *req = (struct udma_cmq_req *)desc.data;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_GLOBAL_PARAM,
				  false);

	udma_reg_write(req, CFG_GLOBAL_PARAM_1US_CYCLES, UDMA_1US_CFG);
	udma_reg_write(req, CFG_GLOBAL_PARAM_UDP_PORT, UDMA_UDP_DPORT);

	return udma_cmq_send(udma_dev, &desc, 1);
}

static int __udma_set_vf_switch_param(struct udma_dev *udma_dev,
				      uint32_t vf_id)
{
	struct udma_vf_switch *swt;
	struct udma_cmq_desc desc;
	int ret;

	swt = (struct udma_vf_switch *)desc.data;
	udma_cmq_setup_basic_desc(&desc, UDMA_SWITCH_PARAMETER_CFG, true);
	swt->udma_sel |= cpu_to_le32(NIC_ICL_SWITCH_CMD_UDMA_SEL);
	udma_set_field(swt->fun_id, VF_SWITCH_DATA_FUN_ID_VF_ID_M,
		       VF_SWITCH_DATA_FUN_ID_VF_ID_S, vf_id);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		return ret;

	desc.flag =
		cpu_to_le16(UDMA_CMD_FLAG_NO_INTR | UDMA_CMD_FLAG_IN);
	desc.flag &= cpu_to_le16(~UDMA_CMD_FLAG_WR);
	udma_set_bit(swt->cfg, VF_SWITCH_DATA_CFG_ALW_LPBK_S, 1);
	udma_set_bit(swt->cfg, VF_SWITCH_DATA_CFG_ALW_LCL_LPBK_S, 0);
	udma_set_bit(swt->cfg, VF_SWITCH_DATA_CFG_ALW_DST_OVRD_S, 1);

	return udma_cmq_send(udma_dev, &desc, 1);
}

static int udma_set_vf_switch_param(struct udma_dev *udma_dev)
{
	uint32_t vf_id;
	int ret;

	for (vf_id = 0; vf_id < udma_dev->func_num; vf_id++) {
		ret = __udma_set_vf_switch_param(udma_dev, vf_id);
		if (ret)
			return ret;
	}
	return 0;
}

static void set_default_jetty_caps(struct udma_dev *dev)
{
	struct udma_caps *caps = &dev->caps;

	caps->num_jfc_shift = ilog2(caps->num_cqs);
	caps->num_jfs_shift = caps->num_qps_shift;
	caps->num_jfr_shift = caps->num_qps_shift;
	caps->num_jetty_shift = caps->num_qps_shift;
}

static void query_hw_speed(struct udma_dev *udma_dev)
{
	struct udma_port_info_cmq *resp;
	struct udma_cmq_desc desc;
	int ret;

	resp = (struct udma_port_info_cmq *)desc.data;
	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_QUERY_PORT_INFO, true);
	resp->query_type = UDMA_QUERY_PORT_INFO;
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_err(udma_dev->dev, "failed to query speed, ret = %d. set default 100G\n", ret);
		udma_dev->caps.speed = SPEED_100G;
		return;
	}
	udma_dev->caps.speed = resp->speed;
}

static int udma_query_caps(struct udma_dev *udma_dev)
{
	enum udma_opcode_type opcode = UDMA_OPC_QUERY_PF_CAPS_NUM;
	struct udma_cmq_desc desc[UDMA_QUERY_PF_CAPS_CMD_NUM];
	struct udma_caps *caps = &udma_dev->caps;
	struct udma_query_pf_caps_a *resp_a;
	struct udma_query_pf_caps_b *resp_b;
	struct udma_query_pf_caps_c *resp_c;
	struct udma_query_pf_caps_d *resp_d;
	struct udma_query_pf_caps_e *resp_e;
	int ctx_hop_num;
	int pbl_hop_num;
	int ret;
	int i;

	for (i = 0; i < UDMA_QUERY_PF_CAPS_CMD_NUM; i++) {
		udma_cmq_setup_basic_desc(&desc[i], opcode, true);
		if (i < (UDMA_QUERY_PF_CAPS_CMD_NUM - 1))
			desc[i].flag |= cpu_to_le16(UDMA_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(UDMA_CMD_FLAG_NEXT);
	}

	ret = udma_cmq_send(udma_dev, desc, UDMA_QUERY_PF_CAPS_CMD_NUM);
	if (ret)
		return ret;

	resp_a = (struct udma_query_pf_caps_a *)desc[0].data;
	resp_b = (struct udma_query_pf_caps_b *)desc[1].data;
	resp_c = (struct udma_query_pf_caps_c *)desc[2].data;
	resp_d = (struct udma_query_pf_caps_d *)desc[3].data;
	resp_e = (struct udma_query_pf_caps_e *)desc[4].data;

	caps->local_ca_ack_delay     = resp_a->local_ca_ack_delay;
	caps->max_sq_sg		     = le16_to_cpu(resp_a->max_sq_sg);
	caps->max_sq_inline	     = le16_to_cpu(resp_a->max_sq_inline);
	caps->max_rq_sg		     = le16_to_cpu(resp_a->max_rq_sg);
	caps->max_rq_sg		     = roundup_pow_of_two(caps->max_rq_sg);
	caps->max_extend_sg	     = le32_to_cpu(resp_a->max_extend_sg);
	caps->num_qpc_timer	     = le16_to_cpu(resp_a->num_qpc_timer);
	caps->max_srq_sges	     = le16_to_cpu(resp_a->max_srq_sges);
	/* reserved for UM header */
	caps->max_srq_sges	     = roundup_pow_of_two(caps->max_srq_sges) - 1;
	caps->num_aeq_vectors	     = resp_a->num_aeq_vectors;
	caps->num_other_vectors	     = resp_a->num_other_vectors;
	caps->max_sq_desc_sz	     = resp_a->max_sq_desc_sz;
	caps->max_rq_desc_sz	     = resp_a->max_rq_desc_sz;
	caps->max_srq_desc_sz	     = resp_a->max_srq_desc_sz;
	caps->cqe_sz		     = resp_a->cqe_sz;

	caps->mtpt_entry_sz	     = resp_b->mtpt_entry_sz;
	caps->irrl_entry_sz	     = resp_b->irrl_entry_sz;
	caps->trrl_entry_sz	     = resp_b->trrl_entry_sz;
	caps->cqc_entry_sz	     = resp_b->cqc_entry_sz;
	caps->srqc_entry_sz	     = resp_b->srqc_entry_sz;
	caps->idx_entry_sz	     = resp_b->idx_entry_sz;
	caps->scc_ctx_sz	     = resp_b->sccc_sz;
	caps->max_mtu		     = (enum ubcore_mtu)resp_b->max_mtu;
	caps->qpc_sz		     = le16_to_cpu(resp_b->qpc_sz);
	caps->min_cqes		     = resp_b->min_cqes;
	caps->min_wqes		     = resp_b->min_wqes;
	caps->page_size_cap	     = le32_to_cpu(resp_b->page_size_cap);
	caps->pkey_table_len[0]	     = resp_b->pkey_table_len;
	caps->phy_num_uars	     = resp_b->phy_num_uars;
	ctx_hop_num		     = resp_b->ctx_hop_num;
	pbl_hop_num		     = resp_b->pbl_hop_num;

	caps->num_pds = 1 << udma_get_field(resp_c->cap_flags_num_pds,
					    QUERY_PF_CAPS_C_NUM_PDS_M,
					    QUERY_PF_CAPS_C_NUM_PDS_S);
	caps->flags = udma_get_field(resp_c->cap_flags_num_pds,
				     QUERY_PF_CAPS_C_CAP_FLAGS_M,
				     QUERY_PF_CAPS_C_CAP_FLAGS_S);
	caps->flags |= le16_to_cpu(resp_d->cap_flags_ex) <<
		       UDMA_CAP_FLAGS_EX_SHIFT;

	caps->num_cqs = 1 << udma_get_field(resp_c->max_gid_num_cqs,
					    QUERY_PF_CAPS_C_NUM_CQS_M,
					    QUERY_PF_CAPS_C_NUM_CQS_S);

	caps->max_cqes = 1 << udma_get_field(resp_c->cq_depth,
					     QUERY_PF_CAPS_C_CQ_DEPTH_M,
					     QUERY_PF_CAPS_C_CQ_DEPTH_S);
	caps->num_mtpts = 1 << udma_get_field(resp_c->num_mrws,
					      QUERY_PF_CAPS_C_NUM_MRWS_M,
					      QUERY_PF_CAPS_C_NUM_MRWS_S);
	caps->num_qps = 1 << udma_get_field(resp_c->ord_num_qps,
					    QUERY_PF_CAPS_C_NUM_QPS_M,
					    QUERY_PF_CAPS_C_NUM_QPS_S);
	caps->num_qps_shift = udma_get_field(resp_c->ord_num_qps,
					     QUERY_PF_CAPS_C_NUM_QPS_M,
					     QUERY_PF_CAPS_C_NUM_QPS_S);
	caps->max_qp_init_rdma = udma_get_field(resp_c->ord_num_qps,
						QUERY_PF_CAPS_C_MAX_ORD_M,
						QUERY_PF_CAPS_C_MAX_ORD_S);
	caps->max_qp_dest_rdma = caps->max_qp_init_rdma;
	caps->max_wqes = 1 << le16_to_cpu(resp_c->sq_depth);
	caps->num_srqs = 1 << udma_get_field(resp_d->wq_hop_num_max_srqs,
					     QUERY_PF_CAPS_D_NUM_SRQS_M,
					     QUERY_PF_CAPS_D_NUM_SRQS_S);
	caps->cong_type = udma_get_field(resp_d->wq_hop_num_max_srqs,
					 QUERY_PF_CAPS_D_CONG_TYPE_M,
					 QUERY_PF_CAPS_D_CONG_TYPE_S);
	caps->max_srq_wrs = 1 << le16_to_cpu(resp_d->srq_depth);

	caps->ceqe_depth = 1 << udma_get_field(resp_d->num_ceqs_ceq_depth,
					       QUERY_PF_CAPS_D_CEQ_DEPTH_M,
					       QUERY_PF_CAPS_D_CEQ_DEPTH_S);
	caps->num_comp_vectors = udma_get_field(resp_d->num_ceqs_ceq_depth,
						QUERY_PF_CAPS_D_NUM_CEQS_M,
						QUERY_PF_CAPS_D_NUM_CEQS_S);

	caps->aeqe_depth = 1 << udma_get_field(resp_d->arm_st_aeq_depth,
					       QUERY_PF_CAPS_D_AEQ_DEPTH_M,
					       QUERY_PF_CAPS_D_AEQ_DEPTH_S);
	caps->default_aeq_arm_st = udma_get_field(resp_d->arm_st_aeq_depth,
						  QUERY_PF_CAPS_D_AEQ_ARM_ST_M,
						  QUERY_PF_CAPS_D_AEQ_ARM_ST_S);
	caps->default_ceq_arm_st = udma_get_field(resp_d->arm_st_aeq_depth,
						  QUERY_PF_CAPS_D_CEQ_ARM_ST_M,
						  QUERY_PF_CAPS_D_CEQ_ARM_ST_S);
	caps->reserved_pds = udma_get_field(resp_d->num_uars_rsv_pds,
					    QUERY_PF_CAPS_D_RSV_PDS_M,
					    QUERY_PF_CAPS_D_RSV_PDS_S);
	caps->num_uars = 1 << udma_get_field(resp_d->num_uars_rsv_pds,
					     QUERY_PF_CAPS_D_NUM_UARS_M,
					     QUERY_PF_CAPS_D_NUM_UARS_S);
	caps->reserved_qps = udma_get_field(resp_d->rsv_uars_rsv_qps,
					    QUERY_PF_CAPS_D_RSV_QPS_M,
					    QUERY_PF_CAPS_D_RSV_QPS_S);
	caps->reserved_uars = udma_get_field(resp_d->rsv_uars_rsv_qps,
					     QUERY_PF_CAPS_D_RSV_UARS_M,
					     QUERY_PF_CAPS_D_RSV_UARS_S);
	caps->reserved_mrws = udma_get_field(resp_e->chunk_size_shift_rsv_mrws,
					     QUERY_PF_CAPS_E_RSV_MRWS_M,
					     QUERY_PF_CAPS_E_RSV_MRWS_S);
	caps->chunk_sz = 1 << udma_get_field(resp_e->chunk_size_shift_rsv_mrws,
					     QUERY_PF_CAPS_E_CHUNK_SIZE_SHIFT_M,
					     QUERY_PF_CAPS_E_CHUNK_SIZE_SHIFT_S);
	caps->reserved_cqs = udma_get_field(resp_e->rsv_cqs,
					    QUERY_PF_CAPS_E_RSV_CQS_M,
					    QUERY_PF_CAPS_E_RSV_CQS_S);
	caps->reserved_srqs = udma_get_field(resp_e->rsv_srqs,
					     QUERY_PF_CAPS_E_RSV_SRQS_M,
					     QUERY_PF_CAPS_E_RSV_SRQS_S);
	caps->reserved_lkey = udma_get_field(resp_e->rsv_lkey,
					     QUERY_PF_CAPS_E_RSV_LKEYS_M,
					     QUERY_PF_CAPS_E_RSV_LKEYS_S);
	caps->default_ceq_max_cnt = le16_to_cpu(resp_e->ceq_max_cnt);
	caps->default_ceq_period = le16_to_cpu(resp_e->ceq_period);
	caps->default_aeq_max_cnt = le16_to_cpu(resp_e->aeq_max_cnt);
	caps->default_aeq_period = le16_to_cpu(resp_e->aeq_period);

	caps->qpc_hop_num = ctx_hop_num;
	caps->sccc_hop_num = ctx_hop_num;
	caps->srqc_hop_num = ctx_hop_num;
	caps->cqc_hop_num = ctx_hop_num;
	caps->mpt_hop_num = ctx_hop_num;
	caps->mtt_hop_num = pbl_hop_num;
	caps->cqe_hop_num = pbl_hop_num;
	caps->srqwqe_hop_num = pbl_hop_num;
	caps->idx_hop_num = pbl_hop_num;
	caps->wqe_sq_hop_num = udma_get_field(resp_d->wq_hop_num_max_srqs,
					      QUERY_PF_CAPS_D_SQWQE_HOP_NUM_M,
					      QUERY_PF_CAPS_D_SQWQE_HOP_NUM_S);
	caps->wqe_sge_hop_num = udma_get_field(resp_d->wq_hop_num_max_srqs,
					       QUERY_PF_CAPS_D_EX_SGE_HOP_NUM_M,
					       QUERY_PF_CAPS_D_EX_SGE_HOP_NUM_S);
	caps->wqe_rq_hop_num = udma_get_field(resp_d->wq_hop_num_max_srqs,
					      QUERY_PF_CAPS_D_RQWQE_HOP_NUM_M,
					      QUERY_PF_CAPS_D_RQWQE_HOP_NUM_S);

	set_default_jetty_caps(udma_dev);
	query_hw_speed(udma_dev);

	return 0;
}

static int load_func_res_caps(struct udma_dev *udma_dev)
{
	struct udma_cmq_desc desc[2];
	struct udma_cmq_req *r_a = (struct udma_cmq_req *)desc[0].data;
	struct udma_cmq_req *r_b = (struct udma_cmq_req *)desc[1].data;
	struct udma_caps *caps = &udma_dev->caps;
	enum udma_opcode_type opcode;
	uint32_t func_num;
	int ret;

	opcode = UDMA_OPC_QUERY_PF_RES;
	func_num = udma_dev->func_num;

	udma_cmq_setup_basic_desc(&desc[0], opcode, true);
	desc[0].flag |= cpu_to_le16(UDMA_CMD_FLAG_NEXT);
	udma_cmq_setup_basic_desc(&desc[1], opcode, true);

	ret = udma_cmq_send(udma_dev, desc, 2);
	if (ret)
		return ret;

	caps->qpc_bt_num = udma_reg_read(r_a, FUNC_RES_A_QPC_BT_NUM) / func_num;
	caps->srqc_bt_num =
		udma_reg_read(r_a, FUNC_RES_A_SRQC_BT_NUM) / func_num;
	caps->cqc_bt_num = udma_reg_read(r_a, FUNC_RES_A_CQC_BT_NUM) / func_num;
	caps->mpt_bt_num = udma_reg_read(r_a, FUNC_RES_A_MPT_BT_NUM) / func_num;
	caps->eqc_bt_num = udma_reg_read(r_a, FUNC_RES_A_EQC_BT_NUM) / func_num;
	caps->smac_bt_num = udma_reg_read(r_b, FUNC_RES_B_SMAC_NUM) / func_num;
	caps->sgid_bt_num = udma_reg_read(r_b, FUNC_RES_B_SGID_NUM) / func_num;
	caps->sccc_bt_num =
		udma_reg_read(r_b, FUNC_RES_B_SCCC_BT_NUM) / func_num;


	caps->sl_num =
		udma_reg_read(r_b, FUNC_RES_B_QID_NUM) / func_num;
	caps->gmv_bt_num =
		udma_reg_read(r_b, FUNC_RES_B_GMV_BT_NUM) / func_num;

	return 0;
}

static int load_ext_cfg_caps(struct udma_dev *udma_dev)
{
	struct udma_cmq_desc desc;
	struct udma_cmq_req *req = (struct udma_cmq_req *)desc.data;
	struct udma_caps *caps = &udma_dev->caps;
	uint32_t func_num, qp_num;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_EXT_CFG, true);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		return ret;

	func_num = max_t(uint32_t, 1, udma_dev->func_num);
	qp_num = udma_reg_read(req, EXT_CFG_QP_PI_NUM) / func_num;
	caps->num_pi_qps = round_down(qp_num, UDMA_QP_BANK_NUM);

	qp_num = udma_reg_read(req, EXT_CFG_QP_NUM) / func_num;
	caps->num_qps = round_down(qp_num, UDMA_QP_BANK_NUM);
	caps->num_qps_shift = ilog2(caps->num_qps);

	/* The extend doorbell memory on the PF is shared by all its VFs. */
	caps->llm_ba_idx = udma_reg_read(req, EXT_CFG_LLM_INDEX);
	caps->llm_ba_num = udma_reg_read(req, EXT_CFG_LLM_NUM);

	return 0;
}

static int query_func_resource_caps(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = load_func_res_caps(udma_dev);
	if (ret) {
		dev_err(dev, "failed to load res caps, ret = %d (pf).\n",
			ret);
		return ret;
	}

	ret = load_ext_cfg_caps(udma_dev);
	if (ret)
		dev_err(dev, "failed to load ext cfg, ret = %d (pf).\n",
			ret);
	return ret;
}

static int load_pf_timer_res_caps(struct udma_dev *udma_dev)
{
	struct udma_cmq_desc desc;
	struct udma_cmq_req *req = (struct udma_cmq_req *)desc.data;
	struct udma_caps *caps = &udma_dev->caps;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_QUERY_PF_TIMER_RES,
				  true);

	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		return ret;

	caps->qpc_timer_bt_num = udma_reg_read(req, PF_TIMER_RES_QPC_ITEM_NUM);
	caps->cqc_timer_bt_num = udma_reg_read(req, PF_TIMER_RES_CQC_ITEM_NUM);

	return 0;
}

static int query_func_oor_caps(struct udma_dev *udma_dev)
{
	struct udma_caps *caps = &udma_dev->caps;
	struct udma_query_oor_cmq *resp;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_QUERY_OOR_CAPS, true);

	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to func oor caps, ret = %d.\n", ret);
		return ret;
	}

	resp = (struct udma_query_oor_cmq *)desc.data;

	caps->oor_en = resp->oor_en;
	caps->reorder_cq_buffer_en = resp->reorder_cq_buffer_en;
	caps->reorder_cap = resp->reorder_cap;
	caps->reorder_cq_shift = resp->reorder_cq_shift;
	caps->onflight_size = resp->on_flight_size;
	caps->dynamic_ack_timeout = resp->dynamic_ack_timeout;

	return ret;
}

static int udma_query_pf_resource(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = query_func_resource_caps(udma_dev);
	if (ret)
		return ret;

	ret = load_pf_timer_res_caps(udma_dev);
	if (ret) {
		dev_err(dev, "failed to load pf timer resource, ret = %d.\n",
			ret);
		return ret;
	}

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_OOR)
		ret = query_func_oor_caps(udma_dev);

	return ret;
}

static void calc_pg_sz(uint32_t obj_num, uint32_t obj_size, uint32_t hop_num,
		       uint32_t ctx_bt_num, uint32_t *buf_page_size,
		       uint32_t *bt_page_size, uint32_t hem_type)
{
	uint64_t buf_chunk_size = PAGE_SIZE;
	uint64_t bt_chunk_size = PAGE_SIZE;
	uint64_t obj_per_chunk_default;
	uint64_t obj_per_chunk;

	obj_per_chunk_default = buf_chunk_size / obj_size;
	*buf_page_size = 0;
	*bt_page_size = 0;

	switch (hop_num) {
	case 3:
		obj_per_chunk = ctx_bt_num * (bt_chunk_size / BA_BYTE_LEN) *
				(bt_chunk_size / BA_BYTE_LEN) *
				(bt_chunk_size / BA_BYTE_LEN) *
				 obj_per_chunk_default;
		break;
	case 2:
		obj_per_chunk = ctx_bt_num * (bt_chunk_size / BA_BYTE_LEN) *
				(bt_chunk_size / BA_BYTE_LEN) *
				 obj_per_chunk_default;
		break;
	case 1:
		obj_per_chunk = ctx_bt_num * (bt_chunk_size / BA_BYTE_LEN) *
				obj_per_chunk_default;
		break;
	case UDMA_HOP_NUM_0:
		obj_per_chunk = ctx_bt_num * obj_per_chunk_default;
		break;
	default:
		pr_err("table %u not support hop_num = %u!\n", hem_type,
		       hop_num);
		return;
	}

	if (hem_type >= HEM_TYPE_MTT)
		*bt_page_size = ilog2(DIV_ROUND_UP(obj_num, obj_per_chunk));
	else
		*buf_page_size = ilog2(DIV_ROUND_UP(obj_num, obj_per_chunk));
}

static void set_hem_page_size(struct udma_dev *udma_dev)
{
	struct udma_caps *caps = &udma_dev->caps;

	/* EQ */
	caps->eqe_ba_pg_sz = 0;
	caps->eqe_buf_pg_sz = 0;

	/* Link Table */
	caps->llm_buf_pg_sz = 0;

	/* MR */
	caps->mpt_ba_pg_sz = 0;
	caps->mpt_buf_pg_sz = 0;
	caps->pbl_ba_pg_sz = UDMA_BA_PG_SZ_SUPPORTED_16K;
	caps->pbl_buf_pg_sz = 0;
	calc_pg_sz(caps->num_mtpts, caps->mtpt_entry_sz, caps->mpt_hop_num,
		   caps->mpt_bt_num, &caps->mpt_buf_pg_sz, &caps->mpt_ba_pg_sz,
		   HEM_TYPE_MTPT);

	/* QP */
	caps->qpc_ba_pg_sz = 0;
	caps->qpc_buf_pg_sz = 0;
	caps->qpc_timer_ba_pg_sz = 0;
	caps->qpc_timer_buf_pg_sz = 0;
	caps->sccc_ba_pg_sz = 0;
	caps->sccc_buf_pg_sz = 0;
	caps->mtt_ba_pg_sz = 0;
	caps->mtt_buf_pg_sz = 0;
	calc_pg_sz(caps->num_qps, caps->qpc_sz, caps->qpc_hop_num,
		   caps->qpc_bt_num, &caps->qpc_buf_pg_sz, &caps->qpc_ba_pg_sz,
		   HEM_TYPE_QPC);

	if (caps->flags & UDMA_CAP_FLAG_QP_FLOW_CTRL)
		calc_pg_sz(caps->num_qps, caps->scc_ctx_sz, caps->sccc_hop_num,
			   caps->sccc_bt_num, &caps->sccc_buf_pg_sz,
			   &caps->sccc_ba_pg_sz, HEM_TYPE_SCCC);

	/* CQ */
	caps->cqc_ba_pg_sz = 0;
	caps->cqc_buf_pg_sz = 0;
	caps->cqc_timer_ba_pg_sz = 0;
	caps->cqc_timer_buf_pg_sz = 0;
	caps->cqe_ba_pg_sz = UDMA_BA_PG_SZ_SUPPORTED_256K;
	caps->cqe_buf_pg_sz = 0;
	calc_pg_sz(caps->num_cqs, caps->cqc_entry_sz, caps->cqc_hop_num,
		   caps->cqc_bt_num, &caps->cqc_buf_pg_sz, &caps->cqc_ba_pg_sz,
		   HEM_TYPE_CQC);
	calc_pg_sz(caps->max_cqes, caps->cqe_sz, caps->cqe_hop_num,
		   1, &caps->cqe_buf_pg_sz, &caps->cqe_ba_pg_sz, HEM_TYPE_CQE);

	/* SRQ */
	if (caps->flags & UDMA_CAP_FLAG_SRQ) {
		caps->srqc_ba_pg_sz = 0;
		caps->srqc_buf_pg_sz = 0;
		caps->srqwqe_ba_pg_sz = 0;
		caps->srqwqe_buf_pg_sz = 0;
		caps->idx_ba_pg_sz = 0;
		caps->idx_buf_pg_sz = 0;
		calc_pg_sz(caps->num_srqs, caps->srqc_entry_sz,
			   caps->srqc_hop_num, caps->srqc_bt_num,
			   &caps->srqc_buf_pg_sz, &caps->srqc_ba_pg_sz,
			   HEM_TYPE_SRQC);
		calc_pg_sz(caps->num_srqwqe_segs, caps->mtt_entry_sz,
			   caps->srqwqe_hop_num, 1, &caps->srqwqe_buf_pg_sz,
			   &caps->srqwqe_ba_pg_sz, HEM_TYPE_SRQWQE);
		calc_pg_sz(caps->num_idx_segs, caps->idx_entry_sz,
			   caps->idx_hop_num, 1, &caps->idx_buf_pg_sz,
			   &caps->idx_ba_pg_sz, HEM_TYPE_INDEX);
	}

	/* GMV */
	caps->gmv_ba_pg_sz = 0;
	caps->gmv_buf_pg_sz = 0;
}

/* Apply all loaded caps before setting to hardware */
static void apply_func_caps(struct udma_dev *udma_dev)
{
	struct udma_caps *caps = &udma_dev->caps;
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;

	caps->qpc_timer_entry_sz = UDMA_QPC_TIMER_ENTRY_SZ;
	caps->cqc_timer_entry_sz = UDMA_CQC_TIMER_ENTRY_SZ;
	caps->mtt_entry_sz = UDMA_MTT_ENTRY_SZ;
	caps->eqe_hop_num = UDMA_EQE_HOP_NUM;
	caps->pbl_hop_num = UDMA_PBL_HOP_NUM;
	caps->qpc_timer_hop_num = UDMA_HOP_NUM_0;
	caps->cqc_timer_hop_num = UDMA_HOP_NUM_0;
	caps->ceqe_size = UDMA_EQE_SIZE;
	caps->aeqe_size = UDMA_EQE_SIZE;
	caps->num_mtt_segs = UDMA_MAX_MTT_SEGS;
	caps->num_srqwqe_segs = UDMA_MAX_SRQWQE_SEGS;
	caps->num_idx_segs = UDMA_MAX_IDX_SEGS;

	/* num_vector = comp_vector + aeq_vector + abn_vector */
	if (!caps->num_comp_vectors) {
		caps->num_comp_vectors =
			min_t(uint32_t, caps->eqc_bt_num - 1,
			      (uint32_t)priv->handle->udmainfo.num_vectors -
			      UDMA_FUNC_IRQ_RSV);
	}
	caps->qpc_sz = UDMA_QPC_SZ;
	caps->cqe_sz = UDMA_CQE_SZ;
	caps->scc_ctx_sz = UDMA_SCCC_SZ;

	/* The following caps are not in ncl config */
	caps->gmv_entry_sz = UDMA_GMV_ENTRY_SZ;
	caps->gmv_hop_num = UDMA_HOP_NUM_0;
	caps->gmv_entry_num = caps->gmv_bt_num * (PAGE_SIZE /
						  caps->gmv_entry_sz);
	caps->max_eid_cnt = (caps->gmv_entry_num > UDMA_MAX_EID_NUM) ?
			    UDMA_MAX_EID_NUM : caps->gmv_entry_num;

	set_hem_page_size(udma_dev);
}

static int config_vf_ext_resource(struct udma_dev *udma_dev, uint32_t vf_id)
{
	struct udma_cmq_desc desc;
	struct udma_cmq_req *req = (struct udma_cmq_req *)desc.data;
	struct udma_caps *caps = &udma_dev->caps;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_EXT_CFG, false);

	udma_reg_write(req, EXT_CFG_VF_ID, vf_id);

	udma_reg_write(req, EXT_CFG_QP_PI_NUM, caps->num_pi_qps);
	udma_reg_write(req, EXT_CFG_QP_PI_INDEX, vf_id * caps->num_pi_qps);
	udma_reg_write(req, EXT_CFG_QP_NUM, caps->num_qps);
	udma_reg_write(req, EXT_CFG_QP_INDEX, vf_id * caps->num_qps);

	return udma_cmq_send(udma_dev, &desc, 1);
}

static int config_vf_hem_resource(struct udma_dev *udma_dev, int vf_id)
{
	struct udma_cmq_desc desc[2];
	struct udma_cmq_req *r_a = (struct udma_cmq_req *)desc[0].data;
	struct udma_cmq_req *r_b = (struct udma_cmq_req *)desc[1].data;
	struct udma_caps *caps = &udma_dev->caps;

	udma_cmq_setup_basic_desc(&desc[0], UDMA_OPC_ALLOC_VF_RES, false);
	desc[0].flag |= cpu_to_le16(UDMA_CMD_FLAG_NEXT);
	udma_cmq_setup_basic_desc(&desc[1], UDMA_OPC_ALLOC_VF_RES, false);

	udma_reg_write(r_a, FUNC_RES_A_VF_ID, vf_id);

	udma_reg_write(r_a, FUNC_RES_A_QPC_BT_NUM, caps->qpc_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_QPC_BT_INDEX, vf_id * caps->qpc_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_SRQC_BT_NUM, caps->srqc_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_SRQC_BT_INDEX, vf_id * caps->srqc_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_CQC_BT_NUM, caps->cqc_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_CQC_BT_INDEX, vf_id * caps->cqc_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_MPT_BT_NUM, caps->mpt_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_MPT_BT_INDEX, vf_id * caps->mpt_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_EQC_BT_NUM, caps->eqc_bt_num);
	udma_reg_write(r_a, FUNC_RES_A_EQC_BT_INDEX, vf_id * caps->eqc_bt_num);
	udma_reg_write(r_b, FUNC_RES_V_QID_NUM, caps->sl_num);
	udma_reg_write(r_b, FUNC_RES_B_QID_INDEX, vf_id * caps->sl_num);
	udma_reg_write(r_b, FUNC_RES_B_SCCC_BT_NUM, caps->sccc_bt_num);
	udma_reg_write(r_b, FUNC_RES_B_SCCC_BT_INDEX, vf_id * caps->sccc_bt_num);
	udma_reg_write(r_b, FUNC_RES_V_GMV_BT_NUM, caps->gmv_bt_num);
	udma_reg_write(r_b, FUNC_RES_B_GMV_BT_INDEX,
		       vf_id * caps->gmv_bt_num);

	return udma_cmq_send(udma_dev, desc, 2);
}

static int udma_alloc_vf_resource(struct udma_dev *udma_dev)
{
	uint32_t vf_id;
	int ret;

	for (vf_id = 0; vf_id < udma_dev->func_num; vf_id++) {
		ret = config_vf_hem_resource(udma_dev, vf_id);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to config vf-%u hem res, ret = %d.\n",
				vf_id, ret);
			return ret;
		}

		ret = config_vf_ext_resource(udma_dev, vf_id);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to config vf-%u ext res, ret = %d.\n",
				vf_id, ret);
			return ret;
		}
	}

	return 0;
}

static int udma_set_bt(struct udma_dev *udma_dev)
{
	struct udma_cmq_desc desc;
	struct udma_cmq_req *req = (struct udma_cmq_req *)desc.data;
	struct udma_caps *caps = &udma_dev->caps;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_BT_ATTR, false);

	udma_reg_write(req, CFG_BT_QPC_BA_PGSZ,
		       caps->qpc_ba_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_QPC_BUF_PGSZ,
		       caps->qpc_buf_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_QPC_HOPNUM,
		       to_udma_hem_hopnum(caps->qpc_hop_num, caps->num_qps));

	udma_reg_write(req, CFG_BT_SRQC_BA_PGSZ,
		       caps->srqc_ba_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_SRQC_BUF_PGSZ,
		       caps->srqc_buf_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_SRQC_HOPNUM,
		       to_udma_hem_hopnum(caps->srqc_hop_num, caps->num_srqs));

	udma_reg_write(req, CFG_BT_CQC_BA_PGSZ,
		       caps->cqc_ba_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_CQC_BUF_PGSZ,
		       caps->cqc_buf_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_CQC_HOPNUM,
		       to_udma_hem_hopnum(caps->cqc_hop_num, caps->num_cqs));

	udma_reg_write(req, CFG_BT_MPT_BA_PGSZ,
		       caps->mpt_ba_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_MPT_BUF_PGSZ,
		       caps->mpt_buf_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_MPT_HOPNUM,
		       to_udma_hem_hopnum(caps->mpt_hop_num, caps->num_mtpts));

	udma_reg_write(req, CFG_BT_SCCC_BA_PGSZ,
		       caps->sccc_ba_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_SCCC_BUF_PGSZ,
		       caps->sccc_buf_pg_sz + PG_SHIFT_OFFSET);
	udma_reg_write(req, CFG_BT_SCCC_HOPNUM,
		       to_udma_hem_hopnum(caps->sccc_hop_num, caps->num_qps));

	return udma_cmq_send(udma_dev, &desc, 1);
}

static int config_hem_entry_size(struct udma_dev *udma_dev, uint32_t type,
				 uint32_t val)
{
	struct udma_cmq_desc desc;
	struct udma_cmq_req *req = (struct udma_cmq_req *)desc.data;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_ENTRY_SIZE,
				  false);

	udma_reg_write(req, CFG_HEM_ENTRY_SIZE_TYPE, type);
	udma_reg_write(req, CFG_HEM_ENTRY_SIZE_VALUE, val);

	return udma_cmq_send(udma_dev, &desc, 1);
}

static int udma_config_entry_size(struct udma_dev *udma_dev)
{
	struct udma_caps *caps = &udma_dev->caps;
	int ret;

	ret = config_hem_entry_size(udma_dev, UDMA_CFG_QPC_SIZE,
				    caps->qpc_sz);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to cfg qpc sz, ret = %d.\n", ret);
		return ret;
	}

	ret = config_hem_entry_size(udma_dev, UDMA_CFG_SCCC_SIZE,
				    caps->scc_ctx_sz);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to cfg sccc sz, ret = %d.\n", ret);

	return ret;
}

static int udma_pf_profile(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_query_func_info(udma_dev);
	if (ret) {
		dev_err(dev, "failed to query func info, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_config_global_param(udma_dev);
	if (ret) {
		dev_err(dev, "failed to config global param, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_set_vf_switch_param(udma_dev);
	if (ret) {
		dev_err(dev, "failed to set switch param, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_query_caps(udma_dev);
	if (ret) {
		dev_err(dev, "failed to query caps, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_query_pf_resource(udma_dev);
	if (ret) {
		dev_err(dev, "failed to query pf resource, ret = %d.\n", ret);
		return ret;
	}

	apply_func_caps(udma_dev);
	ret = udma_alloc_vf_resource(udma_dev);
	if (ret) {
		dev_err(dev, "failed to alloc vf resource, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_set_bt(udma_dev);
	if (ret) {
		dev_err(dev, "failed to config BA table, ret = %d.\n", ret);
		return ret;
	}

	/* Configure the size of QPC, SCCC, etc. */
	return udma_config_entry_size(udma_dev);
}

static int udma_profile(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_cmq_query_hw_info(udma_dev);
	if (ret) {
		dev_err(dev, "failed to query hardware info, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_query_fw_ver(udma_dev);
	if (ret) {
		dev_err(dev, "failed to query firmware info, ret = %d.\n", ret);
		return ret;
	}

	return udma_pf_profile(udma_dev);
}

static int udma_alloc_cmq_desc(struct udma_dev *udma_dev,
			       struct udma_cmq_ring *ring)
{
	int size = ring->desc_num * sizeof(struct udma_cmq_desc);

	ring->desc = kzalloc(size, GFP_KERNEL);
	if (!ring->desc)
		return -ENOMEM;

	ring->desc_dma_addr = dma_map_single(udma_dev->dev, ring->desc, size,
					     DMA_BIDIRECTIONAL);
	if (dma_mapping_error(udma_dev->dev, ring->desc_dma_addr)) {
		ring->desc_dma_addr = 0;
		kfree(ring->desc);
		ring->desc = NULL;

		dev_err_ratelimited(udma_dev->dev,
				    "failed to map cmq desc addr.\n");
		return -ENOMEM;
	}

	return 0;
}

static int init_csq(struct udma_dev *udma_dev,
		    struct udma_cmq_ring *csq)
{
	dma_addr_t dma;
	int ret;

	csq->desc_num = UDMA_CMD_CSQ_DESC_NUM;
	mutex_init(&csq->lock);
	csq->flag = TYPE_CSQ;
	csq->head = 0;

	ret = udma_alloc_cmq_desc(udma_dev, csq);
	if (ret)
		return ret;

	dma = csq->desc_dma_addr;
	ub_write(udma_dev, UDMA_TX_CMQ_BASEADDR_L_REG, lower_32_bits(dma));
	ub_write(udma_dev, UDMA_TX_CMQ_BASEADDR_H_REG, upper_32_bits(dma));
	ub_write(udma_dev, UDMA_TX_CMQ_DEPTH_REG,
		 (uint32_t)csq->desc_num >> UDMA_CMQ_DESC_NUM_S);

	/* Make sure to write CI first and then PI */
	ub_write(udma_dev, UDMA_TX_CMQ_CI_REG, 0);
	ub_write(udma_dev, UDMA_TX_CMQ_PI_REG, 0);

	return 0;
}

static int udma_cmq_init(struct udma_dev *udma_dev)
{
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;
	int ret;

	priv->cmq.tx_timeout = UDMA_CMQ_TX_TIMEOUT;

	ret = init_csq(udma_dev, &priv->cmq.csq);
	if (ret)
		dev_err(udma_dev->dev, "failed to init CSQ, ret = %d.\n", ret);

	return ret;
}

static void udma_cmq_exit(struct udma_dev *udma_dev)
{
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;
	struct udma_cmq_ring *ring = (struct udma_cmq_ring *)&priv->cmq.csq;

	dma_unmap_single(udma_dev->dev, ring->desc_dma_addr,
			 ring->desc_num * sizeof(struct udma_cmq_desc),
			 DMA_BIDIRECTIONAL);

	ring->desc_dma_addr = 0;
	kfree(ring->desc);
	ring->desc = NULL;
}

static void func_clr_hw_resetting_state(struct udma_dev *udma_dev,
					struct hnae3_handle *handle)
{
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;
	int end;

	udma_dev->dis_db = true;

	dev_warn(udma_dev->dev,
		 "Func clear is pending, device in resetting state.\n");
	end = UDMA_HW_RST_TIMEOUT;
	while (end) {
		if (!ops->get_hw_reset_stat(handle)) {
			udma_dev->is_reset = true;
			dev_info(udma_dev->dev,
				 "Func clear success after reset.\n");
			return;
		}
		msleep(UDMA_HW_RST_COMPLETION_WAIT);
		end -= UDMA_HW_RST_COMPLETION_WAIT;
	}

	dev_warn(udma_dev->dev, "Func clear failed.\n");
}

static void func_clr_sw_resetting_state(struct udma_dev *udma_dev,
					struct hnae3_handle *handle)
{
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;
	uint64_t end;

	udma_dev->dis_db = true;

	dev_warn(udma_dev->dev,
		 "Func clear is pending, device in resetting state.\n");
	end = UDMA_HW_RST_TIMEOUT;
	while (end) {
		if (ops->ae_dev_reset_cnt(handle) !=
		    udma_dev->reset_cnt) {
			udma_dev->is_reset = true;
			dev_info(udma_dev->dev,
				 "Func clear success after sw reset\n");
			return;
		}
		msleep(UDMA_HW_RST_COMPLETION_WAIT);
		end -= UDMA_HW_RST_COMPLETION_WAIT;
	}

	dev_warn(udma_dev->dev,
		 "Func clear failed because of unfinished sw reset\n");
}

static void udma_func_clr_rst_proc(struct udma_dev *udma_dev, int retval,
				   int flag)
{
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;
	struct hnae3_handle *handle = priv->handle;
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;

	if (ops->ae_dev_reset_cnt(handle) != udma_dev->reset_cnt) {
		udma_dev->dis_db = true;
		udma_dev->is_reset = true;
		dev_info(udma_dev->dev, "Func clear success after reset.\n");
		return;
	}

	if (ops->get_hw_reset_stat(handle)) {
		func_clr_hw_resetting_state(udma_dev, handle);
		return;
	}

	if (ops->ae_dev_resetting(handle) &&
	    handle->udmainfo.instance_state == UDMA_STATE_INIT) {
		func_clr_sw_resetting_state(udma_dev, handle);
		return;
	}

	if (retval && !flag)
		dev_warn(udma_dev->dev,
			 "Func clear read failed, ret = %d.\n", retval);

	dev_warn(udma_dev->dev, "Func clear failed.\n");
}

static bool check_device_is_in_reset(struct udma_dev *udma_dev)
{
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;
	struct hnae3_handle *handle = priv->handle;
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;

	if (udma_dev->reset_cnt != ops->ae_dev_reset_cnt(handle))
		return true;

	if (ops->get_hw_reset_stat(handle))
		return true;

	if (ops->ae_dev_resetting(handle))
		return true;

	return false;
}

static void __udma_function_clear(struct udma_dev *udma_dev, int vf_id)
{
	bool fclr_write_fail_flag = false;
	struct udma_func_clear *resp;
	struct udma_cmq_desc desc;
	int end;
	int ret = 0;

	if (check_device_is_in_reset(udma_dev))
		goto out;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_FUNC_CLEAR, false);
	resp = (struct udma_func_clear *)desc.data;
	resp->rst_funcid_en = cpu_to_le32(vf_id);

	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		fclr_write_fail_flag = true;
		dev_err(udma_dev->dev, "Func clear write failed, ret = %d.\n",
			ret);
		goto out;
	}

	msleep(UDMA_READ_FUNC_CLEAR_FLAG_INTERVAL);
	end = UDMA_FUNC_CLEAR_TIMEOUT_MSECS;
	while (end) {
		if (check_device_is_in_reset(udma_dev))
			goto out;
		msleep(UDMA_READ_FUNC_CLEAR_FLAG_FAIL_WAIT);
		end -= UDMA_READ_FUNC_CLEAR_FLAG_FAIL_WAIT;

		udma_cmq_setup_basic_desc(&desc, UDMA_OPC_FUNC_CLEAR,
					  true);

		resp->rst_funcid_en = cpu_to_le32(vf_id);
		ret = udma_cmq_send(udma_dev, &desc, 1);
		if (ret)
			continue;

		if (udma_get_bit(resp->func_done, FUNC_CLEAR_RST_FUN_DONE_S)) {
			if (vf_id == 0)
				udma_dev->is_reset = true;
			return;
		}
	}

out:
	udma_func_clr_rst_proc(udma_dev, ret, fclr_write_fail_flag);
}

static void udma_free_vf_resource(struct udma_dev *udma_dev, int vf_id)
{
	enum udma_opcode_type opcode = UDMA_OPC_ALLOC_VF_RES;
	struct udma_cmq_desc desc[2];
	struct udma_cmq_req *req_a;

	req_a = (struct udma_cmq_req *)desc[0].data;
	udma_cmq_setup_basic_desc(&desc[0], opcode, false);
	desc[0].flag |= cpu_to_le16(UDMA_CMD_FLAG_NEXT);
	udma_cmq_setup_basic_desc(&desc[1], opcode, false);
	udma_reg_write(req_a, FUNC_RES_A_VF_ID, vf_id);
	udma_cmq_send(udma_dev, desc, 2);
}

static void udma_function_clear(struct udma_dev *udma_dev)
{
	int i;

	if (udma_dev->cmd.state == UDMA_CMDQ_STATE_FATAL_ERR)
		return;

	for (i = udma_dev->func_num - 1; i >= 0; i--) {
		__udma_function_clear(udma_dev, i);
		if (i != 0)
			udma_free_vf_resource(udma_dev, i);
	}
}

static void config_llm_table(struct udma_buf *data_buf, void *cfg_buf)
{
	uint64_t *entry = (uint64_t *)cfg_buf;
	uint32_t i, next_ptr, page_num;
	dma_addr_t addr;
	uint64_t val;

	page_num = data_buf->npages;
	for (i = 0; i < page_num; i++) {
		addr = udma_buf_page(data_buf, i);
		if (i == (page_num - 1))
			next_ptr = 0;
		else
			next_ptr = i + 1;

		val = UDMA_EXT_LLM_ENTRY(addr, (uint64_t)next_ptr);
		entry[i] = cpu_to_le64(val);
	}
}

static int set_llm_cfg_to_hw(struct udma_dev *udma_dev,
			     struct udma_link_table *table)
{
	struct udma_cmq_desc desc[2];
	struct udma_cmq_req *r_a = (struct udma_cmq_req *)desc[0].data;
	struct udma_cmq_req *r_b = (struct udma_cmq_req *)desc[1].data;
	struct udma_buf *buf = table->buf;
	enum udma_opcode_type opcode;
	dma_addr_t addr;

	opcode = UDMA_OPC_CFG_EXT_LLM;
	udma_cmq_setup_basic_desc(&desc[0], opcode, false);
	desc[0].flag |= cpu_to_le16(UDMA_CMD_FLAG_NEXT);
	udma_cmq_setup_basic_desc(&desc[1], opcode, false);

	udma_reg_write(r_a, CFG_LLM_A_BA_L, lower_32_bits(table->table.map));
	udma_reg_write(r_a, CFG_LLM_A_BA_H, upper_32_bits(table->table.map));
	udma_reg_write(r_a, CFG_LLM_A_DEPTH, buf->npages);
	udma_reg_write(r_a, CFG_LLM_A_PG_SZ,
		       to_hr_hw_page_shift(buf->page_shift));
	udma_reg_enable(r_a, CFG_LLM_A_INIT_EN);

	addr = to_hr_hw_page_addr(udma_buf_page(buf, 0));
	udma_reg_write(r_a, CFG_LLM_A_HEAD_BA_L, lower_32_bits(addr));
	udma_reg_write(r_a, CFG_LLM_A_HEAD_BA_H, upper_32_bits(addr));
	udma_reg_write(r_a, CFG_LLM_A_HEAD_NXT_PTR, 1);
	udma_reg_write(r_a, CFG_LLM_A_HEAD_PTR, 0);

	addr = to_hr_hw_page_addr(udma_buf_page(buf, buf->npages - 1));
	udma_reg_write(r_b, CFG_LLM_B_TAIL_BA_L, lower_32_bits(addr));
	udma_reg_write(r_b, CFG_LLM_B_TAIL_BA_H, upper_32_bits(addr));
	udma_reg_write(r_b, CFG_LLM_B_TAIL_PTR, buf->npages - 1);

	return udma_cmq_send(udma_dev, desc, 2);
}

static struct udma_link_table *
alloc_link_table_buf(struct udma_dev *udma_dev)
{
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;
	uint32_t pg_shift, size, min_size;
	struct udma_link_table *link_tbl;

	link_tbl = &priv->ext_llm;
	pg_shift = udma_dev->caps.llm_buf_pg_sz + PAGE_SHIFT;
	size = udma_dev->caps.num_qps * UDMA_EXT_LLM_ENTRY_SZ;
	min_size = UDMA_EXT_LLM_MIN_PAGES(udma_dev->caps.sl_num) << pg_shift;

	/* Alloc data table */
	size = max(size, min_size);
	link_tbl->buf = udma_buf_alloc(udma_dev, size, pg_shift, 0);
	if (IS_ERR(link_tbl->buf))
		return ERR_PTR(-ENOMEM);

	/* Alloc config table */
	size = link_tbl->buf->npages * sizeof(uint64_t);
	link_tbl->table.buf = dma_alloc_coherent(udma_dev->dev, size,
						 &link_tbl->table.map,
						 GFP_KERNEL);
	if (!link_tbl->table.buf) {
		udma_buf_free(udma_dev, link_tbl->buf);
		return ERR_PTR(-ENOMEM);
	}

	return link_tbl;
}

static void free_link_table_buf(struct udma_dev *udma_dev,
				struct udma_link_table *tbl)
{
	if (tbl->buf) {
		uint32_t size = tbl->buf->npages * sizeof(uint64_t);

		dma_free_coherent(udma_dev->dev, size, tbl->table.buf,
				  tbl->table.map);
	}

	udma_buf_free(udma_dev, tbl->buf);
}

static int udma_init_link_table(struct udma_dev *udma_dev)
{
	struct udma_link_table *link_tbl;
	int ret;

	link_tbl = alloc_link_table_buf(udma_dev);
	if (IS_ERR(link_tbl))
		return -ENOMEM;

	if (WARN_ON(link_tbl->buf->npages > UDMA_EXT_LLM_MAX_DEPTH)) {
		ret = -EINVAL;
		goto err_alloc;
	}

	config_llm_table(link_tbl->buf, link_tbl->table.buf);
	ret = set_llm_cfg_to_hw(udma_dev, link_tbl);
	if (ret)
		goto err_alloc;

	return 0;

err_alloc:
	free_link_table_buf(udma_dev, link_tbl);
	return ret;
}

static void udma_free_link_table(struct udma_dev *udma_dev)
{
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;

	free_link_table_buf(udma_dev, &priv->ext_llm);
}

static void free_dip_list(struct udma_dev *udma_dev)
{
	struct udma_dip *u_dip;
	struct udma_dip *tmp;
	unsigned long flags;

	spin_lock_irqsave(&udma_dev->dip_list_lock, flags);

	list_for_each_entry_safe(u_dip, tmp, &udma_dev->dip_list, node) {
		list_del(&u_dip->node);
		kfree(u_dip);
	}

	spin_unlock_irqrestore(&udma_dev->dip_list_lock, flags);
}

static int udma_get_reset_page(struct udma_dev *dev)
{
	dev->reset_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!dev->reset_page)
		return -ENOMEM;

	dev->reset_kaddr = vmap(&dev->reset_page, 1, VM_MAP, PAGE_KERNEL);
	if (!dev->reset_kaddr)
		goto err_vmap;

	return 0;

err_vmap:
	put_page(dev->reset_page);
	return -ENOMEM;
}

static void udma_put_reset_page(struct udma_dev *dev)
{
	vunmap(dev->reset_kaddr);
	dev->reset_kaddr = NULL;
	put_page(dev->reset_page);
	dev->reset_page = NULL;
}

static int udma_clear_extdb_list_info(struct udma_dev *udma_dev)
{
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CLEAR_EXTDB_LIST_INFO,
				  false);
	ret = udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to clear extended doorbell info, ret = %d.\n",
			ret);

	return ret;
}

int get_hem_table(struct udma_dev *udma_dev)
{
	uint32_t qpc_count;
	uint32_t cqc_count;
	uint32_t gmv_count;
	uint32_t i;
	int ret;

	/* Alloc memory for source address table buffer space chunk */
	for (gmv_count = 0; gmv_count < udma_dev->caps.gmv_entry_num;
	     gmv_count++) {
		ret = udma_table_get(udma_dev, &udma_dev->gmv_table, gmv_count);
		if (ret)
			goto err_gmv_failed;
	}

	/* Alloc memory for QPC Timer buffer space chunk */
	for (qpc_count = 0; qpc_count < udma_dev->caps.qpc_timer_bt_num;
	     qpc_count++) {
		ret = udma_table_get(udma_dev, &udma_dev->qpc_timer_table,
				     qpc_count);
		if (ret) {
			dev_err(udma_dev->dev, "QPC Timer get failed\n");
			goto err_qpc_timer_failed;
		}
	}

	/* Alloc memory for CQC Timer buffer space chunk */
	for (cqc_count = 0; cqc_count < udma_dev->caps.cqc_timer_bt_num;
	     cqc_count++) {
		ret = udma_table_get(udma_dev, &udma_dev->cqc_timer_table,
				     cqc_count);
		if (ret) {
			dev_err(udma_dev->dev, "CQC Timer get failed\n");
			goto err_cqc_timer_failed;
		}
	}

	return 0;

err_cqc_timer_failed:
	for (i = 0; i < cqc_count; i++)
		udma_table_put(udma_dev, &udma_dev->cqc_timer_table, i);

err_qpc_timer_failed:
	for (i = 0; i < qpc_count; i++)
		udma_table_put(udma_dev, &udma_dev->qpc_timer_table, i);

err_gmv_failed:
	for (i = 0; i < gmv_count; i++)
		udma_table_put(udma_dev, &udma_dev->gmv_table, i);

	return ret;
}

void put_hem_table(struct udma_dev *udma_dev)
{
	uint32_t i;

	for (i = 0; i < udma_dev->caps.gmv_entry_num; i++)
		udma_table_put(udma_dev, &udma_dev->gmv_table, i);


	for (i = 0; i < udma_dev->caps.qpc_timer_bt_num; i++)
		udma_table_put(udma_dev, &udma_dev->qpc_timer_table, i);

	for (i = 0; i < udma_dev->caps.cqc_timer_bt_num; i++)
		udma_table_put(udma_dev, &udma_dev->cqc_timer_table, i);
}

static int udma_hw_init(struct udma_dev *udma_dev)
{
	int ret;

	ret = udma_get_reset_page(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev,
			"get reset page failed, ret = %d.\n", ret);
		return ret;
	}

	/* UDMA requires the extdb info to be cleared before using */
	ret = udma_clear_extdb_list_info(udma_dev);
	if (ret)
		goto err_clear_extdb_failed;

	ret = get_hem_table(udma_dev);
	if (ret)
		goto err_clear_extdb_failed;

	ret = udma_init_link_table(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev, "failed to init llm, ret = %d.\n", ret);
		goto err_llm_init_failed;
	}

	return 0;

err_llm_init_failed:
	put_hem_table(udma_dev);
err_clear_extdb_failed:
	udma_put_reset_page(udma_dev);

	return ret;
}

static void udma_hw_exit(struct udma_dev *udma_dev)
{
	udma_function_clear(udma_dev);

	udma_free_link_table(udma_dev);

	put_hem_table(udma_dev);
	free_dip_list(udma_dev);
}

static int get_op_for_set_hem(uint32_t type, int step_idx, uint16_t *mbox_op,
			      bool is_create)
{
	uint16_t op;

	switch (type) {
	case HEM_TYPE_QPC:
		op = is_create ? UDMA_CMD_WRITE_QPC_BT0 :
		     UDMA_CMD_DESTROY_QPC_BT0;
		break;
	case HEM_TYPE_MTPT:
		op = is_create ? UDMA_CMD_WRITE_MPT_BT0 :
		     UDMA_CMD_DESTROY_MPT_BT0;
		break;
	case HEM_TYPE_CQC:
		op = is_create ? UDMA_CMD_WRITE_CQC_BT0 :
		     UDMA_CMD_DESTROY_CQC_BT0;
		break;
	case HEM_TYPE_SRQC:
		op = is_create ? UDMA_CMD_WRITE_SRQC_BT0 :
		     UDMA_CMD_DESTROY_SRQC_BT0;
		break;
	case HEM_TYPE_SCCC:
		op = is_create ? UDMA_CMD_WRITE_SCCC_BT0 : UDMA_CMD_RESERVED;
		break;
	case HEM_TYPE_QPC_TIMER:
		op = is_create ? UDMA_CMD_WRITE_QPC_TIMER_BT0 :
		     UDMA_CMD_RESERVED;
		break;
	case HEM_TYPE_CQC_TIMER:
		op = is_create ? UDMA_CMD_WRITE_CQC_TIMER_BT0 :
		     UDMA_CMD_RESERVED;
		break;
	case HEM_TYPE_GMV:
		op = is_create ? UDMA_CMD_RESERVED : UDMA_CMD_RESERVED;
		break;
	default:
		return -EINVAL;
	}

	if (op != UDMA_CMD_RESERVED)
		*mbox_op = op + step_idx;

	return 0;
}

static int config_gmv_ba_to_hw(struct udma_dev *udma_dev, uint64_t obj,
			       dma_addr_t base_addr)
{
	struct udma_cmq_desc desc;
	struct udma_cmq_req *req = (struct udma_cmq_req *)desc.data;
	uint32_t idx = obj / (UDMA_PAGE_SIZE / udma_dev->caps.gmv_entry_sz);
	uint64_t addr = to_hr_hw_page_addr(base_addr);

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_GMV_BT, false);

	udma_reg_write(req, CFG_GMV_BT_BA_L, lower_32_bits(addr));
	udma_reg_write(req, CFG_GMV_BT_BA_H, upper_32_bits(addr));
	udma_reg_write(req, CFG_GMV_BT_IDX, idx);
	udma_reg_write(req, CFG_GMV_BT_VF_ID, 0);

	return udma_cmq_send(udma_dev, &desc, 1);
}

static int config_hem_ba_to_hw(struct udma_dev *udma_dev, uint64_t obj,
			       uint64_t base_addr, uint16_t op)
{
	struct udma_cmd_mailbox *mbox = udma_alloc_cmd_mailbox(udma_dev);
	struct udma_cmq_desc desc;
	struct udma_mbox *mb;
	int ret;

	if (IS_ERR(mbox))
		return -ENOMEM;

	mb = (struct udma_mbox *)desc.data;
	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, base_addr, mbox->dma, obj, op);
	ret = udma_cmd_mbox(udma_dev, &desc, UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret)
		dev_err(udma_dev->dev, "[mailbox cmd] config hem ba failed.\n");

	udma_free_cmd_mailbox(udma_dev, mbox);

	return ret;
}

static int set_hem_to_hw(struct udma_dev *udma_dev, int obj,
			 dma_addr_t base_addr,
			 uint32_t hem_type, int step_idx)
{
	bool is_create = true;
	uint16_t op;
	int ret;

	if (unlikely(hem_type == HEM_TYPE_GMV))
		return config_gmv_ba_to_hw(udma_dev, obj, base_addr);

	if (unlikely(hem_type == HEM_TYPE_SCCC && step_idx))
		return 0;

	ret = get_op_for_set_hem(hem_type, step_idx, &op, is_create);
	if (ret < 0)
		return ret;

	return config_hem_ba_to_hw(udma_dev, obj, base_addr, op);
}

static int udma_set_hem(struct udma_dev *udma_dev, struct udma_hem_table *table,
			int obj, int step_idx)
{
	struct udma_hem_iter iter;
	struct udma_hem_mhop mhop;
	uint64_t mhop_obj = obj;
	uint32_t chunk_ba_num;
	struct udma_hem *hem;
	uint64_t hem_idx = 0;
	uint64_t l1_idx = 0;
	uint64_t bt_ba = 0;
	uint32_t hop_num;
	int i, j, k;
	int ret;

	if (!udma_check_whether_mhop(udma_dev, table->type))
		return 0;

	udma_calc_hem_mhop(udma_dev, table, &mhop_obj, &mhop);
	i = mhop.l0_idx;
	j = mhop.l1_idx;
	k = mhop.l2_idx;
	hop_num = mhop.hop_num;
	chunk_ba_num = mhop.bt_chunk_size / BA_BYTE_LEN;

	if (hop_num == 2) {
		hem_idx = i * chunk_ba_num * chunk_ba_num + j * chunk_ba_num +
			  k;
		l1_idx = i * chunk_ba_num + j;
	} else if (hop_num == 1) {
		hem_idx = i * chunk_ba_num + j;
	} else if (hop_num == UDMA_HOP_NUM_0) {
		hem_idx = i;
	}

	if (table->type == HEM_TYPE_SCCC)
		obj = mhop.l0_idx;

	if (check_whether_last_step(hop_num, step_idx)) {
		hem = table->hem[hem_idx];
		for (udma_hem_first(hem, &iter);
		     !udma_hem_last(&iter); udma_hem_next(&iter)) {
			bt_ba = udma_hem_addr(&iter);
			ret = set_hem_to_hw(udma_dev, obj, bt_ba, table->type,
					    step_idx);
		}
	} else {
		if (step_idx == 0)
			bt_ba = table->bt_l0_dma_addr[i];
		else if (step_idx == 1 && hop_num == 2)
			bt_ba = table->bt_l1_dma_addr[l1_idx];

		ret = set_hem_to_hw(udma_dev, obj, bt_ba, table->type,
				    step_idx);
	}

	return ret;
}

static int udma_clear_hem(struct udma_dev *udma_dev,
			  struct udma_hem_table *table,
			  int obj, int step_idx)
{
	uint16_t op = UDMA_CMD_RESERVED;
	bool is_create = false;
	int ret;

	if (!udma_check_whether_mhop(udma_dev, table->type))
		return 0;

	ret = get_op_for_set_hem(table->type, step_idx, &op, is_create);
	if (ret < 0 || op == UDMA_CMD_RESERVED)
		return ret;

	return config_hem_ba_to_hw(udma_dev, obj, 0, op);
}

static const struct udma_hw udma_hw = {
	.cmq_init = udma_cmq_init,
	.cmq_exit = udma_cmq_exit,
	.hw_profile = udma_profile,
	.hw_init = udma_hw_init,
	.hw_exit = udma_hw_exit,
	.post_mbox = udma_post_mbox,
	.poll_mbox_done = udma_poll_mbox_done,
	.chk_mbox_avail = udma_chk_mbox_is_avail,
	.set_hem = udma_set_hem,
	.clear_hem = udma_clear_hem,
	.init_eq = udma_init_eq_table,
	.cleanup_eq = udma_cleanup_eq_table,
};

bool udma_is_virtual_func(struct pci_dev *pdev)
{
	uint32_t dev_id = pdev->device;

	switch (dev_id) {
	case HNAE3_DEV_ID_UDMA_OVER_UBL:
	case HNAE3_DEV_ID_UDMA:
		return false;
	case HNAE3_DEV_ID_UDMA_OVER_UBL_VF:
		return true;
	default:
		dev_warn(&pdev->dev, "un-recognized pci deviced-id %x.\n",
			 dev_id);
	}

	return false;
}

static void udma_get_cfg(struct udma_dev *udma_dev,
			 struct hnae3_handle *handle)
{
	struct udma_priv *priv = (struct udma_priv *)udma_dev->priv;
	int i;

	udma_dev->pci_dev = handle->pdev;
	udma_dev->dev = &handle->pdev->dev;
	udma_dev->hw = &udma_hw;

	/* Get info from NIC driver. */
	udma_dev->reg_base = handle->udmainfo.udma_io_base;
	udma_dev->caps.num_ports = 1;
	udma_dev->uboe.netdevs[0] = handle->udmainfo.netdev;

	for (i = 0; i < handle->udmainfo.num_vectors; i++)
		udma_dev->irq[i] = pci_irq_vector(handle->pdev,
						  i +
						  handle->udmainfo.base_vector);

	/* cmd issue mode: 0 is poll, 1 is event */
	udma_dev->cmd_mod = 0;

	udma_dev->reset_cnt = handle->ae_algo->ops->ae_dev_reset_cnt(handle);
	priv->handle = handle;
}

static void udma_init_bank(struct udma_dev *dev)
{
	uint32_t qpn_shift;
	int i;

	dev->bank[0].min = 1;
	dev->bank[0].inuse = 1;
	dev->bank[0].next = dev->bank[0].min;

	qpn_shift = dev->caps.num_qps_shift - UDMA_DEFAULT_MAX_JETTY_X_SHIFT -
		    HNS3_UDMA_JETTY_X_PREFIX_BIT_NUM;
	for (i = 0; i < UDMA_QP_BANK_NUM; i++) {
		ida_init(&dev->bank[i].ida);
		dev->bank[i].max = (1U << qpn_shift) / UDMA_QP_BANK_NUM - 1;
	}
}

static int __udma_init_instance(struct hnae3_handle *handle)
{
	struct udma_dev *udma_dev;
	int ret;

	udma_dev = kzalloc(sizeof(*udma_dev), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(udma_dev))
		return -ENOMEM;

	udma_dev->priv = kzalloc(sizeof(struct udma_priv), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(udma_dev->priv)) {
		ret = -ENOMEM;
		goto error_failed_kzalloc;
	}

	udma_get_cfg(udma_dev, handle);

	ret = udma_hnae_client_init(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev, "UDMA Engine init failed(%d)!\n", ret);
		goto error_failed_get_cfg;
	}
	handle->priv = udma_dev;

	if (dfx_switch) {
		ret = udma_dfx_init(udma_dev);
		if (ret) {
			dev_err(udma_dev->dev,
				"UDMA dfx init failed(%d)!\n", ret);
			goto error_failed_dfx_init;
		}
	}

	ret = udma_register_cc_sysfs(udma_dev);
	if (ret) {
		dev_err(udma_dev->dev,
			"UDMA congest control init failed(%d)!\n", ret);
		if (dfx_switch)
			goto error_failed_scc_init;
		goto error_failed_dfx_init;
	}

	udma_init_bank(udma_dev);
	return 0;

error_failed_scc_init:
	udma_dfx_uninit(udma_dev);
error_failed_dfx_init:
	udma_hnae_client_exit(udma_dev);
error_failed_get_cfg:
	kfree(udma_dev->priv);
error_failed_kzalloc:
	kfree(udma_dev);

	return ret;
}

static void __udma_uninit_instance(struct hnae3_handle *handle,
				   bool reset)
{
	struct udma_dev *udma_dev = handle->priv;

	if (!udma_dev)
		return;

	udma_unregister_cc_sysfs(udma_dev);
	if (dfx_switch)
		udma_dfx_uninit(handle->priv);

	handle->priv = NULL;

	udma_hnae_client_exit(udma_dev);
	kfree(udma_dev->priv);
	kfree(udma_dev);
}

static int udma_init_instance(struct hnae3_handle *handle)
{
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;
	struct device *dev = &handle->pdev->dev;
	const struct pci_device_id *id;
	int ret;

	handle->udmainfo.instance_state = UDMA_STATE_INIT;

	id = pci_match_id(udma_hw_pci_tbl, handle->pdev);
	if (!id)
		return 0;

	ret = __udma_init_instance(handle);
	if (ret) {
		handle->udmainfo.instance_state = UDMA_STATE_NON_INIT;
		if (ret == -EOPNOTSUPP)
			return ret;

		dev_err(dev, "UDMA instance init failed! ret = %d\n", ret);
		if (ops->ae_dev_resetting(handle) ||
		    ops->get_hw_reset_stat(handle))
			goto reset_chk_err;
		else
			return ret;
	}

	handle->udmainfo.instance_state = UDMA_STATE_INITED;

	return 0;

reset_chk_err:
	dev_err(dev, "Device is being reset, please retry later.\n");

	return -EBUSY;
}

static void udma_uninit_instance(struct hnae3_handle *handle, bool reset)
{
	if (handle->udmainfo.instance_state != UDMA_STATE_INITED)
		return;

	handle->udmainfo.instance_state = UDMA_STATE_UNINIT;

	__udma_uninit_instance(handle, reset);

	handle->udmainfo.instance_state = UDMA_STATE_NON_INIT;
}

static void udma_reset_notify_user(struct udma_dev *dev)
{
	struct udma_reset_state *state;

	state = (struct udma_reset_state *)dev->reset_kaddr;

	state->reset_state = UDMA_IS_RESETTING;
	/* Ensure reset state was flushed in memory */
	wmb();
}

static int udma_reset_notify_down(struct hnae3_handle *handle)
{
	struct udma_dev *dev;

	if (handle->udmainfo.instance_state != UDMA_STATE_INITED) {
		set_bit(UDMA_RST_DIRECT_RETURN, &handle->udmainfo.state);
		return 0;
	}

	handle->udmainfo.reset_state = UDMA_STATE_RST_DOWN;
	clear_bit(UDMA_RST_DIRECT_RETURN, &handle->udmainfo.state);

	dev = handle->priv;
	if (!dev)
		return 0;

	dev->dis_db = true;

	udma_reset_notify_user(dev);

	return 0;
}

static int udma_reset_notify_init(struct hnae3_handle *handle)
{
	struct device *dev = &handle->pdev->dev;
	int ret;

	if (test_and_clear_bit(UDMA_RST_DIRECT_RETURN,
			       &handle->udmainfo.state)) {
		handle->udmainfo.reset_state = UDMA_STATE_RST_INITED;
		return 0;
	}

	handle->udmainfo.reset_state = UDMA_STATE_RST_INIT;

	dev_info(&handle->pdev->dev, "In reset process UDMA client reinit.\n");
	ret = __udma_init_instance(handle);
	if (ret) {
		/* when reset notify type is HNAE3_INIT_CLIENT In reset notify
		 * callback function, UB Engine reinitialize. If UDMA reinit
		 * failed, we should inform NIC driver.
		 */
		handle->priv = NULL;
		dev_err(dev, "In reset process UDMA reinit failed %d.\n", ret);
	} else {
		handle->udmainfo.reset_state = UDMA_STATE_RST_INITED;
		dev_info(dev, "Reset done, UDMA client reinit finished.\n");
	}

	return ret;
}

static int udma_reset_notify_uninit(struct hnae3_handle *handle)
{
	if (test_bit(UDMA_RST_DIRECT_RETURN, &handle->udmainfo.state))
		return 0;

	handle->udmainfo.reset_state = UDMA_STATE_RST_UNINIT;
	dev_info(&handle->pdev->dev, "In reset process UDMA client uninit.\n");
	msleep(UDMA_HW_RST_UNINT_DELAY);
	__udma_uninit_instance(handle, false);

	return 0;
}

static int udma_reset_notify(struct hnae3_handle *handle,
			     enum hnae3_reset_notify_type type)
{
	int ret = 0;

	switch (type) {
	case HNAE3_DOWN_CLIENT:
		ret = udma_reset_notify_down(handle);
		break;
	case HNAE3_INIT_CLIENT:
		ret = udma_reset_notify_init(handle);
		break;
	case HNAE3_UNINIT_CLIENT:
		ret = udma_reset_notify_uninit(handle);
		break;
	default:
		break;
	}

	return ret;
}

static void udma_link_status_change(struct hnae3_handle *handle, bool linkup)
{
	struct net_device *net_dev;
	struct ubcore_event event;
	struct udma_dev *dev;
	uint32_t port_id;

	dev = handle->priv;

	if (IS_ERR_OR_NULL(dev)) {
		pr_err("[hns3-udma:link_status_change]: Invalid dev!\n");
		return;
	}

	for (port_id = 0; port_id < dev->caps.num_ports; port_id++) {
		net_dev = dev->uboe.netdevs[port_id];
		if (!net_dev) {
			dev_err(dev->dev, "Find netdev %u failed!\n", port_id);
			return;
		}

		if (net_dev == handle->udmainfo.netdev)
			break;
	}

	if (port_id == dev->caps.num_ports) {
		dev_err(dev->dev, "Cannot find netdev!\n");
		return;
	}

	if (linkup)
		event.event_type = UBCORE_EVENT_PORT_ACTIVE;
	else
		event.event_type = UBCORE_EVENT_PORT_DOWN;

	event.ub_dev = &dev->ub_dev;
	event.element.port_id = port_id;
	ubcore_dispatch_async_event(&event);
}

static const struct hnae3_client_ops udma_ops = {
	.init_instance = udma_init_instance,
	.uninit_instance = udma_uninit_instance,
	.link_status_change = udma_link_status_change,
	.reset_notify = udma_reset_notify,
};

static struct hnae3_client udma_client = {
	.name = "udma",
	.type = HNAE3_CLIENT_UDMA,
	.ops = &udma_ops,
};

static int __init udma_init(void)
{
	udma_init_debugfs();
	return hnae3_register_client(&udma_client);
}

static void __exit udma_exit(void)
{
	udma_cleanup_debugfs();
	hnae3_unregister_client(&udma_client);
}

module_init(udma_init);
module_exit(udma_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("UBUS UDMA Driver");

module_param(dfx_switch, bool, 0444);
MODULE_PARM_DESC(dfx_switch, "Set whether to enable the udma_dfx function, default: 0(0:off, 1:on)");
