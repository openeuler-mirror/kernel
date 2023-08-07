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
#include "hnae3.h"
#include "hns3_udma_cmd.h"

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

	return ret;
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
	udma_dev->caps.fw_ver = (uint64_t)(le32_to_cpu(resp->fw_ver));

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
	uint32_t clock_cycles_of_1us;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_GLOBAL_PARAM,
				  false);

	clock_cycles_of_1us = UDMA_1US_CFG;

	udma_reg_write(req, CFG_GLOBAL_PARAM_1US_CYCLES, clock_cycles_of_1us);
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
	caps->gid_table_len[0] = udma_get_field(resp_c->max_gid_num_cqs,
						QUERY_PF_CAPS_C_MAX_GID_M,
						QUERY_PF_CAPS_C_MAX_GID_S);

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

	return 0;
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

	return 0;
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

	udma_dev->sys_image_guid = be64_to_cpu(udma_dev->ub_dev.attr.guid);

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

static void udma_free_cmq_desc(struct udma_dev *udma_dev,
			       struct udma_cmq_ring *ring)
{
	dma_unmap_single(udma_dev->dev, ring->desc_dma_addr,
			 ring->desc_num * sizeof(struct udma_cmq_desc),
			 DMA_BIDIRECTIONAL);

	ring->desc_dma_addr = 0;
	kfree(ring->desc);
	ring->desc = NULL;
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

	udma_free_cmq_desc(udma_dev, &priv->cmq.csq);
}

static int udma_hw_init(struct udma_dev *udma_dev)
{
	return 0;
}

static void udma_hw_exit(struct udma_dev *udma_dev)
{

}

static const struct udma_hw udma_hw = {
	.cmq_init = udma_cmq_init,
	.cmq_exit = udma_cmq_exit,
	.hw_profile = udma_profile,
	.hw_init = udma_hw_init,
	.hw_exit = udma_hw_exit,
	.post_mbox = udma_post_mbox,
	.poll_mbox_done = udma_poll_mbox_done,
};

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

	return 0;
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

	handle->priv = NULL;

	udma_hnae_client_exit(udma_dev);
	kfree(udma_dev->priv);
	kfree(udma_dev);
}

static int udma_init_instance(struct hnae3_handle *handle)
{
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
	}

	handle->udmainfo.instance_state = UDMA_STATE_INITED;

	return 0;
}

static void udma_uninit_instance(struct hnae3_handle *handle, bool reset)
{
	if (handle->udmainfo.instance_state != UDMA_STATE_INITED)
		return;

	handle->udmainfo.instance_state = UDMA_STATE_UNINIT;

	__udma_uninit_instance(handle, reset);

	handle->udmainfo.instance_state = UDMA_STATE_NON_INIT;
}

static const struct hnae3_client_ops udma_ops = {
	.init_instance = udma_init_instance,
	.uninit_instance = udma_uninit_instance,
};

static struct hnae3_client udma_client = {
	.name = "udma",
	.type = HNAE3_CLIENT_UDMA,
	.ops = &udma_ops,
};

static int __init udma_init(void)
{
	return hnae3_register_client(&udma_client);
}

static void __exit udma_exit(void)
{
	hnae3_unregister_client(&udma_client);
}

module_init(udma_init);
module_exit(udma_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("UBUS UDMA Driver");
