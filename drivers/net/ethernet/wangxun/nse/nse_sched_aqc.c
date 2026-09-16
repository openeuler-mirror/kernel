// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_lib.h"
#include "nse_sched_aqc.h"

void nse_sched_aqc_fill_node_default_sch_param(struct nse_hw *hw,
						struct nse_sch_node_param *param,
							bool is_leaf, u8 tc)
{
	param->valid_section = cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_ARB_MODE_VALID |
					   NSE_SCH_NODE_PARAM_SECTION_NODE_TYPE_VALID);

	param->arb_mode = cpu_to_le16(NSE_SCH_NODE_PARAM_ARB_MODE_WFQ);

	if (is_leaf) {
		param->node_type = cpu_to_le16(NSE_SCH_NODE_PARAM_NODE_TYPE_LEAF_TC);

		param->valid_section |= cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_TC_VAL_VALID);
		param->tc_val = cpu_to_le16((u16)tc);

		param->valid_section |= cpu_to_le16(NSE_SCH_NODE_PARAM_SECTION_PORT_ID_VALID);
		param->port_id = cpu_to_le16(hw->lan_id);
	} else {
		param->node_type = cpu_to_le16(NSE_SCH_NODE_PARAM_NODE_TYPE_PARENT);
	}
}

enum nse_status
nse_sched_aqc_rw_ctl(struct nse_hw *hw, u32 rw_flag, u32 *sch_ctl_val)
{
	struct nse_aq_desc desc;
	struct nse_aqc_qos_sch_rw_ctl cmd_buf;
	enum nse_status ret;

	memset(&cmd_buf, 0, sizeof(cmd_buf));

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS, NSE_AQ_OPC_QOS_SCH_RW_CTL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, NSE_VSI_INVAL_ID);

	cmd_buf.rw_flag = cpu_to_le32(rw_flag);
	cmd_buf.sch_ctl = cpu_to_le32(*sch_ctl_val);

	ret = nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);

	if (!ret && !rw_flag)
		*sch_ctl_val = le32_to_cpu(cmd_buf.sch_ctl);

	return ret;
}

enum nse_status
nse_sched_set_bypass(struct nse_hw *hw, bool bypass)
{
	u32 sch_ctl_val;

	if (bypass)
		sch_ctl_val = (SCH_CTL_SCH_EN_BYPASS << SCH_CTL_SCH_EN_S);
	else
		sch_ctl_val = SCH_CTL_CRL_CAL_EN_M |
					SCH_CTL_PRL_CAL_EN_M |
					(SCH_CTL_SCH_EN_ENABLE << SCH_CTL_SCH_EN_S);

	return nse_sched_aqc_rw_ctl(hw, 1, &sch_ctl_val);
}

enum nse_status
nse_sched_aqc_pf_init(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_sched_info *si = &hw->port_info->sched_info;
	struct nse_aq_desc desc;
	struct nse_aqc_qos_sch_per_pf_init cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_PER_PF_INIT);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	/* at this moment, pf->XXX_start, _size are not set yet, so have to use hw->func_caps*/
	cmd_data.lan_txq_space_start = hw->func_caps.first_lantxq;
	cmd_data.lan_txq_space_size = hw->func_caps.last_lantxq - hw->func_caps.first_lantxq + 1;

	if (hw->func_caps.rdma_qset_space_valid) {
		cmd_data.rdma_qset_space_start = hw->func_caps.first_rdma_qset;
		cmd_data.rdma_qset_space_size = hw->func_caps.last_rdma_qset -
			hw->func_caps.first_rdma_qset + 1;
	}

	cmd_data.sch_qid2lnid_tdm_space_start = cmd_data.lan_txq_space_start;
	cmd_data.sch_qid2lnid_tdm_space_size = cmd_data.lan_txq_space_size;

	cmd_data.sch_qid2lnid_tpe_space_start =
		hw->hw_conf.sched_qid2lnid_table_tdm_pe_boundary_offset +
		cmd_data.rdma_qset_space_start;
	cmd_data.sch_qid2lnid_tpe_space_size = cmd_data.rdma_qset_space_size;

	cmd_data.sch_tc_node_tnid_start = si->tc_node_tnid_start;
	cmd_data.sch_tc_node_tnid_end = si->tc_node_tnid_end;

	si->node_space_start = hw->hw_conf.sched_node_table_initial_tree_size +
		(((cmd_data.lan_txq_space_start +
		  cmd_data.rdma_qset_space_start) *
		  hw->hw_conf.sched_node_table_available_size) /
		  (hw->hw_conf.max_lan_txq_space +
		   hw->hw_conf.max_rdma_qset_space));
	si->node_space_start &= ~(0x1);

	si->node_space_size = ((cmd_data.lan_txq_space_size + cmd_data.rdma_qset_space_size) *
			       hw->hw_conf.sched_node_table_available_size) /
								(hw->hw_conf.max_lan_txq_space +
								 hw->hw_conf.max_rdma_qset_space);
	si->node_space_size &= ~(0x1);

	cmd_data.sch_node_space_start = si->node_space_start;
	cmd_data.sch_node_space_size = si->node_space_size;

	if (hw->debug_mask & NSE_DBG_SCHED) {
		dev_info(dev, "[%s] cmd dump\n", __func__);
		dev_info(dev, "\t lan_txq_space_start=%d, lan_txq_space_size=%d\n",
						cmd_data.lan_txq_space_start,
							cmd_data.lan_txq_space_size);
		dev_info(dev, "\t rdma_qset_space_start=%d, rdma_qset_space_size=%d\n",
						cmd_data.rdma_qset_space_start,
							cmd_data.rdma_qset_space_size);
		dev_info(dev, "\t sch_node_space_start=%d, sch_node_space_size=%d\n",
						cmd_data.sch_node_space_start,
							cmd_data.sch_node_space_size);
		dev_info(dev, "\t sch_tc_node_tnid_start=%d, sch_tc_node_tnid_end=%d\n",
						cmd_data.sch_tc_node_tnid_start,
							cmd_data.sch_tc_node_tnid_end);
		dev_info(dev, "\t sch_qid2lnid_tdm_space_start=%d, sch_qid2lnid_tdm_space_size=%d\n",
						cmd_data.sch_qid2lnid_tdm_space_start,
							cmd_data.sch_qid2lnid_tdm_space_size);
		dev_info(dev, "\t sch_qid2lnid_tpe_space_start=%d, sch_qid2lnid_tpe_space_size=%d\n",
						cmd_data.sch_qid2lnid_tpe_space_start,
							cmd_data.sch_qid2lnid_tpe_space_size);
	}

	/* byteorder xfrm */
	cmd_data.lan_txq_space_start = cpu_to_le32(cmd_data.lan_txq_space_start);
	cmd_data.lan_txq_space_size = cpu_to_le32(cmd_data.lan_txq_space_size);

	cmd_data.rdma_qset_space_start = cpu_to_le32(cmd_data.rdma_qset_space_start);
	cmd_data.rdma_qset_space_size = cpu_to_le32(cmd_data.rdma_qset_space_size);

	cmd_data.sch_node_space_start = cpu_to_le32(cmd_data.sch_node_space_start);
	cmd_data.sch_node_space_size = cpu_to_le32(cmd_data.sch_node_space_size);

	cmd_data.sch_tc_node_tnid_start = cpu_to_le32(cmd_data.sch_tc_node_tnid_start);
	cmd_data.sch_tc_node_tnid_end = cpu_to_le32(cmd_data.sch_tc_node_tnid_end);

	cmd_data.sch_qid2lnid_tdm_space_start = cpu_to_le32(cmd_data.sch_qid2lnid_tdm_space_start);
	cmd_data.sch_qid2lnid_tdm_space_size = cpu_to_le32(cmd_data.sch_qid2lnid_tdm_space_size);

	cmd_data.sch_qid2lnid_tpe_space_start = cpu_to_le32(cmd_data.sch_qid2lnid_tpe_space_start);
	cmd_data.sch_qid2lnid_tpe_space_size = cpu_to_le32(cmd_data.sch_qid2lnid_tpe_space_size);

	return nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);
}

static void
dump_aqc_node_param(struct nse_hw *hw, struct nse_sch_node_param *param)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "sch-param:\n");

	dev_info(dev, "\t valid_section=%X\n", le16_to_cpu(param->valid_section));
	dev_info(dev, "\t\t SECTION_ARB_MODE_VALID=%d",
		 !!(le16_to_cpu(param->valid_section) & NSE_SCH_NODE_PARAM_SECTION_ARB_MODE_VALID));
	dev_info(dev, "\t\t SECTION_SP_VAL_VALID=%d",
		 !!(le16_to_cpu(param->valid_section) & NSE_SCH_NODE_PARAM_SECTION_SP_VAL_VALID));
	dev_info(dev, "\t\t SECTION_NODE_TYPE_VALID=%d", !!(le16_to_cpu(param->valid_section) &
		 NSE_SCH_NODE_PARAM_SECTION_NODE_TYPE_VALID));
	dev_info(dev, "\t\t SECTION_PIR_VALID=%d",
		 !!(le16_to_cpu(param->valid_section) & NSE_SCH_NODE_PARAM_SECTION_PIR_VALID));
	dev_info(dev, "\t\t SECTION_CIR_VALID=%d",
		 !!(le16_to_cpu(param->valid_section) & NSE_SCH_NODE_PARAM_SECTION_CIR_VALID));
	dev_info(dev, "\t\t SECTION_TC_VAL_VALID=%d",
		 !!(le16_to_cpu(param->valid_section) & NSE_SCH_NODE_PARAM_SECTION_TC_VAL_VALID));
	dev_info(dev, "\t\t SECTION_PORT_ID_VALID=%d",
		 !!(le16_to_cpu(param->valid_section) & NSE_SCH_NODE_PARAM_SECTION_PORT_ID_VALID));

	dev_info(dev, "\t arb_mode=%d\n", le16_to_cpu(param->arb_mode));

	dev_info(dev, "\t sp_val=%d\n", le16_to_cpu(param->sp_val));

	dev_info(dev, "\t node_type=%d\n", le16_to_cpu(param->node_type));

	dev_info(dev, "\t pir=%d\n", le16_to_cpu(param->pir));
	dev_info(dev, "\t cir=%d\n", le16_to_cpu(param->cir));

	dev_info(dev, "\t tc_val=%d\n", le16_to_cpu(param->tc_val));

	dev_info(dev, "\t port_id=%d\n", le16_to_cpu(param->port_id));
}

static void
dump_aqc_add_node_one(struct nse_hw *hw, struct nse_aqc_qos_sch_add_node_one *cmd_data)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "issue aq-cmd: NSE_AQ_OPC_QOS_SCH_ADD_NODE_ONE, cmd_data:\n");

	dev_info(dev, "\t parent_tnid=%d\n", le32_to_cpu(cmd_data->parent_tnid));
	dev_info(dev, "\t parent_suid=%d\n", le32_to_cpu(cmd_data->parent_suid));
	dev_info(dev, "\t parent_logic_idx_in_su=%d\n",
		 le32_to_cpu(cmd_data->parent_logic_idx_in_su));
	dev_info(dev, "\t flags=%X\n", le32_to_cpu(cmd_data->flags));
	dev_info(dev, "\t\t ADD_NODE_ONE_FLAG_SUGGEST_CHILD_TNID=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   ADD_NODE_ONE_FLAG_SUGGEST_CHILD_TNID));
	dev_info(dev, "\t\t ADD_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   ADD_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID));
	dev_info(dev, "\t\t ADD_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   ADD_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID));
	dev_info(dev, "\t\t ADD_NODE_ONE_FLAG_LEAF=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   ADD_NODE_ONE_FLAG_LEAF));
	dev_info(dev, "\t new_child_tnid=%d\n", le32_to_cpu(cmd_data->new_child_tnid));
	dev_info(dev, "\t prev_sibling_tnid=%d\n", le32_to_cpu(cmd_data->prev_sibling_tnid));
	dev_info(dev, "\t next_sibling_tnid=%d\n", le32_to_cpu(cmd_data->next_sibling_tnid));
	dev_info(dev, "\t leaf_node_qid=%d\n", le32_to_cpu(cmd_data->leaf_node_qid));

	dump_aqc_node_param(hw, &cmd_data->sch_param);
}

enum nse_status
nse_sched_aqc_add_node_one(struct nse_hw *hw, struct nse_aqc_qos_sch_add_node_one *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_ADD_NODE_ONE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (hw->debug_mask & NSE_DBG_SCHED_AQC)
		dump_aqc_add_node_one(hw, cmd_data);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

static void
dump_aqc_del_node_one(struct nse_hw *hw, struct nse_aqc_qos_sch_del_node_one *cmd_data)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 i, cnt;

	dev_info(dev, "issue aq-cmd: NSE_AQ_OPC_QOS_SCH_DEL_NODE_ONE, cmd_data:\n");

	dev_info(dev, "\t parent_tnid=%d\n", le32_to_cpu(cmd_data->parent_tnid));
	dev_info(dev, "\t parent_suid=%d\n", le32_to_cpu(cmd_data->parent_suid));
	dev_info(dev, "\t parent_logic_idx_in_su=%d\n",
		 le32_to_cpu(cmd_data->parent_logic_idx_in_su));
	dev_info(dev, "\t flags=%X\n", le32_to_cpu(cmd_data->flags));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_DEL_CHILD_SE=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_DEL_CHILD_SE));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_SUGGEST_PREV_SIBLING_TNID));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_SUGGEST_NEXT_SIBLING_TNID));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_LEAF=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_LEAF));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_PREV_SE=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_PREV_SE));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_NEXT_SE=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_NEXT_SE));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_NEED_LOCK_PARENT_SE=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_NEED_LOCK_PARENT_SE));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_NEED_LOCK_PREV_SE=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_NEED_LOCK_PREV_SE));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_HEAD=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_HEAD));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_MIDDLE=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_MIDDLE));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_TAIL=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_DEL_CHILD_SE_POS_TAIL));
	dev_info(dev, "\t\t DEL_NODE_ONE_FLAG_SU_BECOME_EMPTY=%d\n",
						!!(le32_to_cpu(cmd_data->flags) &
						   DEL_NODE_ONE_FLAG_SU_BECOME_EMPTY));

	dev_info(dev, "\t child_tnid=%d\n", le32_to_cpu(cmd_data->child_tnid));
	dev_info(dev, "\t prev_sibling_tnid=%d\n", le32_to_cpu(cmd_data->prev_sibling_tnid));
	dev_info(dev, "\t next_sibling_tnid=%d\n", le32_to_cpu(cmd_data->next_sibling_tnid));

	dev_info(dev, "\t prev_se=%d\n", le32_to_cpu(cmd_data->prev_se));
	dev_info(dev, "\t next_se=%d\n", le32_to_cpu(cmd_data->next_se));

	dev_info(dev, "\t remain_sib_tail_child_se_cnt=%d\n",
		 le32_to_cpu(cmd_data->remain_sib_tail_child_se_cnt));
	cnt = le32_to_cpu(cmd_data->remain_sib_tail_child_se_cnt);
	for (i = 0; i < cnt; i++) {
		dev_info(dev, "\t\t se=%d, new_ptr=%d, new_idx=%d\n",
			 le32_to_cpu(cmd_data->remain_sib_tail_child_se[i]),
			 le32_to_cpu(cmd_data->remain_sib_tail_child_se_new_ptr[i]),
			 le32_to_cpu(cmd_data->remain_sib_tail_child_se_new_idx[i]));
	}

	dev_info(dev, "\t remain_leaf_sib_qid2lnid_cnt=%d\n",
		 le32_to_cpu(cmd_data->remain_leaf_sib_qid2lnid_cnt));
	cnt = le32_to_cpu(cmd_data->remain_leaf_sib_qid2lnid_cnt);
	for (i = 0; i < cnt; i++) {
		dev_info(dev, "\t\t qid2lnid=%d, new_ptr=%d, new_idx=%d\n",
			 le32_to_cpu(cmd_data->remain_leaf_sib_qid2lnid[i]),
			 le32_to_cpu(cmd_data->remain_leaf_sib_qid2lnid_new_ptr[i]),
			 le32_to_cpu(cmd_data->remain_leaf_sib_qid2lnid_new_idx[i]));
	}

	if ((le32_to_cpu(cmd_data->flags) & DEL_NODE_ONE_FLAG_LEAF)) {
		dev_info(dev, "\t leaf_qid2lnid=%d, qid=%d, qid_type=%d\n",
						le32_to_cpu(cmd_data->leaf_qid2lnid),
						le16_to_cpu(cmd_data->qid),
						le16_to_cpu(cmd_data->qid_type));
	}
}

enum nse_status
nse_sched_aqc_del_node_one(struct nse_hw *hw, struct nse_aqc_qos_sch_del_node_one *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_DEL_NODE_ONE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (hw->debug_mask & NSE_DBG_SCHED_AQC)
		dump_aqc_del_node_one(hw, cmd_data);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

static void
dump_aqc_suspend_resume_node_one(struct nse_hw *hw,
				 struct nse_aqc_qos_sch_suspend_resume_node_one *cmd_data)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "issue aq-cmd: NSE_AQ_OPC_QOS_SCH_SUSPEND_RESUME_NODE_ONE, cmd_data:\n");

	dev_info(dev, "\t suspend=%d\n", le16_to_cpu(cmd_data->suspend));
	dev_info(dev, "\t resume_state=%d\n", le16_to_cpu(cmd_data->resume_state));
	dev_info(dev, "\t tnid=%d\n", le32_to_cpu(cmd_data->tnid));
}

enum nse_status
nse_sched_aqc_suspend_resume_node_one(struct nse_hw *hw,
				      struct nse_aqc_qos_sch_suspend_resume_node_one *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_SUSPEND_RESUME_NODE_ONE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (hw->debug_mask & NSE_DBG_SCHED_AQC)
		dump_aqc_suspend_resume_node_one(hw, cmd_data);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_sched_suspend_node_one(struct nse_hw *hw, u32 tnid)
{
	struct nse_aqc_qos_sch_suspend_resume_node_one cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	cmd_data.suspend = cpu_to_le16(1);
	cmd_data.tnid = cpu_to_le32(tnid);

	return nse_sched_aqc_suspend_resume_node_one(hw, &cmd_data);
}

enum nse_status
nse_sched_resume_node_one(struct nse_hw *hw, u32 tnid)
{
	struct nse_aqc_qos_sch_suspend_resume_node_one cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	cmd_data.suspend = 0;
	cmd_data.tnid = cpu_to_le32(tnid);
	cmd_data.resume_state = cpu_to_le16(RESUME_STATE_EIR);

	return nse_sched_aqc_suspend_resume_node_one(hw, &cmd_data);
}

static void
dump_aqc_sch_set_unset_qid2lnid(struct nse_hw *hw,
				struct nse_aqc_qos_sch_set_unset_qid2lnid *cmd_data)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "issue aq-cmd: NSE_AQ_OPC_QOS_SCH_SET_UNSET_QID2LNID, cmd_data:\n");

	dev_info(dev, "\t flags=%d\n", le32_to_cpu(cmd_data->flags));
	dev_info(dev, "\t leaf_tnid=%d\n", le32_to_cpu(cmd_data->leaf_tnid));
	dev_info(dev, "\t leaf_suid=%d\n", le32_to_cpu(cmd_data->leaf_suid));
	dev_info(dev, "\t leaf_logic_idx_in_su=%d\n", le32_to_cpu(cmd_data->leaf_logic_idx_in_su));
	dev_info(dev, "\t qid=%d\n", le16_to_cpu(cmd_data->qid));
	dev_info(dev, "\t qid_type=%d\n", le16_to_cpu(cmd_data->qid_type));
}

enum nse_status
nse_sched_aqc_set_unset_qid2lnid(struct nse_hw *hw,
				 struct nse_aqc_qos_sch_set_unset_qid2lnid *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_SET_UNSET_QID2LNID);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (hw->debug_mask & NSE_DBG_SCHED_AQC)
		dump_aqc_sch_set_unset_qid2lnid(hw, cmd_data);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_sched_set_leaf_qid2lnid(struct nse_hw *hw, u16 qid, u16 qid_type,
							u16 leaf_tnid, u32 leaf_suid,
								u32 leaf_logic_idx_in_su)
{
	struct nse_aqc_qos_sch_set_unset_qid2lnid cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	cmd_data.flags = cpu_to_le32(SET_UNSET_QID2LNID_FLAG_SET);
	cmd_data.leaf_tnid = cpu_to_le32(leaf_tnid);
	cmd_data.leaf_suid = cpu_to_le32(leaf_suid);
	cmd_data.leaf_logic_idx_in_su = cpu_to_le32(leaf_logic_idx_in_su);
	cmd_data.qid = cpu_to_le16(qid);
	cmd_data.qid_type = cpu_to_le16(qid_type);
	if (qid_type == QID_TYPE_LAN_TXQ)
		cmd_data.leaf_qid2lnid =  cpu_to_le32((u32)qid);
	else
		cmd_data.leaf_qid2lnid =
			cpu_to_le32((u32)qid +
				    hw->hw_conf.sched_qid2lnid_table_tdm_pe_boundary_offset);

	return nse_sched_aqc_set_unset_qid2lnid(hw, &cmd_data);
}

enum nse_status
nse_sched_unset_leaf_qid2lnid(struct nse_hw *hw, u16 qid, u16 qid_type)
{
	struct nse_aqc_qos_sch_set_unset_qid2lnid cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	cmd_data.flags = 0;
	cmd_data.qid = cpu_to_le16(qid);
	cmd_data.qid_type = cpu_to_le16(qid_type);
	if (qid_type == QID_TYPE_LAN_TXQ)
		cmd_data.leaf_qid2lnid =  cpu_to_le32((u32)qid);
	else
		cmd_data.leaf_qid2lnid =
			cpu_to_le32((u32)qid +
				    hw->hw_conf.sched_qid2lnid_table_tdm_pe_boundary_offset);

	return nse_sched_aqc_set_unset_qid2lnid(hw, &cmd_data);
}

static void
dump_aqc_sch_get_set_node_param_one(struct nse_hw *hw,
				    struct nse_aqc_qos_sch_get_set_node_param_one *cmd_data,
							bool get_or_set)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "issue aq-cmd: NSE_AQ_OPC_QOS_SCH_GET_SET_NODE_PARAM_ONE, cmd_data:\n");

	dev_info(dev, "\t rw=%d\n", le32_to_cpu(cmd_data->rw));
	dev_info(dev, "\t tnid=%d\n", le32_to_cpu(cmd_data->tnid));

	if (!get_or_set)
		dump_aqc_node_param(hw, &cmd_data->sch_param);
}

enum nse_status
nse_sched_aqc_get_or_set_node_param_one(struct nse_hw *hw,
					struct nse_aqc_qos_sch_get_set_node_param_one *cmd_data,
							bool get_or_set)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_GET_SET_NODE_PARAM_ONE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (get_or_set)
		cmd_data->rw = cpu_to_le32(1);
	else
		cmd_data->rw = 0;

	if (hw->debug_mask & NSE_DBG_SCHED_AQC)
		dump_aqc_sch_get_set_node_param_one(hw, cmd_data, get_or_set);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_sched_aqc_rw_port_ctl(struct nse_hw *hw,
			  struct nse_aqc_qos_sch_rw_port_ctl *cmd_data,
							bool rw)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_RW_PORT_CTL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (rw)
		cmd_data->rw = cpu_to_le32(1);
	else
		cmd_data->rw = 0;

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

static void
dump_aqc_conf_cir(struct nse_hw *hw, struct nse_aqc_qos_sch_conf_cir *cmd_data)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "issue aq-cmd: NSE_AQ_OPC_QOS_SCH_CONF_CIR, cmd_data:\n");

	dev_info(dev, "\t tnid=%d\n", le32_to_cpu(cmd_data->tnid));
	dev_info(dev, "\t op=%d\n", le16_to_cpu(cmd_data->op));
	dev_info(dev, "\t cir=%d\n", le16_to_cpu(cmd_data->cir));
	dev_info(dev, "\t factor_int=%d\n", le16_to_cpu(cmd_data->factor_int));
	dev_info(dev, "\t factor_df_int=%d\n", le16_to_cpu(cmd_data->factor_df_int));
	dev_info(dev, "\t factor_df_df=%d\n", le16_to_cpu(cmd_data->factor_df_df));
}

enum nse_status
nse_sched_aqc_conf_cir(struct nse_hw *hw,
						struct nse_aqc_qos_sch_conf_cir *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS, NSE_AQ_OPC_QOS_SCH_CONF_CIR);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (hw->debug_mask & NSE_DBG_SCHED_AQC)
		dump_aqc_conf_cir(hw, cmd_data);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

static void
dump_aqc_conf_pir(struct nse_hw *hw, struct nse_aqc_qos_sch_conf_pir *cmd_data)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "issue aq-cmd: NSE_AQ_OPC_QOS_SCH_CONF_PIR, cmd_data:\n");

	dev_info(dev, "\t tnid=%d\n", le32_to_cpu(cmd_data->tnid));
	dev_info(dev, "\t op=%d\n", le16_to_cpu(cmd_data->op));
	dev_info(dev, "\t pir=%d\n", le16_to_cpu(cmd_data->pir));
	dev_info(dev, "\t factor_int=%d\n", le16_to_cpu(cmd_data->factor_int));
	dev_info(dev, "\t factor_df_int=%d\n", le16_to_cpu(cmd_data->factor_df_int));
	dev_info(dev, "\t factor_df_df=%d\n", le16_to_cpu(cmd_data->factor_df_df));
}

enum nse_status
nse_sched_aqc_conf_pir(struct nse_hw *hw,
						struct nse_aqc_qos_sch_conf_pir *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS, NSE_AQ_OPC_QOS_SCH_CONF_PIR);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	if (hw->debug_mask & NSE_DBG_SCHED_AQC)
		dump_aqc_conf_pir(hw, cmd_data);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_sched_aqc_dbg_dump_free_se_list(struct nse_hw *hw,
				    struct nse_aqc_qos_sch_dbg_dump_free_se_list *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_DBG_DUMP_FREE_SE_LIST);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

enum nse_status
nse_sched_aqc_dbg_dump_se(struct nse_hw *hw, struct nse_aqc_qos_sch_dbg_dump_se *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_DBG_DUMP_SE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

enum nse_status
nse_sched_aqc_dbg_dump_qid2lnid(struct nse_hw *hw,
				struct nse_aqc_qos_sch_dbg_dump_qid2lnid *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_SCH_DBG_DUMP_QID2LNID);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

