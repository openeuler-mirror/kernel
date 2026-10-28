// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/ethtool.h>

#include "nse_type.h"
#include "nse.h"
#include "nse_adminq_cmd.h"
#include "nse_common.h"
#include "nse_controlq.h"
#include "nse_fdir.h"
#include "nse_lib.h"
#include "nse_lan_tx_rx.h"

enum nse_status
nse_aq_fdir_force_reinit(struct nse_hw *hw)
{
	struct nse_aqc_fdir_reinit cmd_buf;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_FDIR_REINIT);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
}

enum nse_status
nse_aq_fdir_query_setting(struct nse_hw *hw, struct nse_aqc_fdir_query_setting *setting)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_QUERY_SETTING);

	nse_aqc_fill_generic_common_hdr_dft(hw, &setting->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, setting, sizeof(*setting), NULL);
}

enum nse_status
nse_aq_fdir_query_stats(struct nse_hw *hw, struct nse_aqc_fdir_query_stats *stats)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_FDIR_QUERY_STATS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &stats->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, stats, sizeof(*stats), NULL);
}

enum nse_status
nse_aq_fdir_get_vsi_space(struct nse_hw *hw, u16 vsi_abs_id, u32 *gs_size)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fdir_get_set_vsi_space cmd_buf;
	enum nse_status ret;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_VSI_SPACE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, vsi_abs_id);

	cmd_buf.get_or_set = 1;

	ret = nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
	if (!ret)
		*gs_size = le32_to_cpu(cmd_buf.vsi_space);

	return ret;
}

enum nse_status
nse_aq_fdir_set_vsi_space(struct nse_hw *hw, u16 vsi_abs_id, u32 gs_size)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fdir_get_set_vsi_space cmd_buf;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_VSI_SPACE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, vsi_abs_id);

	cmd_buf.get_or_set = 0;

	cmd_buf.vsi_space = cpu_to_le32(gs_size);

	return nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
}

enum nse_status
nse_aq_fdir_get_drop_q(struct nse_hw *hw, u32 *drp_vsi_q)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fdir_get_set_drop_q cmd_buf;
	enum nse_status ret;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_DROP_Q);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, NSE_VSI_INVAL_ID);

	cmd_buf.get_or_set = 1;

	ret = nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
	if (!ret)
		*drp_vsi_q = le32_to_cpu(cmd_buf.drp_vsi_q);

	return ret;
}

enum nse_status
nse_aq_fdir_set_drop_q(struct nse_hw *hw, u16 drp_vsi, u16 q_abs_id)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fdir_get_set_drop_q cmd_buf;
	u32 drp_vsi_q;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_DROP_Q);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, NSE_VSI_INVAL_ID);

	cmd_buf.get_or_set = 0;

	drp_vsi_q = (drp_vsi << FDIR_DRP_VSI_S) |
				(q_abs_id << FDIR_DRP_QUEUE_S);

	cmd_buf.drp_vsi_q = cpu_to_le32(drp_vsi_q);

	return nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
}

enum nse_status
nse_aq_fdir_get_vsi_input_mask(struct nse_hw *hw, u16 vsi_abs_id,
			       struct nse_aqc_fdir_get_set_vsi_input_mask *input_mask)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_VSI_INPUT_MASK);

	nse_aqc_fill_generic_common_hdr_dft(hw, &input_mask->hdr, vsi_abs_id);

	input_mask->get_or_set = 1;

	return nse_aq_send_cmd(hw, &desc, input_mask, sizeof(*input_mask), NULL);
}

enum nse_status
nse_aq_fdir_set_vsi_input_mask(struct nse_hw *hw, u16 vsi_abs_id,
			       struct nse_aqc_fdir_get_set_vsi_input_mask *input_mask)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_VSI_INPUT_MASK);

	nse_aqc_fill_generic_common_hdr_dft(hw, &input_mask->hdr, vsi_abs_id);

	input_mask->get_or_set = 0;

	return nse_aq_send_cmd(hw, &desc, input_mask, sizeof(*input_mask), NULL);
}

static enum nse_status
__nse_aq_fdir_conf_perfect_filter(struct nse_hw *hw, u8 optype,
				  struct nse_aqc_fdir_conf_perfect_filter *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_CONF_PERFECT_FILTER);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	cmd_data->optype = optype;

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_aq_fdir_add_perfect_filter(struct nse_hw *hw, struct nse_aqc_fdir_conf_perfect_filter *cmd_data)
{
	return __nse_aq_fdir_conf_perfect_filter(hw, FDIR_CONF_PERFECT_FILTER_OPTYPE_ADD, cmd_data);
}

enum nse_status
nse_aq_fdir_del_perfect_filter(struct nse_hw *hw, struct nse_aqc_fdir_conf_perfect_filter *cmd_data)
{
	return __nse_aq_fdir_conf_perfect_filter(hw, FDIR_CONF_PERFECT_FILTER_OPTYPE_DEL, cmd_data);
}

enum nse_status
nse_aq_fdir_query_perfect_filter(struct nse_hw *hw,
				 struct nse_aqc_fdir_conf_perfect_filter *cmd_data)
{
	return __nse_aq_fdir_conf_perfect_filter(hw, FDIR_CONF_PERFECT_FILTER_OPTYPE_QUERY,
						 cmd_data);
}

static enum nse_status
__nse_aq_fdir_conf_sig_filter(struct nse_hw *hw, u8 optype,
			      struct nse_aqc_fdir_conf_sig_filter *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_CONF_SIG_FILTER);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	cmd_data->optype = optype;

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_aq_fdir_add_sig_filter(struct nse_hw *hw, struct nse_aqc_fdir_conf_sig_filter *cmd_data)
{
	return __nse_aq_fdir_conf_sig_filter(hw, FDIR_CONF_SIG_FILTER_OPTYPE_ADD, cmd_data);
}

enum nse_status
nse_aq_fdir_del_sig_filter(struct nse_hw *hw, struct nse_aqc_fdir_conf_sig_filter *cmd_data)
{
	return __nse_aq_fdir_conf_sig_filter(hw, FDIR_CONF_SIG_FILTER_OPTYPE_DEL, cmd_data);
}

static enum nse_status
__nse_uq_conf_filter_by_utilq(struct nse_hw *hw,
			      struct nse_fdir_utilq_config_payload *payload)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_aq_desc desc;
	enum nse_status status = 0;

	if (!cb->utilq_initialized) {
		dev_info(dev, "utilQ not ready on this PF main VSI\n");
		status = NSE_ERR_NOT_READY;
		goto out;
	}

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_CONF_FILTER_BY_UTILQ);

	desc.mailbox_id = cpu_to_le16(NSE_AQ_MAILBOX_ID_UTILQ);

	/* always set RD and BUF flag, because always have indirect buffer  */
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_RD);
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_BUF);

	status = nse_sq_send_cmd(hw, &cb->utilq, &desc, payload, sizeof(*payload), NULL);

out:
	return status;
}

enum nse_status
nse_aq_fdir_get_vsi_qtbl(struct nse_hw *hw, u16 vsi_abs_id, u32 *val)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fdir_get_set_vsi_qtbl cmd_buf;
	enum nse_status ret;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_VSI_QTBL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, vsi_abs_id);

	cmd_buf.get_or_set = 1;

	ret = nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
	if (!ret)
		*val = le32_to_cpu(cmd_buf.entry_val);

	return ret;
}

enum nse_status
nse_aq_fdir_set_vsi_qtbl(struct nse_hw *hw, u16 vsi_abs_id, u32 val)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fdir_get_set_vsi_qtbl cmd_buf;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF,
				      NSE_AQ_OPC_FDIR_GET_SET_VSI_QTBL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, vsi_abs_id);

	cmd_buf.get_or_set = 0;

	cmd_buf.entry_val = cpu_to_le32(val);

	return nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
}

void
nse_fdir_dump_setting(struct nse_hw *hw, struct nse_aqc_fdir_query_setting *setting)
{
	struct device *dev = nse_hw_to_dev(hw);
	int i;
	u32 val;

	dev_info(dev, "====== FDIR setting (chan_id = %d)", hw->chan_id);

	dev_info(dev, "fdir_act_root_base = %08X\n", le32_to_cpu(setting->fdir_act_root_base));
	dev_info(dev, "fdir_8act_root_base = %08X\n", le32_to_cpu(setting->fdir_8act_root_base));

	val = le32_to_cpu(setting->fdir_ctl);
	dev_info(dev, "fdir_ctl = %08X\n", val);
	dev_info(dev, "\t INIT_DN: %d\n",
		 (unsigned int)((val & FDIR_CTL_INIT_DN_M) >> FDIR_CTL_INIT_DN_S));
	dev_info(dev, "\t FILTER_MODE: %d\n",
		 (unsigned int)((val & FDIR_CTL_FILTER_MODE_M) >> FDIR_CTL_FILTER_MODE_S));
	dev_info(dev, "\t HASH_BITS: %d\n", ((val & FDIR_CTL_HASH_BITS_M) >> FDIR_CTL_HASH_BITS_S));
	dev_info(dev, "\t MAX_LEN: %d\n", ((val & FDIR_CTL_MAX_LEN_M) >> FDIR_CTL_MAX_LEN_S));
	dev_info(dev, "\t FULL_THRES: %d\n",
		 ((val & FDIR_CTL_FULL_THRES_M) >> FDIR_CTL_FULL_THRES_S));
	dev_info(dev, "\t PBALLOC: %d\n", ((val & FDIR_CTL_PBALLOC_M) >> FDIR_CTL_PBALLOC_S));

	val = le32_to_cpu(setting->fdir_pf_vsi_num);
	dev_info(dev, "fdir_pf_vsi_num = %08X\n", val);

	for (i = 0; i < 4; i++) {
		val = le32_to_cpu(setting->fdir_drp_pf[i]);
		dev_info(dev, "fdir_drp_pf%d = %08X\n", i, val);
		dev_info(dev, "\t drp_vsi: %d\n", ((val & FDIR_DRP_VSI_M) >> FDIR_DRP_VSI_S));
		dev_info(dev, "\t drp_q: %d\n", ((val & FDIR_DRP_QUEUE_M) >> FDIR_DRP_QUEUE_S));
	}

	dev_info(dev, "fdir_hkey = %08X\n", le32_to_cpu(setting->fdir_hkey));
	dev_info(dev, "fdir_skey = %08X\n", le32_to_cpu(setting->fdir_skey));

	dev_info(dev, "fdir_bst_effort_space = %08X(%d)\n",
						le32_to_cpu(setting->fdir_bst_effort_space),
						le32_to_cpu(setting->fdir_bst_effort_space));

	val = le32_to_cpu(setting->hw_md_update);
	dev_info(dev, "hw_md_update = %08X\n", val);
	dev_info(dev, "\t RSS_EN: %d\n", (unsigned int)((val & HW_MD_UPDATE_RSS_EN_M) >>
		 HW_MD_UPDATE_RSS_EN_S));
	dev_info(dev, "\t FDIR_EN: %d\n", (unsigned int)((val & HW_MD_UPDATE_FDIR_EN_M) >>
		 HW_MD_UPDATE_FDIR_EN_S));
}

void
nse_fdir_dump_stats(struct nse_hw *hw, struct nse_aqc_fdir_query_stats *stats)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 val;

	dev_info(dev, "====== FDIR stats (chan_id = %d)", hw->chan_id);

	dev_info(dev, "fdir_bst_effort_free = %08X(%d)\n", le32_to_cpu(stats->fdir_bst_effort_free),
		 le32_to_cpu(stats->fdir_bst_effort_free));
	dev_info(dev, "fdir_free = %08X(%d)\n", le32_to_cpu(stats->fdir_free),
		 le32_to_cpu(stats->fdir_free));

	val = le32_to_cpu(stats->fdir_len);
	dev_info(dev, "fdir_len = %08X\n", val);
	dev_info(dev, "\t MAX_LEN = %d\n", ((val & FDIR_LEN_MAX_LEN_M) >> FDIR_LEN_MAX_LEN_S));
	dev_info(dev, "\t BUCKET_LEN = %d\n",
		 ((val & FDIR_LEN_BUCKET_LEN_M) >> FDIR_LEN_BUCKET_LEN_S));

	val = le32_to_cpu(stats->fdir_use_st);
	dev_info(dev, "fdir_use_st = %08X\n", val);
	dev_info(dev, "\t ADD = %d\n", ((val & FDIR_USE_ST_ADD_M) >> FDIR_USE_ST_ADD_S));
	dev_info(dev, "\t REM = %d\n", ((val & FDIR_USE_ST_REM_M) >> FDIR_USE_ST_REM_S));

	val = le32_to_cpu(stats->fdir_fail_st);
	dev_info(dev, "fdir_fail_st = %08X\n", val);
	dev_info(dev, "\t ADD = %d\n", ((val & FDIR_FAIL_ST_ADD_M) >> FDIR_FAIL_ST_ADD_S));
	dev_info(dev, "\t REM = %d\n", ((val & FDIR_FAIL_ST_REM_M) >> FDIR_FAIL_ST_REM_S));

	dev_info(dev, "fdir_match = %08X(%d)\n", le32_to_cpu(stats->fdir_match),
		 le32_to_cpu(stats->fdir_match));
	dev_info(dev, "fdir_miss = %08X(%d)\n", le32_to_cpu(stats->fdir_miss),
		 le32_to_cpu(stats->fdir_miss));
}

void nse_fdir_dump_cb(struct nse_hw *hw)
{
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct device *dev = nse_hw_to_dev(hw);
	int i = 0;

	dev_info(dev, "====== FDir CB content:\n");

	dev_info(dev, "filter_count=%d\n", cb->filter_count);

	dev_info(dev, "vsi_hw_input_mask_info:\n");
	dev_info(dev, "\t valid_reg_flex_cfg=%d\n", cb->vsi_hw_input_mask_info.valid_reg_flex_cfg);
	for (i = 0; i < 7; i++) {
		dev_info(dev, "\t valid_reg_mask[%d]=%d\n", i,
			 cb->vsi_hw_input_mask_info.valid_reg_mask[i]);
	}

	dev_info(dev, "\t hw_input_mask:\n");
	dev_info(dev, "\t\t flex_cfg=0x%X\n",
		 le32_to_cpu(cb->vsi_hw_input_mask_info.hw_input_mask.flex_cfg));
	for (i = 0; i < 7; i++) {
		dev_info(dev, "\t\t mask[%d]=0x%X\n", i,
			 le32_to_cpu(cb->vsi_hw_input_mask_info.hw_input_mask.mask[i]));
	}

	dev_info(dev, "flex_setting:\n");
	dev_info(dev, "\t flex_fltr=%d\n", cb->flex_setting.flex_fltr);
	dev_info(dev, "\t flex_base=%d\n", cb->flex_setting.flex_base);
	dev_info(dev, "\t flex_offset=%d\n", cb->flex_setting.flex_offset);
	dev_info(dev, "\t flex_word=%d\n", cb->flex_setting.flex_word);

	dev_info(dev, "utilq_initialized=%d\n", cb->utilq_initialized);
	if (cb->utilq_initialized) {
		dev_info(dev, "utilq:\n");
		dev_info(dev, "\t qtype=%d\n", cb->utilq.qtype);
		dev_info(dev, "\t num_sq_entries=%d\n", cb->utilq.num_sq_entries);
		dev_info(dev, "\t sq_buf_size=%d\n", cb->utilq.sq_buf_size);
		dev_info(dev, "\t sq_last_status=%d\n", cb->utilq.sq_last_status);

		dev_info(dev, "\t sq:\n");
		dev_info(dev, "\t\t next_to_use=%d\n", cb->utilq.sq.next_to_use);
		dev_info(dev, "\t\t next_to_clean=%d\n", cb->utilq.sq.next_to_clean);
		dev_info(dev, "\t\t bah(addr=%X)=%X\n",
			 cb->utilq.sq.bah, rd32(hw, cb->utilq.sq.bah));
		dev_info(dev, "\t\t bal(addr=%X)=%X\n",
			 cb->utilq.sq.bal, rd32(hw, cb->utilq.sq.bal));
		dev_info(dev, "\t\t len(addr=%X)=%X\n",
			 cb->utilq.sq.len, rd32(hw, cb->utilq.sq.len));
		dev_info(dev, "\t\t head(addr=%X)=%X\n",
			 cb->utilq.sq.head, rd32(hw, cb->utilq.sq.head));
		dev_info(dev, "\t\t tail(addr=%X)=%X\n",
			 cb->utilq.sq.tail, rd32(hw, cb->utilq.sq.tail));
	}

	dev_info(dev, "drp_rxq_rel_id=%d\n", cb->drp_rxq_rel_id);
	dev_info(dev, "drp_txq_rel_id=%d\n", cb->drp_txq_rel_id);

	dev_info(dev, "mode=%d\n", cb->mode);

	dev_info(dev, "max_num_pfilter=%d\n", cb->max_num_pfilter);
	dev_info(dev, "max_num_sfilter=%d\n", cb->max_num_sfilter);
	dev_info(dev, "max_num_pfilter_pf_vsi=%d\n", cb->max_num_pfilter_pf_vsi);
	dev_info(dev, "max_num_sfilter_pf_vsi=%d\n", cb->max_num_sfilter_pf_vsi);
	dev_info(dev, "max_num_pfilter_vfs=%d\n", cb->max_num_pfilter_vfs);
	dev_info(dev, "max_num_sfilter_vfs=%d\n", cb->max_num_sfilter_vfs);
}

void nse_fdir_dump_filter(struct nse_hw *hw, struct nse_fdir_filter *f, bool verbose)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "--- filter: sw_idx=%d\n", f->sw_idx);

	dev_info(dev, "bkt_hash=%04X, sig_hash=%04X", f->bkt_hash, f->sig_hash);

	if (verbose) {
		dev_info(dev, "is_action_drop=%d\n", f->is_action_drop);
		dev_info(dev, "action_rxq_abs_id=%d\n", f->action_rxq_abs_id);
	}
}

void
nse_fdir_process_reinit_event(struct nse_hw *hw, struct nse_rq_event_info *event)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_fdir_reinit_event *reinit_evt =
		(struct nse_aqc_fdir_reinit_event *)event->msg_buf;

	dev_info(dev, "[%s, %d]: receive a FDIR_REINIT_EVENT (chan_id=%d), hw->chan_id=%d\n",
			__func__, __LINE__,
			reinit_evt->hdr.chan_id, hw->chan_id);
}

static int nse_fdir_alloc_drp_q(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	int ret = 0;

	mutex_lock(&pf->lan_rxq_tracker_mutex);
	mutex_lock(&pf->lan_txq_tracker_mutex);

	cb->drp_rxq_rel_id = NSE_INVAL_Q_ID;
	cb->drp_txq_rel_id = NSE_INVAL_Q_ID;

	/* signature mode does not support DROP. */
	if (cb->mode == FDIR_CTL_FILTER_MODE_SIGNATURE)
		goto out;

	ret = nse_get_res_backward(pf, pf->lan_rxq_tracker, 1, NSE_RES_LAN_RXQ_ID_FDIR_DROP_Q);
	if (ret < 0)
		goto fail;

	cb->drp_rxq_rel_id = ret;

	ret = nse_get_res_backward(pf, pf->lan_txq_tracker, 1, NSE_RES_LAN_TXQ_ID_FDIR_DROP_Q);
	if (ret < 0)
		goto fail;

	cb->drp_txq_rel_id = ret;

	ret = 0;

out:
	mutex_unlock(&pf->lan_txq_tracker_mutex);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);

	return ret;

fail:
	ret = -ENOSPC;

	if (cb->drp_rxq_rel_id != NSE_INVAL_Q_ID)
		(void)nse_free_res(pf->lan_rxq_tracker, cb->drp_rxq_rel_id,
				   NSE_RES_LAN_RXQ_ID_FDIR_DROP_Q);

	if (cb->drp_txq_rel_id != NSE_INVAL_Q_ID)
		(void)nse_free_res(pf->lan_txq_tracker, cb->drp_txq_rel_id,
				   NSE_RES_LAN_TXQ_ID_FDIR_DROP_Q);

	cb->drp_rxq_rel_id = NSE_INVAL_Q_ID;
	cb->drp_txq_rel_id = NSE_INVAL_Q_ID;

	goto out;
}

static void nse_fdir_dealloc_drp_q(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;

	mutex_lock(&pf->lan_rxq_tracker_mutex);
	mutex_lock(&pf->lan_txq_tracker_mutex);

	if (cb->drp_rxq_rel_id != NSE_INVAL_Q_ID)
		(void)nse_free_res(pf->lan_rxq_tracker, cb->drp_rxq_rel_id,
				   NSE_RES_LAN_RXQ_ID_FDIR_DROP_Q);

	if (cb->drp_txq_rel_id != NSE_INVAL_Q_ID)
		(void)nse_free_res(pf->lan_txq_tracker, cb->drp_txq_rel_id,
				   NSE_RES_LAN_TXQ_ID_FDIR_DROP_Q);

	mutex_unlock(&pf->lan_txq_tracker_mutex);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);

	cb->drp_rxq_rel_id = NSE_INVAL_Q_ID;
	cb->drp_txq_rel_id = NSE_INVAL_Q_ID;
}

int nse_fdir_init_pre(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct device *dev = nse_pf_to_dev(pf);
	u32 ctl;
	enum nse_status status;

	if (!pf->sw_conf.fdir_ena)	/* also stands for !NSE_HW_STATIC_FEA_RCF_HAVE_FDIR */
		return 0;

	memset(cb, 0, sizeof(*cb));

	cb->hw = hw;

	mutex_init(&cb->lock);
	INIT_HLIST_HEAD(&cb->filter_list);

	status = nse_aq_fdir_query_setting(hw, &cb->setting);
	if (status) {
		dev_info(dev, "WARN: aq_fdir_query_setting\n");
		goto fail;
	}

	ctl = le32_to_cpu(cb->setting.fdir_ctl);

	if (!(ctl & FDIR_CTL_INIT_DN_M) ||
		!(ctl & FDIR_CTL_PBALLOC_M)) {
		dev_info(dev, "WARN: fdir not initialized at HW-level\n");
		goto fail;
	}

	cb->mode = (ctl & FDIR_CTL_FILTER_MODE_M) >> FDIR_CTL_FILTER_MODE_S;

	if (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT) {
		if (hw->is_only_lan_in_chan)
			cb->max_num_pfilter = hw->hw_conf.fdir_max_num_pfilter;
		else
			cb->max_num_pfilter = hw->hw_conf.fdir_max_num_pfilter / 2;
	} else if (cb->mode == FDIR_CTL_FILTER_MODE_SIGNATURE) {
		if (hw->is_only_lan_in_chan)
			cb->max_num_sfilter = hw->hw_conf.fdir_max_num_sfilter;
		else
			cb->max_num_sfilter = hw->hw_conf.fdir_max_num_sfilter / 2;
	}

	if (test_bit(NSE_FLAG_SRIOV_CAPABLE, pf->flags) && pf->sw_conf.fdir_ena_for_vf) {
		cb->max_num_pfilter_pf_vsi = cb->max_num_pfilter / 2;
		cb->max_num_sfilter_pf_vsi = cb->max_num_sfilter / 2;
		cb->max_num_pfilter_vfs = cb->max_num_pfilter / 2;
		cb->max_num_sfilter_vfs = cb->max_num_sfilter / 2;
	} else {
		cb->max_num_pfilter_pf_vsi = cb->max_num_pfilter;
		cb->max_num_sfilter_pf_vsi = cb->max_num_sfilter;
	}

	return 0;

fail:
	return -EIO;
}

/* should be after nse_init_lanq_scheme() because need alloc dropQ from res_tracker */
int nse_fdir_init_post(struct nse_pf *pf)
{
	int ret;

	if (!pf->sw_conf.fdir_ena)
		return 0;

	ret = nse_fdir_alloc_drp_q(pf);
	if (ret)
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: fdir_alloc_drp_q(), ret=%d\n",
			__func__, ret);

	return ret;
}

/* main-VSI filter flush is in nse_fdir_main_vsi_deinit() */
void nse_fdir_deinit(struct nse_pf *pf)
{
	if (!pf->sw_conf.fdir_ena)
		return;

	nse_fdir_dealloc_drp_q(pf);
}

enum nse_status nse_fdir_setup_drp_queue_ctx(struct nse_hw *hw,
					     struct nse_vsi *main_vsi, u16 q_abs_id)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lan_rxq_ctx *ctx = NULL;
	struct nse_lan_rxq_ctx_amber *ctx_amber = NULL;	//ugly
	enum nse_status ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		ret = NSE_ERR_NO_MEMORY;
		dev_err(dev, "[%s]: fail to alloc mem\n", __func__);
		goto out;
	}

	ctx->ctx_data_len = NSE_LAN_RXQ_CTX_LEN_IN_DWORD_AMBER;

	ctx_amber = &ctx->amber;

	ctx_amber->data[2] |= (((NSE_RXBUF_2048 >> AMBER_LAN_RXQ_CTX_DBUFF_SHIFT) <<
			       AMBER_LAN_RXQ_CTX_DBUFF_S)
							& AMBER_LAN_RXQ_CTX_DBUFF_M);

	ctx_amber->data[3] |= (AMBER_LAN_RXQ_CTX_DTYPE_SINGLE_BUF_DESC <<
			       AMBER_LAN_RXQ_CTX_DTYPE_S);
	ctx_amber->data[3] |= (AMBER_LAN_RXQ_CTX_DSIZE_32B << AMBER_LAN_RXQ_CTX_DSIZE_S);
	ctx_amber->data[3] |= (((u32)hw->pcore_pf_id <<
			       AMBER_LAN_RXQ_CTX_PF_NUM_S) & AMBER_LAN_RXQ_CTX_PF_NUM_M);
	ctx_amber->data[3] |= (AMBER_LAN_RXQ_CTX_DROP_CTRL_ALLOW_DROP <<
			       AMBER_LAN_RXQ_CTX_DROP_CTRL_S);
	ctx_amber->data[3] |= (AMBER_LAN_RXQ_CTX_QTYPE_NATIVE << AMBER_LAN_RXQ_CTX_QTYPE_S);

	ctx_amber->data[4] = (NSE_RXDID_FLEX_BLANK <<
			      AMBER_LAN_RXQ_CTX_RXDID_S) & AMBER_LAN_RXQ_CTX_RXDID_M;
	ctx_amber->data[4] |= (((u32)main_vsi->vsi_abs_num <<
			       AMBER_LAN_RXQ_CTX_VSI_S) & AMBER_LAN_RXQ_CTX_VSI_M);

	ret = nse_write_rxq_ctx(hw, main_vsi, ctx, q_abs_id);
	if (ret) {
		dev_err(dev, "[%s]: fail to write drp_q ctx\n", __func__);
		goto out;
	}

out:
	kfree(ctx);

	return ret;
}

void nse_fdir_main_vsi_init(struct nse_hw *hw, struct nse_vsi *main_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status = 0;

	if (!pf->sw_conf.fdir_ena)
		return;

	main_vsi->sw_conf.fdir_max_num_pfilter_vsi = cb->max_num_pfilter_pf_vsi;
	main_vsi->sw_conf.fdir_max_num_sfilter_vsi = cb->max_num_sfilter_pf_vsi;

	if (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT) {
		status = nse_aq_fdir_set_vsi_space(hw, main_vsi->vsi_abs_num,
						   main_vsi->sw_conf.fdir_max_num_pfilter_vsi);
		if (status) {
			dev_info(dev, "%s: fdir_set_vsi_space(vsi=%d, space=%d) fails: status=%d(%s)\n",
							__func__,
				 main_vsi->vsi_abs_num, main_vsi->sw_conf.fdir_max_num_pfilter_vsi,
							status, nse_stat_str(status));
			goto fail;
		}

		status = nse_aq_fdir_set_drop_q(hw, main_vsi->vsi_abs_num,
						cb->drp_rxq_rel_id + pf->lan_rxq_space_start);
		if (status) {
			dev_info(dev, "%s: fdir_set_drop_q(vsi=%d, dropq_rel_id=%d) fails: status=%d(%s)\n",
							__func__,
							main_vsi->vsi_abs_num, cb->drp_rxq_rel_id,
							status, nse_stat_str(status));
			goto fail;
		}

		status = nse_fdir_setup_drp_queue_ctx(hw, main_vsi, cb->drp_rxq_rel_id +
						      pf->lan_rxq_space_start);
		if (status) {
			dev_info(dev, "%s: fdir_setup_drp_queue_ctx(vsi=%d, dropq_rel_id=%d) fails: status=%d(%s)\n",
							__func__,
							main_vsi->vsi_abs_num, cb->drp_rxq_rel_id,
							status, nse_stat_str(status));
			goto fail;
		}
	} else {
		u32 qtbl_entry = 0;

		qtbl_entry = (((u32)(main_vsi->vsi_rxq_space_start + pf->lan_rxq_space_start))
							<< FDIR_VSI_QTBL_ENTRY_MIN_Q_S) |
					(((u32)(main_vsi->vsi_rxq_space_start +
					 pf->lan_rxq_space_start + main_vsi->alloc_rxq - 1))
							<< FDIR_VSI_QTBL_ENTRY_MAX_Q_S);

		status = nse_aq_fdir_set_vsi_qtbl(hw, main_vsi->vsi_abs_num, qtbl_entry);
		if (status) {
			dev_info(dev, "%s: fdir_set_vsi_qtbl(vsi=%d, entry=%X) fails: status=%d(%s)\n",
							__func__,
							main_vsi->vsi_abs_num, qtbl_entry,
							status, nse_stat_str(status));
			goto fail;
		}
	}

	if (pf->sw_conf.fdir_use_utilq) {
		status = nse_fdir_init_utilq(hw);
		if (status) {
			dev_info(dev, "%s: fdir utilq init fails: status=%d(%s)\n",
							__func__, status, nse_stat_str(status));
			goto fail;
		}
	}

	main_vsi->sw_conf.fdir_ena = 1;
	main_vsi->sw_conf.fdir_use_utilq = pf->sw_conf.fdir_use_utilq;

	return;

fail:
	main_vsi->sw_conf.fdir_ena = 0;
	main_vsi->sw_conf.fdir_max_num_pfilter_vsi = 0;
	main_vsi->sw_conf.fdir_max_num_sfilter_vsi = 0;
}

void nse_fdir_main_vsi_deinit(struct nse_hw *hw, struct nse_vsi *main_vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;

	if (!pf->sw_conf.fdir_ena || !main_vsi->sw_conf.fdir_ena)
		return;

	nse_del_ethool_ntuple_all(hw);

	if (main_vsi->sw_conf.fdir_use_utilq)
		nse_fdir_shutdown_utilq(hw);
}

void nse_fdir_vf_vsi_init(struct nse_hw *hw, struct nse_vsi *vf_vsi, struct nse_vf *vf)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct device *dev = nse_pf_to_dev(pf);
	u32 num_vfs_with_fdir;
	enum nse_status status = 0;

	if (!pf->sw_conf.fdir_ena || !pf->sw_conf.fdir_ena_for_vf)
		goto fail_out;

	num_vfs_with_fdir = cb->max_num_pfilter_vfs / NSE_FDIR_MAX_NUM_PFILTER_VF_VSI;
	if (vf->vf_id >= num_vfs_with_fdir) {
		nse_debug(hw, NSE_DBG_RCF, "[%s] VF-%d (vsi=%d) don't support VF-FDir due to VF-ID too big\n",
					__func__, vf->vf_id, vf_vsi->vsi_abs_num);
		goto fail_out;
	}

	vf_vsi->sw_conf.fdir_max_num_pfilter_vsi = NSE_FDIR_MAX_NUM_PFILTER_VF_VSI;
	vf_vsi->sw_conf.fdir_max_num_sfilter_vsi = NSE_FDIR_MAX_NUM_SFILTER_VF_VSI;

	if (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT) {
		status = nse_aq_fdir_set_vsi_space(hw, vf_vsi->vsi_abs_num,
						   vf_vsi->sw_conf.fdir_max_num_pfilter_vsi);
		if (status) {
			dev_info(dev, "%s: fdir_set_vsi_space(vsi=%d, space=%d) fails: status=%d(%s)\n",
							__func__,
				 vf_vsi->vsi_abs_num, vf_vsi->sw_conf.fdir_max_num_pfilter_vsi,
							status, nse_stat_str(status));
			goto fail_out;
		}

		(void)nse_fdir_flush_vsi_perfect_filter(hw, vf_vsi);
	} else {
		u32 qtbl_entry = 0;

		qtbl_entry = (((u32)(vf_vsi->vsi_rxq_space_start + pf->lan_rxq_space_start))
							<< FDIR_VSI_QTBL_ENTRY_MIN_Q_S) |
					(((u32)(vf_vsi->vsi_rxq_space_start +
					 pf->lan_rxq_space_start + vf_vsi->alloc_rxq - 1))
							<< FDIR_VSI_QTBL_ENTRY_MAX_Q_S);

		status = nse_aq_fdir_set_vsi_qtbl(hw, vf_vsi->vsi_abs_num, qtbl_entry);
		if (status) {
			dev_info(dev, "%s: fdir_set_vsi_qtbl(vsi=%d, entry=%X) fails: status=%d(%s)\n",
							__func__,
							vf_vsi->vsi_abs_num, qtbl_entry,
							status, nse_stat_str(status));
			goto fail_out;
		}
	}

	vf_vsi->sw_conf.fdir_ena = 1;
	vf_vsi->sw_conf.fdir_use_utilq = 1;		/* VF always use utilQ */

	nse_debug(hw, NSE_DBG_RCF, "[%s] VF-%d (vsi=%d) would have VF-FDir feature\n",
		  __func__, vf->vf_id, vf_vsi->vsi_abs_num);

	return;

fail_out:
	vf_vsi->sw_conf.fdir_ena = 0;
	vf_vsi->sw_conf.fdir_max_num_pfilter_vsi = 0;
	vf_vsi->sw_conf.fdir_max_num_sfilter_vsi = 0;

	nse_debug(hw, NSE_DBG_RCF, "[%s] VF-%d (vsi=%d) would NOT have VF-FDir feature\n",
		  __func__, vf->vf_id, vf_vsi->vsi_abs_num);
}

/* get a u64 bits part from Ext_S[366], specified by index
 */
static u64 get_u64_from_ext_s(struct nse_fdir_input_stream *stream, unsigned int bit_idx)
{
	u64 ret = 0;
	u64 orig_val_u64 = 0;
	u16 orig_val_u16 = 0;
	unsigned int u64_idx = 0;
	unsigned int shift = 0;

	/* Ext_S[n] - S[14:0] | S[335:0] | S[335:321] // concatenated
	 */
	if (bit_idx >= 0 && bit_idx <= 14) {
		/* part of LSB bits in S[335:321] part
		 *
		 * part of MSB bits in S[335:0] part
		 */

		/* locate bits in S[335:321] --- which is in last 2 bytes of 42 bytes stream.
		 *
		 * save this 15 bits in u16, and do a shift.
		 */

		orig_val_u16 = *((u16 *)stream + 20);	/* This is S[335:320] 16 bits */

		orig_val_u16 >>= 1;			/* get S[335:321] 15 bits */

		ret = ((u64)orig_val_u16 >> bit_idx);	/* shift */

		/*  locate remain bits in S[335:0] --- these remain bits are in 1st u64 of 42 bytes
		 * stream
		 *
		 * save first u64 in u64, and do a shift to get remain bits.
		 */
		orig_val_u64 = *((u64 *)stream);

		orig_val_u64 <<= (15 - bit_idx);

		/* concat 2 bits together */
		ret |= orig_val_u64;

	} else if (bit_idx >= 15 && bit_idx <= 287) {
		/* a FULL 64 bits in S[335:0] part, and fully in this part
		 *
		 * Note, *** fully in this part ***
		 *
		 *	287 = Ext_S 366 bits - S[14:0] 15 bits - 64 bits
		 */

		u64_idx = (bit_idx - 15) / 64;

		shift = (bit_idx - 15) % 64;

		orig_val_u64 = *((u64 *)stream + u64_idx);

		if (!shift) {
			/* happen in a 64 bit boundary, lucky */
			ret = orig_val_u64;
		} else {
			/* get LSB bits */
			ret = (orig_val_u64 >> shift);

			/* get MSB bits in next u64 */
			u64_idx++;

			orig_val_u64 = *((u64 *)stream + u64_idx);

			/* concat LSB + MSB bits */
			ret |= (orig_val_u64 << (64 - shift));
		}

	} else if (bit_idx >= 288 && bit_idx < 351) {
		u64_idx = (bit_idx - 15) / 64;

		shift = (bit_idx - 15) % 64;

		if (u64_idx < (sizeof(struct nse_fdir_input_stream) / 8)) {
			/* LSB bits starts in (u64 *)stream[4]
			 */

			/* get LSB bits in: (u64 *)stream[4] */

			orig_val_u64 = *((u64 *)stream + u64_idx);

			ret = (orig_val_u64 >> shift);

			/* the whole remain 2 bytes of stream are LSB bits */

			orig_val_u16 = *((u16 *)stream + 20);

			ret |= ((u64)orig_val_u16 << (64 - shift));

			/* determine the shift of MSB bits */
			shift = (64 - shift + 16);

		} else {
			/* LSB bits starts in (u64 *)stream[5]
			 */

			orig_val_u16 = *((u16 *)stream + 20);

			ret = ((u64)orig_val_u16 >> shift);

			/* determine the shift of MSB bits */
			shift = (64 - shift);
		}

		/* MSB bits in S[14:0] */
		/* definitely some bits in (u64 *)stream[5] */

		orig_val_u16 = *((u16 *)stream);	/* This is S[15:0] */

		orig_val_u16 &= ~BIT(15);			/* get S[14:0] */

		ret |= ((u64)orig_val_u16 << shift);

	} else if (bit_idx >= 351 && bit_idx < 366) {
	/* Whole 64 bits in S[14:0] part
	 */

		orig_val_u16 = *((u16 *)stream);	/* This is S[15:0] */

		orig_val_u16 &= ~BIT(15);			/* get S[14:0] */

		shift = bit_idx - 351;

		ret = ((u64)orig_val_u16 >> shift);
	}

	return ret;
}

void nse_fdir_compute_hash(struct nse_fdir_input_stream *stream, u32 key, u16 *hash_p)
{
	unsigned int i, k_bit_idx, j;
	u64 ext_s_part = 0;
	u64 hash = 0;

	/* Tmp_K[11*32 - 1 : 0] is:	32 x 11 = 352 bits
	 *
	 * Ext_K[350 : 0] is Tmp_K[351 : 0]
	 */

	/* First, loop for:
	 *
	 *		Ext_K [30 : 0] 31 bits   which is   Tmp_K [31 : 1]
	 *
	 *
	 * That is:
	 *
	 *		for [i = 0 to 30] portion in datasheet loop: for [i = 0 to 350]
	 */
	ext_s_part = get_u64_from_ext_s(stream, 0);	/* u64 is enough to cover */

	for (k_bit_idx = 1, i = 0;
			k_bit_idx <= 31;
			k_bit_idx++, i++) {
		if (key & BIT(k_bit_idx))
			hash ^= (ext_s_part >> i);
	}

	/* previous, i = [30 : 0] 31 bits was already handled, remain:
	 *
	 *		i = [31, 350] = 320 bits
	 *
	 *		each 32 bits correspond to a full K [31 : 0]
	 *
	 *		j is for this 10 loops
	 */
	for (j = 0; j < 10; j++) {
		/* each loop handle 32 bits, we prefetch 64 bits should be OK. */

		ext_s_part = get_u64_from_ext_s(stream, i);

		for (k_bit_idx = 0;
				k_bit_idx < 32;
				k_bit_idx++, i++) {
			if (key & BIT(k_bit_idx))
				hash ^= (ext_s_part >> k_bit_idx);
		}
	}

	/* keep lowest 16 bits of u64 hash.
	 *
	 * this works on Little-Endian Machine.
	 *
	 * On Big-Endian Machine, this need change.
	 */
	*hash_p = (u16)hash;
}

u16 nse_fdir_compute_bkt_hash(struct nse_hw *hw,
					struct nse_fdir_input_stream *stream,
					struct nse_fdir_input_stream *mask)
{
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	u16 hash;
	int i = 0;

	/* apply mask */
	stream->flex_bytes &= mask->flex_bytes;
	stream->dst_port &= mask->dst_port;
	stream->src_port &= mask->src_port;
	for (i = 0; i < 4; i++) {
		stream->dst_ip[i] &= mask->dst_ip[i];
		stream->src_ip[i] &= mask->src_ip[i];
	}
	stream->ptype &= mask->ptype;

	nse_fdir_compute_hash(stream,
				le32_to_cpu(cb->setting.fdir_hkey),
				&hash);

	/* bkt_hash only use 15 bits */
	return hash & 0x7FFF;
}

u16 nse_fdir_compute_sig_hash(struct nse_hw *hw,
					struct nse_fdir_input_stream *stream,
					struct nse_fdir_input_stream *mask)
{
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	u16 hash;
	int i = 0;

	/* apply mask */
	stream->flex_bytes &= mask->flex_bytes;
	stream->dst_port &= mask->dst_port;
	stream->src_port &= mask->src_port;
	for (i = 0; i < 4; i++) {
		stream->dst_ip[i] &= mask->dst_ip[i];
		stream->src_ip[i] &= mask->src_ip[i];
	}
	stream->ptype &= mask->ptype;

	nse_fdir_compute_hash(stream,
				le32_to_cpu(cb->setting.fdir_skey),
				&hash);

	return hash & 0x1FFF;
}

static bool
match_existing_filter(struct nse_fdir_cb *cb, struct nse_fdir_filter *filter)
{
	struct hlist_node *node2;
	struct nse_fdir_filter *f = NULL;

	hlist_for_each_entry_safe(f, node2, &cb->filter_list, hnode) {
		if (f->bkt_hash == filter->bkt_hash &&
			!memcmp(&f->input_stream, &filter->input_stream, sizeof(f->input_stream))) {
			return true;
		}
	}

	return false;
}

/* cover all IPv4 ptypes in nse_ptype_lkup  */
#define NSE_PTYPE_MAC_IPV4_ALL	0x20	/* 0b' 0010 + Bit3:0 - with bit 3 = 0 */
#define NSE_PTYPE_MAC_IPV6_ALL	0x28	/* 0b' 0010 + Bit3:0 - with bit 3 = 1 */

#define NSE_PTYPE_MAC_IP_STREAM_MASK		0xF8	/* mask bit 7:4, and bit 3*/

static int flow_type_to_ptype(struct ethtool_rx_flow_spec *fsp, u8 *ptype,
			      u8 *stream_ptype_mask, u32 *hw_ptype_mask)
{
	*stream_ptype_mask = 0xFF;
	*hw_ptype_mask = 0;

	switch (fsp->flow_type & ~FLOW_EXT) {
	case UDP_V4_FLOW:
		*ptype = NSE_PTYPE_MAC_IPV4_UDP_PAY4;
		break;
	case TCP_V4_FLOW:
		*ptype = NSE_PTYPE_MAC_IPV4_TCP_PAY4;
		break;
	case SCTP_V4_FLOW:
		*ptype = NSE_PTYPE_MAC_IPV4_SCTP_PAY4;
		break;
	case UDP_V6_FLOW:
		*ptype = NSE_PTYPE_MAC_IPV6_UDP_PAY4;
		break;
	case TCP_V6_FLOW:
		*ptype = NSE_PTYPE_MAC_IPV6_TCP_PAY4;
		break;
	case SCTP_V6_FLOW:
		*ptype = NSE_PTYPE_MAC_IPV6_SCTP_PAY4;
		break;

	case IP_USER_FLOW:
		switch (fsp->h_u.usr_ip4_spec.proto) {
		case IPPROTO_UDP:
			*ptype = NSE_PTYPE_MAC_IPV4_UDP_PAY4;
			break;
		case IPPROTO_TCP:
			*ptype = NSE_PTYPE_MAC_IPV4_TCP_PAY4;
			break;
		case IPPROTO_SCTP:
			*ptype = NSE_PTYPE_MAC_IPV4_SCTP_PAY4;
			break;
		case IPPROTO_ICMP:
			*ptype = NSE_PTYPE_MAC_IPV4_ICMP_PAY4;
			break;
		case 0:
			if (!fsp->m_u.usr_ip4_spec.proto) {
				*ptype = NSE_PTYPE_MAC_IPV4_ALL;
				*stream_ptype_mask = NSE_PTYPE_MAC_IP_STREAM_MASK;
				*hw_ptype_mask = FDIR_MASK_OTHER_L4P_M;
				break;
			}
			fallthrough;
		default:
			return -EOPNOTSUPP;
		}
		break;

	case IPV6_USER_FLOW:
		switch (fsp->h_u.usr_ip6_spec.l4_proto) {
		case IPPROTO_UDP:
			*ptype = NSE_PTYPE_MAC_IPV6_UDP_PAY4;
			break;
		case IPPROTO_TCP:
			*ptype = NSE_PTYPE_MAC_IPV6_TCP_PAY4;
			break;
		case IPPROTO_SCTP:
			*ptype = NSE_PTYPE_MAC_IPV6_SCTP_PAY4;
			break;
		case IPPROTO_ICMPV6:
			*ptype = NSE_PTYPE_MAC_IPV6_ICMP_PAY4;
			break;
		case 0:
			if (!fsp->m_u.usr_ip6_spec.l4_proto) {
				*ptype = NSE_PTYPE_MAC_IPV6_ALL;
				*stream_ptype_mask = NSE_PTYPE_MAC_IP_STREAM_MASK;
				*hw_ptype_mask = FDIR_MASK_OTHER_L4P_M;
				break;
			}
			fallthrough;
		default:
			return -EOPNOTSUPP;
		}
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;	/* success */
}

static int parse_ptype_from_ntuple_flow_type(struct nse_hw *hw, struct nse_fdir_filter *filter,
					     struct ethtool_rx_flow_spec *fsp)
{
	u8 stream_ptype, stream_ptype_mask;
	u32 hw_ptype_mask;
	int ret;

	stream_ptype = 0;
	stream_ptype_mask = 0;
	hw_ptype_mask = 0;

	ret = flow_type_to_ptype(fsp, &stream_ptype, &stream_ptype_mask, &hw_ptype_mask);
	if (ret)
		return ret;

	filter->input_stream.ptype = stream_ptype;
	filter->input_stream_mask.ptype = stream_ptype_mask;

	filter->expected_vsi_hw_input_mask_info.valid_reg_mask[FDIR_MASK_IDX_OTHER] = 1;
	filter->expected_vsi_hw_input_mask_info.hw_input_mask.mask[FDIR_MASK_IDX_OTHER] =
		cpu_to_le32(hw_ptype_mask | FDIR_MASK_OTHER_L4PORT_M);

	return 0;
}

static int parse_port_from_ntuple(struct nse_hw *hw, struct nse_fdir_filter *filter,
				  struct ethtool_rx_flow_spec *fsp, bool ip4_or_6)
{
	u32 val;

	if (ip4_or_6) {
		filter->input_stream.src_port = be16_to_le(fsp->h_u.tcp_ip4_spec.psrc);
		filter->input_stream_mask.src_port = be16_to_le(fsp->m_u.tcp_ip4_spec.psrc);

		filter->input_stream.dst_port = be16_to_le(fsp->h_u.tcp_ip4_spec.pdst);
		filter->input_stream_mask.dst_port = be16_to_le(fsp->m_u.tcp_ip4_spec.pdst);

	} else {
		filter->input_stream.src_port = be16_to_le(fsp->h_u.tcp_ip6_spec.psrc);
		filter->input_stream_mask.src_port = be16_to_le(fsp->m_u.tcp_ip6_spec.psrc);

		filter->input_stream.dst_port = be16_to_le(fsp->h_u.tcp_ip6_spec.pdst);
		filter->input_stream_mask.dst_port = be16_to_le(fsp->m_u.tcp_ip6_spec.pdst);
	}

	val = le16_to_cpu(filter->input_stream_mask.dst_port);
	val <<= FDIR_MASK_TCP_DPORT_S;
	val |= le16_to_cpu(filter->input_stream_mask.src_port);

	if (filter->input_stream.ptype == NSE_PTYPE_MAC_IPV4_UDP_PAY4 ||
		filter->input_stream.ptype == NSE_PTYPE_MAC_IPV6_UDP_PAY4) {
		filter->expected_vsi_hw_input_mask_info.valid_reg_mask[FDIR_MASK_IDX_UDP] = 1;
		filter->expected_vsi_hw_input_mask_info.hw_input_mask.mask[FDIR_MASK_IDX_UDP] =
			~(cpu_to_le32(val));

	} else if (filter->input_stream.ptype == NSE_PTYPE_MAC_IPV4_TCP_PAY4 ||
				filter->input_stream.ptype == NSE_PTYPE_MAC_IPV6_TCP_PAY4) {
		filter->expected_vsi_hw_input_mask_info.valid_reg_mask[FDIR_MASK_IDX_TCP] = 1;
		filter->expected_vsi_hw_input_mask_info.hw_input_mask.mask[FDIR_MASK_IDX_TCP] =
			~(cpu_to_le32(val));

	} else if (filter->input_stream.ptype == NSE_PTYPE_MAC_IPV4_SCTP_PAY4 ||
				filter->input_stream.ptype == NSE_PTYPE_MAC_IPV6_SCTP_PAY4) {
		filter->expected_vsi_hw_input_mask_info.valid_reg_mask[FDIR_MASK_IDX_SCTP] = 1;
		filter->expected_vsi_hw_input_mask_info.hw_input_mask.mask[FDIR_MASK_IDX_SCTP] =
			~(cpu_to_le32(val));

	} else {
/* including, but not limited to:
 *
		else if (filter->input_stream.ptype == NSE_PTYPE_MAC_IPV4_ICMP_PAY4 ||
				filter->input_stream.ptype == NSE_PTYPE_MAC_IPV6_ICMP_PAY4) {
 */

		filter->input_stream.src_port = 0;
		filter->input_stream_mask.src_port = 0;

		filter->input_stream.dst_port = 0;
		filter->input_stream_mask.dst_port = 0;
	}

	return 0;	/* success */
}

static int parse_addr_ipv4_from_ntuple(struct nse_hw *hw, struct nse_fdir_filter *filter,
				       struct ethtool_rx_flow_spec *fsp)
{
	filter->input_stream.src_ip[0] = be32_to_le(fsp->h_u.tcp_ip4_spec.ip4src);
	filter->input_stream_mask.src_ip[0] = be32_to_le(fsp->m_u.tcp_ip4_spec.ip4src);

	filter->input_stream.dst_ip[0] = be32_to_le(fsp->h_u.tcp_ip4_spec.ip4dst);
	filter->input_stream_mask.dst_ip[0] = be32_to_le(fsp->m_u.tcp_ip4_spec.ip4dst);

	filter->expected_vsi_hw_input_mask_info.valid_reg_mask[FDIR_MASK_IDX_DA4] = 1;
	filter->expected_vsi_hw_input_mask_info.hw_input_mask.mask[FDIR_MASK_IDX_DA4] =
		~(filter->input_stream_mask.dst_ip[0]);

	filter->expected_vsi_hw_input_mask_info.valid_reg_mask[FDIR_MASK_IDX_SA4] = 1;
	filter->expected_vsi_hw_input_mask_info.hw_input_mask.mask[FDIR_MASK_IDX_SA4] =
		~(filter->input_stream_mask.src_ip[0]);

	return 0;
}

static bool is_addr_ipv6_mask_supported_by_hw(u8 *addr_m)
{
	u8 *p = addr_m;
	int i;

	for (i = 0; i < 16; i++, p++) {
		if (*p != 0xFF && *p != 0x0)
			return false;
	}

	return true;
}

/* fake HW little endian ... */
static void xfrm_ipv6_addr_to_hw_order(u8 *addr_hw, u8 *addr_be)
{
	int i = 0;

	for (i = 0; i < 16; i++)
		addr_hw[i] = addr_be[15 - i];
}

/* fake HW little endian ... */
static __le16 get_ipv6_mask_as_hw_byte_aligned_mask(u8 *addr_m_be)
{
	u16 h_mask = 0;
	int i = 0;

	for (i = 0; i < 16; i++) {
		if (addr_m_be[i])
			h_mask |= (1 << i);
	}

	return cpu_to_le16(~h_mask);
}

static int parse_addr_ipv6_from_ntuple(struct nse_hw *hw, struct nse_fdir_filter *filter,
				       struct ethtool_rx_flow_spec *fsp)
{
	struct device *dev = nse_hw_to_dev(hw);
	int ret = -EOPNOTSUPP;

	if (fsp->m_u.tcp_ip6_spec.ip6dst[0] ||
	    fsp->m_u.tcp_ip6_spec.ip6dst[1] ||
	    fsp->m_u.tcp_ip6_spec.ip6dst[2] ||
	    fsp->m_u.tcp_ip6_spec.ip6dst[3]) {
		dev_err(dev, "fdir: Error not support IPv6 dst address fitlering, only support src address filtering\n");
		goto out;
	}

	if (!is_addr_ipv6_mask_supported_by_hw((u8 *)fsp->m_u.tcp_ip6_spec.ip6src)) {
		dev_err(dev, "fdir: Error, only support 0xFF or 0x00 like src addr mask\n");
		goto out;
	}

	xfrm_ipv6_addr_to_hw_order((u8 *)filter->input_stream.src_ip,
				   (u8 *)fsp->h_u.tcp_ip6_spec.ip6src);
	xfrm_ipv6_addr_to_hw_order((u8 *)filter->input_stream_mask.src_ip,
				   (u8 *)fsp->m_u.tcp_ip6_spec.ip6src);

	filter->expected_vsi_hw_input_mask_info.valid_reg_mask[FDIR_MASK_IDX_IP6] = 1;
	filter->expected_vsi_hw_input_mask_info.hw_input_mask.mask[FDIR_MASK_IDX_IP6] =
			get_ipv6_mask_as_hw_byte_aligned_mask((u8 *)fsp->m_u.tcp_ip6_spec.ip6src);

	ret = 0;

out:
	return ret;
}

static bool nse_is_mask_valid(u64 mask, u64 field)
{
	return (mask & field) == field;
}

static int
parse_userdef(struct nse_hw *hw, struct ethtool_rx_flow_spec *fsp, u8 ptype,
			    struct nse_fdir_ntuple_userdef *data)
{
	struct device *dev = nse_hw_to_dev(hw);
	u64 value, mask;

	memset(data, 0, sizeof(*data));

	if (!(fsp->flow_type & FLOW_EXT))
		return 0;

	value = be64_to_cpu(*((__force __be64 *)fsp->h_ext.data));
	mask = be64_to_cpu(*((__force __be64 *)fsp->m_ext.data));
	if (!mask)
		return 0;

#define NSE_USERDEF_FLEX_WORD_M	GENMASK_ULL(15, 0)
#define NSE_USERDEF_FLEX_OFFS_S	16
#define NSE_USERDEF_FLEX_OFFS_M	GENMASK_ULL(31, NSE_USERDEF_FLEX_OFFS_S)
#define NSE_USERDEF_FLEX_FLTR_M	GENMASK_ULL(31, 0)

	if (!nse_is_mask_valid(mask, NSE_USERDEF_FLEX_FLTR_M) ||
	    value > NSE_USERDEF_FLEX_FLTR_M)
		return -EINVAL;

	data->flex_word = value & NSE_USERDEF_FLEX_WORD_M;
	data->flex_offset = (value & NSE_USERDEF_FLEX_OFFS_M) >>
			     NSE_USERDEF_FLEX_OFFS_S;

	/* flex_offset given from ethtool in a byte unit */

	if (data->flex_offset & 0x1) {	/* not in word unit */
		return -EINVAL;
	}

	data->flex_offset >>= 1;		/* convert to word unit */

	/* 0x1F (word unit) is the maximum value for offsets stored in the internal
	 */
#define NSE_USERDEF_FLEX_MAX_OFFS_VAL 0x1F

	if (data->flex_offset > NSE_USERDEF_FLEX_MAX_OFFS_VAL)
		return -EINVAL;

	if (ptype == NSE_PTYPE_MAC_IPV4_UDP_PAY4 ||
		ptype == NSE_PTYPE_MAC_IPV4_TCP_PAY4 ||
		ptype == NSE_PTYPE_MAC_IPV4_SCTP_PAY4 ||
		ptype == NSE_PTYPE_MAC_IPV4_ICMP_PAY4 ||
		ptype == NSE_PTYPE_MAC_IPV6_UDP_PAY4 ||
		ptype == NSE_PTYPE_MAC_IPV6_TCP_PAY4 ||
		ptype == NSE_PTYPE_MAC_IPV6_SCTP_PAY4 ||
		ptype == NSE_PTYPE_MAC_IPV6_ICMP_PAY4) {
		data->flex_base = FDIR_FLEX_CFG_BASE_L4_PAYLOAD;
	} else if (ptype == NSE_PTYPE_MAC_IPV4_ALL ||
			ptype == NSE_PTYPE_MAC_IPV6_ALL) {
		data->flex_base = FDIR_FLEX_CFG_BASE_L4_HDR;
	} else {
		dev_err(dev, "can not determine flex_base for this ptype\n");
		return -EINVAL;
	}

	data->flex_fltr = 1;	//true

	return 0;
}

static int parse_flexbyte_from_ntuple_userdef(struct nse_hw *hw, struct nse_fdir_filter *filter,
					      struct ethtool_rx_flow_spec *fsp,
					      struct nse_fdir_ntuple_userdef *userdef)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 val;
	int ret = -EOPNOTSUPP;

	memset(userdef, 0, sizeof(*userdef));

	filter->expected_vsi_hw_input_mask_info.valid_reg_flex_cfg = 1;
	filter->expected_vsi_hw_input_mask_info.hw_input_mask.flex_cfg =
		cpu_to_le32(FDIR_FLEX_CFG_MASK_M);

	if (fsp->flow_type & FLOW_EXT) {
		if (fsp->m_ext.vlan_etype ||
			fsp->m_ext.vlan_tci) {
			dev_err(dev, "fdir: not support VLAN, etype, DMAC filtering\n");
			goto out;
		}

		ret = parse_userdef(hw, fsp, filter->input_stream.ptype, userdef);
		if (ret) {
			dev_err(dev, "fdir: fail - parse_userdef()\n");
			goto out;
		}

		if (userdef->flex_fltr) {
			filter->input_stream.flex_bytes = cpu_to_le16(userdef->flex_word);
			filter->input_stream_mask.flex_bytes = cpu_to_le16(0xFFFF);

			/* flex_msk = 0 (unmask) */
			val = ((userdef->flex_offset << FDIR_FLEX_CFG_OFFSET_S) |
					(userdef->flex_base << FDIR_FLEX_CFG_BASE_S));

			filter->expected_vsi_hw_input_mask_info.hw_input_mask.flex_cfg =
				cpu_to_le32(val);
		}
	}

	ret = 0;

out:
	return ret;
}

static void init_default_vsi_hw_input_mask_info(struct nse_fdir_vsi_hw_input_mask_info *info)
{
	memset(info, 0, sizeof(*info));

	info->valid_reg_flex_cfg = 1;
	info->hw_input_mask.flex_cfg = cpu_to_le32(FDIR_FLEX_CFG_MASK_M);

	/* not sure we are ipv4 or ipv6 rule - for now */
	info->valid_reg_mask[FDIR_MASK_IDX_DA4] = 0;
	info->hw_input_mask.mask[FDIR_MASK_IDX_DA4] = cpu_to_le32(0xFFFFFFFF);

	info->valid_reg_mask[FDIR_MASK_IDX_SA4] = 0;
	info->hw_input_mask.mask[FDIR_MASK_IDX_SA4] = cpu_to_le32(0xFFFFFFFF);

	/* not sure we are tcp or udp or sctp rule - for now */
	info->valid_reg_mask[FDIR_MASK_IDX_TCP] = 0;
	info->hw_input_mask.mask[FDIR_MASK_IDX_TCP] = cpu_to_le32(0xFFFFFFFF);

	info->valid_reg_mask[FDIR_MASK_IDX_UDP] = 0;
	info->hw_input_mask.mask[FDIR_MASK_IDX_UDP] = cpu_to_le32(0xFFFFFFFF);

	info->valid_reg_mask[FDIR_MASK_IDX_SCTP] = 0;
	info->hw_input_mask.mask[FDIR_MASK_IDX_SCTP] = cpu_to_le32(0xFFFFFFFF);

	/* not sure we are ipv4 or ipv6 rule - for now */
	info->valid_reg_mask[FDIR_MASK_IDX_IP6] = 0;
	info->hw_input_mask.mask[FDIR_MASK_IDX_IP6] = cpu_to_le32(0xFFFFFFFF);

	info->valid_reg_mask[FDIR_MASK_IDX_OTHER] = 1;
	info->hw_input_mask.mask[FDIR_MASK_IDX_OTHER] = cpu_to_le32(0xFFFFFFFF);
}

static int add_update_vsi_hw_input_mask_info(struct nse_hw *hw,
					     struct nse_fdir_vsi_hw_input_mask_info *new_info,
					     struct nse_fdir_vsi_hw_input_mask_info *old_info,
					     struct nse_fdir_vsi_hw_input_mask_info *merge_info,
					     bool *need_update_hw)
{
	int ret = -EOPNOTSUPP;
	unsigned int val1, val2;

	*need_update_hw = false;
	memcpy(merge_info, old_info, sizeof(*merge_info));

	/* flex_cfg must be the same, and both set */
	val1 = !!new_info->valid_reg_flex_cfg;
	val2 = !!old_info->valid_reg_flex_cfg;

	if (val1 && val2) {
		if (new_info->hw_input_mask.flex_cfg != old_info->hw_input_mask.flex_cfg)
			goto out;	/* bad */

		merge_info->valid_reg_flex_cfg += 1;

	} else if (val1 != val2) {
		nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
		goto out;	/* bad */
	}

	/* DA4 is mergeable, if new is ipv4 rule and old is ipv6 rule */
	val1 = !!new_info->valid_reg_mask[FDIR_MASK_IDX_DA4];
	val2 = !!old_info->valid_reg_mask[FDIR_MASK_IDX_DA4];
	if (val1 && val2) {		/* new is ipv4 rule, old is ipv4 rule */

		if (new_info->hw_input_mask.mask[FDIR_MASK_IDX_DA4] !=
		    old_info->hw_input_mask.mask[FDIR_MASK_IDX_DA4]) {
			nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
			goto out;	/* bad */
		}

		merge_info->valid_reg_mask[FDIR_MASK_IDX_DA4] += 1;

	} else if (val1 && !val2) {	/* new is ipv4 rule, old is ipv6 rule */

		*need_update_hw = true;

		merge_info->hw_input_mask.mask[FDIR_MASK_IDX_DA4] =
			new_info->hw_input_mask.mask[FDIR_MASK_IDX_DA4];
		merge_info->valid_reg_mask[FDIR_MASK_IDX_DA4] += 1;

	} else {
		/* else if (!val1 && val2)		* new is ipv6 rule, old is ipv4 rule */
		/* else if (!val1 && !val2)		* new is ipv6 rule, old is ipv6 rule */

		/* do nothing, no need to merge this part - keep old */
	}

	/* SA4 is mergeable, if new is ipv4 rule and old is ipv6 rule */
	val1 = !!new_info->valid_reg_mask[FDIR_MASK_IDX_SA4];
	val2 = !!old_info->valid_reg_mask[FDIR_MASK_IDX_SA4];
	if (val1 && val2) {		/* new and old are both ipv4 rule */

		if (new_info->hw_input_mask.mask[FDIR_MASK_IDX_SA4] !=
		    old_info->hw_input_mask.mask[FDIR_MASK_IDX_SA4]) {
			nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
			goto out;	/* bad */
		}

		merge_info->valid_reg_mask[FDIR_MASK_IDX_SA4] += 1;

	} else if (val1 && !val2) {	/* new is ipv4 rule, old is ipv6 rule */

		*need_update_hw = true;

		merge_info->hw_input_mask.mask[FDIR_MASK_IDX_SA4] =
			new_info->hw_input_mask.mask[FDIR_MASK_IDX_SA4];
		merge_info->valid_reg_mask[FDIR_MASK_IDX_SA4] += 1;

	} else {
		/* else if (!val1 && val2)		* new is ipv6 rule, old is ipv4 rule */
		/* else if (!val1 && !val2)		* new is ipv6 rule, old is ipv6 rule */

		/* do nothing, no need to merge this part - keep old */
	}

	val1 = !!new_info->valid_reg_mask[FDIR_MASK_IDX_TCP];
	val2 = !!old_info->valid_reg_mask[FDIR_MASK_IDX_TCP];
	if (val1 && val2) {		/* new and old are both tcp rule */
		if (new_info->hw_input_mask.mask[FDIR_MASK_IDX_TCP] !=
		    old_info->hw_input_mask.mask[FDIR_MASK_IDX_TCP]) {
			nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
			goto out;	/* bad */
		}

		merge_info->valid_reg_mask[FDIR_MASK_IDX_TCP] += 1;

	} else if (val1 && !val2) {			/* new is tcp rule, old is not */

		*need_update_hw = true;

		merge_info->hw_input_mask.mask[FDIR_MASK_IDX_TCP] =
			new_info->hw_input_mask.mask[FDIR_MASK_IDX_TCP];
		merge_info->valid_reg_mask[FDIR_MASK_IDX_TCP] += 1;

	} else {
		/* else if (!val1 && val2)		* new is not tcp rule, old is tcp rule */
		/*  else if (!val1 && !val2) * new is not tcp rule, old is not tcp rule
		 */

		/* do nothing, no need to merge this part - keep old */
	}

	val1 = !!new_info->valid_reg_mask[FDIR_MASK_IDX_UDP];
	val2 = !!old_info->valid_reg_mask[FDIR_MASK_IDX_UDP];
	if (val1 && val2) {		/* new and old are both udp rule */
		if (new_info->hw_input_mask.mask[FDIR_MASK_IDX_UDP] !=
		    old_info->hw_input_mask.mask[FDIR_MASK_IDX_UDP]) {
			nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
			goto out;	/* bad */
		}

		merge_info->valid_reg_mask[FDIR_MASK_IDX_UDP] += 1;

	} else if (val1 && !val2) {			/* new is udp rule, old is not */

		*need_update_hw = true;

		merge_info->hw_input_mask.mask[FDIR_MASK_IDX_UDP] =
			new_info->hw_input_mask.mask[FDIR_MASK_IDX_UDP];
		merge_info->valid_reg_mask[FDIR_MASK_IDX_UDP] += 1;

	} else {
		/* else if (!val1 && val2)		* new is not udp rule, old is udp rule */
		/*  else if (!val1 && !val2) * new is not udp rule, old is not udp rule
		 */

		/* do nothing, no need to merge this part - keep old */
	}

	val1 = !!new_info->valid_reg_mask[FDIR_MASK_IDX_SCTP];
	val2 = !!old_info->valid_reg_mask[FDIR_MASK_IDX_SCTP];
	if (val1 && val2) {		/* new and old are both sctp rule */
		if (new_info->hw_input_mask.mask[FDIR_MASK_IDX_SCTP] !=
		    old_info->hw_input_mask.mask[FDIR_MASK_IDX_SCTP]) {
			nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
			goto out;	/* bad */
		}

		merge_info->valid_reg_mask[FDIR_MASK_IDX_SCTP] += 1;

	} else if (val1 && !val2) {			/* new is sctp rule, old is not */

		*need_update_hw = true;

		merge_info->hw_input_mask.mask[FDIR_MASK_IDX_SCTP] =
			new_info->hw_input_mask.mask[FDIR_MASK_IDX_SCTP];
		merge_info->valid_reg_mask[FDIR_MASK_IDX_SCTP] += 1;

	} else {
		/* else if (!val1 && val2)		* new is not sctp rule, old is sctp rule */
		/*  else if (!val1 && !val2) * new is not sctp rule, old is not sctp rule
		 */

		/* do nothing, no need to merge this part - keep old */
	}

	val1 = !!new_info->valid_reg_mask[FDIR_MASK_IDX_IP6];
	val2 = !!old_info->valid_reg_mask[FDIR_MASK_IDX_IP6];
	if (val1 && val2) {		/* new and old are both ipv6 rule */
		if (new_info->hw_input_mask.mask[FDIR_MASK_IDX_IP6] !=
		    old_info->hw_input_mask.mask[FDIR_MASK_IDX_IP6]) {
			nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
			goto out;	/* bad */
		}

		merge_info->valid_reg_mask[FDIR_MASK_IDX_IP6] += 1;

	} else if (val1 && !val2) {			/* new is ipv6 rule, old is ipv4 rule */

		*need_update_hw = true;

		merge_info->hw_input_mask.mask[FDIR_MASK_IDX_IP6] =
			new_info->hw_input_mask.mask[FDIR_MASK_IDX_IP6];
		merge_info->valid_reg_mask[FDIR_MASK_IDX_IP6] += 1;

	} else {
		/* else if (!val1 && val2)		* new is not ipv6 rule, old is ipv6 rule */
		/*  else if (!val1 && !val2) * new is not ipv6 rule, old is not ipv6 rule
		 */

		/* do nothing, no need to merge this part - keep old */
	}

	val1 = !!new_info->valid_reg_mask[FDIR_MASK_IDX_OTHER];
	val2 = !!old_info->valid_reg_mask[FDIR_MASK_IDX_OTHER];

	if (val1 && val2) {
		if (new_info->hw_input_mask.mask[FDIR_MASK_IDX_OTHER] !=
		    old_info->hw_input_mask.mask[FDIR_MASK_IDX_OTHER]) {
			nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
			goto out;	/* bad */
		}

		merge_info->valid_reg_mask[FDIR_MASK_IDX_OTHER] += 1;

	} else if (val1 != val2) {
		nse_debug(hw, NSE_DBG_RCF, "[%s, %d] BAD\n", __func__, __LINE__);
		goto out;	/* bad */
	}

	ret = 0;

out:
	return ret;
}

static void del_update_vsi_hw_input_mask_info(struct nse_hw *hw,
					      struct nse_fdir_vsi_hw_input_mask_info *dead_info,
					      struct nse_fdir_vsi_hw_input_mask_info *old_info,
					      struct nse_fdir_vsi_hw_input_mask_info *merge_info,
					      bool *need_update_hw)
{
	unsigned int val1;

	*need_update_hw = false;
	memcpy(merge_info, old_info, sizeof(*merge_info));

	val1 = !!dead_info->valid_reg_flex_cfg;

	if (val1) {
		merge_info->valid_reg_flex_cfg -= 1;

		if (!merge_info->valid_reg_flex_cfg) {
			*need_update_hw = true;

			merge_info->hw_input_mask.flex_cfg = cpu_to_le32(FDIR_FLEX_CFG_MASK_M);
		}
	}

	val1 = !!dead_info->valid_reg_mask[FDIR_MASK_IDX_DA4];

	if (val1) {		/* dead is a ipv4 rule */

		merge_info->valid_reg_mask[FDIR_MASK_IDX_DA4] -= 1;

		/* last ipv4 rule to be remove */
		if (!merge_info->valid_reg_mask[FDIR_MASK_IDX_DA4]) {
			*need_update_hw = true;

			merge_info->hw_input_mask.mask[FDIR_MASK_IDX_DA4] = cpu_to_le32(0xFFFFFFFF);
		}
	}

	val1 = !!dead_info->valid_reg_mask[FDIR_MASK_IDX_SA4];

	if (val1) {		/* dead is a ipv4 rule */

		merge_info->valid_reg_mask[FDIR_MASK_IDX_SA4] -= 1;

		/* last ipv4 rule to be remove */
		if (!merge_info->valid_reg_mask[FDIR_MASK_IDX_SA4]) {
			*need_update_hw = true;

			merge_info->hw_input_mask.mask[FDIR_MASK_IDX_SA4] = cpu_to_le32(0xFFFFFFFF);
		}
	}

	val1 = !!dead_info->valid_reg_mask[FDIR_MASK_IDX_TCP];

	if (val1) {		/* dead is a tcp rule */

		merge_info->valid_reg_mask[FDIR_MASK_IDX_TCP] -= 1;

		/* last tcp rule to be remove */
		if (!merge_info->valid_reg_mask[FDIR_MASK_IDX_TCP]) {
			*need_update_hw = true;

			merge_info->hw_input_mask.mask[FDIR_MASK_IDX_TCP] = cpu_to_le32(0xFFFFFFFF);
		}
	}

	val1 = !!dead_info->valid_reg_mask[FDIR_MASK_IDX_UDP];

	if (val1) {		/* dead is a udp rule */

		merge_info->valid_reg_mask[FDIR_MASK_IDX_UDP] -= 1;

		/* last udp rule to be remove */
		if (!merge_info->valid_reg_mask[FDIR_MASK_IDX_UDP]) {
			*need_update_hw = true;

			merge_info->hw_input_mask.mask[FDIR_MASK_IDX_UDP] = cpu_to_le32(0xFFFFFFFF);
		}
	}

	val1 = !!dead_info->valid_reg_mask[FDIR_MASK_IDX_SCTP];

	if (val1) {		/* dead is a udp rule */

		merge_info->valid_reg_mask[FDIR_MASK_IDX_SCTP] -= 1;

		/* last sctp rule to be remove */
		if (!merge_info->valid_reg_mask[FDIR_MASK_IDX_SCTP]) {
			*need_update_hw = true;

			merge_info->hw_input_mask.mask[FDIR_MASK_IDX_SCTP] =
				cpu_to_le32(0xFFFFFFFF);
		}
	}

	val1 = !!dead_info->valid_reg_mask[FDIR_MASK_IDX_IP6];

	if (val1) {		/* dead is a ipv6 rule */

		merge_info->valid_reg_mask[FDIR_MASK_IDX_IP6] -= 1;

		/* last ipv6 rule to be remove */
		if (!merge_info->valid_reg_mask[FDIR_MASK_IDX_IP6]) {
			*need_update_hw = true;

			merge_info->hw_input_mask.mask[FDIR_MASK_IDX_IP6] = cpu_to_le32(0xFFFFFFFF);
		}
	}

	val1 = !!dead_info->valid_reg_mask[FDIR_MASK_IDX_OTHER];

	if (val1) {
		merge_info->valid_reg_mask[FDIR_MASK_IDX_OTHER] -= 1;

		if (!merge_info->valid_reg_mask[FDIR_MASK_IDX_OTHER]) {
			*need_update_hw = true;

			merge_info->hw_input_mask.mask[FDIR_MASK_IDX_OTHER] =
				cpu_to_le32(0xFFFFFFFF);
		}
	}
}

int nse_fdir_set_input_mask(struct nse_hw *hw, struct nse_vsi *vsi,
			    struct nse_fdir_vsi_hw_input_mask_info *info)
{
	struct nse_aqc_fdir_get_set_vsi_input_mask *cmd_buf;
	enum nse_status status;
	int ret = 0;

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_ATOMIC);
	if (!cmd_buf)
		return -ENOMEM;

	memcpy(cmd_buf, &info->hw_input_mask, sizeof(*cmd_buf));

	status = nse_aq_fdir_set_vsi_input_mask(hw, vsi->vsi_abs_num, cmd_buf);
	if (status)
		ret = -EIO;

	kfree(cmd_buf);

	return ret;
}

int nse_fdir_add_perfect_filter(struct nse_hw *hw, struct nse_fdir_filter *filter)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_fdir_input_stream *stream = &filter->input_stream;
	struct nse_aqc_fdir_conf_perfect_filter *aq_cmd;
	struct nse_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nse_status status;
	int ret;

	aq_cmd = kzalloc(sizeof(*aq_cmd), GFP_KERNEL);
	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!aq_cmd || !uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	aq_cmd->sa0 = stream->src_ip[0];
	aq_cmd->ip6_sa1 = stream->src_ip[1];
	aq_cmd->ip6_sa2 = stream->src_ip[2];
	aq_cmd->ip6_sa3 = stream->src_ip[3];

	aq_cmd->da = stream->dst_ip[0];

	val = (((u32)stream->src_port) << FDIR_PORT_SPORT_S) |
			(((u32)stream->dst_port) << FDIR_PORT_DPORT_S);
	aq_cmd->port = cpu_to_le32(val);

	val = ((u32)stream->ptype) |
			((u32)stream->vsi << FDIR_FLEX_VSI_S) |
			(((u32)stream->flex_bytes) << FDIR_FLEX_FLEX_DATA_S);
	aq_cmd->flex = cpu_to_le32(val);

	val = ((u32)filter->sw_idx << FDIR_HASH_SW_IDX_S) |
			FDIR_HASH_VLD_M |
			((u32)filter->bkt_hash << FDIR_HASH_BUCKET_HASH_S);

	aq_cmd->hash = cpu_to_le32(val);

	val = (FDIR_CMD_OP_ADD << FDIR_CMD_OP_S) |
			FDIR_CMD_UPDATE_M |
			FDIR_CMD_LAST_M |
			FDIR_CMD_QUEUE_EN_M;

	if (filter->is_action_drop)
		val |= FDIR_CMD_DROP_M;

	val |= ((u32)filter->action_rxq_abs_id << FDIR_CMD_QUEUE_ACTION_S);

	aq_cmd->cmd = cpu_to_le32(val);

	if (pf->sw_conf.fdir_use_utilq) {	/* equal to main_vsi->sw_conf.fdir_use_utilq */

		uq_cmd->sa0 = aq_cmd->sa0;
		uq_cmd->ip6_sa1 = aq_cmd->ip6_sa1;
		uq_cmd->ip6_sa2 = aq_cmd->ip6_sa2;
		uq_cmd->ip6_sa3 = aq_cmd->ip6_sa3;
		uq_cmd->da = aq_cmd->da;
		uq_cmd->port = aq_cmd->port;
		uq_cmd->flex = aq_cmd->flex;
		uq_cmd->hash = aq_cmd->hash;
		uq_cmd->cmd = aq_cmd->cmd;

		status = __nse_uq_conf_filter_by_utilq(hw, uq_cmd);
	} else {
		status = nse_aq_fdir_add_perfect_filter(hw, aq_cmd);
	}

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	kfree(aq_cmd);
	kfree(uq_cmd);

	return ret;
}

int nse_fdir_add_sig_filter(struct nse_hw *hw, struct nse_fdir_filter *filter)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_aqc_fdir_conf_sig_filter *aq_cmd;
	struct nse_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nse_status status;
	int ret;

	aq_cmd = kzalloc(sizeof(*aq_cmd), GFP_KERNEL);
	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!aq_cmd || !uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = ((u32)filter->sig_hash << FDIR_HASH_SIG_HASH_S) |
			((u32)hw->chan_pf_id << FDIR_HASH_SIG_PF_S) |
			FDIR_HASH_VLD_M |
			((u32)filter->bkt_hash << FDIR_HASH_BUCKET_HASH_S);

	aq_cmd->hash = cpu_to_le32(val);

	val = (FDIR_CMD_OP_ADD << FDIR_CMD_OP_S) |
			FDIR_CMD_UPDATE_M |
			FDIR_CMD_LAST_M |
			FDIR_CMD_QUEUE_EN_M;
	val |= ((u32)filter->action_rxq_abs_id << FDIR_CMD_QUEUE_ACTION_S);

	aq_cmd->cmd = cpu_to_le32(val);

	if (pf->sw_conf.fdir_use_utilq) {	/* equal to main_vsi->sw_conf.fdir_use_utilq */

		uq_cmd->hash = aq_cmd->hash;
		uq_cmd->cmd = aq_cmd->cmd;

		status = __nse_uq_conf_filter_by_utilq(hw, uq_cmd);
	} else {
		status = nse_aq_fdir_add_sig_filter(hw, aq_cmd);
	}

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	kfree(aq_cmd);
	kfree(uq_cmd);

	return ret;
}

int nse_fdir_add_filter(struct nse_hw *hw, struct nse_fdir_filter *filter)
{
	struct nse_fdir_cb *cb = &hw->fdir_cb;

	if (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT)
		return nse_fdir_add_perfect_filter(hw, filter);
	else
		return nse_fdir_add_sig_filter(hw, filter);
}

int nse_fdir_del_perfect_filter(struct nse_hw *hw, struct nse_fdir_filter *filter)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_fdir_input_stream *stream = &filter->input_stream;
	struct nse_aqc_fdir_conf_perfect_filter *aq_cmd;
	struct nse_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nse_status status;
	int ret;

	aq_cmd = kzalloc(sizeof(*aq_cmd), GFP_KERNEL);
	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!aq_cmd || !uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = (u32)stream->vsi << FDIR_FLEX_VSI_S;
	aq_cmd->flex = cpu_to_le32(val);

	val = ((u32)filter->sw_idx << FDIR_HASH_SW_IDX_S) |
			((u32)filter->bkt_hash << FDIR_HASH_BUCKET_HASH_S);

	aq_cmd->hash = cpu_to_le32(val);

	val = (FDIR_CMD_OP_REMOVE << FDIR_CMD_OP_S);

	aq_cmd->cmd = cpu_to_le32(val);

	if (pf->sw_conf.fdir_use_utilq) {	/* equal to main_vsi->sw_conf.fdir_use_utilq */

		uq_cmd->flex = aq_cmd->flex;
		uq_cmd->hash = aq_cmd->hash;
		uq_cmd->cmd = aq_cmd->cmd;

		status = __nse_uq_conf_filter_by_utilq(hw, uq_cmd);
	} else {
		status = nse_aq_fdir_del_perfect_filter(hw, aq_cmd);
	}

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	kfree(aq_cmd);
	kfree(uq_cmd);

	return ret;
}

int nse_fdir_del_sig_filter(struct nse_hw *hw, struct nse_fdir_filter *filter)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_aqc_fdir_conf_sig_filter *aq_cmd;
	struct nse_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nse_status status;
	int ret;

	aq_cmd = kzalloc(sizeof(*aq_cmd), GFP_KERNEL);
	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!aq_cmd || !uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = ((u32)filter->sig_hash << FDIR_HASH_SW_IDX_S) |
			((u32)filter->bkt_hash << FDIR_HASH_BUCKET_HASH_S);
	aq_cmd->hash = cpu_to_le32(val);

	val = (FDIR_CMD_OP_REMOVE << FDIR_CMD_OP_S);

	aq_cmd->cmd = cpu_to_le32(val);

	if (pf->sw_conf.fdir_use_utilq) {	/* equal to main_vsi->sw_conf.fdir_use_utilq */

		uq_cmd->hash = aq_cmd->hash;
		uq_cmd->cmd = aq_cmd->cmd;

		status = __nse_uq_conf_filter_by_utilq(hw, uq_cmd);
	} else {
		status = nse_aq_fdir_del_sig_filter(hw, aq_cmd);
	}

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	kfree(aq_cmd);
	kfree(uq_cmd);

	return ret;
}

int nse_fdir_del_filter(struct nse_hw *hw, struct nse_fdir_filter *filter)
{
	struct nse_fdir_cb *cb = &hw->fdir_cb;

	if (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT)
		return nse_fdir_del_perfect_filter(hw, filter);
	else
		return nse_fdir_del_sig_filter(hw, filter);
}

int nse_fdir_flush_vsi_perfect_filter(struct nse_hw *hw, struct nse_vsi *vsi)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_aqc_fdir_conf_perfect_filter *aq_cmd;
	struct nse_fdir_utilq_config_payload *uq_cmd;
	u32 val;
	enum nse_status status;
	int ret;

	aq_cmd = kzalloc(sizeof(*aq_cmd), GFP_KERNEL);
	uq_cmd = kzalloc(sizeof(*uq_cmd), GFP_KERNEL);
	if (!aq_cmd || !uq_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	val = ((u32)vsi->vsi_abs_num << FDIR_FLEX_VSI_S);

	aq_cmd->flex = cpu_to_le32(val);

	val = FDIR_CMD_RM_VSI_ALL_M |
			(FDIR_CMD_OP_REMOVE << FDIR_CMD_OP_S);

	aq_cmd->cmd = cpu_to_le32(val);

	if (pf->sw_conf.fdir_use_utilq) {	/* equal to main_vsi->sw_conf.fdir_use_utilq */
		uq_cmd->flex = aq_cmd->flex;
		uq_cmd->cmd = aq_cmd->cmd;

		status = __nse_uq_conf_filter_by_utilq(hw, uq_cmd);
	} else {
		status = nse_aq_fdir_add_perfect_filter(hw, aq_cmd);
	}

	if (status) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	nse_debug(hw, NSE_DBG_RCF, "[%s] vsi (abs_id=%d), ret=%d\n",
		  __func__, vsi->vsi_abs_num, ret);

	kfree(aq_cmd);
	kfree(uq_cmd);

	return ret;
}

void nse_fdir_prepare_for_reset(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;

	if (!pf->sw_conf.fdir_ena)
		return;

	if (pf->sw_conf.fdir_use_utilq)
		nse_fdir_shutdown_utilq(hw);
}

static void nse_fdir_main_vsi_replay_filters(struct nse_hw *hw, struct nse_vsi *main_vsi)
{
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct nse_fdir_filter *f = NULL;
	int ret;

	if (!cb->filter_count)
		return;

	ret = nse_fdir_set_input_mask(hw, main_vsi, &cb->vsi_hw_input_mask_info);
	if (ret)
		dev_warn(nse_hw_to_dev(hw), "[%s] fail: fdir_set_input_mask(), ret=%d\n",
			 __func__, ret);

	hlist_for_each_entry(f, &cb->filter_list, hnode) {
		(void)nse_fdir_add_filter(hw, f);
	}
}

void nse_fdir_rebuild(struct nse_hw *hw, enum nse_reset_req reset_type)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *main_vsi = nse_get_main_vsi(pf);

	if (!pf->sw_conf.fdir_ena)
		return;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, reset_type);

	nse_fdir_main_vsi_init(hw, main_vsi);

	if (!main_vsi->sw_conf.fdir_ena) {
		dev_warn(dev, "[%s] WARN, FAIL: fdir_main_vsi_init(), FDir would be disabled\n",
			 __func__);
		return;
	}

	if (nse_is_high_reset_type(reset_type))
		nse_fdir_main_vsi_replay_filters(hw, main_vsi);
}

int nse_fdir_update_ethtool_entry(struct nse_hw *hw,
				  struct nse_fdir_filter *new_filter,
				  u16 sw_idx,
				  bool *del_p,
				  struct nse_fdir_vsi_hw_input_mask_info *del_hw_input_mask_info)
{
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct hlist_node *node2;
	struct nse_fdir_filter *f = NULL, *prev = NULL;
	bool deleted = false;
	int ret;

	hlist_for_each_entry_safe(f, node2,
				  &cb->filter_list, hnode) {
		/* hash found, or no matching entry */
		if (f->sw_idx >= sw_idx)
			break;
		prev = f;
	}

	/* if there is an old rule occupying our place remove it */
	if (f && (f->sw_idx == sw_idx)) {
		if (!new_filter ||
			(new_filter->bkt_hash != f->bkt_hash)) {
			ret = nse_fdir_del_filter(hw, f);
			if (ret)
				return ret;
		}

		deleted = true;
		if (del_p)
			*del_p = deleted;
		if (del_hw_input_mask_info)
			memcpy(del_hw_input_mask_info, &f->expected_vsi_hw_input_mask_info,
			       sizeof(*del_hw_input_mask_info));

		hlist_del(&f->hnode);
		kfree(f);
		cb->filter_count--;
	}

	/* If we weren't given an input, then this was a request to delete a
	 * filter. We should return -EINVAL if the filter wasn't found, but
	 * return 0 if the rule was successfully deleted.
	 */
	if (!new_filter)
		return deleted ? 0 : -EINVAL;

	/* initialize node and set software index */
	INIT_HLIST_NODE(&new_filter->hnode);

	/* add filter to the list */
	if (prev)
		hlist_add_behind(&new_filter->hnode, &prev->hnode);
	else
		hlist_add_head(&new_filter->hnode,
			       &cb->filter_list);

	/* update counts */
	cb->filter_count++;

	return 0;
}

int nse_add_ethtool_ntuple(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct device *dev = nse_pf_to_dev(pf);
	struct ethtool_rx_flow_spec *fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
	struct nse_fdir_filter *filter = NULL;
	struct nse_fdir_ntuple_userdef userdef;
	u16 rxq_rel_id;
	bool del = false;
	struct nse_fdir_vsi_hw_input_mask_info del_hw_input_mask_info;
	bool need_update_hw = false;
	int i;
	int ret = 0;

	if (!vsi || vsi != nse_get_main_vsi(pf)) {
		ret = -EINVAL;
		goto err_out;
	}

	if (!vsi->sw_conf.fdir_ena) {
		ret = -EOPNOTSUPP;
		goto err_out;
	}

	/* Do not program filters during reset */
	if (nse_is_reset_in_progress(pf->state)) {
		dev_err(dev, "Device is resetting - adding ntuple filters not supported during reset\n");
		ret = -EBUSY;
		goto err_out;
	}

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC &&
		cb->mode == FDIR_CTL_FILTER_MODE_SIGNATURE) {
		dev_err(dev, "fdir: signature mode does not support drop\n");
		ret = -EOPNOTSUPP;
		goto err_out;
	}

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		rxq_rel_id = cb->drp_rxq_rel_id;
	} else {
		u32 ring_id = ethtool_get_flow_spec_ring(fsp->ring_cookie);

		if (ring_id >= vsi->num_rxq) {
			dev_err(dev, "fdir: specified rxq out of enabled rxq range.\n");
			ret = -EINVAL;
			goto err_out;
		}

		rxq_rel_id = vsi->rx_rings[ring_id]->reg_idx;
	}

	/* Don't allow indexes to exist outside of available space */
	if ((cb->mode == FDIR_CTL_FILTER_MODE_PERFECT &&
	    fsp->location >= (cb->max_num_pfilter_pf_vsi - 2)) ||
		(cb->mode == FDIR_CTL_FILTER_MODE_SIGNATURE &&
		 fsp->location >= (cb->max_num_sfilter_pf_vsi - 2))) {
		dev_err(dev, "fdir: ntuple filter location out of range\n");
		ret = -EINVAL;
		goto err_out;
	}

	filter = kzalloc(sizeof(*filter), GFP_ATOMIC);
	if (!filter) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* set SW index */
	filter->sw_idx = fsp->location;

	init_default_vsi_hw_input_mask_info(&filter->expected_vsi_hw_input_mask_info);

	ret = parse_ptype_from_ntuple_flow_type(hw, filter, fsp);
	if (ret) {
		dev_err(dev, "fdir: Unrecognized flow type, ret=%d\n", ret);
		goto err_out;
	}

	/* ptype is IPv6 */
	if ((filter->input_stream.ptype & NSE_PTYPE_MAC_IP_STREAM_MASK) == NSE_PTYPE_MAC_IPV6_ALL) {
		ret = parse_addr_ipv6_from_ntuple(hw, filter, fsp);
		if (ret) {
			dev_err(dev, "fdir: fail - parse_addr_ipv6_from_ntuple(), ret=%d\n", ret);
			goto err_out;
		}

		ret = parse_port_from_ntuple(hw, filter, fsp, false);
		if (ret) {
			dev_err(dev, "fdir: Unsupported port setting, ret=%d\n", ret);
			goto err_out;
		}
	} else {
		ret = parse_addr_ipv4_from_ntuple(hw, filter, fsp);
		if (ret) {
			dev_err(dev, "fdir: fail - parse_addr_ipv4_from_ntuple(), ret=%d\n", ret);
			goto err_out;
		}

		ret = parse_port_from_ntuple(hw, filter, fsp, true);
		if (ret) {
			dev_err(dev, "fdir: Unsupported port setting, ret=%d\n", ret);
			goto err_out;
		}
	}

	ret = parse_flexbyte_from_ntuple_userdef(hw, filter, fsp, &userdef);
	if (ret) {
		dev_err(dev, "fdir: fail - parse_flexbyte_from_ntuple_userdef(), ret=%d\n", ret);
		goto err_out;
	}

	/* determine if we need to drop or route the packet */
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC)
		filter->is_action_drop = 1;
	else
		filter->is_action_drop = 0;

	filter->action_rxq_abs_id = rxq_rel_id + pf->lan_rxq_space_start;

	/* save fsp for later quick GET */
	memcpy(&filter->fs, fsp, sizeof(filter->fs));

	/* fill the missing part of filter stream and mask */
	filter->input_stream.vsi = vsi->vsi_abs_num;
	filter->input_stream_mask.vsi = 0xFF;

	filter->bkt_hash = nse_fdir_compute_bkt_hash(hw, &filter->input_stream,
						     &filter->input_stream_mask);
	if (cb->mode == FDIR_CTL_FILTER_MODE_SIGNATURE)
		filter->sig_hash = nse_fdir_compute_sig_hash(hw, &filter->input_stream,
							     &filter->input_stream_mask);

	mutex_lock(&cb->lock);

	/* check if new entry does not exist on filter list */
	if (match_existing_filter(cb, filter)) {
		dev_err(dev, "fdir: already exist this filter\n");
		ret = -EEXIST;
		goto err_out_w_lock;
	}

	nse_debug(hw, NSE_DBG_RCF, "[%s]: expected_vsi_hw_input_mask_info:\n", __func__);
	nse_debug(hw, NSE_DBG_RCF, "\t valid_reg_flex_cfg=%d\n",
		  filter->expected_vsi_hw_input_mask_info.valid_reg_flex_cfg);
	for (i = 0; i < 7; i++)
		nse_debug(hw, NSE_DBG_RCF, "\t valid_reg_mask[%d]=%d\n", i,
			  filter->expected_vsi_hw_input_mask_info.valid_reg_mask[i]);

	/* handle mask */
	if (hlist_empty(&cb->filter_list)) {
		memcpy(&cb->flex_setting, &userdef, sizeof(cb->flex_setting));

		/* save 0th filter's vsi_hw_input_mask and program into HW */
		memcpy(&cb->vsi_hw_input_mask_info, &filter->expected_vsi_hw_input_mask_info,
		       sizeof(cb->vsi_hw_input_mask_info));
		memcpy(&cb->vsi_hw_input_mask_info_tohw, &filter->expected_vsi_hw_input_mask_info,
		       sizeof(cb->vsi_hw_input_mask_info_tohw));

		/* apply vsi_hw_input_mask */
		ret = nse_fdir_set_input_mask(hw, vsi, &cb->vsi_hw_input_mask_info_tohw);
		if (ret) {
			dev_err(dev, "[%s, %d] fail writing mask, ret=%d\n",
				__func__, __LINE__, ret);
			goto err_out_w_lock;
		}

	} else {
		ret = add_update_vsi_hw_input_mask_info(hw,
					&filter->expected_vsi_hw_input_mask_info,
					&cb->vsi_hw_input_mask_info,
					&cb->vsi_hw_input_mask_info_tohw,
					&need_update_hw);

		if (ret) {
			dev_err(dev, "fdir: Hardware only supports one mask per VSP. To change the mask you must first delete all the rules.\n");
			ret = -EIO;
			goto err_out_w_lock;
		}

		if (need_update_hw) {
			/* update vsi_hw_input_mask */
			ret = nse_fdir_set_input_mask(hw, vsi, &cb->vsi_hw_input_mask_info_tohw);
			if (ret) {
				dev_err(dev, "[%s, %d] fail writing mask, ret=%d\n",
					__func__, __LINE__, ret);
				goto err_out_w_lock;
			}
		}

		/*  don't put into if(need_update_hw), because add_update_vsi_hw_input_mask_info()
		 * would change valid refcnt in merge_info
		 */
		memcpy(&cb->vsi_hw_input_mask_info, &cb->vsi_hw_input_mask_info_tohw,
		       sizeof(cb->vsi_hw_input_mask_info));
	}

	ret = nse_fdir_add_filter(hw, filter);
	if (ret) {
		dev_err(dev, "[%s, %d] fail add filter to HW, ret=%d\n",
			__func__, __LINE__, ret);
		goto err_out_w_lock;
	}

	del = false;
	memset(&del_hw_input_mask_info, 0, sizeof(del_hw_input_mask_info));

	ret = nse_fdir_update_ethtool_entry(hw, filter, filter->sw_idx,
					    &del, &del_hw_input_mask_info);

	/* only happens when adding a non-first rule and replacing a existing rule */
	if (!ret && del) {
		del_update_vsi_hw_input_mask_info(hw,
						  &del_hw_input_mask_info,
						  &cb->vsi_hw_input_mask_info,
						  &cb->vsi_hw_input_mask_info_tohw,
						  &need_update_hw);
		if (need_update_hw) {
			ret = nse_fdir_set_input_mask(hw, vsi, &cb->vsi_hw_input_mask_info_tohw);
			if (ret)
				dev_err(dev, "[%s, %d] fail writing mask, ret=%d\n",
					__func__, __LINE__, ret);
		}

		/* even fail, update SW-level info, maybe for later add or del rule retry */
		memcpy(&cb->vsi_hw_input_mask_info, &cb->vsi_hw_input_mask_info_tohw,
		       sizeof(cb->vsi_hw_input_mask_info));
	}

	mutex_unlock(&cb->lock);

	return 0;

err_out_w_lock:
	mutex_unlock(&cb->lock);

err_out:
	kfree(filter);

	return ret;
}

int nse_del_ethtool_ntuple(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	bool del = false;
	struct nse_fdir_vsi_hw_input_mask_info del_hw_input_mask_info;
	bool need_update_hw = false;
	int i = 0;
	int ret;

	memset(&del_hw_input_mask_info, 0, sizeof(del_hw_input_mask_info));

	mutex_lock(&cb->lock);

	/* give filter = NULL, would delete HW filter internnally */
	ret = nse_fdir_update_ethtool_entry(hw, NULL, fsp->location, &del, &del_hw_input_mask_info);

	if (!ret && del) {
		del_update_vsi_hw_input_mask_info(hw,
						  &del_hw_input_mask_info,
						  &cb->vsi_hw_input_mask_info,
						  &cb->vsi_hw_input_mask_info_tohw,
						  &need_update_hw);

		nse_debug(hw, NSE_DBG_RCF, "[%s]: del_hw_input_mask_info:", __func__);
		nse_debug(hw, NSE_DBG_RCF, "\t valid_reg_flex_cfg=%d\n",
			  del_hw_input_mask_info.valid_reg_flex_cfg);
		for (i = 0; i < 7; i++)
			nse_debug(hw, NSE_DBG_RCF, "\t valid_reg_mask[%d]=%d\n",
				  i, del_hw_input_mask_info.valid_reg_mask[i]);

		if (need_update_hw) {
			nse_debug(hw, NSE_DBG_RCF, "[%s]: update_hw input_mask\n", __func__);

			ret = nse_fdir_set_input_mask(hw, vsi, &cb->vsi_hw_input_mask_info_tohw);
			if (ret)
				dev_err(nse_pf_to_dev(pf),
					"[%s] fdir - error writing mask, ret=%d\n",
					__func__, ret);

			/* still return 0 to upper caller */
			ret = 0;
		}

		/* even fail, update SW-level info, maybe for later add or del rule retry */
		memcpy(&cb->vsi_hw_input_mask_info, &cb->vsi_hw_input_mask_info_tohw,
		       sizeof(cb->vsi_hw_input_mask_info));
	}

	mutex_unlock(&cb->lock);

	return ret;
}

int nse_get_ethtool_ntuple(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct hlist_node *node;
	struct nse_fdir_filter *f;
	int ret;

	/* report total rule count */
	cmd->data = (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT) ?
					(cb->max_num_pfilter_pf_vsi - 2) :
						(cb->max_num_sfilter_pf_vsi - 2);

	mutex_lock(&cb->lock);

	hlist_for_each_entry_safe(f, node,
				  &cb->filter_list, hnode) {
		if (fsp->location <= f->sw_idx)
			break;
	}

	if (!f || fsp->location != f->sw_idx) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(fsp, &f->fs, sizeof(*fsp));
	fsp->location = f->sw_idx;

	ret = 0;

out:
	mutex_unlock(&cb->lock);
	return ret;
}

int nse_get_ethtool_ntuple_ids(struct nse_vsi *vsi, struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct hlist_node *node;
	struct nse_fdir_filter *f;
	int cnt = 0;
	int ret;

	/* report total rule count */
	cmd->data = (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT) ?
					(cb->max_num_pfilter_pf_vsi - 2) :
						(cb->max_num_sfilter_pf_vsi - 2);

	mutex_lock(&cb->lock);

	hlist_for_each_entry_safe(f, node,
				  &cb->filter_list, hnode) {
		if (cnt == cmd->rule_cnt) {
			ret = -EMSGSIZE;
			goto out;
		}
		rule_locs[cnt] = f->sw_idx;
		cnt++;
	}

	ret = 0;

out:
	mutex_unlock(&cb->lock);

	return ret;
}

void nse_del_ethool_ntuple_all(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	struct hlist_node *node2;
	struct nse_fdir_filter *f = NULL;
	struct nse_vsi *vsi = nse_get_main_vsi(pf);

	mutex_lock(&cb->lock);

	/* perfect mode support flush all filter of a VSI */
	if (cb->mode == FDIR_CTL_FILTER_MODE_PERFECT)
		(void)nse_fdir_flush_vsi_perfect_filter(hw, vsi);

	hlist_for_each_entry_safe(f, node2,
				  &cb->filter_list, hnode) {
		if (cb->mode == FDIR_CTL_FILTER_MODE_SIGNATURE)
			(void)nse_fdir_del_filter(hw, f);

		hlist_del(&f->hnode);
		kfree(f);

		cb->filter_count--;
	}

	mutex_unlock(&cb->lock);
}

