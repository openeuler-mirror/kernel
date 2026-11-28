// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_sdf.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/jhash.h>
#include <linux/bitmap.h>
#include "sxe2_common.h"
#include "sxe2_cmd.h"
#include "sxe2_log.h"
#include "sxe2_fnav.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_arfs.h"
#include "sxe2_tx.h"

static s32 sxe2_sdf_en(struct sxe2_adapter *adapter, bool sdf_en)
{
	s32 ret = 0;
	struct sxe2_fwc_sdf_req      sdf_req = { 0 };
	struct sxe2_cmd_params       cmd    = { 0 };
	struct sxe2_sdf_ctxt       *sdf_ctxt = &adapter->sdf_ctxt;
	struct sxe2_vsi           *vsi    = adapter->vsi_ctxt.main_vsi;

	lockdep_assert_held(&adapter->vsi_ctxt.lock);

	if (!test_bit(SXE2_VSI_S_CLOSE, vsi->state)) {
		LOG_ERROR_BDF("sxe2 sdf need in stopped\n");
		ret = -EINVAL;
		goto l_end;
	}

	sdf_req.en = sdf_en;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SDF_EN,
				  &sdf_req, sizeof(sdf_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 sdf enable failed, ret=%d\n",
			      ret);
		ret = -EIO;
		goto l_end;
	}

	sdf_ctxt->en = sdf_en;

l_end:
	return ret;
}

static s32 sxe2_sdf_etype_set(struct sxe2_adapter *adapter, u16 eth_type, u16 mask)
{
	s32 ret = 0;
	struct sxe2_fwc_sdf_req    sdf_req = { 0 };
	struct sxe2_cmd_params     cmd    = { 0 };
	struct sxe2_sdf_ctxt      *sdf_ctxt = &adapter->sdf_ctxt;
	struct sxe2_vsi          *vsi     = adapter->vsi_ctxt.main_vsi;

	lockdep_assert_held(&adapter->vsi_ctxt.lock);

	if (!test_bit(SXE2_VSI_S_CLOSE, vsi->state)) {
		LOG_ERROR_BDF("sxe2 sdf need in stopped\n");
		ret = -EINVAL;
		goto l_end;
	}

	LOG_INFO_BDF("dump sdf set info, eth_type=[0x%x] mask=[0x%x]\n", eth_type, mask);

	sdf_req.eth_type = cpu_to_le16(eth_type);
	sdf_req.mask = cpu_to_le16(~mask);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_SDF_CFG_SET,
				  &sdf_req, sizeof(sdf_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 sdf enable failed, ret=%d\n",
			      ret);
		ret = -EIO;
		goto l_end;
	}

	sdf_ctxt->eth_type = eth_type;
	sdf_ctxt->mask = mask;

l_end:
	return ret;
}

s32 sxe2_sdf_etype_get(struct sxe2_adapter *adapter, u16 *eth_type, u16 *mask)
{
	s32 ret = 0;
	struct sxe2_sdf_ctxt     *sdf_ctxt = &adapter->sdf_ctxt;

	*eth_type = sdf_ctxt->eth_type;
	*mask = sdf_ctxt->mask;

	LOG_DEBUG_BDF("get sdf info, eth_type=[0x%x], mask=[0x%x]\n", *eth_type, *mask);

	return ret;
}

static s32 sxe2_sdf_fwc_update_profile(struct sxe2_adapter *adapter,
				       struct sxe2_sdf_flow_cfg *flow_cfg)
{
	s32 ret = 0;
	u16 data_end;
	u16 entry_cnt = 0;
	u16 buf_size = 0;
	u32 i = 0;
	struct sxe2_fwc_prof_pkg   *pkg       = NULL;
	struct sxe2_fwc_prof_buf   *buf       = NULL;
	struct sxe2_cmd_params     cmd       = { 0 };
	struct sxe2_fwc_es_entry   *entry_es   = NULL;
	struct sxe2_fwc_tcam_entry  *entry_tcam = NULL;
	struct device *dev	     = SXE2_ADAPTER_TO_DEV(adapter);

	entry_cnt = 2;
	buf_size += sizeof(struct sxe2_fwc_prof_buf);
	buf_size += sizeof(struct sxe2_fwc_tcam_entry);
	buf_size += sizeof(struct sxe2_fwc_es_entry);
	buf_size += (u16)flex_array_size(buf, sect, entry_cnt);

	if (buf_size > SXE2_OG_BUF_SIZE) {
		LOG_DEBUG_BDF("have no valid entry cnt(%u) or buf_size(%u)!\n",
			      entry_cnt, buf_size);
		ret = -EINVAL;
		goto l_out;
	}

	pkg = devm_kzalloc(dev, sizeof(struct sxe2_fwc_prof_pkg) + buf_size, GFP_KERNEL);
	if (!pkg) {
		LOG_ERROR_BDF("no memory!\n");
		ret = -ENOMEM;
		goto l_out;
	}

	pkg->blk = flow_cfg->blk;
	memset(pkg->buf, 0, buf_size);
	buf = (struct sxe2_fwc_prof_buf *)pkg->buf;

	data_end = offsetof(struct sxe2_fwc_prof_buf, sect);
	data_end += (u16)flex_array_size(buf, sect, entry_cnt);
	buf->data_end = cpu_to_le16(data_end);

	entry_tcam = (struct sxe2_fwc_tcam_entry *)sxe2_section_buf_alloc(buf,
		SXE2_TCAM_CLASS_ID, sizeof(struct sxe2_fwc_tcam_entry));
	if (!entry_tcam) {
		ret = -ENOSPC;
		goto l_out;
	}
	entry_tcam->addr = cpu_to_le16(flow_cfg->tcam_id);
	entry_tcam->prof_id = flow_cfg->prof_id;
	memcpy(entry_tcam->key, flow_cfg->key, SXE2_TCAM_KEY_LEN);
	for (i = 0; i < SXE2_TCAM_KEY_LEN; i++)
		LOG_DEBUG("\tkey[%d]: %u\n", i, entry_tcam->key[i]);

	entry_es = (struct sxe2_fwc_es_entry *)sxe2_section_buf_alloc(buf,
		SXE2_EXTRACTOR_CLASS_ID, sizeof(struct sxe2_fwc_es_entry));
	if (!entry_es) {
		ret = -ENOSPC;
		goto l_out;
	}
	entry_es->prof_id = flow_cfg->prof_id;
	entry_es->cnt = sxe2_blk_fv_cnt_get(flow_cfg->blk);
	for (i = 0; i < entry_es->cnt; i++) {
		entry_es->fv[i].prot_id = flow_cfg->fv[i].prot_id;
		entry_es->fv[i].off = cpu_to_le16(flow_cfg->fv[i].off);
		LOG_DEBUG("\tfv[%u], protocol: %u, off: %d\n",
			  i, flow_cfg->fv[i].prot_id, flow_cfg->fv[i].off);
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_OG_CFG_UPDATE, pkg,
				  sizeof(struct sxe2_fwc_prof_pkg) + buf_size, NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("og config cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

l_out:
	if (pkg)
		devm_kfree(dev, pkg);
	return ret;
}

static s32 sxe2_sdf_flow_tcam_key_get(struct sxe2_adapter *adapter,
				      struct sxe2_sdf_flow_cfg *flow_cfg)
{
	struct sxe2_prof_tcam_full_key full_key = { 0 };
	s32 ret = 0;
	u8 cdid = 0;
	u8 vl_mask[SXE2_TCAM_KEY_VAL_SZ] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	u8 dc_mask[SXE2_TCAM_KEY_VAL_SZ] = { 0xFF, 0xFF, 0xFF, 0x0F, 0x00 };
	u8 nm_mask[SXE2_TCAM_KEY_VAL_SZ] = { 0x00, 0x00, 0x00, 0x00, 0x00 };

	full_key.vsig = cpu_to_le16(SXE2_PPP_DEFAULT_VSIG_IDX & SXE2_FLOW_TCAM_FULL_KEY_MASK_VSIG);
	full_key.flg = cpu_to_le16(SXE2_TCAM_DEFAULT_FLAGS);
	full_key.ptg = flow_cfg->ptg_id;
	cdid = SXE2_TCAM_DEFAULT_CD_ID | adapter->port_idx;
	full_key.cdid = cdid & SXE2_FLOW_TCAM_FULL_KEY_MASK_CDID;

	ret = sxe2_flow_set_key(flow_cfg->key, SXE2_TCAM_KEY_SZ, (u8 *)&full_key,
				vl_mask, dc_mask, nm_mask, 0, SXE2_TCAM_KEY_SZ / 2);

	return ret;
}

static s32 sxe2_sdf_flow_fv_fill(struct sxe2_adapter *adapter, struct sxe2_sdf_flow_cfg *flow_cfg)
{
	s32 ret = 0;
	u16 fv_max_cnt = 0;
	u16 mac_fv_id = 0;
	u16 etype_fv_id = 0;
	u16 mac_fv_cnt = 1;

	fv_max_cnt = sxe2_blk_fv_cnt_get(flow_cfg->blk);

	if (flow_cfg->mask_id >= fv_max_cnt) {
		ret = -EINVAL;
		goto l_end;
	} else {
		mac_fv_id = flow_cfg->mask_id;
		etype_fv_id = mac_fv_id + mac_fv_cnt;
		if (etype_fv_id >= fv_max_cnt)
			etype_fv_id -= fv_max_cnt;
	}

	flow_cfg->fv[mac_fv_id].prot_id = SXE2_PROT_MAC_OF_OR_S;
	flow_cfg->fv[mac_fv_id].off = 0;

	flow_cfg->fv[etype_fv_id].prot_id = SXE2_PROT_ETYPE_OL;
	flow_cfg->fv[etype_fv_id].off = 0;

	flow_cfg->mac_fv_id = mac_fv_id;
	flow_cfg->etype_fv_id = etype_fv_id;

l_end:
	return ret;
}

static s32 sxe2_sdf_flow_create(struct sxe2_adapter *adapter, struct sxe2_sdf_flow_cfg *flow_cfg)
{
	s32 ret       = 0;
	u32 size      = 0;
	struct sxe2_fwc_tcam_idx_batch *tcam_batch = NULL;

	if (flow_cfg->ptg_cnt != 1) {
		LOG_ERROR_BDF("flow cfg is invalid, ptg_cnt=%d.\n", flow_cfg->ptg_cnt);
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_fwc_alloc_prof_id(adapter, flow_cfg->blk, &flow_cfg->prof_id);
	if (ret) {
		LOG_ERROR_BDF("failed to alloc new hw prof, ret:%d\n", ret);
		goto l_end;
	}

	ret = sxe2_fwc_alloc_mask_id(adapter, flow_cfg->blk, &flow_cfg->mask_id);
	if (ret) {
		LOG_ERROR_BDF("failed to alloc new hw mask, ret:%d\n", ret);
		goto l_prof_free;
	}

	ret = sxe2_sdf_flow_fv_fill(adapter, flow_cfg);
	if (ret) {
		LOG_ERROR_BDF("failed to alloc new hw mask, ret:%d\n", ret);
		goto l_mask_free;
	}

	size = sizeof(struct sxe2_fwc_tcam_idx_batch) + sizeof(struct sxe2_fwc_tcam_info);
	tcam_batch = kzalloc(size, GFP_KERNEL);
	if (!tcam_batch) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("failed to alloc new hw mask, ret:%d\n", ret);
		goto l_mask_free;
	}
	tcam_batch->blk = flow_cfg->blk;
	tcam_batch->tcam_cnt = cpu_to_le16(flow_cfg->ptg_cnt);
	tcam_batch->tcam_info[0].action = SXE2_FWC_TCAM_ACTION_ADD;
	ret = sxe2_fwc_process_tcam_batch(adapter, tcam_batch, size);
	if (ret) {
		LOG_ERROR_BDF("failed to alloc hw tcam, ret=%d\n", ret);
		goto l_mask_free;
	}
	flow_cfg->tcam_id = tcam_batch->tcam_info[0].tcam_idx;

	ret = sxe2_sdf_flow_tcam_key_get(adapter, flow_cfg);
	if (ret) {
		LOG_ERROR_BDF("get tcam key failed, ret=%d\n", ret);
		goto l_tcam_free;
	}

	ret = sxe2_fwc_update_mask(adapter, flow_cfg->blk,
				   flow_cfg->mask_id, flow_cfg->mask_id, flow_cfg->mask);
	if (ret != 0) {
		LOG_ERROR_BDF("failed to update hw mask, ret:%d\n", ret);
		goto l_tcam_free;
	}
	ret = sxe2_fwc_update_mask_sel(adapter, flow_cfg->blk,
				       flow_cfg->prof_id, BIT(flow_cfg->mask_id));
	if (ret != 0) {
		LOG_ERROR_BDF("failed to update hw mask sel, ret:%d\n", ret);
		goto l_tcam_free;
	}

	ret = sxe2_sdf_fwc_update_profile(adapter, flow_cfg);
	if (ret) {
		LOG_ERROR_BDF("failed to update profile, ret=%d\n", ret);
		goto l_tcam_free;
	}

	LOG_DEBUG_BDF("create sdf flow success, prof_id=%d, mask_id=%d, tcam_id=%d\n",
		      flow_cfg->prof_id, flow_cfg->mask_id, flow_cfg->tcam_id);

	goto l_end;

l_tcam_free:
	tcam_batch->blk = flow_cfg->blk;
	tcam_batch->tcam_cnt = cpu_to_le16(flow_cfg->ptg_cnt);
	tcam_batch->tcam_info[0].action = SXE2_FWC_TCAM_ACTION_DEL;
	(void)sxe2_fwc_process_tcam_batch(adapter, tcam_batch, size);
l_mask_free:
	(void)sxe2_fwc_free_mask_id(adapter, flow_cfg->blk, flow_cfg->mask_id);
l_prof_free:
	(void)sxe2_fwc_free_prof_id(adapter, flow_cfg->blk, flow_cfg->prof_id);
l_end:
	kfree(tcam_batch);
	return ret;
}

static void sxe2_sdf_fnav_filter_fill(struct sxe2_adapter *adapter,
				      struct sxe2_sdf_fnav_filter *filter, struct sxe2_sdf_flow_cfg  *flow_cfg,
				   struct sxe2_sdf_fnav_cfg *fnav_cfg)
{
	__be16 flex_val;
	__be16 eth_type;
	u8 *inputset = filter->inputset;
	u16 prof_id = flow_cfg->prof_id;

	filter->filter_loc = fnav_cfg->loc;
	filter->fdid_prio = SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_THREE;
	filter->q_index = fnav_cfg->dst_queue;
	filter->q_region = 0;
	filter->act_prio = SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_THREE;
	filter->ori_vsi_hw = fnav_cfg->vsi_id_hw;
	filter->dst_vsi_hw = fnav_cfg->vsi_id_hw;
	filter->act_type = SXE2_FNAV_ACT_QINDEX;
	filter->complete_report = SXE2_FNAV_TX_DESC_QW0_COMP_RPT_FAIL;
	filter->fd_space = SXE2_FNAV_FD_SPACE_FROM_BEST_EFFORT;
	filter->prof_id = prof_id;

	flex_val = fnav_cfg->flex_word;
	flex_val = flex_val & cpu_to_be16(fnav_cfg->flex_mask);
	eth_type = fnav_cfg->eth_type;

	memcpy(&inputset[(flow_cfg->mac_fv_id * 2)], &flex_val, SXE2_FLOW_FV_SIZE);
	memcpy(&inputset[(flow_cfg->etype_fv_id * 2)], &eth_type, SXE2_FLOW_FV_SIZE);
}

STATIC s32 sxe2_sdf_fwc_fnav_filter_update(struct sxe2_adapter *adapter,
					   struct sxe2_sdf_fnav_filter *filter,
				       bool is_add)
{
	s32 ret				    = 0;
	struct sxe2_cmd_params cmd	    = { 0 };
	struct sxe2_fwc_fnav_kt_resp kt_resp = {0};
	struct sxe2_fwc_fnav_kt_entry entry = { 0 };

	entry.is_add  = (u8)is_add;
	entry.prof_id = (u8)(filter->prof_id);
	entry.ori_vsi = cpu_to_le16(filter->ori_vsi_hw);
	memcpy(entry.inputset, filter->inputset, SXE2_FNAV_INPUT_CNT * SXE2_FLOW_FV_SIZE);
	entry.vsi     = cpu_to_le16(filter->dst_vsi_hw);
	entry.fdid    = cpu_to_le32(filter->filter_loc);
	entry.fdid_prio = filter->fdid_prio;
	entry.flow_id   = cpu_to_le16((u16)filter->flow_type);
	entry.toq_prio   = filter->act_prio;
	entry.drop    = filter->act_type == SXE2_FNAV_ACT_DROP ? 1 : 0;
	entry.qindex   = cpu_to_le16(filter->q_index);
	entry.to_queue  = filter->q_region;
	entry.fd_space  = filter->fd_space;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_FILTER_UPDATE, &entry,
				  sizeof(entry), &kt_resp, sizeof(kt_resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF(
			"update fnav filter failed, is_add:%d,  ret:%d\n", is_add, ret);
	} else {
		adapter->fnav_ctxt.space_bcnt = (u16)(le32_to_cpu(kt_resp.bcnt_global));
		adapter->fnav_ctxt.space_gcnt = (u16)(le32_to_cpu(kt_resp.gcnt_pf));
	}

	return ret;
}

STATIC struct sxe2_sdf_fnav_filter *
	sxe2_sdf_find_filter_by_loc(struct sxe2_adapter *adapter, u32 loc)
{
	struct sxe2_sdf_ctxt      *sdf_ctxt = &adapter->sdf_ctxt;
	struct sxe2_sdf_fnav_filter *filter_tmp  = NULL;
	struct sxe2_sdf_fnav_filter *filter_find = NULL;

	list_for_each_entry(filter_tmp, &sdf_ctxt->filter_list, l_node) {
		if (loc == filter_tmp->filter_loc) {
			filter_find = filter_tmp;
			break;
		}

		if (loc < filter_tmp->filter_loc)
			break;
	}

	return filter_find;
}

static s32 sxe2_sdf_fnav_filter_create(struct sxe2_adapter *adapter,
				       struct sxe2_sdf_fnav_cfg *fnav_cfg)
{
	s32 ret = 0;
	struct sxe2_sdf_fnav_filter *filter = NULL;
	struct sxe2_sdf_ctxt     *sdf_ctxt = &adapter->sdf_ctxt;
	struct sxe2_sdf_flow_cfg  *flow_cfg = &sdf_ctxt->flow_cfg;
	struct device         *dev   = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_sdf_fnav_filter *filter_tmp, *pre = NULL;

	filter = sxe2_sdf_find_filter_by_loc(adapter, fnav_cfg->loc);
	if (filter) {
		LOG_ERROR_BDF("has same loc=%d in filter list.\n", fnav_cfg->loc);
		ret = -EINVAL;
		goto l_end;
	}

	filter = devm_kzalloc(dev, sizeof(*filter), GFP_KERNEL);
	if (!filter) {
		LOG_ERROR_BDF("no memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	sxe2_sdf_fnav_filter_fill(adapter, filter, flow_cfg, fnav_cfg);

	ret = sxe2_sdf_fwc_fnav_filter_update(adapter, filter, true);
	if (ret) {
		devm_kfree(dev, filter);
		goto l_end;
	}

	list_for_each_entry(filter_tmp, &sdf_ctxt->filter_list, l_node) {
		if (filter_tmp->filter_loc >= filter->filter_loc)
			break;
		pre = filter_tmp;
	}
	if (pre)
		list_add(&filter->l_node, &pre->l_node);
	else
		list_add(&filter->l_node, &sdf_ctxt->filter_list);
	sdf_ctxt->filter_cnt++;

l_end:
	return ret;
}

static s32 sxe2_sdf_flow_destroy(struct sxe2_adapter *adapter, struct sxe2_sdf_flow_cfg *flow_cfg)
{
	s32 ret       = 0;
	u32 size      = 0;
	struct sxe2_fwc_tcam_idx_batch *tcam_batch = NULL;

	size = sizeof(struct sxe2_fwc_tcam_idx_batch) + sizeof(struct sxe2_fwc_tcam_info);
	tcam_batch = kzalloc(size, GFP_KERNEL);
	if (!tcam_batch) {
		ret = -ENOMEM;
		goto l_end;
	}
	tcam_batch->blk = flow_cfg->blk;
	tcam_batch->tcam_cnt = cpu_to_le16(flow_cfg->ptg_cnt);
	tcam_batch->tcam_info[0].action = SXE2_FWC_TCAM_ACTION_DEL;
	tcam_batch->tcam_info[0].tcam_idx = flow_cfg->tcam_id;
	ret = sxe2_fwc_process_tcam_batch(adapter, tcam_batch, size);
	if (ret) {
		LOG_ERROR_BDF("failed to free tcam_id=%d failed, ret=%d\n", flow_cfg->tcam_id, ret);
		goto l_end;
	}

	ret = sxe2_fwc_free_mask_id(adapter, flow_cfg->blk, flow_cfg->mask_id);
	if (ret) {
		LOG_ERROR_BDF("failed to free hw mask_id=%d, ret:%d\n", flow_cfg->mask_id, ret);
		goto l_end;
	}

	ret = sxe2_fwc_free_prof_id(adapter, flow_cfg->blk, flow_cfg->prof_id);
	if (ret) {
		LOG_ERROR_BDF("failed to free hw prof_id=%d, ret:%d\n", flow_cfg->prof_id, ret);
		goto l_end;
	}

	LOG_DEBUG_BDF("destroy sdf flow success, prof_id=%d, mask_id=%d, tcam_id=%d\n",
		      flow_cfg->prof_id, flow_cfg->mask_id, flow_cfg->tcam_id);

l_end:
	kfree(tcam_batch);
	return ret;
}

STATIC s32 sxe2_sdf_fnav_rule_add(struct sxe2_adapter *adapter, struct sxe2_sdf_fnav_cfg *fnav_cfg)
{
	s32 ret = 0;
	struct sxe2_sdf_ctxt     *sdf_ctxt = &adapter->sdf_ctxt;
	struct sxe2_sdf_flow_cfg  *flow_cfg = &sdf_ctxt->flow_cfg;

	if (!flow_cfg->used) {
		flow_cfg->blk = SXE2_HW_BLOCK_ID_FNAV;
		flow_cfg->mask = fnav_cfg->flex_mask;
		flow_cfg->ptg_id = SXE2_SDF_PTG_ID;
		flow_cfg->ptg_cnt = SXE2_SDF_PTG_CNT;
		ret = sxe2_sdf_flow_create(adapter, flow_cfg);
		if (ret) {
			LOG_ERROR_BDF("sxe2 sdf flow create failed, ret = %d.\n", ret);
			goto l_end;
		}
		flow_cfg->used = true;
	}

	ret = sxe2_sdf_fnav_filter_create(adapter, fnav_cfg);
	if (ret) {
		LOG_ERROR_BDF("sxe2 sdf filter create failed, ret = %d.\n", ret);
		if (sdf_ctxt->filter_cnt == 0) {
			(void)sxe2_sdf_flow_destroy(adapter, flow_cfg);
			flow_cfg->used = false;
		}
	}

l_end:
	return ret;
}

static s32 sxe2_sdf_fnav_filter_destroy(struct sxe2_adapter *adapter, u16 loc)
{
	s32 ret = 0;
	struct sxe2_sdf_fnav_filter *filter = NULL;
	struct sxe2_sdf_ctxt     *sdf_ctxt = &adapter->sdf_ctxt;
	struct device          *dev   = SXE2_ADAPTER_TO_DEV(adapter);

	filter = sxe2_sdf_find_filter_by_loc(adapter, loc);
	if (!filter) {
		LOG_ERROR_BDF("failed to find loc=%d filter.\n", loc);
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_sdf_fwc_fnav_filter_update(adapter, filter, false);
	if (ret) {
		LOG_ERROR_BDF("sxe2 sdf filter destroy failed, ret = %d.\n", ret);
		goto l_end;
	}

	sdf_ctxt->filter_cnt--;
	list_del(&filter->l_node);
	devm_kfree(dev, filter);

l_end:
	return ret;
}

STATIC s32 sxe2_sdf_fnav_rule_del(struct sxe2_adapter *adapter, u16 rule_loc)
{
	s32 ret = 0;
	struct sxe2_sdf_ctxt     *sdf_ctxt = &adapter->sdf_ctxt;
	struct sxe2_sdf_flow_cfg  *flow_cfg = &sdf_ctxt->flow_cfg;

	ret = sxe2_sdf_fnav_filter_destroy(adapter, rule_loc);
	if (ret)
		LOG_ERROR_BDF("sxe2 sdf filter destroy failed, ret = %d.\n", ret);

	if (sdf_ctxt->filter_cnt == 0 && flow_cfg->used) {
		ret = sxe2_sdf_flow_destroy(adapter, flow_cfg);
		if (ret) {
			LOG_ERROR_BDF("sxe2 sdf flow create failed, ret = %d.\n", ret);
			goto l_end;
		}
		memset(flow_cfg, 0, sizeof(struct sxe2_sdf_flow_cfg));
		flow_cfg->used = false;
	}

l_end:
	return ret;
}

void sxe2_sdf_clear_cfg(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_sdf_ctxt      *sdf_ctxt = &adapter->sdf_ctxt;
	struct sxe2_sdf_fnav_filter  *filter, *tmp;

	if (sdf_ctxt->filter_cnt == 0)
		return;

	list_for_each_entry_safe(filter, tmp, &sdf_ctxt->filter_list, l_node) {
		ret = sxe2_sdf_fnav_rule_del(adapter, filter->filter_loc);
		if (ret)
			LOG_ERROR_BDF("sdf fnav filter delete failed, loc=%u, ret:%d\n",
				      filter->filter_loc, ret);
	}
}

void sxe2_sdf_ctxt_init(struct sxe2_adapter *adapter)
{
	struct sxe2_sdf_ctxt *sdf_ctxt = &adapter->sdf_ctxt;

	memset(sdf_ctxt, 0, sizeof(struct sxe2_sdf_ctxt));

	INIT_LIST_HEAD(&sdf_ctxt->filter_list);
}

void sxe2_sdf_ctxt_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_sdf_ctxt *sdf_ctxt = &adapter->sdf_ctxt;

	sxe2_sdf_clear_cfg(adapter);

	memset(sdf_ctxt, 0, sizeof(struct sxe2_sdf_ctxt));
}

void sxe2_sdf_open_test(struct sxe2_adapter *adapter)
{
	s32 ret    = 0;
	u16 etype   = 0xfc00;
	u16 mask    = 0xFF22;
	struct sxe2_vsi       *vsi     = adapter->vsi_ctxt.main_vsi;
	struct sxe2_sdf_fnav_cfg fnav_cfg  = {0};
	u16 cpu_core = 0x19;

	mutex_lock(&adapter->vsi_ctxt.lock);

	ret = sxe2_sdf_en(adapter, true);

	ret = sxe2_sdf_etype_set(adapter, etype, mask);

	fnav_cfg.vsi_id_hw = vsi->idx_in_dev;

	fnav_cfg.dst_queue     = 2;
	fnav_cfg.flex_offset   = 0;
	fnav_cfg.flex_mask     = 0xFE00;
	fnav_cfg.flex_word     = cpu_to_le16(cpu_core << 1);
	fnav_cfg.eth_type      = cpu_to_be16(etype);
	fnav_cfg.loc          = 0;

	ret = sxe2_sdf_fnav_rule_add(adapter, &fnav_cfg);
	if (ret) {
		LOG_ERROR_BDF("sxe2 sdf flow create failed, ret = %d.\n", ret);
		goto l_end;
	}

	fnav_cfg.dst_queue     = 3;
	fnav_cfg.flex_offset   = 0;
	fnav_cfg.flex_mask     = 0xFE00;
	fnav_cfg.flex_word     = cpu_to_le16(((u16)0x4b) << 1);
	fnav_cfg.eth_type      = cpu_to_be16(0xfcdd);
	fnav_cfg.loc          = 1;

	ret = sxe2_sdf_fnav_rule_add(adapter, &fnav_cfg);
	if (ret)
		LOG_ERROR_BDF("sxe2 sdf flow create failed, ret = %d.\n", ret);

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

void sxe2_sdf_close_test(struct sxe2_adapter *adapter)
{
	mutex_lock(&adapter->vsi_ctxt.lock);

	(void)sxe2_sdf_en(adapter, false);

	sxe2_sdf_clear_cfg(adapter);

	mutex_unlock(&adapter->vsi_ctxt.lock);
}

