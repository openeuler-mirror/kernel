// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_acl.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "linux/device.h"
#include "linux/list.h"
#include "linux/mutex.h"
#include "linux/slab.h"
#include "sxe2.h"
#include "sxe2_acl.h"
#include "sxe2_log.h"
#include "sxe2_common.h"
#include "sxe2_flow_public.h"
#include "sxe2_ethtool.h"
#include "sxe2_vsi.h"

s32 sxe2_fwc_acl_trace_trigger(struct sxe2_adapter *adapter)
{
	struct sxe2_cmd_params cmd = {0};
	s32 ret = 0;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_TRACE_TRIGGER, NULL, 0, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("acl trace trigger cmd fail, ret=%d", ret);

	return ret;
}

STATIC void sxe2_acl_trace_hit_info_print(struct sxe2_acl_hit_info *hit_info)
{
	LOG_INFO("profile_id: %u\n", hit_info->profile_id);
	LOG_INFO("fv 0-3 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv0, hit_info->fv1,
		 hit_info->fv2, hit_info->fv3);
	LOG_INFO("fv 4-7 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv4, hit_info->fv5,
		 hit_info->fv6, hit_info->fv7);
	LOG_INFO("fv 8-11 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv8, hit_info->fv9,
		 hit_info->fv10, hit_info->fv11);
	LOG_INFO("fv 12-15 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv12, hit_info->fv13,
		 hit_info->fv14, hit_info->fv15);
	LOG_INFO("fv 16-19 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv16, hit_info->fv17,
		 hit_info->fv18, hit_info->fv19);
	LOG_INFO("fv 20-23 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv20, hit_info->fv21,
		 hit_info->fv22, hit_info->fv23);
	LOG_INFO("fv 24-27 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv24, hit_info->fv25,
		 hit_info->fv26, hit_info->fv27);
	LOG_INFO("fv 28-31 0x%x 0x%x 0x%x 0x%x\n", hit_info->fv28, hit_info->fv29,
		 hit_info->fv30, hit_info->fv31);
}

s32 sxe2_fwc_acl_trace_recorder(struct sxe2_adapter *adapter)
{
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_acl_trace_recorder recorder = {0};
	s32 ret = 0;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_TRACE_RECORDER, NULL, 0, &recorder,
				  sizeof(struct sxe2_acl_trace_recorder));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("acl trace recorder cmd fail, ret %d", ret);
		goto l_end;
	}

	LOG_INFO("****acl trace recorder start****\n");
	LOG_INFO("status0: %u\n", recorder.trace_status0);
	if (recorder.trace_status0 == 0)
		sxe2_acl_trace_hit_info_print(&recorder.hit_info);

	LOG_INFO("****acl trace recorder end****\n");
l_end:
	return ret;
}

STATIC void sxe2_acl_dfx_info_print(struct sxe2_acl_dfx_info *dfx_info)
{
	s32 i = 0;

	if (!dfx_info) {
		LOG_INFO("Error: dfx_info is NULL\n");
		return;
	}

	LOG_INFO("===== ACL DFX Info =====\n");
	LOG_INFO("\n--- Statistics ---\n");
	LOG_INFO("og_inbuf_hdr_cnt:      %u\n", le32_to_cpu(dfx_info->og_inbuf_hdr_cnt));
	LOG_INFO("og_inbuf_info_cnt:     %u\n", le32_to_cpu(dfx_info->og_inbuf_info_cnt));
	LOG_INFO("og_proc_hdr_cnt:       %u\n", le32_to_cpu(dfx_info->og_proc_hdr_cnt));
	LOG_INFO("og_proc_info_cnt:      %u\n", le32_to_cpu(dfx_info->og_proc_info_cnt));
	LOG_INFO("og_to_engine_cnt:      %u\n", le32_to_cpu(dfx_info->og_to_engine_cnt));
	LOG_INFO("og_in_rg_cnt:          %u\n", le32_to_cpu(dfx_info->og_in_rg_cnt));
	LOG_INFO("og_out_rg_cnt:         %u\n", le32_to_cpu(dfx_info->og_out_rg_cnt));
	LOG_INFO("sel_base_cnt:          %u\n", le32_to_cpu(dfx_info->sel_base_cnt));
	LOG_INFO("key_gen_cnt:           %u\n", le32_to_cpu(dfx_info->key_gen_cnt));
	LOG_INFO("key_gen_to_lkt_cnt:    %u\n",
		 le32_to_cpu(dfx_info->key_gen_to_lkt_cnt));
	LOG_INFO("act_mem_cnt:           %u\n", le32_to_cpu(dfx_info->act_mem_cnt));
	LOG_INFO("osc_act_cnt:           %u\n", le32_to_cpu(dfx_info->osc_act_cnt));
	LOG_INFO("osc_pkt_cnt:           %u\n", le32_to_cpu(dfx_info->osc_pkt_cnt));
	LOG_INFO("acl_rxft_cnt:          %u\n", le32_to_cpu(dfx_info->acl_rxft_cnt));
	LOG_INFO("acl_recv_drop_cnt:     %u\n", le32_to_cpu(dfx_info->acl_recv_drop_cnt));
	LOG_INFO("acl_action_drop_cnt:   %u\n",
		 le32_to_cpu(dfx_info->acl_action_drop_cnt));
	LOG_INFO("acl_vsi_disable_drop_cnt: %u\n",
		 le32_to_cpu(dfx_info->acl_vsi_disable_drop_cnt));
	LOG_INFO("prfl_tcam_hit_cnt:     %u\n", le32_to_cpu(dfx_info->prfl_tcam_hit_cnt));
	LOG_INFO("prfl_tcam_miss_cnt:    %u\n",
		 le32_to_cpu(dfx_info->prfl_tcam_miss_cnt));
	LOG_INFO("prfl_tcam_bypss_cnt:   %u\n",
		 le32_to_cpu(dfx_info->prfl_tcam_bypss_cnt));

	LOG_INFO("\n--- TCAM Hit/Miss Count ---\n");
	for (i = 0; i < SXE2_ACL_ACTION_TCAM_CNT; i++) {
		LOG_INFO("act_tcam_hit_cnt[%d]:   %u\n", i,
			 le32_to_cpu(dfx_info->act_tcam_hit_cnt[i]));
		LOG_INFO("act_tcam_miss_cnt[%d]:  %u\n", i,
			 le32_to_cpu(dfx_info->act_tcam_miss_cnt[i]));
	}

	LOG_INFO("\n--- ACL DFX ---\n");
	for (i = 0; i < SXE2_ACL_ACTION_TCAM_CNT; i++) {
		LOG_INFO("act_idx_first[%d]:       %u\n", i,
			 le16_to_cpu(dfx_info->act_idx_first[i]));
		LOG_INFO("act_idx_last[%d]:        %u\n", i,
			 le16_to_cpu(dfx_info->act_idx_last[i]));
		LOG_INFO("act_key_first_low[%d]:   0x%x\n", i,
			 le32_to_cpu(dfx_info->act_key_first_low[i]));
		LOG_INFO("act_key_first_high[%d]:  0x%x\n", i,
			 le32_to_cpu(dfx_info->act_key_first_high[i]));
		LOG_INFO("act_key_last_low[%d]:    0x%x\n", i,
			 le32_to_cpu(dfx_info->act_key_last_low[i]));
		LOG_INFO("act_key_last_high[%d]:   0x%x\n", i,
			 le32_to_cpu(dfx_info->act_key_last_high[i]));
	}

	LOG_INFO("key_first:             0x%llx\n", le64_to_cpu(dfx_info->key_first));
	LOG_INFO("key_last:              0x%llx\n", le64_to_cpu(dfx_info->key_last));

	LOG_INFO("\n--- IDs and Indexes ---\n");
	LOG_INFO("first_prfl_id:         %u\n", dfx_info->first_prfl_id);
	LOG_INFO("last_prfl_id:          %u\n", dfx_info->last_prfl_id);
	LOG_INFO("first_scen_id:         %u\n", dfx_info->first_scen_id);
	LOG_INFO("last_scen_id:          %u\n", dfx_info->last_scen_id);
	LOG_INFO("first_prfl_tcam_idx:   %u\n",
		 le16_to_cpu(dfx_info->first_prfl_tcam_idx));
	LOG_INFO("last_prfl_tcam_idx:    %u\n",
		 le16_to_cpu(dfx_info->last_prfl_tcam_idx));

	LOG_INFO("\n--- Flags ---\n");
	LOG_INFO("first_cascade:         %u\n", dfx_info->first_cascade);
	LOG_INFO("last_cascade:          %u\n", dfx_info->last_cascade);
	LOG_INFO("first_stack:           %u\n", dfx_info->first_stack);
	LOG_INFO("last_stack:            %u\n", dfx_info->last_stack);
	LOG_INFO("first_tcam_en:         %u\n", dfx_info->first_tcam_en);
	LOG_INFO("last_tcam_en:          %u\n", dfx_info->last_tcam_en);

	LOG_INFO("========================\n");
}

s32 sxe2_fwc_acl_dfx_get(struct sxe2_adapter *adapter)
{
	struct sxe2_acl_dfx_info dfx_info = {0};
	struct sxe2_cmd_params cmd = {0};
	s32 ret = 0;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_DFX_INFO_GET, NULL, 0, &dfx_info,
				  sizeof(struct sxe2_acl_dfx_info));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("acl dfx info get cmd fail, ret %d", ret);
		goto l_end;
	}
	sxe2_acl_dfx_info_print(&dfx_info);

l_end:
	return ret;
}

s32 sxe2_fwc_acl_set_scen_prof(struct sxe2_adapter *adapter,
			       struct sxe2_fwc_acl_prof_sel_base_req *prof_sel_req)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_PROF_SEL_BASE_SET, prof_sel_req,
				  sizeof(*prof_sel_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to set acl profile, ret=%d", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_acl_lut_alloc(struct sxe2_adapter *adapter,
				  struct sxe2_acl_tbl_params *tbl_params,
				  struct sxe2_acl_tbl_info *acl_tbl_info)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_lut_alloc_req acl_lut_alloc_req = {0};
	struct sxe2_fwc_acl_lut_alloc_resp acl_lut_alloc_resp = {0};
	u8 i = 0;

	acl_lut_alloc_req.width = cpu_to_le16(tbl_params->width);
	acl_lut_alloc_req.depth = cpu_to_le16(tbl_params->depth);
	acl_lut_alloc_req.act_pairs_per_entry = tbl_params->entry_act_pairs;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_LUT_ALLOC, &acl_lut_alloc_req,
				  sizeof(acl_lut_alloc_req), &acl_lut_alloc_resp,
				  sizeof(acl_lut_alloc_resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to add acl entry, ret=%d\n", ret);
		goto l_end;
	}

	acl_tbl_info->id = le16_to_cpu(acl_lut_alloc_resp.alloc_id);
	acl_tbl_info->first_tcam = acl_lut_alloc_resp.first_tcam;
	acl_tbl_info->last_tcam = acl_lut_alloc_resp.last_tcam;
	acl_tbl_info->first_entry = le16_to_cpu(acl_lut_alloc_resp.first_entry);
	acl_tbl_info->last_entry = le16_to_cpu(acl_lut_alloc_resp.last_entry);

	acl_tbl_info->table_info.width = tbl_params->width;
	acl_tbl_info->table_info.depth = tbl_params->depth;
	acl_tbl_info->table_info.entry_act_pairs = tbl_params->entry_act_pairs;

	for (i = 0; i < SXE2_ACL_ACTION_MEM_CNT; i++) {
		acl_tbl_info->act_mems[i].act_mem = acl_lut_alloc_resp.act_mem[i];
		LOG_DEBUG_BDF("dump acl entry msg,act_mems[%u]:%u\n", i,
			      acl_tbl_info->act_mems[i].act_mem);
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_acl_qvsi_map_set(struct sxe2_adapter *adapter, u16 act_entry_idx, u16 vsi_num)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_qvsi_map_req req = {0};

	if (!test_bit(SXE2_FLAG_ACL_EXT_CAPABLE, adapter->flags))
		return -EOPNOTSUPP;

	req.act_entry_idx = cpu_to_le16(act_entry_idx);
	req.vsi_num = cpu_to_le16(vsi_num);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_QVSI_MAP_SET, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to set acl qvsi map, ret=%d\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_acl_lut_dealloc(struct sxe2_adapter *adapter, u16 alloc_id)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_lut_dealloc_req act_lut_dealloc_req = {0};

	act_lut_dealloc_req.alloc_id = cpu_to_le16(alloc_id);
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_LUT_DEALLOC, &act_lut_dealloc_req,
				  sizeof(act_lut_dealloc_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to dealloc acl lut, ret=%d", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_acl_act_entry(struct sxe2_adapter *adapter, u8 act_mem_idx,
				  u16 act_entry_idx,
				  struct sxe2_acl_act_entry_data *act_entry_data, u8 act_cnt)
{
	s32 ret = 0;
	s32 i = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_act_entry_set_req act_entry_req = {};

	act_entry_req.act_mem_idx = act_mem_idx;
	act_entry_req.act_entry_idx = cpu_to_le16(act_entry_idx);

	for (i = 0; i < act_cnt && i < SXE2_ACL_ACTION_NUM_PER_ENTRY; i++) {
		act_entry_req.data[i].prio = act_entry_data[i].prio;
		act_entry_req.data[i].mdid = act_entry_data[i].mdid;
		act_entry_req.data[i].value = cpu_to_le16(act_entry_data[i].value);
	}
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_ACT_ENTRY_SET, &act_entry_req,
				  sizeof(act_entry_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to add acl entry, ret=%d\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_acl_lut_entry(struct sxe2_adapter *adapter, u8 tcam_idx,
				  u16 entry_idx,
				  struct sxe2_acl_entry_data *lut_entry_data)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_lut_entry_set_req acl_lut_entry_req;

	acl_lut_entry_req.tcam_idx = tcam_idx;
	acl_lut_entry_req.entry_idx = cpu_to_le16(entry_idx);
	acl_lut_entry_req.data = *lut_entry_data;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_LUT_ENTRY_SET, &acl_lut_entry_req,
				  sizeof(acl_lut_entry_req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to add acl entry, ret=%d\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_acl_scen_alloc(struct sxe2_adapter *adapter,
				   struct sxe2_fwc_acl_scen_alloc_req *req, u16 *scen_id)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_scen_alloc_resp act_scen_alloc_rsp = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_SCEN_ALLOC, req, sizeof(*req),
				  &act_scen_alloc_rsp, sizeof(act_scen_alloc_rsp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to alloc scen, ret=%d\n", ret);
		goto l_end;
	}

	*scen_id = le16_to_cpu(act_scen_alloc_rsp.scen_id);

	LOG_DEBUG_BDF("acl scen alloc id:%u\n", *scen_id);

l_end:
	return ret;
}

STATIC s32 sxe2_fwc_acl_scen_dealloc(struct sxe2_adapter *adapter, u16 scen_id)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_scen_dealloc_req act_scen_dealloc_req = {0};

	act_scen_dealloc_req.scen_id = cpu_to_le16(scen_id);
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_SCEN_DEALLOC, &act_scen_dealloc_req,
				  sizeof(act_scen_dealloc_req), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("Failed to dealloc scen, ret=%d\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

struct sxe2_acl_flow_cfg *
sxe2_acl_find_flow_cfg_by_flow_type(struct sxe2_vsi *vsi,
				    enum sxe2_fnav_flow_type flow_type)
{
	struct sxe2_acl_flow_cfg *flow_cfg = NULL;
	struct sxe2_acl_flow_cfg *flow_cfg_find = NULL;

	list_for_each_entry(flow_cfg, &vsi->acl.flow_cfg_list, l_node) {
		if (flow_type == flow_cfg->flow_type) {
			flow_cfg_find = flow_cfg;
			break;
		}
		if (flow_type < flow_cfg->flow_type)
			break;
	}

	return flow_cfg_find;
}

void sxe2_acl_flow_cfg_add_list(struct sxe2_vsi *vsi, struct sxe2_acl_flow_cfg *flow_cfg)
{
	struct sxe2_acl_flow_cfg *flow_tmp;
	struct sxe2_vsi_acl *vsi_acl = &vsi->acl;
	struct list_head *head = &vsi_acl->flow_cfg_list;

	list_for_each_entry(flow_tmp, head, l_node) {
		if (flow_tmp->flow_type == flow_cfg->flow_type)
			return;

		if (flow_tmp->flow_type > flow_cfg->flow_type) {
			list_add_tail(&flow_cfg->l_node, &flow_tmp->l_node);
			return;
		}
	}

	list_add_tail(&flow_cfg->l_node, head);
}

STATIC s32 sxe2_acl_add_act(struct sxe2_adapter *adapter, struct sxe2_acl_scen_info *scen,
			    u16 entry_idx, struct sxe2_acl_act_entry_data *act_entry_data,
			    u8 act_cnt)
{
	s32 ret = -EINVAL;
	struct sxe2_acl_tbl_info *acl_tbl_info = adapter->acl_ctxt.acl_tbl_info;
	struct sxe2_acl_act_mem *act_mem = NULL;
	u16 cnt_cascade, first_tcam_id, last_tcam_id;
	u16 line_in_mem;
	u16 i = 0;

	line_in_mem = entry_idx % SXE2_FW_ACL_TCAM_DEPTH;
	cnt_cascade = DIV_ROUND_UP(scen->width, SXE2_FW_ACL_KEY_WIDTH_BYTES);
	first_tcam_id = (scen->start / SXE2_FW_ACL_TCAM_DEPTH) +
		(entry_idx / SXE2_FW_ACL_TCAM_DEPTH) * cnt_cascade;
	last_tcam_id = first_tcam_id + cnt_cascade;

	for_each_set_bit(i, scen->acl_act_mem_bitmap, SXE2_FW_MAX_ACTION_MEMORIES) {
		act_mem = &acl_tbl_info->act_mems[i];
		if (act_mem->member_of_tcam >= first_tcam_id &&
		    act_mem->member_of_tcam < last_tcam_id) {
			ret = sxe2_fwc_acl_act_entry(adapter, i, line_in_mem,
						     act_entry_data, act_cnt);
			if (ret) {
				LOG_ERROR_BDF("Acl add flow act entry cmd failed, ret:%d\n", ret);
				goto l_end;
			}
		}
	}

l_end:
	return ret;
}

STATIC void
sxe2_acl_assign_act_mems_res_to_tcams(struct sxe2_acl_tbl_info *acl_table_info,
				      u8 cur_tcam_idx, u8 *cur_mem_idx, u8 num_mem)
{
	u8 i = 0;
	struct sxe2_acl_act_mem *act_mem = NULL;

	for (i = 0; *cur_mem_idx < SXE2_FW_MAX_ACTION_MEMORIES && i < num_mem;
	     (*cur_mem_idx)++) {
		act_mem = &acl_table_info->act_mems[*cur_mem_idx];

		if (act_mem->act_mem == 0xff)
			continue;

		act_mem->member_of_tcam = cur_tcam_idx;
		i++;
	}
}

STATIC void
sxe2_acl_divide_act_mems_res_to_tcams(struct sxe2_acl_tbl_info *acl_table_info)
{
	u16 num_depth = 0;
	u16 num_width = 0;
	u8 act_mem = 0;
	u8 act_mem_remainder = 0;
	u16 i = 0;
	u16 j = 0;
	u16 total_act_mem = 0;
	u8 tcam_idx = 0;
	u8 current_mem_idx = 0;

	num_depth = DIV_ROUND_UP(acl_table_info->table_info.depth,
				 SXE2_FW_ACL_TCAM_DEPTH);
	num_width = DIV_ROUND_UP(acl_table_info->table_info.width,
				 SXE2_FW_ACL_KEY_WIDTH_BYTES);

	act_mem = acl_table_info->table_info.entry_act_pairs / num_width;
	act_mem_remainder = acl_table_info->table_info.entry_act_pairs % num_width;

	tcam_idx = acl_table_info->first_tcam;
	for (i = 0; i < num_depth; i++) {
		for (j = 0; j < num_width; j++) {
			total_act_mem = act_mem;
			if (j < act_mem_remainder)
				total_act_mem += 1;

			sxe2_acl_assign_act_mems_res_to_tcams(acl_table_info, tcam_idx,
							      &current_mem_idx,
							      total_act_mem);
			tcam_idx++;
		}
	}
}

STATIC s32 sxe2_acl_create_table(struct sxe2_adapter *adapter,
				 struct sxe2_acl_tbl_params *params)
{
	s32 ret = 0;
	u16 width = 0;
	u16 depth = 0;
	struct sxe2_acl_tbl_params tbl_params = {0};
	struct sxe2_acl_tbl_info *acl_tbl_info = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 first_entry_in_pf = 0;
	u16 last_entry_in_pf = 0;
	u16 i = 0;
	u16 num_cascades;
	u16 num_stacks;

	width = (u16)roundup((s32)params->width, SXE2_FW_ACL_KEY_WIDTH_BYTES);
	depth = ALIGN(params->depth, SXE2_ACL_ENTRY_ALLOC_UNIT);

	if (params->entry_act_pairs < width / SXE2_FW_ACL_KEY_WIDTH_BYTES) {
		params->entry_act_pairs = (u8)(width / SXE2_FW_ACL_KEY_WIDTH_BYTES);

		if (params->entry_act_pairs > SXE2_AQC_TBL_MAX_ACTION_PAIRS)
			params->entry_act_pairs = SXE2_AQC_TBL_MAX_ACTION_PAIRS;
	}

	num_cascades = width / SXE2_FW_ACL_KEY_WIDTH_BYTES;
	num_stacks = DIV_ROUND_UP(depth, SXE2_FW_ACL_TCAM_DEPTH);
	if (num_stacks * num_cascades > SXE2_FW_ACL_LUT_NUM) {
		LOG_ERROR_BDF("Requested ACL exceeds hardware limit (Total TCAMs needed: %u).\n",
			      num_cascades * num_stacks);
		ret = -ENOSPC;
		goto l_end;
	}

	memset(&tbl_params, 0, sizeof(tbl_params));
	tbl_params.depth = depth;
	tbl_params.width = width;
	tbl_params.entry_act_pairs = params->entry_act_pairs;

	acl_tbl_info = devm_kzalloc(dev, sizeof(*acl_tbl_info), GFP_KERNEL);
	if (!acl_tbl_info) {
		LOG_ERROR_BDF("Failed to alloc acl tbl info.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	ret = sxe2_fwc_acl_lut_alloc(adapter, &tbl_params, acl_tbl_info);
	if (ret) {
		LOG_ERROR_BDF("acl table create cmd fail, ret:%d.\n", ret);
		goto l_free_acl_tbl_info;
	}

	sxe2_acl_divide_act_mems_res_to_tcams(acl_tbl_info);

	first_entry_in_pf = acl_tbl_info->first_tcam * SXE2_FW_MAX_TCAM_ALLOC_UNITS +
			    acl_tbl_info->first_entry / SXE2_ACL_ENTRY_ALLOC_UNIT;
	last_entry_in_pf = acl_tbl_info->last_tcam * SXE2_FW_MAX_TCAM_ALLOC_UNITS +
			   acl_tbl_info->last_entry / SXE2_ACL_ENTRY_ALLOC_UNIT;

	for (i = first_entry_in_pf; i < last_entry_in_pf + 1; i++)
		set_bit(i, acl_tbl_info->avail);

	acl_tbl_info->max_slot_cnt = depth;

	INIT_LIST_HEAD(&acl_tbl_info->scens);

	adapter->acl_ctxt.acl_tbl_info = acl_tbl_info;
	ret = 0;
	goto l_end;

l_free_acl_tbl_info:
	adapter->acl_ctxt.acl_tbl_info = NULL;
	devm_kfree(dev, acl_tbl_info);
	ret = -ENOMEM;
l_end:
	return ret;
}

STATIC void sxe2_acl_tbl_param_calc(struct sxe2_adapter *adapter,
				    struct sxe2_acl_tbl_params *params)
{
	u8 pf_cnt = adapter->pf_cnt;

	if (pf_cnt <= 0 || pf_cnt > 4)
		pf_cnt = 4;

	params->width = SXE2_FW_ACL_KEY_WIDTH_BYTES * SXE2_ACL_MAX_CASCADE_WIDTH;
	params->depth = (SXE2_FW_ACL_TCAM_DEPTH *
			 (SXE2_FW_ACL_LUT_NUM / SXE2_ACL_MAX_CASCADE_WIDTH)) /
			pf_cnt;
	params->entry_act_pairs = 1;
}

STATIC inline u16 sxe2_acl_calc_tbl_end_idx(u16 start, u16 num_entries, u16 width)
{
	u16 end_idx = 0;
	u16 add_entries = 0;
	u16 num_stack_level = 0;

	end_idx = start + (num_entries - 1);

	if (width > 1) {
		num_stack_level = (start % SXE2_FW_ACL_TCAM_DEPTH) + num_entries;

		num_stack_level = DIV_ROUND_UP(num_stack_level, SXE2_FW_ACL_TCAM_DEPTH);

		add_entries = (width - 1) * num_stack_level * SXE2_FW_ACL_TCAM_DEPTH;
	}

	return end_idx + add_entries;
}

STATIC s32 sxe2_acl_alloc_partition_from_tbl(struct sxe2_adapter *adapter,
					     struct sxe2_acl_scen_info *scen)
{
	struct sxe2_acl_tbl_info *acl_tbl_info = adapter->acl_ctxt.acl_tbl_info;
	s32 ret = 0;
	u16 width = 0;
	u16 num_entry = 0;
	u16 first_tcam_index = 0;
	bool is_cascade = false;
	bool is_ser_finish = false;
	u16 i = 0;
	u16 j = 0;
	u16 cnt_entry = 0;
	u16 start = 0;
	bool slice_avail = true;
	u16 slice_pos_in_tcams = 0;
	u16 slice_pos_in_tcam = 0;
	u16 offset = 0;

	width = DIV_ROUND_UP(scen->width, SXE2_FW_ACL_KEY_WIDTH_BYTES);
	if (width > acl_tbl_info->last_tcam - acl_tbl_info->first_tcam + 1) {
		ret = -EINVAL;
		goto l_end;
	}

	num_entry = ALIGN(scen->num_entry, SXE2_ACL_ENTRY_ALLOC_UNIT);
	if (width == 1) {
		is_cascade = false;
		first_tcam_index = acl_tbl_info->first_tcam;
	} else {
		is_cascade = true;
		first_tcam_index = acl_tbl_info->last_tcam + 1 - width;
	}

	do {
		for (i = 0; i < SXE2_FW_MAX_TCAM_ALLOC_UNITS && cnt_entry < num_entry;
		     i++) {
			slice_avail = true;
			slice_pos_in_tcam = !is_cascade ? i
							: SXE2_FW_MAX_TCAM_ALLOC_UNITS -
									    i - 1;
			for (j = first_tcam_index;
			     j < first_tcam_index + width && slice_avail; j++) {
				slice_pos_in_tcams = (j * SXE2_FW_MAX_TCAM_ALLOC_UNITS) +
						     slice_pos_in_tcam;

				slice_avail = slice_avail &&
					      (!!(test_bit(slice_pos_in_tcams,
							   acl_tbl_info->avail)));
			}

			if (!slice_avail) {
				cnt_entry = 0;
			} else {
				if (cnt_entry == 0 || is_cascade) {
					start = (first_tcam_index *
						 SXE2_FW_ACL_TCAM_DEPTH) +
						(slice_pos_in_tcam *
						 SXE2_ACL_ENTRY_ALLOC_UNIT);
				}
				cnt_entry += SXE2_ACL_ENTRY_ALLOC_UNIT;
			}
		}

		if (cnt_entry >= num_entry) {
			scen->start = start;
			scen->num_entry = num_entry;
			scen->end = sxe2_acl_calc_tbl_end_idx(start, num_entry, width);
		}

		first_tcam_index = (!is_cascade) ? first_tcam_index + width
						 : first_tcam_index - width;
		if (first_tcam_index > acl_tbl_info->last_tcam ||
		    first_tcam_index < acl_tbl_info->first_tcam) {
			offset++;

			if (offset >= width) {
				is_ser_finish = true;
			} else {
				first_tcam_index =
						(!is_cascade) ? offset
							      : acl_tbl_info->last_tcam +
										1 -
										offset -
										width;
			}
		}
	} while (!is_ser_finish);

	if (cnt_entry < num_entry) {
		LOG_ERROR_BDF("no contiguous ACL partition found\n");
		ret = -ENOSPC;
	}

l_end:
	return ret;
}

STATIC void sxe2_acl_fill_scen_chunk_mask(struct sxe2_fwc_acl_scen_alloc_req *req,
					  struct sxe2_acl_scen_info *scen)
{
	u16 tcam_idx = 0;
	u8 chunk_offset = 0;
	u16 cnt_slice = 0;
	u16 cnt_cascade = 0;
	u16 i = 0;
	u16 j = 0;

	tcam_idx = scen->start / SXE2_FW_ACL_TCAM_DEPTH;

	chunk_offset = (u8)((scen->start % SXE2_FW_ACL_TCAM_DEPTH) /
			    SXE2_ACL_ENTRY_ALLOC_UNIT);

	cnt_slice = scen->num_entry / SXE2_ACL_ENTRY_ALLOC_UNIT;

	cnt_cascade = scen->width / SXE2_FW_ACL_KEY_WIDTH_BYTES;

	for (i = 0; i < cnt_slice; i++) {
		for (j = tcam_idx;
		     j < tcam_idx + cnt_cascade && j < SXE2_ACL_ACTION_TCAM_CNT; j++)
			req->tcam_cfg[j].enable |= BIT(chunk_offset);

		chunk_offset++;
		chunk_offset %= SXE2_FW_MAX_TCAM_ALLOC_UNITS;

		if (chunk_offset == 0)
			tcam_idx += cnt_cascade;
	}
}

STATIC void sxe2_acl_fill_scen_tcam_select(struct sxe2_fwc_acl_scen_alloc_req *req,
					   u16 tcam_idx, u16 tcam_idx_in_cascade)
{
	u16 idx = 0;
	u16 i = 0;
	u8 val = 0;

	idx = tcam_idx_in_cascade * SXE2_FW_ACL_KEY_WIDTH_BYTES;

	for (i = 0; i < SXE2_FW_ACL_KEY_WIDTH_BYTES; i++) {
		val = (u8)(SXE2_FW_ACL_BYTE_SEL_BASE + idx + i);
		if (val > SXE2_FW_ACL_BYTE_SEL_BASE_RNG_CHK)
			continue;

		req->tcam_cfg[tcam_idx].tcam_select[i] = val;
	}
}

STATIC void sxe2_acl_fill_scen_act_mem(struct sxe2_acl_tbl_info *tbl_info,
				       struct sxe2_fwc_acl_scen_alloc_req *req,
				       struct sxe2_acl_scen_info *scen,
				       u8 current_tcam_idx, u8 target_tcam_idx)
{
	struct sxe2_acl_act_mem *act_mem = NULL;
	u8 i = 0;

	for (i = 0; i < SXE2_FW_MAX_ACTION_MEMORIES; i++) {
		act_mem = &tbl_info->act_mems[i];

		if (act_mem->act_mem == 0xff ||
		    act_mem->member_of_tcam != current_tcam_idx) {
			continue;
		}

		req->act_mem_cfg[i] = target_tcam_idx;
		req->act_mem_cfg[i] |= SXE2_ACL_ACT_MEM_EN;

		set_bit(i, scen->acl_act_mem_bitmap);
	}
}

STATIC void sxe2_acl_update_tbl_avail_sign(struct sxe2_acl_tbl_info *tbl_info,
					   struct sxe2_acl_scen_info *scen, bool is_avail)
{
	u16 tcam_idx = 0;
	u16 cnt_cascade = 0;
	u16 offset = 0;
	u16 cnt_alloc_uint = 0;
	u16 i = 0;
	u16 j = 0;
	u32 b_avail = 0;

	tcam_idx = scen->start / SXE2_FW_ACL_TCAM_DEPTH;
	offset = (scen->start % SXE2_FW_ACL_TCAM_DEPTH) / SXE2_ACL_ENTRY_ALLOC_UNIT;

	cnt_alloc_uint = scen->num_entry / SXE2_ACL_ENTRY_ALLOC_UNIT;

	cnt_cascade = scen->width / SXE2_FW_ACL_KEY_WIDTH_BYTES;

	for (i = 0; i < cnt_alloc_uint; i++) {
		for (j = 0; j < cnt_cascade; j++) {
			b_avail = (tcam_idx + j) * SXE2_FW_MAX_TCAM_ALLOC_UNITS + offset;
			if (is_avail)
				set_bit(b_avail, tbl_info->avail);
			else
				clear_bit(b_avail, tbl_info->avail);
		}

		offset += 1;
		offset %= SXE2_FW_MAX_TCAM_ALLOC_UNITS;

		if (!offset)
			tcam_idx += cnt_cascade;
	}
}

STATIC void sxe2_acl_init_entry_idx(struct sxe2_acl_scen_info *scen)
{
	scen->entry_first_index[SXE2_ACL_LUT_ENTRY_PRIO_NORMAL] = 0;
	scen->entry_last_index[SXE2_ACL_LUT_ENTRY_PRIO_NORMAL] = scen->num_entry - 1;
}

STATIC s32 sxe2_acl_create_scen_info(struct sxe2_adapter *adapter,
				     struct sxe2_acl_scen_info *scen)
{
	struct sxe2_acl_tbl_info *tbl_info = adapter->acl_ctxt.acl_tbl_info;
	u8 first_tcam = 0;
	u8 last_tcam = 0;
	u16 cnt_cascade = 0;
	s32 ret = 0;
	struct sxe2_fwc_acl_scen_alloc_req req = {};
	u16 i = 0;
	u16 j = 0;
	u16 last_tcam_idx_cascade = 0;
	u16 scen_id = 0;

	cnt_cascade = DIV_ROUND_UP(scen->width, SXE2_FW_ACL_KEY_WIDTH_BYTES);
	first_tcam = scen->start / SXE2_FW_ACL_TCAM_DEPTH;
	last_tcam = scen->end / SXE2_FW_ACL_TCAM_DEPTH;

	scen->avail_width = cnt_cascade * SXE2_FW_ACL_KEY_WIDTH_BYTES - 3;

	scen->rnage_chk_idx = (cnt_cascade - 1) * SXE2_FW_ACL_KEY_WIDTH_BYTES + 4;
	scen->pid_idx = (cnt_cascade - 1) * SXE2_FW_ACL_KEY_WIDTH_BYTES + 3;
	scen->pkt_dir_idx = (cnt_cascade - 1) * SXE2_FW_ACL_KEY_WIDTH_BYTES + 2;

	sxe2_acl_fill_scen_chunk_mask(&req, scen);
	req.tcam_cfg[first_tcam].start_cmp_set |= SXE2_ACL_ALLOC_SCEN_START_SET;
	i = first_tcam;
	while (i <= last_tcam) {
		last_tcam_idx_cascade = i + cnt_cascade - 1;
		req.tcam_cfg[i].start_cmp_set |= SXE2_ACL_ALLOC_SCEN_START_CMP;
		for (j = 0; j < cnt_cascade; j++) {
			sxe2_acl_fill_scen_tcam_select(&req, i + j, j);
			sxe2_acl_fill_scen_act_mem(tbl_info, &req, scen, i + j,
						   last_tcam_idx_cascade);
		}

		i += cnt_cascade;
	}

	i = 0;
	while (i < first_tcam) {
		req.tcam_cfg[i++].start_cmp_set = SXE2_ACL_ALLOC_SCEN_START_CMP |
						  SXE2_ACL_ALLOC_SCEN_START_SET;
	}

	i = last_tcam + 1;
	while (i < SXE2_FW_ACL_LUT_NUM) {
		req.tcam_cfg[i++].start_cmp_set = SXE2_ACL_ALLOC_SCEN_START_CMP |
						  SXE2_ACL_ALLOC_SCEN_START_SET;
	}

	ret = sxe2_fwc_acl_scen_alloc(adapter, &req, &scen_id);
	if (ret) {
		LOG_ERROR_BDF("Alloc scen cmd failed, ret:%d.\n", ret);
		goto l_end;
	}

	scen->scen_id = scen_id;
	sxe2_acl_update_tbl_avail_sign(tbl_info, scen, false);
	sxe2_acl_init_entry_idx(scen);

l_end:
	return ret;
}

STATIC s32 sxe2_acl_create_scenario(struct sxe2_adapter *adapter,
				    struct sxe2_acl_tbl_params *params)
{
	struct sxe2_acl_scen_info *scen = NULL;
	struct sxe2_acl_tbl_info *acl_tbl_info = adapter->acl_ctxt.acl_tbl_info;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;

	scen = devm_kzalloc(dev, sizeof(*scen), GFP_KERNEL);
	if (!scen) {
		LOG_ERROR_BDF("Failed to alloc scen mem.\n");
		ret = -ENOMEM;
		goto l_end;
	}
	INIT_LIST_HEAD(&scen->l_entry);
	scen->start = acl_tbl_info->first_entry;
	scen->width = SXE2_FW_ACL_KEY_WIDTH_BYTES *
		      DIV_ROUND_UP(params->width, SXE2_FW_ACL_KEY_WIDTH_BYTES);
	scen->num_entry = params->depth;

	ret = sxe2_acl_alloc_partition_from_tbl(adapter, scen);
	if (ret) {
		LOG_ERROR_BDF("Failed to alloc scen mem.\n");
		goto l_free_scen;
	}

	ret = sxe2_acl_create_scen_info(adapter, scen);
	if (ret) {
		LOG_ERROR_BDF("Failed to init scen.\n");
		goto l_free_scen;
	}
	list_add(&scen->l_entry, &acl_tbl_info->scens);
	LOG_DEBUG_BDF("acl scenario added to table: scen_id=%u\n", scen->scen_id);
	goto l_end;

l_free_scen:
	if (scen) {
		devm_kfree(dev, scen);
		scen = NULL;
	}

l_end:
	return ret;
}

STATIC void sxe2_acl_stat_ctxt_init(struct sxe2_adapter *adapter)
{
	struct sxe2_acl_stat_ctxt *acl_stat_ctxt =
			&adapter->acl_ctxt.acl_stat_ctxt;

	mutex_init(&acl_stat_ctxt->acl_stat_lock);
	acl_stat_ctxt->stat_base = adapter->caps_ctxt.acl_stat_base;
	acl_stat_ctxt->stat_num = adapter->caps_ctxt.acl_stat_num;
	INIT_LIST_HEAD(&acl_stat_ctxt->acl_stat_list);
}

s32 sxe2_acl_init(struct sxe2_adapter *adapter)
{
	struct sxe2_acl_tbl_params params = {};
	struct sxe2_acl_context *acl_ctx = &adapter->acl_ctxt;
	s32 ret = 0;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return 0;

	mutex_init(&acl_ctx->filter_lock);
	bitmap_fill(adapter->acl_ctxt.slots, SXE2_ACL_MAX_NUM_ENTRY);
	sxe2_flow_ppp_comm_ctxt_init(&acl_ctx->ppp, adapter, SXE2_HW_BLOCK_ID_ACL);
	sxe2_acl_stat_ctxt_init(adapter);

	sxe2_acl_tbl_param_calc(adapter, &params);
	LOG_DEBUG_BDF("acl init: pf_idx=%u, pf_cnt=%u, table width=%u, depth=%u\n",
		      adapter->pf_idx, adapter->pf_cnt, params.width, params.depth);

	ret = sxe2_acl_create_table(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("Failed to create acl table, ret=%d\n", ret);
		goto l_deinit;
	}

	ret = sxe2_acl_create_scenario(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("Failed to create acl scenario, ret=%d\n", ret);
		goto l_deinit;
	}

	goto l_end;

l_deinit:
	sxe2_acl_deinit(adapter);

l_end:
	return ret;
}

STATIC s32 sxe2_acl_hw_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_acl_context *acl_ctx = &adapter->acl_ctxt;
	struct sxe2_acl_tbl_info *acl_tbl_info = acl_ctx->acl_tbl_info;
	struct sxe2_acl_scen_info *scen, *tmp_scen;
	s32 ret = 0;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		goto l_end;

	if (!acl_tbl_info)
		goto l_end;

	LOG_DEBUG_BDF("acl hw deinit: table id=%u\n", acl_tbl_info->id);

	list_for_each_entry_safe(scen, tmp_scen, &acl_tbl_info->scens, l_entry) {
		LOG_DEBUG_BDF("acl dealloc scenario: scen_id=%u\n", scen->scen_id);
		ret = sxe2_fwc_acl_scen_dealloc(adapter, scen->scen_id);
		if (ret) {
			LOG_ERROR_BDF("Dealloc scen cmd failed, ret:%d.\n", ret);
			goto l_end;
		}
	}

	ret = sxe2_fwc_acl_lut_dealloc(adapter, acl_tbl_info->id);
	if (ret) {
		LOG_ERROR_BDF("Acl tbl dealloc cmd failed, ret:%d\n", ret);
		goto l_end;
	}

	LOG_DEBUG_BDF("acl table deallocated: id=%u\n", acl_tbl_info->id);

l_end:
	return ret;
}

STATIC void sxe2_acl_flow_ctxt_deinit(struct sxe2_adapter *adapter)
{
	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return;

	sxe2_flow_ppp_comm_ctxt_deinit(&adapter->acl_ctxt.ppp);
}

STATIC void sxe2_acl_sw_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_acl_context *acl_ctx = &adapter->acl_ctxt;
	struct sxe2_acl_tbl_info *acl_tbl_info = acl_ctx->acl_tbl_info;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_acl_scen_info *scen, *tmp_scen;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return;

	if (!acl_tbl_info)
		return;

	LOG_DEBUG_BDF("acl sw deinit: cleaning scenarios and table\n");

	list_for_each_entry_safe(scen, tmp_scen, &acl_tbl_info->scens, l_entry) {
		LOG_DEBUG_BDF("acl free scenario sw node: scen_id=%u\n", scen->scen_id);
		list_del(&scen->l_entry);
		devm_kfree(dev, scen);
	}

	devm_kfree(dev, acl_tbl_info);
	acl_tbl_info = NULL;
	mutex_destroy(&acl_ctx->filter_lock);
	adapter->acl_ctxt.acl_tbl_info = NULL;
	bitmap_fill(adapter->acl_ctxt.slots, SXE2_ACL_MAX_NUM_ENTRY);
}

void sxe2_acl_deinit(struct sxe2_adapter *adapter)
{
	LOG_DEBUG_BDF("acl deinit start\n");

	(void)sxe2_acl_hw_deinit(adapter);

	sxe2_acl_flow_ctxt_deinit(adapter);

	sxe2_acl_sw_deinit(adapter);

	LOG_DEBUG_BDF("acl deinit done\n");
}

s32 sxe2_acl_ptg_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u16 i = 0;
	u16 j = 0;
	u16 table_idx = 0;
	u16 per_size = 0;
	u16 ddp_max_cnt = 0;
	u8 port_idx = adapter->port_idx;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return -EOPNOTSUPP;

	per_size = sizeof(struct sxe2_ddp_acl_ptg);
	ddp_max_cnt = (SXE2_MAX_PTYPE_NUM * SXE2_MAX_CDID_NUM) / per_size;
	if (!data || base_id >= ddp_max_cnt || cnt > ddp_max_cnt) {
		LOG_ERROR_BDF("sxe2 acl ptg parse from ddp failed, port_idx=%u !\n",
			      port_idx);
		ret = -EINVAL;
		goto l_end;
	}

	table_idx = base_id * per_size;
	for (i = 0; i < cnt; i++) {
		for (j = 0; j < per_size; j++) {
			if (table_idx >= (port_idx * SXE2_MAX_PTYPE_NUM) &&
			    table_idx < ((port_idx + 1) * SXE2_MAX_PTYPE_NUM)) {
				adapter->acl_ctxt.ppp
						.pt_to_grp[table_idx % SXE2_MAX_PTYPE_NUM]
						.idx = *data;
			}
			table_idx++;
			data++;
		}
	}
	LOG_INFO_BDF("sxe2 acl ptg parse from ddp, port_idx=%u !\n", port_idx);

l_end:
	return ret;
}

STATIC u16 sxe2_acl_get_avail_entry_idx(struct sxe2_acl_scen_info *scen,
					enum sxe2_acl_lut_entry_priority priority)
{
	u16 first_idx = 0;
	u16 last_idx = 0;
	u16 i = 0;
	s8 step = 0;
	u16 entry_idx = 0xffff;

	first_idx = scen->entry_first_index[priority];
	last_idx = scen->entry_last_index[priority];
	step = (first_idx < last_idx) ? 1 : -1;

	for (i = first_idx; i != last_idx + step; i += step) {
		if (!test_bit(i, scen->acl_entry_bitmap)) {
			set_bit(i, scen->acl_entry_bitmap);
			entry_idx = i;
			goto l_ret;
		}
	}

l_ret:
	return entry_idx;
}

STATIC s32 sxe2_acl_remove_flow_lut_entry(struct sxe2_adapter *adapter,
					  struct sxe2_acl_scen_info *scen, u16 entry_idx)
{
	struct sxe2_acl_tbl_info *acl_tbl_info = adapter->acl_ctxt.acl_tbl_info;
	struct sxe2_acl_entry_data lut_entry_data = {};
	struct sxe2_acl_act_entry_data act_entry_data[SXE2_ACL_ACTION_NUM_PER_ENTRY] = {};
	struct sxe2_acl_act_mem *act_mem = NULL;
	s32 ret = 0, last_err = 0;
	u16 cnt_cascade = 0;
	u16 first_tcam = 0;
	u16 idx_in_tcam = 0;
	u16 i = 0;

	if (!scen || scen->num_entry <= entry_idx) {
		LOG_ERROR_BDF("Invalid entry_idx %d\n", entry_idx);
		last_err = -EINVAL;
		goto l_end;
	}

	if (!test_bit(entry_idx, scen->acl_entry_bitmap)) {
		LOG_WARN_BDF("Entry %u already cleared in bitmap\n", entry_idx);
		last_err = 0;
		goto l_end;
	}

	first_tcam   = (u16)(scen->start / SXE2_FW_ACL_TCAM_DEPTH);
	idx_in_tcam  = (u16)(entry_idx % SXE2_FW_ACL_TCAM_DEPTH);
	cnt_cascade = DIV_ROUND_UP(scen->width, SXE2_FW_ACL_KEY_WIDTH_BYTES);
	first_tcam += (entry_idx / SXE2_FW_ACL_TCAM_DEPTH) * cnt_cascade;
	for (i = 0; i < cnt_cascade; i++) {
		ret = sxe2_fwc_acl_lut_entry(adapter, (u8)(first_tcam + i),
					     idx_in_tcam, &lut_entry_data);
		if (ret) {
			LOG_ERROR_BDF("Acl remove flow lut entry cmd failed, ret:%d\n",
				      ret);
			last_err = ret;
		}
	}

	for_each_set_bit(i, scen->acl_act_mem_bitmap, SXE2_FW_MAX_ACTION_MEMORIES) {
		act_mem = &acl_tbl_info->act_mems[i];
		if (act_mem->member_of_tcam >= first_tcam &&
		    act_mem->member_of_tcam < first_tcam + cnt_cascade) {
			ret = sxe2_fwc_acl_act_entry(adapter, (u8)i, idx_in_tcam, act_entry_data,
						     SXE2_ACL_ACTION_NUM_PER_ENTRY);
			if (ret) {
				LOG_ERROR_BDF("Acl remove flow act cmd failed, ret:%d\n", ret);
				last_err = ret;
			}
		}
	}

	clear_bit(entry_idx, scen->acl_entry_bitmap);
	LOG_DEBUG_BDF("acl entry removed: scen_id=%u, entry_idx=%u\n",
		      scen->scen_id, entry_idx);

l_end:
	return last_err;
}

STATIC s32 sxe2_acl_add_flow_lut_entry(struct sxe2_adapter *adapter,
				       struct sxe2_acl_scen_info *scen, u16 *entry_idx,
				       enum sxe2_acl_lut_entry_priority priority, u8 *keys,
				       u8 *inverts,
				       struct sxe2_acl_flow_action *act_entry_data,
					   u8 act_cnt)
{
	struct sxe2_acl_entry_data lut_entry_data = {};
	struct sxe2_acl_act_entry_data tmp_acts[SXE2_ACL_ACTION_NUM_PER_ENTRY] = {};
	s32 ret = 0;
	u16 cnt_cascade = 0;
	u16 i = 0;
	u8 k = 0;
	u8 cascade_ver_idx = 0;
	u16 tcam_block_offset = 0;
	u16 line_idx_in_tcam = 0;
	u16 target_tcam_id = 0;

	if (!scen) {
		LOG_ERROR_BDF("Invalid scen\n");
		ret = -EINVAL;
		goto l_end;
	}

	*entry_idx = sxe2_acl_get_avail_entry_idx(scen, priority);
	if (*entry_idx >= scen->num_entry) {
		LOG_ERROR_BDF("Invalid entry_idx %d, max entry_idx is %d\n",
			      *entry_idx, scen->num_entry);
		ret = -ENOSPC;
		goto l_end;
	}

	line_idx_in_tcam = (u16)(*entry_idx % SXE2_FW_ACL_TCAM_DEPTH);
	cnt_cascade = DIV_ROUND_UP(scen->width, SXE2_FW_ACL_KEY_WIDTH_BYTES);
	tcam_block_offset = (u16)(scen->start / SXE2_FW_ACL_TCAM_DEPTH +
		(*entry_idx / SXE2_FW_ACL_TCAM_DEPTH) * cnt_cascade);

	for (i = 0; i < cnt_cascade; i++) {
		cascade_ver_idx = (u8)(cnt_cascade - i - 1);
		target_tcam_id = tcam_block_offset + cascade_ver_idx;

		memcpy(&lut_entry_data.entry_key.val,
		       &keys[cascade_ver_idx * SXE2_FW_ACL_KEY_WIDTH_BYTES],
		       SXE2_FW_ACL_KEY_WIDTH_BYTES);
		memcpy(&lut_entry_data.entry_key_invert.val,
		       &inverts[cascade_ver_idx * SXE2_FW_ACL_KEY_WIDTH_BYTES],
		       SXE2_FW_ACL_KEY_WIDTH_BYTES);

		lut_entry_data.entry_key.enable = 1;
		lut_entry_data.entry_key_invert.enable = 1;
		LOG_DEBUG_BDF("Acl add flow lut entry, idx:%d, tcam_id:%d.\n",
			      line_idx_in_tcam, target_tcam_id);
		ret = sxe2_fwc_acl_lut_entry(adapter, target_tcam_id, line_idx_in_tcam,
					     &lut_entry_data);
		if (ret) {
			LOG_ERROR_BDF("LUT Entry write failed at TCAM:%u, Line:%u, ret:%d\n",
				      target_tcam_id, line_idx_in_tcam, ret);
			goto l_rem_flow_entry;
		}
	}

	for (k = 0; k < act_cnt && k < SXE2_ACL_ACTION_NUM_PER_ENTRY; k++)
		tmp_acts[k] = act_entry_data[k].data.acl_act;
	ret = sxe2_acl_add_act(adapter, scen, *entry_idx, tmp_acts, act_cnt);
	if (ret) {
		LOG_ERROR_BDF("Acl add flow act cmd failed, ret:%d\n", ret);
		goto l_rem_flow_entry;
	}

l_rem_flow_entry:
	if (ret) {
		(void)sxe2_acl_remove_flow_lut_entry(adapter, scen, *entry_idx);
		*entry_idx = 0;
	}

l_end:
	return ret;
}

STATIC void sxe2_flow_acl_set_diss_fld(struct sxe2_flow_dissector_info *dissector,
				       u16 fld_id)
{
	u16 val_loc = 0;
	u16 mask_loc = 0;

	switch (fld_id) {
	case SXE2_FLOW_FLD_ID_ETH_DA:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, eth.h_dest);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, eth_mask.h_dest);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id, val_loc,
				       mask_loc, SXE2_U16_MASK);
		break;
	case SXE2_FLOW_FLD_ID_ETH_SA:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, eth.h_source);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, eth_mask.h_source);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id, val_loc,
				       mask_loc, SXE2_U16_MASK);
		break;
	case SXE2_FLOW_FLD_ID_IPV4_SA:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, ip.v4.src_ip);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, mask.v4.src_ip);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id, val_loc,
				       mask_loc, SXE2_U16_MASK);
		break;
	case SXE2_FLOW_FLD_ID_IPV4_DA:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, ip.v4.dst_ip);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, mask.v4.dst_ip);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id, val_loc,
				       mask_loc, SXE2_U16_MASK);
		break;
	case SXE2_FLOW_FLD_ID_TCP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_UDP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_SCTP_SRC_PORT:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, l4.src_port);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, l4_mask.src_port);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id, val_loc,
				       mask_loc, SXE2_U16_MASK);
		break;
	case SXE2_FLOW_FLD_ID_TCP_DST_PORT:
	case SXE2_FLOW_FLD_ID_UDP_DST_PORT:
	case SXE2_FLOW_FLD_ID_SCTP_DST_PORT:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, l4.dst_port);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, l4_mask.dst_port);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id, val_loc,
				       mask_loc, SXE2_U16_MASK);
		break;
	case SXE2_FLOW_FLD_ID_IPV6_SA:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, ip.v6.src_ip);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, mask.v6.src_ip);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id,
				       val_loc, mask_loc,
				       SXE2_U16_MASK);
		break;
	case SXE2_FLOW_FLD_ID_IPV6_DA:
		val_loc = offsetof(struct sxe2_fnav_filter_full_key, ip.v6.dst_ip);
		mask_loc = offsetof(struct sxe2_fnav_filter_full_key, mask.v6.dst_ip);
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)fld_id,
				       val_loc, mask_loc,
				       SXE2_U16_MASK);
		break;
	default:
		break;
	}
}

STATIC void sxe2_acl_gen_dissector_info(struct sxe2_flow_dissector_info *dissectors,
					u8 dissectors_cnt, struct sxe2_fnav_flow_seg *seg)
{
	u64 i = 0;
	struct sxe2_flow_dissector_info *dissector = NULL;

	dissector = &dissectors[dissectors_cnt - 1];

	for_each_set_bit(i, seg->fields, SXE2_FLOW_FLD_ID_MAX) {
		sxe2_flow_acl_set_diss_fld(dissector, (u16)i);
	}

	bitmap_or(dissector->headers, dissector->headers, seg->headers,
		  SXE2_FLOW_HDR_MAX);

	for (i = 0; i < seg->raw_cnt; i++) {
		sxe2_flow_add_diss_raw(dissector, seg->raw[i].offset, SXE2_U16_MASK,
				       SXE2_U16_MASK, seg->raw[i].len);
	}
}

STATIC struct sxe2_flow_info_node *sxe2_acl_hw_flow_add(struct sxe2_adapter *adapter,
							struct sxe2_fnav_flow_seg *segs)
{
	s32 ret = 0;
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &adapter->acl_ctxt.ppp;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_flow_dissector_info *dissectors = NULL;
	bool is_tunnel = segs->is_tunnel;
	u8 dissectors_cnt = is_tunnel ? 2 : 1;
	struct sxe2_flow_info_node *flow = NULL;
	u16 i = 0;
	struct sxe2_fnav_flow_seg *seg = NULL;

	dissectors = devm_kcalloc(dev, dissectors_cnt, sizeof(*dissectors), GFP_KERNEL);
	if (!dissectors)
		goto l_end;

	for (i = 0; i < dissectors_cnt; i++) {
		seg = &segs[i];
		LOG_DEV_DEBUG("add a flow, header:0x%lX, field[0]:0x%lX, is_tun:%d.\n",
			      seg->headers[0], seg->fields[0], seg->is_tunnel);
		sxe2_acl_gen_dissector_info(dissectors, (u8)(i + 1), seg);
	}

	flow = sxe2_find_flow(ppp_ctxt, dissectors, dissectors_cnt);
	if (flow) {
		LOG_DEBUG_BDF("find a flow with seg cfg.\n");
		goto l_end;
	}

	ret = sxe2_flow_creat(ppp_ctxt, dissectors, dissectors_cnt, &flow);
	if (ret) {
		LOG_ERROR_BDF("create a flow with seg cfg failed, ret:%d\n", ret);
	} else {
		INIT_LIST_HEAD(&flow->acl_entry);
		mutex_init(&flow->acl_entry_lock);
	}

l_end:
	if (dissectors)
		devm_kfree(dev, dissectors);

	return flow;
}

STATIC s32 sxe2_acl_hw_flow_del(struct sxe2_vsi *vsi, struct sxe2_flow_info_node *flow)
{
	s32 ret = 0;
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &vsi->adapter->acl_ctxt.ppp;

	if (!flow)
		return 0;

	if (bitmap_empty((unsigned long *)flow->used_vsi, SXE2_MAX_VSI_NUM))
		ret = sxe2_flow_delete(ppp_ctxt, flow);

	return ret;
}

STATIC s32 sxe2_acl_flow_cfg_del(struct sxe2_vsi *vsi, struct sxe2_acl_flow_cfg *flow_cfg)
{
	s32 ret = 0;
	u64 vsi_sw_id = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &adapter->acl_ctxt.ppp;
	struct sxe2_flow_info_node *flow = NULL;

	if (!flow_cfg->seg)
		return 0;

	if (!flow_cfg->seg->flow_ptr)
		return 0;

	list_del(&flow_cfg->l_node);
	flow = flow_cfg->seg->flow_ptr;

	for_each_set_bit(vsi_sw_id, flow_cfg->seg->vsis, SXE2_MAX_VSI_NUM) {
		ret = sxe2_flow_disassoc_vsi(ppp_ctxt, flow, (u16)vsi_sw_id);
		if (ret) {
			LOG_ERROR_BDF("acl hw flow disassociate vsi failed, vsi_sw_id:%u ret:%d\n",
				      (u16)vsi_sw_id, ret);
		}
		clear_bit((u16)vsi_sw_id, flow_cfg->seg->vsis);
	}

	ret = sxe2_acl_hw_flow_del(vsi, flow);
	if (ret) {
		LOG_ERROR_BDF("acl hw flow del failed, vsi_sw_id:%u ret:%d\n",
			      (u16)vsi_sw_id, ret);
	}

	return ret;
}

s32 sxe2_acl_flow_cfg_add(struct sxe2_vsi *vsi, struct sxe2_acl_flow_cfg *flow_cfg,
			  struct sxe2_fnav_flow_seg *seg)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &adapter->acl_ctxt.ppp;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_fnav_flow_seg *seg_old = flow_cfg->seg;
	struct sxe2_flow_info_node *flow = NULL;

	if (seg_old) {
		if (bitmap_equal(seg_old->headers, seg->headers, SXE2_FLOW_HDR_MAX) &&
		    bitmap_equal(seg_old->fields, seg->fields, SXE2_FLOW_FLD_ID_MAX)) {
			LOG_INFO_BDF("both segs are same, flow_type:%d, tun:%d.\n",
				     flow_cfg->flow_type, seg->is_tunnel);
			devm_kfree(dev, seg);
			return -EEXIST;
		}

		if (bitmap_equal(seg_old->headers, seg->headers, SXE2_FLOW_HDR_MAX)) {
			LOG_ERROR_BDF("same headers with different fields, "
				      "flow_type:%d not allowed.\n",
				      flow_cfg->flow_type);
			ret = -EINVAL;
			goto l_flow_add_failed;
		}
	}

	flow = sxe2_acl_hw_flow_add(adapter, seg);
	if (!flow) {
		LOG_ERROR_BDF("fnav hw flow add failed, ret:%d\n", ret);
		ret = -EIO;
		goto l_flow_add_failed;
	}

	ret = sxe2_flow_assoc_vsi(ppp_ctxt, flow, vsi->id_in_pf);
	if (ret) {
		LOG_ERROR_BDF("fnav hw flow associate main vsi failed, ret:%d\n", ret);
		(void)sxe2_acl_hw_flow_del(vsi, flow);
		goto l_flow_add_failed;
	}

	if (seg_old)
		devm_kfree(dev, seg_old);

	set_bit(vsi->id_in_pf, seg->vsis);
	seg->flow_ptr = flow;
	flow_cfg->seg = seg;

	return 0;

l_flow_add_failed:
	if (seg) {
		devm_kfree(dev, seg);
		seg = NULL;
	}
	return ret;
}

STATIC s32 sxe2_acl_slot_id_alloc(unsigned long *slots, u32 *slot_id)
{
	u32 pos = 0;
	s32 ret = 0;

	pos = find_next_bit(slots, SXE2_ACL_MAX_NUM_ENTRY, 0);
	if (pos >= SXE2_ACL_MAX_NUM_ENTRY) {
		ret = -EINVAL;
		goto l_end;
	}
	clear_bit(pos, slots);

	*slot_id = pos;

l_end:
	return ret;
}

STATIC void sxe2_acl_slot_id_free(unsigned long *slots, u32 slot_id)
{
	if (slot_id >= SXE2_ACL_MAX_NUM_ENTRY)
		return;

	set_bit(slot_id, slots);
}

STATIC s32 sxe2_acl_slot_id_set(unsigned long *slots, u32 max_bits)
{
	s32 pos = -1;
	s32 ret = 0;
	s32 i;

	for (i = max_bits - 1; i >= 0; i--) {
		if (!test_bit(i, slots)) {
			pos = i;
			break;
		}
	}

	if (pos < 0) {
		ret = -EINVAL;
		goto l_end;
	}

	if (test_and_set_bit(pos, slots)) {
		ret = -EAGAIN;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC struct sxe2_acl_flow_entry *
sxe2_flow_acl_scen_entry_cond_compare(struct sxe2_flow_info_node *flow_node,
				      struct sxe2_acl_flow_entry *flow_entry,
				      bool *do_chg_action, bool *do_add_entry)
{
	struct sxe2_acl_flow_entry *return_node = NULL;
	struct sxe2_acl_flow_entry *node = NULL;
	struct sxe2_acl_flow_entry *tmp = NULL;
	bool action_mismatch;
	bool found_match;
	u8 i, j;

	*do_chg_action = false;
	*do_add_entry = true;

	mutex_lock(&flow_node->acl_entry_lock);
	list_for_each_entry_safe(node, tmp, &flow_node->acl_entry, l_entry) {
		if (node->entry_size != flow_entry->entry_size ||
		    memcmp(node->entry, flow_entry->entry, node->entry_size)) {
			continue;
		}
		*do_add_entry = false;
		return_node = node;

		if (node->act_cnt != flow_entry->act_cnt) {
			*do_chg_action = true;
			break;
		}

		action_mismatch = false;
		for (i = 0; i < node->act_cnt; i++) {
			found_match = false;
			for (j = 0; j < flow_entry->act_cnt; j++) {
				if (memcmp(&node->action[i], &flow_entry->action[j],
					   sizeof(*node->action)) == 0) {
					found_match = true;
					break;
				}
			}

			if (!found_match) {
				action_mismatch = true;
				break;
			}
		}
		if (action_mismatch) {
			*do_chg_action = true;
			break;
		}
		break;
	}
	mutex_unlock(&flow_node->acl_entry_lock);

	return return_node;
}

STATIC s32 sxe2_flow_acl_add_scen_entry(struct sxe2_adapter *adapter,
					struct sxe2_acl_flow_entry *flow_entry,
					struct sxe2_flow_info_node *flow)
{
	struct sxe2_acl_flow_entry *node = NULL;
	s32 ret = -EEXIST;
	bool do_add_entry = false;
	bool do_chg_action = false;
	u8 *keys = NULL;
	u8 *inverts = NULL;
	u16 entry_idx = 0;

	node = sxe2_flow_acl_scen_entry_cond_compare(flow, flow_entry, &do_chg_action,
						     &do_add_entry);
	LOG_DEBUG_BDF("acl scen entry compare: do_add=%d, do_chg_action=%d, flow=%p\n",
		      do_add_entry, do_chg_action, flow);
	if (do_add_entry) {
		keys = (u8 *)flow_entry->entry;
		inverts = keys + (flow_entry->entry_size / 2);
		LOG_DEBUG_BDF("acl scen add new entry: flow=%p, act_cnt=%u\n",
			      flow, flow_entry->act_cnt);
		ret = sxe2_acl_add_flow_lut_entry(adapter, flow->cfg.scen, &entry_idx,
						  SXE2_ACL_LUT_ENTRY_PRIO_NORMAL, keys,
						  inverts, flow_entry->action, flow_entry->act_cnt);
		if (ret) {
			LOG_ERROR_BDF("Failed to add flow entry, ret:%d\n", ret);
			goto l_end;
		}
		flow_entry->scen_entry_idx = entry_idx;
		mutex_lock(&flow->acl_entry_lock);
		list_add_tail(&flow_entry->l_entry, &flow->acl_entry);
		mutex_unlock(&flow->acl_entry_lock);
		LOG_DEBUG_BDF("acl scen entry added: scen_entry_idx=%u\n", entry_idx);
	} else if (!do_chg_action && node) {
		flow_entry->scen_entry_idx = node->scen_entry_idx;
		mutex_lock(&flow->acl_entry_lock);
		list_add_tail(&flow_entry->l_entry, &flow->acl_entry);
		mutex_unlock(&flow->acl_entry_lock);
		LOG_DEBUG_BDF("acl scen entry reused: scen_entry_idx=%u\n",
			      flow_entry->scen_entry_idx);
		ret = 0;
	} else {
		ret = -EEXIST;
		LOG_INFO_BDF("flow entry is exist, do change action.\n");
	}
l_end:
	return ret;
}

s32 sxe2_acl_lut_entry_add(struct sxe2_vsi *ori_vsi,
			   struct sxe2_vsi *rule_vsi,
						   struct sxe2_acl_filter *filter,
						   struct sxe2_acl_flow_action *acts)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = ori_vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_acl_flow_cfg *flow_cfg = NULL;
	struct sxe2_flow_info_node *flow = NULL;
	struct sxe2_acl_flow_entry *acl_flow_entry = NULL;
	u16 max_filter_cnt = adapter->acl_ctxt.acl_tbl_info->max_slot_cnt;
	u32 slot_id = 0;

	mutex_lock(&adapter->acl_ctxt.filter_lock);

	LOG_DEBUG_BDF("acl lut entry add start: slot_id=%u, flow_type=%d, rule_vsi=%u\n",
		      slot_id, filter->flow_type, rule_vsi->id_in_pf);

	ret = sxe2_acl_slot_id_alloc(adapter->acl_ctxt.slots, &slot_id);
	if (ret) {
		LOG_ERROR_BDF("failed to alloc slot id, ret:%d\n", ret);
		goto l_unlock;
	}

	LOG_DEBUG_BDF("acl slot allocated: slot_id=%u, max_filter_cnt=%u\n",
		      slot_id, max_filter_cnt);
	if (slot_id >= max_filter_cnt) {
		LOG_ERROR_BDF("Exceed the max entry number:%d of HW support\n",
			      max_filter_cnt);
		ret = -EOPNOTSUPP;
		goto l_free_slot_id;
	}

	flow_cfg = sxe2_acl_find_flow_cfg_by_flow_type(ori_vsi, filter->flow_type);
	if (!flow_cfg) {
		LOG_ERROR_BDF("flow node is not exist, flow_type: %d.\n",
			      filter->flow_type);
		ret = -EINVAL;
		goto l_free_slot_id;
	}
	flow = flow_cfg->seg->flow_ptr;

	acl_flow_entry = devm_kzalloc(dev, sizeof(*acl_flow_entry), GFP_KERNEL);
	if (!acl_flow_entry) {
		LOG_ERROR_BDF("Failed to alloc acl flow entry\n");
		ret = -ENOMEM;
		goto l_free_slot_id;
	}

	acl_flow_entry->flow = flow;

	ret = sxe2_flow_acl_format_lut_act_entry(adapter, acl_flow_entry, flow, acts,
						 (u8 *)&filter->full_key);
	if (ret) {
		LOG_ERROR_BDF("Failed to format lut and act entry, ret %d.\n", ret);
		goto l_err_free_flow_struct;
	}

	ret = sxe2_flow_acl_add_scen_entry(adapter, acl_flow_entry, flow);
	if (ret) {
		LOG_ERROR_BDF("Failed to add scen entry, ret %d.\n", ret);
		goto l_err_free_flow_members;
	}

	filter->flow_entry = acl_flow_entry;
	list_add(&filter->l_node, &rule_vsi->acl.filter_list);
	flow_cfg->filter_cnt++;
	LOG_DEBUG_BDF("acl lut entry add done: filter_id=%llu, slot_id=%u, "
		      "flow_type=%d, flow_cfg_filter_cnt=%u\n",
		      filter->filter_id, slot_id, filter->flow_type,
		      flow_cfg->filter_cnt);
	mutex_unlock(&adapter->acl_ctxt.filter_lock);
	return 0;

l_err_free_flow_members:
	LOG_DEBUG_BDF("acl lut entry add failed, free members: ret=%d\n", ret);
	if (acl_flow_entry->action) {
		devm_kfree(dev, acl_flow_entry->action);
		acl_flow_entry->action = NULL;
	}

	if (acl_flow_entry->entry) {
		devm_kfree(dev, acl_flow_entry->entry);
		acl_flow_entry->entry = NULL;
	}

l_err_free_flow_struct:
	LOG_DEBUG_BDF("acl lut entry add failed, free flow struct: ret=%d\n", ret);
	devm_kfree(dev, acl_flow_entry);

l_free_slot_id:
	LOG_DEBUG_BDF("acl lut entry add failed, free slot: slot_id=%u, ret=%d\n",
		      slot_id, ret);
	sxe2_acl_slot_id_free(adapter->acl_ctxt.slots, slot_id);

l_unlock:
	mutex_unlock(&adapter->acl_ctxt.filter_lock);
	return ret;
}

STATIC s32 sxe2_acl_del_entry(struct sxe2_adapter *adapter,
			      struct sxe2_acl_flow_entry *flow_entry)
{
	s32 ret = 0;
	struct sxe2_acl_scen_info *scen = NULL;
	struct sxe2_flow_info_node *flow = NULL;
	struct sxe2_acl_flow_entry *curr, *tmp;
	u16 entry_idx;
	u32 match_count = 0;
	bool found = false;

	if (!flow_entry) {
		LOG_DEBUG_BDF("flow_entry is NULL, nothing to delete\n");
		return 0;
	}

	entry_idx = flow_entry->scen_entry_idx;
	flow = flow_entry->flow;
	if (flow) {
		mutex_lock(&flow->acl_entry_lock);
		list_for_each_entry_safe(curr, tmp, &flow->acl_entry, l_entry) {
			if (curr == flow_entry) {
				list_del(&curr->l_entry);
				found = true;
				break;
			}
		}

		if (!found) {
			mutex_unlock(&flow->acl_entry_lock);
			LOG_WARN_BDF("Flow entry not found in SW list, scen_idx: %d\n", entry_idx);
			return -ENOENT;
		}

		list_for_each_entry(curr, &flow->acl_entry, l_entry) {
			if (curr->scen_entry_idx == entry_idx)
				match_count++;
		}

		mutex_unlock(&flow->acl_entry_lock);
		if (match_count == 0) {
			scen = flow->cfg.scen;
			if (!scen) {
				LOG_ERROR_BDF("scen is NULL, nothing to delete\n");
			} else {
				entry_idx = flow_entry->scen_entry_idx;
				LOG_DEBUG_BDF("acl delete hw entry: scen_id=%u, entry_idx=%u, "
					      "flow_entry=%p\n",
					      scen->scen_id, entry_idx, flow_entry);
				ret = sxe2_acl_remove_flow_lut_entry(adapter, scen, entry_idx);
				if (ret)
					LOG_ERROR_BDF("Failed to delete entry,scen_entry_idx:%u\n",
						      entry_idx);
			}
		} else {
			LOG_DEBUG_BDF("There are still %u entries sharing the same HW index %u\n",
				      match_count, flow_entry->scen_entry_idx);
			ret = 0;
		}
	}

	LOG_DEBUG_BDF("acl del entry done: flow_entry=%p, scen_entry_idx=%u, ret=%d\n",
		      flow_entry, flow_entry->scen_entry_idx, ret);
	return ret;
}

STATIC s32 sxe2_acl_filter_del_hw(struct sxe2_vsi *vsi, struct sxe2_acl_filter *filter)
{
	s32 ret1 = 0;
	s32 ret2 = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_acl_flow_cfg *flow_cfg;
	struct sxe2_acl_flow_entry *acl_flow_entry = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 max_filter_cnt = adapter->acl_ctxt.acl_tbl_info->max_slot_cnt;

	flow_cfg = sxe2_acl_find_flow_cfg_by_flow_type(vsi, filter->flow_type);
	if (!flow_cfg) {
		LOG_ERROR_BDF("Flow cfg not found, filter_id:%llu, flow_type:%d\n",
			      filter->filter_id, filter->flow_type);
		if (!list_empty(&filter->l_node))
			list_del(&filter->l_node);
		else
			LOG_ERROR_BDF("filter %p not in any list\n", filter);

		devm_kfree(dev, filter);
		return -EINVAL;
	}

	if (!list_empty(&filter->l_node)) {
		list_del(&filter->l_node);
		acl_flow_entry = filter->flow_entry;
		LOG_DEBUG_BDF("acl filter del hw: filter_id=%llu, flow_type=%d, flow_entry=%p\n",
			      filter->filter_id, filter->flow_type, acl_flow_entry);
		ret1 = sxe2_acl_del_entry(adapter, acl_flow_entry);
		if (ret1) {
			LOG_ERROR_BDF("Failed to delete, filter_id:%llu, flow_type:%d,ret:%d\n",
				      filter->filter_id, filter->flow_type, ret1);
		}

		if (flow_cfg->filter_cnt > 0) {
			flow_cfg->filter_cnt--;
		} else {
			LOG_WARN_BDF("filter_cnt already 0 for flow_type %d, filter_id=%llu\n",
				     filter->flow_type, filter->filter_id);
		}
	}

	if (flow_cfg->filter_cnt == 0) {
		LOG_DEBUG_BDF("flow cfg is empty, flow_type:%d.\n", filter->flow_type);
		ret2 = sxe2_acl_flow_cfg_del(vsi, flow_cfg);
		if (ret2) {
			LOG_WARN_BDF("delete hw failed, filter_id:%llu, flow_type:%d, ret:%d\n",
				     filter->filter_id, filter->flow_type, ret2);
		}

		if (flow_cfg->seg) {
			devm_kfree(dev, flow_cfg->seg);
			flow_cfg->seg = NULL;
		}

		devm_kfree(dev, flow_cfg);
	}

	if (acl_flow_entry) {
		if (acl_flow_entry->action) {
			devm_kfree(dev, acl_flow_entry->action);
			acl_flow_entry->action = NULL;
		}

		if (acl_flow_entry->entry) {
			devm_kfree(dev, acl_flow_entry->entry);
			acl_flow_entry->entry = NULL;
		}
		devm_kfree(dev, acl_flow_entry);
		filter->flow_entry = NULL;
	}

	devm_kfree(dev, filter);
	(void)sxe2_acl_slot_id_set(adapter->acl_ctxt.slots, max_filter_cnt);
	LOG_DEBUG_BDF("acl filter del hw done: ret1=%d, ret2=%d\n", ret1, ret2);

	return ret1 ? ret1 : ret2;
}

s32 sxe2_acl_filter_del(struct sxe2_vsi *rule_vsi, struct sxe2_acl_filter *filter)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = rule_vsi->adapter;
	u16 ori_vsi_id = 0;
	struct sxe2_vsi *ori_vsi = NULL;
	u32 flow_id = 0;

	ori_vsi_id = filter->ori_vsi_hw;
	flow_id = filter->filter_id;
	ori_vsi = sxe2_vsi_get_by_idx(adapter, ori_vsi_id);

	if (!ori_vsi) {
		LOG_DEBUG_BDF("acl filter del: no ori_vsi, flow_id=%u, ori_vsi_hw=%u\n",
			      flow_id, ori_vsi_id);
		return -EINVAL;
	}

	LOG_DEBUG_BDF("acl filter del: flow_id=%u, ori_vsi_id=%u\n",
		      flow_id, ori_vsi->id_in_pf);

	ret = sxe2_acl_filter_del_hw(ori_vsi, filter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 acl delete filter failed, flow_id=%u,\t"
					  "ori_vsi_id=%u, ret:%d\n",
					  flow_id, ori_vsi->id_in_pf, ret);
	}

	return ret;
}

s32 sxe2_acl_del_filter_by_vsi(struct sxe2_vsi *rule_vsi)
{
	s32 ret = 0;
	s32 error = 0;
	struct sxe2_adapter *adapter = rule_vsi->adapter;
	struct sxe2_acl_filter *filter = NULL;
	struct sxe2_acl_filter *tmp = NULL;
	struct sxe2_vsi_acl *vsi_acl = &rule_vsi->acl;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return 0;

	LOG_DEBUG_BDF("acl del filter by vsi start: rule_vsi_id=%u\n",
		      rule_vsi->idx_in_dev);

	mutex_lock(&vsi_acl->flow_cfg_lock);
	list_for_each_entry_safe(filter, tmp, &rule_vsi->acl.filter_list, l_node) {
		ret = sxe2_acl_filter_del(rule_vsi, filter);
		if (ret) {
			LOG_ERROR_BDF("sxe2 acl delete filter failed, rule_vsi_id=%u, ret:%d\n",
				      rule_vsi->idx_in_dev, ret);
			error = ret;
		}
	}

	mutex_unlock(&vsi_acl->flow_cfg_lock);

	LOG_DEBUG_BDF("acl del filter by vsi done: rule_vsi_id=%u, error=%d\n",
		      rule_vsi->idx_in_dev, error);

	return error;
}

STATIC s32 sxe2_acl_hw_stats_get(struct sxe2_adapter *adapter, u16 stat_index,
				 u32 is_clear, struct sxe2_fwc_acl_stats_resp *resp)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_acl_stats_req req = {};

	if (!test_bit(SXE2_FLAG_ACL_EXT_CAPABLE, adapter->flags))
		return -EOPNOTSUPP;

	req.is_clear = (u8)is_clear;
	req.counter_idx = cpu_to_le16(stat_index);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_ACL_STATS_GET,
				  &req, sizeof(req), resp, sizeof(*resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 acl get state failed, stat_index=%u, ret=%d",
			      stat_index, ret);
	}
	return ret;
}

STATIC s32 sxe2_acl_stats_clear_by_vsi(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_acl_stat_node *stat_node = NULL;
	struct sxe2_acl_stat_node *tmp = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	u16 vsi_id = vsi->id_in_pf;
	struct sxe2_fwc_acl_stats_resp resp = {};

	mutex_lock(&adapter->acl_ctxt.acl_stat_ctxt.acl_stat_lock);

	list_for_each_entry_safe(stat_node, tmp,
				 &adapter->acl_ctxt.acl_stat_ctxt.acl_stat_list,
				 l_node) {
		if (stat_node->vsi_id == vsi_id) {
			ret = sxe2_acl_hw_stats_get(adapter, stat_node->stat_index, true, &resp);
			if (ret) {
				LOG_ERROR_BDF("sxe2 acl stats clear failed,\t"
					      "stat_index=%u, ret=%d",
					      stat_node->stat_index, ret);
				break;
			}
			list_del(&stat_node->l_node);
			devm_kfree(dev, stat_node);
			adapter->acl_ctxt.acl_stat_ctxt.stat_cnt--;
		}
	}

	mutex_unlock(&adapter->acl_ctxt.acl_stat_ctxt.acl_stat_lock);
	return ret;
}

static s32 sxe2_acl_queue_vsi_map_init(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 i;
	u16 offset;

	sxe2_for_each_vsi_alloc_rxq(vsi, i)
	{
		offset = vsi->rxqs.q[i]->idx_in_pf + adapter->q_ctxt.rxq_base_idx_in_dev;
		ret = sxe2_fwc_acl_qvsi_map_set(adapter, offset, vsi->idx_in_dev);
		if (ret) {
			LOG_ERROR_BDF("sxe2 acl queue vsi map init failed, ret:%d\n", ret);
			goto l_end;
		}
	}
l_end:
	return ret;
}

s32 sxe2_vsi_acl_init(struct sxe2_vsi *vsi)
{
	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, vsi->adapter->flags))
		return 0;

	memset(&vsi->acl, 0, sizeof(vsi->acl));
	mutex_init(&vsi->acl.flow_cfg_lock);
	INIT_LIST_HEAD(&vsi->acl.filter_list);
	INIT_LIST_HEAD(&vsi->acl.flow_cfg_list);
	bitmap_fill(vsi->acl.filter_ids, SXE2_ACL_MAX_NUM_ENTRY);

	if (test_bit(SXE2_FLAG_ACL_EXT_CAPABLE, vsi->adapter->flags))
		return sxe2_acl_queue_vsi_map_init(vsi);
	return 0;
}

void sxe2_vsi_acl_deinit(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_acl *vsi_acl = &vsi->acl;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, vsi->adapter->flags))
		return;

	(void)sxe2_acl_del_filter_by_vsi(vsi);
	(void)sxe2_acl_stats_clear_by_vsi(vsi);

	mutex_destroy(&vsi_acl->flow_cfg_lock);
	bitmap_zero(vsi->acl.filter_ids, SXE2_ACL_MAX_NUM_ENTRY);
}

STATIC struct sxe2_acl_filter *sxe2_acl_find_filter_by_id_unlock(struct sxe2_vsi_acl *vsi_acl,
								 u64 loc)
{
	struct sxe2_acl_filter *filter_tmp = NULL;
	struct sxe2_acl_filter *filter_find = NULL;

	list_for_each_entry(filter_tmp, &vsi_acl->filter_list, l_node) {
		if (loc == filter_tmp->filter_id) {
			filter_find = filter_tmp;
			break;
		}
	}

	return filter_find;
}

s32 sxe2_acl_del_filter_by_id(struct sxe2_vsi *vsi, u64 filter_id)
{
	s32 ret = -ENOENT;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_acl_filter *filter = NULL;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, vsi->adapter->flags)) {
		LOG_INFO_BDF("acl not supported.\n");
		return -EOPNOTSUPP;
	}

	mutex_lock(&adapter->acl_ctxt.filter_lock);
	filter = sxe2_acl_find_filter_by_id_unlock(&vsi->acl, filter_id);
	if (filter) {
		ret = sxe2_acl_filter_del(vsi, filter);
		if (ret) {
			LOG_ERROR_BDF("delete filter failed, filter_id:%llu, ret:%d\n",
				      filter_id, ret);
		}
	} else {
		LOG_ERROR_BDF("filter not found, filter_id:%llu.\n", filter_id);
	}

	mutex_unlock(&adapter->acl_ctxt.filter_lock);
	return ret;
}

STATIC u8 sxe2_acl_field_width(enum sxe2_flow_fld_id fld)
{
	switch (fld) {
	case SXE2_FLOW_FLD_ID_ETH_DA:
	case SXE2_FLOW_FLD_ID_ETH_SA:
		return ETH_ALEN;
	case SXE2_FLOW_FLD_ID_IPV4_DA:
	case SXE2_FLOW_FLD_ID_IPV4_SA:
		return SXE2_FLOW_FLD_SZ_IPV4_ADDR;
	case SXE2_FLOW_FLD_ID_IPV6_DA:
	case SXE2_FLOW_FLD_ID_IPV6_SA:
		return SXE2_FLOW_FLD_SZ_IPV6_ADDR;
	case SXE2_FLOW_FLD_ID_TCP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_TCP_DST_PORT:
	case SXE2_FLOW_FLD_ID_UDP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_UDP_DST_PORT:
	case SXE2_FLOW_FLD_ID_SCTP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_SCTP_DST_PORT:
		return SXE2_FLOW_FLD_SZ_PORT;
	default:
		LOG_WARN("unknown acl filed id:%d, returning 0.\n", fld);
		return 0;
	}
}

STATIC s32 sxe2_acl_fields_width_check(unsigned long *fld_spec)
{
	u64 i;
	u16 total = 0;

	for_each_set_bit(i, fld_spec, SXE2_FLOW_FLD_ID_MAX) {
		total += sxe2_acl_field_width((enum sxe2_flow_fld_id)i);
	}

	if (total > SXE2_FW_ACL_KEY_WIDTH_BYTES * SXE2_ACL_MAX_CASCADE_WIDTH - 3) {
		LOG_ERROR("acl fields total width %u exceeds avail %u.\n",
			  total, SXE2_FW_ACL_KEY_WIDTH_BYTES * SXE2_ACL_MAX_CASCADE_WIDTH - 3);
		return -ENOSPC;
	}

	return 0;
}

STATIC s32 sxe2_com_acl_input_parse(struct sxe2_acl_filter *filter,
				    struct sxe2_fnav_flow_seg *seg,
				    const struct sxe2_flow_pattern_ext *pattern,
				    u16 flow_type)
{
	struct sxe2_fnav_filter_full_key *full_key = &filter->full_key;
	const struct sxe2_flow_item_ext *it;
	bool has_l4 = false;
	u32 weight;
	s32 ret = 0;
	DECLARE_BITMAP(fld_spec, SXE2_FLOW_FLD_ID_MAX);
	DECLARE_BITMAP(head_spec, SXE2_FLOW_HDR_MAX);

	bitmap_zero(fld_spec, SXE2_FLOW_FLD_ID_MAX);
	bitmap_zero(head_spec, SXE2_FLOW_HDR_MAX);

	if (test_bit(SXE2_FLOW_HDR_ETH, pattern->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_ETH);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_DA, pattern->map_spec)) {
			memcpy(&full_key->eth.h_dest, &it->val.eth.dst_addr,
			       ETH_ALEN * sizeof(u8));
			memcpy(&full_key->eth_mask.h_dest,
			       &it->mask.eth.dst_addr, ETH_ALEN * sizeof(u8));
			set_bit(SXE2_FLOW_FLD_ID_ETH_DA, fld_spec);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_SA, pattern->map_spec)) {
			memcpy(&full_key->eth.h_source, &it->val.eth.src_addr,
			       ETH_ALEN * sizeof(u8));
			memcpy(&full_key->eth_mask.h_source,
			       &it->mask.eth.src_addr, ETH_ALEN * sizeof(u8));
			set_bit(SXE2_FLOW_FLD_ID_ETH_SA, fld_spec);
		}

		set_bit(SXE2_FLOW_HDR_ETH, head_spec);
	}

	if (test_bit(SXE2_FLOW_HDR_IPV4, pattern->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_IPV4);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_DA, pattern->map_spec)) {
			full_key->ip.v4.dst_ip = it->val.ipv4.daddr;
			full_key->mask.v4.dst_ip = it->mask.ipv4.daddr;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, fld_spec);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_SA, pattern->map_spec)) {
			full_key->ip.v4.src_ip = it->val.ipv4.saddr;
			full_key->mask.v4.src_ip = it->mask.ipv4.saddr;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, fld_spec);
		}

		set_bit(SXE2_FLOW_HDR_IPV4, head_spec);
	}

	if (test_bit(SXE2_FLOW_HDR_IPV6, pattern->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_IPV6);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_DA, pattern->map_spec)) {
			memcpy(&full_key->ip.v6.dst_ip, &it->val.ipv6.daddr,
			       sizeof(full_key->ip.v6.dst_ip));
			memcpy(&full_key->mask.v6.dst_ip, &it->mask.ipv6.daddr,
			       sizeof(full_key->mask.v6.dst_ip));
			set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, fld_spec);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_SA, pattern->map_spec)) {
			memcpy(&full_key->ip.v6.src_ip, &it->val.ipv6.saddr,
			       sizeof(full_key->ip.v6.src_ip));
			memcpy(&full_key->mask.v6.src_ip, &it->mask.ipv6.saddr,
			       sizeof(full_key->mask.v6.src_ip));
			set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, fld_spec);
		}
		set_bit(SXE2_FLOW_HDR_IPV6, head_spec);
	}

	if (test_bit(SXE2_FLOW_HDR_TCP, pattern->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_TCP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, pattern->map_spec)) {
			full_key->l4.src_port = it->val.tcp.source;
			full_key->l4_mask.src_port = it->mask.tcp.source;
			set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, fld_spec);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, pattern->map_spec)) {
			full_key->l4.dst_port = it->val.tcp.dest;
			full_key->l4_mask.dst_port = it->mask.tcp.dest;
			set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, fld_spec);
		}

		set_bit(SXE2_FLOW_HDR_TCP, head_spec);
		full_key->ip.v4.proto = IPPROTO_TCP;
		has_l4 = true;
	}

	if (test_bit(SXE2_FLOW_HDR_UDP, pattern->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_UDP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, pattern->map_spec)) {
			full_key->l4.src_port = it->val.udp.source;
			full_key->l4_mask.src_port = it->mask.udp.source;
			set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, fld_spec);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, pattern->map_spec)) {
			full_key->l4.dst_port = it->val.udp.dest;
			full_key->l4_mask.dst_port = it->mask.udp.dest;
			set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, fld_spec);
		}

		set_bit(SXE2_FLOW_HDR_UDP, head_spec);
		full_key->ip.v4.proto = IPPROTO_UDP;
		has_l4 = true;
	}

	if (test_bit(SXE2_FLOW_HDR_SCTP, pattern->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_SCTP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, pattern->map_spec)) {
			full_key->l4.src_port = it->val.sctp.src_port;
			full_key->l4_mask.src_port = it->mask.sctp.src_port;
			set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, fld_spec);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, pattern->map_spec)) {
			full_key->l4.dst_port = it->val.sctp.dst_port;
			full_key->l4_mask.dst_port = it->mask.sctp.dst_port;
			set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, fld_spec);
		}

		set_bit(SXE2_FLOW_HDR_SCTP, head_spec);
		full_key->ip.v4.proto = IPPROTO_SCTP;
		has_l4 = true;
	}

	if (!bitmap_equal(pattern->map_spec, fld_spec, SXE2_FLOW_FLD_ID_MAX)) {
		LOG_ERROR("map_spec not match.\n");
		return -EINVAL;
	}

	if (flow_type != SXE2_FLOW_MAC_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV4_TCP_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV4_UDP_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV4_SCTP_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV4_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV6_TCP_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV6_UDP_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV6_SCTP_PAY &&
	    flow_type !=  SXE2_FLOW_MAC_IPV6_PAY) {
		LOG_ERROR("flow_type:%d not support.\n", flow_type);
		return -EOPNOTSUPP;
	}

	weight = bitmap_weight(head_spec, SXE2_FLOW_HDR_MAX);
	if (weight > 3 || weight == 0) {
		LOG_ERROR("head_spec weight is %d, max is 3.\n", weight);
		return -EINVAL;
	}

	if (test_bit(SXE2_FLOW_HDR_IPV4, head_spec) && !has_l4) {
		set_bit(SXE2_FLOW_HDR_IPV_OTHER, head_spec);
		full_key->ip.v4.proto = 0;
	}

	if (test_bit(SXE2_FLOW_HDR_IPV6, head_spec) && !has_l4) {
		set_bit(SXE2_FLOW_HDR_IPV_OTHER, head_spec);
			full_key->ip.v6.proto = 0;
	}

	ret = sxe2_acl_fields_width_check(fld_spec);
	if (ret)
		return ret;

	bitmap_copy(seg->headers, head_spec, SXE2_FLOW_HDR_MAX);
	bitmap_copy(seg->fields, fld_spec, SXE2_FLOW_FLD_ID_MAX);
	filter->flow_type = flow_type;
	return 0;
}

STATIC void sxe2_acl_stat_ctrl_convert(enum sxe2_fnav_stat_ctrl_type ori_stat_ctrl,
				       u32 *stat_ctrl)
{
	switch (ori_stat_ctrl) {
	case SXE2_FNAV_STAT_ENA_PKTS:
		*stat_ctrl = SXE2_ACL_ACTION_MDID_CNT_PKT;
		break;
	case SXE2_FNAV_STAT_ENA_BYTES:
		*stat_ctrl = SXE2_ACL_ACTION_MDID_CNT_BYTE;
		break;
	case SXE2_FNAV_STAT_ENA_ALL:
	case SXE2_FNAV_STAT_ENA_NONE:
	default:
		*stat_ctrl = SXE2_ACL_ACTION_MDID_CNT_PKT_BYTE;
		break;
	}
}

STATIC u16 sxe2_qindex_in_hw_get_by_vsi(struct sxe2_adapter *adapter, u16 dst_vsi_id, u16 q_index)
{
	struct sxe2_vsi *dst_vsi;

	dst_vsi = sxe2_vsi_get_by_idx(adapter, dst_vsi_id);
	if (!dst_vsi) {
		LOG_ERROR_BDF("Failed to get vsi, vsi_id=%d\n", dst_vsi_id);
		return 0;
	}

	return (adapter->q_ctxt.rxq_base_idx_in_dev + dst_vsi->rxqs.q[q_index]->idx_in_pf);
}

STATIC u8 sxe2_com_acl_action_parse(struct sxe2_adapter *adapter,
				    struct sxe2_acl_flow_action *action,
				    struct sxe2_flow_action *flow_action)
{
	u32 stat_ctrl;
	u16 q_index_in_dev;
	u16 dst_vsi_id;
	u8 cnt = 0;

	if (test_bit(SXE2_FLOW_ACTION_QUEUE, flow_action->act_types)) {
		dst_vsi_id = flow_action->queue.vsi_index;
		action[cnt].type = SXE2_ACL_ACT_QINDEX;
		action[cnt].data.acl_act.mdid = SXE2_ACL_ACTION_MDID_RX_DST_Q;
		action[cnt].data.acl_act.prio = 3;
		q_index_in_dev = sxe2_qindex_in_hw_get_by_vsi(adapter, dst_vsi_id,
							      flow_action->queue.q_index);
		action[cnt].data.acl_act.value = cpu_to_le16(q_index_in_dev);
		cnt++;
	}

	if (test_bit(SXE2_FLOW_ACTION_DROP, flow_action->act_types)) {
		action[cnt].type = SXE2_ACL_ACT_DROP;
		action[cnt].data.acl_act.mdid = SXE2_ACL_ACTION_MDID_PKT_DROP;
		action[cnt].data.acl_act.prio = 3;
		action[cnt].data.acl_act.value = cpu_to_le16(0x1);
		cnt++;
	}

	if (test_bit(SXE2_FLOW_ACTION_Q_REGION, flow_action->act_types)) {
		dst_vsi_id = flow_action->q_region.vsi_index;
		action[cnt].type = SXE2_ACL_ACT_QGROUP;
		action[cnt].data.acl_act.mdid = SXE2_ACL_ACTION_MDID_RX_DST_Q_REGION;
		action[cnt].data.acl_act.prio = 3;
		q_index_in_dev = sxe2_qindex_in_hw_get_by_vsi(adapter, dst_vsi_id,
							      flow_action->q_region.q_index);
		action[cnt].data.acl_act.value =
				((cpu_to_le16(q_index_in_dev) & 0x7ff)
				 << 3) |
				(cpu_to_le16(flow_action->q_region.region) & 0x7);
		cnt++;
	}

	if (test_bit(SXE2_FLOW_ACTION_COUNT, flow_action->act_types)) {
		action[cnt].type = SXE2_ACL_ACT_OTHER;
		sxe2_acl_stat_ctrl_convert(flow_action->count.stat_ctrl, &stat_ctrl);
		action[cnt].data.acl_act.mdid = stat_ctrl;
		action[cnt].data.acl_act.prio = 3;
		action[cnt].data.acl_act.value = cpu_to_le16(flow_action->count.stat_index);
		cnt++;
	}

	return cnt;
}

STATIC s32 sxe2_com_acl_filter_add_internal(struct sxe2_vsi *ori_vsi,
					    struct sxe2_vsi *rule_vsi,
					    u16 flow_type,
					    const struct sxe2_flow_pattern_ext *pattern,
					    struct sxe2_flow_action *action,
					    u32 filter_id)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = ori_vsi->adapter;
	struct sxe2_acl_flow_action acts[SXE2_FLOW_ACTION_MAX] = {};
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_fnav_flow_seg *seg = NULL;
	struct sxe2_acl_flow_cfg *flow_cfg = NULL;
	struct sxe2_acl_filter *filter = NULL;
	bool new_alloc_flow = false;
	u8 action_cnt = 0;

	flow_cfg = sxe2_acl_find_flow_cfg_by_flow_type(ori_vsi, flow_type);
	if (!flow_cfg) {
		flow_cfg = devm_kzalloc(dev, sizeof(*flow_cfg), GFP_KERNEL);
		if (!flow_cfg) {
			LOG_ERROR_BDF("no memory for flow cfg.\n");
			ret = -ENOMEM;
			goto l_end;
		}
		flow_cfg->flow_type = flow_type;
		new_alloc_flow = true;
	}

	action_cnt = sxe2_com_acl_action_parse(adapter, acts, action);
	if (action_cnt == 0 || action_cnt > SXE2_ACL_ACTION_NUM_PER_ENTRY) {
		LOG_ERROR_BDF("no action or action_cnt is %d.\n", action_cnt);
		ret = -EINVAL;
		goto l_free_cfg;
	}
	LOG_DEBUG_BDF("action_cnt is %d.\n", action_cnt);

	seg = devm_kzalloc(dev, sizeof(*seg), GFP_KERNEL);
	if (!seg) {
		LOG_ERROR_BDF("no memory for seg.\n");
		ret = -ENOMEM;
		goto l_free_cfg;
	}

	filter = devm_kzalloc(dev, sizeof(*filter), GFP_KERNEL);
	if (!filter) {
		LOG_ERROR_BDF("no memory for input.\n");
		ret = -ENOMEM;
		goto l_free_seg;
	}

	ret = sxe2_com_acl_input_parse(filter, seg, pattern, flow_type);
	if (ret) {
		LOG_ERROR_BDF("acl input parse failed, ret:%d\n", ret);
		goto l_free_filter;
	}

	filter->ori_vsi_sw = ori_vsi->id_in_pf;
	filter->ori_vsi_hw = ori_vsi->idx_in_dev;
	filter->rule_vsi_sw = rule_vsi->id_in_pf;

	ret = sxe2_acl_flow_cfg_add(ori_vsi, flow_cfg, seg);
	if (ret == -EEXIST) {
		seg = NULL;
		LOG_DEBUG_BDF("acl rule exist.\n");
		if (new_alloc_flow)
			new_alloc_flow = false;
		ret = 0;
	} else if (ret) {
		seg = NULL;
		LOG_ERROR_BDF("outer rule add failed, ret:%d\n", ret);
		goto l_free_filter;
	}

	if (ret == 0 && new_alloc_flow)
		sxe2_acl_flow_cfg_add_list(ori_vsi, flow_cfg);

	INIT_LIST_HEAD(&filter->l_node);
	ret = sxe2_acl_lut_entry_add(ori_vsi, rule_vsi, filter, acts);
	if (ret) {
		LOG_ERROR_BDF("acl lut entry add failed, ret:%d\n", ret);
		(void)sxe2_acl_filter_del(ori_vsi, filter);
		goto l_end;
	}

	filter->filter_id = SXE2_GEN_FILTER_ID(rule_vsi->idx_in_dev, filter_id);
	LOG_DEBUG_BDF("filter_id:%llu\n", filter->filter_id);
	goto l_end;

l_free_filter:
	if (filter)
		devm_kfree(dev, filter);
l_free_seg:
	if (seg)
		devm_kfree(dev, seg);
l_free_cfg:
	if (new_alloc_flow) {
		if (flow_cfg)
			devm_kfree(dev, flow_cfg);
	}
l_end:
	return ret;
}

s32 sxe2_com_add_acl_filter(struct sxe2_adapter *adapter, u16 ori_vsi_id,
			    u16 rule_vsi_id, u16 flow_type,
			      const struct sxe2_flow_pattern_ext *pattern,
			      struct sxe2_flow_action *action, u32 *flow_id)
{
	struct sxe2_vsi *ori_vsi = NULL;
	struct sxe2_vsi *rule_vsi = NULL;
	u32 pos = 0;
	s32 ret = 0;

	LOG_INFO_BDF("add acl filter, ori_vsi_id(in_pf)=%u, rule_vsi_id(in_pf)=%u, flow_type=%u\n",
		     ori_vsi_id, rule_vsi_id, flow_type);

	mutex_lock(&adapter->vsi_ctxt.lock);
	ori_vsi = adapter->vsi_ctxt.vsi[ori_vsi_id];
	rule_vsi = adapter->vsi_ctxt.vsi[rule_vsi_id];
	if (!ori_vsi || !rule_vsi) {
		LOG_ERROR_BDF("vsi is null, ori_vsi_id(in_pf)=%u, rule_vsi_id(in_pf)=%u, "
			      "base_idx_in_dev=%u\n",
			      ori_vsi_id, rule_vsi_id,
			      adapter->vsi_ctxt.base_idx_in_dev);
		ret = -EINVAL;
		goto l_end;
	}
	LOG_INFO_BDF("acl vsi found, ori(idx_in_dev=%u type=%d), rule(idx_in_dev=%u type=%d)\n",
		     ori_vsi->idx_in_dev, ori_vsi->type, rule_vsi->idx_in_dev, rule_vsi->type);

	pos = find_next_bit(rule_vsi->acl.filter_ids, SXE2_ACL_MAX_NUM_ENTRY, 0);
	if (pos >= SXE2_ACL_MAX_NUM_ENTRY) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_com_acl_filter_add_internal(ori_vsi, rule_vsi, flow_type,
					       pattern, action, pos);
	if (ret) {
		LOG_ERROR_BDF("failed to add acl filter, ret:%d\n", ret);
		goto l_end;
	}

	clear_bit(pos, rule_vsi->acl.filter_ids);
	*flow_id = pos;

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_com_flow_acl_filter_del_by_flow_id(struct sxe2_adapter *adapter,
					    u16 rule_vsi_id, u32 flow_id)
{
	s32 ret = 0;
	struct sxe2_vsi *rule_vsi = NULL;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags)) {
		LOG_INFO_BDF("acl not supported.\n");
		return -EOPNOTSUPP;
	}

	LOG_INFO_BDF("del acl filter, rule_vsi_id(in_pf)=%u, flow_id=%u\n",
		     rule_vsi_id, flow_id);

	mutex_lock(&adapter->vsi_ctxt.lock);
	rule_vsi = adapter->vsi_ctxt.vsi[rule_vsi_id];
	if (!rule_vsi) {
		LOG_ERROR_BDF("vsi is null, rule_vsi_id(in_pf)=%u, base_idx_in_dev=%u\n",
			      rule_vsi_id, adapter->vsi_ctxt.base_idx_in_dev);
		ret = -EINVAL;
		mutex_unlock(&adapter->vsi_ctxt.lock);
		return ret;
	}
	ret = sxe2_acl_del_filter_by_id(rule_vsi,
					SXE2_GEN_FILTER_ID(rule_vsi->idx_in_dev, flow_id));
	if (ret)
		LOG_ERROR_BDF("delete acl filter failed, ret:%d\n", ret);

	set_bit(flow_id, rule_vsi->acl.filter_ids);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_acl_stat_idx_alloc_with_lock(struct sxe2_adapter *adapter, u16 vsi_id,
				      u16 *stat_index, bool need_update)
{
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_node *tmp, *pre = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	u16 stat_base_id = adapter->acl_ctxt.acl_stat_ctxt.stat_base;
	u16 stat_num = adapter->acl_ctxt.acl_stat_ctxt.stat_num;
	u16 count = adapter->acl_ctxt.acl_stat_ctxt.stat_cnt;
	u16 new_index = stat_base_id;

	if (count >= stat_num)
		return -ENOMEM;

	mutex_lock(&adapter->acl_ctxt.acl_stat_ctxt.acl_stat_lock);
	list_for_each_entry(tmp, &adapter->acl_ctxt.acl_stat_ctxt.acl_stat_list, l_node) {
		if (tmp->stat_index > new_index)
			break;
		else if (tmp->stat_index == new_index)
			new_index++;

		pre = tmp;
	}

	stat_node = devm_kzalloc(dev, sizeof(*stat_node), GFP_KERNEL);
	if (!stat_node) {
		LOG_ERROR_BDF("no memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}
	stat_node->stat_index = new_index;
	stat_node->vsi_id = vsi_id;
	stat_node->need_update = need_update;
	if (pre) {
		list_add(&stat_node->l_node, &pre->l_node);
	} else {
		list_add(&stat_node->l_node,
			 &adapter->acl_ctxt.acl_stat_ctxt.acl_stat_list);
	}
	adapter->acl_ctxt.acl_stat_ctxt.stat_cnt++;
	*stat_index = new_index;

l_end:
	mutex_unlock(&adapter->acl_ctxt.acl_stat_ctxt.acl_stat_lock);
	return ret;
}

s32 sxe2_acl_stat_idx_free_with_lock(struct sxe2_adapter *adapter, u16 stat_index)
{
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_node *tmp = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	u16 stat_base_id = adapter->acl_ctxt.acl_stat_ctxt.stat_base;
	u16 stat_num = adapter->acl_ctxt.acl_stat_ctxt.stat_num;
	struct sxe2_fwc_acl_stats_resp resp = {};

	if (stat_index < stat_base_id || stat_index >= stat_base_id + stat_num) {
		LOG_ERROR_BDF("stat_index is out of range.\n");
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_acl_hw_stats_get(adapter, stat_index, true, &resp);
	if (ret) {
		LOG_ERROR_BDF("sxe2 acl now has valid stat index! idx: %u\n",
			      stat_index);
		goto l_end;
	}

	mutex_lock(&adapter->acl_ctxt.acl_stat_ctxt.acl_stat_lock);
	list_for_each_entry_safe(stat_node, tmp,
				 &adapter->acl_ctxt.acl_stat_ctxt.acl_stat_list,
				 l_node) {
		if (stat_node->stat_index == stat_index) {
			list_del(&stat_node->l_node);
			devm_kfree(dev, stat_node);
			break;
		}
	}
	adapter->acl_ctxt.acl_stat_ctxt.stat_cnt--;
	mutex_unlock(&adapter->acl_ctxt.acl_stat_ctxt.acl_stat_lock);

l_end:
	return ret;
}

void sxe2_acl_flow_ctxt_clean(struct sxe2_adapter *adapter)
{
	u32 i;
	struct sxe2_vsi *vsi;
	struct sxe2_acl_flow_cfg *flow_cfg = NULL;

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return;

	for (i = 0; i < adapter->vsi_ctxt.cnt; i++) {
		vsi = adapter->vsi_ctxt.vsi[i];
		if (vsi)
			(void)sxe2_acl_del_filter_by_vsi(vsi);
	}

	sxe2_flow_ppp_comm_ctxt_clean(&adapter->acl_ctxt.ppp);

	for (i = 0; i < adapter->vsi_ctxt.cnt; i++) {
		vsi = adapter->vsi_ctxt.vsi[i];
		if (vsi) {
			mutex_lock(&vsi->acl.flow_cfg_lock);
			list_for_each_entry(flow_cfg, &vsi->acl.flow_cfg_list, l_node) {
				if (flow_cfg->seg)
					flow_cfg->seg->flow_ptr = NULL;
			}
			mutex_unlock(&vsi->acl.flow_cfg_lock);
		}
	}

	sxe2_acl_sw_deinit(adapter);
}

void sxe2_acl_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_acl_tbl_params params = {};

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags))
		return;

	sxe2_acl_tbl_param_calc(adapter, &params);
	ret = sxe2_acl_create_table(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("Failed to create acl table, ret=%d\n", ret);
		return;
	}

	ret = sxe2_acl_create_scenario(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("Failed to create acl scenario, ret=%d\n", ret);
		return;
	}
}
