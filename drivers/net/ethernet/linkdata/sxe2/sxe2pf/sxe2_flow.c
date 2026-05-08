// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_flow.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_compat.h"
#include "sxe2_common.h"
#include "sxe2_log.h"
#include "sxe2_cmd.h"
#include "sxe2_mbx_public.h"
#include "sxe2_flow.h"
#include "sxe2_acl.h"

#define SXE2_FWC_OG_PKG_BUF_MAX (4096)

#define SXE2_FLOW_FIND_FLOW_COND_VSI (0x01)
#define SXE2_FLOW_FIND_FLOW_COND_FLD (0x02)
#define SXE2_FLOW_MAX_RECORD_ATTR_NUM (1024)
#define SXE2_FLOW_FV_SIZE (2)

#define SXE2_SET_USED(x) ((void)(x))

static s32 sxe2_flow_vsi_move_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				   u16 vsi_sw_idx, u16 vsig_idx);

static s32 sxe2_flow_reless_tcam(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				 u16 tcam_idx);

static s32 sxe2_flow_op_vsig_add_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				      struct sxe2_flow_info_node *flow, u16 vsig_idx,
				      bool tail, struct list_head *op_list);
static s32
sxe2_flow_op_adjust_vsig_tcams_priority(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					u16 vsig_idx, struct list_head *op_list);

static s32 sxe2_flow_op_creat_vsig_with_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					     struct sxe2_flow_info_node *flow,
					     u16 vsi_sw_idx,
					     struct list_head *op_list);

static void sxe2_rss_delete_cfg_list(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
				     struct sxe2_flow_info_node *flow);

STATIC u8 sxe2_blk_fv_cnt_get(enum sxe2_block_id blk)
{
	switch (blk) {
	case SXE2_HW_BLOCK_ID_FNAV:
		return SXE2_FNAV_FV_CNT;
	case SXE2_HW_BLOCK_ID_RSS:
		return SXE2_RSS_FV_CNT;
	case SXE2_HW_BLOCK_ID_ACL:
		return SXE2_ACL_FV_CNT;
	default:
		return 0;
	};
}

STATIC u8 sxe2_blk_def_mask_fv_cnt_get(enum sxe2_block_id blk)
{
	switch (blk) {
	case SXE2_HW_BLOCK_ID_FNAV:
		return SXE2_FNAV_DEFAULT_MASK_CNT;
	case SXE2_HW_BLOCK_ID_RSS:
		return 0;
	default:
		return 0;
	};
}

STATIC u8 sxe2_blk_prof_cnt_get(enum sxe2_block_id blk)
{
	switch (blk) {
	case SXE2_HW_BLOCK_ID_FNAV:
		return SXE2_FNAV_PROF_CNT;
	case SXE2_HW_BLOCK_ID_RSS:
		return SXE2_RSS_PROF_CNT;
	case SXE2_HW_BLOCK_ID_ACL:
		return SXE2_ACL_PROF_CNT;
	default:
		return 0;
	};
}

STATIC void *sxe2_section_buf_alloc(struct sxe2_fwc_prof_buf *buf,
				    enum sxe2_class_id type, u16 size)
{
	u16 data_end;
	u16 entry_cnt;
	void *p;

	data_end = le16_to_cpu(buf->data_end);
	entry_cnt = le16_to_cpu(buf->entry_cnt);

	if (data_end + size > SXE2_OG_BUF_SIZE)
		return NULL;

	p = (u8 *)buf + data_end;

	buf->sect[entry_cnt].type = type;
	buf->sect[entry_cnt].offset = cpu_to_le16(data_end);
	buf->sect[entry_cnt].size = cpu_to_le16(size);

	entry_cnt++;
	data_end += size;
	buf->data_end = cpu_to_le16(data_end);
	buf->entry_cnt = cpu_to_le16(entry_cnt);

	return p;
}

STATIC s32 sxe2_add_xlt2_entry(struct sxe2_fwc_prof_buf *buf, enum sxe2_block_id blk,
			       struct list_head *chgs)
{
	s32 ret = 0;
	struct sxe2_og_chg *tmp;
	struct sxe2_fwc_xlt2_entry *entry;

	SXE2_SET_USED(blk);

	list_for_each_entry(tmp, chgs, l_entry) {
		if (tmp->type == SXE2_OG_CHG_TYPE_XLT2) {
			entry = (struct sxe2_fwc_xlt2_entry *)
				 sxe2_section_buf_alloc(buf,
							SXE2_XLT2_CLASS_ID,
							sizeof(struct sxe2_fwc_xlt2_entry));
			if (!entry)
				return -ENOSPC;
			entry->vsi_hw_idx = cpu_to_le16(tmp->info.xlt2.vsi_hw_idx);
			entry->vsig = cpu_to_le16(tmp->info.xlt2.vsig);
			LOG_DEBUG("add vsi[hw:%u] to vsig[%u]\n",
				  tmp->info.xlt2.vsi_hw_idx, tmp->info.xlt2.vsig);
		}
	}

	return ret;
}

STATIC s32 sxe2_add_tcam_entry(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			       struct sxe2_fwc_prof_buf *buf, enum sxe2_block_id blk,
			       struct list_head *chgs)
{
	s32 ret = 0;
	s32 i;
	struct sxe2_og_chg *tmp;
	struct sxe2_fwc_tcam_entry *entry;
	struct sxe2_prof_tcam_entry *tcam_entry;

	SXE2_SET_USED(blk);

	list_for_each_entry(tmp, chgs, l_entry) {
		if (tmp->type == SXE2_OG_CHG_TYPE_TCAM) {
			entry = (struct sxe2_fwc_tcam_entry *)
				 sxe2_section_buf_alloc(buf, SXE2_TCAM_CLASS_ID,
							sizeof(struct sxe2_fwc_tcam_entry));
			if (!entry)
				return -ENOSPC;
			entry->addr = cpu_to_le16(tmp->info.tcam.tcam_idx);
			entry->prof_id = tmp->info.tcam.prof_id;
			tcam_entry = &ppp_ctxt->tcam_entry[tmp->info.tcam.tcam_idx];
			memcpy(entry->key, tcam_entry->key, SXE2_TCAM_KEY_LEN);
			LOG_DEBUG("add tcam[%u]\n", tmp->info.tcam.tcam_idx);
			for (i = 0; i < SXE2_TCAM_KEY_LEN; i++)
				LOG_DEBUG("\tkey[%d]: %u\n", i, tcam_entry->key[i]);
			LOG_DEBUG("\tprofile:%u\n", tmp->info.tcam.prof_id);
		}
	}

	return ret;
}

STATIC s32 sxe2_add_es_entry(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			     struct sxe2_fwc_prof_buf *buf, enum sxe2_block_id blk,
			     struct list_head *chgs)
{
	s32 ret = 0;
	u8 i = 0;
	struct sxe2_og_chg *tmp;
	struct sxe2_fwc_es_entry *entry;
	struct sxe2_flow_hw_prof *hw_prof;

	list_for_each_entry(tmp, chgs, l_entry) {
		if (tmp->type == SXE2_OG_CHG_TYPE_ES) {
			entry = (struct sxe2_fwc_es_entry *)
				 sxe2_section_buf_alloc(buf, SXE2_EXTRACTOR_CLASS_ID,
							sizeof(struct sxe2_fwc_es_entry));
			if (!entry)
				return -ENOSPC;
			entry->prof_id = tmp->info.es.prof_id;
			entry->cnt = sxe2_blk_fv_cnt_get(blk);
			if (!entry->cnt)
				return -EINVAL;
			LOG_DEBUG("update profile[%u]\n", tmp->info.es.prof_id);
			hw_prof = &ppp_ctxt->hw_prof[tmp->info.es.prof_id];
			for (i = 0; i < entry->cnt; i++) {
				entry->fv[i].prot_id = hw_prof->fv[i].prot_id;
				entry->fv[i].off = cpu_to_le16(hw_prof->fv[i].off);
				LOG_DEBUG("\tfv[%u], protocol: %u, off: %d\n", i,
					  hw_prof->fv[i].prot_id,
					  hw_prof->fv[i].off);
			}
		}
	}

	return ret;
}

s32 sxe2_fwc_update_profile(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			    enum sxe2_block_id blk, struct list_head *chgs)
{
	s32 ret = 0;
	u16 data_end;
	u16 xlt2_cnt = 0;
	u16 tcam_cnt = 0;
	u16 es_cnt = 0;
	u16 entry_cnt = 0;
	struct sxe2_og_chg *tmp;
	struct sxe2_fwc_prof_pkg *pkg = NULL;
	u16 buf_size = 0;
	struct sxe2_fwc_prof_buf *buf;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	buf_size += sizeof(struct sxe2_fwc_prof_buf);
	list_for_each_entry(tmp, chgs, l_entry) {
		switch (tmp->type) {
		case SXE2_OG_CHG_TYPE_XLT2:
			buf_size += sizeof(struct sxe2_fwc_xlt2_entry);
			xlt2_cnt++;
			entry_cnt++;
			break;
		case SXE2_OG_CHG_TYPE_TCAM:
			buf_size += sizeof(struct sxe2_fwc_tcam_entry);
			tcam_cnt++;
			entry_cnt++;
			break;
		case SXE2_OG_CHG_TYPE_ES:
			buf_size += sizeof(struct sxe2_fwc_es_entry);
			es_cnt++;
			entry_cnt++;
			break;
		default:
			break;
		}
	}
	buf_size += (u16)flex_array_size(buf, sect, entry_cnt);

	if (entry_cnt == 0 || buf_size > SXE2_OG_BUF_SIZE) {
		LOG_DEBUG_BDF("have no valid entry cnt(%u) or buf_size(%u)!\n",
			      entry_cnt, buf_size);
		goto l_out;
	}

	pkg = devm_kzalloc(dev, sizeof(struct sxe2_fwc_prof_pkg) + buf_size,
			   GFP_KERNEL);
	if (!pkg) {
		LOG_ERROR_BDF("no memory!\n");
		ret = -ENOMEM;
		goto l_out;
	}

	pkg->blk = blk;
	memset(pkg->buf, 0, buf_size);
	buf = (struct sxe2_fwc_prof_buf *)pkg->buf;

	data_end = offsetof(struct sxe2_fwc_prof_buf, sect);
	data_end += (u16)flex_array_size(buf, sect, entry_cnt);
	buf->data_end = cpu_to_le16(data_end);

	if (xlt2_cnt) {
		ret = sxe2_add_xlt2_entry(buf, blk, chgs);
		if (ret != 0) {
			LOG_ERROR_BDF("add xlt2 entry failed, ret: %d\n", ret);
			goto l_out;
		}
	}

	if (tcam_cnt) {
		ret = sxe2_add_tcam_entry(ppp_ctxt, buf, blk, chgs);
		if (ret != 0) {
			LOG_ERROR_BDF("add tcam entry failed, ret: %d\n", ret);
			goto l_out;
		}
	}

	if (es_cnt) {
		ret = sxe2_add_es_entry(ppp_ctxt, buf, blk, chgs);
		if (ret != 0) {
			LOG_ERROR_BDF("add es entry failed, ret: %d\n", ret);
			goto l_out;
		}
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_OG_CFG_UPDATE, pkg,
				  sizeof(struct sxe2_fwc_prof_pkg) + buf_size, NULL,
				  0);

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

STATIC s32 sxe2_fwc_process_tcam_batch(struct sxe2_adapter *adapter,
				       struct sxe2_fwc_tcam_idx_batch *tcam_batch,
				       u32 size)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_OG_TCAM_ENTRY_BATCH, tcam_batch,
				  size, tcam_batch, size);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("tcam entry batch cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_fwc_alloc_prof_id(struct sxe2_adapter *adapter,
				  enum sxe2_block_id blk, u16 *prof_id)
{
	s32 ret = 0;
	struct sxe2_fwc_prof_id entry;
	struct sxe2_cmd_params cmd = {0};

	entry.blk = blk;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_OG_PROF_ID_ALLOC, &entry,
				  sizeof(struct sxe2_fwc_prof_id), &entry,
				  sizeof(struct sxe2_fwc_prof_id));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("profile id alloc cmd fail, ret=%d\n", ret);
		ret = -EIO;
		goto l_out;
	}

	*prof_id = le16_to_cpu(entry.prof_id);

l_out:
	return ret;
}

STATIC s32 sxe2_fwc_free_prof_id(struct sxe2_adapter *adapter,
				 enum sxe2_block_id blk, u16 prof_id)
{
	s32 ret = 0;
	struct sxe2_fwc_prof_id entry;
	struct sxe2_cmd_params cmd = {0};

	entry.blk = blk;
	entry.prof_id = cpu_to_le16(prof_id);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_OG_PROF_ID_FREE, &entry,
				  sizeof(struct sxe2_fwc_prof_id), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("profile id free cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_fwc_update_mask_sel(struct sxe2_adapter *adapter,
				    enum sxe2_block_id blk, u16 prof_id,
				    u32 mask_sel)
{
	s32 ret = 0;
	struct sxe2_fwc_mask_sel entry;
	struct sxe2_cmd_params cmd = {0};

	entry.blk = blk;
	entry.prof_id = cpu_to_le16(prof_id);
	entry.mask_sel = cpu_to_le32(mask_sel);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_OG_MASK_SEL_UPDATE, &entry,
				  sizeof(struct sxe2_fwc_mask_sel), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("mask sel update cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static inline bool
sxe2_flow_compare_dissector_fld(struct sxe2_flow_dissector_info *dis0,
				struct sxe2_flow_dissector_info *dis1)
{
	return (bitmap_equal(dis0->headers, dis1->headers, SXE2_FLOW_HDR_MAX) &&
		bitmap_equal(dis0->fields, dis1->fields, SXE2_FLOW_FLD_ID_MAX));
}

static inline bool
sxe2_flow_compare_dissector_raw(struct sxe2_flow_dissector_info *dis0,
				struct sxe2_flow_dissector_info *dis1)
{
	if (dis0->raw_cnt != dis1->raw_cnt)
		return false;

	if (memcmp(dis0->raw, dis1->raw, sizeof(dis0->raw)))
		return false;

	return true;
}

static inline bool sxe2_flow_compare_flow(struct sxe2_flow_info_node *flow0,
					  struct sxe2_flow_info_node *flow1)
{
	u16 i;
	bool ret = false;

	if (flow0->dissector_cnt != flow1->dissector_cnt)
		goto l_end;

	for (i = 0; i < flow0->dissector_cnt; i++) {
		if (!sxe2_flow_compare_dissector_fld(&flow0->dissectors[i],
						     &flow1->dissectors[i]))
			goto l_end;

		if (!sxe2_flow_compare_dissector_raw(&flow0->dissectors[i],
						     &flow1->dissectors[i]))
			goto l_end;
	}

	ret = true;
l_end:
	return ret;
}

STATIC u16 sxe2_flow_alloc_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	u16 i;

	for (i = 1; i < SXE2_MAX_VSIG_NUM; i++) {
		if (!ppp_ctxt->vsig[i].used) {
			INIT_LIST_HEAD(&ppp_ctxt->vsig[i].associated_flow_list);
			ppp_ctxt->vsig[i].used = true;
			goto l_end;
		}
	}

	i = SXE2_PPP_DEFAULT_VSIG_IDX;
l_end:
	return i;
}

STATIC s32 sxe2_flow_alloc_hw_prof_id(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				      u8 *prof_id)
{
	s32 ret;
	u16 prof_id_new;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	ret = sxe2_fwc_alloc_prof_id(ppp_ctxt->adapter, ppp_ctxt->block_id,
				     &prof_id_new);
	if (ret != 0) {
		LOG_DEBUG_BDF("failed to alloc block[%u] new hw prof, ret:%d\n",
			      ppp_ctxt->block_id, ret);
		goto l_end;
	}

	*prof_id = (u8)prof_id_new;
	LOG_DEBUG_BDF("alloc block[%u] hw prof, id = %u.\n", ppp_ctxt->block_id,
		      prof_id_new);
l_end:
	return ret;
}

static s32 sxe2_flow_free_hw_prof_id(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				     u8 prof_id)
{
	s32 ret;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	ret = sxe2_fwc_free_prof_id(ppp_ctxt->adapter, ppp_ctxt->block_id, prof_id);
	LOG_DEBUG_BDF("free block[%u] hw prof id[%u], ret:%d.\n", ppp_ctxt->block_id,
		      prof_id, ret);

	return ret;
}

STATIC s32 sxe2_flow_hw_prof_inc_ref(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				     u8 prof_id)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (prof_id >= ppp_ctxt->hw_prof_num) {
		ret = -EINVAL;
		LOG_ERROR_BDF("failed to inc hw prof ref.id:%u >= %u.\n", prof_id,
			      ppp_ctxt->hw_prof_num);
		goto l_end;
	}

	ppp_ctxt->hw_prof[prof_id].ref_cnt++;
l_end:
	return ret;
}

static void sxe2_flow_update_hw_prof_fv(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					u8 prof_id, struct sxe2_fv_word *fv)
{
	if (!fv) {
		memset(ppp_ctxt->hw_prof[prof_id].fv, 0,
		       ppp_ctxt->hw_fv_num * sizeof(*fv));
		ppp_ctxt->hw_prof[prof_id].avail = false;
	} else {
		memcpy(ppp_ctxt->hw_prof[prof_id].fv, fv,
		       ppp_ctxt->hw_fv_num * sizeof(*fv));
	}
}

s32 sxe2_flow_update_fv_mask_sel(struct sxe2_ppp_common_ctxt *ppp_ctxt, u8 prof_id,
				 u32 mask_sel)
{
	s32 ret;

	ret = sxe2_fwc_update_mask_sel(ppp_ctxt->adapter, ppp_ctxt->block_id,
				       prof_id, mask_sel);
	if (ret == 0)
		ppp_ctxt->hw_prof[prof_id].fv_masks_sel = mask_sel;

	return ret;
}

STATIC s32 sxe2_flow_acl_disassoc_prof_scen(struct sxe2_adapter *adapter,
					    u16 prof_id)
{
	s32 ret;
	struct sxe2_fwc_acl_prof_sel_base_req act_scen_dealloc_req;

	memset(&act_scen_dealloc_req, 0, sizeof(act_scen_dealloc_req));

	act_scen_dealloc_req.prof_id = cpu_to_le16(prof_id);
	act_scen_dealloc_req.pf_scenario_num[adapter->pf_idx] =
			SXE2_ACL_INVALID_PF_SCEN_NUM;
	ret = sxe2_fwc_acl_set_scen_prof(adapter, &act_scen_dealloc_req);
	if (ret)
		goto l_end;

l_end:
	return ret;
}

STATIC s32 sxe2_flow_hw_prof_dec_ref(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				     u8 prof_id)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (prof_id >= ppp_ctxt->hw_prof_num) {
		ret = -EINVAL;
		LOG_ERROR_BDF("failed to dec hw prof ref.id:%u >= %u.\n", prof_id,
			      ppp_ctxt->hw_prof_num);
		goto l_end;
	}

	if (ppp_ctxt->hw_prof[prof_id].ref_cnt > 0) {
		ppp_ctxt->hw_prof[prof_id].ref_cnt--;
		if (ppp_ctxt->hw_prof[prof_id].ref_cnt == 0) {
			if (ppp_ctxt->block_id == SXE2_HW_BLOCK_ID_ACL) {
				ret = sxe2_flow_acl_disassoc_prof_scen(ppp_ctxt->adapter,
								       prof_id);
				if (ret) {
					LOG_ERROR("Failed to disassoc prof:%u scen.",
						  prof_id);
					goto l_end;
				}
			}
			sxe2_flow_update_hw_prof_fv(ppp_ctxt, prof_id, NULL);
			ret = sxe2_flow_free_hw_prof_id(ppp_ctxt, prof_id);
		}
	} else {
		LOG_WARN_BDF("dec hw prof ref is %u.\n",
			     ppp_ctxt->hw_prof[prof_id].ref_cnt);
	}

l_end:
	return ret;
}

s32 sxe2_flow_find_vsig_with_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				 u16 vsi_sw_idx, u16 *vsig_idx)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (!vsig_idx || vsi_sw_idx >= SXE2_MAX_VSI_NUM) {
		LOG_ERROR_BDF("invalid param, vsig: %p, vsi: %u\n", vsig_idx,
			      vsi_sw_idx);
		ret = -EINVAL;
		goto l_end;
	}
	*vsig_idx = ppp_ctxt->vsi_to_grp[vsi_sw_idx].idx;
l_end:
	return ret;
}

STATIC bool
sxe2_flow_compare_associated_flow_list(struct list_head *associated_flow_list0,
				       struct list_head *associated_flow_list1)
{
	struct sxe2_associated_flow_node *flow0;
	struct sxe2_associated_flow_node *flow1;
	u16 count0 = 0;
	u16 count1 = 0;
	bool ret = false;

	list_for_each_entry(flow0, associated_flow_list0, l_node) {
		count0++;
	}
	list_for_each_entry(flow1, associated_flow_list1, l_node) {
		count1++;
	}
	if (!count0 || count0 != count1)
		goto l_end;

	flow0 = list_first_entry(associated_flow_list0,
				 struct sxe2_associated_flow_node, l_node);
	flow1 = list_first_entry(associated_flow_list1,
				 struct sxe2_associated_flow_node, l_node);
	while (count0--) {
		if (!sxe2_flow_compare_flow(flow0->flow_ptr, flow1->flow_ptr))
			goto l_end;
		flow0 = list_next_entry(flow0, l_node);
		flow1 = list_next_entry(flow1, l_node);
	}
	ret = true;

l_end:
	return ret;
}

static s32
sxe2_flow_find_vsig_with_associated_flow_list(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					      struct list_head *associated_flow_list,
					      u16 *vsig_idx)
{
	s32 ret = -ENOENT;
	u16 i;

	for (i = 0; i < SXE2_MAX_VSIG_NUM; i++) {
		if (ppp_ctxt->vsig[i].used &&
		    sxe2_flow_compare_associated_flow_list(&ppp_ctxt->vsig[i].associated_flow_list,
							   associated_flow_list)) {
			*vsig_idx = i;
			ret = 0;
			break;
		}
	}

	return ret;
}

STATIC bool sxe2_flow_check_flow_in_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					 struct sxe2_flow_info_node *flow,
					 u16 vsig_idx)
{
	struct sxe2_associated_flow_node *entry;
	bool find = false;

	list_for_each_entry(entry, &ppp_ctxt->vsig[vsig_idx].associated_flow_list,
			    l_node) {
		if (sxe2_flow_compare_flow(entry->flow_ptr, flow)) {
			find = true;
			break;
		}
	}

	return find;
}

STATIC s32 sxe2_flow_op_hw_prof(struct sxe2_ppp_common_ctxt *ppp_ctxt, u8 hw_prof_id,
				struct list_head *op_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_og_chg *chg;
	s32 ret = 0;

	if (ppp_ctxt->hw_prof[hw_prof_id].avail) {
		ret = 0;
		goto l_end;
	}

	chg = devm_kzalloc(dev, sizeof(*chg), GFP_KERNEL);
	if (!chg) {
		LOG_ERROR_BDF("failed to alloc chg op memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	chg->type = SXE2_OG_CHG_TYPE_ES;
	chg->info.es.prof_id = hw_prof_id;
	list_add(&chg->l_entry, op_list);

	ppp_ctxt->hw_prof[hw_prof_id].avail = true;

l_end:
	return ret;
}

STATIC s32 sxe2_flow_get_associated_flow_list(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					      u16 vsig_idx,
					      struct list_head *associated_flow_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *tmp;
	struct sxe2_associated_flow_node *flow;
	s32 ret = 0;

	list_for_each_entry(flow, &ppp_ctxt->vsig[vsig_idx].associated_flow_list,
			    l_node) {
		tmp = (struct sxe2_associated_flow_node *)devm_kmemdup(dev,
								       (void *)flow,
								       sizeof(*flow),
								       GFP_KERNEL);
		if (!tmp) {
			LOG_ERROR_BDF("failed to alloc vsig flow memory.\n");
			ret = -ENOMEM;
			goto l_end;
		}
		list_add_tail(&tmp->l_node, associated_flow_list);
	}

l_end:
	if (ret != 0) {
		list_for_each_entry_safe(flow, tmp, associated_flow_list, l_node) {
			list_del(&flow->l_node);
			devm_kfree(dev, flow);
		}
	}
	return ret;
}

STATIC void
sxe2_flow_list_add_with_priority(struct list_head *head,
				 struct sxe2_associated_flow_node *new_node)
{
	struct sxe2_associated_flow_node *pos;

	list_for_each_entry(pos, head, l_node) {
		if (pos->flow_ptr->priority <= new_node->flow_ptr->priority) {
			list_add_tail(&new_node->l_node, &pos->l_node);
			return;
		}
	}

	list_add_tail(&new_node->l_node, head);
}

STATIC s32 sxe2_flow_add_flow_to_list(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				      struct list_head *associated_flow_list,
				      struct sxe2_flow_info_node *flow)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *associated_flow;
	s32 ret = 0;

	associated_flow = devm_kzalloc(dev, sizeof(*associated_flow), GFP_KERNEL);
	if (!associated_flow) {
		LOG_ERROR_BDF("failed to alloc vsig flow memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	associated_flow->flow_ptr = flow;

	sxe2_flow_list_add_with_priority(associated_flow_list, associated_flow);

l_end:
	return ret;
}

s32 sxe2_flow_op_move_vsi_to_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				  u16 vsi_sw_idx, u16 vsig_idx,
				  struct list_head *op_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_og_chg *chg;
	s32 ret = 0;
	u16 or_vsig_idx;

	chg = devm_kzalloc(dev, sizeof(*chg), GFP_KERNEL);
	if (!chg) {
		LOG_ERROR_BDF("failed to alloc chg op memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &or_vsig_idx);
	if (ret != 0) {
		devm_kfree(dev, chg);
		goto l_end;
	}

	ret = sxe2_flow_vsi_move_vsig(ppp_ctxt, vsi_sw_idx, vsig_idx);
	if (ret != 0) {
		devm_kfree(dev, chg);
		goto l_end;
	}

	chg->type = SXE2_OG_CHG_TYPE_XLT2;
	chg->info.xlt2.vsi_hw_idx = adapter->vsi_ctxt.vsi[vsi_sw_idx]->idx_in_dev;
	chg->info.xlt2.vsig = vsig_idx;
	list_add(&chg->l_entry, op_list);

l_end:
	LOG_INFO_BDF("move vsi[%u](hw_idx:%u) to vsig[%u] ret:%d.\n", vsi_sw_idx,
		     adapter->vsi_ctxt.vsi[vsi_sw_idx]->idx_in_dev, vsig_idx, ret);
	return ret;
}

static s32 sxe2_flow_free_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt, u16 vsig_idx)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *flow;
	struct sxe2_associated_flow_node *tmp;
	u16 vsi_sw_idx = 0;
	u16 i;

	if (vsig_idx >= SXE2_MAX_VSIG_NUM) {
		LOG_ERROR_BDF("invalid param, vsig: %u\n", vsig_idx);
		ret = -EINVAL;
		goto l_end;
	}

	if (!ppp_ctxt->vsig[vsig_idx].used) {
		LOG_ERROR_BDF("vsig: %d unused\n", vsig_idx);
		ret = -ENOENT;
		goto l_end;
	}
	ppp_ctxt->vsig[vsig_idx].used = false;

	list_for_each_entry_safe(flow, tmp,
				 &ppp_ctxt->vsig[vsig_idx].associated_flow_list,
				 l_node) {
		list_del(&flow->l_node);
		devm_kfree(dev, flow);
	}
	INIT_LIST_HEAD(&ppp_ctxt->vsig[vsig_idx].associated_flow_list);

	for (i = 0; i < ppp_ctxt->vsig[vsig_idx].vsi_cnt; i++) {
		vsi_sw_idx = (u16)find_next_bit(ppp_ctxt->vsig[vsig_idx].vsis,
						SXE2_MAX_VSI_NUM, vsi_sw_idx);
		if (vsi_sw_idx >= SXE2_MAX_VSI_NUM) {
			LOG_ERROR_BDF("vsig %d vsi info[%d %d] error.\n", vsig_idx,
				      ppp_ctxt->vsig[vsig_idx].vsi_cnt, i);
			ret = -EINVAL;
		}

		clear_bit(vsi_sw_idx, ppp_ctxt->vsig[vsig_idx].vsis);
		ppp_ctxt->vsi_to_grp[vsi_sw_idx].idx = SXE2_PPP_DEFAULT_VSIG_IDX;
	}
	ppp_ctxt->vsig[vsig_idx].vsi_cnt = 0;

l_end:
	return ret;
}

static s32
sxe2_flow_remove_associated_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				 struct sxe2_associated_flow_node *associated_flow)
{
	s32 ret = 0;
	u16 i;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct sxe2_fwc_tcam_idx_batch *tcam_batch = NULL;
	u16 batch_cnt = 0;
	u32 size;

	for (i = 0; i < associated_flow->tcam_cnt; i++) {
		if (associated_flow->tcams[i].used)
			batch_cnt++;
	}
	if (batch_cnt == 0) {
		ret = 0;
		goto l_end;
	}
	size = sizeof(struct sxe2_fwc_tcam_idx_batch) +
	       batch_cnt * sizeof(struct sxe2_fwc_tcam_info);
	tcam_batch = kzalloc(size, GFP_KERNEL);
	if (!tcam_batch) {
		ret = -ENOMEM;
		goto l_end;
	}
	tcam_batch->blk = ppp_ctxt->block_id;
	tcam_batch->tcam_cnt = cpu_to_le16(batch_cnt);
	for (i = 0; i < associated_flow->tcam_cnt; i++) {
		if (associated_flow->tcams[i].used) {
			batch_cnt--;
			tcam_batch->tcam_info[batch_cnt].action =
					SXE2_FWC_TCAM_ACTION_DEL;
			tcam_batch->tcam_info[batch_cnt].tcam_idx =
					associated_flow->tcams[i].idx;
		}
	}

	ret = sxe2_fwc_process_tcam_batch(adapter, tcam_batch, size);
	if (ret) {
		LOG_ERROR_BDF("batch application for TCAM failed, ret=%d\n", ret);
		goto l_end;
	}

	for (i = 0; i < associated_flow->tcam_cnt; i++) {
		if (associated_flow->tcams[i].used) {
			(void)sxe2_flow_reless_tcam(ppp_ctxt,
						    associated_flow->tcams[i].idx);
			associated_flow->tcams[i].used = false;
		}
	}

l_end:
	kfree(tcam_batch);

	return ret;
}

STATIC s32 sxe2_flow_op_remove_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				    u16 vsig_idx, struct list_head *op_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *flow;
	struct sxe2_associated_flow_node *tmp;
	struct sxe2_og_chg *chg;
	s32 ret = 0;
	u16 vsi_sw_idx = 0;
	u16 i;

	list_for_each_entry_safe(flow, tmp,
				 &ppp_ctxt->vsig[vsig_idx].associated_flow_list,
				 l_node) {
		ret = sxe2_flow_remove_associated_flow(ppp_ctxt, flow);
		if (ret != 0) {
			LOG_ERROR_BDF("tcam entry free cmd done, ret=%d.\n", ret);
			goto l_end;
		}
		list_del(&flow->l_node);
		devm_kfree(dev, flow);
	}

	for (i = 0; i < ppp_ctxt->vsig[vsig_idx].vsi_cnt; i++) {
		vsi_sw_idx = (u16)find_next_bit(ppp_ctxt->vsig[vsig_idx].vsis,
						SXE2_MAX_VSI_NUM, vsi_sw_idx);
		if (vsi_sw_idx == SXE2_MAX_VSI_NUM) {
			LOG_ERROR_BDF("vsig %d vsi info[%d %d] error.\n", vsig_idx,
				      ppp_ctxt->vsig[vsig_idx].vsi_cnt, i);
			ret = -ENOENT;
			goto l_end;
		}
		chg = devm_kzalloc(dev, sizeof(*chg), GFP_KERNEL);
		if (!chg) {
			ret = -ENOMEM;
			goto l_end;
		}

		chg->type = SXE2_OG_CHG_TYPE_XLT2;
		chg->info.xlt2.vsi_hw_idx =
				adapter->vsi_ctxt.vsi[vsi_sw_idx]->idx_in_dev;
		chg->info.xlt2.vsig = SXE2_PPP_DEFAULT_VSIG_IDX;

		list_add(&chg->l_entry, op_list);
	}

	ret = sxe2_flow_free_vsig(ppp_ctxt, vsig_idx);
l_end:
	LOG_DEBUG_BDF("remove vsig[%u] ret:%d\n", vsig_idx, ret);
	return ret;
}

static s32 sxe2_flow_op_crt_vsig_assoc_flow_list(struct sxe2_ppp_common_ctxt *ppp_ctxt,
						 u16 vsi_sw_idx,
						 struct list_head *associated_flow_list,
						 u16 *vsig_idx,
						 struct list_head *op_list)
{
	struct sxe2_associated_flow_node *associated_flow;
	s32 ret = 0;
	u16 vsig_idx_tmp;
	u16 or_vsig_idx;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &or_vsig_idx);
	if (ret != 0)
		goto l_end;

	vsig_idx_tmp = sxe2_flow_alloc_vsig(ppp_ctxt);
	if (vsig_idx_tmp == SXE2_PPP_DEFAULT_VSIG_IDX) {
		ret = -EIO;
		goto l_end;
	}

	ret = sxe2_flow_op_move_vsi_to_vsig(ppp_ctxt, vsi_sw_idx, vsig_idx_tmp,
					    op_list);
	if (ret != 0)
		goto l_free;

	list_for_each_entry(associated_flow, associated_flow_list, l_node) {
		ret = sxe2_flow_op_vsig_add_flow(ppp_ctxt, associated_flow->flow_ptr,
						 vsig_idx_tmp, true, op_list);
		if (ret != 0) {
			LOG_ERROR_BDF("flow op vsig add flow failed, dst_vsig=%u, \t"
				      "ret=%d.\n",
				      vsig_idx_tmp, ret);
			goto l_move;
		}
	}

	*vsig_idx = vsig_idx_tmp;
l_end:
	LOG_DEBUG_BDF("create new vsig[%u](vsi:%u) with flow list, ret:%d.\n",
		      *vsig_idx, vsi_sw_idx, ret);
	return ret;
l_move:
	(void)sxe2_flow_vsi_move_vsig(ppp_ctxt, vsi_sw_idx, or_vsig_idx);
l_free:
	(void)sxe2_flow_free_vsig(ppp_ctxt, vsig_idx_tmp);
	goto l_end;
}

STATIC s32 sxe2_flow_find_vsig_with_only_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					      struct sxe2_flow_info_node *flow,
					      u16 *vsig_idx)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *tmp;
	struct list_head associated_flow_list;
	s32 ret = 0;

	INIT_LIST_HEAD(&associated_flow_list);

	tmp = devm_kzalloc(dev, sizeof(*tmp), GFP_KERNEL);
	if (!tmp) {
		ret = -ENOMEM;
		goto l_end;
	}
	tmp->flow_ptr = flow;
	list_add(&tmp->l_node, &associated_flow_list);

	ret = sxe2_flow_find_vsig_with_associated_flow_list(ppp_ctxt,
							    &associated_flow_list, vsig_idx);
	list_del(&tmp->l_node);
	devm_kfree(dev, tmp);

l_end:
	return ret;
}

static u16 sxe2_flow_associated_flow_cnt(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					 u16 vsig_idx)
{
	struct sxe2_associated_flow_node *flow;
	u16 cnt = 0;

	list_for_each_entry(flow, &ppp_ctxt->vsig[vsig_idx].associated_flow_list,
			    l_node) {
		cnt++;
	}

	return cnt;
}

static s32 sxe2_flow_remove_flow_in_list(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					 struct sxe2_flow_info_node *flow,
					 struct list_head *associated_flow_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *tmp;
	struct sxe2_associated_flow_node *associated_flow;
	s32 ret = -ENOENT;

	SXE2_SET_USED(ppp_ctxt);
	list_for_each_entry_safe(associated_flow, tmp, associated_flow_list, l_node) {
		if (sxe2_flow_compare_flow(associated_flow->flow_ptr, flow)) {
			list_del(&associated_flow->l_node);
			devm_kfree(dev, associated_flow);
			ret = 0;
			break;
		}
	}
	return ret;
}

static s32 sxe2_flow_op_vsig_remove_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					 struct sxe2_flow_info_node *flow,
					 u16 vsig_idx, struct list_head *op_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *tmp;
	struct sxe2_associated_flow_node *associated_flow;
	s32 ret = -ENOENT;

	list_for_each_entry_safe(associated_flow, tmp,
				 &ppp_ctxt->vsig[vsig_idx].associated_flow_list,
				 l_node) {
		if (sxe2_flow_compare_flow(associated_flow->flow_ptr, flow)) {
			if (sxe2_flow_associated_flow_cnt(ppp_ctxt, vsig_idx) == 1) {
				ret = sxe2_flow_op_remove_vsig(ppp_ctxt, vsig_idx,
							       op_list);
				if (ret != 0)
					goto l_end;

			} else {
				ret = sxe2_flow_remove_associated_flow(ppp_ctxt,
								       associated_flow);
				if (ret != 0)
					goto l_end;

				list_del(&associated_flow->l_node);
				devm_kfree(dev, associated_flow);
			}
			break;
		}
	}

l_end:
	return ret;
}

STATIC s32 sxe2_flow_op_flow_assoc_vsi_insert_tmp_list(struct sxe2_ppp_common_ctxt *ppp_ctxt,
						       struct sxe2_flow_info_node *flow,
						       u16 vsi_sw_idx,
						       struct list_head *op_list,
						       struct list_head *associated_flow_list,
						       u16 or_vsig_idx)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	s32 ret = 0;
	bool only_vsi;
	u16 vsig_idx;

	if (sxe2_flow_check_flow_in_vsig(ppp_ctxt, flow, or_vsig_idx)) {
		LOG_INFO_BDF("flow already accessed vsi[%d].\n", vsi_sw_idx);
		ret = -EEXIST;
		goto l_end;
	}

	only_vsi = (ppp_ctxt->vsig[or_vsig_idx].vsi_cnt == 1);

	ret = sxe2_flow_get_associated_flow_list(ppp_ctxt, or_vsig_idx,
						 associated_flow_list);
	if (ret != 0)
		goto l_end;

	ret = sxe2_flow_add_flow_to_list(ppp_ctxt, associated_flow_list, flow);
	if (ret != 0)
		goto l_end;

	ret = sxe2_flow_find_vsig_with_associated_flow_list(ppp_ctxt,
							    associated_flow_list, &vsig_idx);
	if (ret == 0) {
		LOG_DEBUG_BDF("flow accessed vsi, find same flows vsig[%u].\n",
			      vsig_idx);
		ret = sxe2_flow_op_move_vsi_to_vsig(ppp_ctxt, vsi_sw_idx, vsig_idx,
						    op_list);
		if (ret != 0)
			goto l_end;

		if (only_vsi) {
			ret = sxe2_flow_op_remove_vsig(ppp_ctxt, or_vsig_idx,
						       op_list);
			if (ret != 0)
				goto l_end;
		}
	} else if (only_vsi) {
		LOG_DEBUG_BDF("flow accessed vsi, find only vsi vsig[%u].\n",
			      or_vsig_idx);
		ret = sxe2_flow_op_vsig_add_flow(ppp_ctxt, flow, or_vsig_idx, false,
						 op_list);
		if (ret != 0)
			goto l_end;

		ret = sxe2_flow_op_adjust_vsig_tcams_priority(ppp_ctxt, or_vsig_idx,
							      op_list);
		if (ret != 0)
			goto l_end;

	} else {
		ret = sxe2_flow_op_crt_vsig_assoc_flow_list(ppp_ctxt,
							    vsi_sw_idx,
							    associated_flow_list,
							    &vsig_idx, op_list);
		LOG_DEBUG_BDF("flow accessed vsi, or_vsig:%u, create new vsig[%u], \t"
			      "ret:%d.\n",
			      or_vsig_idx, vsig_idx, ret);
		if (ret != 0)
			goto l_end;

		ret = sxe2_flow_op_adjust_vsig_tcams_priority(ppp_ctxt, vsig_idx,
							      op_list);
		if (ret != 0)
			goto l_end;
	}
l_end:
	return ret;
}

static s32 sxe2_flow_op_flow_assoc_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				       struct sxe2_flow_info_node *flow,
				       u16 vsi_sw_idx)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct list_head op_list;
	struct list_head associated_flow_list;
	struct sxe2_associated_flow_node *tmp;
	struct sxe2_associated_flow_node *del;
	struct sxe2_og_chg *tmp_chg;
	struct sxe2_og_chg *del_chg;
	s32 ret;
	u16 vsig_idx;
	u16 or_vsig_idx;

	INIT_LIST_HEAD(&op_list);
	INIT_LIST_HEAD(&associated_flow_list);

	ret = sxe2_flow_op_hw_prof(ppp_ctxt, flow->prof_id, &op_list);
	if (ret != 0)
		goto l_end;

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &or_vsig_idx);
	if (ret == 0 && or_vsig_idx != SXE2_PPP_DEFAULT_VSIG_IDX) {
		ret = sxe2_flow_op_flow_assoc_vsi_insert_tmp_list(ppp_ctxt,
								  flow, vsi_sw_idx, &op_list,
								  &associated_flow_list,
								  or_vsig_idx);
		if (ret)
			goto l_end;

	} else {
		ret = sxe2_flow_find_vsig_with_only_flow(ppp_ctxt, flow, &vsig_idx);
		if (ret == 0) {
			LOG_DEBUG_BDF("flow assoc vsi, find only flow vsig[%d], \t"
				      "move vsi[%u].\n",
				      vsig_idx, vsi_sw_idx);
			ret = sxe2_flow_op_move_vsi_to_vsig(ppp_ctxt, vsi_sw_idx,
							    vsig_idx, &op_list);
			if (ret != 0)
				goto l_end;

		} else {
			ret = sxe2_flow_op_creat_vsig_with_flow(ppp_ctxt, flow,
								vsi_sw_idx, &op_list);
			LOG_DEBUG_BDF("flow accessed vsi, create new vsig, \t"
				      "ret:%d.\n",
				      ret);
			if (ret != 0)
				goto l_end;
		}
	}

	if (ret == 0) {
		ret = sxe2_fwc_update_profile(ppp_ctxt, ppp_ctxt->block_id,
					      &op_list);
	}

l_end:
	list_for_each_entry_safe(del, tmp, &associated_flow_list, l_node) {
		list_del(&del->l_node);
		devm_kfree(dev, del);
	}

	list_for_each_entry_safe(del_chg, tmp_chg, &op_list, l_entry) {
		list_del(&del_chg->l_entry);
		devm_kfree(dev, del_chg);
	}
	return ret;
}

static s32 sxe2_flow_op_flow_dissoc_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					struct sxe2_flow_info_node *flow,
					u16 vsi_sw_idx)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct list_head op_list;
	struct list_head associated_flow_list;
	struct sxe2_associated_flow_node *tmp;
	struct sxe2_associated_flow_node *del;
	struct sxe2_og_chg *tmp_chg;
	struct sxe2_og_chg *del_chg;
	s32 ret;
	u16 vsig_idx;
	bool only_vsi;
	bool only_flow;

	INIT_LIST_HEAD(&op_list);
	INIT_LIST_HEAD(&associated_flow_list);

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &vsig_idx);
	if (ret != 0)
		goto l_end;

	if (vsig_idx == SXE2_PPP_DEFAULT_VSIG_IDX)
		goto l_end;

	only_flow = (sxe2_flow_associated_flow_cnt(ppp_ctxt, vsig_idx) == 1);
	only_vsi = (ppp_ctxt->vsig[vsig_idx].vsi_cnt == 1);

	LOG_DEBUG_BDF("flow dissoc vsi, vsig only_flow:%d only_vsi:%d.\n", only_flow,
		      only_vsi);

	if (only_vsi) {
		if (only_flow) {
			ret = sxe2_flow_op_remove_vsig(ppp_ctxt, vsig_idx, &op_list);
			if (ret != 0)
				goto l_end;
		} else {
			ret = sxe2_flow_op_vsig_remove_flow(ppp_ctxt, flow, vsig_idx,
							    &op_list);
			if (ret != 0)
				goto l_end;
			ret = sxe2_flow_op_adjust_vsig_tcams_priority(ppp_ctxt,
								      vsig_idx, &op_list);
			if (ret != 0)
				goto l_end;
		}
	} else {
		ret = sxe2_flow_get_associated_flow_list(ppp_ctxt, vsig_idx,
							 &associated_flow_list);
		if (ret != 0)
			goto l_end;

		ret = sxe2_flow_remove_flow_in_list(ppp_ctxt, flow,
						    &associated_flow_list);
		if (ret != 0)
			goto l_end;

		if (list_empty(&associated_flow_list)) {
			ret = sxe2_flow_op_move_vsi_to_vsig(ppp_ctxt, vsi_sw_idx,
							    SXE2_PPP_DEFAULT_VSIG_IDX,
							    &op_list);
			if (ret != 0)
				goto l_end;
		} else {
			ret = sxe2_flow_find_vsig_with_associated_flow_list(ppp_ctxt,
									    &associated_flow_list,
									    &vsig_idx);
			if (ret == 0) {
				ret = sxe2_flow_op_move_vsi_to_vsig(ppp_ctxt,
								    vsi_sw_idx, vsig_idx,
								    &op_list);
				if (ret != 0)
					goto l_end;
			} else {
				ret = sxe2_flow_op_crt_vsig_assoc_flow_list(ppp_ctxt,
									    vsi_sw_idx,
									    &associated_flow_list,
									    &vsig_idx,
									    &op_list);
				if (ret != 0)
					goto l_end;
				ret = sxe2_flow_op_adjust_vsig_tcams_priority(ppp_ctxt,
									      vsig_idx,
									      &op_list);
				if (ret != 0)
					goto l_end;
			}
		}
	}

	if (ret == 0) {
		ret = sxe2_fwc_update_profile(ppp_ctxt, ppp_ctxt->block_id,
					      &op_list);
	}

l_end:
	list_for_each_entry_safe(del, tmp, &associated_flow_list, l_node) {
		list_del(&del->l_node);
		devm_kfree(dev, del);
	}
	list_for_each_entry_safe(del_chg, tmp_chg, &op_list, l_entry) {
		list_del(&del_chg->l_entry);
		devm_kfree(dev, del_chg);
	}
	return ret;
}

STATIC void
sxe2_flow_acl_prof_set_fld(struct sxe2_flow_fld *flow_fld,
			   struct sxe2_fwc_acl_prof_sel_base_req *prof_sel_req)
{
	u16 dst, i;
	u8 src;

	src = flow_fld->xtrct.idx * SXE2_FLOW_FV_SIZE +
	      flow_fld->xtrct.disp / BITS_PER_BYTE;
	dst = flow_fld->last_val.val;
	for (i = 0; i < flow_fld->last_val.len; i++)
		prof_sel_req->byte_selection[dst++] = src++;
}

STATIC s32 sxe2_flow_acl_assoc_prof_scen(struct sxe2_adapter *adapter,
					 struct sxe2_flow_info_node *flow_info)
{
	s32 ret;
	struct sxe2_fwc_acl_prof_sel_base_req acl_prof_set;
	struct sxe2_fwc_acl_prof_querey_resp acl_prof_query;
	struct sxe2_flow_dissector_info *dis_info;
	struct sxe2_flow_fld *flow_fld;
	u16 i;

	memset(&acl_prof_set, 0x1f, sizeof(acl_prof_set));
	memset(&acl_prof_query, 0, sizeof(acl_prof_query));

	dis_info = &flow_info->dissectors[0];
	for_each_set_bit(i, dis_info->fields, SXE2_FLOW_FLD_ID_MAX) {
		flow_fld = &dis_info->fld[i];
		sxe2_flow_acl_prof_set_fld(flow_fld, &acl_prof_set);
	}

	for (i = 0; i < dis_info->raw_cnt; i++) {
		flow_fld = &dis_info->raw[i].fld;
		sxe2_flow_acl_prof_set_fld(flow_fld, &acl_prof_set);
	}
	acl_prof_set.prof_id = flow_info->prof_id;
	acl_prof_set.pf_scenario_num[adapter->pf_idx] = flow_info->cfg.scen->scen_id;
	ret = sxe2_fwc_acl_set_scen_prof(adapter, &acl_prof_set);
	if (ret) {
		LOG_ERROR_BDF("Acl prof scen set cmd failed, ret:%d", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC bool
sxe2_flow_check_flow_conflict_in_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				      struct sxe2_flow_info_node *flow_check,
				      u16 vsi_sw_idx)
{
	s32 ret = 0;
	u8 i, j;
	u8 find;
	bool conflict = false;
	u16 or_vsig_idx = SXE2_PPP_DEFAULT_VSIG_IDX;
	struct sxe2_associated_flow_node *assoc_flow;
	struct sxe2_flow_info_node *flow_tmp = NULL;

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &or_vsig_idx);
	if (ret == 0 && or_vsig_idx != SXE2_PPP_DEFAULT_VSIG_IDX) {
		list_for_each_entry(assoc_flow,
				    &ppp_ctxt->vsig[or_vsig_idx].associated_flow_list,
				    l_node) {
			flow_tmp = assoc_flow->flow_ptr;
			if (flow_check->ptg_info.ptg_cnt !=
			    flow_tmp->ptg_info.ptg_cnt)
				continue;
			for (i = 0; i < flow_check->ptg_info.ptg_cnt; i++) {
				find = 0;
				for (j = 0; j < flow_tmp->ptg_info.ptg_cnt; j++) {
					if (flow_check->ptg_info.ptg[i] ==
					    flow_tmp->ptg_info.ptg[j]) {
						find = 1;
						break;
					}
				}
				if (!find)
					break;
			}

			if (find) {
				conflict = true;
				break;
			}
		}
	} else {
	}

	return conflict;
}

s32 sxe2_flow_assoc_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			struct sxe2_flow_info_node *flow, u16 vsi_sw_idx)
{
	s32 ret;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (test_bit(vsi_sw_idx, flow->used_vsi)) {
		LOG_DEBUG_BDF("vsi %d is already assoc with flow.\n", vsi_sw_idx);
		ret = 0;
		goto l_end;
	}

	if (ppp_ctxt->block_id == SXE2_HW_BLOCK_ID_ACL) {
		ret = sxe2_flow_acl_assoc_prof_scen(ppp_ctxt->adapter, flow);
		if (ret)
			goto l_end;
	}

	ret = sxe2_flow_op_flow_assoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
	if (ret != 0) {
		LOG_ERROR_BDF("fail to assoc vsi to flow, ret = %d.\n", ret);
		goto l_end;
	}

	set_bit(vsi_sw_idx, flow->used_vsi);
l_end:
	return ret;
}

s32 sxe2_flow_disassoc_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			   struct sxe2_flow_info_node *flow, u16 vsi_sw_idx)
{
	s32 ret;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (!test_bit(vsi_sw_idx, flow->used_vsi)) {
		LOG_DEBUG_BDF("vsi %d is not assoc with flow.\n", vsi_sw_idx);
		ret = 0;
		goto l_end;
	}

	ret = sxe2_flow_op_flow_dissoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
	if (ret != 0) {
		LOG_ERROR_BDF("fail to disassoc vsi to flow, ret = %d.\n", ret);
		goto l_end;
	}

	clear_bit(vsi_sw_idx, flow->used_vsi);
	LOG_DEBUG_BDF("flow[%p] disassoc vsi[%u].\n", flow, vsi_sw_idx);
l_end:
	return ret;
}

s32 sxe2_flow_assoc_vsi_fnav(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			     struct sxe2_flow_info_node *flow, u16 vsi_sw_idx,
			     enum sxe2_fnav_flow_type flow_type)
{
	s32 ret;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (test_bit(vsi_sw_idx, flow->used_vsi)) {
		LOG_DEBUG_BDF("vsi %d is already assoc with flow.\n", vsi_sw_idx);
		ret = 0;
		goto l_end;
	}

	if (!sxe2_fnav_flow_sup_arfs(flow_type) &&
	    sxe2_flow_check_flow_conflict_in_vsig(ppp_ctxt, flow, vsi_sw_idx)) {
		LOG_INFO_BDF("vsi %d is new flow is conflict with same ptgs,.\n",
			     vsi_sw_idx);
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_flow_op_flow_assoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
	if (ret != 0) {
		LOG_ERROR_BDF("fail to assoc vsi to flow, ret = %d.\n", ret);
		goto l_end;
	}

	set_bit(vsi_sw_idx, flow->used_vsi);
l_end:
	return ret;
}

static s32 sxe2_flow_remove_vsi_from_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					  u16 vsi_sw_idx, u16 vsig_idx)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (vsig_idx >= SXE2_MAX_VSIG_NUM || vsi_sw_idx >= SXE2_MAX_VSI_NUM) {
		ret = -EINVAL;
		goto l_end;
	}

	if (!ppp_ctxt->vsig[vsig_idx].used) {
		ret = -ENOENT;
		goto l_end;
	}

	if (vsig_idx == SXE2_PPP_DEFAULT_VSIG_IDX) {
		ret = 0;
		goto l_end;
	}

	if (!test_bit(vsi_sw_idx, ppp_ctxt->vsig[vsig_idx].vsis)) {
		LOG_INFO_BDF("remove vsi error, vsi %d not in vsig %d.\n",
			     vsi_sw_idx, vsig_idx);
		ret = -ENOENT;
		goto l_end;
	}

	ppp_ctxt->vsi_to_grp[vsi_sw_idx].idx = SXE2_PPP_DEFAULT_VSIG_IDX;
	clear_bit(vsi_sw_idx, ppp_ctxt->vsig[vsig_idx].vsis);
	ppp_ctxt->vsig[vsig_idx].vsi_cnt--;

l_end:
	return ret;
}

static s32 sxe2_flow_vsi_move_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				   u16 vsi_sw_idx, u16 vsig_idx)
{
	s32 ret = 0;
	u16 or_vsig_idx;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (vsig_idx >= SXE2_MAX_VSIG_NUM || vsi_sw_idx >= SXE2_MAX_VSI_NUM) {
		ret = -EINVAL;
		goto l_end;
	}

	if (vsig_idx != SXE2_PPP_DEFAULT_VSIG_IDX &&
	    !ppp_ctxt->vsig[vsig_idx].used) {
		ret = -ENOENT;
		goto l_end;
	}

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &or_vsig_idx);
	if (ret != 0)
		goto l_end;

	if (or_vsig_idx == vsig_idx) {
		LOG_DEBUG_BDF("vsi %d already in vsig %d.\n", vsi_sw_idx, vsig_idx);
		ret = 0;
		goto l_end;
	}

	if (or_vsig_idx != SXE2_PPP_DEFAULT_VSIG_IDX) {
		ret = sxe2_flow_remove_vsi_from_vsig(ppp_ctxt, vsi_sw_idx,
						     or_vsig_idx);
		if (ret != 0)
			goto l_end;
	}

	if (vsig_idx == SXE2_PPP_DEFAULT_VSIG_IDX)
		goto l_end;

	ppp_ctxt->vsi_to_grp[vsi_sw_idx].idx = vsig_idx;
	set_bit(vsi_sw_idx, ppp_ctxt->vsig[vsig_idx].vsis);
	ppp_ctxt->vsig[vsig_idx].vsi_cnt++;
l_end:
	return ret;
}

static s32 sxe2_flow_op_creat_vsig_with_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					     struct sxe2_flow_info_node *flow,
					     u16 vsi_sw_idx,
					     struct list_head *op_list)
{
	s32 ret = 0;
	u16 new_vsig = 0;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	new_vsig = sxe2_flow_alloc_vsig(ppp_ctxt);
	if (new_vsig == SXE2_PPP_DEFAULT_VSIG_IDX) {
		ret = -EIO;
		goto l_end;
	}

	ret = sxe2_flow_op_move_vsi_to_vsig(ppp_ctxt, vsi_sw_idx, new_vsig, op_list);
	if (ret != 0)
		goto l_free;

	ret = sxe2_flow_op_vsig_add_flow(ppp_ctxt, flow, new_vsig, false, op_list);
	if (ret != 0)
		goto l_free;

l_end:
	LOG_DEBUG_BDF("create new vsig[%u](vsi:%u) with flow, ret:%d.\n", new_vsig,
		      vsi_sw_idx, ret);
	return ret;
l_free:
	(void)sxe2_flow_free_vsig(ppp_ctxt, new_vsig);
	goto l_end;
}

static s32 sxe2_flow_op_vsig_add_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				      struct sxe2_flow_info_node *flow, u16 vsig_idx,
				      bool tail, struct list_head *op_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_associated_flow_node *associated_flow = NULL;
	struct sxe2_og_chg *chg;

	u8 vl_mask[SXE2_TCAM_KEY_VAL_SZ] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u8 dc_mask[SXE2_TCAM_KEY_VAL_SZ] = {0x00, 0xF0, 0xFF, 0x0F, 0x00};
	u8 nm_mask[SXE2_TCAM_KEY_VAL_SZ] = {0x00, 0x00, 0x00, 0x00, 0x00};
	s32 ret = 0;
	u16 tcam_idx;
	u16 i;
	u32 size;
	struct sxe2_fwc_tcam_idx_batch *tcam_batch = NULL;

	if (sxe2_flow_check_flow_in_vsig(ppp_ctxt, flow, vsig_idx)) {
		ret = -EEXIST;
		goto l_end;
	}

	associated_flow = devm_kzalloc(dev, sizeof(*associated_flow), GFP_KERNEL);
	if (!associated_flow) {
		ret = -ENOMEM;
		goto l_end;
	}

	size = sizeof(struct sxe2_fwc_tcam_idx_batch) +
	       flow->ptg_info.ptg_cnt * sizeof(struct sxe2_fwc_tcam_info);

	tcam_batch = kzalloc(size, GFP_KERNEL);
	if (!tcam_batch) {
		ret = -ENOMEM;
		goto l_free;
	}
	tcam_batch->blk = ppp_ctxt->block_id;
	tcam_batch->tcam_cnt = cpu_to_le16((u16)flow->ptg_info.ptg_cnt);
	for (i = 0; i < flow->ptg_info.ptg_cnt; i++)
		tcam_batch->tcam_info[i].action = SXE2_FWC_TCAM_ACTION_ADD;

	ret = sxe2_fwc_process_tcam_batch(adapter, tcam_batch, size);
	if (ret) {
		LOG_ERROR_BDF("batch application for TCAM failed, ret=%d\n", ret);
		goto l_free;
	}

	associated_flow->flow_ptr = flow;
	associated_flow->tcam_cnt = flow->ptg_info.ptg_cnt;

	for (i = 0; i < associated_flow->tcam_cnt; i++) {
		tcam_idx = le16_to_cpu(tcam_batch->tcam_info[i].tcam_idx);
		associated_flow->tcams[i].idx = tcam_idx;
		associated_flow->tcams[i].ptg = flow->ptg_info.ptg[i];
		associated_flow->tcams[i].prof_id = flow->prof_id;
		associated_flow->tcams[i].used = true;
		LOG_DEBUG_BDF("alloc tcam[%u]\n", tcam_idx);
	}

	for (i = 0; i < associated_flow->tcam_cnt; i++) {
		tcam_idx = tcam_batch->tcam_info[i].tcam_idx;
		chg = devm_kzalloc(dev, sizeof(*chg), GFP_KERNEL);
		if (!chg) {
			ret = -ENOMEM;
			goto l_free;
		}

		chg->type = SXE2_OG_CHG_TYPE_TCAM;
		chg->info.tcam.prof_id = flow->prof_id;
		chg->info.tcam.tcam_idx = tcam_idx;

		LOG_DEBUG_BDF("config tcam, tcam_idx:%u, prof_id:%u, ptg:%u, \t"
			      "vsig:%d, cdid:%u\n",
			      tcam_idx, flow->prof_id, associated_flow->tcams[i].ptg,
			      vsig_idx, ppp_ctxt->adapter->port_idx);
		ret = sxe2_flow_cfg_tcam_entry(ppp_ctxt, tcam_idx, flow->prof_id,
					       associated_flow->tcams[i].ptg,
					       vsig_idx, SXE2_TCAM_DEFAULT_CD_ID,
					       SXE2_TCAM_DEFAULT_FLAGS, vl_mask,
					       dc_mask, nm_mask);
		if (ret != 0) {
			devm_kfree(dev, chg);
			goto l_free;
		}
		list_add(&chg->l_entry, op_list);
	}

	if (tail) {
		list_add_tail(&associated_flow->l_node,
			      &ppp_ctxt->vsig[vsig_idx].associated_flow_list);
	} else {
		sxe2_flow_list_add_with_priority(&ppp_ctxt->vsig[vsig_idx].associated_flow_list,
						 associated_flow);
	}

l_end:
	kfree(tcam_batch);
	return ret;
l_free:
	(void)sxe2_flow_remove_associated_flow(ppp_ctxt, associated_flow);
	devm_kfree(dev, associated_flow);
	goto l_end;
}

#define SXE2_MATCH_DC_KEY 0x0
#define SXE2_MATCH_DC_KEY_MASK 0x0
#define SXE2_MATCH_NM_KEY 0x1
#define SXE2_MATCH_NM_KEY_MASK 0x1
#define SXE2_MATCH_0_KEY 0x0
#define SXE2_MATCH_0_KEY_MASK 0x1
#define SXE2_MATCH_1_KEY 0x1
#define SXE2_MATCH_1_KEY_MASK 0x0

static s32 sxe2_flow_gen_key_word(u8 val, u8 vl_mask, u8 dc_mask, u8 nm_mask,
				  u8 *key, u8 *key_mask)
{
	s32 ret = 0;
	u8 key_temp = *key;
	u8 key_mask_temp = *key_mask;
	u8 i;

	if ((dc_mask ^ nm_mask) != (dc_mask | nm_mask)) {
		ret = -EINVAL;
		goto l_end;
	}

	*key = 0;
	*key_mask = 0;

	for (i = 0; i < 8; i++) {
		*key >>= 1;
		*key_mask >>= 1;

		if (!(vl_mask & 0x1)) {
			*key |= (key_temp & 0x1) << 7;
			*key_mask |= (key_mask_temp & 0x1) << 7;
		} else if (dc_mask & 0x1) {
			*key |= SXE2_MATCH_DC_KEY << 7;
			*key_mask |= SXE2_MATCH_DC_KEY_MASK << 7;
		} else if (nm_mask & 0x1) {
			*key |= SXE2_MATCH_NM_KEY << 7;
			*key_mask |= SXE2_MATCH_NM_KEY_MASK << 7;
		} else if (val & 0x01) {
			*key |= SXE2_MATCH_1_KEY << 7;
			*key_mask |= SXE2_MATCH_1_KEY_MASK << 7;
		} else {
			*key |= SXE2_MATCH_0_KEY << 7;
			*key_mask |= SXE2_MATCH_0_KEY_MASK << 7;
		}

		dc_mask >>= 1;
		nm_mask >>= 1;
		vl_mask >>= 1;
		val >>= 1;
		key_temp >>= 1;
		key_mask_temp >>= 1;
	}

l_end:
	return ret;
}

static inline u8 sxe2_setbit_cnt_u8(u8 num)
{
	u8 bits = 0;
	u32 i;

	for (i = 0; i < 8; i++) {
		bits += (num & 0x1);
		num >>= 1;
	}

	return bits;
}

static inline bool max_set_bit_check(const u8 *mask, u16 size, u16 max)
{
	u16 count = 0;
	u16 i;
	bool ret = false;

	for (i = 0; i < size; i++) {
		if (!mask[i])
			continue;

		if (count == max)
			goto l_end;

		count += sxe2_setbit_cnt_u8(mask[i]);
		if (count > max)
			goto l_end;
	}

	ret = true;
l_end:
	return ret;
}

static s32 sxe2_flow_set_key(u8 *key, u16 size, u8 *val, u8 *vl_mask, u8 *dc_mask,
			     u8 *nm_mask, u16 off, u16 len)
{
	s32 ret = 0;
	u16 half_size;
	u16 i;

	if (size % 2) {
		ret = -EINVAL;
		goto l_end;
	}
	half_size = size / 2;

	if (off + len > half_size) {
		ret = -EINVAL;
		goto l_end;
	}

	if (nm_mask &&
	    !max_set_bit_check(nm_mask, len, SXE2_KEY_MATCH_MAX_NM_SET_NUM)) {
		ret = -EINVAL;
		goto l_end;
	}

	for (i = 0; i < len; i++) {
		ret = sxe2_flow_gen_key_word((u8)(val[i]),
					     (u8)(vl_mask ? vl_mask[i] : (u8)0xff),
					     (u8)(dc_mask ? dc_mask[i] : (u8)0),
					     (u8)(nm_mask ? nm_mask[i] : (u8)0), key + off + i,
					     key + half_size + off + i);
		if (ret != 0)
			goto l_end;
	}

l_end:
	return ret;
}

static s32 sxe2_flow_reless_tcam(struct sxe2_ppp_common_ctxt *ppp_ctxt, u16 tcam_idx)
{
	u8 vl_mask[SXE2_TCAM_KEY_VAL_SZ] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u8 dc_mask[SXE2_TCAM_KEY_VAL_SZ] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF};
	u8 nm_mask[SXE2_TCAM_KEY_VAL_SZ] = {0x01, 0x00, 0x00, 0x00, 0x00};
	s32 ret = 0;

	ret = sxe2_flow_cfg_tcam_entry(ppp_ctxt, tcam_idx, 0, 0, 0, 0, 0, vl_mask,
				       dc_mask, nm_mask);
	return ret;
}

#define SXE2_FLOW_TCAM_FULL_KEY_MASK_VSIG 0x0FFF
#define SXE2_FLOW_TCAM_FULL_KEY_MASK_CDID 0x0F
s32 sxe2_flow_cfg_tcam_entry(struct sxe2_ppp_common_ctxt *ppp_ctxt, u16 tcam_idx,
			     u8 prof_id, u8 ptg_idx, u16 vsig_idx, u8 cdid,
			     u16 flags, u8 vl_mask[SXE2_TCAM_KEY_VAL_SZ],
			     u8 dc_mask[SXE2_TCAM_KEY_VAL_SZ],
			     u8 nm_mask[SXE2_TCAM_KEY_VAL_SZ])
{
	struct sxe2_prof_tcam_full_key full_key;
	struct sxe2_prof_tcam_entry *entry;
	s32 ret = 0;

	full_key.vsig = cpu_to_le16(vsig_idx & SXE2_FLOW_TCAM_FULL_KEY_MASK_VSIG);
	full_key.flg = cpu_to_le16(flags);
	full_key.ptg = ptg_idx;

	cdid |= ppp_ctxt->adapter->port_idx;
	full_key.cdid = cdid & SXE2_FLOW_TCAM_FULL_KEY_MASK_CDID;

	entry = &ppp_ctxt->tcam_entry[tcam_idx];

	ret = sxe2_flow_set_key(entry->key, SXE2_TCAM_KEY_SZ, (u8 *)&full_key,
				vl_mask, dc_mask, nm_mask, 0, SXE2_TCAM_KEY_SZ / 2);
	if (ret != 0)
		goto l_end;

	entry->addr = cpu_to_le16(tcam_idx);
	entry->prof_id = prof_id;

l_end:
	return ret;
}

static void sxe2_flow_op_remove_tcam_add(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					 u16 tcam_idx, struct list_head *op_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_og_chg *chg;
	struct sxe2_og_chg *tmp;

	SXE2_SET_USED(ppp_ctxt);
	list_for_each_entry_safe(chg, tmp, op_list, l_entry) {
		if (chg->type == SXE2_OG_CHG_TYPE_TCAM &&
		    chg->info.tcam.tcam_idx == tcam_idx) {
			list_del(&chg->l_entry);
			devm_kfree(dev, chg);
		}
	}
}

STATIC s32 sxe2_flow_op_tcam_avail_cfg(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				       u16 vsig_idx,
				       struct sxe2_prof_tcam_info *tcam, bool avail,
				       struct list_head *op_list)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u8 vl_mask[SXE2_TCAM_KEY_VAL_SZ] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	u8 dc_mask[SXE2_TCAM_KEY_VAL_SZ] = {0x00, 0xF0, 0xFF, 0x0F, 0x00};
	u8 nm_mask[SXE2_TCAM_KEY_VAL_SZ] = {0x00, 0x00, 0x00, 0x00, 0x00};
	struct sxe2_og_chg *chg;
	s32 ret;

	if (!avail) {
		ret = sxe2_flow_reless_tcam(ppp_ctxt, tcam->idx);
		sxe2_flow_op_remove_tcam_add(ppp_ctxt, tcam->idx, op_list);
		tcam->idx = 0;
		tcam->used = false;
	} else {
		chg = devm_kzalloc(dev, sizeof(*chg), GFP_KERNEL);
		if (!chg) {
			LOG_ERROR_BDF("failed to alloc chg op memory.\n");
			ret = -ENOMEM;
			goto l_end;
		}

		ret = sxe2_flow_cfg_tcam_entry(ppp_ctxt, tcam->idx,
					       tcam->prof_id, tcam->ptg,
					       vsig_idx, SXE2_TCAM_DEFAULT_CD_ID,
					       SXE2_TCAM_DEFAULT_FLAGS,
					       vl_mask, dc_mask, nm_mask);
		if (ret != 0) {
			LOG_ERROR_BDF("tcam entry config failed, ret=%d\n", ret);
			devm_kfree(dev, chg);
			goto l_end;
		}
		tcam->used = true;

		chg->type = SXE2_OG_CHG_TYPE_TCAM;
		chg->info.tcam.prof_id = tcam->prof_id;
		chg->info.tcam.tcam_idx = tcam->idx;
		list_add(&chg->l_entry, op_list);
	}

l_end:
	return ret;
}

static bool sxe2_flow_record_ptg_is_used(struct sxe2_prof_tcam_info *tcam,
					 unsigned long *ptgs_used)
{
	return (bool)test_bit(tcam->ptg, ptgs_used);
}

static s32
sxe2_flow_op_adjust_vsig_tcams_priority(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					u16 vsig_idx, struct list_head *op_list)
{
	DECLARE_BITMAP(ptgs_used, SXE2_MAX_PTG_NUM);
	struct sxe2_associated_flow_node *associated_flow;
	s32 ret = 0;
	u16 i, j = 0;
	bool used;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct sxe2_fwc_tcam_idx_batch *tcam_batch = NULL;
	struct sxe2_prof_tcam_info **tcam_info = NULL;
	u16 batch_cnt = 0;
	u32 size;

	bitmap_zero(ptgs_used, SXE2_MAX_PTG_NUM);
	list_for_each_entry(associated_flow,
			    &ppp_ctxt->vsig[vsig_idx].associated_flow_list, l_node) {
		for (i = 0; i < associated_flow->tcam_cnt; i++) {
			used = sxe2_flow_record_ptg_is_used(&associated_flow->tcams[i],
							    (unsigned long *)ptgs_used);
			if (used && associated_flow->tcams[i].used)
				batch_cnt++;
			else if (!used && !associated_flow->tcams[i].used)
				batch_cnt++;
			set_bit(associated_flow->tcams[i].ptg, ptgs_used);
		}
	}

	if (batch_cnt == 0) {
		ret = 0;
		goto l_end;
	}

	size = sizeof(struct sxe2_fwc_tcam_idx_batch) +
	       batch_cnt * sizeof(struct sxe2_fwc_tcam_info);
	tcam_batch = kzalloc(size, GFP_KERNEL);
	tcam_info = kcalloc(batch_cnt, sizeof(struct sxe2_prof_tcam_info *),
			    GFP_KERNEL);
	if (!tcam_batch || !tcam_info) {
		ret = -ENOMEM;
		goto l_end;
	}
	tcam_batch->blk = ppp_ctxt->block_id;
	tcam_batch->tcam_cnt = cpu_to_le16(batch_cnt);
	bitmap_zero(ptgs_used, SXE2_MAX_PTG_NUM);
	list_for_each_entry(associated_flow,
			    &ppp_ctxt->vsig[vsig_idx].associated_flow_list, l_node) {
		for (i = 0; i < associated_flow->tcam_cnt; i++) {
			used = sxe2_flow_record_ptg_is_used(&associated_flow->tcams[i],
							    (unsigned long *)ptgs_used);
			if (used && associated_flow->tcams[i].used) {
				tcam_batch->tcam_info[j].action =
						SXE2_FWC_TCAM_ACTION_DEL;
				tcam_batch->tcam_info[j].tcam_idx =
						cpu_to_le16(associated_flow->tcams[i].idx);
				tcam_info[j] = &associated_flow->tcams[i];
				j++;
			} else if (!used && !associated_flow->tcams[i].used) {
				tcam_batch->tcam_info[j].action =
						SXE2_FWC_TCAM_ACTION_ADD;
				tcam_info[j] = &associated_flow->tcams[i];
				j++;
			}
			set_bit(associated_flow->tcams[i].ptg, ptgs_used);
		}
	}
	ret = sxe2_fwc_process_tcam_batch(adapter, tcam_batch, size);
	if (ret) {
		LOG_ERROR_BDF("process tcam batch failed, ret=%d\n", ret);
		goto l_end;
	}

	for (i = 0; i < batch_cnt; i++) {
		if (tcam_batch->tcam_info[i].action == SXE2_FWC_TCAM_ACTION_DEL) {
			LOG_DEBUG_BDF("free used tcam[%u], ptg=%u, prof_id=%u\n",
				      tcam_info[i]->idx, tcam_info[i]->ptg,
				      tcam_info[i]->prof_id);
			(void)sxe2_flow_op_tcam_avail_cfg(ppp_ctxt, vsig_idx,
							  tcam_info[i], false,
							  op_list);
		}
	}
	for (i = 0; i < batch_cnt; i++) {
		if (tcam_batch->tcam_info[i].action == SXE2_FWC_TCAM_ACTION_ADD) {
			tcam_info[i]->idx =
				le16_to_cpu(tcam_batch->tcam_info[i].tcam_idx);
			ret = sxe2_flow_op_tcam_avail_cfg(ppp_ctxt, vsig_idx,
							  tcam_info[i], true,
							  op_list);
			LOG_DEBUG_BDF("alloc unused tcam[%u], ptg=%u, prof_id=%u\n",
				      tcam_info[i]->idx, tcam_info[i]->ptg,
				      tcam_info[i]->prof_id);
			if (ret) {
				LOG_ERROR_BDF("add tcam op list failed, ret=%d\n",
					      ret);
				break;
			}
		}
	}

l_end:
	kfree(tcam_batch);
	kfree(tcam_info);
	return ret;
}

static struct sxe2_rss_symm_fv_pair sxe2_rss_symm_fv_list[] = {
		{SXE2_FLOW_FLD_ID_IPV4_SA, SXE2_FLOW_FLD_ID_IPV4_DA,
		 SXE2_FLOW_FLD_SZ_IPV4_ADDR},
		{SXE2_FLOW_FLD_ID_IPV6_SA, SXE2_FLOW_FLD_ID_IPV6_DA,
		 SXE2_FLOW_FLD_SZ_IPV6_ADDR},
		{SXE2_FLOW_FLD_ID_TCP_SRC_PORT, SXE2_FLOW_FLD_ID_TCP_DST_PORT,
		 SXE2_FLOW_FLD_SZ_PORT},
		{SXE2_FLOW_FLD_ID_UDP_SRC_PORT, SXE2_FLOW_FLD_ID_UDP_DST_PORT,
		 SXE2_FLOW_FLD_SZ_PORT},
		{SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, SXE2_FLOW_FLD_ID_SCTP_DST_PORT,
		 SXE2_FLOW_FLD_SZ_PORT}};

static const struct sxe2_flow_fld_info sxe2_flds_info[SXE2_FLOW_FLD_ID_MAX] = {
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_ETH, 0, ETH_ALEN),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_ETH, ETH_ALEN, ETH_ALEN),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_VLAN, 2, SXE2_FLOW_FLD_SZ_VLAN),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_VLAN, 2, SXE2_FLOW_FLD_SZ_VLAN),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_VLAN, 0, SXE2_FLOW_FLD_SZ_VLAN),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_VLAN, 0, SXE2_FLOW_FLD_SZ_VLAN),
		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_VLAN, 2, SXE2_FLOW_FLD_SZ_VLAN,
					0x0fff),
		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_VLAN, 2, SXE2_FLOW_FLD_SZ_VLAN,
					0x0fff),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_ETH, 0, SXE2_FLOW_FLD_SZ_ETH_TYPE),

		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_IPV4, 0,
					SXE2_FLOW_FLD_SZ_IP_DSCP, 0x00ff),
		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_IPV6, 0,
					SXE2_FLOW_FLD_SZ_IP_DSCP, 0x0ff0),
		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_IPV4, 8,
					SXE2_FLOW_FLD_SZ_IP_TTL, 0xff00),
		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_IPV4, 8,
					SXE2_FLOW_FLD_SZ_IP_PROT, 0x00ff),
		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_IPV6, 6,
					SXE2_FLOW_FLD_SZ_IP_TTL, 0x00ff),
		SXE2_FLOW_FLD_INFO_MASK(SXE2_FLOW_HDR_IPV6, 6,
					SXE2_FLOW_FLD_SZ_IP_PROT, 0xff00),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV4, 12,
				   SXE2_FLOW_FLD_SZ_IPV4_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV4, 16,
				   SXE2_FLOW_FLD_SZ_IPV4_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 8,
				   SXE2_FLOW_FLD_SZ_IPV6_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 24,
				   SXE2_FLOW_FLD_SZ_IPV6_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV4, 10,
				   SXE2_FLOW_FLD_SZ_IP_CHKSUM),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV4, 4, SXE2_FLOW_FLD_SZ_IPV4_ID),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV_FRAG, 4,
				   SXE2_FLOW_FLD_SZ_IPV6_ID),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 8,
				   SXE2_FLOW_FLD_SZ_IPV6_PRE32_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 24,
				   SXE2_FLOW_FLD_SZ_IPV6_PRE32_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 8,
				   SXE2_FLOW_FLD_SZ_IPV6_PRE48_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 24,
				   SXE2_FLOW_FLD_SZ_IPV6_PRE48_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 8,
				   SXE2_FLOW_FLD_SZ_IPV6_PRE64_ADDR),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_IPV6, 24,
				   SXE2_FLOW_FLD_SZ_IPV6_PRE64_ADDR),

		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_TCP, 0, SXE2_FLOW_FLD_SZ_PORT),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_TCP, 2, SXE2_FLOW_FLD_SZ_PORT),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_UDP, 0, SXE2_FLOW_FLD_SZ_PORT),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_UDP, 2, SXE2_FLOW_FLD_SZ_PORT),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_SCTP, 0, SXE2_FLOW_FLD_SZ_PORT),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_SCTP, 2, SXE2_FLOW_FLD_SZ_PORT),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_TCP, 13,
				   SXE2_FLOW_FLD_SZ_TCP_FLAGS),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_TCP, 16,
				   SXE2_FLOW_FLD_SZ_TCP_CHKSUM),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_UDP, 6,
				   SXE2_FLOW_FLD_SZ_UDP_CHKSUM),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_SCTP, 8,
				   SXE2_FLOW_FLD_SZ_SCTP_CHKSUM),

		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_VXLAN, 12,
				   SXE2_FLOW_FLD_SZ_VXLAN_VNI),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_GENEVE, 12,
				   SXE2_FLOW_FLD_SZ_GENEVE_VNI),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_GTPU, 12,
				   SXE2_FLOW_FLD_SZ_GTPU_TEID),
		SXE2_FLOW_FLD_INFO(SXE2_FLOW_HDR_GRE, 4, SXE2_FLOW_FLD_SZ_GRE_TNI),
};

static const struct sxe2_ptype_map g_ptype_map = {
		.sxe2_ptypes_mac_ofos_all = {
						SXE2_PTYPE_BITMAP(BF, BF, 7F, 7E, FD,
								  C0, 0C, C6),
						SXE2_PTYPE_BITMAP(FE, FD, FD, FB, F7,
								  EF, DF, DF),
						SXE2_PTYPE_BITMAP(00, 00, 00, FF, 03,
								  BF, 7F, 7E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  5F, 00, 00),
						SXE2_PTYPE_BITMAP(20, 08, 03, 07, FF,
								  FF, FF, 80),
						SXE2_PTYPE_BITMAP(00, 00, 0F, FF, FF,
								  FF, F0, 80),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, F3, FF, 03, FF,
								  3F, 3F, 3E),
						SXE2_PTYPE_BITMAP(FF, FF, FF, F0, 00,
								  00, FF, F9),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF, FF,
								  FF, FF, FF),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF, FF,
								  FF, FF, FF),
				},
		.sxe2_ptypes_mac_il_all = {
						SXE2_PTYPE_BITMAP(BC, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(F0, 00, 00, 00, 00,
								  EF, DF, DF),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 03,
								  BF, 7F, 7E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 0F, FF, FF,
								  FF, F0, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, F0, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, FF, F9),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF, FF,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF, FF,
								  FF, FF, FF),
				},
		.sxe2_ptypes_mac_ofos_with_l3 = {
						SXE2_PTYPE_BITMAP(BF, BF, 7F, 7E, FD,
								  C0, 00, 00),
						SXE2_PTYPE_BITMAP(FE, FD, FD, FB, F7,
								  EF, DF, DF),
						SXE2_PTYPE_BITMAP(00, 00, 00, FF, 03,
								  BF, 7F, 7E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  0F, 00, 00),
						SXE2_PTYPE_BITMAP(20, 00, 03, 07, FF,
								  FF, FF, 80),
						SXE2_PTYPE_BITMAP(00, 00, 0F, FF, FF,
								  FF, F0, 80),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, F3, FF, 03, FF,
								  3F, 3F, 00),
						SXE2_PTYPE_BITMAP(FF, FF, FF, F0, 00,
								  00, FF, F9),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF, FF,
								  FF, FF, FF),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF, FF,
								  FF, FF, FF),
				},
		.sxe2_ptypes_mac_il_with_l3 = {
						SXE2_PTYPE_BITMAP(B8, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(E0, 00, 00, 00, 00,
								  EF, DD, DF),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 03,
								  BF, 77, 7E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 0F, FF, FF,
								  FF, F0, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, E0, 00, 00, 00,
								  00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, FF, F1),
						SXE2_PTYPE_BITMAP(EF, FF, 7F, FB,
								  FF, 00, 00, 00),
						SXE2_PTYPE_BITMAP(DF, FE, FF, F7,
								  FF, BF, FD, FF),
				},
		.sxe2_ptypes_mac_ofos_no_l3 = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 0C, C6),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 50, 00, 00),
						SXE2_PTYPE_BITMAP(00, 08, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 3E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
		.sxe2_ptypes_mac_il_no_l3 = {
						SXE2_PTYPE_BITMAP(04, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(10, 00, 00, 00,
								  00, 00, 02, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 08, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 10, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 08),
						SXE2_PTYPE_BITMAP(10, 00, 80, 04,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(20, 01, 00, 08,
								  00, 40, 02, 00),
				},
		.sxe2_ptypes_ipv4_ofos_with_l4 = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  0D, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 50,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(20, 00, 00, 01,
								  83, E0, FA, 80),
						SXE2_PTYPE_BITMAP(00, 00, 05, 55,
								  55, 55, 50, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 03,
								  FF, 00, 38, 00),
						SXE2_PTYPE_BITMAP(3F, FE, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(80, 03, FF, E0,
								  00, FF, F8, 00),
						SXE2_PTYPE_BITMAP(FF, F8, 00, 3F,
								  FE, 00, 0F, FF),
				},
		.sxe2_ptypes_ipv4_il_with_l4 = {
						SXE2_PTYPE_BITMAP(A0, 03, 40, 06,
								  80, 00, 00, 00),
						SXE2_PTYPE_BITMAP(80, 0D, 00, 1A,
								  00, 00, D0, 01),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 03, 40, 06),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 1C, E0, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(03, 80, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(31, 01, 88, 00,
								  00, 00, 01, C0),
						SXE2_PTYPE_BITMAP(62, 03, 10, 18,
								  80, C4, 06, 20),
						SXE2_PTYPE_BITMAP(C4, 06, 20, 31,
								  01, 88, 0C, 40),
				},
		.sxe2_ptypes_ipv6_ofos_with_l4 = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  34, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, A0,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 06,
								  7C, 1F, 05, 00),
						SXE2_PTYPE_BITMAP(00, 00, 0A, AA,
								  AA, AA, A0, 80),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 03, FF, 00,
								  00, 38, 00, 00),
						SXE2_PTYPE_BITMAP(C0, 01, FF, F0,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(7F, FC, 00, 1F,
								  FF, 00, 07, FF),
						SXE2_PTYPE_BITMAP(00, 07, FF, C0,
								  01, FF, F0, 00),
				},
		.sxe2_ptypes_ipv6_il_with_l4 = {
						SXE2_PTYPE_BITMAP(01, A0, 03, 40,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(06, 80, 0D, 00,
								  00, 68, 00, D0),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  01, A0, 03, 40),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  73, 80, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(E0, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(80, 64, 03, 20,
								  00, 00, 70, 00),
						SXE2_PTYPE_BITMAP(00, C8, 06, 40,
								  32, 01, 90, 0C),
						SXE2_PTYPE_BITMAP(01, 90, 0C, 80,
								  64, 03, 20, 19),
				},
		.sxe2_ptypes_ipv4_ofos_no_l4 = {
						SXE2_PTYPE_BITMAP(BF, BF, 7F, 7E,
								  F0, C0, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, EF, DF, DF),
						SXE2_PTYPE_BITMAP(00, 00, 00, 05,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 03, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 01, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 07, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
		.sxe2_ptypes_ipv4_il_no_l4 = {
						SXE2_PTYPE_BITMAP(18, 04, 30, 08,
								  60, 00, 00, 00),
						SXE2_PTYPE_BITMAP(60, 10, C0, 21,
								  80, 01, 0C, 02),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 04, 30, 08),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 03, 18, 00),
						SXE2_PTYPE_BITMAP(00, 00, 03, 33,
								  33, 03, F0, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(04, 60, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(06, 80, 34, 00,
								  00, 00, 02, 30),
						SXE2_PTYPE_BITMAP(0D, 00, 68, 03,
								  40, 1A, 00, D0),
						SXE2_PTYPE_BITMAP(1A, 00, D0, 06,
								  80, 34, 01, A0),
				},
		.sxe2_ptypes_ipv6_ofos_no_l4 = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(FE, FD, FD, E1,
								  C3, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 0A,
								  03, BF, 7F, 7E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 0C, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 02, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, F0, 00, 00,
								  00, 07, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, FF, F9),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
		.sxe2_ptypes_ipv6_il_no_l4 = {
						SXE2_PTYPE_BITMAP(02, 18, 04, 30,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(08, 60, 10, C0,
								  00, 86, 01, 0C),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  02, 18, 04, 30),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  0C, 60, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 0C, CC,
								  CC, FC, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(18, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(40, 1A, 00, D0,
								  00, 00, 8C, 01),
						SXE2_PTYPE_BITMAP(80, 34, 01, A0,
								  0D, 00, 68, 03),
						SXE2_PTYPE_BITMAP(00, 68, 03, 40,
								  1A, 00, D0, 06),
				},
		.sxe2_ptypes_udp_ofos = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  01, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  04, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, F0,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(20, 00, 00, 07,
								  FF, FF, FF, 80),
						SXE2_PTYPE_BITMAP(00, 00, 0F, FF,
								  FF, FF, F0, 80),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 03, FC, 03,
								  FC, 38, 38, 00),
						SXE2_PTYPE_BITMAP(FF, FF, FF, F0,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF,
								  FF, FF, FF, FF),
						SXE2_PTYPE_BITMAP(FF, FF, FF, FF,
								  FF, FF, FF, FF),
				},
		.sxe2_ptypes_udp_il = {
						SXE2_PTYPE_BITMAP(20, 20, 40, 40,
								  80, 00, 00, 00),
						SXE2_PTYPE_BITMAP(80, 81, 01, 02,
								  00, 08, 10, 10),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 20, 40, 40),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  10, 84, 20, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(20, 80, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(10, 20, 81, 00,
								  00, 00, 10, 40),
						SXE2_PTYPE_BITMAP(20, 41, 02, 08,
								  10, 40, 82, 04),
						SXE2_PTYPE_BITMAP(40, 82, 04, 10,
								  20, 81, 04, 08),
				},
		.sxe2_ptypes_tcp_ofos = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  04, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  10, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 03, 00,
								  03, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
		.sxe2_ptypes_tcp_il = {
						SXE2_PTYPE_BITMAP(80, 81, 01, 02,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(02, 04, 04, 08,
								  00, 20, 40, 40),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 81, 01, 02),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  21, 08, 40, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(41, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(20, 41, 02, 00,
								  00, 00, 20, 80),
						SXE2_PTYPE_BITMAP(40, 82, 04, 10,
								  20, 81, 04, 08),
						SXE2_PTYPE_BITMAP(81, 04, 08, 20,
								  41, 02, 08, 10),
				},
		.sxe2_ptypes_sctp_ofos = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  08, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  20, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
		.sxe2_ptypes_sctp_il = {
						SXE2_PTYPE_BITMAP(01, 02, 02, 04,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(04, 08, 08, 10,
								  00, 40, 80, 81),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  01, 02, 02, 04),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  42, 10, 80, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(82, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(81, 04, 08, 20,
								  00, 00, 41, 00),
						SXE2_PTYPE_BITMAP(02, 08, 10, 40,
								  82, 04, 10, 20),
						SXE2_PTYPE_BITMAP(04, 10, 20, 81,
								  04, 08, 20, 41),
				},
		.sxe2_ptypes_vxlan_vni = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(3F, FF, FF, F0,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 03, FF, FF,
								  FF, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 3F,
								  FF, FF, F0, 00),
				},
		.sxe2_ptypes_gre_of = {
						SXE2_PTYPE_BITMAP(BF, BF, 78, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(FE, FD, E0, 00,
								  00, EF, DF, DF),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  03, BF, 7F, 7E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(C0, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, FC, 00, 00,
								  00, FF, FF, FF),
						SXE2_PTYPE_BITMAP(FF, FF, FF, C0,
								  00, 00, 0F, FF),
				},
		.sxe2_ptypes_ipv4_ofos_frag = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 40, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
		.sxe2_ptypes_ipv4_il_frag = {
						SXE2_PTYPE_BITMAP(08, 00, 10, 00,
								  20, 00, 00, 00),
						SXE2_PTYPE_BITMAP(20, 00, 40, 00,
								  80, 00, 04, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 10, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 01, 08, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 20, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(04, 00, 20, 00,
								  00, 00, 00, 10),
						SXE2_PTYPE_BITMAP(08, 00, 40, 02,
								  00, 10, 00, 80),
						SXE2_PTYPE_BITMAP(10, 00, 80, 04,
								  00, 20, 01, 00),
				},
		.sxe2_ptypes_ipv6_ofos_frag = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  01, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
		.sxe2_ptypes_ipv6_il_frag = {
						SXE2_PTYPE_BITMAP(00, 08, 00, 10,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 20, 00, 40,
								  00, 02, 00, 04),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 08, 00, 10),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  04, 20, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(08, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 10, 00, 80,
								  00, 00, 04, 00),
						SXE2_PTYPE_BITMAP(00, 20, 01, 00,
								  08, 00, 40, 02),
						SXE2_PTYPE_BITMAP(00, 40, 02, 00,
								  10, 00, 80, 04),
				},
		.sxe2_ptypes_ipv4_ofos_all = {
						SXE2_PTYPE_BITMAP(BF, BF, 7F, 7E,
								  FD, C0, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, EF, DF, DF),
						SXE2_PTYPE_BITMAP(00, 00, 00, 55,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 03, 00, 00),
						SXE2_PTYPE_BITMAP(20, 00, 01, 01,
								  83, E0, FA, 80),
						SXE2_PTYPE_BITMAP(00, 00, 05, 55,
								  55, 55, 50, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 03,
								  FF, 00, 3F, 00),
						SXE2_PTYPE_BITMAP(3F, FE, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(80, 03, FF, E0,
								  00, FF, F8, 00),
						SXE2_PTYPE_BITMAP(FF, F8, 00, 3F,
								  FE, 00, 0F, FF),
				},
		.sxe2_ptypes_ipv4_il_all = {
						SXE2_PTYPE_BITMAP(B8, 07, 70, 0E,
								  E0, 00, 00, 00),
						SXE2_PTYPE_BITMAP(E0, 1D, C0, 3B,
								  80, 01, DC, 03),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 07, 70, 0E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 1F, F8, 00),
						SXE2_PTYPE_BITMAP(00, 00, 03, 33,
								  33, 03, F0, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(07, E0, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(37, 81, BC, 00,
								  00, 00, 03, F0),
						SXE2_PTYPE_BITMAP(6F, 03, 78, 1B,
								  C0, DE, 06, F0),
						SXE2_PTYPE_BITMAP(DE, 06, F0, 37,
								  81, BC, 0D, E0),
				},
		.sxe2_ptypes_ipv6_ofos_all = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(FE, FD, FD, FB,
								  F7, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, AA,
								  03, BF, 7F, 7E),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 0C, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 02, 06,
								  7C, 1F, 05, 00),
						SXE2_PTYPE_BITMAP(00, 00, 0A, AA,
								  AA, AA, A0, 80),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(FF, F3, FF, 00,
								  00, 3F, 00, 00),
						SXE2_PTYPE_BITMAP(C0, 01, FF, F0,
								  00, 00, FF, F9),
						SXE2_PTYPE_BITMAP(7F, FC, 00, 1F,
								  FF, 00, 07, FF),
						SXE2_PTYPE_BITMAP(00, 07, FF, C0,
								  01, FF, F0, 00),
				},
		.sxe2_ptypes_ipv6_il_all = {
						SXE2_PTYPE_BITMAP(03, B8, 07, 70,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(0E, E0, 1D, C0,
								  00, EE, 01, DC),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  03, B8, 07, 70),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  7F, E0, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 0C, CC,
								  CC, FC, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(F8, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(C0, 7E, 03, F0,
								  00, 00, FC, 01),
						SXE2_PTYPE_BITMAP(80, FC, 07, E0,
								  3F, 01, F8, 0F),
						SXE2_PTYPE_BITMAP(01, F8, 0F, C0,
								  7E, 03, F0, 1F),
				},
		.sxe2_ptypes_gtpu = {
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  7F, FF, FE, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
						SXE2_PTYPE_BITMAP(00, 00, 00, 00,
								  00, 00, 00, 00),
				},
};

STATIC void
sxe2_flow_parse_dissectors_hdrs_l2(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				   struct sxe2_flow_info_params *flow_params,
				   const struct sxe2_ptype_map *ptype_map_ptr,
				   unsigned long *headers, u8 i)
{
	const unsigned long *ptypes_src;

	if (test_bit(SXE2_FLOW_HDR_ETH, headers) &&
	    test_bit(SXE2_FLOW_HDR_ETH_NON_IP, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_mac_il_no_l3)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_mac_ofos_no_l3);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority =
				i ? SXE2_FLOW_PRIO_LEVEL_INNER_ETH
				  : SXE2_FLOW_PRIO_LEVEL_OUTER_ETH;

	} else if (test_bit(SXE2_FLOW_HDR_ETH, headers) &&
		   (test_bit(SXE2_FLOW_HDR_IPV4, headers) ||
		    test_bit(SXE2_FLOW_HDR_IPV6, headers))) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_mac_il_with_l3)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_mac_ofos_with_l3);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority =
				i ? SXE2_FLOW_PRIO_LEVEL_INNER_ETH
				  : SXE2_FLOW_PRIO_LEVEL_OUTER_ETH;

	} else if (test_bit(SXE2_FLOW_HDR_ETH, headers)) {
		if (ppp_ctxt->block_id == SXE2_HW_BLOCK_ID_FNAV) {
			ptypes_src = i ? (const unsigned long
					  *)(ptype_map_ptr->sxe2_ptypes_mac_il_no_l3)
				       : (const unsigned long
					  *)(ptype_map_ptr->sxe2_ptypes_mac_ofos_no_l3);
		} else {
			ptypes_src = i ? (const unsigned long
					  *)(ptype_map_ptr->sxe2_ptypes_mac_il_all)
				       : (const unsigned long
					  *)(ptype_map_ptr->sxe2_ptypes_mac_ofos_all);
		}
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority =
				i ? SXE2_FLOW_PRIO_LEVEL_INNER_ETH
				  : SXE2_FLOW_PRIO_LEVEL_OUTER_ETH;
	}
}

STATIC void
sxe2_flow_parse_dissectors_hdrs_l3(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				   struct sxe2_flow_info_params *flow_params,
				   const struct sxe2_ptype_map *ptype_map_ptr,
				   unsigned long *headers, u8 i)
{
	const unsigned long *ptypes_src;

	if (test_bit(SXE2_FLOW_HDR_IPV4, headers) &&
	    (test_bit(SXE2_FLOW_HDR_TCP, headers) ||
	     test_bit(SXE2_FLOW_HDR_UDP, headers) ||
	     test_bit(SXE2_FLOW_HDR_SCTP, headers))) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_il_with_l4)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_ofos_with_l4);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L3
						     : SXE2_FLOW_PRIO_LEVLE_OUTER_L3;

	} else if (test_bit(SXE2_FLOW_HDR_IPV4, headers) &&
		   test_bit(SXE2_FLOW_HDR_IPV_OTHER, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_il_no_l4)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_ofos_no_l4);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L3
						     : SXE2_FLOW_PRIO_LEVLE_OUTER_L3;

	} else if (test_bit(SXE2_FLOW_HDR_IPV4, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_il_all)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_ofos_all);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L3
						     : SXE2_FLOW_PRIO_LEVLE_OUTER_L3;

	} else if (test_bit(SXE2_FLOW_HDR_IPV6, headers) &&
		   (test_bit(SXE2_FLOW_HDR_TCP, headers) ||
		    test_bit(SXE2_FLOW_HDR_UDP, headers) ||
		    test_bit(SXE2_FLOW_HDR_SCTP, headers))) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_il_with_l4)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_ofos_with_l4);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L3
						     : SXE2_FLOW_PRIO_LEVLE_OUTER_L3;

	} else if (test_bit(SXE2_FLOW_HDR_IPV6, headers) &&
		   test_bit(SXE2_FLOW_HDR_IPV_OTHER, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_il_no_l4)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_ofos_no_l4);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L3
						     : SXE2_FLOW_PRIO_LEVLE_OUTER_L3;

	} else if (test_bit(SXE2_FLOW_HDR_IPV6, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_il_all)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_ofos_all);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L3
						     : SXE2_FLOW_PRIO_LEVLE_OUTER_L3;
	}
}

STATIC void
sxe2_flow_parse_dissectors_hdrs_l3_frag(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					struct sxe2_flow_info_params *flow_params,
					const struct sxe2_ptype_map *ptype_map_ptr,
					unsigned long *headers, u8 i)
{
	const unsigned long *ptypes_src;

	if (test_bit(SXE2_FLOW_HDR_IPV4, headers) &&
	    test_bit(SXE2_FLOW_HDR_IPV_FRAG, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_il_frag)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv4_ofos_frag);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority =
				i ? SXE2_FLOW_PRIO_LEVLE_INNER_L3_FRAG
				  : SXE2_FLOW_PRIO_LEVEL_OUTER_L3_FRAG;
	} else if (test_bit(SXE2_FLOW_HDR_IPV6, headers) &&
		   test_bit(SXE2_FLOW_HDR_IPV_FRAG, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_il_frag)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_ipv6_ofos_frag);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority =
				i ? SXE2_FLOW_PRIO_LEVLE_INNER_L3_FRAG
				  : SXE2_FLOW_PRIO_LEVEL_OUTER_L3_FRAG;
	}
}

STATIC void
sxe2_flow_parse_dissectors_hdrs_l4(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				   struct sxe2_flow_info_params *flow_params,
				   const struct sxe2_ptype_map *ptype_map_ptr,
				   unsigned long *headers, u8 i)
{
	const unsigned long *ptypes_src;

	if (test_bit(SXE2_FLOW_HDR_UDP, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_udp_il)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_udp_ofos);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L4
						     : SXE2_FLOW_PRIO_LEVEL_OUTER_L4;

	} else if (test_bit(SXE2_FLOW_HDR_TCP, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_tcp_il)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_tcp_ofos);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L4
						     : SXE2_FLOW_PRIO_LEVEL_OUTER_L4;

	} else if (test_bit(SXE2_FLOW_HDR_SCTP, headers)) {
		ptypes_src = i ? (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_sctp_il)
			       : (const unsigned long
						  *)(ptype_map_ptr->sxe2_ptypes_sctp_ofos);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
		flow_params->flow_info->priority = i ? SXE2_FLOW_PRIO_LEVEL_INNER_L4
						     : SXE2_FLOW_PRIO_LEVEL_OUTER_L4;
	}

	if (test_bit(SXE2_FLOW_HDR_GRE, headers)) {
		ptypes_src = (const unsigned long
					      *)(ptype_map_ptr->sxe2_ptypes_gre_of);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
	} else if (test_bit(SXE2_FLOW_HDR_VXLAN, headers) ||
		   test_bit(SXE2_FLOW_HDR_GENEVE, headers)) {
		ptypes_src = (const unsigned long
					      *)(ptype_map_ptr->sxe2_ptypes_vxlan_vni);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
	} else if (test_bit(SXE2_FLOW_HDR_GTPU, headers)) {
		ptypes_src = (const unsigned long
					      *)(ptype_map_ptr->sxe2_ptypes_gtpu);
		bitmap_and(flow_params->ptypes, flow_params->ptypes, ptypes_src,
			   SXE2_MAX_PTYPE_NUM);
	}
}

static s32 sxe2_flow_parse_dissectors_hdrs(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					   struct sxe2_flow_info_params *flow_params)
{
	DECLARE_BITMAP(headers, SXE2_FLOW_HDR_MAX);
	s32 ret = 0;
	u8 i;
	const struct sxe2_ptype_map *ptype_map_ptr = &g_ptype_map;

	memset(flow_params->ptypes, 0xff, sizeof(flow_params->ptypes));

	for (i = 0; i < flow_params->flow_info->dissector_cnt; i++) {
		bitmap_copy(headers, flow_params->flow_info->dissectors[i].headers,
			    SXE2_FLOW_HDR_MAX);

		sxe2_flow_parse_dissectors_hdrs_l2(ppp_ctxt, flow_params,
						   ptype_map_ptr, headers, i);

		sxe2_flow_parse_dissectors_hdrs_l3(ppp_ctxt, flow_params,
						   ptype_map_ptr, headers, i);

		sxe2_flow_parse_dissectors_hdrs_l3_frag(ppp_ctxt, flow_params,
							ptype_map_ptr, headers, i);

		sxe2_flow_parse_dissectors_hdrs_l4(ppp_ctxt, flow_params,
						   ptype_map_ptr, headers, i);
	}

	LOG_INFO("generate ptypes: 0x%lX, 0x%lX, 0x%lX, 0x%lX\n, priority: %u",
		 flow_params->ptypes[0], flow_params->ptypes[1],
		 flow_params->ptypes[2], flow_params->ptypes[5],
		 flow_params->flow_info->priority);

	return ret;
}

static s32 sxe2_flow_parse_fld_to_fv_set_prot_id(struct sxe2_adapter *adapter,
						 enum sxe2_flow_fld_id fld_id,
						 u8 dissector,
						 enum sxe2_prot_id *prot_id)
{
	s32 ret = 0;

	switch (fld_id) {
	case SXE2_FLOW_FLD_ID_ETH_DA:
	case SXE2_FLOW_FLD_ID_ETH_SA:
		*prot_id = (dissector == 0) ? SXE2_PROT_MAC_OF_OR_S
					    : SXE2_PROT_MAC_IL;
		break;

	case SXE2_FLOW_FLD_ID_S_TPID:
	case SXE2_FLOW_FLD_ID_S_TCI:
	case SXE2_FLOW_FLD_ID_S_VID:
		*prot_id = (dissector == 0) ? SXE2_PROT_EVLAN_O : SXE2_PROT_VLAN_IF;
		break;

	case SXE2_FLOW_FLD_ID_C_TPID:
	case SXE2_FLOW_FLD_ID_C_TCI:
	case SXE2_FLOW_FLD_ID_C_VID:
		*prot_id = SXE2_PROT_VLAN_O;
		break;
	case SXE2_FLOW_FLD_ID_ETH_TYPE:
		*prot_id = (dissector == 0) ? SXE2_PROT_ETYPE_OL
					    : SXE2_PROT_ETYPE_IL;
		break;

	case SXE2_FLOW_FLD_ID_IPV4_TOS:
	case SXE2_FLOW_FLD_ID_IPV4_SA:
	case SXE2_FLOW_FLD_ID_IPV4_DA:
	case SXE2_FLOW_FLD_ID_IPV4_CHKSUM:
	case SXE2_FLOW_FLD_ID_IPV4_PROT:
	case SXE2_FLOW_FLD_ID_IPV4_TTL:
	case SXE2_FLOW_FLD_ID_IPV4_ID:
		*prot_id = (dissector == 0) ? SXE2_PROT_IPV4_OF_OR_S
					    : SXE2_PROT_IPV4_IL;
		break;

	case SXE2_FLOW_FLD_ID_TCP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_TCP_DST_PORT:
	case SXE2_FLOW_FLD_ID_TCP_FLAGS:
	case SXE2_FLOW_FLD_ID_TCP_CHKSUM:
		*prot_id = SXE2_PROT_TCP_IL;
		break;
	case SXE2_FLOW_FLD_ID_UDP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_UDP_DST_PORT:
	case SXE2_FLOW_FLD_ID_UDP_CHKSUM:
		*prot_id = (dissector == 0) ? SXE2_PROT_UDP_OF
					    : SXE2_PROT_UDP_IL_OR_S;
		break;
	case SXE2_FLOW_FLD_ID_SCTP_SRC_PORT:
	case SXE2_FLOW_FLD_ID_SCTP_DST_PORT:
	case SXE2_FLOW_FLD_ID_SCTP_CHKSUM:
		*prot_id = SXE2_PROT_SCTP_IL;
		break;

	case SXE2_FLOW_FLD_ID_IPV6_PROT:
	case SXE2_FLOW_FLD_ID_IPV6_DSCP:
	case SXE2_FLOW_FLD_ID_IPV6_SA:
	case SXE2_FLOW_FLD_ID_IPV6_DA:
	case SXE2_FLOW_FLD_ID_IPV6_TTL:
	case SXE2_FLOW_FLD_ID_IPV6_PRE32_SA:
	case SXE2_FLOW_FLD_ID_IPV6_PRE32_DA:
	case SXE2_FLOW_FLD_ID_IPV6_PRE48_SA:
	case SXE2_FLOW_FLD_ID_IPV6_PRE48_DA:
	case SXE2_FLOW_FLD_ID_IPV6_PRE64_SA:
	case SXE2_FLOW_FLD_ID_IPV6_PRE64_DA:
		*prot_id = (dissector == 0) ? SXE2_PROT_IPV6_OF_OR_S
					    : SXE2_PROT_IPV6_IL;
		break;
	case SXE2_FLOW_FLD_ID_IPV6_ID:
		*prot_id = SXE2_PROT_IPV6_FRAG;
		break;
	case SXE2_FLOW_FLD_ID_VXLAN_VNI:
	case SXE2_FLOW_FLD_ID_GENEVE_VNI:
	case SXE2_FLOW_FLD_ID_GTPU_TEID:
		*prot_id = SXE2_PROT_UDP_OF;
		break;
	case SXE2_FLOW_FLD_ID_NVGRE_TNI:
		*prot_id = SXE2_PROT_GRE_OF;
		break;
	default:
		LOG_ERROR_BDF("failed to parse unsupport fld_id[%u].\n", fld_id);
		ret = -EINVAL;
		goto l_end;
	}
l_end:
	return ret;
}

static s32 sxe2_flow_parse_fld_to_fv(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				     struct sxe2_flow_info_params *flow_params,
				     u8 dissector, enum sxe2_flow_fld_id fld_id,
				     unsigned long *fields)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct sxe2_flow_fld *fld;
	enum sxe2_prot_id prot_id = SXE2_PROT_INVALID;
	s32 ret = 0;
	u16 mask;
	u16 off;
	u16 i;
	u8 fv_num = ppp_ctxt->hw_fv_num;
	u8 fv_word_size;
	u8 fv_cnt;
	u8 fv_idx;
	u16 def_mask_id = 0;
	u16 def_fv_id = 0;

	SXE2_SET_USED(fields);
	fld = flow_params->flow_info->dissectors[dissector].fld;

	ret = sxe2_flow_parse_fld_to_fv_set_prot_id(adapter, fld_id, dissector,
						    &prot_id);
	if (ret)
		goto l_end;

	fv_word_size = SXE2_FLOW_FV_SIZE * BITS_PER_BYTE;

	if (sxe2_flds_info[fld_id].mask != 0 &&
	    ppp_ctxt->block_id != SXE2_HW_BLOCK_ID_ACL) {
		ret = sxe2_flow_default_mask_get(ppp_ctxt->block_id, adapter, fld_id,
						 &def_mask_id, &def_fv_id);
		if (ret) {
			LOG_ERROR_BDF("failed to parse default mask fld_id[%u].\n",
				      fld_id);
			goto l_end;
		}
		fld[fld_id].xtrct.prot_id = (u8)prot_id;
		fld[fld_id].xtrct.off =
				(u16)((sxe2_flds_info[fld_id].off / fv_word_size) *
				      (u16)SXE2_FLOW_FV_SIZE);
		fld[fld_id].xtrct.disp =
				(u8)(sxe2_flds_info[fld_id].off % fv_word_size);
		fld[fld_id].xtrct.mask = sxe2_flds_info[fld_id].mask;
		fld[fld_id].xtrct.idx = (u8)def_fv_id;

		if (flow_params->fv[def_fv_id].prot_id != SXE2_FV_PORT_ID_INVAL) {
			LOG_ERROR_BDF("Failed to fv[%d] mask cfg, fv[%d] prot_id:%d \t"
				      "off:%d mask:0x%x\n",
				      fld_id, def_fv_id,
				      flow_params->fv[def_fv_id].prot_id,
				      flow_params->fv[def_fv_id].off,
				      flow_params->fv_mask[def_fv_id]);
			ret = -EINVAL;
			goto l_end;
		}

		flow_params->fv[def_fv_id].prot_id = (u8)prot_id;
		flow_params->fv[def_fv_id].off = fld[fld_id].xtrct.off;
		flow_params->fv_mask[def_fv_id] = fld[fld_id].xtrct.mask;

		goto l_end;
	}

	fld[fld_id].xtrct.prot_id = (u8)prot_id;
	fld[fld_id].xtrct.off = (u16)((sxe2_flds_info[fld_id].off / fv_word_size) *
				      (u16)SXE2_FLOW_FV_SIZE);
	fld[fld_id].xtrct.disp = (u8)(sxe2_flds_info[fld_id].off % fv_word_size);
	fld[fld_id].xtrct.mask = sxe2_flds_info[fld_id].mask;
	fld[fld_id].xtrct.idx = flow_params->fv_cnt;

	LOG_DEBUG_BDF("parse fld[%u] prot_id:%u off:%u disp:%u mask:%u idx:%u.\n",
		      fld_id, prot_id, fld[fld_id].xtrct.off, fld[fld_id].xtrct.disp,
		      fld[fld_id].xtrct.mask, fld[fld_id].xtrct.idx);

	fv_cnt = (u8)DIV_ROUND_UP((s16)(fld[fld_id].xtrct.disp +
				  sxe2_flds_info[fld_id].size),
				  (s16)fv_word_size);

	off = fld[fld_id].xtrct.off;
	mask = fld[fld_id].xtrct.mask;
	for (i = 0; i < fv_cnt; i++) {
		if (flow_params->fv_cnt >= (fv_num - ppp_ctxt->hw_fv_mask_num)) {
			ret = -ENOSPC;
			LOG_ERROR_BDF("parse flow flds, used fv max limit, \t"
				      "fv_cnt=%u, fv_num=%u, fv_mask_num=%u.\n",
				      flow_params->fv_cnt, fv_num,
				      ppp_ctxt->hw_fv_mask_num);
			goto l_end;
		}

		fv_idx = flow_params->fv_cnt;

		flow_params->fv[fv_idx].prot_id = (u8)prot_id;
		flow_params->fv[fv_idx].off = off;
		flow_params->fv_mask[fv_idx] = mask;

		LOG_DEBUG_BDF("parse fld[%u] fv[%u] prot_id:%u off:%u mask:%u.\n",
			      fld_id, fv_idx, prot_id, off, mask);
		flow_params->fv_cnt++;
		off += SXE2_FLOW_FV_SIZE;
	}

l_end:
	return ret;
}

static s32 sxe2_flow_parse_raw_to_fv(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				     struct sxe2_flow_info_params *flow_params,
				     u8 dissector)
{
	s32 ret = 0;
	u8 i, j;
	u16 off;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct sxe2_flow_raw *raw;
	u8 raw_cnt = flow_params->flow_info->dissectors[dissector].raw_cnt;
	u8 fv_num = ppp_ctxt->hw_fv_num;
	u8 fv_cnt;

	if (!raw_cnt)
		return 0;

	if (raw_cnt > SXE2_MAX_RAW_CNT)
		return -ENOSPC;

	for (i = 0; i < raw_cnt; i++) {
		raw = &flow_params->flow_info->dissectors[dissector].raw[i];
		raw->fld.xtrct.prot_id = SXE2_PROT_MAC_OF_OR_S;
		raw->fld.xtrct.off = raw->offset;
		raw->fld.xtrct.disp = 0;
		raw->fld.xtrct.idx = flow_params->fv_cnt;
		fv_cnt = (u8)DIV_ROUND_UP(raw->fld.xtrct.disp +
					  raw->fld.fld_val.len *
					  SXE2_FLOW_FV_SIZE,
					  SXE2_FLOW_FV_SIZE * BITS_PER_BYTE);
		off = raw->fld.xtrct.off;
		for (j = 0; j < fv_cnt; j++) {
			if (flow_params->fv_cnt >=
			    (fv_num - ppp_ctxt->hw_fv_mask_num)) {
				ret = -ENOSPC;
				LOG_INFO_BDF("parse flow raws, used fv max \t"
					     "limit.\n");
				goto l_end;
			}

			flow_params->fv[flow_params->fv_cnt].prot_id =
					raw->fld.xtrct.prot_id;
			flow_params->fv[flow_params->fv_cnt].off = off;
			flow_params->fv_mask[flow_params->fv_cnt] = 0;
			flow_params->fv_cnt++;
			off += SXE2_FLOW_FV_SIZE;
		}
	}

l_end:
	return ret;
}

static s32 sxe2_flow_parse_dissectors_fld(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					  struct sxe2_flow_info_params *flow_params)
{
	DECLARE_BITMAP(fields, SXE2_FLOW_FLD_ID_MAX);
	s32 ret = 0;
	enum sxe2_flow_fld_id j = 0;
	unsigned long tmp;
	u8 i;

	bitmap_zero(fields, SXE2_FLOW_FLD_ID_MAX);

	for (i = 0; i < flow_params->flow_info->dissector_cnt; i++) {
		bitmap_copy(fields, flow_params->flow_info->dissectors[i].fields,
			    SXE2_FLOW_FLD_ID_MAX);

		for_each_set_bit(tmp, fields, SXE2_FLOW_FLD_ID_MAX) {
			j = (enum sxe2_flow_fld_id)tmp;
			ret = sxe2_flow_parse_fld_to_fv(ppp_ctxt, flow_params, i, j,
							fields);
			if (ret != 0)
				goto l_end;

			clear_bit((int)j, fields);
		}

		ret = sxe2_flow_parse_raw_to_fv(ppp_ctxt, flow_params, i);
		if (ret)
			goto l_end;
	}

l_end:
	return ret;
}

#define SXE2_FLOW_FLD_OFF_INVAL 0xffff
STATIC void sxe2_flow_acl_frmt_entry_field(u16 fld, struct sxe2_flow_fld *info,
					   u8 *buf, u8 *dontcare, u8 *data)
{
	u16 dst, src, mask, k, end_disp, tmp_s = 0, tmp_m = 0;
	bool use_mask = false;
	u8 disp;

	src = info->fld_val.val;
	mask = info->fld_val.mask;
	dst = info->last_val.val - SXE2_ACL_PROF_BYTE_SEL_START_IDX;
	disp = info->xtrct.disp % BITS_PER_BYTE;

	if (mask != SXE2_FLOW_FLD_OFF_INVAL)
		use_mask = true;

	for (k = 0; k < info->last_val.len; k++, dst++) {
		buf[dst] = (tmp_s & 0xff00) >> 8;

		dontcare[dst] = (tmp_m & 0xff00) >> 8;

		if (!disp || k < info->last_val.len - 1) {
			tmp_s = data[src++] << disp;

			buf[dst] |= tmp_s & 0xff;

			if (use_mask) {
				tmp_m = (~data[mask++] & 0xff) << disp;
				dontcare[dst] |= tmp_m & 0xff;
			}
		}
	}

	if (disp) {
		dst = info->last_val.val - SXE2_ACL_PROF_BYTE_SEL_START_IDX;
		for (k = 0; k < disp; k++)
			dontcare[dst] |= BIT(k);
	}

	end_disp = (disp + sxe2_flds_info[fld].size) % BITS_PER_BYTE;

	if (end_disp) {
		dst = info->last_val.val - SXE2_ACL_PROF_BYTE_SEL_START_IDX +
		      info->last_val.len - 1;
		for (k = end_disp; k < BITS_PER_BYTE; k++)
			dontcare[dst] |= BIT(k);
	}
}

s32 sxe2_flow_acl_format_lut_act_entry(struct sxe2_adapter *adapter,
				       struct sxe2_acl_flow_entry *flow_entry,
				       struct sxe2_flow_info_node *flow,
				       struct sxe2_acl_flow_action *acts, u8 *data)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_flow_dissector_info *dis_info;
	struct sxe2_flow_fld *field;
	s32 ret = 0;
	u8 *dontcare = NULL;
	u8 *buf = NULL;
	u8 *key = NULL;
	u16 buf_size;
	u16 i, j;

	flow_entry->action = devm_kzalloc(dev, sizeof(struct sxe2_acl_flow_action),
					  GFP_KERNEL);
	if (!flow_entry->action) {
		ret = -ENOMEM;
		goto l_end;
	}
	memcpy(flow_entry->action, acts, sizeof(*acts));

	buf_size = flow->cfg.scen->width;
	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto l_end;
	}

	dontcare = kzalloc(buf_size, GFP_KERNEL);
	if (!dontcare) {
		ret = -ENOMEM;
		goto l_end;
	}
	memset(dontcare, 0xff, buf_size);

	key = devm_kzalloc(dev, buf_size * 2, GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		goto l_end;
	}

	for (i = 0; i < flow->dissector_cnt; i++) {
		dis_info = &flow->dissectors[i];
		for_each_set_bit(j, dis_info->fields, SXE2_FLOW_FLD_ID_MAX) {
			field = &dis_info->fld[j];
			sxe2_flow_acl_frmt_entry_field(j, field, buf, dontcare,
						       data);
		}

		for (j = 0; j < dis_info->raw_cnt; j++) {
			struct sxe2_flow_raw *raw = &dis_info->raw[j];
			u16 dst, src, mask, k;
			bool use_mask = false;

			src = raw->fld.fld_val.val;
			dst = raw->fld.last_val.val -
			      SXE2_ACL_PROF_BYTE_SEL_START_IDX;
			mask = raw->fld.fld_val.mask;

			if (mask != SXE2_FLOW_FLD_OFF_INVAL)
				use_mask = true;

			for (k = 0; k < raw->fld.last_val.len; k++, dst++) {
				buf[dst] = data[src++];
				if (use_mask)
					dontcare[dst] = ~data[mask++];
				else
					dontcare[dst] = 0;
			}
		}
	}

	ret = sxe2_flow_set_key(key, buf_size * 2, buf, NULL, dontcare, NULL, 0,
				buf_size);
	if (ret)
		goto l_end;

	flow_entry->entry = key;
	flow_entry->entry_size = buf_size * 2;

	kfree(buf);
	kfree(dontcare);
	return 0;

l_end:
	kfree(buf);
	kfree(dontcare);

	if (ret && key)
		devm_kfree(dev, key);

	if (ret && flow_entry->action) {
		devm_kfree(dev, flow_entry->action);
		flow_entry->action = NULL;
	}
	return ret;
}

STATIC s32 sxe2_flow_acl_fill_last_fld(struct sxe2_flow_info_params *flow_params)
{
	struct sxe2_flow_dissector_info *dissectors;
	DECLARE_BITMAP(fields, SXE2_FLOW_FLD_ID_MAX);
	struct sxe2_flow_fld *flow_fld;
	struct sxe2_flow_raw *flow_raw;
	s32 ret = 0;
	u32 fld = 0;
	u16 index;
	u16 i, j;
	u8 dis_cnt;

	index = SXE2_ACL_PROF_BYTE_SEL_START_IDX;

	dis_cnt = flow_params->flow_info->dissector_cnt;
	for (i = 0; i < dis_cnt; i++) {
		dissectors = &flow_params->flow_info->dissectors[i];

		bitmap_zero(fields, SXE2_FLOW_FLD_ID_MAX);
		bitmap_copy(fields, dissectors->fields, SXE2_FLOW_FLD_ID_MAX);
		for_each_set_bit(fld, fields, SXE2_FLOW_FLD_ID_MAX) {
			flow_fld = &dissectors->fld[fld];
			flow_fld->last_val.mask = 0xffff;

			if (flow_fld->type == SXE2_FLOW_FLD_TYPE_VAL) {
				flow_fld->last_val.len = DIV_ROUND_UP(sxe2_flds_info[fld].size +
								      (flow_fld->xtrct.disp %
								      BITS_PER_BYTE),
						BITS_PER_BYTE);
				flow_fld->last_val.val = index;

				index += flow_fld->last_val.len;
			}
		}

		for (j = 0; j < dissectors->raw_cnt; j++) {
			flow_raw = &dissectors->raw[j];

			flow_raw->fld.last_val.mask = 0xffff;
			flow_raw->fld.last_val.val = index;
			flow_raw->fld.last_val.len = flow_raw->fld.fld_val.len;

			index += flow_raw->fld.last_val.len;
		}
	}

	if (index > SXE2_ACL_PROF_BYTE_SEL_ELEMS) {
		ret = -EINVAL;
		goto l_end;
	}

	flow_params->match_size = index;

l_end:
	return ret;
}

STATIC s32 sxe2_flow_acl_select_scen(struct sxe2_ppp_common_ctxt *ppp_ctx,
				     struct sxe2_flow_info_params *flow_params)
{
	struct sxe2_acl_scen_info *scen;
	struct sxe2_acl_scen_info *tmp_scen;
	struct sxe2_acl_scen_info *find_scen = NULL;
	struct sxe2_acl_tbl_info *acl_tbl_info =
			ppp_ctx->adapter->acl_ctxt.acl_tbl_info;
	struct sxe2_adapter *adapter = ppp_ctx->adapter;
	s32 ret = 0;

	if (list_empty(&acl_tbl_info->scens)) {
		LOG_ERROR_BDF("no acl scen.\n");
		ret = -ENODATA;
		goto l_end;
	}
	LOG_DEBUG_BDF("match_size:%d\n", flow_params->match_size);
	list_for_each_entry_safe(scen, tmp_scen, &acl_tbl_info->scens, l_entry) {
		LOG_DEBUG_BDF("scen:%d, avail_width:%d\n", scen->scen_id,
			      scen->avail_width);
		if (scen->avail_width >= flow_params->match_size &&
		    (!find_scen || find_scen->avail_width > scen->avail_width)) {
			find_scen = scen;
		}
	}

	if (!find_scen) {
		LOG_ERROR_BDF("no acl scen.\n");
		ret = -ENODATA;
		goto l_end;
	}

	flow_params->flow_info->cfg.scen = find_scen;

l_end:
	return ret;
}

static s32 sxe2_flow_parse_dissectors(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				      struct sxe2_flow_info_params *flow_params)
{
	s32 ret;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	ret = sxe2_flow_parse_dissectors_hdrs(ppp_ctxt, flow_params);
	if (ret != 0) {
		LOG_DEBUG_BDF("failed to parse dissectors hdrs.\n");
		goto l_end;
	}

	ret = sxe2_flow_parse_dissectors_fld(ppp_ctxt, flow_params);
	if (ret != 0)
		LOG_DEBUG_BDF("failed to parse dissectors flds.\n");

	if (ppp_ctxt->block_id == SXE2_HW_BLOCK_ID_ACL) {
		ret = sxe2_flow_acl_fill_last_fld(flow_params);
		if (ret) {
			LOG_ERROR_BDF("failed to fill last fld.\n");
			goto l_end;
		}
		ret = sxe2_flow_acl_select_scen(ppp_ctxt, flow_params);
		if (ret) {
			LOG_ERROR_BDF("failed to select scen.\n");
			goto l_end;
		}
	}

l_end:
	return ret;
}

static s32 sxe2_flow_add_profile(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				 struct sxe2_flow_info_params *flow_params,
				 bool fnav_swap)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	DECLARE_BITMAP(ptgs_used, SXE2_MAX_PTG_NUM);
	struct sxe2_flow_info_node *flow = flow_params->flow_info;
	s32 ret = 0;
	u64 ptype_64;
	u16 ptype;
	u8 prof_id;
	u8 ptg;

	SXE2_SET_USED(fnav_swap);

	bitmap_zero((unsigned long *)ptgs_used, SXE2_MAX_PTG_NUM);

	ret = sxe2_flow_alloc_hw_prof_id(ppp_ctxt, &prof_id);
	if (ret != 0)
		goto l_end;

	if (ppp_ctxt->block_id != SXE2_HW_BLOCK_ID_ACL) {
		ret = sxe2_flow_fnav_update_hw_prof_fv_mask(ppp_ctxt, prof_id,
							    flow_params->fv_mask);
		if (ret != 0)
			goto l_end;
	}

	sxe2_flow_update_hw_prof_fv(ppp_ctxt, prof_id, flow_params->fv);

	LOG_DEBUG_BDF("alloc profile[%u]\n", prof_id);

	(void)sxe2_flow_hw_prof_inc_ref(ppp_ctxt, prof_id);
	flow->prof_id = prof_id;

	for_each_set_bit(ptype_64, flow_params->ptypes, SXE2_MAX_PTYPE_NUM) {
		ptype = (u16)ptype_64;
		ptg = ppp_ctxt->pt_to_grp[ptype].idx;

		if (test_bit(ptg, ptgs_used))
			continue;

		LOG_INFO_BDF("process ptype[%u] ptg[%u]\n", ptype, ptg);

		set_bit(ptg, ptgs_used);

		flow->ptg_info.ptg[flow->ptg_info.ptg_cnt] = ptg;

		flow->ptg_info.ptg_cnt++;
		if (flow->ptg_info.ptg_cnt >= SXE2_MAX_PTG_PER_PROF_NUM) {
			LOG_DEBUG_BDF("profile add [%u] used max ptg num %u.\n",
				      prof_id, flow->ptg_info.ptg_cnt);
			break;
		}
	}
	LOG_DEBUG_BDF("profile[%u] used ptg num %u.\n", prof_id,
		      flow->ptg_info.ptg_cnt);

l_end:
	return ret;
}

static s32 sxe2_flow_creat_sync(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				struct sxe2_flow_dissector_info *dissectors,
				u8 dissectors_cnt, struct sxe2_flow_info_node **flow)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_flow_info_params *flow_params;
	s32 ret;
	u32 i;

	if (!flow) {
		LOG_ERROR_BDF("flow is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}

	flow_params = devm_kzalloc(dev, sizeof(*flow_params), GFP_KERNEL);
	if (!flow_params) {
		LOG_ERROR_BDF("failed to alloc flow_params.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	flow_params->flow_info = devm_kzalloc(dev, sizeof(*flow_params->flow_info),
					      GFP_KERNEL);
	if (!flow_params->flow_info) {
		LOG_ERROR_BDF("failed to alloc flow_info.\n");
		ret = -ENOMEM;
		goto l_end_free;
	}

	for (i = 0; i < SXE2_MAX_FV_WORDS; i++) {
		flow_params->fv[i].prot_id = SXE2_FV_PORT_ID_INVAL;
		flow_params->fv[i].off = SXE2_FV_OFFSET_INVAL;
	}

	flow_params->flow_info->dissector_cnt = dissectors_cnt;
	for (i = 0; i < dissectors_cnt; i++)
		flow_params->flow_info->dissectors[i] = dissectors[i];

	ret = sxe2_flow_parse_dissectors(ppp_ctxt, flow_params);
	if (ret != 0) {
		LOG_ERROR_BDF("failed to parse dissectors.\n");
		goto l_end_free;
	}

	ret = sxe2_flow_add_profile(ppp_ctxt, flow_params, true);
	if (ret != 0) {
		LOG_ERROR_BDF("failed to add profile.\n");
		goto l_end_free;
	}

	*flow = flow_params->flow_info;

l_end_free:
	if (ret != 0)
		devm_kfree(dev, flow_params->flow_info);

	devm_kfree(dev, flow_params);
l_end:
	return ret;
}

enum protocol_stack_layer {
	protocol_stack_layer_L2,
	protocol_stack_layer_L3,
	protocol_stack_layer_L4,
};

static void sxe2_layer_hdrs_bitmap_get(enum protocol_stack_layer layer,
				       unsigned long *headers)
{
	bitmap_zero(headers, SXE2_FLOW_HDR_MAX);
	switch (layer) {
	case protocol_stack_layer_L2:
		set_bit(SXE2_FLOW_HDR_ETH, headers);
		set_bit(SXE2_FLOW_HDR_VLAN, headers);
		break;
	case protocol_stack_layer_L3:
		set_bit(SXE2_FLOW_HDR_IPV4, headers);
		set_bit(SXE2_FLOW_HDR_IPV6, headers);
		break;
	case protocol_stack_layer_L4:
		set_bit(SXE2_FLOW_HDR_TCP, headers);
		set_bit(SXE2_FLOW_HDR_UDP, headers);
		set_bit(SXE2_FLOW_HDR_SCTP, headers);
		break;
	default:
		break;
	}
}

static bool sxe2_flow_check_hdrs_correct(struct sxe2_flow_dissector_info *dissectors,
					 u8 dissectors_cnt)
{
	u8 i;
	bool ret = false;
	DECLARE_BITMAP(headers_l3, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(headers_l4, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(headers_tmp, SXE2_FLOW_HDR_MAX);

	sxe2_layer_hdrs_bitmap_get(protocol_stack_layer_L3, headers_l3);
	sxe2_layer_hdrs_bitmap_get(protocol_stack_layer_L4, headers_l4);

	for (i = 0; i < dissectors_cnt; i++) {
		bitmap_and(headers_tmp, dissectors[i].headers, headers_l3,
			   SXE2_FLOW_HDR_MAX);
		if (!bitmap_empty(headers_tmp, SXE2_FLOW_HDR_MAX) &&
		    (bitmap_weight(headers_tmp, SXE2_FLOW_HDR_MAX) != 1)) {
			goto l_end;
		}

		bitmap_and(headers_tmp, dissectors[i].headers, headers_l4,
			   SXE2_FLOW_HDR_MAX);
		if (!bitmap_empty(headers_tmp, SXE2_FLOW_HDR_MAX) &&
		    (bitmap_weight(headers_tmp, SXE2_FLOW_HDR_MAX) != 1)) {
			goto l_end;
		}
	}

	ret = true;
l_end:
	return ret;
}

s32 sxe2_flow_creat(struct sxe2_ppp_common_ctxt *ppp_ctxt,
		    struct sxe2_flow_dissector_info *dissectors, u8 dissectors_cnt,
		    struct sxe2_flow_info_node **flow)
{
	s32 ret;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;

	if (!dissectors) {
		LOG_ERROR_BDF("dissectors is NULL.\n");
		ret = -EINVAL;
		goto l_end;
	}
	if (dissectors_cnt == 0 || dissectors_cnt > SXE2_MAX_DISSECTOR_NUM) {
		LOG_ERROR_BDF("dissectors_cnt is %u.\n", dissectors_cnt);
		ret = -EINVAL;
		goto l_end;
	}

	if (!sxe2_flow_check_hdrs_correct(dissectors, dissectors_cnt)) {
		LOG_ERROR_BDF("failed to check hdrs not correct.\n");
		ret = -EINVAL;
		goto l_end;
	}

	mutex_lock(&ppp_ctxt->flow_list_lock);
	ret = sxe2_flow_creat_sync(ppp_ctxt, dissectors, dissectors_cnt, flow);
	if (ret == 0)
		list_add(&(*flow)->l_node, &ppp_ctxt->flow_list);
	else
		LOG_ERROR_BDF("failed to create flow.\n");

	mutex_unlock(&ppp_ctxt->flow_list_lock);

l_end:
	return ret;
}

static s32 sxe2_flow_op_remove_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				    struct sxe2_flow_info_node *flow)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_og_chg *tmp_chg;
	struct sxe2_og_chg *del_chg;
	struct list_head op_list;
	s32 ret;
	u16 i;

	INIT_LIST_HEAD(&op_list);

	for (i = 0; i < SXE2_MAX_VSIG_NUM; i++) {
		if (ppp_ctxt->vsig[i].used) {
			if (sxe2_flow_check_flow_in_vsig(ppp_ctxt, flow, i)) {
				ret = sxe2_flow_op_vsig_remove_flow(ppp_ctxt, flow,
								    i, &op_list);
				if (ret != 0)
					goto l_end;
			}
		}
	}

	(void)sxe2_flow_hw_prof_dec_ref(ppp_ctxt, flow->prof_id);

	ret = sxe2_fwc_update_profile(ppp_ctxt, ppp_ctxt->block_id, &op_list);
l_end:
	list_for_each_entry_safe(del_chg, tmp_chg, &op_list, l_entry) {
		list_del(&del_chg->l_entry);
		devm_kfree(dev, del_chg);
	}
	return ret;
}

s32 sxe2_flow_delete(struct sxe2_ppp_common_ctxt *ppp_ctxt,
		     struct sxe2_flow_info_node *flow)
{
	s32 ret;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	mutex_lock(&ppp_ctxt->flow_list_lock);
	ret = sxe2_flow_op_remove_flow(ppp_ctxt, flow);
	if (ret == 0) {
		list_del(&flow->l_node);
		devm_kfree(dev, flow);
	}
	mutex_unlock(&ppp_ctxt->flow_list_lock);

	return ret;
}

s32 sxe2_flow_cfg_clear_muti_vsi_in_vsig(struct sxe2_adapter *adapter,
					 struct sxe2_ppp_common_ctxt *ppp_ctxt,
					 u16 vsi_sw_idx)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_flow_info_node *flow;
	struct sxe2_flow_info_node *flow_tmp;
	struct sxe2_og_chg *tmp_chg;
	struct sxe2_og_chg *del_chg;
	struct list_head op_list;
	s32 ret = 0;

	INIT_LIST_HEAD(&op_list);

	list_for_each_entry_safe(flow, flow_tmp, &ppp_ctxt->flow_list, l_node) {
		if (test_bit(vsi_sw_idx, flow->used_vsi))
			clear_bit(vsi_sw_idx, flow->used_vsi);
	}

	ret = sxe2_flow_op_move_vsi_to_vsig(ppp_ctxt, vsi_sw_idx,
					    SXE2_PPP_DEFAULT_VSIG_IDX, &op_list);
	if (ret == 0) {
		ret = sxe2_fwc_update_profile(ppp_ctxt, ppp_ctxt->block_id,
					      &op_list);
	}

	list_for_each_entry_safe(del_chg, tmp_chg, &op_list, l_entry) {
		list_del(&del_chg->l_entry);
		devm_kfree(dev, del_chg);
	}

	return ret;
}

s32 sxe2_rss_delete_vsi_flows_for_vfr(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx)
{
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &rss_ctxt->ppp;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct sxe2_flow_info_node *flow;
	struct sxe2_flow_info_node *tmp;
	s32 ret = 0;
	u16 vsig_idx;
	bool only_vsi;

	if (list_empty(&ppp_ctxt->flow_list))
		goto l_end;

	mutex_lock(&rss_ctxt->rss_cfgs_lock);

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &vsig_idx);
	if (ret != 0)
		goto l_unlock;

	if (vsig_idx == SXE2_PPP_DEFAULT_VSIG_IDX)
		goto l_unlock;

	only_vsi = (ppp_ctxt->vsig[vsig_idx].vsi_cnt == 1);
	if (!only_vsi) {
		ret = sxe2_flow_cfg_clear_muti_vsi_in_vsig(adapter, ppp_ctxt,
							   vsi_sw_idx);
		if (ret) {
			LOG_WARN_BDF("move vsi[%u] to default vsig failed, ret=%d\n",
				     vsi_sw_idx, ret);
		}
		goto l_unlock;
	}

	list_for_each_entry_safe(flow, tmp, &ppp_ctxt->flow_list, l_node) {
		if (test_bit(vsi_sw_idx, flow->used_vsi)) {
			ret = sxe2_flow_disassoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
			if (ret != 0)
				goto l_unlock;

			if (bitmap_empty((unsigned long *)flow->used_vsi,
					 SXE2_MAX_VSI_NUM)) {
				ret = sxe2_flow_delete(ppp_ctxt, flow);
				if (ret != 0)
					goto l_unlock;
			}
		}
	}

l_unlock:
	mutex_unlock(&rss_ctxt->rss_cfgs_lock);
l_end:
	LOG_DEBUG_BDF("delete vsi flows end, ret:%d.\n", ret);
	return ret;
}

s32 sxe2_rss_delete_vsi_flows(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx)
{
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &rss_ctxt->ppp;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct sxe2_flow_info_node *flow;
	struct sxe2_flow_info_node *tmp;
	s32 ret = 0;
	u16 vsig_idx;
	bool only_vsi;

	mutex_lock(&rss_ctxt->rss_cfgs_lock);

	if (list_empty(&ppp_ctxt->flow_list))
		goto l_delete;

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &vsig_idx);
	if (ret != 0)
		goto l_unlock;

	if (vsig_idx == SXE2_PPP_DEFAULT_VSIG_IDX)
		goto l_delete;

	only_vsi = (ppp_ctxt->vsig[vsig_idx].vsi_cnt == 1);
	if (!only_vsi) {
		ret = sxe2_flow_cfg_clear_muti_vsi_in_vsig(adapter, ppp_ctxt,
							   vsi_sw_idx);
		if (ret)
			goto l_unlock;
		else
			goto l_delete;
	}

	list_for_each_entry_safe(flow, tmp, &ppp_ctxt->flow_list, l_node) {
		if (test_bit(vsi_sw_idx, flow->used_vsi)) {
			ret = sxe2_flow_disassoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
			if (ret != 0)
				goto l_unlock;

			if (bitmap_empty((unsigned long *)flow->used_vsi,
					 SXE2_MAX_VSI_NUM)) {
				ret = sxe2_flow_delete(ppp_ctxt, flow);
				if (ret != 0)
					goto l_unlock;
			}
		}
	}

l_delete:
	sxe2_rss_delete_vsi_cfg_list(rss_ctxt, vsi_sw_idx);

l_unlock:
	mutex_unlock(&rss_ctxt->rss_cfgs_lock);

	LOG_DEBUG_BDF("delete vsi flows end, ret:%d.\n", ret);
	return ret;
}

struct sxe2_flow_info_node *
sxe2_find_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
	       struct sxe2_flow_dissector_info *dissectors, u8 dissectors_cnt)
{
	struct sxe2_flow_info_node *flow_tmp;
	struct sxe2_flow_info_node *flow_find = NULL;
	u8 i, j;

	mutex_lock(&ppp_ctxt->flow_list_lock);

	list_for_each_entry(flow_tmp, &ppp_ctxt->flow_list, l_node) {
		if (dissectors_cnt && dissectors_cnt == flow_tmp->dissector_cnt) {
			for (i = 0; i < dissectors_cnt; i++) {
				if (!bitmap_equal(dissectors[i].headers,
						  flow_tmp->dissectors[i].headers,
						  SXE2_FLOW_HDR_MAX)) {
					break;
				}
				if (!bitmap_equal(dissectors[i].fields,
						  flow_tmp->dissectors[i].fields,
						  SXE2_FLOW_FLD_ID_MAX)) {
					break;
				}

				if (dissectors[i].raw_cnt !=
				    flow_tmp->dissectors[i].raw_cnt) {
					break;
				}
				for (j = 0; j < dissectors[i].raw_cnt; j++) {
					if (dissectors[i].raw[j].offset !=
					    flow_tmp->dissectors[i].raw[j].offset) {
						break;
					}
					if (dissectors[i].raw[j].fld.type !=
					    flow_tmp->dissectors[i]
							    .raw[j]
							    .fld.type) {
						break;
					}
					if (memcmp(&dissectors[i].raw[j].fld.fld_val,
						   &flow_tmp->dissectors[i]
								    .raw[j]
								    .fld.fld_val,
						   sizeof(struct
							  sxe2_flow_fld_val))) {
						break;
					}
				}
				if (j != dissectors[i].raw_cnt)
					break;
			}

			if (i == dissectors_cnt) {
				flow_find = flow_tmp;
				break;
			}
		}
	}
	mutex_unlock(&ppp_ctxt->flow_list_lock);

	return flow_find;
}

STATIC struct sxe2_flow_info_node *
sxe2_find_flow_with_cond(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			 struct sxe2_flow_dissector_info *dissectors,
			 u8 dissectors_cnt, u16 vsi_sw_idx, u32 conds)
{
	struct sxe2_flow_info_node *flow_tmp;
	struct sxe2_flow_info_node *flow_find = NULL;
	u8 i;

	mutex_lock(&ppp_ctxt->flow_list_lock);

	list_for_each_entry(flow_tmp, &ppp_ctxt->flow_list, l_node) {
		if (dissectors_cnt && dissectors_cnt == flow_tmp->dissector_cnt) {
			if ((conds & SXE2_FLOW_FIND_FLOW_COND_VSI) &&
			    (!test_bit(vsi_sw_idx, flow_tmp->used_vsi))) {
				continue;
			}

			for (i = 0; i < dissectors_cnt; i++) {
				if (!bitmap_equal(dissectors[i].headers,
						  flow_tmp->dissectors[i].headers,
						  SXE2_FLOW_HDR_MAX) ||
				    ((conds & SXE2_FLOW_FIND_FLOW_COND_FLD) &&
				     !bitmap_equal(dissectors[i].fields,
						   flow_tmp->dissectors[i].fields,
						   SXE2_FLOW_FLD_ID_MAX))) {
					break;
				}
			}

			if (i == dissectors_cnt) {
				flow_find = flow_tmp;
				break;
			}
		}
	}
	mutex_unlock(&ppp_ctxt->flow_list_lock);
	return flow_find;
}

static void sxe2_rss_xor_symm_fv(struct sxe2_adapter *adapter,
				 struct sxe2_rss_symm_fv *symm_fv, u8 src, u8 dst,
				 u8 len)
{
	u8 i;

	len = len / SXE2_FLOW_FV_SIZE;
	for (i = 0; i < len; i++) {
		symm_fv[src + i].valid = 1;
		symm_fv[dst + i].valid = 1;
		symm_fv[src + i].fv_idx = dst + i;
		symm_fv[dst + i].fv_idx = src + i;
		LOG_DEBUG_BDF("Rss symm fv xor[%d:%d].", src + i, dst + i);
	}
}

static s32 sxe2_fwc_rss_symm_fv_set(struct sxe2_adapter *adapter, u16 prof_id,
				    struct sxe2_rss_symm_fv *symm_fv)
{
	struct sxe2_rss_symm_fv_cfg symm_cfg = {0};
	struct sxe2_cmd_params cmd = {0};
	s32 ret = 0;

	if (!symm_fv) {
		ret = -EINVAL;
		LOG_ERROR_BDF("Failed to set rss hash symm fv, param error.");
		goto l_end;
	}

	symm_cfg.prof_id = prof_id;
	memcpy(symm_cfg.fv, symm_fv, SXE2_RSS_FV_CNT);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_SYMM_FV_SET, &symm_cfg,
				  sizeof(symm_cfg), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("Rss hash symm fv set cmd fail, ret=%d", ret);

l_end:
	return ret;
}

static s32 sxe2_rss_update_symm(struct sxe2_rss_ctxt *rss_ctxt,
				struct sxe2_flow_info_node *flow)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = rss_ctxt->ppp.adapter;
	struct sxe2_flow_dissector_info *dissector;
	struct sxe2_rss_symm_fv_pair *symm_pair;
	struct sxe2_rss_symm_fv symm_fv[SXE2_RSS_FV_CNT] = {{0}};
	struct sxe2_flow_fld_xtrct *src_fld;
	struct sxe2_flow_fld_xtrct *dst_fld;
	u8 i = 0;
	u8 valid_fld_cnt = 0;

	valid_fld_cnt = sizeof(sxe2_rss_symm_fv_list) /
			sizeof(sxe2_rss_symm_fv_list[0]);

	if (flow->cfg.symm) {
		dissector = &flow->dissectors[flow->dissector_cnt - 1];
		for (i = 0; i < valid_fld_cnt; i++) {
			symm_pair = &sxe2_rss_symm_fv_list[i];

			src_fld = &dissector->fld[symm_pair->src_fld].xtrct;
			dst_fld = &dissector->fld[symm_pair->dst_fld].xtrct;

			if (src_fld->prot_id != 0 && dst_fld->prot_id != 0) {
				sxe2_rss_xor_symm_fv(adapter, symm_fv, src_fld->idx,
						     dst_fld->idx,
						     symm_pair->fld_len);
			}
		}
	}

	ret = sxe2_fwc_rss_symm_fv_set(adapter, flow->prof_id, symm_fv);
	if (ret)
		LOG_ERROR_BDF("Failed to update rss symm, ret:%d.", ret);
	return ret;
}

void sxe2_flow_set_diss_fld(struct sxe2_flow_dissector_info *dissector,
			    enum sxe2_flow_fld_id fld, u16 val, u16 mask, u16 len)
{
	set_bit((int)fld, dissector->fields);
	dissector->fld[fld].type = SXE2_FLOW_FLD_TYPE_VAL;
	dissector->fld[fld].fld_val.val = val;
	dissector->fld[fld].fld_val.mask = mask;
	dissector->fld[fld].fld_val.len = len;

	set_bit((int)sxe2_flds_info[fld].hdr, dissector->headers);
}

void sxe2_flow_add_diss_raw(struct sxe2_flow_dissector_info *dissector, u16 off,
			    u16 val, u16 mask, u8 len)
{
	if (dissector->raw_cnt < SXE2_MAX_RAW_CNT) {
		dissector->raw[dissector->raw_cnt].offset = off;
		dissector->raw[dissector->raw_cnt].fld.type = SXE2_FLOW_FLD_TYPE_VAL;
		dissector->raw[dissector->raw_cnt].fld.fld_val.val = val;
		dissector->raw[dissector->raw_cnt].fld.fld_val.mask = mask;
		dissector->raw[dissector->raw_cnt].fld.fld_val.len = len;
	}

	dissector->raw_cnt++;
}

static void sxe2_rss_flow_support_hdrs_get(unsigned long *hdrs)
{
	bitmap_zero(hdrs, SXE2_FLOW_HDR_MAX);
	set_bit(SXE2_FLOW_HDR_ETH, hdrs);
	set_bit(SXE2_FLOW_HDR_VLAN, hdrs);
	set_bit(SXE2_FLOW_HDR_IPV4, hdrs);
	set_bit(SXE2_FLOW_HDR_IPV6, hdrs);
	set_bit(SXE2_FLOW_HDR_TCP, hdrs);
	set_bit(SXE2_FLOW_HDR_UDP, hdrs);
	set_bit(SXE2_FLOW_HDR_SCTP, hdrs);
	set_bit(SXE2_FLOW_HDR_GENEVE, hdrs);
	set_bit(SXE2_FLOW_HDR_GTPU, hdrs);
	set_bit(SXE2_FLOW_HDR_VXLAN, hdrs);
	set_bit(SXE2_FLOW_HDR_GRE, hdrs);
	set_bit(SXE2_FLOW_HDR_IPV_OTHER, hdrs);
	set_bit(SXE2_FLOW_HDR_IPV_FRAG, hdrs);
	set_bit(SXE2_FLOW_HDR_ETH_NON_IP, hdrs);
}

static s32 sxe2_rss_gen_dissector_info(struct sxe2_flow_dissector_info *dissectors,
				       u8 dissectors_cnt,
				       const struct sxe2_rss_hash_cfg *cfg)
{
	s32 ret = 0;
	u64 i;
	struct sxe2_flow_dissector_info *dissector;
	DECLARE_BITMAP(hdrs, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(rss_support_hdrs, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(headers_l3, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(headers_l4, SXE2_FLOW_HDR_MAX);

	sxe2_rss_flow_support_hdrs_get(rss_support_hdrs);
	sxe2_layer_hdrs_bitmap_get(protocol_stack_layer_L3, headers_l3);
	sxe2_layer_hdrs_bitmap_get(protocol_stack_layer_L4, headers_l4);

	dissector = &dissectors[dissectors_cnt - 1];

	for_each_set_bit(i, cfg->hash_flds, SXE2_FLOW_FLD_ID_MAX) {
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)i, 0xffff,
				       0xffff, 0xffff);
	}

	bitmap_or(dissector->headers, dissector->headers, cfg->headers,
		  SXE2_FLOW_HDR_MAX);

	switch (cfg->hdr_type) {
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4:
		set_bit(SXE2_FLOW_HDR_IPV4,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_IPV_OTHER,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6:
		set_bit(SXE2_FLOW_HDR_IPV6,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_IPV_OTHER,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_GRE:
		set_bit(SXE2_FLOW_HDR_IPV4,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_IPV_OTHER,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GRE,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_GRE:
		set_bit(SXE2_FLOW_HDR_IPV6,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_IPV_OTHER,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GRE,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_GRE:
		set_bit(SXE2_FLOW_HDR_IPV4,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GRE,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_GRE:
		set_bit(SXE2_FLOW_HDR_IPV6,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GRE,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_VXLAN:
		set_bit(SXE2_FLOW_HDR_IPV4,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_VXLAN,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_VXLAN:
		set_bit(SXE2_FLOW_HDR_IPV6,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_VXLAN,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_GENEVE:
		set_bit(SXE2_FLOW_HDR_IPV4,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GENEVE,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_GENEVE:
		set_bit(SXE2_FLOW_HDR_IPV6,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GENEVE,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_GTPU:
		set_bit(SXE2_FLOW_HDR_IPV4,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GTPU,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	case SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_GTPU:
		set_bit(SXE2_FLOW_HDR_IPV6,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_UDP,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		set_bit(SXE2_FLOW_HDR_GTPU,
			dissectors[SXE2_RSS_OUTER_HEADERS].headers);
		break;
	default:
		break;
	}

	bitmap_andnot(hdrs, dissector->headers, rss_support_hdrs, SXE2_FLOW_HDR_MAX);
	if (bitmap_weight(hdrs, SXE2_FLOW_HDR_MAX)) {
		ret = -EINVAL;
		LOG_ERROR("flow param dissector headers error.\n");
		goto l_end;
	}

	bitmap_and(hdrs, dissector->headers, headers_l3, SXE2_FLOW_HDR_MAX);
	if (!bitmap_empty(hdrs, SXE2_FLOW_HDR_MAX) &&
	    (bitmap_weight(hdrs, SXE2_FLOW_HDR_MAX) != 1)) {
		LOG_ERROR("flow cfg dissector headers l3 error.\n");
		ret = -EIO;
		goto l_end;
	}

	bitmap_and(hdrs, dissector->headers, headers_l4, SXE2_FLOW_HDR_MAX);
	if (!bitmap_empty(hdrs, SXE2_FLOW_HDR_MAX) &&
	    (bitmap_weight(hdrs, SXE2_FLOW_HDR_MAX) != 1)) {
		LOG_ERROR("flow cfg dissector headers l4 error.\n");
		ret = -EIO;
		goto l_end;
	}

l_end:
	return ret;
}

s32 sxe2_flow_default_mask_get(enum sxe2_block_id block_id,
			       struct sxe2_adapter *adapter,
			       enum sxe2_flow_fld_id fld_id, u16 *mask_idx,
			       u16 *fv_idx)
{
	u32 i = 0;

	switch (block_id) {
	case SXE2_HW_BLOCK_ID_FNAV:
		for (i = 0; i < SXE2_MAX_FV_MASK; i++) {
			if (test_bit((int)fld_id,
				     adapter->fnav_ctxt.fnav_flow_ctxt.ppp.fv_mask[i]
						     .filds)) {
				*mask_idx = adapter->fnav_ctxt.fnav_flow_ctxt.ppp
							    .fv_mask[i]
							    .mask_idx;
				*fv_idx = adapter->fnav_ctxt.fnav_flow_ctxt.ppp
							  .fv_mask[i]
							  .mask_idx;
				LOG_INFO_BDF("sxe2 fnav mask filds=0x%lX, \t"
					     "mask_idx=%u.\n",
					     *adapter->fnav_ctxt.fnav_flow_ctxt.ppp
							      .fv_mask[i]
							      .filds,
					     *mask_idx);
				return 0;
			}
		}
		return -EINVAL;
	case SXE2_HW_BLOCK_ID_RSS:
		for (i = 0; i < SXE2_MAX_FV_MASK; i++) {
			if (test_bit((int)fld_id,
				     adapter->rss_flow_ctxt.ppp.fv_mask[i].filds)) {
				*mask_idx = adapter->rss_flow_ctxt.ppp.fv_mask[i]
							    .mask_idx;
				*fv_idx = adapter->rss_flow_ctxt.ppp.fv_mask[i]
							  .mask_idx;
				LOG_INFO_BDF("sxe2 fnav mask filds=0x%lX, \t"
					     "mask_idx=%u.\n",
					     *adapter->rss_flow_ctxt.ppp.fv_mask[i]
							      .filds,
					     *mask_idx);
				return 0;
			}
		}
		return -EINVAL;
	default:
		return 0;
	};
}

static void sxe2_flow_free_all_flows(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_flow_info_node *flow;
	struct sxe2_flow_info_node *tmp;

	mutex_lock(&ppp_ctxt->flow_list_lock);
	list_for_each_entry_safe(flow, tmp, &ppp_ctxt->flow_list, l_node) {
		list_del(&flow->l_node);
		devm_kfree(dev, flow);
	}
	mutex_unlock(&ppp_ctxt->flow_list_lock);

	INIT_LIST_HEAD(&ppp_ctxt->flow_list);
}

static void sxe2_flow_free_all_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	u16 i;

	for (i = 0; i < SXE2_MAX_VSIG_NUM; i++) {
		if (ppp_ctxt->vsig[i].used)
			(void)sxe2_flow_free_vsig(ppp_ctxt, i);
	}
}

void sxe2_flow_ppp_comm_ctxt_init(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				  struct sxe2_adapter *adapter,
				  enum sxe2_block_id block_id)
{
	u16 i;

	memset(ppp_ctxt, 0, sizeof(*ppp_ctxt));

	ppp_ctxt->block_id = block_id;
	ppp_ctxt->adapter = adapter;

	ppp_ctxt->hw_prof_num = sxe2_blk_prof_cnt_get(block_id);
	ppp_ctxt->hw_fv_num = sxe2_blk_fv_cnt_get(block_id);
	ppp_ctxt->hw_fv_mask_num = sxe2_blk_def_mask_fv_cnt_get(block_id);

	INIT_LIST_HEAD(&ppp_ctxt->flow_list);
	mutex_init(&ppp_ctxt->flow_list_lock);

	for (i = 0; i < SXE2_MAX_VSIG_NUM; i++)
		INIT_LIST_HEAD(&ppp_ctxt->vsig[i].associated_flow_list);
}

void sxe2_flow_ppp_comm_ctxt_deinit(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	sxe2_flow_free_all_flows(ppp_ctxt);
	mutex_destroy(&ppp_ctxt->flow_list_lock);

	sxe2_flow_free_all_vsig(ppp_ctxt);
}

void sxe2_flow_ppp_comm_ctxt_clean(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	sxe2_flow_free_all_flows(ppp_ctxt);

	sxe2_flow_free_all_vsig(ppp_ctxt);

	memset(ppp_ctxt->hw_prof, 0,
	       sizeof(struct sxe2_flow_hw_prof) * SXE2_MAX_PROF_NUM);
	memset(ppp_ctxt->tcam_entry, 0,
	       sizeof(struct sxe2_prof_tcam_entry) * SXE2_MAX_TCAM_NUM);
}

void sxe2_rss_ppp_ctxt_clean(struct sxe2_rss_ctxt *rss_ctxt)
{
	sxe2_flow_ppp_comm_ctxt_clean(&rss_ctxt->ppp);
}

s32 sxe2_rss_add_cfg(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
		     const struct sxe2_rss_hash_cfg *cfg)
{
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &rss_ctxt->ppp;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_flow_dissector_info *dissectors = NULL;
	struct sxe2_flow_info_node *flow;
	s32 ret;
	u8 dissectors_cnt;

	if (cfg->hdr_type == SXE2_RSS_OUTER_HEADERS)
		dissectors_cnt = SXE2_FLOW_DISSECTOR_SINGLE;
	else
		dissectors_cnt = SXE2_FLOW_DISSECTOR_DOUBLE;

	dissectors = devm_kcalloc(dev, dissectors_cnt, sizeof(*dissectors),
				  GFP_KERNEL);
	if (!dissectors) {
		LOG_ERROR_BDF("failed to alloc dissectors.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	LOG_DEBUG_BDF("add rss cfg, header: %lu, filed: %lu, type: %d\n",
		      cfg->headers[0], cfg->hash_flds[0], cfg->hdr_type);

	ret = sxe2_rss_gen_dissector_info(dissectors, dissectors_cnt, cfg);
	if (ret != 0)
		goto l_end;

	flow = sxe2_find_flow_with_cond(ppp_ctxt, dissectors, dissectors_cnt,
					vsi_sw_idx,
					SXE2_FLOW_FIND_FLOW_COND_VSI |
					SXE2_FLOW_FIND_FLOW_COND_FLD);
	if (flow) {
		LOG_DEBUG_BDF("add rss cfg, find vsi and (fld、hdr) same flow.\n");
		if (flow->cfg.symm == cfg->symm) {
			goto l_end;
		} else {
			flow->cfg.symm = cfg->symm;
			goto l_update_symm;
		}
	}

	flow = sxe2_find_flow_with_cond(ppp_ctxt, dissectors, dissectors_cnt,
					vsi_sw_idx, SXE2_FLOW_FIND_FLOW_COND_VSI);
	if (flow) {
		LOG_DEBUG_BDF("add rss cfg, find vsi and hdr same flow.\n");
		ret = sxe2_flow_disassoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
		if (ret != 0)
			goto l_end;

		sxe2_rss_delete_cfg_list(rss_ctxt, vsi_sw_idx, flow);

		if (bitmap_empty(flow->used_vsi, SXE2_MAX_VSI_NUM)) {
			ret = sxe2_flow_delete(ppp_ctxt, flow);
			if (ret != 0)
				goto l_end;
		}
	}

	flow = sxe2_find_flow_with_cond(ppp_ctxt, dissectors, dissectors_cnt,
					vsi_sw_idx, SXE2_FLOW_FIND_FLOW_COND_FLD);
	if (flow) {
		LOG_DEBUG_BDF("add rss cfg, find (hdr、fld) same flow.\n");
		if (flow->cfg.symm == cfg->symm) {
			ret = sxe2_flow_assoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
			if (ret == 0) {
				ret = sxe2_rss_save_cfg_list(rss_ctxt, vsi_sw_idx,
							     flow);
			}
		} else {
			ret = -EOPNOTSUPP;
		}
		goto l_end;
	}

	ret = sxe2_flow_creat(ppp_ctxt, dissectors, dissectors_cnt, &flow);
	if (ret != 0) {
		LOG_INFO_BDF("failed to Create new flow disassoc cnt:%u flow[%p].\n",
			     dissectors_cnt, flow);
		goto l_end;
	}
	LOG_DEBUG_BDF("create new flow disassoc cnt:%u flow[%p].\n", dissectors_cnt,
		      flow);

	ret = sxe2_flow_assoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
	if (ret != 0) {
		(void)sxe2_flow_delete(ppp_ctxt, flow);
		goto l_end;
	}

	ret = sxe2_rss_save_cfg_list(rss_ctxt, vsi_sw_idx, flow);

	flow->cfg.symm = cfg->symm;
l_update_symm:
	(void)sxe2_rss_update_symm(rss_ctxt, flow);
l_end:
	if (dissectors)
		devm_kfree(dev, dissectors);

	return ret;
}

s32 sxe2_rss_rem_cfg(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
		     const struct sxe2_rss_hash_cfg *cfg)
{
	struct sxe2_ppp_common_ctxt *ppp_ctxt = &rss_ctxt->ppp;
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_flow_dissector_info *dissectors;
	struct sxe2_flow_info_node *flow;
	s32 ret;
	u8 dissectors_cnt;

	if (cfg->hdr_type == SXE2_RSS_OUTER_HEADERS)
		dissectors_cnt = SXE2_FLOW_DISSECTOR_SINGLE;
	else
		dissectors_cnt = SXE2_FLOW_DISSECTOR_DOUBLE;

	dissectors = devm_kcalloc(dev, dissectors_cnt, sizeof(*dissectors),
				  GFP_KERNEL);
	if (!dissectors) {
		ret = -ENOMEM;
		goto l_end;
	}

	ret = sxe2_rss_gen_dissector_info(dissectors, dissectors_cnt, cfg);
	if (ret != 0)
		goto l_free;

	flow = sxe2_find_flow_with_cond(ppp_ctxt, dissectors, dissectors_cnt,
					vsi_sw_idx, SXE2_FLOW_FIND_FLOW_COND_FLD);
	if (!flow) {
		ret = -ENOENT;
		LOG_INFO_BDF("remove rss cfg, failed find porf.\n");
		goto l_free;
	}

	ret = sxe2_flow_disassoc_vsi(ppp_ctxt, flow, vsi_sw_idx);
	if (ret != 0)
		goto l_free;

	sxe2_rss_delete_cfg_list(rss_ctxt, vsi_sw_idx, flow);

	if (bitmap_empty(flow->used_vsi, SXE2_MAX_VSI_NUM)) {
		ret = sxe2_flow_delete(ppp_ctxt, flow);
		LOG_DEBUG_BDF("remove rss cfg. delete flow ret:%d.\n", ret);
	}
l_free:
	devm_kfree(dev, dissectors);
l_end:
	return ret;
}

static enum sxe2_rss_cfg_hdr_type
sxe2_rss_get_hdr_type(struct sxe2_flow_info_node *flow)
{
	enum sxe2_rss_cfg_hdr_type hdr_type = SXE2_RSS_ANY_HEADERS;

	if (flow->dissector_cnt == SXE2_FLOW_DISSECTOR_SINGLE) {
		hdr_type = SXE2_RSS_OUTER_HEADERS;
	} else if (flow->dissector_cnt == SXE2_FLOW_DISSECTOR_DOUBLE) {
		if (bitmap_empty(flow->dissectors[SXE2_RSS_OUTER_HEADERS].headers,
				 SXE2_FLOW_HDR_MAX)) {
			hdr_type = SXE2_RSS_INNER_HEADERS;
		} else if (test_bit(SXE2_FLOW_HDR_IPV4,
				    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
						    .headers)) {
			if (test_bit(SXE2_FLOW_HDR_GRE,
				     flow->dissectors[SXE2_RSS_OUTER_HEADERS]
						     .headers)) {
				if (test_bit(SXE2_FLOW_HDR_UDP,
					     flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							     .headers))
					hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_GRE;
				else
					hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_GRE;
			} else if (test_bit(SXE2_FLOW_HDR_VXLAN,
					    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							    .headers)) {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_VXLAN;
			} else if (test_bit(SXE2_FLOW_HDR_GENEVE,
					    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							    .headers)) {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_GENEVE;
			} else if (test_bit(SXE2_FLOW_HDR_GTPU,
					    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							    .headers)) {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4_UDP_GTPU;
			} else {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV4;
			}
		} else if (test_bit(SXE2_FLOW_HDR_IPV6,
				    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
						    .headers)) {
			if (test_bit(SXE2_FLOW_HDR_GRE,
				     flow->dissectors[SXE2_RSS_OUTER_HEADERS]
						     .headers)) {
				if (test_bit(SXE2_FLOW_HDR_UDP,
					     flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							     .headers))
					hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_GRE;
				else
					hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_GRE;
			} else if (test_bit(SXE2_FLOW_HDR_VXLAN,
					    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							    .headers)) {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_VXLAN;
			} else if (test_bit(SXE2_FLOW_HDR_GENEVE,
					    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							    .headers)) {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_GENEVE;
			} else if (test_bit(SXE2_FLOW_HDR_GTPU,
					    flow->dissectors[SXE2_RSS_OUTER_HEADERS]
							    .headers)) {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6_UDP_GTPU;
			} else {
				hdr_type = SXE2_RSS_INNER_HEADERS_WITH_OUTER_IPV6;
			}
		}
	}

	return hdr_type;
}

s32 sxe2_rss_save_cfg_list(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
			   struct sxe2_flow_info_node *flow)
{
	struct sxe2_adapter *adapter = rss_ctxt->ppp.adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_rss_cfg *rss_cfg;
	enum sxe2_rss_cfg_hdr_type hdr_type;
	s32 ret = 0;
	u8 dissector_idx;

	hdr_type = sxe2_rss_get_hdr_type(flow);
	dissector_idx = (u8)(flow->dissector_cnt - (u8)1);

	list_for_each_entry(rss_cfg, &rss_ctxt->rss_cfgs, l_node) {
		if (bitmap_equal(rss_cfg->hash_cfg.hash_flds,
				 flow->dissectors[dissector_idx].fields,
				 SXE2_FLOW_FLD_ID_MAX) &&
		    bitmap_equal(rss_cfg->hash_cfg.headers,
				 flow->dissectors[dissector_idx].headers,
				 SXE2_FLOW_HDR_MAX) &&
		    rss_cfg->hash_cfg.hdr_type == hdr_type) {
			set_bit(vsi_sw_idx, rss_cfg->vsis);
			goto l_end;
		}
	}

	rss_cfg = devm_kzalloc(dev, sizeof(*rss_cfg), GFP_KERNEL);
	if (!rss_cfg) {
		LOG_ERROR_BDF("failed to alloc rss_cfg memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	bitmap_copy(rss_cfg->hash_cfg.hash_flds,
		    flow->dissectors[dissector_idx].fields, SXE2_FLOW_FLD_ID_MAX);
	bitmap_copy(rss_cfg->hash_cfg.headers,
		    flow->dissectors[dissector_idx].headers, SXE2_FLOW_HDR_MAX);
	rss_cfg->hash_cfg.hdr_type = hdr_type;
	rss_cfg->hash_cfg.symm = flow->cfg.symm;
	set_bit(vsi_sw_idx, rss_cfg->vsis);

	list_add_tail(&rss_cfg->l_node, &rss_ctxt->rss_cfgs);
l_end:
	return ret;
}

static void sxe2_rss_delete_cfg_list(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
				     struct sxe2_flow_info_node *flow)
{
	struct sxe2_adapter *adapter = rss_ctxt->ppp.adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_rss_cfg *rss_cfg;
	struct sxe2_rss_cfg *tmp;
	enum sxe2_rss_cfg_hdr_type hdr_type;
	u8 dissector_idx;

	hdr_type = sxe2_rss_get_hdr_type(flow);
	dissector_idx = (u8)(flow->dissector_cnt - (u8)1);

	list_for_each_entry_safe(rss_cfg, tmp, &rss_ctxt->rss_cfgs, l_node) {
		if (bitmap_equal(rss_cfg->hash_cfg.hash_flds,
				 flow->dissectors[dissector_idx].fields,
				 SXE2_FLOW_FLD_ID_MAX) &&
		    bitmap_equal(rss_cfg->hash_cfg.headers,
				 flow->dissectors[dissector_idx].headers,
				 SXE2_FLOW_HDR_MAX) &&
		    rss_cfg->hash_cfg.hdr_type == hdr_type) {
			clear_bit(vsi_sw_idx, rss_cfg->vsis);
			if (bitmap_empty(rss_cfg->vsis, SXE2_MAX_VSI_NUM)) {
				list_del(&rss_cfg->l_node);
				devm_kfree(dev, rss_cfg);
			}
			goto l_end;
		}
	}

	LOG_WARN_BDF("delete cfg list error, not find rss cfg.\n");
l_end:
	return;
}

void sxe2_rss_delete_vsi_cfg_list(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx)
{
	struct sxe2_adapter *adapter = rss_ctxt->ppp.adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_rss_cfg *rss_cfg;
	struct sxe2_rss_cfg *tmp;

	if (list_empty(&rss_ctxt->rss_cfgs))
		goto l_end;

	list_for_each_entry_safe(rss_cfg, tmp, &rss_ctxt->rss_cfgs, l_node) {
		if (test_bit(vsi_sw_idx, rss_cfg->vsis)) {
			clear_bit(vsi_sw_idx, rss_cfg->vsis);
			if (bitmap_empty(rss_cfg->vsis, SXE2_MAX_VSI_NUM)) {
				list_del(&rss_cfg->l_node);
				devm_kfree(dev, rss_cfg);
			}
		}
	}
l_end:
	return;
}

void sxe2_rss_get_hash_cfg_with_hdrs(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
				     unsigned long *headers,
				     unsigned long *hash_flds)
{
	struct sxe2_rss_cfg *rss_cfg;

	if (bitmap_empty(headers, SXE2_FLOW_HDR_MAX) ||
	    vsi_sw_idx >= SXE2_MAX_VSI_NUM) {
		return;
	}

	bitmap_zero(hash_flds, SXE2_FLOW_FLD_ID_MAX);

	mutex_lock(&rss_ctxt->rss_cfgs_lock);
	list_for_each_entry(rss_cfg, &rss_ctxt->rss_cfgs, l_node) {
		if (test_bit(vsi_sw_idx, rss_cfg->vsis) &&
		    bitmap_equal(rss_cfg->hash_cfg.headers, headers,
				 SXE2_FLOW_HDR_MAX)) {
			bitmap_copy(hash_flds, rss_cfg->hash_cfg.hash_flds,
				    SXE2_FLOW_FLD_ID_MAX);
			break;
		}
	}
	mutex_unlock(&rss_ctxt->rss_cfgs_lock);
}

s32 sxe2_rss_replay_hash_cfg(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx)
{
	struct sxe2_adapter *adapter = rss_ctxt->ppp.adapter;
	struct sxe2_rss_cfg *rss_cfg;
	s32 ret = 0;

	if (vsi_sw_idx >= SXE2_VSI_MAX_CNT) {
		ret = -EINVAL;
		goto l_end;
	}

	mutex_lock(&rss_ctxt->rss_cfgs_lock);
	list_for_each_entry(rss_cfg, &rss_ctxt->rss_cfgs, l_node) {
		if (test_bit(vsi_sw_idx, rss_cfg->vsis)) {
			ret = sxe2_rss_add_cfg(rss_ctxt, vsi_sw_idx,
					       &rss_cfg->hash_cfg);
			if (ret != 0) {
				LOG_ERROR_BDF("replay vsi[%d] rss cfg error, \t"
					      "ret:%d.\n",
					      vsi_sw_idx, ret);
				break;
			}
		}
	}
	mutex_unlock(&rss_ctxt->rss_cfgs_lock);
l_end:
	return ret;
}

void sxe2_rss_comm_init(struct sxe2_rss_ctxt *rss_ctxt)
{
	mutex_init(&rss_ctxt->rss_cfgs_lock);
	INIT_LIST_HEAD(&rss_ctxt->rss_cfgs);
}

void sxe2_rss_comm_deinit(struct sxe2_rss_ctxt *rss_ctxt)
{
	struct sxe2_adapter *adapter = rss_ctxt->ppp.adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_rss_cfg *rss_cfg, *tmp;

	mutex_lock(&rss_ctxt->rss_cfgs_lock);
	list_for_each_entry_safe(rss_cfg, tmp, &rss_ctxt->rss_cfgs, l_node) {
		list_del(&rss_cfg->l_node);
		devm_kfree(dev, rss_cfg);
	}
	mutex_unlock(&rss_ctxt->rss_cfgs_lock);
	mutex_destroy(&rss_ctxt->rss_cfgs_lock);
}

s32 sxe2_add_rss_flow(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
		      const struct sxe2_rss_hash_cfg *cfg)
{
	s32 ret;
	struct sxe2_rss_hash_cfg cfg_tmp;

	if (vsi_sw_idx >= SXE2_VSI_MAX_CNT || !cfg || !rss_ctxt ||
	    cfg->hdr_type > SXE2_RSS_ANY_HEADERS ||
	    bitmap_empty(cfg->hash_flds, SXE2_FLOW_FLD_ID_MAX)) {
		return -EINVAL;
	}

	cfg_tmp = *cfg;
	mutex_lock(&rss_ctxt->rss_cfgs_lock);
	if (cfg->hdr_type < SXE2_RSS_ANY_HEADERS) {
		ret = sxe2_rss_add_cfg(rss_ctxt, vsi_sw_idx, &cfg_tmp);
	} else {
		cfg_tmp.hdr_type = SXE2_RSS_OUTER_HEADERS;
		ret = sxe2_rss_add_cfg(rss_ctxt, vsi_sw_idx, &cfg_tmp);
		if (!ret) {
			cfg_tmp.hdr_type = SXE2_RSS_INNER_HEADERS;
			ret = sxe2_rss_add_cfg(rss_ctxt, vsi_sw_idx, &cfg_tmp);
		}
	}
	mutex_unlock(&rss_ctxt->rss_cfgs_lock);

	return ret;
}

void sxe2_flow_xlt2_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	u32 i = 0;

	LOG_DEV_INFO("xlt2 info dump start, block id %u\n", ppp_ctxt->block_id);
	for (i = 0; i < SXE2_MAX_VSI_NUM; i++) {
		if (ppp_ctxt->vsi_to_grp[i].idx && adapter->vsi_ctxt.vsi[i]) {
			LOG_DEV_INFO("vsi[%u](hw_id:%u)-->vsig[%u]\n",
				     adapter->vsi_ctxt.vsi[i]->id_in_pf,
				     adapter->vsi_ctxt.vsi[i]->idx_in_dev,
				     ppp_ctxt->vsi_to_grp[i].idx);
		}
	}
	LOG_DEV_INFO("xlt2 info dump end, block id %u\n", ppp_ctxt->block_id);
}

void sxe2_flow_vsig_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	u64 i = 0, j = 0;
	struct sxe2_associated_flow_node *associated_flow;
	DECLARE_BITMAP(vsis, SXE2_MAX_VSI_NUM);

	bitmap_zero(vsis, SXE2_MAX_VSI_NUM);

	LOG_DEV_INFO("vsig info dump start, block id %u\n", ppp_ctxt->block_id);
	for (i = 0; i < SXE2_MAX_VSIG_NUM; i++) {
		if (ppp_ctxt->vsig[i].used) {
			bitmap_zero(vsis, SXE2_MAX_VSI_NUM);
			bitmap_copy(vsis, ppp_ctxt->vsig[i].vsis, SXE2_MAX_VSI_NUM);
			LOG_DEV_INFO("vsig[%llu], vsi cnt: %u\n", i,
				     ppp_ctxt->vsig[i].vsi_cnt);
			LOG_DEV_INFO("vsi list:\n");
			for_each_set_bit(j, vsis, SXE2_MAX_VSI_NUM) {
				if (adapter->vsi_ctxt.vsi[j]) {
					LOG_DEV_INFO("\tvsi sw_id: %u, hw_id: %u\n",
						     adapter->vsi_ctxt.vsi[j]
								     ->id_in_pf,
						     adapter->vsi_ctxt.vsi[j]
								     ->idx_in_dev);
				}
				clear_bit((int)j, vsis);
			}
			LOG_DEV_INFO("profile list:\n");
			list_for_each_entry(associated_flow,
					    &ppp_ctxt->vsig[i].associated_flow_list,
					    l_node) {
				LOG_DEV_INFO("\tprof id: %u, priority: %d, \t"
					     "tcam_cnt: %u\n",
					     associated_flow->flow_ptr->prof_id,
					     associated_flow->flow_ptr->priority,
					     associated_flow->tcam_cnt);
				for (j = 0; j < associated_flow->tcam_cnt; j++) {
					LOG_DEV_INFO("\t\ttcam[%u], used: %d, \t"
						     "prof_id: %u, ptg: %u\n",
						     associated_flow->tcams[j].idx,
						     associated_flow->tcams[j].used,
						     associated_flow->tcams[j]
								     .prof_id,
						     associated_flow->tcams[j].ptg);
				}
			}
		}
	}
	LOG_DEV_INFO("vsig info dump end, block id %u\n", ppp_ctxt->block_id);
}

void sxe2_flow_prof_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	u32 i = 0, j = 0;

	LOG_DEV_INFO("profile info dump start, block id %u\n", ppp_ctxt->block_id);
	for (i = 0; i < ppp_ctxt->hw_prof_num; i++) {
		if (ppp_ctxt->hw_prof[i].avail) {
			LOG_DEV_INFO("prof[%u], mask_sel: 0x%x\n", i,
				     ppp_ctxt->hw_prof[i].fv_masks_sel);
			for (j = 0; j < ppp_ctxt->hw_fv_num; j++) {
				LOG_DEV_INFO("\tfv[%u], protocol: %u, offset: %u\n",
					     j, ppp_ctxt->hw_prof[i].fv[j].prot_id,
					     ppp_ctxt->hw_prof[i].fv[j].off);
			}
		}
	}
	LOG_DEV_INFO("profile info dump end, block id %u\n", ppp_ctxt->block_id);
}

void sxe2_flow_mask_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	u32 i = 0;

	LOG_DEV_INFO("mask info dump start, block id %u\n", ppp_ctxt->block_id);
	for (i = 0; i < SXE2_MAX_FV_MASK; i++) {
		LOG_DEV_INFO("mask[%u], fv_idx: %u, mask_val: 0x%x\n", i,
			     ppp_ctxt->fv_mask[i].mask_idx,
			     ppp_ctxt->fv_mask[i].mask);
	}
	LOG_DEV_INFO("mask info dump end, block id %u\n", ppp_ctxt->block_id);
}
