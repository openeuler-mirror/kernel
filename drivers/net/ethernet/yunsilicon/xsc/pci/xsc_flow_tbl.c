// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_flow_tbl.h"
#include "xsc_flow_pool.h"
#include "xsc_flow.h"

static struct xsc_flow_grp_idx_range grp_idx_range_tbl[FLOW_GRP_RESV_MAX] = {
	[FLOW_GRP_INGRESS_1] = {.max_entries = FLOW_GRP_DEFAULT_MAX_ENTRIES},
	[FLOW_GRP_INGRESS_2] = {.max_entries = FLOW_GRP_DEFAULT_NODEPORT_NUM},
	[FLOW_GRP_INGRESS_DEFAULT] = {.max_entries = 8},
	[FLOW_GRP_EGRESS_1] = {.max_entries = FLOW_GRP_DEFAULT_MAX_ENTRIES},
	[FLOW_GRP_EGRESS_2] = {.max_entries = FLOW_GRP_DEFAULT_ENTRIES_NUM},
	[FLOW_GRP_EGRESS_3] = {.max_entries = 0},
	[FLOW_GRP_EGRESS_4] = {.max_entries = FLOW_GRP_DEFAULT_NODEPORT_NUM},
	[FLOW_GRP_EGRESS_5] = {.max_entries = FLOW_GRP_DEFAULT_ENTRIES_NUM},
	[FLOW_GRP_EGRESS_6] = {.max_entries = FLOW_GRP_DEFAULT_ENTRIES_NUM},
	[FLOW_GRP_EGRESS_7] = {.max_entries = FLOW_GRP_DEFAULT_ENTRIES_NUM},
	[FLOW_GRP_EGRESS_8] = {.max_entries = 8},
	[FLOW_GRP_EGRESS_DEFAULT]  = {.max_entries = 2},
};

static int xsc_flow_tbl_res_alloc(struct xsc_core_device *dev,
				  struct xsc_flow_tbl_mgr *tbl_mgr,
				  u8 res_tbl_id, u32 base_index, u32 max_entries)
{
	struct xsc_flow_tbl_res *tbl_res;

	if (res_tbl_id >= XSC_RES_MGR_MAX_TBL_NUM)
		return -EINVAL;

	tbl_res = &tbl_mgr->res_tables[res_tbl_id];

	tbl_res->bitmap = kcalloc(BITS_TO_LONGS(max_entries), sizeof(unsigned long), GFP_KERNEL);
	if (!tbl_res->bitmap)
		return -ENOMEM;

	tbl_res->base_idx = base_index;
	tbl_res->max_entries = max_entries;
	spin_lock_init(&tbl_res->lock);

	xsc_core_info(dev, "[tbl_res_alloc], res_tbl_id:%d, base_idx:%d, max_entries:%d",
		      res_tbl_id, tbl_res->base_idx, tbl_res->max_entries);

	return 0;
}

static int xsc_flow_tbl_res_mgr_init(struct xsc_core_device *dev, struct xsc_flow_tbl_mgr *tbl_mgr)
{
	struct xsc_cmd_get_res_mgr_tbl_mbox_out *out;
	struct xsc_cmd_get_res_mgr_tbl_mbox_in in;
	void *data_ptr;
	int err;
	u16 rsp_data_size;
	u8 table_id;

	rsp_data_size = sizeof(struct xsc_flow_tbl_res_mgr) * XSC_RES_MGR_MAX_TBL_NUM;
	out = kzalloc(sizeof(*out) + rsp_data_size, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_RES_MGR_TBL_INFO);

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out) + rsp_data_size);
	if (err)
		goto out;

	if (out->hdr.status) {
		err = xsc_cmd_status_to_err(&out->hdr);
		goto out;
	}

	memset(tbl_mgr->res_tables, 0, sizeof(tbl_mgr->res_tables));
	data_ptr = out->data;
	for (table_id = 0; table_id < XSC_RES_MGR_MAX_TBL_NUM; table_id++) {
		struct xsc_flow_tbl_res_mgr *res_mgr_tbl = (struct xsc_flow_tbl_res_mgr *)data_ptr;

		xsc_flow_tbl_res_alloc(dev, tbl_mgr, table_id,
				       be32_to_cpu(res_mgr_tbl->base_idx),
				       be32_to_cpu(res_mgr_tbl->max_entries));
		data_ptr += sizeof(struct xsc_flow_tbl_res_mgr);
	}

	return 0;

out:
	kfree(out);

	return err;
}

static int xsc_flow_tbl_ofld_init(struct xsc_core_device *dev, struct xsc_flow_tbl_mgr *tbl_mgr)
{
	struct xsc_cmd_get_ofld_tbl_mbox_out *out;
	struct xsc_cmd_get_ofld_tbl_mbox_in in;
	void *data_ptr;
	int err;
	u16 rsp_data_size;

	rsp_data_size = sizeof(struct xsc_flow_tbl_ofld) * XSC_OFLD_MAX_TBL_NUM;
	out = kzalloc(sizeof(*out) + rsp_data_size, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_OFLD_TBL_INFO);

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out) + rsp_data_size);
	if (err)
		goto out;

	if (out->hdr.status) {
		err = xsc_cmd_status_to_err(&out->hdr);
		goto out;
	}

	memset(tbl_mgr->ofld_tables, 0, sizeof(tbl_mgr->ofld_tables));
	data_ptr = out->data;
	memcpy(tbl_mgr->ofld_tables, data_ptr,
	       sizeof(struct xsc_flow_tbl_ofld) * XSC_OFLD_MAX_TBL_NUM);

	return 0;

out:
	kfree(out);

	return err;
}

static int xsc_flow_tbl_list_init(struct xsc_core_device *dev, struct xsc_flow_tbl_mgr *tbl_mgr)
{
	struct xsc_hw_tbl_head *hw_tbl_hdr = NULL;
	u8 table_id;

	for (table_id = 0; table_id < XSC_RES_MGR_MAX_TBL_NUM; table_id++) {
		hw_tbl_hdr = kzalloc(sizeof(*hw_tbl_hdr), GFP_KERNEL);
		if (!hw_tbl_hdr)
			return -ENOMEM;
		INIT_LIST_HEAD(&hw_tbl_hdr->entry_list);
		spin_lock_init(&hw_tbl_hdr->lock);
		tbl_mgr->hw_tbl_list[table_id] = hw_tbl_hdr;
	}

	return 0;
}

static int xsc_flow_tbl_list_free(struct xsc_flow_tbl_mgr *tbl_mgr)
{
	struct xsc_hw_tbl_head *hw_tbl_hdr = NULL;
	struct xsc_hw_tbl *hw_tbl = NULL;
	struct xsc_hw_tbl *tmp = NULL;
	u8 table_id;

	for (table_id = 0; table_id < XSC_RES_MGR_MAX_TBL_NUM; table_id++) {
		hw_tbl_hdr = tbl_mgr->hw_tbl_list[table_id];
		if (!hw_tbl_hdr)
			continue;

		spin_lock(&hw_tbl_hdr->lock);
		list_for_each_entry_safe(hw_tbl, tmp, &hw_tbl_hdr->entry_list, list) {
			list_del(&hw_tbl->list);
			kfree(hw_tbl->raw_data);
			kfree(hw_tbl);
		}
		spin_unlock(&hw_tbl_hdr->lock);
		kfree(hw_tbl_hdr);
		tbl_mgr->hw_tbl_list[table_id] = NULL;
	}

	return 0;
}

struct xsc_flow_tbl_mgr *xsc_flow_tbl_mgr_alloc(struct xsc_core_device *dev)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = NULL;
	int ret = 0;

	tbl_mgr = kzalloc(sizeof(*tbl_mgr), GFP_KERNEL);
	if (!tbl_mgr)
		return NULL;

	ret = xsc_flow_tbl_res_mgr_init(dev, tbl_mgr);
	if (ret) {
		xsc_core_err(dev, "failed to init res mgr tbl");
		goto error;
	}

	ret = xsc_flow_tbl_ofld_init(dev, tbl_mgr);
	if (ret) {
		xsc_core_err(dev, "failed to init ofld tbl");
		goto error;
	}

	ret = xsc_flow_tbl_list_init(dev, tbl_mgr);
	if (ret) {
		xsc_core_err(dev, "failed to init hw tbl list");
		goto error;
	}

	return tbl_mgr;
error:
	kfree(tbl_mgr);

	return NULL;
}

void xsc_flow_tbl_mgr_free(struct xsc_flow_tbl_mgr *tbl_mgr)
{
	int i;

	if (!tbl_mgr)
		return;

	for (i = 0; i < XSC_RES_MGR_MAX_TBL_NUM; i++) {
		kfree(tbl_mgr->res_tables[i].bitmap);
		tbl_mgr->res_tables[i].bitmap = NULL;
		tbl_mgr->res_tables[i].max_entries = 0;
		tbl_mgr->res_tables[i].base_idx = 0;
	}

	xsc_flow_tbl_list_free(tbl_mgr);
}

struct xsc_hw_tbl *xsc_hw_tbl_create(struct xsc_core_device *dev,
				     u8 ofld_tbl_id,
				     const void *data, u16 data_len,
				     u32 entry_idx,
				     enum xsc_tbl_index_mgr_type idx_mgr_type)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_hw_tbl_head *hw_tbl_hdr = NULL;
	struct xsc_hw_tbl *hw_tbl = NULL;
	void *raw_data = NULL;
	u8 res_tbl_id;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow tbl mgr is null");
		return NULL;
	}

	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM) {
		xsc_core_err(dev, "invalid offload table id %d", ofld_tbl_id);
		return NULL;
	}

	hw_tbl = kzalloc(sizeof(*hw_tbl), GFP_KERNEL);
	if (!hw_tbl)
		return NULL;

	if (data && data_len != 0) {
		raw_data = kzalloc(data_len, GFP_KERNEL);
		if (!raw_data)
			return NULL;
		memcpy(raw_data, data, data_len);
	}

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	hw_tbl_hdr = tbl_mgr->hw_tbl_list[res_tbl_id];

	hw_tbl->idx = entry_idx;
	hw_tbl->raw_data = raw_data;
	hw_tbl->res_tbl_type = res_tbl_id;
	hw_tbl->idx_mgr_type = idx_mgr_type;

	xsc_core_info(dev, "[hw_tbl] ofld_tbl_id:%d(%d), entry_idx:%d",
		      ofld_tbl_id, hw_tbl->res_tbl_type, hw_tbl->idx);

	spin_lock(&hw_tbl_hdr->lock);
	list_add_tail(&hw_tbl->list, &hw_tbl_hdr->entry_list);
	spin_unlock(&hw_tbl_hdr->lock);

	return hw_tbl;
}

void xsc_hw_tbl_free(struct xsc_core_device *dev,
		     struct xsc_hw_tbl *hw_tbl)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_hw_tbl_head *hw_tbl_hdr = NULL;
	u8 res_tbl_id;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow tbl mgr is null");
		return;
	}

	res_tbl_id = hw_tbl->res_tbl_type;
	hw_tbl_hdr = tbl_mgr->hw_tbl_list[res_tbl_id];
	spin_lock(&hw_tbl_hdr->lock);
	list_del(&hw_tbl->list);
	kfree(hw_tbl->raw_data);
	kfree(hw_tbl->action_data);
	kfree(hw_tbl->key);
	kfree(hw_tbl);
	spin_unlock(&hw_tbl_hdr->lock);
}

struct xsc_hw_tbl *xsc_hw_tbl_find(struct xsc_core_device *dev,
				   u8 ofld_tbl_id, const void *data, u16 data_len)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_hw_tbl_head *hw_tbl_hdr = NULL;
	struct xsc_hw_tbl *hw_tbl = NULL;
	u8 res_tbl_id;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow tbl mgr is null");
		return NULL;
	}

	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM) {
		xsc_core_err(dev, "invalid offload table id %d", ofld_tbl_id);
		return NULL;
	}

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	hw_tbl_hdr = tbl_mgr->hw_tbl_list[res_tbl_id];

	spin_lock(&hw_tbl_hdr->lock);
	list_for_each_entry(hw_tbl, &hw_tbl_hdr->entry_list, list) {
		if (!memcmp(hw_tbl->raw_data, data, data_len)) {
			spin_unlock(&hw_tbl_hdr->lock);
			return hw_tbl;
		}
	}
	spin_unlock(&hw_tbl_hdr->lock);

	return NULL;
}

struct xsc_hw_tbl *xsc_hw_tbl_find_with_idx(struct xsc_core_device *dev,
					    u8 ofld_tbl_id, u32 idx)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_hw_tbl_head *hw_tbl_hdr = NULL;
	struct xsc_hw_tbl *hw_tbl = NULL;
	u8 res_tbl_id;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow tbl mgr is null");
		return NULL;
	}

	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM) {
		xsc_core_err(dev, "invalid offload table id %d", ofld_tbl_id);
		return NULL;
	}

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	hw_tbl_hdr = tbl_mgr->hw_tbl_list[res_tbl_id];

	spin_lock(&hw_tbl_hdr->lock);
	list_for_each_entry(hw_tbl, &hw_tbl_hdr->entry_list, list) {
		if (hw_tbl->idx == idx) {
			spin_unlock(&hw_tbl_hdr->lock);
			return hw_tbl;
		}
	}
	spin_unlock(&hw_tbl_hdr->lock);

	return NULL;
}

int xsc_hw_tbl_fill_action_data(struct xsc_core_device *dev,
				struct xsc_hw_tbl *hw_tbl,
				void *data, u16 data_len)
{
	void *action_data = NULL;

	if (data && data_len != 0) {
		action_data = kzalloc(data_len, GFP_KERNEL);
		if (!action_data)
			return -ENOMEM;
		memcpy(action_data, data, data_len);
	} else {
		return -EINVAL;
	}

	hw_tbl->action_data = action_data;

	return 0;
}

int xsc_hw_tbl_fill_em_key(struct xsc_core_device *dev,
			   struct xsc_hw_tbl *hw_tbl, void *data, u16 data_len)
{
	void *key = NULL;

	if (!hw_tbl) {
		xsc_core_err(dev, "hw tbl is null");
		return -EINVAL;
	}

	if (data && data_len != 0) {
		key = kzalloc(data_len, GFP_KERNEL);
		if (!key)
			return -ENOMEM;
		memcpy(key, data, data_len);
	} else {
		return -EINVAL;
	}

	hw_tbl->key = key;

	return 0;
}

int xsc_hw_tbl_alloc_idx(struct xsc_core_device *dev, u8 ofld_tbl_id, u32 *index)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_flow_tbl_res *tbl_res;
	u32 offset;
	u8 res_tbl_id;
	unsigned long flags;
	int ret = 0;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow table mgr is null");
		return -EINVAL;
	}

	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM) {
		xsc_core_err(dev, "invalid hw tbl ofld table id %d", ofld_tbl_id);
		return -EINVAL;
	}

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	tbl_res = &tbl_mgr->res_tables[res_tbl_id];

	spin_lock_irqsave(&tbl_res->lock, flags);
	offset = find_first_zero_bit(tbl_res->bitmap, tbl_res->max_entries);
	if (offset < tbl_res->max_entries) {
		set_bit(offset, tbl_res->bitmap);
		*index = tbl_res->base_idx + offset;
	} else {
		spin_unlock_irqrestore(&tbl_res->lock, flags);
		xsc_core_err(dev, "no resources available for flow res table id %d", res_tbl_id);
		ret = -ENOMEM;
	}
	spin_unlock_irqrestore(&tbl_res->lock, flags);

	return ret;
}

void xsc_hw_tbl_free_idx(struct xsc_core_device *dev, struct xsc_hw_tbl *hw_tbl, u8 ofld_tbl_id)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_flow_tbl_res *tbl_res;
	unsigned long flags;
	u8 res_tbl_id;
	u32 offset;
	u32 index = hw_tbl->idx;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow tbl mgr is null");
		return;
	}

	if (hw_tbl->idx_mgr_type != XSC_TBL_INDEX_LOCAL_MGR) {
		xsc_core_info(dev, "[tbl_res] index not local manager, idx_mgr_type:%d",
			      hw_tbl->idx_mgr_type);
		return;
	}

	xsc_core_info(dev, "[tbl_res] free ofld_tbl_id:%d, index:%d", ofld_tbl_id, index);
	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM)
		return;

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	tbl_res = &tbl_mgr->res_tables[res_tbl_id];

	if (index < tbl_res->base_idx || index >= (tbl_res->base_idx + tbl_res->max_entries))
		return;

	offset = index - tbl_res->base_idx;

	spin_lock_irqsave(&tbl_res->lock, flags);
	clear_bit(offset, tbl_res->bitmap);
	spin_unlock_irqrestore(&tbl_res->lock, flags);
}

int xsc_hw_tbl_bulk_alloc(struct xsc_core_device *dev, u8 ofld_tbl_id, u32 *base_id, u32 count)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_flow_tbl_res *tbl_res;
	u32 offset;
	u8 res_tbl_id;
	unsigned long flags;
	int ret = 0;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow table mgr is null");
		return -EINVAL;
	}

	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM) {
		xsc_core_err(dev, "invalid hw tbl ofld table id %d", ofld_tbl_id);
		return -EINVAL;
	}

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	tbl_res = &tbl_mgr->res_tables[res_tbl_id];

	spin_lock_irqsave(&tbl_res->lock, flags);

	offset = bitmap_find_next_zero_area(tbl_res->bitmap, tbl_res->max_entries, 0, count, 0);
	if (offset < tbl_res->max_entries) {
		bitmap_set(tbl_res->bitmap, offset, count);
		*base_id = tbl_res->base_idx + offset;
	} else {
		xsc_core_err(dev, "no %u consecutive resources available for res_tbl_id %d",
			     count, res_tbl_id);
		ret = -ENOMEM;
	}

	spin_unlock_irqrestore(&tbl_res->lock, flags);
	return ret;
}

int xsc_hw_tbl_bulk_free(struct xsc_core_device *dev, u8 ofld_tbl_id, u32 base_id, u32 count)
{
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_flow_tbl_res *tbl_res;
	unsigned long flags;
	u8 res_tbl_id;
	u32 offset;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow tbl mgr is null");
		return -EINVAL;
	}

	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM)
		return -EINVAL;

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	tbl_res = &tbl_mgr->res_tables[res_tbl_id];

	if (base_id < tbl_res->base_idx ||
	    base_id + count > tbl_res->base_idx + tbl_res->max_entries) {
		xsc_core_err(dev, "invalid base_id or count,base_i:%d, count:%d",
			     base_id, count);
		return -EINVAL;
	}

	offset = base_id - tbl_res->base_idx;

	spin_lock_irqsave(&tbl_res->lock, flags);
	bitmap_clear(tbl_res->bitmap, offset, count);
	spin_unlock_irqrestore(&tbl_res->lock, flags);

	xsc_core_info(dev, "[tbl_res_block] free ofld_tbl_id:%d, index:%d, count:%d",
		      ofld_tbl_id, base_id, count);

	return 0;
}

int xsc_flow_grp_res_alloc(struct xsc_core_device *dev, u32 grp_id)
{
	struct xsc_flow_grp_res_mgr *grp_res_mgr = dev->board_info->flow_grp_res_mgr;
	struct xsc_flow_grp_res *grp_res;
	struct xsc_flow_grp_idx_range *grp_idx_range;
	u32 max_entries;

	if (grp_id >= FLOW_GRP_RESV_MAX) {
		xsc_core_err(dev, "invalid group id:%d, max support group: %d",
			     grp_id, FLOW_GRP_RESV_MAX);
		return -EINVAL;
	}

	grp_idx_range = &grp_idx_range_tbl[grp_id];
	max_entries = grp_idx_range->max_entries;

	grp_res = &grp_res_mgr->grp_res[grp_id];
	if (grp_res->initialized) {
		atomic_inc(&grp_res->refcnt);
		xsc_core_info(dev, "[grp_res_alloc] res already initialized grp_id:%d, ref_cnt:%d",
			      grp_id, atomic_read(&grp_res->refcnt));
		return 0;
	}

	grp_res->bitmap = kcalloc(BITS_TO_LONGS(max_entries), sizeof(unsigned long), GFP_KERNEL);
	if (!grp_res->bitmap)
		return -ENOMEM;

	grp_res->base_idx = grp_idx_range->start_idx;
	grp_res->max_entries = max_entries;
	spin_lock_init(&grp_res->lock);
	grp_res->initialized = true;
	atomic_inc(&grp_res->refcnt);

	xsc_core_info(dev,
		      "[grp_res_alloc] allocated, grp_id:%d, base_idx:%d, max_entr:%d, ref_cnt:%d",
		      grp_id, grp_res->base_idx, grp_res->max_entries,
		      atomic_read(&grp_res->refcnt));

	return 0;
}

bool xsc_flow_grp_res_free(struct xsc_core_device *dev, u32 grp_id)
{
	struct xsc_flow_grp_res_mgr *grp_res_mgr = dev->board_info->flow_grp_res_mgr;
	struct xsc_flow_grp_res *grp_res;

	if (grp_id >= FLOW_GRP_RESV_MAX) {
		xsc_core_err(dev, "invalid group id:%d, max support group: %d",
			     grp_id, FLOW_GRP_RESV_MAX);
		return false;
	}

	grp_res = &grp_res_mgr->grp_res[grp_id];
	if (!grp_res->initialized) {
		xsc_core_warn(dev, "group res not initialized, nothing to free, grp_id:%d",
			      grp_id);
		return false;
	}

	if (!atomic_dec_and_test(&grp_res->refcnt)) {
		xsc_core_info(dev, "[grp_res_free] res still in use, grp_id:%d, ref_cnt:%d",
			      grp_id, atomic_read(&grp_res->refcnt));
		return false;
	}

	kfree(grp_res->bitmap);
	grp_res->bitmap = NULL;
	grp_res->base_idx = 0;
	grp_res->max_entries = 0;
	grp_res->initialized = false;

	xsc_core_info(dev, "[grp_res_free] freed, grp_id:%d", grp_id);

	return true;
}

int xsc_flow_grp_idx_range_init(struct xsc_core_device *dev,
				u32 pct_start, u32 pct_end)
{
	struct xsc_flow_grp_idx_range *grp_idx_range;
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	u32 base_idx, max_entries, support_end_idx;
	int grp_id;

	if (!tbl_mgr) {
		xsc_core_err(dev, "tbl_mgr is null\n");
		return -EINVAL;
	}

	base_idx = tbl_mgr->res_tables[XSC_RES_MGR_PCT_TBL].base_idx;
	max_entries = tbl_mgr->res_tables[XSC_RES_MGR_PCT_TBL].max_entries;
	support_end_idx = base_idx + max_entries - 1;

	if (pct_start > base_idx)
		base_idx = pct_start;

	if (pct_end < support_end_idx)
		support_end_idx = pct_end;

	xsc_core_info(dev, "[grp_idx_range] pct available idx range, base_idx:%u, end_idx:%u",
		      base_idx, support_end_idx);

	for (grp_id = 0; grp_id < FLOW_GRP_RESV_MAX; grp_id++) {
		grp_idx_range = &grp_idx_range_tbl[grp_id];
		if (grp_idx_range->max_entries == 0)
			continue;

		if (base_idx + grp_idx_range->max_entries - 1 > support_end_idx) {
			xsc_core_err(dev, "no available pct entries for grp:%u, max_entr:%u\n",
				     grp_id, grp_idx_range->max_entries);
			return -EINVAL;
		}

		grp_idx_range->start_idx = base_idx;
		grp_idx_range->end_idx = base_idx + grp_idx_range->max_entries - 1;

		base_idx = grp_idx_range->end_idx + 1;

		xsc_core_info(dev, "[grp_idx_range] grp_id:%d, s_idx=%u, e_idx=%u, max_entr=%u\n",
			      grp_id, grp_idx_range->start_idx, grp_idx_range->end_idx,
			      grp_idx_range->max_entries);
	}

	return 0;
}

struct xsc_flow_grp_res_mgr *xsc_flow_grp_res_mgr_alloc(struct xsc_core_device *dev)
{
	struct xsc_flow_grp_res_mgr *grp_res_mgr = NULL;

	grp_res_mgr = kzalloc(sizeof(*grp_res_mgr), GFP_KERNEL);
	if (!grp_res_mgr)
		return NULL;

	return grp_res_mgr;
}

void xsc_flow_grp_res_mgr_free(struct xsc_flow_grp_res_mgr *grp_res_mgr)
{
	int grp_id;

	if (!grp_res_mgr)
		return;

	for (grp_id = 0; grp_id < FLOW_GRP_RESV_MAX; grp_id++) {
		kfree(grp_res_mgr->grp_res[grp_id].bitmap);
		grp_res_mgr->grp_res[grp_id].bitmap = NULL;
		grp_res_mgr->grp_res[grp_id].max_entries = 0;
		grp_res_mgr->grp_res[grp_id].base_idx = 0;
		grp_res_mgr->grp_res[grp_id].initialized = false;
	}

	kfree(grp_res_mgr);
}

int xsc_flow_grp_res_alloc_idx(struct xsc_core_device *dev, u8 grp_id, u32 *index)
{
	struct xsc_flow_grp_res_mgr *grp_res_mgr = dev->board_info->flow_grp_res_mgr;
	struct xsc_flow_grp_res *grp_res;
	u32 offset;
	unsigned long flags;
	int ret = 0;

	if (!grp_res_mgr) {
		xsc_core_err(dev, "group res mgr is null");
		return -EINVAL;
	}

	if (grp_id >= FLOW_GRP_RESV_MAX) {
		xsc_core_err(dev, "invalid group id:%d, max support group: %d",
			     grp_id, FLOW_GRP_RESV_MAX);
		return -EINVAL;
	}

	grp_res = &grp_res_mgr->grp_res[grp_id];

	spin_lock_irqsave(&grp_res->lock, flags);
	offset = find_first_zero_bit(grp_res->bitmap, grp_res->max_entries);
	if (offset < grp_res->max_entries) {
		set_bit(offset, grp_res->bitmap);
		*index = grp_res->base_idx + offset;
	} else {
		spin_unlock_irqrestore(&grp_res->lock, flags);
		xsc_core_err(dev, "no resources available for grp:%d, max:%d, used:%d",
			     grp_id, grp_res->max_entries,
			     bitmap_weight(grp_res->bitmap, grp_res->max_entries));
		ret = -ENOMEM;
	}
	spin_unlock_irqrestore(&grp_res->lock, flags);

	xsc_core_info(dev, "[grp_res_idx_alloc] grp_id:%d, index:%d", grp_id, *index);

	return ret;
}

void xsc_flow_grp_res_free_idx(struct xsc_core_device *dev, u8 grp_id, u32 index)
{
	struct xsc_flow_grp_res_mgr *grp_res_mgr = dev->board_info->flow_grp_res_mgr;
	struct xsc_flow_grp_res *grp_res = NULL;
	unsigned long flags;
	u32 offset;

	if (!grp_res_mgr) {
		xsc_core_err(dev, "group res mgr is null");
		return;
	}

	if (grp_id >= FLOW_GRP_RESV_MAX) {
		xsc_core_err(dev, "invalid group id:%d, max support group: %d",
			     grp_id, FLOW_GRP_RESV_MAX);
		return;
	}

	xsc_core_info(dev, "[grp_res_idx_free] grp_id:%d, index:%d", grp_id, index);

	grp_res = &grp_res_mgr->grp_res[grp_id];

	if (index < grp_res->base_idx || index >= (grp_res->base_idx + grp_res->max_entries)) {
		xsc_core_err(dev, "invalid group res index %d", index);
		return;
	}

	offset = index - grp_res->base_idx;

	spin_lock_irqsave(&grp_res->lock, flags);
	clear_bit(offset, grp_res->bitmap);
	spin_unlock_irqrestore(&grp_res->lock, flags);
}
