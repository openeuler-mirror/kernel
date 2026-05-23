/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_fw_update.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <asm/byteorder.h>
#include "ossl_knl.h"
#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hw_cfg.h"
#include "hinic5_chip_info.h"
#include "comm_defs.h"
#include "mpu_inband_cmd.h"
#include "mpu_inband_cmd_defs.h"
#include "hinic5_hw_mt.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_fw_update.h"

/* Reference for below defines: hwsdk/hinic5_cqm/hinic5_cqm_bat_cla.h */
#define SM_BAT_NO_BYPASS_CACHE	0
#define SM_BAT_ENTRY_SIZE_256	0
#define SM_CLA_LVL_0		0
#define SM_CHIP_GPA_HIMASK	0x1ffffff
#define SM_CHIP_GPA_LOMASK	0xffffffff
#define SM_MAX_INDEX_BIT	19

#define SM_CHIP_GPA_HI(gpa)	((u32)(((u64)((gpa)) >> 32) & SM_CHIP_GPA_HIMASK))
#define SM_CHIP_GPA_LW(gpa)	((u32)((u64)(gpa) & SM_CHIP_GPA_LOMASK))

/* Reference: hwsdk/hinic5_cqm/hinic5_cqm_bat_cla.h#tag_hinic5_cqm_bat_entry_standerd */
struct sm_bat_entry_standerd {
	u32 entry_size : 2;
	u32 rsv1 : 6;
	u32 max_number : 22;
	u32 rsv2 : 2;

	u32 cla_gpa_h : 32;

	u32 cla_gpa_l : 32;

	u32 rsv3 : 8;
	u32 z : 5;
	u32 y : 5;
	u32 x : 5;
	u32 rsv24 : 1;
	u32 bypass : 1;
	u32 cla_level : 2;
	u32 rsv5 : 5;
};

/* Reference: pfm_load_api.h */
#define FW_SEC_TYPE_TILE_TEXT	0x4
#define FW_SEC_TYPE_PHY		0x18

#define BAT_L3I_MEM_SIZE	(2U * 1024 * 1024)

#define FW_SEC_HDR_SIZE		0x2100
#define FW_SEC_SIZE_TILE_TEXT	(1U * 1024 * 1024)      /* FW .text section max size: 1MB */
#define FW_SEC_SIZE_PHY		(512U * 1024)           /* FW .phy  section max size: 512KB */

static int bat_l3i_get_entry_offset(struct tag_fw_update_handle *handle,
				    u32 *l3i_entry_offset)
{
	struct hinic5_hwdev *hwdev = handle->hwdev;
	struct hinic5_bat_entry_config l3i_config = { 0 };
	int ret;

	ret = hinic5_bat_get_l3i_entry_config(hwdev, &l3i_config);
	if (unlikely(ret != 0)) {
		sdk_err(hwdev->dev_hdl, "hinic5_bat_get_l3i_entry_config fail.\n");
		return ret;
	}
	if (unlikely(!l3i_config.mapping)) {
		sdk_err(hwdev->dev_hdl, "l3i should not mapping in current function.\n");
		return -EINVAL;
	}
	if (unlikely(l3i_config.bat_entry_size != sizeof(struct sm_bat_entry_standerd))) {
		sdk_err(hwdev->dev_hdl, "l3i entry size mismatch.\n");
		return -EINVAL;
	}

	*l3i_entry_offset = l3i_config.bat_entry_offset;
	return 0;
}

static void bat_l3i_fill_bat_entry_data(struct sm_bat_entry_standerd *data,
					const struct tag_fw_update_bat_l3i_entry *entry,
					const struct tag_fw_update_handle *handle)
{
	u8 z = SM_MAX_INDEX_BIT;

	data->entry_size = SM_BAT_ENTRY_SIZE_256;
	data->max_number = entry->buf_size / FW_UPDATE_CHIP_CACHELINE;
	data->cla_gpa_h = SM_CHIP_GPA_HI(entry->buf_pa);
	data->cla_gpa_l = SM_CHIP_GPA_LW(entry->buf_pa) | handle->gpa_check_enable;
	data->z = z;
	data->y = 0;
	data->x = 0;
	data->bypass = SM_BAT_NO_BYPASS_CACHE;
	data->cla_level = SM_CLA_LVL_0;
}

#ifdef __FW_UPDATE_DEBUG__
#define FUD_PR_BYTE_MAX		16
#define FUD_PR_BYTE_MUL		3
#define FUD_PR_BYTE_BUF_MAX	(FUD_PR_BYTE_MAX * FUD_PR_BYTE_MUL + 1)
static void mpu_set_bat_l3i_entry_print_data(struct tag_fw_update_handle *handle,
					     struct comm_cmd_set_bat_info *cmd)
{
	struct hinic5_hwdev *hwdev = handle->hwdev;
	u8 buf[FUD_PR_BYTE_BUF_MAX];
	u8 *p, *pe;
	u32 i, size;

	size = cmd->data_size;
	if (size > FUD_PR_BYTE_MAX)
		size = FUD_PR_BYTE_MAX;

	p = buf;
	pe = p + FUD_PR_BYTE_BUF_MAX;
	memset(buf, 0, FUD_PR_BYTE_BUF_MAX);

	for (i = 0; i < size; i++) {
		(void)sprintf_s(p, pe - p, "%02X ", cmd->data[i]);
		p += FUD_PR_BYTE_MUL;
	}

	sdk_info(hwdev->dev_hdl, "fw_update: BAT L3I update: data %s\n", buf);
}
#endif

static int mgmt_set_bat_l3i_entry(struct tag_fw_update_handle *handle,
				  u8 smf_id, u16 func_id,
				  struct tag_fw_update_bat_l3i_entry *entry)
{
	struct hinic5_hwdev *hwdev = handle->hwdev;
	struct sm_bat_entry_standerd bat_data = {0};
	struct comm_cmd_set_bat_info buf;
	u16 out_size = sizeof(buf);
	u32 l3i_entry_offset = HINIC5_BAT_MAX;
	int ret;

	ret = bat_l3i_get_entry_offset(handle, &l3i_entry_offset);
	if (unlikely(ret != 0))
		return ret;

	bat_l3i_fill_bat_entry_data(&bat_data, entry, handle);

	memset(&buf, 0, sizeof(buf));
	buf.func_id = func_id;
	buf.smf_id = smf_id;
	buf.bat_offset = l3i_entry_offset;
	buf.data_size = sizeof(bat_data);
	memcpy(buf.data, (void *)&bat_data, sizeof(bat_data));

#ifdef __FW_UPDATE_DEBUG__
	sdk_info(hwdev->dev_hdl,
		 "fw_update: BAT L3I update: smf_id %u, func_id %u, bat_off %u\n",
		 smf_id, func_id, l3i_entry_offset);
	mpu_set_bat_l3i_entry_print_data(handle, &buf);
#endif

	ret = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM,
				      COMM_MGMT_CMD_SET_BAT_INFO,
				      &buf, sizeof(buf), &buf, &out_size,
				      0, HINIC5_CHANNEL_COMM);
	if (ret != 0 || out_size == 0 || buf.head.status != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to set bat info, err: %d, \
			status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			ret, buf.head.status, out_size, HINIC5_CHANNEL_COMM);
		return ret;
	}

	return 0;
}

static int fw_update_init_bat_l3i_entry(struct tag_fw_update_handle *handle,
					struct tag_fw_update_bat_l3i_entry *entry,
					u32 page_order)
{
	struct hinic5_hwdev *hwdev = handle->hwdev;
	struct device *dev = handle->dev;
	u32 buf_size;
	dma_addr_t pa;
	int ret;
	void *va = (void *)(uintptr_t)__get_free_pages(GFP_KERNEL | __GFP_ZERO, page_order);

	if (!va) {
		sdk_err(hwdev->dev_hdl,
			"BAT L3I buffer alloc failed, page_order %u\n",
			page_order);
		return -ENOMEM;
	}

	buf_size = PAGE_SIZE << page_order;
	pa = dma_map_single(dev, va, buf_size, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, pa) != 0) {
		sdk_err(hwdev->dev_hdl,
			"BAT L3I buffer map failed, size 0x%x\n", buf_size);
		ret = -EIO;
		goto pci_map_failed;
	}

	entry->page_order = page_order;
	entry->buf_size = buf_size;
	entry->buf_va = va;
	entry->buf_pa = pa;

	return 0;

pci_map_failed:
	free_pages((uintptr_t)va, page_order);
	return ret;
}

static void fw_update_deinit_bat_l3i_entry(struct tag_fw_update_handle *handle,
					   struct tag_fw_update_bat_l3i_entry *entry)
{
	struct device *dev = handle->dev;

	if (entry->buf_pa != 0) {
		dma_unmap_single(dev, entry->buf_pa, entry->buf_size,
				 DMA_BIDIRECTIONAL);
		entry->buf_pa = 0;
	}

	if (entry->buf_va != 0) {
		free_pages((uintptr_t)entry->buf_va, entry->page_order);
		entry->buf_va = 0;
	}

	memset(entry, 0, sizeof(*entry));
}

static int fw_update_init_bat_l3i(struct tag_fw_update_handle *handle)
{
	struct hinic5_hwdev *hwdev = handle->hwdev;
	struct hinic5_func_attr *func_attr = &hwdev->hwif->attr;
	struct tag_fw_update_bat_l3i_entry *smf_entry = NULL;
	u16 func_id = func_attr->func_global_idx;
	u32 per_smf_size;
	int page_order;
	u8 smf_id;
	int smf_idx, smf_num;
	int ret = 0;

	if (handle->smf_enabled_num == 0) {
		sdk_err(hwdev->dev_hdl, "smf_enabled_num is zero\n");
		return -EINVAL;
	}

	per_smf_size = BAT_L3I_MEM_SIZE / handle->smf_enabled_num;
	page_order = get_order(per_smf_size);
	if (page_order < 0) {
		sdk_err(hwdev->dev_hdl, "get_order fail, ret %d\n", page_order);
		return -EINVAL;
	}

	smf_num = (int)handle->smf_enabled_num;

	sdk_info(hwdev->dev_hdl, "fw_update: smf num %d, per size 0x%X, page order %d\n",
		 smf_num, per_smf_size, page_order);

	for (smf_idx = 0; smf_idx < smf_num; smf_idx++) {
		smf_id = handle->smf_enabled[smf_idx];
		smf_entry = &handle->bat_l3i_entries[smf_id];
		ret = fw_update_init_bat_l3i_entry(handle, smf_entry, (u32)page_order);
		if (ret != 0)
			goto entry_init_error;

#ifdef __FW_UPDATE_DEBUG__
		sdk_info(hwdev->dev_hdl,
			 "fw_update: BAT L3I init: smf_id %u, va 0x%lx, pa 0x%lx, size 0x%x\n",
			 smf_id, (uintptr_t)smf_entry->buf_va,
			 (uintptr_t)smf_entry->buf_pa, smf_entry->buf_size);
#endif

		ret = mgmt_set_bat_l3i_entry(handle, smf_id, func_id, smf_entry);
		if (ret != 0)
			goto entry_init_error;
	}

	return 0;

entry_init_error:
	while (smf_idx >= 0) {
		smf_id = handle->smf_enabled[smf_idx];
		smf_entry = &handle->bat_l3i_entries[smf_id];
		fw_update_deinit_bat_l3i_entry(handle, smf_entry);
		smf_idx--;
	}

	return ret;
}

static void fw_update_deinit_bat_l3i(struct tag_fw_update_handle *handle)
{
	struct tag_fw_update_bat_l3i_entry *smf_entry = NULL;
	u32 smf_id, i;

	for (i = 0; i < handle->smf_enabled_num; i++) {
		smf_id = handle->smf_enabled[i];
		smf_entry = &handle->bat_l3i_entries[smf_id];
		fw_update_deinit_bat_l3i_entry(handle, smf_entry);
	}
}

static void fw_update_capability_init_smf(struct tag_fw_update_handle *handle)
{
	struct hinic5_hwdev *hwdev = handle->hwdev;
	struct service_cap *svc_cap = &hwdev->cfg_mgmt->svc_cap;
	const u32 smf_max_num = svc_cap->smf_max_num;
	const u32 smf_pg = svc_cap->smf_pg;
	u32 smf_id, i;

	i = 0;
	for (smf_id = 0; smf_id < smf_max_num; smf_id++) {
		if ((smf_pg & (1U << smf_id)) != 0) {
			handle->smf_enabled[i] = (u8)smf_id;
			i++;
		}
	}
	handle->smf_enabled_num = i;
}

static void fw_update_capability_init(struct tag_fw_update_handle *handle)
{
	struct hinic5_hwdev *hwdev = handle->hwdev;
	struct service_cap *svc_cap = &hwdev->cfg_mgmt->svc_cap;

	fw_update_capability_init_smf(handle);

	handle->gpa_check_enable = true;
	if (svc_cap->test_mode != 0)
		handle->gpa_check_enable = svc_cap->test_gpa_check_enable;
}

static int fw_update_alloc(struct hinic5_hwdev *hwdev)
{
	struct tag_fw_update_handle *handle = NULL;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (unlikely(!handle)) {
		sdk_err(hwdev->dev_hdl, "fw_update_hdl alloc fail.\n");
		return -ENOMEM;
	}

	handle->hwdev = hwdev;
	handle->dev = hwdev->dev_hdl;
	hwdev->fw_update_hdl = (void *)handle;

	return 0;
}

int hinic5_fw_update_init(void *hwdev_hdl)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)hwdev_hdl;
	struct tag_fw_update_handle *handle = NULL;
	int ret;

	if (unlikely(!hwdev_hdl)) {
		pr_err("hwdev_hdl is null.\n");
		return -EINVAL;
	}

	if (!hinic5_fw_update_ddr_enabled(hwdev_hdl))
		return 0;

	ret = fw_update_alloc(hwdev);
	if (unlikely(ret != 0))
		return ret;
	handle = (struct tag_fw_update_handle *)hwdev->fw_update_hdl;

	fw_update_capability_init(handle);

	ret = fw_update_init_bat_l3i(handle);
	if (ret != 0) {
		sdk_err(hwdev->dev_hdl, "init resources failed %d\n", ret);
		goto init_res_err;
	}

	return 0;

init_res_err:
	kfree(hwdev->fw_update_hdl);
	hwdev->fw_update_hdl = NULL;
	return ret;
}

void hinic5_fw_update_deinit(void *hwdev_hdl)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)hwdev_hdl;
	struct tag_fw_update_handle *handle = NULL;

	if (likely(!hwdev || !hwdev->fw_update_hdl))
		return;

	handle = (struct tag_fw_update_handle *)hwdev->fw_update_hdl;

	fw_update_deinit_bat_l3i(handle);

	kfree(hwdev->fw_update_hdl);
	hwdev->fw_update_hdl = NULL;
}

bool hinic5_fw_update_ddr_enabled(void *hwdev_hdl)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)hwdev_hdl;

	if (unlikely(!hwdev))
		return false;

	return COMM_SUPPORT_UFHD_FLEX_SEG(hwdev) || COMM_SUPPORT_UFHD(hwdev);
}

static struct fw_update_context *hinic5_fw_update_create_context(struct hinic5_hwdev *hwdev)
{
	struct fw_update_context *context;

	context = vzalloc(sizeof(*context));

	if (!context)
		return NULL;

	context->sec_text.data_cap = get_device_capablity(hwdev)->fw_update_cap.fw_tile_text_size;
	if (context->sec_text.data_cap == 0) {
		/* for compatibility */
		context->sec_text.data_cap = FW_SEC_SIZE_TILE_TEXT;
	}
	context->sec_text.data = vzalloc(context->sec_text.data_cap);
	if (!context->sec_text.data)
		goto alloc_sec_text_data_failed;

	context->sec_phy.data_cap = FW_SEC_SIZE_PHY;
	context->sec_phy.data = vzalloc(FW_SEC_SIZE_PHY);
	if (!context->sec_phy.data)
		goto alloc_sec_phy_data_failed;

	return context;

alloc_sec_phy_data_failed:
	vfree(context->sec_text.data);
alloc_sec_text_data_failed:
	vfree(context);
	return NULL;
}

void hinic5_fw_update_free_context(void *update_context_hdl)
{
	struct fw_update_context *context = (struct fw_update_context *)update_context_hdl;

	if (!context)
		return;

	if (context->sec_phy.data) {
		vfree(context->sec_phy.data);
		context->sec_phy.data = NULL;
	}

	if (context->sec_text.data) {
		vfree(context->sec_text.data);
		context->sec_text.data = NULL;
	}

	vfree(context);
}

static int fw_update_context_get(struct hinic5_hwdev *hwdev,
				 struct fw_update_context **context)
{
	struct card_node *chip_node = hwdev->chip_node;
	spinlock_t *lock = NULL;
	int ret;

	if (unlikely(!chip_node)) {
		sdk_warn(hwdev->dev_hdl, "fw_update: chip_node not init, try later.\n");
		return -EAGAIN;
	}

	lock = &chip_node->fw_update_context_lock;

	ret = spin_trylock(lock);
	if (unlikely(ret == 0)) {
		sdk_warn(hwdev->dev_hdl, "fw_update: not allowed to concurrent update, ret %d, abort!",
			 ret);
		return -EBUSY;
	}

	if (unlikely(!chip_node->fw_update_context)) {
		chip_node->fw_update_context = hinic5_fw_update_create_context(hwdev);
		if (!chip_node->fw_update_context) {
			pr_err("fw_update: create context failed.\n");
			spin_unlock(lock);
			return -ENOMEM;
		}
	}
	*context = chip_node->fw_update_context;

	return 0;
}

static void fw_update_context_put(struct hinic5_hwdev *hwdev)
{
	struct card_node *chip_node = hwdev->chip_node;

	spin_unlock(&chip_node->fw_update_context_lock);
}

static void fw_update_context_reset(struct fw_update_context *context)
{
	context->update_started = 0;

	context->sec_text.data_size = 0;
	context->sec_text.data_off = 0;
	context->sec_text.verified = 0;

	context->sec_phy.data_size = 0;
	context->sec_phy.data_off = 0;
	context->sec_phy.verified = 0;
}

static int check_fw_section_update(struct fw_section_data *section,
				   struct fw_update_msg_st *update)
{
	u32 data_len = (u32)update->ctl_info.Fragment_Len;

	/* handle text section first transmission */
	if (update->ctl_info.SF == 1) {
		if (section->data_off != 0 || section->data_size != 0) {
			pr_err("fw_update: broken fw section, last off %u, size %u\n",
			       section->data_off, section->data_size);
			return -EINVAL;
		}
		if (update->setion_total_len > section->data_cap) {
			pr_err("fw_update: fw section size too large, type 0x%x, size 0x%x, cap 0x%x\n",
			       update->section_info.FW_section_type,
			       update->setion_total_len, section->data_cap);
			return -EFBIG;
		}

		memset(section->data, 0, section->data_cap);
		section->data_size = update->setion_total_len;
		section->verified = 0;
	}

	if (section->data_off != update->section_offset) {
		pr_err("fw_update: unmatched offset, data_off %u, in_off %u\n",
		       section->data_off, update->section_offset);
		return -EINVAL;
	}

	if (section->data_size - section->data_off < data_len)
		return -EINVAL;

	if (update->ctl_info.SL == 1) {
		if (section->data_off + data_len != section->data_size) {
			pr_err("fw_update: unmatched length\n");
			return -EINVAL;
		}
	}

	return 0;
}

static inline int mgmt_cmd_update_fw_op(void *hwdev, struct hinic5_mt_cmd_info *cmd_info)
{
	return hinic5_msg_to_mgmt_sync(hwdev, cmd_info->mod, cmd_info->cmd,
				       cmd_info->buf_in, cmd_info->in_size, cmd_info->buf_out,
				       cmd_info->out_size, cmd_info->timeout,
				       HINIC5_CHANNEL_DEFAULT);
}

static int handle_fw_section_update(void *hwdev, struct hinic5_mt_cmd_info *cmd_info,
				    struct fw_section_data *section)
{
	struct fw_update_msg_st *update = (struct fw_update_msg_st *)(cmd_info->buf_in);
	struct mgmt_msg_head *result_head = NULL;
	u32 data_len;
	int ret = 0;

	ret = check_fw_section_update(section, update);
	if (ret != 0)
		return ret;

	ret = mgmt_cmd_update_fw_op(hwdev, cmd_info);
	if (ret != 0) {
		pr_err("fw_update failed, ret %d\n", ret);
		return ret;
	}

	if (*cmd_info->out_size < sizeof(struct mgmt_msg_head)) {
		pr_err("fw_update: incompatible protocol, out_size %u\n", *cmd_info->out_size);
		return -EINVAL;
	}
	result_head = (struct mgmt_msg_head *)(cmd_info->buf_out);

	/* MPU will not return verify result if Repeat-Msg requested
	 * so we skip updating section data
	 */
	if (result_head->status == MPU_FW_UPDATE_FLUSH_FLASH_REPEAT)
		return 0;

	if (update->ctl_info.SL == 1) {
		/* check fw bin verification result */
		if (result_head->status == MPU_FW_UPDATE_FW_VERIFY_ERR) {
			pr_err("fw_update: invalid update file\n");
			return MPU_FW_UPDATE_FW_VERIFY_ERR;
		}
		section->verified = 1;
	}

	data_len = (u32)update->ctl_info.Fragment_Len;

	memcpy(section->data + section->data_off, update->data, data_len);
	section->data_off += data_len;

	if (update->ctl_info.SL == 1) {
		pr_info("fw_update: tile text section upload success. section type 0x%x, size 0x%x\n",
			update->section_info.FW_section_type, section->data_size);
	}

	return 0;
}

static int handle_cmd_update(void *hwdev, struct hinic5_mt_cmd_info *cmd_info,
			     struct fw_update_context *context)
{
	struct fw_update_msg_st *update = (struct fw_update_msg_st *)(cmd_info->buf_in);
	struct fw_section_data *section = NULL;
	int ret = 0;

	if (cmd_info->in_size < sizeof(struct fw_update_msg_st)) {
		pr_err("fw_update: invalid argument size\n");
		ret = -EINVAL;
		goto reset_update_context;
	}

#ifdef __FW_UPDATE_DEBUG__
	pr_info("fw_update: sec_type %u, off 0x%x, len %u\n",
		update->section_info.FW_section_type,
		update->section_offset,
		(u32)update->ctl_info.Fragment_Len);
#endif

	/* handle new update session */
	if (update->total_len != 0) {
		if (context->update_started != 0 &&
		    (context->sec_text.data_off != context->sec_text.data_size ||
		     context->sec_phy.data_off != context->sec_phy.data_size))
			pr_warn("fw_update: previous update may not completed, .text off 0x%x size 0x%x, .phy off 0x%x size 0x%x\n",
				context->sec_text.data_off, context->sec_text.data_size,
				context->sec_phy.data_off, context->sec_phy.data_size);
		fw_update_context_reset(context);
		context->update_started = 1;
	}

	if (context->update_started != 1) {
		pr_err("fw_update: incompatible protocol\n");
		return -EINVAL;
	}

	if (update->section_info.FW_section_type == FW_SEC_TYPE_TILE_TEXT) {
		section = &context->sec_text;
		ret = handle_fw_section_update(hwdev, cmd_info, section);
	} else if (update->section_info.FW_section_type == FW_SEC_TYPE_PHY) {
		section = &context->sec_phy;
		ret = handle_fw_section_update(hwdev, cmd_info, section);
	} else {
		ret = mgmt_cmd_update_fw_op(hwdev, cmd_info);
	}

	if (ret == 0)
		return ret;

reset_update_context:
	fw_update_context_reset(context);
	return ret;
}

int hinic5_fw_update_cmd_update(void *hwdev_hdl, struct hinic5_mt_cmd_info *cmd_info)
{
	struct fw_update_context *context = NULL;
	int ret = 0;

	/* use extended upload procedure if FW hot update via L3I
	 * is enabled, otherwise use normal way
	 */
	if (!hinic5_fw_update_ddr_enabled(hwdev_hdl))
		return mgmt_cmd_update_fw_op(hwdev_hdl, cmd_info);

	ret = fw_update_context_get((struct hinic5_hwdev *)hwdev_hdl, &context);
	if (ret != 0)
		return ret;

	ret = handle_cmd_update(hwdev_hdl, cmd_info, context);

	fw_update_context_put((struct hinic5_hwdev *)hwdev_hdl);

	/* this type of error is considered a successful result of ioctl() */
	if (ret == MPU_FW_UPDATE_FW_VERIFY_ERR)
		ret = 0;

	return ret;
}

/**
 * @brief hinic5_bat_l3i_store - store data into L3I buffer
 * @param hwdev: device pointer to hwdev
 * @param data: pointer to data
 * @param data_size: data size, must aligned to cache line
 * @retval zero: success
 * @retval non-zero: failure
 */
STATIC int hinic5_bat_l3i_store(const struct hinic5_hwdev *hwdev, const u8 *data, u32 data_size)
{
	struct tag_fw_update_handle *handle = (struct tag_fw_update_handle *)hwdev->fw_update_hdl;
	struct service_cap *svc_cap = &hwdev->cfg_mgmt->svc_cap;
	struct tag_fw_update_bat_l3i_entry *smf_entry = NULL;
	const u32 cache_line = FW_UPDATE_CHIP_CACHELINE;
	u32 smf_id, smf_enabled_num;
	u32 scale, block_size;
	u32 i, block_num;
	u32 buf_off;
	u8 *buf = NULL, *buf_end = NULL;
	u8 *va = NULL, *va_end = NULL;

	if (unlikely(!data || data_size == 0 ||
		     (data_size % cache_line != 0) ||
		     data_size > FW_UPDATE_DDR_MAX))
		return -EINVAL;

	smf_enabled_num = handle->smf_enabled_num;
	scale = svc_cap->smf_max_num / smf_enabled_num;
	block_size = cache_line * scale;
	block_num = (data_size + block_size - 1) / block_size;

	for (i = 0; i < block_num; i++) {
		smf_id = handle->smf_enabled[i % smf_enabled_num];
		smf_entry = &handle->bat_l3i_entries[smf_id];
		buf = (u8 *)smf_entry->buf_va;
		buf_end = buf + smf_entry->buf_size;

		buf_off = i / smf_enabled_num * block_size;
		va = (u8 *)smf_entry->buf_va + buf_off;
		va_end = va + block_size;
		if (va_end > buf_end)
			va_end = buf_end;

		while (va < va_end) {
			*(u32 *)va = cpu_to_be32(*(u32 *)data);
			va += sizeof(u32);
			data += sizeof(u32);
		}
	}

	return 0;
}

/**
 * @brief hinic5_bat_l3i_clean - clean data in L3I buffer
 * @param hwdev: device pointer to hwdev
 */
STATIC void hinic5_bat_l3i_clean(const struct hinic5_hwdev *hwdev)
{
	struct tag_fw_update_handle *handle = (struct tag_fw_update_handle *)hwdev->fw_update_hdl;
	struct tag_fw_update_bat_l3i_entry *smf_entry = NULL;
	u32 i, smf_id;

	if (!handle)
		return;

	for (i = 0; i < handle->smf_enabled_num; i++) {
		smf_id = handle->smf_enabled[i];
		smf_entry = &handle->bat_l3i_entries[smf_id];
		memset(smf_entry->buf_va, 0, smf_entry->buf_size);
	}
}

static inline bool fw_section_data_valid(struct hinic5_hwdev *hwdev,
					 const struct fw_section_data *section)
{
	u32 fw_img_hdr_size = get_device_capablity(hwdev)->fw_update_cap.fw_img_hdr_size;
	/* for compatibility */
	if (fw_img_hdr_size == 0)
		fw_img_hdr_size = FW_SEC_HDR_SIZE;

	return section->verified == 1 &&
	       section->data_off == section->data_size &&
	       section->data_size >= fw_img_hdr_size;
}

static int hot_active_fw_check(struct hinic5_hwdev *hwdev,
			       struct fw_update_context *context)
{
	struct fw_section_data *sec_text = &context->sec_text;
	struct fw_section_data *sec_phy = &context->sec_phy;
	const bool has_phy_section = sec_phy->data_size != 0;

	if (!fw_section_data_valid(hwdev, sec_text)) {
		pr_err("fw_update: invalid tile text section, off %u, size %u, verify %u\n",
		       sec_text->data_off, sec_text->data_size, sec_text->verified);
		return -EINVAL;
	}

	if (has_phy_section && !fw_section_data_valid(hwdev, sec_phy)) {
		pr_err("fw_update: invalid phy section, off %u, size %u, verify %u\n",
		       sec_phy->data_off, sec_phy->data_size, sec_phy->verified);
		return -EINVAL;
	}

	return 0;
}

static int hot_active_fw_prepare(struct hinic5_hwdev *hwdev,
				 struct fw_update_context *context)
{
	struct fw_section_data *sec_text = &context->sec_text;
	struct fw_section_data *sec_phy = &context->sec_phy;
	const bool has_phy_section = sec_phy->data_size != 0;
	const u32 cache_line = FW_UPDATE_CHIP_CACHELINE;
	u32 data_len, data_len_aligned, data_off, fw_img_hdr_size;
	u8 *data = NULL;
	int ret = 0;

	fw_img_hdr_size = get_device_capablity(hwdev)->fw_update_cap.fw_img_hdr_size;
	if (fw_img_hdr_size == 0) {
		/* for compatibility */
		fw_img_hdr_size = FW_SEC_HDR_SIZE;
	}

	data_len = sec_text->data_size - fw_img_hdr_size;
	if (has_phy_section)
		data_len += sec_phy->data_size - fw_img_hdr_size;

	if (data_len % cache_line != 0) {
		data_len_aligned = (data_len + cache_line - 1) / cache_line * cache_line;
		if (data_len_aligned > FW_UPDATE_DDR_MAX) {
			sdk_err(hwdev->dev_hdl, "fw_update: update data too large, size 0x%x, aligned size 0x%x\n",
				data_len, data_len_aligned);
			return -EINVAL;
		}
	} else {
		data_len_aligned = data_len;
	}

	sdk_info(hwdev->dev_hdl, "fw_update: update data size 0x%x, aligned size 0x%x\n",
		 data_len, data_len_aligned);

	data = vzalloc(data_len_aligned);
	if (!data) {
		return -ENOMEM;
	}

	memcpy(data,
	       sec_text->data + fw_img_hdr_size,
	       sec_text->data_size - fw_img_hdr_size);

	if (has_phy_section && sec_phy->data_size > fw_img_hdr_size) {
		data_off = sec_text->data_size - fw_img_hdr_size;
		memcpy(data + data_off,
		       sec_phy->data + fw_img_hdr_size,
		       sec_phy->data_size - fw_img_hdr_size);
	}

	ret = hinic5_bat_l3i_store(hwdev, data, data_len_aligned);
	if (ret != 0)
		sdk_err(hwdev->dev_hdl, "fw_update: hinic5_bat_l3i_store fail, data len %u\n",
			data_len_aligned);

	return ret;
}

int hinic5_fw_update_cmd_hot_active(void *hwdev_hdl, struct hinic5_mt_cmd_info *cmd_info)
{
	struct hinic5_hwdev *hwdev = (struct hinic5_hwdev *)hwdev_hdl;
	struct cmd_hot_active_fw *hot_active = (struct cmd_hot_active_fw *)(cmd_info->buf_in);
	struct fw_update_context *context = NULL;
	int ret = 0;

	if (cmd_info->in_size < sizeof(struct cmd_hot_active_fw)) {
		pr_err("fw_update: invalid argument size %u\n", cmd_info->in_size);
		return -EINVAL;
	}

	if (hot_active->type != FW_HOW_ACTIVE_TYPE_NPU)
		return mgmt_cmd_update_fw_op(hwdev, cmd_info);

	if (!hinic5_fw_update_ddr_enabled(hwdev_hdl)) {
		sdk_info(hwdev->dev_hdl, "fw_update: this function does not support hot update via DDR.\n");
		return mgmt_cmd_update_fw_op(hwdev, cmd_info);
	}

	if (unlikely(!hwdev->fw_update_hdl)) {
		sdk_err(hwdev->dev_hdl, "fw_update: DDR not ready.\n");
		return -EINVAL;
	}

	ret = fw_update_context_get(hwdev, &context);
	if (ret != 0)
		return ret;

	ret = hot_active_fw_check(hwdev, context);
	if (ret != 0)
		goto fail;

	ret = hot_active_fw_prepare(hwdev, context);
	if (ret != 0)
		goto fail;

	ret = mgmt_cmd_update_fw_op(hwdev, cmd_info);
	if (ret == 0)
		goto success;

	sdk_err(hwdev->dev_hdl, "fw update hot active failed, ret %d", ret);

fail:
	fw_update_context_reset(context);

success:
#ifndef __FW_UPDATE_DEBUG__
	hinic5_bat_l3i_clean(hwdev);
#endif
	fw_update_context_put(hwdev);
	return ret;
}
