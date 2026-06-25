/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_bat_cla.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/gfp.h>

#ifdef __LINUX__
#include <linux/mmzone.h>
#endif

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_hw_comm.h"
#include "hinic5_hw_cfg.h"
#include "hinic5_hinic5_vram_api.h"
#include "hinic5_typedef_inner.h"

#include "hinic5_cqm_object.h"
#include "hinic5_cqm_bitmap_table.h"
#include "hinic5_cqm_cmd.h"
#include "hinic5_cqm_object_intern.h"
#include "hinic5_cqm_main.h"
#include "hinic5_cqm_bat_cla.h"

#include "comm_defs.h"
#include "hinic5_cqm_npu_cmd.h"
#include "hinic5_cqm_npu_cmd_defs.h"
#include "hinic5_cqm_cmdq.h"

#include "hinic5_vram_common.h"

static unsigned char hinic5_cqm_ver = 8;
module_param(hinic5_cqm_ver, byte, 0444);
MODULE_PARM_DESC(hinic5_cqm_ver, "for hinic5_cqm version control (default=8)");

static bool hinic5_cqm_cla_hugepage_hint;
module_param(hinic5_cqm_cla_hugepage_hint, bool, 0444);
MODULE_PARM_DESC(hinic5_cqm_cla_hugepage_hint,
		 "Hint for hugepage alloc to improve TLB locality (default false). " \
		 "This option only impacts QPC and Timer Spoke Lists.");

#ifdef __HINIC5_CQM_DEBUG__
bool hinic5_cqm_verbose;
module_param(hinic5_cqm_verbose, bool, 0644);
#endif

bool secure_mem_en = true;

static inline u32 get_cacheline_size(u32 entry_type)
{
	/* The cacheline of the timer is changed to 512. */
	if (entry_type == HINIC5_CQM_BAT_ENTRY_T_TIMER && hinic5_cqm_ver == 0x8)
		return HINIC5_CQM_CHIP_TIMER_CACHELINE;

	return HINIC5_CQM_CHIP_CACHELINE;
}

static void hinic5_cqm_bat_fill_cla_common_gpa(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					struct tag_hinic5_cqm_cla_table *cla_table,
					struct tag_hinic5_cqm_bat_entry_standerd *bat_entry_standerd)
{
	u8 gpa_check_enable = hinic5_cqm_handle->func_capability.gpa_check_enable;
	struct hinic5_func_attr *func_attr = NULL;
	struct tag_hinic5_cqm_bat_entry_vf2pf gpa = {0};
	u32 cla_gpa_h = 0;
	dma_addr_t pa;

	if (cla_table->cla_lvl == HINIC5_CQM_CLA_LVL_0)
		pa = cla_table->cla_z_buf.buf_list[0].pa;
	else if (cla_table->cla_lvl == HINIC5_CQM_CLA_LVL_1)
		pa = cla_table->cla_y_buf.buf_list[0].pa;
	else
		pa = cla_table->cla_x_buf.buf_list[0].pa;

	gpa.cla_gpa_h = HINIC5_CQM_ADDR_HI(pa) & HINIC5_CQM_CHIP_GPA_HIMASK;
	gpa.acs_spu_en = hinic5_cqm_get_acs_spu_en(hinic5_cqm_handle);

	/* In fake mode, fake_vf_en in the GPA address of the BAT
	 * must be set to 1.
	 */
	if (HINIC5_CQM_IS_FAKE_CHILD_AGENT(hinic5_cqm_handle)) {
		gpa.fake_vf_en = 1;
		func_attr = &hinic5_cqm_handle->parent_hinic5_cqm_handle->func_attribute;
		gpa.pf_id = func_attr->func_global_idx;
	} else {
		gpa.fake_vf_en = 0;
	}

	memcpy(&cla_gpa_h, &gpa, sizeof(u32));
	bat_entry_standerd->cla_gpa_h = cla_gpa_h;

	/* GPA is valid when gpa[0] = 1.
	 * HINIC5_CQM_BAT_ENTRY_T_REORDER does not support GPA validity check.
	 */
	if (cla_table->type == HINIC5_CQM_BAT_ENTRY_T_REORDER)
		bat_entry_standerd->cla_gpa_l = HINIC5_CQM_ADDR_LW(pa);
	else
		bat_entry_standerd->cla_gpa_l = HINIC5_CQM_ADDR_LW(pa) |
						gpa_check_enable;

	hinic5_cqm_info(hinic5_cqm_handle->dev, "Bat fill: cla_type %u, pa 0x%llx, gpa 0x%x-0x%x, level %u\n",
		 cla_table->type, pa, bat_entry_standerd->cla_gpa_h, bat_entry_standerd->cla_gpa_l,
		 bat_entry_standerd->cla_level);
}

static void hinic5_cqm_bat_fill_cla_common(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				    struct tag_hinic5_cqm_cla_table *cla_table,
				    u8 *entry_base_addr)
{
	struct tag_hinic5_cqm_bat_entry_standerd *bat_entry_standerd = NULL;
	u32 cache_line = get_cacheline_size(cla_table->type);

	if (cla_table->obj_num == 0) {
		hinic5_cqm_dbg(hinic5_cqm_handle->dev,
			"Bat fill: cla_type %u, obj_num=0, don't init bat entry\n",
			cla_table->type);
		return;
	}

	bat_entry_standerd = (struct tag_hinic5_cqm_bat_entry_standerd *)entry_base_addr;

	/* The QPC value is 256/512/1024 and the timer value is 512.
	 * The other cacheline value is 256B.
	 * The conversion operation is performed inside the chip.
	 */
	if (cla_table->obj_size > cache_line) {
		if (cla_table->obj_size == HINIC5_CQM_OBJECT_512)
			bat_entry_standerd->entry_size = HINIC5_CQM_BAT_ENTRY_SIZE_512;
		else
			bat_entry_standerd->entry_size =
			    HINIC5_CQM_BAT_ENTRY_SIZE_1024;
		bat_entry_standerd->max_number = cla_table->max_buffer_size /
						 cla_table->obj_size;
	} else {
		if (cache_line == HINIC5_CQM_CHIP_CACHELINE) {
			bat_entry_standerd->entry_size = HINIC5_CQM_BAT_ENTRY_SIZE_256;
			bat_entry_standerd->max_number =
			    cla_table->max_buffer_size / cache_line;
		} else {
			bat_entry_standerd->entry_size = HINIC5_CQM_BAT_ENTRY_SIZE_512;
			bat_entry_standerd->max_number =
			    cla_table->max_buffer_size / cache_line;
		}
	}

	bat_entry_standerd->max_number = bat_entry_standerd->max_number - 1;

	bat_entry_standerd->bypass = HINIC5_CQM_BAT_NO_BYPASS_CACHE;
	bat_entry_standerd->z = cla_table->cacheline_z;
	bat_entry_standerd->y = cla_table->cacheline_y;
	bat_entry_standerd->x = cla_table->cacheline_x;
	bat_entry_standerd->cla_level = cla_table->cla_lvl;

	hinic5_cqm_bat_fill_cla_common_gpa(hinic5_cqm_handle, cla_table, bat_entry_standerd);
}

static void hinic5_cqm_bat_fill_cla_cfg(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				 struct tag_hinic5_cqm_cla_table *cla_table,
				 u8 **entry_base_addr)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_bat_entry_cfg *bat_entry_cfg = NULL;

	bat_entry_cfg = (struct tag_hinic5_cqm_bat_entry_cfg *)(*entry_base_addr);
	bat_entry_cfg->cur_conn_cache = 0;
	bat_entry_cfg->max_conn_cache =
	    func_cap->flow_table_based_conn_cache_number;
	bat_entry_cfg->cur_conn_num_h_4 = 0;
	bat_entry_cfg->cur_conn_num_l_16 = 0;
	bat_entry_cfg->max_conn_num = func_cap->flow_table_based_conn_number;

	/* Aligns with 64 buckets and shifts rightward by 6 bits.
	 * The maximum value of this field is 16 bits. A maximum of 4M buckets
	 * can be supported. The value is subtracted by 1. It is used for &hash
	 * value.
	 */
	if ((func_cap->hash_number >> HINIC5_CQM_HASH_NUMBER_UNIT) != 0) {
		bat_entry_cfg->bucket_num = ((func_cap->hash_number >>
					      HINIC5_CQM_HASH_NUMBER_UNIT) - 1);
	}
	if (func_cap->bloomfilter_length != 0) {
		bat_entry_cfg->bloom_filter_len = func_cap->bloomfilter_length -
						  1;
		bat_entry_cfg->bloom_filter_addr = func_cap->bloomfilter_addr;
	}

	(*entry_base_addr) += sizeof(struct tag_hinic5_cqm_bat_entry_cfg);
}

static void hinic5_cqm_bat_fill_cla_other(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				   struct tag_hinic5_cqm_cla_table *cla_table,
				   u8 **entry_base_addr)
{
	hinic5_cqm_bat_fill_cla_common(hinic5_cqm_handle, cla_table, *entry_base_addr);

	(*entry_base_addr) += sizeof(struct tag_hinic5_cqm_bat_entry_standerd);
}

static void hinic5_cqm_bat_fill_cla_taskmap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				     const struct tag_hinic5_cqm_cla_table *cla_table,
				     u8 **entry_base_addr)
{
	struct tag_hinic5_cqm_bat_entry_taskmap *bat_entry_taskmap = NULL;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	int i;

	if (hinic5_cqm_handle->func_capability.taskmap_number != 0) {
		bat_entry_taskmap =
		    (struct tag_hinic5_cqm_bat_entry_taskmap *)(*entry_base_addr);
		for (i = 0; i < HINIC5_CQM_BAT_ENTRY_TASKMAP_NUM; i++) {
			bat_entry_taskmap->addr[i].gpa_h =
			    (u32)(cla_table->cla_z_buf.buf_list[i].pa >>
				  HINIC5_CQM_CHIP_GPA_HSHIFT);
			bat_entry_taskmap->addr[i].gpa_l =
			    (u32)(cla_table->cla_z_buf.buf_list[i].pa &
				  HINIC5_CQM_CHIP_GPA_LOMASK);
			hinic5_cqm_info(handle->dev_hdl,
				 "Cla alloc: taskmap bat entry: 0x%x 0x%x\n",
				 bat_entry_taskmap->addr[i].gpa_h,
				 bat_entry_taskmap->addr[i].gpa_l);
		}
	}

	(*entry_base_addr) += sizeof(struct tag_hinic5_cqm_bat_entry_taskmap);
}

static void hinic5_cqm_bat_fill_cla_timer(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				   struct tag_hinic5_cqm_cla_table *cla_table,
				   u8 **entry_base_addr)
{
	/* Only the PPF allocates timer resources. */
	if (!HINIC5_CQM_IS_PPF(hinic5_cqm_handle)) {
		(*entry_base_addr) += HINIC5_CQM_BAT_ENTRY_SIZE;
	} else {
		hinic5_cqm_bat_fill_cla_common(hinic5_cqm_handle, cla_table,
					*entry_base_addr);

		(*entry_base_addr) += sizeof(struct tag_hinic5_cqm_bat_entry_standerd);
	}
}

static void hinic5_cqm_bat_fill_cla_invalid(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				     struct tag_hinic5_cqm_cla_table *cla_table,
				     u8 **entry_base_addr)
{
	(*entry_base_addr) += HINIC5_CQM_BAT_ENTRY_SIZE;
}

/**
 * Prototype    : hinic5_cqm_bat_fill_cla
 * Description  : Fill the base address of the CLA table into the BAT table.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/15
 *   Modification : Created function
 */
static void hinic5_cqm_bat_fill_cla(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_hwdev *hwdev = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	u32 entry_type = HINIC5_CQM_BAT_ENTRY_T_INVALID;
	u8 *entry_base_addr = NULL;
	u32 i = 0;

	/* Fills each item in the BAT table according to the BAT format. */
	entry_base_addr = bat_table->bat;
	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		hinic5_cqm_dbg_on(hinic5_cqm_verbose, hinic5_cqm_handle->dev,
			   "entry_base_addr = %p\n", entry_base_addr);
		entry_type = bat_table->bat_entry_type[i];
		cla_table = &bat_table->entry[i];

		if (entry_type == HINIC5_CQM_BAT_ENTRY_T_CFG) {
			hinic5_cqm_bat_fill_cla_cfg(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else if (entry_type == HINIC5_CQM_BAT_ENTRY_T_TASKMAP) {
			hinic5_cqm_bat_fill_cla_taskmap(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else if (entry_type == HINIC5_CQM_BAT_ENTRY_T_INVALID) {
			hinic5_cqm_bat_fill_cla_invalid(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else if (entry_type == HINIC5_CQM_BAT_ENTRY_T_TIMER) {
			if (HINIC5_CQM_IS_PPF(hinic5_cqm_handle) && HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle)) {
				/* The fill of Timer Entry is delayed,
				 * because it needs to be based on a specific SMF. */
				entry_base_addr += sizeof(struct tag_hinic5_cqm_bat_entry_standerd);
				continue;
			}

			hinic5_cqm_bat_fill_cla_timer(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else if (entry_type == HINIC5_CQM_BAT_ENTRY_T_HASH) {
			if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle)) {
				/* The fill of Hash Entry is delayed,
				 * because it needs to be based on a specific SMF. */
				entry_base_addr += sizeof(struct tag_hinic5_cqm_bat_entry_standerd);
				continue;
			}

			hinic5_cqm_bat_fill_cla_other(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else if (entry_type == HINIC5_CQM_BAT_ENTRY_T_XID2CID) {
			if (COMM_SUPPORT_VIRTIO_FC_CACHE(hwdev) && HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle)) {
				/* The fill of XID2CID Entry is delayed,
				 * because it needs to be based on a specific SMF. */
				entry_base_addr += sizeof(struct tag_hinic5_cqm_bat_entry_standerd);
				continue;
			}

			hinic5_cqm_bat_fill_cla_other(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else {
			hinic5_cqm_bat_fill_cla_other(hinic5_cqm_handle, cla_table, &entry_base_addr);
		}

		/* Check whether entry_base_addr is out-of-bounds array. */
		if (entry_base_addr >=
		    (bat_table->bat + HINIC5_CQM_BAT_ENTRY_MAX * HINIC5_CQM_BAT_ENTRY_SIZE))
			break;
	}
}

u32 hinic5_cqm_lb0_get_smf_id(const struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	u32 smf_sel, funcid, smf_pg_partial, smf_id;
	/* SMFID is selected based on SMF_PG[1:0] and SMF_Selection(0-1) */
	u32 smfsel_smfid01[4][2] = { {0, 0}, {0, 0}, {1, 1}, {0, 1} };
	/* SMFID is selected based on SMF_PG[3:2] and SMF_Selection(2-4) */
	u32 smfsel_smfid23[4][2] = { {2, 2}, {2, 2}, {3, 3}, {2, 3} };

	/* SMF_Selection is selected based on
	 * the lower two bits of the function id
	 */
	funcid = hinic5_cqm_handle->func_attribute.func_global_idx & 0x3;
	/* if smf2 and smf3 are disabled, only select smf0/smf1 */
	if ((hinic5_cqm_handle->func_capability.smf_pg >> 2) == 0) {
		u32 lbf_smfsel[4] = {0, 1, 0, 1};
		smf_sel = lbf_smfsel[funcid];
	} else {
		u32 lbf_smfsel[4] = {0, 2, 1, 3};
		smf_sel = lbf_smfsel[funcid];
	}

	if (smf_sel < 0x2) {
		smf_pg_partial = hinic5_cqm_handle->func_capability.smf_pg & 0x3;
		smf_id = smfsel_smfid01[smf_pg_partial][smf_sel];
	} else {
		smf_pg_partial =
			/* shift to right by 2 bits */
			(hinic5_cqm_handle->func_capability.smf_pg >> 2) & 0x3;
		smf_id = smfsel_smfid23[smf_pg_partial][smf_sel - 0x2];
	}

	return smf_id;
}

u32 hinic5_cqm_funcid2smfid(const struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	u32 smf_id;

	/* When the LB mode is disabled, SMF0 is always returned. */
	if (HINIC5_CQM_IS_LB_MODE_NORMAL(hinic5_cqm_handle)) {
		smf_id = 0;
	} else {
		smf_id = hinic5_cqm_lb0_get_smf_id(hinic5_cqm_handle);
	}

	return smf_id;
}

/* This function is used in LB mode 1/2. Some BAT entries
 * of independent space needs to be configured for all enabled SMFs.
 */
static void hinic5_cqm_update_bat_gpa(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 smf_id)
{
	struct hinic5_hwdev *hwdev = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	u32 entry_type = HINIC5_CQM_BAT_ENTRY_T_INVALID;
	u8 *entry_base_addr = bat_table->bat;
	u32 i = 0;

	if (!HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle))
		return;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		entry_type = bat_table->bat_entry_type[i];
		if (HINIC5_CQM_IS_PPF(hinic5_cqm_handle) &&
		    entry_type == HINIC5_CQM_BAT_ENTRY_T_TIMER) {
			cla_table = &bat_table->timer_entry[smf_id];
			hinic5_cqm_bat_fill_cla_timer(hinic5_cqm_handle, cla_table,
					       &entry_base_addr);
		} else if (entry_type == HINIC5_CQM_BAT_ENTRY_T_HASH) {
			cla_table = &bat_table->hash_entry[smf_id];
			hinic5_cqm_bat_fill_cla_other(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else if (COMM_SUPPORT_VIRTIO_FC_CACHE(hwdev) &&
			   entry_type == HINIC5_CQM_BAT_ENTRY_T_XID2CID) {
			cla_table = &bat_table->xid2cid_entry[smf_id];
			hinic5_cqm_bat_fill_cla_other(hinic5_cqm_handle, cla_table, &entry_base_addr);
		} else {
			if (entry_type == HINIC5_CQM_BAT_ENTRY_T_TASKMAP)
				entry_base_addr += sizeof(struct tag_hinic5_cqm_bat_entry_taskmap);
			else
				entry_base_addr += HINIC5_CQM_BAT_ENTRY_SIZE;
		}

		/* Check whether entry_base_addr is out-of-bounds array. */
		if (entry_base_addr >=
		    (bat_table->bat + HINIC5_CQM_BAT_ENTRY_MAX * HINIC5_CQM_BAT_ENTRY_SIZE))
			break;
	}
}

static s32 hinic5_cqm_bat_update_smf_cmd(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				  struct tag_hinic5_cqm_cmd_buf *buf_in,
				  struct tag_hinic5_cqm_bat_update_param *param)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_cqm_cmdq_ops *ops = hinic5_cqm_handle->cmdq_ops;
	u8 cmd;
	bool illegal_args = true;
	s32 ret = HINIC5_CQM_FAIL;

	illegal_args = (param->bat_offset % HINIC5_CQM_BAT_ENTRY_SIZE != 0) ||
		       (param->update_size % HINIC5_CQM_BAT_ENTRY_SIZE != 0) ||
		       (param->update_size == 0) ||
		       (param->bat_offset + param->update_size > bat_table->bat_size);
	if (unlikely(illegal_args)) {
		hinic5_cqm_err(handle->dev_hdl,
			"Bat update: invalid args, bat_offset %u, update_size %u.",
			param->bat_offset, param->update_size);
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_info(handle->dev_hdl,
		 "Bat update: smf_id %u, func_id %u, bat_offset %u, update_size %u.",
		 param->smf_id, param->func_id,
		 param->bat_offset, param->update_size);

	ret = ops->prepare_cmd_buf_bat_update(hinic5_cqm_handle, buf_in, param, &cmd);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(prepare_cmd_buf_bat_update));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_dbg_byte_print(handle->dev_hdl, (u32 *)bat_table->bat, sizeof(bat_table->bat));

	ret = hinic5_cqm_send_cmd_box((void *)(handle), HINIC5_CQM_MOD_HINIC5_CQM,
				cmd, buf_in, NULL, NULL,
				HINIC5_CQM_CMD_TIMEOUT, HINIC5_CHANNEL_DEFAULT);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_send_cmd_box));
		hinic5_cqm_err(handle->dev_hdl, "%s: send_cmd_box ret=%d\n", __func__,
			ret);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_bat_update_smf(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			      struct tag_hinic5_cqm_cmd_buf *buf_in,
			      u32 smf_id, u32 func_id)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_bat_update_param param = { 0 };
	struct hinic5_bat_entry_config l3i_config = { 0 };
	int is_in_kexec;
	s32 ret = HINIC5_CQM_FAIL;

	is_in_kexec = hinic5_vram_get_kexec_flag();
	if (is_in_kexec != 0) {
		hinic5_cqm_info(handle->dev_hdl, "Skip updating the hinic5_cqm_bat to chip during kexec!");
		return HINIC5_CQM_SUCCESS;
	}

	if (bat_table->bat_size > HINIC5_CQM_BAT_MAX_SIZE) {
		hinic5_cqm_err(handle->dev_hdl, "bat_size = %u, which is more than %d.",
			bat_table->bat_size, HINIC5_CQM_BAT_MAX_SIZE);
		return HINIC5_CQM_FAIL;
	}

	ret = hinic5_bat_get_l3i_entry_config(handle, &l3i_config);
	if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_bat_get_l3i_entry_config));
		return ret;
	}

	param.smf_id = smf_id;
	param.func_id = func_id;

	/* The L3I entry is not managed by HINIC5_CQM */
	if (l3i_config.mapping &&
	    bat_table->bat_size > l3i_config.bat_entry_offset) {
		/* update bat entries before L3I */
		param.bat_offset = 0;
		param.update_size = l3i_config.bat_entry_offset;
		ret = hinic5_cqm_bat_update_smf_cmd(hinic5_cqm_handle, buf_in, &param);
		if (ret != HINIC5_CQM_SUCCESS)
			goto cmd_err;

		/* update bat entries after L3I */
		param.bat_offset = l3i_config.bat_entry_offset + l3i_config.bat_entry_size;
		if (bat_table->bat_size > param.bat_offset) {
			param.update_size = bat_table->bat_size - param.bat_offset;
			ret = hinic5_cqm_bat_update_smf_cmd(hinic5_cqm_handle, buf_in, &param);
			if (ret != HINIC5_CQM_SUCCESS)
				goto cmd_err;
		}
	} else {
		/* update all bat entries */
		param.bat_offset = 0;
		param.update_size = bat_table->bat_size;
		ret = hinic5_cqm_bat_update_smf_cmd(hinic5_cqm_handle, buf_in, &param);
		if (ret != HINIC5_CQM_SUCCESS)
			goto cmd_err;
	}

	return HINIC5_CQM_SUCCESS;

cmd_err:
	hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bat_update_smf_cmd));
	return ret;
}

static s32 hinic5_cqm_bat_update_all_smf(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				  struct tag_hinic5_cqm_cmd_buf *buf_in,
				  u32 func_id)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	u32 smf_id = 0;
	s32 ret = HINIC5_CQM_SUCCESS;

	for (smf_id = 0; smf_id < func_cap->smf_max_num; smf_id++) {
		if ((func_cap->smf_pg & (1U << smf_id)) == 0)
			continue;

		hinic5_cqm_update_bat_gpa(hinic5_cqm_handle, smf_id);
		ret = hinic5_cqm_bat_update_smf(hinic5_cqm_handle, buf_in, smf_id, func_id);
		if (ret != HINIC5_CQM_SUCCESS)
			return ret;
	}

	return ret;
}

/**
 * The LB scenario is supported.
 * - The normal mode is the traditional mode and is configured on SMF0.
 * - In mode 0, load is balanced to all SMFs based on the func ID (except
 *   the PPF func ID). The PPF in mode 0 needs to be configured on all SMFs,
 *   so the timer resources can be shared by the all timer engine.
 * - Mode 1/2 is load balanced to all SMFs by flow. Therefore, one function
 *   needs to be configured to all SMFs.
 */
static s32 hinic5_cqm_bat_update_lb(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			     struct tag_hinic5_cqm_cmd_buf *buf_in,
			     u32 func_id)
{
	struct hinic5_hwdev *hwdev = hinic5_cqm_handle->ex_handle;
	u32 smf_id;

	if (HINIC5_CQM_IS_LB_MODE_NORMAL(hinic5_cqm_handle)) {
		smf_id = hinic5_cqm_funcid2smfid(hinic5_cqm_handle);
		return hinic5_cqm_bat_update_smf(hinic5_cqm_handle, buf_in, smf_id, func_id);
	}

	if (HINIC5_CQM_IS_LB_MODE_0(hinic5_cqm_handle)) {
		if (HINIC5_CQM_IS_PPF(hinic5_cqm_handle))
			return hinic5_cqm_bat_update_all_smf(hinic5_cqm_handle, buf_in, func_id);
		smf_id = hinic5_cqm_funcid2smfid(hinic5_cqm_handle);
		return hinic5_cqm_bat_update_smf(hinic5_cqm_handle, buf_in, smf_id, func_id);
	}

	if (HINIC5_CQM_IS_LB_MODE_1(hinic5_cqm_handle) || HINIC5_CQM_IS_LB_MODE_2(hinic5_cqm_handle))
		return hinic5_cqm_bat_update_all_smf(hinic5_cqm_handle, buf_in, func_id);

	hinic5_cqm_err(hwdev->dev_hdl, "Bat update: unsupported lb mode=%u\n",
		hinic5_cqm_handle->func_capability.lb_mode);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_bat_update
 * Description  : Send a command to tile to update the BAT table through cmdq.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/15
 *   Modification : Created function
 */
static s32 hinic5_cqm_bat_update(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_hwdev *hwdev = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_cmd_buf *buf_in = NULL;
	s32 ret = HINIC5_CQM_FAIL;
	u32 func_id = 0;

	/* The BAT is maintained by the parent function. */
	if (HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle)) {
		hinic5_cqm_err(hwdev->dev_hdl, "Bat update: unsupported for fake child\n");
		return HINIC5_CQM_FAIL;
	}

	buf_in = hinic5_cqm_cmd_alloc((void *)(hinic5_cqm_handle->ex_handle));
	if (unlikely((buf_in) == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(buf_in));
		return HINIC5_CQM_FAIL;
	}

	/* In non-fake mode, func_id is set to 0xffff, indicating the current
	 * func. In fake mode, the value of func_id is specified. This is a fake
	 * func_id.
	 */
	if (HINIC5_CQM_IS_FAKE_CHILD_AGENT(hinic5_cqm_handle))
		func_id = hinic5_cqm_handle->func_attribute.func_global_idx;
	else
		func_id = 0xffff;

	ret = hinic5_cqm_bat_update_lb(hinic5_cqm_handle, buf_in, func_id);

	hinic5_cqm_cmd_free((void *)(hinic5_cqm_handle->ex_handle), buf_in);
	return ret;
}

static s32 hinic5_cqm_bat_init_ft(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_bat_table *bat_table,
			   enum func_type function_type)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 i = 0;

	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX0] = HINIC5_CQM_BAT_ENTRY_T_CFG;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX1] = HINIC5_CQM_BAT_ENTRY_T_HASH;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX2] = HINIC5_CQM_BAT_ENTRY_T_QPC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX3] = HINIC5_CQM_BAT_ENTRY_T_SCQC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX4] = HINIC5_CQM_BAT_ENTRY_T_LUN;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX5] = HINIC5_CQM_BAT_ENTRY_T_TASKMAP;

	if (function_type == HINIC5_CQM_PF || function_type == HINIC5_CQM_PPF) {
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX6] = HINIC5_CQM_BAT_ENTRY_T_L3I;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX7] = HINIC5_CQM_BAT_ENTRY_T_CHILDC;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX8] = HINIC5_CQM_BAT_ENTRY_T_TIMER;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX9] = HINIC5_CQM_BAT_ENTRY_T_XID2CID;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX10] = HINIC5_CQM_BAT_ENTRY_T_REORDER;
		bat_table->bat_size = HINIC5_CQM_BAT_SIZE_FT_PF;
	} else if (function_type == HINIC5_CQM_VF) {
		bat_table->bat_size = HINIC5_CQM_BAT_SIZE_FT_VF;
	} else {
		for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++)
			bat_table->bat_entry_type[i] = HINIC5_CQM_BAT_ENTRY_T_INVALID;

		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(function_type));
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_bat_init_rdma(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			     struct tag_hinic5_cqm_bat_table *bat_table,
			     enum func_type function_type)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 i = 0;

	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX0] = HINIC5_CQM_BAT_ENTRY_T_QPC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX1] = HINIC5_CQM_BAT_ENTRY_T_SCQC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX2] = HINIC5_CQM_BAT_ENTRY_T_SRQC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX3] = HINIC5_CQM_BAT_ENTRY_T_MPT;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX4] = HINIC5_CQM_BAT_ENTRY_T_GID;

	if (function_type == HINIC5_CQM_PF || function_type == HINIC5_CQM_PPF) {
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX5] = HINIC5_CQM_BAT_ENTRY_T_L3I;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX6] =
		    HINIC5_CQM_BAT_ENTRY_T_CHILDC;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX7] =
		    HINIC5_CQM_BAT_ENTRY_T_TIMER;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX8] =
		    HINIC5_CQM_BAT_ENTRY_T_XID2CID;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX9] =
		    HINIC5_CQM_BAT_ENTRY_T_REORDER;
		bat_table->bat_size = HINIC5_CQM_BAT_SIZE_RDMA_PF;
	} else if (function_type == HINIC5_CQM_VF) {
		bat_table->bat_size = HINIC5_CQM_BAT_SIZE_RDMA_VF;
	} else {
		for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++)
			bat_table->bat_entry_type[i] = HINIC5_CQM_BAT_ENTRY_T_INVALID;

		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(function_type));
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_bat_init_ft_rdma(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				struct tag_hinic5_cqm_bat_table *bat_table,
				enum func_type function_type)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 i = 0;

	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX0] = HINIC5_CQM_BAT_ENTRY_T_CFG;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX1] = HINIC5_CQM_BAT_ENTRY_T_HASH;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX2] = HINIC5_CQM_BAT_ENTRY_T_QPC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX3] = HINIC5_CQM_BAT_ENTRY_T_SCQC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX4] = HINIC5_CQM_BAT_ENTRY_T_SRQC;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX5] = HINIC5_CQM_BAT_ENTRY_T_MPT;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX6] = HINIC5_CQM_BAT_ENTRY_T_GID;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX7] = HINIC5_CQM_BAT_ENTRY_T_LUN;
	bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX8] = HINIC5_CQM_BAT_ENTRY_T_TASKMAP;

	if (function_type == HINIC5_CQM_PF || function_type == HINIC5_CQM_PPF) {
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX9] = HINIC5_CQM_BAT_ENTRY_T_L3I;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX10] =
		    HINIC5_CQM_BAT_ENTRY_T_CHILDC;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX11] =
		    HINIC5_CQM_BAT_ENTRY_T_TIMER;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX12] =
		    HINIC5_CQM_BAT_ENTRY_T_XID2CID;
		bat_table->bat_entry_type[HINIC5_CQM_BAT_INDEX13] =
		    HINIC5_CQM_BAT_ENTRY_T_REORDER;
		bat_table->bat_size = HINIC5_CQM_BAT_SIZE_FT_RDMA_PF;
	} else if (function_type == HINIC5_CQM_VF) {
		bat_table->bat_size = HINIC5_CQM_BAT_SIZE_FT_RDMA_VF;
	} else {
		for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++)
			bat_table->bat_entry_type[i] = HINIC5_CQM_BAT_ENTRY_T_INVALID;

		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(function_type));
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_bat_init
 * Description  : Initialize the BAT table. Only the items to be initialized and
 *		  the entry sequence are selected. The content of the BAT entry
 *		  is filled after the CLA is allocated.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/15
 *   Modification : Created function
 */
s32 hinic5_cqm_bat_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *capability = &hinic5_cqm_handle->func_capability;
	enum func_type function_type = hinic5_cqm_handle->func_attribute.func_type;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	u32 i;

	memset(bat_table, 0, sizeof(struct tag_hinic5_cqm_bat_table));

	/* Initialize the type of each bat entry. */
	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++)
		bat_table->bat_entry_type[i] = HINIC5_CQM_BAT_ENTRY_T_INVALID;

	/* Select BATs based on service types. Currently,
	 * feature-related resources of the VF are stored in the BATs of the VF.
	 */
	if (capability->ft_enable && capability->rdma_enable)
		return hinic5_cqm_bat_init_ft_rdma(hinic5_cqm_handle, bat_table, function_type);
	else if (capability->ft_enable)
		return hinic5_cqm_bat_init_ft(hinic5_cqm_handle, bat_table, function_type);
	else if (capability->rdma_enable)
		return hinic5_cqm_bat_init_rdma(hinic5_cqm_handle, bat_table, function_type);

	return HINIC5_CQM_SUCCESS;
}

STATIC s32 hinic5_cqm_cla_reset(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_cmd_buf *buf_in = NULL;
	struct tag_hinic5_cqm_cla_reset_cmd *cmd_data = NULL;
	int ret = HINIC5_CQM_SUCCESS;

	buf_in = hinic5_cqm_cmd_alloc(handle);
	if (unlikely(!buf_in)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(buf_in));
		return HINIC5_CQM_FAIL;
	}

	cmd_data = buf_in->buf;
	memset(cmd_data, 0, sizeof(*cmd_data));

	cmd_data->func_id = hinic5_global_func_id(handle);
	hinic5_cqm_swab32((u8 *)cmd_data, sizeof(struct tag_hinic5_cqm_cla_reset_cmd) >> HINIC5_CQM_DW_SHIFT);
	ret = hinic5_cqm_send_cmd_box(handle, HINIC5_CQM_MOD_HINIC5_CQM, HINIC5_CQM_CMD_T_CLA_RESET,
			       buf_in, NULL, NULL,
			       HINIC5_CQM_CMD_TIMEOUT, HINIC5_CHANNEL_DEFAULT);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_send_cmd_box));
	}

	return ret;
}

/**
 * Prototype    : hinic5_cqm_bat_uninit
 * Description  : Deinitialize the BAT table.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/15
 *   Modification : Created function
 */
void hinic5_cqm_bat_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 i;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++)
		bat_table->bat_entry_type[i] = HINIC5_CQM_BAT_ENTRY_T_INVALID;

	/* The BAT is maintained by the parent function.
	   Reset CLA instead of clear BAT. */
	if (HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle)) {
		hinic5_cqm_cla_reset(hinic5_cqm_handle);
		return;
	}

	memset(bat_table->bat, 0, HINIC5_CQM_BAT_ENTRY_MAX * HINIC5_CQM_BAT_ENTRY_SIZE);
	/* Instruct the chip to update the BAT table. */
	if (hinic5_cqm_bat_update(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS)
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bat_update));
}

static u64 hinic5_cqm_cla_chip_gpa_flags(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u8 gpa_check_enable)
{
	struct hinic5_func_attr *func_attr = NULL;
	u64 fake_en, spu_en, pf_id;

	spu_en = ((u64)hinic5_cqm_get_acs_spu_en(hinic5_cqm_handle)) << 0x3F;

	/* fake enable */
	fake_en = 0;
	pf_id = 0;
	if (HINIC5_CQM_IS_FAKE_CHILD_AGENT(hinic5_cqm_handle)) {
		fake_en = 1ULL << 0x3E;
		func_attr = &hinic5_cqm_handle->parent_hinic5_cqm_handle->func_attribute;
		pf_id = (u64)(func_attr->func_global_idx & 0x1f) << 0x39;
	}

	return spu_en | fake_en | pf_id | gpa_check_enable;
}

/**
 * Create mapping from cla_base_buf to cla_sub_buf.
 * The pointer in cla_base_buf is mapped from base_offset, and the target buf
 * in cla_sub_buf is used from sub_offset.
 */
static s32 hinic5_cqm_cla_map_buf(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			   struct tag_hinic5_cqm_buf *cla_base_buf,
			   const struct tag_hinic5_cqm_buf *cla_sub_buf,
			   u32 base_offset, u32 sub_offset, u32 num,
			   u8 gpa_check_enable)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 buf_addr_cap, base_addr_cap;
	u64 gpa_flags = 0;
	u32 i, base_buf_index, base_buf_offset, index_base_offset, index_sub_offset;
	dma_addr_t *base = NULL;

	buf_addr_cap = cla_base_buf->buf_size / sizeof(dma_addr_t);
	base_addr_cap = cla_base_buf->buf_number * buf_addr_cap;

	if (unlikely(num == 0 || (base_offset + num > base_addr_cap) ||
		     (sub_offset + num > cla_sub_buf->buf_number))) {
		hinic5_cqm_err(handle->dev_hdl,
			"Cla alloc: truncate! mapping num %u, base off %u, sub cap %u, sub offset %u, sub cap %u",
			num, base_offset, base_addr_cap, sub_offset, cla_sub_buf->buf_number);
		return HINIC5_CQM_FAIL;
	}

	gpa_flags = hinic5_cqm_cla_chip_gpa_flags(hinic5_cqm_handle, gpa_check_enable);

	hinic5_cqm_dbg(handle->dev_hdl,
		"hinic5_cqm_cla_map_buf: mapping num %u, base off %u, sub cap %u, sub offset %u, sub cap %u, gpa_flags 0x%llX\n",
		num, base_offset, base_addr_cap, sub_offset, cla_sub_buf->buf_number, gpa_flags);

	index_base_offset = base_offset;
	index_sub_offset = sub_offset;
	for (i = 0; i < num; i++) {
		base_buf_index = index_base_offset  / buf_addr_cap;
		base_buf_offset = index_base_offset  % buf_addr_cap;
		base = (dma_addr_t *)(cla_base_buf->buf_list[base_buf_index].va);
		base += base_buf_offset;

#define HINIC5_CQM_TIMER_FUNC_BUF_NUM 64
		hinic5_cqm_dbg_on(i % HINIC5_CQM_TIMER_FUNC_BUF_NUM == 0, handle->dev_hdl,
			"hinic5_cqm_cla_map_buf: mapping %4u, pointer(va 0x%lX, base_buf+%03u) --> sub_buf(idx %4u, pa 0x%lX), using base_buf(idx %3u, pa 0x%lX, va 0x%lX).\n",
			i, (uintptr_t)base, base_buf_offset,
			index_sub_offset, (uintptr_t)cla_sub_buf->buf_list[index_sub_offset].pa,
			base_buf_index, (uintptr_t)cla_base_buf->buf_list[base_buf_index].pa,
			(uintptr_t)cla_base_buf->buf_list[base_buf_index].va);

		*base = (dma_addr_t)(((u64)(cla_sub_buf->buf_list[index_sub_offset].pa) & HINIC5_CQM_CHIP_GPA_MASK)
			| gpa_flags);
		hinic5_cqm_swab64((u8 *)base, 1);

		index_base_offset++;
		index_sub_offset++;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_cla_fill_buf(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *cla_base_buf,
			    struct tag_hinic5_cqm_buf *cla_sub_buf, u8 gpa_check_enable)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	dma_addr_t *base = NULL;
	u64 gpa_flags = 0;
	u32 i = 0;
	u32 addr_num;
	u32 buf_index = 0;
	s32 ret;

	/* Apply for space for base_buf */
	if (!cla_base_buf->buf_list) {
		ret = hinic5_cqm_buf_alloc(hinic5_cqm_handle, cla_base_buf, false);
		if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(cla_base_buf));
			return ret;
		}
	}

	/* Apply for space for sub_buf */
	if (!cla_sub_buf->buf_list) {
		ret = hinic5_cqm_buf_alloc(hinic5_cqm_handle, cla_sub_buf, false);
		if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(cla_sub_buf));
			hinic5_cqm_buf_free(cla_base_buf, hinic5_cqm_handle->dev);
			return ret;
		}
	}

	gpa_flags = hinic5_cqm_cla_chip_gpa_flags(hinic5_cqm_handle, gpa_check_enable);
	hinic5_cqm_dbg(handle->dev_hdl, "hinic5_cqm_cla_fill_buf: gpa_flags 0x%llX\n", gpa_flags);

	/* Fill base_buff with the gpa of sub_buf */
	addr_num = cla_base_buf->buf_size / sizeof(dma_addr_t);
	base = (dma_addr_t *)(cla_base_buf->buf_list[0].va);
	for (i = 0; i < cla_sub_buf->buf_number; i++) {
		*base = (dma_addr_t)(((u64)(cla_sub_buf->buf_list[i].pa) & HINIC5_CQM_CHIP_GPA_MASK)
			| gpa_flags);

		hinic5_cqm_swab64((u8 *)base, 1);
		if ((i + 1) % addr_num == 0) {
			buf_index++;
			if (buf_index < cla_base_buf->buf_number)
				base = cla_base_buf->buf_list[buf_index].va;
		} else {
			base++;
		}
	}

	return HINIC5_CQM_SUCCESS;
}

static void hinic5_cqm_apply_new_buf(struct tag_hinic5_cqm_buf *cla_buf, u32 buf_size, u32 buf_num, u32 buf_order)
{
	cla_buf->buf_size = buf_size;
	cla_buf->buf_number = buf_num;
	cla_buf->page_number = cla_buf->buf_number << buf_order;
}

static s32 hinic5_cqm_cla_secure_mem_buf_alloc(struct tag_hinic5_cqm_cla_table *cla_table,
					struct tag_hinic5_cqm_buf *buf)
{
	/* Applying for the buffer list descriptor space */
	buf->buf_list = vmalloc(buf->buf_number * sizeof(struct tag_hinic5_cqm_buf_list));
	if (unlikely(buf->buf_list == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(secure_mem_buf_alloc));
		return HINIC5_CQM_FAIL;
	}
	memset(buf->buf_list,
	       0, buf->buf_number * sizeof(struct tag_hinic5_cqm_buf_list));

	buf->buf_list->va = cla_table->secure_mem.va;
	buf->buf_list->pa = cla_table->secure_mem.pa;
	buf->secure_mem_flag = HINIC5_CQM_SECURE_BUFFER_EN;

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_cla_xyz_lvl0(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_cla_table *cla_table, u32 trunk_size)
{
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	s32 ret;

	cla_table->cla_lvl = HINIC5_CQM_CLA_LVL_0;

	cla_table->z = cla_table->max_index_bit;
	cla_table->y = 0;
	cla_table->x = 0;

	cla_table->cacheline_z = cla_table->z;
	cla_table->cacheline_y = cla_table->y;
	cla_table->cacheline_x = cla_table->x;

	/* Applying for CLA_Z_BUF Space */
	cla_z_buf->buf_size = trunk_size;
	cla_z_buf->buf_number = 1;
	cla_z_buf->page_number = cla_z_buf->buf_number << cla_table->trunk_order;

	if (secure_mem_en && HINIC5_CQM_IS_VF(hinic5_cqm_handle) && HINIC5_CQM_CLA_IS_SECURE_MEM(cla_table->type))
		return hinic5_cqm_cla_secure_mem_buf_alloc(cla_table, cla_z_buf);

	ret = hinic5_cqm_buf_alloc(hinic5_cqm_handle, cla_z_buf, false);
	if (unlikely(ret != HINIC5_CQM_SUCCESS))
		hinic5_cqm_warn(hinic5_cqm_handle->dev,
			 "lvl_0_z_buf alloc fail. buf size 0x%x, ret %d.\n",
			 trunk_size, ret);
	return ret;
}

static s32 hinic5_cqm_cla_xyz_lvl1(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_cla_table *cla_table, u32 trunk_size)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	u32 shift = 0, z_buf_num;
	u8 gpa_check_enable = hinic5_cqm_handle->func_capability.gpa_check_enable;
	u32 cache_line = get_cacheline_size(cla_table->type);
	s32 ret;

	if (cla_table->type == HINIC5_CQM_BAT_ENTRY_T_REORDER)
		gpa_check_enable = 0;

	cla_table->cla_lvl = HINIC5_CQM_CLA_LVL_1;

	shift = hinic5_cqm_shift(trunk_size / cla_table->obj_size);
	cla_table->z = ((shift != 0) ? (shift - 1) : (shift));
	cla_table->y = cla_table->max_index_bit;
	cla_table->x = 0;

	if (cla_table->obj_size >= cache_line) {
		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;
	} else {
		shift = hinic5_cqm_shift(trunk_size / cache_line);
		cla_table->cacheline_z = ((shift != 0) ? (shift - 1) : (shift));
		cla_table->cacheline_y = cla_table->max_index_bit;
		cla_table->cacheline_x = 0;
	}

	/* Applying for CLA_Y_BUF Space */
	hinic5_cqm_apply_new_buf(cla_y_buf, trunk_size, 1, cla_table->trunk_order);
	ret = hinic5_cqm_buf_alloc(hinic5_cqm_handle, cla_y_buf, false);
	if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_warn(hinic5_cqm_handle->dev,
			 "lvl_1_y_buf alloc fail. buf size 0x%x, ret %d.\n",
			 trunk_size, ret);
		return ret;
	}

	/* Applying for CLA_Z_BUF Space */
	z_buf_num = ALIGN(cla_table->max_buffer_size, trunk_size) / trunk_size;
	hinic5_cqm_apply_new_buf(cla_z_buf, trunk_size, z_buf_num, cla_table->trunk_order);
	/* All buffer space must be statically allocated. */
	if (cla_table->alloc_static) {
		ret = hinic5_cqm_cla_fill_buf(hinic5_cqm_handle, cla_y_buf, cla_z_buf, gpa_check_enable);
		if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_fill_buf));
			/* cla_y_buf freed by hinic5_cqm_cla_fill_buf() */
			return ret;
		}
	} else { /* Only the buffer list space is initialized. The buffer space
		  * is dynamically allocated in services.
		  */
		ret = hinic5_cqm_buf_list_alloc(cla_z_buf);
		if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(lvl_1_z_buf));
			hinic5_cqm_buf_free(cla_y_buf, hinic5_cqm_handle->dev);
			return ret;
		}
	}

	return HINIC5_CQM_SUCCESS;
}

static void hinic5_cqm_cla_xyz_lvl2_param_init(struct tag_hinic5_cqm_cla_table *cla_table,  u32 trunk_size)
{
	u32 shift = 0;
	u32 cache_line = get_cacheline_size(cla_table->type);

	cla_table->cla_lvl = HINIC5_CQM_CLA_LVL_2;

	shift = hinic5_cqm_shift(trunk_size / cla_table->obj_size);
	cla_table->z = ((shift != 0) ? (shift - 1) : (shift));
	shift = hinic5_cqm_shift(trunk_size / sizeof(dma_addr_t));
	cla_table->y = cla_table->z + shift;
	cla_table->x = cla_table->max_index_bit;

	if (cla_table->obj_size >= cache_line) {
		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;
	} else {
		shift = hinic5_cqm_shift(trunk_size / cache_line);
		cla_table->cacheline_z = ((shift != 0) ? (shift - 1) : (shift));
		shift = hinic5_cqm_shift(trunk_size / sizeof(dma_addr_t));
		cla_table->cacheline_y = cla_table->cacheline_z + shift;
		cla_table->cacheline_x = cla_table->max_index_bit;
	}
}

static s32 hinic5_cqm_cla_xyz_lvl2_xyz_apply(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				      struct tag_hinic5_cqm_cla_table *cla_table, u32 trunk_size)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	s32 ret;

	/* Apply for CLA_X_BUF Space */
	cla_x_buf->buf_size = trunk_size;
	cla_x_buf->buf_number = 1;
	cla_x_buf->page_number = cla_x_buf->buf_number << cla_table->trunk_order;
	cla_x_buf->buf_info.use_hinic5_vram = get_use_hinic5_vram_flag();
	ret = hinic5_cqm_buf_alloc(hinic5_cqm_handle, cla_x_buf, false);
	if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(lvl_2_x_buf));
		return ret;
	}

	/* Apply for CLA_Z_BUF and CLA_Y_BUF Space */
	cla_z_buf->buf_size = trunk_size;
	cla_z_buf->buf_number = (ALIGN(cla_table->max_buffer_size, trunk_size)) / trunk_size;
	cla_z_buf->page_number = cla_z_buf->buf_number << cla_table->trunk_order;

	cla_y_buf->buf_size = trunk_size;
	cla_y_buf->buf_number =
	    (u32)(ALIGN(cla_z_buf->buf_number * sizeof(dma_addr_t), trunk_size)) / trunk_size;
	cla_y_buf->page_number = cla_y_buf->buf_number << cla_table->trunk_order;

	return 0;
}

static s32 hinic5_cqm_cla_xyz_hinic5_vram_name_init(struct tag_hinic5_cqm_cla_table *cla_table,
				      struct hinic5_hwdev *handle)
{
	struct tag_hinic5_cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	const int use_hinic5_vram = get_use_hinic5_vram_flag();
	int ret;

	cla_x_buf->buf_info.use_hinic5_vram = use_hinic5_vram;
	ret = snprintf(cla_x_buf->buf_info.buf_hinic5_vram_name, HINIC5_VRAM_NAME_MAX_LEN,
		       "%s%s", cla_table->name, HINIC5_VRAM_HINIC5_CQM_CLA_COORD_X);
	if (ret < 0) {
		hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm cla x hinic5_vram name snprintf_s failed, cla_table->name:%s", cla_table->name);
		return HINIC5_CQM_FAIL;
	}

	cla_y_buf->buf_info.use_hinic5_vram = use_hinic5_vram;
	ret = snprintf(cla_y_buf->buf_info.buf_hinic5_vram_name, HINIC5_VRAM_NAME_MAX_LEN,
		       "%s%s", cla_table->name, HINIC5_VRAM_HINIC5_CQM_CLA_COORD_Y);
	if (ret < 0) {
		hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm cla y hinic5_vram name snprintf_s failed");
		return HINIC5_CQM_FAIL;
	}

	cla_z_buf->buf_info.use_hinic5_vram = use_hinic5_vram;
	ret = snprintf(cla_z_buf->buf_info.buf_hinic5_vram_name, HINIC5_VRAM_NAME_MAX_LEN,
		       "%s%s", cla_table->name, HINIC5_VRAM_HINIC5_CQM_CLA_COORD_Z);
	if (ret < 0) {
		hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm cla z hinic5_vram name snprintf_s failed");
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_cla_xyz_lvl2(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			    struct tag_hinic5_cqm_cla_table *cla_table, u32 trunk_size)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	s32 ret = HINIC5_CQM_FAIL;
	u8 gpa_check_enable = hinic5_cqm_handle->func_capability.gpa_check_enable;

	hinic5_cqm_cla_xyz_lvl2_param_init(cla_table, trunk_size);

	ret = hinic5_cqm_cla_xyz_lvl2_xyz_apply(hinic5_cqm_handle, cla_table, trunk_size);
	if (ret != HINIC5_CQM_SUCCESS)
		return ret;

	if (cla_table->type == HINIC5_CQM_BAT_ENTRY_T_REORDER)
		gpa_check_enable = 0;

	/* All buffer space must be statically allocated. */
	if (cla_table->alloc_static) {
		/* Apply for y buf and z buf, and fill the gpa of z buf list in y buf */
		ret = hinic5_cqm_cla_fill_buf(hinic5_cqm_handle, cla_y_buf, cla_z_buf,
				       gpa_check_enable);
		if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_fill_buf));
			hinic5_cqm_buf_free(cla_x_buf, hinic5_cqm_handle->dev);
			return ret;
		}

		/* Fill the gpa with the y buf list into the x buf.
		 * After the x and y bufs are applied for, this function will not fail.
		 * Use void to forcibly convert the return of the function.
		 */
		(void)hinic5_cqm_cla_fill_buf(hinic5_cqm_handle, cla_x_buf, cla_y_buf, gpa_check_enable);
	} else { /* Only the buffer list space is initialized. The buffer space
		  * is dynamically allocated in services.
		  */
		ret = hinic5_cqm_buf_list_alloc(cla_z_buf);
		if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(lvl_2_z_buf));
			hinic5_cqm_buf_free(cla_x_buf, hinic5_cqm_handle->dev);
			return ret;
		}

		ret = hinic5_cqm_buf_list_alloc(cla_y_buf);
		if (unlikely(ret != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(lvl_2_y_buf));
			hinic5_cqm_buf_free(cla_z_buf, hinic5_cqm_handle->dev);
			hinic5_cqm_buf_free(cla_x_buf, hinic5_cqm_handle->dev);
			return ret;
		}
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_cla_xyz_lvl2_timer_xyz_apply(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					    struct tag_hinic5_cqm_cla_table *cla_table,
					    u32 trunk_size)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_func_capability *cap = &hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	u32 timer_func_num, timer_number, actual_buffer_size;
	s32 ret;

	ret = hinic5_cqm_cla_xyz_lvl2_xyz_apply(hinic5_cqm_handle, cla_table, trunk_size);
	if (ret != HINIC5_CQM_SUCCESS)
		return ret;

	/* Apply for space for CLA_Y_BUF */
	if (unlikely(hinic5_cqm_buf_alloc(hinic5_cqm_handle, cla_y_buf, false) != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(lvl_2_y_buf));
		hinic5_cqm_buf_free(cla_x_buf, hinic5_cqm_handle->dev);
		return HINIC5_CQM_FAIL;
	}

	/* Ref: hinic5_cqm_capability_init_timer() */
	timer_func_num = cap->timer_pf_num + cap->timer_vf_num_actual;
	timer_number = HINIC5_CQM_TIMER_ALIGN_SCALE_NUM * timer_func_num;
	/* Ref: hinic5_cqm_bat_entry_init_timer() */
	actual_buffer_size = timer_number * cap->timer_basic_size;

	/* Ref: hinic5_cqm_cla_xyz_lvl2_xyz_apply() */
	cla_z_buf->buf_number = (ALIGN(actual_buffer_size, trunk_size)) / trunk_size;
	cla_z_buf->page_number = cla_z_buf->buf_number << cla_table->trunk_order;

	/* Apply for space for CLA_Z_BUF */
	if (unlikely(hinic5_cqm_buf_alloc(hinic5_cqm_handle, cla_z_buf, false) != HINIC5_CQM_SUCCESS)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(lvl_2_z_buf));
		hinic5_cqm_buf_free(cla_y_buf, hinic5_cqm_handle->dev);
		hinic5_cqm_buf_free(cla_x_buf, hinic5_cqm_handle->dev);
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_dbg(handle->dev_hdl,
		"timer xyz apply: x buf va 0x%lX, pa 0x%lX. y buf num %u, z buf num %u\n",
		(uintptr_t)cla_x_buf->buf_list[0].va, (uintptr_t)cla_x_buf->buf_list[0].pa,
		cla_y_buf->buf_number, cla_z_buf->buf_number);

	return HINIC5_CQM_SUCCESS;
}

/**
 * Level-2 CLA for timer
 * Allocates CLA_X_BUF, CLA_Y_BUF, and CLA_Z_BUF during initialization.
 *
 * SMF Timer accesses VF's spokes by offset based on timer_vf_id_start.
 * Some VF may not require initialization, the allocation is based on VF segments.
 *
 * The mapping from 1st CLA (Y buf) to 2nd CLA (Z buf) is as follows:
 *
 * <pre>
 * ▯ Empty buffer    ▮ Buffer with pointer to Z buffer
 *
 *  Ptr to first timer PF                                 Ptr to VF seg N start
 *   (timer_pf_id_start)   (timer_vf_id_start)           (timer_vf_segs[N].start)
 *          |               |                                         |
 * 1st CLA  ▮▮▮▮▮▮▮▮▮▮▮▮▮▯▯▯▯▯▮▮▮..▮▮▮▯▯▯▯▯▯▯▮▮▮▮▮
 *          ┊               ┊      ╰───────╮ ╰────╮      ┊╭───────────╯         ┊
 *          ┊    Ptr to VF seg 0 start     ╰─────╮┊      ┊┊                     ┊
 *          ┊   (timer_vf_segs[0].start)         ┊┊      ┊┊                     ┊
 *          ↓               ↓                    ↓↓      ↓↓                     ↓
 * 2nd CLA  ▯▯▯▯...▯▯▯▯▯▯▯▯▯....▯▯▯▯▯▯▯▯▯▯▯▯▯.......▯▯▯▯
 *          \______________/\____________________/\______/\____________________/
 *            timer_pf_num   timer_vf_segs[0].num   ....   timer_vf_segs[N].num
 * </pre>
 */
static s32 hinic5_cqm_cla_xyz_lvl2_timer(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				  struct tag_hinic5_cqm_cla_table *cla_table,
				  u32 trunk_size)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	u8 gpa_check_enable = hinic5_cqm_handle->func_capability.gpa_check_enable;
	u32 func_timer_size, func_z_buf_num;
	u32 base_idx, sub_idx, func_num;
	int i;

	if (!cla_table->alloc_static ||
	    func_cap->timer_vf_num == func_cap->timer_vf_num_actual)
		return hinic5_cqm_cla_xyz_lvl2(hinic5_cqm_handle, cla_table, trunk_size);

	func_cap->timer_vf_deploy_with_segs = true;

	hinic5_cqm_cla_xyz_lvl2_param_init(cla_table, trunk_size);

	if (hinic5_cqm_cla_xyz_lvl2_timer_xyz_apply(hinic5_cqm_handle, cla_table, trunk_size) != HINIC5_CQM_SUCCESS)
		return HINIC5_CQM_FAIL;

	func_timer_size = HINIC5_CQM_TIMER_ALIGN_SCALE_NUM * func_cap->timer_basic_size;
	func_z_buf_num = func_timer_size / trunk_size;

	/* Fill the gpa with the z buf list into the y buf for PF. */
	base_idx = 0;
	sub_idx  = 0;
	func_num = func_cap->timer_pf_num;
	if (hinic5_cqm_cla_map_buf(hinic5_cqm_handle, cla_y_buf, cla_z_buf,
			    base_idx * func_z_buf_num,
			    sub_idx  * func_z_buf_num,
			    func_num * func_z_buf_num,
			    gpa_check_enable) == HINIC5_CQM_FAIL)
		goto mapping_buf_fail;

	/* Fill the gpa with the z buf list into the y buf for VF. */
	for (i = 0; i < ARRAY_SIZE(func_cap->timer_vf_segs); i++) {
		u16 seg_start = func_cap->timer_vf_segs[i].start;
		if (seg_start == 0)
			break;

		base_idx = func_cap->timer_pf_num +
			   (seg_start - func_cap->timer_vf_id_start);
		sub_idx += func_num;
		func_num = func_cap->timer_vf_segs[i].num;
		if (hinic5_cqm_cla_map_buf(hinic5_cqm_handle, cla_y_buf, cla_z_buf,
				    base_idx * func_z_buf_num,
				    sub_idx  * func_z_buf_num,
				    func_num * func_z_buf_num,
				    gpa_check_enable) == HINIC5_CQM_FAIL)
			goto mapping_buf_fail;
	}

	/* Fill the gpa with the y buf list into the x buf.
	 * After the x and y bufs are applied for, this function will not fail.
	 * Use void to forcibly convert the return of the function.
	 */
	(void)hinic5_cqm_cla_fill_buf(hinic5_cqm_handle, cla_x_buf, cla_y_buf, gpa_check_enable);

	return HINIC5_CQM_SUCCESS;

mapping_buf_fail:
	hinic5_cqm_err(handle->dev_hdl,
		"Failed to create mapping from Y buf to Z buf. base_idx %u, sub_idx %u, func_num %u",
		base_idx, sub_idx, func_num);
	hinic5_cqm_buf_free(cla_z_buf, hinic5_cqm_handle->dev);
	hinic5_cqm_buf_free(cla_y_buf, hinic5_cqm_handle->dev);
	hinic5_cqm_buf_free(cla_x_buf, hinic5_cqm_handle->dev);
	return HINIC5_CQM_FAIL;
}

static inline int min_order_for_cla_obj(struct tag_hinic5_cqm_cla_table *cla_table)
{
	return get_order(cla_table->obj_size);
}

static u32 calc_cla_lvl(u64 max_size, u32 order)
{
	const u64 buf_size = (u64)PAGE_SIZE << order;
	const u64 buf_addr_cap = buf_size / sizeof(dma_addr_t);

	if (max_size <= buf_size)
		return HINIC5_CQM_CLA_LVL_0;
	if (max_size <= buf_size * buf_addr_cap)
		return HINIC5_CQM_CLA_LVL_1;
	if (max_size <= buf_size * buf_addr_cap * buf_addr_cap)
		return HINIC5_CQM_CLA_LVL_2;
	return HINIC5_CQM_CLA_LVL_UNSUPPORT;
}

static s32 hinic5_cqm_cla_xyz_alloc(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			     struct tag_hinic5_cqm_cla_table *cla_table,
			     u32 order)
{
	const u32 cla_lvl = calc_cla_lvl(cla_table->max_buffer_size, order);
	const u32 buf_size = (u32)(PAGE_SIZE << order);
	s32 ret;

	/* Level-0 CLA occupies a small space.
	 * Only CLA_Z_BUF can be allocated during initialization.
	 */
	if (cla_lvl == HINIC5_CQM_CLA_LVL_0) {
		ret = hinic5_cqm_cla_xyz_lvl0(hinic5_cqm_handle, cla_table, buf_size);
		if (unlikely(ret != HINIC5_CQM_SUCCESS))
			hinic5_cqm_warn(hinic5_cqm_handle->dev, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_xyz_lvl0));
		return ret;
	}

	/* Level-1 CLA
	 * Allocates CLA_Y_BUF and CLA_Z_BUF during initialization.
	 */
	if (cla_lvl == HINIC5_CQM_CLA_LVL_1) {
		ret = hinic5_cqm_cla_xyz_lvl1(hinic5_cqm_handle, cla_table, buf_size);
		if (unlikely(ret != HINIC5_CQM_SUCCESS))
			hinic5_cqm_warn(hinic5_cqm_handle->dev, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_xyz_lvl1));
		return ret;
	}

	/* Level-2 CLA
	 * Allocates CLA_X_BUF, CLA_Y_BUF, and CLA_Z_BUF during initialization.
	 */
	if (cla_lvl == HINIC5_CQM_CLA_LVL_2) {
		if (cla_table->type == HINIC5_CQM_BAT_ENTRY_T_TIMER) {
			ret = hinic5_cqm_cla_xyz_lvl2_timer(hinic5_cqm_handle, cla_table, buf_size);
			if (unlikely(ret != HINIC5_CQM_SUCCESS))
				hinic5_cqm_warn(hinic5_cqm_handle->dev, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_xyz_lvl2_timer));
			return ret;
		} else {
			ret = hinic5_cqm_cla_xyz_lvl2(hinic5_cqm_handle, cla_table, buf_size);
			if (unlikely(ret != HINIC5_CQM_SUCCESS))
				hinic5_cqm_warn(hinic5_cqm_handle->dev, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_xyz_lvl2));
			return ret;
		}
	}

	/* The current memory management mode does not support such a large
	 * buffer addressing. The order value needs to be increased.
	 */
	hinic5_cqm_err(hinic5_cqm_handle->dev,
		"Cla alloc: cla max_buffer_size 0x%x exceeds support range\n",
		cla_table->max_buffer_size);
	return HINIC5_CQM_FAIL;
}

/**
 * Try hugepages for CLA tables, fallback to 4K pages.
 * Fallback is limited to alloc_pages() failures during CLA buffers init.
 */
static s32 hinic5_cqm_cla_xyz_hugepage(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				struct tag_hinic5_cqm_cla_table *cla_table)
{
	const u32 max_size  = cla_table->max_buffer_size;
	int min_order, max_order, order, ret;

	min_order = min_order_for_cla_obj(cla_table);
	max_order = get_order(max_size);
	if (max_order > MAX_ORDER)
		max_order = MAX_ORDER;

	hinic5_cqm_dbg(hinic5_cqm_handle->dev,
		"Cla alloc: try hugepage, size 0x%x, order %d - %d.\n",
		max_size, min_order, max_order);

	for (order = max_order; order >= min_order; order--) {
		ret = hinic5_cqm_cla_xyz_alloc(hinic5_cqm_handle, cla_table, (u32)order);
		if (ret == HINIC5_CQM_BUF_ALLOC_BUDDY_PAGES_FAIL) {
			hinic5_cqm_warn(hinic5_cqm_handle->dev,
				"Cla alloc: insufficient pages (order %d).\n",
				order);
			continue;
		}

		if (unlikely(ret != HINIC5_CQM_SUCCESS))
			hinic5_cqm_err(hinic5_cqm_handle->dev, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_xyz_alloc));
		return ret;
	}

	return HINIC5_CQM_FAIL;
}

static s32 hinic5_cqm_cla_xyz_check(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			     struct tag_hinic5_cqm_cla_table *cla_table)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	/* Check whether obj_size is 2^n-aligned. An error is reported when
	 * obj_size is 0 or 1.
	 */
	if (!hinic5_cqm_check_align(cla_table->obj_size)) {
		hinic5_cqm_err(handle->dev_hdl,
			"Cla alloc: cla_type %u, obj_size 0x%x is not align on 2^n\n",
			cla_table->type, cla_table->obj_size);
		return HINIC5_CQM_FAIL;
	}

	if (min_order_for_cla_obj(cla_table) > MAX_ORDER) {
		hinic5_cqm_err(hinic5_cqm_handle->dev,
			"Cla alloc: cla_type %u, obj_size 0x%x is too big\n",
			cla_table->type, cla_table->obj_size);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_cla_xyz
 * Description  : Calculate the number of levels of CLA tables and allocate
 *		  space for each level of CLA table.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 *		  struct tag_hinic5_cqm_cla_table *cla_table
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/15
 *   Modification : Created function
 */
STATIC s32 hinic5_cqm_cla_xyz(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_cla_table *cla_table)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	s32 ret = HINIC5_CQM_FAIL;

	/* The BAT and CLA of the Fake VF are maintained by the parent function. */
	if (HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle)) {
		hinic5_cqm_dbg(handle->dev_hdl,
			"Cla alloc: cla_type %u, obj_num 0x%x, fake child func skip alloc\n",
			cla_table->type, cla_table->obj_num);
		return HINIC5_CQM_SUCCESS;
	}

	/* If the capability(obj_num) is set to 0, the CLA does not need to be
	 * initialized and exits directly.
	 */
	if (cla_table->obj_num == 0) {
		hinic5_cqm_info(handle->dev_hdl,
			 "Cla alloc: cla_type %u, obj_num 0, don't alloc buffer\n",
			 cla_table->type);
		return HINIC5_CQM_SUCCESS;
	}

	hinic5_cqm_info(handle->dev_hdl,
		 "Cla alloc: cla_type %u, obj_num 0x%x, hugetable_hint %d\n",
		 cla_table->type, cla_table->obj_num, cla_table->hugepage_hint);

	ret = hinic5_cqm_cla_xyz_check(hinic5_cqm_handle, cla_table);
	if (ret != HINIC5_CQM_SUCCESS)
		return ret;

	ret = hinic5_cqm_cla_xyz_hinic5_vram_name_init(cla_table, handle);
	if (ret != HINIC5_CQM_SUCCESS)
		return ret;

	/* Try hugepages for CLA tables. */
	if (unlikely(cla_table->hugepage_hint))
		return hinic5_cqm_cla_xyz_hugepage(hinic5_cqm_handle, cla_table);

	/* Build CLA tables with specified page order. */
	if ((int)cla_table->trunk_order < min_order_for_cla_obj(cla_table)) {
		hinic5_cqm_err(handle->dev_hdl,
			"Cla alloc: cla type %u, obj_size 0x%x is out of a CLA buffer(order %u)\n",
			cla_table->type, cla_table->obj_size, cla_table->trunk_order);
		return HINIC5_CQM_FAIL;
	}
	return hinic5_cqm_cla_xyz_alloc(hinic5_cqm_handle, cla_table, cla_table->trunk_order);
}

static void update_entry_cap_for_secure_mem(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					    struct tag_hinic5_cqm_cla_table *cla_table,
					    struct tag_hinic5_cqm_func_capability *capability)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	if (!secure_mem_en || !HINIC5_CQM_IS_VF(hinic5_cqm_handle))
		return;

	/* No multi-level CLA and dynamic allocation
	 * when Secure Memory is enabled. */
	cla_table->trunk_order = (u32)get_order(cla_table->max_buffer_size);
	cla_table->hugepage_hint = false;
	cla_table->alloc_static = true;
	hinic5_cqm_info(handle->dev_hdl, "Secure mem: cla_type=%u, max_buffer_size=0x%x, order=%u\n",
		 cla_table->type, cla_table->max_buffer_size, cla_table->trunk_order);
}

static void init_hash_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				struct tag_hinic5_cqm_cla_table *cla_table,
				struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->hash_basic_size;
	cla_table->obj_num  = capability->hash_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->alloc_static = true;
}

static void init_qpc_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			       struct tag_hinic5_cqm_cla_table *cla_table,
			       struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->qpc_basic_size;
	cla_table->obj_num  = capability->qpc_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->alloc_static = capability->qpc_alloc_static;

	if (hinic5_cqm_cla_hugepage_hint)
		cla_table->hugepage_hint = true;

	update_entry_cap_for_secure_mem(hinic5_cqm_handle, cla_table, capability);
}

static void init_scqc_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				struct tag_hinic5_cqm_cla_table *cla_table,
				struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->scqc_basic_size;
	cla_table->obj_num  = capability->scqc_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->alloc_static = capability->scqc_alloc_static;

	update_entry_cap_for_secure_mem(hinic5_cqm_handle, cla_table, capability);
}

static void init_srqc_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				struct tag_hinic5_cqm_cla_table *cla_table,
				struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->srqc_basic_size;
	cla_table->obj_num  = capability->srqc_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->alloc_static = capability->srqc_alloc_static;

	update_entry_cap_for_secure_mem(hinic5_cqm_handle, cla_table, capability);
}

static void init_mpt_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			       struct tag_hinic5_cqm_cla_table *cla_table,
			       struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->mpt_number * capability->mpt_basic_size;
	cla_table->obj_size = capability->mpt_basic_size;
	cla_table->obj_num = capability->mpt_number;
	/* CCB decided. MPT uses only static application scenarios. */
	cla_table->alloc_static = true;

	update_entry_cap_for_secure_mem(hinic5_cqm_handle, cla_table, capability);
}

static void init_gid_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			       struct tag_hinic5_cqm_cla_table *cla_table,
			       struct tag_hinic5_cqm_func_capability *capability)
{
	/* Level-0 CLA table required */
	cla_table->obj_size = capability->gid_basic_size;
	cla_table->obj_num  = capability->gid_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = hinic5_cqm_shift(ALIGN(cla_table->max_buffer_size, PAGE_SIZE) / PAGE_SIZE);
	cla_table->alloc_static = true;
}

static void init_lun_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			       struct tag_hinic5_cqm_cla_table *cla_table,
			       struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->lun_basic_size;
	cla_table->obj_num  = capability->lun_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = CLA_TABLE_PAGE_ORDER;
	cla_table->alloc_static = true;
}

static void init_taskmap_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				   struct tag_hinic5_cqm_cla_table *cla_table,
				   struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->taskmap_basic_size;
	cla_table->obj_num  = capability->taskmap_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = HINIC5_CQM_4K_PAGE_ORDER;
	cla_table->alloc_static = true;
}

static void init_l3i_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			       struct tag_hinic5_cqm_cla_table *cla_table,
			       struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->l3i_basic_size;
	cla_table->obj_num  = capability->l3i_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = CLA_TABLE_PAGE_ORDER;
	cla_table->alloc_static = true;
}

static void init_childc_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				  struct tag_hinic5_cqm_cla_table *cla_table,
				  struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->childc_basic_size;
	cla_table->obj_num  = capability->childc_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->alloc_static = true;
}

static void init_timer_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				 struct tag_hinic5_cqm_cla_table *cla_table,
				 struct tag_hinic5_cqm_func_capability *capability)
{
	/* Ensure that the basic size of the timer buffer page does not
	 * exceed 128 x 4 KB. Otherwise, clearing the timer buffer of
	 * the function is complex.
	 */
	cla_table->obj_size = capability->timer_basic_size;
	cla_table->obj_num  = capability->timer_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = HINIC5_CQM_8K_PAGE_ORDER;
	cla_table->alloc_static = true;

	if (hinic5_cqm_cla_hugepage_hint)
		cla_table->hugepage_hint = true;
}

static void init_xid2cid_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				   struct tag_hinic5_cqm_cla_table *cla_table,
				   struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->obj_size = capability->xid2cid_basic_size;
	cla_table->obj_num = capability->xid2cid_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = HINIC5_CQM_8K_PAGE_ORDER;
	cla_table->alloc_static = true;

	if (capability->bat_cid_index_bit_width > 0)
		cla_table->max_index_bit = capability->bat_cid_index_bit_width - 1;
}

static void init_reorder_entry_cap(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				   struct tag_hinic5_cqm_cla_table *cla_table,
				   struct tag_hinic5_cqm_func_capability *capability)
{
	/* This entry supports only IWARP and doesn't support GPA validity check. */
	cla_table->obj_size = capability->reorder_basic_size;
	cla_table->obj_num  = capability->reorder_number;
	cla_table->max_buffer_size = cla_table->obj_size * cla_table->obj_num;
	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->alloc_static = true;
}

typedef void (*init_entry_cap)(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			       struct tag_hinic5_cqm_cla_table *cla_table,
			       struct tag_hinic5_cqm_func_capability *capability);

static const init_entry_cap init_entry_cap_funcs[HINIC5_CQM_BAT_ENTRY_T_MAX] = {
	NULL, /* HINIC5_CQM_BAT_ENTRY_T_CFG */
	init_hash_entry_cap,
	init_qpc_entry_cap,
	init_scqc_entry_cap,
	init_srqc_entry_cap,
	init_mpt_entry_cap,
	init_gid_entry_cap,
	init_lun_entry_cap,
	init_taskmap_entry_cap,
	init_l3i_entry_cap,
	init_childc_entry_cap,
	init_timer_entry_cap,
	init_xid2cid_entry_cap,
	init_reorder_entry_cap,
	NULL, /* HINIC5_CQM_BAT_ENTRY_T_INVALID */
};

static void hinic5_cqm_cla_init_entry_capability(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					  struct tag_hinic5_cqm_cla_table *cla_table,
					  struct tag_hinic5_cqm_func_capability *capability)
{
	cla_table->max_index_bit = HINIC5_CQM_MAX_INDEX_BIT_DEFAULT;

	if (cla_table->type < ARRAY_SIZE(init_entry_cap_funcs) &&
	    init_entry_cap_funcs[cla_table->type])
		init_entry_cap_funcs[cla_table->type](hinic5_cqm_handle, cla_table, capability);
}

static s32 hinic5_cqm_cla_init_entry_memory(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 entry_idx)
{
	struct hinic5_hwdev *hwdev = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_cla_table *cla_table = &bat_table->entry[entry_idx];
	struct tag_hinic5_cqm_cla_table *cla_table_tmp = NULL;
	u32 entry_type = cla_table->type;
	u32 i;
	int ret;

	/* When the SMF API LB is mode 1 or 2, some entries need to be
	 * configured for all enabled SMFs and the address space is independent.
	 */
	if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle) &&
	    (entry_type == HINIC5_CQM_BAT_ENTRY_T_TIMER || entry_type == HINIC5_CQM_BAT_ENTRY_T_HASH ||
	     (entry_type == HINIC5_CQM_BAT_ENTRY_T_XID2CID && COMM_SUPPORT_VIRTIO_FC_CACHE(hwdev)))) {
		for (i = 0; i < hinic5_cqm_handle->func_capability.smf_max_num; i++) {
			if (cla_table->type == HINIC5_CQM_BAT_ENTRY_T_TIMER)
				cla_table_tmp = &bat_table->timer_entry[i];
			else if (entry_type == HINIC5_CQM_BAT_ENTRY_T_HASH)
				cla_table_tmp = &bat_table->hash_entry[i];
			else
				cla_table_tmp = &bat_table->xid2cid_entry[i];

			memcpy(cla_table_tmp,
				       cla_table, sizeof(struct tag_hinic5_cqm_cla_table));

			ret = snprintf(cla_table_tmp->name, HINIC5_VRAM_NAME_MAX_LEN,
				 "%s%s%01u", cla_table->name,
				 HINIC5_VRAM_HINIC5_CQM_CLA_SMF_BASE, i);
			if (ret < 0) {
				hinic5_cqm_err(hinic5_cqm_handle->ex_handle->dev_hdl,
					"hinic5_cqm cla timer hinic5_vram name snprintf_s failed");
				hinic5_cqm_cla_uninit(hinic5_cqm_handle, entry_idx);
				return HINIC5_CQM_FAIL;
			}

			if (hinic5_cqm_cla_xyz(hinic5_cqm_handle, cla_table_tmp) ==
			    HINIC5_CQM_FAIL) {
				hinic5_cqm_cla_uninit(hinic5_cqm_handle, entry_idx);
				return HINIC5_CQM_FAIL;
			}
		}
		return HINIC5_CQM_SUCCESS;
	}

	if (hinic5_cqm_cla_xyz(hinic5_cqm_handle, cla_table) == HINIC5_CQM_FAIL) {
		hinic5_cqm_cla_uninit(hinic5_cqm_handle, entry_idx);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_cla_init_entry(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			      struct tag_hinic5_cqm_func_capability *capability)
{
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	s32 ret;
	u32 i = 0;
	int err;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		cla_table->type = bat_table->bat_entry_type[i];

		err = snprintf(cla_table->name, HINIC5_VRAM_NAME_MAX_LEN,
			       "%s%s%s%02u", hinic5_cqm_handle->name, HINIC5_VRAM_HINIC5_CQM_CLA_BASE,
			       HINIC5_VRAM_HINIC5_CQM_CLA_TYPE_BASE, cla_table->type);
		if (err < 0) {
			hinic5_cqm_err(hinic5_cqm_handle->ex_handle->dev_hdl,
				"hinic5_cqm cla table hinic5_vram name snprintf_s failed");
			return HINIC5_CQM_FAIL;
		}

		mutex_init(&cla_table->lock);

		hinic5_cqm_cla_init_entry_capability(hinic5_cqm_handle, cla_table, capability);

		/* Those entries don't need to alloc memory */
		if (cla_table->type < HINIC5_CQM_BAT_ENTRY_T_HASH ||
		    cla_table->type > HINIC5_CQM_BAT_ENTRY_T_REORDER) {
			continue;
		}

		/* Timer entry is only deployed in PPF */
		if (cla_table->type == HINIC5_CQM_BAT_ENTRY_T_TIMER &&
		    !HINIC5_CQM_IS_PPF(hinic5_cqm_handle))
			continue;

		ret = hinic5_cqm_cla_init_entry_memory(hinic5_cqm_handle, i);
		if (ret != HINIC5_CQM_SUCCESS)
			return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static u32 hinic5_cqm_cla_get_ctx_mem_size(struct tag_hinic5_cqm_func_capability *capability, u32 cla_type)
{
	u32 basic_size;
	u32 num;

	switch (cla_type) {
	case HINIC5_CQM_BAT_ENTRY_T_SCQC:
		basic_size = capability->scqc_basic_size;
		num = capability->scqc_number;
		break;

	case HINIC5_CQM_BAT_ENTRY_T_SRQC:
		basic_size = capability->srqc_basic_size;
		num = capability->srqc_number;
		break;
	case HINIC5_CQM_BAT_ENTRY_T_QPC:
		basic_size = capability->qpc_basic_size;
		num = capability->qpc_number;
		break;
	case HINIC5_CQM_BAT_ENTRY_T_MPT:
		basic_size = capability->mpt_basic_size;
		num = capability->mpt_number;
		break;
	default:
		return 0;
	}

	return basic_size * num;
}

#if defined(__UEFI__) || defined(SECURE_MEM_STUB)
static s32 hinic5_cqm_stub_get_func_secure_mem_size(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					     struct tag_hinic5_cqm_func_capability *capability,
					     u32 *total_size)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 cla_type[] = { HINIC5_CQM_BAT_ENTRY_T_SCQC,
			   HINIC5_CQM_BAT_ENTRY_T_QPC,
			   HINIC5_CQM_BAT_ENTRY_T_MPT,
			   HINIC5_CQM_BAT_ENTRY_T_SRQC };
	u32 cla_num = sizeof(cla_type) / sizeof(cla_type[0]);
	u32 mem_size, i;

	/* mem size check */
	for (i = 0; i < cla_num; i++) {
		mem_size = hinic5_cqm_cla_get_ctx_mem_size(capability, cla_type[i]);
		if (!HINIC5_CQM_IS_SECURE_MEMSIZE_VALID(mem_size)) {
			hinic5_cqm_err(handle->dev_hdl,
				"%s: mem check failed, type=%d, mem_size=0x%x\n",
				__func__, cla_type[i], mem_size);
			return HINIC5_CQM_FAIL;
		}
		*total_size += mem_size;
	}

	return HINIC5_CQM_SUCCESS;
}

/* Currently secure mem stub is allocated by SDK; for production, it will be allocated by QEMU and read from SML table */
static s32 hinic5_cqm_stub_alloc_secure_mem(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				     struct tag_hinic5_cqm_func_capability *capability)
{
	struct hinic5_cqm_secure_mem_info *secure_mem_info = &hinic5_cqm_handle->bat_table.func_secure_mem;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct device *dev = hinic5_cqm_handle->dev;
	u32 secure_mem_size = 0;
	u32 ret, order, map_size;

	ret = hinic5_cqm_stub_get_func_secure_mem_size(hinic5_cqm_handle, capability, &secure_mem_size);
	if (ret != HINIC5_CQM_SUCCESS)
		return ret;

	order = (u32)get_order(secure_mem_size);
	/* map total mem size(2^n) */
	map_size = 1 << (order + PAGE_SHIFT);
	hinic5_cqm_info(handle->dev_hdl, "total_mem_size=0x%x, map_size=0x%x, order=%d\n",
		 secure_mem_size, map_size, order);
	secure_mem_info->addr.va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!secure_mem_info->addr.va) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(secure_mem));
		return HINIC5_CQM_FAIL;
	}

	secure_mem_info->len = map_size;
	secure_mem_info->addr.pa = dma_map_single(dev, secure_mem_info->addr.va, map_size,
						  DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, secure_mem_info->addr.pa)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(secure_mem));
		free_pages((ulong)secure_mem_info->addr.va, order);
		return HINIC5_CQM_FAIL;
	}
	return HINIC5_CQM_SUCCESS;
}

#else

/* Get VF secure memory address from SML table and do mapping */
static s32 hinic5_cqm_cla_get_secure_mem(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_cqm_secure_mem_info *secure_mem_info = &hinic5_cqm_handle->bat_table.func_secure_mem;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	s32 ret;

	ret = hinic5_get_secure_mem_cfg(handle, &secure_mem_info->addr.pa, &secure_mem_info->len);
	if (ret == HINIC5_CQM_CONTINUE) {
		secure_mem_en = false;
		return HINIC5_CQM_SUCCESS;
	} else if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, "failed to get secure mem, ret: %d, func_id %hu\n",
			ret, hinic5_global_func_id((void *)handle));
		return HINIC5_CQM_FAIL;
	}

	secure_mem_info->addr.va = ioremap(secure_mem_info->addr.pa, secure_mem_info->len);
	if (!secure_mem_info->addr.va) {
		hinic5_cqm_err(handle->dev_hdl,
			"failed to remap secure mem, func_id %u, gpa=0x%llx, len=0x%x\n",
			hinic5_global_func_id((void *)handle), (u64)secure_mem_info->addr.pa,
			secure_mem_info->len);
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_info(handle->dev_hdl,
		"get secure mem: func_id=0x%x, gpa=0x%llx, va=0x%lx, len=0x%x\n",
		hinic5_global_func_id((void *)handle), (u64)secure_mem_info->addr.pa,
		(uintptr_t)secure_mem_info->addr.va, secure_mem_info->len);
	return HINIC5_CQM_SUCCESS;
}
#endif

#if defined(__UEFI__) || defined(SECURE_MEM_STUB)
/* Currently secure mem stub is allocated by SDK, memory is freed if ctx size is invalid; for production, Qemu will free it */
static void hinic5_cqm_free_secure_mem(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_cqm_secure_mem_info *secure_mem_info = &hinic5_cqm_handle->bat_table.func_secure_mem;
	struct device *dev = hinic5_cqm_handle->dev;
	u32 order;

	if (secure_mem_info->addr.va) {
		order = (u32)get_order(secure_mem_info->len);
		dma_unmap_single(dev, secure_mem_info->addr.pa,
				 secure_mem_info->len,
				 DMA_BIDIRECTIONAL);
		free_pages((ulong)(secure_mem_info->addr.va), order);
		secure_mem_info->addr.va = NULL;
	}
}
#else
static void hinic5_cqm_free_secure_mem(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_cqm_secure_mem_info *secure_mem_info = &hinic5_cqm_handle->bat_table.func_secure_mem;

	if (secure_mem_en && secure_mem_info->addr.va != NULL) {
		iounmap(secure_mem_info->addr.va);
		secure_mem_info->addr.va = NULL;
	}
}
#endif

static struct tag_hinic5_cqm_cla_table *hinic5_cqm_cla_get_entry(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 cla_type)
{
	u32 *bat_entry_type = hinic5_cqm_handle->bat_table.bat_entry_type;
	struct tag_hinic5_cqm_cla_table *cla_entry = hinic5_cqm_handle->bat_table.entry;
	u32 i;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		if (bat_entry_type[i] == cla_type)
			return &cla_entry[i];
	}

	return NULL;
}

static s32 hinic5_cqm_cla_secure_mem_assign(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_func_capability *capability,
				     u32 cla_type, u32 *mem_offset)
{
	struct hinic5_cqm_secure_mem_info *secure_mem_info = &hinic5_cqm_handle->bat_table.func_secure_mem;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_cla_table *cla_entry = NULL;
	u32 cla_mem_size;

	cla_entry = hinic5_cqm_cla_get_entry(hinic5_cqm_handle, cla_type);
	if (!cla_entry) {
		hinic5_cqm_err(handle->dev_hdl, "Get cla entry failed: cla_type=%u\n", cla_type);
		return HINIC5_CQM_FAIL;
	}
	cla_entry->secure_mem.va = secure_mem_info->addr.va + *mem_offset;
	cla_entry->secure_mem.pa = secure_mem_info->addr.pa + *mem_offset;

	cla_mem_size = hinic5_cqm_cla_get_ctx_mem_size(capability, cla_type);

	*mem_offset += cla_mem_size;
	if (*mem_offset >= secure_mem_info->len) {
		hinic5_cqm_err(handle->dev_hdl, "Mem size exceeds: mem_offset=0x%x, max_size=0x%x\n",
			*mem_offset, secure_mem_info->len);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_cla_secure_mem_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *capability = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	/* SCQC must be first (UB-VTP Table Use SCQC) */
	u32 cla_type[] = { HINIC5_CQM_BAT_ENTRY_T_SCQC,
			   HINIC5_CQM_BAT_ENTRY_T_QPC,
			   HINIC5_CQM_BAT_ENTRY_T_MPT,
			   HINIC5_CQM_BAT_ENTRY_T_SRQC };
	u32 cla_num = sizeof(cla_type) / sizeof(cla_type[0]);
	u32 mem_offset = 0;
	s32 ret;
	u32 i;

	/* Currently secure mem stub is allocated by SDK; for production, it will be allocated by QEMU and read from VF BAR space */
#if defined(__UEFI__) || defined(SECURE_MEM_STUB)
	if (hinic5_cqm_stub_alloc_secure_mem(hinic5_cqm_handle, capability) != HINIC5_CQM_SUCCESS)
#else
	if ((hinic5_cqm_cla_get_secure_mem(hinic5_cqm_handle)) != HINIC5_CQM_SUCCESS)
#endif
		return HINIC5_CQM_FAIL;

	if (!secure_mem_en) {
		return HINIC5_CQM_SUCCESS;
	}

	for (i = 0; i < cla_num; i++) {
		ret = hinic5_cqm_cla_secure_mem_assign(hinic5_cqm_handle, capability, cla_type[i], &mem_offset);
		if (ret != HINIC5_CQM_SUCCESS) {
			hinic5_cqm_err(handle->dev_hdl, "Cla secure mem assign failed: cla_type=%u\n", cla_type[i]);
			hinic5_cqm_free_secure_mem(hinic5_cqm_handle);
			return HINIC5_CQM_FAIL;
		}
	}

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_cla_init
 * Description  : Initialize the CLA table.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/5/15
 *   Modification : Created function
 */
s32 hinic5_cqm_cla_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *capability = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	s32 ret;

	if (secure_mem_en && HINIC5_CQM_IS_VF(hinic5_cqm_handle)) {
		if (unlikely(hinic5_cqm_cla_secure_mem_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS)) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(secure_mem_init));
			return HINIC5_CQM_FAIL;
		}
	}

	/* Applying for CLA Entries */
	if (hinic5_cqm_cla_init_entry(hinic5_cqm_handle, capability) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_init_entry));
		return HINIC5_CQM_FAIL;
	}

	/* The BAT and CLA of the Fake VF are maintained by the parent function. */
	if (HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle)) {
		return hinic5_cqm_cla_reset(hinic5_cqm_handle);
	}

	/* After the CLA entry is applied, the address is filled
	 * in the BAT table.
	 */
	hinic5_cqm_bat_fill_cla(hinic5_cqm_handle);

	/* Instruct the chip to update the BAT table. */
	if (hinic5_cqm_bat_update(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bat_update));
		goto err;
	}

	hinic5_cqm_info(handle->dev_hdl, "Timer start: func_type=%d, timer_enable=%u\n",
		 hinic5_cqm_handle->func_attribute.func_type,
		 hinic5_cqm_handle->func_capability.timer_enable);

	if (HINIC5_CQM_IS_PPF(hinic5_cqm_handle) &&
	    hinic5_cqm_handle->func_capability.timer_enable == HINIC5_CQM_TIMER_ENABLE) {
		/* Enable the timer after the timer resources are applied for */
		ret = hinic5_ppf_tmr_start(handle);
		if (ret != HINIC5_CQM_SUCCESS) {
			hinic5_cqm_err(handle->dev_hdl, "PPF timer start failed, err %d\n", ret);
			goto err;
		}
	}

	return HINIC5_CQM_SUCCESS;

err:
	hinic5_cqm_cla_uninit(hinic5_cqm_handle, HINIC5_CQM_BAT_ENTRY_MAX);
	return HINIC5_CQM_FAIL;
}

/* Inverse operation of hinic5_cqm_cla_xyz() */
static void hinic5_cqm_cla_table_free_cache_inv(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					 struct tag_hinic5_cqm_cla_table *cla_table,
					 s32 *inv_flag)
{
	/* The CLA memory are maintained by the parent function. */
	if (HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle))
		return;

	hinic5_cqm_buf_free_cache_inv(hinic5_cqm_handle, &cla_table->cla_x_buf, inv_flag);
	hinic5_cqm_buf_free_cache_inv(hinic5_cqm_handle, &cla_table->cla_y_buf, inv_flag);
	hinic5_cqm_buf_free_cache_inv(hinic5_cqm_handle, &cla_table->cla_z_buf, inv_flag);
}

STATIC INLINE void hinic5_cqm_cla_uninit_entry(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					struct tag_hinic5_cqm_cla_table *cla_table,
					s32 *inv_flag)
{
	if (cla_table->type != HINIC5_CQM_BAT_ENTRY_T_INVALID)
		hinic5_cqm_cla_table_free_cache_inv(hinic5_cqm_handle, cla_table, inv_flag);
	mutex_deinit(&cla_table->lock);
}

/**
 * Prototype    : hinic5_cqm_cla_uninit
 * Description  : Deinitialize the CLA table.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/15
 *   Modification : Created function
 */
void hinic5_cqm_cla_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 entry_numb)
{
	struct hinic5_hwdev *hwdev = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	s32 inv_flag = 0;
	u32 i;

	for (i = 0; i < entry_numb; i++) {
		cla_table = &bat_table->entry[i];
		hinic5_cqm_cla_uninit_entry(hinic5_cqm_handle, cla_table, &inv_flag);
	}

	/* When the lb mode is 1/2, the following entries allocated to all SMFs
	 * needs to be released.
	 */
	if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle) && HINIC5_CQM_IS_PPF(hinic5_cqm_handle)) {
		for (i = 0; i < hinic5_cqm_handle->func_capability.smf_max_num; i++) {
			cla_table = &bat_table->timer_entry[i];
			hinic5_cqm_cla_uninit_entry(hinic5_cqm_handle, cla_table, &inv_flag);
		}
	}

	if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle)) {
		for (i = 0; i < hinic5_cqm_handle->func_capability.smf_max_num; i++) {
			cla_table = &bat_table->hash_entry[i];
			hinic5_cqm_cla_uninit_entry(hinic5_cqm_handle, cla_table, &inv_flag);
		}
	}

	if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle) && COMM_SUPPORT_VIRTIO_FC_CACHE(hwdev)) {
		for (i = 0; i < hinic5_cqm_handle->func_capability.smf_max_num; i++) {
			cla_table = &bat_table->xid2cid_entry[i];
			hinic5_cqm_cla_uninit_entry(hinic5_cqm_handle, cla_table, &inv_flag);
		}
	}

	/* Free secure memory. For production, Qemu will free it */
	hinic5_cqm_free_secure_mem(hinic5_cqm_handle);
}

static s32 hinic5_cqm_cla_update_cmd(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			      struct tag_hinic5_cqm_cmd_buf *buf_in,
			      hinic5_cqm_cla_update_cmd_s *cmd_info)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	s32 ret = HINIC5_CQM_FAIL;
	u8 cmd;

	hinic5_cqm_handle->cmdq_ops->prepare_cmd_buf_cla_update(cmd_info, buf_in, &cmd);
	ret = hinic5_cqm_send_cmd_box((void *)(hinic5_cqm_handle->ex_handle), HINIC5_CQM_MOD_HINIC5_CQM,
			       cmd, buf_in, NULL, NULL,
			       HINIC5_CQM_CMD_TIMEOUT, HINIC5_CHANNEL_DEFAULT);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_send_cmd_box));
		hinic5_cqm_err(handle->dev_hdl, "Cla alloc: hinic5_cqm_cla_update, hinic5_cqm_send_cmd_box_ret=%d\n",
			ret);
		hinic5_cqm_err(handle->dev_hdl, "Cla alloc: hinic5_cqm_cla_update, cla_update_cmd: 0x%x 0x%x 0x%x 0x%x\n",
			cmd_info->gpa_h, cmd_info->gpa_l, cmd_info->value_h, cmd_info->value_l);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static void hinic5_cqm_cla_cmd_init(hinic5_cqm_cla_update_cmd_s *cmd, struct tag_hinic5_cqm_handle *hinic5_cqm_handle, dma_addr_t parant_pa,
	dma_addr_t child_pa, u8 cla_update_mode)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u64 spu_en = 0;
	dma_addr_t pa = 0;
	u8 gpa_check_enable = hinic5_cqm_handle->func_capability.gpa_check_enable;

	spu_en = ((u64)hinic5_cqm_get_acs_spu_en(hinic5_cqm_handle)) << 0x3F;

	pa = (parant_pa | spu_en);
	cmd->gpa_h = HINIC5_CQM_ADDR_HI(pa);
	cmd->gpa_l = HINIC5_CQM_ADDR_LW(pa);

	pa = (child_pa | spu_en);
	cmd->value_h = HINIC5_CQM_ADDR_HI(pa);
	cmd->value_l = HINIC5_CQM_ADDR_LW(pa);

	/* current CLA GPA CHECK */
	if (gpa_check_enable != 0) {
		switch (cla_update_mode) {
		/* gpa[0]=1 means this GPA is valid */
		case HINIC5_CQM_CLA_RECORD_NEW_GPA:
			cmd->value_l |= 1;
			break;
		/* gpa[0]=0 means this GPA is valid */
		case HINIC5_CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID:
		case HINIC5_CQM_CLA_DEL_GPA_WITH_CACHE_INVALID:
			cmd->value_l &= (~1);
			break;
		default:
			hinic5_cqm_err(handle->dev_hdl, "Cla alloc: %s, wrong cla_update_mode=%u\n", __func__, cla_update_mode);
			break;
		}
	}
}

static s32 hinic5_cqm_cla_update_all_smf(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				  hinic5_cqm_cla_update_cmd_s *cmd,
				  struct tag_hinic5_cqm_cmd_buf *buf_in)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	u32 i = 0;
	s32 ret = HINIC5_CQM_FAIL;

	for (i = 0; i < func_cap->smf_max_num; i++) {
		if ((func_cap->smf_pg & (1U << i)) != 0) {
			cmd->smf_id = i;
			ret = hinic5_cqm_cla_update_cmd(hinic5_cqm_handle, buf_in, cmd);
			if (ret != HINIC5_CQM_SUCCESS)
				return ret;
		}
	}
	return ret;
}

/**
 * Prototype    : hinic5_cqm_cla_update
 * Description  : Send a command to update the CLA table.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
 *		  struct tag_hinic5_cqm_buf_list *buf_node_parent parent node of the content to
 *							   be updated
 *		  struct tag_hinic5_cqm_buf_list *buf_node_child  Subnode for which the buffer
 *							   is to be applied
 *		  u32 child_index		  Index of a child node.
 * Output       : None
 * Return Value : s32
 * 1.Date   : 2015/5/15
 *   Modification : Created function
 */
STATIC s32 hinic5_cqm_cla_update(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, const struct tag_hinic5_cqm_buf_list *buf_node_parent,
	const struct tag_hinic5_cqm_buf_list *buf_node_child, u32 child_index, u8 cla_update_mode)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_cmd_buf *buf_in = NULL;
	hinic5_cqm_cla_update_cmd_s cmd;
	s32 ret = HINIC5_CQM_FAIL;

	buf_in = hinic5_cqm_cmd_alloc(hinic5_cqm_handle->ex_handle);
	if (unlikely(buf_in == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(buf_in));
		return HINIC5_CQM_FAIL;
	}

	/* Fill command format, convert to big endian. */
	hinic5_cqm_cla_cmd_init(&cmd, hinic5_cqm_handle, (buf_node_parent->pa + (child_index * sizeof(dma_addr_t))), buf_node_child->pa,
		cla_update_mode);

	hinic5_cqm_dbg(handle->dev_hdl,
		"Cla alloc: %s, gpa=0x%x 0x%x, value=0x%x 0x%x, cla_update_mode=0x%x\n",
		__func__, cmd.gpa_h, cmd.gpa_l, cmd.value_h, cmd.value_l, cla_update_mode);

	/* In non-fake mode, set func_id to 0xffff.
	 * Indicates the current func fake mode, set func_id to the
	 * specified value, This is a fake func_id.
	 */
	if (HINIC5_CQM_IS_FAKE_CHILD_AGENT(hinic5_cqm_handle))
		cmd.func_id = hinic5_cqm_handle->func_attribute.func_global_idx;
	else
		cmd.func_id = 0xffff;

	/* Normal mode is 1822 traditional mode and is configured on SMF0. */
	/* Mode 0 is hashed to 4 SMF engines (excluding PPF) by func ID. */
	if (HINIC5_CQM_IS_LB_MODE_NORMAL(hinic5_cqm_handle) ||
	    (HINIC5_CQM_IS_LB_MODE_0(hinic5_cqm_handle) && !HINIC5_CQM_IS_PPF(hinic5_cqm_handle))) {
		cmd.smf_id = hinic5_cqm_funcid2smfid(hinic5_cqm_handle);
		ret = hinic5_cqm_cla_update_cmd(hinic5_cqm_handle, buf_in, &cmd);
	/* Modes 1/2 are allocated to four SMF engines by flow.
	 * Therefore, one function needs to be allocated to four SMF engines.
	 */
	/* Mode 0 PPF needs to be configured on 4 engines,
	 * and the timer resources need to be shared by the 4 engines.
	 */
	} else if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle) ||
		   (HINIC5_CQM_IS_LB_MODE_0(hinic5_cqm_handle) && HINIC5_CQM_IS_PPF(hinic5_cqm_handle))) {
		ret = hinic5_cqm_cla_update_all_smf(hinic5_cqm_handle, &cmd, buf_in);
	} else {
		hinic5_cqm_err(handle->dev_hdl, "Cla update: unsupported lb mode=%u\n", hinic5_cqm_handle->func_capability.lb_mode);
		ret = HINIC5_CQM_FAIL;
	}

	hinic5_cqm_cmd_free((void *)(hinic5_cqm_handle->ex_handle), buf_in);
	return ret;
}

/**
 * Prototype    : hinic5_cqm_cla_alloc
 * Description  : Trunk page for applying for a CLA.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
 *		  struct tag_hinic5_cqm_cla_table *cla_table,
 *		  struct tag_hinic5_cqm_buf_list *buf_node_parent parent node of the content to
 *							   be updated
 *		  struct tag_hinic5_cqm_buf_list *buf_node_child  subnode for which the buffer
 *							   is to be applied
 *		  u32 child_index		  index of a child node
 * Output	: None
 * Return Value : s32
 * 1.Date : 2015/5/15
 *   Modification : Created function
 */
static s32 hinic5_cqm_cla_alloc(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			 struct tag_hinic5_cqm_cla_table *cla_table,
			 struct tag_hinic5_cqm_buf_list *buf_node_parent,
			 struct tag_hinic5_cqm_buf_list *buf_node_child, u32 child_index)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	s32 ret = HINIC5_CQM_FAIL;

	/* Apply for trunk page */
	buf_node_child->va = (u8 *)(uintptr_t)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						    cla_table->trunk_order);
	if (unlikely(buf_node_child->va == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(va));
		return HINIC5_CQM_FAIL;
	}
	/* PCI mapping */
	buf_node_child->pa = dma_map_single(hinic5_cqm_handle->dev, buf_node_child->va,
					    PAGE_SIZE << cla_table->trunk_order,
					    DMA_BIDIRECTIONAL);
	if (dma_mapping_error(hinic5_cqm_handle->dev, buf_node_child->pa) != 0) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(buf_node_child->pa));
		goto err1;
	}

	/* Notify the chip of trunk_pa so that the chip fills in cla entry */
	ret = hinic5_cqm_cla_update(hinic5_cqm_handle, buf_node_parent, buf_node_child,
			     child_index, HINIC5_CQM_CLA_RECORD_NEW_GPA);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_update));
		goto err2;
	}

	return HINIC5_CQM_SUCCESS;

err2:
	dma_unmap_single(hinic5_cqm_handle->dev, buf_node_child->pa,
			 PAGE_SIZE << cla_table->trunk_order,
			 DMA_BIDIRECTIONAL);
err1:
	free_pages((ulong)(uintptr_t)(buf_node_child->va), cla_table->trunk_order);
	buf_node_child->va = NULL;
	return HINIC5_CQM_FAIL;
}

static void hinic5_cqm_unmap_and_free_pages(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf_list *buf_node, u32 order)
{
	/* Remove PCI mapping from the trunk page */
	dma_unmap_single(hinic5_cqm_handle->dev, buf_node->pa, PAGE_SIZE << order, DMA_BIDIRECTIONAL);

	/* Release trunk page */
	free_pages((ulong)(uintptr_t)(buf_node->va), order);
	buf_node->va = NULL;
}

/**
 * Prototype    : hinic5_cqm_cla_free_without_cache_invalid
 * Description  : Release trunk page of a CLA
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle
 *		  struct tag_hinic5_cqm_cla_table *cla_table
 *		  struct tag_hinic5_cqm_buf_list *buf_node
 * Output	: None
 * Return Value : void
 * 1.Date : 2015/5/15
 *   Modification : Created function
 */
static void hinic5_cqm_cla_free_without_cache_invalid(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			 struct tag_hinic5_cqm_cla_table *cla_table,
			 struct tag_hinic5_cqm_buf_list *buf_node_parent,
			 struct tag_hinic5_cqm_buf_list *buf_node_child,
			 u32 child_index)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	if (hinic5_cqm_cla_update(hinic5_cqm_handle, buf_node_parent, buf_node_child,
		child_index, HINIC5_CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_update));
		return;
	}
	/* Remove PCI mapping from the trunk page and Release trunk page */
	hinic5_cqm_unmap_and_free_pages(hinic5_cqm_handle, buf_node_child, cla_table->trunk_order);
}

STATIC void hinic5_cqm_cla_free_with_cache_invalid(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			 struct tag_hinic5_cqm_cla_table *cla_table,
			 struct tag_hinic5_cqm_buf_list *buf_node_parent,
			 struct tag_hinic5_cqm_buf_list *buf_node_child,
			 u32 child_index)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 trunk_size;

	if (hinic5_cqm_cla_update(hinic5_cqm_handle, buf_node_parent, buf_node_child,
		child_index, HINIC5_CQM_CLA_DEL_GPA_WITH_CACHE_INVALID) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_update));
		return;
	}

	/* invalid cache */
	trunk_size = (u32)(PAGE_SIZE << cla_table->trunk_order);
	if (hinic5_cqm_cla_cache_invalid(hinic5_cqm_handle, buf_node_child->pa, trunk_size) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_cache_invalid));
		return;
	}

	/* Remove PCI mapping from the trunk page and Release trunk page */
	hinic5_cqm_unmap_and_free_pages(hinic5_cqm_handle, buf_node_child, cla_table->trunk_order);
}

static inline u8 *hinic5_cqm_cla_do_get_lvl0(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				      struct tag_hinic5_cqm_cla_table *cla_table,
				      u32 index, u32 count, dma_addr_t *pa)
{
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	u32 offset = 0;

	/* Level 0 CLA pages are statically allocated. */
	offset = index * cla_table->obj_size;
	*pa = cla_z_buf->buf_list->pa + offset;
	return (u8 *)(cla_z_buf->buf_list->va) + offset;
}

static inline u8 *hinic5_cqm_cla_do_get_lvl1(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				      struct tag_hinic5_cqm_cla_table *cla_table,
				      u32 index, u32 count, dma_addr_t *pa)
{
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf_list *buf_node_y = NULL;
	struct tag_hinic5_cqm_buf_list *buf_node_z = NULL;
	u32 y_index = 0;
	u32 z_index = 0;
	u8 *ret_addr = NULL;
	u32 offset = 0;

	z_index = index & ((1U << (cla_table->z + 1)) - 1);
	y_index = index >> (cla_table->z + 1);

	if (y_index >= cla_z_buf->buf_number) {
		hinic5_cqm_err(handle->dev_hdl,
			"Cla get: index exceeds buf_number, y_index %u, z_buf_number %u\n",
			y_index, cla_z_buf->buf_number);
		return NULL;
	}
	buf_node_z = &cla_z_buf->buf_list[y_index];
	buf_node_y = cla_y_buf->buf_list;

	/* The z buf node does not exist, applying for a page first. */
	if (!buf_node_z->va) {
		if (hinic5_cqm_cla_alloc(hinic5_cqm_handle, cla_table, buf_node_y, buf_node_z,
				  y_index) == HINIC5_CQM_FAIL) {
			hinic5_cqm_err(handle->dev_hdl,
				HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_alloc));
			hinic5_cqm_err(handle->dev_hdl,
				"Cla get: cla_table->type=%u\n",
				cla_table->type);
			return NULL;
		}
	}

	hinic5_cqm_dbg_on(hinic5_cqm_verbose, handle->dev_hdl,
		"Cla get: 1L: z_refcount=0x%x, count=0x%x\n",
		buf_node_z->refcount, count);
	buf_node_z->refcount += count;
	offset = z_index * cla_table->obj_size;
	ret_addr = (u8 *)(buf_node_z->va) + offset;
	*pa = buf_node_z->pa + offset;

	return ret_addr;
}

static inline u8 *hinic5_cqm_cla_do_get_lvl2(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				      struct tag_hinic5_cqm_cla_table *cla_table,
				      u32 index, u32 count, dma_addr_t *pa)
{
	struct tag_hinic5_cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf_list *buf_node_x = NULL;
	struct tag_hinic5_cqm_buf_list *buf_node_y = NULL;
	struct tag_hinic5_cqm_buf_list *buf_node_z = NULL;
	u32 z_index = index & ((1U << (cla_table->z + 1)) - 1);
	u32 y_index = (index >> (cla_table->z + 1)) & ((1U << (cla_table->y - cla_table->z)) - 1);
	u32 x_index = index >> (cla_table->y + 1);
	u64 tmp = x_index * ((u32)(PAGE_SIZE << cla_table->trunk_order) / sizeof(dma_addr_t)) + y_index;
	u8 *ret_addr = NULL;
	u32 offset = 0;

	if (x_index >= cla_y_buf->buf_number || tmp >= cla_z_buf->buf_number) {
		hinic5_cqm_err(handle->dev_hdl,
			"Cla get: index exceeds buf_number, x_index %u, y_index %u, y_buf_number %u, z_buf_number %u\n",
			x_index, y_index, cla_y_buf->buf_number, cla_z_buf->buf_number);
		return NULL;
	}

	buf_node_x = cla_x_buf->buf_list;
	buf_node_y = &cla_y_buf->buf_list[x_index];
	buf_node_z = &cla_z_buf->buf_list[tmp];

	/* The y buf node does not exist, applying for pages for y node. */
	if (!buf_node_y->va) {
		if (hinic5_cqm_cla_alloc(hinic5_cqm_handle, cla_table, buf_node_x, buf_node_y, x_index) == HINIC5_CQM_FAIL) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_alloc));
			return NULL;
		}
	}

	/* The z buf node does not exist, applying for pages for z node. */
	if (!buf_node_z->va) {
		if (hinic5_cqm_cla_alloc(hinic5_cqm_handle, cla_table, buf_node_y, buf_node_z, y_index) == HINIC5_CQM_FAIL) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_alloc));
			if (buf_node_y->refcount == 0)
				/* To release node Y, cache_invalid is
				 * required.
				 */
				hinic5_cqm_cla_free_with_cache_invalid(hinic5_cqm_handle, cla_table, buf_node_x, buf_node_y, x_index);
			return NULL;
		}

		hinic5_cqm_dbg_on(hinic5_cqm_verbose, handle->dev_hdl,
			"Cla get: 2L: y_refcount=0x%x\n", buf_node_y->refcount);
		/* reference counting of the y buffer node needs to increase
		 * by 1.
		 */
		buf_node_y->refcount++;
	}

	hinic5_cqm_dbg_on(hinic5_cqm_verbose, handle->dev_hdl,
		   "Cla get: 2L: z_refcount=0x%x, count=0x%x\n", buf_node_z->refcount, count);
	buf_node_z->refcount += count;
	offset = z_index * cla_table->obj_size;
	ret_addr = (u8 *)(buf_node_z->va) + offset;
	*pa = buf_node_z->pa + offset;

	return ret_addr;
}

static inline u8 *hinic5_cqm_cla_do_get(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				 struct tag_hinic5_cqm_cla_table *cla_table,
				 u32 index, u32 count, dma_addr_t *pa)
{
	if (cla_table->cla_lvl == HINIC5_CQM_CLA_LVL_0)
		return hinic5_cqm_cla_do_get_lvl0(hinic5_cqm_handle, cla_table, index, count, pa);
	if (cla_table->cla_lvl == HINIC5_CQM_CLA_LVL_1)
		return hinic5_cqm_cla_do_get_lvl1(hinic5_cqm_handle, cla_table, index, count, pa);
	if (cla_table->cla_lvl == HINIC5_CQM_CLA_LVL_2)
		return hinic5_cqm_cla_do_get_lvl2(hinic5_cqm_handle, cla_table, index, count, pa);
	WARN_ON(true);
	return NULL;
}

/**
 * Prototype	: hinic5_cqm_cla_get
 * Description	: Apply for block buffer in number of count from the index
 *		  position in the cla table. If the buffer is dynamic, this
 * 		  function may block.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
 *		  struct tag_hinic5_cqm_cla_table *cla_table,
 *		  u32 index,
 *		  u32 count,
 *		  dma_addr_t *pa
 * Output	: None
 * Return Value : u8 *
 * 1.Date : 2025/3/15
 *   Modification : Created function
 */
u8 *hinic5_cqm_cla_get(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
		struct tag_hinic5_cqm_cla_table *cla_table,
		u32 index, u32 count, dma_addr_t *pa)
{
	const bool dynamic_alloc = !cla_table->alloc_static;
	u8 *ret_addr = NULL;

	/* The CLA memory of the Fake VF are holded by the parent
	 * function, so the Fake VF can't get the memory. */
	if (HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle))
		return NULL;

	if (index >= cla_table->obj_num)
		return NULL;

	if (dynamic_alloc)
		mutex_lock(&cla_table->lock);

	ret_addr = hinic5_cqm_cla_do_get(hinic5_cqm_handle, cla_table, index, count, pa);

	if (dynamic_alloc)
		mutex_unlock(&cla_table->lock);

	return ret_addr;
}

/**
 * Prototype    : hinic5_cqm_cla_put
 * Description  : Decrease the value of reference counting on the trunk page.
 *		  If the value is 0, the trunk page is released.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
 *		  struct tag_hinic5_cqm_cla_table *cla_table,
 *		  u32 index,
 *		  u32 count
 * Output       : None
 * Return Value : void
 * 1.Date : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_cla_put(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_cla_table *cla_table, u32 index, u32 count)
{
	struct tag_hinic5_cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	struct tag_hinic5_cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct tag_hinic5_cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf_list *buf_node_z = NULL;
	struct tag_hinic5_cqm_buf_list *buf_node_y = NULL;
	struct tag_hinic5_cqm_buf_list *buf_node_x = NULL;
	u32 x_index = 0;
	u32 y_index = 0;
	u64 tmp;

	/* No buffer is applied for the Fake VF. */
	if (HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle))
		return;

	/* The buffer is applied statically, and the reference counting
	 * does not need to be controlled.
	 */
	if (cla_table->alloc_static)
		return;

	mutex_lock(&cla_table->lock);

	if (cla_table->cla_lvl == HINIC5_CQM_CLA_LVL_1) {
		y_index = index >> (cla_table->z + 1);

		if (y_index >= cla_z_buf->buf_number) {
			hinic5_cqm_err(handle->dev_hdl, "Cla put: idx exceeds buf_number, y_idx %u, z_buf_num %u type %u\n",
				y_index, cla_z_buf->buf_number, cla_table->type);
			goto out;
		}

		buf_node_z = &cla_z_buf->buf_list[y_index];
		buf_node_y = cla_y_buf->buf_list;

		/* When the value of reference counting on the z node page is 0,
		 * the z node page is released.
		 */
		buf_node_z->refcount -= count;
		if (buf_node_z->refcount == 0)
			/* The cache invalid is not required for the Z node. */
			hinic5_cqm_cla_free_without_cache_invalid(hinic5_cqm_handle, cla_table, buf_node_y, buf_node_z, y_index);
	} else if (cla_table->cla_lvl == HINIC5_CQM_CLA_LVL_2) {
		y_index = (index >> (cla_table->z + 1)) & ((1U << (cla_table->y - cla_table->z)) - 1);
		x_index = index >> (cla_table->y + 1);
		tmp = x_index * ((u32)(PAGE_SIZE << cla_table->trunk_order) / sizeof(dma_addr_t)) + y_index;

		if (x_index >= cla_y_buf->buf_number || tmp >= cla_z_buf->buf_number) {
			hinic5_cqm_err(handle->dev_hdl,
				"Cla put: index exceeds buf_number, x_index %u, y_index %u, y_buf_number %u, z_buf_number %u\n",
				x_index, y_index, cla_y_buf->buf_number, cla_z_buf->buf_number);
			goto out;
		}

		buf_node_x = cla_x_buf->buf_list;
		buf_node_y = &cla_y_buf->buf_list[x_index];
		buf_node_z = &cla_z_buf->buf_list[tmp];

		/* When the value of reference counting on the z node page is 0,
		 * the z node page is released.
		 */
		buf_node_z->refcount -= count;
		if (buf_node_z->refcount == 0) {
			hinic5_cqm_cla_free_without_cache_invalid(hinic5_cqm_handle, cla_table, buf_node_y, buf_node_z, y_index);

			/* When the value of reference counting on the y node
			 * page is 0, the y node page is released.
			 */
			buf_node_y->refcount--;
			if (buf_node_y->refcount == 0)
				/* Node y requires cache to be invalid. */
				hinic5_cqm_cla_free_with_cache_invalid(hinic5_cqm_handle, cla_table, buf_node_x, buf_node_y, x_index);
		}
	}

out:
	mutex_unlock(&cla_table->lock);
}

/**
 * Prototype    : hinic5_cqm_cla_table_get
 * Description  : Searches for the CLA table data structure corresponding to a
 *		  BAT entry.
 * Input        : struct tag_hinic5_cqm_bat_table *bat_table,
 *		  u32 entry_type
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_cla_table *
 * 1.Date : 2015/4/15
 *   Modification : Created function
 */
struct tag_hinic5_cqm_cla_table *hinic5_cqm_cla_table_get(struct tag_hinic5_cqm_bat_table *bat_table,
					    u32 entry_type)
{
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	u32 i = 0;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if ((cla_table != NULL) && (entry_type == cla_table->type))
			return cla_table;
	}

	return NULL;
}
