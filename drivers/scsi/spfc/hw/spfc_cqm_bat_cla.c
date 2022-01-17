// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_hwdev.h"
#include "sphw_hwif.h"

#include "spfc_cqm_object.h"
#include "spfc_cqm_bitmap_table.h"
#include "spfc_cqm_bat_cla.h"
#include "spfc_cqm_main.h"

static unsigned char cqm_ver = 8;
module_param(cqm_ver, byte, 0644);
MODULE_PARM_DESC(cqm_ver, "for cqm version control (default=8)");

static void
cqm_bat_fill_cla_common_gpa(struct cqm_handle *cqm_handle,
			    struct cqm_cla_table *cla_table,
			    struct cqm_bat_entry_standerd *bat_entry_standerd)
{
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;
	struct sphw_func_attr *func_attr = NULL;
	struct cqm_bat_entry_vf2pf gpa = {0};
	u32 cla_gpa_h = 0;
	dma_addr_t pa;

	if (cla_table->cla_lvl == CQM_CLA_LVL_0)
		pa = cla_table->cla_z_buf.buf_list[0].pa;
	else if (cla_table->cla_lvl == CQM_CLA_LVL_1)
		pa = cla_table->cla_y_buf.buf_list[0].pa;
	else
		pa = cla_table->cla_x_buf.buf_list[0].pa;

	gpa.cla_gpa_h = CQM_ADDR_HI(pa) & CQM_CHIP_GPA_HIMASK;

	/* On the SPU, the value of spu_en in the GPA address
	 * in the BAT is determined by the host ID and fun IDx.
	 */
	if (sphw_host_id(cqm_handle->ex_handle) == CQM_SPU_HOST_ID) {
		func_attr = &cqm_handle->func_attribute;
		gpa.acs_spu_en = func_attr->func_global_idx & 0x1;
	} else {
		gpa.acs_spu_en = 0;
	}

	memcpy(&cla_gpa_h, &gpa, sizeof(u32));
	bat_entry_standerd->cla_gpa_h = cla_gpa_h;

	/* GPA is valid when gpa[0] = 1.
	 * CQM_BAT_ENTRY_T_REORDER does not support GPA validity check.
	 */
	if (cla_table->type == CQM_BAT_ENTRY_T_REORDER)
		bat_entry_standerd->cla_gpa_l = CQM_ADDR_LW(pa);
	else
		bat_entry_standerd->cla_gpa_l = CQM_ADDR_LW(pa) | gpa_check_enable;
}

static void cqm_bat_fill_cla_common(struct cqm_handle *cqm_handle,
				    struct cqm_cla_table *cla_table,
				    u8 *entry_base_addr)
{
	struct cqm_bat_entry_standerd *bat_entry_standerd = NULL;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 cache_line = 0;

	if (cla_table->type == CQM_BAT_ENTRY_T_TIMER && cqm_ver == 8)
		cache_line = CQM_CHIP_TIMER_CACHELINE;
	else
		cache_line = CQM_CHIP_CACHELINE;

	if (cla_table->obj_num == 0) {
		cqm_info(handle->dev_hdl,
			 "Cla alloc: cla_type %u, obj_num=0, don't init bat entry\n",
			 cla_table->type);
		return;
	}

	bat_entry_standerd = (struct cqm_bat_entry_standerd *)entry_base_addr;

	/* The QPC value is 256/512/1024 and the timer value is 512.
	 * The other cacheline value is 256B.
	 * The conversion operation is performed inside the chip.
	 */
	if (cla_table->obj_size > cache_line) {
		if (cla_table->obj_size == CQM_OBJECT_512)
			bat_entry_standerd->entry_size = CQM_BAT_ENTRY_SIZE_512;
		else
			bat_entry_standerd->entry_size = CQM_BAT_ENTRY_SIZE_1024;
		bat_entry_standerd->max_number = cla_table->max_buffer_size / cla_table->obj_size;
	} else {
		if (cache_line == CQM_CHIP_CACHELINE) {
			bat_entry_standerd->entry_size = CQM_BAT_ENTRY_SIZE_256;
			bat_entry_standerd->max_number = cla_table->max_buffer_size / cache_line;
		} else {
			bat_entry_standerd->entry_size = CQM_BAT_ENTRY_SIZE_512;
			bat_entry_standerd->max_number = cla_table->max_buffer_size / cache_line;
		}
	}

	bat_entry_standerd->max_number = bat_entry_standerd->max_number - 1;

	bat_entry_standerd->bypass = CQM_BAT_NO_BYPASS_CACHE;
	bat_entry_standerd->z = cla_table->cacheline_z;
	bat_entry_standerd->y = cla_table->cacheline_y;
	bat_entry_standerd->x = cla_table->cacheline_x;
	bat_entry_standerd->cla_level = cla_table->cla_lvl;

	cqm_bat_fill_cla_common_gpa(cqm_handle, cla_table, bat_entry_standerd);
}

static void cqm_bat_fill_cla_cfg(struct cqm_handle *cqm_handle,
				 struct cqm_cla_table *cla_table,
				 u8 **entry_base_addr)
{
	struct cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct cqm_bat_entry_cfg *bat_entry_cfg = NULL;

	bat_entry_cfg = (struct cqm_bat_entry_cfg *)(*entry_base_addr);
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
	if ((func_cap->hash_number >> CQM_HASH_NUMBER_UNIT) != 0) {
		bat_entry_cfg->bucket_num = ((func_cap->hash_number >>
					      CQM_HASH_NUMBER_UNIT) - 1);
	}
	if (func_cap->bloomfilter_length != 0) {
		bat_entry_cfg->bloom_filter_len = func_cap->bloomfilter_length -
						  1;
		bat_entry_cfg->bloom_filter_addr = func_cap->bloomfilter_addr;
	}

	(*entry_base_addr) += sizeof(struct cqm_bat_entry_cfg);
}

static void cqm_bat_fill_cla_other(struct cqm_handle *cqm_handle,
				   struct cqm_cla_table *cla_table,
				   u8 **entry_base_addr)
{
	cqm_bat_fill_cla_common(cqm_handle, cla_table, *entry_base_addr);

	(*entry_base_addr) += sizeof(struct cqm_bat_entry_standerd);
}

static void cqm_bat_fill_cla_taskmap(struct cqm_handle *cqm_handle,
				     struct cqm_cla_table *cla_table,
				     u8 **entry_base_addr)
{
	struct cqm_bat_entry_taskmap *bat_entry_taskmap = NULL;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	int i;

	if (cqm_handle->func_capability.taskmap_number != 0) {
		bat_entry_taskmap =
		    (struct cqm_bat_entry_taskmap *)(*entry_base_addr);
		for (i = 0; i < CQM_BAT_ENTRY_TASKMAP_NUM; i++) {
			bat_entry_taskmap->addr[i].gpa_h =
			    (u32)(cla_table->cla_z_buf.buf_list[i].pa >>
				  CQM_CHIP_GPA_HSHIFT);
			bat_entry_taskmap->addr[i].gpa_l =
			    (u32)(cla_table->cla_z_buf.buf_list[i].pa &
				  CQM_CHIP_GPA_LOMASK);
			cqm_info(handle->dev_hdl,
				 "Cla alloc: taskmap bat entry: 0x%x 0x%x\n",
				 bat_entry_taskmap->addr[i].gpa_h,
				 bat_entry_taskmap->addr[i].gpa_l);
		}
	}

	(*entry_base_addr) += sizeof(struct cqm_bat_entry_taskmap);
}

static void cqm_bat_fill_cla_timer(struct cqm_handle *cqm_handle,
				   struct cqm_cla_table *cla_table,
				   u8 **entry_base_addr)
{
	/* Only the PPF allocates timer resources. */
	if (cqm_handle->func_attribute.func_type != CQM_PPF) {
		(*entry_base_addr) += CQM_BAT_ENTRY_SIZE;
	} else {
		cqm_bat_fill_cla_common(cqm_handle, cla_table, *entry_base_addr);

		(*entry_base_addr) += sizeof(struct cqm_bat_entry_standerd);
	}
}

static void cqm_bat_fill_cla_invalid(struct cqm_handle *cqm_handle,
				     struct cqm_cla_table *cla_table,
				     u8 **entry_base_addr)
{
	(*entry_base_addr) += CQM_BAT_ENTRY_SIZE;
}

static void cqm_bat_fill_cla(struct cqm_handle *cqm_handle)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table *cla_table = NULL;
	u32 entry_type = CQM_BAT_ENTRY_T_INVALID;
	u8 *entry_base_addr = NULL;
	u32 i = 0;

	/* Fills each item in the BAT table according to the BAT format. */
	entry_base_addr = bat_table->bat;
	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		entry_type = bat_table->bat_entry_type[i];
		cla_table = &bat_table->entry[i];

		if (entry_type == CQM_BAT_ENTRY_T_CFG)
			cqm_bat_fill_cla_cfg(cqm_handle, cla_table, &entry_base_addr);
		else if (entry_type == CQM_BAT_ENTRY_T_TASKMAP)
			cqm_bat_fill_cla_taskmap(cqm_handle, cla_table, &entry_base_addr);
		else if (entry_type == CQM_BAT_ENTRY_T_INVALID)
			cqm_bat_fill_cla_invalid(cqm_handle, cla_table, &entry_base_addr);
		else if (entry_type == CQM_BAT_ENTRY_T_TIMER)
			cqm_bat_fill_cla_timer(cqm_handle, cla_table, &entry_base_addr);
		else
			cqm_bat_fill_cla_other(cqm_handle, cla_table, &entry_base_addr);

		/* Check whether entry_base_addr is out-of-bounds array. */
		if (entry_base_addr >= (bat_table->bat + CQM_BAT_ENTRY_MAX * CQM_BAT_ENTRY_SIZE))
			break;
	}
}

u32 cqm_funcid2smfid(struct cqm_handle *cqm_handle)
{
	u32 funcid = 0;
	u32 smf_sel = 0;
	u32 smf_id = 0;
	u32 smf_pg_partial = 0;
	/* SMF_Selection is selected based on
	 * the lower two bits of the function id
	 */
	u32 lbf_smfsel[4] = {0, 2, 1, 3};
	/* SMFID is selected based on SMF_PG[1:0] and SMF_Selection(0-1) */
	u32 smfsel_smfid01[4][2] = { {0, 0}, {0, 0}, {1, 1}, {0, 1} };
	/* SMFID is selected based on SMF_PG[3:2] and SMF_Selection(2-4) */
	u32 smfsel_smfid23[4][2] = { {2, 2}, {2, 2}, {3, 3}, {2, 3} };

	/* When the LB mode is disabled, SMF0 is always returned. */
	if (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_NORMAL) {
		smf_id = 0;
	} else {
		funcid = cqm_handle->func_attribute.func_global_idx & 0x3;
		smf_sel = lbf_smfsel[funcid];

		if (smf_sel < 2) {
			smf_pg_partial = cqm_handle->func_capability.smf_pg & 0x3;
			smf_id = smfsel_smfid01[smf_pg_partial][smf_sel];
		} else {
			smf_pg_partial = (cqm_handle->func_capability.smf_pg >> 2) & 0x3;
			smf_id = smfsel_smfid23[smf_pg_partial][smf_sel - 2];
		}
	}

	return smf_id;
}

/* This function is used in LB mode 1/2. The timer spoker info
 * of independent space needs to be configured for 4 SMFs.
 */
static void cqm_update_timer_gpa(struct cqm_handle *cqm_handle, u32 smf_id)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table *cla_table = NULL;
	u32 entry_type = CQM_BAT_ENTRY_T_INVALID;
	u8 *entry_base_addr = NULL;
	u32 i = 0;

	if (cqm_handle->func_attribute.func_type != CQM_PPF)
		return;

	if (cqm_handle->func_capability.lb_mode != CQM_LB_MODE_1 &&
	    cqm_handle->func_capability.lb_mode != CQM_LB_MODE_2)
		return;

	cla_table = &bat_table->timer_entry[smf_id];
	entry_base_addr = bat_table->bat;
	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		entry_type = bat_table->bat_entry_type[i];

		if (entry_type == CQM_BAT_ENTRY_T_TIMER) {
			cqm_bat_fill_cla_timer(cqm_handle, cla_table, &entry_base_addr);
			break;
		}

		if (entry_type == CQM_BAT_ENTRY_T_TASKMAP)
			entry_base_addr += sizeof(struct cqm_bat_entry_taskmap);
		else
			entry_base_addr += CQM_BAT_ENTRY_SIZE;

		/* Check whether entry_base_addr is out-of-bounds array. */
		if (entry_base_addr >=
		    (bat_table->bat + CQM_BAT_ENTRY_MAX * CQM_BAT_ENTRY_SIZE))
			break;
	}
}

static s32 cqm_bat_update_cmd(struct cqm_handle *cqm_handle, struct cqm_cmd_buf *buf_in,
			      u32 smf_id, u32 func_id)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cmdq_bat_update *bat_update_cmd = NULL;
	s32 ret = CQM_FAIL;

	bat_update_cmd = (struct cqm_cmdq_bat_update *)(buf_in->buf);
	bat_update_cmd->offset = 0;

	if (cqm_handle->bat_table.bat_size > CQM_BAT_MAX_SIZE) {
		cqm_err(handle->dev_hdl,
			"bat_size = %u, which is more than %d.\n",
			cqm_handle->bat_table.bat_size, CQM_BAT_MAX_SIZE);
		return CQM_FAIL;
	}
	bat_update_cmd->byte_len = cqm_handle->bat_table.bat_size;

	memcpy(bat_update_cmd->data, cqm_handle->bat_table.bat, bat_update_cmd->byte_len);

	bat_update_cmd->smf_id = smf_id;
	bat_update_cmd->func_id = func_id;

	cqm_info(handle->dev_hdl, "Bat update: smf_id=%u\n", bat_update_cmd->smf_id);
	cqm_info(handle->dev_hdl, "Bat update: func_id=%u\n", bat_update_cmd->func_id);

	cqm_swab32((u8 *)bat_update_cmd, sizeof(struct cqm_cmdq_bat_update) >> CQM_DW_SHIFT);

	ret = cqm3_send_cmd_box((void *)(cqm_handle->ex_handle), CQM_MOD_CQM,
				CQM_CMD_T_BAT_UPDATE, buf_in, NULL, NULL,
				CQM_CMD_TIMEOUT, SPHW_CHANNEL_DEFAULT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm3_send_cmd_box));
		cqm_err(handle->dev_hdl, "%s: send_cmd_box ret=%d\n", __func__,
			ret);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_bat_update(struct cqm_handle *cqm_handle)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cmd_buf *buf_in = NULL;
	s32 ret = CQM_FAIL;
	u32 smf_id = 0;
	u32 func_id = 0;
	u32 i = 0;

	buf_in = cqm3_cmd_alloc((void *)(cqm_handle->ex_handle));
	CQM_PTR_CHECK_RET(buf_in, CQM_FAIL, CQM_ALLOC_FAIL(buf_in));
	buf_in->size = sizeof(struct cqm_cmdq_bat_update);

	/* In non-fake mode, func_id is set to 0xffff */
	func_id = 0xffff;

	/* The LB scenario is supported.
	 * The normal mode is the traditional mode and is configured on SMF0.
	 * In mode 0, load is balanced to four SMFs based on the func ID (except
	 * the PPF func ID). The PPF in mode 0 needs to be configured on four
	 * SMF, so the timer resources can be shared by the four timer engine.
	 * Mode 1/2 is load balanced to four SMF by flow. Therefore, one
	 * function needs to be configured to four SMF.
	 */
	if (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_NORMAL ||
	    (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_0 &&
	     cqm_handle->func_attribute.func_type != CQM_PPF)) {
		smf_id = cqm_funcid2smfid(cqm_handle);
		ret = cqm_bat_update_cmd(cqm_handle, buf_in, smf_id, func_id);
	} else if ((cqm_handle->func_capability.lb_mode == CQM_LB_MODE_1) ||
		   (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_2) ||
		   ((cqm_handle->func_capability.lb_mode == CQM_LB_MODE_0) &&
		    (cqm_handle->func_attribute.func_type == CQM_PPF))) {
		for (i = 0; i < CQM_LB_SMF_MAX; i++) {
			cqm_update_timer_gpa(cqm_handle, i);

			/* The smf_pg variable stores the currently enabled SMF. */
			if (cqm_handle->func_capability.smf_pg & (1U << i)) {
				smf_id = i;
				ret = cqm_bat_update_cmd(cqm_handle, buf_in, smf_id, func_id);
				if (ret != CQM_SUCCESS)
					goto out;
			}
		}
	} else {
		cqm_err(handle->dev_hdl, "Bat update: unsupport lb mode=%u\n",
			cqm_handle->func_capability.lb_mode);
		ret = CQM_FAIL;
	}

out:
	cqm3_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
	return ret;
}

s32 cqm_bat_init_ft(struct cqm_handle *cqm_handle, struct cqm_bat_table *bat_table,
		    enum func_type function_type)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 i = 0;

	bat_table->bat_entry_type[CQM_BAT_INDEX0] = CQM_BAT_ENTRY_T_CFG;
	bat_table->bat_entry_type[CQM_BAT_INDEX1] = CQM_BAT_ENTRY_T_HASH;
	bat_table->bat_entry_type[CQM_BAT_INDEX2] = CQM_BAT_ENTRY_T_QPC;
	bat_table->bat_entry_type[CQM_BAT_INDEX3] = CQM_BAT_ENTRY_T_SCQC;
	bat_table->bat_entry_type[CQM_BAT_INDEX4] = CQM_BAT_ENTRY_T_LUN;
	bat_table->bat_entry_type[CQM_BAT_INDEX5] = CQM_BAT_ENTRY_T_TASKMAP;

	if (function_type == CQM_PF || function_type == CQM_PPF) {
		bat_table->bat_entry_type[CQM_BAT_INDEX6] = CQM_BAT_ENTRY_T_L3I;
		bat_table->bat_entry_type[CQM_BAT_INDEX7] = CQM_BAT_ENTRY_T_CHILDC;
		bat_table->bat_entry_type[CQM_BAT_INDEX8] = CQM_BAT_ENTRY_T_TIMER;
		bat_table->bat_entry_type[CQM_BAT_INDEX9] = CQM_BAT_ENTRY_T_XID2CID;
		bat_table->bat_entry_type[CQM_BAT_INDEX10] = CQM_BAT_ENTRY_T_REORDER;
		bat_table->bat_size = CQM_BAT_SIZE_FT_PF;
	} else if (function_type == CQM_VF) {
		bat_table->bat_size = CQM_BAT_SIZE_FT_VF;
	} else {
		for (i = 0; i < CQM_BAT_ENTRY_MAX; i++)
			bat_table->bat_entry_type[i] = CQM_BAT_ENTRY_T_INVALID;

		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(function_type));
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_bat_init(struct cqm_handle *cqm_handle)
{
	struct cqm_func_capability *capability = &cqm_handle->func_capability;
	enum func_type function_type = cqm_handle->func_attribute.func_type;
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 i;

	memset(bat_table, 0, sizeof(struct cqm_bat_table));

	/* Initialize the type of each bat entry. */
	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++)
		bat_table->bat_entry_type[i] = CQM_BAT_ENTRY_T_INVALID;

	/* Select BATs based on service types. Currently,
	 * feature-related resources of the VF are stored in the BATs of the VF.
	 */
	if (capability->ft_enable)
		return cqm_bat_init_ft(cqm_handle, bat_table, function_type);

	cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(capability->ft_enable));

	return CQM_FAIL;
}

void cqm_bat_uninit(struct cqm_handle *cqm_handle)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 i;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++)
		bat_table->bat_entry_type[i] = CQM_BAT_ENTRY_T_INVALID;

	memset(bat_table->bat, 0, CQM_BAT_ENTRY_MAX * CQM_BAT_ENTRY_SIZE);

	/* Instruct the chip to update the BAT table. */
	if (cqm_bat_update(cqm_handle) != CQM_SUCCESS)
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_update));
}

s32 cqm_cla_fill_buf(struct cqm_handle *cqm_handle, struct cqm_buf *cla_base_buf,
		     struct cqm_buf *cla_sub_buf, u8 gpa_check_enable)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct sphw_func_attr *func_attr = NULL;
	dma_addr_t *base = NULL;
	u64 fake_en = 0;
	u64 spu_en = 0;
	u64 pf_id = 0;
	u32 i = 0;
	u32 addr_num;
	u32 buf_index = 0;

	/* Apply for space for base_buf */
	if (!cla_base_buf->buf_list) {
		if (cqm_buf_alloc(cqm_handle, cla_base_buf, false) ==
		    CQM_FAIL) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(cla_base_buf));
			return CQM_FAIL;
		}
	}

	/* Apply for space for sub_buf */
	if (!cla_sub_buf->buf_list) {
		if (cqm_buf_alloc(cqm_handle, cla_sub_buf, false) == CQM_FAIL) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(cla_sub_buf));
			cqm_buf_free(cla_base_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
	}

	/* Fill base_buff with the gpa of sub_buf */
	addr_num = cla_base_buf->buf_size / sizeof(dma_addr_t);
	base = (dma_addr_t *)(cla_base_buf->buf_list[0].va);
	for (i = 0; i < cla_sub_buf->buf_number; i++) {
		/* The SPU SMF supports load balancing from the SMF to the CPI,
		 * depending on the host ID and func ID.
		 */
		if (sphw_host_id(cqm_handle->ex_handle) == CQM_SPU_HOST_ID) {
			func_attr = &cqm_handle->func_attribute;
			spu_en = (u64)(func_attr->func_global_idx & 0x1) << 63;
		} else {
			spu_en = 0;
		}

		*base = (((((cla_sub_buf->buf_list[i].pa & CQM_CHIP_GPA_MASK) |
			    spu_en) |
			   fake_en) |
			  pf_id) |
			 gpa_check_enable);

		cqm_swab64((u8 *)base, 1);
		if ((i + 1) % addr_num == 0) {
			buf_index++;
			if (buf_index < cla_base_buf->buf_number)
				base = cla_base_buf->buf_list[buf_index].va;
		} else {
			base++;
		}
	}

	return CQM_SUCCESS;
}

s32 cqm_cla_xyz_lvl1(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		     u32 trunk_size)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf *cla_y_buf = NULL;
	struct cqm_buf *cla_z_buf = NULL;
	s32 shift = 0;
	s32 ret = CQM_FAIL;
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;
	u32 cache_line = 0;

	if (cla_table->type == CQM_BAT_ENTRY_T_TIMER && cqm_ver == 8)
		cache_line = CQM_CHIP_TIMER_CACHELINE;
	else
		cache_line = CQM_CHIP_CACHELINE;

	if (cla_table->type == CQM_BAT_ENTRY_T_REORDER)
		gpa_check_enable = 0;

	cla_table->cla_lvl = CQM_CLA_LVL_1;

	shift = cqm_shift(trunk_size / cla_table->obj_size);
	cla_table->z = shift ? (shift - 1) : (shift);
	cla_table->y = CQM_MAX_INDEX_BIT;
	cla_table->x = 0;

	if (cla_table->obj_size >= cache_line) {
		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;
	} else {
		shift = cqm_shift(trunk_size / cache_line);
		cla_table->cacheline_z = shift ? (shift - 1) : (shift);
		cla_table->cacheline_y = CQM_MAX_INDEX_BIT;
		cla_table->cacheline_x = 0;
	}

	/* Applying for CLA_Y_BUF Space */
	cla_y_buf = &cla_table->cla_y_buf;
	cla_y_buf->buf_size = trunk_size;
	cla_y_buf->buf_number = 1;
	cla_y_buf->page_number = cla_y_buf->buf_number <<
				 cla_table->trunk_order;
	ret = cqm_buf_alloc(cqm_handle, cla_y_buf, false);
	CQM_CHECK_EQUAL_RET(handle->dev_hdl, ret, CQM_SUCCESS, CQM_FAIL,
			    CQM_ALLOC_FAIL(lvl_1_y_buf));

	/* Applying for CLA_Z_BUF Space */
	cla_z_buf = &cla_table->cla_z_buf;
	cla_z_buf->buf_size = trunk_size;
	cla_z_buf->buf_number =
	    (ALIGN(cla_table->max_buffer_size, trunk_size)) / trunk_size;
	cla_z_buf->page_number = cla_z_buf->buf_number <<
				 cla_table->trunk_order;
	/* All buffer space must be statically allocated. */
	if (cla_table->alloc_static) {
		ret = cqm_cla_fill_buf(cqm_handle, cla_y_buf, cla_z_buf,
				       gpa_check_enable);
		CQM_CHECK_EQUAL_RET(handle->dev_hdl, ret, CQM_SUCCESS, CQM_FAIL,
				    CQM_FUNCTION_FAIL(cqm_cla_fill_buf));
	} else { /* Only the buffer list space is initialized. The buffer space
		  * is dynamically allocated in services.
		  */
		cla_z_buf->buf_list = vmalloc(cla_z_buf->buf_number *
					      sizeof(struct cqm_buf_list));
		if (!cla_z_buf->buf_list) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_1_z_buf));
			cqm_buf_free(cla_y_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
		memset(cla_z_buf->buf_list, 0,
		       cla_z_buf->buf_number * sizeof(struct cqm_buf_list));
	}

	return CQM_SUCCESS;
}

s32 cqm_cla_xyz_lvl2(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		     u32 trunk_size)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf *cla_x_buf = NULL;
	struct cqm_buf *cla_y_buf = NULL;
	struct cqm_buf *cla_z_buf = NULL;
	s32 shift = 0;
	s32 ret = CQM_FAIL;
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;
	u32 cache_line = 0;

	if (cla_table->type == CQM_BAT_ENTRY_T_TIMER && cqm_ver == 8)
		cache_line = CQM_CHIP_TIMER_CACHELINE;
	else
		cache_line = CQM_CHIP_CACHELINE;

	if (cla_table->type == CQM_BAT_ENTRY_T_REORDER)
		gpa_check_enable = 0;

	cla_table->cla_lvl = CQM_CLA_LVL_2;

	shift = cqm_shift(trunk_size / cla_table->obj_size);
	cla_table->z = shift ? (shift - 1) : (shift);
	shift = cqm_shift(trunk_size / sizeof(dma_addr_t));
	cla_table->y = cla_table->z + shift;
	cla_table->x = CQM_MAX_INDEX_BIT;

	if (cla_table->obj_size >= cache_line) {
		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;
	} else {
		shift = cqm_shift(trunk_size / cache_line);
		cla_table->cacheline_z = shift ? (shift - 1) : (shift);
		shift = cqm_shift(trunk_size / sizeof(dma_addr_t));
		cla_table->cacheline_y = cla_table->cacheline_z + shift;
		cla_table->cacheline_x = CQM_MAX_INDEX_BIT;
	}

	/* Apply for CLA_X_BUF Space */
	cla_x_buf = &cla_table->cla_x_buf;
	cla_x_buf->buf_size = trunk_size;
	cla_x_buf->buf_number = 1;
	cla_x_buf->page_number = cla_x_buf->buf_number <<
				 cla_table->trunk_order;
	ret = cqm_buf_alloc(cqm_handle, cla_x_buf, false);
	CQM_CHECK_EQUAL_RET(handle->dev_hdl, ret, CQM_SUCCESS, CQM_FAIL,
			    CQM_ALLOC_FAIL(lvl_2_x_buf));

	/* Apply for CLA_Z_BUF and CLA_Y_BUF Space */
	cla_z_buf = &cla_table->cla_z_buf;
	cla_z_buf->buf_size = trunk_size;
	cla_z_buf->buf_number =
	    (ALIGN(cla_table->max_buffer_size, trunk_size)) / trunk_size;
	cla_z_buf->page_number = cla_z_buf->buf_number <<
				 cla_table->trunk_order;

	cla_y_buf = &cla_table->cla_y_buf;
	cla_y_buf->buf_size = trunk_size;
	cla_y_buf->buf_number =
	    (ALIGN(cla_z_buf->buf_number * sizeof(dma_addr_t), trunk_size)) /
	    trunk_size;
	cla_y_buf->page_number = cla_y_buf->buf_number <<
				 cla_table->trunk_order;
	/* All buffer space must be statically allocated. */
	if (cla_table->alloc_static) {
		/* Apply for y buf and z buf, and fill the gpa of
		 * z buf list in y buf
		 */
		if (cqm_cla_fill_buf(cqm_handle, cla_y_buf, cla_z_buf,
				     gpa_check_enable) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_fill_buf));
			cqm_buf_free(cla_x_buf, cqm_handle->dev);
			return CQM_FAIL;
		}

		/* Fill the gpa of the y buf list into the x buf.
		 * After the x and y bufs are applied for,
		 * this function will not fail.
		 * Use void to forcibly convert the return of the function.
		 */
		(void)cqm_cla_fill_buf(cqm_handle, cla_x_buf, cla_y_buf,
				       gpa_check_enable);
	} else { /* Only the buffer list space is initialized. The buffer space
		  * is dynamically allocated in services.
		  */
		cla_z_buf->buf_list = vmalloc(cla_z_buf->buf_number *
					      sizeof(struct cqm_buf_list));
		if (!cla_z_buf->buf_list) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_2_z_buf));
			cqm_buf_free(cla_x_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
		memset(cla_z_buf->buf_list, 0,
		       cla_z_buf->buf_number * sizeof(struct cqm_buf_list));

		cla_y_buf->buf_list = vmalloc(cla_y_buf->buf_number *
					      sizeof(struct cqm_buf_list));
		if (!cla_y_buf->buf_list) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_2_y_buf));
			cqm_buf_free(cla_z_buf, cqm_handle->dev);
			cqm_buf_free(cla_x_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
		memset(cla_y_buf->buf_list, 0,
		       cla_y_buf->buf_number * sizeof(struct cqm_buf_list));
	}

	return CQM_SUCCESS;
}

s32 cqm_cla_xyz_check(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		      u32 *size)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 trunk_size = 0;

	/* If the capability(obj_num) is set to 0, the CLA does not need to be
	 * initialized and exits directly.
	 */
	if (cla_table->obj_num == 0) {
		cqm_info(handle->dev_hdl,
			 "Cla alloc: cla_type %u, obj_num=0, don't alloc buffer\n",
			 cla_table->type);
		return CQM_SUCCESS;
	}

	cqm_info(handle->dev_hdl,
		 "Cla alloc: cla_type %u, obj_num=0x%x, gpa_check_enable=%d\n",
		 cla_table->type, cla_table->obj_num,
		 cqm_handle->func_capability.gpa_check_enable);

	/* Check whether obj_size is 2^n-aligned. An error is reported when
	 * obj_size is 0 or 1.
	 */
	if (!cqm_check_align(cla_table->obj_size)) {
		cqm_err(handle->dev_hdl,
			"Cla alloc: cla_type %u, obj_size 0x%x is not align on 2^n\n",
			cla_table->type, cla_table->obj_size);
		return CQM_FAIL;
	}

	trunk_size = (u32)(PAGE_SIZE << cla_table->trunk_order);

	if (trunk_size < cla_table->obj_size) {
		cqm_err(handle->dev_hdl,
			"Cla alloc: cla type %u, obj_size 0x%x is out of trunk size\n",
			cla_table->type, cla_table->obj_size);
		return CQM_FAIL;
	}

	*size = trunk_size;

	return CQM_CONTINUE;
}

s32 cqm_cla_xyz(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf *cla_z_buf = NULL;
	u32 trunk_size = 0;
	s32 ret = CQM_FAIL;

	ret = cqm_cla_xyz_check(cqm_handle, cla_table, &trunk_size);
	if (ret != CQM_CONTINUE)
		return ret;

	/* Level-0 CLA occupies a small space.
	 * Only CLA_Z_BUF can be allocated during initialization.
	 */
	if (cla_table->max_buffer_size <= trunk_size) {
		cla_table->cla_lvl = CQM_CLA_LVL_0;

		cla_table->z = CQM_MAX_INDEX_BIT;
		cla_table->y = 0;
		cla_table->x = 0;

		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;

		/* Applying for CLA_Z_BUF Space */
		cla_z_buf = &cla_table->cla_z_buf;
		cla_z_buf->buf_size = trunk_size; /* (u32)(PAGE_SIZE <<
						   * cla_table->trunk_order);
						   */
		cla_z_buf->buf_number = 1;
		cla_z_buf->page_number = cla_z_buf->buf_number << cla_table->trunk_order;
		ret = cqm_buf_alloc(cqm_handle, cla_z_buf, false);
		CQM_CHECK_EQUAL_RET(handle->dev_hdl, ret, CQM_SUCCESS, CQM_FAIL,
				    CQM_ALLOC_FAIL(lvl_0_z_buf));
	}
	/* Level-1 CLA
	 * Allocates CLA_Y_BUF and CLA_Z_BUF during initialization.
	 */
	else if (cla_table->max_buffer_size <= (trunk_size * (trunk_size / sizeof(dma_addr_t)))) {
		if (cqm_cla_xyz_lvl1(cqm_handle, cla_table, trunk_size) == CQM_FAIL) {
			cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_xyz_lvl1));
			return CQM_FAIL;
		}
	}
	/* Level-2 CLA
	 * Allocates CLA_X_BUF, CLA_Y_BUF, and CLA_Z_BUF during initialization.
	 */
	else if (cla_table->max_buffer_size <=
		 (trunk_size * (trunk_size / sizeof(dma_addr_t)) *
		  (trunk_size / sizeof(dma_addr_t)))) {
		if (cqm_cla_xyz_lvl2(cqm_handle, cla_table, trunk_size) ==
		    CQM_FAIL) {
			cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_xyz_lvl2));
			return CQM_FAIL;
		}
	} else { /* The current memory management mode does not support such
		  * a large buffer addressing. The order value needs to
		  * be increased.
		  */
		cqm_err(handle->dev_hdl,
			"Cla alloc: cla max_buffer_size 0x%x exceeds support range\n",
			cla_table->max_buffer_size);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

void cqm_cla_init_entry_normal(struct cqm_handle *cqm_handle,
			       struct cqm_cla_table *cla_table,
			       struct cqm_func_capability *capability)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;

	switch (cla_table->type) {
	case CQM_BAT_ENTRY_T_HASH:
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->hash_number * capability->hash_basic_size;
		cla_table->obj_size = capability->hash_basic_size;
		cla_table->obj_num = capability->hash_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_QPC:
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->qpc_number * capability->qpc_basic_size;
		cla_table->obj_size = capability->qpc_basic_size;
		cla_table->obj_num = capability->qpc_number;
		cla_table->alloc_static = capability->qpc_alloc_static;
		cqm_info(handle->dev_hdl, "Cla alloc: qpc alloc_static=%d\n",
			 cla_table->alloc_static);
		break;
	case CQM_BAT_ENTRY_T_MPT:
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->mpt_number * capability->mpt_basic_size;
		cla_table->obj_size = capability->mpt_basic_size;
		cla_table->obj_num = capability->mpt_number;
		/* CCB decided. MPT uses only static application scenarios. */
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_SCQC:
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->scqc_number * capability->scqc_basic_size;
		cla_table->obj_size = capability->scqc_basic_size;
		cla_table->obj_num = capability->scqc_number;
		cla_table->alloc_static = capability->scqc_alloc_static;
		cqm_info(handle->dev_hdl, "Cla alloc: scqc alloc_static=%d\n",
			 cla_table->alloc_static);
		break;
	case CQM_BAT_ENTRY_T_SRQC:
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->srqc_number * capability->srqc_basic_size;
		cla_table->obj_size = capability->srqc_basic_size;
		cla_table->obj_num = capability->srqc_number;
		cla_table->alloc_static = false;
		break;
	default:
		break;
	}
}

void cqm_cla_init_entry_extern(struct cqm_handle *cqm_handle,
			       struct cqm_cla_table *cla_table,
			       struct cqm_func_capability *capability)
{
	switch (cla_table->type) {
	case CQM_BAT_ENTRY_T_GID:
		/* Level-0 CLA table required */
		cla_table->max_buffer_size = capability->gid_number * capability->gid_basic_size;
		cla_table->trunk_order =
			(u32)cqm_shift(ALIGN(cla_table->max_buffer_size, PAGE_SIZE) / PAGE_SIZE);
		cla_table->obj_size = capability->gid_basic_size;
		cla_table->obj_num = capability->gid_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_LUN:
		cla_table->trunk_order = CLA_TABLE_PAGE_ORDER;
		cla_table->max_buffer_size = capability->lun_number * capability->lun_basic_size;
		cla_table->obj_size = capability->lun_basic_size;
		cla_table->obj_num = capability->lun_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_TASKMAP:
		cla_table->trunk_order = CQM_4K_PAGE_ORDER;
		cla_table->max_buffer_size = capability->taskmap_number *
					     capability->taskmap_basic_size;
		cla_table->obj_size = capability->taskmap_basic_size;
		cla_table->obj_num = capability->taskmap_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_L3I:
		cla_table->trunk_order = CLA_TABLE_PAGE_ORDER;
		cla_table->max_buffer_size = capability->l3i_number * capability->l3i_basic_size;
		cla_table->obj_size = capability->l3i_basic_size;
		cla_table->obj_num = capability->l3i_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_CHILDC:
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->childc_number *
					     capability->childc_basic_size;
		cla_table->obj_size = capability->childc_basic_size;
		cla_table->obj_num = capability->childc_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_TIMER:
		/* Ensure that the basic size of the timer buffer page does not
		 * exceed 128 x 4 KB. Otherwise, clearing the timer buffer of
		 * the function is complex.
		 */
		cla_table->trunk_order = CQM_4K_PAGE_ORDER;
		cla_table->max_buffer_size = capability->timer_number *
					     capability->timer_basic_size;
		cla_table->obj_size = capability->timer_basic_size;
		cla_table->obj_num = capability->timer_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_XID2CID:
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->xid2cid_number *
					     capability->xid2cid_basic_size;
		cla_table->obj_size = capability->xid2cid_basic_size;
		cla_table->obj_num = capability->xid2cid_number;
		cla_table->alloc_static = true;
		break;
	case CQM_BAT_ENTRY_T_REORDER:
		/* This entry supports only IWARP and does not support GPA validity check. */
		cla_table->trunk_order = capability->pagesize_reorder;
		cla_table->max_buffer_size = capability->reorder_number *
					     capability->reorder_basic_size;
		cla_table->obj_size = capability->reorder_basic_size;
		cla_table->obj_num = capability->reorder_number;
		cla_table->alloc_static = true;
		break;
	default:
		break;
	}
}

s32 cqm_cla_init_entry_condition(struct cqm_handle *cqm_handle, u32 entry_type)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table *cla_table = &bat_table->entry[entry_type];
	struct cqm_cla_table *cla_table_timer = NULL;
	u32 i;

	/* When the timer is in LB mode 1 or 2, the timer needs to be
	 * configured for four SMFs and the address space is independent.
	 */
	if (cla_table->type == CQM_BAT_ENTRY_T_TIMER &&
	    (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_1 ||
	     cqm_handle->func_capability.lb_mode == CQM_LB_MODE_2)) {
		for (i = 0; i < CQM_LB_SMF_MAX; i++) {
			cla_table_timer = &bat_table->timer_entry[i];
			memcpy(cla_table_timer, cla_table, sizeof(struct cqm_cla_table));

			if (cqm_cla_xyz(cqm_handle, cla_table_timer) == CQM_FAIL) {
				cqm_cla_uninit(cqm_handle, entry_type);
				return CQM_FAIL;
			}
		}
	}

	if (cqm_cla_xyz(cqm_handle, cla_table) == CQM_FAIL) {
		cqm_cla_uninit(cqm_handle, entry_type);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_cla_init_entry(struct cqm_handle *cqm_handle,
		       struct cqm_func_capability *capability)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table *cla_table = NULL;
	s32 ret;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		cla_table->type = bat_table->bat_entry_type[i];

		cqm_cla_init_entry_normal(cqm_handle, cla_table, capability);
		cqm_cla_init_entry_extern(cqm_handle, cla_table, capability);

		/* Allocate CLA entry space at each level. */
		if (cla_table->type < CQM_BAT_ENTRY_T_HASH ||
		    cla_table->type > CQM_BAT_ENTRY_T_REORDER) {
			mutex_init(&cla_table->lock);
			continue;
		}

		/* For the PPF, resources (8 wheels x 2k scales x 32B x
		 * func_num) need to be applied for to the timer. The
		 * structure of the timer entry in the BAT table needs
		 * to be filled. For the PF, no resource needs to be
		 * applied for the timer and no structure needs to be
		 * filled in the timer entry in the BAT table.
		 */
		if (!(cla_table->type == CQM_BAT_ENTRY_T_TIMER &&
		      cqm_handle->func_attribute.func_type != CQM_PPF)) {
			ret = cqm_cla_init_entry_condition(cqm_handle, i);
			if (ret != CQM_SUCCESS)
				return CQM_FAIL;
		}
		mutex_init(&cla_table->lock);
	}

	return CQM_SUCCESS;
}

s32 cqm_cla_init(struct cqm_handle *cqm_handle)
{
	struct cqm_func_capability *capability = &cqm_handle->func_capability;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	s32 ret;

	/* Applying for CLA Entries */
	ret = cqm_cla_init_entry(cqm_handle, capability);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_init_entry));
		return ret;
	}

	/* After the CLA entry is applied, the address is filled in the BAT table. */
	cqm_bat_fill_cla(cqm_handle);

	/* Instruct the chip to update the BAT table. */
	ret = cqm_bat_update(cqm_handle);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_update));
		goto err;
	}

	cqm_info(handle->dev_hdl, "Timer start: func_type=%d, timer_enable=%u\n",
		 cqm_handle->func_attribute.func_type,
		 cqm_handle->func_capability.timer_enable);

	if (cqm_handle->func_attribute.func_type == CQM_PPF &&
	    cqm_handle->func_capability.timer_enable == CQM_TIMER_ENABLE) {
		/* Enable the timer after the timer resources are applied for */
		cqm_info(handle->dev_hdl, "Timer start: spfc ppf timer start\n");
		ret = sphw_ppf_tmr_start((void *)(cqm_handle->ex_handle));
		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl, "Timer start: spfc ppf timer start, ret=%d\n",
				ret);
			goto err;
		}
	}

	return CQM_SUCCESS;

err:
	cqm_cla_uninit(cqm_handle, CQM_BAT_ENTRY_MAX);
	return CQM_FAIL;
}

void cqm_cla_uninit(struct cqm_handle *cqm_handle, u32 entry_numb)
{
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table *cla_table = NULL;
	s32 inv_flag = 0;
	u32 i;

	for (i = 0; i < entry_numb; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->type != CQM_BAT_ENTRY_T_INVALID) {
			cqm_buf_free_cache_inv(cqm_handle, &cla_table->cla_x_buf, &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle, &cla_table->cla_y_buf, &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle, &cla_table->cla_z_buf, &inv_flag);
		}
	}

	/* When the lb mode is 1/2, the timer space allocated to the 4 SMFs
	 * needs to be released.
	 */
	if (cqm_handle->func_attribute.func_type == CQM_PPF &&
	    (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_1 ||
	     cqm_handle->func_capability.lb_mode == CQM_LB_MODE_2)) {
		for (i = 0; i < CQM_LB_SMF_MAX; i++) {
			cla_table = &bat_table->timer_entry[i];
			cqm_buf_free_cache_inv(cqm_handle, &cla_table->cla_x_buf, &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle, &cla_table->cla_y_buf, &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle, &cla_table->cla_z_buf, &inv_flag);
		}
	}
}

s32 cqm_cla_update_cmd(struct cqm_handle *cqm_handle, struct cqm_cmd_buf *buf_in,
		       struct cqm_cla_update_cmd *cmd)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cla_update_cmd *cla_update_cmd = NULL;
	s32 ret = CQM_FAIL;

	cla_update_cmd = (struct cqm_cla_update_cmd *)(buf_in->buf);

	cla_update_cmd->gpa_h = cmd->gpa_h;
	cla_update_cmd->gpa_l = cmd->gpa_l;
	cla_update_cmd->value_h = cmd->value_h;
	cla_update_cmd->value_l = cmd->value_l;
	cla_update_cmd->smf_id = cmd->smf_id;
	cla_update_cmd->func_id = cmd->func_id;

	cqm_swab32((u8 *)cla_update_cmd,
		   (sizeof(struct cqm_cla_update_cmd) >> CQM_DW_SHIFT));

	ret = cqm3_send_cmd_box((void *)(cqm_handle->ex_handle), CQM_MOD_CQM,
				CQM_CMD_T_CLA_UPDATE, buf_in, NULL, NULL,
				CQM_CMD_TIMEOUT, SPHW_CHANNEL_DEFAULT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm3_send_cmd_box));
		cqm_err(handle->dev_hdl, "Cla alloc: cqm_cla_update, cqm3_send_cmd_box_ret=%d\n",
			ret);
		cqm_err(handle->dev_hdl, "Cla alloc: cqm_cla_update, cla_update_cmd: 0x%x 0x%x 0x%x 0x%x\n",
			cmd->gpa_h, cmd->gpa_l, cmd->value_h, cmd->value_l);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_cla_update(struct cqm_handle *cqm_handle, struct cqm_buf_list *buf_node_parent,
		   struct cqm_buf_list *buf_node_child, u32 child_index, u8 cla_update_mode)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cmd_buf *buf_in = NULL;
	struct cqm_cla_update_cmd cmd;
	dma_addr_t pa = 0;
	s32 ret = CQM_FAIL;
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;
	u32 i = 0;
	u64 spu_en;

	buf_in = cqm3_cmd_alloc(cqm_handle->ex_handle);
	CQM_PTR_CHECK_RET(buf_in, CQM_FAIL, CQM_ALLOC_FAIL(buf_in));
	buf_in->size = sizeof(struct cqm_cla_update_cmd);

	/* Fill command format, convert to big endian. */
	/* SPU function sets bit63: acs_spu_en based on function id. */
	if (sphw_host_id(cqm_handle->ex_handle) == CQM_SPU_HOST_ID)
		spu_en = ((u64)(cqm_handle->func_attribute.func_global_idx &
				0x1)) << 63;
	else
		spu_en = 0;

	pa = ((buf_node_parent->pa + (child_index * sizeof(dma_addr_t))) |
	      spu_en);
	cmd.gpa_h = CQM_ADDR_HI(pa);
	cmd.gpa_l = CQM_ADDR_LW(pa);

	pa = (buf_node_child->pa | spu_en);
	cmd.value_h = CQM_ADDR_HI(pa);
	cmd.value_l = CQM_ADDR_LW(pa);

	/* current CLA GPA CHECK */
	if (gpa_check_enable) {
		switch (cla_update_mode) {
		/* gpa[0]=1 means this GPA is valid */
		case CQM_CLA_RECORD_NEW_GPA:
			cmd.value_l |= 1;
			break;
		/* gpa[0]=0 means this GPA is valid */
		case CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID:
		case CQM_CLA_DEL_GPA_WITH_CACHE_INVALID:
			cmd.value_l &= (~1);
			break;
		default:
			cqm_err(handle->dev_hdl,
				"Cla alloc: %s, wrong cla_update_mode=%u\n",
				__func__, cla_update_mode);
			break;
		}
	}

	/* In non-fake mode, set func_id to 0xffff. */
	cmd.func_id = 0xffff;

	/* Mode 0 is hashed to 4 SMF engines (excluding PPF) by func ID. */
	if (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_NORMAL ||
	    (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_0 &&
	     cqm_handle->func_attribute.func_type != CQM_PPF)) {
		cmd.smf_id = cqm_funcid2smfid(cqm_handle);
		ret = cqm_cla_update_cmd(cqm_handle, buf_in, &cmd);
	}
	/* Modes 1/2 are allocated to four SMF engines by flow.
	 * Therefore, one function needs to be allocated to four SMF engines.
	 */
	/* Mode 0 PPF needs to be configured on 4 engines,
	 * and the timer resources need to be shared by the 4 engines.
	 */
	else if (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_1 ||
		 cqm_handle->func_capability.lb_mode == CQM_LB_MODE_2 ||
		 (cqm_handle->func_capability.lb_mode == CQM_LB_MODE_0 &&
		  cqm_handle->func_attribute.func_type == CQM_PPF)) {
		for (i = 0; i < CQM_LB_SMF_MAX; i++) {
			/* The smf_pg variable stores currently enabled SMF. */
			if (cqm_handle->func_capability.smf_pg & (1U << i)) {
				cmd.smf_id = i;
				ret = cqm_cla_update_cmd(cqm_handle, buf_in,
							 &cmd);
				if (ret != CQM_SUCCESS)
					goto out;
			}
		}
	} else {
		cqm_err(handle->dev_hdl, "Cla update: unsupport lb mode=%u\n",
			cqm_handle->func_capability.lb_mode);
		ret = CQM_FAIL;
	}

out:
	cqm3_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
	return ret;
}

s32 cqm_cla_alloc(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		  struct cqm_buf_list *buf_node_parent,
		  struct cqm_buf_list *buf_node_child, u32 child_index)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	s32 ret = CQM_FAIL;

	/* Apply for trunk page */
	buf_node_child->va = (u8 *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						    cla_table->trunk_order);
	CQM_PTR_CHECK_RET(buf_node_child->va, CQM_FAIL, CQM_ALLOC_FAIL(va));

	/* PCI mapping */
	buf_node_child->pa = pci_map_single(cqm_handle->dev, buf_node_child->va,
					    PAGE_SIZE << cla_table->trunk_order,
					    PCI_DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(cqm_handle->dev, buf_node_child->pa)) {
		cqm_err(handle->dev_hdl, CQM_MAP_FAIL(buf_node_child->pa));
		goto err1;
	}

	/* Notify the chip of trunk_pa so that the chip fills in cla entry */
	ret = cqm_cla_update(cqm_handle, buf_node_parent, buf_node_child,
			     child_index, CQM_CLA_RECORD_NEW_GPA);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_update));
		goto err2;
	}

	return CQM_SUCCESS;

err2:
	pci_unmap_single(cqm_handle->dev, buf_node_child->pa,
			 PAGE_SIZE << cla_table->trunk_order,
			 PCI_DMA_BIDIRECTIONAL);
err1:
	free_pages((ulong)(buf_node_child->va), cla_table->trunk_order);
	buf_node_child->va = NULL;
	return CQM_FAIL;
}

void cqm_cla_free(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		  struct cqm_buf_list *buf_node_parent,
		  struct cqm_buf_list *buf_node_child, u32 child_index, u8 cla_update_mode)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 trunk_size;

	if (cqm_cla_update(cqm_handle, buf_node_parent, buf_node_child,
			   child_index, cla_update_mode) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_update));
		return;
	}

	if (cla_update_mode == CQM_CLA_DEL_GPA_WITH_CACHE_INVALID) {
		trunk_size = (u32)(PAGE_SIZE << cla_table->trunk_order);
		if (cqm_cla_cache_invalid(cqm_handle, buf_node_child->pa,
					  trunk_size) != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_cache_invalid));
			return;
		}
	}

	/* Remove PCI mapping from the trunk page */
	pci_unmap_single(cqm_handle->dev, buf_node_child->pa,
			 PAGE_SIZE << cla_table->trunk_order,
			 PCI_DMA_BIDIRECTIONAL);

	/* Rlease trunk page */
	free_pages((ulong)(buf_node_child->va), cla_table->trunk_order);
	buf_node_child->va = NULL;
}

u8 *cqm_cla_get_unlock_lvl0(struct cqm_handle *cqm_handle,
			    struct cqm_cla_table *cla_table,
			    u32 index, u32 count, dma_addr_t *pa)
{
	struct cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	u8 *ret_addr = NULL;
	u32 offset = 0;

	/* Level 0 CLA pages are statically allocated. */
	offset = index * cla_table->obj_size;
	ret_addr = (u8 *)(cla_z_buf->buf_list->va) + offset;
	*pa = cla_z_buf->buf_list->pa + offset;

	return ret_addr;
}

u8 *cqm_cla_get_unlock_lvl1(struct cqm_handle *cqm_handle,
			    struct cqm_cla_table *cla_table,
			    u32 index, u32 count, dma_addr_t *pa)
{
	struct cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_list *buf_node_y = NULL;
	struct cqm_buf_list *buf_node_z = NULL;
	u32 y_index = 0;
	u32 z_index = 0;
	u8 *ret_addr = NULL;
	u32 offset = 0;

	z_index = index & ((1U << (cla_table->z + 1)) - 1);
	y_index = index >> (cla_table->z + 1);

	if (y_index >= cla_z_buf->buf_number) {
		cqm_err(handle->dev_hdl,
			"Cla get: index exceeds buf_number, y_index %u, z_buf_number %u\n",
			y_index, cla_z_buf->buf_number);
		return NULL;
	}
	buf_node_z = &cla_z_buf->buf_list[y_index];
	buf_node_y = cla_y_buf->buf_list;

	/* The z buf node does not exist, applying for a page first. */
	if (!buf_node_z->va) {
		if (cqm_cla_alloc(cqm_handle, cla_table, buf_node_y, buf_node_z,
				  y_index) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_alloc));
			cqm_err(handle->dev_hdl,
				"Cla get: cla_table->type=%u\n",
				cla_table->type);
			return NULL;
		}
	}

	buf_node_z->refcount += count;
	offset = z_index * cla_table->obj_size;
	ret_addr = (u8 *)(buf_node_z->va) + offset;
	*pa = buf_node_z->pa + offset;

	return ret_addr;
}

u8 *cqm_cla_get_unlock_lvl2(struct cqm_handle *cqm_handle,
			    struct cqm_cla_table *cla_table,
			    u32 index, u32 count, dma_addr_t *pa)
{
	struct cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_list *buf_node_x = NULL;
	struct cqm_buf_list *buf_node_y = NULL;
	struct cqm_buf_list *buf_node_z = NULL;
	u32 x_index = 0;
	u32 y_index = 0;
	u32 z_index = 0;
	u32 trunk_size = (u32)(PAGE_SIZE << cla_table->trunk_order);
	u8 *ret_addr = NULL;
	u32 offset = 0;
	u64 tmp;

	z_index = index & ((1U << (cla_table->z + 1)) - 1);
	y_index = (index >> (cla_table->z + 1)) &
		  ((1U << (cla_table->y - cla_table->z)) - 1);
	x_index = index >> (cla_table->y + 1);
	tmp = x_index * (trunk_size / sizeof(dma_addr_t)) + y_index;

	if (x_index >= cla_y_buf->buf_number || tmp >= cla_z_buf->buf_number) {
		cqm_err(handle->dev_hdl,
			"Cla get: index exceeds buf_number, x_index %u, y_index %u, y_buf_number %u, z_buf_number %u\n",
			x_index, y_index, cla_y_buf->buf_number,
			cla_z_buf->buf_number);
		return NULL;
	}

	buf_node_x = cla_x_buf->buf_list;
	buf_node_y = &cla_y_buf->buf_list[x_index];
	buf_node_z = &cla_z_buf->buf_list[tmp];

	/* The y buf node does not exist, applying for pages for y node. */
	if (!buf_node_y->va) {
		if (cqm_cla_alloc(cqm_handle, cla_table, buf_node_x, buf_node_y,
				  x_index) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_alloc));
			return NULL;
		}
	}

	/* The z buf node does not exist, applying for pages for z node. */
	if (!buf_node_z->va) {
		if (cqm_cla_alloc(cqm_handle, cla_table, buf_node_y, buf_node_z,
				  y_index) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_alloc));
			if (buf_node_y->refcount == 0)
				/* To release node Y, cache_invalid is
				 * required.
				 */
				cqm_cla_free(cqm_handle, cla_table, buf_node_x, buf_node_y, x_index,
					     CQM_CLA_DEL_GPA_WITH_CACHE_INVALID);
			return NULL;
		}

		/* reference counting of the y buffer node needs to increase
		 * by 1.
		 */
		buf_node_y->refcount++;
	}

	buf_node_z->refcount += count;
	offset = z_index * cla_table->obj_size;
	ret_addr = (u8 *)(buf_node_z->va) + offset;
	*pa = buf_node_z->pa + offset;

	return ret_addr;
}

u8 *cqm_cla_get_unlock(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		       u32 index, u32 count, dma_addr_t *pa)
{
	u8 *ret_addr = NULL;

	if (cla_table->cla_lvl == CQM_CLA_LVL_0)
		ret_addr = cqm_cla_get_unlock_lvl0(cqm_handle, cla_table, index,
						   count, pa);
	else if (cla_table->cla_lvl == CQM_CLA_LVL_1)
		ret_addr = cqm_cla_get_unlock_lvl1(cqm_handle, cla_table, index,
						   count, pa);
	else
		ret_addr = cqm_cla_get_unlock_lvl2(cqm_handle, cla_table, index,
						   count, pa);

	return ret_addr;
}

u8 *cqm_cla_get_lock(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		     u32 index, u32 count, dma_addr_t *pa)
{
	u8 *ret_addr = NULL;

	mutex_lock(&cla_table->lock);

	ret_addr = cqm_cla_get_unlock(cqm_handle, cla_table, index, count, pa);

	mutex_unlock(&cla_table->lock);

	return ret_addr;
}

void cqm_cla_put(struct cqm_handle *cqm_handle, struct cqm_cla_table *cla_table,
		 u32 index, u32 count)
{
	struct cqm_buf *cla_z_buf = &cla_table->cla_z_buf;
	struct cqm_buf *cla_y_buf = &cla_table->cla_y_buf;
	struct cqm_buf *cla_x_buf = &cla_table->cla_x_buf;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_list *buf_node_z = NULL;
	struct cqm_buf_list *buf_node_y = NULL;
	struct cqm_buf_list *buf_node_x = NULL;
	u32 x_index = 0;
	u32 y_index = 0;
	u32 trunk_size = (u32)(PAGE_SIZE << cla_table->trunk_order);
	u64 tmp;

	/* The buffer is applied statically, and the reference counting
	 * does not need to be controlled.
	 */
	if (cla_table->alloc_static)
		return;

	mutex_lock(&cla_table->lock);

	if (cla_table->cla_lvl == CQM_CLA_LVL_1) {
		y_index = index >> (cla_table->z + 1);

		if (y_index >= cla_z_buf->buf_number) {
			cqm_err(handle->dev_hdl,
				"Cla put: index exceeds buf_number, y_index %u, z_buf_number %u\n",
				y_index, cla_z_buf->buf_number);
			cqm_err(handle->dev_hdl,
				"Cla put: cla_table->type=%u\n",
				cla_table->type);
			mutex_unlock(&cla_table->lock);
			return;
		}

		buf_node_z = &cla_z_buf->buf_list[y_index];
		buf_node_y = cla_y_buf->buf_list;

		/* When the value of reference counting on the z node page is 0,
		 * the z node page is released.
		 */
		buf_node_z->refcount -= count;
		if (buf_node_z->refcount == 0)
			/* The cache invalid is not required for the Z node. */
			cqm_cla_free(cqm_handle, cla_table, buf_node_y,
				     buf_node_z, y_index,
				     CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID);
	} else if (cla_table->cla_lvl == CQM_CLA_LVL_2) {
		y_index = (index >> (cla_table->z + 1)) &
			  ((1U << (cla_table->y - cla_table->z)) - 1);
		x_index = index >> (cla_table->y + 1);
		tmp = x_index * (trunk_size / sizeof(dma_addr_t)) + y_index;

		if (x_index >= cla_y_buf->buf_number || tmp >= cla_z_buf->buf_number) {
			cqm_err(handle->dev_hdl,
				"Cla put: index exceeds buf_number, x_index %u, y_index %u, y_buf_number %u, z_buf_number %u\n",
				x_index, y_index, cla_y_buf->buf_number,
				cla_z_buf->buf_number);
			mutex_unlock(&cla_table->lock);
			return;
		}

		buf_node_x = cla_x_buf->buf_list;
		buf_node_y = &cla_y_buf->buf_list[x_index];
		buf_node_z = &cla_z_buf->buf_list[tmp];

		/* When the value of reference counting on the z node page is 0,
		 * the z node page is released.
		 */
		buf_node_z->refcount -= count;
		if (buf_node_z->refcount == 0) {
			cqm_cla_free(cqm_handle, cla_table, buf_node_y,
				     buf_node_z, y_index,
				     CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID);

			/* When the value of reference counting on the y node
			 * page is 0, the y node page is released.
			 */
			buf_node_y->refcount--;
			if (buf_node_y->refcount == 0)
				/* Node y requires cache to be invalid. */
				cqm_cla_free(cqm_handle, cla_table, buf_node_x, buf_node_y, x_index,
					     CQM_CLA_DEL_GPA_WITH_CACHE_INVALID);
		}
	}

	mutex_unlock(&cla_table->lock);
}

struct cqm_cla_table *cqm_cla_table_get(struct cqm_bat_table *bat_table, u32 entry_type)
{
	struct cqm_cla_table *cla_table = NULL;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (entry_type == cla_table->type)
			return cla_table;
	}

	return NULL;
}
