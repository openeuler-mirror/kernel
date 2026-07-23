// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"

#include "dpp_dev.h"
#include "dpp_acl.h"
#include "dpp_etcam.h"
#include "dpp_se.h"
#include "dpp_se_reg.h"
#include "dpp_reg_api.h"
#include "dpp_reg_info.h"

#define BLOCK_IDXBASE_BIT_OFF (9)
#define BLOCK_IDXBASE_BIT_MASK (0x7f)
#define ACL_AS_IDX_OFFSET_MAX (32 * 1024)
#define ACL_IMPLICIT_PRI (0)

#define DPP_ACL_KEYSIZE_GET(key_mode) (2 * DPP_ETCAM_ENTRY_SIZE_GET(key_mode))
#define DPP_ACL_ENTRY_WRMODE_GET(key_mode, entry_pos) \
	((((1U << (8U >> (key_mode))) - 1) << ((8U >> (key_mode)) * (entry_pos))) & 0xFF)

#define DPP_ACL_AS_RSLT_INFO_GET(buff_base, index, size) (((u8 *)(buff_base) + (index) * (size)))

#define MEM_OFF_NOT_NULL(type, member) \
	(ZXIC_COMM_PTR_TO_VAL(&(((type *)4)->member)) - ZXIC_COMM_PTR_TO_VAL(((type *)4)))

#define GET_STRUCT_ENTRY_POINT(ptr, type, member) \
	((type *)(ZXIC_COMM_PTR_TO_VAL(ptr) - MEM_OFF_NOT_NULL(type, member)))

static struct dpp_acl_cfg_ex_t *g_p_acl_ex_cfg[DPP_PCIE_SLOT_MAX] = { NULL };
u32 dpp_acl_entrynum_to_blocknum(u32 entry_num, u32 key_mode)
{
	u32 value = 0;

	ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NO_ASSERT(DPP_ETCAM_RAM_DEPTH, ((u32)1 << key_mode));
	value = entry_num % (DPP_ETCAM_RAM_DEPTH * ((u32)1 << key_mode));

	if (value == 0)
		return (entry_num / (DPP_ETCAM_RAM_DEPTH * ((u32)1 << key_mode)));

	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(
		entry_num / (DPP_ETCAM_RAM_DEPTH * ((u32)1 << key_mode)), 1);
	return (entry_num / (DPP_ETCAM_RAM_DEPTH * ((u32)1 << key_mode)) + 1);
}
s32 dpp_acl_entry_pri_cmp(void *p_new_key, void *p_old_key, u32 key_len)
{
	if ((*(u32 *)p_new_key) > (*(u32 *)p_old_key))
		return 1;
	else if ((*(u32 *)p_new_key) < (*(u32 *)p_old_key))
		return -1;

	return 0;
}
s32 dpp_acl_key_cmp(void *p_new_key, void *p_old_key, u32 key_len)
{
	ZXIC_COMM_CHECK_POINT(p_new_key);
	ZXIC_COMM_CHECK_POINT(p_old_key);

	ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NO_ASSERT(key_len, (u32)ZXIC_SIZEOF(u32));
	return ZXIC_COMM_MEMCMP(&(((struct dpp_acl_key_info_t *)p_new_key)->pri),
				&(((struct dpp_acl_key_info_t *)p_old_key)->pri),
				key_len - ZXIC_SIZEOF(u32));
}
DPP_STATUS dpp_acl_hdw_addr_get(struct dpp_acl_tbl_cfg_t *p_tbl_cfg, u32 handle, u32 *p_block_idx,
				u32 *p_addr, u32 *p_wr_mask)
{
	u32 block_entry_num = 0;
	u32 entry_pos = 0;

	ZXIC_COMM_CHECK_POINT(p_tbl_cfg);
	ZXIC_COMM_CHECK_POINT(p_block_idx);
	ZXIC_COMM_CHECK_POINT(p_addr);
	ZXIC_COMM_CHECK_POINT(p_wr_mask);

	block_entry_num = DPP_ACL_ENTRY_MAX_GET(p_tbl_cfg->key_mode, 1);
	*p_block_idx = p_tbl_cfg->block_array[handle / block_entry_num];
	*p_addr = (handle % block_entry_num) / (1U << p_tbl_cfg->key_mode);
	entry_pos = (handle % block_entry_num) % (1U << p_tbl_cfg->key_mode);
	ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NO_ASSERT(entry_pos, 8);
	*p_wr_mask = DPP_ACL_ENTRY_WRMODE_GET(p_tbl_cfg->key_mode, entry_pos);
	return DPP_OK;
}
DPP_STATUS dpp_acl_hdw_addr_get_ex(struct dpp_acl_tbl_cfg_t *p_tbl_cfg, u32 handle,
				   u32 *p_block_idx, u32 *p_addr, u32 *p_wr_mask)
{
	u32 block_entry_num = 0;
	u32 entry_pos = 0;
	DPP_STATUS rc = DPP_OK;

	if (0 == (p_tbl_cfg && p_block_idx && p_addr && p_wr_mask)) {
		ZXIC_COMM_TRACE_ERROR("\n ICM %s:%d[Error:POINT NULL] ! FUNCTION : %s!\n", __FILE__,
				      __LINE__, __func__);
		rc = ZXIC_PAR_CHK_POINT_NULL;
		return rc;
	}
	block_entry_num = DPP_ACL_ENTRY_MAX_GET(p_tbl_cfg->key_mode, 1);
	*p_block_idx = p_tbl_cfg->block_array[handle / block_entry_num];
	*p_addr = (handle % block_entry_num) / (1U << p_tbl_cfg->key_mode);
	entry_pos = (handle % block_entry_num) % (1U << p_tbl_cfg->key_mode);
	ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NO_ASSERT(entry_pos, 8);
	*p_wr_mask = DPP_ACL_ENTRY_WRMODE_GET(p_tbl_cfg->key_mode, entry_pos);
	return rc;
}
DPP_STATUS dpp_acl_entry_swap(u32 old_index, u32 new_index, void *p_cfg)
{
	DPP_STATUS rc = 0;
	u32 block_idx = 0;
	u32 ram_addr = 0;
	u32 wr_mask = 0;
	u8 *p_old_rslt_temp = NULL;
	u8 *p_new_rslt_temp = NULL;
	u8 temp_data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };
	u8 temp_mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };
	struct dpp_acl_cfg_t *p_acl_cfg = NULL;
	struct dpp_acl_tbl_cfg_t *p_tbl_cfg = NULL;
	struct dpp_acl_key_info_t *p_acl_key = NULL;
	struct dpp_etcam_entry_t etcam_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cfg);

	p_tbl_cfg = STRUCT_ENTRY_POINT(p_cfg, struct dpp_acl_tbl_cfg_t, index_mng);
	ZXIC_COMM_CHECK_INDEX(p_tbl_cfg->table_id, 0,
			      DPP_ACL_TBL_ID_NUM - 1); /* modify coverity yinxh 2021.03.10*/
	p_acl_cfg = GET_STRUCT_ENTRY_POINT(p_tbl_cfg, struct dpp_acl_cfg_t,
					   acl_tbls[p_tbl_cfg->table_id]);

	ZXIC_COMM_CHECK_INDEX_UPPER(old_index,
				    p_tbl_cfg->entry_num); /* modify coverity yinxh 2021.03.10*/
	p_acl_key = p_tbl_cfg->acl_key_buff[old_index];

	etcam_entry.p_data = temp_data;
	etcam_entry.p_mask = temp_mask;
	etcam_entry.mode = p_tbl_cfg->key_mode;
	ZXIC_COMM_CHECK_DEV_INDEX(p_acl_cfg->dev_id, p_tbl_cfg->key_mode, DPP_ACL_KEY_640b,
				  DPP_ACL_KEY_INVALID - 1); /* modify coverity yinxh 2021.03.10*/
	ZXIC_COMM_MEMCPY(etcam_entry.p_data, p_acl_key->key,
			 DPP_ETCAM_ENTRY_SIZE_GET(p_tbl_cfg->key_mode));
	ZXIC_COMM_MEMCPY(etcam_entry.p_mask,
			 p_acl_key->key + DPP_ETCAM_ENTRY_SIZE_GET(p_tbl_cfg->key_mode),
			 DPP_ETCAM_ENTRY_SIZE_GET(p_tbl_cfg->key_mode));

	/* update new as result */
	if (p_tbl_cfg->as_enable) {
		/* eTcam result table as to eRam. */
		ZXIC_COMM_CHECK_DEV_INDEX(p_acl_cfg->dev_id, p_tbl_cfg->as_mode,
					  DPP_ACL_AS_MODE_16b, DPP_ACL_AS_MODE_INVALID - 1);
		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(p_acl_cfg->dev_id, old_index,
								 (2U << (p_tbl_cfg->as_mode)));
		p_old_rslt_temp =
			DPP_ACL_AS_RSLT_INFO_GET(p_tbl_cfg->as_rslt_buff, old_index,
						 DPP_ACL_AS_RSLT_SIZE_GET_EX(p_tbl_cfg->as_mode));
		rc = p_acl_cfg->p_as_rslt_write_fun(
			p_acl_cfg->dev_id, p_tbl_cfg->as_eRam_base + p_tbl_cfg->as_idx_base,
			new_index, p_tbl_cfg->as_mode, p_old_rslt_temp);
		ZXIC_COMM_CHECK_RC(rc, "acl_as_rslt_write_fun");

		/* update result buffer */
		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(p_acl_cfg->dev_id, new_index,
								 2U << p_tbl_cfg->as_mode);
		p_new_rslt_temp =
			DPP_ACL_AS_RSLT_INFO_GET(p_tbl_cfg->as_rslt_buff, new_index,
						 DPP_ACL_AS_RSLT_SIZE_GET_EX(p_tbl_cfg->as_mode));
		ZXIC_COMM_MEMCPY(p_new_rslt_temp, p_old_rslt_temp,
				 (u32)DPP_ACL_AS_RSLT_SIZE_GET_EX(p_tbl_cfg->as_mode));
	} else if (p_tbl_cfg->is_as_ddr) {
		/* eTcam result table as to DDR. */
		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(p_acl_cfg->dev_id, old_index,
								 2U << p_tbl_cfg->as_mode);
		p_old_rslt_temp =
			DPP_ACL_AS_RSLT_INFO_GET(p_tbl_cfg->as_rslt_buff, old_index,
						 DPP_ACL_AS_RSLT_SIZE_GET_EX(p_tbl_cfg->as_mode));

		rc = p_tbl_cfg->p_as_ddr_wr_fun(p_acl_cfg->dev_id, p_tbl_cfg->tbl_type,
						p_tbl_cfg->table_id, p_tbl_cfg->dir_tbl_share_type,
						p_tbl_cfg->ddr_baddr, p_tbl_cfg->ddr_ecc_en,
						p_tbl_cfg->idx_offset, p_tbl_cfg->as_mode,
						p_old_rslt_temp);
		ZXIC_COMM_CHECK_RC(rc, "acl_as_ddr_rslt_writ_fun");

		/* update result buffer */
		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(p_acl_cfg->dev_id, new_index,
								 2U << p_tbl_cfg->as_mode);
		p_new_rslt_temp =
			DPP_ACL_AS_RSLT_INFO_GET(p_tbl_cfg->as_rslt_buff, new_index,
						 DPP_ACL_AS_RSLT_SIZE_GET_EX(p_tbl_cfg->as_mode));
		ZXIC_COMM_MEMCPY(p_new_rslt_temp, p_old_rslt_temp,
				 (u32)DPP_ACL_AS_RSLT_SIZE_GET_EX(p_tbl_cfg->as_mode));
	}

	/* add new entry */
	rc = dpp_acl_hdw_addr_get_ex(p_tbl_cfg, new_index, &block_idx, &ram_addr, &wr_mask);
	ZXIC_COMM_CHECK_RC(rc, "dpp_acl_hdw_addr_get_ex");

#ifdef DPP_FLOW_HW_INIT
	rc = dpp_etcam_entry_add(p_acl_cfg->dev, ram_addr, block_idx, wr_mask, DPP_ETCAM_OPR_DM,
				 &etcam_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_etcam_entry_add");
#endif

	/* delete old entry */
	rc = dpp_acl_hdw_addr_get_ex(p_tbl_cfg, old_index, &block_idx, &ram_addr, &wr_mask);
	ZXIC_COMM_CHECK_RC(rc, "dpp_acl_hdw_addr_get_ex");

#ifdef DPP_FLOW_HW_INIT
	rc = dpp_etcam_entry_del(p_acl_cfg->dev, ram_addr, block_idx, wr_mask);
	ZXIC_COMM_CHECK_RC(rc, "dpp_etcam_entry_del");
#endif

	p_acl_key->handle = new_index;
	p_tbl_cfg->acl_key_buff[new_index] = p_acl_key;

	return DPP_OK;
}

/** ACL **/
DPP_STATUS dpp_acl_cfg_get(struct dpp_dev_t *dev, struct dpp_acl_cfg_ex_t **p_acl_cfg)
{
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_acl_cfg);

	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	if (!g_p_acl_ex_cfg[slot]) {
		ZXIC_COMM_TRACE_DEBUG("dpp acl_cfg_get[%d] fail, etcam_is not init!\n", slot);
		return DPP_ACL_RC_ETCAMID_NOT_INIT;
	}

	*p_acl_cfg = g_p_acl_ex_cfg[slot];

	return DPP_OK;
}

/** ACL **/
void dpp_acl_cfg_set(struct dpp_dev_t *dev, struct dpp_acl_cfg_ex_t *p_acl_cfg)
{
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT_RETURN_NONE(dev);

	slot = DEV_PCIE_SLOT(dev);
	if (slot < DPP_PCIE_SLOT_MAX)
		g_p_acl_ex_cfg[slot] = p_acl_cfg;
}

#if ZXIC_REAL("init_ex MUL_PRI")
DPP_STATUS dpp_acl_cfg_init_ex(struct dpp_dev_t *dev, struct dpp_acl_cfg_ex_t *p_acl_cfg,
			       void *p_client, u32 flags, ACL_AS_RSLT_WRT_FUNCTION p_as_wrt_fun)
{
	DPP_STATUS rc = 0;
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_acl_cfg);

	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	ZXIC_COMM_MEMSET(p_acl_cfg, 0, ZXIC_SIZEOF(struct dpp_acl_cfg_ex_t));
	g_p_acl_ex_cfg[slot] = p_acl_cfg;

	p_acl_cfg->p_client = p_client;
	// p_acl_cfg->dev_id = (u32)(ZXIC_COMM_PTR_TO_VAL(p_acl_cfg->p_client) & 0xFFFFFFFF);
	p_acl_cfg->dev_id = DEV_ID(dev);
	p_acl_cfg->dev = dev;
	p_acl_cfg->flags = flags;

	if (flags & DPP_ACL_FLAG_ETCAM0_EN) {
		p_acl_cfg->acl_etcamids.is_valid = 1;

		/*        if (flags & DPP_ACL_FLAG_ETCAM0_AS)*/
		/*        {*/
		/*            p_acl_cfg->acl_etcamids[0].as_enable    = 1;*/
		p_acl_cfg->acl_etcamids.as_eRam_base = 0;
		/*        }*/

		rc = zxic_comm_double_link_init(DPP_ACL_TBL_ID_NUM,
						&(p_acl_cfg->acl_etcamids.tbl_list));
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_double_link_init");
	}

	if (!p_as_wrt_fun) {
		// p_acl_cfg->p_as_rslt_write_fun = dpp_acl_as_rslt_write;
		// p_acl_cfg->p_as_rslt_read_fun = dpp_acl_as_rslt_read;
	} else {
		p_acl_cfg->p_as_rslt_write_fun = p_as_wrt_fun;
	}

	return DPP_OK;
}
DPP_STATUS dpp_acl_tbl_init_ex(struct dpp_acl_cfg_ex_t *p_acl_cfg, u32 table_id, u32 as_enable,
			       u32 entry_num, enum dpp_acl_pri_mode_e pri_mode, u32 key_mode,
			       enum dpp_acl_as_mode_e as_mode, u32 as_baddr, u32 block_num,
			       u32 *p_block_idx)
{
	DPP_STATUS rc = 0;
	u32 i = 0;
	u32 acl_key_buff_size = 0;
	u32 slot = 0;
	/*    u32 as_idx_base = 0;*/

	ZXIC_COMM_CHECK_POINT(p_acl_cfg);
	ZXIC_COMM_CHECK_INDEX(table_id, DPP_ACL_TBL_ID_MIN, DPP_ACL_TBL_ID_MAX);
	ZXIC_COMM_CHECK_INDEX(as_enable, 0, 1);
	ZXIC_COMM_CHECK_INDEX(pri_mode, DPP_ACL_PRI_EXPLICIT, DPP_ACL_PRI_SPECIFY);
	ZXIC_COMM_CHECK_INDEX(key_mode, DPP_ACL_KEY_640b, DPP_ACL_KEY_80b);
	ZXIC_COMM_CHECK_INDEX(as_mode, DPP_ACL_AS_MODE_16b, DPP_ACL_AS_MODE_128b);
	ZXIC_COMM_CHECK_INDEX(block_num, 0, DPP_ETCAM_BLOCK_NUM);
	ZXIC_COMM_CHECK_POINT(p_block_idx);
	ZXIC_COMM_CHECK_POINT(p_acl_cfg->dev);

	slot = p_acl_cfg->dev->pcie_channel.slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);
	g_p_acl_ex_cfg[slot] = p_acl_cfg;

	if (p_acl_cfg->acl_tbls[table_id].is_used) {
		ZXIC_COMM_TRACE_ERROR("table_id[ %d ] is already used!\n", table_id);
		ZXIC_COMM_ASSERT(0);
		return DPP_ACL_RC_INVALID_TBLID;
	}

	if (!p_acl_cfg->acl_etcamids.is_valid) {
		ZXIC_COMM_TRACE_ERROR("etcam is not init!\n");
		ZXIC_COMM_ASSERT(0);
		return DPP_ACL_RC_ETCAMID_NOT_INIT;
	}

	if (dpp_acl_entrynum_to_blocknum(entry_num, key_mode) > block_num) {
		ZXIC_COMM_TRACE_ERROR(
			"key_mode[ %d ], the etcam block_num[ %d ] is not enough for entry_num[ 0x%x ].\n",
			key_mode, block_num, entry_num);
		ZXIC_COMM_ASSERT(0);
		return DPP_ACL_RC_INVALID_BLOCKNUM;
	} else if (dpp_acl_entrynum_to_blocknum(entry_num, key_mode) < block_num) {
		ZXIC_COMM_TRACE_DEBUG(
			"key_mode[ %d ], the etcam block_num[ %d ] is more than entry_num[ 0x%x ], better to reduce block_num in order to match with entry_num.\n",
			key_mode, block_num, entry_num);
	} else {
		ZXIC_COMM_TRACE_DEBUG(
			"key_mode[ %d ], the etcam block_num[ %d ] is match with entry_num[ 0x%x ].\n",
			key_mode, block_num, entry_num);
	}

	p_acl_cfg->acl_tbls[table_id].as_enable = as_enable;

	if (as_enable) {
		p_acl_cfg->acl_tbls[table_id].as_idx_base = as_baddr;
		p_acl_cfg->acl_tbls[table_id].as_rslt_buff =
			ZXIC_COMM_MALLOC(entry_num * DPP_ACL_AS_RSLT_SIZE_GET_EX(as_mode));
		ZXIC_COMM_CHECK_POINT(p_acl_cfg->acl_tbls[table_id].as_rslt_buff);
	}

	if ((pri_mode == DPP_ACL_PRI_EXPLICIT) || (pri_mode == DPP_ACL_PRI_IMPLICIT)) {
		rc = (DPP_STATUS)zxic_comm_indexfill_init(
			&(p_acl_cfg->acl_tbls[table_id].index_mng), entry_num,
			dpp_acl_entry_pri_cmp, dpp_acl_entry_swap, ZXIC_SIZEOF(u32));
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_indexfill_init");

		ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(
			p_acl_cfg->dev_id, entry_num,
			(u32)ZXIC_SIZEOF(struct dpp_acl_key_info_t *));
		acl_key_buff_size = (entry_num * ZXIC_SIZEOF(struct dpp_acl_key_info_t *)) &
				    0xffffffff;
		p_acl_cfg->acl_tbls[table_id].acl_key_buff =
			(struct dpp_acl_key_info_t **)ZXIC_COMM_MALLOC(acl_key_buff_size);
		ZXIC_COMM_CHECK_POINT(p_acl_cfg->acl_tbls[table_id].acl_key_buff);
	}

	rc = (DPP_STATUS)zxic_comm_rb_init(&(p_acl_cfg->acl_tbls[table_id].acl_rb), 0,
					   ZXIC_SIZEOF(struct dpp_acl_key_info_t) +
						   DPP_ACL_KEYSIZE_GET(key_mode),
					   dpp_acl_key_cmp);
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_rb_init");

	p_acl_cfg->acl_tbls[table_id].table_id = table_id;
	p_acl_cfg->acl_tbls[table_id].pri_mode = pri_mode;
	p_acl_cfg->acl_tbls[table_id].key_mode = key_mode;
	p_acl_cfg->acl_tbls[table_id].entry_num = entry_num;
	p_acl_cfg->acl_tbls[table_id].as_mode = as_mode;
	p_acl_cfg->acl_tbls[table_id].is_used = 1;

	INIT_D_NODE(&(p_acl_cfg->acl_tbls[table_id].entry_dn), &(p_acl_cfg->acl_tbls[table_id]));
	rc = (DPP_STATUS)zxic_comm_double_link_insert_last(
		&(p_acl_cfg->acl_tbls[table_id].entry_dn), &(p_acl_cfg->acl_etcamids.tbl_list));
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_double_link_insert_last");

	p_acl_cfg->acl_tbls[table_id].block_num = block_num;
	p_acl_cfg->acl_tbls[table_id].block_array = ZXIC_COMM_MALLOC(block_num * ZXIC_SIZEOF(u32));
	ZXIC_COMM_CHECK_POINT(p_acl_cfg->acl_tbls[table_id].block_array);

	for (i = 0; i < block_num; i++) {
		if (p_acl_cfg->acl_blocks[p_block_idx[i]].is_used) {
			ZXIC_COMM_TRACE_ERROR("the block[ %d ] is already used by table[ %d ]!\n",
					      p_block_idx[i],
					      p_acl_cfg->acl_blocks[p_block_idx[i]].tbl_id);
			ZXIC_COMM_ASSERT(0);
			return DPP_ACL_RC_INVALID_BLOCKID;
		}

		p_acl_cfg->acl_tbls[table_id].block_array[i] = p_block_idx[i];
		p_acl_cfg->acl_blocks[p_block_idx[i]].is_used = 1;
		p_acl_cfg->acl_blocks[p_block_idx[i]].tbl_id = table_id;
		p_acl_cfg->acl_blocks[p_block_idx[i]].idx_base =
			((DPP_ACL_ENTRY_MAX_GET(key_mode, i)) >> BLOCK_IDXBASE_BIT_OFF) &
			BLOCK_IDXBASE_BIT_MASK;
	}

	return DPP_OK;
}

DPP_STATUS dpp_acl_res_destroy(u32 dev_id)
{
	DPP_STATUS rc = DPP_OK;
	u32 table_id = 0;
	u32 as_enable = 0;
	u32 pri_mode = 0;
	u32 slot = 0;
	struct dpp_dev_t dev = { 0 };
	struct dpp_acl_cfg_ex_t *p_acl_cfg = NULL;
	struct dpp_acl_tbl_cfg_t *p_tbl_cfg = NULL;

	ZXIC_COMM_CHECK_INDEX_NO_ASSERT(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	for (slot = 0; slot < DPP_PCIE_SLOT_MAX; slot++) {
		dev.device_id = dev_id;
		dev.pcie_channel.slot = slot;
		rc = dpp_acl_cfg_get(&dev, &p_acl_cfg);
		if ((rc != DPP_OK) || (!p_acl_cfg))
			continue;

		if (!p_acl_cfg->acl_etcamids.is_valid) {
			ZXIC_COMM_TRACE_ERROR("etcam is not init!\n");
			return DPP_ACL_RC_ETCAMID_NOT_INIT;
		}

		for (table_id = DPP_ACL_TBL_ID_MIN; table_id <= DPP_ACL_TBL_ID_MAX; table_id++) {
			p_tbl_cfg = p_acl_cfg->acl_tbls + table_id;
			if (!p_tbl_cfg->is_used) {
				ZXIC_COMM_TRACE_DEBUG("table_id[ %d ] is not used!\n", table_id);
				continue;
			}

			rc = (DPP_STATUS)zxic_comm_rb_destroy(&(p_tbl_cfg->acl_rb));
			ZXIC_COMM_CHECK_RC(rc, "zxic_comm_rb_destroy");

			rc = zxic_comm_indexfill_destroy(&(p_tbl_cfg->index_mng));
			ZXIC_COMM_CHECK_RC(rc, "zxic_comm_indexfill_destroy");

			as_enable = p_tbl_cfg->as_enable;
			if (as_enable) {
				if (p_tbl_cfg->as_rslt_buff) {
					ZXIC_COMM_FREE(p_tbl_cfg->as_rslt_buff);
					p_tbl_cfg->as_rslt_buff = NULL;
				}
			}

			pri_mode = p_tbl_cfg->pri_mode;
			if ((pri_mode == DPP_ACL_PRI_EXPLICIT) ||
			    (pri_mode == DPP_ACL_PRI_IMPLICIT)) {
				if (p_tbl_cfg->acl_key_buff) {
					ZXIC_COMM_FREE(p_tbl_cfg->acl_key_buff);
					p_tbl_cfg->acl_key_buff = NULL;
				}
			}

			if (p_tbl_cfg->block_array) {
				ZXIC_COMM_FREE(p_tbl_cfg->block_array);
				p_tbl_cfg->block_array = NULL;
			}
		}
	}

	return DPP_OK;
}

#endif
