// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se_api.h"
#include "dpp_apt_se.h"
#include "dpp_stat_api.h"
#include "dpp_agent_channel.h"
#include "dpp_sdt.h"
#include "dpp_dtb_table_api.h"
#include "dpp_drv_eram.h"
#include "dpp_drv_sdt.h"
#include "dpp_dtb_table.h"
#include "dpp_dtb.h"
#include "dpp_kernel_init.h"

u32 dpp_get_se_buff_size(u32 opr)
{
	u32 buff_size = 0;

	switch (opr) {
	case HASH_FUNC_BULK_REQ: {
		buff_size = ZXIC_SIZEOF(struct se_hash_func_bulk_t);
		break;
	}
	case HASH_TBL_REQ: {
		buff_size = ZXIC_SIZEOF(struct se_hash_tbl_t);
		break;
	}
	case ERAM_TBL_REQ: {
		buff_size = ZXIC_SIZEOF(struct se_eram_tbl_t);
		break;
	}
	case ACL_TBL_REQ: {
		buff_size = ZXIC_SIZEOF(struct se_acl_tbl_t);
		break;
	}
	case LPM_TBL_REQ: {
		buff_size = ZXIC_SIZEOF(struct se_lpm_tbl_t);
		break;
	}
	case DDR_TBL_REQ: {
		buff_size = ZXIC_SIZEOF(struct se_ddr_tbl_t);
		break;
	}
	case STAT_CFG_REQ: {
		buff_size = ZXIC_SIZEOF(struct se_stat_cfg_t);
		break;
	}
	default:
		break;
	}

	return buff_size;
}

static DPP_STATUS dpp_hash_func_bulk_set(struct dpp_apt_hash_res_init_t *pHashResInit,
					 struct se_hash_func_bulk_t *p_func_bulk)
{
	u32 index = 0;
	struct dpp_apt_hash_func_res_t *p_func_res = NULL;
	struct dpp_apt_hash_bulk_res_t *p_bulk_res = NULL;

	ZXIC_COMM_CHECK_POINT(pHashResInit);
	ZXIC_COMM_CHECK_POINT(p_func_bulk);
	ZXIC_COMM_CHECK_POINT(pHashResInit->func_res);
	ZXIC_COMM_CHECK_POINT(pHashResInit->bulk_res);
	ZXIC_COMM_CHECK_INDEX_UPPER(p_func_bulk->func_num, HASH_FUNC_MAX_NUM);
	ZXIC_COMM_CHECK_INDEX_UPPER(p_func_bulk->bulk_num, HASH_BULK_MAX_NUM);

	pHashResInit->func_num = p_func_bulk->func_num;
	pHashResInit->bulk_num = p_func_bulk->bulk_num;
	for (index = 0; index < (pHashResInit->func_num); index++) {
		p_func_res = pHashResInit->func_res + index;

		p_func_res->func_id = p_func_bulk->fun[index].func_id;
		p_func_res->ddr_dis = p_func_bulk->fun[index].ddr_dis;
		p_func_res->zblk_num = p_func_bulk->fun[index].zblk_num;
		p_func_res->zblk_bitmap = p_func_bulk->fun[index].zblk_bitmap;
	}

	for (index = 0; index < (pHashResInit->bulk_num); index++) {
		p_bulk_res = pHashResInit->bulk_res + index;

		p_bulk_res->func_id = p_func_bulk->bulk[index].func_id;
		p_bulk_res->bulk_id = p_func_bulk->bulk[index].bulk_id;
		p_bulk_res->zcell_num = p_func_bulk->bulk[index].zcell_num;
		p_bulk_res->zreg_num = p_func_bulk->bulk[index].zreg_num;
		p_bulk_res->ddr_baddr = p_func_bulk->bulk[index].ddr_baddr;
		p_bulk_res->ddr_item_num = p_func_bulk->bulk[index].ddr_item_num;
		p_bulk_res->ddr_width_mode = p_func_bulk->bulk[index].ddr_width_mode;
		p_bulk_res->ddr_crc_sel = p_func_bulk->bulk[index].ddr_crc_sel;
		p_bulk_res->ddr_ecc_en = p_func_bulk->bulk[index].ddr_ecc_en;
	}

	return DPP_OK;
}

static DPP_STATUS dpp_hash_tbl_set(struct dpp_apt_hash_res_init_t *pHashResInit,
				   struct se_hash_tbl_t *p_hash_tbl)
{
	u32 index = 0;
	struct dpp_apt_hash_table_t *p_tbl_res = NULL;

	ZXIC_COMM_CHECK_POINT(pHashResInit);
	ZXIC_COMM_CHECK_POINT(p_hash_tbl);
	ZXIC_COMM_CHECK_INDEX_UPPER(p_hash_tbl->tbl_num, HASH_TABLE_MAX_NUM);

	pHashResInit->tbl_num = p_hash_tbl->tbl_num;
	for (index = 0; index < (pHashResInit->tbl_num); index++) {
		p_tbl_res = pHashResInit->tbl_res + index;

		p_tbl_res->sdtNo = p_hash_tbl->table[index].sdtNo;
		p_tbl_res->sdt_partner = p_hash_tbl->table[index].sdt_partner;
		p_tbl_res->tbl_flag = p_hash_tbl->table[index].tbl_flag;
		p_tbl_res->hashSdt.table_type = p_hash_tbl->table[index].hashSdt.table_type;
		p_tbl_res->hashSdt.hash_id = p_hash_tbl->table[index].hashSdt.hash_id;
		p_tbl_res->hashSdt.hash_table_width =
			p_hash_tbl->table[index].hashSdt.hash_table_width;
		p_tbl_res->hashSdt.key_size = p_hash_tbl->table[index].hashSdt.key_size;
		p_tbl_res->hashSdt.hash_table_id = p_hash_tbl->table[index].hashSdt.hash_table_id;
		p_tbl_res->hashSdt.learn_en = p_hash_tbl->table[index].hashSdt.learn_en;
		p_tbl_res->hashSdt.keep_alive = p_hash_tbl->table[index].hashSdt.keep_alive;
		p_tbl_res->hashSdt.keep_alive_baddr =
			p_hash_tbl->table[index].hashSdt.keep_alive_baddr;
		p_tbl_res->hashSdt.rsp_mode = p_hash_tbl->table[index].hashSdt.rsp_mode;
		p_tbl_res->hashSdt.hash_clutch_en = p_hash_tbl->table[index].hashSdt.hash_clutch_en;
	}

	return DPP_OK;
}

static DPP_STATUS dpp_eram_tbl_set(struct dpp_apt_eram_res_init_t *pEramResInit,
				   struct se_eram_tbl_t *p_eram_tbl)
{
	u32 index = 0;
	struct dpp_apt_eram_table_t *p_eram_res = NULL;

	ZXIC_COMM_CHECK_POINT(pEramResInit);
	ZXIC_COMM_CHECK_POINT(p_eram_tbl);
	ZXIC_COMM_CHECK_POINT(pEramResInit->eram_res);
	ZXIC_COMM_CHECK_INDEX_UPPER(p_eram_tbl->tbl_num, ERAM_MAX_NUM);

	pEramResInit->tbl_num = p_eram_tbl->tbl_num;
	for (index = 0; index < (pEramResInit->tbl_num); index++) {
		p_eram_res = pEramResInit->eram_res + index;

		p_eram_res->sdtNo = p_eram_tbl->eram[index].sdtNo;
		p_eram_res->opr_mode = p_eram_tbl->eram[index].opr_mode;
		p_eram_res->rd_mode = p_eram_tbl->eram[index].rd_mode;
		p_eram_res->eRamSdt.table_type = p_eram_tbl->eram[index].eRamSdt.table_type;
		p_eram_res->eRamSdt.eram_mode = p_eram_tbl->eram[index].eRamSdt.eram_mode;
		p_eram_res->eRamSdt.eram_base_addr = p_eram_tbl->eram[index].eRamSdt.eram_base_addr;
		p_eram_res->eRamSdt.eram_table_depth =
			p_eram_tbl->eram[index].eRamSdt.eram_table_depth;
		p_eram_res->eRamSdt.eram_clutch_en = p_eram_tbl->eram[index].eRamSdt.eram_clutch_en;
	}

	return DPP_OK;
}

static DPP_STATUS dpp_acl_tbl_set(struct dpp_apt_acl_res_init_t *pAclResInit,
				  struct se_acl_tbl_t *p_acl_tbl)
{
	u32 index = 0;
	struct dpp_apt_acl_table_t *p_acl_res = NULL;

	ZXIC_COMM_CHECK_POINT(pAclResInit);
	ZXIC_COMM_CHECK_POINT(p_acl_tbl);
	ZXIC_COMM_CHECK_POINT(pAclResInit->acl_res);
	ZXIC_COMM_CHECK_INDEX_UPPER(p_acl_tbl->tbl_num, ETCAM_MAX_NUM);

	pAclResInit->tbl_num = p_acl_tbl->tbl_num;
	for (index = 0; index < (p_acl_tbl->tbl_num); index++) {
		p_acl_res = pAclResInit->acl_res + index;

		p_acl_res->sdtNo = p_acl_tbl->acl[index].sdtNo;
		p_acl_res->sdt_partner = p_acl_tbl->acl[index].sdt_partner;
		p_acl_res->aclRes.block_num = p_acl_tbl->acl[index].aclRes.block_num;
		p_acl_res->aclRes.entry_num = p_acl_tbl->acl[index].aclRes.entry_num;
		p_acl_res->aclRes.pri_mode = p_acl_tbl->acl[index].aclRes.pri_mode;
		ZXIC_COMM_MEMCPY_S(p_acl_res->aclRes.block_index, sizeof(u32) * DPP_ETCAM_BLOCK_NUM,
				   p_acl_tbl->acl[index].aclRes.block_index,
				   sizeof(u32) * ETCAM_BLOCK_NUM);
		p_acl_res->aclSdt.table_type = p_acl_tbl->acl[index].aclSdt.table_type;
		p_acl_res->aclSdt.etcam_id = p_acl_tbl->acl[index].aclSdt.etcam_id;
		p_acl_res->aclSdt.etcam_key_mode = p_acl_tbl->acl[index].aclSdt.etcam_key_mode;
		p_acl_res->aclSdt.etcam_table_id = p_acl_tbl->acl[index].aclSdt.etcam_table_id;
		p_acl_res->aclSdt.no_as_rsp_mode = p_acl_tbl->acl[index].aclSdt.no_as_rsp_mode;
		p_acl_res->aclSdt.as_en = p_acl_tbl->acl[index].aclSdt.as_en;
		p_acl_res->aclSdt.as_eram_baddr = p_acl_tbl->acl[index].aclSdt.as_eram_baddr;
		p_acl_res->aclSdt.as_rsp_mode = p_acl_tbl->acl[index].aclSdt.as_rsp_mode;
		p_acl_res->aclSdt.etcam_table_depth =
			p_acl_tbl->acl[index].aclSdt.etcam_table_depth;
		p_acl_res->aclSdt.etcam_clutch_en = p_acl_tbl->acl[index].aclSdt.etcam_clutch_en;
	}

	return DPP_OK;
}

static DPP_STATUS dpp_stat_cfg_set(struct dpp_apt_stat_res_init_t *pStatResInit,
				   struct se_stat_cfg_t *p_stat_cfg)
{
	ZXIC_COMM_CHECK_POINT(pStatResInit);
	ZXIC_COMM_CHECK_POINT(p_stat_cfg);

	pStatResInit->eram_baddr = p_stat_cfg->eram_baddr;
	pStatResInit->eram_depth = p_stat_cfg->eram_depth;
	pStatResInit->ddr_baddr = p_stat_cfg->ddr_baddr;
	pStatResInit->ppu_ddr_offset = p_stat_cfg->ppu_ddr_offset;

	return DPP_OK;
}
static DPP_STATUS dpp_apt_stat_res_init(struct dpp_dev_t *dev,
					struct dpp_apt_stat_res_init_t *stat_res_init)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, stat_res_init);

	// init stat
	rc = dpp_stat_ppu_eram_baddr_set(dev, stat_res_init->eram_baddr);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_stat_ppu_eram_baddr_set");

	rc = dpp_stat_ppu_eram_depth_set(dev, stat_res_init->eram_depth); /* unit: 128bits */
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_stat_ppu_eram_depth_set");

	return rc;
}
u32 dpp_agent_hash_func_bulk_get(struct dpp_dev_t *dev, u32 type,
				 struct dpp_apt_hash_res_init_t *pHashResInit)
{
	u32 rc = DPP_OK;
	u32 dev_id = 0;
	u32 opr = HASH_FUNC_BULK_REQ;
	u32 sub_type = RES_STD_NIC_MSG;
	u32 buff_size = 0;
	struct zxic_mutex_t *p_dtb_mutex = NULL;
	u32 *p_rsp_buff = NULL;
	struct se_hash_func_bulk_t *p_func_bulk = NULL;
	enum dpp_dev_mutex_type_e mutex = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, pHashResInit);

	mutex = DPP_DEV_MUTEX_T_DTB;
	rc = dpp_dev_opr_mutex_get(dev, (u32)mutex, &p_dtb_mutex);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_dtb_mutex);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "zxic_comm_mutex_lock");

	buff_size = dpp_get_se_buff_size(opr) + sizeof(u32);
	p_rsp_buff = (u32 *)ZXIC_COMM_MALLOC(buff_size);
	ZXIC_COMM_CHECK_DEV_POINT_UNLOCK(dev_id, p_rsp_buff, p_dtb_mutex);
	ZXIC_COMM_MEMSET_S(p_rsp_buff, buff_size, 0x0, buff_size);

	sub_type = (type == SE_STD_NIC_RES_TYPE) ? RES_STD_NIC_MSG : RES_OFFLOAD_MSG;

	rc = dpp_agent_channel_se_res_get(dev, sub_type, opr, p_rsp_buff, buff_size);
	if (rc != DPP_OK) {
		ZXIC_COMM_FREE(p_rsp_buff);
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "hash func&bulk res get fail rc=0x%x.\n", rc);
		rc = zxic_comm_mutex_unlock(p_dtb_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock");
		return DPP_ERR;
	}

	rc = zxic_comm_mutex_unlock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock",
						     p_rsp_buff);

	p_func_bulk = (struct se_hash_func_bulk_t *)(p_rsp_buff + 1);
	rc = dpp_hash_func_bulk_set(pHashResInit, p_func_bulk);
	ZXIC_COMM_FREE(p_rsp_buff);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_hash_func_bulk_set");

	return DPP_OK;
}
u32 dpp_agent_hash_tbl_get(struct dpp_dev_t *dev, u32 type,
			   struct dpp_apt_hash_res_init_t *pHashResInit)
{
	u32 rc = DPP_OK;
	u32 dev_id = 0;
	u32 opr = HASH_TBL_REQ;
	u32 sub_type = RES_STD_NIC_MSG;
	u32 buff_size = 0;
	struct zxic_mutex_t *p_dtb_mutex = NULL;
	u32 *p_rsp_buff = NULL;
	struct se_hash_tbl_t *p_hash_tbl = NULL;
	enum dpp_dev_mutex_type_e mutex = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, pHashResInit);

	mutex = DPP_DEV_MUTEX_T_DTB;
	rc = dpp_dev_opr_mutex_get(dev, (u32)mutex, &p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_lock");

	buff_size = dpp_get_se_buff_size(opr) + sizeof(u32);
	p_rsp_buff = (u32 *)ZXIC_COMM_MALLOC(buff_size);
	ZXIC_COMM_CHECK_DEV_POINT_UNLOCK(dev_id, p_rsp_buff, p_dtb_mutex);

	sub_type = (type == SE_STD_NIC_RES_TYPE) ? RES_STD_NIC_MSG : RES_OFFLOAD_MSG;
	rc = dpp_agent_channel_se_res_get(dev, sub_type, opr, p_rsp_buff, buff_size);
	if (rc != DPP_OK) {
		ZXIC_COMM_FREE(p_rsp_buff);
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "hash table res get fail rc=0x%x.\n", rc);
		rc = zxic_comm_mutex_unlock(p_dtb_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock");
		return DPP_ERR;
	}

	rc = zxic_comm_mutex_unlock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock",
						     p_rsp_buff);

	p_hash_tbl = (struct se_hash_tbl_t *)(p_rsp_buff + 1);
	rc = dpp_hash_tbl_set(pHashResInit, p_hash_tbl);
	ZXIC_COMM_FREE(p_rsp_buff);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_hash_tbl_set");

	return DPP_OK;
}
static u32 dpp_agent_eram_tbl_get(struct dpp_dev_t *dev, u32 type,
				  struct dpp_apt_eram_res_init_t *pEramResInit)
{
	u32 rc = DPP_OK;
	u32 dev_id = 0;
	u32 opr = ERAM_TBL_REQ;
	u32 sub_type = RES_STD_NIC_MSG;
	u32 buff_size = 0;
	struct zxic_mutex_t *p_dtb_mutex = NULL;
	u32 *p_rsp_buff = NULL;
	struct se_eram_tbl_t *p_eram_tbl = NULL;
	enum dpp_dev_mutex_type_e mutex = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, pEramResInit);

	mutex = DPP_DEV_MUTEX_T_DTB;
	rc = dpp_dev_opr_mutex_get(dev, (u32)mutex, &p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_lock");

	buff_size = dpp_get_se_buff_size(opr) + sizeof(u32);
	p_rsp_buff = (u32 *)ZXIC_COMM_MALLOC(buff_size);
	ZXIC_COMM_CHECK_DEV_POINT_UNLOCK(dev_id, p_rsp_buff, p_dtb_mutex);

	sub_type = (type == SE_STD_NIC_RES_TYPE) ? RES_STD_NIC_MSG : RES_OFFLOAD_MSG;
	rc = dpp_agent_channel_se_res_get(dev, sub_type, opr, p_rsp_buff, buff_size);
	if (rc != DPP_OK) {
		ZXIC_COMM_FREE(p_rsp_buff);
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "eram table res get fail rc=0x%x.\n", rc);
		rc = zxic_comm_mutex_unlock(p_dtb_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock");
		return DPP_ERR;
	}

	rc = zxic_comm_mutex_unlock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock",
						     p_rsp_buff);

	p_eram_tbl = (struct se_eram_tbl_t *)(p_rsp_buff + 1);
	rc = dpp_eram_tbl_set(pEramResInit, p_eram_tbl);
	ZXIC_COMM_FREE(p_rsp_buff);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_eram_tbl_set");

	return DPP_OK;
}
static u32 dpp_agent_acl_tbl_get(struct dpp_dev_t *dev, u32 type,
				 struct dpp_apt_acl_res_init_t *pAclResInit)
{
	u32 rc = DPP_OK;
	u32 dev_id = 0;
	u32 opr = ACL_TBL_REQ;
	u32 sub_type = RES_STD_NIC_MSG;
	u32 buff_size = 0;
	struct zxic_mutex_t *p_dtb_mutex = NULL;
	u32 *p_rsp_buff = NULL;
	struct se_acl_tbl_t *p_acl_tbl = NULL;
	enum dpp_dev_mutex_type_e mutex = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, pAclResInit);

	mutex = DPP_DEV_MUTEX_T_DTB;
	rc = dpp_dev_opr_mutex_get(dev, (u32)mutex, &p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_lock");

	buff_size = dpp_get_se_buff_size(opr) + sizeof(u32);
	p_rsp_buff = (u32 *)ZXIC_COMM_MALLOC(buff_size);
	ZXIC_COMM_CHECK_DEV_POINT_UNLOCK(dev_id, p_rsp_buff, p_dtb_mutex);

	sub_type = (type == SE_STD_NIC_RES_TYPE) ? RES_STD_NIC_MSG : RES_OFFLOAD_MSG;
	rc = dpp_agent_channel_se_res_get(dev, sub_type, opr, p_rsp_buff, buff_size);
	if (rc != DPP_OK) {
		ZXIC_COMM_FREE(p_rsp_buff);
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "acl table res get fail rc=0x%x.\n", rc);
		rc = zxic_comm_mutex_unlock(p_dtb_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock");
		return DPP_ERR;
	}

	rc = zxic_comm_mutex_unlock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock",
						     p_rsp_buff);

	p_acl_tbl = (struct se_acl_tbl_t *)(p_rsp_buff + 1);
	rc = dpp_acl_tbl_set(pAclResInit, p_acl_tbl);
	ZXIC_COMM_FREE(p_rsp_buff);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_acl_tbl_set");

	return DPP_OK;
}

static u32 dpp_agent_stat_cfg_get(struct dpp_dev_t *dev, u32 type,
				  struct dpp_apt_stat_res_init_t *pStatCfgInit)
{
	u32 rc = DPP_OK;
	u32 dev_id = 0;
	u32 opr = STAT_CFG_REQ;
	u32 sub_type = RES_STD_NIC_MSG;
	u32 buff_size = 0;
	struct zxic_mutex_t *p_dtb_mutex = NULL;
	u32 *p_rsp_buff = NULL;
	struct se_stat_cfg_t *p_stat_cfg = NULL;
	enum dpp_dev_mutex_type_e mutex = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, pStatCfgInit);

	mutex = DPP_DEV_MUTEX_T_DTB;
	rc = dpp_dev_opr_mutex_get(dev, (u32)mutex, &p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_dev_opr_mutex_get");

	rc = zxic_comm_mutex_lock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_lock");

	buff_size = dpp_get_se_buff_size(opr) + sizeof(u32);
	p_rsp_buff = (u32 *)ZXIC_COMM_MALLOC(buff_size);
	ZXIC_COMM_CHECK_DEV_POINT_UNLOCK(dev_id, p_rsp_buff, p_dtb_mutex);

	sub_type = (type == SE_STD_NIC_RES_TYPE) ? RES_STD_NIC_MSG : RES_OFFLOAD_MSG;
	rc = dpp_agent_channel_se_res_get(dev, sub_type, opr, p_rsp_buff, buff_size);
	if (rc != DPP_OK) {
		ZXIC_COMM_FREE(p_rsp_buff);
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "stat res get fail rc=0x%x.\n", rc);
		rc = zxic_comm_mutex_unlock(p_dtb_mutex);
		ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock");
		return DPP_ERR;
	}

	rc = zxic_comm_mutex_unlock(p_dtb_mutex);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE_NO_ASSERT(dev_id, rc, "zxic_comm_mutex_unlock",
						     p_rsp_buff);

	p_stat_cfg = (struct se_stat_cfg_t *)(p_rsp_buff + 1);
	rc = dpp_stat_cfg_set(pStatCfgInit, p_stat_cfg);
	ZXIC_COMM_FREE(p_rsp_buff);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, "dpp_stat_cfg_set");

	return DPP_OK;
}
DPP_STATUS dpp_se_res_mem_alloc(struct dpp_dev_t *dev)
{
	u32 dev_id = 0;
	u16 slot = 0;
	struct dpp_apt_se_res_t *p_se_res = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot, 0, DPP_PCIE_SLOT_MAX - 1);

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(dev);
	if (!p_se_res) {
		p_se_res = (struct dpp_apt_se_res_t *)ZXIC_COMM_MALLOC(
			sizeof(struct dpp_apt_se_res_t));
		ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_se_res);
		ZXIC_COMM_MEMSET_S(p_se_res, sizeof(struct dpp_apt_se_res_t), 0x0,
				   sizeof(struct dpp_apt_se_res_t));
		dpp_dev_set_se_res_ptr(dev, (void *)p_se_res);
	}

	return DPP_OK;
}
DPP_STATUS dpp_se_res_mem_free(struct dpp_dev_t *dev)
{
	u32 dev_id = 0;
	u16 slot = 0;
	struct dpp_apt_se_res_t *p_se_res = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot, 0, DPP_PCIE_SLOT_MAX - 1);

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(dev);
	if (p_se_res) {
		ZXIC_COMM_FREE(p_se_res);
		dpp_dev_set_se_res_ptr(dev, NULL);
	}

	return DPP_OK;
}
DPP_STATUS dpp_agent_se_res_get(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 type = SE_STD_NIC_RES_TYPE;
	struct dpp_apt_se_res_t *p_se_res = NULL;
	struct dpp_apt_hash_res_init_t hash_res = { 0 };
	struct dpp_apt_eram_res_init_t eram_res = { 0 };
	struct dpp_apt_acl_res_init_t acl_res = { 0 };
	//DPP_APT_LPM_RES_INIT_T lpm_res = {0};
	//DPP_APT_DDR_RES_INIT_T ddr_res = {0};

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(dev);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_se_res);

	if (p_se_res->valid) {
		ZXIC_COMM_PRINT("slot[0x%x] res status ready\n", DEV_PCIE_SLOT(dev));
		return DPP_OK;
	}

	ZXIC_COMM_MEMSET_S(&hash_res, sizeof(struct dpp_apt_hash_res_init_t), 0x0,
			   sizeof(struct dpp_apt_hash_res_init_t));
	ZXIC_COMM_MEMSET_S(&eram_res, sizeof(struct dpp_apt_eram_res_init_t), 0x0,
			   sizeof(struct dpp_apt_eram_res_init_t));
	ZXIC_COMM_MEMSET_S(&acl_res, sizeof(struct dpp_apt_acl_res_init_t), 0x0,
			   sizeof(struct dpp_apt_acl_res_init_t));

	hash_res.func_res = p_se_res->hash_func;
	hash_res.bulk_res = p_se_res->hash_bulk;
	hash_res.tbl_res = p_se_res->hash_tbl;
	rc = dpp_agent_hash_func_bulk_get(dev, type, &hash_res);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_agent_hash_func_bulk_get");
	rc = dpp_agent_hash_tbl_get(dev, type, &hash_res);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_agent_hash_tbl_get");
	p_se_res->hash_func_num = hash_res.func_num;
	p_se_res->hash_bulk_num = hash_res.bulk_num;
	p_se_res->hash_tbl_num = hash_res.tbl_num;

	eram_res.eram_res = p_se_res->eram_tbl;
	rc = dpp_agent_eram_tbl_get(dev, type, &eram_res);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_agent_eram_tbl_get");
	p_se_res->eram_num = eram_res.tbl_num;

	acl_res.acl_res = p_se_res->acl_tbl;
	rc = dpp_agent_acl_tbl_get(dev, type, &acl_res);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_agent_acl_tbl_get");
	p_se_res->acl_num = acl_res.tbl_num;

	rc = dpp_agent_stat_cfg_get(dev, type, &(p_se_res->stat_cfg));
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_agent_stat_cfg_get");

	p_se_res->valid = 1;

	return DPP_OK;
}

DPP_STATUS dpp_se_res_init(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	struct dpp_apt_se_res_t *p_se_res = NULL;
	struct dpp_apt_hash_res_init_t tHashResInit = { 0 };
	struct dpp_apt_eram_res_init_t tEramResInit = { 0 };
	struct dpp_apt_acl_res_init_t tAclResInit = { 0 };
	//DPP_APT_DDR_RES_INIT_T tDdrResInit = {0};
	//DPP_APT_LPM_RES_INIT_T tLpmResInit = {0};

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	ZXIC_COMM_MEMSET(&tHashResInit, 0x0, sizeof(struct dpp_apt_hash_res_init_t));
	ZXIC_COMM_MEMSET(&tEramResInit, 0x0, sizeof(struct dpp_apt_eram_res_init_t));
	ZXIC_COMM_MEMSET(&tAclResInit, 0x0, sizeof(struct dpp_apt_acl_res_init_t));
	//ZXIC_COMM_MEMSET(&tDdrResInit,0x0,sizeof(DPP_APT_DDR_RES_INIT_T));
	//ZXIC_COMM_MEMSET(&tLpmResInit,0x0,sizeof(DPP_APT_LPM_RES_INIT_T));

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(dev);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_se_res);
	if (!p_se_res->valid) {
		ZXIC_COMM_TRACE_ERROR("dpp se_res_init:res invlaid!\n");
		return DPP_ERR;
	}

	tHashResInit.func_num = p_se_res->hash_func_num;
	tHashResInit.bulk_num = p_se_res->hash_bulk_num;
	tHashResInit.tbl_num = p_se_res->hash_tbl_num;
	tHashResInit.func_res = p_se_res->hash_func;
	tHashResInit.bulk_res = p_se_res->hash_bulk;
	tHashResInit.tbl_res = p_se_res->hash_tbl;
	tEramResInit.tbl_num = p_se_res->eram_num;
	tEramResInit.eram_res = p_se_res->eram_tbl;
	tAclResInit.tbl_num = p_se_res->acl_num;
	tAclResInit.acl_res = p_se_res->acl_tbl;
	//tLpmResInit.tbl_num = p_se_res->lpm_num;
	//tLpmResInit.glb_res = &p_se_res->lpm_global_res;
	//tLpmResInit.lpm_res = p_se_res->lpm_tbl;
	//tDdrResInit.tbl_num = p_se_res->ddr_num;
	//tDdrResInit.ddr_res = p_se_res->ddr_tbl;

	// hash init
	rc = dpp_apt_hash_global_res_init(dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_global_res_init");

	if (tHashResInit.func_num) {
		rc = dpp_apt_hash_func_res_init(dev, tHashResInit.func_num, tHashResInit.func_res);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_func_res_init");
	}

	if (tHashResInit.bulk_num) {
		rc = dpp_apt_hash_bulk_res_init(dev, tHashResInit.bulk_num, tHashResInit.bulk_res);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_bulk_res_init");
	}

	// tbl-res must be initialized after fun-res and buld-res
	if (tHashResInit.tbl_num) {
		rc = dpp_apt_hash_tbl_res_init(dev, tHashResInit.tbl_num, tHashResInit.tbl_res);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_hash_tbl_res_init");
	}

	// eram init
	if (tEramResInit.tbl_num) {
		rc = dpp_apt_eram_res_init(dev, tEramResInit.tbl_num, tEramResInit.eram_res);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_eram_res_init");
	}

	// init acl
	if (tAclResInit.tbl_num) {
		rc = dpp_apt_acl_res_init(dev, tAclResInit.tbl_num, tAclResInit.acl_res);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_acl_res_init");
	}

	// init stat
	rc = dpp_apt_stat_res_init(dev, &(p_se_res->stat_cfg));
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_stat_res_init");

	return DPP_OK;
}
DPP_STATUS dpp_se_res_get_and_init(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	rc = dpp_agent_se_res_get(dev);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_agent_se_res_get");

	rc = dpp_se_res_init(dev);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_se_res_init");

	return DPP_OK;
}
DPP_STATUS dpp_hash_max_item_num_get(struct dpp_dev_t *dev, u32 sdt_no, u32 *max_num)
{
	DPP_STATUS rc = DPP_OK;
	u32 func_id = 0;
	u32 bulk_id = 0;
	u32 index = 0;
	struct dpp_sdt_tbl_hash_t sdt_hash_info = { 0 };
	struct dpp_apt_se_res_t *p_se_res = NULL;
	struct dpp_apt_hash_bulk_res_t *p_bulk = NULL;
	struct dpp_apt_hash_bulk_res_t *p_temp_bulk = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(max_num);

	ZXIC_COMM_MEMSET_S(&sdt_hash_info, sizeof(struct dpp_sdt_tbl_hash_t), 0x0,
			   sizeof(struct dpp_sdt_tbl_hash_t));
	rc = dpp_soft_sdt_tbl_get(dev, sdt_no, &sdt_hash_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_soft_sdt_tbl_get");

	func_id = sdt_hash_info.hash_id;
	bulk_id = (sdt_hash_info.hash_table_id >> 2) & 0x7;

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(dev);
	ZXIC_COMM_CHECK_POINT(p_se_res);

	p_bulk = p_se_res->hash_bulk;
	for (index = 0; index < HASH_BULK_MAX_NUM; index++) {
		p_temp_bulk = p_bulk + index;
		if ((p_temp_bulk->func_id == func_id) && (p_temp_bulk->bulk_id == bulk_id)) {
			*max_num = p_temp_bulk->ddr_item_num;
			return DPP_OK;
		}
	}
	return DPP_ERR;
}
static DPP_STATUS dpp_stat_tbl_parse(struct dpp_dev_t *dev, u32 sdt_no, u32 entry_num,
				     struct dpp_dtb_eram_entry_info_t *p_dump_data_arr,
				     u32 *p_stat_item_num, struct dpp_stat_item_t *p_stat_item)
{
	DPP_STATUS rc = DPP_OK;
	u32 i = 0;
	u32 valid_item_num = 0;
	u32 *p_data = NULL;
	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_stat_item_t *p_temp_stat_item = NULL;
	struct zxdh_stat_attr_t stat_attr = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_dump_data_arr);
	ZXIC_COMM_CHECK_POINT(p_stat_item_num);
	ZXIC_COMM_CHECK_POINT(p_stat_item);

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback->se_func_info.eramFunc.eram_get_func);

	for (i = 0; (i < entry_num) && (i < STAT_ITEM_MAX_NUM); i++) {
		p_data = p_dump_data_arr[i].p_data;
		ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

		rc = pAptCallback->se_func_info.eramFunc.eram_get_func((void *)&stat_attr, p_data);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "eram_get_func");

		if (stat_attr.valid) {
			valid_item_num++;
			p_temp_stat_item = p_stat_item + i;
			p_temp_stat_item->mode = stat_attr.mode;
			p_temp_stat_item->addr_offset = stat_attr.addr_offset;
			p_temp_stat_item->depth = stat_attr.depth;
		}
	}

	*p_stat_item_num = valid_item_num;

	return DPP_OK;
}
DPP_STATUS dpp_stat_tbl_get(struct dpp_dev_t *dev, struct dpp_apt_se_res_t *p_se_res)
{
	DPP_STATUS rc = DPP_OK;
	u32 queue_id = 0;
	u32 stat_sdt_no = ZXDH_SDT_STAT_ATTR_TABLE;
	u32 exist_flag = 0;
	u32 eram_table_depth = 0;
	u32 byte_num = 0;
	u32 dev_id = 0;
	u32 i = 0;
	u32 entry_num = 0;
	struct dpp_sdt_tbl_eram_t sdt_eram = { 0 };
	struct dpp_dtb_eram_entry_info_t *p_dump_data_arr = NULL;
	u8 *data_buff = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_se_res);

	rc = dpp_apt_sdt_is_exist(p_se_res, DPP_SDT_TBLT_eRAM, stat_sdt_no, &exist_flag);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_sdt_is_exist");
	if (!exist_flag) {
		ZXIC_COMM_PRINT("sdt_no:%d is not exsit, can not get stat item info.\n",
				stat_sdt_no);
		return DPP_OK;
	}

	rc = dpp_soft_sdt_tbl_get(dev, stat_sdt_no, &sdt_eram);
	ZXIC_COMM_CHECK_RC(rc, "dpp_soft_sdt_tbl_get");

	rc = dpp_dtb_queue_id_get(dev, &queue_id);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, sdt_eram.eram_mode, ERAM128_TBL_64b, ERAM128_TBL_128b);
	byte_num = (sdt_eram.eram_mode == ERAM128_TBL_64b) ? 8 : 16;
	eram_table_depth = sdt_eram.eram_table_depth;
	p_dump_data_arr = (struct dpp_dtb_eram_entry_info_t *)ZXIC_COMM_MALLOC(
		eram_table_depth * sizeof(struct dpp_dtb_eram_entry_info_t));
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_dump_data_arr);
	ZXIC_COMM_MEMSET_S(p_dump_data_arr,
			   eram_table_depth * sizeof(struct dpp_dtb_eram_entry_info_t), 0,
			   eram_table_depth * sizeof(struct dpp_dtb_eram_entry_info_t));

	data_buff = (u8 *)ZXIC_COMM_MALLOC(byte_num * eram_table_depth);
	ZXIC_COMM_CHECK_DEV_POINT_MEMORY_FREE(dev_id, data_buff, p_dump_data_arr);
	ZXIC_COMM_MEMSET_S(data_buff, eram_table_depth * byte_num, 0, eram_table_depth * byte_num);

	for (i = 0; i < eram_table_depth; i++) {
		p_dump_data_arr[i].index = i;
		p_dump_data_arr[i].p_data = (u32 *)(data_buff + i * byte_num);
	}

	rc = dpp_dtb_eram_dump(dev, queue_id, stat_sdt_no, (u8 *)p_dump_data_arr, &entry_num);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE2PTR_NO_ASSERT(dev_id, rc, "dpp_dtb_eram_dump", data_buff,
							 p_dump_data_arr);

	rc = dpp_stat_tbl_parse(dev, stat_sdt_no, entry_num, p_dump_data_arr,
				&p_se_res->stat_item_num, p_se_res->stat_item);
	ZXIC_COMM_FREE(data_buff);
	ZXIC_COMM_FREE(p_dump_data_arr);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_stat_tbl_parse");

	return DPP_OK;
}
DPP_STATUS dpp_apt_sdt_is_exist(struct dpp_apt_se_res_t *p_se_res,
				enum dpp_sdt_table_type_e sdt_type, u32 sdt_no, u32 *p_is_exist)
{
	u8 index = 0;

	ZXIC_COMM_CHECK_POINT(p_se_res);

	*p_is_exist = 0;
	if (sdt_type == DPP_SDT_TBLT_eRAM) {
		for (index = 0; (index < p_se_res->eram_num) && (index < ERAM_MAX_NUM); index++) {
			if (p_se_res->eram_tbl[index].sdtNo == sdt_no) {
				*p_is_exist = 1;
				break;
			}
		}
	} else if (sdt_type == DPP_SDT_TBLT_eTCAM) {
		for (index = 0; (index < p_se_res->acl_num) && (index < ETCAM_MAX_NUM); index++) {
			if (p_se_res->acl_tbl[index].sdtNo == sdt_no) {
				*p_is_exist = 1;
				break;
			}
		}
	} else if (sdt_type == DPP_SDT_TBLT_HASH) {
		for (index = 0; (index < p_se_res->hash_tbl_num) && (index < HASH_TABLE_MAX_NUM);
		     index++) {
			if (p_se_res->hash_tbl[index].sdtNo == sdt_no) {
				*p_is_exist = 1;
				break;
			}
		}
	}

	return DPP_OK;
}
