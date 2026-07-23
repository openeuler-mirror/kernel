// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se.h"
#include "dpp_dev.h"
#include "dpp_sdt.h"
#include "dpp_acl.h"
#include "dpp_dtb_table.h"

static struct dpp_acl_cfg_ex_t *g_apt_acl_cfg[DPP_PCIE_SLOT_MAX] = { NULL };

struct dpp_acl_cfg_ex_t *dpp_apt_get_acl_cfg(struct dpp_dev_t *dev)
{
	u32 slot = 0;

	if (dev == NULL)
		return NULL;
	slot = DEV_PCIE_SLOT(dev);
	if (slot < DPP_PCIE_SLOT_MAX)
		return g_apt_acl_cfg[slot];
	return NULL;
}
DPP_STATUS dpp_apt_acl_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				struct dpp_apt_acl_table_t *pAclTblRes)
{
	DPP_STATUS rc = DPP_OK;
	u8 index = 0;
	u32 slot = 0;
	struct dpp_apt_acl_table_t *pTempAclTbl = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(tbl_num, DPP_ETCAM_TBLID_NUM);
	ZXIC_COMM_CHECK_POINT(pAclTblRes);

	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	if (g_apt_acl_cfg[slot] == NULL) {
		g_apt_acl_cfg[slot] = (struct dpp_acl_cfg_ex_t *)ZXIC_COMM_MALLOC(
			sizeof(struct dpp_acl_cfg_ex_t));
		ZXIC_COMM_CHECK_POINT(g_apt_acl_cfg[slot]);
	}

	rc = dpp_acl_cfg_init_ex(dev, g_apt_acl_cfg[slot],
				 (void *)ZXIC_COMM_VAL_TO_PTR(DEV_ID(dev)), DPP_ACL_FLAG_ETCAM0_EN,
				 NULL);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_acl_cfg_init_ex");

	for (index = 0; index < tbl_num; index++) {
		pTempAclTbl = pAclTblRes + index;
		rc = dpp_sdt_tbl_write(dev, pTempAclTbl->sdtNo, pTempAclTbl->aclSdt.table_type,
				       &(pTempAclTbl->aclSdt), SDT_OPER_ADD);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_sdt_tbl_write");

		rc = dpp_acl_tbl_init_ex(
			g_apt_acl_cfg[slot], pTempAclTbl->aclSdt.etcam_table_id,
			pTempAclTbl->aclSdt.as_en, pTempAclTbl->aclRes.entry_num,
			pTempAclTbl->aclRes.pri_mode, pTempAclTbl->aclSdt.etcam_key_mode,
			pTempAclTbl->aclSdt.as_rsp_mode, pTempAclTbl->aclSdt.as_eram_baddr,
			pTempAclTbl->aclRes.block_num, pTempAclTbl->aclRes.block_index);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_acl_tbl_init_ex");

		rc = dpp_apt_set_callback(dev, pTempAclTbl->sdtNo, pTempAclTbl->aclSdt.table_type,
					  (void *)pTempAclTbl);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_apt_set_callback");
	}

	return DPP_OK;
}
DPP_STATUS dpp_apt_acl_soft_res_uninit(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 table_id = 0;
	u32 as_enable = 0;
	u32 pri_mode = 0;
	u32 slot = 0;
	struct dpp_acl_cfg_ex_t *p_acl_cfg = NULL;
	struct dpp_acl_tbl_cfg_t *p_tbl_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	rc = dpp_acl_cfg_get(dev, &p_acl_cfg);
	ZXIC_COMM_CHECK_RC(rc, "dpp_acl_cfg_get");

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
		if ((pri_mode == DPP_ACL_PRI_EXPLICIT) || (pri_mode == DPP_ACL_PRI_IMPLICIT)) {
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

	if (g_apt_acl_cfg[slot] != NULL) {
		ZXIC_COMM_FREE(g_apt_acl_cfg[slot]);
		g_apt_acl_cfg[slot] = NULL;
		dpp_acl_cfg_set(dev, NULL);
	}

	return DPP_OK;
}
DPP_STATUS dpp_apt_dtb_acl_entry_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					void *pData)
{
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[16] = { 0 }; /*128bit*/
	u32 element_id = 0;
	u32 rc = DPP_OK;

	struct dpp_acl_entry_ex_t aclEntry = { 0 };
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };

	struct se_apt_callback_t *pAptCallback = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(pData);

	ZXIC_COMM_MEMSET(data, 0x0, sizeof(data));
	ZXIC_COMM_MEMSET(mask, 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET(rst, 0x0, sizeof(rst));
	ZXIC_COMM_MEMSET(&aclEntry, 0x0, sizeof(struct dpp_acl_entry_ex_t));
	ZXIC_COMM_MEMSET(&tDtbAclEntry, 0x0, sizeof(struct dpp_dtb_acl_entry_info_t));

	aclEntry.key_data = data;
	aclEntry.key_mask = mask;
	aclEntry.p_as_rslt = rst;

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback->se_func_info.aclFunc.acl_set_func);

	rc = pAptCallback->se_func_info.aclFunc.acl_set_func((void *)pData, &aclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "acl_entry_func");

	tDtbAclEntry.handle = aclEntry.pri;
	tDtbAclEntry.key_data = aclEntry.key_data;
	tDtbAclEntry.key_mask = aclEntry.key_mask;
	tDtbAclEntry.p_as_rslt = aclEntry.p_as_rslt;

	rc = dpp_dtb_acl_dma_insert(dev, queue_id, sdt_no, 1, &tDtbAclEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_acl_dma_insert");

	return rc;
}
DPP_STATUS dpp_apt_dtb_acl_entry_del(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData)
{
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[16] = { 0 }; /*128bit*/
	u32 element_id = 0;
	u32 rc = DPP_OK;

	struct dpp_acl_entry_ex_t aclEntry = { 0 };
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(pData);

	ZXIC_COMM_MEMSET(data, 0xff, sizeof(data));
	ZXIC_COMM_MEMSET(mask, 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET(rst, 0x0, sizeof(rst));
	ZXIC_COMM_MEMSET(&aclEntry, 0x0, sizeof(struct dpp_acl_entry_ex_t));
	ZXIC_COMM_MEMSET(&tDtbAclEntry, 0x0, sizeof(struct dpp_dtb_acl_entry_info_t));

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback->se_func_info.aclFunc.acl_set_func);

	rc = pAptCallback->se_func_info.aclFunc.acl_set_func((void *)pData, &aclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "acl_entry_func");

	tDtbAclEntry.handle = aclEntry.pri;
	tDtbAclEntry.key_data = data;
	tDtbAclEntry.key_mask = mask;
	tDtbAclEntry.p_as_rslt = rst;

	rc = dpp_dtb_acl_dma_insert(dev, queue_id, sdt_no, 1, &tDtbAclEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_acl_dma_insert");

	return rc;
}
DPP_STATUS dpp_apt_dtb_acl_entry_search(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					void *pData)
{
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[16] = { 0 }; /*128bit*/
	u32 rc = DPP_OK;

	struct dpp_acl_entry_ex_t aclEntry = { 0 };
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };

	struct se_apt_callback_t *pAptCallback = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(pData);

	ZXIC_COMM_MEMSET(data, 0x0, sizeof(data));
	ZXIC_COMM_MEMSET(mask, 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET(rst, 0x0, sizeof(rst));
	ZXIC_COMM_MEMSET(&aclEntry, 0x0, sizeof(struct dpp_acl_entry_ex_t));
	ZXIC_COMM_MEMSET(&tDtbAclEntry, 0x0, sizeof(struct dpp_dtb_acl_entry_info_t));

	aclEntry.key_data = data;
	aclEntry.key_mask = mask;
	aclEntry.p_as_rslt = rst;

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback->se_func_info.aclFunc.acl_set_func);

	rc = pAptCallback->se_func_info.aclFunc.acl_set_func((void *)pData, &aclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "acl_entry_func");

	tDtbAclEntry.handle = aclEntry.pri;
	tDtbAclEntry.key_data = aclEntry.key_data;
	tDtbAclEntry.key_mask = aclEntry.key_mask;
	tDtbAclEntry.p_as_rslt = aclEntry.p_as_rslt;

	rc = dpp_dtb_acl_data_get(dev, queue_id, sdt_no, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_acl_data_get");

	aclEntry.pri = tDtbAclEntry.handle;
	aclEntry.key_data = tDtbAclEntry.key_data;
	aclEntry.key_mask = tDtbAclEntry.key_mask;
	aclEntry.p_as_rslt = tDtbAclEntry.p_as_rslt;

	rc = pAptCallback->se_func_info.aclFunc.acl_get_func((void *)pData, &aclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "acl_entry_func");

	return rc;
}
DPP_STATUS dpp_apt_dtb_acl_entry_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData)
{
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 }; /*640bit*/
	u8 rst[16] = { 0 }; /*128bit*/
	u32 rc = DPP_OK;

	struct dpp_acl_entry_ex_t aclEntry = { 0 };
	struct dpp_dtb_acl_entry_info_t tDtbAclEntry = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(pData);

	ZXIC_COMM_MEMSET(data, 0x0, sizeof(data));
	ZXIC_COMM_MEMSET(mask, 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET(rst, 0x0, sizeof(rst));
	ZXIC_COMM_MEMSET(&aclEntry, 0x0, sizeof(struct dpp_acl_entry_ex_t));
	ZXIC_COMM_MEMSET(&tDtbAclEntry, 0x0, sizeof(struct dpp_dtb_acl_entry_info_t));

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback->se_func_info.aclFunc.acl_set_func);

	rc = pAptCallback->se_func_info.aclFunc.acl_set_func((void *)pData, &aclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "acl_entry_func");

	tDtbAclEntry.handle = aclEntry.pri;
	tDtbAclEntry.key_data = data;
	tDtbAclEntry.key_mask = mask;
	tDtbAclEntry.p_as_rslt = rst;

	rc = dpp_dtb_etcam_data_get(dev, queue_id, sdt_no, &tDtbAclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_etcam_data_get");

	aclEntry.pri = tDtbAclEntry.handle;
	aclEntry.key_data = tDtbAclEntry.key_data;
	aclEntry.key_mask = tDtbAclEntry.key_mask;
	aclEntry.p_as_rslt = tDtbAclEntry.p_as_rslt;
	rc = pAptCallback->se_func_info.aclFunc.acl_get_func((void *)pData, &aclEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "acl_entry_func");

	return rc;
}
