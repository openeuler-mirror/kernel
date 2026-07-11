// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se.h"
#include "dpp_dev.h"
#include "dpp_sdt.h"
#include "dpp_dtb_table.h"
#include "dpp_dtb_table_api.h"
#include "dpp_apt_se.h"
DPP_STATUS dpp_apt_eram_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				 struct dpp_apt_eram_table_t *pEramTbl)
{
	DPP_STATUS rc = DPP_OK;
	u8 index = 0;
	struct dpp_apt_eram_table_t *pTempEramTbl = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(tbl_num, DPP_DEV_SDT_ID_MAX);
	ZXIC_COMM_CHECK_POINT(pEramTbl);

	for (index = 0; index < tbl_num; index++) {
		pTempEramTbl = pEramTbl + index;
		rc = dpp_sdt_tbl_write(dev, pTempEramTbl->sdtNo, pTempEramTbl->eRamSdt.table_type,
				       &(pTempEramTbl->eRamSdt), SDT_OPER_ADD);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_sdt_tbl_write");

		rc = dpp_apt_set_callback(dev, pTempEramTbl->sdtNo,
					  pTempEramTbl->eRamSdt.table_type, (void *)pTempEramTbl);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_apt_set_callback");
	}

	return DPP_OK;
}
DPP_STATUS dpp_apt_dtb_eram_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				   void *pData)
{
	u32 rc = DPP_OK;
	u32 element_id = 0;
	u32 dump_data[4] = { 0 };

	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_dtb_eram_entry_info_t dtb_eram_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET(dump_data, 0x00, sizeof(dump_data));

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	rc = pAptCallback->se_func_info.eramFunc.eram_set_func(pData, dump_data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "eram_set_func");

	dtb_eram_entry.index = index;
	dtb_eram_entry.p_data = dump_data;
	rc = dpp_dtb_eram_dma_write(dev, queue_id, sdt_no, 1, &dtb_eram_entry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_eram_dma_write");

	return rc;
}
DPP_STATUS dpp_apt_dtb_eram_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				void *pData)
{
	u32 rc = DPP_OK;
	u32 dump_data[4] = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_dtb_eram_entry_info_t dump_eram_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET(dump_data, 0x00, sizeof(dump_data));

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	dump_eram_entry.index = index;
	dump_eram_entry.p_data = dump_data;
	rc = dpp_dtb_eram_data_get(dev, queue_id, sdt_no, &dump_eram_entry);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_eram_data_get");

	rc = pAptCallback->se_func_info.eramFunc.eram_get_func(pData, dump_eram_entry.p_data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "eram_get_func");

	return rc;
}
DPP_STATUS dpp_apt_dtb_eram_clear(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index)
{
	u32 rc = DPP_OK;
	u32 element_id = 0;
	u32 dump_data[4] = { 0 };

	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_dtb_eram_entry_info_t dtb_eram_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET(dump_data, 0x00, sizeof(dump_data));

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	dtb_eram_entry.index = index;
	dtb_eram_entry.p_data = dump_data;
	rc = dpp_dtb_eram_dma_write(dev, queue_id, sdt_no, 1, &dtb_eram_entry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_eram_dma_write");

	return rc;
}
DPP_STATUS dpp_apt_dtb_eram_flush(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no)
{
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	rc = dpp_dtb_eram_table_flush(dev, queue_id, sdt_no);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_eram_table_flush");
	ZXIC_COMM_TRACE_ERROR("dpp apt_dtb_eram_flush sdt_no %d done.\n", sdt_no);

	return rc;
}
