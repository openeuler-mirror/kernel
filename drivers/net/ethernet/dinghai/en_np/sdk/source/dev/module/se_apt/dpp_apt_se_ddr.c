// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se.h"
#include "dpp_dev.h"
#include "dpp_sdt.h"
DPP_STATUS dpp_apt_ddr_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				struct dpp_apt_ddr_table_t *pDdrTbl)
{
	DPP_STATUS rc = DPP_OK;
	u8 index = 0;
	struct dpp_apt_ddr_table_t *pTempDdrTbl = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(tbl_num, DPP_DEV_SDT_ID_MAX);
	ZXIC_COMM_CHECK_POINT(pDdrTbl);

	for (index = 0; index < tbl_num; index++) {
		pTempDdrTbl = pDdrTbl + index;
		rc = dpp_sdt_tbl_write(dev, pTempDdrTbl->sdtNo, pTempDdrTbl->eDdrSdt.table_type,
				       &(pTempDdrTbl->eDdrSdt), SDT_OPER_ADD);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_sdt_tbl_write");

		rc = dpp_apt_set_callback(dev, pTempDdrTbl->sdtNo, pTempDdrTbl->eDdrSdt.table_type,
					  (void *)pTempDdrTbl);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_apt_set_callback");
	}

	return DPP_OK;
}
