// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"

#include "dpp_dev.h"
#include "dpp_sdt_def.h"
#include "dpp_sdt.h"
#include "dpp_sdt_mgr.h"
#include "dpp_se_api.h"

static struct dpp_sdt_mgr_t g_sdt_mgr = { 0 };

#define DPP_SDT_MGR_PTR_GET() (&g_sdt_mgr)

#define DPP_SDT_SOFT_TBL_GET(id) (g_sdt_mgr.sdt_tbl_array[id])

u32 dpp_sdt_mgr_init(void)
{
	if (!g_sdt_mgr.is_init) {
		g_sdt_mgr.channel_num = 0;
		g_sdt_mgr.is_init = 1;
		// g_sdt_mgr.p_sdt_mgr_smmu0_mux = dpp_tbl_dir_sdt_smmu0_mux;
		// g_sdt_mgr.p_sdt_mgr_smmu1_mux = dpp_tbl_dir_sdt_smmu1_mux;
		// g_sdt_mgr.p_sdt_mgr_hash_mux = dpp_tbl_dir_sdt_hash_mux;
		// g_sdt_mgr.p_sdt_mgr_lpm_mux = dpp_tbl_dir_sdt_lpm_mux;
		// g_sdt_mgr.p_sdt_mgr_etcam_mux = dpp_tbl_dir_sdt_etcam_mux;
		ZXIC_COMM_MEMSET(g_sdt_mgr.sdt_tbl_array, 0,
				 DPP_DEV_CHANNEL_MAX * sizeof(struct dpp_sdt_soft_table_t *));
	}

	return DPP_OK;
}

u32 dpp_sdt_mgr_create(u32 dev_id)
{
	struct dpp_sdt_soft_table_t *p_sdt_tbl_temp = NULL;
	struct dpp_sdt_mgr_t *p_sdt_mgr = NULL;

	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	p_sdt_mgr = DPP_SDT_MGR_PTR_GET();

	if (DPP_SDT_SOFT_TBL_GET(dev_id) == NULL) {
		p_sdt_tbl_temp = ZXIC_COMM_MALLOC(sizeof(struct dpp_sdt_soft_table_t));
		ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_sdt_tbl_temp); /* mod for KW_0411 # 474 */

		p_sdt_tbl_temp->device_id = dev_id;
		ZXIC_COMM_MEMSET(p_sdt_tbl_temp->sdt_array, 0,
				 DPP_PCIE_SLOT_MAX * DPP_DEV_SDT_ID_MAX *
					 sizeof(struct dpp_sdt_item_t));

		DPP_SDT_SOFT_TBL_GET(dev_id) = p_sdt_tbl_temp;
		ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(dev_id, p_sdt_mgr->channel_num, 1);
		p_sdt_mgr->channel_num++;
	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "Error: dpp sdt_mgr_create for dev[%d] is called repeatedly!\n",
			dev_id);
	}

	return DPP_OK;
}

u32 dpp_sdt_mgr_destroy(u32 dev_id)
{
	struct dpp_sdt_soft_table_t *p_sdt_tbl_temp = NULL;
	struct dpp_sdt_mgr_t *p_sdt_mgr = NULL;

	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	p_sdt_tbl_temp = DPP_SDT_SOFT_TBL_GET(dev_id);
	p_sdt_mgr = DPP_SDT_MGR_PTR_GET();

	if (p_sdt_tbl_temp)
		ZXIC_COMM_FREE(p_sdt_tbl_temp);

	DPP_SDT_SOFT_TBL_GET(dev_id) = NULL;

	ZXIC_COMM_CHECK_DEV_INDEX_SUB_OVERFLOW_NO_ASSERT(dev_id, p_sdt_mgr->channel_num, 1);
	p_sdt_mgr->channel_num--;

	return DPP_OK;
}

DPP_STATUS dpp_sdt_mgr_sdt_item_add(struct dpp_dev_t *dev, u32 sdt_no, u32 sdt_hig32, u32 sdt_low32)
{
	u32 slot = 0;
	u32 dev_id = 0;
	struct dpp_sdt_soft_table_t *p_sdt_soft_tbl = NULL;
	struct dpp_sdt_item_t *p_sdt_item = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	slot = DEV_PCIE_SLOT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot, 0, DPP_PCIE_SLOT_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	p_sdt_soft_tbl = DPP_SDT_SOFT_TBL_GET(dev_id);

	if (!p_sdt_soft_tbl) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "Error: dpp sdt_mgr_sdt_item_add soft sdt table not Init!\n");
		ZXIC_COMM_ASSERT(0);
		return DPP_RC_TABLE_SDT_MGR_INVALID;
	}

	if (dev_id != p_sdt_soft_tbl->device_id) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "Error: dpp sdt_mgr_sdt_item_add soft sdt table Item Invalid!\n");
		ZXIC_COMM_ASSERT(0);
		return DPP_RC_TABLE_PARA_INVALID;
	}

	p_sdt_item = &(p_sdt_soft_tbl->sdt_array[slot][sdt_no]);
	p_sdt_item->valid = DPP_SDT_VALID;
	p_sdt_item->table_cfg[0] = sdt_hig32; /* hig32 */
	p_sdt_item->table_cfg[1] = sdt_low32; /* low32 */

	ZXIC_COMM_TRACE_DEV_DEBUG(dev_id, "dpp sdt_mgr_sdt_item_add 0x%08x 0x%08x\n",
				  p_sdt_item->table_cfg[0], p_sdt_item->table_cfg[1]);

	return DPP_OK;
}
DPP_STATUS dpp_sdt_mgr_sdt_item_srh(struct dpp_dev_t *dev, u32 sdt_no, u32 *p_sdt_hig32,
				    u32 *p_sdt_low32)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 slot = 0;
	struct dpp_sdt_soft_table_t *p_sdt_soft_tbl = NULL;
	struct dpp_sdt_item_t *p_sdt_item = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot, 0, DPP_PCIE_SLOT_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_sdt_hig32);
	ZXIC_COMM_CHECK_DEV_POINT(dev_id, p_sdt_low32);

	p_sdt_soft_tbl = DPP_SDT_SOFT_TBL_GET(dev_id);

	if (!p_sdt_soft_tbl) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id,
					  "Error: dpp sdt_mgr_sdt_item_srh Soft Table not Init!\n");
		ZXIC_COMM_ASSERT(0);
		return DPP_RC_TABLE_SDT_MGR_INVALID;
	}

	if (dev_id != p_sdt_soft_tbl->device_id) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "Error: dpp sdt_mgr_sdt_item_srh Soft Table Item Invalid !\n");
		ZXIC_COMM_ASSERT(0);
		return DPP_RC_TABLE_PARA_INVALID;
	}

	p_sdt_item = &p_sdt_soft_tbl->sdt_array[slot][sdt_no];

	if (p_sdt_item->valid == DPP_SDT_VALID) {
		*p_sdt_hig32 = p_sdt_item->table_cfg[0];
		*p_sdt_low32 = p_sdt_item->table_cfg[1];
	} else {
		*p_sdt_hig32 = 0xFFFFFFFF;
		*p_sdt_low32 = 0xFFFFFFFF;
	}

	ZXIC_COMM_TRACE_DEV_DEBUG(
		dev_id,
		"dpp sdt_mgr_sdt_item_srh is %s: sdt_no: 0x%08x sdt_hig32:0x%08x sdt_low32:0x%08x\n",
		((p_sdt_item->valid == DPP_SDT_VALID) ? ("success") : ("fail")), sdt_no,
		*p_sdt_hig32, *p_sdt_low32);

	return rc;
}
DPP_STATUS dpp_sdt_mgr_sdt_item_del(struct dpp_dev_t *dev, u32 sdt_no)
{
	u32 dev_id = 0;
	u32 slot = 0;
	struct dpp_sdt_soft_table_t *p_sdt_soft_tbl = NULL;
	struct dpp_sdt_item_t *p_sdt_item = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, slot, 0, DPP_PCIE_SLOT_MAX - 1);

	p_sdt_soft_tbl = DPP_SDT_SOFT_TBL_GET(dev_id);
	if (p_sdt_soft_tbl) {
		if (dev_id != p_sdt_soft_tbl->device_id) {
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id,
				"Error: dpp sdt_mgr_sdt_item_del Soft Table Item Invalid !\n");
			ZXIC_COMM_ASSERT(0);
			return DPP_RC_TABLE_PARA_INVALID;
		}

		p_sdt_item = &p_sdt_soft_tbl->sdt_array[slot][sdt_no];
		p_sdt_item->valid = DPP_SDT_INVALID;
		p_sdt_item->table_cfg[0] = 0;
		p_sdt_item->table_cfg[1] = 0;
	}
	ZXIC_COMM_TRACE_DEV_DEBUG(dev_id, "dpp sdt_mgr_sdt_item_del sdt_no: 0x%08x\n", sdt_no);
	return DPP_OK;
}

enum dpp_tbl_type_e dpp_sdt_mgr_get_tbl_type(struct dpp_dev_t *dev, u32 sdt_no)
{
	u32 dev_id = 0;
	u32 rtn = 0;
	enum dpp_tbl_type_e table_type = 0;
	u32 table_cfg[DPP_SDT_CFG_LEN] = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	rtn = dpp_sdt_mgr_sdt_item_srh(dev, sdt_no, &(table_cfg[0]), &(table_cfg[1]));
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rtn, "dpp sdt_mgr_sdt_item_srh");

	table_type = (enum dpp_tbl_type_e)((table_cfg[0] >> 29) & 0x7);

	ZXIC_COMM_TRACE_DEV_DEBUG(
		dev_id, "dpp sdt_mgr_get_tbl_type: dev_id: %d, sdt_no: %d, table_type: %d.\n",
		dev_id, sdt_no, table_type);

	return table_type;
}
