// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_drv_init.h"
#include "dpp_drv_eram.h"
#include "dpp_drv_sdt.h"
#include "dpp_dev.h"
#include "dpp_dtb.h"
#include "dpp_dtb_table.h"
#include "dpp_tbl_api.h"

u32 dpp_eram_entry_insert(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 index, u8 *p_data)
{
	struct dpp_dev_t dev = { 0 };
	struct dpp_dtb_eram_entry_info_t eram_entry = { 0 };

	u32 queue = 0;
	u32 element_id = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_data);

	ZXIC_COMM_MEMSET_S(&eram_entry, sizeof(struct dpp_dtb_eram_entry_info_t), 0,
			   sizeof(struct dpp_dtb_eram_entry_info_t));
	eram_entry.index = index;
	eram_entry.p_data = (u32 *)p_data;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_eram_dma_write(&dev, queue, sdt_no, 1, &eram_entry, &element_id);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_dma_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_eram_entry_insert);

u32 dpp_eram_entry_delete(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 index)
{
	struct dpp_dev_t dev = { 0 };
	u8 data[DPP_SMMU0_READ_REG_MAX_NUM * 4] = { 0 };
	struct dpp_dtb_eram_entry_info_t eram_entry = { 0 };

	u32 queue = 0;
	u32 element_id = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_MEMSET_S(&eram_entry, sizeof(struct dpp_dtb_eram_entry_info_t), 0,
			   sizeof(struct dpp_dtb_eram_entry_info_t));
	ZXIC_COMM_MEMSET_S(data, sizeof(data), 0, sizeof(data));
	eram_entry.index = index;
	eram_entry.p_data = (u32 *)data;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_eram_dma_write(&dev, queue, sdt_no, 1, &eram_entry, &element_id);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_dma_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_eram_entry_delete);

u32 dpp_eram_entry_get(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 index, u8 *p_data)
{
	struct dpp_dev_t dev = { 0 };
	u32 queue = 0;
	u32 rc = DPP_OK;
	struct dpp_dtb_eram_entry_info_t eram_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_data);

	ZXIC_COMM_MEMSET_S(&eram_entry, sizeof(struct dpp_dtb_eram_entry_info_t), 0,
			   sizeof(struct dpp_dtb_eram_entry_info_t));
	eram_entry.index = index;
	eram_entry.p_data = (u32 *)p_data;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_eram_data_get(&dev, queue, sdt_no, &eram_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_dma_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_eram_entry_get);
