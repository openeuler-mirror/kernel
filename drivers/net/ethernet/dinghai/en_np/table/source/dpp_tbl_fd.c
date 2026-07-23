// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_drv_init.h"
#include "dpp_drv_acl.h"
#include "dpp_drv_hash.h"
#include "dpp_drv_eram.h"
#include "dpp_drv_sdt.h"
#include "dpp_dev.h"
#include "dpp_dtb.h"
#include "dpp_hash.h"
#include "dpp_dtb_table.h"
#include "dpp_dtb_table_api.h"
#include "dpp_tbl_comm.h"
#include "dpp_tbl_fd.h"
#include "dpp_tbl_stat.h"

u32 dpp_fd_acl_index_request(struct dpp_pf_info_t *pf_info, u32 *p_index)
{
	struct dpp_dev_t dev = { 0 };

	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_index);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_acl_index_request(&dev, sdt_no, pf_info->vport, p_index);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_index_request", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u.\n", __func__,
			       pf_info->slot, pf_info->vport, sdt_no, *p_index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_index_request);

u32 dpp_fd_acl_index_release(struct dpp_pf_info_t *pf_info, u32 index)
{
	struct dpp_dev_t dev = { 0 };

	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_acl_index_release(&dev, sdt_no, pf_info->vport, index);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_index_release", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u.\n", __func__,
			       pf_info->slot, pf_info->vport, sdt_no, index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_index_release);

u32 dpp_fd_acl_entry_add(struct dpp_pf_info_t *pf_info, u32 handle, u8 *key, u8 *key_mask,
			 u8 *result)
{
	struct dpp_dev_t dev = { 0 };
	struct dpp_dtb_acl_entry_info_t fd_entry = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;
	u32 element_id = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(key);
	ZXIC_COMM_CHECK_POINT(key_mask);
	ZXIC_COMM_CHECK_POINT(result);

	ZXIC_COMM_MEMSET_S(&fd_entry, sizeof(struct dpp_dtb_acl_entry_info_t), 0,
			   sizeof(struct dpp_dtb_acl_entry_info_t));
	fd_entry.handle = handle;
	fd_entry.key_data = key;
	fd_entry.key_mask = key_mask;
	fd_entry.p_as_rslt = result;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_acl_dma_insert(&dev, queue, sdt_no, 1, &fd_entry, &element_id);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_dma_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_entry_add);

u32 dpp_fd_acl_entry_del(struct dpp_pf_info_t *pf_info, u32 handle)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;
	u32 element_id = 0;
	u8 data[DPP_ETCAM_WIDTH_MAX / 8] = { 0xff };
	u8 mask[DPP_ETCAM_WIDTH_MAX / 8] = { 0 };
	u8 as_rlt[16] = { 0 };
	struct dpp_dtb_acl_entry_info_t fd_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_MEMSET(&fd_entry, 0, sizeof(struct dpp_dtb_acl_entry_info_t));
	ZXIC_COMM_MEMSET_S(data, sizeof(data), 0xff, sizeof(data));
	ZXIC_COMM_MEMSET_S(mask, sizeof(mask), 0x0, sizeof(mask));
	ZXIC_COMM_MEMSET_S(as_rlt, sizeof(as_rlt), 0xff, sizeof(as_rlt));

	fd_entry.handle = handle;
	fd_entry.key_data = data;
	fd_entry.key_mask = mask;
	fd_entry.p_as_rslt = as_rlt;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_acl_dma_insert(&dev, queue, sdt_no, 1, &fd_entry, &element_id);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_dma_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_entry_del);

u32 dpp_fd_acl_entry_get(struct dpp_pf_info_t *pf_info, u32 handle, u8 *key, u8 *key_mask,
			 u8 *result)
{
	struct dpp_dev_t dev = { 0 };
	struct dpp_dtb_acl_entry_info_t fd_entry = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(key);
	ZXIC_COMM_CHECK_POINT(key_mask);
	ZXIC_COMM_CHECK_POINT(result);

	ZXIC_COMM_MEMSET_S(&fd_entry, sizeof(struct dpp_dtb_acl_entry_info_t), 0,
			   sizeof(struct dpp_dtb_acl_entry_info_t));
	fd_entry.handle = handle;
	fd_entry.key_data = key;
	fd_entry.key_mask = key_mask;
	fd_entry.p_as_rslt = result;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_etcam_data_get(&dev, queue, sdt_no, &fd_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_etcam_data_get", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_entry_get);

u32 dpp_fd_acl_entry_search(struct dpp_pf_info_t *pf_info, u32 handle, u8 *key, u8 *key_mask,
			    u8 *result)
{
	struct dpp_dev_t dev = { 0 };
	struct dpp_dtb_acl_entry_info_t fd_entry = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(key);
	ZXIC_COMM_CHECK_POINT(key_mask);
	ZXIC_COMM_CHECK_POINT(result);

	ZXIC_COMM_MEMSET_S(&fd_entry, sizeof(struct dpp_dtb_acl_entry_info_t), 0,
			   sizeof(struct dpp_dtb_acl_entry_info_t));
	fd_entry.handle = handle;
	fd_entry.key_data = key;
	fd_entry.key_mask = key_mask;
	fd_entry.p_as_rslt = result;

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_acl_data_get(&dev, queue, sdt_no, &fd_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_data_get", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_entry_search);

u32 dpp_fd_acl_all_delete(struct dpp_pf_info_t *pf_info)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_acl_offline_delete(&dev, queue, sdt_no, pf_info->vport,
					DPP_STAT_FD_ACL_CNT_ERAM_BAADDR, 1);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_offline_delete", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_all_delete);

u32 dpp_fd_acl_stat_clear(struct dpp_pf_info_t *pf_info)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_FD_CFG_TABLE;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_dtb_acl_stat_clr_by_vport(&dev, queue, sdt_no, pf_info->vport, 1,
					   DPP_STAT_FD_ACL_CNT_ERAM_BAADDR);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_dtb_acl_stat_clr_by_vport", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_fd_acl_stat_clear);
