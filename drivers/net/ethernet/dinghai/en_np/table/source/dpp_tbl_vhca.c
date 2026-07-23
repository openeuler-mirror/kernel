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
#include "dpp_tbl_api.h"
#include "dpp_tbl_comm.h"
#include "dpp_tbl_port.h"

u32 dpp_vport_vhca_id_add(struct dpp_pf_info_t *pf_info, u32 vhca_id)
{
	u32 rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VHCA_TABLE;

	struct zxdh_vhca_t vhca_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u vhca_id: %u start.\n",
			       __func__, pf_info->slot, pf_info->vport, sdt_no, vhca_id);

	ZXIC_COMM_MEMSET(&vhca_entry, 0, sizeof(struct zxdh_vhca_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	vhca_entry.valid = 1;
	vhca_entry.vqm_vfid = VQM_VFID(pf_info->vport);

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, vhca_id, &vhca_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u vhca_id: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, vhca_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_vhca_id_add);

u32 dpp_vport_vhca_id_del(struct dpp_pf_info_t *pf_info, u32 vhca_id)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VHCA_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u vhca_id: %u start.\n",
			       __func__, pf_info->slot, pf_info->vport, sdt_no, vhca_id);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_clear(&dev, queue, sdt_no, vhca_id);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_clear", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u vhca_id: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, vhca_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_vhca_id_del);
