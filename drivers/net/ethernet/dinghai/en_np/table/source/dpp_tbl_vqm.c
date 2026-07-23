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
#include "dpp_tbl_diag.h"
#include "dpp_tbl_vqm.h"

u32 dpp_vqm_vfid_vlan_init(struct dpp_pf_info_t *pf_info)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VQM_VFID_VLAN_ATTR_TABLE;
	u32 index = 0;
	u32 rc = DPP_OK;

	struct zxdh_vqm_vfid_vlan_t vqm_vfid_vlan_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	ZXIC_COMM_MEMSET(&vqm_vfid_vlan_entry, 0, sizeof(struct zxdh_vqm_vfid_vlan_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	vqm_vfid_vlan_entry.hit_flag = 1;
	index = VQM_VFID(pf_info->vport);

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &vqm_vfid_vlan_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x success.\n", __func__, pf_info->slot,
			pf_info->vport);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vqm_vfid_vlan_init);

u32 dpp_vqm_vfid_vlan_delete(struct dpp_pf_info_t *pf_info)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VQM_VFID_VLAN_ATTR_TABLE;
	u32 index = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	index = VQM_VFID(pf_info->vport);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u start.\n",
			       __func__, pf_info->slot, pf_info->vport, sdt_no, index);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_clear(&dev, queue, sdt_no, index);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_clear", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vqm_vfid_vlan_delete);

u32 dpp_vqm_vfid_vlan_set(struct dpp_pf_info_t *pf_info, u32 attr, u32 value)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VQM_VFID_VLAN_ATTR_TABLE;
	u32 index = 0;
	u32 rc = DPP_OK;

	struct zxdh_vqm_vfid_vlan_t vqm_vfid_vlan_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(attr, 0,
			      (u32)((sizeof(struct zxdh_vqm_vfid_vlan_t) / sizeof(u32)) - 1));

	index = VQM_VFID(pf_info->vport);

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u attr: %s(%u) value: %u start.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index,
		dpp_vqm_vfid_vlan_attr_name_get(attr), attr, value);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, index, &vqm_vfid_vlan_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	vqm_vfid_vlan_entry.hit_flag = 1;
	*((((u32 *)(&vqm_vfid_vlan_entry)) + attr)) = value;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &vqm_vfid_vlan_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u attr: %s(%u) value: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index,
		dpp_vqm_vfid_vlan_attr_name_get(attr), attr, value);
	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vqm_vfid_vlan_set);

u32 dpp_vqm_vfid_vlan_get(struct dpp_pf_info_t *pf_info,
			  struct zxdh_vqm_vfid_vlan_t *vqm_vfid_vlan_entry)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VQM_VFID_VLAN_ATTR_TABLE;
	u32 index = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(vqm_vfid_vlan_entry);

	index = VQM_VFID(pf_info->vport);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x index: %u start.\n", __func__,
			       pf_info->slot, pf_info->vport, index);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, index, vqm_vfid_vlan_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_INDEX_NOT_EQUAL_UNLOCK(vqm_vfid_vlan_entry->hit_flag, 1,
					       DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x index: %u success.\n", __func__,
			       pf_info->slot, pf_info->vport, index);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vqm_vfid_vlan_get);
