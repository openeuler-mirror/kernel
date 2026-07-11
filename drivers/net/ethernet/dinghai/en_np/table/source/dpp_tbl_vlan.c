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
#include "dpp_tbl_vlan.h"

u32 dpp_vlan_filter_init(struct dpp_pf_info_t *pf_info)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VLAN_FILTER_TABLE;
	u32 vlan_group_id = 0;
	u32 index = 0;
	u32 rc = DPP_OK;

	struct zxdh_vlan_filter_t vlan_filter_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x start.\n", __func__, pf_info->slot,
			       pf_info->vport);

	ZXIC_COMM_MEMSET(&vlan_filter_entry, 0, sizeof(struct zxdh_vlan_filter_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	vlan_filter_entry.hit_flag = 1;

	for (vlan_group_id = 0; vlan_group_id < VLAN_GROUP_NUM; vlan_group_id++) {
		index = ((vlan_group_id << 11) | (VQM_VFID(pf_info->vport)));
		rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &vlan_filter_entry);
		ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));
	}

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x success.\n", __func__, pf_info->slot,
			pf_info->vport);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vlan_filter_init);

u32 dpp_add_vlan_filter(struct dpp_pf_info_t *pf_info, u16 vlan_id)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VLAN_FILTER_TABLE;

	u32 vlan_group_id = vlan_id / VLAN_ID_NUM_IN_GROUP;
	u32 vlan_remainder = vlan_id % VLAN_ID_NUM_IN_GROUP;

	u32 index = 0;
	u32 rc = DPP_OK;

	struct zxdh_vlan_filter_t vlan_filter_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(vlan_id, 0, 4095);

	index = ((vlan_group_id << 11) | (VQM_VFID(pf_info->vport)));

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: 0x%04x group_id: %u vlan_id: %u start.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index, vlan_group_id, vlan_id);

	ZXIC_COMM_MEMSET(&vlan_filter_entry, 0, sizeof(struct zxdh_vlan_filter_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, index, &vlan_filter_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	vlan_filter_entry.hit_flag = 1;
	vlan_filter_entry.vport_bitmap[vlan_remainder / 8] |= 1 << (7 - (vlan_remainder % 8));

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &vlan_filter_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: 0x%04x group_id: %u vlan_id: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index, vlan_group_id, vlan_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_add_vlan_filter);

u32 dpp_del_vlan_filter(struct dpp_pf_info_t *pf_info, u16 vlan_id)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_VLAN_FILTER_TABLE;

	u32 vlan_group_id = vlan_id / VLAN_ID_NUM_IN_GROUP;
	u32 vlan_remainder = vlan_id % VLAN_ID_NUM_IN_GROUP;

	u32 index = 0;
	u32 rc = DPP_OK;

	struct zxdh_vlan_filter_t vlan_filter_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(vlan_id, 0, 4095);

	index = ((vlan_group_id << 11) | (VQM_VFID(pf_info->vport)));

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: 0x%04x group_id: %u vlan_id: %u start.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index, vlan_group_id, vlan_id);

	ZXIC_COMM_MEMSET(&vlan_filter_entry, 0, sizeof(struct zxdh_vlan_filter_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, index, &vlan_filter_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	vlan_filter_entry.hit_flag = 1;
	vlan_filter_entry.vport_bitmap[vlan_remainder / 8] &= ~(1 << (7 - (vlan_remainder % 8)));

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &vlan_filter_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: 0x%04x group_id: %u vlan_id: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, index, vlan_group_id, vlan_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_del_vlan_filter);
