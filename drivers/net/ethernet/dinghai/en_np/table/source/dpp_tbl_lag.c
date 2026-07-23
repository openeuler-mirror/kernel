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
#include "dpp_tbl_lag.h"

u32 dpp_lag_group_create(struct dpp_pf_info_t *pf_info, u8 lag_id)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_LAG_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_lag_t lag_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u start.\n",
			       __func__, pf_info->slot, pf_info->vport, sdt_no, lag_id);

	ZXIC_COMM_MEMSET(&lag_entry, 0, sizeof(struct zxdh_lag_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	lag_entry.hit_flag = 1;
	lag_entry.bond_mode = LAG_LACP_MODE;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, lag_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_lag_group_create);

u32 dpp_lag_group_delete(struct dpp_pf_info_t *pf_info, u8 lag_id)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_LAG_TABLE;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u start.\n",
			       __func__, pf_info->slot, pf_info->vport, sdt_no, lag_id);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_clear(&dev, queue, sdt_no, lag_id);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_clear", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, lag_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_lag_group_delete);

u32 dpp_lag_mode_set(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 mode)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_LAG_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_lag_t lag_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(mode, LAG_STANDBY_MODE, LAG_LACP_MODE);

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u mode: %u start.\n", __func__,
		pf_info->slot, pf_info->vport, sdt_no, lag_id, mode);

	ZXIC_COMM_MEMSET(&lag_entry, 0, sizeof(struct zxdh_lag_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	lag_entry.hit_flag = 1;
	lag_entry.bond_mode = mode;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u mode: %u success.\n",
			__func__, pf_info->slot, pf_info->vport, sdt_no, lag_id, mode);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_lag_mode_set);

u32 dpp_lag_group_hash_factor_set(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 factor)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_LAG_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_lag_t lag_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u factor: %u start.\n", __func__,
		pf_info->slot, pf_info->vport, sdt_no, lag_id, factor);

	ZXIC_COMM_MEMSET(&lag_entry, 0, sizeof(struct zxdh_lag_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	lag_entry.hit_flag = 1;
	lag_entry.hash_factor = factor;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u factor: %u success.\n",
			__func__, pf_info->slot, pf_info->vport, sdt_no, lag_id, factor);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_lag_group_hash_factor_set);

u32 dpp_lag_group_member_add(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 uplink_phy_port_id)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_LAG_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_lag_t lag_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u uplink_phy_port_id: %u start.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, lag_id, uplink_phy_port_id);

	ZXIC_COMM_MEMSET(&lag_entry, 0, sizeof(struct zxdh_lag_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	lag_entry.hit_flag = 1;

	if ((lag_entry.member_bitmap & (1 << (15 - uplink_phy_port_id))) == 0) {
		lag_entry.member_bitmap |= (1 << (15 - uplink_phy_port_id));
		lag_entry.member_num++;
	}

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u uplink_phy_port_id: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, lag_id, uplink_phy_port_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_lag_group_member_add);

u32 dpp_lag_group_member_del(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 uplink_phy_port_id)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_LAG_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_lag_t lag_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u uplink_phy_port_id: %u start.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, lag_id, uplink_phy_port_id);

	ZXIC_COMM_MEMSET(&lag_entry, 0, sizeof(struct zxdh_lag_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	lag_entry.hit_flag = 1;

	if ((lag_entry.member_bitmap & (1 << (15 - uplink_phy_port_id))) != 0) {
		lag_entry.member_bitmap &= ~(1 << (15 - uplink_phy_port_id));
		ZXIC_COMM_CHECK_INDEX_LOWER_UNLOCK(lag_entry.member_num, 1, DEV_PCIE_LOCK(&dev));
		lag_entry.member_num--;
	}

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u uplink_phy_port_id: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, lag_id, uplink_phy_port_id);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_lag_group_member_del);

u32 dpp_lag_hit_flag_get(struct dpp_pf_info_t *pf_info, u8 lag_id, u8 *hit_flag)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_LAG_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_lag_t lag_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(hit_flag);

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u start.\n", __func__,
			pf_info->slot, pf_info->vport, sdt_no, lag_id);

	ZXIC_COMM_MEMSET_S(&lag_entry, sizeof(struct zxdh_lag_t), 0, sizeof(struct zxdh_lag_t));

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, lag_id, &lag_entry);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	*hit_flag = (u8)lag_entry.hit_flag;

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x sdt_no: %u lag_id: %u hit_flag: %u success.\n",
			__func__, pf_info->slot, pf_info->vport, sdt_no, lag_id, *hit_flag);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_lag_hit_flag_get);
