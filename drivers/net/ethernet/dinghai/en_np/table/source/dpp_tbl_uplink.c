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
#include "dpp_tbl_uplink.h"
#include "dpp_tbl_diag.h"

u32 dpp_uplink_phy_bond_vport(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id)
{
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);

	rc = dpp_vport_attr_set(pf_info, SRIOV_VPORT_UPLINK_PHY_PORT_ID, uplink_phy_id);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	rc = dpp_uplink_phy_attr_set(pf_info, uplink_phy_id, UPLINK_PHY_PORT_PF_VQM_VFID,
				     OWNER_PF_VQM_VFID(pf_info->vport));
	ZXIC_COMM_CHECK_RC(rc, "dpp_uplink_phy_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_uplink_phy_bond_vport);

u32 dpp_uplink_phy_hardware_bond_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = UPLINK_PHY_PORT_HW_BOND_ENABLE;

	rc = dpp_uplink_phy_attr_set(pf_info, uplink_phy_id, attr, enable);
	ZXIC_COMM_CHECK_RC(rc, "dpp_uplink_phy_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_uplink_phy_hardware_bond_set);

u32 dpp_uplink_phy_lacp_pf_vqm_vfid_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id,
					u16 vqm_vfid)
{
	u32 rc = DPP_OK;
	u32 attr = UPLINK_PHY_PORT_LACP_PF_VQM_VFID;

	rc = dpp_uplink_phy_attr_set(pf_info, uplink_phy_id, attr, vqm_vfid);
	ZXIC_COMM_CHECK_RC(rc, "dpp_uplink_phy_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_uplink_phy_lacp_pf_vqm_vfid_set);

u32 dpp_uplink_phy_lacp_pf_memport_qid_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id, u16 qid)
{
	u32 rc = DPP_OK;
	u32 attr = UPLINK_PHY_PORT_LACP_PF_MEMPORT_QID;

	rc = dpp_uplink_phy_attr_set(pf_info, uplink_phy_id, attr, qid);
	ZXIC_COMM_CHECK_RC(rc, "dpp_uplink_phy_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_uplink_phy_lacp_pf_memport_qid_set);

u32 dpp_uplink_phy_attr_set(struct dpp_pf_info_t *pf_info, u8 uplink_phy_id, u32 attr, u32 value)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 sdt_no = ZXDH_SDT_UPLINK_PHY_PORT_ATTR_TABLE;
	u32 rc = DPP_OK;

	struct zxdh_uplink_phy_port_t uplink_phy_port = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(attr, 0,
			      (u32)((sizeof(struct zxdh_uplink_phy_port_t) / sizeof(u32)) - 1));

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u attr: %s(%u) value: %u start.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, uplink_phy_id,
		dpp_uplink_phy_port_table_attr_name_get(attr), attr, value);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_apt_dtb_eram_get(&dev, queue, sdt_no, uplink_phy_id, &uplink_phy_port);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_get", DEV_PCIE_LOCK(&dev));

	uplink_phy_port.hit_flag = 1;
	*((((u32 *)(&uplink_phy_port)) + attr)) = value;

	rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, uplink_phy_id, &uplink_phy_port);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_apt_dtb_eram_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT(
		"[%s] slot: %u vport: 0x%04x sdt_no: %u index: %u attr: %s(%u) value: %u success.\n",
		__func__, pf_info->slot, pf_info->vport, sdt_no, uplink_phy_id,
		dpp_uplink_phy_port_table_attr_name_get(attr), attr, value);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_uplink_phy_attr_set);
