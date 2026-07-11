// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_tbl_plcr.h"
#include "dpp_dev.h"
#include "dpp_drv_sdt.h"
#include "dpp_drv_eram.h"
#include "dpp_dtb.h"
#include "dpp_apt_se_api.h"
#include "dpp_tbl_api.h"

u32 dpp_vport_egress_meter_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_NP_EGRESS_METER_EN_OFF;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_egress_meter_en_set);

u32 dpp_vport_egress_meter_en_get(struct dpp_pf_info_t *pf_info, u32 *enable)
{
	u32 rc = DPP_OK;
	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(enable);

	rc = dpp_vport_attr_get(pf_info, &port_attr_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_get");

	*enable = port_attr_entry.np_egress_meter_enable;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x egress_meter_enable_status: %u success.\n",
			__func__, pf_info->slot, pf_info->vport, *enable);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_egress_meter_en_get);

u32 dpp_vport_ingress_meter_en_set(struct dpp_pf_info_t *pf_info, u8 enable)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_NP_INGRESS_METER_EN_OFF;

	rc = dpp_vport_attr_set(pf_info, attr, enable & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_ingress_meter_en_set);

u32 dpp_vport_ingress_meter_en_get(struct dpp_pf_info_t *pf_info, u32 *enable)
{
	u32 rc = DPP_OK;
	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(enable);

	rc = dpp_vport_attr_get(pf_info, &port_attr_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_get");

	*enable = port_attr_entry.np_ingress_meter_enable;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x ingress_meter_enable_status: %u success.\n",
			__func__, pf_info->slot, pf_info->vport, *enable);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_ingress_meter_en_get);

u32 dpp_vport_egress_meter_mode_set(struct dpp_pf_info_t *pf_info, u8 mode)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_NP_EGRESS_MODE;

	rc = dpp_vport_attr_set(pf_info, attr, mode & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_egress_meter_mode_set);

u32 dpp_vport_egress_meter_mode_get(struct dpp_pf_info_t *pf_info, u32 *mode)
{
	u32 rc = DPP_OK;
	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(mode);

	rc = dpp_vport_attr_get(pf_info, &port_attr_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_get");

	*mode = port_attr_entry.np_egress_meter_mode;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x egress_meter_mode_status: %u success.\n",
			__func__, pf_info->slot, pf_info->vport, *mode);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_egress_meter_mode_get);

u32 dpp_vport_ingress_meter_mode_set(struct dpp_pf_info_t *pf_info, u8 mode)
{
	u32 rc = DPP_OK;
	u32 attr = SRIOV_VPORT_NP_INGRESS_MODE;

	rc = dpp_vport_attr_set(pf_info, attr, mode & 0x1);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_set");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_ingress_meter_mode_set);

u32 dpp_vport_ingress_meter_mode_get(struct dpp_pf_info_t *pf_info, u32 *mode)
{
	u32 rc = DPP_OK;
	struct zxdh_sriov_vport_t port_attr_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(mode);

	rc = dpp_vport_attr_get(pf_info, &port_attr_entry);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_attr_get");

	*mode = port_attr_entry.np_ingress_meter_mode;

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x ingress_meter_mode_status: %u success.\n",
			__func__, pf_info->slot, pf_info->vport, *mode);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_ingress_meter_mode_get);
