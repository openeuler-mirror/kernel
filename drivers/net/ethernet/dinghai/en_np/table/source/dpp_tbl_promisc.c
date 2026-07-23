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
#include "dpp_tbl_promisc.h"

u32 dpp_vport_promisc_info_set(struct dpp_pf_info_t *pf_info,
			       struct dpp_vport_uc_promisc_table_t *promisc_table, u32 enable)
{
	u32 group_id = 0;
	u32 vfunc_num = 0;
	u64 bitmap_mask = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(promisc_table);
	ZXIC_COMM_CHECK_INDEX(enable, 0, 1);

	vfunc_num = VFUNC_NUM(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(vfunc_num, 0, (PROMISC_GROUP_NUM * PROMISC_MEMBER_NUM_IN_GROUP) - 1);

	group_id = vfunc_num / PROMISC_MEMBER_NUM_IN_GROUP;
	ZXIC_COMM_CHECK_INDEX(group_id, 0, PROMISC_GROUP_NUM - 1);

	bitmap_mask = ((u64)(1) << (PROMISC_MEMBER_NUM_IN_GROUP - 1 -
				    (vfunc_num % PROMISC_MEMBER_NUM_IN_GROUP)));

	if (IS_PF(pf_info->vport)) {
		promisc_table->promisc_info.pf_enable = enable;
	} else {
		promisc_table->promisc_info.bitmap[group_id] =
			(enable == 1) ?
				      (promisc_table->promisc_info.bitmap[group_id] | bitmap_mask) :
				      (promisc_table->promisc_info.bitmap[group_id] & ~bitmap_mask);
	}

	return DPP_OK;
}

u32 dpp_vport_promisc_table_insert(struct dpp_pf_info_t *pf_info, u32 sdt_no,
				   struct dpp_vport_uc_promisc_table_t *promisc_table)
{
	struct dpp_dev_t dev = { 0 };

	u32 group_id = 0;
	u32 index = 0;
	u32 queue = 0;
	u32 rc = DPP_OK;

	struct zxdh_promisc_t promisc_entry = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(promisc_table);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	for (group_id = 0; group_id < PROMISC_GROUP_NUM; group_id++) {
		index = (((OWNER_PF_VQM_VFID(pf_info->vport) - PF_VQM_VFID_OFFSET) << 2) |
			 group_id);
		promisc_entry.hit_flag = 1;
		promisc_entry.pf_enable = promisc_table->promisc_info.pf_enable;
		promisc_entry.bitmap = promisc_table->promisc_info.bitmap[group_id];

		rc = dpp_apt_dtb_eram_insert(&dev, queue, sdt_no, index, &promisc_entry);
		ZXIC_COMM_CHECK_RC(rc, "dpp_apt_dtb_eram_insert");

		ZXIC_COMM_TRACE_NOTICE(
			"[%s] slot: %u vport: 0x%04x sdt_no: %u group_id: %u index: 0x%02x.\n",
			__func__, pf_info->slot, pf_info->vport, sdt_no, group_id, index);
		ZXIC_COMM_TRACE_NOTICE(
			"[%s] pf_enable: %u bitmap: %02x %02x %02x %02x %02x %02x %02x %02x.\n",
			__func__, promisc_entry.pf_enable, *((u8 *)(&promisc_entry.bitmap) + 7),
			*((u8 *)(&promisc_entry.bitmap) + 6), *((u8 *)(&promisc_entry.bitmap) + 5),
			*((u8 *)(&promisc_entry.bitmap) + 4), *((u8 *)(&promisc_entry.bitmap) + 3),
			*((u8 *)(&promisc_entry.bitmap) + 2), *((u8 *)(&promisc_entry.bitmap) + 1),
			*((u8 *)(&promisc_entry.bitmap) + 0));
	}

	return DPP_OK;
}

u32 dpp_vport_uc_promisc_set(struct dpp_pf_info_t *pf_info, u32 enable)
{
	struct dpp_dev_t dev = { 0 };

	u32 sdt_no = ZXDH_SDT_UC_PROMISC_TABLE;
	u32 rc = DPP_OK;
	struct dpp_vport_uc_promisc_table_t *promisc_table = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x enable: %u start.\n", __func__,
			       pf_info->slot, pf_info->vport, enable);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_uc_promisc_table_get(pf_info, &promisc_table);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_vport_uc_promisc_table_get", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_promisc_info_set(pf_info, promisc_table, enable);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_vport_promisc_info_set", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_promisc_table_insert(pf_info, sdt_no, promisc_table);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_vport_promisc_table_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x enable: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, enable);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_uc_promisc_set);

u32 dpp_vport_mc_promisc_set(struct dpp_pf_info_t *pf_info, u32 enable)
{
	struct dpp_dev_t dev = { 0 };

	u32 sdt_no = ZXDH_SDT_MC_PROMISC_TABLE;
	u32 rc = DPP_OK;
	struct dpp_vport_uc_promisc_table_t *promisc_table = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x enable: %u start.\n", __func__,
			       pf_info->slot, pf_info->vport, enable);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_vport_table_lock(pf_info, sdt_no, &DEV_PCIE_LOCK(&dev));
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_lock");
	ZXIC_COMM_CHECK_POINT(DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_mc_promisc_table_get(pf_info, &promisc_table);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_vport_mc_promisc_table_get", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_promisc_info_set(pf_info, promisc_table, enable);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_vport_promisc_info_set", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_promisc_table_insert(pf_info, sdt_no, promisc_table);
	ZXIC_COMM_CHECK_RC_UNLOCK(rc, "dpp_vport_promisc_table_insert", DEV_PCIE_LOCK(&dev));

	rc = dpp_vport_table_unlock(pf_info, sdt_no);
	ZXIC_COMM_CHECK_RC(rc, "dpp_vport_table_unlock");

	ZXIC_COMM_PRINT("[%s] slot: %u vport: 0x%04x enable: %u success.\n", __func__,
			pf_info->slot, pf_info->vport, enable);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_vport_mc_promisc_set);
