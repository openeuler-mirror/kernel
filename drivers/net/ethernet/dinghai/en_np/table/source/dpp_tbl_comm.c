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
#include "dpp_tbl_mc.h"
#include "dpp_tbl_bc.h"
#include "dpp_tbl_promisc.h"
#include "dpp_tbl_comm.h"
#include "dpp_tbl_api.h"

static struct dpp_vport_mgr_t g_vport_mgr[DPP_PCIE_SLOT_MAX][DPP_PCIE_CHANNEL_MAX] = { 0 };

u32 dpp_data_print(u8 *data, u32 len)
{
	u32 i = 0;
	u32 loop_cnt = len / 16;
	u32 last_line_len = len % 16;

	ZXIC_COMM_PRINT("-----------------------------------------------\n");
	for (i = 0; i < loop_cnt; i++) {
		ZXIC_COMM_PRINT(
			"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			*(data + (i * 16) + 0), *(data + (i * 16) + 1), *(data + (i * 16) + 2),
			*(data + (i * 16) + 3), *(data + (i * 16) + 4), *(data + (i * 16) + 5),
			*(data + (i * 16) + 6), *(data + (i * 16) + 7), *(data + (i * 16) + 8),
			*(data + (i * 16) + 9), *(data + (i * 16) + 10), *(data + (i * 16) + 11),
			*(data + (i * 16) + 12), *(data + (i * 16) + 13), *(data + (i * 16) + 14),
			*(data + (i * 16) + 15));
	}
	if (last_line_len != 0) {
		if (last_line_len == 1) {
			ZXIC_COMM_PRINT("%02x\n", *(data + (i * 16) + 0));
		} else if (last_line_len == 2) {
			ZXIC_COMM_PRINT("%02x %02x\n", *(data + (i * 16) + 0),
					*(data + (i * 16) + 1));
		} else if (last_line_len == 3) {
			ZXIC_COMM_PRINT("%02x %02x %02x\n", *(data + (i * 16) + 0),
					*(data + (i * 16) + 1), *(data + (i * 16) + 2));
		} else if (last_line_len == 4) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x\n", *(data + (i * 16) + 0),
					*(data + (i * 16) + 1), *(data + (i * 16) + 2),
					*(data + (i * 16) + 3));
		} else if (last_line_len == 5) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x %02x\n", *(data + (i * 16) + 0),
					*(data + (i * 16) + 1), *(data + (i * 16) + 2),
					*(data + (i * 16) + 3), *(data + (i * 16) + 4));
		} else if (last_line_len == 6) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x %02x %02x\n", *(data + (i * 16) + 0),
					*(data + (i * 16) + 1), *(data + (i * 16) + 2),
					*(data + (i * 16) + 3), *(data + (i * 16) + 4),
					*(data + (i * 16) + 5));
		} else if (last_line_len == 7) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x %02x %02x %02x\n",
					*(data + (i * 16) + 0), *(data + (i * 16) + 1),
					*(data + (i * 16) + 2), *(data + (i * 16) + 3),
					*(data + (i * 16) + 4), *(data + (i * 16) + 5),
					*(data + (i * 16) + 6));
		} else if (last_line_len == 8) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
					*(data + (i * 16) + 0), *(data + (i * 16) + 1),
					*(data + (i * 16) + 2), *(data + (i * 16) + 3),
					*(data + (i * 16) + 4), *(data + (i * 16) + 5),
					*(data + (i * 16) + 6), *(data + (i * 16) + 7));
		} else if (last_line_len == 9) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					*(data + (i * 16) + 0), *(data + (i * 16) + 1),
					*(data + (i * 16) + 2), *(data + (i * 16) + 3),
					*(data + (i * 16) + 4), *(data + (i * 16) + 5),
					*(data + (i * 16) + 6), *(data + (i * 16) + 7),
					*(data + (i * 16) + 8));
		} else if (last_line_len == 10) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					*(data + (i * 16) + 0), *(data + (i * 16) + 1),
					*(data + (i * 16) + 2), *(data + (i * 16) + 3),
					*(data + (i * 16) + 4), *(data + (i * 16) + 5),
					*(data + (i * 16) + 6), *(data + (i * 16) + 7),
					*(data + (i * 16) + 8), *(data + (i * 16) + 9));
		} else if (last_line_len == 11) {
			ZXIC_COMM_PRINT("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					*(data + (i * 16) + 0), *(data + (i * 16) + 1),
					*(data + (i * 16) + 2), *(data + (i * 16) + 3),
					*(data + (i * 16) + 4), *(data + (i * 16) + 5),
					*(data + (i * 16) + 6), *(data + (i * 16) + 7),
					*(data + (i * 16) + 8), *(data + (i * 16) + 9),
					*(data + (i * 16) + 10));
		} else if (last_line_len == 12) {
			ZXIC_COMM_PRINT(
				"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				*(data + (i * 16) + 0), *(data + (i * 16) + 1),
				*(data + (i * 16) + 2), *(data + (i * 16) + 3),
				*(data + (i * 16) + 4), *(data + (i * 16) + 5),
				*(data + (i * 16) + 6), *(data + (i * 16) + 7),
				*(data + (i * 16) + 8), *(data + (i * 16) + 9),
				*(data + (i * 16) + 10), *(data + (i * 16) + 11));
		} else if (last_line_len == 13) {
			ZXIC_COMM_PRINT(
				"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				*(data + (i * 16) + 0), *(data + (i * 16) + 1),
				*(data + (i * 16) + 2), *(data + (i * 16) + 3),
				*(data + (i * 16) + 4), *(data + (i * 16) + 5),
				*(data + (i * 16) + 6), *(data + (i * 16) + 7),
				*(data + (i * 16) + 8), *(data + (i * 16) + 9),
				*(data + (i * 16) + 10), *(data + (i * 16) + 11),
				*(data + (i * 16) + 12));
		} else if (last_line_len == 14) {
			ZXIC_COMM_PRINT(
				"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				*(data + (i * 16) + 0), *(data + (i * 16) + 1),
				*(data + (i * 16) + 2), *(data + (i * 16) + 3),
				*(data + (i * 16) + 4), *(data + (i * 16) + 5),
				*(data + (i * 16) + 6), *(data + (i * 16) + 7),
				*(data + (i * 16) + 8), *(data + (i * 16) + 9),
				*(data + (i * 16) + 10), *(data + (i * 16) + 11),
				*(data + (i * 16) + 12), *(data + (i * 16) + 13));
		} else if (last_line_len == 15) {
			ZXIC_COMM_PRINT(
				"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				*(data + (i * 16) + 0), *(data + (i * 16) + 1),
				*(data + (i * 16) + 2), *(data + (i * 16) + 3),
				*(data + (i * 16) + 4), *(data + (i * 16) + 5),
				*(data + (i * 16) + 6), *(data + (i * 16) + 7),
				*(data + (i * 16) + 8), *(data + (i * 16) + 9),
				*(data + (i * 16) + 10), *(data + (i * 16) + 11),
				*(data + (i * 16) + 12), *(data + (i * 16) + 13),
				*(data + (i * 16) + 14));
		}
	}
	ZXIC_COMM_PRINT("-----------------------------------------------\n");

	return DPP_OK;
}

u32 dpp_vport_mgr_init(struct dpp_pf_info_t *pf_info)
{
	u16 slot = 0;
	u16 channel_id = 0;
	u32 sdt_no = 0;
	u32 rc = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	ZXIC_COMM_MEMSET(&g_vport_mgr[slot][channel_id], 0x00, sizeof(struct dpp_vport_mgr_t));

	g_vport_mgr[slot][channel_id].mc_table.mc_info =
		ZXIC_COMM_MALLOC(sizeof(struct dpp_vport_mc_info_t) * MC_TABLE_SIZE);
	ZXIC_COMM_CHECK_POINT(g_vport_mgr[slot][channel_id].mc_table.mc_info);
	ZXIC_COMM_MEMSET(g_vport_mgr[slot][channel_id].mc_table.mc_info, 0x00,
			 sizeof(struct dpp_vport_mc_info_t) * MC_TABLE_SIZE);

	for (sdt_no = 0; sdt_no < DPP_DEV_SDT_ID_MAX; sdt_no++) {
		g_vport_mgr[slot][channel_id].table_lock[sdt_no] =
			ZXIC_COMM_MALLOC(sizeof(struct zxic_mutex_t));
		ZXIC_COMM_CHECK_POINT(g_vport_mgr[slot][channel_id].table_lock[sdt_no]);
		ZXIC_COMM_MEMSET(g_vport_mgr[slot][channel_id].table_lock[sdt_no], 0x00,
				 sizeof(struct zxic_mutex_t));

		rc = zxic_comm_mutex_create(g_vport_mgr[slot][channel_id].table_lock[sdt_no]);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_mutex_create");
	}

	return DPP_OK;
}

u32 dpp_vport_mgr_release(struct dpp_pf_info_t *pf_info)
{
	u16 slot = 0;
	u16 channel_id = 0;
	u32 sdt_no = 0;
	u32 rc = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	ZXIC_COMM_FREE(g_vport_mgr[slot][channel_id].mc_table.mc_info);

	for (sdt_no = 0; sdt_no < DPP_DEV_SDT_ID_MAX; sdt_no++) {
		rc = zxic_comm_mutex_destroy(g_vport_mgr[slot][channel_id].table_lock[sdt_no]);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_mutex_destroy");
		ZXIC_COMM_FREE(g_vport_mgr[slot][channel_id].table_lock[sdt_no]);
	}

	ZXIC_COMM_MEMSET(&g_vport_mgr[slot][channel_id], 0x00, sizeof(struct dpp_vport_mgr_t));

	return DPP_OK;
}

u32 dpp_vport_table_lock(struct dpp_pf_info_t *pf_info, u32 sdt_no,
			 struct zxic_mutex_t **table_lock)
{
	u16 slot = 0;
	u16 channel_id = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(table_lock);

	*table_lock = NULL;

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	rc = zxic_comm_mutex_lock(g_vport_mgr[slot][channel_id].table_lock[sdt_no]);
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_mutex_lock");

	*table_lock = g_vport_mgr[slot][channel_id].table_lock[sdt_no];

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u table lock.\n", __func__,
			       pf_info->slot, pf_info->vport, sdt_no);
	return DPP_OK;
}

u32 dpp_vport_table_unlock(struct dpp_pf_info_t *pf_info, u32 sdt_no)
{
	u16 slot = 0;
	u16 channel_id = 0;
	u32 rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x sdt_no: %u table unlock.\n", __func__,
			       pf_info->slot, pf_info->vport, sdt_no);

	rc = zxic_comm_mutex_unlock(g_vport_mgr[slot][channel_id].table_lock[sdt_no]);
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_mutex_unlock");

	return DPP_OK;
}

u32 dpp_vport_bc_table_get(struct dpp_pf_info_t *pf_info, struct dpp_vport_bc_table_t **bc_table)
{
	u16 slot = 0;
	u16 channel_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(bc_table);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	*bc_table = &g_vport_mgr[slot][channel_id].bc_table;

	return DPP_OK;
}

u32 dpp_vport_mc_table_get(struct dpp_pf_info_t *pf_info, struct dpp_vport_mc_table_t **mc_table)
{
	u16 slot = 0;
	u16 channel_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(mc_table);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	*mc_table = &g_vport_mgr[slot][channel_id].mc_table;

	return DPP_OK;
}

u32 dpp_vport_uc_promisc_table_get(struct dpp_pf_info_t *pf_info,
				   struct dpp_vport_uc_promisc_table_t **promisc_table)
{
	u16 slot = 0;
	u16 channel_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(promisc_table);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	*promisc_table = &g_vport_mgr[slot][channel_id].uc_promisc_table;

	return DPP_OK;
}

u32 dpp_vport_mc_promisc_table_get(struct dpp_pf_info_t *pf_info,
				   struct dpp_vport_uc_promisc_table_t **promisc_table)
{
	u16 slot = 0;
	u16 channel_id = 0;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(promisc_table);

	slot = pf_info->slot;
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);

	channel_id = DPP_PCIE_CHANNEL_ID(pf_info->vport);
	ZXIC_COMM_CHECK_INDEX(channel_id, 0, DPP_PCIE_CHANNEL_MAX - 1);

	*promisc_table = &g_vport_mgr[slot][channel_id].mc_promisc_table;

	return DPP_OK;
}

u32 dpp_vport_get_by_vqm_vfid(u16 pf_vport, u32 vqm_vfid, u16 *vport)
{
	ZXIC_COMM_CHECK_POINT(vport);

	if (vqm_vfid >= PF_VQM_VFID_OFFSET) {
		*vport = pf_vport;
	} else {
		*vport = ((EPID(pf_vport) << 12) | 0x800 | (FUNC_NUM(pf_vport) << 8) |
			  (vqm_vfid - (EPID(pf_vport) * 256)));
	}
	return DPP_OK;
}

u32 dpp_vport_get_by_mc_bitmap(u16 pf_vport, u32 group_id, u64 mc_bitmap, u16 vport[64],
			       u32 *p_vport_num)
{
	u32 i = 0;

	u32 vport_num = 0;

	ZXIC_COMM_CHECK_POINT(vport);
	ZXIC_COMM_CHECK_POINT(p_vport_num);

	for (i = 0; i < MC_MEMBER_NUM_IN_GROUP; i++) {
		if ((mc_bitmap >> i) & 1) {
			vport[vport_num] =
				((EPID(pf_vport) << 12) | 0x800 | (FUNC_NUM(pf_vport) << 8) |
				 ((group_id * MC_MEMBER_NUM_IN_GROUP) + MC_MEMBER_NUM_IN_GROUP - 1 -
				  i));
			vport_num++;
		}
	}

	*p_vport_num = vport_num;

	return DPP_OK;
}

BOOLEAN dpp_vport_in_mc_bitmap(u32 vport, u64 mc_bitmap)
{
	u32 bit_index = 0;

	bit_index = VFUNC_NUM(vport) % MC_MEMBER_NUM_IN_GROUP;

	if ((VF_ACTIVE(vport)) && ((mc_bitmap >> (MC_MEMBER_NUM_IN_GROUP - 1 - bit_index)) & 1))
		return TRUE;

	return FALSE;
}
