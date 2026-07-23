// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se.h"
#include "dpp_dev.h"
#include "dpp_hash.h"
#include "dpp_sdt.h"
#include "dpp_dtb_cfg.h"
#include "dpp_dtb_table.h"
#include "dpp_dtb_table_api.h"

static struct dpp_se_cfg *g_apt_se_cfg[DPP_PCIE_SLOT_MAX] = { NULL };

struct dpp_se_cfg *dpp_apt_get_se_cfg(struct dpp_dev_t *dev)
{
	u32 slot = 0;

	if (!dev)
		return NULL;
	slot = DEV_PCIE_SLOT(dev);
	if (slot < DPP_PCIE_SLOT_MAX)
		return g_apt_se_cfg[slot];
	return NULL;
}
DPP_STATUS dpp_apt_hash_global_res_init(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);
	if (!g_apt_se_cfg[slot]) {
		g_apt_se_cfg[slot] =
			(struct dpp_se_cfg *)ZXIC_COMM_MALLOC(sizeof(struct dpp_se_cfg));
		ZXIC_COMM_CHECK_POINT(g_apt_se_cfg[slot]);
		rc = dpp_se_init(dev, g_apt_se_cfg[slot]);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_se_init");

		rc = dpp_se_client_init(g_apt_se_cfg[slot], ZXIC_COMM_VAL_TO_PTR(DEV_ID(dev)));
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_se_client_init");

		rc = dpp_dev_hash_opr_mutex_create(dev);
		ZXIC_COMM_CHECK_RC(rc, "dpp_dev_hash_opr_mutex_create");
	}

	return rc;
}
DPP_STATUS dpp_apt_hash_global_res_uninit(struct dpp_dev_t *dev)
{
	DPP_STATUS rc = DPP_OK;
	u32 slot = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	slot = DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot, 0, DPP_PCIE_SLOT_MAX - 1);
	if (g_apt_se_cfg[slot]) {
		ZXIC_COMM_FREE(g_apt_se_cfg[slot]);
		g_apt_se_cfg[slot] = NULL;
	}

	rc = dpp_dev_hash_opr_mutex_destroy(dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_hash_opr_mutex_destroy");
	return rc;
}
DPP_STATUS dpp_apt_hash_func_res_init(struct dpp_dev_t *dev, u32 func_num,
				      struct dpp_apt_hash_func_res_t *pHashFuncRes)
{
	DPP_STATUS rc = DPP_OK;
	u32 dev_id = 0;
	u32 index = 0;
	u32 zblk_idx[32] = { 0 };
	struct dpp_apt_hash_func_res_t *pHashFuncResTemp = NULL;
	struct dpp_se_cfg *p_se_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(func_num, HASH_FUNC_ID_NUM);
	ZXIC_COMM_CHECK_POINT(pHashFuncRes);

	p_se_cfg = dpp_apt_get_se_cfg(dev);
	ZXIC_COMM_CHECK_POINT(p_se_cfg);
	for (index = 0; index < func_num; index++) {
		ZXIC_COMM_MEMSET(zblk_idx, 0x0, sizeof(zblk_idx));
		pHashFuncResTemp = pHashFuncRes + index;
		rc = dpp_apt_get_zblock_index(pHashFuncResTemp->zblk_bitmap, zblk_idx);
		ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_apt_get_zblock_index");

		rc = dpp_hash_init(p_se_cfg, pHashFuncResTemp->func_id, pHashFuncResTemp->zblk_num,
				   zblk_idx, pHashFuncResTemp->ddr_dis);
		ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_hash_init");
	}

	return rc;
}
DPP_STATUS
dpp_apt_hash_func_flush_hardware_all(struct dpp_dev_t *dev, u32 func_num,
				     struct dpp_apt_hash_func_res_t *pHashFuncRes, u32 queue_id)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	struct dpp_apt_hash_func_res_t *pHashFuncResTemp = NULL;
	struct dpp_se_cfg *p_se_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(func_num, HASH_FUNC_ID_NUM);
	p_se_cfg = dpp_apt_get_se_cfg(dev);
	ZXIC_COMM_CHECK_POINT(p_se_cfg);
	for (index = 0; index < func_num; index++) {
		pHashFuncResTemp = pHashFuncRes + index;

		rc = dpp_dtb_zcam_space_clr(dev, p_se_cfg, queue_id, pHashFuncResTemp->func_id);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_zcam_space_clr");
	}

	return rc;
}
DPP_STATUS dpp_apt_hash_bulk_res_init(struct dpp_dev_t *dev, u32 bulk_num,
				      struct dpp_apt_hash_bulk_res_t *pBulkRes)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	u32 dev_id = 0;
	struct dpp_apt_hash_bulk_res_t *pHashBulkResTemp = NULL;
	struct dpp_se_cfg *p_se_cfg = NULL;
	struct dpp_hash_ddr_resc_cfg_t ddr_resc_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	dev_id = DEV_ID(dev);
	ZXIC_COMM_CHECK_INDEX(dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(bulk_num, HASH_FUNC_ID_NUM * HASH_BULK_NUM);
	ZXIC_COMM_CHECK_POINT(pBulkRes);
	p_se_cfg = dpp_apt_get_se_cfg(dev);
	ZXIC_COMM_CHECK_POINT(p_se_cfg);

	for (index = 0; index < bulk_num; index++) {
		ZXIC_COMM_MEMSET(&ddr_resc_cfg, 0x0, sizeof(struct dpp_hash_ddr_resc_cfg_t));
		pHashBulkResTemp = pBulkRes + index;

		ddr_resc_cfg.ddr_baddr = pHashBulkResTemp->ddr_baddr;
		ddr_resc_cfg.ddr_item_num = pHashBulkResTemp->ddr_item_num;
		ddr_resc_cfg.ddr_width_mode = pHashBulkResTemp->ddr_width_mode;
		ddr_resc_cfg.ddr_crc_sel = pHashBulkResTemp->ddr_crc_sel;
		ddr_resc_cfg.ddr_ecc_en = pHashBulkResTemp->ddr_ecc_en;

		rc = dpp_hash_bulk_init(p_se_cfg, pHashBulkResTemp->func_id,
					pHashBulkResTemp->bulk_id, &ddr_resc_cfg,
					pHashBulkResTemp->zcell_num, pHashBulkResTemp->zreg_num);
		ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, "dpp_hash_bulk_init");
	}

	return rc;
}
DPP_STATUS dpp_apt_hash_tbl_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				     struct dpp_apt_hash_table_t *pHashTbl)
{
	DPP_STATUS rc = DPP_OK;
	u32 index = 0;
	struct dpp_apt_hash_table_t *pHashTblTemp = NULL;
	struct dpp_se_cfg *p_se_cfg = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_UPPER(tbl_num, HASH_FUNC_ID_NUM * HASH_TBL_ID_NUM);
	ZXIC_COMM_CHECK_POINT(pHashTbl);
	p_se_cfg = dpp_apt_get_se_cfg(dev);
	ZXIC_COMM_CHECK_POINT(p_se_cfg);

	for (index = 0; index < tbl_num; index++) {
		pHashTblTemp = pHashTbl + index;
		rc = dpp_sdt_tbl_write(dev, pHashTblTemp->sdtNo, pHashTblTemp->hashSdt.table_type,
				       &pHashTblTemp->hashSdt, SDT_OPER_ADD);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_sdt_tbl_write");

		rc = dpp_hash_tbl_id_info_init(p_se_cfg, pHashTblTemp->hashSdt.hash_id,
					       pHashTblTemp->hashSdt.hash_table_id,
					       pHashTblTemp->tbl_flag,
					       pHashTblTemp->hashSdt.hash_table_width,
					       pHashTblTemp->hashSdt.key_size);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_hash_tbl_id_info_init_ex");

		rc = dpp_apt_set_callback(dev, pHashTblTemp->sdtNo,
					  pHashTblTemp->hashSdt.table_type, (void *)pHashTblTemp);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_apt_set_callback");
	}

	return rc;
}
DPP_STATUS dpp_apt_dtb_hash_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData)
{
	DPP_STATUS rc = DPP_OK;
	u8 key_valid = 1;
	struct dpp_hash_entry entry = { 0 };
	struct dpp_sdt_tbl_hash_t sdt_hash_info = { 0 };
	u8 aucKey[HASH_KEY_MAX] = { 0 };
	u8 aucRst[HASH_RST_MAX] = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_dtb_hash_entry_info_t tDtbHashEntry = { 0 };
	u32 element_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	rc = dpp_soft_sdt_tbl_get(dev, sdt_no, &sdt_hash_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_soft_sdt_tbl_get");

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	entry.p_key = aucKey;
	entry.p_rst = aucRst;
	ZXIC_COMM_MEMSET(entry.p_key, 0x0, sizeof(aucKey));
	ZXIC_COMM_MEMSET(entry.p_rst, 0x0, sizeof(aucRst));
	entry.p_key[0] = DPP_GET_HASH_KEY_CTRL(key_valid, sdt_hash_info.hash_table_width,
					       sdt_hash_info.hash_table_id);
	rc = pAptCallback->se_func_info.hashFunc.hash_set_func(pData, &entry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "hash_set_func");

	tDtbHashEntry.p_actu_key = &entry.p_key[1];
	tDtbHashEntry.p_rst = entry.p_rst;

	rc = dpp_dtb_hash_dma_insert(dev, queue_id, sdt_no, 1, &tDtbHashEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_hash_dma_insert");

	return rc;
}
DPP_STATUS dpp_apt_dtb_hash_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData)
{
	DPP_STATUS rc = DPP_OK;
	u8 key_valid = 1;
	struct dpp_hash_entry entry = { 0 };
	struct dpp_sdt_tbl_hash_t sdt_hash_info = { 0 };
	u8 aucKey[HASH_KEY_MAX] = { 0 };
	u8 aucRst[HASH_RST_MAX] = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_dtb_hash_entry_info_t tDtbHashEntry = { 0 };
	// u32 queue_id = 0;
	u32 element_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	rc = dpp_soft_sdt_tbl_get(dev, sdt_no, &sdt_hash_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_soft_sdt_tbl_get");

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	entry.p_key = aucKey;
	entry.p_rst = aucRst;
	ZXIC_COMM_MEMSET(entry.p_key, 0x0, sizeof(aucKey));
	ZXIC_COMM_MEMSET(entry.p_rst, 0x0, sizeof(aucRst));
	entry.p_key[0] = DPP_GET_HASH_KEY_CTRL(key_valid, sdt_hash_info.hash_table_width,
					       sdt_hash_info.hash_table_id);
	rc = pAptCallback->se_func_info.hashFunc.hash_set_func(pData, &entry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "hash_set_func");

	ZXIC_COMM_MEMSET(&tDtbHashEntry, 0x0, sizeof(struct dpp_dtb_hash_entry_info_t));
	ZXIC_COMM_MEMSET(entry.p_rst, 0x0, sizeof(aucRst));
	tDtbHashEntry.p_actu_key = &entry.p_key[1];
	tDtbHashEntry.p_rst = entry.p_rst;
	rc = dpp_dtb_hash_dma_delete(dev, queue_id, sdt_no, 1, &tDtbHashEntry, &element_id);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_hash_dma_delete");

	return rc;
}
DPP_STATUS dpp_apt_dtb_multi_hash_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					 u32 entry_num, u32 entry_size, void *pData)
{
	DPP_STATUS rc = DPP_OK;
	u8 key_valid = 1;
	u32 entry_index = 0;
	struct dpp_hash_entry entry = { 0 };
	struct dpp_sdt_tbl_hash_t sdt_hash_info = { 0 };
	u8 aucKey[HASH_KEY_MAX] = { 0 };
	u8 aucRst[HASH_RST_MAX] = { 0 };

	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_dtb_hash_entry_info_t *p_oneHashEntry = NULL;
	struct dpp_dtb_hash_entry_info_t *p_multiHashEntry = NULL;
	u8 *p_key = NULL;
	u8 *p_rst = NULL;
	u8 *p_temp_data = NULL;
	u32 element_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_LOWER(entry_num, 1);

	rc = dpp_soft_sdt_tbl_get(dev, sdt_no, &sdt_hash_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_soft_sdt_tbl_get");

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	entry.p_key = aucKey;
	entry.p_rst = aucRst;

	p_multiHashEntry = (struct dpp_dtb_hash_entry_info_t *)ZXIC_COMM_MALLOC(
		entry_num * sizeof(struct dpp_dtb_hash_entry_info_t));
	ZXIC_COMM_CHECK_POINT(p_multiHashEntry);
	p_key = (u8 *)ZXIC_COMM_MALLOC(entry_num * HASH_KEY_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_FREE(p_key, p_multiHashEntry);
	p_rst = (u8 *)ZXIC_COMM_MALLOC(entry_num * HASH_RST_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_FREE2PTR_NO_ASSERT(p_rst, p_key, p_multiHashEntry);
	ZXIC_COMM_MEMSET_S(p_multiHashEntry, entry_num * sizeof(struct dpp_dtb_hash_entry_info_t),
			   0x0, entry_num * sizeof(struct dpp_dtb_hash_entry_info_t));
	ZXIC_COMM_MEMSET_S(p_key, entry_num * HASH_KEY_MAX, 0x0, entry_num * HASH_KEY_MAX);
	ZXIC_COMM_MEMSET_S(p_rst, entry_num * HASH_RST_MAX, 0x0, entry_num * HASH_RST_MAX);

	for (entry_index = 0; entry_index < entry_num; entry_index++) {
		ZXIC_COMM_MEMSET_S(entry.p_key, HASH_KEY_MAX, 0x0, sizeof(aucKey));
		ZXIC_COMM_MEMSET_S(entry.p_rst, HASH_RST_MAX, 0x0, sizeof(aucRst));
		entry.p_key[0] = DPP_GET_HASH_KEY_CTRL(key_valid, sdt_hash_info.hash_table_width,
						       sdt_hash_info.hash_table_id);
		p_temp_data = (u8 *)pData + entry_index * entry_size;
		rc = pAptCallback->se_func_info.hashFunc.hash_set_func((void *)p_temp_data, &entry);
		ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE3PTR_NO_ASSERT(DEV_ID(dev), rc, "hash_set_func",
								 p_rst, p_key, p_multiHashEntry);

		p_oneHashEntry = p_multiHashEntry + entry_index;
		p_oneHashEntry->p_actu_key = p_key + entry_index * HASH_KEY_MAX;
		p_oneHashEntry->p_rst = p_rst + entry_index * HASH_RST_MAX;
		ZXIC_COMM_MEMCPY_S(p_oneHashEntry->p_actu_key, HASH_KEY_MAX, &entry.p_key[1],
				   sizeof(aucKey) - 1);
		ZXIC_COMM_MEMCPY_S(p_oneHashEntry->p_rst, HASH_RST_MAX, entry.p_rst,
				   sizeof(aucRst));
	}

	rc = dpp_dtb_hash_dma_insert(dev, queue_id, sdt_no, entry_num, p_multiHashEntry,
				     &element_id);
	ZXIC_COMM_FREE(p_rst);
	ZXIC_COMM_FREE(p_key);
	ZXIC_COMM_FREE(p_multiHashEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_hash_dma_insert");

	return rc;
}
DPP_STATUS dpp_apt_dtb_multi_hash_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					 u32 entry_num, u32 entry_size, void *pData)
{
	DPP_STATUS rc = DPP_OK;
	u8 key_valid = 1;
	u32 entry_index = 0;
	struct dpp_hash_entry entry = { 0 };
	struct dpp_sdt_tbl_hash_t sdt_hash_info = { 0 };
	u8 aucKey[HASH_KEY_MAX] = { 0 };
	u8 aucRst[HASH_RST_MAX] = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;
	struct dpp_dtb_hash_entry_info_t *p_oneHashEntry = NULL;
	struct dpp_dtb_hash_entry_info_t *p_multiHashEntry = NULL;
	u8 *p_key = NULL;
	u8 *p_rst = NULL;
	u8 *p_temp_data = NULL;
	u32 element_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_INDEX_LOWER(entry_num, 1);

	rc = dpp_soft_sdt_tbl_get(dev, sdt_no, &sdt_hash_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_soft_sdt_tbl_get");

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	entry.p_key = aucKey;
	entry.p_rst = aucRst;

	p_multiHashEntry = (struct dpp_dtb_hash_entry_info_t *)ZXIC_COMM_MALLOC(
		entry_num * sizeof(struct dpp_dtb_hash_entry_info_t));
	ZXIC_COMM_CHECK_POINT(p_multiHashEntry);
	p_key = (u8 *)ZXIC_COMM_MALLOC(entry_num * HASH_KEY_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_FREE(p_key, p_multiHashEntry);
	p_rst = (u8 *)ZXIC_COMM_MALLOC(entry_num * HASH_RST_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_FREE2PTR_NO_ASSERT(p_rst, p_key, p_multiHashEntry);
	ZXIC_COMM_MEMSET_S(p_multiHashEntry, entry_num * sizeof(struct dpp_dtb_hash_entry_info_t),
			   0x0, entry_num * sizeof(struct dpp_dtb_hash_entry_info_t));
	ZXIC_COMM_MEMSET_S(p_key, entry_num * HASH_KEY_MAX, 0x0, entry_num * HASH_KEY_MAX);
	ZXIC_COMM_MEMSET_S(p_rst, entry_num * HASH_RST_MAX, 0x0, entry_num * HASH_RST_MAX);

	for (entry_index = 0; entry_index < entry_num; entry_index++) {
		ZXIC_COMM_MEMSET_S(entry.p_key, HASH_KEY_MAX, 0x0, sizeof(aucKey));
		ZXIC_COMM_MEMSET_S(entry.p_rst, HASH_RST_MAX, 0x0, sizeof(aucRst));
		entry.p_key[0] = DPP_GET_HASH_KEY_CTRL(key_valid, sdt_hash_info.hash_table_width,
						       sdt_hash_info.hash_table_id);
		p_temp_data = (u8 *)pData + entry_index * entry_size;
		rc = pAptCallback->se_func_info.hashFunc.hash_set_func((void *)p_temp_data, &entry);
		ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE3PTR_NO_ASSERT(DEV_ID(dev), rc, "hash_set_func",
								 p_rst, p_key, p_multiHashEntry);

		p_oneHashEntry = p_multiHashEntry + entry_index;
		p_oneHashEntry->p_actu_key = p_key + entry_index * HASH_KEY_MAX;
		p_oneHashEntry->p_rst = p_rst + entry_index * HASH_RST_MAX;
		ZXIC_COMM_MEMCPY_S(p_oneHashEntry->p_actu_key, HASH_KEY_MAX, &entry.p_key[1],
				   sizeof(aucKey) - 1);
	}

	rc = dpp_dtb_hash_dma_delete(dev, queue_id, sdt_no, entry_num, p_multiHashEntry,
				     &element_id);
	ZXIC_COMM_FREE(p_rst);
	ZXIC_COMM_FREE(p_key);
	ZXIC_COMM_FREE(p_multiHashEntry);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_dtb_hash_dma_delete");

	return rc;
}
