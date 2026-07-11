// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"

#include "dpp_dev.h"
#include "dpp_se.h"
#include "dpp_sdt_def.h"
#include "dpp_sdt_mgr.h"
#include "dpp_sdt.h"

#define DPP_SDT_GET_LOW_DATA(source_value, low_width) (source_value & ((1 << low_width) - 1))

#if ZXIC_REAL("function for FCM_FTM ")
DPP_STATUS dpp_sdt_init(u32 dev_num, u32 *dev_id_array)
{
	DPP_STATUS rc = 0;
	u32 i = 0;

	ZXIC_COMM_CHECK_INDEX(dev_num, 1, DPP_DEV_CHANNEL_MAX);
	ZXIC_COMM_CHECK_POINT(dev_id_array);

	for (i = 0; i < dev_num; i++)
		ZXIC_COMM_CHECK_INDEX(*(dev_id_array + i), 0, DPP_DEV_CHANNEL_MAX - 1);

	dpp_sdt_mgr_init();

	for (i = 0; i < dev_num; i++) {
		rc = dpp_sdt_mgr_create(dev_id_array[i]);
		ZXIC_COMM_CHECK_RC(rc, "dpp_sdt_mgr_create");
	}

	return DPP_OK;
}
DPP_STATUS dpp_sdt_tbl_data_parser(struct dpp_dev_t *dev, u32 sdt_hig32, u32 sdt_low32,
				   void *p_sdt_info)
{
	u32 tmp = 0;
	u32 tbl_type = 0;
	u32 clutch_en = 0;

	struct dpp_sdt_tbl_eram_t *p_sdt_eram = NULL;
	struct dpp_sdt_tbl_ddr3_t *p_sdt_ddr3 = NULL;
	struct dpp_sdt_tbl_hash_t *p_sdt_hash = NULL;
	struct dpp_sdt_tbl_lpm_t *p_sdt_lpm = NULL;
	struct dpp_sdt_tbl_etcam_t *p_sdt_etcam = NULL;
	struct dpp_sdt_tbl_porttbl_t *p_sdt_porttbl = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_sdt_info);

	ZXIC_COMM_UINT32_GET_BITS(tbl_type, sdt_hig32, DPP_SDT_H_TBL_TYPE_BT_POS,
				  DPP_SDT_H_TBL_TYPE_BT_LEN);
	ZXIC_COMM_UINT32_GET_BITS(clutch_en, sdt_low32, DPP_SDT_L_CLUTCH_EN_BT_POS,
				  DPP_SDT_L_CLUTCH_EN_BT_LEN);

	switch (tbl_type) {
	case DPP_SDT_TBLT_eRAM: {
		p_sdt_eram = (struct dpp_sdt_tbl_eram_t *)p_sdt_info;
		p_sdt_eram->table_type = tbl_type;
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_eram->eram_mode, sdt_hig32,
					  DPP_SDT_H_ERAM_MODE_BT_POS, DPP_SDT_H_ERAM_MODE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_eram->eram_base_addr, sdt_hig32,
					  DPP_SDT_H_ERAM_BASE_ADDR_BT_POS,
					  DPP_SDT_H_ERAM_BASE_ADDR_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_eram->eram_table_depth, sdt_low32,
					  DPP_SDT_L_ERAM_TABLE_DEPTH_BT_POS,
					  DPP_SDT_L_ERAM_TABLE_DEPTH_BT_LEN);
		p_sdt_eram->eram_clutch_en = clutch_en;
		break;
	}

	case DPP_SDT_TBLT_DDR3: {
		p_sdt_ddr3 = (struct dpp_sdt_tbl_ddr3_t *)p_sdt_info;
		p_sdt_ddr3->table_type = tbl_type;
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_ddr3->ddr3_base_addr, sdt_hig32,
					  DPP_SDT_H_DDR3_BASE_ADDR_BT_POS,
					  DPP_SDT_H_DDR3_BASE_ADDR_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_ddr3->ddr3_share_type, sdt_hig32,
					  DPP_SDT_H_DDR3_SHARE_TYPE_BT_POS,
					  DPP_SDT_H_DDR3_SHARE_TYPE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_ddr3->ddr3_rw_len, sdt_hig32,
					  DPP_SDT_H_DDR3_RW_LEN_BT_POS,
					  DPP_SDT_H_DDR3_RW_LEN_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(tmp, sdt_hig32, DPP_SDT_H_DDR3_SDT_NUM_BT_POS,
					  DPP_SDT_H_DDR3_SDT_NUM_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_ddr3->ddr3_sdt_num, sdt_low32,
					  DPP_SDT_L_DDR3_SDT_NUM_BT_POS,
					  DPP_SDT_L_DDR3_SDT_NUM_BT_LEN);
		p_sdt_ddr3->ddr3_sdt_num += (tmp << DPP_SDT_L_DDR3_SDT_NUM_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_ddr3->ddr3_ecc_en, sdt_low32,
					  DPP_SDT_L_DDR3_ECC_EN_BT_POS,
					  DPP_SDT_L_DDR3_ECC_EN_BT_LEN);
		p_sdt_ddr3->ddr3_clutch_en = clutch_en;
		break;
	}

	case DPP_SDT_TBLT_HASH: {
		p_sdt_hash = (struct dpp_sdt_tbl_hash_t *)p_sdt_info;
		p_sdt_hash->table_type = tbl_type;
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->hash_id, sdt_hig32, DPP_SDT_H_HASH_ID_BT_POS,
					  DPP_SDT_H_HASH_ID_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->hash_table_width, sdt_hig32,
					  DPP_SDT_H_HASH_TABLE_WIDTH_BT_POS,
					  DPP_SDT_H_HASH_TABLE_WIDTH_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->key_size, sdt_hig32,
					  DPP_SDT_H_HASH_KEY_SIZE_BT_POS,
					  DPP_SDT_H_HASH_KEY_SIZE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->hash_table_id, sdt_hig32,
					  DPP_SDT_H_HASH_TABLE_ID_BT_POS,
					  DPP_SDT_H_HASH_TABLE_ID_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->learn_en, sdt_hig32,
					  DPP_SDT_H_LEARN_EN_BT_POS, DPP_SDT_H_LEARN_EN_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->keep_alive, sdt_hig32,
					  DPP_SDT_H_KEEP_ALIVE_BT_POS, DPP_SDT_H_KEEP_ALIVE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(tmp, sdt_hig32, DPP_SDT_H_KEEP_ALIVE_BADDR_BT_POS,
					  DPP_SDT_H_KEEP_ALIVE_BADDR_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->keep_alive_baddr, sdt_low32,
					  DPP_SDT_L_KEEP_ALIVE_BADDR_BT_POS,
					  DPP_SDT_L_KEEP_ALIVE_BADDR_BT_LEN);
		p_sdt_hash->keep_alive_baddr += (tmp << DPP_SDT_L_KEEP_ALIVE_BADDR_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_hash->rsp_mode, sdt_low32,
					  DPP_SDT_L_RSP_MODE_BT_POS, DPP_SDT_L_RSP_MODE_BT_LEN);
		p_sdt_hash->hash_clutch_en = clutch_en;
		break;
	}

	case DPP_SDT_TBLT_LPM: {
		p_sdt_lpm = (struct dpp_sdt_tbl_lpm_t *)p_sdt_info;
		p_sdt_lpm->table_type = tbl_type;
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_lpm->lpm_v46_id, sdt_hig32,
					  DPP_SDT_H_LPM_V46ID_BT_POS, DPP_SDT_H_LPM_V46ID_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_lpm->rsp_mode, sdt_hig32,
					  DPP_SDT_H_LPM_RSP_MODE_BT_POS,
					  DPP_SDT_H_LPM_RSP_MODE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_lpm->lpm_table_depth, sdt_low32,
					  DPP_SDT_L_LPM_TABLE_DEPTH_BT_POS,
					  DPP_SDT_L_LPM_TABLE_DEPTH_BT_LEN);
		p_sdt_lpm->lpm_clutch_en = clutch_en;
		break;
	}

	case DPP_SDT_TBLT_eTCAM: {
		p_sdt_etcam = (struct dpp_sdt_tbl_etcam_t *)p_sdt_info;
		p_sdt_etcam->table_type = tbl_type;
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->etcam_id, sdt_hig32,
					  DPP_SDT_H_ETCAM_ID_BT_POS, DPP_SDT_H_ETCAM_ID_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->etcam_key_mode, sdt_hig32,
					  DPP_SDT_H_ETCAM_KEY_MODE_BT_POS,
					  DPP_SDT_H_ETCAM_KEY_MODE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->etcam_table_id, sdt_hig32,
					  DPP_SDT_H_ETCAM_TABLE_ID_BT_POS,
					  DPP_SDT_H_ETCAM_TABLE_ID_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->no_as_rsp_mode, sdt_hig32,
					  DPP_SDT_H_ETCAM_NOAS_RSP_MODE_BT_POS,
					  DPP_SDT_H_ETCAM_NOAS_RSP_MODE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->as_en, sdt_hig32,
					  DPP_SDT_H_ETCAM_AS_EN_BT_POS,
					  DPP_SDT_H_ETCAM_AS_EN_BT_LEN);

		ZXIC_COMM_UINT32_GET_BITS(tmp, sdt_hig32, DPP_SDT_H_ETCAM_AS_ERAM_BADDR_BT_POS,
					  DPP_SDT_H_ETCAM_AS_ERAM_BADDR_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->as_eram_baddr, sdt_low32,
					  DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_POS,
					  DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_LEN);
		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(
			p_sdt_etcam->as_eram_baddr, (tmp << DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_LEN));
		p_sdt_etcam->as_eram_baddr += (tmp << DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_LEN);

		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->as_rsp_mode, sdt_low32,
					  DPP_SDT_L_ETCAM_AS_RSP_MODE_BT_POS,
					  DPP_SDT_L_ETCAM_AS_RSP_MODE_BT_LEN);
		ZXIC_COMM_UINT32_GET_BITS(p_sdt_etcam->etcam_table_depth, sdt_low32,
					  DPP_SDT_L_ETCAM_TABLE_DEPTH_BT_POS,
					  DPP_SDT_L_ETCAM_TABLE_DEPTH_BT_LEN);
		p_sdt_etcam->etcam_clutch_en = clutch_en;
		break;
	}

	case DPP_SDT_TBLT_PORTTBL: {
		p_sdt_porttbl = (struct dpp_sdt_tbl_porttbl_t *)p_sdt_info;
		p_sdt_porttbl->table_type = tbl_type;
		p_sdt_porttbl->porttbl_clutch_en = clutch_en;
		break;
	}

	default: {
		ZXIC_COMM_TRACE_ERROR("SDT table_type[ %d ] is invalid!\n", tbl_type);
		ZXIC_COMM_ASSERT(0);
		return DPP_ERR;
	}
	}

	return DPP_OK;
}
DPP_STATUS dpp_sdt_tbl_data_get(struct dpp_dev_t *dev, u32 sdt_no,
				struct dpp_sdt_tbl_data_t *p_sdt_data)
{
	return dpp_sdt_mgr_sdt_item_srh(dev, sdt_no, &p_sdt_data->data_high32,
					&p_sdt_data->data_low32);
}
DPP_STATUS dpp_soft_sdt_tbl_get(struct dpp_dev_t *dev, u32 sdt_no, void *p_sdt_info)
{
	DPP_STATUS rc = 0;

	struct dpp_sdt_tbl_data_t sdt_tbl = { 0 };

	ZXIC_COMM_CHECK_INDEX(sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);
	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_sdt_info);

	rc = dpp_sdt_tbl_data_get(dev, sdt_no, &sdt_tbl);
	ZXIC_COMM_CHECK_RC(rc, "dpp_sdt_tbl_data_get");

	rc = dpp_sdt_tbl_data_parser(dev, sdt_tbl.data_high32, sdt_tbl.data_low32, p_sdt_info);
	ZXIC_COMM_CHECK_RC(rc, "dpp_sdt_tbl_data_parser");

	return rc;
}
DPP_STATUS dpp_sdt_tbl_write(struct dpp_dev_t *dev, u32 sdt_no, u32 table_type, void *p_sdt_info,
			     u32 opr_type)
{
#ifdef DPP_FLOW_HW_INIT
	u32 i = 0;
#endif
	DPP_STATUS rtn = 0;
	struct dpp_sdt_tbl_data_t sdt_tbl = { 0 };
	struct dpp_sdt_tbl_eram_t *p_sdt_eram = NULL;
	struct dpp_sdt_tbl_ddr3_t *p_sdt_ddr3 = NULL;
	struct dpp_sdt_tbl_hash_t *p_sdt_hash = NULL;
	struct dpp_sdt_tbl_lpm_t *p_sdt_lpm = NULL;
	struct dpp_sdt_tbl_etcam_t *p_sdt_etcam = NULL;
	struct dpp_sdt_tbl_porttbl_t *p_sdt_porttbl = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), sdt_no, 0, DPP_DEV_SDT_ID_MAX - 1);

	ZXIC_COMM_MEMSET_S(&sdt_tbl, sizeof(struct dpp_sdt_tbl_data_t), 0,
			   sizeof(struct dpp_sdt_tbl_data_t));

	if (opr_type) {
		rtn = dpp_sdt_mgr_sdt_item_del(dev, sdt_no);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_sdt_mgr_sdt_item_del");
	} else {
		/* add sdt item*/
		ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_sdt_info);
		ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), table_type, DPP_SDT_TBLT_eRAM,
					  DPP_SDT_TBLT_PORTTBL);

		switch (table_type) {
		case DPP_SDT_TBLT_eRAM: {
			p_sdt_eram = (struct dpp_sdt_tbl_eram_t *)p_sdt_info;
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_eram->eram_mode,
						    DPP_SDT_H_ERAM_MODE_BT_POS,
						    DPP_SDT_H_ERAM_MODE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_eram->eram_base_addr,
						    DPP_SDT_H_ERAM_BASE_ADDR_BT_POS,
						    DPP_SDT_H_ERAM_BASE_ADDR_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32,
						    p_sdt_eram->eram_table_depth,
						    DPP_SDT_L_ERAM_TABLE_DEPTH_BT_POS,
						    DPP_SDT_L_ERAM_TABLE_DEPTH_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_eram->eram_clutch_en,
						    DPP_SDT_L_CLUTCH_EN_BT_POS,
						    DPP_SDT_L_CLUTCH_EN_BT_LEN);
			break;
		}

		case DPP_SDT_TBLT_DDR3: {
			p_sdt_ddr3 = (struct dpp_sdt_tbl_ddr3_t *)p_sdt_info;

			ZXIC_COMM_ASSERT(sdt_no == p_sdt_ddr3->ddr3_sdt_num);

			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_ddr3->ddr3_base_addr,
						    DPP_SDT_H_DDR3_BASE_ADDR_BT_POS,
						    DPP_SDT_H_DDR3_BASE_ADDR_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32,
						    p_sdt_ddr3->ddr3_share_type,
						    DPP_SDT_H_DDR3_SHARE_TYPE_BT_POS,
						    DPP_SDT_H_DDR3_SHARE_TYPE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_ddr3->ddr3_rw_len,
						    DPP_SDT_H_DDR3_RW_LEN_BT_POS,
						    DPP_SDT_H_DDR3_RW_LEN_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(
				sdt_tbl.data_high32,
				((p_sdt_ddr3->ddr3_sdt_num) >> DPP_SDT_L_DDR3_SDT_NUM_BT_LEN),
				DPP_SDT_H_DDR3_SDT_NUM_BT_POS, DPP_SDT_H_DDR3_SDT_NUM_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(
				sdt_tbl.data_low32,
				DPP_SDT_GET_LOW_DATA((p_sdt_ddr3->ddr3_sdt_num),
						     DPP_SDT_L_DDR3_SDT_NUM_BT_LEN),
				DPP_SDT_L_DDR3_SDT_NUM_BT_POS, DPP_SDT_L_DDR3_SDT_NUM_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_ddr3->ddr3_ecc_en,
						    DPP_SDT_L_DDR3_ECC_EN_BT_POS,
						    DPP_SDT_L_DDR3_ECC_EN_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_ddr3->ddr3_clutch_en,
						    DPP_SDT_L_CLUTCH_EN_BT_POS,
						    DPP_SDT_L_CLUTCH_EN_BT_LEN);
			break;
		}

		case DPP_SDT_TBLT_HASH: {
			p_sdt_hash = (struct dpp_sdt_tbl_hash_t *)p_sdt_info;
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_hash->hash_id,
						    DPP_SDT_H_HASH_ID_BT_POS,
						    DPP_SDT_H_HASH_ID_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32,
						    p_sdt_hash->hash_table_width,
						    DPP_SDT_H_HASH_TABLE_WIDTH_BT_POS,
						    DPP_SDT_H_HASH_TABLE_WIDTH_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_hash->key_size,
						    DPP_SDT_H_HASH_KEY_SIZE_BT_POS,
						    DPP_SDT_H_HASH_KEY_SIZE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_hash->hash_table_id,
						    DPP_SDT_H_HASH_TABLE_ID_BT_POS,
						    DPP_SDT_H_HASH_TABLE_ID_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_hash->learn_en,
						    DPP_SDT_H_LEARN_EN_BT_POS,
						    DPP_SDT_H_LEARN_EN_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_hash->keep_alive,
						    DPP_SDT_H_KEEP_ALIVE_BT_POS,
						    DPP_SDT_H_KEEP_ALIVE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32,
						    ((p_sdt_hash->keep_alive_baddr) >>
						     DPP_SDT_L_KEEP_ALIVE_BADDR_BT_LEN),
						    DPP_SDT_H_KEEP_ALIVE_BADDR_BT_POS,
						    DPP_SDT_H_KEEP_ALIVE_BADDR_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(
				sdt_tbl.data_low32,
				DPP_SDT_GET_LOW_DATA((p_sdt_hash->keep_alive_baddr),
						     DPP_SDT_L_KEEP_ALIVE_BADDR_BT_LEN),
				DPP_SDT_L_KEEP_ALIVE_BADDR_BT_POS,
				DPP_SDT_L_KEEP_ALIVE_BADDR_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_hash->rsp_mode,
						    DPP_SDT_L_RSP_MODE_BT_POS,
						    DPP_SDT_L_RSP_MODE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_hash->hash_clutch_en,
						    DPP_SDT_L_CLUTCH_EN_BT_POS,
						    DPP_SDT_L_CLUTCH_EN_BT_LEN);
			break;
		}

		case DPP_SDT_TBLT_LPM: {
			p_sdt_lpm = (struct dpp_sdt_tbl_lpm_t *)p_sdt_info;
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_lpm->lpm_v46_id,
						    DPP_SDT_H_LPM_V46ID_BT_POS,
						    DPP_SDT_H_LPM_V46ID_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_lpm->rsp_mode,
						    DPP_SDT_H_LPM_RSP_MODE_BT_POS,
						    DPP_SDT_H_LPM_RSP_MODE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_lpm->lpm_table_depth,
						    DPP_SDT_L_LPM_TABLE_DEPTH_BT_POS,
						    DPP_SDT_L_LPM_TABLE_DEPTH_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_lpm->lpm_clutch_en,
						    DPP_SDT_L_CLUTCH_EN_BT_POS,
						    DPP_SDT_L_CLUTCH_EN_BT_LEN);
			break;
		}

		case DPP_SDT_TBLT_eTCAM: {
			p_sdt_etcam = (struct dpp_sdt_tbl_etcam_t *)p_sdt_info;
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_etcam->etcam_id,
						    DPP_SDT_H_ETCAM_ID_BT_POS,
						    DPP_SDT_H_ETCAM_ID_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32,
						    p_sdt_etcam->etcam_key_mode,
						    DPP_SDT_H_ETCAM_KEY_MODE_BT_POS,
						    DPP_SDT_H_ETCAM_KEY_MODE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32,
						    p_sdt_etcam->etcam_table_id,
						    DPP_SDT_H_ETCAM_TABLE_ID_BT_POS,
						    DPP_SDT_H_ETCAM_TABLE_ID_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32,
						    p_sdt_etcam->no_as_rsp_mode,
						    DPP_SDT_H_ETCAM_NOAS_RSP_MODE_BT_POS,
						    DPP_SDT_H_ETCAM_NOAS_RSP_MODE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, p_sdt_etcam->as_en,
						    DPP_SDT_H_ETCAM_AS_EN_BT_POS,
						    DPP_SDT_H_ETCAM_AS_EN_BT_LEN);

			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32,
						    ((p_sdt_etcam->as_eram_baddr) >>
						     DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_LEN),
						    DPP_SDT_H_ETCAM_AS_ERAM_BADDR_BT_POS,
						    DPP_SDT_H_ETCAM_AS_ERAM_BADDR_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(
				sdt_tbl.data_low32,
				DPP_SDT_GET_LOW_DATA((p_sdt_etcam->as_eram_baddr),
						     DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_LEN),
				DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_POS,
				DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_LEN);

			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32, p_sdt_etcam->as_rsp_mode,
						    DPP_SDT_L_ETCAM_AS_RSP_MODE_BT_POS,
						    DPP_SDT_L_ETCAM_AS_RSP_MODE_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32,
						    p_sdt_etcam->etcam_table_depth,
						    DPP_SDT_L_ETCAM_TABLE_DEPTH_BT_POS,
						    DPP_SDT_L_ETCAM_TABLE_DEPTH_BT_LEN);
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32,
						    p_sdt_etcam->etcam_clutch_en,
						    DPP_SDT_L_CLUTCH_EN_BT_POS,
						    DPP_SDT_L_CLUTCH_EN_BT_LEN);
			break;
		}

		case DPP_SDT_TBLT_PORTTBL: {
			p_sdt_porttbl = (struct dpp_sdt_tbl_porttbl_t *)p_sdt_info;
			ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_low32,
						    p_sdt_porttbl->porttbl_clutch_en,
						    DPP_SDT_L_CLUTCH_EN_BT_POS,
						    DPP_SDT_L_CLUTCH_EN_BT_LEN);
			break;
		}

		default: {
			ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev), "SDT table_type[ %d ] is invalid!\n",
						  table_type);
			return DPP_ERR;
		}
		}

		ZXIC_COMM_UINT32_WRITE_BITS(sdt_tbl.data_high32, table_type,
					    DPP_SDT_H_TBL_TYPE_BT_POS, DPP_SDT_H_TBL_TYPE_BT_LEN);

		rtn = dpp_sdt_mgr_sdt_item_add(dev, sdt_no, sdt_tbl.data_high32,
					       sdt_tbl.data_low32);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_sdt_mgr_sdt_item_add");
	}
#ifdef DPP_FLOW_HW_INIT
	for (i = 0; i < DPP_PPU_CLUSTER_NUM; i++) {
		if (!dpp_ppu_cls_use_get(DEV_ID(dev), i))
			continue;

		rtn = dpp_ppu_sdt_tbl_write(dev, i, sdt_no, &sdt_tbl);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_ppu_sdt_tbl_write");
	}
#endif
	return DPP_OK;
}

#endif
