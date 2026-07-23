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
#include "dpp_stat_api.h"
#include "dpp_tbl_api.h"
#include "dpp_tbl_comm.h"
#include "dpp_tbl_stat.h"

u32 dpp_stat_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 buff[2] = { 0 };
	u32 rc = DPP_OK;
	struct dpp_apt_se_res_t *p_se_res = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x index: %u mode: %u start.\n", __func__,
			       pf_info->slot, pf_info->vport, index, mode);

	ZXIC_COMM_CHECK_POINT(p_cnt);
	ZXIC_COMM_CHECK_INDEX(mode, STAT_RD_CLR_MODE_UNCLR, STAT_RD_CLR_MODE_CLR);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(&dev);
	ZXIC_COMM_CHECK_POINT(p_se_res);
	ZXIC_COMM_CHECK_INDEX_LOWER(p_se_res->stat_cfg.eram_depth, 1);
	ZXIC_COMM_CHECK_INDEX(index, 0, p_se_res->stat_cfg.eram_depth * 2 - 1);
	if (mode == STAT_RD_CLR_MODE_CLR) {
		rc = dpp_stat_ppu_cnt_get(&dev, STAT_64_MODE, index, STAT_RD_CLR_MODE_CLR, buff);
		ZXIC_COMM_CHECK_RC(rc, "dpp_stat_ppu_cnt_get");
	} else {
		rc = dpp_dtb_eram_stat_data_get(&dev, queue, p_se_res->stat_cfg.eram_baddr,
						ERAM128_TBL_64b, index, buff);
		ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_eram_stat_data_get");
	}

	*p_cnt = ((u64)buff[0] << 32) | buff[1];

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x index: %u mode: %u cnt: %llu success.\n", __func__,
		pf_info->slot, pf_info->vport, index, mode, *p_cnt);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_cnt_get);

u32 dpp_stat_cnt_get_128(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_pkB_cnt,
			 u64 *p_pk_cnt)
{
	struct dpp_dev_t dev = { 0 };

	u32 queue = 0;
	u32 buff[4] = { 0 };
	u32 rc = DPP_OK;
	struct dpp_apt_se_res_t *p_se_res = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x index: %u mode: %u start.\n", __func__,
			       pf_info->slot, pf_info->vport, index, mode);

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);
	ZXIC_COMM_CHECK_INDEX(mode, STAT_RD_CLR_MODE_UNCLR, STAT_RD_CLR_MODE_CLR);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_dtb_queue_id_get(&dev, &queue);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_queue_id_get");

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(&dev);
	ZXIC_COMM_CHECK_POINT(p_se_res);
	ZXIC_COMM_CHECK_INDEX_LOWER(p_se_res->stat_cfg.eram_depth, 1);
	ZXIC_COMM_CHECK_INDEX(index, 0, p_se_res->stat_cfg.eram_depth - 1);

	if (mode == STAT_RD_CLR_MODE_CLR) {
		rc = dpp_stat_ppu_cnt_get(&dev, STAT_128_MODE, index, STAT_RD_CLR_MODE_CLR, buff);
		ZXIC_COMM_CHECK_RC(rc, "dpp_stat_ppu_cnt_get");
	} else {
		rc = dpp_dtb_eram_stat_data_get(&dev, queue, p_se_res->stat_cfg.eram_baddr,
						ERAM128_TBL_128b, index, buff);
		ZXIC_COMM_CHECK_RC(rc, "dpp_dtb_eram_stat_data_get");
	}

	*p_pk_cnt = ((u64)buff[0] << 32) | buff[1];
	*p_pkB_cnt = ((u64)buff[2] << 32) | buff[3];

	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x index: %u mode: %u h64_cnt: %llu success.\n", __func__,
		pf_info->slot, pf_info->vport, index, mode, *p_pk_cnt);
	ZXIC_COMM_TRACE_NOTICE(
		"[%s] slot: %u vport: 0x%04x index: %u mode: %u l64_cnt: %llu success.\n", __func__,
		pf_info->slot, pf_info->vport, index, mode, *p_pkB_cnt);

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_cnt_get_128);

u32 dpp_stat_item_cnt_get(struct dpp_pf_info_t *pf_info, u32 stat_item_no, u32 index, u32 rd_mode,
			  union dpp_stat_value_u *p_stat_value)
{
	DPP_STATUS rc = DPP_OK;
	u32 exist_flag = 0;
	struct dpp_dev_t dev = { 0 };
	struct dpp_stat_item_t *p_stat_item = NULL;
	struct dpp_apt_se_res_t *p_se_res = NULL;

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_CHECK_POINT(p_stat_value);
	ZXIC_COMM_CHECK_INDEX(rd_mode, STAT_RD_CLR_MODE_UNCLR, STAT_RD_CLR_MODE_CLR);
	ZXIC_COMM_CHECK_INDEX_UPPER(stat_item_no, STAT_ITEM_MAX_NUM - 1);

	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	p_se_res = (struct dpp_apt_se_res_t *)dpp_dev_get_se_res_ptr(&dev);
	ZXIC_COMM_CHECK_POINT(p_se_res);

	rc = dpp_apt_sdt_is_exist(p_se_res, DPP_SDT_TBLT_eRAM, ZXDH_SDT_STAT_ATTR_TABLE,
				  &exist_flag);
	ZXIC_COMM_CHECK_RC(rc, "dpp_apt_sdt_is_exist");
	if (exist_flag == 0) {
		ZXIC_COMM_TRACE_INFO("The firmware not support stat item table!\n");
		return DPP_RC_TABLE_SDT_NOT_EXIST;
	}

	p_stat_item = &p_se_res->stat_item[stat_item_no];
	ZXIC_COMM_CHECK_INDEX_LOWER(p_stat_item->depth, 1);
	ZXIC_COMM_CHECK_INDEX(index, 0, p_stat_item->depth - 1);

	ZXIC_COMM_MEMSET_S(p_stat_value, sizeof(union dpp_stat_value_u), 0x0,
			   sizeof(union dpp_stat_value_u));
	if (p_stat_item->mode == STAT_64_MODE) {
		rc = dpp_stat_cnt_get(pf_info, index + p_stat_item->addr_offset, rd_mode,
				      &p_stat_value->stat_cnt_64);
		ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");
	} else {
		rc = dpp_stat_cnt_get_128(pf_info, index + p_stat_item->addr_offset, rd_mode,
					  &p_stat_value->stat_cnt_128.bytes,
					  &p_stat_value->stat_cnt_128.pkts);
		ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");
	}

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_item_cnt_get);

u32 dpp_stat_mc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_RX_PF_MULTICAST_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_MC_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_MC_PACKET_RX_CNT_ERAM_BAADDR, mode, p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_mc_packet_rx_cnt_get);

u32 dpp_stat_bc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_RX_VF_BROADCAST_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_BC_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_BC_PACKET_RX_CNT_ERAM_BAADDR, mode, p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_bc_packet_rx_cnt_get);

u32 dpp_stat_1588_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_RX_1588_PKTS, index, mode, &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_1588_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_1588_PACKET_RX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_1588_packet_rx_cnt_get);

u32 dpp_stat_1588_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_TX_1588_PKTS, index, mode, &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_1588_PACKET_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_1588_PACKET_TX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_1588_packet_tx_cnt_get);

u32 dpp_stat_1588_packet_drop_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				      u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_1588_DROP_PKTS, index, mode, &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_1588_PACKET_DROP_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_1588_PACKET_DROP_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_1588_packet_drop_cnt_get);

u32 dpp_stat_1588_enc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_1588_DRS_NP_ENCRYPT_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_1588_ENC_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_1588_ENC_PACKET_RX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_1588_enc_packet_rx_cnt_get);

u32 dpp_stat_1588_enc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_1588_NP_DRS_ENCRYPT_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_1588_ENC_PACKET_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_1588_ENC_PACKET_TX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_1588_enc_packet_tx_cnt_get);

u32 dpp_stat_spoof_packet_drop_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_SPOOF_DROP_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_SPOOF_PACKET_DROP_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_SPOOF_PACKET_DROP_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_spoof_packet_drop_cnt_get);

u32 dpp_stat_mcode_packet_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_MCODE_PPU_PKTS, index, mode, &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_MCODE_PACKET_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_MCODE_PACKET_CNT_ERAM_BAADDR, mode, p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_mcode_packet_cnt_get);

u32 dpp_stat_port_RDMA_packet_msg_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					     u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_RDMA_TX_STAT, index, mode, &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_RDMA_PACKET_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_RDMA_PACKET_TX_CNT_ERAM_BAADDR,
				  mode, p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_RDMA_packet_msg_tx_cnt_get);

u32 dpp_stat_port_RDMA_packet_msg_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					     u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_RDMA_RX_STAT, index, mode, &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_RDMA_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_RDMA_PACKET_RX_CNT_ERAM_BAADDR,
				  mode, p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_RDMA_packet_msg_rx_cnt_get);

u32 dpp_stat_plcr_packet_drop_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					 u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NIC_OUT_RATE_LIMIT_DROP_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PLCR_PACKET_DROP_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PLCR_PACKET_DROP_TX_CNT_ERAM_BAADDR,
				  mode, p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_plcr_packet_drop_tx_cnt_get);

u32 dpp_stat_plcr_packet_drop_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					 u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NIC_IN_RATE_LIMIT_DROP_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PLCR_PACKET_DROP_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PLCR_PACKET_DROP_RX_CNT_ERAM_BAADDR,
				  mode, p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_plcr_packet_drop_rx_cnt_get);

u32 dpp_stat_MTU_packet_msg_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_TX_MTU_DROP_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_MTU_PACKET_DROP_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_MTU_PACKET_DROP_TX_CNT_ERAM_BAADDR,
				  mode, p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_MTU_packet_msg_tx_cnt_get);

u32 dpp_stat_MTU_packet_msg_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_RX_MTU_DROP_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_MTU_PACKET_DROP_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_MTU_PACKET_DROP_RX_CNT_ERAM_BAADDR,
				  mode, p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_MTU_packet_msg_rx_cnt_get);

u32 dpp_stat_port_uc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NP_PORT_UNICAST_RX_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_UC_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_UC_PACKET_RX_CNT_ERAM_BAADDR, mode,
				  p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_uc_packet_rx_cnt_get);

u32 dpp_stat_port_uc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NP_PORT_UNICAST_TX_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_UC_PACKET_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_UC_PACKET_TX_CNT_ERAM_BAADDR, mode,
				  p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_uc_packet_tx_cnt_get);

u32 dpp_stat_port_mc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NP_PORT_MULTICAST_RX_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_MC_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_MC_PACKET_RX_CNT_ERAM_BAADDR, mode,
				  p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_mc_packet_rx_cnt_get);

u32 dpp_stat_port_mc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NP_PORT_MULTICAST_TX_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_MC_PACKET_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_MC_PACKET_TX_CNT_ERAM_BAADDR, mode,
				  p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_mc_packet_tx_cnt_get);

u32 dpp_stat_port_bc_packet_rx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NP_PORT_BROADCAST_RX_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_BC_PACKET_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_BC_PACKET_RX_CNT_ERAM_BAADDR, mode,
				  p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_bc_packet_rx_cnt_get);

u32 dpp_stat_port_bc_packet_tx_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
				       u64 *p_pkB_cnt, u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_NP_PORT_BROADCAST_TX_STAT, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PORT_BC_PACKET_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_PORT_BC_PACKET_TX_CNT_ERAM_BAADDR, mode,
				  p_pkB_cnt, p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_port_bc_packet_tx_cnt_get);

u32 dpp_stat_fd_stat_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode, u64 *p_pkB_cnt,
			     u64 *p_pk_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_pkB_cnt);
	ZXIC_COMM_CHECK_POINT(p_pk_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_FD_FLOW_STAT, index, mode, &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_pkB_cnt = stat_value.stat_cnt_128.bytes;
		*p_pk_cnt = stat_value.stat_cnt_128.pkts;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_FD_ACL_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get_128(pf_info, index + DPP_STAT_FD_ACL_CNT_ERAM_BAADDR, mode, p_pkB_cnt,
				  p_pk_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get_128");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_fd_stat_cnt_get);

u32 dpp_stat_asn_phyport_rx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_ASN_PHYPORT_RX_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_ASN_PHYPORT_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_ASN_PHYPORT_RX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_asn_phyport_rx_pkt_cnt_get);

u32 dpp_stat_psn_phyport_tx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_PSN_PHYPORT_TX_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PSN_PHYPORT_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_PSN_PHYPORT_TX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_psn_phyport_tx_pkt_cnt_get);

u32 dpp_stat_psn_phyport_rx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_PSN_PHYPORT_RX_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PSN_PHYPORT_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_PSN_PHYPORT_RX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_psn_phyport_rx_pkt_cnt_get);

u32 dpp_stat_psn_ack_phyport_tx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					    u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_PSN_ACK_PHYPORT_TX_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PSN_ACK_PHYPORT_TX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_PSN_ACK_PHYPORT_TX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_psn_ack_phyport_tx_pkt_cnt_get);

u32 dpp_stat_psn_ack_phyport_rx_pkt_cnt_get(struct dpp_pf_info_t *pf_info, u32 index, u32 mode,
					    u64 *p_cnt)
{
	u32 rc = DPP_OK;
	union dpp_stat_value_u stat_value = { 0 };

	ZXIC_COMM_CHECK_POINT(p_cnt);

	rc = dpp_stat_item_cnt_get(pf_info, DPP_STAT_ITEM_PSN_ACK_PHYPORT_RX_PKTS, index, mode,
				   &stat_value);
	if (rc != DPP_RC_TABLE_SDT_NOT_EXIST) {
		*p_cnt = stat_value.stat_cnt_64;
		ZXIC_COMM_TRACE_INFO("dpp_stat_item_cnt_get,rc=0x%x\n", rc);
		return rc;
	}

	ZXIC_COMM_CHECK_INDEX(index, 0, DPP_STAT_PSN_ACK_PHYPORT_RX_CNT_ERAM_DEPTH - 1);

	rc = dpp_stat_cnt_get(pf_info, index + DPP_STAT_PSN_ACK_PHYPORT_RX_CNT_ERAM_BAADDR, mode,
			      p_cnt);
	ZXIC_COMM_CHECK_RC(rc, "dpp_stat_cnt_get");

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_stat_psn_ack_phyport_rx_pkt_cnt_get);
