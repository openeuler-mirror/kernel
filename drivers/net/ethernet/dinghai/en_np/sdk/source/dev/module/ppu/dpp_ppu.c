// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_reg.h"
#include "dpp_dev.h"
#include "dpp_ppu_api.h"
#include "dpp_ppu.h"
#include "dpp_ppu4k_reg.h"
#include "dpp_agent_channel.h"

#define OPR_WRITE (0)
#define OPR_READ (1)

struct dpp_ppu_cls_bitmap_t g_ppu_cls_bit_map[DPP_DEV_CHANNEL_MAX];

#if ZXIC_REAL("INIT")

u32 dpp_ppu_cls_use_set(u32 dev_id, u32 cluster_id, u32 flag)
{
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, cluster_id, 0, DPP_PPU_CLUSTER_NUM - 1);
	g_ppu_cls_bit_map[dev_id].cls_use[cluster_id] = flag;

	return DPP_OK;
}

u32 dpp_ppu_cls_use_get(u32 dev_id, u32 cluster_id)
{
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, cluster_id, 0, DPP_PPU_CLUSTER_NUM - 1);

	return g_ppu_cls_bit_map[dev_id].cls_use[cluster_id];
}

u32 dpp_ppu_instr_mem_set(u32 dev_id, u32 mem_id, u32 flag)
{
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, mem_id, 0, PPU_INSTR_MEM_NUM - 1);
	g_ppu_cls_bit_map[dev_id].instr_mem[mem_id] = flag;

	return DPP_OK;
}

u32 dpp_ppu_parse_cls_bitmap(u32 dev_id, u32 bitmap)
{
	u32 cls_id = 0;
	u32 mem_id = 0;

	u32 cls_use = 0;
	u32 instr_mem = 0;

	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, bitmap, 0, DPP_PPU_CLS_ALL_START);

	for (cls_id = 0; cls_id < DPP_PPU_CLUSTER_NUM; cls_id++) {
		cls_use = (bitmap >> cls_id) & 0x1;

		dpp_ppu_cls_use_set(dev_id, cls_id, cls_use);
	}

	for (mem_id = 0; mem_id < PPU_INSTR_MEM_NUM; mem_id++) {
		instr_mem = (bitmap >> (mem_id * 2)) & 0x3;

		dpp_ppu_instr_mem_set(dev_id, mem_id, ((instr_mem > 0) ? 1 : 0));
	}

	return DPP_OK;
}

#endif

#if ZXIC_REAL("TABEL_CFG")
DPP_STATUS dpp_ppu_sdt_tbl_write(struct dpp_dev_t *dev, u32 cluster_id, u32 index,
				 struct dpp_sdt_tbl_data_t *p_sdt_data)
{
	DPP_STATUS rtn = DPP_OK;
	struct dpp_ppu4k_cluster_wr_high_data_r_mex_t high_data = { 0 };
	struct dpp_ppu4k_cluster_wr_low_data_r_mex_t low_data = { 0 };
	struct dpp_ppu4k_cluster_addr_r_mex_t sdt_cmd = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), index, PPU_SDT_IDX_MIN, PPU_SDT_IDX_MAX);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_sdt_data);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), cluster_id, 0, DPP_PPU_CLUSTER_NUM - 1);
	if (!dpp_ppu_cls_use_get(DEV_ID(dev), cluster_id)) {
		ZXIC_COMM_TRACE_DEV_ERROR(DEV_ID(dev),
					  "\n %s:%d[Error:cluster %d stop] ! FUNCTION : %s!\n",
					  __FILE__, __LINE__, cluster_id, __func__);
		ZXIC_COMM_ASSERT(0);
		return DPP_ERR;
	}

	/* write data reg*/
	high_data.wr_high_data_r_mex = p_sdt_data->data_high32;
	low_data.wr_low_data_r_mex = p_sdt_data->data_low32;
	rtn = dpp_reg_write(dev, PPU4K_CLUSTER_WR_HIGH_DATA_R_MEXr, cluster_id, 0, &high_data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	rtn = dpp_reg_write(dev, PPU4K_CLUSTER_WR_LOW_DATA_R_MEXr, cluster_id, 0, &low_data);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	/* write cmd reg*/
	sdt_cmd.operate_type = OPR_WRITE;
	sdt_cmd.addr_r_mex = index;

	rtn = dpp_reg_write(dev, PPU4K_CLUSTER_ADDR_R_MEXr, cluster_id, 0, &sdt_cmd);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}
#endif

#if ZXIC_REAL("PPU_STATICS")
DPP_STATUS dpp_ppu_ppu_cop_thash_rsk_set(struct dpp_dev_t *dev,
					 struct dpp_ppu_ppu_cop_thash_rsk_t *p_para)
{
	DPP_STATUS rc = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_para);

	ZXIC_COMM_TRACE_NOTICE("dpp ppu_ppu_cop_thash_rsk_set start\n");

	rc = dpp_agent_channel_ppu_thash_rsk(dev, DPP_PPU_THASH_RSK_WR, p_para);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_agent_channel_ppu_thash_rsk");

	ZXIC_COMM_PRINT("dpp ppu_ppu_cop_thash_rsk_set end\n");

	return DPP_OK;
}

DPP_STATUS
dpp_ppu_ppu_cop_thash_rsk_get(struct dpp_dev_t *dev,
			      struct dpp_ppu_ppu_cop_thash_rsk_t *p_ppu_cop_thash_rsk)
{
	DPP_STATUS rtn = DPP_OK;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_ppu_cop_thash_rsk);

	ZXIC_COMM_TRACE_NOTICE("dpp ppu_ppu_cop_thash_rsk_get start\n");

	rtn = dpp_agent_channel_ppu_thash_rsk(dev, DPP_PPU_THASH_RSK_RD, p_ppu_cop_thash_rsk);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_agent_channel_ppu_thash_rsk");

	ZXIC_COMM_PRINT("dpp ppu_ppu_cop_thash_rsk_get end\n");

	return DPP_OK;
}

#endif
DPP_STATUS dpp_ppu_debug_en_set(struct dpp_dev_t *dev, u32 enable)
{
	DPP_STATUS rtn = DPP_OK;
	struct dpp_ppu_ppu_ppu_debug_en_r_t debug_en = { 0 };

	debug_en.debug_en_r = enable;

	rtn = dpp_reg_write(dev, PPU_PPU_PPU_DEBUG_EN_Rr, 0, 0, &debug_en);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_write");

	return DPP_OK;
}

DPP_STATUS dpp_pktrx_port_en_set(struct dpp_dev_t *dev, u32 port_no, u32 flag)
{
	DPP_STATUS rc = 0;
	u32 port_en_index = 0;
	u32 port_en_mask = 0;
	struct dpp_nppu_pktrx_cfg_port_en_3_t port_en_3_reg = { 0 };

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), port_no, 0, DPP_PHYPORT_NUM - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), flag, 0, 1);

	port_en_mask = 1u << (port_no % 32);
	port_en_index = flag << (port_no % 32);

	rc = dpp_reg_write(dev, NPPU_PKTRX_CFG_CPU_PORT_EN_MASKr, 0, 0, &port_en_mask);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	if (port_no < 96) {
		rc = dpp_reg_write(dev, NPPU_PKTRX_CFG_PORT_EN_0r + port_no / 32, 0, 0,
				   &port_en_index);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");
	} else {
		rc = dpp_reg_read(dev, NPPU_PKTRX_CFG_PORT_EN_3r, 0, 0, &port_en_3_reg);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

		port_en_3_reg.cfg_isch_port_en_3 = port_en_index;

		rc = dpp_reg_write(dev, NPPU_PKTRX_CFG_PORT_EN_3r, 0, 0, &port_en_3_reg);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");
	}

	return DPP_OK;
}
DPP_STATUS dpp_ppu_debug_valid_get(struct dpp_dev_t *dev, u32 *p_valid)
{
	DPP_STATUS rtn = DPP_OK;
	struct dpp_ppu_ppu_ppu_debug_vld_t debug_vld = { 0 };

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_valid);

	rtn = dpp_reg_read(dev, PPU_PPU_PPU_DEBUG_VLDr, 0, 0, &debug_vld);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rtn, "dpp_reg_read");

	*p_valid = debug_vld.ppu_debug_vld;

	return DPP_OK;
}

DPP_STATUS dpp_ppu_set_debug_mode(struct dpp_pf_info_t *pf_info, u32 *dbg_status)
{
	DPP_STATUS rc = DPP_OK;
	u32 pkt_empty = 0;
	u32 rd_count = 0;
	struct dpp_dev_t dev = { 0 };

	ZXIC_COMM_CHECK_POINT(pf_info);
	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x register start.\n", __func__,
			       pf_info->slot, pf_info->vport);
	rc = dpp_dev_get(pf_info, &dev);
	ZXIC_COMM_CHECK_RC(rc, "dpp_dev_get");

	rc = dpp_ppu_debug_en_set(&dev, 1);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "dpp_ppu_debug_en_set");

	rc = dpp_ppu_debug_valid_get(&dev, &pkt_empty);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "dpp_ppu_debug_valid_get");

	while (!pkt_empty) {
		rc = dpp_ppu_debug_valid_get(&dev, &pkt_empty);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "dpp_ppu_debug_valid_get");

		if (pkt_empty)
			break;

		if (rd_count > DPP_RD_CNT_MAX) {
			ZXIC_COMM_PRINT("debug start is fail!!!\n");
			*dbg_status = 0;
			rc = dpp_ppu_debug_en_set(&dev, 0);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(&dev), rc, "dpp_ppu_debug_en_set");
			return DPP_OK;
		}

		rd_count++;
		usleep_range(5, 10);
	}

	*dbg_status = 1;

	return DPP_OK;
}
EXPORT_SYMBOL(dpp_ppu_set_debug_mode);

DPP_STATUS dpp_ppu_close_debug_mode(struct dpp_pf_info_t *pf_info)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_dev_t dev = { 0 };

	rc = dpp_dev_get(pf_info, &dev);

	ZXIC_COMM_TRACE_NOTICE("[%s] slot: %u vport: 0x%04x debug mode disable\n", __func__,
			       pf_info->slot, pf_info->vport);
	dpp_ppu_debug_en_set(&dev, 0);
	return DPP_OK;
}
EXPORT_SYMBOL(dpp_ppu_close_debug_mode);
