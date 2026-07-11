// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/**************************************************************
 * ��Ȩ���� (C)2013-2015, ����������ͨѶ�ɷ����޹�˾
 * �ļ����� : dpp_stat_cfg.c
 * �ļ���ʶ :
 * ����ժҪ :
 * ����˵�� :

 * ��    �� : ls
 * ������� : 2016/03/29
 * DEPARTMENT: ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT: 100%

 * �޸ļ�¼1:
 * �޸�����:
 * �� �� ��:
 * �� �� ��:
 * �޸�����:
 ***************************************************************
 */
#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_dev.h"
#include "dpp_stat_reg.h"
#include "dpp_stat_cfg.h"
#include "dpp_stat_api.h"
#include "dpp_se_api.h"
#include "dpp_se.h"
#include "dpp_reg_api.h"
#include "dpp_reg_info.h"

struct ppu_stat_cfg_t g_ppu_stat_cfg = { 0 };

#if ZXIC_REAL("Basic Reg Operation")
DPP_STATUS dpp_stat_ppu_eram_depth_get(struct dpp_dev_t *dev, u32 *p_ppu_eram_depth)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_stat_cfg_ppu_eram_depth_t ppu_eram_depth_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_ppu_eram_depth);

	rc = dpp_reg_read(dev, STAT_STAT_CFG_PPU_ERAM_DEPTHr, 0, 0, &ppu_eram_depth_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_ppu_eram_depth = ppu_eram_depth_cfg.ppu_eram_depth;

	return rc;
}
DPP_STATUS dpp_stat_ppu_eram_baddr_get(struct dpp_dev_t *dev, u32 *p_ppu_eram_baddr)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_stat_cfg_ppu_eram_base_addr_t ppu_eram_baddr_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_ppu_eram_baddr);

	rc = dpp_reg_read(dev, STAT_STAT_CFG_PPU_ERAM_BASE_ADDRr, 0, 0, &ppu_eram_baddr_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_ppu_eram_baddr = ppu_eram_baddr_cfg.ppu_eram_base_addr;

	return rc;
}
DPP_STATUS dpp_stat_ppu_ddr_baddr_get(struct dpp_dev_t *dev, u32 *p_ppu_ddr_baddr)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_stat_cfg_ppu_ddr_base_addr_t ppu_ddr_baddr_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_ppu_ddr_baddr);

	rc = dpp_reg_read(dev, STAT_STAT_CFG_PPU_DDR_BASE_ADDRr, 0, 0, &ppu_ddr_baddr_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_ppu_ddr_baddr = ppu_ddr_baddr_cfg.ppu_ddr_base_addr;

	return rc;
}
#endif

#if ZXIC_REAL("Advanced Function")
DPP_STATUS dpp_stat_ppu_cnt_get(struct dpp_dev_t *dev, enum stat_cnt_mode_e rd_mode, u32 index,
				u32 clr_mode, u32 *p_data)
{
	DPP_STATUS rc = DPP_OK;
	u32 ppu_eram_baddr = 0;
	u32 ppu_eram_depth = 0;
	u32 ppu_ddr_baddr = 0;
	u32 eram_rd_mode = 0;
	u32 eram_clr_mode = 0;
	// u32 ddr_rd_mode    = 0;
	// u32 ddr_clr_mode   = 0;
	// u32 ddr_index      = 0;

	ZXIC_COMM_CHECK_POINT(dev);

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), rd_mode, STAT_64_MODE, STAT_MAX_MODE - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), clr_mode, STAT_RD_CLR_MODE_UNCLR,
				  STAT_RD_CLR_MODE_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_data);

	rc = dpp_stat_ppu_eram_depth_get(dev, &ppu_eram_depth);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_ppu_eram_depth_get");

	rc = dpp_stat_ppu_eram_baddr_get(dev, &ppu_eram_baddr);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_ppu_eram_baddr_get");

	rc = dpp_stat_ppu_ddr_baddr_get(dev, &ppu_ddr_baddr);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stat_ppu_ddr_baddr_get");

	if ((index >> (STAT_128_MODE - rd_mode)) < ppu_eram_depth) {
		if (rd_mode == STAT_128_MODE)
			eram_rd_mode = ERAM128_OPR_128b;
		else
			eram_rd_mode = ERAM128_OPR_64b;

		if (clr_mode == STAT_RD_CLR_MODE_UNCLR)
			eram_clr_mode = RD_MODE_HOLD;
		else
			eram_clr_mode = RD_MODE_CLEAR;

		rc = dpp_se_smmu0_ind_read(dev, ppu_eram_baddr, index, eram_rd_mode, eram_clr_mode,
					   p_data);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_se_smmu0_ind_read");
	}

	return rc;
}
DPP_STATUS dpp_stat_ppu_eram_depth_set(struct dpp_dev_t *dev, u32 ppu_eram_depth)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_stat_cfg_ppu_eram_depth_t ppu_eram_depth_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), ppu_eram_depth, 0, DPP_STAT_PPU_ERAM_DEPTH_MAX);

	ppu_eram_depth_cfg.ppu_eram_depth = ppu_eram_depth;

	rc = dpp_reg_write(dev, STAT_STAT_CFG_PPU_ERAM_DEPTHr, 0, 0, &ppu_eram_depth_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	g_ppu_stat_cfg.eram_depth = ppu_eram_depth;

	return rc;
}
DPP_STATUS dpp_stat_ppu_eram_baddr_set(struct dpp_dev_t *dev, u32 ppu_eram_baddr)
{
	DPP_STATUS rc = DPP_OK;
	struct dpp_stat_stat_cfg_ppu_eram_base_addr_t ppu_eram_baddr_cfg = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), ppu_eram_baddr, 0, DPP_STAT_PPU_ERAM_BADDR_MAX);

	ppu_eram_baddr_cfg.ppu_eram_base_addr = ppu_eram_baddr;

	rc = dpp_reg_write(dev, STAT_STAT_CFG_PPU_ERAM_BASE_ADDRr, 0, 0, &ppu_eram_baddr_cfg);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	g_ppu_stat_cfg.eram_baddr = ppu_eram_baddr;

	return rc;
}

#endif
