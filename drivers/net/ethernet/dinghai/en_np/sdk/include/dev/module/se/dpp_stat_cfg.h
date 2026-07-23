/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_STAT_CFG_H_
#define _DPP_STAT_CFG_H_

#include "dpp_stat_api.h"

#if ZXIC_REAL("Variable definition")

#define DPP_STAT_TM_PORT_MAX (4)
#define DPP_STAT_ETM_ADDR_MAX (9 * 1024)
#define DPP_STAT_FTM_ADDR_MAX (2048)
#define DPP_STAT_IND_WR_MODE (0)
#define DPP_STAT_IND_RD_MODE (1)
#define DPP_STAT_TM_MOV_PERIOD_MAX (0xff)

#define DPP_STAT_WIDTH_3_MAX_VALUE ((1 << 3) - 1)
#define DPP_STAT_WIDTH_4_MAX_VALUE ((1 << 4) - 1)
#define DPP_STAT_PPU_ERAM_DEPTH_MAX (0x7ffff)
#define DPP_STAT_PPU_ERAM_BADDR_MAX (0x7ffff)
#define DPP_STAT_PPU_DDR_BADDR_MAX (0x4ffffff)

#define DPP_STAT_OAM_ERAM_BADDR_MAX (0x7ffff)
#define DPP_STAT_OAM_DDR_BADDR_MAX (0x4ffffff)

#define DPP_STAT_PLCR_ERAM_BADDR_MAX (0x7ffff)
#define DPP_STAT_PLCR_ID (0)

#define DPP_STAT_TM_FLAG_FTM_PKT_EN (0)
#define DPP_STAT_TM_FLAG_ETM_PKT_EN (1)
#define DPP_STAT_TM_FLAG_ERAM_EN (2)

#define DPP_STAT_PPU_STAT_CHANNEL_NUM (16)
#define DPP_STAT_PPU_MEX_NUM (6)
#define CMMU_DDR_DIR_CPY_NUM (15)

enum dpp_stat_tm_type_e {
	DPP_STAT_TM_TYPE_ETM = 0,
	DPP_STAT_TM_TYPE_FTM = 1,
	DPP_STAT_TM_TYPE_MAX
};

enum dpp_stat_tm_store_mode_e {
	DPP_STAT_TM_STORE_MODE_ERAM = 0,
	DPP_STAT_TM_STORE_MODE_MIX = 1,
	DPP_STAT_TM_STORE_MODE_MAX,
};

enum dpp_stat_etm_depth_mode_e {
	DPP_STAT_ETM_DEPTH_ERAM_1K = 0,
	DPP_STAT_ETM_DEPTH_ERAM_4K = 1,
	DPP_STAT_ETM_DEPTH_ERAM_5K = 2,
	DPP_STAT_ETM_DEPTH_ERAM_8K = 3,
	DPP_STAT_ETM_DEPTH_ERAM_9K = 4,
	DPP_STAT_ETM_DEPTH_MIX_2K = 5,
	DPP_STAT_ETM_DEPTH_MIX_8K = 6,
	DPP_STAT_ETM_DEPTH_MIX_9K = 7,
	DPP_STAT_ETM_DEPTH_MAX,
};

enum stat_store_mode_e {
	STAT_STORE_MODE_IN_ERAM = 0,
	STAT_STORE_MODE_IN_DDR = 1,
	STAT_STORE_MODE_MAX,
};

enum stat_oam_type_e {
	STAT_OAM_TYPE_ERAM = 0,
	STAT_OAM_TYPE_LM_ERAM = 1,
	STAT_OAM_TYPE_DDR = 2,
	STAT_OAM_TYPE_MAX,
};

struct dpp_stat_dbg_cnt_t {
	u32 stat_to_smmu0_rsp_fc_cnt[DPP_STAT_PPU_STAT_CHANNEL_NUM];
	u32 stat_rcv_smmu0_req_fc_cnt[DPP_STAT_PPU_STAT_CHANNEL_NUM];
	u32 stat_to_ppu_req_fc_cnt[DPP_STAT_PPU_MEX_NUM];
	u32 stat_rcv_ppu_rsp_fc_cnt[DPP_STAT_PPU_MEX_NUM];
	u32 stat_rcv_se_etm_wr_fc_cnt;
	u32 stat_rcv_se_etm_rd_fc_cnt;
	u32 stat_rcv_se_ftm_wr_fc_cnt;
	u32 stat_rcv_se_ftm_rd_fc_cnt;
	u32 stat_to_etm_deq_fc_cnt;
	u32 stat_to_etm_enq_fc_cnt;
	u32 stat_to_ftm_deq_fc_cnt;
	u32 stat_to_ftm_enq_fc_cnt;
	u32 stat_to_oam_lm_fc_cnt;
	u32 stat_rcv_oam_lm_fc_cnt;
	u32 stat_to_oam_fc_cnt;
	u32 stat_rcv_cmmu_fc_cnt;
	u32 stat_to_cmmu_req_cnt;
	u32 stat_rcv_smmu0_rsp_cnt[DPP_STAT_PPU_STAT_CHANNEL_NUM];
	u32 stat_to_smmu0_req_cnt[DPP_STAT_PPU_STAT_CHANNEL_NUM];
	u32 stat_plcr_rcv_smmu0_rsp1_cnt;
	u32 stat_plcr_rcv_smmu0_rsp0_cnt;
	u32 stat_plcr_to_smmu0_req1_cnt;
	u32 stat_plcr_to_smmu0_req0_cnt;
	u32 stat_to_ppu_mex_rsp_cnt[DPP_STAT_PPU_MEX_NUM];
	u32 stat_oam_lm_rsp_cnt;
	u32 stat_rcv_oam_lm_req_cnt;
	u32 stat_rcv_oam_req_cnt;
	u32 stat_rcv_ppu_mex_key_cnt[DPP_STAT_PPU_MEX_NUM];
	u32 stat_rcv_se_etm_rsp_cnt;
	u32 stat_rcv_etm_se_wr_req_cnt;
	u32 stat_rcv_etm_se_rd_req_cnt;
	u32 stat_rcv_se_ftm_rsp_cnt;
	u32 stat_to_ftm_se_wr_req_cnt;
	u32 stat_to_ftm_se_rd_req_cnt;
	u32 stat_rcv_ftm_smmu0_req_cnt0;
	u32 stat_rcv_ftm_smmu0_req_cnt1;
	u32 stat_rcv_etm_smmu0_req_cnt0;
	u32 stat_rcv_etm_smmu0_req_cnt1;
	u32 ppu_no_exist_opcd_ex_cnt[DPP_STAT_PPU_MEX_NUM];
	u32 stat_rcv_tm_eram_cpu_rsp_cnt;
	u32 cpu_rd_eram_req_cnt;
	u32 cpu_wr_eram_req_cnt;
	u32 tm_stat_ddr_cpu_rsp_cnt;
	u32 cpu_rd_ddr_req_cnt;
	u32 cpu_wr_ddr_req_cnt;
};

#endif
DPP_STATUS dpp_stat_ppu_eram_depth_get(struct dpp_dev_t *dev, u32 *p_ppu_eram_depth);
DPP_STATUS dpp_stat_ppu_eram_baddr_get(struct dpp_dev_t *dev, u32 *p_ppu_eram_baddr);
DPP_STATUS dpp_stat_ppu_ddr_baddr_get(struct dpp_dev_t *dev, u32 *p_ppu_ddr_baddr);

#endif
