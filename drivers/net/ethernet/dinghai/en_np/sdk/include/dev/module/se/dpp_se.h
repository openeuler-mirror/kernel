/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/**************************************************************
 * DEPARTMENT: ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT: 100%
 * �? �? �?:
 * �? �? �?:
 ***************************************************************
 */

#ifndef _DPP_SE_H_
#define _DPP_SE_H_
#include "dpp_se_api.h"

#define DPP_HASH_ID_MIN (0)
#define DPP_HASH_ID_MAX (3)
#define DPP_HASH_ID_NUM (4)

#define HASH_BULK_ID_MIN (0)
#define HASH_BULK_ID_MAX (7)
#define HASH_BULK_NUM (8)

#define CRC_POLY_SEL_MIN (0)
#define CRC_POLY_SEL_MAX (3)

#define DPP_LPM_ID_MIN (4)
#define DPP_LPM_ID_MAX (5)
#define DPP_LPM_ID_NUM (2)

#define DPP_ETCAM_ID_MIN (0)
#define DPP_ETCAM_ID_MAX (0)
#define DPP_ETCAM_ID_NUM (1)

#define DPP_AGE_TBL_ID_MIN (0)
#define DPP_AGE_TBL_ID_MAX (15)

#define DPP_SMMU1_DDR_GRP_NUM (1)

//#define DPP_SMMU1_DIR_TBL_BANK_MAX          (15)
#define DPP_SMMU1_DIR_TBL_INDEX_MAX (255)
//#define DPP_SMMU1_UN_DIR_TBL_BANK_MAX       (29)

#define DPP_SMMU1_HASH_TBL_INDEX_BASE (1)
#define DPP_SMMU1_HASH_TBL_INDEX_MAX (31)
#define DPP_SMMU1_LPM_TBL_INDEX_BASE (33)
#define DPP_SMMU1_LPM_TBL_INDEX_MAX (3)
#define DPP_SMMU1_OAM_TBL_INDEX_BASE (37)
#define DPP_SMMU1_FTM_TBL_INDEX_BASE (38)
#define DPP_SMMU1_ETM_TBL_INDEX_BASE (39)
#define DPP_SMMU1_DIR_TBL_INDEX_BASE (40)

#define DPP_SMMU1_SINGLE_BNAK_MAX_ADDR ((1 << 25) - 1)
#define DPP_SMMU1_SINGLE_BANK_MAX_BADDR (DPP_SMMU1_SINGLE_BNAK_MAX_ADDR >> 12)
#define DPP_SMMU1_TOTAL_BANK_NUM (8)
#define DPP_SMMU1_TOTAL_MAX_ADDR (0xffffffff)
#define DPP_SMMU1_TOTAL_MAX_BADDR (DPP_SMMU1_TOTAL_MAX_ADDR >> 12)
#define DPP_SMMU1_BADDR_MASK (0x7ffff800)
#define DPP_SMMU1_DDR_GROUP_NUM (1)
#define DPP_SMMU1_BANK_COPY_MAX_NUM (16)
#define DPP_SMMU1_READ_REG_MAX_NUM (16)
#define DPP_DIR_TBL_BUF_MAX_NUM (DPP_SMMU1_READ_REG_MAX_NUM)

/*hash ext crc cfg*/
#define HASH_ECC_EN_BT_START (2)
#define HASH_ECC_EN_BT_WIDTH (1)
#define HASH_BANK_COPY_BT_START (3)
#define HASH_BANK_COPY_BT_WIDTH (3)
#define HASH_BASE_ADDR_BT_START (6)
#define HASH_BASE_ADDR_BT_WIDTH (15)
/*hash learn  tbl cfg*/
#define LEARN_HASH_TBL_BT_START (0)
#define LEARN_HASH_TBL_BT_WIDTH (19)

#define DPP_SMMU0_MCAST_TBL_MAX_GROUP (0xffff)

#define DPP_SMMU0_CAR0_MONO_POS (0)
#define DPP_SMMU0_CAR0_MONO_LEN (1)
#define DPP_SMMU0_CAR0_EN_POS (1)
#define DPP_SMMU0_CAR0_EN_LEN (1)
#define DPP_SMMU0_CAR1_MONO_POS (2)
#define DPP_SMMU0_CAR1_MONO_LEN (1)
#define DPP_SMMU0_CAR1_EN_POS (3)
#define DPP_SMMU0_CAR1_EN_LEN (1)

#define DPP_SMMU0_LPM_AS_TBL_ID_MAX (7)
#define DPP_SMMU0_LPM_AS_TBL_ID_NUM (8)

#define DPP_SMMU0_MCAST_DATA_VLD_POS (16)
#define DPP_SMMU0_MCAST_DATA_VLD_LEN (1)
#define DPP_SMMU0_MCAST_CNT_POS (0)
#define DPP_SMMU0_MCAST_CNT_LEN (16)

#define DPP_SMMU0_INDIER_RDWR_OFFSET_NUM (4)
#define DPP_SMMU0_READ_REG_MAX_NUM (4)

#define DPP_SMMU0_PPU_FIFO_POS (12)
#define DPP_SMMU0_PPU_FIFO_LEN (8)
#define DPP_SMMU0_STAT_FIFO_POS (11)
#define DPP_SMMU0_STAT_FIFO_LEN (1)
#define DPP_SMMU0_DMA_FIFO_POS (10)
#define DPP_SMMU0_DMA_FIFO_LEN (1)
#define DPP_SMMU0_ODMA_FIFO_POS (6)
#define DPP_SMMU0_ODMA_FIFO_LEN (4)
#define DPP_SMMU0_MCAST_FIFO_POS (5)
#define DPP_SMMU0_MCAST_FIFO_LEN (1)
#define DPP_SMMU0_ETCAM_FIFO_POS (1)
#define DPP_SMMU0_ETCAM_FIFO_LEN (4)
#define DPP_SMMU0_LPM_FIFO_POS (0)
#define DPP_SMMU0_LPM_FIFO_LEN (1)

#define DPP_SMMU0_CTRL_ECC_CFG_POS (0)
#define DPP_SMMU0_CTRL_ECC_CFG_LEN (3)

#define DPP_SMMU0_RSCHD_RAM_POS (0)
#define DPP_SMMU0_RSCHD_RAM_LEN (1)

#define DPP_SMMU0_ERAM_ECC_CFG_POS (0)
#define DPP_SMMU0_ERAM_ECC_CFG_LEN (24)

#define DPP_SMMU0_WR_ARB_ECC_CFG_POS (0)
#define DPP_SMMU0_WR_ARB_ECC_CFG_LEN (1)

/* smmu0 int0 reg bit define */
#define SMMU0_INT0_DMA_ORDFIFO_START (0)
#define SMMU0_INT0_DMA_ORDFIFO_LEN (1)
#define SMMU0_INT0_ODMA_ORDFIFO_START (1)
#define SMMU0_INT0_ODMA_ORDFIFO_LEN (1)
#define SMMU0_INT0_MCAST_ORDFIFO_START (2)
#define SMMU0_INT0_MCAST_ORDFIFO_LEN (1)

#define DPP_ERAM128_BADDR_MASK (0x3FFFF80) /* modified for dpp+ 25bit 2018-09-27*/

#define DPP_SE_SMMU1_MAX_BADDR_NO_SHARE ((1 << 20) - 1)
#define DPP_SE_SMMU1_MAX_BADDR_SHARE ((1 << 13) - 1)
#define DPP_SE_SMMU1_MAX_ADDR ((1 << 30) - 1)

#define DPP_SE_SMMU1_BANK_NUM_POS (16)
#define DPP_SE_SMMU1_BANK_NUM_LEN (5)

#define DPP_SE_SMMU1_SHARE_TYPE_POS (21)
#define DPP_SE_SMMU1_SHARE_TYPE_LEN (2)

#define DPP_SE_SMMU1_RR_STATE_POS (0)
#define DPP_SE_SMMU1_RR_STATE_LEN (15)

#define DPP_SE_CFG_PPU_INFO_POS (0)
#define DPP_SE_CFG_PPU_INFO_LEN (12)

#define DPP_SE_CFG_DPI_FLAG_POS (12)
#define DPP_SE_CFG_DPI_FLAG_LEN (1)

#define DPP_SE_CFG_WR_FLAG_POS (13)
#define DPP_SE_CFG_WR_FLAG_LEN (1)

#define DPP_SE_ALG_SCHD_INT_NUM (14)
#define DPP_SE_ALG_ZBLK_ECC_INT_NUM (32)
#define DPP_SE_ALG_HASH0_INT_NUM (8)
#define DPP_SE_ALG_HASH1_INT_NUM (8)
#define DPP_SE_ALG_HASH2_INT_NUM (8)
#define DPP_SE_ALG_HASH3_INT_NUM (8)
#define DPP_SE_ALG_LPM_INT_NUM (10)

#define DPP_SMMU0_CLS_NUM (6)
#define DPP_SMMU0_STAT_NUM (10)
#define DPP_SMMU0_AS_ETCAM_NUM (DPP_ETCAM_ID_NUM)
#define DPP_SMMU0_PLCR_NUM (1)
#define DPP_SMMU0_ERAM_BLOCK_NUM (32)

#define DPP_SMMU1_SCH_CNT (4)
//#define DPP_SMMU1_GRP_CNT                   (DPP_SMMU1_DDR_GRP_NUM)
#define DPP_SMMU1_GRP_CNT (8)
#define DPP_SMMU1_DIR_CHANNEL_CNT (4)

#define DPP_PARSE_MEX_CHANNEL_NUM (6)
#define DPP_PARSE_KSCHD_CHANNEL_NUM (6)
#define DPP_RSCHD_PPU_CHANNEL_NUM (6)

enum smmu1_stat_type_e {
	STAT_TYPE_PPU = 0,
	STAT_TYPE_OAM = 1,
	STAT_TYPE_MAX,
};

enum alg_lpm_type_e {
	ALG_LPM_V4 = 1,
	ALG_LPM_V6 = 2,
	ALG_LPM_V4_AS = 3,
	ALG_LPM_V6_AS = 4,
	ALG_LPM_MAX
};

enum se_ddr_bank_info_e {
	SE_DDR_BKINFO_LPM4 = 0,
	SE_DDR_BKINFO_LPM6 = 1,
	SE_DDR_BKINFO_LPM4_AS = 2,
	SE_DDR_BKINFO_LPM6_AS = 3,
};

enum alg_zblk_serv_type_e {
	ALG_ZBLK_SERV_LPM = 0,
	ALG_ZBLK_SERV_HASH,
};

enum cmmu_ddr3_bank_enable_e {
	CMMU_DDR3_BANK_DISABLE = 0,
	CMMU_DDR3_BANK_ENABLE,
};

enum stat_tm_rd_ddr_mode_e {
	STAT_TM_RD_DDR_MODE_128 = 0,
	STAT_TM_RD_DDR_MODE_256 = 1,
	STAT_TM_RD_DDR_MODE_512 = 2,
	STAT_TM_RD_DDR_MODE_MAX,
};

enum stat_tm_rd_clr_mode_e {
	STAT_TM_RD_CLR_MODE_UNCLR = 0,
	STAT_TM_RD_CLR_MODE_CLR = 1,
	STAT_TM_RD_CLR_MODE_MAX,
};

enum se_ddr_map_flag_e {
	VIR_TO_PHY_FLAG = 0,
	PHY_TO_VIR_FLAG = 1,
};

enum module_init_se_e {
	MODULE_INIT_SE_SMMU0 = 0,
	MODULE_INIT_SE_SMMU1,
	MODULE_INIT_SE_ALG,
	MODULE_INIT_SE_AS,
	MODULE_INIT_SE_ETCAM,
	MODULE_INIT_SE_STAT,
	MODULE_INIT_SE_FIFO,
	MODULE_INIT_SE_MAX
};

struct smmu1_kschd_hash_ddr_cfg_t {
	u32 baddr;
	u32 crcen;
	u32 mode;
};

struct smmu1_kschd_lpm_ddr_cfg_t {
	u32 baddr;
	u32 bankcopy;
	u32 crcen;
	u32 flag; /* 0-256, 1-384 */
	u32 as_baddr;
	u32 as_bankcopy;
	u32 as_crcen;
	u32 as_mode;
};

struct dpp_lpm_as_eram_info_t {
	u32 as_baddr;
	u32 as_mode;
};

struct dpp_lpm_res_info_t {
	struct dpp_lpm_as_eram_info_t as_eram_info[DPP_SMMU0_LPM_AS_TBL_ID_NUM];
	u32 v4_ddr_baddr;
	u32 v4_as_ddr_baddr;
	u32 v4_as_rsp_len;
	u32 v6_ddr_baddr;
	u32 v6_as_ddr_baddr;
	u32 v6_as_rsp_len;
};

struct dpp_smmu0_dbg_cnt_t {
	u32 smmu0_rcv_as_age_req_cnt;
	u32 smmu0_rcv_parse_req_cnt;
	u32 smmu0_cpu_ind_rd_rsp_cnt;
	u32 smmu0_cpu_ind_rd_req_cnt;
	u32 smmu0_cpu_ind_wr_req_cnt;

	u32 smmu0_to_plcr_rsp_cnt[DPP_SMMU0_PLCR_NUM];
	u32 smmu0_rcv_plcr_req_cnt[DPP_SMMU0_PLCR_NUM];

	u32 smmu0_to_lpm_as_rsp_cnt;
	u32 smmu0_rcv_lpm_as_req_cnt;

	u32 smmu0_to_as_etacm_rsp_cnt[DPP_SMMU0_AS_ETCAM_NUM];
	u32 smmu0_rcv_as_etacm_req_cnt[DPP_SMMU0_AS_ETCAM_NUM];

	u32 smmu0_to_ppu_mc_rsp_cnt;
	u32 smmu0_rcv_ppu_mc_req_cnt;
	u32 smmu0_to_odma_tdm_mc_rsp_cnt;
	u32 smmu0_rcv_odma_tdm_mc_req_cnt;
	u32 smmu0_to_odma_rsp_cnt;
	u32 smmu0_rcv_odma_req_cnt;
	u32 smmu0_to_dma_rsp_cnt;
	u32 smmu0_rcv_dma_req_cnt;

	u32 smmu0_to_stat_rsp_cnt[DPP_SMMU0_STAT_NUM];
	u32 smmu0_rcv_stat_req_cnt[DPP_SMMU0_STAT_NUM];
	u32 smmu0_to_ppu_rsp_cnt[DPP_SMMU0_CLS_NUM];
	u32 smmu0_rcv_ppu_req_cnt[DPP_SMMU0_CLS_NUM];

	u32 smmu0_rcv_ftm_stat_req0_cnt;
	u32 smmu0_rcv_ftm_stat_req1_cnt;
	u32 smmu0_rcv_etm_stat_req0_cnt;
	u32 smmu0_rcv_etm_stat_req1_cnt;

	u32 smmu0_block_rd_cnt[DPP_SMMU0_ERAM_BLOCK_NUM];
	u32 smmu0_block_wr_cnt[DPP_SMMU0_ERAM_BLOCK_NUM];
};

struct dpp_smmu0_dbg_fc_cnt_t {
	u32 smmu0_to_as_age_req_fc_cnt;
	u32 smmu0_to_parse_req_fc_cnt;
	u32 smmu0_rcv_wr_arb_cpu_fc_cnt;
	u32 smmu0_to_as_lpm_req_fc_cnt;
	u32 smmu0_rcv_as_lpm_rsp_fc_cnt;
	u32 smmu0_to_as_etacm_req_fc_cnt[DPP_SMMU0_AS_ETCAM_NUM];
	u32 smmu0_rcv_as_etacm_rsp_fc_cnt[DPP_SMMU0_AS_ETCAM_NUM];
	u32 smmu0_to_ppu_mc_req_fc_cnt;
	u32 smmu0_rcv_ppu_mc_rsp_fc_cnt;
	u32 smmu0_rcv_odma_tdm_mc_rsp_fc_cnt;
	u32 smmu0_to_odma_tdm_mc_req_fc_cnt;
	u32 smmu0_to_odma_req_fc_cnt;
	u32 smmu0_to_dma_req_fc_cnt;
	u32 smmu0_to_stat_req_fc_cnt[DPP_SMMU0_STAT_NUM];
	u32 smmu0_rcv_stat_rsp_fc_cnt[DPP_SMMU0_STAT_NUM];
	u32 smmu0_to_ppu_req_fc_cnt[DPP_SMMU0_CLS_NUM];
	u32 smmu0_rcv_ppu_rsp_fc_cnt[DPP_SMMU0_CLS_NUM];
};

struct dpp_smmu1_dbg_cnt_t {
	u32 ctrl_to_cash_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 cash_to_ctrl_req_cnt[DPP_SMMU1_GRP_CNT];
	u32 rschd_to_cache_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 cash_to_cache_rsp_cnt[DPP_SMMU1_GRP_CNT];
	u32 cash_to_ctrl_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 ctrl_to_cash_rsp_cnt[DPP_SMMU1_GRP_CNT];
	u32 kschd_to_cache_req_cnt[DPP_SMMU1_GRP_CNT];
	u32 cache_to_kschd_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 dma_to_smmu1_rd_req_cnt;
	u32 oam_to_kschd_req_cnt;
	u32 oam_rr_state_rsp_cnt;
	u32 oam_clash_info_cnt;
	u32 oam_to_rr_req_cnt;
	u32 lpm_as_to_kschd_req_cnt;
	u32 lpm_as_rr_state_rsp_cnt;
	u32 lpm_as_clash_info_cnt;
	u32 lpm_as_to_rr_req_cnt;
	u32 lpm_to_kschd_req_cnt;
	u32 lpm_rr_state_rsp_cnt;
	u32 lpm_clash_info_cnt;
	u32 lpm_to_rr_req_cnt;
	u32 hash_to_kschd_req_cnt[DPP_HASH_ID_NUM];
	u32 hash_rr_state_rsp_cnt[DPP_HASH_ID_NUM];
	u32 hash_clash_info_cnt[DPP_HASH_ID_NUM];
	u32 hash_to_rr_req_cnt[DPP_HASH_ID_NUM];
	u32 dir_to_kschd_req_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 dir_clash_info_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 dir_tbl_wr_req_cnt;
	u32 warbi_to_dir_tbl_warbi_fc_cnt;
	u32 dir_to_bank_rr_req_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 kschd_to_dir_fc_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 dir_rr_state_rsp_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 wr_done_to_warbi_fc_cnt;
	u32 wr_done_ptr_req_cnt;
	u32 ctrl_to_warbi_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 warbi_to_ctrl_wr_req_cnt[DPP_SMMU1_GRP_CNT];
	u32 warbi_to_cash_wr_req_cnt[DPP_SMMU1_GRP_CNT];
	u32 warbi_to_cpu_wr_fc_cnt;
	u32 cpu_wr_req_cnt;
	u32 ctrl_to_cpu_rd_rsp_cnt[DPP_SMMU1_GRP_CNT];
	u32 cpu_to_ctrl_rd_req_cnt[DPP_SMMU1_GRP_CNT];
	u32 cpu_rd_dir_tbl_rsp_cnt;
	u32 cpu_to_dir_tbl_rd_wr_req_cnt;
	u32 smmu1_to_mmu_rsp_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 mmu_to_smmu1_rd_rsp_cnt[DPP_SMMU1_GRP_CNT];
	u32 mmu_to_smmu1_rd_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 smmu1_to_mmu_rd_req_cnt[DPP_SMMU1_GRP_CNT];
	u32 mmu_to_smmu1_wr_fc_cnt[DPP_SMMU1_GRP_CNT];
	u32 smmu1_to_mmu_wr_req_cnt[DPP_SMMU1_GRP_CNT];
	u32 se_to_smmu1_wr_rsp_fc_cnt;
	u32 smmu1_to_se_wr_rsp_cnt;
	u32 ddr_wr_rsp_cnt[DPP_SMMU1_GRP_CNT];
	u32 smmu1_to_as_fc_cnt;
	u32 as_to_smmu1_wr_req_cnt;
	u32 smmu1_to_se_parser_fc_cnt;
	u32 se_parser_to_smmu1_req_cnt;
	u32 smmu1_to_etm_wr_fc_cnt;
	u32 etm_wr_req_cnt;
	u32 smmu1_to_ftm_wr_fc_cnt;
	u32 ftm_wr_req_cnt;
	u32 smmu1_to_state_wr_fc_cnt;
	u32 state_wr_req_cnt;
	u32 se_to_dma_rsp_cnt;
	u32 se_to_dma_fc_cnt;
	u32 oam_to_smmu1_fc_cnt;
	u32 smmu1_to_oam_rsp_cnt;
	u32 smmu1_to_oam_fc_cnt;
	u32 oam_to_smmu1_req_cnt;
	u32 smmu1_to_etm_rsp_cnt;
	u32 smmu1_to_ftm_rsp_cnt;
	u32 smmu1_to_etm_fc_cnt;
	u32 etm_to_smmu1_req_cnt;
	u32 smmu1_to_ftm_fc_cnt;
	u32 ftm_to_smmu1_req_cnt;
	u32 smmu1_to_stat_rsp_cnt;
	u32 smmu1_to_stat_fc_cnt;
	u32 stat_to_smmu1_req_cnt; /* cmmu */
	u32 lpm_as_to_smmu1_fc_cnt;
	u32 lpm_to_smmu1_fc_cnt;
	u32 smmu1_to_lpm_as_rsp_cnt;
	u32 smmu1_to_lpm_rsp_cnt;
	u32 smmu1_to_lpm_as_fc_cnt;
	u32 smmu1_to_lpm_fc_cnt;
	u32 lpm_as_to_smmu1_req_cnt;
	u32 lpm_to_smmu1_req_cnt;
	u32 hash_to_smmu1_fc_cnt[DPP_HASH_ID_NUM];
	u32 smmu1_to_hash_rsp_cnt[DPP_HASH_ID_NUM];
	u32 smmu1_to_hash_fc_cnt[DPP_HASH_ID_NUM];
	u32 hash_to_smmu1_cnt[DPP_HASH_ID_NUM];
	u32 se_to_smmu1_dir_rsp_fc_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 smmu1_to_se_dir_rsp_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 smmu1_to_se_dir_fc_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 se_to_smmu1_dir_cnt[DPP_SMMU1_DIR_CHANNEL_CNT];
	u32 cache_to_rschd_rsp_cnt[DPP_SMMU1_GRP_CNT];
};

struct se_parser_dbg_cnt_t {
	u32 mex_req_cnt[DPP_PARSE_MEX_CHANNEL_NUM];
	u32 kschd_req_cnt[DPP_PARSE_KSCHD_CHANNEL_NUM];
	u32 kschd_parser_fc_cnt[DPP_PARSE_KSCHD_CHANNEL_NUM];
	u32 se_ppu_mex_fc_cnt[DPP_PARSE_MEX_CHANNEL_NUM];
	u32 smmu0_marc_fc_cnt;
	u32 smmu0_marc_key_cnt;
	u32 smmu1_key_cnt;
	u32 smmu1_parser_fc_cnt;
	u32 marc_tab_type_err_mex_cnt[DPP_PARSE_MEX_CHANNEL_NUM];
	u32 eram_fulladdr_drop_cnt;
};

struct se_kschd_dbg_cnt_t {
	u32 parser_kschd_key_cnt[DPP_PARSE_KSCHD_CHANNEL_NUM];
	u32 kschd_smmu1_key_cnt[DPP_SMMU1_SCH_CNT];
	u32 kschd_to_as_hash0_key_cnt;
	u32 kschd_to_as_hash1_key_cnt;
	u32 kschd_to_as_hash2_key_cnt;
	u32 kschd_to_as_hash3_key_cnt;
	u32 kschd_to_as_lpm_key_cnt;
	u32 kschd_to_as_etacm0_key_cnt;
	u32 kschd_to_as_etacm1_key_cnt;
	u32 kschd_to_as_pbu_key_cnt;
	u32 kschd_to_parser_fc_cnt[DPP_PARSE_KSCHD_CHANNEL_NUM];
	u32 smmu1_kschd_fc_cnt[DPP_SMMU1_SCH_CNT];
	u32 kschd_rcv_as_hash0_fc_cnt;
	u32 kschd_rcv_as_hash1_fc_cnt;
	u32 kschd_rcv_as_hash2_fc_cnt;
	u32 kschd_rcv_as_hash3_fc_cnt;
	u32 kschd_rcv_as_lpm_fc_cnt;
	u32 kschd_rcv_as_etacm0_fc_cnt;
	u32 kschd_rcv_as_etacm1_fc_cnt;
	u32 kschd_rcv_as_pbu_fc_cnt;
};

struct se_rschd_dbg_cnt_t {
	u32 se_ppu_mex_rsp_cnt[DPP_RSCHD_PPU_CHANNEL_NUM];
	u32 rschd_rcv_as_hash0_rsp_cnt;
	u32 rschd_rcv_as_hash1_rsp_cnt;
	u32 rschd_rcv_as_hash2_rsp_cnt;
	u32 rschd_rcv_as_hash3_rsp_cnt;
	u32 rschd_rcv_as_lpm_rsp_cnt;
	u32 rschd_rcv_as_etacm0_rsp_cnt;
	u32 rschd_rcv_as_etacm1_rsp_cnt;
	u32 rschd_rcv_as_pbu_rsp_cnt;
	u32 smmu1_rschd_rsp_cnt[DPP_SMMU1_SCH_CNT];
	u32 ppu_se_mex_fc_cnt[DPP_RSCHD_PPU_CHANNEL_NUM];
	u32 rschd_to_as_hash0_fc_cnt;
	u32 rschd_to_as_hash1_fc_cnt;
	u32 rschd_to_as_hash2_fc_cnt;
	u32 rschd_to_as_hash3_fc_cnt;
	u32 rschd_to_as_lpm_fc_cnt;
	u32 rschd_to_as_etacm0_fc_cnt;
	u32 rschd_to_as_etacm1_fc_cnt;
	u32 rschd_to_as_pbu_fc_cnt;
	u32 rschd_smmu1_rdy_cnt[DPP_SMMU1_SCH_CNT];
	u32 rschd_rcv_smmu0_wr_done_cnt;
	u32 rschd_to_smmu0_wr_done_fc_cnt;
	u32 rschd_rcv_smmu1_wr_done_cnt;
	u32 rschd_to_smmu1_wr_done_fc_cnt;
	u32 rschd_rcv_alg_wr_done_cnt;
	u32 rschd_to_alg_wr_done_fc_cnt;
};

struct se_cmmu_dbg_cnt_t {
	u32 stat_cmmu_req_cnt;
	u32 cmmu_stat_fc_cnt;
	u32 smmu1_cmmu_wr_fc_cnt;
	u32 smmu1_cmmu_rd_fc_cnt;
};

struct se_as_dbg_cnt_t {
	u32 hash_wr_req_cnt[DPP_HASH_ID_NUM];
	u32 smmu0_etcam_fc_cnt[DPP_ETCAM_ID_NUM];
	u32 etcam_smmu0_req_cnt[DPP_ETCAM_ID_NUM];
	u32 smmu0_etcam_rsp_cnt[DPP_ETCAM_ID_NUM];
	u32 as_hla_hash_key_cnt[DPP_HASH_ID_NUM];
	u32 as_hla_lpm_key_cnt;
	u32 alg_as_hash_rsp_cnt[DPP_HASH_ID_NUM];
	u32 alg_as_hash_smf_rsp_cnt[DPP_HASH_ID_NUM];
	u32 alg_as_lpm_rsp_cnt;
	u32 alg_as_lpm_smf_rsp_cnt;
	u32 as_pbu_key_cnt;
	u32 pbu_se_dpi_rsp_dat_cnt;
	u32 as_etcam_ctrl_req_cnt[DPP_ETCAM_ID_NUM];
	u32 etcam_ctrl_as_index_cnt[DPP_ETCAM_ID_NUM];
	u32 etcam_ctrl_as_hit_cnt[DPP_ETCAM_ID_NUM];
	u32 as_smmu0_req_cnt;
	u32 learn_hla_wr_cnt;
	u32 as_smmu1_req_cnt;
	u32 se_cfg_mac_dat_cnt;
	u32 alg_as_hash_fc_cnt[DPP_HASH_ID_NUM];
	u32 alg_as_lpm_fc_cnt;
	u32 as_alg_hash_fc_cnt[DPP_HASH_ID_NUM];
	u32 as_alg_lpm_fc_cnt;
	u32 as_pbu_fc_cnt;
	u32 pbu_se_dpi_key_fc_cnt;
	u32 as_etcam_ctrl_fc_cnt[DPP_ETCAM_ID_NUM];
	u32 etcam_ctrl_as_fc_cnt[DPP_ETCAM_ID_NUM];
	u32 smmu0_as_mac_age_fc_cnt;
	u32 alg_learn_fc_cnt;
	u32 smmu1_as_fc_cnt;
	u32 cfg_se_mac_fc_cnt;
};

enum se_as_hash_dma_fc_en_e {
	HASH_EN_DMA_FC = 0,
	HASH_UN_EN_DMA_FC = 1,
};

struct se_alg_dbg_cnt_t {
	u32 hash_key_cnt[4];
	u32 hash_rsp_cnt[4];
	u32 hash_hit_cnt[4];
	u32 hash_space_vld_cnt[4];
	u32 hash_ddr3_req_vld_cnt[4];
	u32 hash_ddr3_rsp_vld_cnt[4];

	u32 lpm_key_cnt;
	u32 lpm_rsp_cnt;
	u32 lpm_hit_cnt;
	u32 lpm_key_ddr3_req_vld_cnt;
	u32 lpm_key_ddr3_rsp_vld_cnt;
	u32 lpm_as_ddr3_req_vld_cnt;
	u32 lpm_as_ddr3_rsp_vld_cnt;
};

struct se_alg_dbg_excp_cnt_t {
	u32 schd_learn_fifo_int_cnt;
	u32 schd_hash_fifo_int_cnt[4];
	u32 schd_lpm_fifo_int_cnt;
	u32 schd_learn_fifo_parity_err_cnt;
	u32 schd_hash_fifo_parity_err_cnt[4];
	u32 schd_lpm_fifo_parity_err_cnt;
	u32 rd_init_cft_cnt;
	u32 zblk_ecc_err_cnt[32];
	u32 zcam_hash_parity_err_cnt[4];
	u32 zcam_lpm_err_cnt;

	u32 hash_sreq_fifo_parity_err_cnt[4];
	u32 hash_sreq_fifo_int_cnt[4];
	u32 hash_key_fifo_int_cnt[4];
	u32 hash_int_rsp_fifo_parity_err_cnt[4];
	u32 hash_ext_rsp_fifo_parity_err_cnt[4];
	u32 hash_ext_rsp_fifo_int_cnt[4];
	u32 hash_int_rsp_fifo_int_cnt[4];

	u32 lpm_ext_rsp_fifo_int_cnt;
	u32 lpm_ext_v6_fifo_int_cnt;
	u32 lpm_ext_v4_fifo_int_cnt;
	u32 lpm_ext_addr_fifo_int_cnt;
	u32 lpm_ext_v4_fifo_parity_err_cnt;
	u32 lpm_ext_v6_fifo_parity_err_cnt;
	u32 lpm_ext_rsp_fifo_parity_err_cnt;
	u32 lpm_as_req_fifo_int_cnt;
	u32 lpm_as_int_rsp_fifo_int_cnt;
};

#define LPM_HW_DAT_BUFF_SIZE_MAX (16 * 1024)
enum LPM_DAT_WR_TYPE {
	LPM_DAT_WR_TYPE_DMA = 1UL,
	LPM_DAT_WR_TYPE_REG = 2UL,
};

enum ROUTE_DAT_TYPE {
	LPM_DAT_ZECLL = 1UL,
	LPM_DAT_ZREG = 2UL,
	LPM_DAT_DDR = 3UL,
	LPM_DAT_DDR_RST = 4UL,
	LPM_DAT_ERAM_RST = 5UL,
	LPM_DAT_TYPE_MAX,
};

struct _lpm_hw_dat_ddr {
	u32 dat_type; /* ROUTE_DAT_TYPE :LPM_DAT_DDR/LPM_DAT_DDR_RST */
	u32 v4v6_flag; /* ALG_LPM_TYPE_E */
	u32 lpm_wr_vld; /* 0-WR 1-RD */
	u32 tbl_id;
	u32 base_addr; /* 19b */
	u32 index; /* by rw_len */
	u32 ecc_en;
	u32 rw_len; /* SMMU1_DDR_WRT_MODE_E */
	u8 data[512 / 8];
};

struct _lpm_hw_dat_zcam {
	u32 dat_type; /* ROUTE_DAT_TYPE :LPM_DAT_ZREG/LPM_DAT_ZECLL */
	u32 ram_reg_flag; /* 0-reg 1-cell */
	u32 rw_addr; /* by 512b */
	u8 data[512 / 8];
};

struct _lpm_hw_dat_eram {
	u32 dat_type; /* ROUTE_DAT_TYPE :LPM_DAT_ERAM_RST */
	u32 base_addr; /* by 128b */
	u32 index; /* by rw_len*/
	u32 rw_len; /* DPP_ERAM128_TBL_MODE_E */
	u8 data[128 / 8];
};

struct ppu_stat_cfg_t {
	u32 eram_baddr;
	u32 eram_depth;
	u32 ddr_base_addr;
	u32 ppu_addr_offset;
};

/***********************************************************/
/** dpp hashsmmu1�?
 * @remark  �?
 * @see
 * @author  ls      @date  2016/04/12
 ************************************************************
 */
DPP_STATUS dpp_se_smmu1_hash_tbl_cfg_set(struct dpp_dev_t *dev, u32 hash_id, u32 tbl_id, u32 ecc_en,
					 u32 baddr);

/** hashDDR()
 * @see
 * @author  tf      @date  2016/06/15
 ************************************************************
 */
DPP_STATUS dpp_se_smmu1_hash_tbl_soft_cfg_get(struct dpp_dev_t *dev, u32 hash_id, u32 bulk_id,
					      u32 *p_ecc_en, u32 *p_base_addr);

DPP_STATUS dpp_se_zblk_serv_cfg_set(struct dpp_dev_t *dev, u32 zblk_idx, u32 serv_sel, u32 hash_id,
				    u32 enable);

DPP_STATUS dpp_se_zcell_mono_cfg_set(struct dpp_dev_t *dev, u32 zblk_idx, u32 zcell0_tbl_id,
				     u32 zcell0_mono_flag, u32 zcell1_tbl_id, u32 zcell1_mono_flag,
				     u32 zcell2_tbl_id, u32 zcell2_mono_flag, u32 zcell3_tbl_id,
				     u32 zcell3_mono_flag);

DPP_STATUS dpp_se_zcell_mono_cfg_get(struct dpp_dev_t *dev, u32 zblk_idx, u32 *zcell0_tbl_id,
				     u32 *zcell0_mono_flag, u32 *zcell1_tbl_id,
				     u32 *zcell1_mono_flag, u32 *zcell2_tbl_id,
				     u32 *zcell2_mono_flag, u32 *zcell3_tbl_id,
				     u32 *zcell3_mono_flag);

DPP_STATUS
dpp_se_zreg_mono_cfg_set(struct dpp_dev_t *dev, u32 zblk_idx, u32 zreg0_tbl_id, u32 zreg0_mono_flag,
			 u32 zreg1_tbl_id, u32 zreg1_mono_flag, u32 zreg2_tbl_id,
			 u32 zreg2_mono_flag, u32 zreg3_tbl_id, u32 zreg3_mono_flag);

DPP_STATUS dpp_se_zreg_mono_cfg_get(struct dpp_dev_t *dev, u32 zblk_idx, u32 *zreg0_tbl_id,
				    u32 *zreg0_mono_flag, u32 *zreg1_tbl_id, u32 *zreg1_mono_flag,
				    u32 *zreg2_tbl_id, u32 *zreg2_mono_flag, u32 *zreg3_tbl_id,
				    u32 *zreg3_mono_flag);
DPP_STATUS dpp_se_hash_zcam_mono_flags_set(struct dpp_dev_t *dev, u32 hash0_mono_flag,
					   u32 hash1_mono_flag, u32 hash2_mono_flag,
					   u32 hash3_mono_flag);

DPP_STATUS dpp_se_hash_zcam_mono_flags_get(struct dpp_dev_t *dev, u32 *hash0_mono_flag,
					   u32 *hash1_mono_flag, u32 *hash2_mono_flag,
					   u32 *hash3_mono_flag);

DPP_STATUS dpp_se_hash_ext_cfg_set(struct dpp_dev_t *dev, u32 hash_id, u32 ext_mode, u32 flag);
DPP_STATUS dpp_se_hash_ext_cfg_get(struct dpp_dev_t *dev, u32 hash_id, u32 *p_content_type,
				   u32 *p_flag);
DPP_STATUS dpp_se_hash_tbl_depth_set(struct dpp_dev_t *dev, u32 hash_id, u32 hash_tbl0_depth,
				     u32 hash_tbl1_depth, u32 hash_tbl2_depth, u32 hash_tbl3_depth,
				     u32 hash_tbl4_depth, u32 hash_tbl5_depth, u32 hash_tbl6_depth,
				     u32 hash_tbl7_depth);
DPP_STATUS dpp_se_hash_tbl_depth_get(struct dpp_dev_t *dev, u32 hash_id, u32 *hash_tbl0_depth,
				     u32 *hash_tbl1_depth, u32 *hash_tbl2_depth,
				     u32 *hash_tbl3_depth, u32 *hash_tbl4_depth,
				     u32 *hash_tbl5_depth, u32 *hash_tbl6_depth,
				     u32 *hash_tbl7_depth);

#endif
