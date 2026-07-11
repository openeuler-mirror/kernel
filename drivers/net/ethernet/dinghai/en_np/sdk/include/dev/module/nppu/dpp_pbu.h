/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PBU_H_
#define _DPP_PBU_H_

#include "dpp_nppu_reg.h"
#include "dpp_pbu_api.h"

#if ZXIC_REAL("macro")
#define DPP_PBU_IND_CMD_WRT_FLAG (0)
#define DPP_PBU_IND_CMD_RD_FLAG (1)

#define PBU_FILE_PATH ("sa500t_pbu_output.txt")
#define PBU_FILE_PATH_RAM ("sa500t_pbu_output_ram.txt")

#define DPP_PBU_PORT_NUM (119)
#define DPP_PBU_PORT_TH_MAX (16380)

#define DPP_PBU_LIF0_PORT_NUM (48)
#define DPP_PBU_LIF1_PORT_NUM (56)
#define DPP_PBU_TM_LOOP_PORT_NUM (113)

#define DPP_PBU_COS_NUM (8)
#define DPP_PBU_ALL_FTM_LINK_TH_NUM (6)
#define DPP_PBU_IDMA_MAX_TH (16380)
#define DPP_PBU_LIF_MAX_TH (16384)
#define DPP_PBU_MC_MAX_TH (16380)
#define DPP_PBU_PORT_COS_MAX_TH (16380)
#define DPP_PBU_MC_MAX_DIFF_TH (255)
#define DPP_PBU_MC_MIN_DIFF_TH (5)
#define DPP_PBU_CAP_DATA_MODE_MIN (0)
#define DPP_PBU_CAP_DATA_MODE_MAX (12)

#define DPP_PBU_CAP_FILTER_ADDR (0x185)
#define DPP_PBU_CAP_PKT_NUM (64)

#endif

#if ZXIC_REAL("struct")

enum npe_pbu_ptr_rotate_e {
	DPP_PBU_TOTAL_PTR_ROTATE = 0X1,
	DPP_PBU_MC_PTR_ROTATE = 0X2,
	DPP_PBU_PORT_PTR_ROTATE = 0X4,

};

struct dpp_pbu_cnt_para_t {
	u32 total_cnt;
	u32 idma_pub_cnt;
	u32 lif_pub_cnt;
	u32 mc_total_cnt;
};

struct dpp_mf_info_t {
	char *name;
	u32 start_bit;
	u32 end_bit;
};

enum dpp_pbu_ind_mem_id_e {
	DPP_PBU_IDMATH_RAM = 0,
	DPP_PBU_MACTH_RAM = 1,
	DPP_PBU_CFG_IND_MEM_ID_INVALID = 2,
};

enum dpp_pbu_stat_ind_mem_id_e {
	DPP_PBU_PORT_CNT = 1,
	DPP_PBU_STAT = 2,
	DPP_PBU_IFB_CFG = 3,
	DPP_PBU_CAPTURE_CFG = 4,
	DPP_PBU_PORT_PUB_CNT = 5,
	DPP_PBU_IND_MEM_ID_INVALID = 6,
};

enum dpp_idma_stat_ind_mem_id_e {
	DPP_IDMA_STAT_RAM = 0,
	DPP_IDMA_DEBUG_RAM = 1,
	DPP_IDMA_IND_MEM_ID_INVALID = 2,
};

enum dpp_pbu_other_cnt_id_e {
	DPP_PBU_IDMA_PTR_REQ_CNT = 0,
	DPP_PBU_IDMA_RFD_WR_CNT = 1,
	DPP_PBU_IDMA_IFB_WR1_CNT = 2,
	DPP_PBU_IDMA_IFB_WR2_CNT = 3,
	DPP_PBU_PPU_IFB_RD_CNT = 4,
	DPP_PBU_IFB_PPU_RDRSP_CNT = 5,
	DPP_PBU_ODMA_RECY_PTR_CNT = 6,
	DPP_PBU_PPU_PF_REQ0_CNT = 7,
	DPP_PBU_PBU_PF_RSP0_CNT = 8,
	DPP_PBU_PPU_PF_REQ1_CNT = 9,
	DPP_PBU_PBU_PF_RSP1_CNT = 10,
	DPP_PBU_PPU_USE_PTR_CNT = 11,
	DPP_PBU_PPU_WRBK_CNT = 12,
	DPP_PBU_PPU_REORDER_RSP_CNT = 13,
	DPP_PBU_SE_PBU_KEY_VLD_CNT = 14,
	DPP_PBU_PBU_SE_RSP_VLD_CNT = 15,
	DPP_PBU_ODMA_IFB_RD1_CNT = 16,
	DPP_PBU_ODMA_IFB_RD2_CNT = 17,
	DPP_PBU_IDMA_O_ISU_PKT_CNT = 18,
	DPP_PBU_IDMA_O_ISU_EPKT_CNT = 19,
	DPP_PBU_IDMA_DISPKT_CNT = 20,
	DPP_PBU_OTHER_CNT_ID_INVALID,
};

struct dpp_pbu_port_ptr_cnt_t {
	u32 peak_port_cnt;
	u32 current_port_cnt;
};

struct dpp_pbu_ifb_data_t {
	u32 pbu_ifb_data[64];
};

struct dpp_pbu_all_ftm_link_th_t {
	u32 total_congest_th[7];
};

struct DPP_PBU_LIF_GROUP_PFC_RDY {
	u32 pbu_lif_group0_pfc_rdy[12];
};

#endif

DPP_STATUS dpp_pbu_port_th_get(struct dpp_dev_t *dev, u32 port_id,
			       struct dpp_pbu_port_th_para_t *p_para);
DPP_STATUS dpp_pbu_port_cos_th_get(struct dpp_dev_t *dev, u32 port_id,
				   struct dpp_pbu_port_cos_th_para_t *p_para);
DPP_STATUS dpp_pbu_pfc_delay_time_set(struct dpp_dev_t *dev, u64 delayTime);
DPP_STATUS dpp_pbu_pfc_delay_time_get(struct dpp_dev_t *dev, u64 *delayTime);

#endif /* _DPP_PBU_H_ */
