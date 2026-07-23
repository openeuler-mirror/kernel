/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*********************************************************************
 * DEPARTMENT: ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 ********************************************************************
 */

#ifndef _DPP_SDT_H_
#define _DPP_SDT_H_
#include "dpp_ppu.h"

#define DPP_SDT_H_TBL_TYPE_BT_POS (29)
#define DPP_SDT_H_TBL_TYPE_BT_LEN (3)

#define DPP_SDT_H_ERAM_MODE_BT_POS (26)
#define DPP_SDT_H_ERAM_MODE_BT_LEN (3)
#define DPP_SDT_H_ERAM_BASE_ADDR_BT_POS (7)
#define DPP_SDT_H_ERAM_BASE_ADDR_BT_LEN (19)
#define DPP_SDT_L_ERAM_TABLE_DEPTH_BT_POS (1)
#define DPP_SDT_L_ERAM_TABLE_DEPTH_BT_LEN (22)

#define DPP_SDT_H_DDR3_BASE_ADDR_BT_POS (9)
#define DPP_SDT_H_DDR3_BASE_ADDR_BT_LEN (20)
#define DPP_SDT_H_DDR3_SHARE_TYPE_BT_POS (7)
#define DPP_SDT_H_DDR3_SHARE_TYPE_BT_LEN (2)
#define DPP_SDT_H_DDR3_RW_LEN_BT_POS (5)
#define DPP_SDT_H_DDR3_RW_LEN_BT_LEN (2)
#define DPP_SDT_H_DDR3_SDT_NUM_BT_POS (0)
#define DPP_SDT_H_DDR3_SDT_NUM_BT_LEN (5)
#define DPP_SDT_L_DDR3_SDT_NUM_BT_POS (29)
#define DPP_SDT_L_DDR3_SDT_NUM_BT_LEN (3)
#define DPP_SDT_L_DDR3_ECC_EN_BT_POS (28)
#define DPP_SDT_L_DDR3_ECC_EN_BT_LEN (1)

#define DPP_SDT_H_HASH_ID_BT_POS (27)
#define DPP_SDT_H_HASH_ID_BT_LEN (2)
#define DPP_SDT_H_HASH_TABLE_WIDTH_BT_POS (25)
#define DPP_SDT_H_HASH_TABLE_WIDTH_BT_LEN (2)
#define DPP_SDT_H_HASH_KEY_SIZE_BT_POS (19)
#define DPP_SDT_H_HASH_KEY_SIZE_BT_LEN (6)
#define DPP_SDT_H_HASH_TABLE_ID_BT_POS (14)
#define DPP_SDT_H_HASH_TABLE_ID_BT_LEN (5)
#define DPP_SDT_H_LEARN_EN_BT_POS (13)
#define DPP_SDT_H_LEARN_EN_BT_LEN (1)
#define DPP_SDT_H_KEEP_ALIVE_BT_POS (12)
#define DPP_SDT_H_KEEP_ALIVE_BT_LEN (1)
#define DPP_SDT_H_KEEP_ALIVE_BADDR_BT_POS (0)
#define DPP_SDT_H_KEEP_ALIVE_BADDR_BT_LEN (12)
#define DPP_SDT_L_KEEP_ALIVE_BADDR_BT_POS (25)
#define DPP_SDT_L_KEEP_ALIVE_BADDR_BT_LEN (7)
#define DPP_SDT_L_RSP_MODE_BT_POS (23)
#define DPP_SDT_L_RSP_MODE_BT_LEN (2)

#define DPP_SDT_H_LPM_V46ID_BT_POS (28)
#define DPP_SDT_H_LPM_V46ID_BT_LEN (1)
#define DPP_SDT_H_LPM_RSP_MODE_BT_POS (0)
#define DPP_SDT_H_LPM_RSP_MODE_BT_LEN (2)
#define DPP_SDT_L_LPM_TABLE_DEPTH_BT_POS (1)
#define DPP_SDT_L_LPM_TABLE_DEPTH_BT_LEN (30)

#define DPP_SDT_H_ETCAM_ID_BT_POS (27)
#define DPP_SDT_H_ETCAM_ID_BT_LEN (1)
#define DPP_SDT_H_ETCAM_KEY_MODE_BT_POS (25)
#define DPP_SDT_H_ETCAM_KEY_MODE_BT_LEN (2)
#define DPP_SDT_H_ETCAM_TABLE_ID_BT_POS (21)
#define DPP_SDT_H_ETCAM_TABLE_ID_BT_LEN (4)
#define DPP_SDT_H_ETCAM_NOAS_RSP_MODE_BT_POS (19)
#define DPP_SDT_H_ETCAM_NOAS_RSP_MODE_BT_LEN (2)
#define DPP_SDT_H_ETCAM_AS_EN_BT_POS (18)
#define DPP_SDT_H_ETCAM_AS_EN_BT_LEN (1)
#define DPP_SDT_H_ETCAM_AS_ERAM_BADDR_BT_POS (0)
#define DPP_SDT_H_ETCAM_AS_ERAM_BADDR_BT_LEN (18)
#define DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_POS (31)
#define DPP_SDT_L_ETCAM_AS_ERAM_BADDR_BT_LEN (1)
#define DPP_SDT_L_ETCAM_AS_RSP_MODE_BT_POS (28)
#define DPP_SDT_L_ETCAM_AS_RSP_MODE_BT_LEN (3)
#define DPP_SDT_L_ETCAM_TABLE_DEPTH_BT_POS (1)
#define DPP_SDT_L_ETCAM_TABLE_DEPTH_BT_LEN (20)

#define DPP_SDT_L_CLUTCH_EN_BT_POS (0)
#define DPP_SDT_L_CLUTCH_EN_BT_LEN (1)

#define DPP_SDT_TBL_TYPE_NUM (8)
DPP_STATUS dpp_sdt_tbl_data_parser(struct dpp_dev_t *dev, u32 sdt_hig32, u32 sdt_low32,
				   void *p_sdt_info);
DPP_STATUS dpp_sdt_tbl_data_get(struct dpp_dev_t *dev, u32 sdt_no,
				struct dpp_sdt_tbl_data_t *p_sdt_data);
DPP_STATUS dpp_soft_sdt_tbl_set(struct dpp_dev_t *dev, u32 sdt_no, u32 table_type,
				struct dpp_sdt_tbl_data_t *p_sdt_info);
DPP_STATUS dpp_soft_sdt_tbl_get(struct dpp_dev_t *dev, u32 sdt_no, void *p_sdt_info);

#endif
